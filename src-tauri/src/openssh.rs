//! OpenSSH's own private key format (`-----BEGIN OPENSSH PRIVATE KEY-----`, PROTOCOL.key), which
//! `ssh-keygen` has written by default since OpenSSH 7.8, and the RFC 4716 public key file.
//!
//! Reading covers RSA, ECDSA (nistp256/384/521), Ed25519 and DSA keys, unencrypted or encrypted
//! with any cipher `ssh-keygen -Z` offers: AES-CTR (the default), AES-CBC, 3DES-CBC, AES-GCM and
//! ChaCha20-Poly1305, all keyed through bcrypt-pbkdf. Writing produces an unencrypted key or
//! aes256-ctr with bcrypt, which is what `ssh-keygen` itself writes.

use crate::keys::{self, PrivateKey, ssh_mpint, ssh_string};
use crate::util::{Res, random_bytes, to_pem, trim_leading_zeros, unb64};
use aes::cipher::{BlockDecryptMut, KeyIvInit, StreamCipher, block_padding::NoPadding};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};

const MAGIC: &[u8] = b"openssh-key-v1\0";
const WRONG_PASSWORD: &str = "incorrect private key password";
const NEEDS_PASSWORD: &str = "this private key is encrypted; enter its password";
/// `ssh-keygen -a` defaults to 16 or 24 rounds and each one costs milliseconds. A file asking for
/// far more than anyone waits for at a prompt is not a key, it is a way to hang the app.
const MAX_BCRYPT_ROUNDS: u32 = 10_000;
/// What `ssh-keygen` writes today.
const WRITE_ROUNDS: u32 = 24;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn truncated() -> String {
        "invalid: the OpenSSH key is truncated or corrupt".into()
    }

    fn take(&mut self, len: usize) -> Res<&'a [u8]> {
        if len > self.0.len() {
            return Err(Self::truncated());
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn string(&mut self) -> Res<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn text(&mut self) -> Res<&'a str> {
        std::str::from_utf8(self.string()?).map_err(|_| Self::truncated())
    }

    /// An unsigned multi-precision integer, without the sign padding.
    fn mpint(&mut self) -> Res<BigUint> {
        Ok(BigUint::from_bytes_be(self.string()?))
    }
}

/// How a cipher name maps onto key material and block layout.
struct Cipher {
    key_len: usize,
    iv_len: usize,
    block: usize,
    /// Bytes of authentication tag that follow the encrypted section.
    tag_len: usize,
}

fn cipher_spec(name: &str) -> Res<Cipher> {
    let spec = |key_len, iv_len, block, tag_len| Cipher { key_len, iv_len, block, tag_len };
    Ok(match name {
        "none" => spec(0, 0, 8, 0),
        "aes128-ctr" | "aes128-cbc" => spec(16, 16, 16, 0),
        "aes192-ctr" | "aes192-cbc" => spec(24, 16, 16, 0),
        "aes256-ctr" | "aes256-cbc" => spec(32, 16, 16, 0),
        "3des-cbc" => spec(24, 8, 8, 0),
        "aes128-gcm@openssh.com" => spec(16, 12, 16, 16),
        "aes256-gcm@openssh.com" => spec(32, 12, 16, 16),
        "chacha20-poly1305@openssh.com" => spec(64, 0, 8, 16),
        other => return Err(format!("unsupported: this OpenSSH key is encrypted with {other}, which is not supported. Re-encrypt it with `ssh-keygen -p -Z aes256-ctr -f key`.")),
    })
}

/// The unencrypted outer part of an OpenSSH private key file.
pub struct Envelope<'a> {
    pub cipher: &'a str,
    pub kdf: &'a str,
    kdf_options: &'a [u8],
    /// The public key in SSH wire format. It is stored in the clear, so the key can be identified
    /// without its password.
    pub public_blob: &'a [u8],
    encrypted: &'a [u8],
    /// What follows the encrypted section: the tag of an authenticated cipher.
    trailer: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub fn parse(blob: &'a [u8]) -> Res<Envelope<'a>> {
        let body = blob.strip_prefix(MAGIC).ok_or("invalid: not an OpenSSH private key (the openssh-key-v1 marker is missing)")?;
        let mut r = Reader(body);
        let cipher = r.text()?;
        let kdf = r.text()?;
        let kdf_options = r.string()?;
        if r.u32()? != 1 {
            return Err("unsupported: OpenSSH key files with more than one key are not supported".into());
        }
        let public_blob = r.string()?;
        let encrypted = r.string()?;
        Ok(Envelope { cipher, kdf, kdf_options, public_blob, encrypted, trailer: r.0 })
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher != "none"
    }

    /// bcrypt rounds, when the key is encrypted.
    pub fn rounds(&self) -> Option<u32> {
        let mut r = Reader(self.kdf_options);
        r.string().ok()?;
        r.u32().ok()
    }

    /// The key type named in the public key, e.g. `ssh-ed25519`.
    pub fn key_type(&self) -> String {
        Reader(self.public_blob).text().unwrap_or("unknown").to_string()
    }

    fn decrypt(&self, password: Option<&str>) -> Res<Vec<u8>> {
        let spec = cipher_spec(self.cipher)?;
        if !self.is_encrypted() {
            return Ok(self.encrypted.to_vec());
        }
        if self.kdf != "bcrypt" {
            return Err(format!("unsupported: this OpenSSH key derives its key with {}, which is not supported", self.kdf));
        }
        let password = password.filter(|p| !p.is_empty()).ok_or(NEEDS_PASSWORD)?;
        let mut options = Reader(self.kdf_options);
        let salt = options.string()?;
        let rounds = options.u32()?;
        if rounds == 0 || rounds > MAX_BCRYPT_ROUNDS {
            return Err(format!("invalid: the key asks for {rounds} bcrypt rounds, which is outside the range ssh-keygen writes"));
        }
        if self.encrypted.is_empty() || !self.encrypted.len().is_multiple_of(spec.block) || self.trailer.len() < spec.tag_len {
            return Err(Reader::truncated());
        }
        let mut material = vec![0u8; spec.key_len + spec.iv_len];
        bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut material).map_err(|_| "invalid: the bcrypt parameters of this key are malformed".to_string())?;
        let (key, iv) = material.split_at(spec.key_len);
        let tag = &self.trailer[..spec.tag_len];
        let mut data = self.encrypted.to_vec();
        let bad_key = |_| "invalid: malformed cipher key".to_string();
        match self.cipher {
            "aes128-ctr" => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv).map_err(bad_key)?.apply_keystream(&mut data),
            "aes192-ctr" => ctr::Ctr128BE::<aes::Aes192>::new_from_slices(key, iv).map_err(bad_key)?.apply_keystream(&mut data),
            "aes256-ctr" => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv).map_err(bad_key)?.apply_keystream(&mut data),
            // The private section carries its own padding, so the cipher runs without any.
            "aes128-cbc" => data = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).map_err(bad_key)?.decrypt_padded_vec_mut::<NoPadding>(&data).map_err(|_| WRONG_PASSWORD.to_string())?,
            "aes192-cbc" => data = cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).map_err(bad_key)?.decrypt_padded_vec_mut::<NoPadding>(&data).map_err(|_| WRONG_PASSWORD.to_string())?,
            "aes256-cbc" => data = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(bad_key)?.decrypt_padded_vec_mut::<NoPadding>(&data).map_err(|_| WRONG_PASSWORD.to_string())?,
            "3des-cbc" => data = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv).map_err(bad_key)?.decrypt_padded_vec_mut::<NoPadding>(&data).map_err(|_| WRONG_PASSWORD.to_string())?,
            "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" => {
                use aes_gcm::aead::{Aead, KeyInit};
                let sealed = [self.encrypted, tag].concat();
                let nonce = aes_gcm::Nonce::from_slice(iv);
                data = if key.len() == 16 {
                    aes_gcm::Aes128Gcm::new_from_slice(key).map_err(bad_key)?.decrypt(nonce, sealed.as_slice())
                } else {
                    aes_gcm::Aes256Gcm::new_from_slice(key).map_err(bad_key)?.decrypt(nonce, sealed.as_slice())
                }
                .map_err(|_| WRONG_PASSWORD.to_string())?;
            }
            "chacha20-poly1305@openssh.com" => {
                use chacha20::cipher::StreamCipherSeek;
                use poly1305::universal_hash::KeyInit;
                // The first 32 bytes are the payload key. A key file is "packet" number zero, so
                // the nonce is zero: block 0 of the key stream keys Poly1305, the data starts at
                // block 1.
                let mut stream = chacha20::ChaCha20Legacy::new_from_slices(&key[..32], &[0u8; 8]).map_err(bad_key)?;
                let mut poly_key = [0u8; 32];
                stream.apply_keystream(&mut poly_key);
                let expected = poly1305::Poly1305::new_from_slice(&poly_key).map_err(bad_key)?.compute_unpadded(self.encrypted);
                if expected.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
                    return Err(WRONG_PASSWORD.into());
                }
                stream.seek(64u64);
                stream.apply_keystream(&mut data);
            }
            _ => unreachable!("cipher_spec accepted it"),
        }
        Ok(data)
    }
}

/// A private key read from an OpenSSH file.
#[derive(Debug)]
pub struct DecodedKey {
    pub key: PrivateKey,
    pub comment: String,
}

/// Decodes the binary content of an `OPENSSH PRIVATE KEY` PEM block.
pub fn decode_private_key(blob: &[u8], password: Option<&str>) -> Res<DecodedKey> {
    let envelope = Envelope::parse(blob)?;
    let plain = envelope.decrypt(password)?;
    let mut r = Reader(&plain);
    // Two copies of one random number: they differ when the key was decrypted with the wrong
    // password (for the ciphers that carry no tag of their own).
    let (check1, check2) = (r.u32()?, r.u32()?);
    if check1 != check2 {
        return Err(if envelope.is_encrypted() { WRONG_PASSWORD.into() } else { Reader::truncated() });
    }
    let key_type = r.text().map_err(|_| if envelope.is_encrypted() { WRONG_PASSWORD.to_string() } else { Reader::truncated() })?;
    let key = match key_type {
        "ssh-rsa" => {
            let (n, e, d, _iqmp, p, q) = (r.mpint()?, r.mpint()?, r.mpint()?, r.mpint()?, r.mpint()?, r.mpint()?);
            PrivateKey::Rsa(Box::new(RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|err| format!("invalid RSA key: {err}"))?))
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = r.text()?;
            if key_type.strip_prefix("ecdsa-sha2-") != Some(curve) {
                return Err("invalid: the OpenSSH key names two different curves".into());
            }
            let point = r.string()?;
            let scalar = r.string()?;
            let scalar = trim_leading_zeros(scalar);
            macro_rules! ec {
                ($m:ident, $variant:ident) => {{
                    use $m::elliptic_curve::sec1::ToEncodedPoint;
                    let key = $m::SecretKey::from_slice(scalar).map_err(|_| "invalid EC private key".to_string())?;
                    if key.public_key().to_encoded_point(false).as_bytes() != point {
                        return Err("invalid: the OpenSSH key's private and public halves do not match".into());
                    }
                    PrivateKey::$variant(key)
                }};
            }
            match curve {
                "nistp256" => ec!(p256, P256),
                "nistp384" => ec!(p384, P384),
                _ => ec!(p521, P521),
            }
        }
        "ssh-ed25519" => {
            let public = r.string()?;
            let secret = r.string()?;
            // The "secret key" is the 32-byte seed followed by the public key again.
            let seed: [u8; 32] = secret.get(..32).and_then(|s| s.try_into().ok()).ok_or_else(Reader::truncated)?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            if secret.len() != 64 || key.verifying_key().as_bytes() != public {
                return Err("invalid: the OpenSSH key's private and public halves do not match".into());
            }
            PrivateKey::Ed25519(Box::new(key))
        }
        "ssh-dss" => {
            // Carried, not used: rebuilt as the traditional DSA structure the key module reads.
            let values = [BigUint::from(0u8), r.mpint()?, r.mpint()?, r.mpint()?, r.mpint()?, r.mpint()?];
            let der = yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    for v in &values {
                        w.next().write_bigint_bytes(&v.to_bytes_be(), true);
                    }
                })
            });
            PrivateKey::from_bytes(&der, None)?
        }
        other if other.starts_with("sk-") => return Err(format!("unsupported: {other} is a hardware security key; its private key lives on the device and cannot be converted")),
        other => return Err(format!("unsupported: OpenSSH key type {other} is not supported (RSA, ECDSA, Ed25519 and DSA are)")),
    };
    let comment = r.text().unwrap_or_default().to_string();
    // The rest is padding: 1, 2, 3, …
    if r.0.iter().enumerate().any(|(i, b)| *b != (i + 1) as u8) {
        return Err(Reader::truncated());
    }
    Ok(DecodedKey { key, comment })
}

/// The `SubjectPublicKeyInfo` of a public key in SSH wire format (the base64 part of an
/// `authorized_keys` line, the body of an RFC 4716 file, or the public half stored in the clear
/// in an OpenSSH private key file).
pub fn spki_from_blob(blob: &[u8]) -> Res<Vec<u8>> {
    let mut r = Reader(blob);
    let kind = r.text()?;
    match kind {
        "ssh-rsa" => {
            let (ex, n) = (r.string()?, r.string()?);
            Ok(keys::rsa_spki(&rsa::RsaPublicKey::new_with_max_size(BigUint::from_bytes_be(n), BigUint::from_bytes_be(ex), 16384).map_err(|err| format!("invalid RSA public key: {err}"))?))
        }
        "ssh-ed25519" => keys::ed25519_spki(r.string()?),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = r.text()?;
            if kind.strip_prefix("ecdsa-sha2-") != Some(curve) {
                return Err("invalid: the OpenSSH key names two different curves".into());
            }
            keys::ec_spki(curve, r.string()?)
        }
        "ssh-dss" => {
            let (p, q, g, y) = (r.string()?, r.string()?, r.string()?, r.string()?);
            Ok(keys::dsa_spki(p, q, g, y))
        }
        other if other.starts_with("sk-") => Err(format!("unsupported: {other} is a hardware security key; only its handle is in the file")),
        other if other.contains("-cert-v01@openssh.com") => Err(format!("unsupported: {other} is an OpenSSH certificate, not a plain public key")),
        other => Err(format!("unsupported: OpenSSH key type {other} is not supported (RSA, ECDSA, Ed25519 and DSA are)")),
    }
}

/// The public key of an `authorized_keys`-style line: `type base64 [comment]`, with any options
/// in front of it (`from="…",no-pty ssh-ed25519 AAAA…`).
pub fn spki_from_line(line: &str) -> Res<(Vec<u8>, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|w| is_key_type(w)).ok_or("not an OpenSSH public key line")?;
    let blob = unb64(words.get(at + 1).ok_or("invalid OpenSSH public key: missing key data")?).map_err(|_| "invalid OpenSSH public key: the key data is not base64".to_string())?;
    if Reader(&blob).text().ok() != Some(words[at]) {
        return Err("invalid OpenSSH public key: the key type does not match its data".into());
    }
    Ok((spki_from_blob(&blob)?, words[at + 2..].join(" ")))
}

/// Key type names that start an OpenSSH public key.
pub fn is_key_type(word: &str) -> bool {
    matches!(word, "ssh-rsa" | "ssh-dss" | "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521")
}

/// Reads the `OPENSSH PRIVATE KEY` block out of PEM text.
pub fn private_key_blob(text: &str) -> Option<Vec<u8>> {
    crate::util::pem_blocks(text).into_iter().find(|b| b.tag == "OPENSSH PRIVATE KEY").map(|b| b.der)
}

/// Writes `key` as an OpenSSH private key file. With a password it is encrypted with aes256-ctr
/// under bcrypt-pbkdf, as `ssh-keygen` does.
pub fn encode_private_key(key: &PrivateKey, comment: &str, password: Option<&str>) -> Res<String> {
    let spki = key.public_key_der()?;
    let (key_type, public_blob) = keys::openssh_public_blob(&spki).map_err(|_| format!("the OpenSSH format has no encoding for {} keys (RSA, ECDSA and Ed25519 are supported)", key.algorithm()))?;
    let password = password.filter(|p| !p.is_empty());

    let mut private = Vec::new();
    let check = random_bytes(4);
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    ssh_string(&mut private, key_type.as_bytes());
    match key {
        PrivateKey::Rsa(k) => {
            let primes = k.primes();
            if primes.len() != 2 {
                return Err("multi-prime RSA keys cannot be written as OpenSSH keys".into());
            }
            let iqmp = k.crt_coefficient().ok_or("invalid RSA key")?;
            for value in [k.n(), k.e(), k.d(), &iqmp, &primes[0], &primes[1]] {
                ssh_mpint(&mut private, &value.to_bytes_be());
            }
        }
        PrivateKey::P256(k) => ec_private(&mut private, "nistp256", p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&k.public_key(), false).as_bytes(), &k.to_bytes()),
        PrivateKey::P384(k) => ec_private(&mut private, "nistp384", p384::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&k.public_key(), false).as_bytes(), &k.to_bytes()),
        PrivateKey::P521(k) => ec_private(&mut private, "nistp521", p521::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&k.public_key(), false).as_bytes(), &k.to_bytes()),
        PrivateKey::Ed25519(k) => {
            let public = k.verifying_key();
            ssh_string(&mut private, public.as_bytes());
            ssh_string(&mut private, &[k.to_bytes().as_slice(), public.as_bytes()].concat());
        }
        PrivateKey::Opaque { .. } => unreachable!("openssh_public_blob refused it"),
    }
    ssh_string(&mut private, comment.trim().replace(['\r', '\n'], " ").as_bytes());
    let (cipher, block) = if password.is_some() { ("aes256-ctr", 16) } else { ("none", 8) };
    let mut pad = 1u8;
    while !private.len().is_multiple_of(block) {
        private.push(pad);
        pad += 1;
    }

    let mut kdf_options = Vec::new();
    if let Some(pw) = password {
        let salt = random_bytes(16);
        let mut material = [0u8; 48];
        bcrypt_pbkdf::bcrypt_pbkdf(pw, &salt, WRITE_ROUNDS, &mut material).map_err(|err| format!("could not derive the encryption key: {err}"))?;
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&material[..32], &material[32..]).map_err(|_| "invalid cipher key".to_string())?.apply_keystream(&mut private);
        ssh_string(&mut kdf_options, &salt);
        kdf_options.extend_from_slice(&WRITE_ROUNDS.to_be_bytes());
    }

    let mut out = MAGIC.to_vec();
    ssh_string(&mut out, cipher.as_bytes());
    ssh_string(&mut out, if password.is_some() { b"bcrypt" } else { b"none" });
    ssh_string(&mut out, &kdf_options);
    out.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut out, &public_blob);
    ssh_string(&mut out, &private);
    Ok(to_pem("OPENSSH PRIVATE KEY", &out))
}

fn ec_private(out: &mut Vec<u8>, curve: &str, point: &[u8], scalar: &[u8]) {
    ssh_string(out, curve.as_bytes());
    ssh_string(out, point);
    ssh_mpint(out, scalar);
}

// ---------------------------------------------------------------------------------------------
// RFC 4716 public key files ("SSH2 PUBLIC KEY")
// ---------------------------------------------------------------------------------------------

const SSH2_BEGIN: &str = "---- BEGIN SSH2 PUBLIC KEY ----";
const SSH2_END: &str = "---- END SSH2 PUBLIC KEY ----";

pub fn looks_like_ssh2_public_key(text: &str) -> bool {
    text.contains(SSH2_BEGIN)
}

/// The key blob (SSH wire format) and comment of an RFC 4716 public key file.
pub fn parse_ssh2_public_key(text: &str) -> Res<(Vec<u8>, String)> {
    let start = text.find(SSH2_BEGIN).ok_or("not an SSH2 public key file")? + SSH2_BEGIN.len();
    let end = text[start..].find(SSH2_END).ok_or("invalid SSH2 public key: the END line is missing")? + start;
    let mut comment = String::new();
    let mut base64 = String::new();
    // Only the line ending is trimmed: a continuation line may begin with a space that belongs
    // to the value.
    let mut lines = text[start..end].lines().map(|l| l.trim_end_matches('\r')).filter(|l| !l.trim().is_empty());
    while let Some(line) = lines.next() {
        // A header is "Tag: value"; a value that ends in a backslash continues on the next line.
        let Some((tag, value)) = line.split_once(':').filter(|(tag, _)| !tag.contains(['+', '/', '='])) else {
            base64.push_str(line.trim());
            continue;
        };
        let mut value = value.trim_start().to_string();
        while value.ends_with('\\') {
            value.pop();
            value.push_str(lines.next().unwrap_or_default());
        }
        let value = value.trim_end();
        if tag.eq_ignore_ascii_case("Comment") {
            comment = value.trim_matches('"').to_string();
        }
    }
    let blob = unb64(&base64).map_err(|_| "invalid SSH2 public key: the key data is not base64".to_string())?;
    Ok((blob, comment))
}

/// An RFC 4716 public key file for a key blob in SSH wire format.
pub fn format_ssh2_public_key(blob: &[u8], comment: &str) -> String {
    let mut out = format!("{SSH2_BEGIN}\n");
    let comment = comment.trim().replace(['\r', '\n', '"'], " ");
    if !comment.is_empty() {
        // RFC 4716 limits a line to 72 bytes; a long comment continues after a backslash.
        let header = format!("Comment: \"{comment}\"");
        let chars: Vec<char> = header.chars().collect();
        let chunks: Vec<String> = chars.chunks(70).map(|c| c.iter().collect()).collect();
        out.push_str(&chunks.join("\\\n"));
        out.push('\n');
    }
    let encoded = crate::util::b64(blob);
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(SSH2_END);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_of(pem_text: &str) -> Vec<u8> {
        private_key_blob(pem_text).expect("an OPENSSH PRIVATE KEY block")
    }

    #[test]
    fn every_writable_algorithm_round_trips_with_and_without_a_password() {
        let keys = [
            PrivateKey::generate("RSA", 2048, None).unwrap(),
            PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap(),
            PrivateKey::generate("ECDSA", 0, Some("P-384")).unwrap(),
            PrivateKey::generate("ECDSA", 0, Some("P-521")).unwrap(),
            PrivateKey::generate("Ed25519", 0, None).unwrap(),
        ];
        for key in &keys {
            let pkcs8 = key.to_pkcs8_der().unwrap();
            for password in [None, Some("correct horse")] {
                let text = encode_private_key(key, "me@host", password).unwrap();
                assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
                let blob = blob_of(&text);
                let envelope = Envelope::parse(&blob).unwrap();
                assert_eq!(envelope.is_encrypted(), password.is_some());
                assert_eq!(envelope.rounds(), password.map(|_| WRITE_ROUNDS));
                let back = decode_private_key(&blob, password).unwrap();
                assert_eq!(back.comment, "me@host");
                assert_eq!(back.key.to_pkcs8_der().unwrap(), pkcs8, "{} {password:?}", key.algorithm());
                // The whole-file route through the key module finds it too.
                assert_eq!(PrivateKey::from_bytes(text.as_bytes(), password).unwrap().to_pkcs8_der().unwrap(), pkcs8);
                if password.is_some() {
                    assert_eq!(decode_private_key(&blob, None).err().unwrap(), NEEDS_PASSWORD);
                    assert_eq!(decode_private_key(&blob, Some("wrong")).err().unwrap(), WRONG_PASSWORD);
                }
            }
        }
    }

    #[test]
    fn damaged_and_hostile_files_are_errors_not_panics() {
        let key = PrivateKey::generate("Ed25519", 0, None).unwrap();
        let blob = blob_of(&encode_private_key(&key, "c", None).unwrap());
        for cut in 0..blob.len() {
            assert!(decode_private_key(&blob[..cut], None).is_err(), "a file cut at {cut} bytes was accepted");
        }
        // A length that runs past the end, and a round count that would take hours.
        let mut long = blob.clone();
        long[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_private_key(&long, None).is_err());
        let encrypted = blob_of(&encode_private_key(&key, "c", Some("pw")).unwrap());
        let at = encrypted.windows(4).position(|w| w == WRITE_ROUNDS.to_be_bytes()).unwrap();
        let mut slow = encrypted.clone();
        slow[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let started = std::time::Instant::now();
        assert!(decode_private_key(&slow, Some("pw")).unwrap_err().starts_with("invalid:"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(decode_private_key(b"not a key at all", None).is_err());
    }

    #[test]
    fn an_unknown_cipher_or_key_type_is_named() {
        let mut out = MAGIC.to_vec();
        ssh_string(&mut out, b"twofish-cbc");
        ssh_string(&mut out, b"bcrypt");
        ssh_string(&mut out, &[]);
        out.extend_from_slice(&1u32.to_be_bytes());
        ssh_string(&mut out, &[]);
        ssh_string(&mut out, &[0u8; 16]);
        let err = decode_private_key(&out, Some("pw")).err().unwrap();
        assert!(err.starts_with("unsupported:") && err.contains("twofish-cbc"), "{err}");
    }

    #[test]
    fn ssh2_public_key_files_round_trip() {
        let key = PrivateKey::generate("Ed25519", 0, None).unwrap();
        let (_, blob) = keys::openssh_public_blob(&key.public_key_der().unwrap()).unwrap();
        let long_comment = "a comment that is long enough to need a continuation line in the header, by quite some margin";
        for comment in ["", "256-bit ED25519, converted by me@host", long_comment] {
            let text = format_ssh2_public_key(&blob, comment);
            assert!(looks_like_ssh2_public_key(&text));
            assert!(text.lines().all(|l| l.len() <= 72), "{text}");
            let (back, got) = parse_ssh2_public_key(&text).unwrap();
            assert_eq!(back, blob);
            assert_eq!(got, comment);
        }
        assert!(parse_ssh2_public_key("---- BEGIN SSH2 PUBLIC KEY ----\nAAAA").is_err());
    }
}
