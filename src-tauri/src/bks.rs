//! Bouncy Castle BKS (store versions 1 and 2) and UBER, read and written.
//!
//! Both hold the same entry stream (`BcKeyStoreSpi.saveStore`):
//!
//! ```text
//! header   int version · int saltLength · salt · int iterationCount
//! entry*   byte type · UTF alias · long date · int chainLength · chain* · payload
//! end      byte 0
//! ```
//!
//! - **BKS** leaves the stream in the clear and appends an HMAC-SHA1 over it. The MAC key comes
//!   from the PKCS#12 KDF. Version 1 derives 20 *bits* of key where 20 bytes were meant
//!   (CVE-2018-5382), so it is read here and never written.
//! - **UBER** appends a SHA-1 of the stream instead and encrypts the lot with Twofish-CBC under a
//!   PKCS#12-derived key.
//!
//! A key entry is "sealed": `int saltLength · salt · int iterationCount` and then the key
//! (`byte keyType · UTF format · UTF algorithm · int length · bytes`) under
//! PBEWithSHAAnd3-KeyTripleDES-CBC with the entry's own password.
//!
//! The writer is checked by reproducing real Bouncy Castle files bit for bit: a store read from a
//! file BC wrote, then written again with the salts and iteration counts it had, comes out
//! identical to the last byte, sealed entries included.

use crate::entry;
use crate::keys::PrivateKey;
use crate::model::KeystoreEntry;
use crate::pbe::{self, HashAlg, bc_password, pkcs12_kdf_bytes};
use crate::util::*;
use rand::Rng;
use std::collections::HashMap;
use std::io::{Cursor, Read};

const END: u8 = 0;
const CERTIFICATE: u8 = 1;
const KEY: u8 = 2;
const SECRET: u8 = 3;
const SEALED: u8 = 4;
const KEY_PRIVATE: u8 = 0;
const KEY_PUBLIC: u8 = 1;
const KEY_SECRET: u8 = 2;
/// `STORE_SALT_SIZE` and `KEY_SALT_SIZE` in Bouncy Castle.
const SALT_LEN: usize = 20;
/// Bouncy Castle writes `MIN_ITERATIONS + (random & 0x3ff)`.
const MIN_ITERATIONS: u32 = 1024;
const WRONG_PASSWORD: &str = "wrong-password: keystore password incorrect or file corrupt";

/// Which of the two containers a store is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bks,
    Uber,
}

fn truncated() -> String {
    "invalid: the Bouncy Castle keystore is truncated or corrupt".into()
}

fn read_u8(c: &mut Cursor<&[u8]>) -> Res<u8> {
    let mut b = [0u8; 1];
    c.read_exact(&mut b).map_err(|_| truncated())?;
    Ok(b[0])
}

fn read_u16(c: &mut Cursor<&[u8]>) -> Res<u16> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b).map_err(|_| truncated())?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32(c: &mut Cursor<&[u8]>) -> Res<u32> {
    let mut b = [0u8; 4];
    c.read_exact(&mut b).map_err(|_| truncated())?;
    Ok(u32::from_be_bytes(b))
}

fn read_i64(c: &mut Cursor<&[u8]>) -> Res<i64> {
    let mut b = [0u8; 8];
    c.read_exact(&mut b).map_err(|_| truncated())?;
    Ok(i64::from_be_bytes(b))
}

/// Java `DataInputStream.readUTF`.
fn read_utf(c: &mut Cursor<&[u8]>) -> Res<String> {
    let len = read_u16(c)? as usize;
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).map_err(|_| truncated())?;
    java_utf_decode(&buf).ok_or_else(|| "invalid: a name in the Bouncy Castle keystore is not valid text".to_string())
}

/// An `int length` followed by that many bytes. The length is checked against what is left, so a
/// forged header cannot ask for gigabytes.
fn read_block(c: &mut Cursor<&[u8]>) -> Res<Vec<u8>> {
    let len = read_u32(c)? as usize;
    let left = c.get_ref().len().saturating_sub(c.position() as usize);
    if len > left {
        return Err(truncated());
    }
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).map_err(|_| truncated())?;
    Ok(buf)
}

fn read_cert(c: &mut Cursor<&[u8]>) -> Res<Vec<u8>> {
    let kind = read_utf(c)?;
    let der = read_block(c)?;
    if !kind.eq_ignore_ascii_case("X.509") && !kind.eq_ignore_ascii_case("X509") {
        return Err(format!("unsupported: certificate type '{kind}' in a Bouncy Castle keystore is not X.509"));
    }
    Ok(der)
}

fn write_utf(out: &mut Vec<u8>, text: &str) -> Res<()> {
    let bytes = java_utf_encode(text);
    let len = u16::try_from(bytes.len()).map_err(|_| "invalid: alias too long".to_string())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}

fn write_block(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn write_cert(out: &mut Vec<u8>, der: &[u8]) -> Res<()> {
    write_utf(out, "X.509")?;
    write_block(out, der);
    Ok(())
}

/// The store header shared by BKS and UBER.
struct Header {
    version: u32,
    salt: Vec<u8>,
    iterations: u32,
    /// Offset of the first byte after the header.
    body_at: usize,
}

fn read_header(bytes: &[u8]) -> Res<Header> {
    let mut c = Cursor::new(bytes);
    let version = read_u32(&mut c)?;
    let salt_len = read_u32(&mut c)? as usize;
    if salt_len == 0 || salt_len > 64 {
        return Err("invalid: the Bouncy Castle keystore's salt length is not plausible".into());
    }
    let mut salt = vec![0u8; salt_len];
    c.read_exact(&mut salt).map_err(|_| truncated())?;
    let iterations = read_u32(&mut c)?;
    pbe::check_iterations(iterations as u64)?;
    Ok(Header { version, salt, iterations, body_at: c.position() as usize })
}

fn write_header(version: u32, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + salt.len());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&iterations.to_be_bytes());
    out
}

/// A key as `BcKeyStoreSpi.encodeKey` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyBlob {
    key_type: u8,
    /// `Key.getFormat()`: "PKCS#8", "X.509" or "RAW".
    format: String,
    /// `Key.getAlgorithm()`, the name a Java `KeyFactory` is looked up by.
    algorithm: String,
    encoded: Vec<u8>,
}

impl KeyBlob {
    fn read(c: &mut Cursor<&[u8]>) -> Res<KeyBlob> {
        let key_type = read_u8(c)?;
        let format = read_utf(c)?;
        let algorithm = read_utf(c)?;
        let encoded = read_block(c)?;
        Ok(KeyBlob { key_type, format, algorithm, encoded })
    }

    fn write(&self, out: &mut Vec<u8>) -> Res<()> {
        out.push(self.key_type);
        write_utf(out, &self.format)?;
        write_utf(out, &self.algorithm)?;
        write_block(out, &self.encoded);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Payload {
    Certificate(Vec<u8>),
    /// A key stored without protection.
    Key(KeyBlob),
    /// Bytes stored as they are (`setKeyEntry(alias, byte[], chain)`).
    Secret(Vec<u8>),
    /// A [`KeyBlob`] under the entry's password.
    Sealed(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawEntry {
    alias: String,
    /// `Date.getTime()`: milliseconds since the epoch.
    millis: i64,
    chain: Vec<Vec<u8>>,
    payload: Payload,
}

/// Reads entries up to and including the end marker.
fn read_entries(c: &mut Cursor<&[u8]>) -> Res<Vec<RawEntry>> {
    let mut entries = Vec::new();
    loop {
        let kind = read_u8(c)?;
        if kind == END {
            return Ok(entries);
        }
        let alias = read_utf(c)?;
        let millis = read_i64(c)?;
        let chain_len = read_u32(c)?;
        if chain_len > 64 {
            return Err("invalid: a certificate chain length in the Bouncy Castle keystore is not plausible".into());
        }
        let chain = (0..chain_len).map(|_| read_cert(c)).collect::<Res<Vec<_>>>()?;
        let payload = match kind {
            CERTIFICATE => Payload::Certificate(read_cert(c)?),
            KEY => Payload::Key(KeyBlob::read(c)?),
            SECRET => Payload::Secret(read_block(c)?),
            SEALED => Payload::Sealed(read_block(c)?),
            other => return Err(format!("unsupported: Bouncy Castle keystore entry type {other}")),
        };
        entries.push(RawEntry { alias, millis, chain, payload });
    }
}

/// Writes the entry stream, end marker included.
fn write_entries(entries: &[RawEntry]) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    for e in entries {
        out.push(match e.payload {
            Payload::Certificate(_) => CERTIFICATE,
            Payload::Key(_) => KEY,
            Payload::Secret(_) => SECRET,
            Payload::Sealed(_) => SEALED,
        });
        write_utf(&mut out, &e.alias)?;
        out.extend_from_slice(&e.millis.to_be_bytes());
        out.extend_from_slice(&(e.chain.len() as u32).to_be_bytes());
        for cert in &e.chain {
            write_cert(&mut out, cert)?;
        }
        match &e.payload {
            Payload::Certificate(der) => write_cert(&mut out, der)?,
            Payload::Key(key) => key.write(&mut out)?,
            Payload::Secret(data) | Payload::Sealed(data) => write_block(&mut out, data),
        }
    }
    out.push(END);
    Ok(out)
}

/// The key and IV of PBEWithSHAAnd3-KeyTripleDES-CBC as Bouncy Castle derives them.
fn seal_key_iv(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let pass = bc_password(password);
    (pkcs12_kdf_bytes(HashAlg::Sha1, &pass, salt, iterations as u64, 1, 24), pkcs12_kdf_bytes(HashAlg::Sha1, &pass, salt, iterations as u64, 2, 8))
}

fn seal(key: &KeyBlob, password: &str, salt: &[u8], iterations: u32) -> Res<Vec<u8>> {
    let mut plain = Vec::new();
    key.write(&mut plain)?;
    let (k, iv) = seal_key_iv(password, salt, iterations);
    let mut out = Vec::new();
    write_block(&mut out, salt);
    out.extend_from_slice(&iterations.to_be_bytes());
    out.extend_from_slice(&pbe::des3_cbc_encrypt(&k, &iv, &plain)?);
    Ok(out)
}

/// The salt, iteration count and ciphertext of a sealed entry.
fn sealed_parts(blob: &[u8]) -> Res<(Vec<u8>, u32, &[u8])> {
    let mut c = Cursor::new(blob);
    let salt = read_block(&mut c)?;
    let iterations = read_u32(&mut c)?;
    pbe::check_iterations(iterations as u64)?;
    Ok((salt, iterations, &blob[c.position() as usize..]))
}

/// Opens a sealed entry. Any failure is a wrong password: the padding of a wrong key passes one
/// time in 256, and what comes out then does not parse as a key.
fn unseal(blob: &[u8], password: &str) -> Res<KeyBlob> {
    let (salt, iterations, ciphertext) = sealed_parts(blob)?;
    let (k, iv) = seal_key_iv(password, &salt, iterations);
    let plain = pbe::des3_cbc_decrypt(&k, &iv, ciphertext).map_err(|_| WRONG_PASSWORD.to_string())?;
    let mut c = Cursor::new(plain.as_slice());
    let key = KeyBlob::read(&mut c).map_err(|_| WRONG_PASSWORD.to_string())?;
    if c.position() as usize != plain.len() || key.key_type > KEY_SECRET {
        return Err(WRONG_PASSWORD.into());
    }
    Ok(key)
}

/// Version 2 derives a 20-byte MAC key. Versions 0 and 1 asked the generator for 20 *bits* and
/// got two bytes.
fn mac_key(version: u32, password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    pkcs12_kdf_bytes(HashAlg::Sha1, &bc_password(password), salt, iterations as u64, 3, if version == 2 { 20 } else { 2 })
}

/// What a store holds, in the app's terms.
pub struct Decoded {
    pub entries: Vec<KeystoreEntry>,
    /// Entries that have no counterpart in the app (a public key stored on its own).
    pub notes: Vec<String>,
}

fn key_password<'a>(alias: &str, key_passwords: &'a HashMap<String, String>) -> Option<&'a str> {
    key_passwords.get(alias).or_else(|| key_passwords.iter().find(|(k, _)| k.eq_ignore_ascii_case(alias)).map(|(_, v)| v)).map(String::as_str).filter(|p| !p.is_empty())
}

/// Turns one key into an entry. A public key stored on its own has no place in the app's model
/// (nor in PKCS#12 or JKS), so it is reported in `notes` instead.
fn key_entry(alias: &str, key: &KeyBlob, chain: &[Vec<u8>], created: Option<i64>, notes: &mut Vec<String>) -> Res<Option<KeystoreEntry>> {
    let format = key.format.to_ascii_uppercase().replace('#', "");
    match (key.key_type, format.as_str()) {
        (KEY_PRIVATE, "PKCS8") => entry::key_pair_entry(alias, &key.encoded, chain, created).map(Some),
        (KEY_SECRET, "RAW") => Ok(Some(entry::secret_key_entry(alias, &key.algorithm, &key.encoded, created))),
        (KEY_PUBLIC, _) => {
            notes.push(format!("'{alias}' is a {} public key stored on its own. Keystore Studio lists key pairs, certificates and secret keys, so it is not shown.", key.algorithm));
            Ok(None)
        }
        _ => Err(format!("unsupported: the key '{alias}' is stored in the format '{}' ({}), which is not PKCS#8 or RAW", key.format, key.algorithm)),
    }
}

fn to_model(raw: Vec<RawEntry>, password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    for e in raw {
        let created = Some(e.millis.div_euclid(1000));
        match &e.payload {
            Payload::Certificate(der) => entries.push(entry::trusted_cert_entry(&e.alias, der, created)?),
            Payload::Key(key) => entries.extend(key_entry(&e.alias, key, &e.chain, created, &mut notes)?),
            Payload::Secret(data) => entries.push(entry::secret_key_entry(&e.alias, "Secret", data, created)),
            Payload::Sealed(blob) => {
                // The entry's own password first, then the store's, as keytool users expect.
                let own = key_password(&e.alias, key_passwords);
                let opened = own.and_then(|pw| unseal(blob, pw).ok().map(|key| (pw, key))).or_else(|| unseal(blob, password).ok().map(|key| (password, key)));
                match opened {
                    Some((used, key)) => {
                        if let Some(mut entry) = key_entry(&e.alias, &key, &e.chain, created, &mut notes)? {
                            if used != password {
                                entry.key_password = Some(used.to_string());
                            }
                            entries.push(entry);
                        }
                    }
                    // Still sealed: keep the blob so the entry survives a save and can be unlocked later.
                    None if e.chain.is_empty() => entries.push(entry::locked_secret_entry(&e.alias, blob, created)),
                    None => entries.push(entry::locked_key_pair_entry(&e.alias, blob, &e.chain, created)?),
                }
            }
        }
    }
    Ok(Decoded { entries, notes })
}

/// Reads the header and entries of a BKS file and checks its MAC.
fn read_bks(bytes: &[u8], password: &str) -> Res<(Header, Vec<RawEntry>)> {
    let header = read_header(bytes)?;
    if header.version > 2 {
        return Err(format!("unsupported: BKS store version {} is not supported (versions 1 and 2 are)", header.version));
    }
    let body = &bytes[header.body_at..];
    let mut c = Cursor::new(body);
    let entries = read_entries(&mut c)?;
    let end = c.position() as usize;
    // The MAC follows the end marker. Anything after it is ignored, as Bouncy Castle ignores it.
    let mac = body.get(end..end + 20).ok_or_else(truncated)?;
    if HashAlg::Sha1.hmac(&mac_key(header.version, password, &header.salt, header.iterations), &body[..end]) != mac {
        return Err(WRONG_PASSWORD.into());
    }
    Ok((header, entries))
}

/// Opens a BKS file (store version 1 or 2). `key_passwords` unlocks entries sealed with a
/// password other than the store's; those that stay sealed load as locked entries.
pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let (_, raw) = read_bks(bytes, password)?;
    to_model(raw, password, key_passwords)
}

/// The store version of a BKS file, for display.
pub fn version(bytes: &[u8]) -> Option<u32> {
    read_header(bytes).ok().map(|h| h.version)
}

fn uber_key_iv(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let pass = bc_password(password);
    (pkcs12_kdf_bytes(HashAlg::Sha1, &pass, salt, iterations as u64, 1, 32), pkcs12_kdf_bytes(HashAlg::Sha1, &pass, salt, iterations as u64, 2, 16))
}

/// Decrypts an UBER file and checks the digest of what was inside.
fn read_uber(bytes: &[u8], password: &str) -> Res<(Header, Vec<RawEntry>)> {
    let header = read_header(bytes)?;
    if header.version != 1 {
        // Version 0 used a key derivation that Bouncy Castle itself calls broken and kept only for reading.
        return Err(format!("unsupported: UBER store version {} is not supported (version 1 is)", header.version));
    }
    let ciphertext = &bytes[header.body_at..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(truncated());
    }
    let (key, iv) = uber_key_iv(password, &header.salt, header.iterations);
    let plain = pbe::twofish_cbc_decrypt(&key, &iv, ciphertext).map_err(|_| WRONG_PASSWORD.to_string())?;
    if plain.len() < 21 {
        return Err(WRONG_PASSWORD.into());
    }
    // Nothing inside is trusted until the digest matches, so that comes before any parsing.
    let (stream, digest) = plain.split_at(plain.len() - 20);
    if sha1(stream) != digest {
        return Err(WRONG_PASSWORD.into());
    }
    let mut c = Cursor::new(stream);
    let entries = read_entries(&mut c)?;
    if c.position() as usize != stream.len() {
        return Err(truncated());
    }
    Ok((header, entries))
}

/// Opens an UBER file.
pub fn decode_uber(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let (_, raw) = read_uber(bytes, password)?;
    to_model(raw, password, key_passwords)
}

fn write_bks(version: u32, salt: &[u8], iterations: u32, entries: &[RawEntry], password: &str) -> Res<Vec<u8>> {
    let stream = write_entries(entries)?;
    let mut out = write_header(version, salt, iterations);
    out.extend_from_slice(&stream);
    out.extend_from_slice(&HashAlg::Sha1.hmac(&mac_key(version, password, salt, iterations), &stream));
    Ok(out)
}

fn write_uber(salt: &[u8], iterations: u32, entries: &[RawEntry], password: &str) -> Res<Vec<u8>> {
    let mut plain = write_entries(entries)?;
    let digest = sha1(&plain);
    plain.extend_from_slice(&digest);
    let (key, iv) = uber_key_iv(password, salt, iterations);
    let mut out = write_header(1, salt, iterations);
    out.extend_from_slice(&pbe::twofish_cbc_encrypt(&key, &iv, &plain)?);
    Ok(out)
}

fn random_iterations() -> u32 {
    MIN_ITERATIONS + rand::thread_rng().gen_range(0..MIN_ITERATIONS)
}

/// The `Key.getAlgorithm()` name a Java `KeyFactory` knows this private key by.
fn java_key_algorithm(pkcs8: &[u8]) -> Res<String> {
    let key = PrivateKey::from_pkcs8_der(pkcs8)?;
    let name = key.algorithm();
    Ok(match name.as_str() {
        "ECDSA" => "EC".into(),
        n if n.starts_with("EC (") => "EC".into(),
        // "ML-DSA-65" and the like: the family name is the algorithm, the suffix the parameter set.
        n if n.starts_with("ML-DSA") => "ML-DSA".into(),
        n if n.starts_with("ML-KEM") => "ML-KEM".into(),
        _ => name,
    })
}

fn entry_millis(e: &KeystoreEntry) -> i64 {
    crate::util::parse_ymd(&e.creation_date).map(|d| d.ts() * 1000).unwrap_or_else(crate::util::now_millis)
}

fn from_model(entries: &[KeystoreEntry], password: &str) -> Res<Vec<RawEntry>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for e in entries {
        if !seen.insert(e.alias.clone()) {
            return Err(format!("invalid: duplicate alias '{}'", e.alias));
        }
        let sealed = |key: KeyBlob| -> Res<Payload> {
            let pw = e.key_password.as_deref().filter(|p| !p.is_empty()).unwrap_or(password);
            Ok(Payload::Sealed(seal(&key, pw, &random_bytes(SALT_LEN), random_iterations())?))
        };
        let still_sealed = || -> Res<Payload> {
            let blob = unb64(e.protected_key.as_deref().ok_or_else(|| format!("invalid: '{}' has no key material", e.alias))?)?;
            // Only a blob that is itself a Bouncy Castle sealed entry can be written back as one.
            sealed_parts(&blob).map_err(|_| format!("invalid: '{}' is locked by a key password of another keystore format; unlock it first", e.alias))?;
            Ok(Payload::Sealed(blob))
        };
        let (chain, payload) = match e.entry_type.as_str() {
            "TrustedCertificate" => {
                let cert = entry::chain_der(e)?.into_iter().next().ok_or_else(|| format!("invalid: '{}' has no certificate", e.alias))?;
                (Vec::new(), Payload::Certificate(cert))
            }
            "KeyPair" => {
                let chain = entry::chain_der(e)?;
                if chain.is_empty() {
                    return Err(format!("invalid: key pair '{}' has no certificate chain", e.alias));
                }
                let payload = if e.locked {
                    still_sealed()?
                } else {
                    let mut pkcs8 = entry::private_key_der(e)?;
                    let algorithm = java_key_algorithm(&pkcs8)?;
                    sealed(KeyBlob { key_type: KEY_PRIVATE, format: "PKCS#8".into(), algorithm, encoded: std::mem::take(&mut *pkcs8) })?
                };
                (chain, payload)
            }
            "SecretKey" => {
                let payload = if e.locked {
                    still_sealed()?
                } else {
                    sealed(KeyBlob { key_type: KEY_SECRET, format: "RAW".into(), algorithm: e.algorithm.clone(), encoded: std::mem::take(&mut *entry::secret_bytes(e)?) })?
                };
                (Vec::new(), payload)
            }
            other => return Err(format!("unsupported: entry type '{other}'")),
        };
        out.push(RawEntry { alias: e.alias.clone(), millis: entry_millis(e), chain, payload });
    }
    Ok(out)
}

/// Writes a BKS (store version 2) or UBER file. Every key is sealed with its own key password
/// when it has one, the store password otherwise, which is what `keytool` does.
pub fn encode(entries: &[KeystoreEntry], password: &str, kind: Kind) -> Res<Vec<u8>> {
    let raw = from_model(entries, password)?;
    let salt = random_bytes(SALT_LEN);
    match kind {
        Kind::Bks => write_bks(2, &salt, random_iterations(), &raw, password),
        Kind::Uber => write_uber(&salt, random_iterations(), &raw, password),
    }
}

/// Recognises the cleartext entry stream of a BKS file: an entry that starts plausibly, or the
/// end marker followed by exactly a MAC.
pub fn looks_like_entry_stream(body: &[u8]) -> bool {
    if body.len() == 21 && body[0] == END {
        return true;
    }
    if body.len() < 1 + 2 + 8 + 4 + 20 || !matches!(body[0], CERTIFICATE..=SEALED) {
        return false;
    }
    let alias_len = u16::from_be_bytes([body[1], body[2]]) as usize;
    if alias_len > 1024 || 3 + alias_len + 12 + 20 > body.len() {
        return false;
    }
    if java_utf_decode(&body[3..3 + alias_len]).is_none() {
        return false;
    }
    let chain_pos = 3 + alias_len + 8;
    u32::from_be_bytes(body[chain_pos..chain_pos + 4].try_into().unwrap()) <= 64
}

/// A cheap look at the header: `(version, offset of the body)` when it reads like BKS or UBER.
/// Bouncy Castle's salt is 20 bytes and its iteration count 1024 to 2047; a little slack on both
/// keeps files from other writers in while leaving random data out.
pub fn sniff_header(bytes: &[u8]) -> Option<(u32, usize)> {
    if bytes.len() < 32 {
        return None;
    }
    let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let salt_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if version > 2 || !matches!(salt_len, 16 | 20 | 32) || bytes.len() < 12 + salt_len {
        return None;
    }
    let iterations = u32::from_be_bytes(bytes[8 + salt_len..12 + salt_len].try_into().unwrap());
    (1024..=1_000_000).contains(&iterations).then_some((version, 12 + salt_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
    }

    fn none() -> HashMap<String, String> {
        HashMap::new()
    }

    fn find<'a>(entries: &'a [KeystoreEntry], alias: &str) -> &'a KeystoreEntry {
        entries.iter().find(|e| e.alias == alias).unwrap_or_else(|| panic!("no entry '{alias}' in {:?}", entries.iter().map(|e| &e.alias).collect::<Vec<_>>()))
    }

    #[test]
    fn sample_bks_from_keytool_opens() {
        let bytes = fixture("sample.bks");
        let entries = decode(&bytes, "changeit", &none()).unwrap().entries;
        let names: Vec<_> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert!(names.contains(&"server"), "{names:?}");
        assert!(names.contains(&"trusted"), "{names:?}");
        assert!(names.contains(&"aes"), "{names:?}");
        let server = find(&entries, "server");
        assert_eq!(server.entry_type, "KeyPair");
        assert!(server.private_key_pem.is_some());
        let aes = find(&entries, "aes");
        assert_eq!(aes.entry_type, "SecretKey");
        assert_eq!(aes.key_size, 256, "{:?}", aes.algorithm);
        assert!(decode(&bytes, "nope", &none()).err().unwrap().starts_with("wrong-password"));
    }

    /// The pyjks "christmas" stores hold one entry of every kind, written by Bouncy Castle as
    /// BKS version 1, BKS version 2 and UBER. All three have to read the same.
    #[test]
    fn every_entry_kind_reads_from_bks_v1_v2_and_uber() {
        for (file, uber) in [("pyjks/christmas.bksv1", false), ("pyjks/christmas.bksv2", false), ("pyjks/christmas.uber", true)] {
            let bytes = fixture(file);
            let open = |pw: &str| if uber { decode_uber(&bytes, pw, &none()) } else { decode(&bytes, pw, &none()) };
            let Decoded { entries, notes } = open("12345678").unwrap_or_else(|err| panic!("{file}: {err}"));
            assert_eq!(entries.len(), 5, "{file}");

            let private = find(&entries, "sealed_private_key");
            assert_eq!((private.entry_type.as_str(), private.algorithm.as_str()), ("KeyPair", "RSA"), "{file}");
            assert!(private.private_key_pem.is_some() && private.chain_length >= 1, "{file}");
            // The key belongs to its certificate: key_pair_entry refuses a pair that does not match.

            let sealed_secret = find(&entries, "sealed_secret_key");
            assert_eq!((sealed_secret.algorithm.as_str(), sealed_secret.secret_key_hex.as_deref()), ("AES", Some("3F680504C66CC25AAE65D0FA49C526EC")), "{file}");
            let plain = find(&entries, "plain_key");
            assert_eq!((plain.algorithm.as_str(), plain.secret_key_hex.as_deref()), ("DES", Some("4CF2FE915D082A43")), "{file}");
            let stored = find(&entries, "stored_value");
            assert_eq!(stored.secret_key_hex.as_deref(), Some("020305070B0D111317"), "{file}");
            assert_eq!(find(&entries, "cert").entry_type, "TrustedCertificate", "{file}");

            // A public key on its own cannot be shown; it is reported rather than dropped in silence.
            assert_eq!(notes.len(), 1, "{file}: {notes:?}");
            assert!(notes[0].contains("sealed_public_key") && notes[0].contains("RSA"), "{file}: {notes:?}");
            assert!(open("wrong-password").err().unwrap().starts_with("wrong-password"), "{file}");
        }
    }

    #[test]
    fn entries_with_their_own_passwords_load_locked_and_unlock() {
        for (file, uber) in [("pyjks/custom_entry_passwords.bksv1", false), ("pyjks/custom_entry_passwords.bksv2", false), ("pyjks/custom_entry_passwords.uber", true)] {
            let bytes = fixture(file);
            let open = |keys: &HashMap<String, String>| if uber { decode_uber(&bytes, "store_password", keys) } else { decode(&bytes, "store_password", keys) };
            let locked = open(&none()).unwrap().entries;
            assert_eq!(locked.len(), 3, "{file}");
            assert!(locked.iter().all(|e| e.locked && e.protected_key.is_some()), "{file}");

            let mut passwords = HashMap::new();
            // Aliases are matched without regard to case, as they are typed by hand.
            passwords.insert("SEALED_PRIVATE_KEY".to_string(), "private_password".to_string());
            passwords.insert("sealed_secret_key".to_string(), "secret_password".to_string());
            passwords.insert("sealed_public_key".to_string(), "public_password".to_string());
            let Decoded { entries, notes } = open(&passwords).unwrap();
            let private = find(&entries, "sealed_private_key");
            assert!(!private.locked && private.private_key_pem.is_some(), "{file}");
            assert_eq!(private.key_password.as_deref(), Some("private_password"), "{file}");
            let secret = find(&entries, "sealed_secret_key");
            assert!(!secret.locked && secret.key_password.as_deref() == Some("secret_password"), "{file}");
            assert_eq!(notes.len(), 1, "{file}");

            // A wrong key password leaves that entry locked and the rest as they were.
            passwords.insert("sealed_secret_key".to_string(), "nope".to_string());
            assert!(find(&open(&passwords).unwrap().entries, "sealed_secret_key").locked, "{file}");
        }
    }

    #[test]
    fn empty_stores_and_trailing_bytes() {
        assert!(decode(&fixture("pyjks/empty.bksv1"), "", &none()).unwrap().entries.is_empty());
        assert!(decode(&fixture("pyjks/empty.bksv2"), "", &none()).unwrap().entries.is_empty());
        assert!(decode_uber(&fixture("pyjks/empty.uber"), "", &none()).unwrap().entries.is_empty());
        // Portecle and Bouncy Castle read a BKS file with bytes after its MAC, so this does too.
        for file in ["pyjks/christmas.bksv1", "pyjks/christmas.bksv2"] {
            let mut bytes = fixture(file);
            bytes.extend_from_slice(&[0u8; 1000]);
            assert_eq!(decode(&bytes, "12345678", &none()).unwrap().entries.len(), 5, "{file}");
        }
        // An UBER file is ciphertext to its last byte, so extra bytes there are damage.
        let mut uber = fixture("pyjks/christmas.uber");
        uber.extend_from_slice(&[0u8; 255]);
        assert!(decode_uber(&uber, "12345678", &none()).is_err());
        uber.push(0);
        assert!(decode_uber(&uber, "12345678", &none()).is_err());
    }

    /// The proof that the writer is compatible: every Bouncy Castle file in the fixtures, read and
    /// written again with the salts and iteration counts it had, is reproduced bit for bit.
    #[test]
    fn real_bouncy_castle_files_are_reproduced_bit_for_bit() {
        for (file, password) in [
            ("sample.bks", "changeit"),
            ("pyjks/christmas.bksv2", "12345678"),
            ("pyjks/christmas.bksv1", "12345678"),
            ("pyjks/custom_entry_passwords.bksv2", "store_password"),
            ("pyjks/empty.bksv2", ""),
        ] {
            let original = fixture(file);
            let (header, entries) = read_bks(&original, password).unwrap();
            let rewritten = write_bks(header.version, &header.salt, header.iterations, &entries, password).unwrap();
            assert_eq!(rewritten, original, "{file}");
        }
        for (file, password) in [("sample.uber", "changeit"), ("pyjks/christmas.uber", "12345678"), ("pyjks/custom_entry_passwords.uber", "store_password"), ("pyjks/empty.uber", "")] {
            let original = fixture(file);
            let (header, entries) = read_uber(&original, password).unwrap();
            assert_eq!(write_uber(&header.salt, header.iterations, &entries, password).unwrap(), original, "{file}");
        }
    }

    /// The same for sealed entries: opened and sealed again with the salt and count they had, the
    /// bytes are the ones Bouncy Castle wrote.
    #[test]
    fn sealed_entries_are_reproduced_bit_for_bit() {
        let mut checked = 0;
        let passwords =
            [("sample.bks", vec!["changeit"]), ("pyjks/christmas.bksv2", vec!["12345678"]), ("pyjks/custom_entry_passwords.bksv2", vec!["private_password", "secret_password", "public_password"])];
        for (file, candidates) in passwords {
            let store_password = if file.contains("custom") { "store_password" } else { candidates[0] };
            let (_, entries) = read_bks(&fixture(file), store_password).unwrap();
            for e in &entries {
                let Payload::Sealed(blob) = &e.payload else { continue };
                let (salt, iterations, _) = sealed_parts(blob).unwrap();
                let (password, key) = candidates.iter().find_map(|pw| unseal(blob, pw).ok().map(|key| (pw, key))).unwrap_or_else(|| panic!("{file}: '{}' did not open", e.alias));
                assert_eq!(&seal(&key, password, &salt, iterations).unwrap(), blob, "{file}: '{}'", e.alias);
                // What Bouncy Castle itself writes for the format and algorithm names.
                match key.key_type {
                    KEY_PRIVATE => assert_eq!(key.format, "PKCS#8", "{file}: '{}'", e.alias),
                    KEY_SECRET => assert_eq!(key.format, "RAW", "{file}: '{}'", e.alias),
                    _ => assert_eq!(key.format, "X.509", "{file}: '{}'", e.alias),
                }
                checked += 1;
            }
        }
        assert!(checked >= 8, "only {checked} sealed entries were checked");
    }

    #[test]
    fn written_stores_read_back_with_every_entry_kind() {
        let ca = crate::ops::generate_key_pair(&crate::ops::tests_support::input("ca", "ECDSA", true), None).unwrap();
        let mut rsa = crate::ops::generate_key_pair(&crate::ops::tests_support::input("web", "RSA", false), Some(&ca)).unwrap();
        rsa.key_password = Some("key-pass-1".into());
        let ed = crate::ops::generate_key_pair(&crate::ops::tests_support::input("signer", "Ed25519", false), None).unwrap();
        let trusted = entry::trusted_cert_entry("anchor", &entry::chain_der(&ca).unwrap()[0], None).unwrap();
        let secret = entry::secret_key_entry("aes", "AES", &[9u8; 32], None);
        let all = vec![ca.clone(), rsa.clone(), ed.clone(), trusted, secret.clone()];
        for kind in [Kind::Bks, Kind::Uber] {
            let bytes = encode(&all, "store-pass-1", kind).unwrap();
            let open = |pw: &str, keys: &HashMap<String, String>| if kind == Kind::Uber { decode_uber(&bytes, pw, keys) } else { decode(&bytes, pw, keys) };
            assert!(open("wrong", &none()).err().unwrap().starts_with("wrong-password"), "{kind:?}");

            let entries = open("store-pass-1", &none()).unwrap().entries;
            assert_eq!(entries.len(), 5, "{kind:?}");
            assert_eq!(find(&entries, "ca").private_key_pem, ca.private_key_pem, "{kind:?}");
            assert_eq!(find(&entries, "signer").private_key_pem, ed.private_key_pem, "{kind:?}");
            assert_eq!(find(&entries, "aes").secret_key_hex, secret.secret_key_hex, "{kind:?}");
            assert_eq!(find(&entries, "anchor").entry_type, "TrustedCertificate", "{kind:?}");
            // The key with its own password is sealed with it, not with the store's.
            let web = find(&entries, "web");
            assert!(web.locked && web.chain_length == 2, "{kind:?}");
            let mut keys = HashMap::new();
            keys.insert("web".to_string(), "key-pass-1".to_string());
            let unlocked = open("store-pass-1", &keys).unwrap().entries;
            let web = find(&unlocked, "web");
            assert_eq!(web.private_key_pem, rsa.private_key_pem, "{kind:?}");
            assert_eq!(web.key_password.as_deref(), Some("key-pass-1"), "{kind:?}");

            // A key that stays locked is written back as the sealed blob it was read as.
            let again = encode(&entries, "store-pass-1", kind).unwrap();
            let reopened = if kind == Kind::Uber { decode_uber(&again, "store-pass-1", &keys) } else { decode(&again, "store-pass-1", &keys) }.unwrap().entries;
            assert_eq!(find(&reopened, "web").private_key_pem, rsa.private_key_pem, "{kind:?}");
        }
        assert!(encode(&[ca.clone(), ca], "pw", Kind::Bks).is_err(), "duplicate aliases must be refused");
    }

    #[test]
    fn written_keys_carry_the_names_a_java_key_factory_knows() {
        let cases = [("RSA", "RSA"), ("ECDSA", "EC"), ("Ed25519", "Ed25519")];
        for (algorithm, expected) in cases {
            let e = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", algorithm, false), None).unwrap();
            assert_eq!(java_key_algorithm(&entry::private_key_der(&e).unwrap()).unwrap(), expected);
        }
        // The fixture's own EC key, as keytool and Bouncy Castle named it.
        let (_, entries) = read_bks(&fixture("sample.bks"), "changeit").unwrap();
        let server = entries.iter().find(|e| e.alias == "server").unwrap();
        let Payload::Sealed(blob) = &server.payload else { panic!("the key entry is sealed") };
        let key = unseal(blob, "changeit").unwrap();
        assert_eq!(java_key_algorithm(&key.encoded).unwrap(), key.algorithm);
    }

    #[test]
    fn hostile_headers_are_errors() {
        let good = fixture("pyjks/christmas.bksv2");
        // Every prefix, an absurd iteration count and an absurd block length.
        for cut in [0, 3, 4, 8, 20, 31, 32, 40, good.len() - 21, good.len() - 1] {
            assert!(decode(&good[..cut], "12345678", &none()).is_err(), "cut at {cut}");
        }
        let mut slow = good.clone();
        slow[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
        let started = std::time::Instant::now();
        assert!(decode(&slow, "12345678", &none()).is_err());
        assert!(decode_uber(&slow, "12345678", &none()).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let mut huge = good.clone();
        huge[35..39].copy_from_slice(&[0x7F, 0xFF, 0xFF, 0xFF]);
        assert!(decode(&huge, "12345678", &none()).is_err());
        assert!(sniff_header(&good).is_some() && sniff_header(&[0u8; 64]).is_none() && sniff_header(b"hello world, this is not a keystore").is_none());
    }
}
