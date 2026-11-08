//! Standalone format conversions: certificates, private keys, public keys, raw PEM/DER, and
//! keystore entries to a PEM bundle.
//!
//! Each function takes the bytes the user supplied (a file or pasted text), recognises what they
//! hold and re-encodes them in the requested form. None of them needs an open keystore and none
//! touches the disk; [`deliver`] does the writing, so the same conversion can be previewed or saved.

use crate::keys::{self, PrivateKey};
use crate::model::KeystoreEntry;
use crate::util::{Res, e, looks_textual, pem_blocks, sha256, to_pem, unb64, write_atomic};
use crate::{cms, entry, pbe, x509};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A converted object, before it is written anywhere.
#[derive(Debug, Clone)]
pub struct Output {
    pub bytes: Vec<u8>,
    /// Printable output (PEM, OpenSSH, JSON) as opposed to binary DER.
    pub text: bool,
    /// Holds private key material, so its text is never sent back to the page.
    pub sensitive: bool,
    /// Human-readable name of the output format.
    pub format: String,
    /// Suggested file extension, without the dot.
    pub extension: &'static str,
    /// Objects written: certificates, keys or PEM blocks.
    pub count: usize,
    /// Things the user should know, e.g. what was dropped.
    pub notes: Vec<String>,
}

/// What the UI gets back from a conversion.
#[derive(Debug, Clone, Serialize)]
pub struct ConvertResult {
    /// Where the output was written; absent for a preview.
    pub path: Option<String>,
    pub format: String,
    pub extension: String,
    pub byte_length: usize,
    pub count: usize,
    /// The output itself, for text that holds no private key material.
    pub text: Option<String>,
    pub sensitive: bool,
    pub notes: Vec<String>,
    pub sha256: String,
}

/// Writes `out` to `path` when one is given and describes the result. Without a path the call is
/// a preview: nothing is written, and only non-sensitive text comes back.
pub fn deliver(out: Output, path: Option<&str>) -> Res<ConvertResult> {
    let path = path.map(str::trim).filter(|p| !p.is_empty());
    if let Some(p) = path {
        write_atomic(Path::new(p), &out.bytes)?;
    }
    let text = (out.text && !out.sensitive).then(|| String::from_utf8_lossy(&out.bytes).into_owned());
    Ok(ConvertResult {
        path: path.map(String::from),
        format: out.format,
        extension: out.extension.into(),
        byte_length: out.bytes.len(),
        count: out.count,
        text,
        sensitive: out.sensitive,
        notes: out.notes,
        sha256: hex::encode(sha256(&out.bytes)),
    })
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn subject_cn(der: &[u8]) -> String {
    x509::parse_certificate(der).map(|c| x509::cn_of(&c.subject)).unwrap_or_else(|_| "the leaf".into())
}

// ------------------------------------------------------------------------------------------------
// Certificates
// ------------------------------------------------------------------------------------------------

/// Target identifiers accepted by [`certificates`].
pub const CERT_TARGETS: &[&str] = &["pem", "der", "pkcs7_pem", "pkcs7_der", "pkipath"];

/// Reads certificates from PEM (one or many), DER, PKCS#7 (PEM or DER) or a PkiPath.
pub fn read_certificates(data: &[u8]) -> Res<Vec<Vec<u8>>> {
    match x509::certificates_from_bytes(data) {
        Ok(certs) if !certs.is_empty() => Ok(certs),
        other => {
            if !looks_textual(data)
                && let Some(path) = pkipath(data)
            {
                return Ok(path);
            }
            Err(other.err().unwrap_or_else(|| "no certificate found in the data".into()))
        }
    }
}

/// A PkiPath is a DER SEQUENCE OF Certificate ordered from the trust anchor down.
fn pkipath(der: &[u8]) -> Option<Vec<Vec<u8>>> {
    let certs = yasna::parse_der(der, |r| r.collect_sequence_of(|r| r.read_der())).ok()?;
    if certs.is_empty() || !certs.iter().all(|c| x509::cert_summary(c).is_ok()) {
        return None;
    }
    // Everything else in xkeystore is leaf first.
    Some(certs.into_iter().rev().collect())
}

fn pkipath_der(leaf_first: &[Vec<u8>]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for c in leaf_first.iter().rev() {
                w.next().write_der(c);
            }
        })
    })
}

/// Re-encodes the certificates in `data`. `order` sorts a bundle leaf → root first.
pub fn certificates(data: &[u8], target: &str, order: bool) -> Res<Output> {
    let mut certs = read_certificates(data)?;
    if order {
        certs = x509::order_bundle(&certs);
    }
    let n = certs.len();
    let mut notes = Vec::new();
    let (bytes, text, format, extension, count) = match target {
        "pem" => (certs.iter().map(|c| to_pem("CERTIFICATE", c)).collect::<String>().into_bytes(), true, "X.509 certificate (PEM)", "pem", n),
        "der" => {
            if n > 1 {
                notes.push(format!(
                    "A DER file holds one certificate, so only the first ({}) was written. Choose PEM or PKCS#7 to keep all {n}.",
                    subject_cn(&certs[0])
                ));
            }
            (certs[0].clone(), false, "X.509 certificate (DER)", "cer", 1)
        }
        "pkcs7_pem" => (to_pem("PKCS7", &cms::certs_only(&certs)).into_bytes(), true, "PKCS#7 certificate bundle (PEM)", "p7b", n),
        "pkcs7_der" => (cms::certs_only(&certs), false, "PKCS#7 certificate bundle (DER)", "p7b", n),
        "pkipath" => (pkipath_der(&certs), false, "PkiPath (DER)", "pkipath", n),
        other => return Err(format!("unknown certificate format '{other}'")),
    };
    Ok(Output { bytes, text, sensitive: false, format: format.into(), extension, count, notes })
}

// ------------------------------------------------------------------------------------------------
// Private keys
// ------------------------------------------------------------------------------------------------

/// Target identifiers accepted by [`private_key`].
pub const KEY_TARGETS: &[&str] = &["pkcs8_pem", "pkcs8_der", "pkcs8_encrypted_pem", "pkcs8_encrypted_der", "traditional_pem", "traditional_der", "jwk"];

/// Re-encodes a private key. `password` decrypts the input; `out_password` encrypts the output
/// for the encrypted targets.
pub fn private_key(data: &[u8], password: Option<&str>, target: &str, out_password: Option<&str>) -> Res<Output> {
    let key = PrivateKey::from_bytes(data, password)?;
    let pkcs8 = key.to_pkcs8_der()?;
    let encrypt = || -> Res<Vec<u8>> {
        let pw = out_password.filter(|p| !p.is_empty()).ok_or("enter a password to encrypt the converted key")?;
        pbe::encrypt_pkcs8(pw, &pkcs8, pbe::DEFAULT_ITERATIONS)
    };
    let traditional = || -> Res<(String, Vec<u8>)> {
        let text = key.to_traditional_pem()?;
        let der = pem::parse(text.as_bytes()).map_err(e)?.contents().to_vec();
        Ok((text, der))
    };
    let (bytes, text, format, extension, encrypted) = match target {
        "pkcs8_pem" => (to_pem("PRIVATE KEY", &pkcs8).into_bytes(), true, "PKCS#8 private key (PEM)", "key", false),
        "pkcs8_der" => (pkcs8.clone(), false, "PKCS#8 private key (DER)", "der", false),
        "pkcs8_encrypted_pem" => (to_pem("ENCRYPTED PRIVATE KEY", &encrypt()?).into_bytes(), true, "Encrypted PKCS#8 private key (PEM, AES-256)", "key", true),
        "pkcs8_encrypted_der" => (encrypt()?, false, "Encrypted PKCS#8 private key (DER, AES-256)", "der", true),
        "traditional_pem" => (traditional()?.0.into_bytes(), true, "PKCS#1 / SEC1 private key (PEM)", "key", false),
        "traditional_der" => (traditional()?.1, false, "PKCS#1 / SEC1 private key (DER)", "der", false),
        "jwk" => (serde_json::to_string_pretty(&key.private_jwk()?).map_err(e)?.into_bytes(), true, "JSON Web Key (private)", "jwk.json", false),
        other => return Err(format!("unknown private key format '{other}'")),
    };
    let mut notes = vec![format!("{} {}-bit key.", key.algorithm(), key.key_size())];
    if !encrypted {
        notes.push("The converted key is not encrypted. Anyone who can read the file can use the key.".into());
    }
    Ok(Output { bytes, text, sensitive: true, format: format.into(), extension, count: 1, notes })
}

// ------------------------------------------------------------------------------------------------
// Public keys
// ------------------------------------------------------------------------------------------------

/// Target identifiers accepted by [`public_key`].
pub const PUBLIC_TARGETS: &[&str] = &["pem", "der", "pkcs1_pem", "openssh", "jwk"];

/// Extracts the public key from `data` and encodes it. `comment` ends an OpenSSH line.
pub fn public_key(data: &[u8], password: Option<&str>, target: &str, comment: &str) -> Res<Output> {
    let (spki, source) = spki_from_any(data, password)?;
    let info = keys::public_key_info(&spki)?;
    let (bytes, text, format, extension) = match target {
        "pem" => (to_pem("PUBLIC KEY", &spki).into_bytes(), true, "Public key (SubjectPublicKeyInfo PEM)", "pub.pem"),
        "der" => (spki.clone(), false, "Public key (SubjectPublicKeyInfo DER)", "pub.der"),
        "pkcs1_pem" => {
            if info.algorithm != "RSA" {
                return Err(format!("PKCS#1 is an RSA format; this is a {} key. Choose PEM instead.", info.algorithm));
            }
            let key = RsaPublicKey::from_public_key_der(&spki).map_err(e)?;
            (to_pem("RSA PUBLIC KEY", key.to_pkcs1_der().map_err(e)?.as_bytes()).into_bytes(), true, "RSA public key (PKCS#1 PEM)", "pub.pem")
        }
        "openssh" => {
            let (line, _) = keys::openssh_public_key(&spki, comment)?;
            (format!("{line}\n").into_bytes(), true, "OpenSSH public key", "pub")
        }
        "jwk" => (serde_json::to_string_pretty(&keys::public_jwk_from_spki(&spki)?).map_err(e)?.into_bytes(), true, "JSON Web Key (public)", "jwk.json"),
        other => return Err(format!("unknown public key format '{other}'")),
    };
    let size = if info.key_size > 0 { format!(" {}-bit", info.key_size) } else { String::new() };
    let notes = vec![format!("{}{size} public key, read from {source}.", info.algorithm)];
    Ok(Output { bytes, text, sensitive: false, format: format.into(), extension, count: 1, notes })
}

/// Finds a public key in anything that carries one: a certificate, a CSR, a private key, a public
/// key (SPKI, PKCS#1, OpenSSH or JWK) or a PKCS#7 bundle (its first certificate).
pub fn spki_from_any(data: &[u8], password: Option<&str>) -> Res<(Vec<u8>, &'static str)> {
    if !looks_textual(data) {
        return spki_from_der(data, password);
    }
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();
    if trimmed.contains("-----BEGIN") {
        for block in pem_blocks(trimmed) {
            match block.tag.as_str() {
                "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => return Ok((x509::cert_summary(&block.der)?.spki, "the certificate")),
                t if t.contains("CERTIFICATE REQUEST") => return Ok((x509::csr_parts(&block.der)?.spki, "the certificate request")),
                "PUBLIC KEY" => return Ok((block.der, "the public key")),
                "RSA PUBLIC KEY" => return Ok((rsa_spki(&block.der)?, "the RSA public key")),
                t if t.contains("PRIVATE KEY") => return Ok((PrivateKey::from_bytes(trimmed.as_bytes(), password)?.public_key_der()?, "the private key")),
                "PKCS7" | "CMS" => {
                    let first = cms::certificates_from_pkcs7(&block.der)?.into_iter().next().ok_or("the PKCS#7 bundle holds no certificate")?;
                    return Ok((x509::cert_summary(&first)?.spki, "the first certificate of the PKCS#7 bundle"));
                }
                _ => continue,
            }
        }
        return Err("no certificate, request or key found in the PEM data".into());
    }
    if trimmed.starts_with('{') {
        return Ok((spki_from_jwk(trimmed)?, "the JWK"));
    }
    if let Some(line) = trimmed.lines().map(str::trim).find(|l| is_openssh_line(l)) {
        return Ok((spki_from_openssh(line)?, "the OpenSSH public key"));
    }
    match unb64(&trimmed.split_whitespace().collect::<String>()) {
        Ok(der) => spki_from_der(&der, password),
        Err(_) => Err("unrecognised public key format".into()),
    }
}

fn spki_from_der(der: &[u8], password: Option<&str>) -> Res<(Vec<u8>, &'static str)> {
    if let Ok(summary) = x509::cert_summary(der) {
        return Ok((summary.spki, "the certificate"));
    }
    if keys::split_spki(der).is_ok() && keys::public_key_info(der).is_ok() {
        return Ok((der.to_vec(), "the public key"));
    }
    if let Ok(spki) = rsa_spki(der) {
        return Ok((spki, "the RSA public key"));
    }
    if let Ok(parts) = x509::csr_parts(der) {
        return Ok((parts.spki, "the certificate request"));
    }
    if let Ok(key) = PrivateKey::from_bytes(der, password) {
        return Ok((key.public_key_der()?, "the private key"));
    }
    if let Some(first) = cms::certificates_from_pkcs7(der).ok().and_then(|c| c.into_iter().next()) {
        return Ok((x509::cert_summary(&first)?.spki, "the first certificate of the PKCS#7 bundle"));
    }
    Err("no certificate, request or key found in the data (an encrypted private key needs its password)".into())
}

fn rsa_spki(pkcs1: &[u8]) -> Res<Vec<u8>> {
    let key = RsaPublicKey::from_pkcs1_der(pkcs1).map_err(e)?;
    Ok(key.to_public_key_der().map_err(e)?.as_bytes().to_vec())
}

fn is_openssh_line(line: &str) -> bool {
    line.starts_with("ssh-rsa ") || line.starts_with("ssh-ed25519 ") || line.starts_with("ecdsa-sha2-nistp")
}

/// Reader over the length-prefixed fields of an OpenSSH public key blob.
struct SshReader<'a>(&'a [u8]);

impl<'a> SshReader<'a> {
    fn string(&mut self) -> Res<&'a [u8]> {
        let bad = || "invalid OpenSSH public key: truncated".to_string();
        let len_bytes: [u8; 4] = self.0.get(..4).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let value = self.0.get(4..4 + len).ok_or_else(bad)?;
        self.0 = &self.0[4 + len..];
        Ok(value)
    }
}

fn spki_from_openssh(line: &str) -> Res<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let kind = parts.next().unwrap_or_default();
    let blob = unb64(parts.next().ok_or("invalid OpenSSH public key: missing key data")?).map_err(|_| "invalid OpenSSH public key: the key data is not base64".to_string())?;
    let mut r = SshReader(&blob);
    let inner = r.string()?;
    if inner != kind.as_bytes() {
        return Err("invalid OpenSSH public key: the key type does not match its data".into());
    }
    match kind {
        "ssh-rsa" => {
            let exp = r.string()?;
            let modulus = r.string()?;
            let key = RsaPublicKey::new(BigUint::from_bytes_be(modulus), BigUint::from_bytes_be(exp)).map_err(e)?;
            Ok(key.to_public_key_der().map_err(e)?.as_bytes().to_vec())
        }
        "ssh-ed25519" => ed25519_spki(r.string()?),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let _ident = r.string()?;
            ec_spki(&kind["ecdsa-sha2-nist".len()..], r.string()?)
        }
        other => Err(format!("OpenSSH {other} keys are not supported (RSA, ECDSA and Ed25519 are)")),
    }
}

fn ed25519_spki(raw: &[u8]) -> Res<Vec<u8>> {
    let bytes: [u8; 32] = raw.try_into().map_err(|_| "invalid Ed25519 public key: expected 32 bytes".to_string())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(e)?;
    Ok(key.to_public_key_der().map_err(e)?.as_bytes().to_vec())
}

/// SPKI for an uncompressed or compressed SEC1 point. `curve` is `p256`, `p384` or `p521`
/// (`P-256` etc. are accepted too).
fn ec_spki(curve: &str, point: &[u8]) -> Res<Vec<u8>> {
    let der = match curve.to_ascii_lowercase().replace('-', "").as_str() {
        "p256" => p256::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-256 public key".to_string())?.to_public_key_der(),
        "p384" => p384::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-384 public key".to_string())?.to_public_key_der(),
        "p521" => p521::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-521 public key".to_string())?.to_public_key_der(),
        other => return Err(format!("unsupported EC curve '{other}' (P-256, P-384 and P-521 are supported)")),
    };
    Ok(der.map_err(e)?.as_bytes().to_vec())
}

/// SPKI from a public (or private) JWK, or the first key of a JWK set.
fn spki_from_jwk(text: &str) -> Res<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|err| format!("invalid JSON: {err}"))?;
    let jwk = match value.get("keys").and_then(|k| k.as_array()) {
        Some(keys) => keys.first().cloned().ok_or("the JWK set is empty")?,
        None => value,
    };
    let field = |name: &str| -> Res<Vec<u8>> {
        let v = jwk.get(name).and_then(|v| v.as_str()).ok_or_else(|| format!("the JWK has no '{name}'"))?;
        B64URL.decode(v.trim_end_matches('=')).map_err(|_| format!("the JWK '{name}' is not base64url"))
    };
    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or("the JWK has no 'kty'")?;
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
    match kty {
        "RSA" => {
            let key = RsaPublicKey::new(BigUint::from_bytes_be(&field("n")?), BigUint::from_bytes_be(&field("e")?)).map_err(e)?;
            Ok(key.to_public_key_der().map_err(e)?.as_bytes().to_vec())
        }
        "EC" => {
            let len = match crv {
                "P-256" => 32,
                "P-384" => 48,
                "P-521" => 66,
                other => return Err(format!("unsupported JWK curve '{other}'")),
            };
            let pad = |v: Vec<u8>| -> Res<Vec<u8>> {
                if v.len() > len {
                    return Err(format!("the JWK coordinates are too long for {crv}"));
                }
                Ok([vec![0u8; len - v.len()], v].concat())
            };
            let point = [vec![0x04], pad(field("x")?)?, pad(field("y")?)?].concat();
            ec_spki(crv, &point)
        }
        "OKP" if crv == "Ed25519" => ed25519_spki(&field("x")?),
        "OKP" => Err(format!("unsupported JWK curve '{crv}'")),
        "oct" => Err("this is a symmetric (oct) JWK; it has no public key".into()),
        other => Err(format!("unsupported JWK key type '{other}'")),
    }
}

// ------------------------------------------------------------------------------------------------
// PEM <-> DER
// ------------------------------------------------------------------------------------------------

/// PEM input becomes DER (the first block); DER or bare base64 becomes PEM under `label`, or under
/// the label detected from the content when `label` is empty.
pub fn encoding(data: &[u8], label: Option<&str>) -> Res<Output> {
    let label = label.map(|l| l.trim().to_ascii_uppercase()).filter(|l| !l.is_empty());
    let der = if looks_textual(data) {
        let text = String::from_utf8_lossy(data);
        let blocks = pem_blocks(&text);
        if let Some(first) = blocks.first() {
            let mut notes = Vec::new();
            if blocks.len() > 1 {
                notes.push(format!(
                    "Found {} PEM blocks; a DER file holds one, so only the first ({}) was converted.",
                    blocks.len(),
                    first.tag
                ));
            }
            return Ok(Output {
                bytes: first.der.clone(),
                text: false,
                sensitive: first.tag.contains("PRIVATE KEY"),
                format: format!("DER ({})", first.tag),
                extension: der_extension(&first.tag),
                count: 1,
                notes,
            });
        }
        unb64(&text.split_whitespace().collect::<String>()).map_err(|_| "no PEM block found, and the text is not base64".to_string())?
    } else {
        data.to_vec()
    };
    let tag = match label {
        Some(l) => l,
        None => detect_der_label(&der).ok_or("could not tell what this data holds; choose the PEM label")?.to_string(),
    };
    Ok(Output {
        bytes: to_pem(&tag, &der).into_bytes(),
        text: true,
        sensitive: tag.contains("PRIVATE KEY"),
        format: format!("PEM ({tag})"),
        extension: "pem",
        count: 1,
        notes: Vec::new(),
    })
}

fn der_extension(tag: &str) -> &'static str {
    match tag {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => "cer",
        t if t.contains("CERTIFICATE REQUEST") => "csr",
        "X509 CRL" => "crl",
        "PKCS7" | "CMS" => "p7b",
        _ => "der",
    }
}

fn is_encrypted_pkcs8(der: &[u8]) -> bool {
    const PKCS5: &[u64] = &[1, 2, 840, 113549, 1, 5];
    const PKCS12_PBE: &[u64] = &[1, 2, 840, 113549, 1, 12, 1];
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let alg = pbe::read_algorithm_id(r.next())?;
            r.next().read_bytes()?;
            Ok(alg.oid)
        })
    })
    .map(|oid| oid.starts_with(PKCS5) || oid.starts_with(PKCS12_PBE))
    .unwrap_or(false)
}

/// The PEM label matching a DER object, when it is one xkeystore recognises.
pub fn detect_der_label(der: &[u8]) -> Option<&'static str> {
    if x509::cert_summary(der).is_ok() {
        return Some("CERTIFICATE");
    }
    if x509::parse_csr(der).is_ok() {
        return Some("CERTIFICATE REQUEST");
    }
    if x509::parse_crl(der, None).is_ok() {
        return Some("X509 CRL");
    }
    if keys::split_spki(der).is_ok() && keys::public_key_info(der).is_ok() {
        return Some("PUBLIC KEY");
    }
    if PrivateKey::from_pkcs8_der(der).is_ok() {
        return Some("PRIVATE KEY");
    }
    if is_encrypted_pkcs8(der) {
        return Some("ENCRYPTED PRIVATE KEY");
    }
    if RsaPrivateKey::from_pkcs1_der(der).is_ok() {
        return Some("RSA PRIVATE KEY");
    }
    if RsaPublicKey::from_pkcs1_der(der).is_ok() {
        return Some("RSA PUBLIC KEY");
    }
    // PKCS#8 and PKCS#1 were ruled out above, so a key that still parses is SEC1.
    if PrivateKey::from_bytes(der, None).is_ok() {
        return Some("EC PRIVATE KEY");
    }
    if cms::certificates_from_pkcs7(der).is_ok() {
        return Some("PKCS7");
    }
    None
}

// ------------------------------------------------------------------------------------------------
// Keystore entries -> PEM bundle
// ------------------------------------------------------------------------------------------------

/// What [`entries_to_pem`] writes.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PemBundleOptions {
    /// `chain`, `leaf` or `none`.
    #[serde(default)]
    pub certificates: String,
    /// `none`, `pkcs8`, `encrypted` or `traditional`.
    #[serde(default)]
    pub keys: String,
    /// Encrypts the keys when `keys` is `encrypted`.
    #[serde(default)]
    pub password: Option<String>,
    /// Precede each entry with an OpenSSL-style `Bag Attributes` / `friendlyName` header.
    #[serde(default)]
    pub annotate: bool,
}

/// One PEM file with the certificates and/or private keys of `entries`, the way
/// `openssl pkcs12 -in store.p12 -out store.pem` writes it.
pub fn entries_to_pem(entries: &[KeystoreEntry], opts: &PemBundleOptions) -> Res<Output> {
    let want_certs = matches!(opts.certificates.as_str(), "chain" | "leaf");
    let want_keys = !opts.keys.is_empty() && opts.keys != "none";
    if !want_certs && !want_keys {
        return Err("choose certificates, private keys or both".into());
    }
    if want_keys && !matches!(opts.keys.as_str(), "pkcs8" | "encrypted" | "traditional") {
        return Err(format!("unknown private key format '{}'", opts.keys));
    }
    let password = opts.password.as_deref().filter(|p| !p.is_empty());
    if opts.keys == "encrypted" && password.is_none() {
        return Err("enter a password to encrypt the private keys".into());
    }
    if want_keys {
        let locked: Vec<&str> = entries.iter().filter(|e| e.entry_type == "KeyPair" && e.locked).map(|e| e.alias.as_str()).collect();
        if !locked.is_empty() {
            return Err(format!("the private key of '{}' is locked by a separate key password; enter it first", locked.join("', '")));
        }
    }

    let mut out = String::new();
    let (mut certs, mut keys_written, mut secrets) = (0usize, 0usize, 0usize);
    for e in entries {
        let mut blocks = String::new();
        match e.entry_type.as_str() {
            "KeyPair" => {
                if want_keys {
                    blocks.push_str(&match opts.keys.as_str() {
                        "pkcs8" => to_pem("PRIVATE KEY", &entry::private_key_der(e)?),
                        "encrypted" => to_pem("ENCRYPTED PRIVATE KEY", &pbe::encrypt_pkcs8(password.unwrap_or_default(), &entry::private_key_der(e)?, pbe::DEFAULT_ITERATIONS)?),
                        _ => entry::private_key(e)?.to_traditional_pem()?,
                    });
                    keys_written += 1;
                }
                if want_certs {
                    let chain = entry::chain_der(e)?;
                    let take = if opts.certificates == "leaf" { chain.len().min(1) } else { chain.len() };
                    for c in &chain[..take] {
                        blocks.push_str(&to_pem("CERTIFICATE", c));
                        certs += 1;
                    }
                }
            }
            "TrustedCertificate" => {
                if want_certs && let Some(c) = entry::chain_der(e)?.first() {
                    blocks.push_str(&to_pem("CERTIFICATE", c));
                    certs += 1;
                }
            }
            _ => secrets += 1,
        }
        if blocks.is_empty() {
            continue;
        }
        if opts.annotate {
            out.push_str(&format!("Bag Attributes\n    friendlyName: {}\n", e.alias.replace(['\r', '\n'], " ")));
        }
        out.push_str(&blocks);
    }
    if out.is_empty() {
        return Err("nothing to write: the selected entries have no certificates or private keys of the chosen kind".into());
    }
    let mut notes = Vec::new();
    let mut parts = Vec::new();
    if certs > 0 {
        parts.push(plural(certs, "certificate", "certificates"));
    }
    if keys_written > 0 {
        parts.push(plural(keys_written, "private key", "private keys"));
    }
    notes.push(format!("Wrote {}.", parts.join(" and ")));
    if secrets > 0 {
        notes.push(format!("{} skipped: PEM has no standard form for them.", plural(secrets, "secret key", "secret keys")));
    }
    if keys_written > 0 && opts.keys != "encrypted" {
        notes.push("The private keys are not encrypted. Protect the file.".into());
    }
    let format = match (certs > 0, keys_written > 0) {
        (true, true) => "PEM bundle (certificates and private keys)",
        (false, true) => "PEM private keys",
        _ => "PEM certificates",
    };
    Ok(Output { bytes: out.into_bytes(), text: true, sensitive: keys_written > 0, format: format.into(), extension: "pem", count: certs + keys_written, notes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::tests_support::input;

    fn key_pair(alg: &str) -> KeystoreEntry {
        crate::ops::generate_key_pair(&input("conv", alg, false), None).unwrap()
    }

    fn ca_and_leaf() -> (KeystoreEntry, KeystoreEntry) {
        let ca = crate::ops::generate_key_pair(&input("root", "ECDSA", true), None).unwrap();
        let leaf = crate::ops::generate_key_pair(&input("leaf", "ECDSA", false), Some(&ca)).unwrap();
        (ca, leaf)
    }

    fn csr_of(e: &KeystoreEntry) -> String {
        crate::ops::generate_csr(e, &crate::model::CsrOptions { subject_dn: None, sans: None, signature_hash: None }).unwrap().csr_pem
    }

    fn chain_pem(e: &KeystoreEntry) -> String {
        e.certificate_chain.iter().map(|c| c.pem.clone()).collect()
    }

    #[test]
    fn certificates_round_trip_through_every_target() {
        let (_, leaf) = ca_and_leaf();
        let pem = chain_pem(&leaf);
        assert_eq!(read_certificates(pem.as_bytes()).unwrap().len(), 2);
        for target in CERT_TARGETS {
            let out = certificates(pem.as_bytes(), target, true).unwrap();
            let back = read_certificates(&out.bytes).unwrap();
            if *target == "der" {
                assert_eq!(back.len(), 1);
                assert_eq!(out.notes.len(), 1, "dropping certificates must be reported");
            } else {
                assert_eq!(back.len(), 2, "{target} lost certificates");
                // PKCS#7 keeps certificates in a DER SET, which has no order. The others read back leaf first.
                if !target.starts_with("pkcs7") {
                    assert_eq!(x509::cn_of(&x509::parse_certificate(&back[0]).unwrap().subject), x509::cn_of(&leaf.subject), "{target}");
                }
            }
        }
        assert!(certificates(b"hello", "pem", false).is_err());
        assert!(certificates(pem.as_bytes(), "bogus", false).is_err());
    }

    #[test]
    fn ordering_puts_the_leaf_first() {
        let (_, leaf) = ca_and_leaf();
        let reversed: String = leaf.certificate_chain.iter().rev().map(|c| c.pem.clone()).collect();
        let out = certificates(reversed.as_bytes(), "pem", true).unwrap();
        let first = read_certificates(&out.bytes).unwrap().remove(0);
        assert_eq!(x509::parse_certificate(&first).unwrap().subject, leaf.subject);
    }

    #[test]
    fn private_keys_convert_and_read_back() {
        for alg in ["RSA", "ECDSA", "Ed25519"] {
            let e = key_pair(alg);
            let src = e.private_key_pem.clone().unwrap();
            let original = PrivateKey::from_bytes(src.as_bytes(), None).unwrap().to_pkcs8_der().unwrap();
            for target in KEY_TARGETS {
                let r = private_key(src.as_bytes(), None, target, Some("out-pw-1"));
                if alg == "Ed25519" && target.starts_with("traditional") {
                    assert!(r.is_err(), "Ed25519 has no traditional form");
                    continue;
                }
                let out = r.unwrap_or_else(|err| panic!("{alg} {target}: {err}"));
                assert!(out.sensitive);
                if *target == "jwk" {
                    continue;
                }
                let pw = target.contains("encrypted").then_some("out-pw-1");
                let back = PrivateKey::from_bytes(&out.bytes, pw).unwrap_or_else(|err| panic!("{alg} {target} does not read back: {err}"));
                assert_eq!(back.to_pkcs8_der().unwrap(), original, "{alg} {target}");
            }
        }
    }

    #[test]
    fn encrypted_key_input_and_output_need_passwords() {
        let src = key_pair("ECDSA").private_key_pem.unwrap();
        let enc = private_key(src.as_bytes(), None, "pkcs8_encrypted_pem", Some("secret-1")).unwrap();
        assert!(private_key(&enc.bytes, None, "pkcs8_pem", None).is_err());
        assert!(private_key(&enc.bytes, Some("wrong"), "pkcs8_pem", None).is_err());
        assert!(private_key(&enc.bytes, Some("secret-1"), "pkcs8_pem", None).is_ok());
        assert!(private_key(src.as_bytes(), None, "pkcs8_encrypted_pem", None).is_err());
    }

    #[test]
    fn public_keys_are_found_in_every_container_and_round_trip() {
        for alg in ["RSA", "ECDSA", "Ed25519"] {
            let e = key_pair(alg);
            let expected = pem::parse(e.public_key_pem.as_ref().unwrap()).unwrap().contents().to_vec();
            let csr = csr_of(&e);
            let cert_der = entry::chain_der(&e).unwrap().remove(0);
            let sources: Vec<Vec<u8>> = vec![
                e.certificate_chain[0].pem.clone().into_bytes(),
                cert_der.clone(),
                csr.into_bytes(),
                e.private_key_pem.clone().unwrap().into_bytes(),
                e.public_key_pem.clone().unwrap().into_bytes(),
                expected.clone(),
                to_pem("PKCS7", &cms::certs_only(&[cert_der])).into_bytes(),
            ];
            for (i, src) in sources.iter().enumerate() {
                let (spki, _) = spki_from_any(src, None).unwrap_or_else(|err| panic!("{alg} source {i}: {err}"));
                assert_eq!(spki, expected, "{alg} source {i}");
            }
            // Every output form reads back to the same key.
            for target in PUBLIC_TARGETS {
                if *target == "pkcs1_pem" && alg != "RSA" {
                    assert!(public_key(&sources[0], None, target, "").is_err());
                    continue;
                }
                let out = public_key(&sources[0], None, target, "me@host").unwrap();
                assert!(!out.sensitive);
                let (back, _) = spki_from_any(&out.bytes, None).unwrap_or_else(|err| panic!("{alg} {target} does not read back: {err}"));
                assert_eq!(back, expected, "{alg} {target}");
            }
        }
    }

    #[test]
    fn jwk_sets_and_ec_points_are_accepted() {
        let e = key_pair("ECDSA");
        let spki = pem::parse(e.public_key_pem.as_ref().unwrap()).unwrap().contents().to_vec();
        let jwk = keys::public_jwk_from_spki(&spki).unwrap();
        let set = serde_json::json!({ "keys": [jwk] }).to_string();
        assert_eq!(spki_from_any(set.as_bytes(), None).unwrap().0, spki);
        let (_, _, bits) = keys::split_spki(&spki).unwrap();
        assert_eq!(ec_spki("P-256", &bits).unwrap(), spki);
        assert!(spki_from_any(br#"{"kty":"oct","k":"AAAA"}"#, None).is_err());
        assert!(spki_from_any(b"ssh-rsa AAAA", None).is_err());
    }

    #[test]
    fn pem_and_der_swap_with_detected_labels() {
        let e = key_pair("RSA");
        let cert_pem = e.certificate_chain[0].pem.clone();
        let der = encoding(cert_pem.as_bytes(), None).unwrap();
        assert!(!der.text && der.extension == "cer");
        let back = encoding(&der.bytes, None).unwrap();
        assert_eq!(String::from_utf8(back.bytes).unwrap(), cert_pem);

        let key_der = encoding(e.private_key_pem.as_ref().unwrap().as_bytes(), None).unwrap();
        assert!(key_der.sensitive);
        assert_eq!(detect_der_label(&key_der.bytes), Some("PRIVATE KEY"));
        let traditional = private_key(e.private_key_pem.as_ref().unwrap().as_bytes(), None, "traditional_der", None).unwrap();
        assert_eq!(detect_der_label(&traditional.bytes), Some("RSA PRIVATE KEY"));
        let ec = private_key(key_pair("ECDSA").private_key_pem.unwrap().as_bytes(), None, "traditional_der", None).unwrap();
        assert_eq!(detect_der_label(&ec.bytes), Some("EC PRIVATE KEY"));
        let enc = private_key(e.private_key_pem.as_ref().unwrap().as_bytes(), None, "pkcs8_encrypted_der", Some("pw")).unwrap();
        assert_eq!(detect_der_label(&enc.bytes), Some("ENCRYPTED PRIVATE KEY"));
        let spki = pem::parse(e.public_key_pem.as_ref().unwrap()).unwrap().contents().to_vec();
        assert_eq!(detect_der_label(&spki), Some("PUBLIC KEY"));
        let csr = csr_of(&e);
        let csr_der = encoding(csr.as_bytes(), None).unwrap();
        assert_eq!(csr_der.extension, "csr");
        assert_eq!(detect_der_label(&csr_der.bytes), Some("CERTIFICATE REQUEST"));
        let p7 = cms::certs_only(&entry::chain_der(&e).unwrap());
        assert_eq!(detect_der_label(&p7), Some("PKCS7"));

        // Bare base64 gets its armour back; an explicit label wins over detection.
        let b64 = crate::util::b64(&der.bytes);
        assert!(String::from_utf8(encoding(b64.as_bytes(), None).unwrap().bytes).unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(String::from_utf8(encoding(&der.bytes, Some("x509 certificate")).unwrap().bytes).unwrap().starts_with("-----BEGIN X509 CERTIFICATE-----"));
        assert!(encoding(&[0x01, 0x02, 0x03], None).is_err());
        let two = format!("{cert_pem}{cert_pem}");
        assert_eq!(encoding(two.as_bytes(), None).unwrap().notes.len(), 1);
    }

    #[test]
    fn entries_become_a_pem_bundle() {
        let (ca, leaf) = ca_and_leaf();
        let trusted = entry::trusted_cert_entry("anchor", &entry::chain_der(&ca).unwrap()[0], None).unwrap();
        let secret = entry::secret_key_entry("aes", "AES", &[7u8; 16], None);
        let all = vec![leaf.clone(), trusted, secret];
        let opts = |certificates: &str, keys: &str| PemBundleOptions { certificates: certificates.into(), keys: keys.into(), password: Some("bundle-pw".into()), annotate: true };

        let out = entries_to_pem(&all, &opts("chain", "pkcs8")).unwrap();
        let text = String::from_utf8(out.bytes.clone()).unwrap();
        assert!(out.sensitive);
        assert_eq!(text.matches("BEGIN CERTIFICATE").count(), 3);
        assert_eq!(text.matches("BEGIN PRIVATE KEY").count(), 1);
        assert!(text.contains("friendlyName: leaf"));
        assert!(out.notes.iter().any(|n| n.contains("secret key")));
        assert_eq!(read_certificates(&out.bytes).unwrap().len(), 3);
        assert!(PrivateKey::from_bytes(&out.bytes, None).is_ok());

        let certs_only = entries_to_pem(&all, &opts("leaf", "none")).unwrap();
        assert!(!certs_only.sensitive);
        assert_eq!(String::from_utf8(certs_only.bytes).unwrap().matches("BEGIN CERTIFICATE").count(), 2);

        let enc = entries_to_pem(&all, &opts("none", "encrypted")).unwrap();
        assert!(PrivateKey::from_bytes(&enc.bytes, Some("bundle-pw")).is_ok());
        assert!(entries_to_pem(&all, &PemBundleOptions { keys: "encrypted".into(), ..Default::default() }).is_err());
        assert!(entries_to_pem(&all, &opts("none", "none")).is_err());

        let mut locked = leaf.clone();
        locked.locked = true;
        locked.private_key_pem = None;
        assert!(entries_to_pem(&[locked.clone()], &opts("chain", "pkcs8")).is_err());
        assert!(entries_to_pem(&[locked], &opts("chain", "none")).is_ok(), "certificates of a locked key are still public");
    }

    #[test]
    fn deliver_writes_and_withholds_secrets() {
        let dir = std::env::temp_dir().join(format!("xks-convert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let e = key_pair("ECDSA");
        let preview = deliver(public_key(e.public_key_pem.as_ref().unwrap().as_bytes(), None, "openssh", "c").unwrap(), None).unwrap();
        assert!(preview.path.is_none() && preview.text.unwrap().starts_with("ecdsa-sha2-nistp256 "));
        let key_path = dir.join("k.pem");
        let saved = deliver(private_key(e.private_key_pem.as_ref().unwrap().as_bytes(), None, "pkcs8_pem", None).unwrap(), key_path.to_str()).unwrap();
        assert!(saved.text.is_none(), "private key text must not be returned");
        assert_eq!(std::fs::read(&key_path).unwrap().len(), saved.byte_length);
        std::fs::remove_dir_all(dir).ok();
    }
}
