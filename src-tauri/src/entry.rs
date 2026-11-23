//! Construction of [`KeystoreEntry`] values from real keys and certificates, plus the security
//! assessment (weak algorithms, deprecated digests) shown in the UI.

use crate::keys::{self, PrivateKey};
use crate::model::{CertificateInfo, KeystoreEntry};
use crate::util::*;
use crate::x509;

pub fn new_entry_id() -> String {
    format!("entry-{}", uuid::Uuid::new_v4())
}

/// Weakness findings for an asymmetric entry.
fn assess_certificate_entry(entry: &KeystoreEntry) -> Vec<String> {
    let mut reasons = Vec::new();
    let alg = entry.algorithm.as_str();
    match alg {
        "RSA" | "RSASSA-PSS" if entry.key_size > 0 && entry.key_size < 2048 => reasons.push(format!("RSA key is only {} bits (minimum 2048)", entry.key_size)),
        "ECDSA" if entry.key_size > 0 && entry.key_size < 256 => reasons.push(format!("EC key is only {} bits", entry.key_size)),
        "DSA" => reasons.push("DSA is deprecated (FIPS 186-5)".into()),
        _ => {}
    }
    if let Some(leaf) = entry.certificate_chain.first() {
        let sig = leaf.signature_algorithm.to_ascii_uppercase();
        // A trust anchor's self-signature is never checked, so a SHA-1 root is not a weakness.
        if !leaf.self_signed && (sig.starts_with("SHA1") || sig.starts_with("MD5") || sig.starts_with("MD2")) {
            reasons.push(format!("certificate is signed with {} (collision-prone digest)", leaf.signature_algorithm));
        }
    }
    reasons
}

fn assess_secret(algorithm: &str, bits: u32) -> Vec<String> {
    let mut reasons = Vec::new();
    let upper = algorithm.to_ascii_uppercase().replace('-', "");
    if upper.starts_with("DES") || upper == "TRIPLEDES" || upper == "RC2" || upper == "RC4" || upper == "ARCFOUR" || upper == "BLOWFISH" {
        reasons.push(format!("{algorithm} is a deprecated cipher"));
    } else if upper == "HMACSHA1" {
        reasons.push(format!("{algorithm} is a deprecated MAC"));
    } else if !matches!(upper.as_str(), "AES" | "HMACSHA256" | "HMACSHA384" | "HMACSHA512" | "CHACHA20") {
        reasons.push(format!("{algorithm} is not a recommended secret-key algorithm"));
    } else if bits < 128 {
        reasons.push(format!("secret key is only {bits} bits (minimum 128)"));
    }
    reasons
}

fn finalize(mut entry: KeystoreEntry) -> KeystoreEntry {
    let reasons = if entry.entry_type == "SecretKey" { assess_secret(&entry.algorithm, entry.key_size) } else { assess_certificate_entry(&entry) };
    entry.is_weak = !reasons.is_empty();
    entry.weak_reasons = reasons;
    entry.is_expired = entry.certificate_chain.first().is_some_and(|c| c.not_after < now_ts());
    entry
}

fn fill_from_leaf(entry: &mut KeystoreEntry, leaf: &CertificateInfo, creation_ts: Option<i64>) {
    entry.algorithm = leaf.public_key_algorithm.clone();
    entry.key_size = leaf.key_size;
    entry.curve = leaf.curve.clone();
    entry.subject = leaf.subject.clone();
    entry.issuer = leaf.issuer.clone();
    entry.serial_number = leaf.serial_number.clone();
    entry.sha256_fingerprint = leaf.sha256_fingerprint.clone();
    entry.sha1_fingerprint = leaf.sha1_fingerprint.clone();
    entry.expiry_date = fmt_date(leaf.not_after);
    entry.creation_date = fmt_date(creation_ts.unwrap_or(leaf.not_before));
    entry.is_post_quantum = ["ML-DSA", "ML-KEM", "SLH-DSA"].iter().any(|p| leaf.public_key_algorithm.starts_with(p));
}

/// A key pair entry: PKCS#8 private key plus its certificate chain (leaf first). The chain is
/// re-ordered if needed and the key is checked against the leaf certificate.
pub fn key_pair_entry(alias: &str, pkcs8_der: &[u8], chain: &[Vec<u8>], creation_ts: Option<i64>) -> Res<KeystoreEntry> {
    let key = PrivateKey::from_pkcs8_der(pkcs8_der)?;
    let mut ordered = chain.to_vec();
    // Put the certificate that matches the key first.
    if key.is_usable() {
        if let Some(pos) = ordered.iter().position(|c| x509::cert_summary(c).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false)) {
            let leaf = ordered.remove(pos);
            ordered = x509::build_chain(&leaf, &ordered);
        } else if !ordered.is_empty() {
            return Err(format!("entry '{alias}': the private key does not match its certificate"));
        }
    }
    let certs: Vec<CertificateInfo> = ordered.iter().map(|c| x509::parse_certificate(c)).collect::<Res<_>>()?;
    let mut entry = KeystoreEntry {
        id: new_entry_id(),
        alias: alias.to_string(),
        entry_type: "KeyPair".into(),
        private_key_pem: Some(to_pem("PRIVATE KEY", pkcs8_der)),
        public_key_pem: key.public_key_der().ok().map(|d| to_pem("PUBLIC KEY", &d)),
        chain_length: certs.len(),
        ..Default::default()
    };
    if let Some(leaf) = certs.first() {
        fill_from_leaf(&mut entry, leaf, creation_ts);
        if entry.public_key_pem.is_none() {
            entry.public_key_pem = x509::cert_summary(&ordered[0]).ok().map(|s| to_pem("PUBLIC KEY", &s.spki));
        }
    } else {
        entry.algorithm = key.algorithm();
        entry.key_size = key.key_size();
        entry.curve = key.curve();
        entry.creation_date = fmt_date(creation_ts.unwrap_or_else(now_ts));
    }
    if !key.is_usable() {
        entry.algorithm = key.algorithm();
        entry.is_post_quantum = ["ML-DSA", "ML-KEM", "SLH-DSA"].iter().any(|p| entry.algorithm.starts_with(p));
    }
    entry.certificate_chain = certs;
    Ok(finalize(entry))
}

/// A key pair whose private key could not be decrypted with the store password. The protected
/// blob is preserved so the entry survives a save to the same format.
pub fn locked_key_pair_entry(alias: &str, protected_blob: &[u8], chain: &[Vec<u8>], creation_ts: Option<i64>) -> Res<KeystoreEntry> {
    let certs: Vec<CertificateInfo> = chain.iter().map(|c| x509::parse_certificate(c)).collect::<Res<_>>()?;
    let mut entry = KeystoreEntry {
        id: new_entry_id(),
        alias: alias.to_string(),
        entry_type: "KeyPair".into(),
        locked: true,
        protected_key: Some(b64(protected_blob)),
        chain_length: certs.len(),
        public_key_pem: chain.first().and_then(|c| x509::cert_summary(c).ok()).map(|s| to_pem("PUBLIC KEY", &s.spki)),
        ..Default::default()
    };
    if let Some(leaf) = certs.first() {
        fill_from_leaf(&mut entry, leaf, creation_ts);
    }
    entry.certificate_chain = certs;
    Ok(finalize(entry))
}

pub fn trusted_cert_entry(alias: &str, cert_der: &[u8], creation_ts: Option<i64>) -> Res<KeystoreEntry> {
    let leaf = x509::parse_certificate(cert_der)?;
    let mut entry = KeystoreEntry {
        id: new_entry_id(),
        alias: alias.to_string(),
        entry_type: "TrustedCertificate".into(),
        chain_length: 1,
        public_key_pem: x509::cert_summary(cert_der).ok().map(|s| to_pem("PUBLIC KEY", &s.spki)),
        ..Default::default()
    };
    fill_from_leaf(&mut entry, &leaf, creation_ts);
    entry.certificate_chain = vec![leaf];
    Ok(finalize(entry))
}

/// Canonical Java algorithm name for a secret key algorithm (as stored by keytool).
pub fn canonical_secret_algorithm(name: &str) -> String {
    match name.trim().to_ascii_uppercase().replace('-', "").as_str() {
        "AES" => "AES".into(),
        "HMACSHA1" => "HmacSHA1".into(),
        "HMACSHA224" => "HmacSHA224".into(),
        "HMACSHA256" => "HmacSHA256".into(),
        "HMACSHA384" => "HmacSHA384".into(),
        "HMACSHA512" => "HmacSHA512".into(),
        "DESEDE" | "TRIPLEDES" | "3DES" => "DESede".into(),
        "DES" => "DES".into(),
        "CHACHA20" => "ChaCha20".into(),
        "BLOWFISH" => "Blowfish".into(),
        _ => name.trim().to_string(),
    }
}

pub fn secret_key_entry(alias: &str, algorithm: &str, key: &[u8], creation_ts: Option<i64>) -> KeystoreEntry {
    let bits = (key.len() * 8) as u32;
    let algorithm = canonical_secret_algorithm(algorithm);
    let entry = KeystoreEntry {
        id: new_entry_id(),
        alias: alias.to_string(),
        entry_type: "SecretKey".into(),
        key_size: bits,
        creation_date: fmt_date(creation_ts.unwrap_or_else(now_ts)),
        subject: format!("{algorithm} {bits}-bit secret key"),
        sha256_fingerprint: colon_hex(&sha256(key)),
        sha1_fingerprint: colon_hex(&sha1(key)),
        secret_key_hex: Some(upper_hex(key)),
        algorithm,
        ..Default::default()
    };
    finalize(entry)
}

/// A JCEKS secret key entry whose sealed object we keep opaque (wrong key password).
pub fn locked_secret_entry(alias: &str, sealed: &[u8], creation_ts: Option<i64>) -> KeystoreEntry {
    KeystoreEntry {
        id: new_entry_id(),
        alias: alias.to_string(),
        entry_type: "SecretKey".into(),
        algorithm: "Secret".into(),
        creation_date: fmt_date(creation_ts.unwrap_or_else(now_ts)),
        subject: "Secret key (locked)".into(),
        locked: true,
        protected_key: Some(b64(sealed)),
        ..Default::default()
    }
}

/// DER of every certificate in the entry's chain.
pub fn chain_der(entry: &KeystoreEntry) -> Res<Vec<Vec<u8>>> {
    entry.certificate_chain.iter().map(|c| pem::parse(c.pem.as_bytes()).map(|p| p.contents().to_vec()).map_err(|err| format!("entry '{}': invalid certificate PEM: {err}", entry.alias))).collect()
}

/// The entry's PKCS#8 DER, wiped from memory when dropped.
pub fn private_key_der(entry: &KeystoreEntry) -> Res<zeroize::Zeroizing<Vec<u8>>> {
    let pem_text = entry
        .private_key_pem
        .as_deref()
        .ok_or_else(|| if entry.locked { format!("the private key of '{}' is locked by a separate key password", entry.alias) } else { format!("'{}' has no private key", entry.alias) })?;
    let parsed = pem::parse(pem_text.as_bytes()).map_err(|err| format!("entry '{}': invalid private key PEM: {err}", entry.alias))?;
    Ok(zeroize::Zeroizing::new(parsed.into_contents()))
}

pub fn private_key(entry: &KeystoreEntry) -> Res<PrivateKey> {
    PrivateKey::from_pkcs8_der(&private_key_der(entry)?)
}

/// The secret key bytes, wiped from memory when dropped.
pub fn secret_bytes(entry: &KeystoreEntry) -> Res<zeroize::Zeroizing<Vec<u8>>> {
    let hex_str = entry.secret_key_hex.as_deref().ok_or_else(|| format!("'{}' has no secret key material", entry.alias))?;
    hex::decode(hex_str.replace([':', ' '], "")).map(zeroize::Zeroizing::new).map_err(|_| format!("entry '{}': invalid secret key hex", entry.alias))
}
