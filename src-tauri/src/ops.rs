//! Keystore entry operations: key/secret generation, CSRs, issuing certificates, CA replies,
//! importing keys and certificates, CRLs and key rotation.

use crate::entry;
use crate::keys::{self, parse_hash_name, PrivateKey};
use crate::model::*;
use crate::util::*;
use crate::x509::{self, CertTemplate, San, Signer};

const DAY: i64 = 86_400;

pub fn validate_alias(alias: &str) -> Res<String> {
    let a = alias.trim();
    if a.is_empty() {
        return Err("alias must not be empty".into());
    }
    if a.len() > 255 || a.chars().any(|c| c.is_control()) {
        return Err("alias must be at most 255 printable characters".into());
    }
    Ok(a.to_string())
}

fn parse_sans(list: &[String]) -> Res<Vec<San>> {
    let mut out: Vec<San> = Vec::new();
    for s in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let san = x509::parse_san(s)?;
        if !out.iter().any(|o| x509::san_to_string(o) == x509::san_to_string(&san)) {
            out.push(san);
        }
    }
    Ok(out)
}

fn default_key_usage(is_ca: bool, algorithm: &str) -> Vec<String> {
    if is_ca {
        vec!["digitalSignature".into(), "keyCertSign".into(), "cRLSign".into()]
    } else if algorithm == "RSA" {
        vec!["digitalSignature".into(), "keyEncipherment".into()]
    } else {
        vec!["digitalSignature".into()]
    }
}

/// The issuing CA: its private key plus certificate chain (leaf of the CA entry first).
struct Issuer {
    key: PrivateKey,
    chain: Vec<Vec<u8>>,
    not_after: i64,
}

fn issuer_from(ca: &KeystoreEntry) -> Res<Issuer> {
    if ca.entry_type != "KeyPair" {
        return Err(format!("'{}' has no private key and cannot sign", ca.alias));
    }
    let key = entry::private_key(ca)?;
    if !key.is_usable() {
        return Err(format!("'{}' uses {} which xkeystore cannot sign with", ca.alias, key.algorithm()));
    }
    let chain = entry::chain_der(ca)?;
    let leaf = ca.certificate_chain.first().ok_or_else(|| format!("'{}' has no certificate", ca.alias))?;
    if !leaf.is_ca {
        return Err(format!("'{}' is not a CA certificate (BasicConstraints CA:TRUE is required to issue certificates)", ca.alias));
    }
    if leaf.not_after < now_ts() {
        return Err(format!("the CA certificate '{}' has expired", ca.alias));
    }
    if !leaf.key_usage.is_empty() && !leaf.key_usage.iter().any(|k| k == "Certificate Sign") {
        return Err(format!("'{}' does not allow certificate signing (keyCertSign key usage)", ca.alias));
    }
    Ok(Issuer { key, chain, not_after: leaf.not_after })
}

fn validity(days: u32, issuer: Option<&Issuer>) -> Res<(i64, i64)> {
    if days == 0 || days > 36_500 {
        return Err("validity must be between 1 and 36500 days".into());
    }
    let now = now_ts() - 60; // tolerate small clock skew on the relying side
    let mut not_after = now + days as i64 * DAY;
    if let Some(i) = issuer {
        not_after = not_after.min(i.not_after);
    }
    Ok((now, not_after))
}

fn subject_dn(input: &GenerateKeyPairInput) -> Res<Vec<u8>> {
    let dn = if input.subject_dn.trim().is_empty() {
        x509::dn_from_fields(
            &input.common_name,
            &input.organizational_unit,
            &input.organization,
            &input.locality,
            &input.state,
            &input.country,
            &input.email,
        )?
    } else {
        x509::parse_dn(&input.subject_dn)?
    };
    Ok(x509::encode_dn(&dn))
}

/// Generates a key pair and its certificate: self-signed, or issued by `issuer` (a CA entry).
pub fn generate_key_pair(input: &GenerateKeyPairInput, issuer: Option<&KeystoreEntry>) -> Res<KeystoreEntry> {
    let alias = validate_alias(&input.alias)?;
    let subject = subject_dn(input)?;
    let sans = parse_sans(&input.sans)?;
    let issuer = issuer.map(issuer_from).transpose()?;
    let (not_before, not_after) = validity(input.validity_days, issuer.as_ref())?;
    let key = PrivateKey::generate(&input.algorithm, input.key_size, input.curve.as_deref())?;
    let spki = key.public_key_der()?;
    let ku = if input.key_usage.is_empty() { default_key_usage(input.is_ca, &key.algorithm()) } else { input.key_usage.clone() };
    let eku = if input.extended_key_usage.is_empty() && !input.is_ca {
        vec!["serverAuth".to_string(), "clientAuth".to_string()]
    } else {
        input.extended_key_usage.clone()
    };
    let mut extensions = vec![x509::ext_basic_constraints(input.is_ca, input.path_len)];
    extensions.extend(x509::ext_key_usage(&ku)?);
    extensions.extend(x509::ext_extended_key_usage(&eku)?);
    extensions.extend(x509::ext_subject_alt_name(&sans));
    let template = CertTemplate { serial: random_serial(), subject_der: subject, not_before, not_after, spki_der: spki, extensions };
    let rsa_hash = parse_hash_name(input.signature_hash.as_deref());
    let (cert, mut chain) = match &issuer {
        Some(i) => {
            let sig_alg = i.key.default_sig_alg(rsa_hash)?;
            let cert = x509::build_certificate(template, &Signer { key: &i.key, cert_der: Some(&i.chain[0]), sig_alg })?;
            (cert, i.chain.clone())
        }
        None => {
            let sig_alg = key.default_sig_alg(rsa_hash)?;
            (x509::build_certificate(template, &Signer { key: &key, cert_der: None, sig_alg })?, vec![])
        }
    };
    chain.insert(0, cert);
    let mut e = entry::key_pair_entry(&alias, &key.to_pkcs8_der()?, &chain, None)?;
    e.labels = input.labels.clone();
    Ok(e)
}

pub fn generate_secret_key(input: &GenerateSecretKeyInput) -> Res<KeystoreEntry> {
    let alias = validate_alias(&input.alias)?;
    let algorithm = entry::canonical_secret_algorithm(&input.algorithm);
    let key = match input.custom_hex.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => {
            let cleaned: String = h.chars().filter(|c| !matches!(c, ':' | ' ' | '\n' | '\r' | '\t')).collect();
            hex::decode(&cleaned).map_err(|_| "key material must be hexadecimal".to_string())?
        }
        None => {
            if input.key_size == 0 || !input.key_size.is_multiple_of(8) {
                return Err("key size must be a positive multiple of 8 bits".into());
            }
            random_bytes(input.key_size as usize / 8)
        }
    };
    let bits = key.len() * 8;
    match algorithm.as_str() {
        "AES" if ![128, 192, 256].contains(&bits) => return Err(format!("AES keys must be 128, 192 or 256 bits (got {bits})")),
        "DESede" if bits != 192 && bits != 128 => return Err(format!("DESede keys must be 128 or 192 bits (got {bits})")),
        a if a.starts_with("Hmac") && bits < 128 => return Err("HMAC keys should be at least 128 bits".into()),
        _ if bits == 0 => return Err("key material is empty".into()),
        _ => {}
    }
    let mut e = entry::secret_key_entry(&alias, &algorithm, &key, None);
    e.labels = input.labels.clone();
    Ok(e)
}

fn sans_from_strings(list: &[String]) -> Res<Vec<San>> {
    parse_sans(&list.iter().map(|s| s.trim_start_matches("DirName:").to_string()).filter(|s| !s.starts_with("othername:") && !s.starts_with("RID:")).collect::<Vec<_>>())
}

pub fn generate_csr(e: &KeystoreEntry, options: &CsrOptions) -> Res<CsrResult> {
    if e.entry_type != "KeyPair" {
        return Err("only key pair entries can create a CSR".into());
    }
    let key = entry::private_key(e)?;
    if !key.is_usable() {
        return Err(format!("{} keys cannot sign a CSR in xkeystore", key.algorithm()));
    }
    let chain = entry::chain_der(e)?;
    let subject = match options.subject_dn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(dn) => x509::encode_dn(&x509::parse_dn(dn)?),
        None => x509::cert_summary(chain.first().ok_or("entry has no certificate")?)?.subject_raw,
    };
    let sans = match &options.sans {
        Some(list) => parse_sans(list)?,
        None => sans_from_strings(&e.certificate_chain.first().map(|c| c.sans.clone()).unwrap_or_default())?,
    };
    let exts: Vec<x509::Extension> = x509::ext_subject_alt_name(&sans).into_iter().collect();
    let sig_alg = key.default_sig_alg(parse_hash_name(options.signature_hash.as_deref()))?;
    let der = x509::build_csr(&subject, &key, sig_alg, &exts)?;
    Ok(CsrResult {
        alias: e.alias.clone(),
        subject: x509::name_der_to_string(&subject),
        algorithm: sig_alg.name(),
        csr_pem: to_pem("CERTIFICATE REQUEST", &der),
        sha256_digest: colon_hex(&sha256(&der)),
    })
}

pub fn sign_csr(input: &SignCsrInput, ca: &KeystoreEntry) -> Res<SignedCertificateResult> {
    let der = x509::csr_der_from_bytes(input.csr_pem.as_bytes())?;
    let parts = x509::csr_parts(&der)?;
    let issuer = issuer_from(ca)?;
    let subject = match input.subject_override.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(dn) => x509::encode_dn(&x509::parse_dn(dn)?),
        None => parts.subject_der.clone(),
    };
    let mut san_list: Vec<String> = if input.copy_requested_sans.unwrap_or(true) { parts.sans.clone() } else { vec![] };
    san_list.extend(input.sans.iter().cloned());
    let sans = sans_from_strings(&san_list)?;
    let (not_before, not_after) = validity(input.validity_days, Some(&issuer))?;
    let algorithm = keys::public_key_info(&parts.spki)?.algorithm;
    let ku = if input.key_usage.is_empty() { default_key_usage(input.is_ca, &algorithm) } else { input.key_usage.clone() };
    let eku = if input.extended_key_usage.is_empty() && !input.is_ca { vec!["serverAuth".to_string(), "clientAuth".to_string()] } else { input.extended_key_usage.clone() };
    let mut extensions = vec![x509::ext_basic_constraints(input.is_ca, input.path_len)];
    extensions.extend(x509::ext_key_usage(&ku)?);
    extensions.extend(x509::ext_extended_key_usage(&eku)?);
    extensions.extend(x509::ext_subject_alt_name(&sans));
    let sig_alg = issuer.key.default_sig_alg(None)?;
    let cert = x509::build_certificate(
        CertTemplate { serial: random_serial(), subject_der: subject, not_before, not_after, spki_der: parts.spki, extensions },
        &Signer { key: &issuer.key, cert_der: Some(&issuer.chain[0]), sig_alg },
    )?;
    let mut chain_pem = to_pem("CERTIFICATE", &cert);
    for c in &issuer.chain {
        chain_pem.push_str(&to_pem("CERTIFICATE", c));
    }
    Ok(SignedCertificateResult { certificate: x509::parse_certificate(&cert)?, chain_pem })
}

/// Installs a CA reply (the signed certificate, optionally with its chain) into a key pair.
pub fn import_ca_reply(e: &KeystoreEntry, reply: &[u8]) -> Res<KeystoreEntry> {
    if e.entry_type != "KeyPair" {
        return Err("a CA reply can only be imported into a key pair entry".into());
    }
    let key = entry::private_key(e)?;
    let mut pool = x509::certificates_from_bytes(reply)?;
    let leaf = pool
        .iter()
        .position(|c| x509::cert_summary(c).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false))
        .map(|i| pool.remove(i))
        .ok_or("the CA reply does not contain a certificate for this entry's public key")?;
    pool.extend(entry::chain_der(e)?.into_iter().skip(1));
    let chain = x509::build_chain(&leaf, &pool);
    let mut updated = entry::key_pair_entry(&e.alias, &key.to_pkcs8_der()?, &chain, None)?;
    updated.id = e.id.clone();
    updated.labels = e.labels.clone();
    Ok(updated)
}

/// Imports a private key (PEM/DER, optionally encrypted) with its certificate chain. The key and
/// certificates may come from the same PEM file.
pub fn import_key_pair(alias: &str, key_data: &[u8], key_password: Option<&str>, cert_data: Option<&[u8]>) -> Res<KeystoreEntry> {
    let alias = validate_alias(alias)?;
    let key = PrivateKey::from_bytes(key_data, key_password)?;
    let mut certs = match cert_data {
        Some(d) if !d.is_empty() => x509::certificates_from_bytes(d)?,
        _ => x509::certificates_from_bytes(key_data).unwrap_or_default(),
    };
    if certs.is_empty() {
        return Err("a certificate is required for a key pair entry; select the certificate (or chain) file".into());
    }
    let leaf = certs
        .iter()
        .position(|c| x509::cert_summary(c).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false))
        .map(|i| certs.remove(i))
        .ok_or("none of the certificates matches the private key")?;
    let chain = x509::build_chain(&leaf, &certs);
    entry::key_pair_entry(&alias, &key.to_pkcs8_der()?, &chain, None)
}

/// Imports trusted certificates. A bundle yields one entry per certificate; aliases are made unique.
pub fn import_trusted_certificates(alias: &str, data: &[u8], existing: &[String]) -> Res<Vec<KeystoreEntry>> {
    let base = validate_alias(alias)?;
    let certs = x509::order_bundle(&x509::certificates_from_bytes(data)?);
    let mut used: std::collections::HashSet<String> = existing.iter().map(|a| a.to_lowercase()).collect();
    let mut out = Vec::new();
    for (i, der) in certs.iter().enumerate() {
        let mut candidate = if i == 0 { base.clone() } else { format!("{base}-{}", i + 1) };
        let mut n = 2;
        while used.contains(&candidate.to_lowercase()) {
            candidate = format!("{base}-{n}");
            n += 1;
        }
        used.insert(candidate.to_lowercase());
        out.push(entry::trusted_cert_entry(&candidate, der, None)?);
    }
    Ok(out)
}

pub fn generate_crl(ca: &KeystoreEntry, next_update_days: u32, crl_number: u64, revoked: &[RevokedCertEntry]) -> Res<CrlInfo> {
    if next_update_days == 0 || next_update_days > 3650 {
        return Err("next update must be between 1 and 3650 days".into());
    }
    let issuer = issuer_from(ca)?;
    let leaf = ca.certificate_chain.first().unwrap();
    if !leaf.key_usage.is_empty() && !leaf.key_usage.iter().any(|k| k == "CRL Sign") {
        return Err(format!("'{}' does not allow CRL signing (cRLSign key usage)", ca.alias));
    }
    let now = now_ts();
    let sig_alg = issuer.key.default_sig_alg(None)?;
    let der = x509::build_crl(
        &Signer { key: &issuer.key, cert_der: Some(&issuer.chain[0]), sig_alg },
        now,
        now + next_update_days as i64 * DAY,
        crl_number,
        revoked,
    )?;
    let spki = x509::cert_summary(&issuer.chain[0])?.spki;
    x509::parse_crl(&der, Some(&spki))
}

/// Re-keys an entry: new key of the requested type, same subject, SANs, usages and lifetime.
/// The certificate is re-issued by `issuer` when given, otherwise self-signed.
pub fn rotate_key(e: &KeystoreEntry, algorithm: &str, key_size: u32, curve: Option<&str>, issuer: Option<&KeystoreEntry>) -> Res<KeystoreEntry> {
    if e.entry_type != "KeyPair" {
        return Err("only key pairs can be rotated".into());
    }
    let chain = entry::chain_der(e)?;
    let leaf_der = chain.first().ok_or("entry has no certificate")?;
    let leaf = x509::parse_certificate(leaf_der)?;
    let summary = x509::cert_summary(leaf_der)?;
    let issuer = issuer.map(issuer_from).transpose()?;
    let lifetime_days = ((leaf.not_after - leaf.not_before) / DAY).clamp(1, 36_500) as u32;
    let (not_before, not_after) = validity(lifetime_days, issuer.as_ref())?;
    let key = PrivateKey::generate(algorithm, key_size, curve)?;
    let label_to_id = |l: &str| -> Option<String> {
        Some(
            match l {
                "Digital Signature" => "digitalSignature",
                "Non Repudiation" => "nonRepudiation",
                "Key Encipherment" => "keyEncipherment",
                "Data Encipherment" => "dataEncipherment",
                "Key Agreement" => "keyAgreement",
                "Certificate Sign" => "keyCertSign",
                "CRL Sign" => "cRLSign",
                _ => return None,
            }
            .to_string(),
        )
    };
    let mut ku: Vec<String> = leaf.key_usage.iter().filter_map(|l| label_to_id(l)).collect();
    if key.algorithm() != "RSA" {
        ku.retain(|k| k != "keyEncipherment" && k != "dataEncipherment");
    }
    if ku.is_empty() {
        ku = default_key_usage(leaf.is_ca, &key.algorithm());
    }
    let eku: Vec<String> = leaf
        .extended_key_usage
        .iter()
        .filter_map(|l| {
            Some(
                match l.as_str() {
                    "TLS Web Server Authentication" => "serverAuth",
                    "TLS Web Client Authentication" => "clientAuth",
                    "Code Signing" => "codeSigning",
                    "E-mail Protection" => "emailProtection",
                    "Time Stamping" => "timeStamping",
                    "OCSP Signing" => "OCSPSigning",
                    other if crate::oids::parse_oid_str(other).is_some() => other,
                    _ => return None,
                }
                .to_string(),
            )
        })
        .collect();
    let mut extensions = vec![x509::ext_basic_constraints(leaf.is_ca, leaf.path_len)];
    extensions.extend(x509::ext_key_usage(&ku)?);
    extensions.extend(x509::ext_extended_key_usage(&eku)?);
    extensions.extend(x509::ext_subject_alt_name(&sans_from_strings(&leaf.sans)?));
    let template = CertTemplate {
        serial: random_serial(),
        subject_der: summary.subject_raw,
        not_before,
        not_after,
        spki_der: key.public_key_der()?,
        extensions,
    };
    let (cert, mut new_chain) = match &issuer {
        Some(i) => {
            let sig_alg = i.key.default_sig_alg(None)?;
            (x509::build_certificate(template, &Signer { key: &i.key, cert_der: Some(&i.chain[0]), sig_alg })?, i.chain.clone())
        }
        None => {
            let sig_alg = key.default_sig_alg(None)?;
            (x509::build_certificate(template, &Signer { key: &key, cert_der: None, sig_alg })?, vec![])
        }
    };
    new_chain.insert(0, cert);
    let mut rotated = entry::key_pair_entry(&e.alias, &key.to_pkcs8_der()?, &new_chain, None)?;
    rotated.id = e.id.clone();
    rotated.labels = e.labels.clone();
    Ok(rotated)
}

/// Shared fixtures for unit tests in other modules.
#[cfg(test)]
pub mod tests_support {
    pub use super::tests::input;
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn input(alias: &str, alg: &str, is_ca: bool) -> GenerateKeyPairInput {
        GenerateKeyPairInput {
            alias: alias.into(),
            algorithm: alg.into(),
            key_size: 2048,
            curve: Some("P-256".into()),
            signature_hash: None,
            subject_dn: String::new(),
            common_name: format!("{alias}.example.com"),
            organization: "Example Org".into(),
            organizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: "US".into(),
            email: String::new(),
            validity_days: 365,
            is_ca,
            path_len: None,
            sans: vec![format!("{alias}.example.com")],
            key_usage: vec![],
            extended_key_usage: vec![],
            labels: vec![],
        }
    }

    #[test]
    fn full_pki_workflow() {
        let ca = generate_key_pair(&input("root-ca", "ECDSA", true), None).unwrap();
        assert!(ca.certificate_chain[0].is_ca);
        let leaf = generate_key_pair(&input("web", "RSA", false), Some(&ca)).unwrap();
        assert_eq!(leaf.chain_length, 2);
        assert_eq!(leaf.issuer, ca.subject);
        // A non-CA cannot issue.
        assert!(generate_key_pair(&input("x", "Ed25519", false), Some(&leaf)).is_err());

        // CSR -> sign -> import reply
        let requester = generate_key_pair(&input("api", "Ed25519", false), None).unwrap();
        let csr = generate_csr(&requester, &CsrOptions { subject_dn: None, sans: None, signature_hash: None }).unwrap();
        let signed = sign_csr(
            &SignCsrInput {
                csr_pem: csr.csr_pem.clone(),
                subject_override: None,
                validity_days: 90,
                is_ca: false,
                path_len: None,
                sans: vec!["10.1.2.3".into()],
                key_usage: vec![],
                extended_key_usage: vec![],
                copy_requested_sans: Some(true),
            },
            &ca,
        )
        .unwrap();
        assert_eq!(signed.certificate.sans, vec!["DNS:api.example.com", "IP:10.1.2.3"]);
        let updated = import_ca_reply(&requester, signed.chain_pem.as_bytes()).unwrap();
        assert_eq!(updated.chain_length, 2);
        assert_eq!(updated.issuer, ca.subject);
        // A reply for another key is rejected.
        assert!(import_ca_reply(&leaf, signed.chain_pem.as_bytes()).is_err());

        // CRL
        let crl = generate_crl(&ca, 7, 1, &[RevokedCertEntry { serial_number: leaf.serial_number.clone(), revocation_date: "2026-01-01".into(), reason: "superseded".into() }]).unwrap();
        assert_eq!(crl.signature_valid, Some(true));

        // Rotation keeps subject and issuer
        let rotated = rotate_key(&leaf, "ECDSA", 0, Some("P-384"), Some(&ca)).unwrap();
        assert_eq!(rotated.subject, leaf.subject);
        assert_eq!(rotated.issuer, ca.subject);
        assert_eq!(rotated.curve.as_deref(), Some("P-384"));
        assert_ne!(rotated.private_key_pem, leaf.private_key_pem);
    }

    #[test]
    fn import_pem_key_and_bundle() {
        let ca = generate_key_pair(&input("ca", "RSA", true), None).unwrap();
        let leaf = generate_key_pair(&input("svc", "ECDSA", false), Some(&ca)).unwrap();
        let pem_bundle = format!(
            "{}{}{}",
            leaf.private_key_pem.clone().unwrap(),
            leaf.certificate_chain[1].pem,
            leaf.certificate_chain[0].pem
        );
        let imported = import_key_pair("svc", pem_bundle.as_bytes(), None, None).unwrap();
        assert_eq!(imported.chain_length, 2);
        assert_eq!(imported.sha256_fingerprint, leaf.sha256_fingerprint);
        let certs = import_trusted_certificates("chain", pem_bundle.as_bytes(), &["chain".into()]).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].alias, "chain-2");
    }

    #[test]
    fn secret_key_validation() {
        let ok = generate_secret_key(&GenerateSecretKeyInput { alias: "k".into(), algorithm: "AES".into(), key_size: 256, custom_hex: None, labels: vec![] }).unwrap();
        assert_eq!(ok.key_size, 256);
        assert!(generate_secret_key(&GenerateSecretKeyInput { alias: "k".into(), algorithm: "AES".into(), key_size: 100, custom_hex: None, labels: vec![] }).is_err());
        let custom = generate_secret_key(&GenerateSecretKeyInput { alias: "k".into(), algorithm: "HmacSHA256".into(), key_size: 0, custom_hex: Some("00112233445566778899aabbccddeeff".into()), labels: vec![] }).unwrap();
        assert_eq!(custom.key_size, 128);
        assert!(generate_secret_key(&GenerateSecretKeyInput { alias: "".into(), algorithm: "AES".into(), key_size: 128, custom_hex: None, labels: vec![] }).is_err());
    }
}
