//! "Examine" engine: identifies and decodes arbitrary cryptographic input (PEM, DER, base64,
//! JWT, OpenSSH keys, keystores) into a [`DetectionResult`].

use crate::keys::{self, PrivateKey};
use crate::model::{DetectionResult, KeyInfo};
use crate::util::*;
use crate::{cms, convert, jwt, keystore, openssh, x509};

fn base(bytes: &[u8]) -> DetectionResult {
    DetectionResult { sha256: colon_hex(&sha256(bytes)), byte_length: bytes.len(), ..Default::default() }
}

fn chain_warnings(certs: &[crate::model::CertificateInfo], ders: &[Vec<u8>]) -> Vec<String> {
    let mut w = Vec::new();
    for c in certs {
        let cn = x509::cn_of(&c.subject);
        if c.days_remaining < 0 {
            w.push(format!("'{cn}' expired on {}", c.valid_to));
        } else if c.days_remaining <= 30 {
            w.push(format!("'{cn}' expires in {} days", c.days_remaining));
        }
        if c.public_key_algorithm == "RSA" && c.key_size < 2048 {
            w.push(format!("'{cn}' uses a weak {}-bit RSA key", c.key_size));
        }
        let sig = c.signature_algorithm.to_ascii_uppercase();
        if !c.self_signed && (sig.starts_with("SHA1") || sig.starts_with("MD5")) {
            w.push(format!("'{cn}' is signed with {}", c.signature_algorithm));
        }
    }
    for pair in ders.windows(2) {
        if !x509::issued_by(&pair[0], &pair[1]) {
            w.push("the certificates are not in issuer order (or the chain is incomplete)".into());
            break;
        }
    }
    w
}

fn key_info_private(key: &PrivateKey, format: &str) -> KeyInfo {
    let spki = key.public_key_der().ok();
    KeyInfo {
        kind: "private".into(),
        algorithm: key.algorithm(),
        key_size: key.key_size(),
        curve: key.curve(),
        encrypted: false,
        format: format.into(),
        public_key_sha256: spki.as_ref().map(|s| colon_hex(&sha256(s))),
        public_key_pem: spki.as_ref().map(|s| to_pem("PUBLIC KEY", s)),
    }
}

fn key_info_public(spki: &[u8], format: &str) -> Res<KeyInfo> {
    let info = keys::public_key_info(spki)?;
    Ok(KeyInfo {
        kind: "public".into(),
        algorithm: info.algorithm,
        key_size: info.key_size,
        curve: info.curve,
        encrypted: false,
        format: format.into(),
        public_key_sha256: Some(colon_hex(&sha256(spki))),
        public_key_pem: Some(to_pem("PUBLIC KEY", spki)),
    })
}

/// A private key result. `encrypted` says the file protects it, whether or not it was opened.
fn private_result(mut r: DetectionResult, key: &PrivateKey, title: &str, format: &str, encrypted: bool) -> DetectionResult {
    r.kind = "private_key".into();
    r.title = title.into();
    r.format = format.into();
    r.summary = format!("{} private key{}", key.describe(), if encrypted { " (decrypted with the supplied password)" } else { "" });
    if !encrypted {
        r.warnings.push("this private key is not encrypted".into());
    }
    let mut info = key_info_private(key, format);
    info.encrypted = encrypted;
    r.key = Some(info);
    r
}

/// An encrypted private key that was not opened: what protects it and, when the file shows it
/// without the password, which public key it belongs to.
fn locked_key_result(mut r: DetectionResult, title: &str, format: &str, protection: &str, spki: Option<&[u8]>) -> DetectionResult {
    r.kind = "private_key".into();
    r.title = title.into();
    r.format = format.into();
    r.summary = format!("Protected with {protection}. Enter its password to inspect the key.");
    let public = spki.and_then(|s| keys::public_key_info(s).ok().map(|i| (i, s)));
    r.key = Some(match public {
        Some((info, s)) => KeyInfo {
            kind: "private".into(),
            algorithm: info.algorithm,
            key_size: info.key_size,
            curve: info.curve,
            encrypted: true,
            format: format.into(),
            public_key_sha256: Some(colon_hex(&sha256(s))),
            public_key_pem: Some(to_pem("PUBLIC KEY", s)),
        },
        None => KeyInfo { kind: "private".into(), algorithm: "encrypted".into(), encrypted: true, format: format.into(), ..Default::default() },
    });
    r
}

fn public_result(mut r: DetectionResult, spki: &[u8], title: &str, format: &str) -> Res<DetectionResult> {
    let info = key_info_public(spki, format)?;
    r.kind = "public_key".into();
    r.title = title.into();
    r.format = format.into();
    r.summary = format!("{} {}-bit public key", info.algorithm, info.key_size);
    r.key = Some(info);
    Ok(r)
}

fn pbe_description(der: &[u8]) -> String {
    crate::pbe::parse_encrypted_pkcs8(der).map(|(alg, _)| crate::pbe::describe_algorithm(&alg)).unwrap_or_else(|_| "an unknown scheme".into())
}

fn certificates_result(mut r: DetectionResult, ders: Vec<Vec<u8>>, format: &str) -> Res<DetectionResult> {
    let ordered = x509::order_bundle(&ders);
    let certs = ordered.iter().map(|d| x509::parse_certificate(d)).collect::<Res<Vec<_>>>()?;
    r.warnings = chain_warnings(&certs, &ordered);
    if certs.len() == 1 {
        let c = &certs[0];
        r.kind = "certificate".into();
        r.title = "X.509 certificate".into();
        r.summary = format!(
            "{} — issued by {}, valid until {} ({} key){}",
            x509::cn_of(&c.subject),
            x509::cn_of(&c.issuer),
            c.valid_to,
            c.public_key_algorithm,
            if c.self_signed { ", self-signed" } else { "" }
        );
    } else {
        r.kind = "certificate_chain".into();
        r.title = format!("Certificate chain ({} certificates)", certs.len());
        r.summary = certs.iter().map(|c| x509::cn_of(&c.subject)).collect::<Vec<_>>().join(" → ");
    }
    r.format = format.into();
    r.certificates = certs;
    Ok(r)
}

fn examine_der(bytes: &[u8], password: Option<&str>, format: &str) -> Res<DetectionResult> {
    let mut r = base(bytes);
    if let Some(fmt) = keystore::detect(bytes) {
        let label = match fmt {
            keystore::Format::Pkcs12 => "PKCS#12".to_string(),
            keystore::Format::Bks | keystore::Format::Uber | keystore::Format::Bcfks => format!("Bouncy Castle {}", fmt.name()),
            other => other.name().to_string(),
        };
        r.kind = "keystore".into();
        r.title = format!("{label} keystore");
        r.format = fmt.name().into();
        r.keystore_format = Some(fmt.name().into());
        r.summary = "Open it from the Keystores page to view, edit or convert its entries.".into();
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            match keystore::decode(bytes, pw, &Default::default()) {
                Ok(store) => {
                    r.summary = format!("{} entries: {}", store.entries.len(), store.entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>().join(", "));
                    r.certificates = store.entries.iter().filter_map(|e| e.certificate_chain.first().cloned()).collect();
                    r.warnings.extend(store.notes);
                }
                Err(err) => r.warnings.push(err),
            }
        }
        return Ok(r);
    }
    if x509::exact_certificate(bytes).is_some() {
        // One certificate, or several back to back, or one with OpenSSL trust settings after it.
        let certs = x509::certificates_from_bytes(bytes)?;
        let mut res = certificates_result(r, certs, format)?;
        if x509::exact_certificate(bytes).is_some_and(|c| c.len() < bytes.len()) && res.certificates.len() == 1 {
            res.warnings.push("data follows the certificate (OpenSSL trust settings, or padding); it is not part of the certificate and is not shown".into());
        }
        return Ok(res);
    }
    if let Ok(csr) = x509::parse_csr(bytes) {
        r.kind = "csr".into();
        r.title = "Certificate signing request (PKCS#10)".into();
        r.format = format.into();
        let state = match (csr.signature_checked, csr.signature_valid) {
            (true, true) => "valid".to_string(),
            (true, false) => "INVALID".to_string(),
            (false, _) => format!("not checked ({} is not computed here)", csr.signature_algorithm),
        };
        r.summary = format!("{} — {} {}-bit key, signature {state}", csr.subject, csr.public_key_algorithm, csr.key_size);
        if csr.signature_checked && !csr.signature_valid {
            r.warnings.push("the request's self-signature does not verify; it was altered or corrupted".into());
        } else if !csr.signature_checked {
            r.warnings.push(format!("the request is signed with {}, which Keystore Studio cannot verify, so it cannot be signed here", csr.signature_algorithm));
        }
        r.csr = Some(csr);
        return Ok(r);
    }
    if let Ok(crl) = x509::parse_crl(bytes, None) {
        r.kind = "crl".into();
        r.title = "Certificate revocation list".into();
        r.format = format.into();
        r.summary = format!("Issued by {} — {} revoked, next update {}", x509::cn_of(&crl.issuer), crl.revoked_entries.len(), crl.next_update);
        r.crl = Some(crl);
        return Ok(r);
    }
    if let Ok(certs) = cms::certificates_from_pkcs7(bytes) {
        let verify = cms::verify(bytes, None, &[]).ok();
        let signed = verify.as_ref().is_some_and(|v| !v.signers.is_empty());
        if !signed && !certs.is_empty() {
            let mut res = certificates_result(r, certs, "PKCS#7 certificate bundle")?;
            res.kind = "pkcs7".into();
            res.title = format!("PKCS#7 bundle ({} certificates)", res.certificates.len());
            return Ok(res);
        }
        r.kind = "pkcs7".into();
        r.title = "CMS / PKCS#7 signed data".into();
        r.format = format.into();
        if let Some(v) = verify {
            r.summary = v.message.clone();
            r.certificates = v.certificates.clone();
        }
        return Ok(r);
    }
    // A Netscape certificate sequence or a PkiPath: certificates in an envelope of their own.
    if let Ok(certs) = convert::read_certificates(bytes) {
        return certificates_result(r, certs, format);
    }
    if let Ok(key) = PrivateKey::from_pkcs8_der(bytes) {
        return Ok(private_result(r, &key, "Private key (PKCS#8)", "PKCS#8", false));
    }
    if keys::is_encrypted_pkcs8(bytes) {
        return Ok(match password.filter(|p| !p.is_empty()).map(|pw| PrivateKey::from_bytes(bytes, Some(pw))) {
            Some(Ok(key)) => private_result(r, &key, "Encrypted private key (PKCS#8)", "encrypted PKCS#8", true),
            Some(Err(err)) => {
                let mut res = locked_key_result(r, "Encrypted private key (PKCS#8)", "encrypted PKCS#8", &pbe_description(bytes), None);
                res.warnings.push(err);
                res
            }
            None => locked_key_result(r, "Encrypted private key (PKCS#8)", "encrypted PKCS#8", &pbe_description(bytes), None),
        });
    }
    if let Some(label) = keys::traditional_label(bytes)
        && let Ok(key) = PrivateKey::from_bytes(bytes, None)
    {
        let fmt = traditional_format(label);
        return Ok(private_result(r, &key, &format!("Private key ({fmt})"), fmt, false));
    }
    if keys::split_spki(bytes).is_ok() && key_info_public(bytes, "SubjectPublicKeyInfo").is_ok() {
        return public_result(r, bytes, "Public key", "SubjectPublicKeyInfo");
    }
    if let Ok(key) = keys::rsa_public_from_pkcs1(bytes) {
        return public_result(r, &keys::rsa_spki(&key), "RSA public key (PKCS#1)", "PKCS#1");
    }
    r.kind = "unknown".into();
    r.title = "Unrecognised data".into();
    r.format = "binary".into();
    r.summary = "Not a certificate, CSR, CRL, PKCS#7, key or keystore that Keystore Studio recognises.".into();
    Ok(r)
}

/// "PKCS#1", "SEC1" or "DSA" for a traditional private key PEM label.
fn traditional_format(label: &str) -> &'static str {
    match label {
        "RSA PRIVATE KEY" => "PKCS#1",
        "EC PRIVATE KEY" => "SEC1",
        "DSA PRIVATE KEY" => "DSA",
        _ => "PKCS#8",
    }
}

pub fn examine(bytes: &[u8], password: Option<&str>) -> Res<DetectionResult> {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Err("nothing to examine — paste or open some data first".into());
    }
    if !looks_textual(bytes) {
        return examine_der(bytes, password, "DER (binary)");
    }
    let text = String::from_utf8_lossy(bytes).to_string();
    let trimmed = text.trim();
    let blocks = pem_blocks(trimmed);
    if !blocks.is_empty() {
        let mut r = base(bytes);
        let certs: Vec<Vec<u8>> = blocks.iter().filter(|b| b.tag.contains("CERTIFICATE") && !b.tag.contains("REQUEST")).map(|b| b.der.clone()).collect();
        let has_key = blocks.iter().any(|b| b.tag.contains("PRIVATE KEY"));
        if !certs.is_empty() && !has_key {
            return certificates_result(r, certs, "PEM");
        }
        let first = &blocks[0];
        match first.tag.as_str() {
            t if t.contains("PRIVATE KEY") => {
                let pw = password.filter(|p| !p.is_empty());
                let mut res = match t {
                    "OPENSSH PRIVATE KEY" => {
                        let envelope = openssh::Envelope::parse(&first.der)?;
                        let spki = openssh::spki_from_blob(envelope.public_blob).ok();
                        let protection = format!("{} (bcrypt, {} rounds)", envelope.cipher, envelope.rounds().unwrap_or(0));
                        match (envelope.is_encrypted(), pw) {
                            (false, _) => private_result(r, &PrivateKey::from_bytes(trimmed.as_bytes(), None)?, "OpenSSH private key", "OpenSSH", false),
                            (true, Some(pw)) => match PrivateKey::from_bytes(trimmed.as_bytes(), Some(pw)) {
                                Ok(key) => private_result(r, &key, "OpenSSH private key", "OpenSSH", true),
                                Err(err) => {
                                    let mut res = locked_key_result(r, "OpenSSH private key", "OpenSSH", &protection, spki.as_deref());
                                    res.warnings.push(err);
                                    res
                                }
                            },
                            (true, None) => locked_key_result(r, "OpenSSH private key", "OpenSSH", &protection, spki.as_deref()),
                        }
                    }
                    _ => {
                        let (title, fmt, protection) = match (t, first.legacy_encryption()) {
                            ("ENCRYPTED PRIVATE KEY", _) => ("Encrypted private key (PKCS#8)".to_string(), "encrypted PKCS#8", Some(pbe_description(&first.der))),
                            (t, Some(dek)) => {
                                let fmt = traditional_format(t);
                                (format!("Encrypted private key ({fmt})"), fmt, Some(format!("{} (OpenSSL traditional encryption)", dek.split(',').next().unwrap_or(dek))))
                            }
                            (t, None) => {
                                let fmt = if t == "PRIVATE KEY" || t == "ANY PRIVATE KEY" { "PKCS#8" } else { traditional_format(t) };
                                (format!("Private key ({fmt})"), fmt, None)
                            }
                        };
                        match (protection, pw) {
                            (None, _) => private_result(r, &PrivateKey::from_bytes(trimmed.as_bytes(), None)?, &title, fmt, false),
                            (Some(protection), None) => locked_key_result(r, &title, fmt, &protection, None),
                            (Some(protection), Some(pw)) => match PrivateKey::from_bytes(trimmed.as_bytes(), Some(pw)) {
                                Ok(key) => private_result(r, &key, &title, fmt, true),
                                Err(err) => {
                                    let mut res = locked_key_result(r, &title, fmt, &protection, None);
                                    res.warnings.push(err);
                                    res
                                }
                            },
                        }
                    }
                };
                res.format = format!("PEM ({})", res.format);
                if !certs.is_empty() {
                    res.certificates = certs.iter().filter_map(|d| x509::parse_certificate(d).ok()).collect();
                    if let Ok(key) = PrivateKey::from_bytes(trimmed.as_bytes(), pw) {
                        let matches = certs.iter().any(|c| x509::cert_summary(c).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false));
                        res.summary.push_str(if matches { " — matches the included certificate" } else { " — does NOT match the included certificate(s)" });
                    }
                }
                return Ok(res);
            }
            "PUBLIC KEY" | "RSA PUBLIC KEY" => {
                let spki = keys::public_key_from_bytes(trimmed.as_bytes())?;
                let info = key_info_public(&spki, if first.tag == "RSA PUBLIC KEY" { "PKCS#1" } else { "SubjectPublicKeyInfo" })?;
                r.kind = "public_key".into();
                r.title = "Public key".into();
                r.format = "PEM".into();
                r.summary = format!("{} {}-bit public key", info.algorithm, info.key_size);
                r.key = Some(info);
                return Ok(r);
            }
            "DH PARAMETERS" => {
                let bits = yasna::parse_der(&first.der, |r| {
                    r.read_sequence(|r| {
                        let (p, _) = r.next().read_bigint_bytes()?;
                        r.next().read_der()?;
                        Ok(p)
                    })
                })
                .map(|p| trim_leading_zeros(&p).len() * 8)
                .unwrap_or(0);
                r.kind = "dh_params".into();
                r.title = "Diffie-Hellman parameters (PKCS#3)".into();
                r.format = "PEM".into();
                r.summary = format!("{bits}-bit prime modulus");
                if bits < 2048 {
                    r.warnings.push("DH groups smaller than 2048 bits are considered weak".into());
                }
                return Ok(r);
            }
            _ => {
                let mut res = examine_der(&first.der, password, "PEM")?;
                res.sha256 = r.sha256;
                res.byte_length = r.byte_length;
                return Ok(res);
            }
        }
    }
    // JWT
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() == 3 && !trimmed.contains(char::is_whitespace) && parts[0].starts_with("eyJ") {
        let info = jwt::decode(trimmed)?;
        let mut r = base(bytes);
        r.kind = "jwt".into();
        r.title = "JSON Web Token".into();
        r.format = "JWS compact serialization".into();
        r.summary = format!(
            "{} token{}{}",
            info.algorithm,
            info.key_id.as_deref().map(|k| format!(", key ID '{k}'")).unwrap_or_default(),
            info.expires_at.as_deref().map(|x| format!(", expires {x}")).unwrap_or_default()
        );
        if info.expired == Some(true) {
            r.warnings.push("this token has expired".into());
        }
        if info.algorithm == "none" {
            r.warnings.push("unsigned token (alg \"none\")".into());
        }
        r.jwt = Some(info);
        return Ok(r);
    }
    // RFC 4716 ("---- BEGIN SSH2 PUBLIC KEY ----"), as PuTTYgen and commercial SSH write it.
    if openssh::looks_like_ssh2_public_key(trimmed) {
        let (blob, comment) = openssh::parse_ssh2_public_key(trimmed)?;
        let mut res = public_result(base(bytes), &openssh::spki_from_blob(&blob)?, "SSH2 public key (RFC 4716)", "RFC 4716")?;
        if !comment.is_empty() {
            res.summary.push_str(&format!(" — {comment}"));
        }
        return Ok(res);
    }
    // OpenSSH public key line, or an OpenSSH certificate.
    if let Some(line) = trimmed.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let Some(kind) = words.iter().find(|w| w.starts_with("ssh-") || w.starts_with("ecdsa-sha2-") || w.starts_with("sk-")) {
            let fp = words
                .iter()
                .skip_while(|w| *w != kind)
                .nth(1)
                .and_then(|b| unb64(b).ok())
                .map(|blob| format!("SHA256:{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, sha256(&blob))));
            if kind.contains("-cert-v01@openssh.com") {
                let mut r = base(bytes);
                r.kind = "public_key".into();
                r.title = "OpenSSH certificate".into();
                r.format = "OpenSSH".into();
                r.summary = format!("{kind} — an OpenSSH certificate, which is not X.509. Inspect it with ssh-keygen -L -f <file>.");
                return Ok(r);
            }
            return Ok(match openssh::spki_from_line(line) {
                Ok((spki, comment)) => {
                    let mut res = public_result(base(bytes), &spki, "OpenSSH public key", "OpenSSH")?;
                    if let Some(fp) = &fp {
                        res.summary.push_str(&format!(", fingerprint {fp}"));
                    }
                    if !comment.is_empty() {
                        res.summary.push_str(&format!(" — {comment}"));
                    }
                    res
                }
                Err(err) => {
                    let mut r = base(bytes);
                    r.kind = "public_key".into();
                    r.title = "OpenSSH public key".into();
                    r.format = "OpenSSH".into();
                    r.summary = format!("{kind} key{}", fp.as_ref().map(|f| format!(", fingerprint {f}")).unwrap_or_default());
                    r.warnings.push(err);
                    r.key = Some(KeyInfo { kind: "public".into(), algorithm: kind.to_string(), format: "OpenSSH".into(), public_key_sha256: fp, ..Default::default() });
                    r
                }
            });
        }
    }
    // JSON Web Key, or a JWK set.
    if trimmed.starts_with('{') && serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        if let Ok(key) = PrivateKey::from_jwk(trimmed) {
            let mut res = private_result(base(bytes), &key, "JSON Web Key (private)", "JWK", false);
            res.format = "JWK".into();
            return Ok(res);
        }
        let (spki, _) = convert::spki_from_any(trimmed.as_bytes(), None)?;
        return public_result(base(bytes), &spki, "JSON Web Key (public)", "JWK");
    }
    // Bare base64 of DER
    if let Ok(der) = unb64(trimmed)
        && !der.is_empty()
    {
        let mut r = examine_der(&der, password, "Base64 (DER)")?;
        r.sha256 = colon_hex(&sha256(&der));
        return Ok(r);
    }
    let mut r = base(bytes);
    r.kind = "unknown".into();
    r.title = "Unrecognised text".into();
    r.format = "text".into();
    r.summary = "Expected PEM (-----BEGIN …-----), a JWT, a JWK, an OpenSSH or SSH2 public key, or base64-encoded DER.".into();
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The UI lists a PKCS#7 file on the Certificates page only when it is a certificates-only
    /// bundle (`isCertificateBundle` in src/lib/certificates.ts matches this format); CMS signed
    /// data, which also carries certificates, stays in Examine.
    #[test]
    fn tells_a_pkcs7_bundle_from_a_signature() {
        let input = crate::model::GenerateKeyPairInput {
            alias: "p7".into(),
            algorithm: "ECDSA".into(),
            key_size: 0,
            curve: Some("P-256".into()),
            signature_hash: None,
            subject_dn: "CN=detect.example".into(),
            common_name: String::new(),
            organization: String::new(),
            organizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            email: String::new(),
            validity_days: 10,
            is_ca: false,
            path_len: None,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            labels: vec![],
            not_before: String::new(),
            not_after: String::new(),
            crl_distribution_points: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
        };
        let e = crate::ops::generate_key_pair(&input, None).unwrap();
        let der = pem::parse(e.certificate_chain[0].pem.as_bytes()).unwrap().contents().to_vec();

        let bundle = examine(&cms::certs_only(std::slice::from_ref(&der)), None).unwrap();
        assert_eq!((bundle.kind.as_str(), bundle.format.as_str(), bundle.certificates.len()), ("pkcs7", "PKCS#7 certificate bundle", 1));
        let pem_bundle = examine(to_pem("PKCS7", &cms::certs_only(std::slice::from_ref(&der))).as_bytes(), None).unwrap();
        assert_eq!(pem_bundle.format, "PKCS#7 certificate bundle");

        let key = PrivateKey::from_bytes(e.private_key_pem.as_ref().unwrap().as_bytes(), None).unwrap();
        let signed = examine(&cms::sign(b"hello", &key, std::slice::from_ref(&der), false).unwrap(), None).unwrap();
        assert_eq!(signed.kind, "pkcs7");
        assert_ne!(signed.format, "PKCS#7 certificate bundle");
        assert!(!signed.certificates.is_empty(), "a signature carries its signer's certificate");
    }

    #[test]
    fn encrypted_and_unusual_keys_are_described_not_refused() {
        let e = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        let pem = e.private_key_pem.clone().unwrap();
        let spki_sha = |r: &DetectionResult| r.key.as_ref().and_then(|k| k.public_key_sha256.clone());
        let plain = examine(pem.as_bytes(), None).unwrap();
        assert!(plain.warnings.iter().any(|w| w.contains("not encrypted")));

        // OpenSSH, encrypted: described without the password, opened with it.
        let ssh = crate::convert::private_key(pem.as_bytes(), None, "openssh", Some("pw-1"), "c").unwrap().bytes;
        let locked = examine(&ssh, None).unwrap();
        let info = locked.key.as_ref().unwrap();
        assert!(info.encrypted && info.algorithm == "ECDSA", "{info:?}");
        assert!(locked.summary.contains("aes256-ctr"), "{}", locked.summary);
        assert_eq!(spki_sha(&locked), spki_sha(&plain), "the public key is known without the password");
        assert!(!locked.warnings.iter().any(|w| w.contains("not encrypted")));
        let opened = examine(&ssh, Some("pw-1")).unwrap();
        assert!(opened.summary.contains("decrypted"), "{}", opened.summary);
        assert!(!examine(&ssh, Some("wrong")).unwrap().warnings.is_empty());

        // Encrypted PKCS#8 as DER, and a SEC1 key as DER.
        let enc = crate::convert::private_key(pem.as_bytes(), None, "pkcs8_encrypted_der", Some("pw-2"), "").unwrap().bytes;
        let r = examine(&enc, None).unwrap();
        assert!(r.key.as_ref().unwrap().encrypted && r.summary.contains("PBES2"), "{}", r.summary);
        let sec1 = crate::convert::private_key(pem.as_bytes(), None, "traditional_der", None, "").unwrap().bytes;
        assert_eq!(examine(&sec1, None).unwrap().format, "SEC1");

        // JWK, private and public; RFC 4716.
        let jwk = String::from_utf8(crate::convert::private_key(pem.as_bytes(), None, "jwk", None, "").unwrap().bytes).unwrap();
        assert_eq!(examine(jwk.as_bytes(), None).unwrap().kind, "private_key");
        let public_jwk = crate::convert::public_key(pem.as_bytes(), None, "jwk", "").unwrap().bytes;
        assert_eq!(spki_sha(&examine(&public_jwk, None).unwrap()), spki_sha(&plain));
        let ssh2 = crate::convert::public_key(pem.as_bytes(), None, "ssh2", "a comment").unwrap().bytes;
        let r = examine(&ssh2, None).unwrap();
        assert_eq!((r.kind.as_str(), r.format.as_str()), ("public_key", "RFC 4716"));
        assert_eq!(spki_sha(&r), spki_sha(&plain));

        // An OpenSSH certificate is named, not mistaken for a key.
        let cert = examine(b"ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAA host", None).unwrap();
        assert_eq!(cert.title, "OpenSSH certificate");
    }

    #[test]
    fn certificate_containers_without_pem_are_recognised() {
        let ca = crate::ops::generate_key_pair(&crate::ops::tests_support::input("ca", "ECDSA", true), None).unwrap();
        let leaf = crate::ops::generate_key_pair(&crate::ops::tests_support::input("leaf", "ECDSA", false), Some(&ca)).unwrap();
        let chain = crate::entry::chain_der(&leaf).unwrap();
        assert_eq!(examine(&chain.concat(), None).unwrap().certificates.len(), 2, "certificates back to back");
        let pkipath = crate::convert::certificates(&chain.iter().map(|c| to_pem("CERTIFICATE", c)).collect::<String>().into_bytes(), "pkipath", true).unwrap().bytes;
        assert_eq!(examine(&pkipath, None).unwrap().certificates.len(), 2, "PkiPath");
        let nseq = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&yasna::models::ObjectIdentifier::from_slice(&[2, 16, 840, 1, 113730, 2, 5]));
                w.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_sequence(|w| {
                        for c in &chain {
                            w.next().write_der(c);
                        }
                    })
                });
            })
        });
        assert_eq!(examine(&nseq, None).unwrap().certificates.len(), 2, "Netscape certificate sequence");
        // A keystore of each Bouncy Castle format is named for what it is.
        for (format, name) in [(keystore::Format::Bks, "BKS"), (keystore::Format::Uber, "UBER"), (keystore::Format::Bcfks, "BCFKS")] {
            let bytes = keystore::encode(std::slice::from_ref(&leaf), "pw123456", format).unwrap();
            let r = examine(&bytes, Some("pw123456")).unwrap();
            assert_eq!((r.kind.as_str(), r.keystore_format.as_deref()), ("keystore", Some(name)));
            assert!(r.summary.starts_with("1 entries"), "{}", r.summary);
        }
    }

    #[test]
    fn detects_common_inputs() {
        let input = crate::model::GenerateKeyPairInput {
            alias: "d".into(),
            algorithm: "ECDSA".into(),
            key_size: 0,
            curve: Some("P-256".into()),
            signature_hash: None,
            subject_dn: "CN=detect.example".into(),
            common_name: String::new(),
            organization: String::new(),
            organizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            email: String::new(),
            validity_days: 10,
            is_ca: false,
            path_len: None,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            labels: vec![],
            not_before: String::new(),
            not_after: String::new(),
            crl_distribution_points: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
        };
        let e = crate::ops::generate_key_pair(&input, None).unwrap();
        let cert = examine(e.certificate_chain[0].pem.as_bytes(), None).unwrap();
        assert_eq!(cert.kind, "certificate");
        let key = examine(e.private_key_pem.as_ref().unwrap().as_bytes(), None).unwrap();
        assert_eq!(key.kind, "private_key");
        assert_eq!(key.key.unwrap().algorithm, "ECDSA");
        let der = pem::parse(e.certificate_chain[0].pem.as_bytes()).unwrap().contents().to_vec();
        assert_eq!(examine(&der, None).unwrap().kind, "certificate");
        let csr = crate::ops::generate_csr(&e, &crate::model::CsrOptions { subject_dn: None, sans: None, signature_hash: None }).unwrap();
        let r = examine(csr.csr_pem.as_bytes(), None).unwrap();
        assert_eq!(r.kind, "csr");
        assert!(r.csr.unwrap().signature_valid);
        let token = crate::jwt::sign(&crate::jwt::JwtClaims { issuer: "a", subject: "b", audience: "", validity_minutes: 1, custom_claims_json: "" }, &e, None).unwrap();
        assert_eq!(examine(token.as_bytes(), None).unwrap().kind, "jwt");
        assert_eq!(examine(b"hello there", None).unwrap().kind, "unknown");
        assert!(examine(b"   ", None).is_err());
    }
}
