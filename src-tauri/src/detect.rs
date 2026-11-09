//! "Examine" engine: identifies and decodes arbitrary cryptographic input (PEM, DER, base64,
//! JWT, OpenSSH keys, keystores) into a [`DetectionResult`].

use crate::keys::{self, PrivateKey};
use crate::model::{DetectionResult, KeyInfo};
use crate::util::*;
use crate::{cms, jwt, keystore, x509};

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
        r.kind = "keystore".into();
        r.title = format!("{} keystore", fmt.name());
        r.format = fmt.name().into();
        r.keystore_format = Some(fmt.name().into());
        r.summary = "Open it from the Keystores page to view and edit its entries.".into();
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            match keystore::decode(bytes, pw, &Default::default()) {
                Ok((_, entries)) => {
                    r.summary = format!("{} entries: {}", entries.len(), entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>().join(", "));
                    r.certificates = entries.iter().filter_map(|e| e.certificate_chain.first().cloned()).collect();
                }
                Err(err) => r.warnings.push(err),
            }
        }
        return Ok(r);
    }
    if keystore::looks_like_bks_v2(bytes) {
        r.kind = "keystore".into();
        r.title = "BKS keystore".into();
        r.format = "BKS".into();
        r.keystore_format = Some("BKS".into());
        r.summary = "Bouncy Castle BKS v2 keystore (read-only). Open it from the Keystores page to inspect or convert to PKCS#12.".into();
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            match keystore::decode(bytes, pw, &Default::default()) {
                Ok((_, entries)) => {
                    r.summary = format!("{} entries: {}", entries.len(), entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>().join(", "));
                    r.certificates = entries.iter().filter_map(|e| e.certificate_chain.first().cloned()).collect();
                }
                Err(err) => r.warnings.push(err),
            }
        }
        return Ok(r);
    }
    if let Some(kind) = keystore::detect_unsupported(bytes) {
        let hint = kind.conversion_hint("your-keystore");
        r.kind = "keystore".into();
        r.title = format!("Bouncy Castle {} keystore", kind.name());
        r.format = kind.store_type().into();
        r.keystore_format = Some(kind.store_type().into());
        r.summary = format!("Bouncy Castle {} keystore (unsupported). {hint}", kind.name());
        r.warnings.push(hint);
        return Ok(r);
    }
    if x509_parser::parse_x509_certificate(bytes).is_ok() {
        return certificates_result(r, vec![bytes.to_vec()], format);
    }
    if let Ok(csr) = x509::parse_csr(bytes) {
        r.kind = "csr".into();
        r.title = "Certificate signing request (PKCS#10)".into();
        r.format = format.into();
        r.summary = format!("{} — {} {}-bit key, signature {}", csr.subject, csr.public_key_algorithm, csr.key_size, if csr.signature_valid { "valid" } else { "INVALID" });
        if !csr.signature_valid {
            r.warnings.push("the request's self-signature does not verify; it was altered or corrupted".into());
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
    if let Ok(key) = PrivateKey::from_pkcs8_der(bytes) {
        r.kind = "private_key".into();
        r.title = "Private key (PKCS#8)".into();
        r.format = format.into();
        r.summary = format!("{} {}-bit private key", key.algorithm(), key.key_size());
        r.warnings.push("this private key is not encrypted".into());
        r.key = Some(key_info_private(&key, "PKCS#8"));
        return Ok(r);
    }
    if keys::split_spki(bytes).is_ok()
        && let Ok(info) = key_info_public(bytes, "SubjectPublicKeyInfo")
    {
        r.kind = "public_key".into();
        r.title = "Public key".into();
        r.format = format.into();
        r.summary = format!("{} {}-bit public key", info.algorithm, info.key_size);
        r.key = Some(info);
        return Ok(r);
    }
    r.kind = "unknown".into();
    r.title = "Unrecognised data".into();
    r.format = "binary".into();
    r.summary = "Not a certificate, CSR, CRL, PKCS#7, key or keystore that xkeystore recognises.".into();
    Ok(r)
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
                r.kind = "private_key".into();
                if t == "ENCRYPTED PRIVATE KEY" {
                    r.title = "Encrypted private key (PKCS#8)".into();
                    r.format = "PEM (encrypted PKCS#8)".into();
                    match password.filter(|p| !p.is_empty()) {
                        Some(pw) => {
                            let key = PrivateKey::from_bytes(trimmed.as_bytes(), Some(pw))?;
                            r.summary = format!("{} {}-bit private key (decrypted with the supplied password)", key.algorithm(), key.key_size());
                            let mut info = key_info_private(&key, "PKCS#8");
                            info.encrypted = true;
                            r.key = Some(info);
                        }
                        None => {
                            let alg = yasna::parse_der(&first.der, |r| {
                                r.read_sequence(|r| {
                                    let a = crate::pbe::read_algorithm_id(r.next())?;
                                    r.next().read_der()?;
                                    Ok(a)
                                })
                            })
                            .ok();
                            r.summary =
                                format!("Protected with {}. Enter its password to inspect the key.", alg.as_ref().map(crate::pbe::describe_algorithm).unwrap_or_else(|| "an unknown scheme".into()));
                            r.key = Some(KeyInfo { kind: "private".into(), algorithm: "encrypted".into(), encrypted: true, format: "PKCS#8".into(), ..Default::default() });
                        }
                    }
                } else {
                    let key = PrivateKey::from_bytes(trimmed.as_bytes(), password)?;
                    let fmt = match t {
                        "RSA PRIVATE KEY" => "PKCS#1",
                        "EC PRIVATE KEY" => "SEC1",
                        _ => "PKCS#8",
                    };
                    r.title = format!("Private key ({fmt})");
                    r.format = format!("PEM ({fmt})");
                    r.summary = format!("{} {}-bit private key", key.algorithm(), key.key_size());
                    r.warnings.push("this private key is not encrypted".into());
                    r.key = Some(key_info_private(&key, fmt));
                }
                if !certs.is_empty() {
                    r.certificates = certs.iter().filter_map(|d| x509::parse_certificate(d).ok()).collect();
                    if let (Ok(key), Some(leaf)) = (PrivateKey::from_bytes(trimmed.as_bytes(), password), certs.first()) {
                        let matches = certs.iter().any(|c| x509::cert_summary(c).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false));
                        let _ = leaf;
                        r.summary.push_str(if matches { " — matches the included certificate" } else { " — does NOT match the included certificate(s)" });
                    }
                }
                return Ok(r);
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
    // OpenSSH public key line
    if let Some((kind, rest)) = trimmed.split_once(' ')
        && (kind.starts_with("ssh-") || kind.starts_with("ecdsa-sha2-"))
    {
        let blob = unb64(rest.split_whitespace().next().unwrap_or(""))?;
        let mut r = base(bytes);
        r.kind = "public_key".into();
        r.title = "OpenSSH public key".into();
        r.format = "OpenSSH".into();
        let fp = format!("SHA256:{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, sha256(&blob)));
        r.summary = format!("{kind} key, fingerprint {fp}");
        r.key = Some(KeyInfo { kind: "public".into(), algorithm: kind.into(), format: "OpenSSH".into(), public_key_sha256: Some(fp), ..Default::default() });
        return Ok(r);
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
    r.summary = "Expected PEM (-----BEGIN …-----), a JWT, an OpenSSH public key or base64-encoded DER.".into();
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
