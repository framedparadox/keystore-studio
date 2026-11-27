//! Exporting entries to files in standard formats.

use crate::entry;
use crate::keys;
use crate::model::{ExportResult, KeystoreEntry, KeystoreFile};
use crate::util::*;
use crate::{cms, pbe, pkcs12};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use std::path::Path;

/// Target identifiers accepted by [`export_entry`], with their default file extensions.
pub const TARGETS: &[(&str, &str)] = &[
    ("cert_pem", "pem"),
    ("cert_der", "cer"),
    ("cert_b64_cer", "cer"),
    ("chain_pem", "pem"),
    ("pkcs7_pem", "p7b"),
    ("pkcs7_der", "p7b"),
    ("pkcs7_spc", "spc"),
    ("pkipath", "pkipath"),
    ("public_pem", "pem"),
    ("public_openssh", "pub"),
    ("public_ssh2", "pub"),
    ("public_jwk", "jwk.json"),
    ("private_pkcs8_pem", "key"),
    ("private_traditional", "key"),
    ("private_pkcs8_encrypted", "key"),
    ("private_openssh", "key"),
    ("private_jwk", "jwk.json"),
    ("pkcs12", "p12"),
    ("secret_hex", "txt"),
    ("secret_jwk", "jwk.json"),
];

fn spki_of(e: &KeystoreEntry) -> Res<Vec<u8>> {
    let pem_text = e.public_key_pem.as_deref().ok_or_else(|| format!("'{}' has no public key", e.alias))?;
    Ok(pem::parse(pem_text.as_bytes()).map_err(|err| err.to_string())?.contents().to_vec())
}

fn with_kid(mut jwk: serde_json::Value, alias: &str) -> serde_json::Value {
    if let Some(obj) = jwk.as_object_mut() {
        obj.insert("kid".into(), alias.into());
    }
    jwk
}

/// Builds the export payload; returns (bytes, is_text, format description).
pub fn render(e: &KeystoreEntry, target: &str, password: Option<&str>) -> Res<(Vec<u8>, bool, String)> {
    let chain = || -> Res<Vec<Vec<u8>>> {
        let c = entry::chain_der(e)?;
        if c.is_empty() {
            return Err(format!("'{}' has no certificate", e.alias));
        }
        Ok(c)
    };
    let need_password = || -> Res<&str> { password.filter(|p| !p.is_empty()).ok_or_else(|| "a password is required for this export".to_string()) };
    Ok(match target {
        "cert_pem" => (to_pem("CERTIFICATE", &chain()?[0]).into_bytes(), true, "X.509 certificate (PEM)".into()),
        "cert_der" => (chain()?[0].clone(), false, "X.509 certificate (DER)".into()),
        // Windows' "Base-64 encoded X.509 (.CER)": the PEM text under a .cer name.
        "cert_b64_cer" => (to_pem("CERTIFICATE", &chain()?[0]).into_bytes(), true, "X.509 certificate (Base-64 .cer)".into()),
        "chain_pem" => (chain()?.iter().map(|c| to_pem("CERTIFICATE", c)).collect::<String>().into_bytes(), true, "Certificate chain (PEM)".into()),
        "pkcs7_pem" => (to_pem("PKCS7", &cms::certs_only(&chain()?)).into_bytes(), true, "PKCS#7 certificate bundle (PEM)".into()),
        "pkcs7_der" => (cms::certs_only(&chain()?), false, "PKCS#7 certificate bundle (DER)".into()),
        // Authenticode's Software Publisher Certificate: a DER certs-only PKCS#7 under a .spc name.
        "pkcs7_spc" => (cms::certs_only(&chain()?), false, "Software Publisher Certificate (SPC)".into()),
        "pkipath" => {
            // PkiPath (RFC 6066/Java): SEQUENCE OF Certificate ordered from the trust anchor down.
            let mut certs = chain()?;
            certs.reverse();
            let der = yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    for c in &certs {
                        w.next().write_der(c);
                    }
                })
            });
            (der, false, "PkiPath (DER)".into())
        }
        "public_pem" => (to_pem("PUBLIC KEY", &spki_of(e)?).into_bytes(), true, "Public key (SubjectPublicKeyInfo PEM)".into()),
        "public_openssh" => {
            let (line, _) = keys::openssh_public_key(&spki_of(e)?, &e.alias)?;
            (format!("{line}\n").into_bytes(), true, "OpenSSH public key".into())
        }
        "public_ssh2" => {
            let (_, blob) = keys::openssh_public_blob(&spki_of(e)?)?;
            (crate::openssh::format_ssh2_public_key(&blob, &e.alias).into_bytes(), true, "SSH2 public key (RFC 4716)".into())
        }
        "public_jwk" => {
            let jwk = with_kid(keys::public_jwk_from_spki(&spki_of(e)?)?, &e.alias);
            (serde_json::to_string_pretty(&jwk).unwrap().into_bytes(), true, "JSON Web Key (public)".into())
        }
        "private_pkcs8_pem" => (to_pem("PRIVATE KEY", &entry::private_key_der(e)?).into_bytes(), true, "Private key (unencrypted PKCS#8 PEM)".into()),
        "private_traditional" => (entry::private_key(e)?.to_traditional_pem()?.into_bytes(), true, "Private key (PKCS#1 or SEC1 PEM)".into()),
        "private_pkcs8_encrypted" => {
            let der = pbe::encrypt_pkcs8(need_password()?, &entry::private_key_der(e)?, pbe::DEFAULT_ITERATIONS)?;
            (to_pem("ENCRYPTED PRIVATE KEY", &der).into_bytes(), true, "Private key (encrypted PKCS#8, AES-256)".into())
        }
        // Encrypted with aes256-ctr and bcrypt when a password is given, as ssh-keygen does.
        "private_openssh" => {
            let text = crate::openssh::encode_private_key(&entry::private_key(e)?, &e.alias, password.filter(|p| !p.is_empty()))?;
            (text.into_bytes(), true, if password.is_some_and(|p| !p.is_empty()) { "OpenSSH private key (encrypted)" } else { "OpenSSH private key" }.into())
        }
        "private_jwk" => {
            let jwk = with_kid(entry::private_key(e)?.private_jwk()?, &e.alias);
            (serde_json::to_string_pretty(&jwk).unwrap().into_bytes(), true, "JSON Web Key (private)".into())
        }
        "pkcs12" => (pkcs12::encode(std::slice::from_ref(e), need_password()?)?, false, "PKCS#12 (single entry)".into()),
        "secret_hex" => (format!("{}\n", e.secret_key_hex.clone().ok_or("not a secret key entry")?).into_bytes(), true, "Secret key (hex)".into()),
        "secret_jwk" => {
            let jwk = serde_json::json!({ "kty": "oct", "kid": e.alias, "k": B64URL.encode(entry::secret_bytes(e)?) });
            (serde_json::to_string_pretty(&jwk).unwrap().into_bytes(), true, "JSON Web Key (symmetric)".into())
        }
        other => return Err(format!("unknown export format '{other}'")),
    })
}

pub fn export_entry(e: &KeystoreEntry, target: &str, path: &str, password: Option<&str>) -> Res<ExportResult> {
    let (bytes, is_text, format) = render(e, target, password)?;
    write_atomic(Path::new(path), &bytes)?;
    let text = if is_text && !target.starts_with("private") && !target.starts_with("secret") { Some(String::from_utf8_lossy(&bytes).to_string()) } else { None };
    Ok(ExportResult { path: path.to_string(), format, byte_length: bytes.len(), text })
}

fn csv_field(s: &str) -> String {
    // Quote every field; neutralise spreadsheet formula injection (OWASP: a leading = + - @, and a
    // leading tab or carriage return, which some spreadsheets strip before evaluating the rest).
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn inventory_csv(ks: &KeystoreFile) -> String {
    let mut out = String::from(
        "Alias,Type,Algorithm,Key size,Curve,Subject,Issuer,Serial,Created,Expires,Days remaining,SHA-256 fingerprint,SPKI SHA-256,Chain length,Locked,EKU,Weak,Findings,Labels,Path,Format\n",
    );
    let now = now_ts();
    for e in &ks.entries {
        let days = e.certificate_chain.first().map(|c| ((c.not_after - now).div_euclid(86_400)).to_string()).unwrap_or_default();
        let row = [
            e.alias.clone(),
            e.entry_type.clone(),
            e.algorithm.clone(),
            e.key_size.to_string(),
            e.curve.clone().unwrap_or_default(),
            e.subject.clone(),
            e.issuer.clone(),
            e.serial_number.clone(),
            e.creation_date.clone(),
            e.expiry_date.clone(),
            days,
            e.sha256_fingerprint.clone(),
            e.certificate_chain.first().map(|c| c.spki_sha256.clone()).unwrap_or_default(),
            e.chain_length.to_string(),
            if e.locked { "yes".into() } else { "no".into() },
            e.certificate_chain.first().map(|c| c.extended_key_usage.join("; ")).unwrap_or_default(),
            if e.is_weak { "yes".into() } else { "no".into() },
            e.weak_reasons.join("; "),
            e.labels.join("; "),
            ks.path.clone(),
            ks.format.clone(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_renders_for_a_key_pair() {
        let input = crate::model::GenerateKeyPairInput {
            alias: "exp".into(),
            algorithm: "RSA".into(),
            key_size: 2048,
            curve: None,
            signature_hash: None,
            subject_dn: "CN=export.example".into(),
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
        for (target, _) in TARGETS.iter().filter(|(t, _)| !t.starts_with("secret")) {
            let r = render(&e, target, Some("pw"));
            assert!(r.is_ok(), "{target}: {:?}", r.err());
        }
        let csv = inventory_csv(&KeystoreFile { entries: vec![e], ..Default::default() });
        assert!(csv.lines().count() == 2);
        assert_eq!(csv_field("=cmd()"), "\"'=cmd()\"");
    }

    #[test]
    fn csv_fields_cannot_start_a_formula() {
        for raw in ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1+1", "\r=1+1"] {
            assert!(csv_field(raw).starts_with("\"'"), "{raw:?} was not neutralised");
        }
        assert_eq!(csv_field("plain \"quoted\""), "\"plain \"\"quoted\"\"\"");
        assert_eq!(csv_field("CN=a, O=b"), "\"CN=a, O=b\"");
    }
}
