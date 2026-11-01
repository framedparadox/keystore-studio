//! "Import & classify": figure out what a dropped-in file actually is
//! (certificate, key, CSR, PKCS#12, JKS, or an encrypted blob that needs a
//! password first) and pair orphan keys with the certificates they belong
//! to — the triage step the mockup's Import screen shows as a "needs your
//! input" queue instead of a cryptic parser error.

use x509_parser::prelude::FromDer;

use crate::error::Result;
use crate::jks;
use crate::keys::KeyMaterial;
use crate::pem;
use crate::pkcs12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedKind {
    PemBundle,
    Pkcs12,
    Jks,
    DerCertificate,
    DerPrivateKey,
    DerCsr,
    Unknown,
}

const JKS_MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
/// JKS files produced by old Sun/Oracle tooling with the JCEKS provider
/// share the same outer structure but a different magic number.
const JCEKS_MAGIC: [u8; 4] = [0xCE, 0xCE, 0xCE, 0xCE];

/// Cheap, non-destructive classification: enough to know what question to
/// ask the user next (a password? which role for this ambiguous cert?)
/// without yet committing to a parse that might fail.
pub fn detect_kind(bytes: &[u8]) -> DetectedKind {
    if bytes.len() >= 4 && (bytes[0..4] == JKS_MAGIC || bytes[0..4] == JCEKS_MAGIC) {
        return DetectedKind::Jks;
    }
    if looks_like_pem(bytes) {
        return DetectedKind::PemBundle;
    }
    if bytes.first() != Some(&0x30) {
        return DetectedKind::Unknown;
    }
    // Everything past this point is *some* DER SEQUENCE; disambiguate by
    // trying the most specific parse first.
    if x509_parser::parse_x509_certificate(bytes).is_ok() {
        return DetectedKind::DerCertificate;
    }
    if x509_parser::certification_request::X509CertificationRequest::from_der(bytes).is_ok() {
        return DetectedKind::DerCsr;
    }
    if rcgen::KeyPair::try_from(bytes).is_ok() {
        return DetectedKind::DerPrivateKey;
    }
    // A PKCS#12 file is also a DER SEQUENCE (PFX), and we cannot tell it
    // apart from "some other DER blob" without a password to decrypt it,
    // so it is the fallback rather than a positive match.
    DetectedKind::Pkcs12
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    let probe_len = bytes.len().min(256);
    std::str::from_utf8(&bytes[..probe_len])
        .map(|s| s.contains("-----BEGIN"))
        .unwrap_or(false)
}

/// One file, after classification/decryption, broken into whatever
/// certificates and keys it actually contained.
pub struct ClassifiedFile {
    pub kind: DetectedKind,
    pub keys: Vec<KeyMaterial>,
    /// DER.
    pub certs: Vec<Vec<u8>>,
    /// Set when `kind` is `Pkcs12` or `Jks` and no password was supplied
    /// yet (or the supplied one was wrong) — the caller should prompt.
    pub needs_password: bool,
}

/// Attempt to fully parse `bytes`, given a password to try on anything
/// encrypted. Pass `password = None` to only classify unencrypted content
/// and detect (without yet unlocking) anything that needs a password.
pub fn classify(bytes: &[u8], password: Option<&str>) -> Result<ClassifiedFile> {
    let kind = detect_kind(bytes);
    match kind {
        DetectedKind::PemBundle => {
            let text = String::from_utf8_lossy(bytes);
            let parsed = pem::import_any(&text)?;
            Ok(ClassifiedFile {
                kind,
                keys: parsed.keys,
                certs: parsed.certs,
                needs_password: false,
            })
        }
        DetectedKind::DerCertificate => Ok(ClassifiedFile {
            kind,
            keys: vec![],
            certs: vec![bytes.to_vec()],
            needs_password: false,
        }),
        DetectedKind::DerPrivateKey => Ok(ClassifiedFile {
            kind,
            keys: vec![KeyMaterial::from_pkcs8_der_autodetect(bytes)?],
            certs: vec![],
            needs_password: false,
        }),
        DetectedKind::DerCsr | DetectedKind::Unknown => Ok(ClassifiedFile {
            kind,
            keys: vec![],
            certs: vec![],
            needs_password: false,
        }),
        DetectedKind::Pkcs12 => match password {
            None => Ok(ClassifiedFile {
                kind,
                keys: vec![],
                certs: vec![],
                needs_password: true,
            }),
            Some(pw) => match pkcs12::import_pfx(bytes, pw) {
                Ok(bundle) => {
                    let mut keys = Vec::new();
                    let mut certs = Vec::new();
                    for entry in bundle.entries {
                        if let Some(k) = entry.key {
                            keys.push(k);
                        }
                        certs.extend(entry.certs);
                    }
                    Ok(ClassifiedFile { kind, keys, certs, needs_password: false })
                }
                Err(crate::error::CoreError::WrongPassword) => Ok(ClassifiedFile {
                    kind,
                    keys: vec![],
                    certs: vec![],
                    needs_password: true,
                }),
                Err(e) => Err(e),
            },
        },
        DetectedKind::Jks => match password {
            None => Ok(ClassifiedFile {
                kind,
                keys: vec![],
                certs: vec![],
                needs_password: true,
            }),
            Some(pw) => match jks::import_jks(bytes, pw) {
                Ok(bundle) => {
                    let mut keys = Vec::new();
                    let mut certs = Vec::new();
                    for entry in bundle.entries {
                        if let Some(k) = entry.key {
                            keys.push(k);
                        }
                        certs.extend(entry.certs);
                    }
                    Ok(ClassifiedFile { kind, keys, certs, needs_password: false })
                }
                Err(crate::error::CoreError::WrongPassword) => Ok(ClassifiedFile {
                    kind,
                    keys: vec![],
                    certs: vec![],
                    needs_password: true,
                }),
                Err(e) => Err(e),
            },
        },
    }
}

/// Given a pool of orphan keys and certificates gathered from one or more
/// imported files, pair each key with the certificate whose public key it
/// matches. Returns (pairs, unmatched_keys, unmatched_certs) so the UI can
/// show exactly what still needs a human decision — the mockup's "pick a
/// role for the ambiguous cert.cer" step.
#[allow(clippy::type_complexity)]
pub fn pair_orphans(
    keys: Vec<KeyMaterial>,
    certs: Vec<Vec<u8>>,
) -> Result<(Vec<(KeyMaterial, Vec<u8>)>, Vec<KeyMaterial>, Vec<Vec<u8>>)> {
    let mut pairs = Vec::new();
    let mut unmatched_certs = Vec::new();
    let mut remaining_keys = keys;

    for cert_der in certs {
        let mut matched_index = None;
        for (i, key) in remaining_keys.iter().enumerate() {
            if crate::chain::key_matches_cert(key, &cert_der)? {
                matched_index = Some(i);
                break;
            }
        }
        match matched_index {
            Some(i) => pairs.push((remaining_keys.remove(i), cert_der)),
            None => unmatched_certs.push(cert_der),
        }
    }

    Ok((pairs, remaining_keys, unmatched_certs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::KeyAlg;

    fn sample() -> (KeyMaterial, Vec<u8>) {
        let key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let cert = cert::self_signed(
            &CertSpec {
                subject: Subject::new("classify test"),
                sans: vec![],
                validity_days: 30,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &key,
        )
        .unwrap();
        (key, cert.der().to_vec())
    }

    #[test]
    fn detects_pem_der_cert_and_key() {
        let (key, cert_der) = sample();
        assert_eq!(detect_kind(&cert_der), DetectedKind::DerCertificate);
        assert_eq!(detect_kind(key.to_pkcs8_der()), DetectedKind::DerPrivateKey);
        let bundle = pem::export_bundle(Some(&key), &cert_der, &[]);
        assert_eq!(detect_kind(bundle.as_bytes()), DetectedKind::PemBundle);
    }

    #[test]
    fn pkcs12_without_password_asks_for_one() {
        let (key, cert_der) = sample();
        let pfx = pkcs12::export_pfx(
            "pw",
            "a",
            &key,
            &cert_der,
            &[],
            pkcs12::PfxEncryption::Modern,
        )
        .unwrap();
        assert_eq!(detect_kind(&pfx), DetectedKind::Pkcs12);
        let classified = classify(&pfx, None).unwrap();
        assert!(classified.needs_password);
        let classified = classify(&pfx, Some("pw")).unwrap();
        assert!(!classified.needs_password);
        assert_eq!(classified.keys.len(), 1);
        assert_eq!(classified.certs.len(), 1);
    }

    #[test]
    fn orphan_key_and_cert_are_paired_by_public_key() {
        let (key, cert_der) = sample();
        let (other_key, other_cert_der) = sample();
        let (pairs, leftover_keys, leftover_certs) =
            pair_orphans(vec![key, other_key], vec![cert_der.clone(), other_cert_der.clone()])
                .unwrap();
        assert_eq!(pairs.len(), 2);
        assert!(leftover_keys.is_empty());
        assert!(leftover_certs.is_empty());
    }
}
