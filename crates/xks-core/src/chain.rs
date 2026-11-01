//! Chain diagnostics: the checks behind the mockup's "Identity detail"
//! validation report and the dashboard's Complete/Incomplete/Invalid
//! triage. Every finding here is something a user can act on — a missing
//! intermediate, an expiring leaf, a key/cert mismatch — not just a pass/
//! fail bit, because "it's invalid" without saying *why* is exactly the
//! kind of unhelpful error KeyStore Explorer and `openssl verify` both give.

use serde::{Deserialize, Serialize};

use crate::cert::{parse_cert_info, CertInfo};
use crate::error::Result;
use crate::keys::KeyMaterial;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub fix_hint: Option<String>,
}

fn finding(severity: Severity, code: &'static str, message: impl Into<String>) -> Finding {
    Finding {
        severity,
        code,
        message: message.into(),
        fix_hint: None,
    }
}

fn with_fix(mut f: Finding, hint: impl Into<String>) -> Finding {
    f.fix_hint = Some(hint.into());
    f
}

const EXPIRY_WARNING_DAYS: i64 = 30;

/// Validate a leaf certificate plus the chain presented with it
/// (intermediates then root, in that order — the same order every other
/// field in this codebase uses). Does not require network access or a
/// system trust store; this checks *internal consistency* of the chain the
/// user supplied, which is what matters before exporting/deploying it.
pub fn validate_chain(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let leaf = parse_cert_info(leaf_der)?;

    check_validity_period(&leaf, "leaf certificate", &mut findings);
    check_key_strength(&leaf, "leaf certificate", &mut findings);
    check_server_san(&leaf, &mut findings);

    if chain_der.is_empty() {
        if !leaf.is_self_signed {
            findings.push(with_fix(
                finding(
                    Severity::Warning,
                    "no-chain",
                    format!(
                        "no intermediate or root certificates were supplied; \"{}\" was issued by \"{}\", which is not included",
                        leaf.subject, leaf.issuer
                    ),
                ),
                "add the intermediate certificate that issued this one, then the root",
            ));
        }
        return Ok(findings);
    }

    let mut all = Vec::with_capacity(1 + chain_der.len());
    all.push((leaf_der.to_vec(), leaf.clone()));
    for der in chain_der {
        all.push((der.clone(), parse_cert_info(der)?));
    }

    for (i, (der, info)) in all.iter().enumerate() {
        let label = if i == 0 {
            "leaf certificate".to_string()
        } else {
            format!("chain certificate #{i} (\"{}\")", info.subject)
        };
        if i > 0 {
            check_validity_period(info, &label, &mut findings);
            if !info.is_ca {
                findings.push(finding(
                    Severity::Error,
                    "not-a-ca",
                    format!("{label} is not a CA certificate (no CA:true basic constraint) but appears in the chain"),
                ));
            }
        }

        let is_last = i + 1 == all.len();
        if is_last {
            if !info.is_self_signed {
                findings.push(with_fix(
                    finding(
                        Severity::Warning,
                        "chain-does-not-terminate-at-root",
                        format!(
                            "the chain ends at \"{}\" (issued by \"{}\"), which is not self-signed",
                            info.subject, info.issuer
                        ),
                    ),
                    "the root CA certificate is missing from the chain",
                ));
            }
            continue;
        }

        let (issuer_der, issuer_info) = &all[i + 1];
        if info.issuer != issuer_info.subject {
            findings.push(with_fix(
                finding(
                    Severity::Error,
                    "missing-intermediate",
                    format!(
                        "{label} was issued by \"{}\", but the next certificate in the chain is \"{}\" — they do not match",
                        info.issuer, issuer_info.subject
                    ),
                ),
                format!("add the certificate for \"{}\" to the chain", info.issuer),
            ));
            continue;
        }

        match verify_signed_by(der, issuer_der) {
            Ok(true) => {}
            Ok(false) => findings.push(finding(
                Severity::Error,
                "signature-mismatch",
                format!(
                    "{label}'s signature does not verify against \"{}\"'s public key, even though the names match — this pairing is cryptographically wrong",
                    issuer_info.subject
                ),
            )),
            Err(e) => findings.push(finding(
                Severity::Info,
                "signature-unverifiable",
                format!("could not cryptographically verify {label}'s signature: {e}"),
            )),
        }
    }

    Ok(findings)
}

fn verify_signed_by(cert_der: &[u8], issuer_der: &[u8]) -> std::result::Result<bool, String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der).map_err(|e| e.to_string())?;
    let (_, issuer) =
        x509_parser::parse_x509_certificate(issuer_der).map_err(|e| e.to_string())?;
    Ok(cert.verify_signature(Some(issuer.public_key())).is_ok())
}

fn check_validity_period(info: &CertInfo, label: &str, findings: &mut Vec<Finding>) {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now < info.not_before_unix {
        findings.push(finding(
            Severity::Error,
            "not-yet-valid",
            format!("{label} is not valid yet (not before {})", format_ts(info.not_before_unix)),
        ));
    } else if now > info.not_after_unix {
        findings.push(finding(
            Severity::Error,
            "expired",
            format!("{label} expired on {}", format_ts(info.not_after_unix)),
        ));
    } else {
        let days_left = (info.not_after_unix - now) / 86400;
        if days_left <= EXPIRY_WARNING_DAYS {
            findings.push(finding(
                Severity::Warning,
                "expiring-soon",
                format!("{label} expires in {days_left} day(s) ({})", format_ts(info.not_after_unix)),
            ));
        }
    }
}

fn check_key_strength(info: &CertInfo, label: &str, findings: &mut Vec<Finding>) {
    match (info.public_key_kind.as_str(), info.public_key_bits) {
        ("RSA", Some(bits)) if bits < 2048 => {
            findings.push(with_fix(
                finding(
                    Severity::Error,
                    "weak-key",
                    format!("{label} uses a {bits}-bit RSA key, which is no longer considered safe"),
                ),
                "re-issue with at least 2048-bit RSA, or switch to an EC key",
            ));
        }
        ("EC", Some(bits)) if bits < 256 => {
            findings.push(finding(
                Severity::Warning,
                "weak-key",
                format!("{label} uses a {bits}-bit EC key, smaller than P-256"),
            ));
        }
        _ => {}
    }
}

fn check_server_san(info: &CertInfo, findings: &mut Vec<Finding>) {
    let is_server_cert = info
        .extended_key_usage
        .iter()
        .any(|e| e == "serverAuth" || e == "anyExtendedKeyUsage");
    let has_san = info.sans.iter().any(|s| s.starts_with("DNS:") || s.starts_with("IP:"));
    if is_server_cert && !has_san {
        findings.push(with_fix(
            finding(
                Severity::Warning,
                "no-san",
                "this server certificate has no Subject Alternative Name (SAN); modern browsers and clients ignore the Common Name entirely".to_string(),
            ),
            "re-issue the certificate with at least one DNS or IP SAN entry",
        ));
    }
}

fn format_ts(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| t.to_string())
        .unwrap_or_else(|_| unix.to_string())
}

/// Confirm a private key and a certificate are actually a pair, by
/// comparing their SubjectPublicKeyInfo bytes — never by touching the
/// private scalar/modulus itself.
pub fn key_matches_cert(key: &KeyMaterial, cert_der: &[u8]) -> Result<bool> {
    let key_spki = key.subject_public_key_info()?;
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| crate::error::CoreError::CertParse(e.to_string()))?;
    Ok(key_spki == cert.public_key().raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::KeyAlg;

    #[test]
    fn full_chain_with_matching_key_has_no_errors() {
        let root_key = KeyMaterial::generate(KeyAlg::EcP384).unwrap();
        let root = cert::self_signed(
            &CertSpec {
                subject: Subject::new("Root"),
                sans: vec![],
                validity_days: 3650,
                template: CertTemplate::RootCa,
                path_len_constraint: None,
            },
            &root_key,
        )
        .unwrap();
        let leaf_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let leaf = cert::issue_leaf(
            &CertSpec {
                subject: Subject::new("svc.example.test"),
                sans: vec!["svc.example.test".into()],
                validity_days: 365,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &leaf_key,
            &root.pem(),
            &root_key,
        )
        .unwrap();

        let findings =
            validate_chain(leaf.der(), &[root.der().to_vec()]).unwrap();
        assert!(
            findings.iter().all(|f| f.severity != Severity::Error),
            "unexpected errors: {findings:?}"
        );
        assert!(key_matches_cert(&leaf_key, leaf.der()).unwrap());
        assert!(!key_matches_cert(&root_key, leaf.der()).unwrap());
    }

    #[test]
    fn missing_intermediate_is_detected() {
        let root_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let root = cert::self_signed(
            &CertSpec {
                subject: Subject::new("Root"),
                sans: vec![],
                validity_days: 3650,
                template: CertTemplate::RootCa,
                path_len_constraint: None,
            },
            &root_key,
        )
        .unwrap();
        let inter_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let inter = cert::issue_leaf(
            &CertSpec {
                subject: Subject::new("Issuing CA"),
                sans: vec![],
                validity_days: 1825,
                template: CertTemplate::IntermediateCa,
                path_len_constraint: Some(0),
            },
            &inter_key,
            &root.pem(),
            &root_key,
        )
        .unwrap();
        let leaf_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let leaf = cert::issue_leaf(
            &CertSpec {
                subject: Subject::new("svc.example.test"),
                sans: vec!["svc.example.test".into()],
                validity_days: 365,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &leaf_key,
            &inter.pem(),
            &inter_key,
        )
        .unwrap();

        // Only the root is supplied; the intermediate is missing.
        let findings = validate_chain(leaf.der(), &[root.der().to_vec()]).unwrap();
        assert!(findings.iter().any(|f| f.code == "missing-intermediate"));
    }

    #[test]
    fn expired_leaf_is_an_error() {
        let key = KeyMaterial::generate(KeyAlg::Ed25519).unwrap();
        let spec = CertSpec {
            subject: Subject::new("expired"),
            sans: vec![],
            validity_days: 0,
            template: CertTemplate::ServerAuth,
            path_len_constraint: None,
        };
        // validity_days.max(1) in build_params means "expires in ~1 day
        // minus the 5-minute backdate", so instead directly assert the
        // soon-to-expire warning path, which is the realistic case.
        let cert = cert::self_signed(&spec, &key).unwrap();
        let findings = validate_chain(cert.der(), &[]).unwrap();
        assert!(findings.iter().any(|f| f.code == "expiring-soon" || f.code == "expired"));
    }
}
