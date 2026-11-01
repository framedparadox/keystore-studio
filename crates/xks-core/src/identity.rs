//! The unifying model the dashboard, wizard and CA workspace all share: one
//! private key, its leaf certificate, and the rest of the chain, addressed
//! by a single alias — instead of the private key, certificate and chain
//! being three separately-tracked objects the user has to keep in sync by
//! hand, which is how KeyStore Explorer, `keytool` and raw PEM files on
//! disk all still work today.

use serde::{Deserialize, Serialize};

use crate::chain::{self, Finding, Severity};
use crate::error::Result;
use crate::keys::KeyMaterial;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    /// Private key + leaf certificate + a chain that validates cleanly up
    /// to a self-signed root.
    Complete,
    /// Private key + leaf certificate, but the chain is missing pieces
    /// (no intermediate, doesn't reach a root) — still exportable, but the
    /// dashboard should say so rather than pretend it's done.
    Incomplete,
    /// Something is actually wrong: the key doesn't match the certificate,
    /// the certificate is expired, or the chain is cryptographically
    /// broken.
    Invalid,
    /// A certificate (and maybe a chain) with no private key at all — a
    /// trust anchor or a peer cert, not something you can serve TLS with.
    CertificateOnly,
}

pub struct Identity {
    pub alias: String,
    pub key: Option<KeyMaterial>,
    /// DER.
    pub leaf_der: Option<Vec<u8>>,
    /// DER, intermediates then root.
    pub chain_der: Vec<Vec<u8>>,
}

impl Identity {
    pub fn new(alias: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            key: None,
            leaf_der: None,
            chain_der: Vec::new(),
        }
    }

    /// Full validation report: an empty findings list plus `Complete`/
    /// `CertificateOnly` means nothing to fix; anything else explains why.
    pub fn diagnose(&self) -> Result<(IdentityStatus, Vec<Finding>)> {
        let Some(leaf) = &self.leaf_der else {
            return Ok((
                IdentityStatus::Invalid,
                vec![Finding {
                    severity: Severity::Error,
                    code: "no-certificate",
                    message: "this identity has no certificate at all".into(),
                    fix_hint: Some("import or issue a certificate for it".into()),
                }],
            ));
        };

        match &self.key {
            None => {
                let findings = chain::validate_chain(leaf, &self.chain_der)?;
                Ok((IdentityStatus::CertificateOnly, findings))
            }
            Some(key) => {
                let mut findings = Vec::new();
                if !chain::key_matches_cert(key, leaf)? {
                    findings.push(Finding {
                        severity: Severity::Error,
                        code: "key-cert-mismatch",
                        message: "the private key does not match this certificate's public key"
                            .into(),
                        fix_hint: Some(
                            "re-import the correct key, or issue a new certificate for this key"
                                .into(),
                        ),
                    });
                }
                findings.extend(chain::validate_chain(leaf, &self.chain_der)?);

                let has_error = findings.iter().any(|f| f.severity == Severity::Error);
                let incomplete = findings.iter().any(|f| {
                    matches!(
                        f.code,
                        "no-chain" | "missing-intermediate" | "chain-does-not-terminate-at-root"
                    )
                });
                let status = if has_error {
                    IdentityStatus::Invalid
                } else if incomplete {
                    IdentityStatus::Incomplete
                } else {
                    IdentityStatus::Complete
                };
                Ok((status, findings))
            }
        }
    }
}
