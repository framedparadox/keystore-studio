//! Plain PEM import/export: bundles (key + leaf + chain concatenated, the
//! format nginx/Node/Apache expect) and DER.
//!
//! PEM private keys here are unencrypted, matching what every server that
//! consumes them (nginx, Node, HAProxy...) actually requires; password
//! protection for a single portable file is what PKCS#12 is for (see
//! `pkcs12.rs`) and remains available for every export.

use crate::error::{CoreError, Result};
use crate::keys::KeyMaterial;

fn cert_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec()))
}

/// Everything concatenated into one file: private key, leaf certificate,
/// then the rest of the chain. This is the single-file layout nginx/HAProxy
/// expect for `ssl_certificate`+key-in-one setups and what most
/// "PEM bundle" exports in similar tools produce.
pub fn export_bundle(key: Option<&KeyMaterial>, leaf_der: &[u8], chain_der: &[Vec<u8>]) -> String {
    let mut out = String::new();
    if let Some(k) = key {
        out.push_str(&k.to_pkcs8_pem());
    }
    out.push_str(&cert_pem(leaf_der));
    for c in chain_der {
        out.push_str(&cert_pem(c));
    }
    out
}

/// The same material as separate files: `key.pem` (if a key is present),
/// `cert.pem` (leaf only) and `chain.pem` (intermediates + root, the layout
/// Apache's `SSLCertificateChainFile` and many Node/Express setups want).
pub struct SeparatePem {
    pub key_pem: Option<String>,
    pub cert_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
}

pub fn export_separate(key: Option<&KeyMaterial>, leaf_der: &[u8], chain_der: &[Vec<u8>]) -> SeparatePem {
    let cert_pem_s = cert_pem(leaf_der);
    let mut chain_pem_s = String::new();
    for c in chain_der {
        chain_pem_s.push_str(&cert_pem(c));
    }
    let mut fullchain = cert_pem_s.clone();
    fullchain.push_str(&chain_pem_s);
    SeparatePem {
        key_pem: key.map(|k| k.to_pkcs8_pem()),
        cert_pem: cert_pem_s,
        chain_pem: chain_pem_s,
        fullchain_pem: fullchain,
    }
}

/// What came out of a PEM blob of unknown composition — an imported bundle,
/// a lone cert, a lone key, whatever a user dragged in.
#[derive(Default)]
pub struct PemImport {
    pub keys: Vec<KeyMaterial>,
    /// DER-encoded certificates, in file order.
    pub certs: Vec<Vec<u8>>,
}

/// Classify every PEM block in `input`: certificates go to `certs`,
/// "PRIVATE KEY" (PKCS#8) blocks are parsed into `keys`. Unsupported block
/// types (encrypted keys, legacy `RSA PRIVATE KEY`, CSRs) are reported as
/// an error naming the block, since silently dropping key material is
/// exactly the kind of surprise this app is trying to avoid.
pub fn import_any(input: &str) -> Result<PemImport> {
    let mut out = PemImport::default();
    let blocks = pem::parse_many(input.as_bytes()).map_err(|e| CoreError::Pem(e.to_string()))?;
    if blocks.is_empty() {
        return Err(CoreError::Pem("no PEM blocks found".into()));
    }
    for block in blocks {
        match block.tag() {
            "CERTIFICATE" => out.certs.push(block.contents().to_vec()),
            "PRIVATE KEY" => {
                let key = KeyMaterial::from_pkcs8_der_autodetect(block.contents())?;
                out.keys.push(key);
            }
            "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                return Err(CoreError::Pem(format!(
                    "'{}' blocks (legacy PKCS#1/SEC1 key format) are not supported; \
                     convert to PKCS#8 'PRIVATE KEY' first",
                    block.tag()
                )));
            }
            "ENCRYPTED PRIVATE KEY" => {
                return Err(CoreError::Pem(
                    "password-encrypted PEM private keys are not yet supported for import"
                        .into(),
                ));
            }
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                // A CSR isn't a cert or a key; callers that care (CA
                // workspace import) look for this tag themselves via
                // `pem::parse_many` directly. Here we just skip it rather
                // than failing the whole import.
            }
            other => {
                return Err(CoreError::Pem(format!("unrecognized PEM block type '{other}'")));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::{KeyAlg, KeyMaterial};

    #[test]
    fn bundle_round_trips_through_import_any() {
        let key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let cert = cert::self_signed(
            &CertSpec {
                subject: Subject::new("bundle test"),
                sans: vec![],
                validity_days: 30,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &key,
        )
        .unwrap();

        let bundle = export_bundle(Some(&key), cert.der(), &[]);
        let parsed = import_any(&bundle).unwrap();
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.certs.len(), 1);
        assert_eq!(parsed.certs[0], cert.der().to_vec());
    }

    #[test]
    fn separate_files_split_chain_from_leaf() {
        let key = KeyMaterial::generate(KeyAlg::Ed25519).unwrap();
        let leaf = cert::self_signed(
            &CertSpec {
                subject: Subject::new("leaf"),
                sans: vec![],
                validity_days: 30,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &key,
        )
        .unwrap();
        let root_key = KeyMaterial::generate(KeyAlg::Ed25519).unwrap();
        let root = cert::self_signed(
            &CertSpec {
                subject: Subject::new("root"),
                sans: vec![],
                validity_days: 30,
                template: CertTemplate::RootCa,
                path_len_constraint: None,
            },
            &root_key,
        )
        .unwrap();

        let sep = export_separate(Some(&key), leaf.der(), &[root.der().to_vec()]);
        assert!(sep.key_pem.is_some());
        assert!(sep.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(sep.chain_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(
            import_any(&sep.fullchain_pem).unwrap().certs.len(),
            2
        );
    }
}
