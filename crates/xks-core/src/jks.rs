//! Java KeyStore (JKS) import/export — pure Rust via the `jks` crate, with
//! no JVM and no `keytool` invocation. Kept for interoperability with the
//! large installed base of Java servers that still expect `.jks` files;
//! PKCS#12 (see `pkcs12.rs`) is preferred for anything new.

use std::time::SystemTime;

use jks::{Certificate as JksCertificate, KeyStore, PrivateKeyEntry, TrustedCertificateEntry};

use crate::error::{CoreError, Result};
use crate::keys::KeyMaterial;

fn map_err(e: jks::KeyStoreError) -> CoreError {
    let msg = e.to_string();
    if msg.to_lowercase().contains("checksum") || msg.to_lowercase().contains("password") {
        CoreError::WrongPassword
    } else {
        CoreError::Jks(msg)
    }
}

fn x509(der: &[u8]) -> JksCertificate {
    JksCertificate {
        cert_type: "X509".to_string(),
        content: der.to_vec(),
    }
}

/// Build a JKS containing one private key entry. Historically Java keystore
/// tooling (and `keytool`) assumes the entry's own password equals the
/// store password; we do the same here rather than exposing a confusing
/// dual-password UI that almost nobody actually wants.
pub fn export_jks(
    password: &str,
    alias: &str,
    key: &KeyMaterial,
    leaf_der: &[u8],
    chain_der: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut ks = KeyStore::new();
    let mut chain = Vec::with_capacity(1 + chain_der.len());
    chain.push(x509(leaf_der));
    for c in chain_der {
        chain.push(x509(c));
    }
    let entry = PrivateKeyEntry {
        creation_time: SystemTime::now(),
        private_key: key.to_pkcs8_der().to_vec(),
        certificate_chain: chain,
    };
    ks.set_private_key_entry(alias, entry, password.as_bytes())
        .map_err(map_err)?;

    let mut buf = Vec::new();
    ks.store(&mut buf, password.as_bytes()).map_err(map_err)?;
    Ok(buf)
}

/// Build a certificate-only JKS truststore.
pub fn export_truststore_jks(password: &str, certs: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut ks = KeyStore::new();
    for (alias, der) in certs {
        let entry = TrustedCertificateEntry {
            creation_time: SystemTime::now(),
            certificate: x509(der),
        };
        ks.set_trusted_certificate_entry(alias, entry)
            .map_err(map_err)?;
    }
    let mut buf = Vec::new();
    ks.store(&mut buf, password.as_bytes()).map_err(map_err)?;
    Ok(buf)
}

pub struct JksEntry {
    pub alias: String,
    pub key: Option<KeyMaterial>,
    /// DER-encoded certificates, leaf first.
    pub certs: Vec<Vec<u8>>,
}

pub struct JksBundle {
    pub entries: Vec<JksEntry>,
}

/// Open a JKS with `password` (used both for the store integrity digest and
/// to decrypt every private-key entry; see the note on `export_jks`).
pub fn import_jks(data: &[u8], password: &str) -> Result<JksBundle> {
    let mut ks = KeyStore::new();
    ks.load(data, password.as_bytes()).map_err(map_err)?;

    let mut entries = Vec::new();
    for alias in ks.aliases() {
        if ks.is_private_key_entry(&alias) {
            let pke = ks
                .get_private_key_entry(&alias, password.as_bytes())
                .map_err(map_err)?;
            let key = KeyMaterial::from_pkcs8_der_autodetect(&pke.private_key)?;
            let certs = pke
                .certificate_chain
                .iter()
                .map(|c| c.content.clone())
                .collect();
            entries.push(JksEntry {
                alias,
                key: Some(key),
                certs,
            });
        } else if ks.is_trusted_certificate_entry(&alias) {
            let tce = ks.get_trusted_certificate_entry(&alias).map_err(map_err)?;
            entries.push(JksEntry {
                alias,
                key: None,
                certs: vec![tce.certificate.content],
            });
        }
    }

    if entries.is_empty() {
        return Err(CoreError::Jks(
            "the file decrypted correctly but contained no entries".into(),
        ));
    }
    Ok(JksBundle { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::{KeyAlg, KeyMaterial};

    fn make_chain() -> (KeyMaterial, Vec<u8>, Vec<u8>) {
        let root_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let root = cert::self_signed(
            &CertSpec {
                subject: Subject::new("Test Root"),
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
                subject: Subject::new("leaf.example.test"),
                sans: vec!["leaf.example.test".into()],
                validity_days: 365,
                template: CertTemplate::ServerAuth,
                path_len_constraint: None,
            },
            &leaf_key,
            &root.pem(),
            &root_key,
        )
        .unwrap();
        (leaf_key, leaf.der().to_vec(), root.der().to_vec())
    }

    #[test]
    fn export_then_import_round_trips() {
        let (leaf_key, leaf_der, root_der) = make_chain();
        let jks_bytes =
            export_jks("storepass123", "myalias", &leaf_key, &leaf_der, std::slice::from_ref(&root_der))
                .unwrap();

        let bundle = import_jks(&jks_bytes, "storepass123").unwrap();
        assert_eq!(bundle.entries.len(), 1);
        let entry = &bundle.entries[0];
        assert_eq!(entry.alias, "myalias");
        assert!(entry.key.is_some());
        assert_eq!(entry.certs[0], leaf_der);
        assert_eq!(entry.certs[1], root_der);
    }

    #[test]
    fn truststore_round_trips() {
        let (_leaf_key, _leaf_der, root_der) = make_chain();
        let jks_bytes =
            export_truststore_jks("trustpass", &[("root".to_string(), root_der.clone())])
                .unwrap();
        let bundle = import_jks(&jks_bytes, "trustpass").unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(bundle.entries[0].key.is_none());
        assert_eq!(bundle.entries[0].certs[0], root_der);
    }

    #[test]
    fn wrong_password_is_a_clean_error() {
        let (leaf_key, leaf_der, root_der) = make_chain();
        let jks_bytes =
            export_jks("rightpass", "a", &leaf_key, &leaf_der, &[root_der]).unwrap();
        let err = match import_jks(&jks_bytes, "wrongpass") {
            Ok(_) => panic!("expected wrong password to be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, CoreError::WrongPassword | CoreError::Jks(_)));
    }
}
