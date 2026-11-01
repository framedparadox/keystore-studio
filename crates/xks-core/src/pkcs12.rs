//! PKCS#12 / PFX import and export — entirely in pure Rust via the
//! `p12-keystore` crate, with no dependency on the OpenSSL `pkcs12`
//! command or a JVM `keytool`. This is the core "convert a certificate and
//! private key into a password-protected .pfx/.p12" capability.

use p12_keystore::{
    Certificate as P12Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, LocalKeyId,
    MacAlgorithm, Pkcs12ImportPolicy, PrivateKey as P12PrivateKey, PrivateKeyChain,
};

use crate::error::{CoreError, Result};
use crate::keys::KeyMaterial;

/// Which PBE scheme protects the PFX. `Modern` (AES-256/HMAC-SHA256) is what
/// current OpenSSL defaults to and is what we default to as well; `Legacy`
/// (3DES/SHA-1) exists only because some old Java deployments and hardware
/// still refuse anything else, and KeyStore Explorer / `keytool` users will
/// recognize it as "the old kind that always works".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfxEncryption {
    Modern,
    LegacyCompatible,
}

impl PfxEncryption {
    fn to_p12(self) -> EncryptionAlgorithm {
        match self {
            PfxEncryption::Modern => EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
            PfxEncryption::LegacyCompatible => EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        }
    }
}

/// Build a PFX containing one private key, its leaf certificate and the
/// rest of the chain (intermediates then root, in that order), protected
/// with `password`. This is the operation behind "Create Keystore" and
/// "Converter → PKCS#12".
pub fn export_pfx(
    password: &str,
    alias: &str,
    key: &KeyMaterial,
    leaf_der: &[u8],
    chain_der: &[Vec<u8>],
    encryption: PfxEncryption,
) -> Result<Vec<u8>> {
    let mut ks = KeyStore::new();
    let pk = P12PrivateKey::from_der(key.to_pkcs8_der())
        .map_err(|e| CoreError::Pkcs12(e.to_string()))?;

    let mut certs = Vec::with_capacity(1 + chain_der.len());
    certs.push(P12Certificate::from_der(leaf_der).map_err(|e| CoreError::Pkcs12(e.to_string()))?);
    for c in chain_der {
        certs.push(P12Certificate::from_der(c).map_err(|e| CoreError::Pkcs12(e.to_string()))?);
    }

    let chain = PrivateKeyChain::new(LocalKeyId::from(alias), pk, certs);
    ks.add_entry(alias, KeyStoreEntry::PrivateKeyChain(chain));

    ks.writer(password)
        .encryption_algorithm(encryption.to_p12())
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .write()
        .map_err(|e| CoreError::Pkcs12(e.to_string()))
}

/// Build a "truststore" PFX: certificates only, no private keys. Used by
/// the Converter / wizard's "Truststore" output format.
pub fn export_truststore_pfx(
    password: &str,
    certs: &[(String, Vec<u8>)],
    encryption: PfxEncryption,
) -> Result<Vec<u8>> {
    let mut ks = KeyStore::new();
    for (alias, der) in certs {
        let cert =
            P12Certificate::from_der(der).map_err(|e| CoreError::Pkcs12(e.to_string()))?;
        ks.add_entry(alias, KeyStoreEntry::Certificate(cert));
    }
    ks.writer(password)
        .encryption_algorithm(encryption.to_p12())
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .write()
        .map_err(|e| CoreError::Pkcs12(e.to_string()))
}

/// One alias's worth of material recovered from a PFX.
pub struct PfxEntry {
    pub alias: String,
    /// `Some` for a private-key entry; `None` for a trusted-certificate-only
    /// entry (as found in a truststore).
    pub key: Option<KeyMaterial>,
    /// DER-encoded certificates, leaf first.
    pub certs: Vec<Vec<u8>>,
}

pub struct PfxBundle {
    pub entries: Vec<PfxEntry>,
}

/// Open a PFX with `password`, recovering every private key and
/// certificate it contains. A wrong password or a corrupt/foreign file
/// surfaces as `CoreError::WrongPassword` / `CoreError::Pkcs12` rather than
/// a panic — this is what lets "Import & classify" offer a retry instead of
/// crashing on the first bad guess.
pub fn import_pfx(data: &[u8], password: &str) -> Result<PfxBundle> {
    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed).map_err(|e| {
        let msg = e.to_string();
        if msg.to_lowercase().contains("mac") || msg.to_lowercase().contains("password") {
            CoreError::WrongPassword
        } else {
            CoreError::Pkcs12(msg)
        }
    })?;

    let mut entries = Vec::new();
    for (alias, entry) in ks.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => {
                let key = KeyMaterial::from_pkcs8_der_autodetect(chain.key().as_der())?;
                let certs = chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
                entries.push(PfxEntry {
                    alias: alias.clone(),
                    key: Some(key),
                    certs,
                });
            }
            KeyStoreEntry::Certificate(cert) => {
                entries.push(PfxEntry {
                    alias: alias.clone(),
                    key: None,
                    certs: vec![cert.as_der().to_vec()],
                });
            }
            KeyStoreEntry::Secret(_) => {
                // Raw secret keys (HMAC/AES material) have no cert/key
                // representation we expose yet; skip rather than error so a
                // mixed-purpose PFX still imports its certs/keys.
            }
        }
    }

    if entries.is_empty() {
        return Err(CoreError::Pkcs12(
            "the file decrypted correctly but contained no usable certificate or key entries"
                .into(),
        ));
    }

    Ok(PfxBundle { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::{KeyAlg, KeyMaterial};

    fn make_chain() -> (KeyMaterial, Vec<u8>, KeyMaterial, Vec<u8>) {
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
        let leaf_key = KeyMaterial::generate(KeyAlg::Rsa2048).unwrap();
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
        (leaf_key, leaf.der().to_vec(), root_key, root.der().to_vec())
    }

    #[test]
    fn export_then_import_round_trips_modern() {
        let (leaf_key, leaf_der, _root_key, root_der) = make_chain();
        let pfx = export_pfx(
            "correct horse battery staple",
            "myalias",
            &leaf_key,
            &leaf_der,
            std::slice::from_ref(&root_der),
            PfxEncryption::Modern,
        )
        .unwrap();

        let bundle = import_pfx(&pfx, "correct horse battery staple").unwrap();
        assert_eq!(bundle.entries.len(), 1);
        let entry = &bundle.entries[0];
        assert_eq!(entry.alias, "myalias");
        assert!(entry.key.is_some());
        assert_eq!(entry.certs.len(), 2);
        assert_eq!(entry.certs[0], leaf_der);
        assert_eq!(entry.certs[1], root_der);
    }

    #[test]
    fn export_then_import_round_trips_legacy() {
        let (leaf_key, leaf_der, _root_key, root_der) = make_chain();
        let pfx = export_pfx(
            "p@ssw0rd!",
            "legacy",
            &leaf_key,
            &leaf_der,
            &[root_der],
            PfxEncryption::LegacyCompatible,
        )
        .unwrap();
        let bundle = import_pfx(&pfx, "p@ssw0rd!").unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(bundle.entries[0].key.is_some());
    }

    #[test]
    fn wrong_password_is_a_clean_error_not_a_panic() {
        let (leaf_key, leaf_der, _root_key, root_der) = make_chain();
        let pfx = export_pfx(
            "right-password",
            "a",
            &leaf_key,
            &leaf_der,
            &[root_der],
            PfxEncryption::Modern,
        )
        .unwrap();
        let err = match import_pfx(&pfx, "wrong-password") {
            Ok(_) => panic!("expected the wrong password to be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, CoreError::WrongPassword | CoreError::Pkcs12(_)));
    }

    #[test]
    fn truststore_round_trips_without_any_key() {
        let (_leaf_key, _leaf_der, _root_key, root_der) = make_chain();
        let pfx = export_truststore_pfx(
            "trust-pw",
            &[("root-ca".to_string(), root_der.clone())],
            PfxEncryption::Modern,
        )
        .unwrap();
        let bundle = import_pfx(&pfx, "trust-pw").unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(bundle.entries[0].key.is_none());
        assert_eq!(bundle.entries[0].certs[0], root_der);
    }
}
