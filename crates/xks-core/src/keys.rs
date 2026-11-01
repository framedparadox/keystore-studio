//! Private/public key material.
//!
//! All key generation happens without Java and without shelling out to
//! OpenSSL. Elliptic-curve and Ed25519 keys are generated through `rcgen`'s
//! `ring` backend; RSA keys (which `ring` deliberately cannot generate) are
//! generated with the pure-Rust RustCrypto `rsa` crate and then handed to
//! `rcgen` as PKCS#8 for signing. Every key is held as PKCS#8 DER wrapped in
//! `Zeroizing` so the bytes are wiped when dropped.

use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use rcgen::{
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
    PublicKeyData, SignatureAlgorithm,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Key algorithm/size choices offered to the user. Deliberately excludes
/// anything weaker than 2048-bit RSA or than P-256; KeyStore Explorer and
/// `keytool` both still default to options (1024-bit RSA, raw DSA) that are
/// no longer appropriate, and silently letting a user pick them is one of
/// the gaps this app closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAlg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    Ed25519,
}

impl KeyAlg {
    pub fn label(&self) -> &'static str {
        match self {
            KeyAlg::Rsa2048 => "RSA 2048",
            KeyAlg::Rsa3072 => "RSA 3072",
            KeyAlg::Rsa4096 => "RSA 4096",
            KeyAlg::EcP256 => "ECDSA P-256",
            KeyAlg::EcP384 => "ECDSA P-384",
            KeyAlg::Ed25519 => "Ed25519",
        }
    }

    pub fn all() -> &'static [KeyAlg] {
        &[
            KeyAlg::EcP256,
            KeyAlg::EcP384,
            KeyAlg::Ed25519,
            KeyAlg::Rsa2048,
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
        ]
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096)
    }

    fn rsa_bits(&self) -> Option<usize> {
        match self {
            KeyAlg::Rsa2048 => Some(2048),
            KeyAlg::Rsa3072 => Some(3072),
            KeyAlg::Rsa4096 => Some(4096),
            _ => None,
        }
    }

    /// The signature algorithm this key should be used with when *this
    /// engine* issues certificates with it. (An imported key of unknown
    /// provenance may of course be re-used with a different hash; that is
    /// handled separately in `KeyMaterial::detect`.)
    pub fn signature_algorithm(&self) -> &'static SignatureAlgorithm {
        match self {
            KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => &PKCS_RSA_SHA256,
            KeyAlg::EcP256 => &PKCS_ECDSA_P256_SHA256,
            KeyAlg::EcP384 => &PKCS_ECDSA_P384_SHA384,
            KeyAlg::Ed25519 => &PKCS_ED25519,
        }
    }
}

/// A private key, held as PKCS#8 DER. The byte buffer is zeroized on drop.
pub struct KeyMaterial {
    pub alg: KeyAlg,
    der: Zeroizing<Vec<u8>>,
}

impl KeyMaterial {
    /// Generate a fresh key pair. Pure Rust, no network, no external process.
    pub fn generate(alg: KeyAlg) -> Result<Self> {
        if let Some(bits) = alg.rsa_bits() {
            use pkcs8::EncodePrivateKey;
            let mut rng = StdRng::try_from_rng(&mut SysRng)
                .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
            let key = rsa::RsaPrivateKey::new(&mut rng, bits)
                .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
            let der = key
                .to_pkcs8_der()
                .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
            Ok(Self {
                alg,
                der: Zeroizing::new(der.as_bytes().to_vec()),
            })
        } else {
            let kp = rcgen::KeyPair::generate_for(alg.signature_algorithm())
                .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
            Ok(Self {
                alg,
                der: Zeroizing::new(kp.serialize_der()),
            })
        }
    }

    /// Load a key of a *known* algorithm from PKCS#8 DER (e.g. one we just
    /// generated and stored, or one whose type the caller already knows).
    pub fn from_pkcs8_der(alg: KeyAlg, der: &[u8]) -> Result<Self> {
        // Validate it actually parses as that algorithm before accepting it.
        let _ = Self::rcgen_pair_for(alg, der)?;
        Ok(Self {
            alg,
            der: Zeroizing::new(der.to_vec()),
        })
    }

    /// Load a key of unknown algorithm from PEM, auto-detecting RSA / EC /
    /// Ed25519 from the embedded AlgorithmIdentifier. This is how imported
    /// files (drag-and-drop, "Import & classify") pick up a key without the
    /// user having to tell us what it is.
    pub fn from_pkcs8_pem_autodetect(pem_str: &str) -> Result<Self> {
        let kp = rcgen::KeyPair::from_pem(pem_str)
            .map_err(|e| CoreError::KeyParse(e.to_string()))?;
        let der = kp.serialize_der();
        let alg = Self::classify_rcgen_alg(kp.algorithm(), &der)?;
        Ok(Self {
            alg,
            der: Zeroizing::new(der),
        })
    }

    pub fn from_pkcs8_der_autodetect(der: &[u8]) -> Result<Self> {
        let kp = rcgen::KeyPair::try_from(der).map_err(|e| CoreError::KeyParse(e.to_string()))?;
        let alg = Self::classify_rcgen_alg(kp.algorithm(), der)?;
        Ok(Self {
            alg,
            der: Zeroizing::new(der.to_vec()),
        })
    }

    /// Identify the algorithm of a loaded key. For RSA, the exact modulus
    /// size is measured (rather than assumed) so that an imported 3072- or
    /// 4096-bit key is not silently mislabeled as 2048-bit.
    fn classify_rcgen_alg(sig_alg: &'static SignatureAlgorithm, der: &[u8]) -> Result<KeyAlg> {
        if sig_alg == &PKCS_ED25519 {
            Ok(KeyAlg::Ed25519)
        } else if sig_alg == &PKCS_ECDSA_P256_SHA256 {
            Ok(KeyAlg::EcP256)
        } else if sig_alg == &PKCS_ECDSA_P384_SHA384 {
            Ok(KeyAlg::EcP384)
        } else if sig_alg == &PKCS_RSA_SHA256 {
            use pkcs8::DecodePrivateKey;
            use rsa::traits::PublicKeyParts;
            let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|e| CoreError::KeyParse(e.to_string()))?;
            Ok(match key.n().bits() {
                0..=2048 => KeyAlg::Rsa2048,
                2049..=3072 => KeyAlg::Rsa3072,
                _ => KeyAlg::Rsa4096,
            })
        } else {
            Err(CoreError::KeyParse("unrecognized key algorithm".into()))
        }
    }

    fn rcgen_pair_for(alg: KeyAlg, der: &[u8]) -> Result<rcgen::KeyPair> {
        use rustls_pki_types::PrivatePkcs8KeyDer;
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(der),
            alg.signature_algorithm(),
        )
        .map_err(|e| CoreError::KeyParse(e.to_string()))
    }

    /// Build the `rcgen::KeyPair` needed to sign/issue with this key.
    pub fn to_rcgen_keypair(&self) -> Result<rcgen::KeyPair> {
        Self::rcgen_pair_for(self.alg, &self.der)
    }

    pub fn to_pkcs8_der(&self) -> &[u8] {
        &self.der
    }

    pub fn to_pkcs8_pem(&self) -> String {
        pem::encode(&pem::Pem::new("PRIVATE KEY", self.der.to_vec()))
    }

    /// DER-encoded SubjectPublicKeyInfo, used to pair an orphan key with a
    /// certificate during import classification without ever comparing the
    /// private key bytes themselves.
    pub fn subject_public_key_info(&self) -> Result<Vec<u8>> {
        Ok(self.to_rcgen_keypair()?.subject_public_key_info())
    }
}

impl Clone for KeyMaterial {
    fn clone(&self) -> Self {
        Self {
            alg: self.alg,
            der: self.der.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_each_algorithm_round_trips() {
        for &alg in KeyAlg::all() {
            let key = KeyMaterial::generate(alg).expect("generate");
            let pem = key.to_pkcs8_pem();
            let reloaded = KeyMaterial::from_pkcs8_pem_autodetect(&pem).expect("reload");
            assert_eq!(reloaded.alg, alg);
            let spki_a = key.subject_public_key_info().unwrap();
            let spki_b = reloaded.subject_public_key_info().unwrap();
            assert_eq!(spki_a, spki_b);
        }
    }
}
