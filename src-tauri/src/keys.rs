//! Asymmetric keys: generation, parsing (PKCS#8, encrypted PKCS#8, PKCS#1, SEC1), signing and
//! verification, plus JWK and OpenSSH public key encodings.
//!
//! Keys we cannot use for signing (DSA, Ed448, post-quantum keys from newer JDKs, …) are still
//! carried as opaque PKCS#8 so keystores containing them load and save losslessly.

use crate::oids;
use crate::pbe::HashAlg;
use crate::util::{b64, e, pem_blocks, sha256, to_pem, trim_leading_zeros, Res};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use yasna::DERWriter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    Rsa(HashAlg),
    Ecdsa(HashAlg),
    Ed25519,
}

impl SigAlg {
    pub fn oid(self) -> &'static [u64] {
        match self {
            SigAlg::Rsa(HashAlg::Sha1) => oids::SHA1_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha224) => oids::SHA224_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha256) => oids::SHA256_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha384) => oids::SHA384_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha512) => oids::SHA512_WITH_RSA,
            SigAlg::Ecdsa(HashAlg::Sha1) => oids::ECDSA_SHA1,
            SigAlg::Ecdsa(HashAlg::Sha224) => oids::ECDSA_SHA224,
            SigAlg::Ecdsa(HashAlg::Sha256) => oids::ECDSA_SHA256,
            SigAlg::Ecdsa(HashAlg::Sha384) => oids::ECDSA_SHA384,
            SigAlg::Ecdsa(HashAlg::Sha512) => oids::ECDSA_SHA512,
            SigAlg::Ed25519 => oids::ED25519,
        }
    }

    pub fn from_oid(arcs: &[u64]) -> Option<SigAlg> {
        Some(match arcs {
            a if a == oids::SHA1_WITH_RSA => SigAlg::Rsa(HashAlg::Sha1),
            a if a == oids::SHA224_WITH_RSA => SigAlg::Rsa(HashAlg::Sha224),
            a if a == oids::SHA256_WITH_RSA => SigAlg::Rsa(HashAlg::Sha256),
            a if a == oids::SHA384_WITH_RSA => SigAlg::Rsa(HashAlg::Sha384),
            a if a == oids::SHA512_WITH_RSA => SigAlg::Rsa(HashAlg::Sha512),
            a if a == oids::ECDSA_SHA1 => SigAlg::Ecdsa(HashAlg::Sha1),
            a if a == oids::ECDSA_SHA224 => SigAlg::Ecdsa(HashAlg::Sha224),
            a if a == oids::ECDSA_SHA256 => SigAlg::Ecdsa(HashAlg::Sha256),
            a if a == oids::ECDSA_SHA384 => SigAlg::Ecdsa(HashAlg::Sha384),
            a if a == oids::ECDSA_SHA512 => SigAlg::Ecdsa(HashAlg::Sha512),
            a if a == oids::ED25519 => SigAlg::Ed25519,
            _ => return None,
        })
    }

    pub fn hash(self) -> HashAlg {
        match self {
            SigAlg::Rsa(h) | SigAlg::Ecdsa(h) => h,
            SigAlg::Ed25519 => HashAlg::Sha512,
        }
    }

    pub fn name(self) -> String {
        oids::signature_algorithm_name(self.oid())
    }

    /// Writes the X.509 `AlgorithmIdentifier` (RSA carries an explicit NULL parameter).
    pub fn write_algorithm_id(self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_oid(&oids::oid(self.oid()));
            if matches!(self, SigAlg::Rsa(_)) {
                w.next().write_null();
            }
        });
    }
}

pub fn parse_hash_name(name: Option<&str>) -> Option<HashAlg> {
    match name?.to_ascii_uppercase().replace('-', "").as_str() {
        "SHA1" => Some(HashAlg::Sha1),
        "SHA224" => Some(HashAlg::Sha224),
        "SHA256" => Some(HashAlg::Sha256),
        "SHA384" => Some(HashAlg::Sha384),
        "SHA512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

pub enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// A key we can store but not use (DSA, Ed448, X25519, post-quantum, RSA-PSS, …).
    Opaque { algorithm: String, pkcs8: Vec<u8> },
}

impl PrivateKey {
    /// Generates a fresh key. `algorithm` is "RSA", "ECDSA"/"EC" or "Ed25519".
    pub fn generate(algorithm: &str, key_size: u32, curve: Option<&str>) -> Res<PrivateKey> {
        let mut rng = rand::rngs::OsRng;
        match algorithm.to_ascii_uppercase().as_str() {
            "RSA" => {
                if !(1024..=16384).contains(&key_size) || key_size % 8 != 0 {
                    return Err("RSA key size must be a multiple of 8 between 1024 and 16384 bits".into());
                }
                let key = RsaPrivateKey::new(&mut rng, key_size as usize).map_err(|err| format!("RSA key generation failed: {err}"))?;
                Ok(PrivateKey::Rsa(Box::new(key)))
            }
            "EC" | "ECDSA" => match normalize_curve(curve.unwrap_or("P-256")).as_deref() {
                Some("P-256") => Ok(PrivateKey::P256(p256::SecretKey::random(&mut rng))),
                Some("P-384") => Ok(PrivateKey::P384(p384::SecretKey::random(&mut rng))),
                Some("P-521") => Ok(PrivateKey::P521(p521::SecretKey::random(&mut rng))),
                _ => Err(format!("unsupported elliptic curve '{}'", curve.unwrap_or(""))),
            },
            "ED25519" | "EDDSA" => Ok(PrivateKey::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(&mut rng)))),
            other => Err(format!("unsupported key algorithm '{other}' (use RSA, ECDSA or Ed25519)")),
        }
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` (or `OneAsymmetricKey`).
    pub fn from_pkcs8_der(der: &[u8]) -> Res<PrivateKey> {
        let info = rsa::pkcs8::PrivateKeyInfo::try_from(der).map_err(|err| format!("not a PKCS#8 private key: {err}"))?;
        let alg_arcs: Vec<u64> = info.algorithm.oid.arcs().map(u64::from).collect();
        let alg = alg_arcs.as_slice();
        if alg == oids::RSA_ENCRYPTION {
            return RsaPrivateKey::from_pkcs8_der(der).map(|k| PrivateKey::Rsa(Box::new(k))).map_err(|err| format!("invalid RSA key: {err}"));
        }
        if alg == oids::EC_PUBLIC_KEY {
            let curve: Vec<u64> = info
                .algorithm
                .parameters_oid()
                .map(|o| o.arcs().map(u64::from).collect())
                .unwrap_or_default();
            return match curve.as_slice() {
                c if c == oids::SECP256R1 => p256::SecretKey::from_pkcs8_der(der).map(PrivateKey::P256).map_err(e),
                c if c == oids::SECP384R1 => p384::SecretKey::from_pkcs8_der(der).map(PrivateKey::P384).map_err(e),
                c if c == oids::SECP521R1 => p521::SecretKey::from_pkcs8_der(der).map(PrivateKey::P521).map_err(e),
                c => Ok(PrivateKey::Opaque { algorithm: format!("EC ({})", curve_name(c).unwrap_or_else(|| oids::oid_str(c))), pkcs8: der.to_vec() }),
            };
        }
        if alg == oids::ED25519 {
            return ed25519_dalek::SigningKey::from_pkcs8_der(der)
                .map(|k| PrivateKey::Ed25519(Box::new(k)))
                .map_err(|err| format!("invalid Ed25519 key: {err}"));
        }
        let algorithm = match alg {
            a if a == oids::DSA => "DSA".to_string(),
            a if a == oids::ED448 => "Ed448".to_string(),
            a if a == oids::X25519 => "X25519".to_string(),
            a if a == oids::X448 => "X448".to_string(),
            a if a == oids::RSASSA_PSS => "RSASSA-PSS".to_string(),
            a => oids::post_quantum_name(a).map(String::from).unwrap_or_else(|| oids::oid_str(a)),
        };
        Ok(PrivateKey::Opaque { algorithm, pkcs8: der.to_vec() })
    }

    /// Parses PEM or DER key material. Handles PKCS#8, encrypted PKCS#8 (requires `password`),
    /// PKCS#1 "RSA PRIVATE KEY" and SEC1 "EC PRIVATE KEY".
    pub fn from_bytes(data: &[u8], password: Option<&str>) -> Res<PrivateKey> {
        if let Ok(text) = std::str::from_utf8(data) {
            if text.contains("-----BEGIN") {
                if text.contains("Proc-Type: 4,ENCRYPTED") {
                    return Err("legacy OpenSSL-encrypted PEM keys are not supported; convert with `openssl pkcs8 -topk8 -in key.pem -out key-pkcs8.pem`".into());
                }
                for block in pem_blocks(text) {
                    match block.tag.as_str() {
                        "PRIVATE KEY" => return Self::from_pkcs8_der(&block.der),
                        "ENCRYPTED PRIVATE KEY" => {
                            let pw = password.filter(|p| !p.is_empty()).ok_or("this private key is encrypted; enter its password")?;
                            let der = crate::pbe::decrypt_pkcs8(pw, &block.der).map_err(|_| "incorrect private key password".to_string())?;
                            return Self::from_pkcs8_der(&der);
                        }
                        "RSA PRIVATE KEY" => {
                            return RsaPrivateKey::from_pkcs1_der(&block.der).map(|k| PrivateKey::Rsa(Box::new(k))).map_err(e);
                        }
                        "EC PRIVATE KEY" => return Self::from_sec1_der(&block.der),
                        _ => continue,
                    }
                }
                return Err("no private key found in the PEM data".into());
            }
        }
        // DER: try PKCS#8, then encrypted PKCS#8, PKCS#1 and SEC1.
        if let Ok(k) = Self::from_pkcs8_der(data) {
            return Ok(k);
        }
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            if let Ok(der) = crate::pbe::decrypt_pkcs8(pw, data) {
                return Self::from_pkcs8_der(&der);
            }
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_der(data) {
            return Ok(PrivateKey::Rsa(Box::new(k)));
        }
        Self::from_sec1_der(data).map_err(|_| "unrecognised private key format".to_string())
    }

    fn from_sec1_der(der: &[u8]) -> Res<PrivateKey> {
        let (scalar_len, curve) = yasna::parse_ber(der, |r| {
            r.read_sequence(|r| {
                let _version = r.next().read_u8()?;
                let scalar = r.next().read_bytes()?;
                let curve = r.read_optional(|r| r.read_tagged(yasna::Tag::context(0), |r| r.read_oid()))?;
                let _ = r.read_optional(|r| r.read_tagged(yasna::Tag::context(1), |r| r.read_der()))?;
                Ok((scalar.len(), curve.map(|c| c.components().to_vec())))
            })
        })
        .map_err(|err| format!("invalid EC private key: {err}"))?;
        let curve = curve.unwrap_or_else(|| match scalar_len {
            48 => oids::SECP384R1.to_vec(),
            65 | 66 => oids::SECP521R1.to_vec(),
            _ => oids::SECP256R1.to_vec(),
        });
        match curve.as_slice() {
            c if c == oids::SECP256R1 => p256::SecretKey::from_sec1_der(der).map(PrivateKey::P256).map_err(e),
            c if c == oids::SECP384R1 => p384::SecretKey::from_sec1_der(der).map(PrivateKey::P384).map_err(e),
            c if c == oids::SECP521R1 => p521::SecretKey::from_sec1_der(der).map(PrivateKey::P521).map_err(e),
            c => Err(format!("unsupported EC curve {}", oids::oid_str(c))),
        }
    }

    pub fn to_pkcs8_der(&self) -> Res<Vec<u8>> {
        Ok(match self {
            PrivateKey::Rsa(k) => k.to_pkcs8_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P256(k) => k.to_pkcs8_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P384(k) => k.to_pkcs8_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P521(k) => k.to_pkcs8_der().map_err(e)?.as_bytes().to_vec(),
            // RFC 8410 v1 encoding (no embedded public key): the form OpenSSL writes and the only
            // one OpenSSL 3.0 reads. ed25519-dalek would emit v2 (OneAsymmetricKey).
            PrivateKey::Ed25519(k) => yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_u8(0);
                    w.next().write_sequence(|w| w.next().write_oid(&oids::oid(oids::ED25519)));
                    w.next().write_bytes(&yasna::construct_der(|w| w.write_bytes(&k.to_bytes())));
                })
            }),
            PrivateKey::Opaque { pkcs8, .. } => pkcs8.clone(),
        })
    }

    pub fn to_pkcs8_pem(&self) -> Res<String> {
        Ok(to_pem("PRIVATE KEY", &self.to_pkcs8_der()?))
    }

    pub fn is_usable(&self) -> bool {
        !matches!(self, PrivateKey::Opaque { .. })
    }

    /// DER `SubjectPublicKeyInfo` of the matching public key.
    pub fn public_key_der(&self) -> Res<Vec<u8>> {
        Ok(match self {
            PrivateKey::Rsa(k) => k.to_public_key().to_public_key_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P256(k) => k.public_key().to_public_key_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P384(k) => k.public_key().to_public_key_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::P521(k) => k.public_key().to_public_key_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::Ed25519(k) => k.verifying_key().to_public_key_der().map_err(e)?.as_bytes().to_vec(),
            PrivateKey::Opaque { algorithm, .. } => {
                return Err(format!("{algorithm} keys can be stored but not used for signing in xkeystore"));
            }
        })
    }

    pub fn algorithm(&self) -> String {
        match self {
            PrivateKey::Rsa(_) => "RSA".into(),
            PrivateKey::P256(_) | PrivateKey::P384(_) | PrivateKey::P521(_) => "ECDSA".into(),
            PrivateKey::Ed25519(_) => "Ed25519".into(),
            PrivateKey::Opaque { algorithm, .. } => algorithm.clone(),
        }
    }

    pub fn key_size(&self) -> u32 {
        match self {
            PrivateKey::Rsa(k) => (k.size() * 8) as u32,
            PrivateKey::P256(_) => 256,
            PrivateKey::P384(_) => 384,
            PrivateKey::P521(_) => 521,
            PrivateKey::Ed25519(_) => 255,
            PrivateKey::Opaque { .. } => 0,
        }
    }

    pub fn curve(&self) -> Option<String> {
        match self {
            PrivateKey::P256(_) => Some("P-256".into()),
            PrivateKey::P384(_) => Some("P-384".into()),
            PrivateKey::P521(_) => Some("P-521".into()),
            PrivateKey::Ed25519(_) => Some("Curve25519".into()),
            _ => None,
        }
    }

    /// The signature algorithm used when this key signs certificates, CSRs and CRLs.
    pub fn default_sig_alg(&self, rsa_hash: Option<HashAlg>) -> Res<SigAlg> {
        Ok(match self {
            PrivateKey::Rsa(_) => SigAlg::Rsa(rsa_hash.unwrap_or(HashAlg::Sha256)),
            PrivateKey::P256(_) => SigAlg::Ecdsa(HashAlg::Sha256),
            PrivateKey::P384(_) => SigAlg::Ecdsa(HashAlg::Sha384),
            PrivateKey::P521(_) => SigAlg::Ecdsa(HashAlg::Sha512),
            PrivateKey::Ed25519(_) => SigAlg::Ed25519,
            PrivateKey::Opaque { algorithm, .. } => return Err(format!("{algorithm} keys cannot be used for signing in xkeystore")),
        })
    }

    /// Signs `msg`. ECDSA signatures are DER-encoded (X.509/CMS form); see [`Self::sign_jws`].
    pub fn sign(&self, alg: SigAlg, msg: &[u8]) -> Res<Vec<u8>> {
        self.sign_inner(alg, msg, false)
    }

    /// Signs for JWS: identical to [`Self::sign`] except ECDSA uses the fixed-size r‖s form.
    pub fn sign_jws(&self, alg: SigAlg, msg: &[u8]) -> Res<Vec<u8>> {
        self.sign_inner(alg, msg, true)
    }

    fn sign_inner(&self, alg: SigAlg, msg: &[u8], raw_ecdsa: bool) -> Res<Vec<u8>> {
        use ecdsa_sign::sign_prehash;
        match (self, alg) {
            (PrivateKey::Rsa(k), SigAlg::Rsa(hash)) => {
                let digest = hash.digest(msg);
                k.sign(pkcs1v15_scheme(hash), &digest).map_err(|err| format!("RSA signing failed: {err}"))
            }
            (PrivateKey::P256(k), SigAlg::Ecdsa(hash)) => sign_prehash::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(
                &p256::ecdsa::SigningKey::from(k),
                &hash.digest(msg),
                raw_ecdsa,
            ),
            (PrivateKey::P384(k), SigAlg::Ecdsa(hash)) => sign_prehash::<p384::ecdsa::SigningKey, p384::ecdsa::Signature>(
                &p384::ecdsa::SigningKey::from(k),
                &hash.digest(msg),
                raw_ecdsa,
            ),
            (PrivateKey::P521(k), SigAlg::Ecdsa(hash)) => {
                let signing = p521::ecdsa::SigningKey::from_bytes(&k.to_bytes()).map_err(e)?;
                sign_prehash::<p521::ecdsa::SigningKey, p521::ecdsa::Signature>(&signing, &hash.digest(msg), raw_ecdsa)
            }
            (PrivateKey::Ed25519(k), SigAlg::Ed25519) => {
                use ed25519_dalek::Signer;
                Ok(k.sign(msg).to_bytes().to_vec())
            }
            (_, alg) => Err(format!("{} cannot be produced with a {} key", alg.name(), self.algorithm())),
        }
    }

    pub fn public_jwk(&self) -> Res<serde_json::Value> {
        public_jwk_from_spki(&self.public_key_der()?)
    }

    /// JWK including private parameters (RFC 7517/7518/8037).
    pub fn private_jwk(&self) -> Res<serde_json::Value> {
        let mut jwk = self.public_jwk()?;
        let obj = jwk.as_object_mut().expect("JWK is an object");
        let enc = |b: &[u8]| B64URL.encode(b);
        match self {
            PrivateKey::Rsa(k) => {
                let primes = k.primes();
                obj.insert("d".into(), enc(&k.d().to_bytes_be()).into());
                if primes.len() >= 2 {
                    obj.insert("p".into(), enc(&primes[0].to_bytes_be()).into());
                    obj.insert("q".into(), enc(&primes[1].to_bytes_be()).into());
                }
                if let (Some(dp), Some(dq)) = (k.dp(), k.dq()) {
                    obj.insert("dp".into(), enc(&dp.to_bytes_be()).into());
                    obj.insert("dq".into(), enc(&dq.to_bytes_be()).into());
                }
                if let Some(qi) = k.qinv().and_then(|q| q.to_biguint()) {
                    obj.insert("qi".into(), enc(&qi.to_bytes_be()).into());
                }
            }
            PrivateKey::P256(k) => {
                obj.insert("d".into(), enc(&k.to_bytes()).into());
            }
            PrivateKey::P384(k) => {
                obj.insert("d".into(), enc(&k.to_bytes()).into());
            }
            PrivateKey::P521(k) => {
                obj.insert("d".into(), enc(&k.to_bytes()).into());
            }
            PrivateKey::Ed25519(k) => {
                obj.insert("d".into(), enc(&k.to_bytes()).into());
            }
            PrivateKey::Opaque { .. } => unreachable!("public_jwk fails first"),
        }
        Ok(jwk)
    }
}

mod ecdsa_sign {
    use crate::util::Res;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    pub trait EcSig {
        fn der(&self) -> Vec<u8>;
        fn raw(&self) -> Vec<u8>;
    }
    macro_rules! impl_sig {
        ($t:ty) => {
            impl EcSig for $t {
                fn der(&self) -> Vec<u8> {
                    self.to_der().as_bytes().to_vec()
                }
                fn raw(&self) -> Vec<u8> {
                    self.to_bytes().to_vec()
                }
            }
        };
    }
    impl_sig!(p256::ecdsa::Signature);
    impl_sig!(p384::ecdsa::Signature);
    impl_sig!(p521::ecdsa::Signature);

    pub fn sign_prehash<K: PrehashSigner<S>, S: EcSig>(key: &K, digest: &[u8], raw: bool) -> Res<Vec<u8>> {
        let sig: S = key.sign_prehash(digest).map_err(|err| format!("ECDSA signing failed: {err}"))?;
        Ok(if raw { sig.raw() } else { sig.der() })
    }
}

fn pkcs1v15_scheme(hash: HashAlg) -> Pkcs1v15Sign {
    match hash {
        HashAlg::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        HashAlg::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    }
}

pub fn normalize_curve(name: &str) -> Option<String> {
    let n = name.to_ascii_uppercase().replace(['-', '_', ' '], "");
    if n.contains("256R1") || n.contains("PRIME256V1") || n == "P256" || n.contains("(P256)") {
        Some("P-256".into())
    } else if n.contains("384") {
        Some("P-384".into())
    } else if n.contains("521") {
        Some("P-521".into())
    } else {
        None
    }
}

pub fn curve_name(arcs: &[u64]) -> Option<String> {
    match arcs {
        a if a == oids::SECP256R1 => Some("P-256".into()),
        a if a == oids::SECP384R1 => Some("P-384".into()),
        a if a == oids::SECP521R1 => Some("P-521".into()),
        a if a == oids::SECP256K1 => Some("secp256k1".into()),
        _ => None,
    }
}

/// Algorithm summary of a `SubjectPublicKeyInfo`.
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub is_post_quantum: bool,
}

/// Splits a DER SPKI into (algorithm OID, parameters DER, subjectPublicKey bytes).
pub fn split_spki(spki: &[u8]) -> Res<(Vec<u64>, Option<Vec<u8>>, Vec<u8>)> {
    yasna::parse_der(spki, |r| {
        r.read_sequence(|r| {
            let alg = crate::pbe::read_algorithm_id(r.next())?;
            let (bits, _) = r.next().read_bitvec_bytes()?;
            Ok((alg.oid, alg.params, bits))
        })
    })
    .map_err(|err| format!("invalid SubjectPublicKeyInfo: {err}"))
}

pub fn public_key_info(spki: &[u8]) -> Res<PublicKeyInfo> {
    let (alg, params, bits) = split_spki(spki)?;
    let curve_oid = || -> Option<Vec<u64>> {
        yasna::parse_der(params.as_deref()?, |r| r.read_oid()).ok().map(|o| o.components().to_vec())
    };
    Ok(match alg.as_slice() {
        a if a == oids::RSA_ENCRYPTION || a == oids::RSASSA_PSS => {
            let size = RsaPublicKey::from_pkcs1_der(&bits).map(|k| (k.size() * 8) as u32).unwrap_or(0);
            let name = if a == oids::RSASSA_PSS { "RSASSA-PSS" } else { "RSA" };
            PublicKeyInfo { algorithm: name.into(), key_size: size, curve: None, is_post_quantum: false }
        }
        a if a == oids::EC_PUBLIC_KEY => {
            let c = curve_oid().unwrap_or_default();
            let curve = curve_name(&c).unwrap_or_else(|| oids::oid_str(&c));
            let size = match curve.as_str() {
                "P-256" | "secp256k1" => 256,
                "P-384" => 384,
                "P-521" => 521,
                _ => ((bits.len().saturating_sub(1)) / 2 * 8) as u32,
            };
            PublicKeyInfo { algorithm: "ECDSA".into(), key_size: size, curve: Some(curve), is_post_quantum: false }
        }
        a if a == oids::ED25519 => PublicKeyInfo { algorithm: "Ed25519".into(), key_size: 255, curve: Some("Curve25519".into()), is_post_quantum: false },
        a if a == oids::ED448 => PublicKeyInfo { algorithm: "Ed448".into(), key_size: 448, curve: Some("Curve448".into()), is_post_quantum: false },
        a if a == oids::X25519 => PublicKeyInfo { algorithm: "X25519".into(), key_size: 255, curve: Some("Curve25519".into()), is_post_quantum: false },
        a if a == oids::DSA => {
            // DSA parameters: SEQUENCE { p, q, g } — size is the bit length of p.
            let size = params
                .as_deref()
                .and_then(|p| {
                    yasna::parse_der(p, |r| {
                        r.read_sequence(|r| {
                            let (p, _) = r.next().read_bigint_bytes()?;
                            r.next().read_der()?;
                            r.next().read_der()?;
                            Ok(trim_leading_zeros(&p).len() * 8)
                        })
                    })
                    .ok()
                })
                .unwrap_or(0) as u32;
            PublicKeyInfo { algorithm: "DSA".into(), key_size: size, curve: None, is_post_quantum: false }
        }
        a => match oids::post_quantum_name(a) {
            Some(name) => PublicKeyInfo { algorithm: name.into(), key_size: (bits.len() * 8) as u32, curve: None, is_post_quantum: true },
            None => PublicKeyInfo { algorithm: oids::oid_str(a), key_size: (bits.len() * 8) as u32, curve: None, is_post_quantum: false },
        },
    })
}

/// Normalises a public key given as SPKI PEM/DER or PKCS#1 "RSA PUBLIC KEY" into SPKI DER.
pub fn public_key_from_bytes(data: &[u8]) -> Res<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains("-----BEGIN") {
            for block in pem_blocks(text) {
                match block.tag.as_str() {
                    "PUBLIC KEY" => return Ok(block.der),
                    "RSA PUBLIC KEY" => {
                        let k = RsaPublicKey::from_pkcs1_der(&block.der).map_err(e)?;
                        return Ok(k.to_public_key_der().map_err(e)?.as_bytes().to_vec());
                    }
                    _ => {}
                }
            }
            return Err("no public key found in the PEM data".into());
        }
    }
    split_spki(data).map(|_| data.to_vec())
}

/// Verifies `sig` over `msg` using a DER `SubjectPublicKeyInfo`.
pub fn verify(spki: &[u8], alg: SigAlg, msg: &[u8], sig: &[u8]) -> Res<bool> {
    verify_inner(spki, alg, msg, sig, false)
}

/// JWS variant of [`verify`]: ECDSA signatures are raw r‖s.
pub fn verify_jws(spki: &[u8], alg: SigAlg, msg: &[u8], sig: &[u8]) -> Res<bool> {
    verify_inner(spki, alg, msg, sig, true)
}

fn verify_inner(spki: &[u8], alg: SigAlg, msg: &[u8], sig: &[u8], raw_ecdsa: bool) -> Res<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let info = public_key_info(spki)?;
    match alg {
        SigAlg::Rsa(hash) => {
            let key = RsaPublicKey::from_public_key_der(spki).map_err(|err| format!("invalid RSA public key: {err}"))?;
            Ok(key.verify(pkcs1v15_scheme(hash), &hash.digest(msg), sig).is_ok())
        }
        SigAlg::Ecdsa(hash) => {
            let digest = hash.digest(msg);
            macro_rules! ec_verify {
                ($m:ident) => {{
                    let key = $m::ecdsa::VerifyingKey::from_public_key_der(spki).map_err(e)?;
                    let parsed = if raw_ecdsa { $m::ecdsa::Signature::from_slice(sig) } else { $m::ecdsa::Signature::from_der(sig) };
                    Ok(match parsed {
                        Ok(s) => key.verify_prehash(&digest, &s).is_ok(),
                        Err(_) => false,
                    })
                }};
            }
            match info.curve.as_deref() {
                Some("P-256") => ec_verify!(p256),
                Some("P-384") => ec_verify!(p384),
                Some("P-521") => {
                    let (_, _, point) = split_spki(spki)?;
                    let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(e)?;
                    let parsed = if raw_ecdsa { p521::ecdsa::Signature::from_slice(sig) } else { p521::ecdsa::Signature::from_der(sig) };
                    Ok(match parsed {
                        Ok(s) => key.verify_prehash(&digest, &s).is_ok(),
                        Err(_) => false,
                    })
                }
                other => Err(format!("unsupported EC curve {}", other.unwrap_or("?"))),
            }
        }
        SigAlg::Ed25519 => {
            use ed25519_dalek::Verifier;
            let key = ed25519_dalek::VerifyingKey::from_public_key_der(spki).map_err(e)?;
            let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else { return Ok(false) };
            Ok(key.verify(msg, &sig).is_ok())
        }
    }
}

/// True when `private` is the private half of the public key in `spki`.
pub fn key_matches_spki(private: &PrivateKey, spki: &[u8]) -> bool {
    let Ok(ours) = private.public_key_der() else { return false };
    match (split_spki(&ours), split_spki(spki)) {
        (Ok((a1, _, k1)), Ok((a2, _, k2))) => a1 == a2 && k1 == k2,
        _ => false,
    }
}

fn b64url_uint(bytes: &[u8]) -> String {
    B64URL.encode(trim_leading_zeros(bytes))
}

/// Public JWK (RFC 7517) for RSA, EC and Ed25519 keys.
pub fn public_jwk_from_spki(spki: &[u8]) -> Res<serde_json::Value> {
    let info = public_key_info(spki)?;
    let (_, _, bits) = split_spki(spki)?;
    let thumb_src;
    let jwk = match info.algorithm.as_str() {
        "RSA" => {
            let key = RsaPublicKey::from_public_key_der(spki).map_err(e)?;
            let n = b64url_uint(&key.n().to_bytes_be());
            let ee = b64url_uint(&key.e().to_bytes_be());
            thumb_src = format!(r#"{{"e":"{ee}","kty":"RSA","n":"{n}"}}"#);
            serde_json::json!({ "kty": "RSA", "n": n, "e": ee })
        }
        "ECDSA" => {
            let crv = info.curve.clone().unwrap_or_default();
            if bits.first() != Some(&0x04) {
                return Err("compressed EC points are not supported for JWK export".into());
            }
            let coord_len = (bits.len() - 1) / 2;
            let x = B64URL.encode(&bits[1..1 + coord_len]);
            let y = B64URL.encode(&bits[1 + coord_len..]);
            thumb_src = format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#);
            serde_json::json!({ "kty": "EC", "crv": crv, "x": x, "y": y })
        }
        "Ed25519" => {
            let x = B64URL.encode(&bits);
            thumb_src = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
            serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x })
        }
        other => return Err(format!("JWK export is not supported for {other} keys")),
    };
    let mut jwk = jwk;
    // RFC 7638 thumbprint makes a stable default key ID.
    jwk.as_object_mut().unwrap().insert("kid".into(), B64URL.encode(sha256(thumb_src.as_bytes())).into());
    Ok(jwk)
}

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn ssh_mpint(out: &mut Vec<u8>, data: &[u8]) {
    let trimmed = trim_leading_zeros(data);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = vec![0u8];
        v.extend_from_slice(trimmed);
        ssh_string(out, &v);
    } else {
        ssh_string(out, trimmed);
    }
}

/// OpenSSH `authorized_keys` line and its SHA256 fingerprint.
pub fn openssh_public_key(spki: &[u8], comment: &str) -> Res<(String, String)> {
    let info = public_key_info(spki)?;
    let (_, _, bits) = split_spki(spki)?;
    let mut blob = Vec::new();
    let key_type = match (info.algorithm.as_str(), info.curve.as_deref()) {
        ("RSA", _) => {
            let key = RsaPublicKey::from_public_key_der(spki).map_err(e)?;
            ssh_string(&mut blob, b"ssh-rsa");
            ssh_mpint(&mut blob, &key.e().to_bytes_be());
            ssh_mpint(&mut blob, &key.n().to_bytes_be());
            "ssh-rsa"
        }
        ("ECDSA", Some(curve @ ("P-256" | "P-384" | "P-521"))) => {
            let (name, ident) = match curve {
                "P-256" => ("ecdsa-sha2-nistp256", "nistp256"),
                "P-384" => ("ecdsa-sha2-nistp384", "nistp384"),
                _ => ("ecdsa-sha2-nistp521", "nistp521"),
            };
            ssh_string(&mut blob, name.as_bytes());
            ssh_string(&mut blob, ident.as_bytes());
            ssh_string(&mut blob, &bits);
            name
        }
        ("Ed25519", _) => {
            ssh_string(&mut blob, b"ssh-ed25519");
            ssh_string(&mut blob, &bits);
            "ssh-ed25519"
        }
        (other, _) => return Err(format!("OpenSSH export is not supported for {other} keys")),
    };
    let fingerprint = format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256(&blob)));
    let comment = comment.trim();
    let line = if comment.is_empty() { format!("{key_type} {}", b64(&blob)) } else { format!("{key_type} {} {comment}", b64(&blob)) };
    Ok((line, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(key: PrivateKey) {
        let der = key.to_pkcs8_der().unwrap();
        let parsed = PrivateKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(parsed.to_pkcs8_der().unwrap(), der);
        let spki = key.public_key_der().unwrap();
        assert!(key_matches_spki(&parsed, &spki));
        let alg = key.default_sig_alg(None).unwrap();
        let sig = key.sign(alg, b"hello").unwrap();
        assert!(verify(&spki, alg, b"hello", &sig).unwrap());
        assert!(!verify(&spki, alg, b"hellO", &sig).unwrap());
        if !matches!(key, PrivateKey::Rsa(_)) {
            let raw = key.sign_jws(alg, b"jws").unwrap();
            assert!(verify_jws(&spki, alg, b"jws", &raw).unwrap());
        }
        public_jwk_from_spki(&spki).unwrap();
        key.private_jwk().unwrap();
        openssh_public_key(&spki, "test").unwrap();
    }

    #[test]
    fn all_supported_algorithms_round_trip_and_sign() {
        round_trip(PrivateKey::generate("RSA", 2048, None).unwrap());
        round_trip(PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap());
        round_trip(PrivateKey::generate("ECDSA", 0, Some("P-384")).unwrap());
        round_trip(PrivateKey::generate("ECDSA", 0, Some("P-521")).unwrap());
        round_trip(PrivateKey::generate("Ed25519", 0, None).unwrap());
    }

    #[test]
    fn encrypted_and_traditional_pem_parse() {
        let key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let enc = crate::pbe::encrypt_pkcs8("pw", &der, 1000).unwrap();
        let pem = to_pem("ENCRYPTED PRIVATE KEY", &enc);
        assert!(PrivateKey::from_bytes(pem.as_bytes(), None).is_err());
        assert!(PrivateKey::from_bytes(pem.as_bytes(), Some("bad")).is_err());
        let back = PrivateKey::from_bytes(pem.as_bytes(), Some("pw")).unwrap();
        assert_eq!(back.to_pkcs8_der().unwrap(), der);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(PrivateKey::generate("ML-DSA-65", 0, None).is_err());
        assert!(PrivateKey::generate("RSA", 1000, None).is_err());
    }
}
