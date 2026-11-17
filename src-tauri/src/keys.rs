//! Asymmetric keys: generation, parsing, signing and verification, plus JWK and OpenSSH public
//! key encodings.
//!
//! Private keys are read from PKCS#8, encrypted PKCS#8, PKCS#1 (`RSA PRIVATE KEY`), SEC1
//! (`EC PRIVATE KEY`), the traditional DSA form, OpenSSL's pre-PKCS#8 encrypted PEM
//! (`Proc-Type: 4,ENCRYPTED`), OpenSSH's own format (see [`crate::openssh`]) and JWK.
//!
//! Keys we cannot use for signing (DSA, Ed448, RSASSA-PSS, other curves, post-quantum keys from
//! newer JDKs, …) are still carried as opaque PKCS#8 so keystores containing them load and save
//! losslessly, and their size and public key are worked out where the encoding allows it.

use crate::oids;
use crate::pbe::{self, HashAlg};
use crate::util::{Res, b64, check_der_lengths, e, pem_blocks, sha256, to_pem, trim_leading_zeros};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use num_bigint_dig::ModInverse;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use yasna::{DERWriter, Tag};

/// The RSA crate refuses a modulus over 4096 bits unless told otherwise, and 8192-bit roots are
/// in real trust stores. This is the largest key the app generates.
const MAX_RSA_BITS: usize = 16384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    Rsa(HashAlg),
    /// RSASSA-PSS with MGF1 over the same hash. Verified, never produced.
    RsaPss {
        hash: HashAlg,
        salt_len: usize,
    },
    Ecdsa(HashAlg),
    Ed25519,
    /// Verified so that old chains can be checked. FIPS 186-5 retired DSA for signing.
    Dsa(HashAlg),
}

impl SigAlg {
    pub fn oid(self) -> &'static [u64] {
        match self {
            SigAlg::Rsa(HashAlg::Sha1) => oids::SHA1_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha224) => oids::SHA224_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha256) => oids::SHA256_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha384) => oids::SHA384_WITH_RSA,
            SigAlg::Rsa(HashAlg::Sha512) => oids::SHA512_WITH_RSA,
            SigAlg::RsaPss { .. } => oids::RSASSA_PSS,
            SigAlg::Ecdsa(HashAlg::Sha1) => oids::ECDSA_SHA1,
            SigAlg::Ecdsa(HashAlg::Sha224) => oids::ECDSA_SHA224,
            SigAlg::Ecdsa(HashAlg::Sha256) => oids::ECDSA_SHA256,
            SigAlg::Ecdsa(HashAlg::Sha384) => oids::ECDSA_SHA384,
            SigAlg::Ecdsa(HashAlg::Sha512) => oids::ECDSA_SHA512,
            SigAlg::Ed25519 => oids::ED25519,
            SigAlg::Dsa(HashAlg::Sha1) => oids::DSA_SHA1,
            SigAlg::Dsa(HashAlg::Sha224) => oids::DSA_SHA224,
            SigAlg::Dsa(HashAlg::Sha256) => oids::DSA_SHA256,
            SigAlg::Dsa(HashAlg::Sha384) => oids::DSA_SHA384,
            SigAlg::Dsa(HashAlg::Sha512) => oids::DSA_SHA512,
        }
    }

    /// The algorithm for an OID that needs no parameters. RSASSA-PSS does: see
    /// [`Self::from_algorithm`].
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
            a if a == oids::DSA_SHA1 => SigAlg::Dsa(HashAlg::Sha1),
            a if a == oids::DSA_SHA224 => SigAlg::Dsa(HashAlg::Sha224),
            a if a == oids::DSA_SHA256 => SigAlg::Dsa(HashAlg::Sha256),
            a if a == oids::DSA_SHA384 => SigAlg::Dsa(HashAlg::Sha384),
            a if a == oids::DSA_SHA512 => SigAlg::Dsa(HashAlg::Sha512),
            _ => return None,
        })
    }

    /// The algorithm for a signature `AlgorithmIdentifier`: its OID and the DER of its parameters.
    /// None when it is one this app cannot check, which is not the same as a bad signature.
    pub fn from_algorithm(arcs: &[u64], params: Option<&[u8]>) -> Option<SigAlg> {
        if arcs == oids::RSASSA_PSS {
            let (hash, salt_len) = parse_pss_params(params)?;
            return Some(SigAlg::RsaPss { hash, salt_len });
        }
        Self::from_oid(arcs)
    }

    pub fn hash(self) -> HashAlg {
        match self {
            SigAlg::Rsa(h) | SigAlg::Ecdsa(h) | SigAlg::Dsa(h) | SigAlg::RsaPss { hash: h, .. } => h,
            SigAlg::Ed25519 => HashAlg::Sha512,
        }
    }

    pub fn name(self) -> String {
        match self {
            // The OID alone says nothing about the digest, which is what people look for.
            SigAlg::RsaPss { hash, .. } => format!("{}withRSA/PSS", hash.name().replace('-', "")),
            other => oids::signature_algorithm_name(other.oid()),
        }
    }

    /// Writes the X.509 `AlgorithmIdentifier` (RSA carries an explicit NULL parameter).
    pub fn write_algorithm_id(self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_oid(&oids::oid(self.oid()));
            match self {
                SigAlg::Rsa(_) => w.next().write_null(),
                SigAlg::RsaPss { hash, salt_len } => {
                    let hash_id = |w: DERWriter| {
                        w.write_sequence(|w| {
                            w.next().write_oid(&oids::oid(hash.digest_oid()));
                            w.next().write_null();
                        })
                    };
                    w.next().write_sequence(|w| {
                        w.next().write_tagged(Tag::context(0), hash_id);
                        w.next().write_tagged(Tag::context(1), |w| {
                            w.write_sequence(|w| {
                                w.next().write_oid(&oids::oid(oids::MGF1));
                                hash_id(w.next());
                            })
                        });
                        w.next().write_tagged(Tag::context(2), |w| w.write_u64(salt_len as u64));
                    });
                }
                SigAlg::Ecdsa(_) | SigAlg::Ed25519 | SigAlg::Dsa(_) => {}
            }
        });
    }
}

/// `RSASSA-PSS-params`: the hash and the salt length, when the mask generation function is MGF1
/// over that same hash (the only combination in use). Absent fields take their SHA-1 defaults.
fn parse_pss_params(params: Option<&[u8]>) -> Option<(HashAlg, usize)> {
    let Some(der) = params else { return Some((HashAlg::Sha1, 20)) };
    check_der_lengths(der).ok()?;
    let (hash, mgf, salt, trailer) = yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let hash = r.read_optional(|r| r.read_tagged(Tag::context(0), pbe::read_algorithm_id))?;
            let mgf = r.read_optional(|r| r.read_tagged(Tag::context(1), pbe::read_algorithm_id))?;
            let salt = r.read_optional(|r| r.read_tagged(Tag::context(2), |r| r.read_u64()))?;
            let trailer = r.read_optional(|r| r.read_tagged(Tag::context(3), |r| r.read_u64()))?;
            Ok((hash, mgf, salt, trailer))
        })
    })
    .ok()?;
    let hash = match hash {
        None => HashAlg::Sha1,
        Some(alg) => HashAlg::from_digest_oid(&alg.oid)?,
    };
    let mgf_hash = match mgf {
        None => HashAlg::Sha1,
        Some(alg) if alg.oid == oids::MGF1 => HashAlg::from_digest_oid(&pbe::parse_algorithm_id(alg.params.as_deref()?).ok()?.oid)?,
        Some(_) => return None,
    };
    if mgf_hash != hash || trailer.is_some_and(|t| t != 1) {
        return None;
    }
    let salt_len = usize::try_from(salt.unwrap_or(20)).ok().filter(|l| *l <= 1024)?;
    Some((hash, salt_len))
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
    /// A key we can store but not use (DSA, Ed448, X25519, post-quantum, RSA-PSS, other curves…).
    Opaque {
        algorithm: String,
        pkcs8: Vec<u8>,
        /// Size in bits when the encoding tells, otherwise 0.
        bits: u32,
        curve: Option<String>,
        /// The matching public key, when the encoding carries it or it is cheap to work out.
        spki: Option<Vec<u8>>,
    },
}

/// Names the key and nothing else: key material must never reach a log or an error message.
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey({})", self.describe())
    }
}

/// The parts of a PKCS#8 `PrivateKeyInfo` (or RFC 5958 `OneAsymmetricKey`).
struct Pkcs8 {
    alg: pbe::AlgorithmId,
    alg_der: Vec<u8>,
    private_key: Vec<u8>,
    /// The `[1]` public key of the version 2 form, without its BIT STRING header.
    public_key: Option<Vec<u8>>,
}

/// The content of one DER element whose length is in short or long definite form.
fn der_content(tlv: &[u8]) -> Option<&[u8]> {
    let first = *tlv.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        (tlv.get(2..2 + n)?.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), 2 + n)
    };
    tlv.get(header..header.checked_add(len)?)
}

impl Pkcs8 {
    fn parse(der: &[u8]) -> Res<Pkcs8> {
        check_der_lengths(der)?;
        let (alg_der, private_key, rest) = yasna::parse_ber(der, |r| {
            r.read_sequence(|r| {
                let _version = r.next().read_u8()?;
                let alg_der = r.next().read_der()?;
                let private_key = r.next().read_bytes()?;
                // [0] attributes and [1] publicKey, both optional and both implicitly tagged.
                let mut rest = Vec::new();
                while let Ok(extra) = r.next().read_der() {
                    rest.push(extra);
                }
                Ok((alg_der, private_key, rest))
            })
        })
        .map_err(|err| format!("not a PKCS#8 private key: {err}"))?;
        let alg = pbe::parse_algorithm_id(&alg_der).map_err(|err| format!("not a PKCS#8 private key: {err}"))?;
        // [1] IMPLICIT BIT STRING: one byte of unused bits, then the key.
        let public_key = rest.iter().find(|x| x.first().is_some_and(|t| t & 0x1F == 1 && t & 0xC0 == 0x80)).and_then(|x| der_content(x)).and_then(|c| c.split_first()).map(|(_, key)| key.to_vec());
        Ok(Pkcs8 { alg, alg_der, private_key, public_key })
    }
}

fn wrap_pkcs8(alg_der: &[u8], private_key: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_der(alg_der);
            w.next().write_bytes(private_key);
        })
    })
}

fn wrap_spki(alg_der: &[u8], key_bits: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(alg_der);
            w.next().write_bitvec_bytes(key_bits, key_bits.len() * 8);
        })
    })
}

fn algorithm_id_der(arcs: &[u64], params: Option<&[u8]>) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oids::oid(arcs));
            if let Some(p) = params {
                w.next().write_der(p);
            }
        })
    })
}

/// A SEC1 `ECPrivateKey`.
struct Sec1 {
    scalar: Vec<u8>,
    /// DER of the `[0]` parameters: a curve OID, or the domain parameters written out.
    params: Option<Vec<u8>>,
    public: Option<Vec<u8>>,
}

impl Sec1 {
    fn parse(der: &[u8]) -> Res<Sec1> {
        check_der_lengths(der)?;
        yasna::parse_ber(der, |r| {
            r.read_sequence(|r| {
                // ecPrivkeyVer1. Checking it keeps other small structures from passing as a key.
                if r.next().read_u8()? != 1 {
                    return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                }
                let scalar = r.next().read_bytes()?;
                let params = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
                let public = r.read_optional(|r| r.read_tagged(Tag::context(1), |r| r.read_bitvec_bytes().map(|(b, _)| b)))?;
                Ok(Sec1 { scalar, params, public })
            })
        })
        .map_err(|err| format!("invalid EC private key: {err}"))
    }
}

/// The curve named by EC parameters. Domain parameters that are written out in full are
/// recognised when they are one of the curves this app computes on, which is how LibreSSL (and so
/// `ssh-keygen -m PKCS8` on macOS) writes every EC key.
fn curve_of_params(params: &[u8]) -> Option<Vec<u64>> {
    match params.first()? {
        0x06 => yasna::parse_der(params, |r| r.read_oid()).ok().map(|o| o.components().to_vec()),
        0x30 => named_curve_of_explicit(params).map(<[u64]>::to_vec),
        _ => None,
    }
}

/// `ECParameters ::= SEQUENCE { version, fieldID, curve, base, order, cofactor OPTIONAL }`.
/// The base point identifies the curve: no two named curves share a generator.
fn named_curve_of_explicit(params: &[u8]) -> Option<&'static [u64]> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    check_der_lengths(params).ok()?;
    let base = yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let _version = r.next().read_u64()?;
            r.next().read_der()?;
            r.next().read_der()?;
            let base = r.next().read_bytes()?;
            while r.next().read_der().is_ok() {}
            Ok(base)
        })
    })
    .ok()?;
    // Uncompressed (04 x y) or compressed (02/03 x): the x coordinate settles it either way.
    let same = |generator: &[u8]| -> bool {
        let coord = (generator.len() - 1) / 2;
        match base.first() {
            Some(4) => base.as_slice() == generator,
            Some(2 | 3) => base.len() == 1 + coord && base[1..] == generator[1..1 + coord],
            _ => false,
        }
    };
    if same(p256::AffinePoint::GENERATOR.to_encoded_point(false).as_bytes()) {
        Some(oids::SECP256R1)
    } else if same(p384::AffinePoint::GENERATOR.to_encoded_point(false).as_bytes()) {
        Some(oids::SECP384R1)
    } else if same(p521::AffinePoint::GENERATOR.to_encoded_point(false).as_bytes()) {
        Some(oids::SECP521R1)
    } else {
        None
    }
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one round: how a `Proc-Type: 4,ENCRYPTED` PEM turns
/// its password into a key.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut block: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h = md5::Md5::new();
        h.update(&block);
        h.update(password);
        h.update(salt);
        block = h.finalize().to_vec();
        out.extend_from_slice(&block);
    }
    out.truncate(len);
    out
}

/// Decrypts the body of a PEM block that OpenSSL encrypted the traditional way.
fn decrypt_legacy_pem(dek_info: &str, password: &str, data: &[u8]) -> Res<Vec<u8>> {
    let malformed = || "invalid: the DEK-Info header of this key is malformed".to_string();
    let (cipher, iv_hex) = dek_info.split_once(',').ok_or_else(malformed)?;
    let iv = hex::decode(iv_hex.trim()).map_err(|_| malformed())?;
    if iv.len() < 8 {
        return Err(malformed());
    }
    let key = |len: usize| evp_bytes_to_key(password.as_bytes(), &iv[..8], len);
    let cipher = cipher.trim().to_ascii_uppercase();
    let plain = match cipher.as_str() {
        "AES-128-CBC" => pbe::aes_cbc_decrypt(&key(16), &iv, data),
        "AES-192-CBC" => pbe::aes_cbc_decrypt(&key(24), &iv, data),
        "AES-256-CBC" => pbe::aes_cbc_decrypt(&key(32), &iv, data),
        "DES-EDE3-CBC" => pbe::des3_cbc_decrypt(&key(24), &iv, data),
        "DES-CBC" => pbe::des_cbc_decrypt(&key(8), &iv, data),
        other => Err(format!("unsupported: this key is encrypted with {other}, which is not supported. Convert it with `openssl pkey -in key.pem -out key-pkcs8.pem`.")),
    };
    plain.map_err(wrong_key_password)
}

/// What a caller sees when decryption fails: an unsupported scheme and a damaged file say so,
/// anything else is the password.
fn wrong_key_password(err: String) -> String {
    if pbe::is_unsupported(&err) || err.starts_with("invalid:") { err } else { "incorrect private key password".into() }
}

const ENCRYPTED_NEEDS_PASSWORD: &str = "this private key is encrypted; enter its password";

impl PrivateKey {
    /// Generates a fresh key. `algorithm` is "RSA", "ECDSA"/"EC" or "Ed25519".
    pub fn generate(algorithm: &str, key_size: u32, curve: Option<&str>) -> Res<PrivateKey> {
        let mut rng = rand::rngs::OsRng;
        match algorithm.to_ascii_uppercase().as_str() {
            "RSA" => {
                if !(2048..=MAX_RSA_BITS as u32).contains(&key_size) || !key_size.is_multiple_of(8) {
                    return Err("RSA key size must be a multiple of 8 between 2048 and 16384 bits".into());
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
        let parts = Pkcs8::parse(der)?;
        let alg = parts.alg.oid.as_slice();
        if alg == oids::RSA_ENCRYPTION {
            return RsaPrivateKey::from_pkcs8_der(der).map(|k| PrivateKey::Rsa(Box::new(k))).map_err(|err| format!("invalid RSA key: {err}"));
        }
        if alg == oids::EC_PUBLIC_KEY {
            return Self::from_ec(parts.alg.params.as_deref(), &parts.private_key, Some(der));
        }
        if alg == oids::ED25519 {
            return ed25519_dalek::SigningKey::from_pkcs8_der(der).map(|k| PrivateKey::Ed25519(Box::new(k))).map_err(|err| format!("invalid Ed25519 key: {err}"));
        }
        Ok(opaque_key(&parts, der))
    }

    /// An EC key from the pieces PKCS#8 and SEC1 share: the curve parameters (from the PKCS#8
    /// algorithm identifier when there is one) and the `ECPrivateKey`. `pkcs8` is the encoding
    /// the key arrived in, kept as it is for a curve this app does not compute on.
    fn from_ec(params: Option<&[u8]>, sec1_der: &[u8], pkcs8: Option<&[u8]>) -> Res<PrivateKey> {
        let sec1 = Sec1::parse(sec1_der)?;
        let params = params.map(<[u8]>::to_vec).or_else(|| sec1.params.clone());
        let curve = match params.as_deref() {
            Some(p) => curve_of_params(p),
            // A bare SEC1 key may leave the curve out; its size is then the only hint.
            None => Some(
                match sec1.scalar.len() {
                    48 => oids::SECP384R1,
                    65 | 66 => oids::SECP521R1,
                    _ => oids::SECP256R1,
                }
                .to_vec(),
            ),
        };
        macro_rules! nist {
            ($m:ident, $variant:ident, $len:expr) => {{
                use $m::elliptic_curve::sec1::ToEncodedPoint;
                // Some encoders pad the scalar with a zero byte, others drop leading zeros.
                let scalar = if sec1.scalar.len() > $len { trim_leading_zeros(&sec1.scalar) } else { &sec1.scalar };
                let key = $m::SecretKey::from_slice(scalar).map_err(|_| "invalid EC private key".to_string())?;
                if let Some(stored) = &sec1.public {
                    let ours = key.public_key().to_encoded_point(stored.first() != Some(&4));
                    if ours.as_bytes() != stored.as_slice() {
                        return Err("invalid EC private key: it does not match the public key stored with it".into());
                    }
                }
                Ok(PrivateKey::$variant(key))
            }};
        }
        match curve.as_deref() {
            Some(c) if c == oids::SECP256R1 => nist!(p256, P256, 32),
            Some(c) if c == oids::SECP384R1 => nist!(p384, P384, 48),
            Some(c) if c == oids::SECP521R1 => nist!(p521, P521, 66),
            _ => {
                let params = params.ok_or("invalid EC private key: the curve is not named")?;
                let alg_der = algorithm_id_der(oids::EC_PUBLIC_KEY, Some(&params));
                let pkcs8 = pkcs8.map(<[u8]>::to_vec).unwrap_or_else(|| wrap_pkcs8(&alg_der, sec1_der));
                let named = curve.as_deref().and_then(curve_info);
                let label = match (&named, curve.as_deref()) {
                    (Some((name, _)), _) => name.to_string(),
                    (None, Some(arcs)) => oids::oid_str(arcs),
                    (None, None) => "custom parameters".to_string(),
                };
                Ok(PrivateKey::Opaque {
                    algorithm: format!("EC ({label})"),
                    pkcs8,
                    bits: named.map(|(_, bits)| bits).unwrap_or((sec1.scalar.len() * 8) as u32),
                    curve: Some(label),
                    spki: sec1.public.as_ref().map(|point| wrap_spki(&alg_der, point)),
                })
            }
        }
    }

    /// Parses PEM, DER or JWK key material: PKCS#8, encrypted PKCS#8 (needs `password`), PKCS#1
    /// `RSA PRIVATE KEY`, SEC1 `EC PRIVATE KEY`, `DSA PRIVATE KEY`, any of those encrypted the
    /// traditional OpenSSL way, an OpenSSH private key, or a private JWK.
    pub fn from_bytes(data: &[u8], password: Option<&str>) -> Res<PrivateKey> {
        let password = password.filter(|p| !p.is_empty());
        if let Ok(text) = std::str::from_utf8(data) {
            if text.contains("-----BEGIN") {
                return Self::from_pem(text, password);
            }
            if text.trim_start().starts_with('{') {
                return Self::from_jwk(text);
            }
        }
        // DER: try PKCS#8, then encrypted PKCS#8, PKCS#1, SEC1 and the traditional DSA form.
        if let Ok(k) = Self::from_pkcs8_der(data) {
            return Ok(k);
        }
        if is_encrypted_pkcs8(data) {
            let pw = password.ok_or(ENCRYPTED_NEEDS_PASSWORD)?;
            return Self::from_pkcs8_der(&pbe::decrypt_pkcs8(pw, data).map_err(wrong_key_password)?);
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_der(data) {
            return Ok(PrivateKey::Rsa(Box::new(k)));
        }
        if let Ok(k) = Self::from_ec(None, data, None) {
            return Ok(k);
        }
        dsa_traditional_to_pkcs8(data).and_then(|der| Self::from_pkcs8_der(&der)).map_err(|_| "unrecognised private key format".to_string())
    }

    fn from_pem(text: &str, password: Option<&str>) -> Res<PrivateKey> {
        for block in pem_blocks(text) {
            let tag = block.tag.as_str();
            if !tag.contains("PRIVATE KEY") {
                continue;
            }
            if tag == "OPENSSH PRIVATE KEY" {
                return crate::openssh::decode_private_key(&block.der, password).map(|k| k.key);
            }
            // `Proc-Type: 4,ENCRYPTED`: the body is the traditional encoding under a cipher.
            let body = match block.legacy_encryption() {
                Some(dek_info) => decrypt_legacy_pem(dek_info, password.ok_or(ENCRYPTED_NEEDS_PASSWORD)?, &block.der)?,
                None => block.der,
            };
            return match tag {
                "ENCRYPTED PRIVATE KEY" => {
                    let pw = password.ok_or(ENCRYPTED_NEEDS_PASSWORD)?;
                    Self::from_pkcs8_der(&pbe::decrypt_pkcs8(pw, &body).map_err(wrong_key_password)?)
                }
                "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&body).map(|k| PrivateKey::Rsa(Box::new(k))).map_err(|err| format!("invalid RSA key: {err}")),
                "EC PRIVATE KEY" => Self::from_ec(None, &body, None),
                "DSA PRIVATE KEY" => Self::from_pkcs8_der(&dsa_traditional_to_pkcs8(&body)?),
                // "PRIVATE KEY", and the "ANY PRIVATE KEY" some tools write.
                _ => Self::from_pkcs8_der(&body),
            };
        }
        Err("no private key found in the PEM data".into())
    }

    /// A private JWK (RFC 7517/7518/8037), or the first private key of a JWK set.
    pub fn from_jwk(text: &str) -> Res<PrivateKey> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|err| format!("invalid JSON: {err}"))?;
        let jwk = match value.get("keys").and_then(|k| k.as_array()) {
            Some(keys) => keys.iter().find(|k| k.get("d").is_some()).cloned().ok_or("the JWK set holds no private key")?,
            None => value,
        };
        let field = |name: &str| -> Res<Vec<u8>> {
            let v = jwk.get(name).and_then(|v| v.as_str()).ok_or_else(|| format!("the JWK has no '{name}', so it is not a private key"))?;
            B64URL.decode(v.trim_end_matches('=')).map_err(|_| format!("the JWK '{name}' is not base64url"))
        };
        let optional = |name: &str| -> Res<Option<BigUint>> {
            match jwk.get(name) {
                None => Ok(None),
                Some(_) => field(name).map(|b| Some(BigUint::from_bytes_be(&b))),
            }
        };
        let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or("the JWK has no 'kty'")?;
        let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
        match kty {
            "RSA" => {
                if jwk.get("oth").is_some() {
                    return Err("multi-prime RSA keys are not supported".into());
                }
                let n = BigUint::from_bytes_be(&field("n")?);
                let ex = BigUint::from_bytes_be(&field("e")?);
                let d = BigUint::from_bytes_be(&field("d")?);
                // The primes are optional in a JWK; the RSA crate recovers them from d when absent.
                let primes = match (optional("p")?, optional("q")?) {
                    (Some(p), Some(q)) => vec![p, q],
                    _ => Vec::new(),
                };
                RsaPrivateKey::from_components(n, ex, d, primes).map(|k| PrivateKey::Rsa(Box::new(k))).map_err(|err| format!("invalid RSA key in the JWK: {err}"))
            }
            "EC" => {
                let d = field("d")?;
                let bad = |_| format!("invalid {crv} private key in the JWK");
                let key = match crv {
                    "P-256" => PrivateKey::P256(p256::SecretKey::from_slice(&d).map_err(bad)?),
                    "P-384" => PrivateKey::P384(p384::SecretKey::from_slice(&d).map_err(bad)?),
                    "P-521" => PrivateKey::P521(p521::SecretKey::from_slice(&d).map_err(bad)?),
                    other => return Err(format!("unsupported JWK curve '{other}' (P-256, P-384 and P-521 are supported)")),
                };
                // x and y are redundant with d; when they are there, they have to agree with it.
                if jwk.get("x").is_some() && jwk.get("y").is_some() {
                    let ours = key.public_jwk()?;
                    let same = |name: &str| -> Res<bool> { Ok(B64URL.decode(ours[name].as_str().unwrap_or_default()).ok() == Some(field(name)?)) };
                    if !same("x")? || !same("y")? {
                        return Err("invalid JWK: the public coordinates do not match the private key".into());
                    }
                }
                Ok(key)
            }
            "OKP" if crv == "Ed25519" => {
                let seed: [u8; 32] = field("d")?.try_into().map_err(|_| "invalid Ed25519 private key in the JWK: expected 32 bytes".to_string())?;
                Ok(PrivateKey::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&seed))))
            }
            "OKP" => Err(format!("unsupported JWK curve '{crv}' (Ed25519 is supported)")),
            "oct" => Err("this is a symmetric (oct) JWK, not a private key".into()),
            other => Err(format!("unsupported JWK key type '{other}'")),
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

    /// PKCS#1 for RSA and SEC1 for the three NIST curves. Other algorithms have no traditional encoding.
    pub fn to_traditional_pem(&self) -> Res<String> {
        match self {
            PrivateKey::Rsa(k) => {
                use rsa::pkcs1::EncodeRsaPrivateKey;
                Ok(to_pem("RSA PRIVATE KEY", k.to_pkcs1_der().map_err(e)?.as_bytes()))
            }
            PrivateKey::P256(k) => Ok(to_pem("EC PRIVATE KEY", &k.to_sec1_der().map_err(e)?)),
            PrivateKey::P384(k) => Ok(to_pem("EC PRIVATE KEY", &k.to_sec1_der().map_err(e)?)),
            PrivateKey::P521(k) => Ok(to_pem("EC PRIVATE KEY", &k.to_sec1_der().map_err(e)?)),
            _ => Err("this algorithm has no PKCS#1 or SEC1 form; export PKCS#8 instead".into()),
        }
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
            PrivateKey::Opaque { algorithm, spki, .. } => {
                return spki.clone().ok_or_else(|| format!("the public key of this {algorithm} key cannot be worked out from the private key alone; read it from the certificate instead"));
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
            PrivateKey::Opaque { bits, .. } => *bits,
        }
    }

    pub fn curve(&self) -> Option<String> {
        match self {
            PrivateKey::P256(_) => Some("P-256".into()),
            PrivateKey::P384(_) => Some("P-384".into()),
            PrivateKey::P521(_) => Some("P-521".into()),
            PrivateKey::Ed25519(_) => Some("Curve25519".into()),
            PrivateKey::Opaque { curve, .. } => curve.clone(),
            PrivateKey::Rsa(_) => None,
        }
    }

    /// "RSA 2048-bit", "Ed448", "EC (secp256k1) 256-bit": the algorithm with its size when known.
    pub fn describe(&self) -> String {
        match self.key_size() {
            0 => self.algorithm(),
            bits => format!("{} {bits}-bit", self.algorithm()),
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
            PrivateKey::Opaque { algorithm, .. } => return Err(format!("{algorithm} keys cannot be used for signing in Keystore Studio")),
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
            (PrivateKey::P256(k), SigAlg::Ecdsa(hash)) => sign_prehash::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(&p256::ecdsa::SigningKey::from(k), &hash.digest(msg), raw_ecdsa),
            (PrivateKey::P384(k), SigAlg::Ecdsa(hash)) => sign_prehash::<p384::ecdsa::SigningKey, p384::ecdsa::Signature>(&p384::ecdsa::SigningKey::from(k), &hash.digest(msg), raw_ecdsa),
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
        if let PrivateKey::Opaque { algorithm, .. } = self {
            return Err(format!("JWK export is not supported for {algorithm} keys"));
        }
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
            PrivateKey::Opaque { .. } => unreachable!("returned above"),
        }
        Ok(jwk)
    }
}

/// The PEM label of a traditional (pre-PKCS#8) private key given as DER, when `der` is one.
pub fn traditional_label(der: &[u8]) -> Option<&'static str> {
    if RsaPrivateKey::from_pkcs1_der(der).is_ok() {
        return Some("RSA PRIVATE KEY");
    }
    if PrivateKey::from_ec(None, der, None).is_ok() {
        return Some("EC PRIVATE KEY");
    }
    dsa_traditional_to_pkcs8(der).ok().map(|_| "DSA PRIVATE KEY")
}

/// True for DER shaped like an `EncryptedPrivateKeyInfo`: an algorithm identifier from the
/// PKCS#5 or PKCS#12 password-based families, then an OCTET STRING.
pub fn is_encrypted_pkcs8(der: &[u8]) -> bool {
    const PKCS5: &[u64] = &[1, 2, 840, 113549, 1, 5];
    const PKCS12_PBE: &[u64] = &[1, 2, 840, 113549, 1, 12, 1];
    pbe::parse_encrypted_pkcs8(der).map(|(alg, _)| alg.oid.starts_with(PKCS5) || alg.oid.starts_with(PKCS12_PBE) || alg.oid == oids::PBE_MD5_3DES).unwrap_or(false)
}

/// Builds the opaque form of a key this app stores but does not compute with, reading what it
/// can from the encoding: the size, and the public key.
fn opaque_key(parts: &Pkcs8, der: &[u8]) -> PrivateKey {
    let alg = parts.alg.oid.as_slice();
    let stored_public = || parts.public_key.as_ref().map(|key| wrap_spki(&parts.alg_der, key));
    let (algorithm, bits, curve, spki) = match alg {
        a if a == oids::DSA => {
            let derived = dsa_public(parts.alg.params.as_deref(), &parts.private_key);
            let bits = derived.as_ref().map(|(bits, _)| *bits).unwrap_or(0);
            ("DSA".to_string(), bits, None, derived.map(|(_, y)| wrap_spki(&parts.alg_der, &y)))
        }
        a if a == oids::RSASSA_PSS => {
            // The key itself is an ordinary RSAPrivateKey; only the algorithm identifier differs.
            let public = rsa_public_of_private(&parts.private_key);
            let bits = public.as_ref().map(|(bits, _)| *bits).unwrap_or(0);
            ("RSASSA-PSS".to_string(), bits, None, public.map(|(_, pkcs1)| wrap_spki(&parts.alg_der, &pkcs1)))
        }
        a if a == oids::ED448 => ("Ed448".to_string(), 456, Some("Curve448".to_string()), stored_public()),
        a if a == oids::X25519 => ("X25519".to_string(), 255, Some("Curve25519".to_string()), stored_public()),
        a if a == oids::X448 => ("X448".to_string(), 448, Some("Curve448".to_string()), stored_public()),
        a => (oids::post_quantum_name(a).map(String::from).unwrap_or_else(|| oids::oid_str(a)), 0, None, stored_public()),
    };
    PrivateKey::Opaque { algorithm, pkcs8: der.to_vec(), bits, curve, spki }
}

/// (modulus bits, DER `RSAPublicKey`) for a DER `RSAPrivateKey`.
fn rsa_public_of_private(pkcs1: &[u8]) -> Option<(u32, Vec<u8>)> {
    check_der_lengths(pkcs1).ok()?;
    let (n, ex) = yasna::parse_ber(pkcs1, |r| {
        r.read_sequence(|r| {
            let _version = r.next().read_u8()?;
            let (n, _) = r.next().read_bigint_bytes()?;
            let (ex, _) = r.next().read_bigint_bytes()?;
            while r.next().read_der().is_ok() {}
            Ok((n, ex))
        })
    })
    .ok()?;
    let public = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bigint_bytes(&n, true);
            w.next().write_bigint_bytes(&ex, true);
        })
    });
    Some(((trim_leading_zeros(&n).len() * 8) as u32, public))
}

// ---------------------------------------------------------------------------------------------
// DSA: enough to carry keys and check signatures, never to sign.
// ---------------------------------------------------------------------------------------------

struct DsaParams {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

/// `Dss-Parms ::= SEQUENCE { p, q, g }`. Sizes beyond anything FIPS 186 defines are refused, so
/// a hostile certificate cannot make verification run for minutes.
fn parse_dsa_params(der: &[u8]) -> Option<DsaParams> {
    check_der_lengths(der).ok()?;
    let (p, q, g) = yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let (p, _) = r.next().read_bigint_bytes()?;
            let (q, _) = r.next().read_bigint_bytes()?;
            let (g, _) = r.next().read_bigint_bytes()?;
            Ok((p, q, g))
        })
    })
    .ok()?;
    let (p, q, g) = (BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q), BigUint::from_bytes_be(&g));
    let one = BigUint::from(1u8);
    if p.bits() < 512 || p.bits() > 8192 || q.bits() < 160 || q.bits() > 512 || g <= one || g >= p {
        return None;
    }
    Some(DsaParams { p, q, g })
}

fn der_uint(der: &[u8]) -> Option<BigUint> {
    check_der_lengths(der).ok()?;
    yasna::parse_ber(der, |r| r.read_bigint_bytes()).ok().filter(|(_, positive)| *positive).map(|(bytes, _)| BigUint::from_bytes_be(&bytes))
}

fn uint_der(value: &BigUint) -> Vec<u8> {
    yasna::construct_der(|w| w.write_bigint_bytes(&value.to_bytes_be(), true))
}

/// (bits of p, DER INTEGER y) for a DSA private key: y = g^x mod p.
fn dsa_public(params: Option<&[u8]>, private_key: &[u8]) -> Option<(u32, Vec<u8>)> {
    let params = parse_dsa_params(params?)?;
    let x = der_uint(private_key)?;
    if x >= params.q {
        return None;
    }
    Some((params.p.bits() as u32, uint_der(&params.g.modpow(&x, &params.p))))
}

/// The traditional `DSA PRIVATE KEY` (`SEQUENCE { 0, p, q, g, y, x }`) as PKCS#8.
fn dsa_traditional_to_pkcs8(der: &[u8]) -> Res<Vec<u8>> {
    check_der_lengths(der)?;
    let ints = yasna::parse_ber(der, |r| r.collect_sequence_of(|r| r.read_bigint_bytes().map(|(bytes, _)| bytes))).map_err(|err| format!("invalid DSA private key: {err}"))?;
    let [version, p, q, g, _y, x] = ints.as_slice() else { return Err("invalid DSA private key".into()) };
    if trim_leading_zeros(version) != [0] {
        return Err("invalid DSA private key".into());
    }
    let params = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for value in [p, q, g] {
                w.next().write_bigint_bytes(value, true);
            }
        })
    });
    let x = yasna::construct_der(|w| w.write_bigint_bytes(x, true));
    Ok(wrap_pkcs8(&algorithm_id_der(oids::DSA, Some(&params)), &x))
}

/// FIPS 186-4 section 4.7. `digest` is the hash of the message.
fn dsa_verify(spki: &[u8], digest: &[u8], sig: &[u8]) -> Res<bool> {
    let (_, params, key_bits) = split_spki(spki)?;
    let params = params.as_deref().and_then(parse_dsa_params).ok_or("unsupported DSA public key (its parameters are missing or out of range)")?;
    let y = der_uint(&key_bits).ok_or("invalid DSA public key")?;
    if check_der_lengths(sig).is_err() {
        return Ok(false);
    }
    let Ok((r, s)) = yasna::parse_ber(sig, |rd| {
        rd.read_sequence(|rd| {
            let (r, _) = rd.next().read_bigint_bytes()?;
            let (s, _) = rd.next().read_bigint_bytes()?;
            Ok((BigUint::from_bytes_be(&r), BigUint::from_bytes_be(&s)))
        })
    }) else {
        return Ok(false);
    };
    let zero = BigUint::from(0u8);
    if r == zero || s == zero || r >= params.q || s >= params.q || y <= BigUint::from(1u8) || y >= params.p {
        return Ok(false);
    }
    let Some(w) = (&s).mod_inverse(&params.q).and_then(|w| w.to_biguint()) else { return Ok(false) };
    // z is the leftmost min(N, outlen) bits of the digest.
    let mut z = BigUint::from_bytes_be(digest);
    let (digest_bits, n) = (digest.len() * 8, params.q.bits());
    if digest_bits > n {
        z >>= digest_bits - n;
    }
    let u1 = (&z * &w) % &params.q;
    let u2 = (&r * &w) % &params.q;
    let v = ((params.g.modpow(&u1, &params.p) * y.modpow(&u2, &params.p)) % &params.p) % &params.q;
    Ok(v == r)
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

fn pss_scheme(hash: HashAlg, salt_len: usize) -> Pss {
    match hash {
        HashAlg::Sha1 => Pss::new_with_salt::<Sha1>(salt_len),
        HashAlg::Sha224 => Pss::new_with_salt::<Sha224>(salt_len),
        HashAlg::Sha256 => Pss::new_with_salt::<Sha256>(salt_len),
        HashAlg::Sha384 => Pss::new_with_salt::<Sha384>(salt_len),
        HashAlg::Sha512 => Pss::new_with_salt::<Sha512>(salt_len),
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

/// Name and size in bits of a named curve, for the curves found in certificates and keystores.
pub fn curve_info(arcs: &[u64]) -> Option<(&'static str, u32)> {
    Some(match arcs {
        a if a == oids::SECP256R1 => ("P-256", 256),
        a if a == oids::SECP384R1 => ("P-384", 384),
        a if a == oids::SECP521R1 => ("P-521", 521),
        a if a == oids::SECP256K1 => ("secp256k1", 256),
        [1, 2, 840, 10045, 3, 1, 1] => ("P-192", 192),
        [1, 3, 132, 0, 33] => ("P-224", 224),
        [1, 3, 132, 0, 32] => ("secp224k1", 224),
        [1, 3, 132, 0, 31] => ("secp192k1", 192),
        [1, 3, 132, 0, 8] => ("secp160r1", 160),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 1] => ("brainpoolP160r1", 160),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 3] => ("brainpoolP192r1", 192),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 5] => ("brainpoolP224r1", 224),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 7] => ("brainpoolP256r1", 256),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 8] => ("brainpoolP256t1", 256),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 9] => ("brainpoolP320r1", 320),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 11] => ("brainpoolP384r1", 384),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 12] => ("brainpoolP384t1", 384),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 13] => ("brainpoolP512r1", 512),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 14] => ("brainpoolP512t1", 512),
        [1, 2, 156, 10197, 1, 301] => ("SM2", 256),
        [1, 2, 250, 1, 223, 101, 256, 1] => ("FRP256v1", 256),
        _ => return None,
    })
}

pub fn curve_name(arcs: &[u64]) -> Option<String> {
    curve_info(arcs).map(|(name, _)| name.to_string())
}

/// Algorithm summary of a `SubjectPublicKeyInfo`.
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub is_post_quantum: bool,
}

/// The three parts of a `SubjectPublicKeyInfo`: the algorithm OID, the algorithm's parameters
/// (absent for RSA and the Edwards curves, the curve OID for ECDSA), and the key bits.
pub type SpkiParts = (Vec<u64>, Option<Vec<u8>>, Vec<u8>);

/// Splits a DER SPKI into its algorithm OID, parameters DER and subjectPublicKey bytes.
pub fn split_spki(spki: &[u8]) -> Res<SpkiParts> {
    check_der_lengths(spki)?;
    yasna::parse_der(spki, |r| {
        r.read_sequence(|r| {
            let alg = crate::pbe::read_algorithm_id(r.next())?;
            let (bits, _) = r.next().read_bitvec_bytes()?;
            Ok((alg.oid, alg.params, bits))
        })
    })
    .map_err(|err| format!("invalid SubjectPublicKeyInfo: {err}"))
}

/// An RSA public key from a DER `RSAPublicKey`, without the RSA crate's 4096-bit ceiling.
pub fn rsa_public_from_pkcs1(der: &[u8]) -> Res<RsaPublicKey> {
    check_der_lengths(der)?;
    let (n, ex) = yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let (n, n_positive) = r.next().read_bigint_bytes()?;
            let (ex, e_positive) = r.next().read_bigint_bytes()?;
            if !n_positive || !e_positive {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            Ok((n, ex))
        })
    })
    .map_err(|err| format!("invalid RSA public key: {err}"))?;
    RsaPublicKey::new_with_max_size(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&ex), MAX_RSA_BITS).map_err(|err| format!("invalid RSA public key: {err}"))
}

/// The RSA key in a `SubjectPublicKeyInfo`, whether it is labelled rsaEncryption or RSASSA-PSS.
pub fn rsa_public_from_spki(spki: &[u8]) -> Res<RsaPublicKey> {
    let (alg, _, bits) = split_spki(spki)?;
    if alg != oids::RSA_ENCRYPTION && alg != oids::RSASSA_PSS {
        return Err("not an RSA public key".into());
    }
    rsa_public_from_pkcs1(&bits)
}

/// A `SubjectPublicKeyInfo` (rsaEncryption) for an RSA public key of any size.
pub fn rsa_spki(key: &RsaPublicKey) -> Vec<u8> {
    let pkcs1 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bigint_bytes(&key.n().to_bytes_be(), true);
            w.next().write_bigint_bytes(&key.e().to_bytes_be(), true);
        })
    });
    wrap_spki(
        &yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oids::oid(oids::RSA_ENCRYPTION));
                w.next().write_null();
            })
        }),
        &pkcs1,
    )
}

pub fn public_key_info(spki: &[u8]) -> Res<PublicKeyInfo> {
    let (alg, params, bits) = split_spki(spki)?;
    Ok(match alg.as_slice() {
        a if a == oids::RSA_ENCRYPTION || a == oids::RSASSA_PSS => {
            let size = rsa_public_from_pkcs1(&bits).map(|k| (k.size() * 8) as u32).unwrap_or(0);
            let name = if a == oids::RSASSA_PSS { "RSASSA-PSS" } else { "RSA" };
            PublicKeyInfo { algorithm: name.into(), key_size: size, curve: None, is_post_quantum: false }
        }
        a if a == oids::EC_PUBLIC_KEY => {
            let c = params.as_deref().and_then(curve_of_params);
            let known = c.as_deref().and_then(curve_info);
            let curve = match (&known, &c) {
                (Some((name, _)), _) => name.to_string(),
                (None, Some(arcs)) => oids::oid_str(arcs),
                (None, None) => "custom parameters".to_string(),
            };
            let size = known.map(|(_, bits)| bits).unwrap_or(((bits.len().saturating_sub(1)) / 2 * 8) as u32);
            PublicKeyInfo { algorithm: "ECDSA".into(), key_size: size, curve: Some(curve), is_post_quantum: false }
        }
        a if a == oids::ED25519 => PublicKeyInfo { algorithm: "Ed25519".into(), key_size: 255, curve: Some("Curve25519".into()), is_post_quantum: false },
        a if a == oids::ED448 => PublicKeyInfo { algorithm: "Ed448".into(), key_size: 456, curve: Some("Curve448".into()), is_post_quantum: false },
        a if a == oids::X25519 => PublicKeyInfo { algorithm: "X25519".into(), key_size: 255, curve: Some("Curve25519".into()), is_post_quantum: false },
        a if a == oids::X448 => PublicKeyInfo { algorithm: "X448".into(), key_size: 448, curve: Some("Curve448".into()), is_post_quantum: false },
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
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        for block in pem_blocks(text) {
            match block.tag.as_str() {
                "PUBLIC KEY" => return Ok(block.der),
                "RSA PUBLIC KEY" => return Ok(rsa_spki(&rsa_public_from_pkcs1(&block.der)?)),
                _ => {}
            }
        }
        return Err("no public key found in the PEM data".into());
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
    match alg {
        SigAlg::Rsa(hash) => {
            let key = rsa_public_from_spki(spki)?;
            Ok(key.verify(pkcs1v15_scheme(hash), &hash.digest(msg), sig).is_ok())
        }
        SigAlg::RsaPss { hash, salt_len } => {
            let key = rsa_public_from_spki(spki)?;
            Ok(key.verify(pss_scheme(hash, salt_len), &hash.digest(msg), sig).is_ok())
        }
        SigAlg::Dsa(hash) => dsa_verify(spki, &hash.digest(msg), sig),
        SigAlg::Ecdsa(hash) => {
            let info = public_key_info(spki)?;
            let digest = hash.digest(msg);
            macro_rules! ec_verify {
                ($m:ident) => {{
                    // From the point, not the SPKI: the crates accept a named curve only, and
                    // LibreSSL writes the curve's parameters out in full.
                    let (_, _, point) = split_spki(spki)?;
                    let key = $m::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(e)?;
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
                Some("P-521") => ec_verify!(p521),
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
            let key = rsa_public_from_spki(spki)?;
            let n = b64url_uint(&key.n().to_bytes_be());
            let ee = b64url_uint(&key.e().to_bytes_be());
            thumb_src = format!(r#"{{"e":"{ee}","kty":"RSA","n":"{n}"}}"#);
            serde_json::json!({ "kty": "RSA", "n": n, "e": ee })
        }
        "ECDSA" => {
            let crv = info.curve.clone().unwrap_or_default();
            // The curves JOSE registers (RFC 7518, RFC 8812). Others have no "crv" value.
            if !matches!(crv.as_str(), "P-256" | "P-384" | "P-521" | "secp256k1") {
                return Err(format!("JWK export is not supported for the curve {crv}"));
            }
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

pub(crate) fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

pub(crate) fn ssh_mpint(out: &mut Vec<u8>, data: &[u8]) {
    let trimmed = trim_leading_zeros(data);
    if trimmed == [0] {
        // Zero is the empty string in SSH's mpint encoding.
        ssh_string(out, &[]);
    } else if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = vec![0u8];
        v.extend_from_slice(trimmed);
        ssh_string(out, &v);
    } else {
        ssh_string(out, trimmed);
    }
}

/// `SubjectPublicKeyInfo` of a raw Ed25519 public key.
pub fn ed25519_spki(raw: &[u8]) -> Res<Vec<u8>> {
    let bytes: [u8; 32] = raw.try_into().map_err(|_| "invalid Ed25519 public key: expected 32 bytes".to_string())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(e)?;
    Ok(key.to_public_key_der().map_err(e)?.as_bytes().to_vec())
}

/// `SubjectPublicKeyInfo` of an uncompressed or compressed SEC1 point. `curve` is `P-256`,
/// `nistp384`, `p521` or the like.
pub fn ec_spki(curve: &str, point: &[u8]) -> Res<Vec<u8>> {
    let name = curve.to_ascii_lowercase().replace(['-', '_'], "");
    let der = match name.trim_start_matches("nist") {
        "p256" => p256::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-256 public key".to_string())?.to_public_key_der(),
        "p384" => p384::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-384 public key".to_string())?.to_public_key_der(),
        "p521" => p521::PublicKey::from_sec1_bytes(point).map_err(|_| "invalid P-521 public key".to_string())?.to_public_key_der(),
        _ => return Err(format!("unsupported EC curve '{curve}' (P-256, P-384 and P-521 are supported)")),
    };
    Ok(der.map_err(e)?.as_bytes().to_vec())
}

/// `SubjectPublicKeyInfo` of a DSA public key from its domain parameters and `y`.
pub fn dsa_spki(p: &[u8], q: &[u8], g: &[u8], y: &[u8]) -> Vec<u8> {
    let params = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for v in [p, q, g] {
                w.next().write_bigint_bytes(trim_leading_zeros(v), true);
            }
        })
    });
    let key = yasna::construct_der(|w| w.write_bigint_bytes(trim_leading_zeros(y), true));
    wrap_spki(&algorithm_id_der(oids::DSA, Some(&params)), &key)
}

/// The OpenSSH wire encoding of a public key (the base64 part of an `authorized_keys` line) and
/// its key type.
pub fn openssh_public_blob(spki: &[u8]) -> Res<(&'static str, Vec<u8>)> {
    let info = public_key_info(spki)?;
    let (_, _, bits) = split_spki(spki)?;
    let mut blob = Vec::new();
    let key_type = match (info.algorithm.as_str(), info.curve.as_deref()) {
        ("RSA", _) => {
            let key = rsa_public_from_spki(spki)?;
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
        ("DSA", _) => {
            let (_, params, _) = split_spki(spki)?;
            let params = params.as_deref().and_then(parse_dsa_params).ok_or("invalid DSA public key parameters")?;
            let y = der_uint(&bits).ok_or("invalid DSA public key")?;
            ssh_string(&mut blob, b"ssh-dss");
            for v in [&params.p, &params.q, &params.g, &y] {
                ssh_mpint(&mut blob, &v.to_bytes_be());
            }
            "ssh-dss"
        }
        (other, _) => return Err(format!("OpenSSH export is not supported for {other} keys")),
    };
    Ok((key_type, blob))
}

/// OpenSSH `authorized_keys` line and its SHA256 fingerprint.
pub fn openssh_public_key(spki: &[u8], comment: &str) -> Res<(String, String)> {
    let (key_type, blob) = openssh_public_blob(spki)?;
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
        openssh_public_key(&spki, "test").unwrap();
        // A private JWK reads back as the same key.
        let jwk = key.private_jwk().unwrap().to_string();
        assert_eq!(PrivateKey::from_bytes(jwk.as_bytes(), None).unwrap().to_pkcs8_der().unwrap(), der);
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
        // The same structure as bare DER says what it is waiting for.
        assert!(is_encrypted_pkcs8(&enc) && !is_encrypted_pkcs8(&der));
        assert_eq!(PrivateKey::from_bytes(&enc, None).err().unwrap(), ENCRYPTED_NEEDS_PASSWORD);
        assert_eq!(PrivateKey::from_bytes(&enc, Some("pw")).unwrap().to_pkcs8_der().unwrap(), der);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(PrivateKey::generate("ML-DSA-65", 0, None).is_err());
        assert!(PrivateKey::generate("RSA", 1000, None).is_err());
    }

    #[test]
    fn jwk_import_checks_what_it_reads() {
        let key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let mut jwk = key.private_jwk().unwrap();
        // A set is searched for its private key; a public JWK is not a private key.
        let set = serde_json::json!({ "keys": [key.public_jwk().unwrap(), jwk.clone()] }).to_string();
        assert_eq!(PrivateKey::from_bytes(set.as_bytes(), None).unwrap().to_pkcs8_der().unwrap(), key.to_pkcs8_der().unwrap());
        assert!(PrivateKey::from_bytes(key.public_jwk().unwrap().to_string().as_bytes(), None).is_err());
        assert!(PrivateKey::from_bytes(br#"{"kty":"oct","k":"AAAA"}"#, None).unwrap_err().contains("symmetric"));
        // Coordinates that belong to another key are refused rather than silently dropped.
        let other = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap().public_jwk().unwrap();
        jwk["x"] = other["x"].clone();
        assert!(PrivateKey::from_bytes(jwk.to_string().as_bytes(), None).unwrap_err().contains("do not match"));
        // RSA without the optional primes: they are recovered from d.
        let rsa = PrivateKey::generate("RSA", 2048, None).unwrap();
        let mut slim = rsa.private_jwk().unwrap();
        for name in ["p", "q", "dp", "dq", "qi"] {
            slim.as_object_mut().unwrap().remove(name);
        }
        let back = PrivateKey::from_bytes(slim.to_string().as_bytes(), None).unwrap();
        assert_eq!(back.public_key_der().unwrap(), rsa.public_key_der().unwrap());
    }

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // `openssl enc -aes-256-cbc -md md5 -S 0102030405060708 -pass pass:password -P` prints
        // the 32-byte key followed by the 16-byte IV, which are consecutive output of the KDF.
        let derived = evp_bytes_to_key(b"password", &hex::decode("0102030405060708").unwrap(), 48);
        assert_eq!(hex::encode_upper(&derived[..32]), "E7B0971E52CA5CC8D0539FB3412F6316F7BA2E6EE293D9F3457B99436B51CE02");
        assert_eq!(hex::encode_upper(&derived[32..]), "8D450E2ED75A84A923D4EAC9FE49226B");
        assert_eq!(evp_bytes_to_key(b"password", &[1, 2, 3, 4, 5, 6, 7, 8], 16), derived[..16]);
    }

    #[test]
    fn pss_parameters_are_read_and_written_consistently() {
        for (hash, salt_len) in [(HashAlg::Sha256, 32usize), (HashAlg::Sha384, 48), (HashAlg::Sha512, 20), (HashAlg::Sha1, 20)] {
            let alg = SigAlg::RsaPss { hash, salt_len };
            let der = yasna::construct_der(|w| alg.write_algorithm_id(w));
            let parsed = pbe::parse_algorithm_id(&der).unwrap();
            assert_eq!(SigAlg::from_algorithm(&parsed.oid, parsed.params.as_deref()), Some(alg));
        }
        // No parameters at all means the SHA-1 defaults of RFC 4055.
        assert_eq!(SigAlg::from_algorithm(oids::RSASSA_PSS, None), Some(SigAlg::RsaPss { hash: HashAlg::Sha1, salt_len: 20 }));
        assert_eq!(SigAlg::from_oid(oids::RSASSA_PSS), None);
        assert_eq!(SigAlg::RsaPss { hash: HashAlg::Sha256, salt_len: 32 }.name(), "SHA256withRSA/PSS");
        // A mask generation hash that differs from the message hash is not something we check.
        let mixed = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                let id = |w: DERWriter, arcs: &[u64]| w.write_sequence(|w| w.next().write_oid(&oids::oid(arcs)));
                w.next().write_tagged(Tag::context(0), |w| id(w, oids::SHA256));
                w.next().write_tagged(Tag::context(1), |w| {
                    w.write_sequence(|w| {
                        w.next().write_oid(&oids::oid(oids::MGF1));
                        id(w.next(), oids::SHA1);
                    })
                });
            })
        });
        assert_eq!(SigAlg::from_algorithm(oids::RSASSA_PSS, Some(&mixed)), None);
    }

    #[test]
    fn pss_signatures_verify() {
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let spki = rsa_spki(&key.to_public_key());
        let signer = rsa::pss::SigningKey::<Sha256>::new(key);
        let sig = signer.sign_with_rng(&mut rand::rngs::OsRng, b"message").to_vec();
        let alg = SigAlg::RsaPss { hash: HashAlg::Sha256, salt_len: 32 };
        assert!(verify(&spki, alg, b"message", &sig).unwrap());
        assert!(!verify(&spki, alg, b"messagE", &sig).unwrap());
        assert!(!verify(&spki, SigAlg::RsaPss { hash: HashAlg::Sha256, salt_len: 20 }, b"message", &sig).unwrap());
        assert!(!verify(&spki, SigAlg::Rsa(HashAlg::Sha256), b"message", &sig).unwrap());
    }

    #[test]
    fn large_rsa_public_keys_are_not_capped_at_4096_bits() {
        // n = 2^8191 + 1 is not a real modulus, but it is the size that used to be refused.
        let mut n = vec![0u8; 1024];
        n[0] = 0x80;
        n[1023] = 0x01;
        let pkcs1 = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_bigint_bytes(&n, true);
                w.next().write_u32(65537);
            })
        });
        let key = rsa_public_from_pkcs1(&pkcs1).unwrap();
        assert_eq!(key.size() * 8, 8192);
        let info = public_key_info(&rsa_spki(&key)).unwrap();
        assert_eq!((info.algorithm.as_str(), info.key_size), ("RSA", 8192));
        assert!(openssh_public_key(&rsa_spki(&key), "").is_ok());
    }

    #[test]
    fn opaque_keys_report_their_size_and_never_panic_on_export() {
        // A secp256k1 key in PKCS#8, with its public key inside the ECPrivateKey.
        let point = [vec![4u8], vec![0x11; 32], vec![0x22; 32]].concat();
        let sec1 = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_bytes(&[0x33; 32]);
                w.next().write_tagged(Tag::context(1), |w| w.write_bitvec_bytes(&point, point.len() * 8));
            })
        });
        let curve = yasna::construct_der(|w| w.write_oid(&oids::oid(oids::SECP256K1)));
        let pkcs8 = wrap_pkcs8(&algorithm_id_der(oids::EC_PUBLIC_KEY, Some(&curve)), &sec1);
        let key = PrivateKey::from_pkcs8_der(&pkcs8).unwrap();
        assert!(!key.is_usable());
        assert_eq!((key.algorithm().as_str(), key.key_size(), key.curve().as_deref()), ("EC (secp256k1)", 256, Some("secp256k1")));
        assert_eq!(key.describe(), "EC (secp256k1) 256-bit");
        assert_eq!(key.to_pkcs8_der().unwrap(), pkcs8, "an opaque key is carried byte for byte");
        let spki = key.public_key_der().unwrap();
        assert_eq!(split_spki(&spki).unwrap().2, point);
        // The public half is exportable; the private half says no instead of panicking.
        assert!(key.public_jwk().is_ok());
        assert!(key.private_jwk().unwrap_err().contains("not supported"));
        assert!(key.default_sig_alg(None).is_err());
        // The same key as a bare SEC1 structure (curve inside) lands in the same place.
        let sec1_named = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_bytes(&[0x33; 32]);
                w.next().write_tagged(Tag::context(0), |w| w.write_oid(&oids::oid(oids::SECP256K1)));
            })
        });
        let bare = PrivateKey::from_bytes(&to_pem("EC PRIVATE KEY", &sec1_named).into_bytes(), None).unwrap();
        assert_eq!((bare.algorithm().as_str(), bare.key_size()), ("EC (secp256k1)", 256));
        assert!(bare.public_key_der().is_err(), "no public key was stored, and this curve is not computed on");
    }

    #[test]
    fn a_mismatched_public_key_inside_an_ec_key_is_refused() {
        let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let other = p256::SecretKey::random(&mut rand::rngs::OsRng);
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let wrong = other.public_key().to_encoded_point(false);
        let sec1 = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_bytes(&key.to_bytes());
                w.next().write_tagged(Tag::context(1), |w| w.write_bitvec_bytes(wrong.as_bytes(), wrong.as_bytes().len() * 8));
            })
        });
        assert!(PrivateKey::from_bytes(&sec1, None).is_err());
    }
}
