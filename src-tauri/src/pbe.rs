//! Password-based encryption schemes used by PKCS#12, PKCS#8 and JCEKS.
//!
//! Supported for decryption (so files produced by OpenSSL 1.x/3.x, Java keytool 8–21 and Windows
//! can be opened):
//! - PBES2 (PBKDF2 with HMAC-SHA1/224/256/384/512, AES-128/192/256-CBC or DES-EDE3-CBC)
//! - PKCS#12 PBE: pbeWithSHAAnd3-KeyTripleDES-CBC, 2-KeyTripleDES, 128/40-bit RC2-CBC
//! - Sun PBEWithMD5AndTripleDES (JCEKS key protection)
//! - PBMAC1 (RFC 9579) for PKCS#12 integrity protection
//!
//! New content is always written with PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC.

use crate::oids::{self, oid};
use crate::util::{random_bytes, Res};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, InnerIvInit, KeyInit, KeyIvInit};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use yasna::{DERWriter, Tag};

pub const DEFAULT_ITERATIONS: u64 = 10_000;
const WRONG_PASSWORD: &str = "keystore password incorrect or file corrupt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn from_digest_oid(arcs: &[u64]) -> Option<Self> {
        match arcs {
            a if a == oids::SHA1 => Some(Self::Sha1),
            a if a == oids::SHA224 => Some(Self::Sha224),
            a if a == oids::SHA256 => Some(Self::Sha256),
            a if a == oids::SHA384 => Some(Self::Sha384),
            a if a == oids::SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn from_hmac_oid(arcs: &[u64]) -> Option<Self> {
        match arcs {
            a if a == oids::HMAC_SHA1 => Some(Self::Sha1),
            a if a == oids::HMAC_SHA224 => Some(Self::Sha224),
            a if a == oids::HMAC_SHA256 => Some(Self::Sha256),
            a if a == oids::HMAC_SHA384 => Some(Self::Sha384),
            a if a == oids::HMAC_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn digest_oid(self) -> &'static [u64] {
        match self {
            Self::Sha1 => oids::SHA1,
            Self::Sha224 => oids::SHA224,
            Self::Sha256 => oids::SHA256,
            Self::Sha384 => oids::SHA384,
            Self::Sha512 => oids::SHA512,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Name of the HMAC built on this hash, as Java and OpenSSL spell it.
    pub fn hmac_name(self) -> &'static str {
        match self {
            Self::Sha1 => "HMAC-SHA1",
            Self::Sha224 => "HMAC-SHA224",
            Self::Sha256 => "HMAC-SHA256",
            Self::Sha384 => "HMAC-SHA384",
            Self::Sha512 => "HMAC-SHA512",
        }
    }

    pub fn hmac_oid(self) -> &'static [u64] {
        match self {
            Self::Sha1 => oids::HMAC_SHA1,
            Self::Sha224 => oids::HMAC_SHA224,
            Self::Sha256 => oids::HMAC_SHA256,
            Self::Sha384 => oids::HMAC_SHA384,
            Self::Sha512 => oids::HMAC_SHA512,
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn block_len(self) -> usize {
        match self {
            Self::Sha384 | Self::Sha512 => 128,
            _ => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        macro_rules! run {
            ($d:ty) => {{
                let mut mac = <Hmac<$d> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Self::Sha1 => run!(Sha1),
            Self::Sha224 => run!(Sha224),
            Self::Sha256 => run!(Sha256),
            Self::Sha384 => run!(Sha384),
            Self::Sha512 => run!(Sha512),
        }
    }

    pub fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        match self {
            Self::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, iterations, out),
            Self::Sha224 => pbkdf2::pbkdf2_hmac::<Sha224>(password, salt, iterations, out),
            Self::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, out),
            Self::Sha384 => pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, iterations, out),
            Self::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, out),
        }
    }
}

/// BMPString (UTF-16BE) encoding of a password with the two-byte NUL terminator, as required by
/// the PKCS#12 key derivation function.
pub fn bmp_password(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// RFC 7292 Appendix B.2 key derivation. `id` = 1 (key), 2 (IV) or 3 (MAC key).
pub fn pkcs12_kdf(hash: HashAlg, password: &str, salt: &[u8], iterations: u64, id: u8, out_len: usize) -> Vec<u8> {
    let u = hash.output_len();
    let v = hash.block_len();
    let pass = bmp_password(password);

    let d = vec![id; v];
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let len = v * src.len().div_ceil(v);
        src.iter().cycle().take(len).copied().collect()
    };
    let mut i = fill(salt);
    i.extend(fill(&pass));

    let mut result = Vec::with_capacity(out_len + u);
    while result.len() < out_len {
        let mut a = hash.digest(&[d.as_slice(), i.as_slice()].concat());
        for _ in 1..iterations.max(1) {
            a = hash.digest(&a);
        }
        result.extend_from_slice(&a);
        if result.len() >= out_len {
            break;
        }
        let b: Vec<u8> = a.iter().cycle().take(v).copied().collect();
        for block in i.chunks_mut(v) {
            let mut carry: u16 = 1;
            for k in (0..v).rev() {
                let sum = block[k] as u16 + b[k] as u16 + carry;
                block[k] = sum as u8;
                carry = sum >> 8;
            }
        }
    }
    result.truncate(out_len);
    result
}

// ---------------------------------------------------------------------------------------------
// Block cipher helpers
// ---------------------------------------------------------------------------------------------

fn cbc_decrypt<C>(cipher: C, iv: &[u8], data: &[u8]) -> Res<Vec<u8>>
where
    C: aes::cipher::BlockDecryptMut + aes::cipher::BlockCipher,
{
    let dec = cbc::Decryptor::<C>::inner_iv_slice_init(cipher, iv).map_err(|_| "invalid IV length".to_string())?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(data).map_err(|_| WRONG_PASSWORD.to_string())
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    match key.len() {
        16 => cbc_decrypt(aes::Aes128::new_from_slice(key).map_err(|_| "bad key")?, iv, data),
        24 => cbc_decrypt(aes::Aes192::new_from_slice(key).map_err(|_| "bad key")?, iv, data),
        32 => cbc_decrypt(aes::Aes256::new_from_slice(key).map_err(|_| "bad key")?, iv, data),
        _ => Err("unsupported AES key length".into()),
    }
}

fn des3_key(key: &[u8]) -> Vec<u8> {
    // Two-key triple DES expands K1K2 into K1K2K1.
    if key.len() == 16 { [key, &key[..8]].concat() } else { key.to_vec() }
}

fn des3_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = des::TdesEde3::new_from_slice(&des3_key(key)).map_err(|_| "bad 3DES key".to_string())?;
    cbc_decrypt(cipher, iv, data)
}

fn des3_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(key, iv).map_err(|_| "bad 3DES key".to_string())?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
}

fn rc2_cbc_decrypt(key: &[u8], effective_bits: usize, iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = rc2::Rc2::new_with_eff_key_len(key, effective_bits);
    cbc_decrypt(cipher, iv, data)
}

// ---------------------------------------------------------------------------------------------
// PBMAC1 (RFC 9579)
// ---------------------------------------------------------------------------------------------

/// PBMAC1 parameters: a PBKDF2 key derivation plus the HMAC the derived key is used with.
///
/// RFC 9579 replaces the PKCS#12 KDF with PBKDF2 for integrity protection. The `MacData` salt and
/// iteration count outside these parameters are decorative for PBMAC1 — only the values inside
/// the PBKDF2 parameters are authoritative, so a file whose outer and inner values disagree still
/// verifies. `key_length` is mandatory here (it is optional in plain PBES2) because the MAC key
/// size cannot otherwise be inferred.
pub struct Pbmac1Params {
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub key_length: usize,
    pub prf: HashAlg,
    pub hmac: HashAlg,
}

/// Parses the parameters of a PBMAC1 `AlgorithmIdentifier`.
pub fn parse_pbmac1_params(params: &[u8]) -> Res<Pbmac1Params> {
    let (salt, iterations, key_length, prf, hmac) = yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let (salt, iterations, key_length, prf) = r.next().read_sequence(|r| {
                let kdf = r.next().read_oid()?;
                if kdf.components().as_slice() != oids::PBKDF2 {
                    return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                }
                r.next().read_sequence(|r| {
                    let salt = r.next().read_bytes()?;
                    let iterations = r.next().read_u64()?;
                    let key_length = r.read_optional(|r| r.read_u64())?;
                    let prf = r.read_optional(read_algorithm_id)?;
                    Ok((salt, iterations, key_length, prf))
                })
            })?;
            let hmac = read_algorithm_id(r.next())?;
            Ok((salt, iterations, key_length, prf, hmac))
        })
    })
    .map_err(|err| format!("malformed PBMAC1 parameters: {err}"))?;

    let hmac = HashAlg::from_hmac_oid(&hmac.oid)
        .ok_or_else(|| format!("unsupported PBMAC1 message authentication algorithm {}", oids::oid_str(&hmac.oid)))?;
    // RFC 9579 §3: keyLength MUST be present. Fall back to the HMAC's natural output length so a
    // technically invalid file from a lenient writer still opens.
    let key_length = key_length.unwrap_or(hmac.output_len() as u64);
    let key_length = usize::try_from(key_length).ok().filter(|k| (1..=1024).contains(k)).ok_or("PBMAC1 key length out of range")?;
    Ok(Pbmac1Params {
        salt,
        iterations,
        key_length,
        prf: prf.and_then(|p| HashAlg::from_hmac_oid(&p.oid)).unwrap_or(HashAlg::Sha1),
        hmac,
    })
}

impl Pbmac1Params {
    /// Defaults matching `openssl pkcs12 -export -pbmac1_pbkdf2`: PBKDF2-HMAC-SHA256 and
    /// HMAC-SHA256 with a 32-byte key.
    pub fn new(salt: Vec<u8>, iterations: u64) -> Self {
        Self { salt, iterations, key_length: 32, prf: HashAlg::Sha256, hmac: HashAlg::Sha256 }
    }

    /// Derives the MAC key and computes the authentication tag over `data`.
    pub fn mac(&self, password: &str, data: &[u8]) -> Res<Vec<u8>> {
        let iterations = u32::try_from(self.iterations).map_err(|_| "PBKDF2 iteration count too large".to_string())?;
        if iterations == 0 {
            return Err("PBMAC1 iteration count must be at least 1".into());
        }
        let mut key = vec![0u8; self.key_length];
        // RFC 9579 derives from the UTF-8 password, not the PKCS#12 BMPString encoding.
        self.prf.pbkdf2(password.as_bytes(), &self.salt, iterations, &mut key);
        Ok(self.hmac.hmac(&key, data))
    }

    pub fn describe(&self) -> String {
        format!("PBMAC1 (PBKDF2-{}, {}, {} iterations)", self.prf.name(), self.hmac.hmac_name(), self.iterations)
    }

    /// DER `AlgorithmIdentifier` for these parameters.
    pub fn algorithm_id(&self) -> Vec<u8> {
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(oids::PBMAC1));
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(oids::PBKDF2));
                        w.next().write_sequence(|w| {
                            w.next().write_bytes(&self.salt);
                            w.next().write_u64(self.iterations);
                            w.next().write_u64(self.key_length as u64);
                            w.next().write_sequence(|w| {
                                w.next().write_oid(&oid(self.prf.hmac_oid()));
                                w.next().write_null();
                            });
                        });
                    });
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(self.hmac.hmac_oid()));
                        w.next().write_null();
                    });
                });
            })
        })
    }
}

// ---------------------------------------------------------------------------------------------
// AlgorithmIdentifier dispatch
// ---------------------------------------------------------------------------------------------

/// Parsed `AlgorithmIdentifier`: the OID and the raw DER of its parameters (if any).
pub struct AlgorithmId {
    pub oid: Vec<u64>,
    pub params: Option<Vec<u8>>,
}

pub fn read_algorithm_id(reader: yasna::BERReader) -> yasna::ASN1Result<AlgorithmId> {
    reader.read_sequence(|r| {
        let oid = r.next().read_oid()?.components().to_vec();
        let params = r.read_optional(|r| r.read_der())?;
        Ok(AlgorithmId { oid, params })
    })
}

pub fn parse_algorithm_id(der: &[u8]) -> Res<AlgorithmId> {
    yasna::parse_ber(der, read_algorithm_id).map_err(|err| format!("malformed AlgorithmIdentifier: {err}"))
}

/// Human-readable name for a password-based encryption AlgorithmIdentifier.
pub fn describe_algorithm(alg: &AlgorithmId) -> String {
    match alg.oid.as_slice() {
        a if a == oids::PBES2 => {
            match alg.params.as_deref().map(parse_pbes2_params) {
                Some(Ok(p)) => format!("PBES2 (PBKDF2-HMAC-{}, {}, {} iterations)", p.prf.name(), p.cipher_name(), p.iterations),
                _ => "PBES2".into(),
            }
        }
        a if a == oids::PBE_SHA1_3DES => "PBE-SHA1-3DES".into(),
        a if a == oids::PBE_SHA1_2DES => "PBE-SHA1-2DES".into(),
        a if a == oids::PBE_SHA1_RC2_40 => "PBE-SHA1-RC2-40".into(),
        a if a == oids::PBE_SHA1_RC2_128 => "PBE-SHA1-RC2-128".into(),
        a if a == oids::PBE_MD5_3DES => "PBEWithMD5AndTripleDES".into(),
        other => crate::oids::oid_str(other),
    }
}

/// Decrypts `data` protected with the PBE scheme described by `alg`.
pub fn decrypt(alg: &AlgorithmId, password: &str, data: &[u8]) -> Res<Vec<u8>> {
    let params = alg.params.as_deref().unwrap_or(&[]);
    match alg.oid.as_slice() {
        a if a == oids::PBES2 => pbes2_decrypt(&parse_pbes2_params(params)?, password, data),
        a if a == oids::PBE_SHA1_3DES || a == oids::PBE_SHA1_2DES => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let key_len = if a == oids::PBE_SHA1_3DES { 24 } else { 16 };
            let key = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 1, key_len);
            let iv = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 2, 8);
            des3_cbc_decrypt(&key, &iv, data)
        }
        a if a == oids::PBE_SHA1_RC2_40 || a == oids::PBE_SHA1_RC2_128 => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let bits = if a == oids::PBE_SHA1_RC2_40 { 40 } else { 128 };
            let key = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 1, bits / 8);
            let iv = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 2, 8);
            rc2_cbc_decrypt(&key, bits, &iv, data)
        }
        a if a == oids::PBE_MD5_3DES => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let (key, iv) = sun_md5_3des_derive(password, &salt, iterations)?;
            des3_cbc_decrypt(&key, &iv, data)
        }
        a if a == oids::PBE_SHA1_RC4_128 || a == oids::PBE_SHA1_RC4_40 => {
            Err("RC4-based PKCS#12 encryption is not supported; re-export the file with AES (openssl pkcs12 -export -keypbe AES-256-CBC)".into())
        }
        other => Err(format!("unsupported encryption algorithm {}", crate::oids::oid_str(other))),
    }
}

fn parse_pbe_params(params: &[u8]) -> Res<(Vec<u8>, u64)> {
    yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u64()?;
            Ok((salt, iterations))
        })
    })
    .map_err(|err| format!("malformed PBE parameters: {err}"))
}

pub struct Pbes2Params {
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub key_length: Option<u64>,
    pub prf: HashAlg,
    pub cipher_oid: Vec<u64>,
    pub iv: Vec<u8>,
}

impl Pbes2Params {
    fn cipher_name(&self) -> &'static str {
        match self.cipher_oid.as_slice() {
            a if a == oids::AES128_CBC => "AES-128-CBC",
            a if a == oids::AES192_CBC => "AES-192-CBC",
            a if a == oids::AES256_CBC => "AES-256-CBC",
            a if a == oids::DES_EDE3_CBC => "DES-EDE3-CBC",
            _ => "unknown cipher",
        }
    }
}

pub fn parse_pbes2_params(params: &[u8]) -> Res<Pbes2Params> {
    yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let (salt, iterations, key_length, prf) = r.next().read_sequence(|r| {
                let kdf = r.next().read_oid()?;
                if kdf.components().as_slice() != oids::PBKDF2 {
                    return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                }
                r.next().read_sequence(|r| {
                    let salt = r.next().read_bytes()?;
                    let iterations = r.next().read_u64()?;
                    let key_length = r.read_optional(|r| r.read_u64())?;
                    let prf = r.read_optional(read_algorithm_id)?;
                    Ok((salt, iterations, key_length, prf))
                })
            })?;
            let (cipher_oid, iv) = r.next().read_sequence(|r| {
                let oid = r.next().read_oid()?.components().to_vec();
                let iv = r.next().read_bytes()?;
                Ok((oid, iv))
            })?;
            Ok(Pbes2Params {
                salt,
                iterations,
                key_length,
                prf: prf.and_then(|p| HashAlg::from_hmac_oid(&p.oid)).unwrap_or(HashAlg::Sha1),
                cipher_oid,
                iv,
            })
        })
    })
    .map_err(|err| format!("malformed PBES2 parameters: {err}"))
}

fn pbes2_decrypt(p: &Pbes2Params, password: &str, data: &[u8]) -> Res<Vec<u8>> {
    let key_len = match p.cipher_oid.as_slice() {
        a if a == oids::AES128_CBC => 16,
        a if a == oids::AES192_CBC => 24,
        a if a == oids::AES256_CBC => 32,
        a if a == oids::DES_EDE3_CBC => 24,
        other => return Err(format!("unsupported PBES2 cipher {}", crate::oids::oid_str(other))),
    };
    let key_len = p.key_length.map(|k| k as usize).unwrap_or(key_len);
    let iterations = u32::try_from(p.iterations).map_err(|_| "PBKDF2 iteration count too large".to_string())?;
    let mut key = vec![0u8; key_len];
    p.prf.pbkdf2(password.as_bytes(), &p.salt, iterations, &mut key);
    if p.cipher_oid.as_slice() == oids::DES_EDE3_CBC {
        des3_cbc_decrypt(&key, &p.iv, data)
    } else {
        aes_cbc_decrypt(&key, &p.iv, data)
    }
}

/// Encrypts with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC). Returns the DER AlgorithmIdentifier and
/// the ciphertext.
pub fn pbes2_encrypt(password: &str, plaintext: &[u8], iterations: u64) -> Res<(Vec<u8>, Vec<u8>)> {
    let salt = random_bytes(16);
    let iv = random_bytes(16);
    let mut key = [0u8; 32];
    HashAlg::Sha256.pbkdf2(password.as_bytes(), &salt, iterations as u32, &mut key);
    let enc = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv).map_err(|_| "bad AES key".to_string())?;
    let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let alg = yasna::construct_der(|w| write_pbes2_algorithm_id(w, &salt, iterations, &iv));
    Ok((alg, ciphertext))
}

fn write_pbes2_algorithm_id(writer: DERWriter, salt: &[u8], iterations: u64, iv: &[u8]) {
    writer.write_sequence(|w| {
        w.next().write_oid(&oid(oids::PBES2));
        w.next().write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::PBKDF2));
                w.next().write_sequence(|w| {
                    w.next().write_bytes(salt);
                    w.next().write_u64(iterations);
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(oids::HMAC_SHA256));
                        w.next().write_null();
                    });
                });
            });
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::AES256_CBC));
                w.next().write_bytes(iv);
            });
        });
    });
}

/// Wraps a PKCS#8 PrivateKeyInfo into an `EncryptedPrivateKeyInfo` (PBES2/AES-256-CBC).
pub fn encrypt_pkcs8(password: &str, pkcs8_der: &[u8], iterations: u64) -> Res<Vec<u8>> {
    let (alg, ciphertext) = pbes2_encrypt(password, pkcs8_der, iterations)?;
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&alg);
            w.next().write_bytes(&ciphertext);
        })
    }))
}

/// Parses an `EncryptedPrivateKeyInfo` and decrypts it to the inner PKCS#8 DER.
pub fn decrypt_pkcs8(password: &str, der: &[u8]) -> Res<Vec<u8>> {
    let (alg, data) = yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let alg = read_algorithm_id(r.next())?;
            let data = r.next().read_bytes()?;
            Ok((alg, data))
        })
    })
    .map_err(|err| format!("malformed EncryptedPrivateKeyInfo: {err}"))?;
    decrypt(&alg, password, &data)
}

// ---------------------------------------------------------------------------------------------
// Sun PBEWithMD5AndTripleDES (com.sun.crypto.provider.PBES1Core), used by JCEKS
// ---------------------------------------------------------------------------------------------

fn sun_md5_3des_derive(password: &str, salt: &[u8], iterations: u64) -> Res<(Vec<u8>, Vec<u8>)> {
    if salt.len() != 8 {
        return Err("PBEWithMD5AndTripleDES requires an 8-byte salt".into());
    }
    let pass: Vec<u8> = password.chars().map(|c| (c as u32 & 0x7F) as u8).collect();
    let mut salt = salt.to_vec();
    if salt[..4] == salt[4..] {
        // Identical halves: invert the first half, exactly as the JDK does.
        for i in 0..2 {
            salt.swap(i, 3 - i);
        }
    }
    let mut result = Vec::with_capacity(32);
    for half in salt.chunks(4) {
        let mut to_hash = half.to_vec();
        for _ in 0..iterations.max(1) {
            let mut md = Md5::new();
            md.update(&to_hash);
            md.update(&pass);
            to_hash = md.finalize().to_vec();
        }
        result.extend_from_slice(&to_hash);
    }
    Ok((result[..24].to_vec(), result[24..32].to_vec()))
}

/// Encrypts with Sun PBEWithMD5AndTripleDES, returning (AlgorithmIdentifier DER, ciphertext).
pub fn sun_md5_3des_encrypt(password: &str, plaintext: &[u8], iterations: u64) -> Res<(Vec<u8>, Vec<u8>)> {
    let salt = random_bytes(8);
    let (key, iv) = sun_md5_3des_derive(password, &salt, iterations)?;
    let ciphertext = des3_cbc_encrypt(&key, &iv, plaintext)?;
    let alg = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(oids::PBE_MD5_3DES));
            w.next().write_der(&sun_pbe_params(&salt, iterations));
        })
    });
    Ok((alg, ciphertext))
}

/// DER `PBEParameter ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER }`.
pub fn sun_pbe_params(salt: &[u8], iterations: u64) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bytes(salt);
            w.next().write_u64(iterations);
        })
    })
}

pub fn sun_md5_3des_decrypt_with_params(password: &str, params_der: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let (salt, iterations) = parse_pbe_params(params_der)?;
    let (key, iv) = sun_md5_3des_derive(password, &salt, iterations)?;
    des3_cbc_decrypt(&key, &iv, data)
}

pub fn sun_md5_3des_encrypt_with_params(password: &str, salt: &[u8], iterations: u64, data: &[u8]) -> Res<Vec<u8>> {
    let (key, iv) = sun_md5_3des_derive(password, salt, iterations)?;
    des3_cbc_encrypt(&key, &iv, data)
}

/// Helper used by writers that need `[0] IMPLICIT OCTET STRING` content.
pub fn write_implicit_octets(writer: DERWriter, tag: u64, data: &[u8]) {
    writer.write_tagged_implicit(Tag::context(tag), |w| w.write_bytes(data));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs12_kdf_matches_openssl_vector() {
        // Test vector from OpenSSL's test/pkcs12_format_test / RFC 7292 errata derivations:
        // password "smeg", salt 0x0A58CF64530D823F, id=1, iterations=1, SHA-1, 24 bytes.
        let salt = hex::decode("0A58CF64530D823F").unwrap();
        let key = pkcs12_kdf(HashAlg::Sha1, "smeg", &salt, 1, 1, 24);
        assert_eq!(hex::encode_upper(key), "8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3");
        let iv = pkcs12_kdf(HashAlg::Sha1, "smeg", &salt, 1, 2, 8);
        assert_eq!(hex::encode_upper(iv), "79993DFE048D3B76");
    }

    #[test]
    fn pkcs12_kdf_long_output_and_iterations() {
        // Second published vector: "queeg", salt 0x05DEC959ACFF72F7, 1000 iterations.
        let salt = hex::decode("05DEC959ACFF72F7").unwrap();
        let key = pkcs12_kdf(HashAlg::Sha1, "queeg", &salt, 1000, 1, 24);
        assert_eq!(hex::encode_upper(key), "ED2034E36328830FF09DF1E1A07DD357185DAC0D4F9EB3D4");
        let iv = pkcs12_kdf(HashAlg::Sha1, "queeg", &salt, 1000, 2, 8);
        assert_eq!(hex::encode_upper(iv), "11DEDAD7758D4860");
    }

    #[test]
    fn pbes2_round_trip() {
        let pkcs8 = b"pretend this is a private key".to_vec();
        let enc = encrypt_pkcs8("pässwörd", &pkcs8, 2048).unwrap();
        assert_eq!(decrypt_pkcs8("pässwörd", &enc).unwrap(), pkcs8);
        assert!(decrypt_pkcs8("wrong", &enc).is_err());
    }

    #[test]
    fn sun_md5_3des_round_trip() {
        let (alg, ct) = sun_md5_3des_encrypt("changeit", b"secret material", 200_000).unwrap();
        let parsed = parse_algorithm_id(&alg).unwrap();
        assert_eq!(decrypt(&parsed, "changeit", &ct).unwrap(), b"secret material");
    }
}
