//! Password-based encryption schemes used by PKCS#12, PKCS#8, JCEKS and the Bouncy Castle stores.
//!
//! Supported for decryption (so files produced by OpenSSL 1.x–4.x, Java keytool 8–25, Windows
//! and Bouncy Castle can be opened):
//! - PBES2: PBKDF2 (HMAC-SHA1/224/256/384/512) or scrypt, with AES-128/192/256-CBC,
//!   DES-EDE3-CBC, DES-CBC, AES-CCM or AES key wrap with padding (the last two are BCFKS's)
//! - PBES1: pbeWithMD5/SHA1AndDES-CBC and the 64-bit RC2 variants
//! - PKCS#12 PBE: 3-key and 2-key triple DES, 128/40-bit RC2-CBC, 128/40-bit RC4
//! - Sun PBEWithMD5AndTripleDES (JCEKS key protection)
//! - PBMAC1 (RFC 9579) for PKCS#12 integrity protection
//!
//! New content is written with PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC. The one exception is
//! the legacy PKCS#12 profile ([`pkcs12_3des_encrypt`]), for readers that predate PBES2.
//!
//! An error that starts with `unsupported:` names a scheme this module does not implement. It is
//! kept apart from a wrong password, because telling someone their password is wrong when the
//! file uses Camellia sends them looking in the wrong place.

use crate::modes;
use crate::oids::{self, oid};
use crate::util::{Res, random_bytes};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, InnerIvInit, KeyInit, KeyIvInit, block_padding::Pkcs7};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use yasna::{DERWriter, Tag};

pub const DEFAULT_ITERATIONS: u64 = 10_000;
/// Iterations for the legacy PKCS#12 profile: what `openssl pkcs12 -legacy` writes, and a count
/// every old reader accepts.
pub const LEGACY_ITERATIONS: u64 = 2048;
const WRONG_PASSWORD: &str = "wrong-password: keystore password incorrect or file corrupt";

/// The most key-derivation work a file may ask for. A count beyond this is not a keystore being
/// careful, it is a file that keeps the app busy for hours.
pub const MAX_ITERATIONS: u64 = 100_000_000;
/// scrypt needs 128·N·r bytes; refuse to allocate more than this on a file's say-so.
const MAX_SCRYPT_MEMORY: u64 = 1 << 30;
/// scrypt's running time grows with N·r·p; the same reasoning as [`MAX_ITERATIONS`].
const MAX_SCRYPT_WORK: u64 = 1 << 27;

/// True for an error that reports a scheme this module does not implement.
pub fn is_unsupported(err: &str) -> bool {
    err.starts_with("unsupported:")
}

/// Rejects an iteration count no real file uses, before any time is spent on it.
pub fn check_iterations(iterations: u64) -> Res<u32> {
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(format!("invalid: the file asks for {iterations} key-derivation iterations, which is outside the range any tool writes"));
    }
    Ok(iterations as u32)
}

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

/// The password encoding Bouncy Castle feeds its key derivations (`PKCS12PasswordToBytes`):
/// the BMPString form, except that an empty password is no bytes at all rather than a lone
/// terminator. OpenSSL makes the other choice for an empty PKCS#12 password, which is why
/// [`bmp_password`] stays as it is.
pub fn bc_password(password: &str) -> Vec<u8> {
    if password.is_empty() { Vec::new() } else { bmp_password(password) }
}

/// RFC 7292 Appendix B.2 key derivation. `id` = 1 (key), 2 (IV) or 3 (MAC key).
pub fn pkcs12_kdf(hash: HashAlg, password: &str, salt: &[u8], iterations: u64, id: u8, out_len: usize) -> Vec<u8> {
    pkcs12_kdf_bytes(hash, &bmp_password(password), salt, iterations, id, out_len)
}

/// [`pkcs12_kdf`] over password bytes that are already encoded.
pub fn pkcs12_kdf_bytes(hash: HashAlg, pass: &[u8], salt: &[u8], iterations: u64, id: u8, out_len: usize) -> Vec<u8> {
    let u = hash.output_len();
    let v = hash.block_len();

    let d = vec![id; v];
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let len = v * src.len().div_ceil(v);
        src.iter().cycle().take(len).copied().collect()
    };
    let mut i = fill(salt);
    i.extend(fill(pass));

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
    let dec = cbc::Decryptor::<C>::inner_iv_slice_init(cipher, iv).map_err(|_| "invalid: the cipher's IV has the wrong length".to_string())?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(data).map_err(|_| WRONG_PASSWORD.to_string())
}

pub(crate) fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let bad = |_| "invalid: bad AES key".to_string();
    match key.len() {
        16 => cbc_decrypt(aes::Aes128::new_from_slice(key).map_err(bad)?, iv, data),
        24 => cbc_decrypt(aes::Aes192::new_from_slice(key).map_err(bad)?, iv, data),
        32 => cbc_decrypt(aes::Aes256::new_from_slice(key).map_err(bad)?, iv, data),
        n => Err(format!("unsupported: an AES key is 16, 24 or 32 bytes, not {n}")),
    }
}

fn des3_key(key: &[u8]) -> Vec<u8> {
    // Two-key triple DES expands K1K2 into K1K2K1.
    if key.len() == 16 { [key, &key[..8]].concat() } else { key.to_vec() }
}

pub(crate) fn des3_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = des::TdesEde3::new_from_slice(&des3_key(key)).map_err(|_| "invalid: bad 3DES key".to_string())?;
    cbc_decrypt(cipher, iv, data)
}

pub(crate) fn des3_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(key, iv).map_err(|_| "invalid: bad 3DES key".to_string())?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
}

pub(crate) fn des_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = des::Des::new_from_slice(key).map_err(|_| "invalid: bad DES key".to_string())?;
    cbc_decrypt(cipher, iv, data)
}

fn rc2_cbc_decrypt(key: &[u8], effective_bits: usize, iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = rc2::Rc2::new_with_eff_key_len(key, effective_bits);
    cbc_decrypt(cipher, iv, data)
}

/// Twofish-CBC with PKCS#7 padding: the cipher Bouncy Castle's UBER store wraps itself in.
pub(crate) fn twofish_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let cipher = twofish::Twofish::new_from_slice(key).map_err(|_| "invalid: bad Twofish key".to_string())?;
    cbc_decrypt(cipher, iv, data)
}

pub(crate) fn twofish_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let enc = cbc::Encryptor::<twofish::Twofish>::new_from_slices(key, iv).map_err(|_| "invalid: bad Twofish key".to_string())?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// A stream cipher has no padding to fail on, so a wrong key decrypts to noise without complaint.
/// Everything PKCS#12 and PKCS#8 protect is one DER SEQUENCE, which noise almost never is.
fn is_one_der_sequence(data: &[u8]) -> bool {
    if data.first() != Some(&0x30) {
        return false;
    }
    let Some(&first) = data.get(1) else { return false };
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return false;
        }
        (data[2..2 + n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), 2 + n)
    };
    header + len == data.len()
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

    let hmac = HashAlg::from_hmac_oid(&hmac.oid).ok_or_else(|| format!("unsupported PBMAC1 message authentication algorithm {}", oids::oid_str(&hmac.oid)))?;
    // RFC 9579 §3: keyLength MUST be present. Fall back to the HMAC's natural output length so a
    // technically invalid file from a lenient writer still opens.
    let key_length = key_length.unwrap_or(hmac.output_len() as u64);
    let key_length = usize::try_from(key_length).ok().filter(|k| (1..=1024).contains(k)).ok_or("PBMAC1 key length out of range")?;
    Ok(Pbmac1Params { salt, iterations, key_length, prf: prf.and_then(|p| HashAlg::from_hmac_oid(&p.oid)).unwrap_or(HashAlg::Sha1), hmac })
}

impl Pbmac1Params {
    /// Defaults matching `openssl pkcs12 -export -pbmac1_pbkdf2`: PBKDF2-HMAC-SHA256 and
    /// HMAC-SHA256 with a 32-byte key.
    pub fn new(salt: Vec<u8>, iterations: u64) -> Self {
        Self { salt, iterations, key_length: 32, prf: HashAlg::Sha256, hmac: HashAlg::Sha256 }
    }

    /// Derives the MAC key and computes the authentication tag over `data`.
    pub fn mac(&self, password: &str, data: &[u8]) -> Res<Vec<u8>> {
        let iterations = check_iterations(self.iterations)?;
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
#[derive(Clone, Debug)]
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
        a if a == oids::PBES2 => match alg.params.as_deref().map(parse_pbes2_params) {
            Some(Ok(p)) => p.describe(),
            _ => "PBES2".into(),
        },
        a if a == oids::PBE_SHA1_3DES => "PBE-SHA1-3DES".into(),
        a if a == oids::PBE_SHA1_2DES => "PBE-SHA1-2DES".into(),
        a if a == oids::PBE_SHA1_RC2_40 => "PBE-SHA1-RC2-40".into(),
        a if a == oids::PBE_SHA1_RC2_128 => "PBE-SHA1-RC2-128".into(),
        a if a == oids::PBE_SHA1_RC4_40 => "PBE-SHA1-RC4-40".into(),
        a if a == oids::PBE_SHA1_RC4_128 => "PBE-SHA1-RC4-128".into(),
        a if a == oids::PBE_MD5_DES => "PBE-MD5-DES".into(),
        a if a == oids::PBE_SHA1_DES => "PBE-SHA1-DES".into(),
        a if a == oids::PBE_MD5_RC2 => "PBE-MD5-RC2-64".into(),
        a if a == oids::PBE_SHA1_RC2 => "PBE-SHA1-RC2-64".into(),
        a if a == oids::PBE_MD5_3DES => "PBEWithMD5AndTripleDES".into(),
        other => crate::oids::oid_str(other),
    }
}

/// Decrypts `data` protected with the PBE scheme described by `alg`.
pub fn decrypt(alg: &AlgorithmId, password: &str, data: &[u8]) -> Res<Vec<u8>> {
    let params = alg.params.as_deref().unwrap_or(&[]);
    match alg.oid.as_slice() {
        a if a == oids::PBES2 => parse_pbes2_params(params)?.decrypt(password.as_bytes(), data),
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
        a if a == oids::PBE_SHA1_RC4_40 || a == oids::PBE_SHA1_RC4_128 => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let key = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 1, if a == oids::PBE_SHA1_RC4_40 { 5 } else { 16 });
            let mut plain = data.to_vec();
            modes::rc4(&key, &mut plain);
            if is_one_der_sequence(&plain) { Ok(plain) } else { Err(WRONG_PASSWORD.into()) }
        }
        a if a == oids::PBE_MD5_3DES => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let (key, iv) = sun_md5_3des_derive(password, &salt, iterations)?;
            des3_cbc_decrypt(&key, &iv, data)
        }
        a if a == oids::PBE_MD5_DES || a == oids::PBE_SHA1_DES || a == oids::PBE_MD5_RC2 || a == oids::PBE_SHA1_RC2 => {
            let (salt, iterations) = parse_pbe_params(params)?;
            let md5 = a == oids::PBE_MD5_DES || a == oids::PBE_MD5_RC2;
            let dk = pbkdf1(md5, password.as_bytes(), &salt, iterations);
            let (key, iv) = dk.split_at(8);
            if a == oids::PBE_MD5_DES || a == oids::PBE_SHA1_DES { des_cbc_decrypt(key, iv, data) } else { rc2_cbc_decrypt(key, 64, iv, data) }
        }
        other => Err(format!("unsupported: the encryption scheme {} is not supported", crate::oids::oid_str(other))),
    }
}

/// `PBEParameter ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER }`, with the count
/// checked against [`MAX_ITERATIONS`].
fn parse_pbe_params(params: &[u8]) -> Res<(Vec<u8>, u64)> {
    let (salt, iterations) = yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u64()?;
            Ok((salt, iterations))
        })
    })
    .map_err(|err| format!("invalid: malformed PBE parameters: {err}"))?;
    check_iterations(iterations)?;
    Ok((salt, iterations))
}

/// PBKDF1 (RFC 8018 §5.1) as PBES1 uses it: 16 bytes, the key followed by the IV.
fn pbkdf1(md5: bool, password: &[u8], salt: &[u8], iterations: u64) -> Vec<u8> {
    let hash = |data: &[u8]| -> Vec<u8> { if md5 { Md5::digest(data).to_vec() } else { Sha1::digest(data).to_vec() } };
    let mut t = hash(&[password, salt].concat());
    for _ in 1..iterations.max(1) {
        t = hash(&t);
    }
    t.truncate(16);
    t
}

// ---------------------------------------------------------------------------------------------
// PBES2
// ---------------------------------------------------------------------------------------------

/// A PBES2 key derivation function with its parameters.
#[derive(Clone, Debug)]
pub enum Kdf {
    /// `prf` is the OID of the pseudorandom function, HMAC-SHA1 when the file names none.
    Pbkdf2 {
        salt: Vec<u8>,
        iterations: u64,
        key_length: Option<u64>,
        prf: Vec<u64>,
    },
    Scrypt {
        salt: Vec<u8>,
        n: u64,
        r: u64,
        p: u64,
        key_length: Option<u64>,
    },
}

fn derived_len(specified: Option<u64>, default_len: usize) -> Res<usize> {
    match specified {
        None => Ok(default_len),
        Some(len) => usize::try_from(len).ok().filter(|l| (1..=1024).contains(l)).ok_or_else(|| "invalid: the derived key length is out of range".to_string()),
    }
}

fn prf_name(prf: &[u64]) -> String {
    match prf {
        [2, 16, 840, 1, 101, 3, 4, 2, 13] => "HMAC-SHA3-224".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 14] => "HMAC-SHA3-256".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 15] => "HMAC-SHA3-384".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 16] => "HMAC-SHA3-512".into(),
        [1, 2, 840, 113549, 2, 12] => "HMAC-SHA512/224".into(),
        [1, 2, 840, 113549, 2, 13] => "HMAC-SHA512/256".into(),
        [1, 2, 643, 7, 1, 1, 4, 1] | [1, 2, 643, 7, 1, 1, 4, 2] => "HMAC-GOST R 34.11-2012".into(),
        other => HashAlg::from_hmac_oid(other).map(|h| h.hmac_name().to_string()).unwrap_or_else(|| oids::oid_str(other)),
    }
}

impl Kdf {
    /// Reads a `KeyDerivationFunc` AlgorithmIdentifier.
    pub fn parse(alg: &AlgorithmId) -> Res<Kdf> {
        let params = alg.params.as_deref().unwrap_or(&[]);
        match alg.oid.as_slice() {
            a if a == oids::PBKDF2 => yasna::parse_ber(params, |r| {
                r.read_sequence(|r| {
                    let salt = r.next().read_bytes()?;
                    let iterations = r.next().read_u64()?;
                    let key_length = r.read_optional(|r| r.read_u64())?;
                    let prf = r.read_optional(read_algorithm_id)?;
                    Ok(Kdf::Pbkdf2 { salt, iterations, key_length, prf: prf.map(|p| p.oid).unwrap_or_else(|| oids::HMAC_SHA1.to_vec()) })
                })
            })
            .map_err(|err| format!("invalid: malformed PBKDF2 parameters: {err}")),
            a if a == oids::SCRYPT => yasna::parse_ber(params, |r| {
                r.read_sequence(|r| {
                    let salt = r.next().read_bytes()?;
                    let n = r.next().read_u64()?;
                    let block = r.next().read_u64()?;
                    let p = r.next().read_u64()?;
                    let key_length = r.read_optional(|r| r.read_u64())?;
                    Ok(Kdf::Scrypt { salt, n, r: block, p, key_length })
                })
            })
            .map_err(|err| format!("invalid: malformed scrypt parameters: {err}")),
            other => Err(format!("unsupported: the key derivation function {} is not supported", oids::oid_str(other))),
        }
    }

    /// DER `AlgorithmIdentifier` of this key derivation, as [`Kdf::parse`] reads it. A PBKDF2
    /// PRF of HMAC-SHA1 is the DEFAULT and is left out.
    pub fn algorithm_id(&self) -> Vec<u8> {
        yasna::construct_der(|w| {
            w.write_sequence(|w| match self {
                Kdf::Pbkdf2 { salt, iterations, key_length, prf } => {
                    w.next().write_oid(&oid(oids::PBKDF2));
                    w.next().write_sequence(|w| {
                        w.next().write_bytes(salt);
                        w.next().write_u64(*iterations);
                        if let Some(len) = key_length {
                            w.next().write_u64(*len);
                        }
                        if prf.as_slice() != oids::HMAC_SHA1 {
                            w.next().write_sequence(|w| {
                                w.next().write_oid(&oid(prf));
                                w.next().write_null();
                            });
                        }
                    });
                }
                Kdf::Scrypt { salt, n, r, p, key_length } => {
                    w.next().write_oid(&oid(oids::SCRYPT));
                    w.next().write_sequence(|w| {
                        w.next().write_bytes(salt);
                        w.next().write_u64(*n);
                        w.next().write_u64(*r);
                        w.next().write_u64(*p);
                        if let Some(len) = key_length {
                            w.next().write_u64(*len);
                        }
                    });
                }
            })
        })
    }

    /// The key length the file states, when it states one.
    pub fn key_length(&self) -> Option<u64> {
        match self {
            Kdf::Pbkdf2 { key_length, .. } | Kdf::Scrypt { key_length, .. } => *key_length,
        }
    }

    /// Derives a key from password bytes in whatever encoding the surrounding format prescribes.
    /// `default_len` is used when the parameters carry no key length.
    pub fn derive(&self, password: &[u8], default_len: usize) -> Res<Vec<u8>> {
        let mut key = vec![0u8; derived_len(self.key_length(), default_len)?];
        match self {
            Kdf::Pbkdf2 { salt, iterations, prf, .. } => {
                let hash = HashAlg::from_hmac_oid(prf).ok_or_else(|| format!("unsupported: PBKDF2 with {} is not supported", prf_name(prf)))?;
                hash.pbkdf2(password, salt, check_iterations(*iterations)?, &mut key);
            }
            Kdf::Scrypt { salt, n, r, p, .. } => {
                let bad = || "invalid: the scrypt parameters are out of range".to_string();
                if *n < 2 || !n.is_power_of_two() || *r == 0 || *p == 0 {
                    return Err(bad());
                }
                let memory = n.checked_mul(*r).and_then(|v| v.checked_mul(128)).ok_or_else(bad)?;
                let work = n.checked_mul(*r).and_then(|v| v.checked_mul(*p)).ok_or_else(bad)?;
                if memory > MAX_SCRYPT_MEMORY || work > MAX_SCRYPT_WORK {
                    return Err(format!("invalid: the file asks scrypt for N={n}, r={r}, p={p}, which is more work than any tool writes"));
                }
                let params = scrypt::Params::new(n.trailing_zeros() as u8, *r as u32, *p as u32, scrypt::Params::RECOMMENDED_LEN).map_err(|_| bad())?;
                scrypt::scrypt(password, salt, &params, &mut key).map_err(|_| bad())?;
            }
        }
        Ok(key)
    }

    /// Bouncy Castle up to 1.86 passed scrypt's block size where RFC 7914 has the parallelization
    /// parameter. Stores it wrote that way only open under the same convention, which is what
    /// this returns when it differs from the parameters as written.
    pub fn legacy_bc_scrypt(&self) -> Option<Kdf> {
        match self {
            Kdf::Scrypt { salt, n, r, p, key_length } if r != p => Some(Kdf::Scrypt { salt: salt.clone(), n: *n, r: *r, p: *r, key_length: *key_length }),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Kdf::Pbkdf2 { iterations, prf, .. } => format!("PBKDF2-{}, {iterations} iterations", prf_name(prf)),
            Kdf::Scrypt { n, r, p, .. } => format!("scrypt N={n} r={r} p={p}"),
        }
    }
}

/// Bytes of key a PBES2 encryption scheme takes, for the schemes this module decrypts.
fn scheme_key_len(scheme: &[u64]) -> Option<usize> {
    Some(match scheme {
        a if a == oids::AES128_CBC || a == oids::AES128_CCM || a == oids::AES128_WRAP_PAD => 16,
        a if a == oids::AES192_CBC || a == oids::AES192_CCM || a == oids::AES192_WRAP_PAD => 24,
        a if a == oids::AES256_CBC || a == oids::AES256_CCM || a == oids::AES256_WRAP_PAD => 32,
        a if a == oids::DES_EDE3_CBC => 24,
        a if a == oids::DES_CBC => 8,
        _ => return None,
    })
}

/// Display name of an encryption scheme, including common ones this module cannot decrypt, so
/// the error names the cipher instead of a string of numbers.
pub fn scheme_name(scheme: &[u64]) -> String {
    match scheme {
        a if a == oids::AES128_CBC => "AES-128-CBC".into(),
        a if a == oids::AES192_CBC => "AES-192-CBC".into(),
        a if a == oids::AES256_CBC => "AES-256-CBC".into(),
        a if a == oids::AES128_CCM => "AES-128-CCM".into(),
        a if a == oids::AES192_CCM => "AES-192-CCM".into(),
        a if a == oids::AES256_CCM => "AES-256-CCM".into(),
        a if a == oids::AES128_GCM => "AES-128-GCM".into(),
        a if a == oids::AES192_GCM => "AES-192-GCM".into(),
        a if a == oids::AES256_GCM => "AES-256-GCM".into(),
        a if a == oids::AES128_WRAP_PAD => "AES-128 key wrap".into(),
        a if a == oids::AES192_WRAP_PAD => "AES-192 key wrap".into(),
        a if a == oids::AES256_WRAP_PAD => "AES-256 key wrap".into(),
        a if a == oids::DES_EDE3_CBC => "DES-EDE3-CBC".into(),
        a if a == oids::DES_CBC => "DES-CBC".into(),
        a if a == oids::RC2_CBC => "RC2-CBC".into(),
        [1, 2, 392, 200011, 61, 1, 1, 1, 2] => "Camellia-128-CBC".into(),
        [1, 2, 392, 200011, 61, 1, 1, 1, 3] => "Camellia-192-CBC".into(),
        [1, 2, 392, 200011, 61, 1, 1, 1, 4] => "Camellia-256-CBC".into(),
        [1, 2, 410, 200046, 1, 1, 2] => "ARIA-128-CBC".into(),
        [1, 2, 410, 200046, 1, 1, 7] => "ARIA-192-CBC".into(),
        [1, 2, 410, 200046, 1, 1, 12] => "ARIA-256-CBC".into(),
        [1, 2, 410, 200004, 1, 4] => "SEED-CBC".into(),
        [1, 2, 156, 10197, 1, 104, 2] => "SM4-CBC".into(),
        other => oids::oid_str(other),
    }
}

fn auth_error(err: String) -> String {
    if err == modes::AUTH_FAILED { WRONG_PASSWORD.into() } else { err }
}

/// Decrypts with a PBES2 encryption scheme and a key that is already derived.
pub fn scheme_decrypt(scheme: &AlgorithmId, key: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let params = scheme.params.as_deref().unwrap_or(&[]);
    let iv = || yasna::parse_ber(params, |r| r.read_bytes()).map_err(|err| format!("invalid: malformed cipher parameters: {err}"));
    match scheme.oid.as_slice() {
        a if a == oids::AES128_CBC || a == oids::AES192_CBC || a == oids::AES256_CBC => aes_cbc_decrypt(key, &iv()?, data),
        a if a == oids::DES_EDE3_CBC => des3_cbc_decrypt(key, &iv()?, data),
        a if a == oids::DES_CBC => des_cbc_decrypt(key, &iv()?, data),
        a if a == oids::AES128_CCM || a == oids::AES192_CCM || a == oids::AES256_CCM => {
            // CCMParameters ::= SEQUENCE { nonce OCTET STRING, icvLen INTEGER DEFAULT 12 }
            let (nonce, tag_len) = yasna::parse_ber(params, |r| {
                r.read_sequence(|r| {
                    let nonce = r.next().read_bytes()?;
                    let tag_len = r.read_optional(|r| r.read_u64())?.unwrap_or(12);
                    Ok((nonce, tag_len))
                })
            })
            .map_err(|err| format!("invalid: malformed AES-CCM parameters: {err}"))?;
            modes::aes_ccm_decrypt(key, &nonce, usize::try_from(tag_len).unwrap_or(usize::MAX), &[], data).map_err(auth_error)
        }
        a if a == oids::AES128_WRAP_PAD || a == oids::AES192_WRAP_PAD || a == oids::AES256_WRAP_PAD => modes::aes_kwp_unwrap(key, data).map_err(auth_error),
        other => Err(format!("unsupported: {} encryption is not supported. Re-encrypt the file with AES-256-CBC.", scheme_name(other))),
    }
}

/// The two halves of `PBES2-params`: how the key is derived and what it is used with.
#[derive(Clone, Debug)]
pub struct Pbes2Params {
    pub kdf: Kdf,
    pub scheme: AlgorithmId,
}

pub fn parse_pbes2_params(params: &[u8]) -> Res<Pbes2Params> {
    let (kdf, scheme) = yasna::parse_ber(params, |r| {
        r.read_sequence(|r| {
            let kdf = read_algorithm_id(r.next())?;
            let scheme = read_algorithm_id(r.next())?;
            Ok((kdf, scheme))
        })
    })
    .map_err(|err| format!("invalid: malformed PBES2 parameters: {err}"))?;
    Ok(Pbes2Params { kdf: Kdf::parse(&kdf)?, scheme })
}

impl Pbes2Params {
    /// Derives the key from `password` (in the byte form the surrounding format prescribes: UTF-8
    /// for PKCS#5, something else for BCFKS) and decrypts `data`.
    pub fn decrypt(&self, password: &[u8], data: &[u8]) -> Res<Vec<u8>> {
        self.decrypt_with(&self.kdf, password, data)
    }

    /// [`Self::decrypt`] with another key derivation, for the scrypt convention of old Bouncy
    /// Castle releases ([`Kdf::legacy_bc_scrypt`]).
    pub fn decrypt_with(&self, kdf: &Kdf, password: &[u8], data: &[u8]) -> Res<Vec<u8>> {
        let default_len =
            scheme_key_len(&self.scheme.oid).ok_or_else(|| format!("unsupported: {} encryption is not supported. Re-encrypt the file with AES-256-CBC.", scheme_name(&self.scheme.oid)))?;
        let key = kdf.derive(password, default_len)?;
        scheme_decrypt(&self.scheme, &key, data)
    }

    pub fn describe(&self) -> String {
        match &self.kdf {
            // The order people know from `openssl asn1parse`: PRF, cipher, then the count.
            Kdf::Pbkdf2 { iterations, prf, .. } => format!("PBES2 (PBKDF2-{}, {}, {iterations} iterations)", prf_name(prf), scheme_name(&self.scheme.oid)),
            kdf => format!("PBES2 ({}, {})", kdf.describe(), scheme_name(&self.scheme.oid)),
        }
    }

    /// Derives the key as [`Self::decrypt`] does and encrypts `data` with the scheme's own
    /// parameters (its IV or nonce), so the same parameters give the same bytes.
    pub fn encrypt_with(&self, kdf: &Kdf, password: &[u8], data: &[u8]) -> Res<Vec<u8>> {
        let default_len = scheme_key_len(&self.scheme.oid).ok_or_else(|| format!("unsupported: {} encryption cannot be written", scheme_name(&self.scheme.oid)))?;
        let key = kdf.derive(password, default_len)?;
        scheme_encrypt(&self.scheme, &key, data)
    }

    pub fn encrypt(&self, password: &[u8], data: &[u8]) -> Res<Vec<u8>> {
        self.encrypt_with(&self.kdf, password, data)
    }

    /// DER `AlgorithmIdentifier { PBES2, PBES2-params }`.
    pub fn algorithm_id(&self) -> Vec<u8> {
        let kdf = self.kdf.algorithm_id();
        let scheme = self.scheme.to_der();
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(oids::PBES2));
                w.next().write_sequence(|w| {
                    w.next().write_der(&kdf);
                    w.next().write_der(&scheme);
                });
            })
        })
    }
}

impl AlgorithmId {
    /// DER of the `AlgorithmIdentifier`, parameters as they were read.
    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(&self.oid));
                if let Some(p) = &self.params {
                    w.next().write_der(p);
                }
            })
        })
    }
}

/// AES-256-CCM with `CCMParameters { nonce, icvLen }`. The ICV length is left out when it is the
/// default of 12, as DER requires.
pub fn aes256_ccm_scheme(nonce: &[u8], tag_len: usize) -> AlgorithmId {
    let params = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bytes(nonce);
            if tag_len != 12 {
                w.next().write_u64(tag_len as u64);
            }
        })
    });
    AlgorithmId { oid: oids::AES256_CCM.to_vec(), params: Some(params) }
}

/// AES-256 key wrap with padding (RFC 5649), which has no parameters.
pub fn aes256_kwp_scheme() -> AlgorithmId {
    AlgorithmId { oid: oids::AES256_WRAP_PAD.to_vec(), params: None }
}

/// Encrypts with a PBES2 encryption scheme and a key that is already derived: the inverse of
/// [`scheme_decrypt`] for the schemes this app writes.
pub fn scheme_encrypt(scheme: &AlgorithmId, key: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let params = scheme.params.as_deref().unwrap_or(&[]);
    match scheme.oid.as_slice() {
        a if a == oids::AES128_CCM || a == oids::AES192_CCM || a == oids::AES256_CCM => {
            let (nonce, tag_len) = yasna::parse_ber(params, |r| {
                r.read_sequence(|r| {
                    let nonce = r.next().read_bytes()?;
                    let tag_len = r.read_optional(|r| r.read_u64())?.unwrap_or(12);
                    Ok((nonce, tag_len))
                })
            })
            .map_err(|err| format!("invalid: malformed AES-CCM parameters: {err}"))?;
            modes::aes_ccm_encrypt(key, &nonce, usize::try_from(tag_len).unwrap_or(usize::MAX), &[], data)
        }
        a if a == oids::AES128_WRAP_PAD || a == oids::AES192_WRAP_PAD || a == oids::AES256_WRAP_PAD => modes::aes_kwp_wrap(key, data),
        a if a == oids::AES128_CBC || a == oids::AES192_CBC || a == oids::AES256_CBC => {
            let iv = yasna::parse_ber(params, |r| r.read_bytes()).map_err(|err| format!("invalid: malformed cipher parameters: {err}"))?;
            let bad = |_| "invalid: bad AES key or IV".to_string();
            Ok(match key.len() {
                16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &iv).map_err(bad)?.encrypt_padded_vec_mut::<Pkcs7>(data),
                24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, &iv).map_err(bad)?.encrypt_padded_vec_mut::<Pkcs7>(data),
                _ => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv).map_err(bad)?.encrypt_padded_vec_mut::<Pkcs7>(data),
            })
        }
        other => Err(format!("unsupported: {} encryption cannot be written", scheme_name(other))),
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

fn encrypted_private_key_info(alg: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(alg);
            w.next().write_bytes(ciphertext);
        })
    })
}

/// Wraps a PKCS#8 PrivateKeyInfo into an `EncryptedPrivateKeyInfo` (PBES2/AES-256-CBC).
pub fn encrypt_pkcs8(password: &str, pkcs8_der: &[u8], iterations: u64) -> Res<Vec<u8>> {
    let (alg, ciphertext) = pbes2_encrypt(password, pkcs8_der, iterations)?;
    Ok(encrypted_private_key_info(&alg, &ciphertext))
}

/// Encrypts with pbeWithSHAAnd3-KeyTripleDES-CBC, the PKCS#12 scheme every reader since the
/// 1990s understands. Returns the DER AlgorithmIdentifier and the ciphertext.
pub fn pkcs12_3des_encrypt(password: &str, plaintext: &[u8], iterations: u64) -> Res<(Vec<u8>, Vec<u8>)> {
    // Eight bytes, as OpenSSL writes for this scheme: some old readers size their buffer for it.
    let salt = random_bytes(8);
    let key = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 1, 24);
    let iv = pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 2, 8);
    let ciphertext = des3_cbc_encrypt(&key, &iv, plaintext)?;
    let alg = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(oids::PBE_SHA1_3DES));
            w.next().write_der(&sun_pbe_params(&salt, iterations));
        })
    });
    Ok((alg, ciphertext))
}

/// An `EncryptedPrivateKeyInfo` under [`pkcs12_3des_encrypt`].
pub fn encrypt_pkcs8_3des(password: &str, pkcs8_der: &[u8], iterations: u64) -> Res<Vec<u8>> {
    let (alg, ciphertext) = pkcs12_3des_encrypt(password, pkcs8_der, iterations)?;
    Ok(encrypted_private_key_info(&alg, &ciphertext))
}

/// Splits an `EncryptedPrivateKeyInfo` into its algorithm and ciphertext.
pub fn parse_encrypted_pkcs8(der: &[u8]) -> Res<(AlgorithmId, Vec<u8>)> {
    crate::util::check_der_lengths(der)?;
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let alg = read_algorithm_id(r.next())?;
            let data = r.next().read_bytes()?;
            Ok((alg, data))
        })
    })
    .map_err(|err| format!("invalid: malformed EncryptedPrivateKeyInfo: {err}"))
}

/// Parses an `EncryptedPrivateKeyInfo` and decrypts it to the inner PKCS#8 DER.
pub fn decrypt_pkcs8(password: &str, der: &[u8]) -> Res<Vec<u8>> {
    let (alg, data) = parse_encrypted_pkcs8(der)?;
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
    fn legacy_3des_round_trip() {
        let pkcs8 = yasna::construct_der(|w| w.write_sequence(|w| w.next().write_bytes(b"pretend this is a private key")));
        let enc = encrypt_pkcs8_3des("pässwörd", &pkcs8, LEGACY_ITERATIONS).unwrap();
        let (alg, _) = parse_encrypted_pkcs8(&enc).unwrap();
        assert_eq!(describe_algorithm(&alg), "PBE-SHA1-3DES");
        assert_eq!(decrypt_pkcs8("pässwörd", &enc).unwrap(), pkcs8);
        assert!(decrypt_pkcs8("wrong", &enc).is_err());
    }

    #[test]
    fn sun_md5_3des_round_trip() {
        let (alg, ct) = sun_md5_3des_encrypt("changeit", b"secret material", 200_000).unwrap();
        let parsed = parse_algorithm_id(&alg).unwrap();
        assert_eq!(decrypt(&parsed, "changeit", &ct).unwrap(), b"secret material");
    }

    /// RFC 7914 section 12, the second and third vectors.
    #[test]
    fn scrypt_matches_rfc7914_vectors() {
        let kdf = Kdf::Scrypt { salt: b"NaCl".to_vec(), n: 1024, r: 8, p: 16, key_length: Some(64) };
        assert_eq!(
            hex::encode(kdf.derive(b"password", 32).unwrap()),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        );
        let kdf = Kdf::Scrypt { salt: b"SodiumChloride".to_vec(), n: 16384, r: 8, p: 1, key_length: None };
        assert_eq!(
            hex::encode(kdf.derive(b"pleaseletmein", 64).unwrap()),
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
        );
        // The convention of Bouncy Castle up to 1.86: the block size stands in for p.
        match kdf.legacy_bc_scrypt() {
            Some(Kdf::Scrypt { r: 8, p: 8, .. }) => {}
            other => panic!("unexpected legacy parameters: {other:?}"),
        }
        assert!(Kdf::Scrypt { salt: vec![], n: 1024, r: 8, p: 8, key_length: None }.legacy_bc_scrypt().is_none());
    }

    #[test]
    fn hostile_work_factors_are_refused_before_any_work_is_done() {
        let started = std::time::Instant::now();
        let pbkdf2 = Kdf::Pbkdf2 { salt: vec![1; 8], iterations: u64::MAX, key_length: None, prf: oids::HMAC_SHA256.to_vec() };
        assert!(pbkdf2.derive(b"pw", 32).unwrap_err().starts_with("invalid:"));
        for (n, r, p) in [(1u64 << 40, 8, 1), (1 << 20, 1 << 20, 1), (1024, 8, 1 << 30), (1000, 8, 1), (1024, 0, 1)] {
            let kdf = Kdf::Scrypt { salt: vec![1; 8], n, r, p, key_length: None };
            assert!(kdf.derive(b"pw", 32).unwrap_err().starts_with("invalid:"), "N={n} r={r} p={p}");
        }
        assert!(check_iterations(0).is_err() && check_iterations(MAX_ITERATIONS + 1).is_err() && check_iterations(2048).is_ok());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn an_unknown_scheme_is_reported_as_unsupported_not_as_a_wrong_password() {
        // PBES2 with PBKDF2-HMAC-SHA256 and Camellia-256-CBC, as `openssl pkcs8 -v2 camellia-256-cbc` writes.
        let camellia = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(oids::PBES2));
                    w.next().write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(oids::PBKDF2));
                            w.next().write_sequence(|w| {
                                w.next().write_bytes(&[1u8; 16]);
                                w.next().write_u64(2048);
                            });
                        });
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(&[1, 2, 392, 200011, 61, 1, 1, 1, 4]));
                            w.next().write_bytes(&[2u8; 16]);
                        });
                    });
                });
                w.next().write_bytes(&[3u8; 32]);
            })
        });
        let err = decrypt_pkcs8("pw", &camellia).unwrap_err();
        assert!(is_unsupported(&err) && err.contains("Camellia-256-CBC"), "{err}");
        let (alg, _) = parse_encrypted_pkcs8(&camellia).unwrap();
        assert_eq!(describe_algorithm(&alg), "PBES2 (PBKDF2-HMAC-SHA1, Camellia-256-CBC, 2048 iterations)");
        let unknown = AlgorithmId { oid: vec![1, 2, 3, 4], params: None };
        assert!(is_unsupported(&decrypt(&unknown, "pw", b"data").unwrap_err()));
    }

    #[test]
    fn stream_cipher_output_is_checked_for_shape() {
        assert!(is_one_der_sequence(&[0x30, 0x03, 0x02, 0x01, 0x00]));
        assert!(is_one_der_sequence(&yasna::construct_der(|w| w.write_sequence(|w| w.next().write_bytes(&[7u8; 300])))));
        for noise in [&[0x30u8, 0x03, 0x02, 0x01][..], &[0x31, 0x00], &[0x30, 0x80, 0x00, 0x00], &[0x30], &[]] {
            assert!(!is_one_der_sequence(noise), "{noise:?}");
        }
    }
}
