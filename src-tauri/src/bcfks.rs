//! Bouncy Castle BCFKS, the "FIPS keystore", read and written.
//!
//! ```text
//! ObjectStore      ::= SEQUENCE { storeData, integrityCheck }
//! storeData        ::= EncryptedObjectStoreData | ObjectStoreData
//! EncryptedObjectStoreData ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, OCTET STRING }
//! integrityCheck   ::= PbkdMacIntegrityCheck | [0] EXPLICIT SignatureCheck
//! PbkdMacIntegrityCheck ::= SEQUENCE { macAlgorithm, pbkdAlgorithm KeyDerivationFunc, mac OCTET STRING }
//! SignatureCheck   ::= SEQUENCE { signatureAlgorithm, certificates [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL, BIT STRING }
//! ObjectStoreData  ::= SEQUENCE { version INTEGER, integrityAlgorithm, creationDate GeneralizedTime,
//!                                 lastModifiedDate GeneralizedTime, SEQUENCE OF ObjectData, comment UTF8String OPTIONAL }
//! ObjectData       ::= SEQUENCE { type INTEGER, identifier UTF8String, creationDate, lastModifiedDate,
//!                                 data OCTET STRING, comment UTF8String OPTIONAL }
//! ```
//!
//! Every key is derived from `PKCS12PasswordToBytes(password) ‖ PKCS12PasswordToBytes(purpose)`
//! with the purposes `STORE_ENCRYPTION`, `INTEGRITY_CHECK`, `PRIVATE_KEY_ENCRYPTION` and
//! `SECRET_KEY_ENCRYPTION`; the store and each entry are encrypted with AES-256 (CCM, or key wrap
//! with padding) under PBES2, and the MAC is an HMAC over the DER of the store-data element.
//!
//! The writer is checked by reproducing the Bouncy Castle test stores bit for bit: a store read
//! from a file Bouncy Castle wrote, written again with the salts, nonces and dates it had, comes
//! out identical, encryption and MAC included.

use crate::entry;
use crate::keys;
use crate::model::KeystoreEntry;
use crate::oids::{self, oid};
use crate::pbe::{self, AlgorithmId, HashAlg, Kdf, Pbes2Params, bc_password};
use crate::util::*;
use crate::x509;
use std::collections::HashMap;
use yasna::Tag;

const WRONG_PASSWORD: &str = "wrong-password: keystore password incorrect or file corrupt";

const CERTIFICATE: u64 = 0;
const PRIVATE_KEY: u64 = 1;
const SECRET_KEY: u64 = 2;
const PROTECTED_PRIVATE_KEY: u64 = 3;
const PROTECTED_SECRET_KEY: u64 = 4;
const PBKDF_KEY: u64 = 5;

/// What Bouncy Castle writes by default: a 512-bit salt, 50 × 1024 PBKDF2-HMAC-SHA512 iterations,
/// and AES-CCM with a 96-bit nonce and a 64-bit tag.
const SALT_LEN: usize = 64;
const ITERATIONS: u64 = 50 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 8;

const STORE_ENCRYPTION: &str = "STORE_ENCRYPTION";
const INTEGRITY_CHECK: &str = "INTEGRITY_CHECK";
const PRIVATE_KEY_ENCRYPTION: &str = "PRIVATE_KEY_ENCRYPTION";
const SECRET_KEY_ENCRYPTION: &str = "SECRET_KEY_ENCRYPTION";

/// What a store holds, in the app's terms.
#[derive(Debug)]
pub struct Decoded {
    pub entries: Vec<KeystoreEntry>,
    /// Things worth knowing that the entry list does not show.
    pub notes: Vec<String>,
    /// Entries in the file that are not in `entries`; a save does not write them back.
    pub omitted: usize,
}

fn invalid() -> yasna::ASN1Error {
    yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid)
}

fn malformed(what: &str) -> impl Fn(yasna::ASN1Error) -> String + '_ {
    move |err| format!("invalid: malformed BCFKS {what}: {err}")
}

/// The bytes every BCFKS key derivation starts from.
fn kdf_input(password: &str, purpose: &str) -> Vec<u8> {
    [bc_password(password), bc_password(purpose)].concat()
}

fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawObject {
    kind: u64,
    alias: String,
    /// GeneralizedTime, DER, kept as written.
    created: Vec<u8>,
    modified: Vec<u8>,
    data: Vec<u8>,
    comment: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoreData {
    version: u64,
    /// DER of the `AlgorithmIdentifier` the integrity check must use.
    integrity_alg: Vec<u8>,
    created: Vec<u8>,
    modified: Vec<u8>,
    objects: Vec<RawObject>,
    comment: Option<Vec<u8>>,
}

fn read_time(r: yasna::BERReader) -> yasna::ASN1Result<Vec<u8>> {
    let der = r.read_der()?;
    if der.first() != Some(&0x18) {
        return Err(invalid());
    }
    Ok(der)
}

fn parse_store_data(der: &[u8]) -> Res<StoreData> {
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let version = r.next().read_u64()?;
            let integrity_alg = r.next().read_der()?;
            let created = read_time(r.next())?;
            let modified = read_time(r.next())?;
            let objects = r.next().collect_sequence_of(|r| {
                r.read_sequence(|r| {
                    let kind = r.next().read_u64()?;
                    let alias = r.next().read_utf8string()?;
                    let created = read_time(r.next())?;
                    let modified = read_time(r.next())?;
                    let data = r.next().read_bytes()?;
                    let comment = r.read_optional(|r| r.read_der())?;
                    Ok(RawObject { kind, alias, created, modified, data, comment })
                })
            })?;
            let comment = r.read_optional(|r| r.read_der())?;
            Ok(StoreData { version, integrity_alg, created, modified, objects, comment })
        })
    })
    .map_err(malformed("store data"))
}

fn write_store_data(store: &StoreData) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u64(store.version);
            w.next().write_der(&store.integrity_alg);
            w.next().write_der(&store.created);
            w.next().write_der(&store.modified);
            w.next().write_sequence(|w| {
                for o in &store.objects {
                    w.next().write_sequence(|w| {
                        w.next().write_u64(o.kind);
                        w.next().write_utf8_string(&o.alias);
                        w.next().write_der(&o.created);
                        w.next().write_der(&o.modified);
                        w.next().write_bytes(&o.data);
                        if let Some(c) = &o.comment {
                            w.next().write_der(c);
                        }
                    });
                }
            });
            if let Some(c) = &store.comment {
                w.next().write_der(c);
            }
        })
    })
}

#[derive(Clone, Debug)]
enum Integrity {
    Mac { mac_alg: AlgorithmId, kdf: AlgorithmId, mac: Vec<u8> },
    Signature { sig_alg: AlgorithmId, certs: Vec<Vec<u8>>, signature: Vec<u8> },
}

impl Integrity {
    fn algorithm_oid(&self) -> &[u64] {
        match self {
            Integrity::Mac { mac_alg, .. } => &mac_alg.oid,
            Integrity::Signature { sig_alg, .. } => &sig_alg.oid,
        }
    }
}

fn parse_integrity(der: &[u8]) -> Res<Integrity> {
    match der.first() {
        Some(0x30) => yasna::parse_ber(der, |r| {
            r.read_sequence(|r| {
                let mac_alg = pbe::read_algorithm_id(r.next())?;
                let kdf = pbe::read_algorithm_id(r.next())?;
                let mac = r.next().read_bytes()?;
                Ok(Integrity::Mac { mac_alg, kdf, mac })
            })
        })
        .map_err(malformed("integrity check")),
        Some(0xA0) => yasna::parse_ber(der, |r| {
            r.read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let sig_alg = pbe::read_algorithm_id(r.next())?;
                    let certs = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.collect_sequence_of(|r| r.read_der())))?.unwrap_or_default();
                    let (signature, _) = r.next().read_bitvec_bytes()?;
                    Ok(Integrity::Signature { sig_alg, certs, signature })
                })
            })
        })
        .map_err(malformed("signature check")),
        _ => Err("invalid: the BCFKS integrity check is neither a MAC nor a signature".into()),
    }
}

fn algorithm_oid(der: &[u8]) -> Option<Vec<u64>> {
    pbe::parse_algorithm_id(der).ok().map(|a| a.oid)
}

/// `EncryptedObjectStoreData`, or `ObjectStoreData` in the clear.
fn store_data_shape(der: &[u8]) -> bool {
    let Ok(parts) = yasna::parse_ber(der, |r| r.collect_sequence_of(|r| r.read_der())) else { return false };
    match parts.as_slice() {
        [alg, data] => data.first() == Some(&0x04) && algorithm_oid(alg).is_some_and(|oid| oid == oids::PBES2),
        [version, alg, created, modified, entries, rest @ ..] => {
            version.first() == Some(&0x02) && algorithm_oid(alg).is_some() && created.first() == Some(&0x18) && modified.first() == Some(&0x18) && entries.first() == Some(&0x30) && rest.len() <= 1
        }
        _ => false,
    }
}

/// A MAC with the key derivation it used, or a signature.
fn integrity_shape(der: &[u8]) -> bool {
    match parse_integrity(der) {
        Ok(Integrity::Mac { kdf, .. }) => kdf.oid == oids::PBKDF2 || kdf.oid == oids::SCRYPT,
        Ok(Integrity::Signature { .. }) => true,
        Err(_) => false,
    }
}

/// True for bytes shaped like a BCFKS store. The outer structure is in the clear, so this needs
/// no password. Other DER a user may open (certificates, requests, PKCS#7, PKCS#8, PKCS#12) has
/// a different number of elements or different types in these positions.
pub fn looks_like(bytes: &[u8]) -> bool {
    // Detection probes untrusted bytes with yasna, which overflows on a hostile indefinite length
    // unless every length header has been checked first.
    if bytes.first() != Some(&0x30) || check_der_lengths(bytes).is_err() {
        return false;
    }
    split_outer(bytes).is_ok_and(|(store, integrity)| store_data_shape(&store) && integrity_shape(&integrity))
}

fn split_outer(bytes: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
    yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            let store = r.next().read_der()?;
            let integrity = r.next().read_der()?;
            Ok((store, integrity))
        })
    })
    .map_err(|_| "invalid: not a BCFKS keystore, or the file is damaged".to_string())
}

// ---------------------------------------------------------------------------------------------
// Sealed values: a PBES2 AlgorithmIdentifier and ciphertext
// ---------------------------------------------------------------------------------------------

fn pbes2_of(alg: &AlgorithmId) -> Res<Pbes2Params> {
    if alg.oid != oids::PBES2 {
        return Err(format!("unsupported: BCFKS content protected with {} (PBES2 is supported)", oids::oid_str(&alg.oid)));
    }
    pbe::parse_pbes2_params(alg.params.as_deref().unwrap_or(&[]))
}

/// Decrypts under PBES2, retrying with the scrypt convention of Bouncy Castle up to 1.86.
fn open_sealed(alg: &AlgorithmId, ciphertext: &[u8], password: &str, purpose: &str) -> Res<Vec<u8>> {
    let params = pbes2_of(alg)?;
    let input = kdf_input(password, purpose);
    match params.decrypt(&input, ciphertext) {
        Ok(plain) => Ok(plain),
        Err(err) if pbe::is_unsupported(&err) || err.starts_with("invalid:") => Err(err),
        Err(err) => match params.kdf.legacy_bc_scrypt() {
            Some(legacy) => params.decrypt_with(&legacy, &input, ciphertext).map_err(|_| err),
            None => Err(err),
        },
    }
}

/// Fresh PBES2 parameters as Bouncy Castle writes them.
fn new_pbes2(key_len: u64) -> Pbes2Params {
    Pbes2Params { kdf: new_pbkdf2(key_len), scheme: pbe::aes256_ccm_scheme(&random_bytes(NONCE_LEN), TAG_LEN) }
}

fn new_pbkdf2(key_len: u64) -> Kdf {
    Kdf::Pbkdf2 { salt: random_bytes(SALT_LEN), iterations: ITERATIONS, key_length: Some(key_len), prf: oids::HMAC_SHA512.to_vec() }
}

/// `SEQUENCE { AlgorithmIdentifier, OCTET STRING }`: the shape of both `EncryptedPrivateKeyInfo`
/// and `EncryptedSecretKeyData`.
fn sealed_der(params: &Pbes2Params, password: &str, purpose: &str, plain: &[u8]) -> Res<Vec<u8>> {
    let ciphertext = params.encrypt(&kdf_input(password, purpose), plain)?;
    let alg = params.algorithm_id();
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&alg);
            w.next().write_bytes(&ciphertext);
        })
    }))
}

fn parse_sealed(der: &[u8]) -> Res<(AlgorithmId, Vec<u8>)> {
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let alg = pbe::read_algorithm_id(r.next())?;
            let data = r.next().read_bytes()?;
            Ok((alg, data))
        })
    })
    .map_err(malformed("encrypted key"))
}

/// `EncryptedPrivateKeyData ::= SEQUENCE { EncryptedPrivateKeyInfo, SEQUENCE OF Certificate }`.
fn parse_private_key_data(der: &[u8]) -> Res<(Vec<u8>, Vec<Vec<u8>>)> {
    check_der_lengths(der)?;
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let info = r.next().read_der()?;
            let certs = r.next().collect_sequence_of(|r| r.read_der())?;
            Ok((info, certs))
        })
    })
    .map_err(malformed("private key entry"))
}

fn private_key_data(info: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(info);
            w.next().write_sequence(|w| {
                for c in chain {
                    w.next().write_der(c);
                }
            });
        })
    })
}

/// `SecretKeyData ::= SEQUENCE { keyAlgorithm OBJECT IDENTIFIER, keyBytes OCTET STRING }`.
fn parse_secret_key_data(der: &[u8]) -> Res<(Vec<u64>, Vec<u8>)> {
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let alg = r.next().read_oid()?.components().to_vec();
            let key = r.next().read_bytes()?;
            Ok((alg, key))
        })
    })
    .map_err(malformed("secret key"))
}

fn secret_key_data(alg: &[u64], key: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(alg));
            w.next().write_bytes(key);
        })
    })
}

/// The Java name of a secret key algorithm Bouncy Castle stored by OID.
fn secret_algorithm_name(alg: &[u64]) -> String {
    match alg {
        a if a.starts_with(oids::AES) => "AES".into(),
        a if a == oids::DES_EDE_OIW || a == oids::DES_EDE3_CBC => "DESede".into(),
        a if a == oids::HMAC_SHA1 => "HmacSHA1".into(),
        a if a == oids::HMAC_SHA224 => "HmacSHA224".into(),
        a if a == oids::HMAC_SHA256 => "HmacSHA256".into(),
        a if a == oids::HMAC_SHA384 => "HmacSHA384".into(),
        a if a == oids::HMAC_SHA512 => "HmacSHA512".into(),
        a if a == oids::HMAC_SHA512_224 => "HmacSHA512/224".into(),
        a if a == oids::HMAC_SHA512_256 => "HmacSHA512/256".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 13] => "HmacSHA3-224".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 14] => "HmacSHA3-256".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 15] => "HmacSHA3-384".into(),
        [2, 16, 840, 1, 101, 3, 4, 2, 16] => "HmacSHA3-512".into(),
        [1, 2, 410, 200004, 1, 4] => "SEED".into(),
        [1, 2, 392, 200011, 61, 1, 1, 1, 2..=4] => "Camellia".into(),
        [1, 2, 410, 200046, 1, 1, 2 | 7 | 12] => "ARIA".into(),
        other => oids::oid_str(other),
    }
}

/// The OID Bouncy Castle stores a secret key algorithm under (`oidMap` in `BcFKSKeyStoreSpi`).
fn secret_algorithm_oid(name: &str, bits: usize) -> Res<Vec<u64>> {
    let canonical = entry::canonical_secret_algorithm(name);
    let upper = canonical.to_ascii_uppercase();
    Ok(match upper.as_str() {
        "AES" => oids::AES.to_vec(),
        "DESEDE" => oids::DES_EDE_OIW.to_vec(),
        "HMACSHA1" => oids::HMAC_SHA1.to_vec(),
        "HMACSHA224" => oids::HMAC_SHA224.to_vec(),
        "HMACSHA256" => oids::HMAC_SHA256.to_vec(),
        "HMACSHA384" => oids::HMAC_SHA384.to_vec(),
        "HMACSHA512" => oids::HMAC_SHA512.to_vec(),
        "HMACSHA512/224" => oids::HMAC_SHA512_224.to_vec(),
        "HMACSHA512/256" => oids::HMAC_SHA512_256.to_vec(),
        "HMACSHA3-224" => vec![2, 16, 840, 1, 101, 3, 4, 2, 13],
        "HMACSHA3-256" => vec![2, 16, 840, 1, 101, 3, 4, 2, 14],
        "HMACSHA3-384" => vec![2, 16, 840, 1, 101, 3, 4, 2, 15],
        "HMACSHA3-512" => vec![2, 16, 840, 1, 101, 3, 4, 2, 16],
        "SEED" => vec![1, 2, 410, 200004, 1, 4],
        "CAMELLIA" if matches!(bits, 128 | 192 | 256) => vec![1, 2, 392, 200011, 61, 1, 1, 1, (bits as u64 - 64) / 64 + 1],
        "ARIA" if matches!(bits, 128 | 192 | 256) => vec![1, 2, 410, 200046, 1, 1, [2, 7, 12][(bits - 128) / 64]],
        _ if upper.starts_with("1.") || upper.starts_with("2.") => upper.split('.').map(|p| p.parse::<u64>().map_err(|_| format!("unsupported: '{name}' is not an OID"))).collect::<Res<Vec<_>>>()?,
        _ => {
            return Err(format!(
                "unsupported: BCFKS stores a secret key under its algorithm's OID, and '{canonical}' has none Bouncy Castle knows (AES, DESede, HmacSHA*, SEED, Camellia and ARIA do)"
            ));
        }
    })
}

// ---------------------------------------------------------------------------------------------
// GeneralizedTime
// ---------------------------------------------------------------------------------------------

fn time_der(text: &str) -> Vec<u8> {
    let mut out = vec![0x18, text.len() as u8];
    out.extend_from_slice(text.as_bytes());
    out
}

/// The time Bouncy Castle writes: to the second, in UTC.
fn time_of(seconds: i64) -> Vec<u8> {
    time_der(&format!("{}Z", crate::util::Civil::from_ts(seconds).compact()))
}

fn seconds_of(der: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(der.get(2..)?).ok()?;
    let digits = text.get(..14)?;
    crate::util::parse_compact(digits).map(|t| t.ts())
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// A store with its integrity checked and its contents decrypted. The parameters are kept so a
/// store can be written back exactly as it was read, which the bit-for-bit tests do.
#[cfg_attr(not(test), allow(dead_code))]
struct Opened {
    store: StoreData,
    /// The store's encryption, when it was encrypted.
    encryption: Option<Pbes2Params>,
    integrity: Integrity,
    /// Opened only under the scrypt convention of Bouncy Castle up to 1.86.
    legacy: bool,
    /// The password the store data opened with. A signed store may have none.
    store_password: String,
    notes: Vec<String>,
}

fn verify_mac(store_elem: &[u8], mac_alg: &AlgorithmId, kdf: &AlgorithmId, mac: &[u8], password: &str) -> Res<bool> {
    let hash = HashAlg::from_hmac_oid(&mac_alg.oid).ok_or_else(|| {
        format!(
            "unsupported: this BCFKS store's integrity check uses {}, which Keystore Studio does not compute (HMAC-SHA512 is supported)",
            if mac_alg.oid == oids::HMAC_SHA3_512 { "HMAC-SHA3-512".to_string() } else { oids::oid_str(&mac_alg.oid) }
        )
    })?;
    let kdf = Kdf::parse(kdf)?;
    let input = kdf_input(password, INTEGRITY_CHECK);
    let check = |k: &Kdf| -> Res<bool> { Ok(same_bytes(&hash.hmac(&k.derive(&input, hash.output_len())?, store_elem), mac)) };
    if check(&kdf)? {
        return Ok(false);
    }
    match kdf.legacy_bc_scrypt() {
        Some(legacy) if check(&legacy)? => Ok(true),
        _ => Err(WRONG_PASSWORD.into()),
    }
}

fn verify_signature(store_elem: &[u8], sig_alg: &AlgorithmId, certs: &[Vec<u8>], signature: &[u8]) -> Res<String> {
    let signer = certs.first().ok_or("unsupported: this BCFKS store is signed, and the signer's certificate is not in the file, so the signature cannot be checked")?;
    let alg = keys::SigAlg::from_algorithm(&sig_alg.oid, sig_alg.params.as_deref())
        .ok_or_else(|| format!("unsupported: this BCFKS store is signed with {}, which Keystore Studio cannot verify", oids::signature_algorithm_name(&sig_alg.oid)))?;
    let spki = x509::cert_summary(signer)?.spki;
    if !keys::verify(&spki, alg, store_elem, signature)? {
        return Err("invalid: the BCFKS store's signature does not verify; the file was altered".into());
    }
    Ok(x509::parse_certificate(signer).map(|c| c.subject).unwrap_or_else(|_| "an embedded certificate".into()))
}

fn read(bytes: &[u8], password: &str) -> Res<Opened> {
    check_der_lengths(bytes)?;
    let (store_elem, integrity_der) = split_outer(bytes)?;
    let integrity = parse_integrity(&integrity_der)?;
    let mut notes = Vec::new();
    let mut legacy = false;
    match &integrity {
        Integrity::Mac { mac_alg, kdf, mac } => legacy = verify_mac(&store_elem, mac_alg, kdf, mac, password)?,
        Integrity::Signature { sig_alg, certs, signature } => {
            let signer = verify_signature(&store_elem, sig_alg, certs, signature)?;
            notes.push(format!(
                "The store is protected by a signature rather than a password MAC. The signature verifies against the certificate in the file ({signer}); whether that certificate should be trusted was not checked. Saving writes a password MAC instead."
            ));
        }
    }

    let parts = yasna::parse_ber(&store_elem, |r| r.collect_sequence_of(|r| r.read_der())).map_err(malformed("store"))?;
    let (store, encryption, store_password) = if parts.len() == 2 && parts[0].first() == Some(&0x30) {
        let alg = pbe::parse_algorithm_id(&parts[0])?;
        let params = pbes2_of(&alg)?;
        let ciphertext = yasna::parse_ber(&parts[1], |r| r.read_bytes()).map_err(malformed("store"))?;
        let plain = match &integrity {
            // The MAC settled the password and the scrypt convention; a failure now is damage.
            Integrity::Mac { .. } => {
                let kdf = if legacy { params.kdf.legacy_bc_scrypt().unwrap_or_else(|| params.kdf.clone()) } else { params.kdf.clone() };
                params
                    .decrypt_with(&kdf, &kdf_input(password, STORE_ENCRYPTION), &ciphertext)
                    .map_err(|err| if pbe::is_unsupported(&err) { err } else { "invalid: the BCFKS store does not decrypt although its MAC verified".into() })?
            }
            // A signed store says nothing about its password: try the one given, then none.
            Integrity::Signature { .. } => {
                let candidates: Vec<&str> = if password.is_empty() { vec![""] } else { vec![password, ""] };
                let mut opened = None;
                for pw in candidates {
                    if let Ok(plain) = open_sealed(&alg, &ciphertext, pw, STORE_ENCRYPTION) {
                        opened = Some((plain, pw));
                        break;
                    }
                }
                let (plain, pw) = opened.ok_or(WRONG_PASSWORD)?;
                if pw != password {
                    notes.push("The store contents are encrypted without a password; the password given was used for its keys.".into());
                }
                return finish(parse_store_data(&plain)?, Some(params), integrity, false, pw.to_string(), notes);
            }
        };
        (parse_store_data(&plain)?, Some(params), password.to_string())
    } else {
        (parse_store_data(&store_elem)?, None, password.to_string())
    };
    finish(store, encryption, integrity, legacy, store_password, notes)
}

fn finish(store: StoreData, encryption: Option<Pbes2Params>, integrity: Integrity, legacy: bool, store_password: String, notes: Vec<String>) -> Res<Opened> {
    // Bouncy Castle refuses a store whose contents name a different integrity algorithm than
    // the check that covers them, so an attacker cannot swap one for the other.
    if algorithm_oid(&store.integrity_alg).as_deref() != Some(integrity.algorithm_oid()) {
        return Err("invalid: the BCFKS store's integrity algorithm does not match its integrity check".into());
    }
    if store.version != 1 {
        return Err(format!("unsupported: BCFKS store version {} (version 1 is supported)", store.version));
    }
    Ok(Opened { store, encryption, integrity, legacy, store_password, notes })
}

fn key_password<'a>(alias: &str, key_passwords: &'a HashMap<String, String>) -> Option<&'a str> {
    key_passwords.get(alias).or_else(|| key_passwords.iter().find(|(k, _)| k.eq_ignore_ascii_case(alias)).map(|(_, v)| v)).map(String::as_str)
}

/// The passwords to try on one entry, in order: its own, the one given, the store's.
fn candidates<'a>(own: Option<&'a str>, given: &'a str, store: &'a str) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for pw in [own, Some(given), Some(store)].into_iter().flatten() {
        if !out.contains(&pw) {
            out.push(pw);
        }
    }
    out
}

fn to_model(opened: Opened, password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let Opened { store, store_password, mut notes, .. } = opened;
    let mut entries = Vec::new();
    let mut omitted = 0;
    for o in &store.objects {
        let created = seconds_of(&o.created);
        let tries = candidates(key_password(&o.alias, key_passwords).filter(|p| !p.is_empty()), password, &store_password);
        // The password that opened an entry is its key password when it is not the store's.
        let own = |used: &str| (used != password).then(|| used.to_string());
        match o.kind {
            CERTIFICATE => entries.push(entry::trusted_cert_entry(&o.alias, &o.data, created)?),
            PRIVATE_KEY | PROTECTED_PRIVATE_KEY => {
                let (info, chain) = parse_private_key_data(&o.data)?;
                let (alg, ciphertext) = parse_sealed(&info)?;
                let opened = tries.iter().find_map(|pw| open_sealed(&alg, &ciphertext, pw, PRIVATE_KEY_ENCRYPTION).ok().map(|plain| (plain, *pw)));
                match opened {
                    Some((pkcs8, used)) => {
                        let mut e = entry::key_pair_entry(&o.alias, &pkcs8, &chain, created)?;
                        e.key_password = own(used);
                        entries.push(e);
                    }
                    None => entries.push(entry::locked_key_pair_entry(&o.alias, &o.data, &chain, created)?),
                }
            }
            SECRET_KEY | PROTECTED_SECRET_KEY => {
                let Ok((alg, ciphertext)) = parse_sealed(&o.data) else {
                    notes.push(format!("'{}' is a secret key stored in a form Keystore Studio cannot read, so it is not shown.", o.alias));
                    omitted += 1;
                    continue;
                };
                let opened = tries.iter().find_map(|pw| open_sealed(&alg, &ciphertext, pw, SECRET_KEY_ENCRYPTION).ok().map(|plain| (plain, *pw)));
                match opened {
                    Some((plain, used)) => {
                        let (key_alg, key) = parse_secret_key_data(&plain)?;
                        let mut e = entry::secret_key_entry(&o.alias, &secret_algorithm_name(&key_alg), &key, created);
                        e.key_password = own(used);
                        entries.push(e);
                    }
                    None => entries.push(entry::locked_secret_entry(&o.alias, &o.data, created)),
                }
            }
            PBKDF_KEY => {
                notes.push(format!("'{}' is a password-based key (a PBEKey), which Keystore Studio does not model, so it is not shown.", o.alias));
                omitted += 1;
            }
            other => {
                notes.push(format!("'{}' is an entry of type {other}, which Keystore Studio does not know, so it is not shown.", o.alias));
                omitted += 1;
            }
        }
    }
    Ok(Decoded { entries, notes, omitted })
}

/// Opens a BCFKS file. `key_passwords` unlocks entries protected by a password other than the
/// store's; those that stay protected load as locked entries.
pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let opened = read(bytes, password)?;
    to_model(opened, password, key_passwords)
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

fn hmac_sha512_alg() -> AlgorithmId {
    AlgorithmId { oid: oids::HMAC_SHA512.to_vec(), params: Some(vec![0x05, 0x00]) }
}

/// Writes the store under `encryption` (or in the clear) with a password MAC. Every salt, nonce
/// and date comes from the arguments, so the same arguments give the same bytes.
fn write_store(store: &StoreData, encryption: Option<&Pbes2Params>, mac_alg: &AlgorithmId, mac_kdf: &Kdf, legacy: bool, password: &str) -> Res<Vec<u8>> {
    let plain = write_store_data(store);
    let store_elem = match encryption {
        Some(params) => {
            let kdf = if legacy { params.kdf.legacy_bc_scrypt().unwrap_or_else(|| params.kdf.clone()) } else { params.kdf.clone() };
            let ciphertext = params.encrypt_with(&kdf, &kdf_input(password, STORE_ENCRYPTION), &plain)?;
            let alg = params.algorithm_id();
            yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_der(&alg);
                    w.next().write_bytes(&ciphertext);
                })
            })
        }
        None => plain,
    };
    let hash = HashAlg::from_hmac_oid(&mac_alg.oid).ok_or("unsupported: BCFKS is written with an HMAC-SHA2 MAC")?;
    let kdf = if legacy { mac_kdf.legacy_bc_scrypt().unwrap_or_else(|| mac_kdf.clone()) } else { mac_kdf.clone() };
    let mac = hash.hmac(&kdf.derive(&kdf_input(password, INTEGRITY_CHECK), hash.output_len())?, &store_elem);
    let (mac_alg, kdf_alg) = (mac_alg.to_der(), mac_kdf.algorithm_id());
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&store_elem);
            w.next().write_sequence(|w| {
                w.next().write_der(&mac_alg);
                w.next().write_der(&kdf_alg);
                w.next().write_bytes(&mac);
            });
        })
    }))
}

fn entry_seconds(e: &KeystoreEntry) -> i64 {
    crate::util::parse_ymd(&e.creation_date).map(|d| d.ts()).unwrap_or_else(now_ts)
}

fn object_of(e: &KeystoreEntry, password: &str) -> Res<RawObject> {
    let pw = e.key_password.as_deref().filter(|p| !p.is_empty()).unwrap_or(password);
    let locked_blob = |check: fn(&[u8]) -> bool| -> Res<Vec<u8>> {
        let blob = unb64(e.protected_key.as_deref().ok_or_else(|| format!("invalid: '{}' has no key material", e.alias))?)?;
        if !check(&blob) {
            return Err(format!("invalid: '{}' is locked by a key password of another keystore format; unlock it first", e.alias));
        }
        Ok(blob)
    };
    let (kind, data) = match e.entry_type.as_str() {
        "TrustedCertificate" => (CERTIFICATE, entry::chain_der(e)?.into_iter().next().ok_or_else(|| format!("invalid: '{}' has no certificate", e.alias))?),
        "KeyPair" if e.locked => (PRIVATE_KEY, locked_blob(|b| parse_private_key_data(b).and_then(|(info, _)| parse_sealed(&info)).is_ok())?),
        "KeyPair" => {
            let chain = entry::chain_der(e)?;
            if chain.is_empty() {
                return Err(format!("invalid: key pair '{}' has no certificate chain", e.alias));
            }
            let info = sealed_der(&new_pbes2(32), pw, PRIVATE_KEY_ENCRYPTION, &entry::private_key_der(e)?)?;
            (PRIVATE_KEY, private_key_data(&info, &chain))
        }
        "SecretKey" if e.locked => (SECRET_KEY, locked_blob(|b| parse_sealed(b).is_ok())?),
        "SecretKey" => {
            let key = entry::secret_bytes(e)?;
            let plain = secret_key_data(&secret_algorithm_oid(&e.algorithm, key.len() * 8)?, &key);
            (SECRET_KEY, sealed_der(&new_pbes2(32), pw, SECRET_KEY_ENCRYPTION, &plain)?)
        }
        other => return Err(format!("unsupported: entry type '{other}'")),
    };
    let date = time_of(entry_seconds(e));
    Ok(RawObject { kind, alias: e.alias.clone(), created: date.clone(), modified: date, data, comment: None })
}

/// Writes a BCFKS file as Bouncy Castle does by default: AES-256-CCM under PBKDF2-HMAC-SHA512,
/// and an HMAC-SHA512 MAC. Each key is encrypted with its own key password when it has one.
pub fn encode(entries: &[KeystoreEntry], password: &str) -> Res<Vec<u8>> {
    let mut seen = std::collections::HashSet::new();
    let mut objects = Vec::with_capacity(entries.len());
    for e in entries {
        if !seen.insert(e.alias.clone()) {
            return Err(format!("invalid: duplicate alias '{}'", e.alias));
        }
        objects.push(object_of(e, password)?);
    }
    let now = time_of(now_ts());
    let mac_alg = hmac_sha512_alg();
    let store = StoreData { version: 1, integrity_alg: mac_alg.to_der(), created: now.clone(), modified: now, objects, comment: None };
    write_store(&store, Some(&new_pbes2(32)), &mac_alg, &new_pbkdf2(64), false, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
    }

    fn none() -> HashMap<String, String> {
        HashMap::new()
    }

    fn find<'a>(entries: &'a [KeystoreEntry], alias: &str) -> &'a KeystoreEntry {
        entries.iter().find(|e| e.alias == alias).unwrap_or_else(|| panic!("no entry '{alias}' in {:?}", entries.iter().map(|e| &e.alias).collect::<Vec<_>>()))
    }

    const HELLO: &str = "hello world";

    #[test]
    fn the_bouncy_castle_test_stores_open() {
        for (file, password) in [("bouncycastle/oldKeyStore.bcfks", HELLO), ("bouncycastle/oldKeyStoreNoPW.bcfks", "")] {
            let Decoded { entries, notes, omitted } = decode(&fixture(file), password, &none()).unwrap_or_else(|err| panic!("{file}: {err}"));
            assert_eq!((entries.len(), omitted), (1, 0), "{file}: {notes:?}");
            let key = find(&entries, "privkey");
            assert_eq!((key.entry_type.as_str(), key.chain_length), ("KeyPair", 2), "{file}");
            assert!(key.private_key_pem.is_some() && !key.locked, "{file}");
        }
        assert!(decode(&fixture("bouncycastle/oldKeyStore.bcfks"), "Yello world", &none()).unwrap_err().starts_with("wrong-password"));
    }

    #[test]
    fn every_entry_kind_and_per_entry_passwords_read_from_the_kwp_store() {
        let bytes = fixture("bouncycastle/kwpKeyStore.bcfks");
        let locked = decode(&bytes, HELLO, &none()).unwrap();
        assert!(locked.entries.len() >= 4, "{:?}", locked.entries.iter().map(|e| &e.alias).collect::<Vec<_>>());
        assert!(find(&locked.entries, "secret1").locked && find(&locked.entries, "secret2").locked);
        let privkey = find(&locked.entries, "privkey");
        assert!(!privkey.locked && privkey.algorithm == "RSA" && privkey.chain_length == 2);
        let trusted = find(&locked.entries, "trusted");
        let expected = x509::certificates_from_bytes(&fixture("bouncycastle/trustedCertData.cer")).unwrap().remove(0);
        assert_eq!(trusted.entry_type, "TrustedCertificate");
        assert_eq!(entry::chain_der(trusted).unwrap()[0], expected);

        let mut keys = HashMap::new();
        keys.insert("secret1".to_string(), "secretPwd1".to_string());
        keys.insert("SECRET2".to_string(), "secretPwd2".to_string());
        let open = decode(&bytes, HELLO, &keys).unwrap();
        let s1 = find(&open.entries, "secret1");
        assert_eq!((s1.algorithm.as_str(), s1.secret_key_hex.as_deref()), ("AES", Some("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")));
        assert_eq!(s1.key_password.as_deref(), Some("secretPwd1"));
        let s2 = find(&open.entries, "secret2");
        assert_eq!((s2.algorithm.as_str(), s2.secret_key_hex.as_deref()), ("DESede", Some("010102020404070708080B0B0D0D0E0E")));
    }

    #[test]
    fn legacy_scrypt_and_signed_stores_open() {
        let mut keys = HashMap::new();
        keys.insert("seckey".to_string(), HELLO.to_string());
        let plain = decode(&fixture("bouncycastle/legacyScryptKeyStore.bcfks"), HELLO, &none()).unwrap();
        let seckey = find(&plain.entries, "seckey");
        assert_eq!(seckey.secret_key_hex.as_deref(), Some("000102030405060708090A0B0C0D0E0F"));
        assert!(decode(&fixture("bouncycastle/legacyScryptKeyStore.bcfks"), "nope", &none()).unwrap_err().starts_with("wrong-password"));

        // Signed, and its contents encrypted with no password at all.
        let signed = decode(&fixture("bouncycastle/legacyScryptSignedKeyStore.bcfks"), "", &keys).unwrap();
        assert_eq!(find(&signed.entries, "seckey").secret_key_hex.as_deref(), Some("000102030405060708090A0B0C0D0E0F"));
        assert!(signed.notes.iter().any(|n| n.contains("signature")), "{:?}", signed.notes);
        let with_password = decode(&fixture("bouncycastle/legacyScryptSignedKeyStore.bcfks"), HELLO, &none()).unwrap();
        assert!(!find(&with_password.entries, "seckey").locked);

        // A flipped bit anywhere in the signed part is caught.
        let mut altered = fixture("bouncycastle/legacyScryptSignedKeyStore.bcfks");
        altered[200] ^= 1;
        assert!(decode(&altered, "", &keys).is_err());
    }

    #[test]
    fn the_sample_store_opens() {
        let store = decode(&fixture("sample.bcfks"), "changeit", &none()).unwrap();
        assert!(!store.entries.is_empty());
    }

    /// The proof that the writer is compatible: every password-protected Bouncy Castle store in
    /// the fixtures, read and written again with the salts, nonces and dates it had, is
    /// reproduced bit for bit, which covers the PBES2 encoding, AES-CCM, the key derivations and
    /// the MAC.
    #[test]
    fn real_bouncy_castle_files_are_reproduced_bit_for_bit() {
        for (file, password) in [
            ("bouncycastle/oldKeyStore.bcfks", HELLO),
            ("bouncycastle/oldKeyStoreNoPW.bcfks", ""),
            ("bouncycastle/kwpKeyStore.bcfks", HELLO),
            ("bouncycastle/legacyScryptKeyStore.bcfks", HELLO),
            ("sample.bcfks", "changeit"),
        ] {
            let original = fixture(file);
            let opened = read(&original, password).unwrap_or_else(|err| panic!("{file}: {err}"));
            let Integrity::Mac { mac_alg, kdf, .. } = &opened.integrity else { panic!("{file} is MAC-protected") };
            let rewritten = write_store(&opened.store, opened.encryption.as_ref(), mac_alg, &Kdf::parse(kdf).unwrap(), opened.legacy, password).unwrap();
            assert_eq!(rewritten, original, "{file}");
        }
    }

    /// The same for keys: sealed again with the parameters they had, the bytes are the ones
    /// Bouncy Castle wrote.
    #[test]
    fn sealed_entries_are_reproduced_bit_for_bit() {
        let mut checked = 0;
        for (file, password, extra) in [("bouncycastle/kwpKeyStore.bcfks", HELLO, vec!["secretPwd1", "secretPwd2"]), ("sample.bcfks", "changeit", vec![])] {
            let opened = read(&fixture(file), password).unwrap();
            for o in &opened.store.objects {
                let (sealed, purpose) = match o.kind {
                    PRIVATE_KEY => (parse_private_key_data(&o.data).unwrap().0, PRIVATE_KEY_ENCRYPTION),
                    SECRET_KEY => (o.data.clone(), SECRET_KEY_ENCRYPTION),
                    _ => continue,
                };
                let (alg, ciphertext) = parse_sealed(&sealed).unwrap();
                let params = pbes2_of(&alg).unwrap();
                let (plain, pw) = std::iter::once(password).chain(extra.iter().copied()).find_map(|pw| open_sealed(&alg, &ciphertext, pw, purpose).ok().map(|p| (p, pw))).unwrap();
                assert_eq!(sealed_der(&params, pw, purpose, &plain).unwrap(), sealed, "{file}: '{}'", o.alias);
                checked += 1;
            }
        }
        assert!(checked >= 4, "only {checked} sealed entries were checked");
    }

    #[test]
    fn written_stores_read_back_with_every_entry_kind() {
        let ca = crate::ops::generate_key_pair(&crate::ops::tests_support::input("ca", "ECDSA", true), None).unwrap();
        let mut rsa = crate::ops::generate_key_pair(&crate::ops::tests_support::input("web", "RSA", false), Some(&ca)).unwrap();
        rsa.key_password = Some("key-pass-1".into());
        let ed = crate::ops::generate_key_pair(&crate::ops::tests_support::input("signer", "Ed25519", false), None).unwrap();
        let trusted = entry::trusted_cert_entry("anchor", &entry::chain_der(&ca).unwrap()[0], None).unwrap();
        let aes = entry::secret_key_entry("aes", "AES", &[9u8; 32], None);
        let hmac = entry::secret_key_entry("mac", "HmacSHA256", &[7u8; 32], None);
        let all = vec![ca.clone(), rsa.clone(), ed.clone(), trusted, aes.clone(), hmac.clone()];
        let bytes = encode(&all, "store-pass-1").unwrap();
        assert!(looks_like(&bytes));
        assert!(decode(&bytes, "wrong", &none()).unwrap_err().starts_with("wrong-password"));

        let entries = decode(&bytes, "store-pass-1", &none()).unwrap().entries;
        assert_eq!(entries.len(), 6);
        assert_eq!(find(&entries, "ca").private_key_pem, ca.private_key_pem);
        assert_eq!(find(&entries, "signer").private_key_pem, ed.private_key_pem);
        assert_eq!(find(&entries, "aes").secret_key_hex, aes.secret_key_hex);
        assert_eq!(find(&entries, "mac").algorithm, "HmacSHA256");
        assert_eq!(find(&entries, "anchor").entry_type, "TrustedCertificate");
        let web = find(&entries, "web");
        assert!(web.locked && web.chain_length == 2);

        // The locked key goes back as the blob it was read as, and still opens with its password.
        let again = encode(&entries, "store-pass-1").unwrap();
        let mut keys = HashMap::new();
        keys.insert("web".to_string(), "key-pass-1".to_string());
        let web = find(&decode(&again, "store-pass-1", &keys).unwrap().entries, "web").clone();
        assert_eq!(web.private_key_pem, rsa.private_key_pem);
        assert_eq!(web.key_password.as_deref(), Some("key-pass-1"));

        assert!(encode(&[ca.clone(), ca], "pw",).is_err(), "duplicate aliases must be refused");
        let unnamed = entry::secret_key_entry("raw", "Secret", &[1u8; 16], None);
        assert!(encode(&[unnamed], "pw").unwrap_err().starts_with("unsupported:"));
    }

    #[test]
    fn secret_key_algorithms_map_both_ways() {
        for (name, bits) in [("AES", 256), ("DESede", 192), ("HmacSHA1", 160), ("HmacSHA512", 512), ("HmacSHA512/256", 256), ("SEED", 128), ("Camellia", 192), ("ARIA", 256)] {
            let oid = secret_algorithm_oid(name, bits).unwrap();
            assert_eq!(secret_algorithm_name(&oid), name, "{name}");
        }
        assert_eq!(secret_algorithm_oid("Camellia", 128).unwrap(), vec![1, 2, 392, 200011, 61, 1, 1, 1, 2]);
        assert_eq!(secret_algorithm_oid("ARIA", 192).unwrap(), vec![1, 2, 410, 200046, 1, 1, 7]);
    }

    #[test]
    fn hostile_files_are_errors_and_fail_fast() {
        let good = fixture("bouncycastle/oldKeyStore.bcfks");
        for cut in [0, 1, 4, 100, good.len() / 2, good.len() - 1] {
            assert!(decode(&good[..cut], HELLO, &none()).is_err(), "cut at {cut}");
            assert!(!looks_like(&good[..cut]) || cut == good.len(), "cut at {cut} still looks like a store");
        }
        // scrypt's N rewritten in place (same length) to a value that is not a power of two, and
        // to the largest two-byte cost: both are refused or bounded before any real work.
        let scrypt = fixture("bouncycastle/legacyScryptKeyStore.bcfks");
        let at = scrypt.windows(4).rposition(|w| w == [0x02, 0x02, 0x04, 0x00]).expect("the MAC's scrypt N");
        let started = std::time::Instant::now();
        for n in [[0x7F, 0xFF], [0x00, 0x03]] {
            let mut m = scrypt.clone();
            m[at + 2..at + 4].copy_from_slice(&n);
            assert!(decode(&m, HELLO, &none()).unwrap_err().starts_with("invalid:"), "N = {n:?}");
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        for flip in [10, 200, good.len() - 30] {
            let mut m = good.clone();
            m[flip] ^= 0x01;
            assert!(decode(&m, HELLO, &none()).is_err(), "flip at {flip}");
        }
    }
}
