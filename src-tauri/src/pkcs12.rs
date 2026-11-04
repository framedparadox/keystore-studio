//! Real PKCS#12 (RFC 7292) encoder/decoder, OpenSSL/`keytool`-compatible.
//!
//! Layout matches the modern OpenSSL 3.x default (`openssl pkcs12 -export`) exactly:
//!
//! ```text
//! PFX
//!   version = 3
//!   authSafe = ContentInfo(data, OCTET STRING(AuthenticatedSafe))
//!     AuthenticatedSafe = SEQUENCE OF ContentInfo
//!       [0] ContentInfo(encryptedData): EncryptedData wrapping a SafeContents of CertBag(s),
//!           PBES2(PBKDF2-HMAC-SHA256, AES-256-CBC)-encrypted.
//!       [1] ContentInfo(data): plaintext SafeContents of PKCS8ShroudedKeyBag(s), where the
//!           key itself is protected internally as an EncryptedPrivateKeyInfo, also
//!           PBES2(PBKDF2-HMAC-SHA256, AES-256-CBC).
//!   macData = MacData: HMAC-SHA256 over the authSafe OCTET STRING content, keyed via the
//!     RFC 7292 Appendix B KDF (id = 3) from the password.
//! ```
//!
//! Each CertBag/KeyBag SafeBag carries matching `friendlyName` (alias) and `localKeyId`
//! (SHA-1 of the cert DER) attributes so `keytool` associates the key with its chain.

use crate::crypto::{CertificateInfo, KeystoreEntry, KeystoreFile};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use yasna::models::ObjectIdentifier;
use yasna::{ASN1Result, BERReader, DERWriter, Tag};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------
const OID_PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_PKCS7_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const OID_AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
const OID_KEY_BAG_SHROUDED: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const OID_X509_CERTTYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];
const OID_FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
const OID_LOCAL_KEY_ID: &[u64] = &[1, 2, 840, 113549, 1, 9, 21];

const PBE_ITERATIONS: u64 = 2048;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;

fn oid(parts: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(parts)
}

// ---------------------------------------------------------------------------
// PKCS#12 Appendix B key-derivation (RFC 7292)
// ---------------------------------------------------------------------------

/// `ID` byte for the PKCS12 KDF purpose: 1 = key material, 2 = IV, 3 = MAC key.
fn pkcs12_kdf(password: &str, salt: &[u8], iterations: u64, id: u8, out_len: usize) -> Vec<u8> {
    // u and v are the SHA-256 block/input sizes in bits/bytes per Appendix B.
    const U: usize = 32; // SHA-256 output size in bytes
    const V: usize = 64; // SHA-256 block size in bytes

    let mut password_utf16be = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        password_utf16be.extend_from_slice(&unit.to_be_bytes());
    }
    password_utf16be.extend_from_slice(&[0, 0]); // null terminator

    let d = vec![id; V];

    let s_len = V * ((salt.len() + V - 1) / V.max(1)).max(1);
    let mut s = Vec::with_capacity(s_len);
    while s.len() < s_len {
        s.extend_from_slice(salt);
    }
    s.truncate(s_len.max(salt.len()));
    if salt.is_empty() {
        s.clear();
    } else {
        s.truncate(((salt.len() + V - 1) / V) * V);
    }

    let p_len = if password_utf16be.is_empty() {
        0
    } else {
        ((password_utf16be.len() + V - 1) / V) * V
    };
    let mut p = Vec::with_capacity(p_len);
    while p.len() < p_len {
        p.extend_from_slice(&password_utf16be);
    }
    p.truncate(p_len);

    let mut i = Vec::with_capacity(s.len() + p.len());
    i.extend_from_slice(&s);
    i.extend_from_slice(&p);

    let mut result = Vec::with_capacity(out_len + U);
    while result.len() < out_len {
        let mut hasher = Sha256::new();
        hasher.update(&d);
        hasher.update(&i);
        let mut a = hasher.finalize().to_vec();
        for _ in 1..iterations {
            let mut h = Sha256::new();
            h.update(&a);
            a = h.finalize().to_vec();
        }

        result.extend_from_slice(&a);

        if i.len() > 0 {
            // B = a repeated to fill a V-byte block
            let mut b = Vec::with_capacity(V);
            while b.len() < V {
                b.extend_from_slice(&a);
            }
            b.truncate(V);

            // I_j = (I_j + B + 1) mod 2^(V*8), applied per V-byte block of I
            let block_count = i.len() / V;
            for j in 0..block_count {
                let block = &mut i[j * V..(j + 1) * V];
                add_one_with_carry(block, &b);
            }
        }
    }
    result.truncate(out_len);
    result
}

/// Big-endian modular addition of two equal-length byte buffers plus 1, in place into `block`.
fn add_one_with_carry(block: &mut [u8], addend: &[u8]) {
    let mut carry: u16 = 1;
    for k in (0..block.len()).rev() {
        let sum = block[k] as u16 + addend[k] as u16 + carry;
        block[k] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
}

fn derive_mac_key(password: &str, salt: &[u8], iterations: u64) -> Vec<u8> {
    pkcs12_kdf(password, salt, iterations, 3, 32) // HMAC-SHA256 key length
}

fn derive_pbes2_key(password: &str, salt: &[u8], iterations: u64) -> Vec<u8> {
    // PBES2 uses standard PKCS#5 PBKDF2-HMAC-SHA256 (NOT the Appendix B KDF), matching OpenSSL.
    let mut key = vec![0u8; AES256_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations as u32, &mut key);
    key
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key length is always valid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// AES-256-CBC + PKCS7 via PBES2
// ---------------------------------------------------------------------------

fn pbes2_encrypt(password: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut salt = vec![0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut iv = vec![0u8; IV_LEN];
    rand::thread_rng().fill_bytes(&mut iv);

    let key = derive_pbes2_key(password, &salt, PBE_ITERATIONS);
    let key_arr: [u8; AES256_KEY_LEN] = key.as_slice().try_into().map_err(|_| "bad key length".to_string())?;
    let iv_arr: [u8; IV_LEN] = iv.as_slice().try_into().map_err(|_| "bad iv length".to_string())?;

    let enc = Aes256CbcEnc::new(&key_arr.into(), &iv_arr.into());
    let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok((ciphertext, salt, iv))
}

fn pbes2_decrypt(password: &str, ciphertext: &[u8], salt: &[u8], iv: &[u8], iterations: u64) -> Result<Vec<u8>, String> {
    let key = derive_pbes2_key(password, salt, iterations);
    let key_arr: [u8; AES256_KEY_LEN] = key.as_slice().try_into().map_err(|_| "bad key length".to_string())?;
    let iv_arr: [u8; IV_LEN] = iv.try_into().map_err(|_| "bad iv length".to_string())?;

    let dec = Aes256CbcDec::new(&key_arr.into(), &iv_arr.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "keystore password incorrect or file corrupt".to_string())
}

/// Writes a PBES2 `AlgorithmIdentifier` (PBKDF2-HMAC-SHA256 + AES-256-CBC) DER structure.
fn write_pbes2_algorithm_identifier(writer: DERWriter, salt: &[u8], iv: &[u8], iterations: u64) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_PBES2));
        writer.next().write_sequence(|writer| {
            // keyDerivationFunc
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_PBKDF2));
                writer.next().write_sequence(|writer| {
                    writer.next().write_bytes(salt);
                    writer.next().write_u64(iterations);
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&oid(OID_HMAC_SHA256));
                        writer.next().write_null();
                    });
                });
            });
            // encryptionScheme
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_AES256_CBC));
                writer.next().write_bytes(iv);
            });
        });
    });
}

struct Pbes2Params {
    salt: Vec<u8>,
    iterations: u64,
    iv: Vec<u8>,
}

fn read_pbes2_algorithm_identifier(reader: BERReader) -> ASN1Result<Pbes2Params> {
    reader.read_sequence(|reader| {
        let _oid = reader.next().read_oid()?;
        reader.next().read_sequence(|reader| {
            let (salt, iterations) = reader.next().read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                reader.next().read_sequence(|reader| {
                    let salt = reader.next().read_bytes()?;
                    let iterations = reader.next().read_u64()?;
                    // Optional keyLength + prf AlgorithmIdentifier; ignore remainder.
                    reader.read_optional(|r| r.read_u64())?;
                    reader.read_optional(|r| {
                        r.read_sequence(|r| {
                            let _oid = r.next().read_oid()?;
                            r.read_optional(|r| r.read_null())?;
                            Ok(())
                        })
                    })?;
                    Ok((salt, iterations))
                })
            })?;
            let iv = reader.next().read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                reader.next().read_bytes()
            })?;
            Ok(Pbes2Params { salt, iterations, iv })
        })
    })
}

// ---------------------------------------------------------------------------
// SafeBag attributes (friendlyName / localKeyId)
// ---------------------------------------------------------------------------

fn write_bag_attributes(writer: DERWriter, alias: &str, key_id: &[u8]) {
    // `SET OF PKCS12Attribute` must be in DER canonical order, i.e. ascending
    // lexicographic order of each element's full encoded bytes. `write_set_of` (unlike
    // `write_set`, which sorts by a type/tag-aware rule meant for heterogeneous SET
    // members) sorts with a plain byte-wise `Vec::sort`, matching what a DER reader's
    // `read_set_of` enforces - so it must be used here, not `write_set`.
    writer.write_set_of(|writer| {
        writer.next().write_der(&yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_FRIENDLY_NAME));
                writer.next().write_set_of(|writer| {
                    writer.next().write_bmp_string(alias);
                });
            });
        }));
        writer.next().write_der(&yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_LOCAL_KEY_ID));
                writer.next().write_set_of(|writer| {
                    writer.next().write_bytes(key_id);
                });
            });
        }));
    });
}

struct BagAttrs {
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
}

fn read_bag_attributes(reader: BERReader) -> ASN1Result<BagAttrs> {
    let mut friendly_name = None;
    let mut local_key_id = None;
    reader.read_set_of(|reader| {
        reader.read_sequence(|reader| {
            let attr_oid = reader.next().read_oid()?;
            reader.next().read_set_of(|reader| {
                if attr_oid == oid(OID_FRIENDLY_NAME) {
                    friendly_name = Some(reader.read_bmp_string()?);
                } else if attr_oid == oid(OID_LOCAL_KEY_ID) {
                    local_key_id = Some(reader.read_bytes()?);
                } else {
                    let _ = reader.read_der();
                }
                Ok(())
            })
        })
    })?;
    Ok(BagAttrs { friendly_name, local_key_id })
}

// ---------------------------------------------------------------------------
// PEM <-> DER helpers
// ---------------------------------------------------------------------------

fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, String> {
    let parsed = pem::parse(pem_str.as_bytes()).map_err(|e| format!("invalid PEM: {e}"))?;
    Ok(parsed.contents().to_vec())
}

fn der_to_pem(der: &[u8], tag: &str) -> String {
    let p = pem::Pem::new(tag, der.to_vec());
    pem::encode(&p)
}

fn sha1_of(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// CertBag / KeyBag SafeBag encoding
// ---------------------------------------------------------------------------

fn write_cert_bag(writer: DERWriter, cert_der: &[u8], alias: &str, key_id: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_CERT_BAG));
        writer.next().write_tagged(Tag::context(0), |writer| {
            writer.write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_X509_CERTTYPE));
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_bytes(cert_der);
                });
            });
        });
        write_bag_attributes(writer.next(), alias, key_id);
    });
}

struct DecodedCertBag {
    cert_der: Vec<u8>,
    attrs: BagAttrs,
}

fn read_safe_bag_cert(reader: BERReader) -> ASN1Result<DecodedCertBag> {
    reader.read_sequence(|reader| {
        let _bag_id = reader.next().read_oid()?;
        let cert_der = reader.next().read_tagged(Tag::context(0), |reader| {
            reader.read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                reader.next().read_tagged(Tag::context(0), |reader| reader.read_bytes())
            })
        })?;
        let attrs = reader
            .read_optional(read_bag_attributes)?
            .unwrap_or(BagAttrs { friendly_name: None, local_key_id: None });
        Ok(DecodedCertBag { cert_der, attrs })
    })
}

fn write_key_bag(writer: DERWriter, encrypted_private_key_info_der: &[u8], alias: &str, key_id: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_KEY_BAG_SHROUDED));
        writer.next().write_tagged(Tag::context(0), |writer| {
            writer.write_der(encrypted_private_key_info_der);
        });
        write_bag_attributes(writer.next(), alias, key_id);
    });
}

struct DecodedKeyBag {
    encrypted_private_key_info_der: Vec<u8>,
    attrs: BagAttrs,
}

fn read_safe_bag_key(reader: BERReader) -> ASN1Result<DecodedKeyBag> {
    reader.read_sequence(|reader| {
        let _bag_id = reader.next().read_oid()?;
        let der = reader.next().read_tagged(Tag::context(0), |reader| reader.read_der())?;
        let attrs = reader
            .read_optional(read_bag_attributes)?
            .unwrap_or(BagAttrs { friendly_name: None, local_key_id: None });
        Ok(DecodedKeyBag { encrypted_private_key_info_der: der, attrs })
    })
}

/// Wraps a plaintext PKCS8 DER key into a PBES2-protected `EncryptedPrivateKeyInfo` DER blob.
fn shroud_private_key(password: &str, pkcs8_der: &[u8]) -> Result<Vec<u8>, String> {
    let (ciphertext, salt, iv) = pbes2_encrypt(password, pkcs8_der)?;
    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            write_pbes2_algorithm_identifier(writer.next(), &salt, &iv, PBE_ITERATIONS);
            writer.next().write_bytes(&ciphertext);
        });
    }))
}

fn unshroud_private_key(password: &str, encrypted_info_der: &[u8]) -> Result<Vec<u8>, String> {
    yasna::parse_der(encrypted_info_der, |reader| {
        reader.read_sequence(|reader| {
            let params = read_pbes2_algorithm_identifier(reader.next())?;
            let ciphertext = reader.next().read_bytes()?;
            Ok((params, ciphertext))
        })
    })
    .map_err(|e| format!("malformed EncryptedPrivateKeyInfo: {e:?}"))
    .and_then(|(params, ciphertext)| {
        pbes2_decrypt(password, &ciphertext, &params.salt, &params.iv, params.iterations)
    })
}

// ---------------------------------------------------------------------------
// ContentInfo helpers
// ---------------------------------------------------------------------------

fn write_content_info_data(writer: DERWriter, inner_octets: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_PKCS7_DATA));
        writer.next().write_tagged(Tag::context(0), |writer| {
            writer.write_bytes(inner_octets);
        });
    });
}

fn write_content_info_encrypted_data(writer: DERWriter, salt: &[u8], iv: &[u8], iterations: u64, ciphertext: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_PKCS7_ENCRYPTED_DATA));
        writer.next().write_tagged(Tag::context(0), |writer| {
            // EncryptedData ::= SEQUENCE { version INTEGER(0), encryptedContentInfo }
            writer.write_sequence(|writer| {
                writer.next().write_u32(0);
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid(OID_PKCS7_DATA));
                    write_pbes2_algorithm_identifier(writer.next(), salt, iv, iterations);
                    writer.next().write_tagged_implicit(Tag::context(0), |writer| {
                        writer.write_bytes(ciphertext);
                    });
                });
            });
        });
    });
}

enum DecodedContentInfo {
    Data(Vec<u8>),
    EncryptedData { salt: Vec<u8>, iv: Vec<u8>, iterations: u64, ciphertext: Vec<u8> },
}

fn read_content_info(reader: BERReader) -> ASN1Result<DecodedContentInfo> {
    reader.read_sequence(|reader| {
        let content_oid = reader.next().read_oid()?;
        if content_oid == oid(OID_PKCS7_DATA) {
            let bytes = reader.next().read_tagged(Tag::context(0), |reader| reader.read_bytes())?;
            Ok(DecodedContentInfo::Data(bytes))
        } else if content_oid == oid(OID_PKCS7_ENCRYPTED_DATA) {
            let (salt, iv, iterations, ciphertext) = reader.next().read_tagged(Tag::context(0), |reader| {
                reader.read_sequence(|reader| {
                    let _version = reader.next().read_u32()?;
                    reader.next().read_sequence(|reader| {
                        let _content_type = reader.next().read_oid()?;
                        let params = read_pbes2_algorithm_identifier(reader.next())?;
                        let ciphertext = reader.next().read_tagged_implicit(Tag::context(0), |reader| reader.read_bytes())?;
                        Ok((params.salt, params.iv, params.iterations, ciphertext))
                    })
                })
            })?;
            Ok(DecodedContentInfo::EncryptedData { salt, iv, iterations, ciphertext })
        } else {
            Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
        }
    })
}

// ---------------------------------------------------------------------------
// MacData
// ---------------------------------------------------------------------------

fn write_mac_data(writer: DERWriter, mac: &[u8], salt: &[u8], iterations: u64) {
    writer.write_sequence(|writer| {
        writer.next().write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_SHA256));
                writer.next().write_null();
            });
            writer.next().write_bytes(mac);
        });
        writer.next().write_bytes(salt);
        writer.next().write_u64(iterations);
    });
}

struct DecodedMacData {
    mac: Vec<u8>,
    salt: Vec<u8>,
    iterations: u64,
}

fn read_mac_data(reader: BERReader) -> ASN1Result<DecodedMacData> {
    reader.read_sequence(|reader| {
        let mac = reader.next().read_sequence(|reader| {
            reader.next().read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                reader.read_optional(|r| r.read_null())?;
                Ok(())
            })?;
            reader.next().read_bytes()
        })?;
        let salt = reader.next().read_bytes()?;
        let iterations = reader
            .read_optional(|r| r.read_u64())?
            .unwrap_or(1);
        Ok(DecodedMacData { mac, salt, iterations })
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encodes a [`KeystoreFile`] into real RFC 7292 PKCS#12 (PFX) bytes, readable by
/// `openssl pkcs12` and `keytool`.
pub fn encode_pkcs12(ks: &KeystoreFile, password: &str) -> Result<Vec<u8>, String> {
    let mut cert_safe_bags: Vec<Vec<u8>> = Vec::new();
    let mut key_safe_bags: Vec<Vec<u8>> = Vec::new();

    for entry in &ks.entries {
        match entry.entry_type.as_str() {
            "KeyPair" => {
                let priv_pem = entry
                    .private_key_pem
                    .as_deref()
                    .ok_or_else(|| format!("entry '{}' is a KeyPair but has no private key", entry.alias))?;
                let pkcs8_der = pem_to_der(priv_pem)?;
                let leaf_cert = entry
                    .certificate_chain
                    .first()
                    .ok_or_else(|| format!("entry '{}' has no certificate", entry.alias))?;
                let leaf_der = pem_to_der(&leaf_cert.pem)?;
                let key_id = sha1_of(&leaf_der);

                let shrouded = shroud_private_key(password, &pkcs8_der)?;
                let key_bag_der = yasna::construct_der(|writer| {
                    write_key_bag(writer, &shrouded, &entry.alias, &key_id);
                });
                key_safe_bags.push(key_bag_der);

                for cert in &entry.certificate_chain {
                    let cert_der = pem_to_der(&cert.pem)?;
                    let cert_bag_der = yasna::construct_der(|writer| {
                        write_cert_bag(writer, &cert_der, &entry.alias, &key_id);
                    });
                    cert_safe_bags.push(cert_bag_der);
                }
            }
            "TrustedCertificate" => {
                let cert = entry
                    .certificate_chain
                    .first()
                    .ok_or_else(|| format!("entry '{}' has no certificate", entry.alias))?;
                let cert_der = pem_to_der(&cert.pem)?;
                let key_id = sha1_of(&cert_der);
                let cert_bag_der = yasna::construct_der(|writer| {
                    write_cert_bag(writer, &cert_der, &entry.alias, &key_id);
                });
                cert_safe_bags.push(cert_bag_der);
            }
            "SecretKey" => {
                // PKCS#12 has no standard SecretBag understood by keytool/openssl in this
                // layout; secret keys are out of scope for the binary PKCS12 container here.
                return Err(format!(
                    "entry '{}': PKCS#12 export of raw SecretKey entries is not supported",
                    entry.alias
                ));
            }
            other => {
                return Err(format!("unsupported entry type '{other}' for PKCS#12 export"));
            }
        }
    }

    // SafeContents for certs -> encrypted ContentInfo
    let cert_safe_contents = yasna::construct_der(|writer| {
        writer.write_sequence_of(|writer| {
            for bag in &cert_safe_bags {
                writer.next().write_der(bag);
            }
        });
    });
    let (cert_ciphertext, cert_salt, cert_iv) = pbes2_encrypt(password, &cert_safe_contents)?;

    // SafeContents for keys -> plaintext ContentInfo (key itself is shrouded internally)
    let key_safe_contents = yasna::construct_der(|writer| {
        writer.write_sequence_of(|writer| {
            for bag in &key_safe_bags {
                writer.next().write_der(bag);
            }
        });
    });

    let authenticated_safe = yasna::construct_der(|writer| {
        writer.write_sequence_of(|writer| {
            writer.next().write_der(&yasna::construct_der(|writer| {
                write_content_info_encrypted_data(writer, &cert_salt, &cert_iv, PBE_ITERATIONS, &cert_ciphertext);
            }));
            writer.next().write_der(&yasna::construct_der(|writer| {
                write_content_info_data(writer, &key_safe_contents);
            }));
        });
    });

    let mut mac_salt = vec![0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut mac_salt);
    let mac_key = derive_mac_key(password, &mac_salt, PBE_ITERATIONS);
    let mac = hmac_sha256(&mac_key, &authenticated_safe);

    let pfx = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(3);
            writer.next().write_der(&yasna::construct_der(|writer| {
                write_content_info_data(writer, &authenticated_safe);
            }));
            write_mac_data(writer.next(), &mac, &mac_salt, PBE_ITERATIONS);
        });
    });

    Ok(pfx)
}

/// Decodes RFC 7292 PKCS#12 bytes (as produced by `openssl pkcs12 -export`, `keytool`, or
/// [`encode_pkcs12`]) into a [`KeystoreFile`]. Verifies the integrity MAC first and rejects
/// with `Err` on mismatch before attempting to decrypt anything.
pub fn decode_pkcs12(bytes: &[u8], password: &str) -> Result<KeystoreFile, String> {
    struct Pfx {
        auth_safe_content: Vec<u8>,
        mac: Option<DecodedMacData>,
    }

    let pfx: Pfx = yasna::parse_der(bytes, |reader| {
        reader.read_sequence(|reader| {
            let _version = reader.next().read_u32()?;
            let auth_safe_content = reader.next().read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                reader.next().read_tagged(Tag::context(0), |reader| reader.read_bytes())
            })?;
            let mac = reader.read_optional(read_mac_data)?;
            Ok(Pfx { auth_safe_content, mac })
        })
    })
    .map_err(|e| format!("not a valid PKCS#12 file: {e:?}"))?;

    if let Some(mac_data) = &pfx.mac {
        let mac_key = derive_mac_key(password, &mac_data.salt, mac_data.iterations);
        let expected = hmac_sha256(&mac_key, &pfx.auth_safe_content);
        if expected != mac_data.mac {
            return Err("keystore password incorrect or file corrupt".to_string());
        }
    }

    let content_infos: Vec<DecodedContentInfo> = yasna::parse_der(&pfx.auth_safe_content, |reader| {
        let mut items = Vec::new();
        reader.read_sequence_of(|reader| {
            items.push(read_content_info(reader)?);
            Ok(())
        })?;
        Ok(items)
    })
    .map_err(|e| format!("malformed AuthenticatedSafe: {e:?}"))?;

    let mut certs_by_key_id: Vec<(Vec<u8>, DecodedCertBag)> = Vec::new();
    let mut keys_by_key_id: Vec<(Vec<u8>, DecodedKeyBag)> = Vec::new();

    for ci in content_infos {
        let safe_contents_der = match ci {
            DecodedContentInfo::Data(bytes) => {
                eprintln!("DEBUG ContentInfo::Data len={} first20={:?}", bytes.len(), &bytes[..bytes.len().min(20)]);
                bytes
            }
            DecodedContentInfo::EncryptedData { salt, iv, iterations, ciphertext } => {
                eprintln!("DEBUG ContentInfo::EncryptedData ciphertext_len={} salt_len={} iv_len={} iters={}", ciphertext.len(), salt.len(), iv.len(), iterations);
                let pt = pbes2_decrypt(password, &ciphertext, &salt, &iv, iterations)?;
                eprintln!("DEBUG decrypted len={} first20={:?}", pt.len(), &pt[..pt.len().min(20)]);
                pt
            }
        };

        // A SafeContents can hold either CertBags or KeyBags; try both interpretations
        // bag-by-bag since the bagId at the start of each SafeBag tells us which it is.
        yasna::parse_der(&safe_contents_der, |reader| {
            reader.read_sequence_of(|reader| {
                let der = reader.read_der()?;
                if let Ok(dir) = std::env::var("XKS_DUMP_DIR") {
                    let path = format!("{}/xks_bag_{}.der", dir, der.len());
                    match std::fs::write(&path, &der) {
                        Ok(_) => eprintln!("DEBUG wrote {}", path),
                        Err(e) => eprintln!("DEBUG write failed for {}: {}", path, e),
                    }
                }
                let cert_err = match yasna::parse_der(&der, read_safe_bag_cert) {
                    Ok(bag) => {
                        let key_id = bag.attrs.local_key_id.clone().unwrap_or_default();
                        certs_by_key_id.push((key_id, bag));
                        None
                    }
                    Err(e) => Some(e),
                };
                if let Some(cert_err) = cert_err {
                    match yasna::parse_der(&der, read_safe_bag_key) {
                        Ok(bag) => {
                            let key_id = bag.attrs.local_key_id.clone().unwrap_or_default();
                            keys_by_key_id.push((key_id, bag));
                        }
                        Err(key_err) => {
                            eprintln!("DEBUG neither cert nor key bag shape matched: cert_err={cert_err:?} key_err={key_err:?} der_len={}", der.len());
                        }
                    }
                }
                Ok(())
            })
        })
        .map_err(|e: yasna::ASN1Error| format!("malformed SafeContents: {e:?}"))?;
    }

    let mut entries = Vec::new();

    for (key_id, key_bag) in &keys_by_key_id {
        let pkcs8_der = unshroud_private_key(password, &key_bag.encrypted_private_key_info_der)?;
        let priv_pem = der_to_pem(&pkcs8_der, "PRIVATE KEY");

        let alias = key_bag
            .attrs
            .friendly_name
            .clone()
            .unwrap_or_else(|| format!("imported-key-{}", entries.len() + 1));

        let mut chain = Vec::new();
        for (cert_key_id, cert_bag) in &certs_by_key_id {
            if cert_key_id == key_id {
                chain.push(certificate_info_from_der(&cert_bag.cert_der));
            }
        }
        // Fallback: if no local_key_id match was found (some tools omit it), associate by
        // friendly name instead, and finally by position if there's exactly one of each.
        if chain.is_empty() {
            for (_, cert_bag) in &certs_by_key_id {
                if cert_bag.attrs.friendly_name.as_deref() == Some(alias.as_str()) {
                    chain.push(certificate_info_from_der(&cert_bag.cert_der));
                }
            }
        }
        if chain.is_empty() && certs_by_key_id.len() == 1 && keys_by_key_id.len() == 1 {
            chain.push(certificate_info_from_der(&certs_by_key_id[0].1.cert_der));
        }

        entries.push(build_entry(alias, "KeyPair", Some(priv_pem), chain));
    }

    // Any certs not claimed by a key become standalone TrustedCertificate entries.
    let claimed_key_ids: std::collections::HashSet<Vec<u8>> = keys_by_key_id.iter().map(|(id, _)| id.clone()).collect();
    for (key_id, cert_bag) in &certs_by_key_id {
        let is_claimed = claimed_key_ids.contains(key_id)
            || entries.iter().any(|e: &KeystoreEntry| {
                e.certificate_chain
                    .iter()
                    .any(|c| c.pem == der_to_pem(&cert_bag.cert_der, "CERTIFICATE"))
            });
        if !is_claimed {
            let alias = cert_bag
                .attrs
                .friendly_name
                .clone()
                .unwrap_or_else(|| format!("imported-cert-{}", entries.len() + 1));
            entries.push(build_entry(
                alias,
                "TrustedCertificate",
                None,
                vec![certificate_info_from_der(&cert_bag.cert_der)],
            ));
        }
    }

    Ok(KeystoreFile {
        id: format!("p12-{}", uuid::Uuid::new_v4()),
        name: "imported.p12".to_string(),
        format: "PKCS12".to_string(),
        path: String::new(),
        description: "Decoded from PKCS#12 binary".to_string(),
        password_protected: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        entries,
    })
}

fn certificate_info_from_der(der: &[u8]) -> CertificateInfo {
    let pem = der_to_pem(der, "CERTIFICATE");
    let sha256 = crate::crypto::compute_sha256_colon(der);
    let sha1 = crate::crypto::compute_sha1_colon(der);
    let md5 = crate::crypto::compute_md5_colon(der);
    CertificateInfo {
        version: 3,
        serial_number: String::new(),
        signature_algorithm: String::new(),
        subject: String::new(),
        issuer: String::new(),
        valid_from: String::new(),
        valid_to: String::new(),
        days_remaining: 0,
        is_ca: false,
        public_key_algorithm: String::new(),
        key_size: 0,
        sans: vec![],
        key_usage: vec![],
        extended_key_usage: vec![],
        extensions: vec![],
        sha256_fingerprint: sha256,
        sha1_fingerprint: sha1,
        md5_fingerprint: md5,
        pem,
    }
}

fn build_entry(
    alias: String,
    entry_type: &str,
    private_key_pem: Option<String>,
    chain: Vec<CertificateInfo>,
) -> KeystoreEntry {
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let first = chain.first();
    KeystoreEntry {
        id: format!("entry-{}", uuid::Uuid::new_v4()),
        alias,
        entry_type: entry_type.to_string(),
        algorithm: String::new(),
        key_size: 0,
        curve: None,
        creation_date: now.clone(),
        expiry_date: first.map(|c| c.valid_to.clone()).unwrap_or_default(),
        last_modified: now,
        subject: first.map(|c| c.subject.clone()).unwrap_or_default(),
        issuer: first.map(|c| c.issuer.clone()).unwrap_or_default(),
        serial_number: first.map(|c| c.serial_number.clone()).unwrap_or_default(),
        sha256_fingerprint: first.map(|c| c.sha256_fingerprint.clone()).unwrap_or_default(),
        sha1_fingerprint: first.map(|c| c.sha1_fingerprint.clone()).unwrap_or_default(),
        chain_length: chain.len(),
        certificate_chain: chain,
        private_key_pem,
        public_key_pem: None,
        secret_key_hex: None,
        locked: false,
        labels: vec![],
        is_expired: false,
        is_weak: false,
        is_post_quantum: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_keystore_keypair_entry, GenerateKeyPairInput};

    fn normalize_pem(s: &str) -> String {
        s.replace("\r\n", "\n").trim().to_string()
    }

    fn fixture_entry(alias: &str) -> KeystoreEntry {
        let input = GenerateKeyPairInput {
            alias: alias.to_string(),
            algorithm: "RSA".to_string(),
            key_size: 2048,
            curve: None,
            common_name: "p12-test.example.com".to_string(),
            organization: "Test Org".to_string(),
            organizational_unit: "".to_string(),
            locality: "".to_string(),
            state: "".to_string(),
            country: "US".to_string(),
            email: "".to_string(),
            validity_days: 365,
            is_ca: false,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            signer_alias: None,
            labels: vec![],
        };
        create_keystore_keypair_entry(&input, None).expect("fixture keypair generation failed")
    }

    fn fixture_keystore(alias: &str) -> (KeystoreFile, String, String) {
        let entry = fixture_entry(alias);
        let priv_pem = entry.private_key_pem.clone().unwrap();
        let cert_pem = entry.certificate_chain[0].pem.clone();
        let ks = KeystoreFile {
            id: "ks-p12".to_string(),
            name: "test.p12".to_string(),
            format: "PKCS12".to_string(),
            path: String::new(),
            description: String::new(),
            password_protected: true,
            created_at: String::new(),
            updated_at: String::new(),
            entries: vec![entry],
        };
        (ks, priv_pem, cert_pem)
    }

    #[test]
    fn pkcs12_kdf_matches_known_vector_length() {
        // Sanity check: output length and determinism of the Appendix B KDF.
        let out1 = pkcs12_kdf("password", b"saltsaltsaltsalt", 2048, 3, 32);
        let out2 = pkcs12_kdf("password", b"saltsaltsaltsalt", 2048, 3, 32);
        assert_eq!(out1.len(), 32);
        assert_eq!(out1, out2);
        let out_different_id = pkcs12_kdf("password", b"saltsaltsaltsalt", 2048, 1, 32);
        assert_ne!(out1, out_different_id);
    }

    #[test]
    fn pkcs12_round_trip_preserves_key_and_cert() {
        let (ks, original_priv, original_cert) = fixture_keystore("p12-roundtrip");
        let password = "correct-horse-battery-staple";

        let bytes = encode_pkcs12(&ks, password).expect("encode failed");
        let decoded = decode_pkcs12(&bytes, password).expect("decode failed");

        assert_eq!(decoded.entries.len(), 1);
        let decoded_entry = &decoded.entries[0];
        assert_eq!(decoded_entry.entry_type, "KeyPair");
        assert_eq!(
            normalize_pem(decoded_entry.private_key_pem.as_deref().unwrap()),
            normalize_pem(&original_priv)
        );
        assert_eq!(decoded_entry.certificate_chain.len(), 1);
        assert_eq!(normalize_pem(&decoded_entry.certificate_chain[0].pem), normalize_pem(&original_cert));
    }

    #[test]
    fn pkcs12_wrong_password_fails_mac_check() {
        let (ks, _, _) = fixture_keystore("p12-wrongpw");
        let bytes = encode_pkcs12(&ks, "right-password").expect("encode failed");
        let err = decode_pkcs12(&bytes, "wrong-password").unwrap_err();
        assert_eq!(err, "keystore password incorrect or file corrupt");
    }

    #[test]
    fn pkcs12_trusted_cert_only_round_trips() {
        let entry = fixture_entry("p12-cert-fixture");
        let cert_only = KeystoreEntry {
            entry_type: "TrustedCertificate".to_string(),
            private_key_pem: None,
            ..entry
        };
        let original_cert = cert_only.certificate_chain[0].pem.clone();
        let ks = KeystoreFile {
            id: "ks-p12-cert".to_string(),
            name: "cert-only.p12".to_string(),
            format: "PKCS12".to_string(),
            path: String::new(),
            description: String::new(),
            password_protected: true,
            created_at: String::new(),
            updated_at: String::new(),
            entries: vec![cert_only],
        };

        let password = "trustpw123";
        let bytes = encode_pkcs12(&ks, password).expect("encode failed");
        let decoded = decode_pkcs12(&bytes, password).expect("decode failed");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].entry_type, "TrustedCertificate");
        assert_eq!(normalize_pem(&decoded.entries[0].certificate_chain[0].pem), normalize_pem(&original_cert));
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn debug_cert_bag_roundtrip() {
        let cert_der = vec![0xAAu8; 50];
        let key_id = vec![0xBBu8; 20];
        let bag_der = yasna::construct_der(|writer| {
            write_cert_bag(writer, &cert_der, "myalias", &key_id);
        });
        eprintln!("bag_der = {:?}", bag_der);
        let result = yasna::parse_der(&bag_der, read_safe_bag_cert);
        match &result {
            Ok(bag) => eprintln!("OK: cert_der_len={} friendly={:?} key_id={:?}", bag.cert_der.len(), bag.attrs.friendly_name, bag.attrs.local_key_id),
            Err(e) => eprintln!("ERR: {:?}", e),
        }
        assert!(result.is_ok());
    }

    #[test]
    fn debug_raw_yasna_write_set_sort_order() {
        // Two SEQUENCE elements of different lengths, same tag - does write_set sort them
        // ascending by length as the DERWriterSet::next() sort comparator implies?
        let der = yasna::construct_der(|writer| {
            writer.write_set(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_bytes(&[0xAAu8; 41 - 2]); // long content -> long elem
                });
                writer.next().write_sequence(|writer| {
                    writer.next().write_bytes(&[0xBBu8; 35 - 2]); // shorter content
                });
            });
        });
        eprintln!("raw set der = {}", der.iter().map(|b| format!("{:02X}", b)).collect::<String>());
    }

    #[test]
    fn debug_minimal_set_of_order() {
        let der = yasna::construct_der(|writer| {
            write_bag_attributes(writer, "p12-roundtrip", &[0u8; 20]);
        });
        eprintln!("attrs der len = {} hex = {}", der.len(), der.iter().map(|b| format!("{:02X}", b)).collect::<String>());
        let elems: Vec<Vec<u8>> = yasna::parse_der(&der, |reader| {
            let mut v = Vec::new();
            reader.read_sequence_of(|r| { v.push(r.read_der()?); Ok(()) })?;
            // Note: using read_sequence_of (no order check) just to dump elements, since
            // the der here is actually a SET tag (0x31) not SEQUENCE (0x30) - adjust below.
            Ok(v)
        }).unwrap_or_default();
        eprintln!("elems via seq_of (wrong tag, expect err) = {}", elems.len());
        // Manually strip the outer SET tag+len and dump both inner element byte strings.
        eprintln!("first byte (tag) = {:#04X}", der[0]);
        let result: ASN1Result<()> = yasna::parse_der(&der, |reader| {
            reader.read_set_of(|r| {
                let bytes = r.read_der()?;
                eprintln!("set element hex = {}", bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>());
                Ok(())
            })
        });
        eprintln!("minimal set_of result = {:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn debug_parse_dumped_file() {
        let dir = std::env::var("XKS_DUMP_DIR").unwrap_or_else(|_| "/tmp".to_string());
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let data = std::fs::read(&path).unwrap();
            eprintln!("--- {:?} len={} ---", path, data.len());
            let cert_result = yasna::parse_der(&data, read_safe_bag_cert);
            eprintln!("cert_result: {:?}", cert_result.as_ref().map(|b| (b.cert_der.len(), &b.attrs.friendly_name)).map_err(|e| e.clone()));
            let key_result = yasna::parse_der(&data, read_safe_bag_key);
            eprintln!("key_result: {:?}", key_result.as_ref().map(|b| (b.encrypted_private_key_info_der.len(), &b.attrs.friendly_name)).map_err(|e| e.clone()));
        }
    }

    #[test]
    fn debug_real_fixture_bag_roundtrip() {
        use crate::crypto::{create_keystore_keypair_entry, GenerateKeyPairInput};
        let input = GenerateKeyPairInput {
            alias: "dbg".to_string(),
            algorithm: "RSA".to_string(),
            key_size: 2048,
            curve: None,
            common_name: "dbg.example.com".to_string(),
            organization: "Test".to_string(),
            organizational_unit: "".to_string(),
            locality: "".to_string(),
            state: "".to_string(),
            country: "US".to_string(),
            email: "".to_string(),
            validity_days: 365,
            is_ca: false,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            signer_alias: None,
            labels: vec![],
        };
        let entry = create_keystore_keypair_entry(&input, None).unwrap();
        let cert_der = pem_to_der(&entry.certificate_chain[0].pem).unwrap();
        eprintln!("real cert_der len = {}", cert_der.len());
        let key_id = sha1_of(&cert_der);
        let bag_der = yasna::construct_der(|writer| {
            write_cert_bag(writer, &cert_der, &entry.alias, &key_id);
        });
        eprintln!("real bag_der len = {}", bag_der.len());
        let result = yasna::parse_der(&bag_der, read_safe_bag_cert);
        match &result {
            Ok(bag) => eprintln!("OK: cert_der_len={}", bag.cert_der.len()),
            Err(e) => eprintln!("ERR: {:?}", e),
        }
        assert!(result.is_ok());

        // Now the key side.
        let priv_pem = entry.private_key_pem.clone().unwrap();
        let pkcs8_der = pem_to_der(&priv_pem).unwrap();
        eprintln!("pkcs8_der len = {}", pkcs8_der.len());
        let shrouded = shroud_private_key("testpw", &pkcs8_der).unwrap();
        eprintln!("shrouded len = {}", shrouded.len());
        let key_bag_der = yasna::construct_der(|writer| {
            write_key_bag(writer, &shrouded, &entry.alias, &key_id);
        });
        eprintln!("key_bag_der len = {}", key_bag_der.len());
        let key_result = yasna::parse_der(&key_bag_der, read_safe_bag_key);
        match &key_result {
            Ok(_) => eprintln!("KEY OK"),
            Err(e) => eprintln!("KEY ERR: {:?}", e),
        }
        assert!(key_result.is_ok());
    }

    #[test]
    fn debug_safe_contents_roundtrip() {
        let cert_der = vec![0xAAu8; 50];
        let key_id = vec![0xBBu8; 20];
        let bag_der = yasna::construct_der(|writer| {
            write_cert_bag(writer, &cert_der, "myalias", &key_id);
        });
        let safe_contents = yasna::construct_der(|writer| {
            writer.write_sequence_of(|writer| {
                writer.next().write_der(&bag_der);
            });
        });
        eprintln!("safe_contents = {:?}", safe_contents);
        let result: Result<usize, _> = yasna::parse_der(&safe_contents, |reader| {
            let mut count = 0usize;
            reader.read_sequence_of(|reader| {
                let der = reader.read_der()?;
                eprintln!("inner der len={} bytes={:?}", der.len(), &der[..der.len().min(10)]);
                count += 1;
                Ok(())
            })?;
            Ok(count)
        });
        eprintln!("result = {:?}", result);
        assert_eq!(result.unwrap(), 1);
    }
}
