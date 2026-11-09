//! Read-only Bouncy Castle BKS (store version 2).
//!
//! The store body is cleartext and integrity-protected with HMAC-SHA1. The MAC key comes from
//! the PKCS#12 KDF (id 3), which is what `BcKeyStoreSpi` uses for version 2. Private keys are
//! PKCS#8. A sealed entry is `PBEWithSHAAnd3-KeyTripleDES-CBC`, which this crate already decrypts.
//! UBER encrypts the whole file with Twofish and is still refused. BCFKS is parsed separately.

use crate::entry;
use crate::model::KeystoreEntry;
use crate::pbe::{self, HashAlg};
use crate::util::*;
use std::collections::HashMap;
use std::io::{Cursor, Read};

const KEY: u8 = 2;
const CERTIFICATE: u8 = 1;
const SECRET: u8 = 3;
const SEALED: u8 = 4;
const KEY_PRIVATE: u8 = 0;
const KEY_SECRET: u8 = 2;

fn read_u8(c: &mut Cursor<&[u8]>) -> Res<u8> {
    let mut b = [0u8; 1];
    c.read_exact(&mut b).map_err(|_| "invalid: truncated BKS keystore")?;
    Ok(b[0])
}

fn read_u16(c: &mut Cursor<&[u8]>) -> Res<u16> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b).map_err(|_| "invalid: truncated BKS keystore")?;
    Ok(u16::from_be_bytes(b))
}

fn read_i32(c: &mut Cursor<&[u8]>) -> Res<i32> {
    let mut b = [0u8; 4];
    c.read_exact(&mut b).map_err(|_| "invalid: truncated BKS keystore")?;
    Ok(i32::from_be_bytes(b))
}

fn read_u32(c: &mut Cursor<&[u8]>) -> Res<u32> {
    Ok(read_i32(c)? as u32)
}

fn read_i64(c: &mut Cursor<&[u8]>) -> Res<i64> {
    let mut b = [0u8; 8];
    c.read_exact(&mut b).map_err(|_| "invalid: truncated BKS keystore")?;
    Ok(i64::from_be_bytes(b))
}

/// Java `DataInputStream.readUTF` for the ASCII aliases BKS actually stores.
fn read_utf(c: &mut Cursor<&[u8]>) -> Res<String> {
    let len = read_u16(c)? as usize;
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).map_err(|_| "invalid: truncated BKS string")?;
    String::from_utf8(buf).map_err(|_| "invalid: BKS alias is not UTF-8".to_string())
}

fn read_block(c: &mut Cursor<&[u8]>) -> Res<Vec<u8>> {
    let len = read_i32(c)?;
    if !(0..=2 * 1024 * 1024).contains(&len) {
        return Err("invalid: BKS length is not plausible".into());
    }
    let mut buf = vec![0u8; len as usize];
    c.read_exact(&mut buf).map_err(|_| "invalid: truncated BKS block")?;
    Ok(buf)
}

fn read_cert(c: &mut Cursor<&[u8]>) -> Res<Vec<u8>> {
    let kind = read_utf(c)?;
    let der = read_block(c)?;
    if !kind.eq_ignore_ascii_case("X.509") && !kind.eq_ignore_ascii_case("X509") {
        return Err(format!("unsupported: BKS certificate type '{kind}' is not X.509"));
    }
    Ok(der)
}

fn unseal(password: &str, blob: &[u8]) -> Res<Vec<u8>> {
    let mut c = Cursor::new(blob);
    let salt = read_block(&mut c)?;
    let iterations = read_i32(&mut c)? as u64;
    let rest = &blob[c.position() as usize..];
    // PBEWithSHAAnd3-KeyTripleDES-CBC, the cipher BcKeyStoreSpi names KEY_CIPHER.
    let params = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bytes(&salt);
            w.next().write_u64(iterations);
        })
    });
    let alg = crate::pbe::AlgorithmId { oid: crate::oids::PBE_SHA1_3DES.to_vec(), params: Some(params) };
    pbe::decrypt(&alg, password, rest)
}

fn decode_key(c: &mut Cursor<&[u8]>) -> Res<(String, Vec<u8>, bool)> {
    let key_type = read_u8(c)?;
    let format = read_utf(c)?;
    let algorithm = read_utf(c)?;
    let enc = read_block(c)?;
    let pkcs8 = format.eq_ignore_ascii_case("PKCS#8") || format.eq_ignore_ascii_case("PKCS8");
    if key_type == KEY_PRIVATE && pkcs8 {
        return Ok((algorithm, enc, true));
    }
    if key_type == KEY_SECRET && format.eq_ignore_ascii_case("RAW") {
        return Ok((algorithm, enc, false));
    }
    Err(format!("unsupported: BKS key format '{format}' ({algorithm}) is not PKCS#8 or RAW"))
}

/// Opens a BKS version 2 file. `key_passwords` unlocks sealed entries whose password is not the store password.
pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<Vec<KeystoreEntry>> {
    if bytes.len() < 48 {
        return Err("invalid: truncated BKS keystore".into());
    }
    let mut c = Cursor::new(bytes);
    let version = read_u32(&mut c)?;
    if version != 2 {
        return Err(format!("unsupported: BKS version {version} is not read (version 2 is)"));
    }
    let salt_len = read_u32(&mut c)? as usize;
    if salt_len == 0 || salt_len > 64 {
        return Err("invalid: BKS salt length is not plausible".into());
    }
    let mut salt = vec![0u8; salt_len];
    c.read_exact(&mut salt).map_err(|_| "invalid: truncated BKS keystore")?;
    let iterations = read_u32(&mut c)? as u64;
    let header = c.position() as usize;
    if bytes.len() < header + 20 {
        return Err("invalid: truncated BKS keystore".into());
    }
    let (body, mac) = bytes[header..].split_at(bytes.len() - header - 20);
    let mac_key = pbe::pkcs12_kdf(HashAlg::Sha1, password, &salt, iterations, 3, 20);
    if HashAlg::Sha1.hmac(&mac_key, body) != mac {
        return Err("wrong-password: BKS integrity check failed".into());
    }
    let mut entries = Vec::new();
    let mut body_c = Cursor::new(body);
    loop {
        let type_byte = read_u8(&mut body_c)?;
        if type_byte == 0 {
            break;
        }
        let alias = read_utf(&mut body_c)?;
        let created = Some(read_i64(&mut body_c)? / 1000);
        let chain_len = read_i32(&mut body_c)?;
        if !(0..=32).contains(&chain_len) {
            return Err("invalid: BKS certificate chain length is not plausible".into());
        }
        let mut chain = Vec::new();
        for _ in 0..chain_len {
            chain.push(read_cert(&mut body_c)?);
        }
        match type_byte {
            CERTIFICATE => {
                let der = read_cert(&mut body_c)?;
                entries.push(entry::trusted_cert_entry(&alias, &der, created)?);
            }
            KEY => {
                let (algorithm, material, private) = decode_key(&mut body_c)?;
                if private {
                    entries.push(entry::key_pair_entry(&alias, &material, &chain, created)?);
                } else {
                    entries.push(entry::secret_key_entry(&alias, &algorithm, &material, created));
                }
            }
            SECRET | SEALED => {
                let blob = read_block(&mut body_c)?;
                let supplied_pw =
                    key_passwords.get(&alias).or_else(|| key_passwords.iter().find(|(k, _)| k.eq_ignore_ascii_case(&alias)).map(|(_, v)| v)).map(String::as_str).filter(|p| !p.is_empty());
                if type_byte == SEALED {
                    let unsealed = supplied_pw.and_then(|pw| unseal(pw, &blob).ok().map(|plain| (pw, plain))).or_else(|| unseal(password, &blob).ok().map(|plain| (password, plain)));
                    match unsealed {
                        Some((used_pw, plain)) => {
                            let (algorithm, material, private) = decode_key(&mut Cursor::new(plain.as_slice()))?;
                            let mut e = if private { entry::key_pair_entry(&alias, &material, &chain, created)? } else { entry::secret_key_entry(&alias, &algorithm, &material, created) };
                            if used_pw != password {
                                e.key_password = Some(used_pw.to_string());
                            }
                            entries.push(e);
                        }
                        None => {
                            if !chain.is_empty() {
                                entries.push(entry::locked_key_pair_entry(&alias, &blob, &chain, created)?);
                            } else {
                                entries.push(entry::locked_secret_entry(&alias, &blob, created));
                            }
                        }
                    }
                } else {
                    entries.push(entry::secret_key_entry(&alias, "Secret", &blob, created));
                }
            }
            other => return Err(format!("unsupported: BKS entry type {other}")),
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_bks_from_keytool_opens() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.bks");
        let bytes = std::fs::read(path).expect("fixture");
        let entries = decode(&bytes, "changeit", &HashMap::new()).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert!(names.contains(&"server"), "{names:?}");
        assert!(names.contains(&"trusted"), "{names:?}");
        assert!(names.contains(&"aes"), "{names:?}");
        let server = entries.iter().find(|e| e.alias == "server").unwrap();
        assert_eq!(server.entry_type, "KeyPair");
        assert!(server.private_key_pem.is_some());
        let aes = entries.iter().find(|e| e.alias == "aes").unwrap();
        assert_eq!(aes.entry_type, "SecretKey");
        assert_eq!(aes.key_size, 256, "{:?}", aes.algorithm);
        assert!(decode(&bytes, "nope", &HashMap::new()).unwrap_err().starts_with("wrong-password"));
    }
}
