//! Sun JKS and JCEKS keystore codecs (as written by `keytool` in JDK 8–21).
//!
//! Layout: magic (0xFEEDFEED JKS / 0xCECECECE JCEKS), version 2, entry count, entries, then a
//! SHA-1 integrity digest over `UTF16BE(password) || "Mighty Aphrodite" || body`.
//! - Private keys (tag 1) are an `EncryptedPrivateKeyInfo`: JKS uses Sun's SHA-1 keystream
//!   protector (OID 1.3.6.1.4.1.42.2.17.1.1); JCEKS uses PBEWithMD5AndTripleDES.
//! - Trusted certificates (tag 2).
//! - Secret keys (tag 3, JCEKS only) are a Java-serialized `SealedObjectForKeyProtector` whose
//!   content is a serialized `SecretKeySpec`, sealed with PBEWithMD5AndTripleDES.

use crate::entry;
use crate::javaser;
use crate::model::KeystoreEntry;
use crate::oids::{self, oid};
use crate::pbe;
use crate::util::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

pub const JKS_MAGIC: u32 = 0xFEED_FEED;
pub const JCEKS_MAGIC: u32 = 0xCECE_CECE;
const VERSION: u32 = 2;
const MIGHTY_APHRODITE: &[u8] = b"Mighty Aphrodite";
const WRONG_PASSWORD: &str = "wrong-password: keystore password incorrect or file corrupt";
/// JDK default for JCEKS key protection (`jdk.jceks.iterationCount`).
const JCEKS_ITERATIONS: u64 = 200_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Jks,
    Jceks,
}

pub fn detect(bytes: &[u8]) -> Option<Kind> {
    match bytes.get(..4).map(|b| u32::from_be_bytes(b.try_into().unwrap())) {
        Some(JKS_MAGIC) => Some(Kind::Jks),
        Some(JCEKS_MAGIC) => Some(Kind::Jceks),
        _ => None,
    }
}

fn utf16be(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

fn integrity_digest(password: &str, body: &[u8]) -> Vec<u8> {
    sha1(&[utf16be(password).as_slice(), MIGHTY_APHRODITE, body].concat())
}

// ---------------------------------------------------------------------------------------------
// JKS proprietary key protector
// ---------------------------------------------------------------------------------------------

fn jks_keystream(pw: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 20);
    let mut running = seed.to_vec();
    while out.len() < len {
        running = sha1(&[pw, running.as_slice()].concat());
        out.extend_from_slice(&running);
    }
    out.truncate(len);
    out
}

fn jks_protect(password: &str, pkcs8: &[u8]) -> Vec<u8> {
    let pw = utf16be(password);
    let seed = random_bytes(20);
    let stream = jks_keystream(&pw, &seed, pkcs8.len());
    let mut blob = seed.clone();
    blob.extend(pkcs8.iter().zip(stream).map(|(a, b)| a ^ b));
    blob.extend(sha1(&[pw.as_slice(), pkcs8].concat()));
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::JKS_KEY_PROTECTOR));
                w.next().write_null();
            });
            w.next().write_bytes(&blob);
        })
    })
}

fn jks_recover(password: &str, blob: &[u8]) -> Res<Vec<u8>> {
    if blob.len() < 40 {
        return Err("protected key too short".into());
    }
    let pw = utf16be(password);
    let (seed, rest) = blob.split_at(20);
    let (enc, check) = rest.split_at(rest.len() - 20);
    let stream = jks_keystream(&pw, seed, enc.len());
    let plain: Vec<u8> = enc.iter().zip(stream).map(|(a, b)| a ^ b).collect();
    if sha1(&[pw.as_slice(), plain.as_slice()].concat()) != check {
        return Err(WRONG_PASSWORD.into());
    }
    Ok(plain)
}

/// Decrypts a protected private key from either format.
fn recover_private_key(password: &str, protected: &[u8]) -> Res<Vec<u8>> {
    let (alg, data) = yasna::parse_ber(protected, |r| {
        r.read_sequence(|r| {
            let alg = pbe::read_algorithm_id(r.next())?;
            let data = r.next().read_bytes()?;
            Ok((alg, data))
        })
    })
    .map_err(|err| format!("malformed protected private key: {err}"))?;
    if alg.oid.as_slice() == oids::JKS_KEY_PROTECTOR { jks_recover(password, &data) } else { pbe::decrypt(&alg, password, &data).map_err(|_| WRONG_PASSWORD.to_string()) }
}

fn jceks_protect(password: &str, pkcs8: &[u8]) -> Res<Vec<u8>> {
    let (alg, ciphertext) = pbe::sun_md5_3des_encrypt(password, pkcs8, JCEKS_ITERATIONS)?;
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&alg);
            w.next().write_bytes(&ciphertext);
        })
    }))
}

// ---------------------------------------------------------------------------------------------
// JCEKS sealed secret keys
// ---------------------------------------------------------------------------------------------

fn unseal_secret(password: &str, sealed: &javaser::JValue) -> Res<(String, Vec<u8>)> {
    let params = sealed.field("encodedParams").and_then(|v| v.as_bytes()).ok_or("sealed key has no parameters")?;
    let content = sealed.field("encryptedContent").and_then(|v| v.as_bytes()).ok_or("sealed key has no content")?;
    let plain = pbe::sun_md5_3des_decrypt_with_params(password, params, content).map_err(|_| WRONG_PASSWORD.to_string())?;
    let key_obj = javaser::parse(&plain)?;
    // SecretKeySpec { algorithm, key } or KeyRep { algorithm, encoded, format, type }.
    let algorithm = key_obj.field("algorithm").and_then(|v| v.as_str()).unwrap_or("Secret").to_string();
    let bytes = key_obj.field("key").or_else(|| key_obj.field("encoded")).and_then(|v| v.as_bytes()).ok_or_else(|| format!("unsupported sealed key class {}", key_obj.class().unwrap_or("?")))?;
    Ok((algorithm, bytes.to_vec()))
}

fn seal_secret(password: &str, algorithm: &str, key: &[u8]) -> Res<Vec<u8>> {
    let salt = random_bytes(8);
    let params = pbe::sun_pbe_params(&salt, JCEKS_ITERATIONS);
    let plain = javaser::write_secret_key_spec(algorithm, key);
    let content = pbe::sun_md5_3des_encrypt_with_params(password, &salt, JCEKS_ITERATIONS, &plain)?;
    Ok(javaser::write_sealed_object(&params, &content, "PBEWithMD5AndTripleDES"))
}

// ---------------------------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------------------------

fn read_utf(c: &mut Cursor<&[u8]>) -> Res<String> {
    let len = c.read_u16::<BigEndian>().map_err(|_| truncated())? as usize;
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).map_err(|_| truncated())?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn truncated() -> String {
    "invalid: the keystore file is truncated or corrupt".into()
}

fn read_cert(c: &mut Cursor<&[u8]>) -> Res<Vec<u8>> {
    let cert_type = read_utf(c)?;
    if cert_type != "X.509" {
        return Err(format!("unsupported: certificate type '{cert_type}'"));
    }
    let len = c.read_u32::<BigEndian>().map_err(|_| truncated())? as usize;
    if len > c.get_ref().len() {
        return Err(truncated());
    }
    let mut der = vec![0u8; len];
    c.read_exact(&mut der).map_err(|_| truncated())?;
    Ok(der)
}

/// Decodes JKS/JCEKS bytes. `key_passwords` maps aliases to per-key passwords that differ from
/// the store password; keys that still cannot be decrypted load as locked entries.
pub fn decode(bytes: &[u8], password: &str, key_passwords: &std::collections::HashMap<String, String>) -> Res<Vec<KeystoreEntry>> {
    let kind = detect(bytes).ok_or("unrecognized: not a JKS or JCEKS keystore")?;
    if bytes.len() < 32 {
        return Err(truncated());
    }
    let (body, digest) = bytes.split_at(bytes.len() - 20);
    if integrity_digest(password, body) != digest {
        return Err(WRONG_PASSWORD.into());
    }
    let mut c = Cursor::new(body);
    c.set_position(4);
    let version = c.read_u32::<BigEndian>().map_err(|_| truncated())?;
    if version != 1 && version != 2 {
        return Err(format!("unsupported: keystore version {version}"));
    }
    let count = c.read_u32::<BigEndian>().map_err(|_| truncated())?;
    let mut entries = Vec::new();
    let lookup_pw = |alias: &str| -> Option<&str> {
        key_passwords.get(alias).or_else(|| key_passwords.iter().find(|(k, _)| k.eq_ignore_ascii_case(alias)).map(|(_, v)| v)).map(String::as_str).filter(|p| !p.is_empty())
    };
    for _ in 0..count {
        let tag = c.read_u32::<BigEndian>().map_err(|_| truncated())?;
        let alias = read_utf(&mut c)?;
        let millis = c.read_i64::<BigEndian>().map_err(|_| truncated())?;
        let created = Some(millis / 1000);
        let read_v1_cert = |c: &mut Cursor<&[u8]>| -> Res<Vec<u8>> {
            if version == 2 {
                read_cert(c)
            } else {
                let len = c.read_u32::<BigEndian>().map_err(|_| truncated())? as usize;
                let mut der = vec![0u8; len];
                c.read_exact(&mut der).map_err(|_| truncated())?;
                Ok(der)
            }
        };
        match tag {
            1 => {
                let len = c.read_u32::<BigEndian>().map_err(|_| truncated())? as usize;
                if len > body.len() {
                    return Err(truncated());
                }
                let mut protected = vec![0u8; len];
                c.read_exact(&mut protected).map_err(|_| truncated())?;
                let chain_len = c.read_u32::<BigEndian>().map_err(|_| truncated())?;
                let chain: Vec<Vec<u8>> = (0..chain_len).map(|_| read_v1_cert(&mut c)).collect::<Res<_>>()?;
                let recovered = lookup_pw(&alias)
                    .and_then(|pw| recover_private_key(pw, &protected).ok().map(|pkcs8| (pw, pkcs8)))
                    .or_else(|| recover_private_key(password, &protected).ok().map(|pkcs8| (password, pkcs8)));
                match recovered {
                    Some((used_pw, pkcs8)) => {
                        let mut entry = entry::key_pair_entry(&alias, &pkcs8, &chain, created)?;
                        if used_pw != password {
                            entry.key_password = Some(used_pw.to_string());
                        }
                        entries.push(entry);
                    }
                    None => entries.push(entry::locked_key_pair_entry(&alias, &protected, &chain, created)?),
                }
            }
            2 => {
                let cert = read_v1_cert(&mut c)?;
                entries.push(entry::trusted_cert_entry(&alias, &cert, created)?);
            }
            3 if kind == Kind::Jceks => {
                let start = c.position() as usize;
                let mut reader = javaser::Reader::new(&body[start..])?;
                let sealed = reader.object()?;
                let raw = &body[start..start + reader.position()];
                c.set_position((start + reader.position()) as u64);
                let unsealed = lookup_pw(&alias)
                    .and_then(|pw| unseal_secret(pw, &sealed).ok().map(|(alg, key)| (pw, alg, key)))
                    .or_else(|| unseal_secret(password, &sealed).ok().map(|(alg, key)| (password, alg, key)));
                match unsealed {
                    Some((used_pw, alg, key)) => {
                        let mut entry = entry::secret_key_entry(&alias, &alg, &key, created);
                        if used_pw != password {
                            entry.key_password = Some(used_pw.to_string());
                        }
                        entries.push(entry);
                    }
                    None => entries.push(entry::locked_secret_entry(&alias, raw, created)),
                }
            }
            other => return Err(format!("unsupported: keystore entry type {other}")),
        }
    }
    Ok(entries)
}

fn write_utf(buf: &mut Vec<u8>, s: &str) -> Res<()> {
    let b = s.as_bytes();
    if b.len() > u16::MAX as usize {
        return Err("alias too long".into());
    }
    buf.write_u16::<BigEndian>(b.len() as u16).map_err(e)?;
    buf.write_all(b).map_err(e)
}

fn write_cert(buf: &mut Vec<u8>, der: &[u8]) -> Res<()> {
    write_utf(buf, "X.509")?;
    buf.write_u32::<BigEndian>(der.len() as u32).map_err(e)?;
    buf.write_all(der).map_err(e)
}

fn entry_millis(entry: &KeystoreEntry) -> i64 {
    chrono::NaiveDate::parse_from_str(&entry.creation_date, "%Y-%m-%d").map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis()).unwrap_or_else(|_| chrono::Utc::now().timestamp_millis())
}

pub fn encode(entries: &[KeystoreEntry], password: &str, kind: Kind) -> Res<Vec<u8>> {
    let mut buf = Vec::new();
    buf.write_u32::<BigEndian>(if kind == Kind::Jks { JKS_MAGIC } else { JCEKS_MAGIC }).map_err(e)?;
    buf.write_u32::<BigEndian>(VERSION).map_err(e)?;
    buf.write_u32::<BigEndian>(entries.len() as u32).map_err(e)?;
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        // Java lowercases JKS and JCEKS aliases on read and on write. PKCS#12 is handled
        // elsewhere and keeps the case OpenSSL stored.
        let alias = entry.alias.to_lowercase();
        if !seen.insert(alias.to_lowercase()) {
            return Err(format!("invalid: duplicate alias '{alias}' (JKS/JCEKS aliases are case-insensitive)"));
        }
        match entry.entry_type.as_str() {
            "KeyPair" => {
                let chain = entry::chain_der(entry)?;
                if chain.is_empty() {
                    return Err(format!("invalid: key pair '{}' has no certificate chain", entry.alias));
                }
                let protected = if entry.locked {
                    unb64(entry.protected_key.as_deref().ok_or_else(|| format!("invalid: '{}' has no key material", entry.alias))?)?
                } else {
                    let pkcs8 = entry::private_key_der(entry)?;
                    let key_pw = entry.key_password.as_deref().filter(|p| !p.is_empty()).unwrap_or(password);
                    if kind == Kind::Jks { jks_protect(key_pw, &pkcs8) } else { jceks_protect(key_pw, &pkcs8)? }
                };
                buf.write_u32::<BigEndian>(1).map_err(e)?;
                write_utf(&mut buf, &alias)?;
                buf.write_i64::<BigEndian>(entry_millis(entry)).map_err(e)?;
                buf.write_u32::<BigEndian>(protected.len() as u32).map_err(e)?;
                buf.write_all(&protected).map_err(e)?;
                buf.write_u32::<BigEndian>(chain.len() as u32).map_err(e)?;
                for c in &chain {
                    write_cert(&mut buf, c)?;
                }
            }
            "TrustedCertificate" => {
                let chain = entry::chain_der(entry)?;
                let cert = chain.first().ok_or_else(|| format!("invalid: '{}' has no certificate", entry.alias))?;
                buf.write_u32::<BigEndian>(2).map_err(e)?;
                write_utf(&mut buf, &alias)?;
                buf.write_i64::<BigEndian>(entry_millis(entry)).map_err(e)?;
                write_cert(&mut buf, cert)?;
            }
            "SecretKey" => {
                if kind == Kind::Jks {
                    return Err(format!("unsupported: JKS cannot store secret keys ('{}'); save as PKCS#12 or JCEKS instead", entry.alias));
                }
                let sealed = if entry.locked {
                    unb64(entry.protected_key.as_deref().ok_or_else(|| format!("invalid: '{}' has no key material", entry.alias))?)?
                } else {
                    let key_pw = entry.key_password.as_deref().filter(|p| !p.is_empty()).unwrap_or(password);
                    seal_secret(key_pw, &entry.algorithm, &entry::secret_bytes(entry)?)?
                };
                buf.write_u32::<BigEndian>(3).map_err(e)?;
                write_utf(&mut buf, &alias)?;
                buf.write_i64::<BigEndian>(entry_millis(entry)).map_err(e)?;
                buf.write_all(&sealed).map_err(e)?;
            }
            other => return Err(format!("unsupported: entry type '{other}'")),
        }
    }
    let digest = integrity_digest(password, &buf);
    buf.extend(digest);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_entries() -> Vec<KeystoreEntry> {
        let input = crate::model::GenerateKeyPairInput {
            alias: "server".into(),
            algorithm: "ECDSA".into(),
            key_size: 0,
            curve: Some("P-256".into()),
            signature_hash: None,
            subject_dn: "CN=server.example, O=Test".into(),
            common_name: String::new(),
            organization: String::new(),
            organizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            email: String::new(),
            validity_days: 30,
            is_ca: false,
            path_len: None,
            sans: vec!["server.example".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
            labels: vec![],
            not_before: String::new(),
            not_after: String::new(),
            crl_distribution_points: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
        };
        let kp = crate::ops::generate_key_pair(&input, None).unwrap();
        let der = entry::chain_der(&kp).unwrap();
        let trusted = entry::trusted_cert_entry("ca", &der[0], None).unwrap();
        vec![kp, trusted]
    }

    #[test]
    fn jks_and_jceks_round_trip() {
        for kind in [Kind::Jks, Kind::Jceks] {
            let mut entries = sample_entries();
            if kind == Kind::Jceks {
                entries.push(entry::secret_key_entry("aes", "AES", &[5u8; 32], None));
            }
            let bytes = encode(&entries, "storepass", kind).unwrap();
            assert_eq!(detect(&bytes), Some(kind));
            let back = decode(&bytes, "storepass", &HashMap::new()).unwrap();
            assert_eq!(back.len(), entries.len());
            assert_eq!(back[0].private_key_pem, entries[0].private_key_pem);
            assert_eq!(back[1].sha256_fingerprint, entries[1].sha256_fingerprint);
            if kind == Kind::Jceks {
                assert_eq!(back[2].secret_key_hex, entries[2].secret_key_hex);
                assert_eq!(back[2].algorithm, "AES");
            }
            assert_eq!(decode(&bytes, "wrong", &HashMap::new()).unwrap_err(), WRONG_PASSWORD);
        }
    }

    #[test]
    fn jceks_aliases_are_stored_in_lower_case() {
        let mut entry = sample_entries().remove(0);
        entry.alias = "API".into();
        for kind in [Kind::Jks, Kind::Jceks] {
            let bytes = encode(std::slice::from_ref(&entry), "pw", kind).unwrap();
            let back = decode(&bytes, "pw", &HashMap::new()).unwrap();
            assert_eq!(back[0].alias, "api", "{kind:?}");
        }
    }

    #[test]
    fn a_distinct_key_password_survives_save() {
        let mut entry = sample_entries().remove(0);
        entry.key_password = Some("keypass99".into());
        let bytes = encode(std::slice::from_ref(&entry), "storepass", Kind::Jks).unwrap();
        let locked = decode(&bytes, "storepass", &HashMap::new()).unwrap();
        assert!(locked[0].locked, "the store password must not unwrap a distinct key password");
        let mut kp = HashMap::new();
        kp.insert("server".into(), "keypass99".into());
        let opened = decode(&bytes, "storepass", &kp).unwrap();
        assert!(!opened[0].locked);
        assert_eq!(opened[0].key_password.as_deref(), Some("keypass99"));
        assert_eq!(opened[0].private_key_pem, entry.private_key_pem);
    }

    #[test]
    fn jks_rejects_secret_keys() {
        let entries = vec![entry::secret_key_entry("aes", "AES", &[1u8; 16], None)];
        assert!(encode(&entries, "pw", Kind::Jks).is_err());
    }

    #[test]
    fn locked_keys_survive_resave() {
        // Key protected with a different password than the store.
        let entries = sample_entries();
        let pkcs8 = entry::private_key_der(&entries[0]).unwrap();
        let mut locked = entries[0].clone();
        locked.locked = true;
        locked.private_key_pem = None;
        locked.protected_key = Some(b64(&jks_protect("keypass", &pkcs8)));
        let bytes = encode(&[locked], "storepass", Kind::Jks).unwrap();
        let back = decode(&bytes, "storepass", &HashMap::new()).unwrap();
        assert!(back[0].locked);
        let mut kp = HashMap::new();
        kp.insert("server".to_string(), "keypass".to_string());
        let unlocked = decode(&bytes, "storepass", &kp).unwrap();
        assert!(!unlocked[0].locked);
        assert_eq!(unlocked[0].private_key_pem, entries[0].private_key_pem);
    }
}
