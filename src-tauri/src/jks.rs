//! Real Sun JKS (Java KeyStore) binary encoder/decoder.
//!
//! Implements the documented on-disk format used by `sun.security.provider.JavaKeyStore`
//! (and reimplemented by compatible tools such as the Python `pyjks` and Go `jingo`
//! libraries): magic `0xFEEDFEED`, version, entry count, then per-entry records, and a
//! whole-file SHA-1 integrity digest at the tail. Private keys are protected with the
//! JKS-proprietary key-protection algorithm (NOT PKCS#8 PBE): a SHA-1-based keystream
//! XORed with the PKCS8 DER bytes, wrapped in an `EncryptedPrivateKeyInfo` DER structure
//! tagged with the JavaSoft OID `1.3.6.1.4.1.42.2.17.1.1`.
//!
//! This module is self-contained and only depends on the `KeystoreEntry`/`KeystoreFile`
//! models from [`crate::crypto`].

use crate::crypto::{CertificateInfo, KeystoreEntry, KeystoreFile};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Digest as Sha1Digest, Sha1};
use std::io::{Cursor, Read, Write};

/// JavaSoft proprietary key-protection OID used inside `EncryptedPrivateKeyInfo`.
const JAVASOFT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1];
/// The literal ASCII salt string mixed into the whole-keystore integrity digest.
const JKS_MAGIC_STRING: &[u8] = b"Mighty Aphrodite";
const JKS_MAGIC: u32 = 0xFEED_FEED;
const JKS_VERSION: u32 = 2;
const SEED_LEN: usize = 20;
const SHA1_LEN: usize = 20;

/// UTF-16BE encoding of a password, as used by every JKS hashing step.
fn password_utf16be(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

fn sha1_digest(chunks: &[&[u8]]) -> [u8; SHA1_LEN] {
    let mut hasher = Sha1::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; SHA1_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Derives the JKS keystream: repeated SHA-1(password_utf16be || running_seed), running_seed
/// starting as the random 20-byte seed and then becoming the previous digest output,
/// concatenated until it covers `len` bytes.
fn jks_keystream(password_utf16: &[u8], seed: &[u8; SEED_LEN], len: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(len + SHA1_LEN);
    let mut running = *seed;
    while stream.len() < len {
        running = sha1_digest(&[password_utf16, &running]);
        stream.extend_from_slice(&running);
    }
    stream.truncate(len);
    stream
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Encrypts a PKCS8 DER private key with the JKS proprietary algorithm and wraps the
/// result in the standard `EncryptedPrivateKeyInfo` DER structure.
fn protect_private_key(password: &str, pkcs8_der: &[u8]) -> Vec<u8> {
    let pw16 = password_utf16be(password);

    let mut seed = [0u8; SEED_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);

    let keystream = jks_keystream(&pw16, &seed, pkcs8_der.len());
    let xored = xor_bytes(pkcs8_der, &keystream);

    // Integrity check digest over (password || plaintext pkcs8 der).
    let check = sha1_digest(&[&pw16, pkcs8_der]);

    let mut encrypted_blob = Vec::with_capacity(SEED_LEN + xored.len() + SHA1_LEN);
    encrypted_blob.extend_from_slice(&seed);
    encrypted_blob.extend_from_slice(&xored);
    encrypted_blob.extend_from_slice(&check);

    // EncryptedPrivateKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, encryptedData OCTET STRING }
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER }  (no parameters, as JKS writes it)
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&yasna::models::ObjectIdentifier::from_slice(JAVASOFT_OID));
            });
            writer.next().write_bytes(&encrypted_blob);
        });
    })
}

/// Reverses [`protect_private_key`]: parses the `EncryptedPrivateKeyInfo` DER, recovers the
/// plaintext PKCS8 DER, and verifies the embedded SHA-1 integrity check.
fn recover_private_key(password: &str, encrypted_info_der: &[u8]) -> Result<Vec<u8>, String> {
    let encrypted_blob: Vec<u8> = yasna::parse_der(encrypted_info_der, |reader| {
        reader.read_sequence(|reader| {
            // AlgorithmIdentifier - skip over it (we don't need to validate the OID value for decoding).
            reader.next().read_sequence(|reader| {
                let _oid = reader.next().read_oid()?;
                Ok(())
            })?;
            reader.next().read_bytes()
        })
    })
    .map_err(|e| format!("malformed EncryptedPrivateKeyInfo: {e:?}"))?;

    if encrypted_blob.len() < SEED_LEN + SHA1_LEN {
        return Err("encrypted private key blob too short".to_string());
    }

    let seed: [u8; SEED_LEN] = encrypted_blob[..SEED_LEN].try_into().unwrap();
    let xored = &encrypted_blob[SEED_LEN..encrypted_blob.len() - SHA1_LEN];
    let stored_check = &encrypted_blob[encrypted_blob.len() - SHA1_LEN..];

    let pw16 = password_utf16be(password);
    let keystream = jks_keystream(&pw16, &seed, xored.len());
    let pkcs8_der = xor_bytes(xored, &keystream);

    let expected_check = sha1_digest(&[&pw16, &pkcs8_der]);
    if expected_check.as_slice() != stored_check {
        return Err("keystore password incorrect or file corrupt".to_string());
    }

    Ok(pkcs8_der)
}

fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, String> {
    let parsed = pem::parse(pem_str.as_bytes()).map_err(|e| format!("invalid PEM: {e}"))?;
    Ok(parsed.contents().to_vec())
}

fn der_to_pem(der: &[u8], tag: &str) -> String {
    let p = pem::Pem::new(tag, der.to_vec());
    pem::encode(&p)
}

fn write_utf_string(buf: &mut Vec<u8>, s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    buf.write_u16::<BigEndian>(bytes.len() as u16).map_err(|e| e.to_string())?;
    buf.write_all(bytes).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_utf_string(cursor: &mut Cursor<&[u8]>) -> Result<String, String> {
    let len = cursor.read_u16::<BigEndian>().map_err(|e| e.to_string())? as usize;
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Encodes a [`KeystoreFile`] into real Sun JKS binary bytes, readable by `keytool`.
pub fn encode_jks(ks: &KeystoreFile, password: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    buf.write_u32::<BigEndian>(JKS_MAGIC).map_err(|e| e.to_string())?;
    buf.write_u32::<BigEndian>(JKS_VERSION).map_err(|e| e.to_string())?;
    buf.write_u32::<BigEndian>(ks.entries.len() as u32).map_err(|e| e.to_string())?;

    for entry in &ks.entries {
        let is_key_pair = entry.entry_type == "KeyPair";
        let tag: u32 = if is_key_pair { 1 } else { 2 };
        buf.write_u32::<BigEndian>(tag).map_err(|e| e.to_string())?;
        write_utf_string(&mut buf, &entry.alias)?;
        buf.write_i64::<BigEndian>(chrono::Utc::now().timestamp_millis())
            .map_err(|e| e.to_string())?;

        if is_key_pair {
            let priv_pem = entry
                .private_key_pem
                .as_deref()
                .ok_or_else(|| format!("entry '{}' is a KeyPair but has no private key", entry.alias))?;
            let pkcs8_der = pem_to_der(priv_pem)?;
            let protected = protect_private_key(password, &pkcs8_der);
            buf.write_u32::<BigEndian>(protected.len() as u32).map_err(|e| e.to_string())?;
            buf.write_all(&protected).map_err(|e| e.to_string())?;

            buf.write_u32::<BigEndian>(entry.certificate_chain.len() as u32)
                .map_err(|e| e.to_string())?;
            for cert in &entry.certificate_chain {
                write_cert(&mut buf, cert)?;
            }
        } else {
            let cert = entry
                .certificate_chain
                .first()
                .ok_or_else(|| format!("entry '{}' has no certificate to store", entry.alias))?;
            write_cert(&mut buf, cert)?;
        }
    }

    let pw16 = password_utf16be(password);
    let whole_digest = sha1_digest(&[&pw16, JKS_MAGIC_STRING, &buf]);
    buf.write_all(&whole_digest).map_err(|e| e.to_string())?;

    Ok(buf)
}

fn write_cert(buf: &mut Vec<u8>, cert: &CertificateInfo) -> Result<(), String> {
    write_utf_string(buf, "X.509")?;
    let der = pem_to_der(&cert.pem)?;
    buf.write_u32::<BigEndian>(der.len() as u32).map_err(|e| e.to_string())?;
    buf.write_all(&der).map_err(|e| e.to_string())?;
    Ok(())
}

/// Decodes real Sun JKS binary bytes (as produced by `keytool` or [`encode_jks`]) into a
/// [`KeystoreFile`]. Verifies the whole-file integrity digest and, for each private key
/// entry, the per-key SHA-1 check; returns `Err` on any mismatch or malformed structure.
pub fn decode_jks(bytes: &[u8], password: &str) -> Result<KeystoreFile, String> {
    if bytes.len() < 4 + 4 + 4 + SHA1_LEN {
        return Err("keystore password incorrect or file corrupt".to_string());
    }
    let body_len = bytes.len() - SHA1_LEN;
    let body = &bytes[..body_len];
    let stored_digest = &bytes[body_len..];

    let pw16 = password_utf16be(password);
    let expected_digest = sha1_digest(&[&pw16, JKS_MAGIC_STRING, body]);
    if expected_digest.as_slice() != stored_digest {
        return Err("keystore password incorrect or file corrupt".to_string());
    }

    let mut cursor = Cursor::new(body);
    let magic = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
    if magic != JKS_MAGIC {
        return Err("not a JKS keystore (bad magic)".to_string());
    }
    let _version = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
    let count = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;

    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let tag = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
        let alias = read_utf_string(&mut cursor)?;
        let creation_millis = cursor.read_i64::<BigEndian>().map_err(|e| e.to_string())?;
        let creation_dt = chrono::DateTime::from_timestamp_millis(creation_millis)
            .unwrap_or_else(chrono::Utc::now);
        let creation_date = creation_dt.format("%Y-%m-%d").to_string();

        if tag == 1 {
            let protected_len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
            let mut protected = vec![0u8; protected_len];
            cursor.read_exact(&mut protected).map_err(|e| e.to_string())?;
            let pkcs8_der = recover_private_key(password, &protected)?;
            let priv_pem = der_to_pem(&pkcs8_der, "PRIVATE KEY");

            let chain_count = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
            let mut chain = Vec::with_capacity(chain_count as usize);
            for _ in 0..chain_count {
                chain.push(read_cert_entry(&mut cursor)?);
            }

            entries.push(build_entry(alias, "KeyPair", creation_date, Some(priv_pem), None, chain));
        } else if tag == 2 {
            let cert = read_cert_entry(&mut cursor)?;
            entries.push(build_entry(
                alias,
                "TrustedCertificate",
                creation_date,
                None,
                None,
                vec![cert],
            ));
        } else {
            return Err(format!("unknown JKS entry tag {tag}"));
        }
    }

    Ok(KeystoreFile {
        id: format!("jks-{}", uuid::Uuid::new_v4()),
        name: "imported.jks".to_string(),
        format: "JKS".to_string(),
        path: String::new(),
        description: "Decoded from JKS binary".to_string(),
        password_protected: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        entries,
    })
}

fn read_cert_entry(cursor: &mut Cursor<&[u8]>) -> Result<CertificateInfo, String> {
    let _cert_type = read_utf_string(cursor)?;
    let len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
    let mut der = vec![0u8; len];
    cursor.read_exact(&mut der).map_err(|e| e.to_string())?;
    Ok(certificate_info_from_der(&der))
}

/// Builds a minimal (but internally consistent) [`CertificateInfo`] from raw DER bytes for
/// entries decoded from a foreign keystore, where only the certificate bytes are known.
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
    creation_date: String,
    private_key_pem: Option<String>,
    secret_key_hex: Option<String>,
    chain: Vec<CertificateInfo>,
) -> KeystoreEntry {
    let first = chain.first();
    KeystoreEntry {
        id: format!("entry-{}", uuid::Uuid::new_v4()),
        alias,
        entry_type: entry_type.to_string(),
        algorithm: String::new(),
        key_size: 0,
        curve: None,
        creation_date: creation_date.clone(),
        expiry_date: first.map(|c| c.valid_to.clone()).unwrap_or_default(),
        last_modified: creation_date,
        subject: first.map(|c| c.subject.clone()).unwrap_or_default(),
        issuer: first.map(|c| c.issuer.clone()).unwrap_or_default(),
        serial_number: first.map(|c| c.serial_number.clone()).unwrap_or_default(),
        sha256_fingerprint: first.map(|c| c.sha256_fingerprint.clone()).unwrap_or_default(),
        sha1_fingerprint: first.map(|c| c.sha1_fingerprint.clone()).unwrap_or_default(),
        chain_length: chain.len(),
        certificate_chain: chain,
        private_key_pem,
        public_key_pem: None,
        secret_key_hex,
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
            common_name: "jks-test.example.com".to_string(),
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

    #[test]
    fn jks_round_trip_preserves_key_and_cert() {
        let entry = fixture_entry("jks-roundtrip");
        let original_priv = entry.private_key_pem.clone().unwrap();
        let original_cert = entry.certificate_chain[0].pem.clone();

        let ks = KeystoreFile {
            id: "ks-1".to_string(),
            name: "test.jks".to_string(),
            format: "JKS".to_string(),
            path: String::new(),
            description: String::new(),
            password_protected: true,
            created_at: String::new(),
            updated_at: String::new(),
            entries: vec![entry],
        };

        let password = "correct-horse-battery-staple";
        let bytes = encode_jks(&ks, password).expect("encode failed");

        // Sanity-check the on-disk magic/version header.
        assert_eq!(&bytes[0..4], &JKS_MAGIC.to_be_bytes());
        assert_eq!(&bytes[4..8], &JKS_VERSION.to_be_bytes());

        let decoded = decode_jks(&bytes, password).expect("decode failed");
        assert_eq!(decoded.entries.len(), 1);
        let decoded_entry = &decoded.entries[0];

        assert_eq!(
            normalize_pem(decoded_entry.private_key_pem.as_deref().unwrap()),
            normalize_pem(&original_priv)
        );
        assert_eq!(
            normalize_pem(&decoded_entry.certificate_chain[0].pem),
            normalize_pem(&original_cert)
        );
    }

    #[test]
    fn jks_wrong_password_fails_digest_check() {
        let entry = fixture_entry("jks-wrongpw");
        let ks = KeystoreFile {
            id: "ks-2".to_string(),
            name: "test2.jks".to_string(),
            format: "JKS".to_string(),
            path: String::new(),
            description: String::new(),
            password_protected: true,
            created_at: String::new(),
            updated_at: String::new(),
            entries: vec![entry],
        };

        let bytes = encode_jks(&ks, "right-password").expect("encode failed");
        let err = decode_jks(&bytes, "wrong-password").unwrap_err();
        assert_eq!(err, "keystore password incorrect or file corrupt");
    }

    #[test]
    fn jks_trusted_cert_entry_round_trips() {
        let entry = fixture_entry("jks-cert-fixture");
        let cert_only = KeystoreEntry {
            entry_type: "TrustedCertificate".to_string(),
            private_key_pem: None,
            ..entry
        };
        let original_cert = cert_only.certificate_chain[0].pem.clone();

        let ks = KeystoreFile {
            id: "ks-3".to_string(),
            name: "test3.jks".to_string(),
            format: "JKS".to_string(),
            path: String::new(),
            description: String::new(),
            password_protected: true,
            created_at: String::new(),
            updated_at: String::new(),
            entries: vec![cert_only],
        };

        let password = "trustpw123";
        let bytes = encode_jks(&ks, password).expect("encode failed");
        let decoded = decode_jks(&bytes, password).expect("decode failed");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].entry_type, "TrustedCertificate");
        assert_eq!(
            normalize_pem(&decoded.entries[0].certificate_chain[0].pem),
            normalize_pem(&original_cert)
        );
    }
}
