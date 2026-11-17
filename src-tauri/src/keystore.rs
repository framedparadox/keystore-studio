//! Keystore format detection and the open/save entry points used by the commands.

use crate::bcfks;
use crate::bks;
use crate::jks;
use crate::model::{KeystoreEntry, KeystoreFile};
use crate::pkcs12;
use crate::util::*;
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pkcs12,
    Jks,
    Jceks,
    /// Bouncy Castle BKS. Store versions 1 and 2 are read; version 2 is what is written.
    Bks,
    /// Bouncy Castle UBER: the BKS entry stream with the whole file under Twofish.
    Uber,
    /// Bouncy Castle BCFKS, the ASN.1 "FIPS keystore".
    Bcfks,
}

impl Format {
    pub const ALL: [Format; 6] = [Format::Pkcs12, Format::Jks, Format::Jceks, Format::Bks, Format::Uber, Format::Bcfks];

    /// Accepts the names the app uses and the ones `keytool -storetype` takes.
    pub fn parse(name: &str) -> Res<Format> {
        match name.trim().to_ascii_uppercase().replace(['#', '-'], "").as_str() {
            "PKCS12" | "P12" | "PFX" => Ok(Format::Pkcs12),
            "JKS" => Ok(Format::Jks),
            "JCEKS" => Ok(Format::Jceks),
            "BKS" | "BKSV1" => Ok(Format::Bks),
            "UBER" => Ok(Format::Uber),
            "BCFKS" | "BCFKSDEF" => Ok(Format::Bcfks),
            other => Err(format!("unsupported: keystore format '{other}'")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Pkcs12 => "PKCS12",
            Format::Jks => "JKS",
            Format::Jceks => "JCEKS",
            Format::Bks => "BKS",
            Format::Uber => "UBER",
            Format::Bcfks => "BCFKS",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Pkcs12 => "p12",
            Format::Jks => "jks",
            Format::Jceks => "jceks",
            Format::Bks => "bks",
            Format::Uber => "uber",
            Format::Bcfks => "bcfks",
        }
    }

    /// Formats that protect a key the same way. A key that is still locked by its own password
    /// is an opaque blob, and only a format of the same family can carry that blob.
    fn key_protection(self) -> u8 {
        match self {
            Format::Pkcs12 => 0,
            Format::Jks => 1,
            Format::Jceks => 2,
            Format::Bks | Format::Uber => 3,
            Format::Bcfks => 4,
        }
    }
}

/// Identifies a keystore by content (never by file name alone).
pub fn detect(bytes: &[u8]) -> Option<Format> {
    match jks::detect(bytes) {
        Some(jks::Kind::Jks) => return Some(Format::Jks),
        Some(jks::Kind::Jceks) => return Some(Format::Jceks),
        None => {}
    }
    if pkcs12::looks_like_pkcs12(bytes) {
        return Some(Format::Pkcs12);
    }
    if bcfks::looks_like(bytes) {
        return Some(Format::Bcfks);
    }
    detect_bks_or_uber(bytes)
}

/// BKS and UBER share a header. What follows it is an entry stream in the clear for BKS and
/// Twofish ciphertext for UBER, which is how the two are told apart without the password.
fn detect_bks_or_uber(bytes: &[u8]) -> Option<Format> {
    let (version, body_at) = bks::sniff_header(bytes)?;
    let body = &bytes[body_at..];
    if bks::looks_like_entry_stream(body) {
        return Some(Format::Bks);
    }
    // An UBER store is version 1 (0 in files from before 2000) and whole cipher blocks: at
    // least the end marker and its digest, which pad to two.
    (version <= 1 && body.len() >= 32 && body.len().is_multiple_of(16)).then_some(Format::Uber)
}

/// What a keystore file holds.
#[derive(Debug)]
pub struct Decoded {
    pub format: Format,
    pub entries: Vec<KeystoreEntry>,
    /// Things worth knowing about the file that the entry list does not show: an entry of a kind
    /// the app has no model for, a weak integrity check, how the integrity was verified.
    pub notes: Vec<String>,
    /// Entries in the file that are not in `entries` (each has a note). Saving over the file
    /// drops them.
    pub omitted: usize,
}

pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<Decoded> {
    let format = detect(bytes).ok_or_else(|| "unrecognized: not a recognised keystore (expected PKCS#12, JKS, JCEKS, BKS, UBER or BCFKS)".to_string())?;
    let (entries, mut notes, omitted) = match format {
        Format::Pkcs12 => (pkcs12::decode_with_key_passwords(bytes, password, key_passwords)?, Vec::new(), 0),
        Format::Jks | Format::Jceks => (jks::decode(bytes, password, key_passwords)?, Vec::new(), 0),
        Format::Bks | Format::Uber => {
            let store = if format == Format::Bks { bks::decode(bytes, password, key_passwords)? } else { bks::decode_uber(bytes, password, key_passwords)? };
            // Every note of this codec is an entry it could not show.
            let omitted = store.notes.len();
            (store.entries, store.notes, omitted)
        }
        Format::Bcfks => {
            let store = bcfks::decode(bytes, password, key_passwords)?;
            (store.entries, store.notes, store.omitted)
        }
    };
    if format == Format::Bks && bks::version(bytes).is_some_and(|v| v < 2) {
        notes.push("This is a BKS version 1 store. Its integrity check uses a 16-bit key (CVE-2018-5382), so it does not prove the file is unaltered. Saving it as BKS writes version 2.".into());
    }
    Ok(Decoded { format, entries, notes, omitted })
}

/// How a keystore is written, beyond its format and password.
#[derive(Clone, Copy, Debug)]
pub struct SavePolicy {
    pub mac: crate::pkcs12::MacKind,
    /// Replace a file that changed after it was opened.
    pub force: bool,
}

impl Default for SavePolicy {
    fn default() -> Self {
        Self { mac: crate::pkcs12::MacKind::Pkcs12, force: false }
    }
}

fn encode_with(entries: &[KeystoreEntry], password: &str, format: Format, policy: SavePolicy) -> Res<Vec<u8>> {
    match format {
        Format::Pkcs12 => pkcs12::encode_with_mac(entries, password, policy.mac),
        Format::Jks => jks::encode(entries, password, jks::Kind::Jks),
        Format::Jceks => jks::encode(entries, password, jks::Kind::Jceks),
        Format::Bks => bks::encode(entries, password, bks::Kind::Bks),
        Format::Uber => bks::encode(entries, password, bks::Kind::Uber),
        Format::Bcfks => bcfks::encode(entries, password),
    }
}

pub fn encode(entries: &[KeystoreEntry], password: &str, format: Format) -> Res<Vec<u8>> {
    if password.is_empty() {
        return Err("invalid: a keystore password is required".into());
    }
    encode_with(entries, password, format, SavePolicy::default())
}

fn file_timestamps(path: &Path) -> (String, String) {
    let meta = std::fs::metadata(path).ok();
    let fmt = |t: Option<std::time::SystemTime>| t.map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
    (fmt(meta.as_ref().and_then(|m| m.created().ok())), fmt(meta.as_ref().and_then(|m| m.modified().ok())))
}

pub fn open(path: &str, password: &str, key_passwords: &HashMap<String, String>) -> Res<KeystoreFile> {
    let p = Path::new(path);
    let bytes = std::fs::read(p).map_err(|err| format!("cannot read {path}: {err}"))?;
    let Decoded { format, entries, notes, omitted } = decode(&bytes, password, key_passwords)?;
    let (created, modified) = file_timestamps(p);
    let source_mtime_ms = mtime_ms(p);
    Ok(KeystoreFile {
        id: format!("ks-{}", uuid::Uuid::new_v4()),
        name: file_name_of(path),
        format: format.name().into(),
        path: path.to_string(),
        description: format!("{} keystore", format.name()),
        password_protected: true,
        created_at: created,
        updated_at: modified,
        source_mtime_ms,
        entries,
        notes,
        omitted_entries: omitted,
    })
}

pub fn mtime_ms(path: &Path) -> Option<i64> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64)
}

/// Encodes and atomically writes the keystore. Returns the written byte count.
pub fn save(ks: &KeystoreFile, path: &str, password: &str, format: Format) -> Res<usize> {
    save_with(ks, path, password, format, SavePolicy::default())
}

/// Whether `a` and `b` name the same file, also through symlinks and `..`.
fn same_file(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

pub fn save_with(ks: &KeystoreFile, path: &str, password: &str, format: Format, policy: SavePolicy) -> Res<usize> {
    if password.is_empty() {
        return Err("invalid: a keystore password is required. An empty password is rejected so a saved file is never left unprotected.".into());
    }
    // A key still locked by its own password is the source format's ciphertext. Refuse before
    // anything is written (the backup included) rather than let a codec wrap a blob it cannot read.
    if let Ok(source) = Format::parse(&ks.format)
        && source.key_protection() != format.key_protection()
        && let Some(locked) = ks.entries.iter().find(|e| e.locked)
    {
        return Err(format!("invalid: '{}' is locked by its own key password, which only a {} file can carry. Unlock it before saving as {}.", locked.alias, source.name(), format.name()));
    }
    let dest = Path::new(path);
    if dest.exists() {
        // The "changed on disk" guard protects the file the keystore was read from. Saving as a
        // different file that happens to exist is a plain overwrite the save dialog already
        // confirmed; comparing that file's time with the source's would always fail.
        if !policy.force
            && same_file(&ks.path, path)
            && let (Some(opened), Some(disk)) = (ks.source_mtime_ms, mtime_ms(dest))
            && disk != opened
        {
            return Err(format!("changed-on-disk: {path} was modified after it was opened. Save again and choose Override to replace it."));
        }
        if let Ok(previous) = std::fs::read(dest) {
            let bak = format!("{path}.bak");
            write_atomic(Path::new(&bak), &previous)?;
        }
    }
    let bytes = encode_with(&ks.entries, password, format, policy)?;
    let mut key_passwords = HashMap::new();
    for entry in &ks.entries {
        if let Some(kp) = entry.key_password.as_deref().filter(|p| !p.is_empty()) {
            key_passwords.insert(entry.alias.clone(), kp.to_string());
            key_passwords.insert(entry.alias.to_lowercase(), kp.to_string());
        }
    }
    // Prove the file reads back before replacing anything on disk.
    decode(&bytes, password, &key_passwords).map_err(|err| format!("internal error: the encoded keystore does not read back ({err})"))?;
    write_atomic(dest, &bytes)?;
    Ok(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
    }

    #[test]
    fn every_format_name_parses_and_round_trips() {
        for format in Format::ALL {
            assert_eq!(Format::parse(format.name()).unwrap(), format);
            assert_eq!(Format::parse(&format.name().to_ascii_lowercase()).unwrap(), format);
        }
        assert_eq!(Format::parse("PKCS#12").unwrap(), Format::Pkcs12);
        assert_eq!(Format::parse("pfx").unwrap(), Format::Pkcs12);
        assert_eq!(Format::parse("BCFKS-DEF").unwrap(), Format::Bcfks);
        assert!(Format::parse("PKCS11").unwrap_err().starts_with("unsupported:"));
    }

    #[test]
    fn written_files_detect_as_the_format_they_were_written_in() {
        let entry = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        for format in [Format::Pkcs12, Format::Jks, Format::Jceks, Format::Bks, Format::Uber, Format::Bcfks] {
            let bytes = encode(std::slice::from_ref(&entry), "pw123456", format).unwrap();
            assert_eq!(detect(&bytes), Some(format), "{}", format.name());
            let back = decode(&bytes, "pw123456", &HashMap::new()).unwrap();
            assert_eq!((back.format, back.entries.len()), (format, 1), "{}", format.name());
        }
    }

    #[test]
    fn bouncy_castle_fixtures_detect_by_content() {
        let cases = [
            ("sample.bks", Format::Bks),
            ("pyjks/christmas.bksv1", Format::Bks),
            ("pyjks/christmas.bksv2", Format::Bks),
            ("pyjks/custom_entry_passwords.bksv1", Format::Bks),
            ("pyjks/empty.bksv2", Format::Bks),
            ("sample.uber", Format::Uber),
            ("pyjks/christmas.uber", Format::Uber),
            ("pyjks/empty.uber", Format::Uber),
            ("sample.bcfks", Format::Bcfks),
            ("bouncycastle/oldKeyStore.bcfks", Format::Bcfks),
            ("bouncycastle/oldKeyStoreNoPW.bcfks", Format::Bcfks),
            ("bouncycastle/kwpKeyStore.bcfks", Format::Bcfks),
            ("bouncycastle/legacyScryptKeyStore.bcfks", Format::Bcfks),
            ("bouncycastle/legacyScryptSignedKeyStore.bcfks", Format::Bcfks),
        ];
        for (file, expected) in cases {
            assert_eq!(detect(&fixture(file)), Some(expected), "{file}");
        }
        // A certificate is DER too, and must not be taken for a BCFKS store.
        assert_eq!(detect(&fixture("bouncycastle/trustedCertData.cer")), None);
    }

    #[test]
    fn bks_and_uber_fixtures_open_through_the_keystore_entry_point() {
        let bks = decode(&fixture("pyjks/christmas.bksv2"), "12345678", &HashMap::new()).unwrap();
        assert_eq!((bks.format, bks.entries.len(), bks.omitted), (Format::Bks, 5, 1));
        assert!(bks.notes.iter().any(|n| n.contains("sealed_public_key")), "{:?}", bks.notes);
        let v1 = decode(&fixture("pyjks/christmas.bksv1"), "12345678", &HashMap::new()).unwrap();
        assert!(v1.notes.iter().any(|n| n.contains("CVE-2018-5382")), "{:?}", v1.notes);
        let uber = decode(&fixture("sample.uber"), "changeit", &HashMap::new()).unwrap();
        assert_eq!(uber.format, Format::Uber);
        assert!(!uber.entries.is_empty());
        assert!(decode(&fixture("sample.uber"), "wrong", &HashMap::new()).unwrap_err().starts_with("wrong-password"));
        let bcfks = decode(&fixture("bouncycastle/kwpKeyStore.bcfks"), "hello world", &HashMap::new()).unwrap();
        assert_eq!(bcfks.format, Format::Bcfks);
        assert!(bcfks.entries.len() >= 4);
    }

    #[test]
    fn ordinary_files_are_not_claimed_to_be_keystores() {
        for data in [&b"hello world"[..], &[0u8; 32], &[0xFF; 64], &[0u8; 64], b"-----BEGIN CERTIFICATE-----\nAAAA\n"] {
            assert_eq!(detect(data), None, "{data:?} misdetected");
        }
        let entry = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        let cert = crate::entry::chain_der(&entry).unwrap().remove(0);
        assert_eq!(detect(&cert), None, "a certificate is not a keystore");
        assert_eq!(detect(&crate::cms::certs_only(&[cert])), None, "a PKCS#7 bundle is not a keystore");
        assert_eq!(detect(&crate::entry::private_key_der(&entry).unwrap()), None, "a PKCS#8 key is not a keystore");
        assert!(decode(b"hello", "pw", &HashMap::new()).unwrap_err().starts_with("unrecognized:"));
    }

    #[test]
    fn hostile_indefinite_ber_does_not_abort_detection() {
        // CI keystore fuzz crash 84d79cfc: yasna overflowed while BCFKS detection probed the bytes.
        let crash: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x01, 0xff, 0x22, 0x80, 0x80, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x17, 0x2e, 0x02, 0x02, 0x2a, 0x30, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x17, 0x86, 0xd1, 0x00, 0xff, 0xff, 0xff,
        ];
        assert_eq!(detect(crash), None);
        assert!(decode(crash, "fuzz", &HashMap::new()).is_err());
    }

    #[test]
    fn a_key_locked_by_its_own_password_stays_in_its_family() {
        let dir = tempfile::tempdir().unwrap();
        let mut entry = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        entry.key_password = Some("key-pass-1".into());
        let path = dir.path().join("k.bks");
        std::fs::write(&path, encode(std::slice::from_ref(&entry), "pw123456", Format::Bks).unwrap()).unwrap();
        let ks = open(path.to_str().unwrap(), "pw123456", &HashMap::new()).unwrap();
        assert!(ks.entries[0].locked);
        // BKS and UBER seal keys the same way, so the blob can move between them; PKCS#12 cannot carry it.
        save(&ks, dir.path().join("k.uber").to_str().unwrap(), "pw123456", Format::Uber).unwrap();
        let err = save(&ks, dir.path().join("k.p12").to_str().unwrap(), "pw123456", Format::Pkcs12).unwrap_err();
        assert!(err.starts_with("invalid:") && err.contains("'k'"), "{err}");
        assert!(!dir.path().join("k.p12").exists());
    }

    #[test]
    fn changed_on_disk_guard_applies_only_to_the_source_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        let source = dir.path().join("source.p12");
        let other = dir.path().join("other.p12");
        for p in [&source, &other] {
            std::fs::write(p, encode(std::slice::from_ref(&entry), "pw123456", Format::Pkcs12).unwrap()).unwrap();
        }
        let mut ks = open(source.to_str().unwrap(), "pw123456", &HashMap::new()).unwrap();
        // Give the other file a different time, as any second file would have.
        std::fs::File::options().write(true).open(&other).unwrap().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000)).unwrap();
        save(&ks, other.to_str().unwrap(), "pw123456", Format::Pkcs12).expect("saving as another existing file must not report it as changed on disk");

        // The source itself changing after it was opened is still caught, and Override still works.
        std::fs::File::options().write(true).open(&source).unwrap().set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000)).unwrap();
        let err = save(&ks, source.to_str().unwrap(), "pw123456", Format::Pkcs12).unwrap_err();
        assert!(err.starts_with("changed-on-disk:"), "{err}");
        save_with(&ks, source.to_str().unwrap(), "pw123456", Format::Pkcs12, SavePolicy { force: true, ..Default::default() }).unwrap();

        // A path spelled differently (here through `..`) is still the source file.
        ks.source_mtime_ms = Some(1);
        let indirect = dir.path().join("sub").join("..").join("source.p12");
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let err = save(&ks, indirect.to_str().unwrap(), "pw123456", Format::Pkcs12).unwrap_err();
        assert!(err.starts_with("changed-on-disk:"), "{err}");
    }
}
