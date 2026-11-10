//! Keystore format detection and the open/save entry points used by the commands.

use crate::jks;
use crate::model::KeystoreFile;
use crate::pkcs12;
use crate::util::*;
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pkcs12,
    Jks,
    Jceks,
    /// Read-only. Saving a BKS file is refused; save as PKCS#12 instead.
    Bks,
}

impl Format {
    pub fn parse(name: &str) -> Res<Format> {
        match name.trim().to_ascii_uppercase().replace(['#', '-'], "").as_str() {
            "PKCS12" | "P12" | "PFX" => Ok(Format::Pkcs12),
            "JKS" => Ok(Format::Jks),
            "JCEKS" => Ok(Format::Jceks),
            "BKS" | "BCFKS" | "UBER" => Err(format!(
                "unsupported: {name} (Bouncy Castle) keystores are not supported.\n\n{}",
                if name.trim().eq_ignore_ascii_case("BCFKS") { Unsupported::Bcfks } else { Unsupported::BksOrUber }.conversion_hint("your-keystore")
            )),
            other => Err(format!("unsupported: keystore format '{other}'")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Pkcs12 => "PKCS12",
            Format::Jks => "JKS",
            Format::Jceks => "JCEKS",
            Format::Bks => "BKS",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Pkcs12 => "p12",
            Format::Jks => "jks",
            Format::Jceks => "jceks",
            Format::Bks => "bks",
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
    None
}

/// A Bouncy Castle keystore format Keystore Studio cannot open, recognised well enough to tell the user
/// exactly which one it is and how to convert it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// BKS or UBER: a proprietary binary layout. The two share a header shape, and telling them
    /// apart needs the store password (UBER encrypts the whole file), so they are reported
    /// together.
    BksOrUber,
    /// BCFKS: Bouncy Castle's modern ASN.1 format (`ObjectStore`, see RFC-style definition in the
    /// BC sources). Recognisable without the password because the outer structure is cleartext.
    Bcfks,
}

impl Unsupported {
    /// The `-srcstoretype` value `keytool` needs. Getting this wrong makes the suggested command
    /// fail, so BCFKS must not be reported as BKS.
    pub fn store_type(self) -> &'static str {
        match self {
            Unsupported::BksOrUber => "BKS",
            Unsupported::Bcfks => "BCFKS",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Unsupported::BksOrUber => "BKS or UBER",
            Unsupported::Bcfks => "BCFKS",
        }
    }

    /// A command the user can paste. `bcprov.jar` has to be downloaded separately, so name it
    /// rather than pretending the conversion works out of the box.
    pub fn conversion_hint(self, path: &str) -> String {
        let extra = match self {
            Unsupported::BksOrUber => " (use -srcstoretype UBER for .uber files)",
            Unsupported::Bcfks => "",
        };
        // One line, so it pastes into any shell: a `\` continuation works only in POSIX shells.
        format!(
            "Convert it to PKCS#12 with Bouncy Castle on the classpath{extra}:\n\
             keytool -importkeystore -srcstoretype {} -srckeystore \"{path}\" -deststoretype PKCS12 -destkeystore converted.p12 \
             -providerpath bcprov.jar -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider\n\
             Download bcprov.jar from https://www.bouncycastle.org/download/",
            self.store_type()
        )
    }
}

/// Best-effort recognition of keystore formats we cannot open, for a helpful error.
pub fn detect_unsupported(bytes: &[u8]) -> Option<Unsupported> {
    // BCFKS is a DER SEQUENCE whose first element is an integer version (1 or 2). Check this
    // first: it is a precise structural match, where the BKS test below is only a heuristic.
    if looks_like_bcfks(bytes) {
        return Some(Unsupported::Bcfks);
    }
    // BKS/UBER begin with a 4-byte version (1, 2 or 3) followed by a salt length, salt bytes, and
    // a 4-byte iteration count at offset `8 + salt_len`. Bouncy Castle uses a 20-byte salt by
    // default; 16 and 32 also occur.
    if bytes.len() >= 28 {
        let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let salt_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if (1..=3).contains(&version) && matches!(salt_len, 16 | 20 | 32) && bytes.len() >= 12 + salt_len && !looks_like_bks_v2(bytes) {
            let real_iter = u32::from_be_bytes(bytes[8 + salt_len..12 + salt_len].try_into().unwrap());
            let header_iter = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
            // The iteration count rules out files that merely start with small integers: Bouncy Castle
            // writes at least 1024, and a plausible upper bound keeps random data out.
            if (1024..=10_000_000).contains(&real_iter) || (bytes.len() == 12 + salt_len && (1024..=10_000_000).contains(&header_iter)) {
                return Some(Unsupported::BksOrUber);
            }
        }
    }
    None
}

fn looks_like_bks_body(body: &[u8]) -> bool {
    // A BKS v2 store ends with a 1-byte `0` terminator and a 20-byte HMAC-SHA1.
    if body.len() == 21 && body[0] == 0 {
        return true;
    }
    if body.len() < 1 + 2 + 8 + 4 + 20 || !matches!(body[0], 1..=4) {
        return false;
    }
    let alias_len = u16::from_be_bytes([body[1], body[2]]) as usize;
    if alias_len > 1024 || 3 + alias_len + 12 + 20 > body.len() {
        return false;
    }
    if std::str::from_utf8(&body[3..3 + alias_len]).is_err() {
        return false;
    }
    let chain_pos = 3 + alias_len + 8;
    let chain_len = u32::from_be_bytes(body[chain_pos..chain_pos + 4].try_into().unwrap());
    chain_len <= 64
}

/// Recognises the cleartext outer structure of a BKS v2 file.
pub fn looks_like_bks_v2(bytes: &[u8]) -> bool {
    if bytes.len() < 32 {
        return false;
    }
    let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let salt_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if version != 2 || salt_len != 20 {
        return false;
    }
    let at = 8 + salt_len as usize;
    if bytes.len() < at + 4 {
        return false;
    }
    let iterations = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    (1024..1_000_000).contains(&iterations) && looks_like_bks_body(&bytes[at + 4..])
}

fn looks_like_bcfks(bytes: &[u8]) -> bool {
    // Detection probes untrusted bytes with yasna. Without the length guard, a hostile indefinite
    // length overflows yasna's `self.pos + length` and aborts the process (CI keystore fuzz crash
    // 84d79cfc). Returning false here is correct: a file that fails the length check is not BCFKS.
    if crate::util::check_der_lengths(bytes).is_err() {
        return false;
    }
    let unencrypted_store = yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            let version = r.next().read_u64()?;
            if version != 1 && version != 2 {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            let next = r.next().read_der()?;
            if next.first().map(|t| t & 0x20 == 0) != Some(false) {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            while r.next().read_der().is_ok() {}
            Ok(())
        })
    })
    .is_ok();
    if unencrypted_store {
        return true;
    }
    // Encrypted BCFKS (`ObjectStore ::= SEQUENCE { EncryptedObjectStoreData, IntegrityCheck }`)
    // where `EncryptedObjectStoreData ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }`.
    yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            r.next().read_sequence(|r| {
                r.next().read_sequence(|r| {
                    let _alg_oid = r.next().read_oid()?;
                    while r.next().read_der().is_ok() {}
                    Ok(())
                })?;
                let _ciphertext = r.next().read_bytes()?;
                Ok(())
            })?;
            r.next().read_sequence(|r| {
                while r.next().read_der().is_ok() {}
                Ok(())
            })
        })
    })
    .is_ok()
}

pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<(Format, Vec<crate::model::KeystoreEntry>)> {
    let format = match detect(bytes) {
        Some(f) => f,
        None => {
            if looks_like_bks_v2(bytes) {
                let entries = crate::bks::decode(bytes, password, key_passwords)?;
                return Ok((Format::Bks, entries));
            }
            if let Some(kind) = detect_unsupported(bytes) {
                return Err(format!("unsupported: this is a Bouncy Castle {} keystore, which Keystore Studio cannot open.\n\n{}", kind.name(), kind.conversion_hint("your-keystore")));
            }
            return Err("unrecognized: not a recognised keystore (expected PKCS#12, JKS or JCEKS)".into());
        }
    };
    let entries = match format {
        Format::Pkcs12 => pkcs12::decode_with_key_passwords(bytes, password, key_passwords)?,
        Format::Jks | Format::Jceks => jks::decode(bytes, password, key_passwords)?,
        Format::Bks => crate::bks::decode(bytes, password, key_passwords)?,
    };
    Ok((format, entries))
}

pub fn encode(entries: &[crate::model::KeystoreEntry], password: &str, format: Format) -> Res<Vec<u8>> {
    if password.is_empty() {
        return Err("invalid: a keystore password is required".into());
    }
    match format {
        Format::Pkcs12 => pkcs12::encode(entries, password),
        Format::Jks => jks::encode(entries, password, jks::Kind::Jks),
        Format::Jceks => jks::encode(entries, password, jks::Kind::Jceks),
        Format::Bks => Err("unsupported: BKS is read-only. Save as PKCS#12 to keep the entries.".into()),
    }
}

fn file_timestamps(path: &Path) -> (String, String) {
    let meta = std::fs::metadata(path).ok();
    let fmt = |t: Option<std::time::SystemTime>| t.map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
    (fmt(meta.as_ref().and_then(|m| m.created().ok())), fmt(meta.as_ref().and_then(|m| m.modified().ok())))
}

pub fn open(path: &str, password: &str, key_passwords: &HashMap<String, String>) -> Res<KeystoreFile> {
    let p = Path::new(path);
    let bytes = std::fs::read(p).map_err(|err| format!("cannot read {path}: {err}"))?;
    let (format, entries) = decode(&bytes, password, key_passwords)?;
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
    })
}

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
    let bytes = match format {
        Format::Pkcs12 => crate::pkcs12::encode_with_mac(&ks.entries, password, policy.mac)?,
        Format::Jks => jks::encode(&ks.entries, password, jks::Kind::Jks)?,
        Format::Jceks => jks::encode(&ks.entries, password, jks::Kind::Jceks)?,
        Format::Bks => return Err("unsupported: BKS is read-only. Save as PKCS#12 to keep the entries.".into()),
    };
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

    #[test]
    fn supported_formats_are_never_reported_as_bouncy_castle() {
        // A real file of each supported format must detect normally and must not trip the
        // Bouncy Castle heuristics, or opening it would fail with a misleading error.
        let entry = crate::ops::generate_key_pair(&crate::ops::tests_support::input("k", "ECDSA", false), None).unwrap();
        for format in [Format::Pkcs12, Format::Jks, Format::Jceks] {
            let bytes = encode(std::slice::from_ref(&entry), "pw123456", format).unwrap();
            assert_eq!(detect(&bytes), Some(format));
            assert_eq!(detect_unsupported(&bytes), None, "{} misdetected as Bouncy Castle", format.name());
        }
    }

    #[test]
    fn bcfks_is_told_apart_from_bks() {
        // BCFKS: SEQUENCE { version 1, SEQUENCE {} }.
        let bcfks = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_sequence(|_| {});
            })
        });
        assert_eq!(detect_unsupported(&bcfks), Some(Unsupported::Bcfks));
        assert_eq!(Unsupported::Bcfks.store_type(), "BCFKS");

        // BKS: version 2, 20-byte salt, 8192 iterations.
        let mut bks = Vec::new();
        bks.extend(2u32.to_be_bytes());
        bks.extend(20u32.to_be_bytes());
        bks.extend(8192u32.to_be_bytes());
        bks.extend([0u8; 20]);
        assert_eq!(detect_unsupported(&bks), Some(Unsupported::BksOrUber));
        assert_eq!(Unsupported::BksOrUber.store_type(), "BKS");

        // The suggested command must name the right source type, otherwise it fails when pasted.
        assert!(Unsupported::Bcfks.conversion_hint("a.bcfks").contains("-srcstoretype BCFKS"));
        assert!(Unsupported::BksOrUber.conversion_hint("a.bks").contains("-srcstoretype BKS"));
    }

    #[test]
    fn ordinary_files_are_not_claimed_to_be_keystores() {
        for data in [&b"hello world"[..], &[0u8; 32], &[0xFF; 64], b"-----BEGIN CERTIFICATE-----\nAAAA\n"] {
            assert_eq!(detect(data), None);
            assert_eq!(detect_unsupported(data), None, "{data:?} misdetected");
        }
    }

    #[test]
    fn hostile_indefinite_ber_does_not_abort_detection() {
        // CI keystore fuzz crash 84d79cfc: yasna overflowed while looks_like_bcfks probed the bytes.
        let crash: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x01, 0xff, 0x22, 0x80, 0x80, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x17, 0x2e, 0x02, 0x02, 0x2a, 0x30, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x17, 0x86, 0xd1, 0x00, 0xff, 0xff, 0xff,
        ];
        assert_eq!(detect_unsupported(crash), None);
        assert!(decode(crash, "fuzz", &HashMap::new()).is_err());
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

    #[test]
    fn unsupported_format_names_give_a_usable_command() {
        let err = Format::parse("BCFKS").unwrap_err();
        assert!(err.contains("-srcstoretype BCFKS"), "{err}");
        let err = Format::parse("UBER").unwrap_err();
        assert!(err.contains("-srcstoretype BKS"), "{err}");
    }
}
