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
}

impl Format {
    pub fn parse(name: &str) -> Res<Format> {
        match name.trim().to_ascii_uppercase().replace(['#', '-'], "").as_str() {
            "PKCS12" | "P12" | "PFX" => Ok(Format::Pkcs12),
            "JKS" => Ok(Format::Jks),
            "JCEKS" => Ok(Format::Jceks),
            "BKS" | "BCFKS" | "UBER" => Err(format!(
                "{name} (Bouncy Castle) keystores are not supported.\n\n{}",
                if name.trim().eq_ignore_ascii_case("BCFKS") { Unsupported::Bcfks } else { Unsupported::BksOrUber }.conversion_hint("your-keystore")
            )),
            other => Err(format!("unsupported keystore format '{other}'")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Pkcs12 => "PKCS12",
            Format::Jks => "JKS",
            Format::Jceks => "JCEKS",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Pkcs12 => "p12",
            Format::Jks => "jks",
            Format::Jceks => "jceks",
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

/// A Bouncy Castle keystore format xkeystore cannot open, recognised well enough to tell the user
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
        format!(
            "Convert it to PKCS#12 with Bouncy Castle on the classpath:\n\
             keytool -importkeystore -srcstoretype {} -srckeystore \"{path}\" -deststoretype PKCS12 -destkeystore converted.p12 \\\n  \
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
    // BKS/UBER begin with a 4-byte version (1, 2 or 3) followed by a salt length. Bouncy Castle
    // uses a 20-byte salt by default; 16 and 32 also occur.
    if bytes.len() > 12 {
        let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let salt_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let iterations = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        // The iteration count rules out files that merely start with small integers: Bouncy Castle
        // writes at least 1024, and a plausible upper bound keeps random data out.
        if (1..=3).contains(&version) && matches!(salt_len, 16 | 20 | 32) && (1024..=10_000_000).contains(&iterations) {
            return Some(Unsupported::BksOrUber);
        }
    }
    None
}

/// Recognises the cleartext outer structure of a BCFKS file: `SEQUENCE { version INTEGER, … }`.
fn looks_like_bcfks(bytes: &[u8]) -> bool {
    yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            let version = r.next().read_u64()?;
            // Reject anything that is not a version BCFKS actually uses, so a PKCS#12 file (whose
            // version is 3) is not misreported. PKCS#12 is detected before this is reached, but
            // the check costs nothing and keeps the function honest on its own.
            if version != 1 && version != 2 {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            // The next element is the store's encryption/integrity AlgorithmIdentifier or the
            // ObjectStoreData itself; either way a constructed value follows. Reading it as raw
            // DER confirms the outer framing without committing to the whole schema.
            let next = r.next().read_der()?;
            if next.first().map(|t| t & 0x20 == 0) != Some(false) {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            Ok(())
        })
    })
    .is_ok()
}

pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<(Format, Vec<crate::model::KeystoreEntry>)> {
    let format = match detect(bytes) {
        Some(f) => f,
        None => {
            if let Some(kind) = detect_unsupported(bytes) {
                return Err(format!(
                    "this is a Bouncy Castle {} keystore, which xkeystore cannot open.\n\n{}",
                    kind.name(),
                    kind.conversion_hint("your-keystore")
                ));
            }
            return Err("not a recognised keystore (expected PKCS#12, JKS or JCEKS)".into());
        }
    };
    let entries = match format {
        Format::Pkcs12 => pkcs12::decode(bytes, password)?,
        Format::Jks | Format::Jceks => jks::decode(bytes, password, key_passwords)?,
    };
    Ok((format, entries))
}

pub fn encode(entries: &[crate::model::KeystoreEntry], password: &str, format: Format) -> Res<Vec<u8>> {
    if password.is_empty() {
        return Err("a keystore password is required".into());
    }
    match format {
        Format::Pkcs12 => pkcs12::encode(entries, password),
        Format::Jks => jks::encode(entries, password, jks::Kind::Jks),
        Format::Jceks => jks::encode(entries, password, jks::Kind::Jceks),
    }
}

fn file_timestamps(path: &Path) -> (String, String) {
    let meta = std::fs::metadata(path).ok();
    let fmt = |t: Option<std::time::SystemTime>| {
        t.map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
    };
    (fmt(meta.as_ref().and_then(|m| m.created().ok())), fmt(meta.as_ref().and_then(|m| m.modified().ok())))
}

pub fn open(path: &str, password: &str, key_passwords: &HashMap<String, String>) -> Res<KeystoreFile> {
    let p = Path::new(path);
    let bytes = std::fs::read(p).map_err(|err| format!("cannot read {path}: {err}"))?;
    let (format, entries) = decode(&bytes, password, key_passwords)?;
    let (created, modified) = file_timestamps(p);
    Ok(KeystoreFile {
        id: format!("ks-{}", uuid::Uuid::new_v4()),
        name: file_name_of(path),
        format: format.name().into(),
        path: path.to_string(),
        description: format!("{} keystore", format.name()),
        password_protected: true,
        created_at: created,
        updated_at: modified,
        entries,
    })
}

/// Encodes and atomically writes the keystore. Returns the written byte count.
pub fn save(ks: &KeystoreFile, path: &str, password: &str, format: Format) -> Res<usize> {
    let bytes = encode(&ks.entries, password, format)?;
    // Prove the file reads back before replacing anything on disk.
    decode(&bytes, password, &HashMap::new()).map_err(|err| format!("internal error: the encoded keystore does not read back ({err})"))?;
    write_atomic(Path::new(path), &bytes)?;
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
    fn unsupported_format_names_give_a_usable_command() {
        let err = Format::parse("BCFKS").unwrap_err();
        assert!(err.contains("-srcstoretype BCFKS"), "{err}");
        let err = Format::parse("UBER").unwrap_err();
        assert!(err.contains("-srcstoretype BKS"), "{err}");
    }
}
