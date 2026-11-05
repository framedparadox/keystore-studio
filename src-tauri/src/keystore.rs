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
                "{name} (Bouncy Castle) keystores are not supported. Convert it first: keytool -importkeystore -srcstoretype {name} -providerpath bcprov.jar -deststoretype PKCS12"
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

/// Best-effort recognition of keystore formats we cannot open, for a helpful error.
pub fn detect_unsupported(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() > 12 {
        let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let salt_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if (version == 1 || version == 2) && (salt_len == 20 || salt_len == 16) {
            return Some("BKS/UBER");
        }
    }
    None
}

pub fn decode(bytes: &[u8], password: &str, key_passwords: &HashMap<String, String>) -> Res<(Format, Vec<crate::model::KeystoreEntry>)> {
    let format = match detect(bytes) {
        Some(f) => f,
        None => {
            if let Some(kind) = detect_unsupported(bytes) {
                return Err(format!(
                    "this looks like a Bouncy Castle {kind} keystore, which xkeystore cannot open. Convert it with: keytool -importkeystore -srcstoretype BKS -providerpath bcprov.jar -deststoretype PKCS12"
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
