//! Finds the keystores and certificate files under a folder, for folder workspaces. Nothing is
//! written, and no password is needed: keystores are only recognised, never opened.

use crate::util::Res;
use crate::{keystore, x509};
use serde::Serialize;
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 8;
const MAX_VISITED: usize = 20_000;
const MAX_FOUND: usize = 500;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

const KEYSTORE_EXTENSIONS: [&str; 10] = ["p12", "pfx", "jks", "jceks", "bks", "uber", "bcfks", "keystore", "ks", "truststore"];
const CERTIFICATE_EXTENSIONS: [&str; 7] = ["pem", "crt", "cer", "der", "p7b", "p7c", "pkipath"];
/// Build output and dependency folders: large, and not where anyone keeps their own certificates.
const SKIPPED_FOLDERS: [&str; 2] = ["node_modules", "target"];

#[derive(Debug, Clone, Serialize)]
pub struct FolderFile {
    pub path: String,
    pub name: String,
    /// "keystore" or "certificate".
    pub kind: String,
    pub keystore_format: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderScan {
    pub files: Vec<FolderFile>,
    /// A limit stopped the scan, so there may be files that are not listed.
    pub truncated: bool,
}

/// Lists keystore and certificate files under `root`, judged by content. Hidden files and folders
/// and symbolic links are skipped; unreadable subfolders and files are passed over.
pub fn scan(root: &str) -> Res<FolderScan> {
    let meta = std::fs::metadata(root).map_err(|err| format!("cannot read {root}: {err}"))?;
    if !meta.is_dir() {
        return Err(format!("{root} is not a folder"));
    }
    let mut out = FolderScan { files: Vec::new(), truncated: false };
    let mut visited = 0;
    let mut pending: Vec<(PathBuf, usize)> = vec![(PathBuf::from(root), 0)];
    let mut next = 0;
    // Breadth first, so a limit cuts off the deepest files rather than whole top-level folders.
    while next < pending.len() {
        let (dir, depth) = pending[next].clone();
        next += 1;
        let listing = match std::fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(err) if depth == 0 => return Err(format!("cannot read {root}: {err}")),
            Err(_) => continue,
        };
        let mut children: Vec<_> = listing.flatten().collect();
        children.sort_by_key(|c| c.file_name());
        for child in children {
            visited += 1;
            if visited > MAX_VISITED || out.files.len() >= MAX_FOUND {
                out.truncated = true;
                return Ok(out);
            }
            let name = child.file_name().to_string_lossy().into_owned();
            let Ok(kind) = child.file_type() else { continue };
            if name.starts_with('.') {
                continue;
            }
            if kind.is_dir() {
                if SKIPPED_FOLDERS.contains(&name.as_str()) {
                    continue;
                }
                if depth < MAX_DEPTH {
                    pending.push((child.path(), depth + 1));
                } else {
                    out.truncated = true;
                }
            } else if kind.is_file()
                && let Some(found) = classify(&child.path(), name)
            {
                out.files.push(found);
            }
        }
    }
    Ok(out)
}

fn classify(path: &Path, name: String) -> Option<FolderFile> {
    let extension = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    let (store_name, certificate_name) = match extension.as_deref() {
        Some(e) => (KEYSTORE_EXTENSIONS.contains(&e), CERTIFICATE_EXTENSIONS.contains(&e)),
        // Java's `cacerts` and many keystores have no extension.
        None => (true, false),
    };
    if !store_name && !certificate_name {
        return None;
    }
    if std::fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let found = |kind: &str, keystore_format: Option<String>| FolderFile { path: path.to_string_lossy().into_owned(), name, kind: kind.into(), keystore_format };
    if let Some(format) = keystore::detect(&bytes) {
        return Some(found("keystore", Some(format.name().to_string())));
    }
    (certificate_name && x509::certificates_from_bytes(&bytes).is_ok_and(|c| !c.is_empty())).then(|| found("certificate", None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_keystores_and_certificates_by_content() {
        let root = std::env::temp_dir().join(format!("xks-folder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["nested/deeper", ".hidden", "node_modules"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let store = include_bytes!("../tests/fixtures/sample.bcfks");
        let certificate = include_bytes!("../tests/fixtures/bouncycastle/trustedCertData.cer");
        for (name, bytes) in [
            ("nested/deeper/app.bcfks", &store[..]),
            ("cacerts", &store[..]),
            ("nested/root.cer", &certificate[..]),
            (".hidden/secret.bcfks", &store[..]),
            ("node_modules/dep.cer", &certificate[..]),
            ("notes.pem", &b"not a certificate"[..]),
            ("README", &b"hello"[..]),
            ("photo.png", &certificate[..]),
        ] {
            std::fs::write(root.join(name), bytes).unwrap();
        }
        let scan = scan(root.to_str().unwrap()).unwrap();
        let found: Vec<_> = scan.files.iter().map(|f| (f.name.as_str(), f.kind.as_str())).collect();
        assert_eq!(found, [("cacerts", "keystore"), ("root.cer", "certificate"), ("app.bcfks", "keystore")]);
        assert!(!scan.truncated);
        assert!(super::scan(root.join("README").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
