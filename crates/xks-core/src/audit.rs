//! A local, append-only audit log of what this app did to which identity.
//! Nothing here is sent anywhere; it is a plain JSON-Lines file the user
//! controls, and it exists because none of KeyStore Explorer, `keytool` or
//! the OpenSSL CLI record *who exported what, when* — useful the moment
//! more than one person touches the same keystore.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp_unix: i64,
    /// e.g. "export.pkcs12", "ca.issue", "import", "key.generate".
    pub action: String,
    pub alias: Option<String>,
    pub detail: String,
}

impl AuditEntry {
    pub fn now(action: impl Into<String>, alias: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            timestamp_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
            action: action.into(),
            alias: alias.map(str::to_string),
            detail: detail.into(),
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn record(&self, entry: &AuditEntry) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry)
            .map_err(|e| CoreError::Other(format!("could not serialize audit entry: {e}")))?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    pub fn read_all(&self) -> Result<Vec<AuditEntry>> {
        if !Path::new(&self.path).exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => out.push(entry),
                // A corrupt/partial line (e.g. the process was killed
                // mid-write) shouldn't make the whole log unreadable.
                Err(_) => continue,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip_in_append_order() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl"));
        log.record(&AuditEntry::now("key.generate", Some("alpha"), "EC P-256"))
            .unwrap();
        log.record(&AuditEntry::now("export.pkcs12", Some("alpha"), "modern AES"))
            .unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "key.generate");
        assert_eq!(entries[1].action, "export.pkcs12");
    }

    #[test]
    fn missing_log_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("does-not-exist.jsonl"));
        assert!(log.read_all().unwrap().is_empty());
    }
}
