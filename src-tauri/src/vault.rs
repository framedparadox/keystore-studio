//! Master-key vault: an Argon2id-derived AES-256-GCM key that protects stored secrets (keystore
//! passwords) at rest. The derived key only ever lives in memory while the vault is unlocked.
//!
//! On disk (app data directory):
//! - `vault.json`: Argon2id salt/parameters and an encrypted check value used to verify a
//!   candidate master key. Never contains the key.
//! - `vault_secrets.json`: `{ id: { label, nonce, ciphertext, updated_at } }`, each secret sealed
//!   with AES-256-GCM under the vault key using a fresh random nonce.
//! - `vault_secrets.json.next`: present only while the master key is being changed (see
//!   [`VaultState::change_master_key`]).

use crate::util::{Res, random_bytes, write_atomic};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroize;

const CHECK_VALUE: &[u8] = b"xkeystore-vault-check-v1";
pub const MIN_MASTER_KEY_LEN: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2ParamsRecord {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2ParamsRecord {
    fn default() -> Self {
        // OWASP minimum for Argon2id: 19 MiB, 2 iterations, 1 lane.
        Self { m_cost: 19 * 1024, t_cost: 2, p_cost: 1 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    salt: String,
    argon2_params: Argon2ParamsRecord,
    check_nonce: String,
    check_ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedSecret {
    label: String,
    nonce: String,
    ciphertext: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub secret_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSummary {
    pub id: String,
    pub label: String,
    pub updated_at: String,
}

/// Tauri-managed vault session.
pub struct VaultState {
    dir: PathBuf,
    key: Mutex<Option<[u8; 32]>>,
    /// Held across every read-modify-write of the vault files. Commands run on separate threads,
    /// and two unsynchronised writers each read the map, add their secret and write it back, so
    /// the last write silently drops the other's secret.
    files: Mutex<()>,
}

impl VaultState {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, key: Mutex::new(None), files: Mutex::new(()) }
    }

    fn files_lock(&self) -> Res<std::sync::MutexGuard<'_, ()>> {
        self.files.lock().map_err(|_| "vault state poisoned".to_string())
    }

    /// The default location: `<data dir>/xkeystore`.
    pub fn default_dir() -> PathBuf {
        let mut d = dirs::data_dir().unwrap_or_else(std::env::temp_dir);
        d.push("xkeystore");
        d
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.dir.join("vault_secrets.json")
    }

    /// Secrets re-encrypted under a new master key, waiting for the vault file to switch over.
    fn staged_secrets_path(&self) -> PathBuf {
        self.dir.join("vault_secrets.json.next")
    }

    fn read_secrets_at(path: &std::path::Path) -> Res<BTreeMap<String, SealedSecret>> {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).map_err(|err| format!("the vault secrets file is corrupted: {err}")),
            Err(_) => Ok(BTreeMap::new()),
        }
    }

    fn read_vault(&self) -> Res<VaultFile> {
        let raw = std::fs::read_to_string(self.vault_path()).map_err(|_| "the vault has not been set up yet".to_string())?;
        serde_json::from_str(&raw).map_err(|err| format!("the vault file is corrupted: {err}"))
    }

    fn read_secrets(&self) -> Res<BTreeMap<String, SealedSecret>> {
        Self::read_secrets_at(&self.secrets_path())
    }

    fn write_secrets(&self, secrets: &BTreeMap<String, SealedSecret>) -> Res<()> {
        let json = serde_json::to_vec_pretty(secrets).map_err(|e| e.to_string())?;
        write_atomic(&self.secrets_path(), &json)
    }

    fn current_key(&self) -> Res<[u8; 32]> {
        self.key.lock().map_err(|_| "vault state poisoned".to_string())?.ok_or_else(|| "the vault is locked".to_string())
    }

    fn set_key(&self, key: Option<[u8; 32]>) -> Res<()> {
        let mut guard = self.key.lock().map_err(|_| "vault state poisoned".to_string())?;
        if let Some(mut old) = guard.take() {
            old.zeroize();
        }
        *guard = key;
        Ok(())
    }

    pub fn status(&self) -> Res<VaultStatus> {
        Ok(VaultStatus {
            exists: self.vault_path().is_file(),
            unlocked: self.key.lock().map_err(|_| "vault state poisoned".to_string())?.is_some(),
            secret_count: self.read_secrets().map(|s| s.len()).unwrap_or(0),
        })
    }

    pub fn init(&self, master_key: &str) -> Res<()> {
        if master_key.chars().count() < MIN_MASTER_KEY_LEN {
            return Err(format!("the master key must be at least {MIN_MASTER_KEY_LEN} characters"));
        }
        let _files = self.files_lock()?;
        if self.vault_path().is_file() {
            return Err("a vault already exists".into());
        }
        let (file, key) = new_vault_file(master_key)?;
        let json = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        write_atomic(&self.vault_path(), &json)?;
        // Remove secrets from a previous (reset) vault, which could never be decrypted anyway.
        let _ = std::fs::remove_file(self.secrets_path());
        let _ = std::fs::remove_file(self.staged_secrets_path());
        self.set_key(Some(key))
    }

    pub fn unlock(&self, master_key: &str) -> Res<()> {
        let _files = self.files_lock()?;
        let file = self.read_vault()?;
        let key = derive_and_check(master_key, &file)?;
        self.finish_interrupted_change(&key)?;
        self.set_key(Some(key))
    }

    pub fn lock(&self) -> Res<()> {
        self.set_key(None)
    }

    /// Rotates the master key and re-encrypts every stored secret under the new key.
    ///
    /// The vault file and the secrets file cannot be replaced together, and whichever is written
    /// first, a crash before the other leaves the master key unable to open the secrets. So the
    /// re-encrypted secrets are first staged in a file of their own; the vault file then switches
    /// to the new key; the staged file then replaces the secrets. A crash at any point leaves a
    /// state that [`Self::finish_interrupted_change`] completes or rolls back on the next unlock.
    pub fn change_master_key(&self, old_master_key: &str, new_master_key: &str) -> Res<()> {
        if new_master_key.chars().count() < MIN_MASTER_KEY_LEN {
            return Err(format!("the new master key must be at least {MIN_MASTER_KEY_LEN} characters"));
        }
        let _files = self.files_lock()?;
        let old_file = self.read_vault()?;
        let mut old_key = derive_and_check(old_master_key, &old_file)?;
        // An earlier change that was interrupted is settled first, under the key that opens the vault now.
        self.finish_interrupted_change(&old_key)?;
        let (new_file, new_key) = new_vault_file(new_master_key)?;
        let mut secrets = self.read_secrets()?;
        for (id, sealed) in secrets.iter_mut() {
            let mut plain = open(&old_key, id, sealed)?;
            // Re-encrypting is not an update of the secret: keep when it was last stored.
            let updated_at = std::mem::take(&mut sealed.updated_at);
            *sealed = seal(&new_key, id, &sealed.label, &plain)?;
            sealed.updated_at = updated_at;
            plain.zeroize();
        }
        old_key.zeroize();
        self.stage_secrets(&secrets)?;
        self.commit_vault_file(&new_file)?;
        self.promote_staged_secrets()?;
        self.set_key(Some(new_key))
    }

    /// Step 1 of a master key change: the re-encrypted secrets, beside the live ones.
    fn stage_secrets(&self, secrets: &BTreeMap<String, SealedSecret>) -> Res<()> {
        let json = serde_json::to_vec_pretty(secrets).map_err(|e| e.to_string())?;
        write_atomic(&self.staged_secrets_path(), &json)
    }

    /// Step 2: from here on the new master key opens the vault.
    fn commit_vault_file(&self, file: &VaultFile) -> Res<()> {
        let json = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
        write_atomic(&self.vault_path(), &json)
    }

    /// Step 3: the staged secrets become the live ones.
    fn promote_staged_secrets(&self) -> Res<()> {
        std::fs::rename(self.staged_secrets_path(), self.secrets_path()).map_err(|err| format!("cannot update the vault secrets: {err}"))?;
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Settles a master key change that a crash interrupted, given the key that opens the vault
    /// file now. If that key opens the staged secrets, the vault file had already switched over
    /// and the change is completed. Otherwise the vault file never switched, the live secrets are
    /// still the right ones, and the staged copy is discarded.
    fn finish_interrupted_change(&self, key: &[u8; 32]) -> Res<()> {
        let staged_path = self.staged_secrets_path();
        if !staged_path.exists() {
            return Ok(());
        }
        let staged = Self::read_secrets_at(&staged_path).unwrap_or_default();
        let opens = |s: &BTreeMap<String, SealedSecret>| {
            s.iter().all(|(id, sealed)| {
                open(key, id, sealed)
                    .map(|mut p| {
                        p.zeroize();
                        true
                    })
                    .unwrap_or(false)
            })
        };
        // With no secrets either way there is nothing to choose between; keep the live file.
        if !staged.is_empty() && opens(&staged) { self.promote_staged_secrets() } else { std::fs::remove_file(&staged_path).map_err(|err| format!("cannot remove {}: {err}", staged_path.display())) }
    }

    /// Deletes the vault and every stored secret (used when the master key is forgotten).
    pub fn reset(&self) -> Res<()> {
        let _files = self.files_lock()?;
        self.set_key(None)?;
        for p in [self.vault_path(), self.secrets_path(), self.staged_secrets_path()] {
            if p.exists() {
                std::fs::remove_file(&p).map_err(|err| format!("cannot delete {}: {err}", p.display()))?;
            }
        }
        Ok(())
    }

    pub fn store_secret(&self, id: &str, label: &str, secret: &str) -> Res<()> {
        if id.trim().is_empty() {
            return Err("secret id must not be empty".into());
        }
        let _files = self.files_lock()?;
        let mut key = self.current_key()?;
        let mut secrets = self.read_secrets()?;
        let sealed = seal(&key, id, label, secret.as_bytes());
        key.zeroize();
        secrets.insert(id.to_string(), sealed?);
        self.write_secrets(&secrets)
    }

    pub fn get_secret(&self, id: &str) -> Res<Option<String>> {
        // Under the file lock: during a master key change the secrets file switches to the new key
        // before the in-memory key does, and a read in between would fail to decrypt.
        let _files = self.files_lock()?;
        let mut key = self.current_key()?;
        let secrets = self.read_secrets()?;
        let plain = secrets.get(id).map(|sealed| open(&key, id, sealed));
        key.zeroize();
        match plain {
            None => Ok(None),
            Some(plain) => String::from_utf8(plain?).map(Some).map_err(|_| "stored secret is not valid UTF-8".to_string()),
        }
    }

    pub fn delete_secret(&self, id: &str) -> Res<()> {
        let _files = self.files_lock()?;
        let mut secrets = self.read_secrets()?;
        if secrets.remove(id).is_some() {
            self.write_secrets(&secrets)?;
        }
        Ok(())
    }

    pub fn list_secrets(&self) -> Res<Vec<SecretSummary>> {
        let _files = self.files_lock()?;
        Ok(self.read_secrets()?.into_iter().map(|(id, s)| SecretSummary { id, label: s.label, updated_at: s.updated_at }).collect())
    }
}

fn derive_key(master_key: &str, salt: &[u8], p: &Argon2ParamsRecord) -> Res<[u8; 32]> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32)).map_err(|err| format!("invalid Argon2 parameters: {err}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(master_key.as_bytes(), salt, &mut key).map_err(|err| format!("key derivation failed: {err}"))?;
    Ok(key)
}

fn new_vault_file(master_key: &str) -> Res<(VaultFile, [u8; 32])> {
    let salt = random_bytes(16);
    let params = Argon2ParamsRecord::default();
    let key = derive_key(master_key, &salt, &params)?;
    let nonce = random_bytes(12);
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key)).encrypt(Nonce::from_slice(&nonce), CHECK_VALUE).map_err(|_| "failed to encrypt the vault check value".to_string())?;
    Ok((VaultFile { salt: B64.encode(salt), argon2_params: params, check_nonce: B64.encode(nonce), check_ciphertext: B64.encode(ct) }, key))
}

fn derive_and_check(master_key: &str, file: &VaultFile) -> Res<[u8; 32]> {
    let salt = B64.decode(&file.salt).map_err(|_| "the vault file is corrupted".to_string())?;
    let mut key = derive_key(master_key, &salt, &file.argon2_params)?;
    let nonce = B64.decode(&file.check_nonce).map_err(|_| "the vault file is corrupted".to_string())?;
    let ct = B64.decode(&file.check_ciphertext).map_err(|_| "the vault file is corrupted".to_string())?;
    let ok = nonce.len() == 12 && Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key)).decrypt(Nonce::from_slice(&nonce), ct.as_slice()).map(|pt| pt == CHECK_VALUE).unwrap_or(false);
    if !ok {
        key.zeroize();
        return Err("incorrect master key".into());
    }
    Ok(key)
}

/// Seals `plain` with the secret id as associated data, so ciphertexts cannot be swapped
/// between entries.
fn seal(key: &[u8; 32], id: &str, label: &str, plain: &[u8]) -> Res<SealedSecret> {
    let nonce = random_bytes(12);
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)).encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: id.as_bytes() }).map_err(|_| "failed to encrypt secret".to_string())?;
    Ok(SealedSecret { label: label.to_string(), nonce: B64.encode(nonce), ciphertext: B64.encode(ct), updated_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string() })
}

fn open(key: &[u8; 32], id: &str, sealed: &SealedSecret) -> Res<Vec<u8>> {
    let nonce = B64.decode(&sealed.nonce).map_err(|_| "corrupt secret".to_string())?;
    let ct = B64.decode(&sealed.ciphertext).map_err(|_| "corrupt secret".to_string())?;
    if nonce.len() != 12 {
        return Err("corrupt secret".into());
    }
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: id.as_bytes() })
        .map_err(|_| "a stored secret could not be decrypted (wrong key or tampered file)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> (tempfile::TempDir, VaultState) {
        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path().to_path_buf());
        (dir, v)
    }

    #[test]
    fn lifecycle_with_secrets_and_rotation() {
        let (_d, v) = vault();
        assert!(!v.status().unwrap().exists);
        assert!(v.init("short").is_err());
        v.init("correct horse battery").unwrap();
        assert!(v.init("another-master-key").is_err());
        v.store_secret("/tmp/a.p12", "a.p12", "storepass-a").unwrap();
        v.store_secret("/tmp/b.jks", "b.jks", "storepass-b").unwrap();
        assert_eq!(v.get_secret("/tmp/a.p12").unwrap().as_deref(), Some("storepass-a"));
        assert_eq!(v.list_secrets().unwrap().len(), 2);

        v.lock().unwrap();
        assert!(v.get_secret("/tmp/a.p12").is_err());
        assert_eq!(v.unlock("wrong master key").unwrap_err(), "incorrect master key");
        v.unlock("correct horse battery").unwrap();

        assert!(v.change_master_key("not it", "new master key!").is_err());
        v.change_master_key("correct horse battery", "new master key!").unwrap();
        v.lock().unwrap();
        assert!(v.unlock("correct horse battery").is_err());
        v.unlock("new master key!").unwrap();
        assert_eq!(v.get_secret("/tmp/b.jks").unwrap().as_deref(), Some("storepass-b"));

        v.delete_secret("/tmp/b.jks").unwrap();
        assert_eq!(v.get_secret("/tmp/b.jks").unwrap(), None);
        v.reset().unwrap();
        assert!(!v.status().unwrap().exists);
        assert_eq!(v.status().unwrap().secret_count, 0);
    }

    #[test]
    fn concurrent_writes_keep_every_secret() {
        // Each command runs on its own thread. Without the file lock, two writers both read the
        // map, add their secret and write it back, and the slower one drops the other's secret.
        let (_d, v) = vault();
        v.init("master-key-123").unwrap();
        let v = std::sync::Arc::new(v);
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let v = v.clone();
                std::thread::spawn(move || v.store_secret(&format!("id-{i}"), &format!("label-{i}"), &format!("secret-{i}")).unwrap())
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(v.list_secrets().unwrap().len(), 16);
        for i in 0..16 {
            assert_eq!(v.get_secret(&format!("id-{i}")).unwrap().as_deref(), Some(format!("secret-{i}").as_str()));
        }
    }

    /// Runs a master key change up to (not including) `stop_before`, as if the app crashed there.
    fn interrupted_change(v: &VaultState, old: &str, new: &str, stop_before: u8) {
        let old_key = derive_and_check(old, &v.read_vault().unwrap()).unwrap();
        let (new_file, new_key) = new_vault_file(new).unwrap();
        let mut secrets = v.read_secrets().unwrap();
        for (id, sealed) in secrets.iter_mut() {
            *sealed = seal(&new_key, id, &sealed.label, &open(&old_key, id, sealed).unwrap()).unwrap();
        }
        if stop_before > 1 {
            v.stage_secrets(&secrets).unwrap();
        }
        if stop_before > 2 {
            v.commit_vault_file(&new_file).unwrap();
        }
        v.lock().unwrap();
    }

    #[test]
    fn a_crash_while_changing_the_master_key_never_strands_secrets() {
        for stop_before in [1u8, 2, 3] {
            let (_d, v) = vault();
            v.init("old master key").unwrap();
            v.store_secret("a", "a.p12", "pw-a").unwrap();
            v.store_secret("b", "b.jks", "pw-b").unwrap();
            interrupted_change(&v, "old master key", "new master key", stop_before);

            // Whichever key opens the vault after the crash also opens every secret.
            let key = if stop_before > 2 { "new master key" } else { "old master key" };
            let other = if stop_before > 2 { "old master key" } else { "new master key" };
            assert!(v.unlock(other).is_err(), "step {stop_before}: the other key must not open the vault");
            v.unlock(key).unwrap_or_else(|e| panic!("step {stop_before}: {e}"));
            assert_eq!(v.get_secret("a").unwrap().as_deref(), Some("pw-a"), "step {stop_before}");
            assert_eq!(v.get_secret("b").unwrap().as_deref(), Some("pw-b"), "step {stop_before}");
            assert!(!v.staged_secrets_path().exists(), "step {stop_before}: the staged file must be settled");

            // And the vault keeps working: a later change completes normally.
            v.change_master_key(key, "third master key").unwrap();
            v.lock().unwrap();
            v.unlock("third master key").unwrap();
            assert_eq!(v.get_secret("b").unwrap().as_deref(), Some("pw-b"), "step {stop_before}");
        }
    }

    #[test]
    fn changing_the_master_key_keeps_when_each_secret_was_stored() {
        let (_d, v) = vault();
        v.init("old master key").unwrap();
        v.store_secret("a", "a.p12", "pw-a").unwrap();
        let mut secrets = v.read_secrets().unwrap();
        secrets.get_mut("a").unwrap().updated_at = "2001-02-03 04:05".into();
        v.write_secrets(&secrets).unwrap();
        v.change_master_key("old master key", "new master key").unwrap();
        assert_eq!(v.list_secrets().unwrap()[0].updated_at, "2001-02-03 04:05");
        assert_eq!(v.get_secret("a").unwrap().as_deref(), Some("pw-a"));
    }

    #[test]
    fn swapped_ciphertexts_are_rejected() {
        let (_d, v) = vault();
        v.init("master-key-123").unwrap();
        v.store_secret("one", "1", "first").unwrap();
        v.store_secret("two", "2", "second").unwrap();
        let mut s = v.read_secrets().unwrap();
        let one = s["one"].clone();
        s.insert("two".into(), one);
        v.write_secrets(&s).unwrap();
        assert!(v.get_secret("two").is_err());
    }
}
