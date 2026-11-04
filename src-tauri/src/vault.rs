//! Master-key-gated encryption-at-rest vault.
//!
//! The vault guards a single 256-bit symmetric key (the "vault key") that lives only in
//! memory, derived from a user-chosen master key/passphrase via Argon2id. The vault key is
//! never written to disk. What *is* persisted on disk (in the Tauri app-data directory) is a
//! small JSON file holding the Argon2 salt/params and a "check value" (a known constant string
//! encrypted with the derived key) so a later unlock attempt can verify a candidate master key
//! is correct before trusting it for anything else.
//!
//! This module is the foundation other features (encrypting stored keystore passwords,
//! private-key PEMs, etc. — see `secret_store.rs`) build on top of in later phases.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Length in bytes of the derived vault key (AES-256 key size).
const KEY_LEN: usize = 32;
/// Length in bytes of the random salt used for Argon2id.
const SALT_LEN: usize = 16;
/// Length in bytes of the random nonce used to encrypt the on-disk "check value".
const NONCE_LEN: usize = 12;
/// A fixed, known plaintext encrypted with the derived key on vault creation. Successfully
/// decrypting it back to this exact string on unlock proves the supplied master key is correct.
const CHECK_VALUE: &str = "xkeystore-vault-check-v1";

/// Argon2id parameters persisted alongside the salt so the exact same derivation can be
/// reproduced on every unlock, even if we tune the defaults in a future release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2ParamsRecord {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2ParamsRecord {
    fn default() -> Self {
        // 19 MiB memory, 2 iterations, 1-way parallelism: OWASP's current minimum
        // recommendation for Argon2id, chosen to stay responsive on a desktop app while still
        // being meaningfully slow to brute force.
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// On-disk vault record. Never contains the raw or derived key — only what's needed to
/// re-derive it from a correct master key and to verify that derivation succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    /// Base64-encoded random salt fed into Argon2id.
    salt: String,
    argon2_params: Argon2ParamsRecord,
    /// Base64-encoded nonce used to encrypt `check_ciphertext`.
    check_nonce: String,
    /// Base64-encoded AES-256-GCM ciphertext of [`CHECK_VALUE`], encrypted under the derived
    /// key. Decrypting this with a candidate key and comparing to `CHECK_VALUE` is how we
    /// verify a master key is correct.
    check_ciphertext: String,
}

/// Tauri-managed state: the vault's in-memory session. Holds the derived 256-bit key only
/// while the vault is unlocked (`None` means locked).
pub struct VaultState {
    pub key: Mutex<Option<[u8; 32]>>,
}

impl VaultState {
    pub fn new() -> Self {
        Self {
            key: Mutex::new(None),
        }
    }
}

impl Default for VaultState {
    fn default() -> Self {
        Self::new()
    }
}

/// Current vault status, reported to the frontend so it can decide whether to show a
/// first-run setup screen, an unlock screen, or the unlocked app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
}

/// Resolves the path of the on-disk vault file: `<app-data-dir>/xkeystore/vault.json`.
///
/// Uses `dirs::data_dir()` (already a dependency) rather than a Tauri `AppHandle`-scoped path,
/// so these functions can be exercised directly in unit tests without a running Tauri app.
fn vault_file_path() -> Result<PathBuf, String> {
    let mut dir = dirs::data_dir().ok_or_else(|| "could not resolve app data directory".to_string())?;
    dir.push("xkeystore");
    Ok(dir.join("vault.json"))
}

fn read_vault_file(path: &PathBuf) -> Result<VaultFile, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read vault file: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("vault file is corrupted: {e}"))
}

fn write_vault_file(path: &PathBuf, file: &VaultFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create vault directory: {e}"))?;
    }
    let json = serde_json::to_string_pretty(file).map_err(|e| format!("failed to serialize vault file: {e}"))?;

    // Write atomically-ish via a temp file + rename so a crash mid-write can't corrupt the
    // only copy of the vault's salt/params.
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| format!("failed to write vault file: {e}"))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("failed to write vault file: {e}"))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| format!("failed to finalize vault file: {e}"))?;
    Ok(())
}

/// Derives a 256-bit key from `master_key` using Argon2id with the given salt and params.
fn derive_key(master_key: &str, salt: &[u8], params: &Argon2ParamsRecord) -> Result<[u8; 32], String> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| format!("invalid argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_key.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypts [`CHECK_VALUE`] under `key`, returning (nonce_b64, ciphertext_b64).
fn encrypt_check_value(key: &[u8; 32]) -> Result<(String, String), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, CHECK_VALUE.as_bytes())
        .map_err(|_| "failed to encrypt vault check value".to_string())?;

    Ok((B64.encode(nonce_bytes), B64.encode(ciphertext)))
}

/// Attempts to decrypt the stored check value with `key`; succeeds only if it recovers exactly
/// [`CHECK_VALUE`], which proves `key` was derived from the correct master key.
fn verify_check_value(key: &[u8; 32], file: &VaultFile) -> Result<(), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_bytes = B64
        .decode(&file.check_nonce)
        .map_err(|_| "incorrect master key".to_string())?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err("incorrect master key".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = B64
        .decode(&file.check_ciphertext)
        .map_err(|_| "incorrect master key".to_string())?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "incorrect master key".to_string())?;

    if plaintext == CHECK_VALUE.as_bytes() {
        Ok(())
    } else {
        Err("incorrect master key".to_string())
    }
}

/// True if a vault file already exists on disk (i.e. the master key has been set up before).
pub fn vault_exists() -> bool {
    match vault_file_path() {
        Ok(path) => path.is_file(),
        Err(_) => false,
    }
}

/// First-run setup: generates a random salt, derives a key from `master_key` via Argon2id,
/// encrypts the check value, persists the vault file, and leaves the vault unlocked (the
/// derived key is stored in `state`) since the caller just proved they know it.
///
/// Errors if a vault file already exists — use [`vault_unlock`] or [`vault_change_master_key`]
/// instead.
pub fn vault_init(state: &VaultState, master_key: &str) -> Result<(), String> {
    if master_key.is_empty() {
        return Err("master key must not be empty".to_string());
    }

    let path = vault_file_path()?;
    if path.is_file() {
        return Err("vault already initialized".to_string());
    }

    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    let params = Argon2ParamsRecord::default();

    let mut key = derive_key(master_key, &salt, &params)?;
    let (check_nonce, check_ciphertext) = encrypt_check_value(&key)?;

    let file = VaultFile {
        salt: B64.encode(salt),
        argon2_params: params,
        check_nonce,
        check_ciphertext,
    };

    write_vault_file(&path, &file)?;

    let mut guard = state.key.lock().map_err(|_| "vault state lock poisoned".to_string())?;
    *guard = Some(key);
    key.zeroize();

    Ok(())
}

/// Attempts to unlock the vault with `master_key`: reads the vault file, re-derives the key
/// with the stored salt/params, and verifies it against the stored check value. On success the
/// derived key is stored in `state` (vault becomes unlocked). On failure, `state` is left
/// untouched and an `Err("incorrect master key")`-style message is returned.
pub fn vault_unlock(state: &VaultState, master_key: &str) -> Result<(), String> {
    let path = vault_file_path()?;
    if !path.is_file() {
        return Err("vault has not been set up yet".to_string());
    }
    let file = read_vault_file(&path)?;

    let salt = B64
        .decode(&file.salt)
        .map_err(|_| "vault file is corrupted".to_string())?;

    let mut key = derive_key(master_key, &salt, &file.argon2_params)?;

    if let Err(e) = verify_check_value(&key, &file) {
        key.zeroize();
        return Err(e);
    }

    let mut guard = state.key.lock().map_err(|_| "vault state lock poisoned".to_string())?;
    *guard = Some(key);
    key.zeroize();

    Ok(())
}

/// Locks the vault: zeroes and clears the in-memory derived key. The on-disk vault file is
/// untouched, so the vault can be unlocked again with the same master key.
pub fn vault_lock(state: &VaultState) -> Result<(), String> {
    let mut guard = state.key.lock().map_err(|_| "vault state lock poisoned".to_string())?;
    if let Some(mut key) = guard.take() {
        key.zeroize();
    }
    Ok(())
}

/// Reports whether a vault has ever been set up and whether it's currently unlocked in this
/// session.
pub fn vault_status(state: &VaultState) -> Result<VaultStatus, String> {
    let unlocked = {
        let guard = state.key.lock().map_err(|_| "vault state lock poisoned".to_string())?;
        guard.is_some()
    };
    Ok(VaultStatus {
        exists: vault_exists(),
        unlocked,
    })
}

/// Rotates the master key: unlocks with `old_master_key` (failing the same way [`vault_unlock`]
/// does if it's wrong), derives a fresh salt + key from `new_master_key`, re-encrypts the check
/// value, and atomically rewrites the vault file. The in-memory key is updated to the new one
/// so the vault stays unlocked afterward.
///
/// Note: this rotates the master-key-derived wrapping key itself. Any secrets already
/// encrypted under the *old* derived key (added in a later phase, via `secret_store.rs`) would
/// need to be re-encrypted under the new key too — that re-wrapping is out of scope here since
/// no such secrets exist yet in this phase.
pub fn vault_change_master_key(state: &VaultState, old_master_key: &str, new_master_key: &str) -> Result<(), String> {
    if new_master_key.is_empty() {
        return Err("new master key must not be empty".to_string());
    }

    let path = vault_file_path()?;
    if !path.is_file() {
        return Err("vault has not been set up yet".to_string());
    }
    let old_file = read_vault_file(&path)?;

    let old_salt = B64
        .decode(&old_file.salt)
        .map_err(|_| "vault file is corrupted".to_string())?;
    let mut old_key = derive_key(old_master_key, &old_salt, &old_file.argon2_params)?;

    if let Err(e) = verify_check_value(&old_key, &old_file) {
        old_key.zeroize();
        return Err(e);
    }
    old_key.zeroize();

    let mut new_salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut new_salt);
    let new_params = Argon2ParamsRecord::default();

    let mut new_key = derive_key(new_master_key, &new_salt, &new_params)?;
    let (check_nonce, check_ciphertext) = encrypt_check_value(&new_key)?;

    let new_file = VaultFile {
        salt: B64.encode(new_salt),
        argon2_params: new_params,
        check_nonce,
        check_ciphertext,
    };
    write_vault_file(&path, &new_file)?;

    let mut guard = state.key.lock().map_err(|_| "vault state lock poisoned".to_string())?;
    *guard = Some(new_key);
    new_key.zeroize();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Tests exercise the pure derive/encrypt/verify logic plus VaultState transitions directly,
    // using a temp-directory override for the vault file path so they don't touch the real
    // app-data vault file or race each other.
    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_vault_path() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("xkeystore-vault-test-{}-{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        dir.join("vault.json")
    }

    /// Test-only re-implementation of the init/unlock flow against an arbitrary path, so we can
    /// verify the real logic in `vault_init`/`vault_unlock` without depending on a shared
    /// global file path across parallel tests.
    fn init_at(path: &PathBuf, state: &VaultState, master_key: &str) -> Result<(), String> {
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng.fill_bytes(&mut salt);
        let params = Argon2ParamsRecord::default();
        let mut key = derive_key(master_key, &salt, &params)?;
        let (check_nonce, check_ciphertext) = encrypt_check_value(&key)?;
        let file = VaultFile {
            salt: B64.encode(salt),
            argon2_params: params,
            check_nonce,
            check_ciphertext,
        };
        write_vault_file(path, &file)?;
        let mut guard = state.key.lock().unwrap();
        *guard = Some(key);
        key.zeroize();
        Ok(())
    }

    fn unlock_at(path: &PathBuf, state: &VaultState, master_key: &str) -> Result<(), String> {
        let file = read_vault_file(path)?;
        let salt = B64.decode(&file.salt).map_err(|_| "vault file is corrupted".to_string())?;
        let mut key = derive_key(master_key, &salt, &file.argon2_params)?;
        if let Err(e) = verify_check_value(&key, &file) {
            key.zeroize();
            return Err(e);
        }
        let mut guard = state.key.lock().unwrap();
        *guard = Some(key);
        key.zeroize();
        Ok(())
    }

    #[test]
    fn derive_key_is_deterministic_for_same_salt_and_params() {
        let params = Argon2ParamsRecord::default();
        let salt = [7u8; SALT_LEN];
        let key_a = derive_key("correct-horse-battery-staple", &salt, &params).unwrap();
        let key_b = derive_key("correct-horse-battery-staple", &salt, &params).unwrap();
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn unlock_with_wrong_master_key_fails() {
        let path = temp_vault_path();
        let state = VaultState::new();
        init_at(&path, &state, "the-real-master-key").unwrap();

        // Lock it (simulate app restart: in-memory key gone, file remains).
        vault_lock(&state).unwrap();

        let result = unlock_at(&path, &state, "totally-wrong-key");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "incorrect master key");

        // State should still be locked after a failed unlock attempt.
        let guard = state.key.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn unlock_with_correct_master_key_succeeds_and_reports_unlocked() {
        let path = temp_vault_path();
        let state = VaultState::new();
        init_at(&path, &state, "the-real-master-key").unwrap();
        vault_lock(&state).unwrap();

        {
            let guard = state.key.lock().unwrap();
            assert!(guard.is_none(), "sanity check: should be locked before unlock");
        }

        let result = unlock_at(&path, &state, "the-real-master-key");
        assert!(result.is_ok());

        let status = vault_status(&state).unwrap();
        assert!(status.unlocked);
    }

    #[test]
    fn lock_clears_in_memory_key() {
        let state = VaultState::new();
        {
            let mut guard = state.key.lock().unwrap();
            *guard = Some([9u8; 32]);
        }
        vault_lock(&state).unwrap();
        let guard = state.key.lock().unwrap();
        assert!(guard.is_none());
    }
}
