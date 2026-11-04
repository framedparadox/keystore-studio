//! Symmetric encryption primitives used to protect secrets at rest (keystore private keys,
//! secret key material, and stored passphrases) once the vault is unlocked.
//!
//! This module only provides the primitives: encrypting/decrypting a blob with an already
//! -derived 256-bit key, and pulling that key out of [`crate::vault::VaultState`] if the vault
//! is currently unlocked. Wiring this into the existing `KeystoreEntry`-producing commands in
//! `crypto.rs` is a later phase.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::vault::VaultState;

/// Length in bytes of the random nonce AES-256-GCM uses per encryption (96 bits, the
/// standard/recommended nonce size for GCM).
const NONCE_LEN: usize = 12;

/// An encrypted secret, ready to be stored on disk or in a `KeystoreEntry`. Both fields are
/// base64-encoded so the struct serializes cleanly to/from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Base64-encoded 96-bit nonce used for this specific encryption. A fresh random nonce is
    /// generated on every call to [`encrypt_secret`] — nonces must never be reused with the
    /// same key.
    pub nonce: String,
    /// Base64-encoded AES-256-GCM ciphertext (includes the authentication tag).
    pub ciphertext: String,
}

/// Encrypts `plaintext` with AES-256-GCM under `key`, using a fresh random 96-bit nonce.
pub fn encrypt_secret(plaintext: &str, key: &[u8; 32]) -> Result<EncryptedBlob, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "failed to encrypt secret".to_string())?;

    Ok(EncryptedBlob {
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Decrypts `blob` with AES-256-GCM under `key`. Returns an error (never a partial/garbled
/// plaintext) if the key is wrong or the blob was tampered with, since GCM authenticates the
/// ciphertext.
pub fn decrypt_secret(blob: &EncryptedBlob, key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_bytes = B64
        .decode(&blob.nonce)
        .map_err(|_| "invalid nonce encoding".to_string())?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err("invalid nonce length".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = B64
        .decode(&blob.ciphertext)
        .map_err(|_| "invalid ciphertext encoding".to_string())?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "decryption failed: wrong key or corrupted data".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "decrypted data is not valid UTF-8".to_string())
}

/// Pulls the currently-unlocked 256-bit vault key out of managed state, or an error if the
/// vault is locked (no key resident in memory).
pub fn get_unlocked_key(vault_state: &VaultState) -> Result<[u8; 32], String> {
    let guard = vault_state
        .key
        .lock()
        .map_err(|_| "vault state lock poisoned".to_string())?;

    match guard.as_ref() {
        Some(key) => Ok(*key),
        None => Err("vault is locked".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn round_trip_encrypt_decrypt_succeeds() {
        let key = test_key(0x42);
        let plaintext = "super-secret-private-key-pem-material";

        let blob = encrypt_secret(plaintext, &key).expect("encryption should succeed");
        let decrypted = decrypt_secret(&blob, &key).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = test_key(0x01);
        let wrong_key = test_key(0x02);
        let plaintext = "another-secret-value";

        let blob = encrypt_secret(plaintext, &key).expect("encryption should succeed");
        let result = decrypt_secret(&blob, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let key = test_key(0x09);
        let blob_a = encrypt_secret("same plaintext", &key).unwrap();
        let blob_b = encrypt_secret("same plaintext", &key).unwrap();

        assert_ne!(blob_a.nonce, blob_b.nonce);
    }
}
