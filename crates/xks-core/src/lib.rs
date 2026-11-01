//! xks-core: the certificate / key / keystore engine behind xkeystore.
//!
//! Nothing in this crate shells out to `openssl` or `keytool`, and nothing
//! requires a JVM. Certificate and CSR handling is pure Rust via `rcgen`
//! (on the `ring` cryptography backend); RSA key *generation* — the one
//! operation `ring` deliberately does not provide — uses the pure-Rust
//! RustCrypto `rsa` crate. PKCS#12/PFX and JKS container formats are
//! implemented in pure Rust as well (`p12-keystore`, `jks`).

pub mod error;
pub mod keys;
pub mod cert;
pub mod pkcs12;
pub mod jks;
pub mod pem;
pub mod chain;
pub mod identity;
pub mod classify;
pub mod password;
pub mod audit;
pub mod presets;
pub mod ca;

pub use error::{CoreError, Result};
