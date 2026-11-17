//! Data structures exchanged with the frontend over Tauri IPC. Field names are snake_case and
//! mirrored in `src/types/crypto.ts`.

use serde::{Deserialize, Serialize};

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct X509ExtensionInfo {
    pub oid: String,
    pub name: String,
    pub critical: bool,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateInfo {
    pub version: u8,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub not_before: i64,
    pub not_after: i64,
    pub days_remaining: i64,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub self_signed: bool,
    pub public_key_algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub sans: Vec<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub extensions: Vec<X509ExtensionInfo>,
    pub subject_key_id: Option<String>,
    pub authority_key_id: Option<String>,
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    pub md5_fingerprint: String,
    /// SHA-256 of the subjectPublicKeyInfo. This is the value operators pin.
    #[serde(default)]
    pub spki_sha256: String,
    #[serde(default)]
    pub crl_distribution_points: Vec<String>,
    #[serde(default)]
    pub ocsp_urls: Vec<String>,
    #[serde(default)]
    pub ca_issuer_urls: Vec<String>,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeystoreEntry {
    pub id: String,
    pub alias: String,
    /// "KeyPair", "TrustedCertificate" or "SecretKey".
    pub entry_type: String,
    pub algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    /// YYYY-MM-DD; from the keystore entry date (JKS/JCEKS) or the certificate's notBefore.
    pub creation_date: String,
    /// YYYY-MM-DD of the leaf certificate's notAfter; empty for secret keys.
    pub expiry_date: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    pub chain_length: usize,
    pub certificate_chain: Vec<CertificateInfo>,
    /// Unencrypted PKCS#8 PEM. Lives only in memory and in the keystore files the user saves.
    pub private_key_pem: Option<String>,
    pub public_key_pem: Option<String>,
    pub secret_key_hex: Option<String>,
    /// True when the private key could not be decrypted with the store password (JKS/JCEKS allow
    /// per-key passwords). The opaque protected blob is kept in `protected_key` so a save to the
    /// same format can write it back untouched.
    pub locked: bool,
    pub protected_key: Option<String>,
    /// When set, save re-wraps this key with this password instead of the store password.
    #[serde(default)]
    pub key_password: Option<String>,
    pub labels: Vec<String>,
    pub is_expired: bool,
    pub is_weak: bool,
    pub weak_reasons: Vec<String>,
    pub is_post_quantum: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeystoreFile {
    pub id: String,
    pub name: String,
    /// "PKCS12", "JKS", "JCEKS", "BKS", "UBER" or "BCFKS".
    pub format: String,
    /// Absolute path on disk; empty for a keystore that has never been saved.
    pub path: String,
    pub description: String,
    pub password_protected: bool,
    pub created_at: String,
    pub updated_at: String,
    /// File mtime in unix milliseconds, captured at open. Save refuses a newer file unless forced.
    #[serde(default)]
    pub source_mtime_ms: Option<i64>,
    pub entries: Vec<KeystoreEntry>,
    /// What the decoder found that the entry list does not show (see `keystore::Decoded`).
    #[serde(default)]
    pub notes: Vec<String>,
    /// Entries in the file the app could not represent. Saving over the file drops them.
    #[serde(default)]
    pub omitted_entries: usize,
}

/// Inputs for building a PKCS#12 (.p12/.pfx) straight from a certificate and its private key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildPkcs12Input {
    /// Friendly name stored in the file. Defaults to "1" when blank.
    #[serde(default)]
    pub alias: String,
    /// The private key: PKCS#8, PKCS#1 or SEC1, PEM or DER, optionally encrypted.
    pub key: Vec<u8>,
    /// The certificate, or a chain. When omitted, certificates found in `key` are used.
    #[serde(default)]
    pub certificate: Option<Vec<u8>>,
    /// Password that decrypts `key` when it arrives encrypted.
    #[serde(default)]
    pub key_password: Option<String>,
    /// Passphrase protecting the produced file. Required.
    pub passphrase: String,
    /// Integrity MAC: "pkcs12" (default, compatible) or "pbmac1".
    #[serde(default)]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyPairInput {
    pub alias: String,
    /// "RSA", "ECDSA" or "Ed25519".
    pub algorithm: String,
    /// RSA modulus size in bits (ignored for EC/EdDSA).
    pub key_size: u32,
    /// "P-256", "P-384" or "P-521" for ECDSA.
    pub curve: Option<String>,
    /// Signature hash for RSA ("SHA256", "SHA384", "SHA512"); EC uses the curve's natural hash.
    pub signature_hash: Option<String>,
    /// Full subject DN in RFC 4514 order ("CN=host, O=Org, C=US"). When empty, the DN is assembled
    /// from the individual fields below.
    #[serde(default)]
    pub subject_dn: String,
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub organizational_unit: String,
    #[serde(default)]
    pub locality: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub email: String,
    pub validity_days: u32,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    #[serde(default)]
    pub sans: Vec<String>,
    /// Key usage identifiers: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
    /// keyAgreement, keyCertSign, cRLSign. Empty selects sensible defaults.
    #[serde(default)]
    pub key_usage: Vec<String>,
    /// Extended key usage identifiers: serverAuth, clientAuth, codeSigning, emailProtection,
    /// timeStamping, OCSPSigning.
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    /// YYYY-MM-DD. Empty means "now".
    #[serde(default)]
    pub not_before: String,
    /// YYYY-MM-DD. Empty means not_before plus `validity_days`.
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub crl_distribution_points: Vec<String>,
    #[serde(default)]
    pub ocsp_urls: Vec<String>,
    #[serde(default)]
    pub ca_issuer_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSecretKeyInput {
    pub alias: String,
    /// "AES", "HmacSHA256", "HmacSHA384", "HmacSHA512" or "DESede".
    pub algorithm: String,
    pub key_size: u32,
    pub custom_hex: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrOptions {
    /// Override the subject DN; defaults to the entry certificate's subject.
    pub subject_dn: Option<String>,
    /// Override SANs; defaults to the entry certificate's SANs.
    pub sans: Option<Vec<String>>,
    pub signature_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrInfo {
    pub subject: String,
    pub public_key_algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub signature_algorithm: String,
    pub signature_valid: bool,
    /// False when the signature uses an algorithm this app cannot verify (Ed448, post-quantum,
    /// a curve it does not compute on). `signature_valid` is then false too, but that says
    /// nothing about the request.
    #[serde(default = "yes")]
    pub signature_checked: bool,
    pub sans: Vec<String>,
    /// Builder ids requested by the CSR (`digitalSignature`, …). Empty when the CSR has no key usage.
    #[serde(default)]
    pub key_usage: Vec<String>,
    /// Builder ids requested by the CSR (`serverAuth`, `codeSigning`, …).
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    pub extensions: Vec<X509ExtensionInfo>,
    pub public_key_sha256: String,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrResult {
    pub alias: String,
    pub subject: String,
    pub algorithm: String,
    pub csr_pem: String,
    pub sha256_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCsrInput {
    pub csr_pem: String,
    /// Override the CSR subject.
    pub subject_override: Option<String>,
    pub validity_days: u32,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    /// Extra SANs added to those requested in the CSR.
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub key_usage: Vec<String>,
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    /// Copy the SANs requested in the CSR (default true).
    pub copy_requested_sans: Option<bool>,
    /// Copy key usage and extended key usage from the CSR when it requests them (default true).
    /// When false, `key_usage` and `extended_key_usage` are written as given, including when empty.
    #[serde(default)]
    pub copy_requested_usages: Option<bool>,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub crl_distribution_points: Vec<String>,
    #[serde(default)]
    pub ocsp_urls: Vec<String>,
    #[serde(default)]
    pub ca_issuer_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificateResult {
    pub certificate: CertificateInfo,
    /// Leaf first, followed by the issuing CA's chain.
    pub chain_pem: String,
    /// Set when the requested lifetime was shortened to the CA certificate's expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertEntry {
    pub serial_number: String,
    /// YYYY-MM-DD
    pub revocation_date: String,
    /// keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation,
    /// certificateHold, privilegeWithdrawn, unspecified
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlInfo {
    pub issuer: String,
    pub this_update: String,
    pub next_update: String,
    pub crl_number: Option<String>,
    pub signature_algorithm: String,
    pub revoked_entries: Vec<RevokedCertEntry>,
    pub extensions: Vec<X509ExtensionInfo>,
    pub sha256_fingerprint: String,
    pub pem: String,
    /// Set when the CRL was verified against a known issuer certificate.
    pub signature_valid: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsSignResult {
    pub signer_alias: String,
    pub algorithm: String,
    pub detached: bool,
    pub content_sha256: String,
    pub cms_pem: String,
    pub byte_length: usize,
    pub signed_at: String,
    /// Set when the signature was timestamped by a TSA.
    pub timestamp: Option<TimestampInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsSignerInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub signing_time: Option<String>,
    pub signature_valid: bool,
    pub content_digest_valid: Option<bool>,
    /// RFC 3161 timestamp from the signer's unsigned attributes, when present.
    pub timestamp: Option<TimestampInfo>,
    pub error: Option<String>,
}

/// An RFC 3161 timestamp, as shown after signing or when verifying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampInfo {
    pub time: String,
    pub authority: String,
    pub serial_number: String,
    pub hash_algorithm: String,
    pub policy: Option<String>,
    /// False when the token is present but does not match this signature.
    pub valid: bool,
    pub error: Option<String>,
    /// Some when a TSA trust bundle was supplied. True only when the token's certificates chain to it.
    #[serde(default)]
    pub chain_trusted: Option<bool>,
}

/// An RFC 6960 OCSP revocation check for one certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspInfo {
    /// "good", "revoked" or "unknown".
    pub status: String,
    pub responder: String,
    pub produced_at: String,
    pub this_update: String,
    pub next_update: Option<String>,
    pub revocation_time: Option<String>,
    pub revocation_reason: Option<String>,
    pub signature_valid: bool,
    pub signature_warning: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsVerifyResult {
    pub valid: bool,
    pub detached: bool,
    pub content_available: bool,
    pub content_text: Option<String>,
    pub content_sha256: Option<String>,
    pub signers: Vec<CmsSignerInfo>,
    pub certificates: Vec<CertificateInfo>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtInfo {
    pub header_json: String,
    pub payload_json: String,
    pub algorithm: String,
    pub key_id: Option<String>,
    pub issued_at: Option<String>,
    pub not_before: Option<String>,
    pub expires_at: Option<String>,
    pub expired: Option<bool>,
    pub signature_b64url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVerifyResult {
    pub valid: bool,
    pub message: String,
    pub info: JwtInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhParamsResult {
    pub bit_size: u32,
    /// "ffdhe2048" etc. for RFC 7919 groups, or "custom".
    pub group: String,
    pub prime_hex: String,
    pub generator: u32,
    pub pem: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInspectionResult {
    pub host: String,
    pub port: u16,
    pub address: String,
    pub protocol: String,
    pub cipher_suite: String,
    pub alpn: Option<String>,
    pub trusted: bool,
    pub verification_error: Option<String>,
    pub hostname_matches: bool,
    pub certificates: Vec<CertificateInfo>,
    pub handshake_ms: u64,
    pub inspected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyInfo {
    pub kind: String, // "private" | "public" | "secret"
    pub algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub encrypted: bool,
    pub format: String,
    pub public_key_sha256: Option<String>,
    pub public_key_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionResult {
    /// "certificate", "certificate_chain", "csr", "crl", "private_key", "public_key", "jwt",
    /// "pkcs7", "keystore" or "unknown".
    pub kind: String,
    pub title: String,
    pub format: String,
    pub summary: String,
    pub certificates: Vec<CertificateInfo>,
    pub csr: Option<CsrInfo>,
    pub crl: Option<CrlInfo>,
    pub key: Option<KeyInfo>,
    pub jwt: Option<JwtInfo>,
    pub keystore_format: Option<String>,
    pub warnings: Vec<String>,
    pub sha256: String,
    pub byte_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub path: String,
    pub format: String,
    pub byte_length: usize,
    /// Text form (PEM, JSON, OpenSSH line) for preview/copy; None for binary exports.
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarSignResult {
    pub output_path: String,
    pub signer_alias: String,
    pub signature_algorithm: String,
    pub digest_algorithm: String,
    pub entries_signed: usize,
    pub manifest_preview: String,
    pub signature_file_name: String,
    pub signed_at: String,
    /// Set when the JAR was timestamped by a TSA.
    pub timestamp: Option<TimestampInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProbe {
    pub path: String,
    pub name: String,
    pub size: u64,
    /// "keystore", "certificate", "csr", "crl", "private_key", "public_key", "jwt", "pkcs7",
    /// "jar" or "unknown".
    pub kind: String,
    pub keystore_format: Option<String>,
}
