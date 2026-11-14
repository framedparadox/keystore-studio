//! The Tauri command layer: every function the frontend can call.
//!
//! This is separated from the engine modules so the engine can be built and fuzzed without the
//! GUI toolchain. Fuzz targets link the library with `--no-default-features`, which drops this
//! module along with Tauri, WebKit and the dialog plugin; linking those into a sanitizer build
//! fails, and none of them are needed to parse a file.

use crate::model::*;
use crate::util::Res;
use crate::vault::{SecretSummary, VaultState, VaultStatus};
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Manager, State};

static E2E_PAGE_LOADED: AtomicBool = AtomicBool::new(false);
use zeroize::Zeroize;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

async fn blocking<T, F>(f: F) -> Res<T>
where
    T: Send + 'static,
    F: FnOnce() -> Res<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await.map_err(|err| format!("background task failed: {err}"))?
}

/// Input that may come from a file the user picked, pasted text, or base64 bytes.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DataSource {
    pub path: Option<String>,
    pub text: Option<String>,
    pub base64: Option<String>,
}

impl DataSource {
    pub fn bytes(&self) -> Res<Vec<u8>> {
        if let Some(path) = self.path.as_deref().filter(|p| !p.is_empty()) {
            let meta = std::fs::metadata(path).map_err(|err| format!("cannot read {path}: {err}"))?;
            if meta.len() > MAX_INPUT_BYTES {
                return Err(format!("{path} is larger than 64 MB"));
            }
            return std::fs::read(path).map_err(|err| format!("cannot read {path}: {err}"));
        }
        if let Some(b) = self.base64.as_deref().filter(|b| !b.is_empty()) {
            return util::unb64(b);
        }
        if let Some(t) = self.text.as_deref() {
            return Ok(t.as_bytes().to_vec());
        }
        Err("no input provided".into())
    }

    fn is_empty(&self) -> bool {
        self.path.as_deref().unwrap_or("").is_empty() && self.text.as_deref().unwrap_or("").trim().is_empty() && self.base64.as_deref().unwrap_or("").is_empty()
    }
}

struct AppPaths {
    data_dir: std::path::PathBuf,
}

// ------------------------------------------------------------------------------------------------
// App info & persisted UI state
// ------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct AppInfo {
    version: String,
    data_dir: String,
    platform: String,
    home_dir: String,
    /// Set by the end-to-end test harness (KEYSTORE_STUDIO_E2E=1) to script file dialogs.
    e2e: bool,
}

#[tauri::command]
fn app_info(paths: State<Arc<AppPaths>>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        data_dir: paths.data_dir.to_string_lossy().into(),
        platform: std::env::consts::OS.into(),
        home_dir: dirs::home_dir().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        e2e: std::env::var_os("KEYSTORE_STUDIO_E2E").is_some(),
    }
}

#[tauri::command]
async fn load_app_state(paths: State<'_, Arc<AppPaths>>) -> Res<serde_json::Value> {
    let path = paths.data_dir.join("state.json");
    blocking(move || match std::fs::read_to_string(&path) {
        Ok(raw) => Ok(serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)),
        Err(_) => Ok(serde_json::Value::Null),
    })
    .await
}

#[tauri::command]
async fn save_app_state(paths: State<'_, Arc<AppPaths>>, state: serde_json::Value) -> Res<()> {
    let path = paths.data_dir.join("state.json");
    blocking(move || {
        let json = serde_json::to_vec_pretty(&state).map_err(util::e)?;
        if json.len() > 8 * 1024 * 1024 {
            return Err("application state is unexpectedly large".into());
        }
        util::write_atomic(&path, &json)
    })
    .await
}

// ------------------------------------------------------------------------------------------------
// Keystore files
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn probe_file(path: String) -> Res<FileProbe> {
    blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|err| format!("cannot read {path}: {err}"))?;
        if meta.is_dir() {
            return Err(format!("{path} is a folder"));
        }
        let mut f = std::fs::File::open(&path).map_err(util::e)?;
        let mut head = vec![0u8; meta.len().min(1024 * 1024) as usize];
        std::io::Read::read_exact(&mut f, &mut head).map_err(util::e)?;
        let name = util::file_name_of(&path);
        let lower = name.to_ascii_lowercase();
        let (kind, keystore_format) = if let Some(fmt) = keystore::detect(&head) {
            ("keystore".to_string(), Some(fmt.name().to_string()))
        } else if keystore::looks_like_bks_v2(&head) {
            ("keystore".to_string(), Some("BKS".to_string()))
        } else if lower.ends_with(".apk") {
            ("apk".to_string(), None)
        } else if lower.ends_with(".jar") || lower.ends_with(".war") || lower.ends_with(".ear") {
            ("jar".to_string(), None)
        } else if let Some(kind) = keystore::detect_unsupported(&head) {
            // Report the actual format: the conversion command differs per store type, and
            // suggesting BKS for a BCFKS file produces a command that fails.
            ("unsupported_keystore".to_string(), Some(kind.store_type().to_string()))
        } else {
            match detect::examine(&head, None) {
                Ok(r) => (r.kind, None),
                Err(_) => ("unknown".to_string(), None),
            }
        };
        Ok(FileProbe { path, name, size: meta.len(), kind, keystore_format })
    })
    .await
}

#[tauri::command]
async fn open_keystore(path: String, password: String, key_passwords: Option<HashMap<String, String>>) -> Res<KeystoreFile> {
    blocking(move || keystore::open(&path, &password, &key_passwords.unwrap_or_default())).await
}

#[derive(Serialize)]
struct SaveResult {
    path: String,
    name: String,
    format: String,
    byte_length: usize,
    mtime_ms: Option<i64>,
}

#[tauri::command]
async fn save_keystore(mut ks: KeystoreFile, path: String, mut password: String, format: String, mac: Option<String>, force: Option<bool>) -> Res<SaveResult> {
    blocking(move || {
        let fmt = keystore::Format::parse(&format)?;
        let mac_kind = match mac.as_deref() {
            Some("pbmac1") => pkcs12::MacKind::Pbmac1,
            _ => pkcs12::MacKind::Pkcs12,
        };
        let saved = keystore::save_with(&ks, &path, &password, fmt, keystore::SavePolicy { mac: mac_kind, force: force.unwrap_or(false) });
        password.zeroize();
        for entry in &mut ks.entries {
            if let Some(kp) = entry.key_password.as_mut() {
                kp.zeroize();
            }
        }
        let n = saved?;
        let mtime_ms = keystore::mtime_ms(std::path::Path::new(&path));
        Ok(SaveResult { name: util::file_name_of(&path), path, format: fmt.name().into(), byte_length: n, mtime_ms })
    })
    .await
}

#[tauri::command]
async fn export_keystore_csv(ks: KeystoreFile, path: String) -> Res<ExportResult> {
    blocking(move || {
        let csv = export::inventory_csv(&ks);
        util::write_atomic(std::path::Path::new(&path), csv.as_bytes())?;
        Ok(ExportResult { path, format: "CSV inventory".into(), byte_length: csv.len(), text: None })
    })
    .await
}

// ------------------------------------------------------------------------------------------------
// Entries
// ------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct GeneratedKeyPair {
    #[serde(flatten)]
    entry: KeystoreEntry,
    /// Set when the requested lifetime was shortened to the CA certificate's expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    validity_note: Option<String>,
}

#[tauri::command]
async fn generate_key_pair(input: GenerateKeyPairInput, issuer: Option<KeystoreEntry>, paths: State<'_, Arc<AppPaths>>) -> Res<GeneratedKeyPair> {
    let dir = paths.data_dir.clone();
    blocking(move || {
        let (entry, validity_note) = ops::issue_key_pair(&input, issuer.as_ref())?;
        if let Some(ca) = &issuer {
            record_issuance(&dir, entry.certificate_chain.first(), ca.certificate_chain.first(), "generate");
        }
        Ok(GeneratedKeyPair { entry, validity_note })
    })
    .await
}

#[tauri::command]
async fn generate_secret_key(input: GenerateSecretKeyInput) -> Res<KeystoreEntry> {
    blocking(move || ops::generate_secret_key(&input)).await
}

#[tauri::command]
async fn import_trusted_certificates(alias: String, data: DataSource, existing_aliases: Vec<String>) -> Res<Vec<KeystoreEntry>> {
    blocking(move || ops::import_trusted_certificates(&alias, &data.bytes()?, &existing_aliases)).await
}

#[tauri::command]
async fn import_key_pair(alias: String, key: DataSource, key_password: Option<String>, certificates: Option<DataSource>) -> Res<KeystoreEntry> {
    blocking(move || {
        let cert_bytes = match &certificates {
            Some(c) if !c.is_empty() => Some(c.bytes()?),
            _ => None,
        };
        ops::import_key_pair(&alias, &key.bytes()?, key_password.as_deref(), cert_bytes.as_deref())
    })
    .await
}

/// Builds a PKCS#12 (.p12/.pfx) from a certificate, a private key and a passphrase, and writes it
/// to `path`. The standalone counterpart to importing a key pair and then exporting it.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn build_pkcs12(
    path: String,
    key: DataSource,
    certificate: Option<DataSource>,
    key_password: Option<String>,
    passphrase: String,
    alias: Option<String>,
    mac: Option<String>,
) -> Res<ExportResult> {
    blocking(move || {
        let cert_bytes = match &certificate {
            Some(c) if !c.is_empty() => Some(c.bytes()?),
            _ => None,
        };
        let input = BuildPkcs12Input { alias: alias.unwrap_or_default(), key: key.bytes()?, certificate: cert_bytes, key_password, passphrase, mac };
        let der = ops::build_pkcs12(&input)?;
        util::write_atomic(std::path::Path::new(&path), &der)?;
        Ok(ExportResult { path, format: "PKCS#12 (certificate and private key)".into(), byte_length: der.len(), text: None })
    })
    .await
}

#[tauri::command]
async fn generate_csr(entry: KeystoreEntry, options: CsrOptions) -> Res<CsrResult> {
    blocking(move || ops::generate_csr(&entry, &options)).await
}

#[tauri::command]
async fn import_ca_reply(entry: KeystoreEntry, reply: DataSource) -> Res<KeystoreEntry> {
    blocking(move || ops::import_ca_reply(&entry, &reply.bytes()?)).await
}

#[tauri::command]
async fn rotate_key(entry: KeystoreEntry, algorithm: String, key_size: u32, curve: Option<String>, issuer: Option<KeystoreEntry>, paths: State<'_, Arc<AppPaths>>) -> Res<KeystoreEntry> {
    let dir = paths.data_dir.clone();
    blocking(move || {
        let rotated = ops::rotate_key(&entry, &algorithm, key_size, curve.as_deref(), issuer.as_ref())?;
        if let Some(ca) = &issuer {
            record_issuance(&dir, rotated.certificate_chain.first(), ca.certificate_chain.first(), "rotate");
        }
        Ok(rotated)
    })
    .await
}

#[tauri::command]
async fn export_entry(entry: KeystoreEntry, target: String, path: String, password: Option<String>) -> Res<ExportResult> {
    blocking(move || export::export_entry(&entry, &target, &path, password.as_deref())).await
}

// ------------------------------------------------------------------------------------------------
// Conversions
// ------------------------------------------------------------------------------------------------

/// Certificates (PEM, DER, PKCS#7, PkiPath) to another certificate format. Without `path` this is
/// a preview and nothing is written.
#[tauri::command]
async fn convert_certificates(data: DataSource, target: String, order: Option<bool>, path: Option<String>) -> Res<convert::ConvertResult> {
    blocking(move || convert::deliver(convert::certificates(&data.bytes()?, &target, order.unwrap_or(true))?, path.as_deref())).await
}

#[tauri::command]
async fn convert_private_key(data: DataSource, password: Option<String>, target: String, out_password: Option<String>, path: Option<String>) -> Res<convert::ConvertResult> {
    blocking(move || {
        let mut out_password = out_password;
        let result = convert::private_key(&data.bytes()?, password.as_deref(), &target, out_password.as_deref());
        if let Some(pw) = out_password.as_mut() {
            pw.zeroize();
        }
        convert::deliver(result?, path.as_deref())
    })
    .await
}

#[tauri::command]
async fn convert_public_key(data: DataSource, password: Option<String>, target: String, comment: Option<String>, path: Option<String>) -> Res<convert::ConvertResult> {
    blocking(move || convert::deliver(convert::public_key(&data.bytes()?, password.as_deref(), &target, comment.as_deref().unwrap_or(""))?, path.as_deref())).await
}

#[tauri::command]
async fn convert_encoding(data: DataSource, label: Option<String>, path: Option<String>) -> Res<convert::ConvertResult> {
    blocking(move || convert::deliver(convert::encoding(&data.bytes()?, label.as_deref())?, path.as_deref())).await
}

/// Certificates and private keys of keystore entries as one PEM file.
#[tauri::command]
async fn entries_to_pem(entries: Vec<KeystoreEntry>, options: convert::PemBundleOptions, path: Option<String>) -> Res<convert::ConvertResult> {
    blocking(move || {
        let mut options = options;
        let result = convert::entries_to_pem(&entries, &options);
        if let Some(pw) = options.password.as_mut() {
            pw.zeroize();
        }
        convert::deliver(result?, path.as_deref())
    })
    .await
}

#[tauri::command]
async fn jwt_algorithms(entry: KeystoreEntry) -> Res<Vec<String>> {
    Ok(jwt::algorithms_for(&entry).into_iter().map(String::from).collect())
}

// ------------------------------------------------------------------------------------------------
// CA & signing
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn sign_csr(input: SignCsrInput, ca_entry: KeystoreEntry, paths: State<'_, Arc<AppPaths>>) -> Res<SignedCertificateResult> {
    let dir = paths.data_dir.clone();
    blocking(move || {
        let signed = ops::sign_csr(&input, &ca_entry)?;
        record_issuance(&dir, Some(&signed.certificate), ca_entry.certificate_chain.first(), "sign-csr");
        Ok(signed)
    })
    .await
}

#[tauri::command]
async fn inspect_csr(data: DataSource) -> Res<CsrInfo> {
    blocking(move || x509::parse_csr(&x509::csr_der_from_bytes(&data.bytes()?)?)).await
}

#[tauri::command]
async fn generate_crl(ca_entry: KeystoreEntry, next_update_days: u32, crl_number: u64, revoked_entries: Vec<RevokedCertEntry>, paths: State<'_, Arc<AppPaths>>) -> Res<CrlInfo> {
    let dir = paths.data_dir.clone();
    blocking(move || {
        let crl = ops::generate_crl(&ca_entry, next_update_days, crl_number, &revoked_entries)?;
        if let Some(ski) = ca_entry.certificate_chain.first().and_then(|c| c.subject_key_id.as_deref()).filter(|s| !s.is_empty()) {
            let path = dir.join("crl_numbers.json");
            let mut map: HashMap<String, u64> = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let entry = map.entry(ski.to_string()).or_insert(0);
            if crl_number > *entry {
                *entry = crl_number;
            }
            if let Ok(json) = serde_json::to_vec_pretty(&map) {
                let _ = util::write_atomic(&path, &json);
            }
        }
        Ok(crl)
    })
    .await
}

#[tauri::command]
async fn ca_next_crl_number(paths: State<'_, Arc<AppPaths>>, ca_ski: String) -> Res<u64> {
    let path = paths.data_dir.join("crl_numbers.json");
    blocking(move || {
        let map: HashMap<String, u64> = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        Ok(map.get(&ca_ski).copied().unwrap_or(0).saturating_add(1))
    })
    .await
}

#[tauri::command]
async fn cms_sign(content: DataSource, signer_entry: KeystoreEntry, detached: bool, tsa_url: Option<String>, tsa_trust_pem: Option<String>) -> Res<CmsSignResult> {
    blocking(move || {
        let data = content.bytes()?;
        let key = entry::private_key(&signer_entry)?;
        let chain = entry::chain_der(&signer_entry)?;
        let (der, timestamp) = cms::sign_timestamped(&data, &key, &chain, detached, tsa_url.as_deref())?;
        let (_, alg) = cms::cms_algorithms(&key)?;
        Ok(CmsSignResult {
            signer_alias: signer_entry.alias.clone(),
            algorithm: alg.name(),
            detached,
            content_sha256: util::upper_hex(&util::sha256(&data)),
            cms_pem: util::to_pem("PKCS7", &der),
            byte_length: der.len(),
            signed_at: util::fmt_ts(util::now_ts()),
            timestamp: timestamp.map(|ts| {
                let mut info = ts.info(true, None);
                if let Some(pem) = tsa_trust_pem.as_deref() {
                    info.chain_trusted = tsa::chain_trusted(&ts, pem);
                }
                info
            }),
        })
    })
    .await
}

#[tauri::command]
async fn cms_verify(signature: DataSource, content: Option<DataSource>, entry: Option<KeystoreEntry>, tsa_trust_pem: Option<String>) -> Res<CmsVerifyResult> {
    blocking(move || {
        let der = cms::cms_der_from_bytes(&signature.bytes()?)?;
        let content_bytes = match &content {
            Some(c) if !c.is_empty() => Some(c.bytes()?),
            _ => None,
        };
        let extra = match &entry {
            Some(e) => entry::chain_der(e)?,
            None => vec![],
        };
        cms::verify_with_trust(&der, content_bytes.as_deref(), &extra, tsa_trust_pem.as_deref())
    })
    .await
}

#[derive(Deserialize)]
struct JwtSignInput {
    issuer: String,
    subject: String,
    audience: String,
    validity_minutes: u32,
    custom_claims_json: String,
    algorithm: Option<String>,
}

#[tauri::command]
async fn jwt_sign(input: JwtSignInput, signer_entry: KeystoreEntry) -> Res<String> {
    blocking(move || {
        jwt::sign(
            &jwt::JwtClaims { issuer: &input.issuer, subject: &input.subject, audience: &input.audience, validity_minutes: input.validity_minutes, custom_claims_json: &input.custom_claims_json },
            &signer_entry,
            input.algorithm.as_deref(),
        )
    })
    .await
}

#[tauri::command]
async fn jwt_verify(token: String, entry: KeystoreEntry) -> Res<JwtVerifyResult> {
    blocking(move || jwt::verify(&token, &entry)).await
}

#[tauri::command]
async fn dh_params(bits: u32, mode: String) -> Res<DhParamsResult> {
    blocking(move || if mode == "generate" { dh::generate(bits) } else { dh::ffdhe(bits) }).await
}

#[tauri::command]
async fn jar_sign(input_path: String, output_path: String, signer_entry: KeystoreEntry, tsa_url: Option<String>, tsa_trust_pem: Option<String>) -> Res<JarSignResult> {
    blocking(move || {
        if input_path.to_ascii_lowercase().ends_with(".apk") || output_path.to_ascii_lowercase().ends_with(".apk") {
            return Err("apk: Android APKs use APK Signature Scheme v2 or v3. A JAR signature is ignored by Android, so this tool will not write one.".into());
        }
        jar::sign_jar_with_trust(&input_path, &output_path, &signer_entry, tsa_url.as_deref(), tsa_trust_pem.as_deref())
    })
    .await
}

// ------------------------------------------------------------------------------------------------
// Examine
// ------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct IssuanceRecord {
    serial: String,
    subject: String,
    ski: String,
    not_after: String,
    profile: String,
    issuer_ski: String,
}

fn record_issuance(dir: &std::path::Path, leaf: Option<&CertificateInfo>, issuer: Option<&CertificateInfo>, profile: &str) {
    let Some(leaf) = leaf else { return };
    let rec = IssuanceRecord {
        serial: leaf.serial_number.clone(),
        subject: leaf.subject.clone(),
        ski: leaf.subject_key_id.clone().unwrap_or_default(),
        not_after: leaf.valid_to.clone(),
        profile: profile.into(),
        issuer_ski: issuer.and_then(|c| c.subject_key_id.clone()).unwrap_or_default(),
    };
    let Ok(line) = serde_json::to_string(&rec) else { return };
    let path = dir.join("issuance.jsonl");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = writeln!(file, "{line}");
    }
}

#[tauri::command]
async fn ledger_search(paths: State<'_, Arc<AppPaths>>, query: String) -> Res<Vec<IssuanceRecord>> {
    let path = paths.data_dir.join("issuance.jsonl");
    blocking(move || {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let q = query.trim().to_ascii_lowercase();
        let mut out = Vec::new();
        for line in text.lines() {
            if let Ok(rec) = serde_json::from_str::<IssuanceRecord>(line) {
                let blob = format!("{} {} {}", rec.serial, rec.subject, rec.ski).to_ascii_lowercase();
                if q.is_empty() || blob.contains(&q) {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    })
    .await
}

#[tauri::command]
async fn ledger_delete(paths: State<'_, Arc<AppPaths>>, serial: String) -> Res<()> {
    let path = paths.data_dir.join("issuance.jsonl");
    blocking(move || {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut kept = String::new();
        for line in text.lines() {
            if let Ok(rec) = serde_json::from_str::<IssuanceRecord>(line)
                && rec.serial.eq_ignore_ascii_case(serial.trim())
            {
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        util::write_atomic(&path, kept.as_bytes())
    })
    .await
}

/// The operating system's trust anchors as PEM, for `validate_chain` against the same roots a
/// live TLS handshake (`examine_tls`) would trust.
#[tauri::command]
async fn system_trust_anchors() -> Res<String> {
    blocking(|| Ok(tls::system_trust_anchors_pem())).await
}

#[tauri::command]
async fn validate_chain(leaf_pem: String, intermediates_pem: String, anchors_pem: String, hostname: Option<String>) -> Res<Vec<String>> {
    blocking(move || {
        let leaf = x509::certificates_from_bytes(leaf_pem.as_bytes())?;
        let leaf = leaf.first().cloned().ok_or("no leaf certificate")?;
        let intermediates = if intermediates_pem.trim().is_empty() {
            Vec::new()
        } else {
            x509::certificates_from_bytes(intermediates_pem.as_bytes()).map_err(|err| format!("invalid intermediate certificate(s): {err}"))?
        };
        let anchors =
            if anchors_pem.trim().is_empty() { Vec::new() } else { x509::certificates_from_bytes(anchors_pem.as_bytes()).map_err(|err| format!("invalid trust anchor certificate(s): {err}"))? };
        Ok(x509::validate_chain(&leaf, &intermediates, &anchors, hostname.as_deref()))
    })
    .await
}

#[tauri::command]
async fn read_crl(data: DataSource) -> Res<CrlInfo> {
    blocking(move || {
        let bytes = data.bytes()?;
        let der = if util::looks_textual(&bytes) {
            let text = String::from_utf8_lossy(&bytes);
            util::pem_blocks(&text).into_iter().find(|b| b.tag.contains("CRL")).map(|b| b.der).ok_or("no CRL found in the PEM data")?
        } else {
            bytes
        };
        x509::parse_crl(&der, None)
    })
    .await
}

/// Live revocation check for one certificate against an OCSP responder (RFC 6960).
///
/// `subject_pem` and `issuer_pem` are each a single PEM certificate. `url` defaults to the first
/// of the subject certificate's `ocsp_urls` (its Authority Information Access extension) when
/// empty.
#[tauri::command]
async fn check_ocsp(subject_pem: String, issuer_pem: String, url: Option<String>) -> Res<OcspInfo> {
    blocking(move || {
        let subject = x509::certificates_from_bytes(subject_pem.as_bytes())?.into_iter().next().ok_or("no subject certificate")?;
        let issuer = x509::certificates_from_bytes(issuer_pem.as_bytes())?.into_iter().next().ok_or("no issuer certificate")?;
        let url = match url.filter(|u| !u.trim().is_empty()) {
            Some(u) => u,
            None => x509::parse_certificate(&subject)?.ocsp_urls.into_iter().next().ok_or("this certificate carries no OCSP responder URL")?,
        };
        Ok(ocsp::check(&url, &subject, &issuer)?.info())
    })
    .await
}

#[tauri::command]
async fn examine_tls(host: String, port: u16) -> Res<TlsInspectionResult> {
    blocking(move || tls::inspect(&host, port, 10)).await
}

/// A TCP reachability test, as `Test-NetConnection -Port` (Examine, and the terminal's built-in).
#[tauri::command]
async fn test_connection(target: String, port: u16, timeout_secs: Option<u64>) -> Res<netcheck::ConnectionTest> {
    blocking(move || netcheck::test(&target, port, timeout_secs.unwrap_or(5))).await
}

#[tauri::command]
async fn examine_data(data: DataSource, password: Option<String>) -> Res<DetectionResult> {
    blocking(move || detect::examine(&data.bytes()?, password.as_deref())).await
}

// ------------------------------------------------------------------------------------------------
// Files
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn write_text_file(path: String, content: String) -> Res<()> {
    blocking(move || util::write_atomic(std::path::Path::new(&path), content.as_bytes())).await
}

#[tauri::command]
async fn read_text_file(path: String) -> Res<String> {
    blocking(move || {
        let bytes = DataSource { path: Some(path.clone()), ..Default::default() }.bytes()?;
        if util::looks_textual(&bytes) {
            Ok(String::from_utf8_lossy(&bytes).to_string())
        } else {
            // Binary DER: hand back PEM so it can be shown in a text box.
            match detect::examine(&bytes, None)?.kind.as_str() {
                "certificate" | "certificate_chain" => Ok(x509::certificates_from_bytes(&bytes)?.iter().map(|c| util::to_pem("CERTIFICATE", c)).collect()),
                "csr" => Ok(util::to_pem("CERTIFICATE REQUEST", &bytes)),
                "crl" => Ok(util::to_pem("X509 CRL", &bytes)),
                "pkcs7" => Ok(util::to_pem("PKCS7", &bytes)),
                "private_key" => Ok(util::to_pem("PRIVATE KEY", &bytes)),
                "public_key" => Ok(util::to_pem("PUBLIC KEY", &bytes)),
                _ => Err(format!("{path} is a binary file that cannot be shown as text")),
            }
        }
    })
    .await
}

// ------------------------------------------------------------------------------------------------
// Vault
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn vault_status(state: State<'_, Arc<VaultState>>) -> Res<VaultStatus> {
    let v = state.inner().clone();
    blocking(move || v.status()).await
}

#[tauri::command]
async fn vault_init(state: State<'_, Arc<VaultState>>, master_key: String) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || v.init(&master_key)).await
}

#[tauri::command]
async fn vault_unlock(state: State<'_, Arc<VaultState>>, master_key: String) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || {
        let result = v.unlock(&master_key);
        if result.is_err() {
            // Slow down guessing a little beyond Argon2's own cost.
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        result
    })
    .await
}

#[tauri::command]
async fn vault_lock(state: State<'_, Arc<VaultState>>) -> Res<()> {
    state.lock()
}

#[tauri::command]
async fn vault_change_master_key(state: State<'_, Arc<VaultState>>, old_master_key: String, new_master_key: String) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || v.change_master_key(&old_master_key, &new_master_key)).await
}

#[tauri::command]
async fn vault_reset(state: State<'_, Arc<VaultState>>) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || v.reset()).await
}

#[tauri::command]
async fn vault_store_secret(state: State<'_, Arc<VaultState>>, id: String, label: String, secret: String) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || v.store_secret(&id, &label, &secret)).await
}

#[tauri::command]
async fn vault_get_secret(state: State<'_, Arc<VaultState>>, id: String) -> Res<Option<String>> {
    let v = state.inner().clone();
    blocking(move || v.get_secret(&id)).await
}

#[tauri::command]
async fn vault_delete_secret(state: State<'_, Arc<VaultState>>, id: String) -> Res<()> {
    let v = state.inner().clone();
    blocking(move || v.delete_secret(&id)).await
}

#[tauri::command]
async fn vault_list_secrets(state: State<'_, Arc<VaultState>>) -> Res<Vec<SecretSummary>> {
    let v = state.inner().clone();
    blocking(move || v.list_secrets()).await
}

// ------------------------------------------------------------------------------------------------
// Terminal
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn run_terminal_command(command: String, cwd: Option<String>, timeout_secs: Option<u64>) -> Res<terminal::TerminalOutput> {
    blocking(move || terminal::run(&command, cwd, timeout_secs.unwrap_or(120))).await
}

// ------------------------------------------------------------------------------------------------
// Tools
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn tool_status() -> Vec<tools::ToolStatus> {
    tauri::async_runtime::spawn_blocking(tools::status).await.unwrap_or_default()
}

/// Localhost JavaScript bridge used by `e2e/eval-drive.mjs`.
///
/// Started only when `KEYSTORE_STUDIO_E2E` is set (the same switch that lets the harness script file
/// dialogs). It binds `127.0.0.1` and writes the port to `e2e.port` in the data directory.
/// Each connection carries length-prefixed UTF-8 frames: a script in, a JSON value out.
fn start_e2e_bridge(app: tauri::AppHandle, data_dir: std::path::PathBuf) {
    std::thread::spawn(move || {
        if let Err(err) = e2e_listen(app, &data_dir) {
            eprintln!("e2e bridge: {err}");
        }
    });
}

fn e2e_listen(app: tauri::AppHandle, data_dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|err| err.to_string())?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    let port = listener.local_addr().map_err(|err| err.to_string())?.port();
    e2e_wait_ready(&app, data_dir)?;
    std::fs::write(data_dir.join("e2e.port"), port.to_string()).map_err(|err| err.to_string())?;
    eprintln!("e2e bridge listening on 127.0.0.1:{port}");
    for conn in listener.incoming() {
        let mut conn = match conn {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("e2e bridge accept: {err}");
                continue;
            }
        };
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(60)));
        let _ = conn.set_write_timeout(Some(std::time::Duration::from_secs(60)));
        while let Ok(script) = e2e_read_frame(&mut conn) {
            let result = e2e_eval(&app, script).unwrap_or_else(|err| serde_json::json!({ "__e2eError": err }).to_string());
            if e2e_write_frame(&mut conn, &result).is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn e2e_read_frame(conn: &mut std::net::TcpStream) -> Result<String, String> {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).map_err(|err| err.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_000_000 {
        return Err("script is too large".into());
    }
    let mut buf = vec![0u8; len];
    conn.read_exact(&mut buf).map_err(|err| err.to_string())?;
    String::from_utf8(buf).map_err(|err| err.to_string())
}

fn e2e_write_frame(conn: &mut std::net::TcpStream, body: &str) -> Result<(), String> {
    let bytes = body.as_bytes();
    conn.write_all(&(bytes.len() as u32).to_be_bytes()).map_err(|err| err.to_string())?;
    conn.write_all(bytes).map_err(|err| err.to_string())?;
    Ok(())
}

enum EvalWait {
    Gone,
    Late,
}

const READINESS_HINT: &str = "the page never ran the readiness script. Build with the `custom-protocol` \
feature so the window serves the embedded frontend (cargo build --features custom-protocol, or \
`pnpm tauri build --debug`); without it the webview loads devUrl and stays blank unless `pnpm dev` is running.";

/// Waits until the webview reports that the page finished loading, then confirms the document is
/// actually able to run scripts. The event alone is not proof: when the window never reaches the
/// foreground, macOS can withhold it even though the page is fine, so a missing event is reported
/// but not treated as fatal until the document itself fails to answer.
fn e2e_wait_ready(app: &tauri::AppHandle, _data_dir: &std::path::Path) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !E2E_PAGE_LOADED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !E2E_PAGE_LOADED.load(Ordering::SeqCst) {
        eprintln!("e2e bridge: no page load event yet; asking the document directly");
    }
    match e2e_eval_once(app, "return document.readyState".into(), std::time::Duration::from_secs(10))? {
        Ok(value) if value.contains("complete") || value.contains("interactive") => Ok(()),
        Ok(value) => Err(format!("the page answered unexpectedly: {value}")),
        // By far the most common cause: the binary was built without the `custom-protocol`
        // feature, so the webview is pointed at devUrl (the Vite server) instead of the embedded
        // frontend. With nothing serving that URL the page never loads and no script ever runs.
        Err(EvalWait::Gone) => Err(READINESS_HINT.into()),
        Err(EvalWait::Late) => Err(READINESS_HINT.into()),
    }
}

fn e2e_eval(app: &tauri::AppHandle, script: String) -> Result<String, String> {
    match e2e_eval_once(app, script, std::time::Duration::from_secs(90))? {
        Ok(value) => Ok(value),
        Err(EvalWait::Gone) => Err("the page dropped the script".into()),
        Err(EvalWait::Late) => Err("the page did not answer within 90s".into()),
    }
}

fn e2e_eval_once(app: &tauri::AppHandle, script: String, timeout: std::time::Duration) -> Result<Result<String, EvalWait>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    // Native evaluateJavaScript compiles this string itself. Calling eval() from the page would
    // be refused by the CSP (`script-src 'self'`), so the script is spliced in directly.
    // Synchronous on purpose. WKWebView's completion handler does not resolve a Promise, so an
    // async wrapper would report null and let the driver race ahead of the script.
    let wrapped =
        format!("(() => {{ try {{ const __v = (() => {{\n{script}\n}})(); return __v === undefined ? null : __v; }} catch (e) {{ return {{ __e2eError: String((e && e.message) || e) }}; }} }})()");
    let window_app = app.clone();
    let tx_fail = tx.clone();
    app.run_on_main_thread(move || {
        let Some(window) = window_app.get_webview_window("main") else {
            let _ = tx.send(r#"{"__e2eError":"the main window is not open"}"#.to_string());
            return;
        };
        if let Err(err) = window.eval_with_callback(wrapped, move |result| {
            let _ = tx.send(if result.is_empty() { "null".into() } else { result });
        }) {
            let _ = tx_fail.send(serde_json::json!({ "__e2eError": format!("eval failed: {err}") }).to_string());
        }
    })
    .map_err(|err| err.to_string())?;
    match rx.recv_timeout(timeout) {
        Ok(value) => Ok(Ok(value)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(Err(EvalWait::Late)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(Err(EvalWait::Gone)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let data_dir = std::env::var_os("KEYSTORE_STUDIO_DATA_DIR").map(std::path::PathBuf::from).unwrap_or_else(VaultState::default_dir);
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(VaultState::new(data_dir.clone())))
        .manage(Arc::new(AppPaths { data_dir: data_dir.clone() }))
        .on_page_load(|_, payload| {
            if std::env::var_os("KEYSTORE_STUDIO_E2E").is_none() {
                return;
            }
            let url = payload.url().to_string();
            // The window finishes about:blank before the embedded page. Evaluating during that
            // gap is cancelled by the real navigation, so only the app document counts.
            if payload.event() == tauri::webview::PageLoadEvent::Finished && !url.starts_with("about:") {
                E2E_PAGE_LOADED.store(true, Ordering::SeqCst);
                eprintln!("e2e page ready {url}");
            }
        })
        .setup(move |app| {
            if std::env::var_os("KEYSTORE_STUDIO_E2E").is_some() {
                start_e2e_bridge(app.handle().clone(), data_dir.clone());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            load_app_state,
            save_app_state,
            probe_file,
            open_keystore,
            save_keystore,
            export_keystore_csv,
            generate_key_pair,
            generate_secret_key,
            import_trusted_certificates,
            import_key_pair,
            build_pkcs12,
            generate_csr,
            import_ca_reply,
            rotate_key,
            export_entry,
            jwt_algorithms,
            convert_certificates,
            convert_private_key,
            convert_public_key,
            convert_encoding,
            entries_to_pem,
            sign_csr,
            inspect_csr,
            generate_crl,
            ca_next_crl_number,
            read_crl,
            ledger_search,
            ledger_delete,
            validate_chain,
            system_trust_anchors,
            check_ocsp,
            cms_sign,
            cms_verify,
            jwt_sign,
            jwt_verify,
            dh_params,
            jar_sign,
            examine_tls,
            test_connection,
            examine_data,
            write_text_file,
            read_text_file,
            vault_status,
            vault_init,
            vault_unlock,
            vault_lock,
            vault_change_master_key,
            vault_reset,
            vault_store_secret,
            vault_get_secret,
            vault_delete_secret,
            vault_list_secrets,
            run_terminal_command,
            tool_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Keystore Studio");
}
