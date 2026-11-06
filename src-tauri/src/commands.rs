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
use std::sync::Arc;
use tauri::State;

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
    /// Set by the end-to-end test harness (XKEYSTORE_E2E=1) to script file dialogs.
    e2e: bool,
}

#[tauri::command]
fn app_info(paths: State<Arc<AppPaths>>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        data_dir: paths.data_dir.to_string_lossy().into(),
        platform: std::env::consts::OS.into(),
        home_dir: dirs::home_dir().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        e2e: std::env::var_os("XKEYSTORE_E2E").is_some(),
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
        } else if lower.ends_with(".jar") || lower.ends_with(".war") || lower.ends_with(".ear") || lower.ends_with(".apk") {
            ("jar".to_string(), None)
        } else if let Some(kind) = keystore::detect_unsupported(&head).filter(|_| lower.ends_with(".bks") || lower.ends_with(".uber") || lower.ends_with(".bcfks")) {
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
}

#[tauri::command]
async fn save_keystore(ks: KeystoreFile, path: String, password: String, format: String) -> Res<SaveResult> {
    blocking(move || {
        let fmt = keystore::Format::parse(&format)?;
        let n = keystore::save(&ks, &path, &password, fmt)?;
        Ok(SaveResult { name: util::file_name_of(&path), path, format: fmt.name().into(), byte_length: n })
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

#[tauri::command]
async fn generate_key_pair(input: GenerateKeyPairInput, issuer: Option<KeystoreEntry>) -> Res<KeystoreEntry> {
    blocking(move || ops::generate_key_pair(&input, issuer.as_ref())).await
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

#[tauri::command]
async fn generate_csr(entry: KeystoreEntry, options: CsrOptions) -> Res<CsrResult> {
    blocking(move || ops::generate_csr(&entry, &options)).await
}

#[tauri::command]
async fn import_ca_reply(entry: KeystoreEntry, reply: DataSource) -> Res<KeystoreEntry> {
    blocking(move || ops::import_ca_reply(&entry, &reply.bytes()?)).await
}

#[tauri::command]
async fn rotate_key(entry: KeystoreEntry, algorithm: String, key_size: u32, curve: Option<String>, issuer: Option<KeystoreEntry>) -> Res<KeystoreEntry> {
    blocking(move || ops::rotate_key(&entry, &algorithm, key_size, curve.as_deref(), issuer.as_ref())).await
}

#[tauri::command]
async fn refresh_entry(entry: KeystoreEntry) -> Res<KeystoreEntry> {
    blocking(move || entry::refresh(&entry)).await
}

#[tauri::command]
async fn export_entry(entry: KeystoreEntry, target: String, path: String, password: Option<String>) -> Res<ExportResult> {
    blocking(move || export::export_entry(&entry, &target, &path, password.as_deref())).await
}

#[tauri::command]
async fn jwt_algorithms(entry: KeystoreEntry) -> Res<Vec<String>> {
    Ok(jwt::algorithms_for(&entry).into_iter().map(String::from).collect())
}

// ------------------------------------------------------------------------------------------------
// CA & signing
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn sign_csr(input: SignCsrInput, ca_entry: KeystoreEntry) -> Res<SignedCertificateResult> {
    blocking(move || ops::sign_csr(&input, &ca_entry)).await
}

#[tauri::command]
async fn inspect_csr(data: DataSource) -> Res<CsrInfo> {
    blocking(move || x509::parse_csr(&x509::csr_der_from_bytes(&data.bytes()?)?)).await
}

#[tauri::command]
async fn generate_crl(ca_entry: KeystoreEntry, next_update_days: u32, crl_number: u64, revoked_entries: Vec<RevokedCertEntry>) -> Res<CrlInfo> {
    blocking(move || ops::generate_crl(&ca_entry, next_update_days, crl_number, &revoked_entries)).await
}

#[tauri::command]
async fn cms_sign(content: DataSource, signer_entry: KeystoreEntry, detached: bool, tsa_url: Option<String>) -> Res<CmsSignResult> {
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
            timestamp: timestamp.map(|ts| ts.info(true, None)),
        })
    })
    .await
}

#[tauri::command]
async fn cms_verify(signature: DataSource, content: Option<DataSource>, entry: Option<KeystoreEntry>) -> Res<CmsVerifyResult> {
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
        cms::verify(&der, content_bytes.as_deref(), &extra)
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
            &jwt::JwtClaims {
                issuer: &input.issuer,
                subject: &input.subject,
                audience: &input.audience,
                validity_minutes: input.validity_minutes,
                custom_claims_json: &input.custom_claims_json,
            },
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
async fn jar_sign(input_path: String, output_path: String, signer_entry: KeystoreEntry, tsa_url: Option<String>) -> Res<JarSignResult> {
    blocking(move || jar::sign_jar_timestamped(&input_path, &output_path, &signer_entry, tsa_url.as_deref())).await
}

// ------------------------------------------------------------------------------------------------
// Examine
// ------------------------------------------------------------------------------------------------

#[tauri::command]
async fn examine_tls(host: String, port: u16) -> Res<TlsInspectionResult> {
    blocking(move || tls::inspect(&host, port, 10)).await
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let data_dir = std::env::var_os("XKEYSTORE_DATA_DIR").map(std::path::PathBuf::from).unwrap_or_else(VaultState::default_dir);
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(VaultState::new(data_dir.clone())))
        .manage(Arc::new(AppPaths { data_dir }))
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
            generate_csr,
            import_ca_reply,
            rotate_key,
            refresh_entry,
            export_entry,
            jwt_algorithms,
            sign_csr,
            inspect_csr,
            generate_crl,
            cms_sign,
            cms_verify,
            jwt_sign,
            jwt_verify,
            dh_params,
            jar_sign,
            examine_tls,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running xkeystore");
}
