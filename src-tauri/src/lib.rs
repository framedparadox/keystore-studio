pub mod crypto;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use crypto::*;
use uuid::Uuid;

#[tauri::command]
fn generate_keypair_entry(
    input: GenerateKeyPairInput,
    issuer_dn: Option<String>,
) -> Result<KeystoreEntry, String> {
    create_keystore_keypair_entry(&input, issuer_dn)
}

#[tauri::command]
fn generate_secret_key_entry(input: GenerateSecretKeyInput) -> Result<KeystoreEntry, String> {
    create_secret_key_entry(&input)
}

#[tauri::command]
fn generate_csr(entry: KeystoreEntry, format: String) -> Result<CsrResult, String> {
    generate_csr_for_entry(&entry, &format)
}

#[tauri::command]
fn sign_csr(input: SignCsrInput, ca_entry: KeystoreEntry) -> Result<CertificateInfo, String> {
    sign_csr_with_ca(&input, &ca_entry)
}

#[tauri::command]
fn generate_crl(
    ca_entry: KeystoreEntry,
    next_update_days: u32,
    revoked_entries: Vec<RevokedCertEntry>,
) -> Result<CrlResult, String> {
    generate_signed_crl(&ca_entry, next_update_days, revoked_entries)
}

#[tauri::command]
fn sign_jar(
    jar_name: String,
    class_files: Vec<String>,
    signer_entry: KeystoreEntry,
    tsa_url: Option<String>,
) -> Result<JarSignatureResult, String> {
    sign_jar_archive(&jar_name, class_files, &signer_entry, tsa_url)
}

#[tauri::command]
fn sign_cms(
    payload: String,
    signer_entry: KeystoreEntry,
    detached: bool,
) -> Result<CmsSignResult, String> {
    sign_cms_payload(&payload, &signer_entry, detached)
}

#[tauri::command]
fn verify_cms(
    payload: String,
    signature_hex: String,
    signer_entry: KeystoreEntry,
) -> Result<bool, String> {
    verify_cms_signature(&payload, &signature_hex, &signer_entry)
}

#[tauri::command]
fn generate_dh_params(bit_size: u32) -> Result<DhParamsResult, String> {
    generate_dh_parameters(bit_size)
}

#[tauri::command]
fn sign_jwt(
    issuer: String,
    subject: String,
    audience: String,
    validity_hours: u32,
    custom_claims_json: String,
    signer_entry: KeystoreEntry,
) -> Result<String, String> {
    sign_jwt_token(
        &issuer,
        &subject,
        &audience,
        validity_hours,
        &custom_claims_json,
        &signer_entry,
    )
}

#[tauri::command]
fn examine_ssl(host: String, port: u16) -> Result<SslInspectionResult, String> {
    examine_ssl_host(&host, port)
}

#[tauri::command]
fn detect_and_examine(raw_input: String) -> Result<FileDetectionResult, String> {
    detect_and_examine_data(&raw_input)
}

#[tauri::command]
fn export_entry(entry: KeystoreEntry, export_target: String) -> Result<ExportPayloadResult, String> {
    export_entry_in_format(&entry, &export_target)
}

#[tauri::command]
fn export_keystore_to_csv(ks: KeystoreFile) -> Result<ExportPayloadResult, String> {
    export_keystore_csv(&ks)
}

#[tauri::command]
fn save_keystore_file(ks: KeystoreFile, password: String) -> Result<ExportPayloadResult, String> {
    let jks_bytes = serialize_keystore_to_jks_bytes(&ks, &password)?;
    let b64_content = B64.encode(&jks_bytes);
    let filename = ks.name.clone();

    let mut saved_path = None;
    if let Some(mut dl_dir) = dirs::download_dir().or_else(dirs::home_dir) {
        dl_dir.push("xkeystore_Exports");
        let _ = std::fs::create_dir_all(&dl_dir);
        dl_dir.push(&filename);
        if std::fs::write(&dl_dir, &jks_bytes).is_ok() {
            saved_path = Some(dl_dir.to_string_lossy().to_string());
        }
    }

    Ok(ExportPayloadResult {
        filename,
        format: format!("{} Native KeyStore Binary", ks.format),
        mime_type: "application/octet-stream".to_string(),
        content: b64_content,
        saved_path,
        byte_length: jks_bytes.len(),
    })
}

#[tauri::command]
fn import_pem_certificate(
    alias: String,
    subject_cn: String,
    issuer_cn: String,
    pem_data: String,
    labels: Vec<String>,
) -> Result<KeystoreEntry, String> {
    let clean_pem = if pem_data.trim().is_empty() {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(format!("X509-TRUSTED-CERT:{}:{}", alias, subject_cn).as_bytes())
        )
    } else {
        pem_data.trim().to_string()
    };

    let sha256_fp = compute_sha256_colon(clean_pem.as_bytes());
    let sha1_fp = compute_sha1_colon(clean_pem.as_bytes());
    let md5_fp = compute_md5_colon(clean_pem.as_bytes());
    let now = Utc::now();
    let expiry = now + chrono::Duration::days(730);
    let serial = format!("{:032X}", Uuid::new_v4().as_u128());

    let cert_info = CertificateInfo {
        version: 3,
        serial_number: serial.clone(),
        signature_algorithm: "SHA256withRSA".to_string(),
        subject: format!("CN={}, O=Imported Trusted Entity, C=US", subject_cn),
        issuer: format!("CN={}, O=Trusted Root CA, C=US", issuer_cn),
        valid_from: now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        valid_to: expiry.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        days_remaining: 730,
        is_ca: true,
        public_key_algorithm: "RSA".to_string(),
        key_size: 4096,
        sans: vec![subject_cn.clone()],
        key_usage: vec!["Digital Signature".to_string(), "Key Cert Sign".to_string()],
        extended_key_usage: vec!["TLS Web Server Authentication".to_string()],
        extensions: vec![X509ExtensionInfo {
            oid: "2.5.29.19".to_string(),
            name: "Basic Constraints".to_string(),
            critical: true,
            value: "CA:TRUE".to_string(),
        }],
        sha256_fingerprint: sha256_fp.clone(),
        sha1_fingerprint: sha1_fp.clone(),
        md5_fingerprint: md5_fp,
        pem: clean_pem.clone(),
    };

    Ok(KeystoreEntry {
        id: format!("entry-{}", Uuid::new_v4()),
        alias: alias.trim().to_lowercase(),
        entry_type: "TrustedCertificate".to_string(),
        algorithm: "RSA".to_string(),
        key_size: 4096,
        curve: None,
        creation_date: now.format("%Y-%m-%d").to_string(),
        expiry_date: expiry.format("%Y-%m-%d").to_string(),
        last_modified: now.format("%Y-%m-%d").to_string(),
        subject: cert_info.subject.clone(),
        issuer: cert_info.issuer.clone(),
        serial_number: serial,
        sha256_fingerprint: sha256_fp,
        sha1_fingerprint: sha1_fp,
        chain_length: 1,
        certificate_chain: vec![cert_info],
        private_key_pem: None,
        public_key_pem: Some(clean_pem),
        secret_key_hex: None,
        locked: false,
        labels: if labels.is_empty() {
            vec!["TrustedCert".to_string(), "Imported".to_string()]
        } else {
            labels
        },
        is_expired: false,
        is_weak: false,
        is_post_quantum: false,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            generate_keypair_entry,
            generate_secret_key_entry,
            generate_csr,
            sign_csr,
            generate_crl,
            sign_jar,
            sign_cms,
            verify_cms,
            generate_dh_params,
            sign_jwt,
            examine_ssl,
            detect_and_examine,
            export_entry,
            export_keystore_to_csv,
            save_keystore_file,
            import_pem_certificate
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
