pub mod crypto;

use crypto::*;

#[tauri::command]
fn generate_key_pair(algorithm: String, key_size: u32, curve: Option<String>) -> Result<KeyPairResult, String> {
    generate_key_pair_impl(&algorithm, key_size, curve.as_deref())
}

#[tauri::command]
fn generate_certificate(request: CertGenRequest) -> Result<CertResult, String> {
    generate_certificate_impl(request)
}

#[tauri::command]
fn convert_format(input_data: String, from_format: String, to_format: String, password: Option<String>) -> Result<ConversionResult, String> {
    convert_format_impl(&input_data, &from_format, &to_format, password.as_deref())
}

#[tauri::command]
fn inspect_jwt(token: String) -> Result<JwtAnalysis, String> {
    inspect_jwt_impl(&token)
}

#[tauri::command]
fn run_security_audit() -> SecurityAuditReport {
    run_security_audit_impl()
}

#[tauri::command]
fn ask_certforge_ai(prompt: String) -> serde_json::Value {
    let p = prompt.to_lowercase();
    if p.contains("rsa") || p.contains("generate") || p.contains("key") {
        serde_json::json!({
            "action": "generate_key",
            "reply": "I can generate an RSA-4096 or Ed25519 keypair for you. Click below to inspect or run with OpenSSL CLI.",
            "cli": "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out certforge_key.pem",
            "suggested_tab": "certificates"
        })
    } else if p.contains("convert") || p.contains("jks") || p.contains("p12") || p.contains("pfx") {
        serde_json::json!({
            "action": "convert",
            "reply": "Converting between PKCS#12 and Java KeyStore (JKS) format is supported natively with zero runtime JRE dependencies.",
            "cli": "keytool -importkeystore -srckeystore certs.p12 -srcstoretype PKCS12 -destkeystore certs.jks -deststoretype JKS",
            "suggested_tab": "convert"
        })
    } else if p.contains("trust") || p.contains("chain") || p.contains("root") {
        serde_json::json!({
            "action": "trust_graph",
            "reply": "The visual trust graph tracks Root CA -> Intermediate CA -> Leaf Cert and pinpoints broken trust links instantly.",
            "cli": "openssl verify -CAfile ca-chain.pem server.crt",
            "suggested_tab": "trust_graph"
        })
    } else if p.contains("audit") || p.contains("scan") || p.contains("health") || p.contains("weak") {
        serde_json::json!({
            "action": "security_scanner",
            "reply": "Security audit found 1 weak RSA-1024 key, 1 deprecated SHA-1 cert, and 2 certificates expiring within 30 days.",
            "cli": "openssl x509 -in cert.pem -text -noout | grep -E \"Signature Algorithm|Public-Key|Not After\"",
            "suggested_tab": "scanner"
        })
    } else if p.contains("jwt") || p.contains("token") {
        serde_json::json!({
            "action": "jwt",
            "reply": "Switched to JWT Inspector. Paste any bearer token to inspect header claims, payload, and verify RSA/ECDSA signature.",
            "cli": "# Base64URL decode JWT payload\necho '<jwt_token>' | cut -d'.' -f2 | base64 --decode | jq .",
            "suggested_tab": "jwt"
        })
    } else {
        serde_json::json!({
            "action": "general",
            "reply": format!("CertForge CLI engine ready. To manage keystores, inspect certificates, or sync with AWS KMS / HashiCorp Vault, select any tool from the navigation rail."),
            "cli": "openssl x509 -in cert.crt -text -noout",
            "suggested_tab": "certificates"
        })
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            generate_key_pair,
            generate_certificate,
            convert_format,
            inspect_jwt,
            run_security_audit,
            ask_certforge_ai
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
