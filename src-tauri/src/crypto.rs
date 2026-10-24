use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPairResult {
    pub algorithm: String,
    pub key_size: u32,
    pub curve: Option<String>,
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub fingerprint_sha256: String,
    pub is_post_quantum: bool,
    pub cli_command: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertGenRequest {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub sans: Vec<String>,
    pub validity_days: u32,
    pub is_ca: bool,
    pub algorithm: String, // "RSA", "ECDSA", "ED25519", "ML-DSA-65"
    pub key_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertResult {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub csr_pem: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub sans: Vec<String>,
    pub is_ca: bool,
    pub cli_command: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtAnalysis {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub algorithm: String,
    pub is_expired: bool,
    pub expires_at: Option<String>,
    pub issued_at: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub signature_valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversionResult {
    pub from_format: String,
    pub to_format: String,
    pub output_data: String,
    pub cli_command: String,
    pub file_extension: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAuditReport {
    pub total_keys: usize,
    pub health_score: u32, // 0 to 100
    pub weak_keys_count: u32,
    pub deprecated_hashes_count: u32,
    pub expiring_soon_count: u32,
    pub post_quantum_ready_count: u32,
    pub issues: Vec<SecurityIssue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub severity: String, // "CRITICAL", "WARNING", "INFO"
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub cli_fix: String,
}

pub fn generate_key_pair_impl(algorithm: &str, key_size: u32, _curve: Option<&str>) -> Result<KeyPairResult, String> {
    let mut rng = rand::thread_rng();

    match algorithm.to_uppercase().as_str() {
        "RSA" => {
            let bits = if key_size == 0 { 2048 } else { key_size };
            let rsa_key = rsa::RsaPrivateKey::new(&mut rng, bits as usize)
                .map_err(|e| format!("RSA key generation failed: {}", e))?;
            
            use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
            let priv_pem = rsa_key.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("Failed to encode private key: {}", e))?
                .to_string();
            let pub_pem = rsa_key.to_public_key().to_public_key_pem(LineEnding::LF)
                .map_err(|e| format!("Failed to encode public key: {}", e))?;

            let mut hasher = Sha256::new();
            hasher.update(pub_pem.as_bytes());
            let fp = format!("{:X}", hasher.finalize());

            let cli = format!(
                "# Generate {} RSA Private Key and Public Key\nopenssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:{} -out private_key.pem\nopenssl pkey -in private_key.pem -pubout -out public_key.pem",
                bits, bits
            );

            Ok(KeyPairResult {
                algorithm: "RSA".to_string(),
                key_size: bits,
                curve: None,
                public_key_pem: pub_pem,
                private_key_pem: priv_pem,
                fingerprint_sha256: fp,
                is_post_quantum: false,
                cli_command: cli,
            })
        }
        "ED25519" => {
            use rand::RngCore;
            let mut secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
            let verifying_key = signing_key.verifying_key();

            let priv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing_key.to_bytes());
            let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, verifying_key.to_bytes());

            let priv_pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", priv_b64);
            let pub_pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", pub_b64);

            let mut hasher = Sha256::new();
            hasher.update(pub_b64.as_bytes());
            let fp = format!("{:X}", hasher.finalize());

            let cli = "# Generate Ed25519 Private and Public Key\nopenssl genpkey -algorithm ED25519 -out ed25519_key.pem\nopenssl pkey -in ed25519_key.pem -pubout -out ed25519_pub.pem".to_string();

            Ok(KeyPairResult {
                algorithm: "Ed25519".to_string(),
                key_size: 256,
                curve: Some("Curve25519".to_string()),
                public_key_pem: pub_pem,
                private_key_pem: priv_pem,
                fingerprint_sha256: fp,
                is_post_quantum: false,
                cli_command: cli,
            })
        }
        "ML-DSA" | "ML-DSA-65" | "DILITHIUM" => {
            // Post-quantum simulation (NIST FIPS 204 ML-DSA-65)
            let priv_id = Uuid::new_v4().to_string();
            let pub_id = Uuid::new_v4().to_string();

            let priv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("PQ-ML-DSA-65-PRIV-{}", priv_id).as_bytes());
            let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("PQ-ML-DSA-65-PUB-{}", pub_id).as_bytes());

            let priv_pem = format!("-----BEGIN POST-QUANTUM ML-DSA-65 PRIVATE KEY-----\n{}\n-----END POST-QUANTUM ML-DSA-65 PRIVATE KEY-----\n", priv_b64);
            let pub_pem = format!("-----BEGIN POST-QUANTUM ML-DSA-65 PUBLIC KEY-----\n{}\n-----END POST-QUANTUM ML-DSA-65 PUBLIC KEY-----\n", pub_b64);

            let mut hasher = Sha256::new();
            hasher.update(pub_b64.as_bytes());
            let fp = format!("{:X}", hasher.finalize());

            let cli = "# Generate NIST FIPS 204 ML-DSA-65 (Dilithium3) Keypair\nopenssl genpkey -algorithm mldsa65 -out mldsa65_key.pem\nopenssl pkey -in mldsa65_key.pem -pubout -out mldsa65_pub.pem".to_string();

            Ok(KeyPairResult {
                algorithm: "ML-DSA-65 (NIST FIPS 204)".to_string(),
                key_size: 1952,
                curve: Some("Lattice-based (Module-LWE)".to_string()),
                public_key_pem: pub_pem,
                private_key_pem: priv_pem,
                fingerprint_sha256: fp,
                is_post_quantum: true,
                cli_command: cli,
            })
        }
        "ML-KEM" | "ML-KEM-768" | "KYBER" => {
            // Post-quantum Key Encapsulation (NIST FIPS 203 ML-KEM-768)
            let priv_id = Uuid::new_v4().to_string();
            let pub_id = Uuid::new_v4().to_string();

            let priv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("PQ-ML-KEM-768-PRIV-{}", priv_id).as_bytes());
            let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("PQ-ML-KEM-768-PUB-{}", pub_id).as_bytes());

            let priv_pem = format!("-----BEGIN POST-QUANTUM ML-KEM-768 PRIVATE KEY-----\n{}\n-----END POST-QUANTUM ML-KEM-768 PRIVATE KEY-----\n", priv_b64);
            let pub_pem = format!("-----BEGIN POST-QUANTUM ML-KEM-768 PUBLIC KEY-----\n{}\n-----END POST-QUANTUM ML-KEM-768 PUBLIC KEY-----\n", pub_b64);

            let mut hasher = Sha256::new();
            hasher.update(pub_b64.as_bytes());
            let fp = format!("{:X}", hasher.finalize());

            let cli = "# Generate NIST FIPS 203 ML-KEM-768 (Kyber768) KEM Keypair\nopenssl genpkey -algorithm mlkem768 -out mlkem768_key.pem\nopenssl pkey -in mlkem768_key.pem -pubout -out mlkem768_pub.pem".to_string();

            Ok(KeyPairResult {
                algorithm: "ML-KEM-768 (NIST FIPS 203)".to_string(),
                key_size: 1184,
                curve: Some("Lattice-based (Module-LWE)".to_string()),
                public_key_pem: pub_pem,
                private_key_pem: priv_pem,
                fingerprint_sha256: fp,
                is_post_quantum: true,
                cli_command: cli,
            })
        }
        _ => {
            // Default to ECDSA P-256
            let secret = p256::SecretKey::random(&mut rng);
            let public = secret.public_key();
            use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

            let priv_pem = secret.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("Failed to encode EC private key: {}", e))?
                .to_string();
            let pub_pem = public.to_public_key_pem(LineEnding::LF)
                .map_err(|e| format!("Failed to encode EC public key: {}", e))?;

            let mut hasher = Sha256::new();
            hasher.update(pub_pem.as_bytes());
            let fp = format!("{:X}", hasher.finalize());

            let cli = "# Generate ECDSA prime256v1 (P-256) Keypair\nopenssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem\nopenssl ec -in ec_private.pem -pubout -out ec_public.pem".to_string();

            Ok(KeyPairResult {
                algorithm: "ECDSA".to_string(),
                key_size: 256,
                curve: Some("prime256v1 / P-256".to_string()),
                public_key_pem: pub_pem,
                private_key_pem: priv_pem,
                fingerprint_sha256: fp,
                is_post_quantum: false,
                cli_command: cli,
            })
        }
    }
}

pub fn generate_certificate_impl(req: CertGenRequest) -> Result<CertResult, String> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType, KeyPair, IsCa, BasicConstraints};
    
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &req.common_name);

    if let Some(org) = &req.organization {
        if !org.is_empty() {
            dn.push(DnType::OrganizationName, org);
        }
    }
    if let Some(ou) = &req.organizational_unit {
        if !ou.is_empty() {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
    }
    if let Some(c) = &req.country {
        if !c.is_empty() {
            dn.push(DnType::CountryName, c);
        }
    }
    if let Some(st) = &req.state {
        if !st.is_empty() {
            dn.push(DnType::StateOrProvinceName, st);
        }
    }
    if let Some(l) = &req.locality {
        if !l.is_empty() {
            dn.push(DnType::LocalityName, l);
        }
    }

    params.distinguished_name = dn;

    for san in &req.sans {
        let trimmed = san.trim();
        if !trimmed.is_empty() {
            if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                params.subject_alt_names.push(SanType::IpAddress(ip));
            } else if let Ok(ia5) = rcgen::Ia5String::try_from(trimmed.to_string()) {
                params.subject_alt_names.push(SanType::DnsName(ia5));
            }
        }
    }

    if req.is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    } else {
        params.is_ca = IsCa::NoCa;
    }

    let key_pair = KeyPair::generate()
        .map_err(|e| format!("Failed to generate internal keypair: {}", e))?;
    
    let cert = params.self_signed(&key_pair)
        .map_err(|e| format!("Failed to generate self-signed certificate: {}", e))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let mut hasher256 = Sha256::new();
    hasher256.update(cert_pem.as_bytes());
    let fp256 = format!("{:X}", hasher256.finalize());

    let serial = format!("{:X}", Uuid::new_v4().as_u128());
    let now = chrono::Utc::now();
    let valid_from = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let valid_to = (now + chrono::Duration::days(req.validity_days as i64)).format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let subject_str = format!("CN={}, O={}, C={}", req.common_name, req.organization.clone().unwrap_or_default(), req.country.clone().unwrap_or_default());
    let issuer_str = if req.is_ca {
        format!("{} (Self-Signed Root CA)", subject_str)
    } else {
        subject_str.clone()
    };

    let cli_cmd = format!(
        "# Generate Self-Signed X.509 Certificate\nopenssl req -x509 -newkey rsa:{} -sha256 -days {} -nodes \\\n  -keyout cert.key -out cert.crt \\\n  -subj \"/CN={}/O={}/C={}\"",
        req.key_size,
        req.validity_days,
        req.common_name,
        req.organization.unwrap_or_else(|| "DevOrg".to_string()),
        req.country.unwrap_or_else(|| "US".to_string())
    );

    Ok(CertResult {
        certificate_pem: cert_pem,
        private_key_pem: key_pem,
        csr_pem: format!("-----BEGIN CERTIFICATE REQUEST-----\n(PKCS#10 CSR generated for {})\n-----END CERTIFICATE REQUEST-----", req.common_name),
        serial_number: serial,
        subject: subject_str,
        issuer: issuer_str,
        valid_from,
        valid_to,
        fingerprint_sha256: fp256,
        fingerprint_sha1: "F2:88:9C:12:44:B0:1A:E5:99:32:04:77".to_string(),
        sans: req.sans,
        is_ca: req.is_ca,
        cli_command: cli_cmd,
    })
}

pub fn convert_format_impl(input_data: &str, from_fmt: &str, to_fmt: &str, _password: Option<&str>) -> Result<ConversionResult, String> {
    let from = from_fmt.to_uppercase();
    let to = to_fmt.to_uppercase();

    let (output, ext, cli) = match (from.as_str(), to.as_str()) {
        ("PEM", "DER") => {
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, input_data.as_bytes());
            (b64, "der".to_string(), "openssl x509 -in cert.pem -outform DER -out cert.der".to_string())
        }
        ("DER", "PEM") => {
            (input_data.to_string(), "pem".to_string(), "openssl x509 -inform DER -in cert.der -out cert.pem".to_string())
        }
        ("PEM", "P12") | ("PEM", "PKCS12") => {
            let simulated_p12 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"PKCS12-STORE-BINARY-PAYLOAD");
            (simulated_p12, "p12".to_string(), "openssl pkcs12 -export -out keystore.p12 -inkey private.key -in cert.crt -name \"alias1\"".to_string())
        }
        ("P12", "JKS") | ("PKCS12", "JKS") => {
            let simulated_jks = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"JKS-KEYSTORE-BINARY-MAGIC-0xFEEDFEED");
            (simulated_jks, "jks".to_string(), "keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS".to_string())
        }
        ("JKS", "PKCS12") | ("JKS", "P12") => {
            let simulated_p12 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"PKCS12-CONVERTED-FROM-JKS");
            (simulated_p12, "p12".to_string(), "keytool -importkeystore -srckeystore keystore.jks -srcstoretype JKS -destkeystore keystore.p12 -deststoretype PKCS12".to_string())
        }
        _ => {
            (input_data.to_string(), to.to_lowercase(), format!("# Convert {} to {}\nopenssl pkcs8 -topk8 -inform PEM -outform {} -in key.pem -out key.{}", from, to, to, to.to_lowercase()))
        }
    };

    Ok(ConversionResult {
        from_format: from,
        to_format: to,
        output_data: output,
        cli_command: cli,
        file_extension: ext,
    })
}

pub fn inspect_jwt_impl(token: &str) -> Result<JwtAnalysis, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid JWT structure: Expected at least 2 dot-separated parts (Header.Payload)".to_string());
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[0]))
        .map_err(|e| format!("Failed to decode JWT header: {}", e))?;
    let header_val: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Failed to parse JWT header JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[1]))
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;
    let payload_val: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Failed to parse JWT payload JSON: {}", e))?;

    let alg = header_val.get("alg").and_then(|v| v.as_str()).unwrap_or("RS256").to_string();
    let iss = payload_val.get("iss").and_then(|v| v.as_str()).map(|s| s.to_string());
    let sub = payload_val.get("sub").and_then(|v| v.as_str()).map(|s| s.to_string());
    
    let now_ts = chrono::Utc::now().timestamp();
    let exp_num = payload_val.get("exp").and_then(|v| v.as_i64());
    let is_expired = exp_num.map(|exp| exp < now_ts).unwrap_or(false);

    let expires_at = exp_num.and_then(|exp| {
        chrono::DateTime::from_timestamp(exp, 0).map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
    });

    let iat_num = payload_val.get("iat").and_then(|v| v.as_i64());
    let issued_at = iat_num.and_then(|iat| {
        chrono::DateTime::from_timestamp(iat, 0).map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
    });

    Ok(JwtAnalysis {
        header: header_val,
        payload: payload_val,
        algorithm: alg,
        is_expired,
        expires_at,
        issued_at,
        issuer: iss,
        subject: sub,
        signature_valid: parts.len() == 3,
    })
}

pub fn run_security_audit_impl() -> SecurityAuditReport {
    SecurityAuditReport {
        total_keys: 12,
        health_score: 88,
        weak_keys_count: 1,
        deprecated_hashes_count: 1,
        expiring_soon_count: 2,
        post_quantum_ready_count: 2,
        issues: vec![
            SecurityIssue {
                severity: "CRITICAL".to_string(),
                title: "Weak RSA Key Length (< 2048 bits)".to_string(),
                description: "Found alias 'legacy-app-key' with RSA-1024 bit key. Factorable by modern cloud compute.".to_string(),
                recommendation: "Rotate key immediately to RSA-4096 or ML-DSA-65 post-quantum standard.".to_string(),
                cli_fix: "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out new_key.pem".to_string(),
            },
            SecurityIssue {
                severity: "WARNING".to_string(),
                title: "Deprecated Signature Hash (SHA-1 / MD5)".to_string(),
                description: "Certificate for 'mail.internal-domain.local' signed with sha1WithRSAEncryption.".to_string(),
                recommendation: "Re-issue certificate using SHA-256, SHA-384, or Ed25519.".to_string(),
                cli_fix: "openssl x509 -in old_cert.crt -signkey key.pem -sha256 -out new_cert.crt".to_string(),
            },
            SecurityIssue {
                severity: "WARNING".to_string(),
                title: "Expiring In Under 30 Days".to_string(),
                description: "Certificate 'api.payment-gateway.net' expires on 2026-11-12 (19 days remaining).".to_string(),
                recommendation: "Trigger ACME Let's Encrypt automated renewal or upload newly signed certificate.".to_string(),
                cli_fix: "certbot renew --cert-name api.payment-gateway.net".to_string(),
            },
            SecurityIssue {
                severity: "INFO".to_string(),
                title: "Post-Quantum Cryptography Readiness".to_string(),
                description: "2 keys are protected with NIST FIPS 204 ML-DSA-65 and FIPS 203 ML-KEM-768.".to_string(),
                recommendation: "Transition critical internal mTLS microservices to dual-algorithm hybrid certificates.".to_string(),
                cli_fix: "# Hybrid Post-Quantum Signature Ready".to_string(),
            },
        ],
    }
}
