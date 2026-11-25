//! A minimal HTTP sidecar exposing the engine operations the UI calls, so the real frontend can be
//! driven in a headless browser on machines where the webview cannot run (no display surface).
//! Dev-only: it binds 127.0.0.1 on an ephemeral port and speaks one JSON request per connection.

use std::io::{BufRead, BufReader, Read, Write};

/// The app state the UI saves, kept in memory so a page reload restores it like a restart does.
static APP_STATE: std::sync::Mutex<serde_json::Value> = std::sync::Mutex::new(serde_json::Value::Null);

/// The real vault, kept in a fresh folder of its own for each bridge run, so it starts empty.
fn vault() -> &'static keystore_studio_lib::vault::VaultState {
    static VAULT: std::sync::OnceLock<keystore_studio_lib::vault::VaultState> = std::sync::OnceLock::new();
    VAULT.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ui-bridge-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("vault folder");
        keystore_studio_lib::vault::VaultState::new(dir)
    })
}

fn json_err(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

/// A required argument, deserialised into the engine's own type.
fn arg<T: serde::de::DeserializeOwned>(args: &serde_json::Value, k: &str) -> Result<T, String> {
    serde_json::from_value(args.get(k).cloned().ok_or_else(|| format!("missing {k}"))?).map_err(|e| format!("bad {k}: {e}"))
}

/// An optional argument: absent or null is None.
fn opt_arg<T: serde::de::DeserializeOwned>(args: &serde_json::Value, k: &str) -> Result<Option<T>, String> {
    match args.get(k) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| format!("bad {k}: {e}")),
    }
}

fn to_json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

fn handle(cmd: &str, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let s = |k: &str| -> String { args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string() };
    // A DataSource from the UI: { path } or { text }.
    let source = |k: &str| -> Result<Vec<u8>, String> {
        let v = args.get(k).ok_or_else(|| format!("missing {k}"))?;
        if let Some(p) = v.get("path").and_then(|p| p.as_str()).filter(|p| !p.is_empty()) {
            return std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"));
        }
        if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
            return Ok(t.as_bytes().to_vec());
        }
        Err(format!("{k} has neither path nor text"))
    };

    match cmd {
        // e2e: true makes the UI take file-dialog answers from window.__xksStub instead of
        // calling the native dialog plugin, which does not exist in a plain browser.
        "app_info" => Ok(serde_json::json!({
            "version": "1.0.0",
            "data_dir": std::env::temp_dir().to_string_lossy(),
            "platform": "macos",
            "home_dir": std::env::var("HOME").unwrap_or_default(),
            "e2e": true,
        })),
        "load_app_state" => Ok(APP_STATE.lock().map_err(|e| e.to_string())?.clone()),
        "save_app_state" => {
            *APP_STATE.lock().map_err(|e| e.to_string())? = args.get("state").cloned().unwrap_or_default();
            Ok(serde_json::Value::Null)
        }
        "vault_status" => to_json(vault().status()?),
        "vault_init" => to_json(vault().init(&s("masterKey"))?),
        "vault_unlock" => to_json(vault().unlock(&s("masterKey"))?),
        "vault_lock" => to_json(vault().lock()?),
        "vault_store_secret" => to_json(vault().store_secret(&s("id"), &s("label"), &s("secret"))?),
        "vault_get_secret" => to_json(vault().get_secret(&s("id"))?),
        "vault_delete_secret" => to_json(vault().delete_secret(&s("id"))?),
        "vault_list_secrets" => to_json(vault().list_secrets()?),
        "examine_tls" => {
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
            to_json(keystore_studio_lib::tls::inspect(&s("host"), port, 10)?)
        }
        "run_terminal_command" => {
            let cwd = args.get("cwd").and_then(|v| v.as_str()).map(String::from);
            let timeout = args.get("timeoutSecs").and_then(|v| v.as_u64()).unwrap_or(120);
            to_json(keystore_studio_lib::terminal::run(&s("command"), cwd, timeout)?)
        }
        "build_pkcs12" => {
            let key_password = args.get("keyPassword").and_then(|v| v.as_str()).map(String::from).filter(|p| !p.is_empty());
            let certificate = match args.get("certificate") {
                Some(v) if !v.is_null() => Some(source("certificate")?),
                _ => None,
            };
            let input = keystore_studio_lib::model::BuildPkcs12Input {
                alias: args.get("alias").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                key: source("key")?,
                certificate,
                key_password,
                passphrase: s("passphrase"),
                mac: args.get("mac").and_then(|v| v.as_str()).map(String::from),
            };
            let der = keystore_studio_lib::ops::build_pkcs12(&input)?;
            let path = s("path");
            keystore_studio_lib::util::write_atomic(std::path::Path::new(&path), &der)?;
            Ok(serde_json::json!({
                "path": path,
                "format": "PKCS#12 (certificate and private key)",
                "byte_length": der.len(),
                "text": serde_json::Value::Null,
            }))
        }
        // The three commands the keystore screens need: sniff a file, open it, save it.
        "probe_file" => {
            // As probe_file in src/commands.rs: a keystore, else whatever examine recognises, so a
            // dropped certificate is routed to Examine like it is in the app.
            let path = s("path");
            let head = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
            let fmt = keystore_studio_lib::keystore::detect(&head).map(|f| f.name().to_string());
            let kind = match &fmt {
                Some(_) => "keystore".to_string(),
                None => keystore_studio_lib::detect::examine(&head, None).map(|r| r.kind).unwrap_or_else(|_| "unknown".into()),
            };
            let probe = keystore_studio_lib::model::FileProbe { name: keystore_studio_lib::util::file_name_of(&path), size: head.len() as u64, kind, keystore_format: fmt, path };
            serde_json::to_value(probe).map_err(|e| e.to_string())
        }
        "open_keystore" => {
            let key_passwords: std::collections::HashMap<String, String> = match args.get("keyPasswords") {
                Some(v) if !v.is_null() => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
                _ => Default::default(),
            };
            let ks = keystore_studio_lib::keystore::open(&s("path"), &s("password"), &key_passwords)?;
            serde_json::to_value(ks).map_err(|e| e.to_string())
        }
        "save_keystore" => {
            let ks: keystore_studio_lib::model::KeystoreFile = serde_json::from_value(args.get("ks").cloned().unwrap_or_default()).map_err(|e| e.to_string())?;
            let fmt = keystore_studio_lib::keystore::Format::parse(&s("format"))?;
            let mac = keystore_studio_lib::pkcs12::MacKind::parse(args.get("mac").and_then(|v| v.as_str()));
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            let path = s("path");
            let n = keystore_studio_lib::keystore::save_with(&ks, &path, &s("password"), fmt, keystore_studio_lib::keystore::SavePolicy { mac, force })?;
            Ok(serde_json::json!({
                "name": keystore_studio_lib::util::file_name_of(&path),
                "path": path,
                "format": fmt.name(),
                "byte_length": n,
                "mtime_ms": keystore_studio_lib::keystore::mtime_ms(std::path::Path::new(&path)),
            }))
        }
        "test_connection" => {
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
            let timeout = args.get("timeoutSecs").and_then(|v| v.as_u64()).unwrap_or(5);
            to_json(keystore_studio_lib::netcheck::test(&s("target"), port, timeout)?)
        }
        "examine_data" => {
            let pw = args.get("password").and_then(|v| v.as_str()).filter(|p| !p.is_empty());
            serde_json::to_value(keystore_studio_lib::detect::examine(&source("data")?, pw)?).map_err(|e| e.to_string())
        }
        // Conversions: the same engine calls the Tauri commands make.
        "convert_certificates" | "convert_private_key" | "convert_public_key" | "convert_encoding" | "convert_truststore" | "entries_to_pem" => {
            use keystore_studio_lib::convert;
            let opt = |k: &str| args.get(k).and_then(|v| v.as_str()).map(String::from).filter(|v| !v.is_empty());
            let out = match cmd {
                "convert_certificates" => convert::certificates(&source("data")?, &s("target"), args.get("order").and_then(|v| v.as_bool()).unwrap_or(true))?,
                "convert_private_key" => convert::private_key(&source("data")?, opt("password").as_deref(), &s("target"), opt("outPassword").as_deref(), &s("comment"))?,
                "convert_truststore" => convert::truststore(&source("data")?, &s("format"), &s("password"), &s("alias"))?,
                "convert_public_key" => convert::public_key(&source("data")?, opt("password").as_deref(), &s("target"), &s("comment"))?,
                "convert_encoding" => convert::encoding(&source("data")?, opt("label").as_deref())?,
                _ => {
                    let entries: Vec<keystore_studio_lib::model::KeystoreEntry> = serde_json::from_value(args.get("entries").cloned().unwrap_or_default()).map_err(|e| e.to_string())?;
                    let options: convert::PemBundleOptions = serde_json::from_value(args.get("options").cloned().unwrap_or_default()).map_err(|e| e.to_string())?;
                    convert::entries_to_pem(&entries, &options)?
                }
            };
            serde_json::to_value(convert::deliver(out, opt("path").as_deref())?).map_err(|e| e.to_string())
        }
        "write_text_file" => {
            let path = s("path");
            keystore_studio_lib::util::write_atomic(std::path::Path::new(&path), s("content").as_bytes())?;
            Ok(serde_json::Value::Null)
        }
        // Entries: the same engine calls as the Tauri commands (see src/commands.rs).
        "generate_key_pair" => {
            let input: keystore_studio_lib::model::GenerateKeyPairInput = arg(args, "input")?;
            let issuer: Option<keystore_studio_lib::model::KeystoreEntry> = opt_arg(args, "issuer")?;
            let (entry, note) = keystore_studio_lib::ops::issue_key_pair(&input, issuer.as_ref())?;
            let mut value = serde_json::to_value(entry).map_err(|e| e.to_string())?;
            if let (Some(note), Some(obj)) = (note, value.as_object_mut()) {
                obj.insert("validity_note".into(), note.into());
            }
            Ok(value)
        }
        "generate_secret_key" => to_json(keystore_studio_lib::ops::generate_secret_key(&arg(args, "input")?)?),
        "import_trusted_certificates" => {
            let existing: Vec<String> = arg(args, "existingAliases")?;
            to_json(keystore_studio_lib::ops::import_trusted_certificates(&s("alias"), &source("data")?, &existing)?)
        }
        "generate_csr" => to_json(keystore_studio_lib::ops::generate_csr(&arg(args, "entry")?, &arg(args, "options")?)?),
        "import_ca_reply" => to_json(keystore_studio_lib::ops::import_ca_reply(&arg(args, "entry")?, &source("reply")?)?),
        "sign_csr" => to_json(keystore_studio_lib::ops::sign_csr(&arg(args, "input")?, &arg(args, "caEntry")?)?),
        "inspect_csr" => to_json(keystore_studio_lib::x509::parse_csr(&keystore_studio_lib::x509::csr_der_from_bytes(&source("data")?)?)?),
        "rotate_key" => {
            let issuer: Option<keystore_studio_lib::model::KeystoreEntry> = opt_arg(args, "issuer")?;
            let curve = args.get("curve").and_then(|v| v.as_str()).map(String::from);
            let size = args.get("keySize").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            to_json(keystore_studio_lib::ops::rotate_key(&arg(args, "entry")?, &s("algorithm"), size, curve.as_deref(), issuer.as_ref())?)
        }
        "export_entry" => {
            let password = args.get("password").and_then(|v| v.as_str()).filter(|p| !p.is_empty());
            to_json(keystore_studio_lib::export::export_entry(&arg(args, "entry")?, &s("target"), &s("path"), password)?)
        }
        "jwt_algorithms" => {
            let entry: keystore_studio_lib::model::KeystoreEntry = arg(args, "entry")?;
            to_json(keystore_studio_lib::jwt::algorithms_for(&entry))
        }
        "validate_chain" => {
            let pems = |k: &str| -> Result<Vec<Vec<u8>>, String> {
                let text = s(k);
                if text.trim().is_empty() { Ok(Vec::new()) } else { keystore_studio_lib::x509::certificates_from_bytes(text.as_bytes()) }
            };
            let leaf = pems("leafPem")?.into_iter().next().ok_or("no leaf certificate")?;
            let hostname = args.get("hostname").and_then(|v| v.as_str());
            let (mut problems, path) = keystore_studio_lib::x509::validate_chain_path(&leaf, &pems("intermediatesPem")?, &pems("anchorsPem")?, hostname);
            if args.get("checkRevocation").and_then(|v| v.as_bool()).unwrap_or(false) && problems.is_empty() {
                problems.extend(keystore_studio_lib::revocation::check_path(&path, &keystore_studio_lib::revocation::network()));
            }
            to_json(problems)
        }
        // A browser has no native window to mark.
        "set_document_edited" => to_json(()),
        "system_trust_anchors" => to_json(keystore_studio_lib::tls::system_trust_anchors_pem()),
        "check_ocsp" => {
            let subject = keystore_studio_lib::x509::certificates_from_bytes(s("subjectPem").as_bytes())?.into_iter().next().ok_or("no subject certificate")?;
            let issuer = keystore_studio_lib::x509::certificates_from_bytes(s("issuerPem").as_bytes())?.into_iter().next().ok_or("no issuer certificate")?;
            let url = match opt_arg::<String>(args, "url")?.filter(|u| !u.trim().is_empty()) {
                Some(u) => u,
                None => keystore_studio_lib::x509::parse_certificate(&subject)?.ocsp_urls.into_iter().next().ok_or("this certificate carries no OCSP responder URL")?,
            };
            to_json(keystore_studio_lib::ocsp::check(&url, &subject, &issuer)?.info())
        }
        // State the UI reads on its pages; the bridge keeps none, so these answer "empty".
        "tool_status" => to_json(keystore_studio_lib::tools::status()),
        "ledger_search" => Ok(serde_json::json!([])),
        "ca_next_crl_number" => Ok(serde_json::json!(1)),
        other => Err(format!("ui_bridge does not implement '{other}'")),
    }
}

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    println!("{}", listener.local_addr().unwrap().port());
    std::io::stdout().flush().unwrap();
    for conn in listener.incoming() {
        let mut conn = match conn {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut len = 0usize;
        let mut line = String::new();
        // Read request headers; we only need Content-Length.
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let l = line.trim_end().to_string();
            if l.is_empty() {
                break;
            }
            if let Some(v) = l.to_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
            line.clear();
        }
        let mut body = vec![0u8; len];
        let _ = reader.read_exact(&mut body);
        let reply = match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(req) => {
                let cmd = req.get("cmd").and_then(|c| c.as_str()).unwrap_or("").to_string();
                let args = req.get("args").cloned().unwrap_or(serde_json::Value::Null);
                match handle(&cmd, &args) {
                    Ok(value) => serde_json::json!({ "ok": value }).to_string(),
                    Err(err) => json_err(&err),
                }
            }
            Err(err) => json_err(&format!("bad request: {err}")),
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        );
        let _ = conn.write_all(head.as_bytes());
        let _ = conn.write_all(reply.as_bytes());
        let _ = conn.flush();
    }
}
