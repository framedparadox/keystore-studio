//! A minimal HTTP sidecar exposing the engine operations the UI calls, so the real frontend can be
//! driven in a headless browser on machines where the webview cannot run (no display surface).
//! Dev-only: it binds 127.0.0.1 on an ephemeral port and speaks one JSON request per connection.

use std::io::{BufRead, BufReader, Read, Write};

fn json_err(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
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
        "load_app_state" => Ok(serde_json::Value::Null),
        "save_app_state" => Ok(serde_json::Value::Null),
        "vault_status" => Ok(serde_json::json!({ "exists": false, "unlocked": false, "secret_count": 0 })),
        "build_pkcs12" => {
            let key_password = args.get("keyPassword").and_then(|v| v.as_str()).map(String::from).filter(|p| !p.is_empty());
            let certificate = match args.get("certificate") {
                Some(v) if !v.is_null() => Some(source("certificate")?),
                _ => None,
            };
            let input = xkeystore_lib::model::BuildPkcs12Input {
                alias: args.get("alias").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                key: source("key")?,
                certificate,
                key_password,
                passphrase: s("passphrase"),
                mac: args.get("mac").and_then(|v| v.as_str()).map(String::from),
            };
            let der = xkeystore_lib::ops::build_pkcs12(&input)?;
            let path = s("path");
            xkeystore_lib::util::write_atomic(std::path::Path::new(&path), &der)?;
            Ok(serde_json::json!({
                "path": path,
                "format": "PKCS#12 (certificate and private key)",
                "byte_length": der.len(),
                "text": serde_json::Value::Null,
            }))
        }
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
