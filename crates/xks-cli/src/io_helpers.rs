use std::io::BufRead;
use std::path::Path;

use anyhow::{bail, Context, Result};
use xks_core::keys::KeyMaterial;

pub fn read_key(path: &Path) -> Result<KeyMaterial> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading key file {}", path.display()))?;
    KeyMaterial::from_pkcs8_pem_autodetect(&text)
        .with_context(|| format!("parsing private key from {}", path.display()))
}

/// Read every "CERTIFICATE" PEM block from a file, in order. Accepts a
/// single cert or a concatenated chain file.
pub fn read_certs(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading certificate file {}", path.display()))?;
    let blocks =
        pem::parse_many(&bytes).with_context(|| format!("parsing PEM from {}", path.display()))?;
    let certs: Vec<Vec<u8>> = blocks
        .into_iter()
        .filter(|b| b.tag() == "CERTIFICATE")
        .map(|b| b.contents().to_vec())
        .collect();
    if certs.is_empty() {
        bail!("no CERTIFICATE blocks found in {}", path.display());
    }
    Ok(certs)
}

pub fn read_one_cert(path: &Path) -> Result<Vec<u8>> {
    let mut certs = read_certs(path)?;
    if certs.len() > 1 {
        eprintln!(
            "note: {} contains {} certificates; using only the first",
            path.display(),
            certs.len()
        );
    }
    Ok(certs.remove(0))
}

/// Resolve `--chain <path>`, a comma-separated list of paths, into a flat
/// DER list (intermediates then root, in the order given).
pub fn read_chain(paths_csv: Option<&str>) -> Result<Vec<Vec<u8>>> {
    let Some(csv) = paths_csv else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for p in csv.split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        out.extend(read_certs(Path::new(p))?);
    }
    Ok(out)
}

/// A password from `--password`, `--password-file`, or (last resort) a
/// plain-text prompt on stdin. There's no hidden-input story here without
/// adding another dependency; scripted use should prefer `--password-file`.
pub fn resolve_password(password: Option<&str>, password_file: Option<&Path>, prompt: &str) -> Result<String> {
    if let Some(p) = password {
        return Ok(p.to_string());
    }
    if let Some(path) = password_file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading password file {}", path.display()))?;
        return Ok(text.trim_end_matches(['\n', '\r']).to_string());
    }
    eprint!("{prompt}: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub fn write_out(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}
