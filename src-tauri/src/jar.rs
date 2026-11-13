//! JAR signing compatible with `jarsigner -verify`: per-entry SHA-256 manifest digests, a
//! signature file (.SF) and a detached CMS signature block (.RSA/.EC) over the .SF.

use crate::entry;
use crate::model::{JarSignResult, KeystoreEntry};
use crate::util::*;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::io::{Read, Write};

fn is_signature_file(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("META-INF/") else { return false };
    !rest.contains('/') && (rest.ends_with(".SF") || rest.ends_with(".RSA") || rest.ends_with(".DSA") || rest.ends_with(".EC") || rest.starts_with("SIG-"))
}

/// One manifest header, wrapped at 72 bytes with single-space continuation lines.
fn header(key: &str, value: &str) -> String {
    let line = format!("{key}: {value}");
    let mut out = String::new();
    let mut current = String::new();
    let mut limit = 72;
    for ch in line.chars() {
        if current.len() + ch.len_utf8() > limit {
            out.push_str(&current);
            out.push_str("\r\n ");
            current.clear();
            limit = 71;
        }
        current.push(ch);
    }
    out.push_str(&current);
    out.push_str("\r\n");
    out
}

/// Keeps the main attributes of an existing manifest (re-wrapped), dropping per-entry sections.
fn main_section(existing: Option<&str>) -> String {
    let mut attrs: Vec<(String, String)> = Vec::new();
    if let Some(text) = existing {
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let mut logical: Vec<String> = Vec::new();
        for line in normalized.lines() {
            if line.is_empty() {
                break;
            }
            if let Some(cont) = line.strip_prefix(' ') {
                if let Some(last) = logical.last_mut() {
                    last.push_str(cont);
                }
            } else {
                logical.push(line.to_string());
            }
        }
        for l in logical {
            if let Some((k, v)) = l.split_once(": ") {
                attrs.push((k.to_string(), v.to_string()));
            }
        }
    }
    attrs.retain(|(k, _)| !k.eq_ignore_ascii_case("Manifest-Version") && !k.eq_ignore_ascii_case("Created-By"));
    let mut out = header("Manifest-Version", "1.0");
    out.push_str(&header("Created-By", &format!("Keystore Studio {}", env!("CARGO_PKG_VERSION"))));
    for (k, v) in attrs {
        out.push_str(&header(&k, &v));
    }
    out.push_str("\r\n");
    out
}

fn block_base_name(alias: &str) -> String {
    let mut name: String = alias.to_ascii_uppercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).take(8).collect();
    if name.is_empty() {
        name = "SIGNER".into();
    }
    name
}

pub fn sign_jar(input: &str, output: &str, signer: &KeystoreEntry) -> Res<JarSignResult> {
    sign_jar_timestamped(input, output, signer, None)
}

/// Signs a JAR, optionally adding an RFC 3161 timestamp from `tsa_url`.
///
/// Timestamping matters most here: a signed JAR outlives its signing certificate, and without a
/// timestamp `jarsigner -verify` warns that the signer certificate has expired once it does.
pub fn sign_jar_timestamped(input: &str, output: &str, signer: &KeystoreEntry, tsa_url: Option<&str>) -> Res<JarSignResult> {
    sign_jar_with_trust(input, output, signer, tsa_url, None)
}

pub fn sign_jar_with_trust(input: &str, output: &str, signer: &KeystoreEntry, tsa_url: Option<&str>, tsa_trust_pem: Option<&str>) -> Res<JarSignResult> {
    if signer.entry_type != "KeyPair" {
        return Err("JAR signing needs a key pair entry".into());
    }
    if std::path::Path::new(input).canonicalize().ok() == std::path::Path::new(output).canonicalize().ok() {
        return Err("choose a different output file; the original JAR is never modified in place".into());
    }
    let key = entry::private_key(signer)?;
    let chain = entry::chain_der(signer)?;
    if chain.is_empty() {
        return Err(format!("'{}' has no certificate", signer.alias));
    }
    if let Some(leaf) = signer.certificate_chain.first()
        && leaf.not_after < now_ts()
    {
        return Err(format!("the certificate of '{}' has expired", signer.alias));
    }
    let file = std::fs::File::open(input).map_err(|err| format!("cannot open {input}: {err}"))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| format!("{input} is not a valid JAR/ZIP file: {err}"))?;

    let mut existing_manifest = None;
    let mut digests: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(e)?;
        let name = f.name().to_string();
        if f.is_dir() {
            continue;
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data).map_err(|err| format!("cannot read {name}: {err}"))?;
        if name.eq_ignore_ascii_case("META-INF/MANIFEST.MF") {
            existing_manifest = Some(String::from_utf8_lossy(&data).to_string());
            continue;
        }
        if is_signature_file(&name) {
            continue;
        }
        digests.push((name, B64.encode(sha256(&data))));
    }
    if digests.is_empty() {
        return Err("the archive contains no files to sign".into());
    }

    let main = main_section(existing_manifest.as_deref());
    let mut manifest = main.clone();
    let mut sections = Vec::new();
    for (name, digest) in &digests {
        let section = format!("{}{}\r\n", header("Name", name), header("SHA-256-Digest", digest));
        manifest.push_str(&section);
        sections.push((name.clone(), section));
    }

    let (cms_hash, sig_alg) = crate::cms::cms_algorithms(&key)?;
    let mut sf = header("Signature-Version", "1.0");
    sf.push_str(&header("SHA-256-Digest-Manifest-Main-Attributes", &B64.encode(sha256(main.as_bytes()))));
    sf.push_str(&header("SHA-256-Digest-Manifest", &B64.encode(sha256(manifest.as_bytes()))));
    sf.push_str(&header("Created-By", &format!("Keystore Studio {}", env!("CARGO_PKG_VERSION"))));
    sf.push_str("\r\n");
    for (name, section) in &sections {
        sf.push_str(&header("Name", name));
        sf.push_str(&header("SHA-256-Digest", &B64.encode(sha256(section.as_bytes()))));
        sf.push_str("\r\n");
    }
    let (block, timestamp) = crate::cms::sign_timestamped(sf.as_bytes(), &key, &chain, true, tsa_url)?;
    let base = block_base_name(&signer.alias);
    let ext = match key.algorithm().as_str() {
        "RSA" => "RSA",
        "DSA" => "DSA",
        _ => "EC",
    };
    let sf_name = format!("META-INF/{base}.SF");
    let block_name = format!("META-INF/{base}.{ext}");

    let tmp_out = format!("{output}.xks-tmp");
    {
        let out_file = std::fs::File::create(&tmp_out).map_err(|err| format!("cannot create {output}: {err}"))?;
        let mut w = zip::ZipWriter::new(out_file);
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let had_meta_dir = (0..archive.len()).any(|i| archive.by_index_raw(i).map(|f| f.name() == "META-INF/").unwrap_or(false));
        if had_meta_dir {
            w.add_directory("META-INF/", opts).map_err(e)?;
        }
        for (name, data) in [("META-INF/MANIFEST.MF", manifest.as_bytes()), (sf_name.as_str(), sf.as_bytes()), (block_name.as_str(), block.as_slice())] {
            w.start_file(name, opts).map_err(e)?;
            w.write_all(data).map_err(e)?;
        }
        for i in 0..archive.len() {
            let f = archive.by_index_raw(i).map_err(e)?;
            let name = f.name().to_string();
            if name == "META-INF/" || name.eq_ignore_ascii_case("META-INF/MANIFEST.MF") || is_signature_file(&name) {
                continue;
            }
            w.raw_copy_file(f).map_err(|err| format!("cannot copy {name}: {err}"))?;
        }
        w.finish().map_err(e)?;
    }
    std::fs::rename(&tmp_out, output).map_err(|err| {
        let _ = std::fs::remove_file(&tmp_out);
        format!("cannot write {output}: {err}")
    })?;

    Ok(JarSignResult {
        output_path: output.to_string(),
        signer_alias: signer.alias.clone(),
        signature_algorithm: sig_alg.name(),
        digest_algorithm: format!("SHA-256 (manifest), {} (signature)", cms_hash.name()),
        entries_signed: digests.len(),
        manifest_preview: manifest.chars().take(4000).collect(),
        signature_file_name: sf_name,
        signed_at: fmt_ts(now_ts()),
        timestamp: timestamp.map(|ts| {
            let mut info = ts.info(true, None);
            if let Some(pem) = tsa_trust_pem {
                info.chain_trusted = crate::tsa::chain_trusted(&ts, pem);
            }
            info
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_lines_wrap_at_72_bytes() {
        let long = "a".repeat(150);
        let h = header("Name", &long);
        for line in h.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(line.len() <= 72, "{}", line.len());
        }
        assert_eq!(h.replace("\r\n ", "").trim_end(), format!("Name: {long}"));
    }

    #[test]
    fn signature_file_detection() {
        assert!(is_signature_file("META-INF/SIGNER.SF"));
        assert!(is_signature_file("META-INF/x.rsa"));
        assert!(!is_signature_file("META-INF/services/x.SF"));
        assert!(!is_signature_file("com/App.class"));
    }
}
