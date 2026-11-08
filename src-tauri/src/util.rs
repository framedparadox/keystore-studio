//! Small shared helpers: encodings, digests, PEM handling and ASN.1 time encoding.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Datelike, TimeZone, Utc};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub type Res<T> = Result<T, String>;

/// Converts any displayable error into the `String` error type used across the command layer.
pub fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// Rejects DER/BER whose declared lengths cannot fit the data that follows.
///
/// This guards a panic in `yasna` 0.5/0.6: when skipping an indefinite-length construction its
/// reader computes `self.pos + length` *before* the bounds check
/// (`yasna/src/reader/mod.rs:349`), so a length near `usize::MAX` aborts the process with
/// "attempt to add with overflow" instead of returning a parse error. Found by the `keys` fuzz
/// target; upstream fixed the same bug on one line in 0.6.0 but not this one.
///
/// Scanning every length header first is cheap — one linear pass, no allocation — and it means a
/// hostile file is rejected before `yasna` can see it. Call this at the boundary where untrusted
/// bytes arrive, not at every nested parse.
pub fn check_der_lengths(data: &[u8]) -> Res<()> {
    const MALFORMED: &str = "malformed ASN.1: a declared length exceeds the data";
    // Walks the structure, not the bytes: content of a definite-length *primitive* is skipped
    // rather than descended into, because a key or ciphertext payload is arbitrary bytes that
    // would otherwise be misread as tags. Constructed values are descended into, which is where
    // the nested hostile length actually sits.
    fn walk(data: &[u8], depth: u32) -> Res<()> {
        // Bound recursion as well: a chain of constructed headers is otherwise a stack overflow.
        if depth > 64 {
            return Ok(());
        }
        let mut i = 0usize;
        while i < data.len() {
            let tag = data[i];
            // Tag, including multi-byte (high-tag-number) forms.
            if tag & 0x1F == 0x1F {
                i += 1;
                while i < data.len() && data[i] & 0x80 != 0 {
                    i += 1;
                }
            }
            i += 1;
            let Some(&first) = data.get(i) else { return Ok(()) };
            i += 1;
            if first == 0x80 {
                // Indefinite length: the content runs to an end-of-contents marker, so there is
                // no length to validate here. Keep scanning from just after the header, which is
                // how the nested hostile header gets reached.
                continue;
            }
            let length = if first < 0x80 {
                first as usize
            } else {
                let count = (first & 0x7F) as usize;
                // A length field wider than a usize cannot describe anything in memory, and is
                // exactly what overflows yasna's `self.pos + length`.
                if count > std::mem::size_of::<usize>() {
                    return Err(MALFORMED.into());
                }
                let Some(bytes) = data.get(i..i + count) else { return Err(MALFORMED.into()) };
                i += count;
                let mut length = 0usize;
                for b in bytes {
                    length = match length.checked_mul(256).and_then(|l| l.checked_add(*b as usize)) {
                        Some(l) => l,
                        None => return Err(MALFORMED.into()),
                    };
                }
                length
            };
            // The declared content must fit in what is left; `checked_add` is the actual fix.
            let end = match i.checked_add(length) {
                Some(end) if end <= data.len() => end,
                _ => return Err(MALFORMED.into()),
            };
            // 0x20 marks a constructed value, whose content is more TLVs worth checking. A
            // primitive's content is opaque bytes, so skip over it.
            if tag & 0x20 != 0 {
                walk(&data[i..end], depth + 1)?;
            }
            i = end;
        }
        Ok(())
    }
    walk(data, 0)
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn unb64(data: &str) -> Res<Vec<u8>> {
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(cleaned.as_bytes()).map_err(|err| format!("invalid base64 data: {err}"))
}

pub fn colon_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub fn upper_hex(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

pub fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// A positive, non-zero, 16-byte certificate serial number (RFC 5280 allows up to 20 octets).
pub fn random_serial() -> Vec<u8> {
    let mut serial = random_bytes(16);
    serial[0] &= 0x7F;
    if serial[0] == 0 {
        serial[0] = 0x01;
    }
    serial
}

/// One decoded PEM block.
pub struct PemBlock {
    pub tag: String,
    pub der: Vec<u8>,
}

/// Extracts every PEM block from `text`, tolerating surrounding text (as produced by
/// `openssl x509 -text`, bag attributes from `openssl pkcs12`, etc.).
pub fn pem_blocks(text: &str) -> Vec<PemBlock> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(tag_end) = after.find("-----") else { break };
        let tag = after[..tag_end].trim().to_string();
        let end_marker = format!("-----END {tag}-----");
        let Some(end) = rest[start..].find(&end_marker) else { break };
        let block = &rest[start..start + end + end_marker.len()];
        if let Ok(parsed) = pem::parse(block.as_bytes()) {
            out.push(PemBlock { tag: parsed.tag().to_string(), der: parsed.contents().to_vec() });
        }
        rest = &rest[start + end + end_marker.len()..];
    }
    out
}

pub fn to_pem(tag: &str, der: &[u8]) -> String {
    pem::encode_config(&pem::Pem::new(tag, der.to_vec()), pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF))
}

/// True if `bytes` looks like printable text (PEM, JWT, base64, …) rather than binary DER.
pub fn looks_textual(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let sample = &bytes[..bytes.len().min(4096)];
    std::str::from_utf8(sample).is_ok() && sample.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7F).contains(&b) || b >= 0x80)
}

pub fn ts_to_datetime(ts: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(ts, 0).single().unwrap_or_else(Utc::now)
}

pub fn fmt_ts(ts: i64) -> String {
    ts_to_datetime(ts).format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

pub fn fmt_date(ts: i64) -> String {
    ts_to_datetime(ts).format("%Y-%m-%d").to_string()
}

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

/// DER encoding of an X.509 `Time`: UTCTime for years 1950–2049, GeneralizedTime otherwise
/// (RFC 5280 §4.1.2.5).
pub fn asn1_time_der(ts: i64) -> Vec<u8> {
    let dt = ts_to_datetime(ts);
    let (tag, body) = if (1950..2050).contains(&dt.year()) { (0x17u8, dt.format("%y%m%d%H%M%SZ").to_string()) } else { (0x18u8, dt.format("%Y%m%d%H%M%SZ").to_string()) };
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body.as_bytes());
    out
}

/// DER GeneralizedTime (used for CMS signing time and CRL invalidity dates).
pub fn generalized_time_der(ts: i64) -> Vec<u8> {
    let body = ts_to_datetime(ts).format("%Y%m%d%H%M%SZ").to_string();
    let mut out = vec![0x18u8, body.len() as u8];
    out.extend_from_slice(body.as_bytes());
    out
}

/// Strips leading zero bytes from a big-endian unsigned integer (keeping at least one byte).
pub fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len().saturating_sub(1));
    &bytes[first..]
}

/// Parses a hex serial number typed by a user ("01:AB:cd", "0x01abcd", "01 ab cd").
pub fn parse_hex_serial(input: &str) -> Res<Vec<u8>> {
    let cleaned: String = input.trim().trim_start_matches("0x").trim_start_matches("0X").chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect();
    if cleaned.is_empty() {
        return Err("serial number is empty".into());
    }
    let padded = if cleaned.len() % 2 == 1 { format!("0{cleaned}") } else { cleaned };
    let bytes = hex::decode(&padded).map_err(|_| format!("'{input}' is not a hexadecimal serial number"))?;
    Ok(trim_leading_zeros(&bytes).to_vec())
}

/// Writes `data` to `path` atomically (temp file in the same directory, then rename), so a crash
/// or full disk never leaves a half-written keystore behind.
///
/// - A new file is created readable by its owner only (0600 on Unix). A file that already exists
///   keeps its permission bits: a keystore that a service reads through its group (say 0640) must
///   stay readable by that service after it is saved here.
/// - A symlink is written through: its target is replaced, not the link. Replacing the link would
///   leave the real file, the one other programs read, untouched.
/// - The temp file never outlives a failed write; it may hold key material.
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> Res<()> {
    use std::io::Write;
    let fail = |err: std::io::Error| format!("cannot write {}: {err}", path.display());
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => resolve_link(path).map_err(fail)?,
        _ => path.to_path_buf(),
    };
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir).map_err(|err| format!("cannot create folder {}: {err}", dir.display()))?;
    let file_name = target.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let existing = std::fs::metadata(&target).ok().map(|m| m.permissions());

    let written = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        // Applied to the open file, after the data is in: the bytes are never readable by more
        // than the owner until they are complete.
        if let Some(perms) = existing {
            f.set_permissions(perms)?;
        }
        f.sync_all()?;
        Ok(())
    })();
    if let Err(err) = written.and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(fail(err));
    }
    // Make the rename itself durable: until the directory entry reaches the disk, a power cut can
    // bring back the old file (or none at all, for a new one).
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The file a symlink points to. A dangling link resolves to where its target would be, so writing
/// through it creates that file.
fn resolve_link(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    if let Ok(real) = std::fs::canonicalize(path) {
        return Ok(real);
    }
    let link = std::fs::read_link(path)?;
    Ok(if link.is_absolute() { link } else { path.parent().unwrap_or(std::path::Path::new(".")).join(link) })
}

pub fn file_name_of(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_time_switches_to_generalized_after_2049() {
        let t2030 = Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap().timestamp();
        assert_eq!(asn1_time_der(t2030)[0], 0x17);
        assert_eq!(&asn1_time_der(t2030)[2..], b"300102030405Z");
        let t2050 = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap().timestamp();
        assert_eq!(asn1_time_der(t2050)[0], 0x18);
    }

    #[test]
    fn hex_serial_parsing() {
        assert_eq!(parse_hex_serial("01:ab:CD").unwrap(), vec![0x01, 0xab, 0xcd]);
        assert_eq!(parse_hex_serial("0x0001").unwrap(), vec![0x01]);
        assert_eq!(parse_hex_serial("abc").unwrap(), vec![0x0a, 0xbc]);
        assert!(parse_hex_serial("zz").is_err());
    }

    #[test]
    fn pem_blocks_skip_surrounding_text() {
        let text = format!("Bag Attributes\n{}\nnoise\n{}", to_pem("CERTIFICATE", &[1, 2, 3]), to_pem("PRIVATE KEY", &[4]));
        let blocks = pem_blocks(&text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].tag, "CERTIFICATE");
        assert_eq!(blocks[1].der, vec![4]);
    }

    fn temp_files_in(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.ends_with(".tmp")).collect()
    }

    #[test]
    fn atomic_write_replaces_content_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.p12");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(temp_files_in(dir.path()).is_empty());

        // A failed write (here: the destination is a folder) must not leave its temp file, which
        // may hold key material, lying next to it.
        let folder = dir.path().join("taken");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("inner"), b"x").unwrap();
        assert!(write_atomic(&folder, b"secret").is_err());
        assert!(temp_files_in(dir.path()).is_empty(), "a temp file survived a failed write");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_permissions_of_an_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let fresh = dir.path().join("new.p12");
        write_atomic(&fresh, b"k").unwrap();
        assert_eq!(mode(&fresh), 0o600, "a new keystore must be private to its owner");

        // A keystore a service reads through its group stays readable by that group.
        let shared = dir.path().join("shared.p12");
        std::fs::write(&shared, b"old").unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&shared, b"new").unwrap();
        assert_eq!(mode(&shared), 0o640);
        assert_eq!(std::fs::read(&shared).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_goes_through_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.p12");
        let link = dir.path().join("link.p12");
        std::fs::write(&real, b"old").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic(&link, b"new").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link was replaced by a file");
        assert_eq!(std::fs::read(&real).unwrap(), b"new", "the file behind the link was not updated");

        // A dangling link creates the file it points to.
        let dangling = dir.path().join("dangling.p12");
        std::os::unix::fs::symlink("created.p12", &dangling).unwrap();
        write_atomic(&dangling, b"made").unwrap();
        assert_eq!(std::fs::read(dir.path().join("created.p12")).unwrap(), b"made");
        assert!(std::fs::symlink_metadata(&dangling).unwrap().file_type().is_symlink());
    }

    #[test]
    fn known_digests() {
        assert_eq!(upper_hex(&md5(b"")), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(upper_hex(&sha1(b"abc")), "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }

    #[test]
    fn der_length_check_accepts_well_formed_structures() {
        // SEQUENCE { INTEGER 1, OCTET STRING "ab" }
        let good = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_bytes(b"ab");
            })
        });
        assert!(check_der_lengths(&good).is_ok());
        // Empty input and a bare tag are not our problem to reject; the parser reports those.
        assert!(check_der_lengths(&[]).is_ok());
        assert!(check_der_lengths(&[0x30]).is_ok());
        // A primitive's content must not be walked into: random bytes inside an OCTET STRING are
        // not tags, and treating them as such is what made the first version of this reject
        // valid keystores.
        let opaque = yasna::construct_der(|w| w.write_bytes(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(check_der_lengths(&opaque).is_ok());
    }

    #[test]
    fn der_length_check_rejects_lengths_that_cannot_fit() {
        // Declared 0x7FFFFFFF inside a 5-byte buffer.
        assert!(check_der_lengths(&[0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]).is_err());
        // A length field wider than usize.
        assert!(check_der_lengths(&[0x04, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1]).is_err());
        // The input that crashed the `keys` fuzz target: an indefinite-length construction whose
        // nested header declares a length near usize::MAX, which overflowed yasna's
        // `self.pos + length` before its bounds check.
        let crash =
            [0x30, 0x80, 0x30, 0x80, 0x06, 0x08, 0x00, 0x3e, 0x10, 0x00, 0x84, 0x25, 0x02, 0x30, 0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0x00, 0x00, 0x21, 0x0c];
        assert!(check_der_lengths(&crash).is_err());
    }

    #[test]
    fn der_length_check_terminates_on_deep_nesting() {
        // 10 000 nested constructed headers: the walk must bound its own recursion rather than
        // overflow the stack. Returning Ok is fine — the parser still gets to reject it.
        let mut nested: Vec<u8> = vec![0x05, 0x00];
        for _ in 0..10_000 {
            let len = nested.len();
            let mut next = vec![0x30, 0x82, (len >> 8) as u8, len as u8];
            next.extend(nested);
            nested = next;
        }
        let _ = check_der_lengths(&nested);
    }
}
