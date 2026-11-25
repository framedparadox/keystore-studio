//! Small shared helpers: encodings, digests, PEM handling and ASN.1 time encoding.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
    /// RFC 1421 headers between the BEGIN line and the data, as OpenSSL's traditional encrypted
    /// keys carry them (`Proc-Type`, `DEK-Info`).
    pub headers: Vec<(String, String)>,
}

impl PemBlock {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The `DEK-Info` of a block encrypted the pre-PKCS#8 OpenSSL way, e.g. `AES-256-CBC,0A1B…`.
    pub fn legacy_encryption(&self) -> Option<&str> {
        self.header("Proc-Type").filter(|v| v.replace(' ', "").eq_ignore_ascii_case("4,ENCRYPTED")).and_then(|_| self.header("DEK-Info"))
    }
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
            let headers = parsed.headers().iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            out.push(PemBlock { tag: parsed.tag().to_string(), der: parsed.contents().to_vec(), headers });
        }
        rest = &rest[start + end + end_marker.len()..];
    }
    out
}

/// Decodes Java's "modified UTF-8" (`DataInput.readUTF`), which the JKS, JCEKS and BKS formats
/// use for aliases: U+0000 takes two bytes, and a character outside the Basic Multilingual Plane
/// is a surrogate pair of three bytes each rather than one four-byte sequence.
pub fn java_utf_decode(bytes: &[u8]) -> Option<String> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let cont = |b: u8| (b & 0xC0 == 0x80).then_some((b & 0x3F) as u16);
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            units.push(((b as u16 & 0x1F) << 6) | cont(*bytes.get(i + 1)?)?);
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            units.push(((b as u16 & 0x0F) << 12) | (cont(*bytes.get(i + 1)?)? << 6) | cont(*bytes.get(i + 2)?)?);
            i += 3;
        } else {
            return None;
        }
    }
    String::from_utf16(&units).ok()
}

/// Encodes a string as Java's `DataOutput.writeUTF` does, without the length prefix.
pub fn java_utf_encode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for unit in text.encode_utf16() {
        match unit {
            0x0001..=0x007F => out.push(unit as u8),
            0x0000 | 0x0080..=0x07FF => out.extend_from_slice(&[0xC0 | (unit >> 6) as u8, 0x80 | (unit & 0x3F) as u8]),
            _ => out.extend_from_slice(&[0xE0 | (unit >> 12) as u8, 0x80 | ((unit >> 6) & 0x3F) as u8, 0x80 | (unit & 0x3F) as u8]),
        }
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

// ------------------------------------------------------------------------------------------------
// UTC calendar time
//
// Every date this app reads or writes is UTC in a fixed format (ASN.1 UTCTime/GeneralizedTime,
// `YYYY-MM-DD`, RFC 3339), so the proleptic Gregorian calendar below is all that is needed: no time
// zones, no locale data, and no date crate (chrono is unmaintained, RUSTSEC-2026-0543).
// ------------------------------------------------------------------------------------------------

/// A UTC calendar instant to the second. `second` may be 60 for a leap second read from input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// Days from 1970-01-01 to the given date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

impl Civil {
    pub fn from_ts(ts: i64) -> Self {
        let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400) as u32);
        let (year, month, day) = civil_from_days(days);
        Civil { year, month, day, hour: secs / 3600, minute: secs / 60 % 60, second: secs % 60 }
    }

    /// Validates the fields; None for impossible dates such as February 30th.
    pub fn new(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<Self> {
        let ok = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month) && hour < 24 && minute < 60 && second <= 60;
        ok.then_some(Civil { year, month, day, hour, minute, second })
    }

    /// Seconds since the Unix epoch. A leap second counts as the second before it, as chrono did.
    pub fn ts(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400 + i64::from(self.hour) * 3600 + i64::from(self.minute) * 60 + i64::from(self.second.min(59))
    }

    fn ymd(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `YYYYMMDDHHMMSS`, the digits of a GeneralizedTime.
    pub fn compact(&self) -> String {
        format!("{:04}{:02}{:02}{:02}{:02}{:02}", self.year, self.month, self.day, self.hour, self.minute, self.second)
    }

    /// `YYYY-MM-DD HH:MM:SS UTC`.
    pub fn display(&self) -> String {
        format!("{} {:02}:{:02}:{:02} UTC", self.ymd(), self.hour, self.minute, self.second)
    }
}

/// Parses an all-digit field, rejecting signs and spaces that `str::parse` would accept.
fn digits<T: std::str::FromStr>(s: &str) -> Option<T> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// `YYYYMMDDHHMMSS` (exactly 14 digits).
pub fn parse_compact(s: &str) -> Option<Civil> {
    if s.len() != 14 || !s.is_ascii() {
        return None;
    }
    Civil::new(digits(&s[0..4])?, digits(&s[4..6])?, digits(&s[6..8])?, digits(&s[8..10])?, digits(&s[10..12])?, digits(&s[12..14])?)
}

/// `YYYY-MM-DD`; month and day may have one digit, as chrono's parser allowed.
pub fn parse_ymd(s: &str) -> Option<Civil> {
    let mut parts = s.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || !(1..=2).contains(&m.len()) || !(1..=2).contains(&d.len()) {
        return None;
    }
    Civil::new(digits(y)?, digits(m)?, digits(d)?, 0, 0, 0)
}

/// `HH:MM` or `HH:MM:SS`, optionally with fractional seconds when `fraction` is allowed.
fn parse_hms(s: &str, fraction: bool) -> Option<(u32, u32, u32)> {
    let (s, frac) = match s.split_once('.') {
        Some((whole, f)) if fraction && !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => (whole, true),
        Some(_) => return None,
        None => (s, false),
    };
    let parts: Vec<&str> = s.split(':').collect();
    if parts.iter().any(|p| p.len() != 2) {
        return None;
    }
    match parts.as_slice() {
        [h, m] if !frac => Some((digits(h)?, digits(m)?, 0)),
        [h, m, sec] => Some((digits(h)?, digits(m)?, digits(sec)?)),
        _ => None,
    }
}

/// `YYYY-MM-DD HH:MM[:SS]` or with a `T`, read as UTC.
pub fn parse_naive_datetime(s: &str) -> Option<Civil> {
    let (date, time) = s.split_once(['T', ' '])?;
    let d = parse_ymd(date)?;
    let (h, mi, sec) = parse_hms(time, false)?;
    Civil::new(d.year, d.month, d.day, h, mi, sec)
}

/// RFC 3339 (`2026-01-02T03:04:05Z`, `…+02:00`, fractional seconds allowed) as a Unix timestamp.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let d = parse_ymd(date)?;
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0i64)
    } else {
        let i = rest.rfind(['+', '-'])?;
        let (t, off) = rest.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        if oh.len() != 2 || om.len() != 2 {
            return None;
        }
        let (oh, om): (i64, i64) = (digits(oh)?, digits(om)?);
        if oh > 23 || om > 59 {
            return None;
        }
        (t, sign * (oh * 3600 + om * 60))
    };
    let (h, mi, sec) = parse_hms(time, true)?;
    if time.split('.').next()?.len() != 8 {
        return None; // RFC 3339 always has seconds.
    }
    Some(Civil::new(d.year, d.month, d.day, h, mi, sec)?.ts() - offset_secs)
}

pub fn fmt_ts(ts: i64) -> String {
    Civil::from_ts(ts).display()
}

pub fn fmt_date(ts: i64) -> String {
    Civil::from_ts(ts).ymd()
}

/// `YYYY-MM-DD HH:MM`, to the minute.
pub fn fmt_minute(ts: i64) -> String {
    let c = Civil::from_ts(ts);
    format!("{} {:02}:{:02}", c.ymd(), c.hour, c.minute)
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn fmt_rfc3339z(ts: i64) -> String {
    let c = Civil::from_ts(ts);
    format!("{}T{:02}:{:02}:{:02}Z", c.ymd(), c.hour, c.minute, c.second)
}

/// Seconds since the epoch of a file time (negative before 1970).
pub fn system_time_ts(t: std::time::SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

pub fn now_ts() -> i64 {
    system_time_ts(std::time::SystemTime::now())
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// DER encoding of an X.509 `Time`: UTCTime for years 1950–2049, GeneralizedTime otherwise
/// (RFC 5280 §4.1.2.5).
pub fn asn1_time_der(ts: i64) -> Vec<u8> {
    let c = Civil::from_ts(ts);
    let full = c.compact();
    let (tag, body) = if (1950..2050).contains(&c.year) { (0x17u8, format!("{}Z", &full[2..])) } else { (0x18u8, format!("{full}Z")) };
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body.as_bytes());
    out
}

/// DER GeneralizedTime (used for CMS signing time and CRL invalidity dates).
pub fn generalized_time_der(ts: i64) -> Vec<u8> {
    let body = format!("{}Z", Civil::from_ts(ts).compact());
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
    fn calendar_matches_reference_timestamps() {
        // Expected values from Python's datetime (UTC).
        let cases = [
            (1970, 1, 1, 0, 0, 0, 0i64),
            (1969, 12, 31, 23, 59, 59, -1i64),
            (2000, 2, 29, 12, 0, 0, 951825600i64),
            (1900, 3, 1, 0, 0, 0, -2203891200i64),
            (2024, 2, 29, 23, 59, 59, 1709251199i64),
            (2049, 12, 31, 23, 59, 59, 2524607999i64),
            (2050, 1, 1, 0, 0, 0, 2524608000i64),
            (9999, 12, 31, 23, 59, 59, 253402300799i64),
            (1, 1, 1, 0, 0, 0, -62135596800i64),
            (1600, 2, 29, 6, 7, 8, -11670976372i64),
            (2038, 1, 19, 3, 14, 8, 2147483648i64),
        ];
        for (y, mo, d, h, mi, s, ts) in cases {
            let c = Civil::new(y, mo, d, h, mi, s).unwrap();
            assert_eq!(c.ts(), ts, "{y}-{mo}-{d}");
            assert_eq!(Civil::from_ts(ts), c, "{ts}");
        }
        // Every day for ±1000 years round-trips.
        for day in -365_250..365_250i64 {
            let ts = day * 86_400 + 3_723;
            assert_eq!(Civil::from_ts(ts).ts(), ts);
        }
    }

    #[test]
    fn date_parsing_accepts_what_the_engine_writes_and_rejects_the_rest() {
        assert_eq!(parse_ymd("2026-01-02").unwrap().ts(), 1_767_312_000);
        assert_eq!(parse_ymd("2026-1-2"), parse_ymd("2026-01-02"));
        for bad in ["2026-02-30", "2026-13-01", "2026-00-10", "26-01-02", "2026-01-02x", "2026/01/02", "+026-01-02", "2026-01"] {
            assert!(parse_ymd(bad).is_none(), "{bad}");
        }
        assert_eq!(parse_compact("20260102030405").unwrap().display(), "2026-01-02 03:04:05 UTC");
        assert_eq!(parse_compact("20161231235960").unwrap().display(), "2016-12-31 23:59:60 UTC");
        assert_eq!(parse_compact("20161231235960").unwrap().ts(), parse_compact("20161231235959").unwrap().ts());
        for bad in ["2026010203040", "202601020304051", "2026013203040x", "20260132030405", "20260102250405"] {
            assert!(parse_compact(bad).is_none(), "{bad}");
        }
        let base = parse_compact("20260102030405").unwrap().ts();
        assert_eq!(parse_rfc3339("2026-01-02T03:04:05Z"), Some(base));
        assert_eq!(parse_rfc3339("2026-01-02t03:04:05.123z"), Some(base));
        assert_eq!(parse_rfc3339("2026-01-02T05:04:05+02:00"), Some(base));
        assert_eq!(parse_rfc3339("2026-01-01T23:04:05-04:00"), Some(base));
        for bad in ["2026-01-02T03:04Z", "2026-01-02T03:04:05", "2026-01-02T03:04:05+2:00", "2026-01-02T03:04:05+24:00"] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
        assert_eq!(parse_naive_datetime("2026-01-02T03:04").unwrap().ts(), base - 5);
        assert_eq!(parse_naive_datetime("2026-01-02 03:04:05").unwrap().ts(), base);
        assert!(parse_naive_datetime("2026-01-02T3:04").is_none());
    }

    #[test]
    fn formatting_matches_the_previous_strings() {
        let ts = parse_compact("20260102030405").unwrap().ts();
        assert_eq!(fmt_ts(ts), "2026-01-02 03:04:05 UTC");
        assert_eq!(fmt_date(ts), "2026-01-02");
        assert_eq!(fmt_minute(ts), "2026-01-02 03:04");
        assert_eq!(fmt_rfc3339z(ts), "2026-01-02T03:04:05Z");
        assert_eq!(&generalized_time_der(ts)[2..], b"20260102030405Z");
        assert_eq!(fmt_ts(-1), "1969-12-31 23:59:59 UTC");
        assert!((now_ts() - 1_700_000_000) > 0);
    }

    #[test]
    fn asn1_time_switches_to_generalized_after_2049() {
        let t2030 = Civil::new(2030, 1, 2, 3, 4, 5).unwrap().ts();
        assert_eq!(asn1_time_der(t2030)[0], 0x17);
        assert_eq!(&asn1_time_der(t2030)[2..], b"300102030405Z");
        let t2050 = Civil::new(2050, 1, 1, 0, 0, 0).unwrap().ts();
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
    fn java_modified_utf8_matches_data_output_stream() {
        // Plain ASCII and BMP text is ordinary UTF-8.
        for text in ["server", "Ünïcödé alias", "日本語"] {
            assert_eq!(java_utf_encode(text), text.as_bytes());
            assert_eq!(java_utf_decode(text.as_bytes()).as_deref(), Some(text));
        }
        // U+0000 is C0 80, and U+1F511 (a key emoji) is the surrogate pair D83D DD11, three bytes each.
        assert_eq!(java_utf_encode("a\0b"), [b'a', 0xC0, 0x80, b'b']);
        assert_eq!(java_utf_encode("\u{1F511}"), [0xED, 0xA0, 0xBD, 0xED, 0xB4, 0x91]);
        assert_eq!(java_utf_decode(&[0xED, 0xA0, 0xBD, 0xED, 0xB4, 0x91]).as_deref(), Some("\u{1F511}"));
        assert_eq!(java_utf_decode(&[b'a', 0xC0, 0x80, b'b']).as_deref(), Some("a\0b"));
        // Truncated sequences, a stray continuation byte and an unpaired surrogate are rejected.
        for bad in [&[0xC3u8][..], &[0xE2, 0x82], &[0x80], &[0xF0, 0x9F, 0x94, 0x91], &[0xED, 0xA0, 0xBD]] {
            assert_eq!(java_utf_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pem_blocks_carry_their_headers() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\nAAECAwQFBgc=\n-----END RSA PRIVATE KEY-----\n";
        let blocks = pem_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].der, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(blocks[0].legacy_encryption(), Some("AES-256-CBC,00112233445566778899AABBCCDDEEFF"));
        assert_eq!(pem_blocks(&to_pem("PRIVATE KEY", &[1]))[0].legacy_encryption(), None);
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
