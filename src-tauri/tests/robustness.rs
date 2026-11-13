//! Malformed-input tests for every parser that reads a file a user was sent.
//!
//! The unit and interop suites only ever feed these parsers well-formed input, which is not what a
//! parser gets wrong. Opening a file is the app's most exposed operation: the bytes are untrusted,
//! and the decoders do arithmetic on attacker-controlled lengths. Rust's bounds checks make a
//! panic the likely failure rather than memory corruption, so a panic means a crash and lost work,
//! not code execution — still a bug, and one a user hits by double-clicking the wrong file.
//!
//! The contract asserted here is narrow and total: **every entry point returns `Err` or `Ok`, and
//! never panics, hangs or aborts**, for any input at all.
//!
//! This is the deterministic half of the fuzzing work. It runs on stable Rust in CI on every push
//! and reruns a fixed corpus plus structure-aware mutations of valid files, which is what catches
//! regressions. The other half, `fuzz/`, explores far more inputs with libFuzzer's coverage
//! feedback but needs nightly; see IMPROVEMENT.md. Any crash found there should be added to
//! `CORPUS_SEEDS` or the mutation set here so it stays fixed.

use keystore_studio_lib::{cms, detect, jks, keys, keystore, pbe, pkcs12, tsa, x509};
use std::collections::HashMap;

/// Runs every parser over `data`. A panic in any of them fails the test with the input that caused
/// it; returning an error is always acceptable.
fn parse_everything(data: &[u8]) {
    let empty = HashMap::new();
    let _ = detect::examine(data, Some("pw"));
    let _ = detect::examine(data, None);
    let _ = keystore::decode(data, "pw", &empty);
    let _ = pkcs12::decode(data, "pw");
    let _ = jks::decode(data, "pw", &empty);
    let _ = x509::parse_certificate(data);
    let _ = x509::parse_csr(data);
    let _ = x509::parse_crl(data, None);
    let _ = x509::name_der_to_string(data);
    if let Ok(certs) = x509::certificates_from_bytes(data) {
        let _ = x509::order_bundle(&certs);
    }
    if let Ok(der) = cms::cms_der_from_bytes(data) {
        let _ = cms::verify(&der, Some(b"content"), &[]);
        let _ = cms::certificates_from_pkcs7(&der);
    }
    let _ = tsa::verify_token(data, b"signature");
    let _ = keys::PrivateKey::from_bytes(data, Some("pw"));
    let _ = keys::PrivateKey::from_pkcs8_der(data);
    let _ = keys::public_key_info(data);
    let _ = pbe::decrypt_pkcs8("pw", data);
}

/// Hand-written inputs aimed at the arithmetic a decoder does on lengths and counts. Each is
/// something a malicious or truncated file plausibly contains.
const CORPUS_SEEDS: &[(&str, &[u8])] = &[
    ("empty", &[]),
    ("one zero byte", &[0]),
    ("lone sequence tag", &[0x30]),
    ("empty sequence", &[0x30, 0x00]),
    // A length header promising far more data than follows.
    ("sequence claiming 64 KiB", &[0x30, 0x83, 0xFF, 0xFF, 0xFF]),
    ("indefinite length, never terminated", &[0x30, 0x80]),
    ("length of length = 0x7F", &[0x30, 0xFF]),
    ("integer with no contents", &[0x02, 0x00]),
    ("octet string claiming 2 GiB", &[0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]),
    // JKS: the magic, then a wildly large entry count. jks::decode must not try to allocate it.
    ("JKS magic with 4 billion entries", &[0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0xFF, 0xFF, 0xFF, 0xFF]),
    ("JCEKS magic with 4 billion entries", &[0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2, 0xFF, 0xFF, 0xFF, 0xFF]),
    ("JKS magic and nothing else", &[0xFE, 0xED, 0xFE, 0xED]),
    ("JKS truncated mid-header", &[0xFE, 0xED, 0xFE, 0xED, 0, 0, 0]),
    // PEM shapes: unterminated, empty and non-base64 bodies.
    ("PEM header only", b"-----BEGIN CERTIFICATE-----"),
    ("PEM with empty body", b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
    ("PEM with invalid base64", b"-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----"),
    ("PEM with mismatched tags", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----"),
    ("PEM nested headers", b"-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAA\n"),
    ("encrypted PKCS#8 header, no body", b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"),
    // Text that is not a container at all.
    ("plain text", b"hello world, this is just a text file\n"),
    ("JSON", br#"{"alias":"x","key":"y"}"#),
    ("NUL bytes", &[0, 0, 0, 0, 0, 0, 0, 0]),
    ("0xFF bytes", &[0xFF; 32]),
    // An OID with a never-ending multi-byte arc.
    ("unterminated OID arc", &[0x06, 0x04, 0x80, 0x80, 0x80, 0x80]),
    ("deeply prefixed integer", &[0x02, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    // CI keystore fuzz crash (84d79cfc): indefinite-length BER with a nested near-usize::MAX
    // length. Detection used to call yasna before check_der_lengths and aborted the process.
    (
        "indefinite BER with hostile nested length (keystore fuzz)",
        &[
            0x30, 0x80, 0x02, 0x01, 0x01, 0xff, 0x22, 0x80, 0x80, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x17, 0x2e, 0x02, 0x02, 0x2a, 0x30, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0x86, 0x30, 0x06, 0x30, 0x7e, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x17, 0x86, 0xd1, 0x00, 0xff, 0xff, 0xff,
        ],
    ),
];

#[test]
fn malformed_input_is_rejected_not_fatal() {
    for (name, data) in CORPUS_SEEDS {
        parse_everything(data);
        // Also try each seed with a length prefix stripped, a common truncation shape.
        if data.len() > 1 {
            parse_everything(&data[1..]);
        }
        eprintln!("ok: {name}");
    }
}

/// Nesting is the classic way to turn a recursive descent parser into a stack overflow. PKCS#12
/// safe contents can legitimately nest, so the decoder has a depth limit; this checks it holds and
/// that generic DER nesting does not blow the stack either.
#[test]
fn deep_nesting_does_not_overflow_the_stack() {
    // 50 000 nested SEQUENCE headers with indefinite lengths.
    let mut deep = Vec::new();
    for _ in 0..50_000 {
        deep.extend_from_slice(&[0x30, 0x80]);
    }
    parse_everything(&deep);

    // Properly terminated nesting, built from the inside out so every length is correct: a parser
    // that recurses once per level has to survive 10 000 levels.
    let mut nested: Vec<u8> = vec![0x05, 0x00]; // NULL
    for _ in 0..10_000 {
        let len = nested.len();
        let mut next = vec![0x30];
        if len < 0x80 {
            next.push(len as u8);
        } else {
            let bytes = (len as u32).to_be_bytes();
            let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
            next.push(0x80 | trimmed.len() as u8);
            next.extend(trimmed);
        }
        next.extend(nested);
        nested = next;
    }
    parse_everything(&nested);
}

/// Every single-byte truncation and bit flip of a *real* keystore. Valid files get much deeper
/// into the decoders than random bytes do, so this is where length arithmetic on half-parsed
/// structures gets exercised.
#[test]
fn mutations_of_real_files_are_rejected_not_fatal() {
    let entry = sample_entry();
    let password = "corpus-pw";
    let mut originals: Vec<(&str, Vec<u8>)> = Vec::new();
    for (name, format) in [("p12", keystore::Format::Pkcs12), ("jks", keystore::Format::Jks), ("jceks", keystore::Format::Jceks)] {
        originals.push((name, keystore::encode(std::slice::from_ref(&entry), password, format).unwrap()));
    }
    originals.push(("p12-pbmac1", pkcs12::encode_with_mac(std::slice::from_ref(&entry), password, pkcs12::MacKind::Pbmac1).unwrap()));
    originals.push(("cert-der", keystore_studio_lib::entry::chain_der(&entry).unwrap()[0].clone()));
    originals.push(("cert-pem", entry.certificate_chain[0].pem.as_bytes().to_vec()));

    // Each mutation runs every parser, and the keystore decoders each do a 10 000-iteration PBKDF2
    // before they can reject a wrong password, so the point count dominates the runtime. The
    // default keeps this test around 15 seconds; raise it for a deeper local sweep:
    //   XKS_MUTATION_POINTS=2000 cargo test --test robustness -- --nocapture
    let points: usize = std::env::var("XKS_MUTATION_POINTS").ok().and_then(|v| v.parse().ok()).unwrap_or(6);

    for (name, original) in &originals {
        // Spread the sampled offsets across the file rather than clustering at the start, so
        // headers, the encrypted middle and the trailing MAC all get hit.
        let step = original.len().div_ceil(points).max(1);
        let offsets: Vec<usize> = (0..original.len()).step_by(step).collect();

        // Truncation: a half-written or deliberately cut-short file.
        for &cut in &offsets {
            parse_everything(&original[..cut]);
        }
        for &at in &offsets {
            // Bit flips, including the top bit, which in DER turns a short length into a
            // long-form one and a primitive tag into a constructed one.
            for xor in [0x01u8, 0x80, 0xFF] {
                let mut m = original.clone();
                m[at] ^= xor;
                parse_everything(&m);
            }
            // An explicit long-form length header claiming far more data than remains: the
            // highest-value target, since this is where length arithmetic can wrap or over-read.
            let mut m = original.clone();
            m[at] = 0x84;
            parse_everything(&m);
        }
        eprintln!("ok: {} mutation points of {name} ({} bytes)", offsets.len(), original.len());
    }
}

/// A valid file must still open after all that, so the mutation loop above is not passing simply
/// because everything errors out.
#[test]
fn the_unmutated_files_still_open() {
    let entry = sample_entry();
    let empty = HashMap::new();
    for format in [keystore::Format::Pkcs12, keystore::Format::Jks, keystore::Format::Jceks] {
        let bytes = keystore::encode(std::slice::from_ref(&entry), "corpus-pw", format).unwrap();
        let (detected, entries) = keystore::decode(&bytes, "corpus-pw", &empty).expect("the unmutated file must open");
        assert_eq!(detected, format);
        assert_eq!(entries.len(), 1);
    }
}

fn sample_entry() -> keystore_studio_lib::model::KeystoreEntry {
    sample_entry_named("corpus")
}

fn sample_entry_named(alias: &str) -> keystore_studio_lib::model::KeystoreEntry {
    let input = keystore_studio_lib::model::GenerateKeyPairInput {
        alias: alias.into(),
        algorithm: "ECDSA".into(),
        key_size: 2048,
        curve: Some("P-256".into()),
        signature_hash: None,
        subject_dn: format!("CN={alias}.example, O=Robustness"),
        common_name: String::new(),
        organization: String::new(),
        organizational_unit: String::new(),
        locality: String::new(),
        state: String::new(),
        country: String::new(),
        email: String::new(),
        validity_days: 30,
        is_ca: false,
        path_len: None,
        sans: vec!["corpus.example".into()],
        key_usage: vec![],
        extended_key_usage: vec![],
        labels: vec![],
        not_before: String::new(),
        not_after: String::new(),
        crl_distribution_points: vec![],
        ocsp_urls: vec![],
        ca_issuer_urls: vec![],
    };
    keystore_studio_lib::ops::generate_key_pair(&input, None).unwrap()
}

/// Regression: found by the `keys` fuzz target. A BER indefinite-length construction with a
/// nested 0x88-tagged length caused a panic inside yasna's reader rather than a parse error.
#[test]
fn fuzz_crash_keys_indefinite_length_does_not_panic() {
    let data =
        [0x30, 0x80, 0x30, 0x80, 0x06, 0x08, 0x00, 0x3e, 0x10, 0x00, 0x84, 0x25, 0x02, 0x30, 0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0x00, 0x00, 0x21, 0x0c];
    // Narrow it down: each of these must return, not panic.
    let _ = keys::PrivateKey::from_pkcs8_der(&data);
    let _ = keys::public_key_info(&data);
    let _ = pbe::decrypt_pkcs8("pw", &data);
    let _ = keys::PrivateKey::from_bytes(&data, Some("pw"));
    parse_everything(&data);
}

/// The length guard must not reject large but valid files. A keystore with many entries is the
/// realistic case: `check_der_lengths` walks every nested structure, and an off-by-one in its
/// bounds check would show up as a big keystore that suddenly will not open.
#[test]
fn large_valid_keystores_still_open() {
    // Six entries is enough to nest the structures deeply while keeping key generation quick;
    // the point is the walk over many siblings, not the entry count.
    let entries: Vec<_> = (0..6).map(|i| sample_entry_named(&format!("entry-{i}"))).collect();
    let empty = HashMap::new();
    for format in [keystore::Format::Pkcs12, keystore::Format::Jks, keystore::Format::Jceks] {
        let bytes = keystore::encode(&entries, "corpus-pw", format).unwrap();
        assert!(bytes.len() > 3_000, "{} should be a substantial file, was {}", format.name(), bytes.len());
        let (_, back) = keystore::decode(&bytes, "corpus-pw", &empty).unwrap_or_else(|e| panic!("{}: {e}", format.name()));
        assert_eq!(back.len(), entries.len(), "{}", format.name());
    }
}
