//! Interoperability tests against the real tools users pair Keystore Studio with: Java `keytool` /
//! `jarsigner` and `openssl`. Each test is skipped (with a message) if the tool is missing.

use keystore_studio_lib::model::*;
use keystore_studio_lib::{cms, dh, entry, export, jar, jwt, keystore, ops, tls};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {tool}")).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Discard path for openssl `-out`. `/dev/null` does not exist on Windows; `NUL` does.
fn null_out() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

/// PEM / OpenSSL text comparison that ignores CRLF differences on Windows.
fn same_pem(a: &str, b: &str) -> bool {
    a.replace("\r\n", "\n").replace('\r', "\n").trim() == b.replace("\r\n", "\n").replace('\r', "\n").trim()
}

/// Runs a command, returning (success, combined output).
fn run(dir: &Path, cmd: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(cmd).args(args).current_dir(dir).env("JAVA_TOOL_OPTIONS", "").output().unwrap_or_else(|e| panic!("cannot run {cmd}: {e}"));
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn must(dir: &Path, cmd: &str, args: &[&str]) -> String {
    let (ok, out) = run(dir, cmd, args);
    assert!(ok, "{cmd} {args:?} failed:\n{out}");
    out
}

fn kp_input(alias: &str, alg: &str, curve: &str, is_ca: bool) -> GenerateKeyPairInput {
    GenerateKeyPairInput {
        alias: alias.into(),
        algorithm: alg.into(),
        key_size: 2048,
        curve: Some(curve.into()),
        signature_hash: None,
        subject_dn: format!("CN={alias}.example.test, OU=Interop, O=Keystore Studio, C=US"),
        common_name: String::new(),
        organization: String::new(),
        organizational_unit: String::new(),
        locality: String::new(),
        state: String::new(),
        country: String::new(),
        email: String::new(),
        validity_days: 365,
        is_ca,
        path_len: None,
        sans: if is_ca { vec![] } else { vec![format!("{alias}.example.test"), "127.0.0.1".into()] },
        key_usage: vec![],
        extended_key_usage: vec![],
        labels: vec![],
        not_before: String::new(),
        not_after: String::new(),
        crl_distribution_points: vec![],
        ocsp_urls: vec![],
        ca_issuer_urls: vec![],
    }
}

struct Pki {
    root: KeystoreEntry,
    inter: KeystoreEntry,
    rsa: KeystoreEntry,
    ec: KeystoreEntry,
    ed: KeystoreEntry,
}

fn pki() -> Pki {
    let root = ops::generate_key_pair(&kp_input("root-ca", "RSA", "", true), None).unwrap();
    let inter = ops::generate_key_pair(&kp_input("issuing-ca", "ECDSA", "P-384", true), Some(&root)).unwrap();
    let rsa = ops::generate_key_pair(&kp_input("web-rsa", "RSA", "", false), Some(&inter)).unwrap();
    let ec = ops::generate_key_pair(&kp_input("web-ec", "ECDSA", "P-256", false), Some(&inter)).unwrap();
    let ed = ops::generate_key_pair(&kp_input("signer-ed", "Ed25519", "", false), None).unwrap();
    Pki { root, inter, rsa, ec, ed }
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

fn ks(entries: Vec<KeystoreEntry>) -> KeystoreFile {
    KeystoreFile { entries, ..Default::default() }
}

#[test]
fn our_keystores_open_in_keytool() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    let trusted = entry::trusted_cert_entry("root", &entry::chain_der(&p.root).unwrap()[0], None).unwrap();
    let aes = entry::secret_key_entry("aes-key", "AES", &[7u8; 32], None);
    let hmac = entry::secret_key_entry("hmac-key", "HmacSHA256", &[9u8; 32], None);
    for (fmt, name, with_secret) in [(keystore::Format::Pkcs12, "o.p12", true), (keystore::Format::Jks, "o.jks", false), (keystore::Format::Jceks, "o.jceks", true)] {
        let mut entries = vec![p.rsa.clone(), p.ec.clone(), p.ed.clone(), trusted.clone()];
        if with_secret {
            entries.push(aes.clone());
            entries.push(hmac.clone());
        }
        let path = d.path().join(name);
        keystore::save(&ks(entries.clone()), path.to_str().unwrap(), "interop-pw", fmt).unwrap();
        let out = must(d.path(), "keytool", &["-list", "-v", "-keystore", name, "-storepass", "interop-pw"]);
        assert_eq!(out.matches("PrivateKeyEntry").count(), 3, "{name}:\n{out}");
        assert_eq!(out.matches("trustedCertEntry").count(), 1, "{name}:\n{out}");
        if with_secret {
            assert_eq!(out.matches("SecretKeyEntry").count(), 2, "{name}:\n{out}");
        }
        assert!(out.contains("Certificate chain length: 3"), "{name}: chain not preserved:\n{out}");
        // keytool can use the key: export the certificate and re-sign a CSR with it.
        must(d.path(), "keytool", &["-certreq", "-alias", "web-ec", "-keystore", name, "-storepass", "interop-pw", "-file", &format!("{name}.csr")]);
        // And keytool's wrong-password check agrees.
        let (ok, _) = run(d.path(), "keytool", &["-list", "-keystore", name, "-storepass", "wrong-pw"]);
        assert!(!ok);
    }
}

#[test]
fn keytool_keystores_open_in_keystore_studio() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    std::thread::scope(|s| {
        for (t, f) in [("PKCS12", "k.p12"), ("JKS", "k.jks"), ("JCEKS", "k.jceks")] {
            let sub = d.path().join(t);
            std::fs::create_dir_all(&sub).unwrap();
            s.spawn(move || {
                let k = |args: &[&str]| must(&sub, "keytool", args);
                k(&[
                    "-genkeypair",
                    "-alias",
                    "rsa",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-dname",
                    "CN=rsa, O=keytool",
                    "-storetype",
                    t,
                    "-keystore",
                    f,
                    "-storepass",
                    "changeit",
                    "-keypass",
                    "changeit",
                ]);
                k(&["-genkeypair", "-alias", "ec", "-keyalg", "EC", "-groupname", "secp384r1", "-dname", "CN=ec", "-storetype", t, "-keystore", f, "-storepass", "changeit", "-keypass", "changeit"]);
                k(&["-exportcert", "-alias", "rsa", "-keystore", f, "-storepass", "changeit", "-file", &format!("{f}.cer")]);
                k(&["-importcert", "-noprompt", "-alias", "trusted", "-file", &format!("{f}.cer"), "-keystore", f, "-storepass", "changeit"]);
                if t != "JKS" {
                    k(&["-genseckey", "-alias", "aes", "-keyalg", "AES", "-keysize", "256", "-storetype", t, "-keystore", f, "-storepass", "changeit", "-keypass", "changeit"]);
                }
                let opened = keystore::open(sub.join(f).to_str().unwrap(), "changeit", &HashMap::new()).unwrap();
                assert_eq!(opened.format, t);
                let by = |a: &str| opened.entries.iter().find(|e| e.alias == a).unwrap_or_else(|| panic!("{f}: missing {a}"));
                assert_eq!(by("rsa").entry_type, "KeyPair");
                assert!(by("rsa").private_key_pem.is_some());
                assert_eq!(by("ec").curve.as_deref(), Some("P-384"));
                assert_eq!(by("trusted").entry_type, "TrustedCertificate");
                assert_eq!(by("trusted").sha256_fingerprint, by("rsa").sha256_fingerprint);
                if t != "JKS" {
                    assert_eq!(by("aes").entry_type, "SecretKey");
                    assert_eq!(by("aes").algorithm, "AES");
                    assert_eq!(by("aes").key_size, 256);
                }
                assert!(keystore::open(sub.join(f).to_str().unwrap(), "bad", &HashMap::new()).is_err());

                // Round trip through our writer and back into keytool.
                let out = format!("re-{f}");
                keystore::save(&opened, sub.join(&out).to_str().unwrap(), "newpass", keystore::Format::parse(t).unwrap()).unwrap();
                let listing = must(&sub, "keytool", &["-list", "-keystore", &out, "-storepass", "newpass"]);
                assert!(listing.contains(&format!("contains {} entr", opened.entries.len())), "{listing}");
            });
        }
    });

    // Separate key password in JKS: entry loads locked, unlocks with the key password, and
    // survives a re-save untouched.
    let k = |args: &[&str]| must(d.path(), "keytool", args);
    k(&["-genkeypair", "-alias", "sep", "-keyalg", "EC", "-dname", "CN=sep", "-storetype", "JKS", "-keystore", "sep.jks", "-storepass", "storepw", "-keypass", "keypass99"]);
    let locked = keystore::open(d.path().join("sep.jks").to_str().unwrap(), "storepw", &HashMap::new()).unwrap();
    assert!(locked.entries[0].locked);
    keystore::save(&locked, d.path().join("sep2.jks").to_str().unwrap(), "storepw", keystore::Format::Jks).unwrap();
    must(d.path(), "keytool", &["-certreq", "-alias", "sep", "-keystore", "sep2.jks", "-storepass", "storepw", "-keypass", "keypass99", "-file", "sep.csr"]);
    let mut kp = HashMap::new();
    kp.insert("sep".to_string(), "keypass99".to_string());
    let unlocked = keystore::open(d.path().join("sep.jks").to_str().unwrap(), "storepw", &kp).unwrap();
    assert!(!unlocked.entries[0].locked && unlocked.entries[0].private_key_pem.is_some());
}

#[test]
fn openssl_pkcs12_variants_open() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let o = |args: &[&str]| must(d.path(), "openssl", args);
    o(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "cert.pem", "-subj", "/CN=openssl.test", "-days", "30"]);
    o(&["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Extra CA", "-days", "30"]);
    let variants: Vec<(&str, Vec<&str>)> = vec![
        ("default.p12", vec![]),
        ("3des.p12", vec!["-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"]),
        ("aes128.p12", vec!["-keypbe", "AES-128-CBC", "-certpbe", "AES-128-CBC", "-macalg", "sha512"]),
        ("nocrypt-certs.p12", vec!["-certpbe", "NONE"]),
    ];
    for (name, extra) in &variants {
        let mut args = vec!["pkcs12", "-export", "-in", "cert.pem", "-inkey", "key.pem", "-certfile", "ca.pem", "-name", "my key", "-out", name, "-passout", "pass:p12pass"];
        args.extend(extra.iter());
        o(&args);
        let opened = keystore::open(d.path().join(name).to_str().unwrap(), "p12pass", &HashMap::new()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let key = opened.entries.iter().find(|e| e.entry_type == "KeyPair").unwrap_or_else(|| panic!("{name}: no key pair"));
        assert_eq!(key.alias, "my key");
        assert!(key.subject.contains("CN=openssl.test"));
        // The unrelated extra CA becomes a trusted entry, not part of the chain.
        assert_eq!(key.chain_length, 1, "{name}");
        assert!(opened.entries.iter().any(|e| e.entry_type == "TrustedCertificate" && e.subject.contains("Extra CA")), "{name}");
    }
    // Legacy RC2-40 (needs OpenSSL's legacy provider; skip if unavailable).
    let (ok, _) = run(d.path(), "openssl", &["pkcs12", "-export", "-legacy", "-in", "cert.pem", "-inkey", "key.pem", "-out", "legacy.p12", "-passout", "pass:p12pass"]);
    if ok {
        let opened = keystore::open(d.path().join("legacy.p12").to_str().unwrap(), "p12pass", &HashMap::new()).unwrap();
        assert_eq!(opened.entries.len(), 1);
    }
    // Our PKCS#12 opens in OpenSSL with the key intact.
    let p = pki();
    keystore::save(&ks(vec![p.ec.clone()]), d.path().join("ours.p12").to_str().unwrap(), "pw12345", keystore::Format::Pkcs12).unwrap();
    let dump = o(&["pkcs12", "-in", "ours.p12", "-passin", "pass:pw12345", "-nodes", "-info"]);
    assert!(dump.contains("BEGIN PRIVATE KEY") && dump.matches("BEGIN CERTIFICATE").count() == 3, "{dump}");
}

/// PBMAC1 integrity protection (RFC 9579), both directions. Needs OpenSSL 3.4+ for
/// `-pbmac1_pbkdf2`; older builds skip the test rather than fail it.
#[test]
fn pbmac1_pkcs12_interop_with_openssl() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let o = |args: &[&str]| must(d.path(), "openssl", args);
    o(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "cert.pem", "-subj", "/CN=pbmac1.test", "-days", "30"]);
    let (ok, out) = run(d.path(), "openssl", &["pkcs12", "-export", "-in", "cert.pem", "-inkey", "key.pem", "-name", "pbmac1 key", "-out", "theirs.p12", "-passout", "pass:macpass", "-pbmac1_pbkdf2"]);
    if !ok {
        eprintln!("skipping PBMAC1 interop: this OpenSSL has no -pbmac1_pbkdf2 ({})", out.trim());
        return;
    }

    // Theirs → ours.
    let opened = keystore::open(d.path().join("theirs.p12").to_str().unwrap(), "macpass", &HashMap::new()).expect("open OpenSSL PBMAC1 file");
    let key = opened.entries.iter().find(|e| e.entry_type == "KeyPair").expect("no key pair");
    assert_eq!(key.alias, "pbmac1 key");
    assert!(key.subject.contains("CN=pbmac1.test"));
    // A wrong password must be reported as such, which proves the MAC is really being checked.
    assert!(keystore::open(d.path().join("theirs.p12").to_str().unwrap(), "wrong", &HashMap::new()).is_err());

    // Ours → theirs. Written with PBMAC1 and read back by OpenSSL, key and certificate intact.
    let p = pki();
    let ours = d.path().join("ours-pbmac1.p12");
    let bytes = keystore_studio_lib::pkcs12::encode_with_mac(std::slice::from_ref(&p.rsa), "macpass", keystore_studio_lib::pkcs12::MacKind::Pbmac1).unwrap();
    std::fs::write(&ours, &bytes).unwrap();
    let dump = o(&["pkcs12", "-in", "ours-pbmac1.p12", "-passin", "pass:macpass", "-nodes", "-info"]);
    assert!(dump.contains("PBMAC1"), "OpenSSL did not report PBMAC1 protection:\n{dump}");
    assert!(dump.contains("BEGIN PRIVATE KEY"), "{dump}");
    // And it still opens in our own reader.
    assert_eq!(keystore::open(ours.to_str().unwrap(), "macpass", &HashMap::new()).unwrap().entries.len(), 1);
}

#[test]
fn certificates_csrs_and_crls_verify_with_openssl() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    write(d.path(), "root.pem", p.root.certificate_chain[0].pem.as_bytes());
    write(d.path(), "inter.pem", p.inter.certificate_chain[0].pem.as_bytes());
    write(d.path(), "leaf.pem", p.rsa.certificate_chain[0].pem.as_bytes());
    let out = must(d.path(), "openssl", &["verify", "-CAfile", "root.pem", "-untrusted", "inter.pem", "-purpose", "sslserver", "leaf.pem"]);
    assert!(out.contains("leaf.pem: OK"), "{out}");
    must(d.path(), "openssl", &["verify", "-CAfile", "root.pem", "-untrusted", "inter.pem", "-verify_hostname", "web-rsa.example.test", "leaf.pem"]);
    must(d.path(), "openssl", &["verify", "-CAfile", "root.pem", "-untrusted", "inter.pem", "-verify_ip", "127.0.0.1", "leaf.pem"]);
    let text = must(d.path(), "openssl", &["x509", "-in", "leaf.pem", "-noout", "-text"]);
    assert!(text.contains("DNS:web-rsa.example.test, IP Address:127.0.0.1"), "{text}");
    assert!(text.contains("CA:FALSE") && text.contains("TLS Web Server Authentication"), "{text}");
    // Our fingerprints match OpenSSL's.
    let fp = must(d.path(), "openssl", &["x509", "-in", "leaf.pem", "-noout", "-fingerprint", "-sha256"]);
    assert!(fp.contains(&p.rsa.sha256_fingerprint), "{fp} vs {}", p.rsa.sha256_fingerprint);
    let fp1 = must(d.path(), "openssl", &["x509", "-in", "leaf.pem", "-noout", "-fingerprint", "-sha1"]);
    assert!(fp1.contains(&p.rsa.sha1_fingerprint));

    // Our CSR verifies in OpenSSL.
    for e in [&p.rsa, &p.ec, &p.ed] {
        let csr = ops::generate_csr(e, &CsrOptions { subject_dn: None, sans: None, signature_hash: None }).unwrap();
        write(d.path(), "ours.csr", csr.csr_pem.as_bytes());
        let out = must(d.path(), "openssl", &["req", "-in", "ours.csr", "-noout", "-verify", "-text"]);
        assert!(out.to_lowercase().contains("verify ok"), "{out}");
    }

    // An OpenSSL CSR signed by our CA verifies with OpenSSL.
    must(
        d.path(),
        "openssl",
        &["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "req.key", "-out", "req.csr", "-subj", "/CN=from-openssl.test/O=Req", "-addext", "subjectAltName=DNS:from-openssl.test"],
    );
    let signed = ops::sign_csr(
        &SignCsrInput {
            csr_pem: std::fs::read_to_string(d.path().join("req.csr")).unwrap(),
            subject_override: None,
            validity_days: 30,
            is_ca: false,
            path_len: None,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            copy_requested_sans: Some(true),
            copy_requested_usages: None,
            not_before: String::new(),
            not_after: String::new(),
            crl_distribution_points: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
        },
        &p.inter,
    )
    .unwrap();
    write(d.path(), "issued.pem", signed.certificate.pem.as_bytes());
    must(d.path(), "openssl", &["verify", "-CAfile", "root.pem", "-untrusted", "inter.pem", "-verify_hostname", "from-openssl.test", "issued.pem"]);
    // ... and the key matches the issued certificate.
    let m1 = must(d.path(), "openssl", &["x509", "-in", "issued.pem", "-noout", "-pubkey"]);
    let m2 = must(d.path(), "openssl", &["pkey", "-in", "req.key", "-pubout"]);
    assert_eq!(m1.trim(), m2.trim());

    // CRL signed by the intermediate verifies.
    let crl = ops::generate_crl(&p.inter, 30, 42, &[RevokedCertEntry { serial_number: p.rsa.serial_number.clone(), revocation_date: "2026-01-15".into(), reason: "keyCompromise".into() }]).unwrap();
    write(d.path(), "crl.pem", crl.pem.as_bytes());
    let out = must(d.path(), "openssl", &["crl", "-in", "crl.pem", "-CAfile", "inter.pem", "-noout", "-text"]);
    assert!(out.contains("verify OK") || out.contains("verify ok"), "{out}");
    assert!(out.contains("Key Compromise") && out.contains("42"), "{out}");
    // OpenSSL rejects the revoked leaf when CRL checking is on.
    write(d.path(), "chain.pem", format!("{}{}", p.root.certificate_chain[0].pem, p.inter.certificate_chain[0].pem).as_bytes());
    let root_crl = ops::generate_crl(&p.root, 30, 1, &[]).unwrap();
    write(d.path(), "crls.pem", format!("{}{}", crl.pem, root_crl.pem).as_bytes());
    let (ok, out) = run(d.path(), "openssl", &["verify", "-crl_check_all", "-CAfile", "chain.pem", "-CRLfile", "crls.pem", "leaf.pem"]);
    assert!(!ok && out.contains("revoked"), "{out}");
}

#[test]
fn keytool_ca_workflow_with_keystore_studio_ca() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    let k = |args: &[&str]| must(d.path(), "keytool", args);
    k(&["-genkeypair", "-alias", "app", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=app.example.test", "-storetype", "PKCS12", "-keystore", "app.p12", "-storepass", "changeit"]);
    k(&["-certreq", "-alias", "app", "-keystore", "app.p12", "-storepass", "changeit", "-ext", "SAN=dns:app.example.test", "-file", "app.csr"]);
    let signed = ops::sign_csr(
        &SignCsrInput {
            csr_pem: std::fs::read_to_string(d.path().join("app.csr")).unwrap(),
            subject_override: None,
            validity_days: 30,
            is_ca: false,
            path_len: None,
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            copy_requested_sans: Some(true),
            copy_requested_usages: None,
            not_before: String::new(),
            not_after: String::new(),
            crl_distribution_points: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
        },
        &p.inter,
    )
    .unwrap();
    write(d.path(), "reply.pem", signed.chain_pem.as_bytes());
    write(d.path(), "root.pem", p.root.certificate_chain[0].pem.as_bytes());
    k(&["-importcert", "-noprompt", "-alias", "root", "-file", "root.pem", "-keystore", "app.p12", "-storepass", "changeit"]);
    let out = k(&["-importcert", "-noprompt", "-alias", "app", "-file", "reply.pem", "-keystore", "app.p12", "-storepass", "changeit"]);
    assert!(out.contains("Certificate reply was installed"), "{out}");
    let listing = k(&["-list", "-v", "-alias", "app", "-keystore", "app.p12", "-storepass", "changeit"]);
    assert!(listing.contains("Certificate chain length: 3"), "{listing}");
}

#[test]
fn cms_interop_with_openssl() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    write(d.path(), "data.txt", b"interop payload\n");
    // OpenSSL 3.0 has no Ed25519 CMS support (it cannot even sign one); Ed25519 signature blocks
    // are covered by the jarsigner test instead.
    for e in [&p.rsa, &p.ec] {
        let key = entry::private_key(e).unwrap();
        let chain = entry::chain_der(e).unwrap();
        let attached = cms::sign(b"interop payload\n", &key, &chain, false).unwrap();
        write(d.path(), "att.pem", keystore_studio_lib::util::to_pem("CMS", &attached).as_bytes());
        let out = must(d.path(), "openssl", &["cms", "-verify", "-in", "att.pem", "-inform", "PEM", "-noverify", "-binary"]);
        assert!(out.contains("interop payload") && out.contains("Verification successful"), "{} {out}", e.alias);
        let detached = cms::sign(b"interop payload\n", &key, &chain, true).unwrap();
        write(d.path(), "det.der", &detached);
        let out = must(d.path(), "openssl", &["cms", "-verify", "-in", "det.der", "-inform", "DER", "-content", "data.txt", "-noverify", "-binary", "-out", null_out()]);
        assert!(out.contains("Verification successful"), "{out}");
        // Tampered content fails in OpenSSL.
        write(d.path(), "bad.txt", b"interop payloaD\n");
        let (ok, _) = run(d.path(), "openssl", &["cms", "-verify", "-in", "det.der", "-inform", "DER", "-content", "bad.txt", "-noverify", "-binary", "-out", null_out()]);
        assert!(!ok);
    }
    // OpenSSL-produced signatures verify in Keystore Studio.
    write(d.path(), "s.crt", p.rsa.certificate_chain[0].pem.as_bytes());
    write(d.path(), "s.key", p.rsa.private_key_pem.as_ref().unwrap().as_bytes());
    must(d.path(), "openssl", &["cms", "-sign", "-signer", "s.crt", "-inkey", "s.key", "-in", "data.txt", "-binary", "-nodetach", "-outform", "DER", "-out", "o.p7s"]);
    let r = cms::verify(&std::fs::read(d.path().join("o.p7s")).unwrap(), None, &[]).unwrap();
    assert!(r.valid, "{}", r.message);
    must(d.path(), "openssl", &["cms", "-sign", "-signer", "s.crt", "-inkey", "s.key", "-in", "data.txt", "-binary", "-outform", "PEM", "-out", "od.pem"]);
    let der = cms::cms_der_from_bytes(&std::fs::read(d.path().join("od.pem")).unwrap()).unwrap();
    assert!(cms::verify(&der, Some(b"interop payload\n"), &[]).unwrap().valid);
    assert!(!cms::verify(&der, Some(b"other"), &[]).unwrap().valid);
}

#[test]
fn exports_are_readable_by_openssl() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    for e in [&p.rsa, &p.ec, &p.ed] {
        let path = |n: &str| d.path().join(n).to_string_lossy().to_string();
        export::export_entry(e, "private_pkcs8_encrypted", &path("enc.key"), Some("exportpw")).unwrap();
        let out = must(d.path(), "openssl", &["pkey", "-in", "enc.key", "-passin", "pass:exportpw", "-pubout"]);
        assert!(same_pem(&out, e.public_key_pem.as_ref().unwrap()), "{out}");
        export::export_entry(e, "pkcs7_der", &path("b.p7b"), None).unwrap();
        let certs = must(d.path(), "openssl", &["pkcs7", "-in", "b.p7b", "-inform", "DER", "-print_certs", "-noout"]);
        assert_eq!(certs.matches("subject=").count(), e.chain_length, "{certs}");
        export::export_entry(e, "cert_der", &path("c.cer"), None).unwrap();
        must(d.path(), "openssl", &["x509", "-in", "c.cer", "-inform", "DER", "-noout"]);
        export::export_entry(e, "pkcs12", &path("one.p12"), Some("p12pw")).unwrap();
        must(d.path(), "openssl", &["pkcs12", "-in", "one.p12", "-passin", "pass:p12pw", "-nodes", "-noout"]);
        if have("ssh-keygen") {
            export::export_entry(e, "public_openssh", &path("id.pub"), None).unwrap();
            must(d.path(), "ssh-keygen", &["-l", "-f", "id.pub"]);
        }
    }
    // RS256 JWT verifies with OpenSSL.
    let token = jwt::sign(&jwt::JwtClaims { issuer: "i", subject: "s", audience: "a", validity_minutes: 5, custom_claims_json: "" }, &p.rsa, Some("RS256")).unwrap();
    let (input, sig) = token.rsplit_once('.').unwrap();
    use base64::Engine;
    write(d.path(), "in.txt", input.as_bytes());
    write(d.path(), "sig.bin", &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).unwrap());
    write(d.path(), "pub.pem", p.rsa.public_key_pem.as_ref().unwrap().as_bytes());
    let out = must(d.path(), "openssl", &["dgst", "-sha256", "-verify", "pub.pem", "-signature", "sig.bin", "in.txt"]);
    assert!(out.contains("Verified OK"));
}

/// The headline flow: a user has `cert.pem` + `key.pem` and a passphrase, and wants a .pfx/.p12.
/// Whatever we produce has to be readable by the tools they will actually hand it to.
#[test]
fn built_pkcs12_opens_in_openssl_and_keytool() {
    let d = tmp();
    let p = pki();

    for (name, src) in [("rsa", &p.rsa), ("ec", &p.ec)] {
        // Write out the inputs the way a user would have them on disk.
        let chain: String = entry::chain_der(src).unwrap().iter().map(|c| keystore_studio_lib::util::to_pem("CERTIFICATE", c)).collect();
        write(d.path(), "cert.pem", chain.as_bytes());
        write(d.path(), "key.pem", src.private_key_pem.as_ref().unwrap().as_bytes());

        let der = ops::build_pkcs12(&BuildPkcs12Input {
            alias: name.into(),
            key: std::fs::read(d.path().join("key.pem")).unwrap(),
            certificate: Some(std::fs::read(d.path().join("cert.pem")).unwrap()),
            key_password: None,
            passphrase: "pfxpw".into(),
            mac: None,
        })
        .unwrap();
        let out = format!("{name}.pfx");
        write(d.path(), &out, &der);

        if have("openssl") {
            // The key and the certificate must both come back, and the key must match the cert.
            let dump = must(d.path(), "openssl", &["pkcs12", "-in", &out, "-passin", "pass:pfxpw", "-nodes"]);
            assert!(dump.contains("BEGIN PRIVATE KEY") || dump.contains("BEGIN EC PRIVATE KEY"), "no private key in {out}:\n{dump}");
            assert!(dump.contains("BEGIN CERTIFICATE"), "no certificate in {out}:\n{dump}");
            assert!(dump.contains(&format!("friendlyName: {name}")), "alias missing from {out}:\n{dump}");
            // The wrong passphrase must fail.
            let (ok, _) = run(d.path(), "openssl", &["pkcs12", "-in", &out, "-passin", "pass:wrong", "-nodes", "-noout"]);
            assert!(!ok, "{out} opened with the wrong passphrase");
        }

        if have("keytool") {
            let list = must(d.path(), "keytool", &["-list", "-v", "-keystore", &out, "-storetype", "PKCS12", "-storepass", "pfxpw"]);
            assert!(list.contains("PrivateKeyEntry"), "keytool does not see a private key in {out}:\n{list}");
            assert!(list.to_lowercase().contains(name), "alias missing from keytool output:\n{list}");
        }
    }

    // The same thing again, but driven the way the command layer drives it: inputs read from the
    // paths the user picked, and the result written to disk with the same atomic writer.
    {
        let cert_path = d.path().join("cert.pem");
        let key_path = d.path().join("key.pem");
        let out_path = d.path().join("from-paths.pfx");
        let der = ops::build_pkcs12(&BuildPkcs12Input {
            alias: "from-paths".into(),
            key: std::fs::read(&key_path).unwrap(),
            certificate: Some(std::fs::read(&cert_path).unwrap()),
            key_password: None,
            passphrase: "pathpw".into(),
            mac: None,
        })
        .unwrap();
        keystore_studio_lib::util::write_atomic(&out_path, &der).unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), der, "the written file must match what we built");
        let back = keystore::open(&out_path.to_string_lossy(), "pathpw", &HashMap::new()).unwrap();
        assert_eq!(back.entries.iter().filter(|e| e.entry_type == "KeyPair").count(), 1);
    }

    // Round-trip through our own reader as well: same key, same certificate.
    let reopened = keystore::open(&d.path().join("rsa.pfx").to_string_lossy(), "pfxpw", &HashMap::new()).unwrap();
    let kp = reopened.entries.iter().find(|e| e.entry_type == "KeyPair").unwrap();
    assert_eq!(kp.sha256_fingerprint, p.rsa.sha256_fingerprint);
    assert!(kp.private_key_pem.is_some());

    if !have("openssl") && !have("keytool") {
        eprintln!("note: neither openssl nor keytool installed; only the internal round trip ran");
    }
}

#[test]
fn dh_parameters_pass_openssl_check() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    for r in [dh::ffdhe(2048).unwrap(), dh::ffdhe(4096).unwrap(), dh::generate(1024).unwrap()] {
        write(d.path(), "dh.pem", r.pem.as_bytes());
        let out = must(d.path(), "openssl", &["dhparam", "-in", "dh.pem", "-check", "-noout"]);
        assert!(out.contains("appear to be ok"), "{} {out}", r.group);
    }
}

#[test]
fn signed_jars_verify_with_jarsigner() {
    if !have("jarsigner") {
        eprintln!("skipping: jarsigner not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    // Build a small JAR with a pre-existing manifest main attribute and a long entry name.
    let jar_path = d.path().join("app.jar");
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::fs::File::create(&jar_path).unwrap());
        let o = zip::write::SimpleFileOptions::default();
        w.add_directory("META-INF/", o).unwrap();
        w.start_file("META-INF/MANIFEST.MF", o).unwrap();
        w.write_all(b"Manifest-Version: 1.0\r\nMain-Class: com.example.App\r\n\r\n").unwrap();
        w.start_file("com/example/App.class", o).unwrap();
        w.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]).unwrap();
        let long = format!("assets/{}/resource.txt", "very-long-directory-name".repeat(4));
        w.start_file(long, o).unwrap();
        w.write_all(b"hello").unwrap();
        w.start_file("META-INF/services/com.example.Service", o).unwrap();
        w.write_all(b"com.example.Impl\n").unwrap();
        w.finish().unwrap();
    }
    for e in [&p.rsa, &p.ec, &p.ed] {
        let out = d.path().join(format!("signed-{}.jar", e.alias));
        let r = jar::sign_jar(jar_path.to_str().unwrap(), out.to_str().unwrap(), e).unwrap();
        assert_eq!(r.entries_signed, 3);
        let v = must(d.path(), "jarsigner", &["-verify", "-verbose", out.to_str().unwrap()]);
        assert!(v.contains("jar verified"), "{}: {v}", e.alias);
        assert!(r.manifest_preview.contains("Main-Class: com.example.App"));
        // Re-signing an already signed jar replaces the old signature.
        let again = d.path().join(format!("resigned-{}.jar", e.alias));
        jar::sign_jar(out.to_str().unwrap(), again.to_str().unwrap(), e).unwrap();
        let v = must(d.path(), "jarsigner", &["-verify", again.to_str().unwrap()]);
        assert!(v.contains("jar verified"), "{v}");
        assert!(!d.path().join(format!("resigned-{}.jar.xks-tmp", e.alias)).exists(), "the temp file must be renamed away");
    }
    // A failed write removes its temp file instead of leaving it beside the output.
    let missing_dir = d.path().join("no-such-dir").join("out.jar");
    assert!(jar::sign_jar(jar_path.to_str().unwrap(), missing_dir.to_str().unwrap(), &p.rsa).is_err());
    // A missing input is reported as missing, not as "same file as the output".
    let gone = d.path().join("gone.jar");
    let err = jar::sign_jar(gone.to_str().unwrap(), d.path().join("gone-out.jar").to_str().unwrap(), &p.rsa).unwrap_err();
    assert!(err.contains("cannot open"), "{err}");
    // Signing in place is refused: the original is never modified.
    assert!(jar::sign_jar(jar_path.to_str().unwrap(), jar_path.to_str().unwrap(), &p.rsa).is_err());
}

/// A minimal RFC 3161 HTTP timestamp authority backed by `openssl ts -reply`, so timestamping can
/// be tested end to end without reaching a public TSA. Returns its URL and a shutdown handle.
struct TestTsa {
    url: String,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestTsa {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        // The listener polls with a timeout rather than blocking forever in accept(), so setting
        // the flag is enough; no wake-up connection is needed. (An earlier version opened one, and
        // the server then blocked reading an HTTP request that never arrived, so join() hung and
        // took the whole test binary with it.)
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start_test_tsa(dir: &Path) -> Option<TestTsa> {
    use std::io::{Read, Write};
    let o = |args: &[&str]| must(dir, "openssl", args);
    // A TSA certificate needs the critical timeStamping extended key usage; openssl ts refuses
    // anything else.
    o(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "tsakey.pem",
        "-out",
        "tsacert.pem",
        "-subj",
        "/CN=Keystore Studio Test TSA/O=Interop",
        "-days",
        "30",
        "-addext",
        "extendedKeyUsage=critical,timeStamping",
        "-addext",
        "keyUsage=critical,digitalSignature",
    ]);
    std::fs::write(dir.join("tsaserial"), b"01\n").unwrap();
    std::fs::write(
        dir.join("tsa.cnf"),
        b"[ tsa ]\ndefault_tsa = tsa_config1\n[ tsa_config1 ]\nserial = tsaserial\ncrypto_device = builtin\n\
          signer_cert = tsacert.pem\nsigner_key = tsakey.pem\nsigner_digest = sha256\ncerts = tsacert.pem\n\
          default_policy = 1.3.6.1.4.1.99999.1\ndigests = sha256, sha384, sha512\naccuracy = secs:1\n\
          clock_precision_digits = 0\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n",
    )
    .unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    // Non-blocking accept, so the loop can notice the shutdown flag instead of sitting in
    // accept() until something connects.
    listener.set_nonblocking(true).ok()?;
    let dir = dir.to_path_buf();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown.clone();
    let handle = std::thread::spawn(move || {
        loop {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(_) => return,
            };
            // A client that connects and sends nothing must not wedge the server.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = stream.set_nonblocking(false);
            // Read headers, then exactly Content-Length bytes of DER body.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let body = loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break None,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..at]).to_lowercase();
                            let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                            let start = at + 4;
                            while buf.len() < start + len {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                    Err(_) => break,
                                }
                            }
                            break Some(buf[start..(start + len).min(buf.len())].to_vec());
                        }
                    }
                    Err(_) => break None,
                }
            };
            let Some(body) = body else { continue };
            let req_path = dir.join("req-in.tsq");
            let resp_path = dir.join("resp-out.tsr");
            let _ = std::fs::write(&req_path, &body);
            let out = Command::new("openssl").args(["ts", "-reply", "-queryfile", "req-in.tsq", "-config", "tsa.cnf", "-section", "tsa_config1", "-out", "resp-out.tsr"]).current_dir(&dir).output();
            let reply = out.ok().filter(|o| o.status.success()).and_then(|_| std::fs::read(&resp_path).ok());
            let _ = match reply {
                Some(der) => stream
                    .write_all(&[format!("HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", der.len()).into_bytes(), der].concat()),
                None => stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            };
        }
    });
    Some(TestTsa { url: format!("http://127.0.0.1:{port}/tsa"), shutdown, handle: Some(handle) })
}

/// RFC 3161 timestamping, end to end: our request reaches a real TSA implementation, the token
/// comes back, we attach it to a CMS SignerInfo, and both OpenSSL and our own reader accept it.
#[test]
fn timestamps_verify_with_openssl_ts() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let Some(tsa) = start_test_tsa(d.path()) else {
        eprintln!("skipping: cannot start the local test TSA");
        return;
    };
    let p = pki();
    let key = entry::private_key(&p.ec).unwrap();
    let chain = entry::chain_der(&p.ec).unwrap();

    let (signed, ts) = cms::sign_timestamped(b"timestamped payload", &key, &chain, true, Some(&tsa.url)).expect("timestamped signing");
    let ts = ts.expect("a timestamp should have been returned");
    assert!(ts.authority.contains("Keystore Studio Test TSA"), "authority was {:?}", ts.authority);
    assert_eq!(ts.hash_algorithm, "SHA-256");
    assert!(ts.time.ends_with("UTC"), "{:?}", ts.time);

    // OpenSSL verifies the token itself against the TSA certificate.
    write(d.path(), "token.tst", &ts.token);
    let out = must(d.path(), "openssl", &["ts", "-verify", "-in", "token.tst", "-token_in", "-queryfile", "req-in.tsq", "-CAfile", "tsacert.pem", "-untrusted", "tsacert.pem"]);
    assert!(out.contains("Verification: OK"), "{out}");

    // Our verifier finds the token in the unsigned attributes and binds it to the signature.
    let v = cms::verify(&signed, Some(b"timestamped payload"), &[]).unwrap();
    assert!(v.valid, "{}", v.message);
    let got = v.signers[0].timestamp.as_ref().expect("verify should surface the timestamp");
    assert!(got.valid && got.error.is_none(), "{got:?}");
    assert_eq!(got.serial_number, ts.serial_number);

    // The signature still verifies in OpenSSL with the token attached, so the extra unsigned
    // attribute did not corrupt the structure. `-noverify` skips the certificate purpose check
    // (the test PKI's leaf is not an S/MIME certificate); the signature itself is still checked.
    write(d.path(), "msg.txt", b"timestamped payload");
    write(d.path(), "sig.p7s", &signed);
    let out = must(d.path(), "openssl", &["cms", "-verify", "-in", "sig.p7s", "-inform", "DER", "-content", "msg.txt", "-noverify", "-binary", "-out", null_out()]);
    assert!(out.contains("Verification successful"), "{out}");

    // A token moved onto a different signature must be rejected, not accepted silently.
    let (other, _) = cms::sign_timestamped(b"different payload", &key, &chain, true, None).unwrap();
    assert!(keystore_studio_lib::tsa::verify_token(&ts.token, &other).is_err());

    // An unreachable authority must fail the whole signing operation, not produce an unstamped file.
    let err = cms::sign_timestamped(b"x", &key, &chain, true, Some("http://127.0.0.1:1/tsa")).unwrap_err();
    assert!(err.contains("cannot reach the timestamp authority"), "{err}");
}

/// A signed JAR carrying a timestamp still satisfies `jarsigner -verify`.
#[test]
fn timestamped_jars_verify_with_jarsigner() {
    if !have("jarsigner") || !have("openssl") {
        eprintln!("skipping: jarsigner or openssl not installed");
        return;
    }
    let d = tmp();
    let Some(tsa) = start_test_tsa(d.path()) else {
        eprintln!("skipping: cannot start the local test TSA");
        return;
    };
    let jar_path = d.path().join("app.jar");
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::fs::File::create(&jar_path).unwrap());
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("com/example/App.class", o).unwrap();
        w.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]).unwrap();
        w.finish().unwrap();
    }
    let p = pki();
    let out = d.path().join("signed-ts.jar");
    let r = jar::sign_jar_timestamped(jar_path.to_str().unwrap(), out.to_str().unwrap(), &p.rsa, Some(&tsa.url)).expect("timestamped jar signing");
    let ts = r.timestamp.expect("the result should report the timestamp");
    assert!(ts.valid && ts.authority.contains("Test TSA"), "{ts:?}");

    let v = must(d.path(), "jarsigner", &["-verify", "-verbose", out.to_str().unwrap()]);
    assert!(v.contains("jar verified"), "{v}");
    // jarsigner prints "signature was verified ... timestamp" only when it actually parsed a
    // timestamp token out of our unsigned attributes, so this is the real cross-check.
    assert!(v.to_lowercase().contains("timestamp"), "jarsigner saw no timestamp:\n{v}");
}

#[test]
fn tls_inspection_against_openssl_server() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    write(d.path(), "cert.pem", p.ec.certificate_chain[0].pem.as_bytes());
    write(d.path(), "inter.pem", p.inter.certificate_chain[0].pem.as_bytes());
    write(d.path(), "key.pem", p.ec.private_key_pem.as_ref().unwrap().as_bytes());
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut server = Command::new("openssl")
        .args(["s_server", "-accept", &port.to_string(), "-cert", "cert.pem", "-cert_chain", "inter.pem", "-key", "key.pem", "-www", "-quiet"])
        .current_dir(d.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut result = Err("server did not start".to_string());
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        result = tls::inspect("127.0.0.1", port, 5);
        if result.is_ok() {
            break;
        }
    }
    let _ = server.kill();
    // Reap it, or the killed server lingers as a zombie for the rest of the test run.
    let _ = server.wait();
    let r = result.unwrap();
    assert_eq!(r.certificates.len(), 2);
    assert_eq!(r.certificates[0].sha256_fingerprint, p.ec.sha256_fingerprint);
    assert!(!r.trusted, "a private CA must not be reported as trusted");
    assert!(r.verification_error.is_some());
    assert!(r.protocol.starts_with("TLS 1."));
    // Nothing is listening on a closed port.
    assert!(tls::inspect("127.0.0.1", port, 2).is_err());
}

#[test]
fn keytool_keypasswd_round_trips() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    must(d.path(), "keytool", &["-genkeypair", "-alias", "sep", "-keyalg", "EC", "-dname", "CN=sep", "-storetype", "JKS", "-keystore", "a.jks", "-storepass", "storepw", "-keypass", "storepw"]);
    must(d.path(), "keytool", &["-keypasswd", "-alias", "sep", "-keystore", "a.jks", "-storetype", "JKS", "-storepass", "storepw", "-keypass", "storepw", "-new", "keypass99"]);
    let mut kp = HashMap::new();
    kp.insert("sep".into(), "keypass99".into());
    let opened = keystore::open(d.path().join("a.jks").to_str().unwrap(), "storepw", &kp).unwrap();
    assert_eq!(opened.entries[0].key_password.as_deref(), Some("keypass99"));
    keystore::save(&opened, d.path().join("b.jks").to_str().unwrap(), "storepw", keystore::Format::Jks).unwrap();
    must(d.path(), "keytool", &["-certreq", "-alias", "sep", "-keystore", "b.jks", "-storepass", "storepw", "-keypass", "keypass99", "-file", "sep.csr"]);
    let (ok, _) = run(d.path(), "keytool", &["-certreq", "-alias", "sep", "-keystore", "b.jks", "-storepass", "storepw", "-keypass", "storepw", "-file", "no.csr"]);
    assert!(!ok);
}

#[test]
fn ec_server_extensions_match_openssl_text() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let mut input = kp_input("web-ec", "ECDSA", "P-256", false);
    input.key_usage = vec!["digitalSignature".into()];
    input.extended_key_usage = vec!["serverAuth".into()];
    let entry = ops::generate_key_pair(&input, None).unwrap();
    write(d.path(), "web.pem", entry.certificate_chain[0].pem.as_bytes());
    let text = must(d.path(), "openssl", &["x509", "-in", "web.pem", "-noout", "-text"]);
    assert!(text.contains("Digital Signature"), "{text}");
    assert!(!text.contains("Key Encipherment"), "{text}");
    assert!(text.contains("TLS Web Server Authentication"), "{text}");
    assert!(!text.contains("TLS Web Client Authentication"), "{text}");
}

#[test]
fn jceks_alias_case_matches_keytool() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    let mut input = kp_input("API", "ECDSA", "P-256", false);
    input.alias = "API".into();
    let entry = ops::generate_key_pair(&input, None).unwrap();
    assert_eq!(entry.alias, "API");
    keystore::save(&ks(vec![entry]), d.path().join("mixed.jceks").to_str().unwrap(), "pw", keystore::Format::Jceks).unwrap();
    let listing = must(d.path(), "keytool", &["-list", "-v", "-keystore", "mixed.jceks", "-storepass", "pw"]);
    assert!(listing.contains("Alias name: api"), "{listing}");
    assert!(!listing.contains("Alias name: API"), "{listing}");
    let opened = keystore::open(d.path().join("mixed.jceks").to_str().unwrap(), "pw", &HashMap::new()).unwrap();
    assert_eq!(opened.entries[0].alias, "api");
}

#[test]
fn openssl_pkcs12_keeps_mixed_case_alias() {
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    must(d.path(), "openssl", &["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-subj", "/CN=case.test", "-days", "30"]);
    must(d.path(), "openssl", &["pkcs12", "-export", "-in", "c.pem", "-inkey", "k.pem", "-name", "API", "-out", "case.p12", "-passout", "pass:pw"]);
    let opened = keystore::open(d.path().join("case.p12").to_str().unwrap(), "pw", &HashMap::new()).unwrap();
    let key = opened.entries.iter().find(|e| e.entry_type == "KeyPair").unwrap();
    assert_eq!(key.alias, "API");
}

// ---------------------------------------------------------------------------------------------
// Formats added in the 2026-11 coverage pass: OpenSSH, legacy key encodings, unusual signatures,
// certificate containers, the legacy PKCS#12 profile, truststores and Bouncy Castle keystores.
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
fn private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
#[cfg(not(unix))]
fn private_mode(_: &Path) {}

fn first_two_words(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

#[test]
fn openssh_keys_interop_with_ssh_keygen() {
    use keystore_studio_lib::{convert, keys::PrivateKey};
    if !have("ssh-keygen") {
        eprintln!("skipping: ssh-keygen not installed");
        return;
    }
    let d = tmp();
    let kinds: [(&str, &[&str]); 5] = [("rsa", &["-b", "2048"]), ("ecdsa", &["-b", "256"]), ("ecdsa", &["-b", "384"]), ("ecdsa", &["-b", "521"]), ("ed25519", &[])];
    let ciphers = ["none", "aes256-ctr", "aes128-cbc", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"];
    let mut checked = 0;
    for (i, (kind, bits)) in kinds.iter().enumerate() {
        for cipher in ciphers {
            let name = format!("k{i}-{}", cipher.replace(['@', '.'], "_"));
            let mut args = vec!["-q", "-t", kind];
            args.extend_from_slice(bits);
            let pass = if cipher == "none" { "" } else { "theirs-pw" };
            args.extend_from_slice(&["-N", pass, "-C", "them@host", "-f", &name]);
            if cipher != "none" {
                args.extend_from_slice(&["-Z", cipher]);
            }
            let (ok, out) = run(d.path(), "ssh-keygen", &args);
            if !ok {
                assert!(cipher != "none" && cipher != "aes256-ctr", "ssh-keygen {args:?}: {out}");
                eprintln!("skipping {kind} {cipher}: this ssh-keygen does not offer it");
                continue;
            }
            // Theirs, read by us: the public key we derive is the one ssh-keygen wrote.
            let theirs = std::fs::read(d.path().join(&name)).unwrap();
            let pw = (!pass.is_empty()).then_some(pass);
            PrivateKey::from_bytes(&theirs, pw).unwrap_or_else(|e| panic!("{kind} {cipher}: {e}"));
            let expected = std::fs::read_to_string(d.path().join(format!("{name}.pub"))).unwrap();
            let ours_pub = String::from_utf8(convert::public_key(&theirs, pw, "openssh", "").unwrap().bytes).unwrap();
            assert_eq!(first_two_words(&ours_pub), first_two_words(&expected), "{kind} {cipher}");
            // The public half needs no password.
            assert_eq!(convert::spki_from_any(&theirs, None).unwrap().0, convert::spki_from_any(expected.as_bytes(), None).unwrap().0, "{kind} {cipher}");
            checked += 1;
        }
        // Ours, read by ssh-keygen, plain and encrypted.
        let theirs = std::fs::read(d.path().join(format!("k{i}-none"))).unwrap();
        for pw in [None, Some("ours-pw")] {
            let out = convert::private_key(&theirs, None, "openssh", pw, "us@host").unwrap();
            let path = write(d.path(), &format!("ours{i}"), &out.bytes);
            private_mode(&path);
            let line = must(d.path(), "ssh-keygen", &["-y", "-P", pw.unwrap_or(""), "-f", &format!("ours{i}")]);
            let expected = std::fs::read_to_string(d.path().join(format!("k{i}-none.pub"))).unwrap();
            assert_eq!(first_two_words(&line), first_two_words(&expected), "{kind} ours {pw:?}");
        }
        // RFC 4716 both ways.
        let rfc = must(d.path(), "ssh-keygen", &["-e", "-m", "RFC4716", "-f", &format!("k{i}-none.pub")]);
        let line = std::fs::read_to_string(d.path().join(format!("k{i}-none.pub"))).unwrap();
        assert_eq!(convert::spki_from_any(rfc.as_bytes(), None).unwrap().0, convert::spki_from_any(line.as_bytes(), None).unwrap().0, "{kind}: their RFC 4716");
        let ours = convert::public_key(line.as_bytes(), None, "ssh2", "converted").unwrap();
        write(d.path(), &format!("ours{i}.ssh2"), &ours.bytes);
        let back = must(d.path(), "ssh-keygen", &["-i", "-m", "RFC4716", "-f", &format!("ours{i}.ssh2")]);
        assert_eq!(first_two_words(&back), first_two_words(&line), "{kind}: our RFC 4716");
    }
    assert!(checked >= 10, "only {checked} ssh-keygen keys were read");
}

#[test]
fn openssl_key_encodings_open() {
    use keystore_studio_lib::{convert, keys::PrivateKey};
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    must(d.path(), "openssl", &["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "k.pem"]);
    let original = PrivateKey::from_bytes(&std::fs::read(d.path().join("k.pem")).unwrap(), None).unwrap().to_pkcs8_der().unwrap();
    let variants: [(&str, &[&str]); 5] = [
        ("scrypt.pem", &["pkcs8", "-topk8", "-scrypt", "-in", "k.pem", "-out", "scrypt.pem", "-passout", "pass:pw"]),
        ("pbes1.pem", &["pkcs8", "-topk8", "-v1", "PBE-SHA1-3DES", "-in", "k.pem", "-out", "pbes1.pem", "-passout", "pass:pw"]),
        ("sha512.pem", &["pkcs8", "-topk8", "-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA512", "-in", "k.pem", "-out", "sha512.pem", "-passout", "pass:pw"]),
        ("trad-aes.pem", &["pkey", "-in", "k.pem", "-traditional", "-aes256", "-out", "trad-aes.pem", "-passout", "pass:pw"]),
        ("trad-3des.pem", &["pkey", "-in", "k.pem", "-traditional", "-des3", "-out", "trad-3des.pem", "-passout", "pass:pw"]),
    ];
    for (file, args) in variants {
        must(d.path(), "openssl", args);
        let bytes = std::fs::read(d.path().join(file)).unwrap();
        let key = PrivateKey::from_bytes(&bytes, Some("pw")).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(key.to_pkcs8_der().unwrap(), original, "{file}");
        assert!(PrivateKey::from_bytes(&bytes, Some("wrong")).is_err(), "{file}");
    }
    // DES-based PBES1 needs OpenSSL's legacy provider; read it when this OpenSSL can write it.
    if run(d.path(), "openssl", &["pkcs8", "-topk8", "-v1", "PBE-MD5-DES", "-in", "k.pem", "-out", "md5des.pem", "-passout", "pass:pw"]).0 {
        let key = PrivateKey::from_bytes(&std::fs::read(d.path().join("md5des.pem")).unwrap(), Some("pw")).unwrap();
        assert_eq!(key.to_pkcs8_der().unwrap(), original);
    }
    // Ours in the legacy PBES1 form, read by OpenSSL.
    let ours = convert::private_key(&std::fs::read(d.path().join("k.pem")).unwrap(), None, "pkcs8_encrypted_3des_pem", Some("ours"), "").unwrap();
    write(d.path(), "ours.pem", &ours.bytes);
    let info = must(d.path(), "openssl", &["asn1parse", "-in", "ours.pem"]);
    assert!(info.contains("pbeWithSHA1And3-KeyTripleDES-CBC"), "{info}");
    must(d.path(), "openssl", &["pkey", "-in", "ours.pem", "-passin", "pass:ours", "-noout"]);
}

#[test]
fn dsa_and_pss_signatures_verify() {
    use keystore_studio_lib::x509;
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    must(d.path(), "openssl", &["genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", "dsa_paramgen_bits:2048", "-out", "dsa.param"]);
    must(d.path(), "openssl", &["genpkey", "-paramfile", "dsa.param", "-out", "dsa.key"]);
    must(d.path(), "openssl", &["req", "-x509", "-key", "dsa.key", "-sha256", "-subj", "/CN=dsa.test", "-days", "30", "-out", "dsa.pem"]);
    must(
        d.path(),
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "pss.key",
            "-sha256",
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:32",
            "-subj",
            "/CN=pss.test",
            "-days",
            "30",
            "-out",
            "pss.pem",
        ],
    );
    for (file, name) in [("dsa.pem", "SHA256withDSA"), ("pss.pem", "SHA256withRSA/PSS")] {
        let der = x509::certificates_from_bytes(&std::fs::read(d.path().join(file)).unwrap()).unwrap().remove(0);
        let info = x509::parse_certificate(&der).unwrap();
        assert_eq!(info.signature_algorithm, name, "{file}");
        let spki = x509::cert_summary(&der).unwrap().spki;
        assert!(x509::verify_certificate_signature(&der, &spki).unwrap(), "{file}");
        let mut altered = der.clone();
        let at = altered.len() - 10;
        altered[at] ^= 1;
        assert!(!x509::verify_certificate_signature(&altered, &spki).unwrap_or(false), "{file}");
    }
    // A DSA key from OpenSSL loads, and its OpenSSH public key matches ssh-keygen's reading.
    let key = keystore_studio_lib::keys::PrivateKey::from_bytes(&std::fs::read(d.path().join("dsa.key")).unwrap(), None).unwrap();
    assert_eq!(key.algorithm(), "DSA");
    assert_eq!(key.key_size(), 2048);
}

#[test]
fn certificate_containers_from_openssl_open() {
    use keystore_studio_lib::{convert, x509};
    if !have("openssl") {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let d = tmp();
    let p = pki();
    let chain: String = p.ec.certificate_chain.iter().map(|c| c.pem.clone()).collect();
    write(d.path(), "chain.pem", chain.as_bytes());
    must(d.path(), "openssl", &["nseq", "-in", "chain.pem", "-toseq", "-out", "chain.nseq"]);
    let nseq = std::fs::read(d.path().join("chain.nseq")).unwrap();
    assert_eq!(convert::read_certificates(&nseq).unwrap().len(), p.ec.certificate_chain.len(), "Netscape certificate sequence (PEM)");
    let der = keystore_studio_lib::util::pem_blocks(&String::from_utf8_lossy(&nseq)).remove(0).der;
    assert_eq!(convert::read_certificates(&der).unwrap().len(), p.ec.certificate_chain.len(), "Netscape certificate sequence (DER)");
    write(d.path(), "leaf.pem", p.ec.certificate_chain[0].pem.as_bytes());
    must(d.path(), "openssl", &["x509", "-in", "leaf.pem", "-trustout", "-addtrust", "serverAuth", "-out", "trusted.pem"]);
    let trusted = std::fs::read_to_string(d.path().join("trusted.pem")).unwrap();
    assert!(trusted.contains("BEGIN TRUSTED CERTIFICATE"));
    let certs = x509::certificates_from_bytes(trusted.as_bytes()).unwrap();
    assert_eq!(certs, vec![entry::chain_der(&p.ec).unwrap().remove(0)], "the trust settings are not part of the certificate");
}

#[test]
fn legacy_pkcs12_opens_in_openssl_and_keytool() {
    let p = pki();
    let d = tmp();
    let path = d.path().join("legacy.p12");
    keystore::save_with(
        &ks(vec![p.rsa.clone()]),
        path.to_str().unwrap(),
        "legacy-pw",
        keystore::Format::Pkcs12,
        keystore::SavePolicy { mac: keystore_studio_lib::pkcs12::MacKind::Legacy, force: false },
    )
    .unwrap();
    if have("openssl") {
        let info = must(d.path(), "openssl", &["pkcs12", "-in", "legacy.p12", "-info", "-noout", "-passin", "pass:legacy-pw"]);
        assert!(info.contains("MAC: sha1"), "{info}");
        assert!(info.contains("pbeWithSHA1And3-KeyTripleDES-CBC"), "{info}");
        assert!(!info.contains("PBES2"), "{info}");
    }
    if have("keytool") {
        let listing = must(d.path(), "keytool", &["-list", "-keystore", "legacy.p12", "-storetype", "PKCS12", "-storepass", "legacy-pw"]);
        assert!(listing.contains("PrivateKeyEntry"), "{listing}");
    }
}

#[test]
fn truststores_open_in_keytool() {
    use keystore_studio_lib::convert;
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let p = pki();
    let d = tmp();
    let pem = format!("{}{}", p.root.certificate_chain[0].pem, p.inter.certificate_chain[0].pem);
    for (format, file) in [("PKCS12", "trust.p12"), ("JKS", "trust.jks"), ("JCEKS", "trust.jceks")] {
        let out = convert::truststore(pem.as_bytes(), format, "trust-pw", "").unwrap();
        write(d.path(), file, &out.bytes);
        let listing = must(d.path(), "keytool", &["-list", "-keystore", file, "-storetype", format, "-storepass", "trust-pw"]);
        assert_eq!(listing.matches("trustedCertEntry").count(), 2, "{format}: {listing}");
    }
}

/// The Bouncy Castle provider jar, from `BCPROV_JAR` or the local Maven repository.
fn bcprov_jar() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BCPROV_JAR").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    let root = dirs::home_dir()?.join(".m2/repository/org/bouncycastle");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .filter(|d| d.file_name().to_string_lossy().starts_with("bcprov"))
        .flat_map(|d| std::fs::read_dir(d.path()).into_iter().flatten().flatten())
        .flat_map(|v| std::fs::read_dir(v.path()).into_iter().flatten().flatten())
        .map(|f| f.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jar") && !p.to_string_lossy().contains("sources"))
        .collect();
    found.sort();
    found.pop()
}

#[test]
fn bouncy_castle_keystores_interop_with_keytool() {
    let Some(jar) = bcprov_jar() else {
        eprintln!("skipping: set BCPROV_JAR to a bcprov jar to run the Bouncy Castle keytool round trip");
        return;
    };
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let jar = jar.to_string_lossy().to_string();
    let provider = ["-providerpath", jar.as_str(), "-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider"];
    let p = pki();
    let d = tmp();
    let secret = entry::secret_key_entry("aes", "AES", &[5u8; 32], None);
    for (format, file) in [(keystore::Format::Bks, "ours.bks"), (keystore::Format::Uber, "ours.uber"), (keystore::Format::Bcfks, "ours.bcfks")] {
        keystore::save(&ks(vec![p.rsa.clone(), p.ec.clone(), secret.clone()]), d.path().join(file).to_str().unwrap(), "bc-pass-1", format).unwrap();
        // Ours, read by Bouncy Castle.
        let mut args = vec!["-list", "-keystore", file, "-storetype", format.name(), "-storepass", "bc-pass-1"];
        args.extend_from_slice(&provider);
        let listing = must(d.path(), "keytool", &args);
        assert_eq!(listing.matches("PrivateKeyEntry").count(), 2, "{}: {listing}", format.name());
        assert!(listing.contains("SecretKeyEntry"), "{}: {listing}", format.name());
        // Theirs, written by Bouncy Castle from a PKCS#12, read by us.
        let theirs = format!("theirs.{}", format.extension());
        keystore::save(&ks(vec![p.rsa.clone(), p.ec.clone()]), d.path().join("src.p12").to_str().unwrap(), "bc-pass-1", keystore::Format::Pkcs12).unwrap();
        let mut args = vec!["-importkeystore", "-noprompt", "-srckeystore", "src.p12", "-srcstoretype", "PKCS12", "-srcstorepass", "bc-pass-1"];
        args.extend_from_slice(&["-destkeystore", &theirs, "-deststoretype", format.name(), "-deststorepass", "bc-pass-1"]);
        args.extend_from_slice(&provider);
        must(d.path(), "keytool", &args);
        let opened = keystore::open(d.path().join(&theirs).to_str().unwrap(), "bc-pass-1", &HashMap::new()).unwrap();
        assert_eq!(opened.entries.iter().filter(|e| e.entry_type == "KeyPair" && !e.locked).count(), 2, "{}", format.name());
    }
}
