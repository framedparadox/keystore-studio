//! Interoperability tests against the real tools users pair xkeystore with: Java `keytool` /
//! `jarsigner` and `openssl`. Each test is skipped (with a message) if the tool is missing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use xkeystore_lib::model::*;
use xkeystore_lib::{cms, dh, entry, export, jar, jwt, keystore, ops, tls};

fn have(tool: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {tool}")).output().map(|o| o.status.success()).unwrap_or(false)
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
        subject_dn: format!("CN={alias}.example.test, OU=Interop, O=xkeystore, C=US"),
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
fn keytool_keystores_open_in_xkeystore() {
    if !have("keytool") {
        eprintln!("skipping: keytool not installed");
        return;
    }
    let d = tmp();
    let k = |args: &[&str]| must(d.path(), "keytool", args);
    for (t, f) in [("PKCS12", "k.p12"), ("JKS", "k.jks"), ("JCEKS", "k.jceks")] {
        k(&["-genkeypair", "-alias", "rsa", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=rsa, O=keytool", "-storetype", t, "-keystore", f, "-storepass", "changeit", "-keypass", "changeit"]);
        k(&["-genkeypair", "-alias", "ec", "-keyalg", "EC", "-groupname", "secp384r1", "-dname", "CN=ec", "-storetype", t, "-keystore", f, "-storepass", "changeit", "-keypass", "changeit"]);
        k(&["-exportcert", "-alias", "rsa", "-keystore", f, "-storepass", "changeit", "-file", &format!("{f}.cer")]);
        k(&["-importcert", "-noprompt", "-alias", "trusted", "-file", &format!("{f}.cer"), "-keystore", f, "-storepass", "changeit"]);
        if t != "JKS" {
            k(&["-genseckey", "-alias", "aes", "-keyalg", "AES", "-keysize", "256", "-storetype", t, "-keystore", f, "-storepass", "changeit", "-keypass", "changeit"]);
        }
        let opened = keystore::open(d.path().join(f).to_str().unwrap(), "changeit", &HashMap::new()).unwrap();
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
        assert!(keystore::open(d.path().join(f).to_str().unwrap(), "bad", &HashMap::new()).is_err());

        // Round trip through our writer and back into keytool.
        let out = format!("re-{f}");
        keystore::save(&opened, d.path().join(&out).to_str().unwrap(), "newpass", keystore::Format::parse(t).unwrap()).unwrap();
        let listing = must(d.path(), "keytool", &["-list", "-keystore", &out, "-storepass", "newpass"]);
        assert!(listing.contains(&format!("contains {} entr", opened.entries.len())), "{listing}");
    }

    // Separate key password in JKS: entry loads locked, unlocks with the key password, and
    // survives a re-save untouched.
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
    must(d.path(), "openssl", &["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "req.key", "-out", "req.csr", "-subj", "/CN=from-openssl.test/O=Req", "-addext", "subjectAltName=DNS:from-openssl.test"]);
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
fn keytool_ca_workflow_with_xkeystore_ca() {
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
        write(d.path(), "att.pem", xkeystore_lib::util::to_pem("CMS", &attached).as_bytes());
        let out = must(d.path(), "openssl", &["cms", "-verify", "-in", "att.pem", "-inform", "PEM", "-noverify", "-binary"]);
        assert!(out.contains("interop payload") && out.contains("Verification successful"), "{} {out}", e.alias);
        let detached = cms::sign(b"interop payload\n", &key, &chain, true).unwrap();
        write(d.path(), "det.der", &detached);
        let out = must(d.path(), "openssl", &["cms", "-verify", "-in", "det.der", "-inform", "DER", "-content", "data.txt", "-noverify", "-binary", "-out", "/dev/null"]);
        assert!(out.contains("Verification successful"), "{out}");
        // Tampered content fails in OpenSSL.
        write(d.path(), "bad.txt", b"interop payloaD\n");
        let (ok, _) = run(d.path(), "openssl", &["cms", "-verify", "-in", "det.der", "-inform", "DER", "-content", "bad.txt", "-noverify", "-binary", "-out", "/dev/null"]);
        assert!(!ok);
    }
    // OpenSSL-produced signatures verify in xkeystore.
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
        assert!(out.trim() == e.public_key_pem.as_ref().unwrap().trim(), "{out}");
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
    }
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
    let r = result.unwrap();
    assert_eq!(r.certificates.len(), 2);
    assert_eq!(r.certificates[0].sha256_fingerprint, p.ec.sha256_fingerprint);
    assert!(!r.trusted, "a private CA must not be reported as trusted");
    assert!(r.verification_error.is_some());
    assert!(r.protocol.starts_with("TLS 1."));
    // Nothing is listening on a closed port.
    assert!(tls::inspect("127.0.0.1", port, 2).is_err());
}
