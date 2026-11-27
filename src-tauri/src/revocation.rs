//! Revocation checking for a validated chain: each certificate below the trust anchor is checked
//! against its issuer, by OCSP (RFC 6960) when it names a responder and by its CRL distribution
//! point (RFC 5280 §4.2.1.13) otherwise, or when the responder cannot be reached.
//!
//! It is opt-in. Keystore Studio works offline by default, and checking revocation sends the
//! certificate's serial number (OCSP) or the fact that it is in use (CRL fetch) to the CA.
//!
//! The network calls are passed in, so the decisions here are tested without a network.

use crate::model::OcspInfo;
use crate::util::{Res, fmt_ts, now_ts, upper_hex};
use crate::x509;
use std::time::Duration;
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

/// Largest CRL fetched. Public CA CRLs reach a few MB; this leaves room without unbounded reads.
const MAX_CRL_BYTES: u64 = 16 * 1024 * 1024;

/// How each certificate's status was settled, for the problems list.
#[derive(Debug, PartialEq, Eq)]
enum Status {
    Good,
    Revoked(String),
    /// No method gave an answer; the reasons, one per method tried.
    Unknown(Vec<String>),
}

/// Asks the OCSP responder at the URL about (certificate, issuer).
pub type OcspFetch<'a> = dyn Fn(&str, &[u8], &[u8]) -> Res<OcspInfo> + 'a;
/// Downloads the CRL at the URL.
pub type CrlFetch<'a> = dyn Fn(&str) -> Res<Vec<u8>> + 'a;

/// The network side, replaceable in tests.
pub struct Fetchers<'a> {
    pub ocsp: &'a OcspFetch<'a>,
    pub crl: &'a CrlFetch<'a>,
}

/// The real network: the OCSP client in `ocsp.rs`, and a plain HTTP GET for CRLs.
pub fn network() -> Fetchers<'static> {
    Fetchers { ocsp: &|url, subject, issuer| ocsp::check_info(url, subject, issuer), crl: &fetch_crl }
}

mod ocsp {
    pub fn check_info(url: &str, subject: &[u8], issuer: &[u8]) -> crate::util::Res<crate::model::OcspInfo> {
        crate::ocsp::check(url, subject, issuer).map(|r| r.info())
    }
}

fn fetch_crl(url: &str) -> Res<Vec<u8>> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!("'{url}' is not an http:// or https:// URL (LDAP distribution points are not fetched)"));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(20))).user_agent(concat!("keystore-studio/", env!("CARGO_PKG_VERSION"))).build().into();
    let mut response = agent.get(url).call().map_err(|err| format!("cannot download the CRL from {url}: {err}"))?;
    response.body_mut().with_config().limit(MAX_CRL_BYTES).read_to_vec().map_err(|err| format!("cannot read the CRL from {url}: {err}"))
}

/// Revocation problems for `path` (leaf first, as [`x509::validate_chain_path`] returns it). The
/// last certificate is not checked when it is self-signed: a trust anchor is trusted as configured.
pub fn check_path(path: &[Vec<u8>], fetch: &Fetchers) -> Vec<String> {
    let mut problems = Vec::new();
    for pair in path.windows(2) {
        let (cert, issuer) = (&pair[0], &pair[1]);
        let subject = x509::parse_certificate(cert).map(|c| c.subject).unwrap_or_else(|_| "a certificate".into());
        match status_of(cert, issuer, fetch, now_ts()) {
            Status::Good => {}
            Status::Revoked(detail) => problems.push(format!("{subject} has been revoked{detail}")),
            Status::Unknown(why) => problems.push(format!("the revocation status of {subject} could not be checked: {}", why.join("; "))),
        }
    }
    if path.len() == 1 {
        problems.push("revocation was not checked: the issuer of the certificate is not among the supplied certificates".into());
    }
    problems
}

fn status_of(cert: &[u8], issuer: &[u8], fetch: &Fetchers, now: i64) -> Status {
    let Ok(info) = x509::parse_certificate(cert) else { return Status::Unknown(vec!["the certificate could not be parsed".into()]) };
    let mut why = Vec::new();
    for url in &info.ocsp_urls {
        match (fetch.ocsp)(url, cert, issuer) {
            Ok(r) if !r.signature_valid => why.push(format!("the OCSP response from {url} is not signed by the issuer ({})", r.signature_warning.unwrap_or_default())),
            Ok(r) if r.status == "good" => return Status::Good,
            Ok(r) if r.status == "revoked" => {
                let when = r.revocation_time.map(|t| format!(" on {t}")).unwrap_or_default();
                let reason = r.revocation_reason.map(|t| format!(" ({t})")).unwrap_or_default();
                return Status::Revoked(format!("{when}{reason}, according to the OCSP responder at {url}"));
            }
            Ok(_) => why.push(format!("the OCSP responder at {url} does not know this certificate")),
            Err(err) => why.push(err),
        }
    }
    for url in &info.crl_distribution_points {
        match (fetch.crl)(url).and_then(|der| crl_status(cert, issuer, &der, now)) {
            Ok(Status::Unknown(mut w)) => why.append(&mut w),
            Ok(status) => return status,
            Err(err) => why.push(err),
        }
    }
    if info.ocsp_urls.is_empty() && info.crl_distribution_points.is_empty() {
        why.push("it names neither an OCSP responder nor a CRL distribution point".into());
    }
    Status::Unknown(why)
}

/// One method's answer about one certificate, for the Verify panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodResult {
    /// "ocsp" or "crl".
    pub method: &'static str,
    pub url: String,
    /// "good", "revoked" or "unknown".
    pub status: &'static str,
    /// Why the answer is "unknown", or when and why the certificate was revoked.
    pub detail: Option<String>,
}

/// Asks every responder and distribution point `cert` names, each on its own, so the caller can
/// show what each one said. `methods` limits the methods tried ("ocsp", "crl").
pub fn check_each(cert: &[u8], issuer: &[u8], methods: &[&str], fetch: &Fetchers) -> Res<Vec<MethodResult>> {
    let info = x509::parse_certificate(cert)?;
    let mut out = Vec::new();
    if methods.contains(&"ocsp") {
        for url in &info.ocsp_urls {
            let r = match (fetch.ocsp)(url, cert, issuer) {
                Ok(r) if !r.signature_valid => MethodResult { method: "ocsp", url: url.clone(), status: "unknown", detail: Some(format!("the response is not signed by the issuer ({})", r.signature_warning.unwrap_or_default())) },
                Ok(r) if r.status == "good" => MethodResult { method: "ocsp", url: url.clone(), status: "good", detail: None },
                Ok(r) if r.status == "revoked" => {
                    let when = r.revocation_time.map(|t| format!("on {t}")).unwrap_or_default();
                    let reason = r.revocation_reason.map(|t| format!(" ({t})")).unwrap_or_default();
                    MethodResult { method: "ocsp", url: url.clone(), status: "revoked", detail: Some(format!("{when}{reason}").trim().to_string()).filter(|d| !d.is_empty()) }
                }
                Ok(_) => MethodResult { method: "ocsp", url: url.clone(), status: "unknown", detail: Some("the responder does not know this certificate".into()) },
                Err(err) => MethodResult { method: "ocsp", url: url.clone(), status: "unknown", detail: Some(err) },
            };
            out.push(r);
        }
    }
    if methods.contains(&"crl") {
        for url in &info.crl_distribution_points {
            let r = match (fetch.crl)(url).and_then(|der| crl_status(cert, issuer, &der, now_ts())) {
                Ok(Status::Good) => MethodResult { method: "crl", url: url.clone(), status: "good", detail: None },
                Ok(Status::Revoked(d)) => MethodResult { method: "crl", url: url.clone(), status: "revoked", detail: Some(d.trim().trim_end_matches(", according to its CRL").to_string()) },
                Ok(Status::Unknown(w)) => MethodResult { method: "crl", url: url.clone(), status: "unknown", detail: Some(w.join("; ")) },
                Err(err) => MethodResult { method: "crl", url: url.clone(), status: "unknown", detail: Some(err) },
            };
            out.push(r);
        }
    }
    Ok(out)
}

/// What a CRL says about `cert`, after checking that `issuer` signed it and that it is current.
fn crl_status(cert: &[u8], issuer: &[u8], crl_der: &[u8], now: i64) -> Res<Status> {
    // A CRL may also be served as PEM.
    let crl_der = if crate::util::looks_textual(crl_der) {
        crate::util::pem_blocks(&String::from_utf8_lossy(crl_der)).into_iter().find(|b| b.tag.contains("CRL")).map(|b| b.der).ok_or("the downloaded file is not a CRL")?
    } else {
        crl_der.to_vec()
    };
    let issuer_spki = x509::cert_summary(issuer)?.spki;
    let info = x509::parse_crl(&crl_der, Some(&issuer_spki))?;
    if info.signature_valid != Some(true) {
        return Ok(Status::Unknown(vec![format!("the CRL is not signed by {}", info.issuer)]));
    }
    let (_, crl) = CertificateRevocationList::from_der(&crl_der).map_err(|err| format!("not a valid X.509 CRL: {err}"))?;
    if let Some(next) = crl.next_update().map(|t| t.timestamp())
        && next < now
    {
        return Ok(Status::Unknown(vec![format!("the CRL from {} is out of date (its next update was due {})", info.issuer, fmt_ts(next))]));
    }
    let (_, parsed) = X509Certificate::from_der(cert).map_err(|err| format!("invalid certificate: {err}"))?;
    let serial = upper_hex(parsed.raw_serial());
    Ok(match info.revoked_entries.iter().find(|r| r.serial_number.trim_start_matches('0') == serial.trim_start_matches('0')) {
        Some(r) => Status::Revoked(format!(" on {}{}, according to its CRL", r.revocation_date, if r.reason.is_empty() { String::new() } else { format!(" ({})", r.reason) })),
        None => Status::Good,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;
    use crate::model::RevokedCertEntry;
    use crate::util::random_serial;
    use crate::x509::*;

    struct Pki {
        ca_key: PrivateKey,
        ca: Vec<u8>,
        leaf: Vec<u8>,
        serial_hex: String,
    }

    fn pki(ocsp: bool, crl: bool) -> Pki {
        let now = now_ts();
        let ca_key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let ca = build_certificate(
            CertTemplate {
                serial: random_serial(),
                subject_der: encode_dn(&parse_dn("CN=Revocation Root").unwrap()),
                not_before: now - 60,
                not_after: now + 86_400 * 30,
                spki_der: ca_key.public_key_der().unwrap(),
                extensions: vec![ext_basic_constraints(true, None), ext_key_usage(&["keyCertSign".into(), "cRLSign".into()]).unwrap().unwrap()],
            },
            &Signer { key: &ca_key, cert_der: None, sig_alg: ca_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let leaf_key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let mut extensions = vec![ext_basic_constraints(false, None)];
        if crl {
            extensions.push(ext_crl_distribution_points(&["http://crl.test/root.crl".into()]).unwrap());
        }
        if ocsp {
            extensions.push(ext_authority_info_access(&["http://ocsp.test".into()], &[]).unwrap());
        }
        let serial = random_serial();
        let leaf = build_certificate(
            CertTemplate {
                serial: serial.clone(),
                subject_der: encode_dn(&parse_dn("CN=leaf.test").unwrap()),
                not_before: now - 60,
                not_after: now + 86_400,
                spki_der: leaf_key.public_key_der().unwrap(),
                extensions,
            },
            &Signer { key: &ca_key, cert_der: Some(&ca), sig_alg: ca_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let (_, parsed) = X509Certificate::from_der(&leaf).unwrap();
        let serial_hex = upper_hex(parsed.raw_serial());
        Pki { ca_key, ca, leaf, serial_hex }
    }

    fn crl(p: &Pki, key: &PrivateKey, revoked: &[&str], next_update: i64) -> Vec<u8> {
        let entries: Vec<RevokedCertEntry> = revoked.iter().map(|s| RevokedCertEntry { serial_number: s.to_string(), revocation_date: "2026-01-02".into(), reason: "keyCompromise".into() }).collect();
        let now = now_ts();
        build_crl(&Signer { key, cert_der: Some(&p.ca), sig_alg: key.default_sig_alg(None).unwrap() }, now - 3600, next_update, 1, &entries).unwrap()
    }

    fn no_ocsp(_: &str, _: &[u8], _: &[u8]) -> Res<OcspInfo> {
        Err("unreachable".into())
    }

    fn ocsp_says(status: &'static str, signed: bool) -> impl Fn(&str, &[u8], &[u8]) -> Res<OcspInfo> {
        move |url, _, _| {
            Ok(OcspInfo {
                status: status.into(),
                responder: "test".into(),
                produced_at: String::new(),
                this_update: String::new(),
                next_update: None,
                revocation_time: (status == "revoked").then(|| "2026-01-02 00:00:00 UTC".into()),
                revocation_reason: (status == "revoked").then(|| "keyCompromise".into()),
                signature_valid: signed,
                signature_warning: (!signed).then(|| "bad signature".into()),
                url: url.into(),
            })
        }
    }

    #[test]
    fn a_crl_listing_the_serial_revokes_the_certificate() {
        let p = pki(false, true);
        let good = crl(&p, &p.ca_key, &["0A0B"], now_ts() + 86_400);
        let bad = crl(&p, &p.ca_key, &[&p.serial_hex], now_ts() + 86_400);
        let path = vec![p.leaf.clone(), p.ca.clone()];

        let ok = |_: &str| Ok(good.clone());
        assert!(check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &ok }).is_empty());

        let revoked = |_: &str| Ok(bad.clone());
        let problems = check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &revoked });
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("CN=leaf.test has been revoked") && problems[0].contains("keyCompromise"), "{problems:?}");

        // The same CRL as PEM is read too.
        let pem = crate::util::to_pem("X509 CRL", &bad);
        let as_pem = |_: &str| Ok(pem.clone().into_bytes());
        assert!(check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &as_pem })[0].contains("revoked"));
    }

    #[test]
    fn a_crl_from_another_key_or_past_its_next_update_settles_nothing() {
        let p = pki(false, true);
        let path = vec![p.leaf.clone(), p.ca.clone()];
        let other = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let forged = crl(&p, &other, &[], now_ts() + 86_400);
        let forged_fetch = |_: &str| Ok(forged.clone());
        let problems = check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &forged_fetch });
        assert!(problems[0].contains("could not be checked") && problems[0].contains("not signed by"), "{problems:?}");

        let stale = crl(&p, &p.ca_key, &[], now_ts() - 60);
        let stale_fetch = |_: &str| Ok(stale.clone());
        let problems = check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &stale_fetch });
        assert!(problems[0].contains("out of date"), "{problems:?}");
    }

    #[test]
    fn ocsp_answers_first_and_an_unreachable_responder_falls_back_to_the_crl() {
        let p = pki(true, true);
        let path = vec![p.leaf.clone(), p.ca.clone()];
        let revoked_crl = crl(&p, &p.ca_key, &[&p.serial_hex], now_ts() + 86_400);
        let crl_fetch = |_: &str| Ok(revoked_crl.clone());
        let never = |_: &str| -> Res<Vec<u8>> { panic!("the CRL must not be fetched once OCSP answered") };

        assert!(check_path(&path, &Fetchers { ocsp: &ocsp_says("good", true), crl: &never }).is_empty());
        let problems = check_path(&path, &Fetchers { ocsp: &ocsp_says("revoked", true), crl: &never });
        assert!(problems[0].contains("revoked on 2026-01-02") && problems[0].contains("OCSP"), "{problems:?}");
        // A response the issuer did not sign is not believed; the CRL decides.
        let problems = check_path(&path, &Fetchers { ocsp: &ocsp_says("good", false), crl: &crl_fetch });
        assert!(problems[0].contains("has been revoked") && problems[0].contains("CRL"), "{problems:?}");
        // Unreachable responder: the CRL decides.
        let problems = check_path(&path, &Fetchers { ocsp: &no_ocsp, crl: &crl_fetch });
        assert!(problems[0].contains("according to its CRL"), "{problems:?}");
    }

    #[test]
    fn each_method_reports_on_its_own() {
        let p = pki(true, true);
        let revoked_crl = crl(&p, &p.ca_key, &[&p.serial_hex], now_ts() + 86_400);
        let crl_fetch = |_: &str| Ok(revoked_crl.clone());
        let both = check_each(&p.leaf, &p.ca, &["ocsp", "crl"], &Fetchers { ocsp: &ocsp_says("good", true), crl: &crl_fetch }).unwrap();
        assert_eq!(both.iter().map(|r| (r.method, r.status)).collect::<Vec<_>>(), vec![("ocsp", "good"), ("crl", "revoked")]);
        let only_crl = check_each(&p.leaf, &p.ca, &["crl"], &Fetchers { ocsp: &ocsp_says("good", true), crl: &crl_fetch }).unwrap();
        assert_eq!(only_crl.len(), 1);
        assert!(only_crl[0].detail.as_deref().is_some_and(|d| d.starts_with("on ")), "{:?}", only_crl[0].detail);
        let unreachable = check_each(&p.leaf, &p.ca, &["ocsp"], &Fetchers { ocsp: &no_ocsp, crl: &crl_fetch }).unwrap();
        assert_eq!(unreachable[0].status, "unknown");
    }

    #[test]
    fn nothing_to_check_is_reported_not_passed() {
        let p = pki(false, false);
        let unused = |_: &str| -> Res<Vec<u8>> { unreachable!() };
        let problems = check_path(&[p.leaf.clone(), p.ca.clone()], &Fetchers { ocsp: &no_ocsp, crl: &unused });
        assert!(problems[0].contains("neither an OCSP responder nor a CRL distribution point"), "{problems:?}");
        // A chain that never found the issuer cannot be checked at all.
        assert!(check_path(std::slice::from_ref(&p.leaf), &Fetchers { ocsp: &no_ocsp, crl: &unused })[0].contains("not checked"));
    }

    /// Live: a public site's chain, checked over the network. `cargo test -- --ignored live_`.
    #[test]
    #[ignore]
    fn live_public_chain_is_not_revoked() {
        for host in ["www.google.com", "github.com"] {
            let tls = crate::tls::inspect(host, 443, 10).unwrap();
            let ders: Vec<Vec<u8>> = tls.certificates.iter().map(|c| crate::x509::certificates_from_bytes(c.pem.as_bytes()).unwrap().remove(0)).collect();
            let anchors = crate::x509::certificates_from_bytes(crate::tls::system_trust_anchors_pem().as_bytes()).unwrap();
            let (problems, path) = validate_chain_path(&ders[0], &ders[1..], &anchors, Some(host));
            assert!(problems.is_empty(), "{host}: {problems:?}");
            let revoked = check_path(&path, &network());
            assert!(revoked.is_empty(), "{host}: {revoked:?}");
        }
    }

    #[test]
    fn crl_urls_must_be_http() {
        assert!(fetch_crl("ldap://ldap.example/cn=crl").unwrap_err().contains("LDAP"));
    }
}
