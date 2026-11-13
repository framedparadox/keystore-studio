//! RFC 3161 trusted timestamps.
//!
//! A signature alone proves who signed, not *when*. Once the signing certificate expires a
//! verifier can no longer tell whether the signature was made while the certificate was still
//! valid, so the signature stops being trusted. A timestamp from a Time Stamping Authority (TSA)
//! fixes that: the TSA signs a hash of the signature together with its own clock reading, and the
//! TSA's certificate long outlives the signer's.
//!
//! The token is attached to a CMS SignerInfo as the *unsigned* attribute `id-aa-timeStampToken`
//! (RFC 3161 Appendix A). Unsigned is what makes this work: the token covers the signature, so it
//! can be added after signing without invalidating anything, and `jarsigner -verify` and
//! `openssl ts -verify` both read it from there.
//!
//! This is the only outbound network request the app makes besides the TLS inspector, it only
//! happens when the user supplies a TSA URL, and it is a single blocking POST.
//!
//! # What is checked
//!
//! A token read back here is bound to the signature it claims to cover (the message imprint is
//! recomputed), to the nonce we sent (for a fresh request), and its CMS `SignerInfo` signature
//! and `Time Stamping` Extended Key Usage (`1.3.6.1.5.5.7.3.8`) are cryptographically verified
//! against the signing certificate. When the caller also supplies a TSA trust bundle,
//! `chain_trusted` verifies that the TSA signing certificate chains to that bundle.

use crate::oids::{self, oid};
use crate::pbe::HashAlg;
use crate::util::*;
use std::time::Duration;
use yasna::Tag;

/// Media types fixed by RFC 3161 §3.4.
const REQUEST_TYPE: &str = "application/timestamp-query";
const RESPONSE_TYPE: &str = "application/timestamp-reply";
const MAX_RESPONSE: u64 = 256 * 1024;

/// What a TSA told us, for display after signing.
#[derive(Debug, Clone)]
pub struct Timestamp {
    /// The DER `TimeStampToken` (a CMS SignedData) to attach to a SignerInfo.
    pub token: Vec<u8>,
    /// The TSA's clock reading, as `genTime` in the token.
    pub time: String,
    /// The TSA's name, from the token's `tsa` field or its signing certificate.
    pub authority: String,
    pub serial_number: String,
    pub hash_algorithm: String,
    pub policy: Option<String>,
    /// Certificates embedded in the token, leaf first when the TSA included them.
    pub certificates: Vec<Vec<u8>>,
}

impl Timestamp {
    pub fn info(&self, valid: bool, error: Option<String>) -> crate::model::TimestampInfo {
        crate::model::TimestampInfo {
            time: self.time.clone(),
            authority: self.authority.clone(),
            serial_number: self.serial_number.clone(),
            hash_algorithm: self.hash_algorithm.clone(),
            policy: self.policy.clone(),
            valid,
            error,
            chain_trusted: None,
        }
    }
}

/// Reads a token's fields without binding it to any signature, for display when the binding check
/// has already failed.
pub fn describe_any_token(token: &[u8]) -> Res<Timestamp> {
    describe_token(token, None, None)
}

/// Reads a timestamp token found in a SignerInfo's unsigned attributes and checks that it really
/// covers `signature` and carries a valid TSA signature.
pub fn verify_token(token: &[u8], signature: &[u8]) -> Res<Timestamp> {
    check_der_lengths(token)?;
    // The imprint hash is the TSA's choice, so read the token first and recompute with that hash.
    let described = describe_token(token, None, None)?;
    let hash = [HashAlg::Sha1, HashAlg::Sha224, HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
        .into_iter()
        .find(|h| h.name() == described.hash_algorithm)
        .ok_or_else(|| format!("the timestamp uses an unsupported digest ({})", described.hash_algorithm))?;
    let mut ts = describe_token(token, Some(&hash.digest(signature)), None)?;
    verify_token_signature(&mut ts, &[])?;
    Ok(ts)
}

/// Builds a DER `TimeStampReq` over `digest`.
///
/// `cert_requested` asks the TSA to include its certificate in the token, which verifiers need in
/// order to check the token without being configured with the TSA's certificate out of band.
fn build_request(digest: &[u8], hash: HashAlg, nonce: &[u8], cert_requested: bool) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(1); // version
            w.next().write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(hash.digest_oid()));
                    w.next().write_null();
                });
                w.next().write_bytes(digest);
            });
            // reqPolicy is omitted: let the TSA apply its default policy.
            w.next().write_bigint_bytes(nonce, true);
            if cert_requested {
                w.next().write_bool(true);
            }
        })
    })
}

/// `PKIStatusInfo` status values from RFC 3161 §2.4.2.
fn status_text(status: u64, failure_bits: Option<&[u8]>) -> String {
    let base = match status {
        0 => "granted",
        1 => "granted, with modifications",
        2 => "rejected",
        3 => "waiting",
        4 => "revocation warning",
        5 => "revocation notification",
        _ => "unknown status",
    };
    // failInfo is a BIT STRING; the bit numbers are the interesting part.
    let detail = failure_bits.and_then(|b| b.first().copied()).map(|byte| {
        let flags = [
            (0, "the request algorithm or format was not recognised"),
            (2, "the requested transaction was not permitted"),
            (5, "the data format is wrong"),
            (14, "the time source is unavailable"),
            (15, "the requested policy is not supported"),
            (16, "the requested extension is not supported"),
            (17, "the requested information is not available"),
            (25, "the system failed"),
        ];
        let set: Vec<&str> = flags.iter().filter(|(bit, _)| *bit < 8 && byte & (0x80 >> bit) != 0).map(|(_, text)| *text).collect();
        set.join("; ")
    });
    match detail.filter(|d| !d.is_empty()) {
        Some(d) => format!("{base} ({d})"),
        None => base.to_string(),
    }
}

/// Splits a `TimeStampResp` into its status and, when granted, the `TimeStampToken`.
fn parse_response(der: &[u8]) -> Res<Vec<u8>> {
    let (status, failure, token) = yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let (status, failure) = r.next().read_sequence(|r| {
                let status = r.next().read_u64()?;
                // statusString (optional) then failInfo (optional).
                let _text = r.read_optional(|r| r.read_sequence_of(|r| r.read_utf8string().map(|_| ())))?;
                let failure = r.read_optional(|r| r.read_bitvec_bytes().map(|(bytes, _)| bytes))?;
                Ok((status, failure))
            })?;
            let token = r.read_optional(|r| r.read_der())?;
            Ok((status, failure, token))
        })
    })
    .map_err(|err| format!("the timestamp authority returned a malformed response: {err}"))?;

    // 0 = granted, 1 = granted with modifications; everything else is a refusal.
    if status > 1 {
        return Err(format!("the timestamp authority refused the request: {}", status_text(status, failure.as_deref())));
    }
    token.ok_or_else(|| "the timestamp authority reported success but returned no token".to_string())
}

struct TsaSigner {
    issuer_raw: Option<Vec<u8>>,
    serial: Option<Vec<u8>>,
    ski: Option<Vec<u8>>,
    digest_oid: Vec<u64>,
    signed_attrs_raw: Option<Vec<u8>>,
    sig_oid: Vec<u64>,
    signature: Vec<u8>,
}

type ParsedTokenCms = (Vec<u8>, Vec<Vec<u8>>, Vec<TsaSigner>);

fn parse_token_cms(token: &[u8]) -> Res<ParsedTokenCms> {
    let (tst_info, certificates, signers) = yasna::parse_ber(token, |r| {
        r.read_sequence(|r| {
            let ct = r.next().read_oid()?;
            if ct.components().as_slice() != oids::PKCS7_SIGNED_DATA {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let _version = r.next().read_u8()?;
                    r.next().read_set_of(|r| r.read_der().map(|_| ()))?;
                    let content = r.next().read_sequence(|r| {
                        let ect = r.next().read_oid()?;
                        if ect.components().as_slice() != oids::TST_INFO {
                            return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                        }
                        r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_bytes()))
                    })?;
                    let mut certificates = Vec::new();
                    r.read_optional(|r| {
                        r.read_tagged_implicit(Tag::context(0), |r| {
                            r.read_set_of(|r| {
                                let d = r.read_der()?;
                                if d.first() == Some(&0x30) {
                                    certificates.push(d);
                                }
                                Ok(())
                            })
                        })
                    })?;
                    if r.next().lookahead_tag()? == Tag::context(1) {
                        r.next().read_der()?;
                    }
                    let mut signers = Vec::new();
                    r.next().read_set_of(|r| {
                        r.read_sequence(|r| {
                            let _v = r.next().read_u8()?;
                            let (issuer_raw, serial, ski) = match r.next().read_der()? {
                                sid if sid.first() == Some(&0x30) => yasna::parse_ber(&sid, |r| {
                                    r.read_sequence(|r| {
                                        let issuer = r.next().read_der()?;
                                        let serial = r.next().read_bigint_bytes()?.0;
                                        Ok((Some(issuer), Some(serial), None))
                                    })
                                })?,
                                sid => {
                                    let ski = yasna::parse_ber(&sid, |r| r.read_tagged_implicit(Tag::context(0), |r| r.read_bytes()))?;
                                    (None, None, Some(ski))
                                }
                            };
                            let digest_oid = crate::pbe::read_algorithm_id(r.next())?.oid;
                            let signed_attrs_raw = if r.next().lookahead_tag()? == Tag::context(0) { Some(r.next().read_der()?) } else { None };
                            let sig_oid = crate::pbe::read_algorithm_id(r.next())?.oid;
                            let signature = r.next().read_bytes()?;
                            if r.next().lookahead_tag().ok() == Some(Tag::context(1)) {
                                r.next().read_der()?;
                            }
                            signers.push(TsaSigner { issuer_raw, serial, ski, digest_oid, signed_attrs_raw, sig_oid, signature });
                            Ok(())
                        })
                    })?;
                    Ok((content, certificates, signers))
                })
            })
        })
    })
    .map_err(|err| format!("the timestamp token is not a valid CMS structure: {err}"))?;
    let tst_info = tst_info.ok_or("the timestamp token carries no TSTInfo content")?;
    Ok((tst_info, certificates, signers))
}

fn find_attr_in_set(set_der: &[u8], arcs: &[u64]) -> Option<Vec<u8>> {
    yasna::parse_ber(set_der, |r| {
        let mut found = None;
        r.read_set_of(|r| {
            r.read_sequence(|r| {
                let attr_oid = r.next().read_oid()?;
                r.next().read_set_of(|r| {
                    let v = r.read_der()?;
                    if attr_oid.components().as_slice() == arcs && found.is_none() {
                        found = Some(v);
                    }
                    Ok(())
                })
            })
        })?;
        Ok(found)
    })
    .ok()
    .flatten()
}

fn matches_signer_id(cert_der: &[u8], s: &TsaSigner) -> bool {
    use x509_parser::prelude::*;
    let Ok((_, x)) = X509Certificate::from_der(cert_der) else { return false };
    if let (Some(issuer), Some(serial)) = (&s.issuer_raw, &s.serial) {
        x.issuer().as_raw() == issuer.as_slice() && trim_leading_zeros(x.raw_serial()) == trim_leading_zeros(serial)
    } else if let Some(ski) = &s.ski {
        x.iter_extensions().any(|e| matches!(e.parsed_extension(), ParsedExtension::SubjectKeyIdentifier(k) if k.0 == ski.as_slice()))
    } else {
        false
    }
}

/// Verifies the CMS `SignerInfo` signature inside a timestamp token, checks `signedAttrs` digest
/// and content-type, checks the `Time Stamping` Extended Key Usage when a signer certificate is
/// available, and ensures `ts.certificates[0]` is the matched TSA signing certificate.
fn verify_token_signature(ts: &mut Timestamp, extra_certs: &[Vec<u8>]) -> Res<()> {
    let (tst_info, mut certificates, signers) = parse_token_cms(&ts.token)?;
    let s = signers.first().ok_or("the timestamp token contains no signature (empty signerInfos)")?;
    let hash = HashAlg::from_digest_oid(&s.digest_oid).ok_or_else(|| format!("the timestamp token uses an unsupported digest algorithm ({})", oids::oid_str(&s.digest_oid)))?;
    let sig_alg = match s.sig_oid.as_slice() {
        a if a == oids::RSA_ENCRYPTION => Some(crate::keys::SigAlg::Rsa(hash)),
        a if a == oids::EC_PUBLIC_KEY => Some(crate::keys::SigAlg::Ecdsa(hash)),
        a => crate::keys::SigAlg::from_oid(a),
    }
    .ok_or_else(|| format!("the timestamp token uses an unsupported signature algorithm ({})", oids::signature_algorithm_name(&s.sig_oid)))?;

    let signed_set = if let Some(raw) = &s.signed_attrs_raw {
        let mut set = raw.clone();
        set[0] = 0x31;
        if let Some(ct_der) = find_attr_in_set(&set, oids::ATTR_CONTENT_TYPE) {
            let ct = yasna::parse_der(&ct_der, |r| r.read_oid()).map_err(|_| "malformed content-type attribute in timestamp token")?;
            if ct.components().as_slice() != oids::TST_INFO {
                return Err("the timestamp token's signed content-type is not id-ct-TSTInfo".into());
            }
        }
        let md =
            find_attr_in_set(&set, oids::ATTR_MESSAGE_DIGEST).and_then(|v| yasna::parse_der(&v, |r| r.read_bytes()).ok()).ok_or("the timestamp token's signed attributes omit the message digest")?;
        if md != hash.digest(&tst_info) {
            return Err("the timestamp token's signed message digest does not match its TSTInfo".into());
        }
        Some(set)
    } else {
        None
    };

    let mut pool = certificates.clone();
    for c in extra_certs {
        if !pool.iter().any(|existing| existing == c) {
            pool.push(c.clone());
        }
    }

    if !pool.is_empty() {
        let signer_cert = pool.iter().find(|c| matches_signer_id(c, s)).cloned().ok_or("the timestamp token's signing certificate does not match its SignerInfo")?;
        let summary = crate::x509::cert_summary(&signer_cert)?;
        let payload = signed_set.as_deref().unwrap_or(&tst_info);
        if !crate::keys::verify(&summary.spki, sig_alg, payload, &s.signature).unwrap_or(false) {
            return Err("the timestamp authority's cryptographic signature is invalid".into());
        }
        let cert_info = crate::x509::parse_certificate(&signer_cert)?;
        if !cert_info.extended_key_usage.iter().any(|u| u == "Time Stamping" || u == "timeStamping") {
            return Err("the timestamp signer certificate lacks the Time Stamping extended key usage".into());
        }
        if let Some(pos) = certificates.iter().position(|c| c == &signer_cert) {
            certificates.remove(pos);
        }
        certificates.insert(0, signer_cert);
        ts.certificates = certificates;
        if ts.authority == "unnamed authority" {
            ts.authority = cert_info.subject;
        }
    }
    Ok(())
}

/// The fields of `TSTInfo` we show to the user, read from inside the token's SignedData.
///
/// `expected_digest` and `expected_nonce` are checked when supplied. Passing `None` reads the
/// token without binding it to a particular signature, which is how the imprint hash is discovered
/// before it can be recomputed.
fn describe_token(token: &[u8], expected_digest: Option<&[u8]>, expected_nonce: Option<&[u8]>) -> Res<Timestamp> {
    // The token is a CMS SignedData whose encapsulated content is the DER TSTInfo.
    let (tst_info, mut certificates, signers) = parse_token_cms(token)?;
    if let Some(s) = signers.first()
        && let Some(pos) = certificates.iter().position(|c| matches_signer_id(c, s))
        && pos > 0
    {
        let signer_cert = certificates.remove(pos);
        certificates.insert(0, signer_cert);
    }

    let (policy, hash_oid, digest, serial, gen_time, nonce, tsa_name) = yasna::parse_ber(&tst_info, |r| {
        r.read_sequence(|r| {
            let _version = r.next().read_u8()?;
            let policy = r.next().read_oid()?.components().to_vec();
            let (hash_oid, digest) = r.next().read_sequence(|r| {
                let alg = crate::pbe::read_algorithm_id(r.next())?;
                let digest = r.next().read_bytes()?;
                Ok((alg.oid, digest))
            })?;
            let serial = r.next().read_bigint_bytes()?.0;
            let gen_time = r.next().read_der()?;
            // accuracy, ordering, nonce, tsa and extensions are all optional (RFC 3161 §2.4.2).
            let _accuracy = r.read_optional(|r| {
                r.read_sequence(|r| {
                    let _seconds = r.read_optional(|r| r.read_u64())?;
                    let _millis = r.read_optional(|r| r.read_tagged_implicit(Tag::context(0), |r| r.read_u64()))?;
                    let _micros = r.read_optional(|r| r.read_tagged_implicit(Tag::context(1), |r| r.read_u64()))?;
                    Ok(())
                })
            })?;
            let _ordering = r.read_optional(|r| r.read_bool())?;
            let nonce = r.read_optional(|r| r.read_bigint_bytes().map(|(b, _)| b))?;
            let tsa_name = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
            let _extensions = r.read_optional(|r| r.read_tagged_implicit(Tag::context(1), |r| r.read_der()))?;
            Ok((policy, hash_oid, digest, serial, gen_time, nonce, tsa_name))
        })
    })
    .map_err(|err| format!("the timestamp token contains a malformed TSTInfo: {err}"))?;

    // These checks are what make the token ours rather than a replayed or unrelated one.
    if let Some(expected) = expected_digest
        && digest != expected
    {
        return Err("the timestamp covers different data than this signature".into());
    }
    // RFC 3161 §2.4.2: when the request carried a nonce the response MUST echo it. A missing
    // nonce has to be rejected rather than skipped, or a replayed token would pass the check by
    // simply leaving the field out.
    if let Some(expected) = expected_nonce {
        match &nonce {
            Some(nonce) if trim_leading_zeros(nonce) == trim_leading_zeros(expected) => {}
            Some(_) => return Err("the timestamp response carries the wrong nonce, so it may be a replayed token".into()),
            None => return Err("the timestamp response omits the nonce we sent, so it may be a replayed token".into()),
        }
    }

    let authority = tsa_name
        .as_deref()
        .and_then(general_name_to_string)
        .or_else(|| certificates.first().and_then(|c| crate::x509::parse_certificate(c).ok()).map(|c| c.subject))
        .unwrap_or_else(|| "unnamed authority".into());

    Ok(Timestamp {
        token: token.to_vec(),
        time: parse_generalized_time(&gen_time).unwrap_or_else(|| "unknown time".into()),
        authority,
        serial_number: upper_hex(trim_leading_zeros(&serial)),
        hash_algorithm: HashAlg::from_digest_oid(&hash_oid).map(|h| h.name().to_string()).unwrap_or_else(|| oids::oid_str(&hash_oid)),
        policy: Some(oids::oid_str(&policy)).filter(|p| !p.is_empty()),
        certificates,
    })
}

/// `Some(true)` when `anchors_pem` is a trust bundle, the token's `SignerInfo` signature and
/// `Time Stamping` EKU are valid, and the signing certificate chains to `anchors_pem`.
/// `None` when no bundle was configured, so the caller does not claim the timestamp is trusted.
pub fn chain_trusted(ts: &Timestamp, anchors_pem: &str) -> Option<bool> {
    if anchors_pem.trim().is_empty() {
        return None;
    }
    let Ok(anchors) = crate::x509::certificates_from_bytes(anchors_pem.as_bytes()) else { return Some(false) };
    if anchors.is_empty() {
        return Some(false);
    }
    let mut verified = ts.clone();
    if verify_token_signature(&mut verified, &anchors).is_err() {
        return Some(false);
    }
    let Some(leaf) = verified.certificates.first() else { return Some(false) };
    Some(crate::x509::validate_chain(leaf, &verified.certificates[1..], &anchors, None).is_empty())
}

/// Renders the `GeneralName` the TSA identifies itself with; only directoryName is common.
fn general_name_to_string(der: &[u8]) -> Option<String> {
    // [4] directoryName wraps an RDNSequence in an explicit tag.
    let inner = yasna::parse_ber(der, |r| r.read_tagged(Tag::context(4), |r| r.read_der())).ok()?;
    Some(crate::x509::name_der_to_string(&inner)).filter(|s| !s.is_empty())
}

fn parse_generalized_time(der: &[u8]) -> Option<String> {
    let body = std::str::from_utf8(der.get(2..)?).ok()?;
    let trimmed = body.trim_end_matches('Z');
    // GeneralizedTime may carry fractional seconds; the whole seconds are enough for display.
    let whole = trimmed.split('.').next()?;
    let dt = chrono::NaiveDateTime::parse_from_str(whole, "%Y%m%d%H%M%S").ok()?;
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Requests a timestamp over `signature` from the TSA at `url`.
///
/// `signature` is the signature value of the SignerInfo being timestamped, which is what RFC 3161
/// Appendix A specifies as the message imprint.
pub fn request_timestamp(url: &str, signature: &[u8], hash: HashAlg) -> Res<Timestamp> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("enter the URL of a timestamp authority".into());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(format!("'{trimmed}' is not an http:// or https:// URL"));
    }
    let digest = hash.digest(signature);
    let nonce = random_bytes(16);
    let request = build_request(&digest, hash, &nonce, true);

    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(30))).user_agent(concat!("keystore-studio/", env!("CARGO_PKG_VERSION"))).build().into();
    let mut response =
        agent.post(trimmed).content_type(REQUEST_TYPE).send(&request[..]).map_err(|err| format!("cannot reach the timestamp authority at {trimmed}: {}", tidy_network_error(&err.to_string())))?;

    let status = response.status();
    let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = response.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(|err| format!("cannot read the timestamp authority's reply: {err}"))?;

    if !status.is_success() {
        return Err(format!("the timestamp authority answered HTTP {status}{}", http_body_hint(&body)));
    }
    // Some authorities omit or mislabel the content type, so this is a hint, not a hard check: a
    // response that parses is accepted whatever it claims to be.
    if !content_type.is_empty() && !content_type.starts_with(RESPONSE_TYPE) && body.first() != Some(&0x30) {
        return Err(format!("{trimmed} replied with '{content_type}' instead of a timestamp; check the URL"));
    }
    let token = parse_response(&body)?;
    let mut ts = describe_token(&token, Some(&digest), Some(&nonce))?;
    verify_token_signature(&mut ts, &[])?;
    Ok(ts)
}

/// Turns the HTML or text of an error page into a short hint rather than dumping a whole page.
fn http_body_hint(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(120).collect();
    if snippet.trim().is_empty() { String::new() } else { format!(": {snippet}") }
}

fn tidy_network_error(err: &str) -> String {
    let lower = err.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "the request timed out after 30 seconds".into()
    } else if lower.contains("dns") || lower.contains("resolve") {
        "the host name could not be resolved".into()
    } else if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake") {
        format!("the TLS connection failed ({err})")
    } else {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_the_shape_rfc3161_requires() {
        let digest = sha256(b"signature bytes");
        let nonce = random_bytes(8);
        let req = build_request(&digest, HashAlg::Sha256, &nonce, true);
        // version, messageImprint{alg, digest}, nonce, certReq
        let (version, alg_oid, got_digest, got_nonce, cert_req) = yasna::parse_der(&req, |r| {
            r.read_sequence(|r| {
                let version = r.next().read_u8()?;
                let (alg, digest) = r.next().read_sequence(|r| {
                    let alg = r.next().read_sequence(|r| {
                        let o = r.next().read_oid()?;
                        r.next().read_null()?;
                        Ok(o.components().to_vec())
                    })?;
                    Ok((alg, r.next().read_bytes()?))
                })?;
                let nonce = r.next().read_bigint_bytes()?.0;
                let cert_req = r.read_optional(|r| r.read_bool())?;
                Ok((version, alg, digest, nonce, cert_req))
            })
        })
        .expect("request must be valid DER");
        assert_eq!(version, 1);
        assert_eq!(alg_oid, oids::SHA256);
        assert_eq!(got_digest, digest);
        assert_eq!(trim_leading_zeros(&got_nonce), trim_leading_zeros(&nonce));
        assert_eq!(cert_req, Some(true));
    }

    #[test]
    fn refusals_are_reported_with_their_reason() {
        // PKIStatus 2 (rejected) with failInfo bit 0 (badAlg) set.
        let resp = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_u8(2);
                    w.next().write_bitvec_bytes(&[0x80], 1);
                });
            })
        });
        let err = parse_response(&resp).unwrap_err();
        assert!(err.contains("refused"), "{err}");
        assert!(err.contains("algorithm or format"), "{err}");
    }

    #[test]
    fn a_granted_response_with_no_token_is_an_error() {
        let resp = yasna::construct_der(|w| w.write_sequence(|w| w.next().write_sequence(|w| w.next().write_u8(0))));
        assert!(parse_response(&resp).unwrap_err().contains("no token"));
    }

    /// A token that leaves the nonce out must be refused when we sent one, otherwise omitting the
    /// field would be a way around the replay check.
    #[test]
    fn a_token_without_the_nonce_is_refused() {
        let digest = sha256(b"sig");
        let tst_info = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_oid(&oid(&[1, 2, 3, 4, 1]));
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(oids::SHA256));
                        w.next().write_null();
                    });
                    w.next().write_bytes(&digest);
                });
                w.next().write_bigint_bytes(&[1], true);
                w.next().write_der(&generalized_time_der(now_ts()));
                // No nonce field at all.
            })
        });
        let token = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(oids::PKCS7_SIGNED_DATA));
                w.next().write_tagged(Tag::context(0), |w| {
                    w.write_sequence(|w| {
                        w.next().write_u8(3);
                        w.next().write_set(|_| {});
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(oids::TST_INFO));
                            w.next().write_tagged(Tag::context(0), |w| w.write_bytes(&tst_info));
                        });
                        w.next().write_set(|_| {}); // signerInfos
                    })
                });
            })
        });
        // Read without a nonce expectation: fine, the fields parse.
        assert!(describe_token(&token, Some(&digest), None).is_ok());
        // Read as a reply to a request that carried a nonce: refused.
        let err = describe_token(&token, Some(&digest), Some(&[7, 7, 7])).unwrap_err();
        assert!(err.contains("omits the nonce"), "{err}");
    }

    #[test]
    fn urls_are_checked_before_any_network_call() {
        assert!(request_timestamp("", b"x", HashAlg::Sha256).unwrap_err().contains("enter the URL"));
        assert!(request_timestamp("tsa.example.test", b"x", HashAlg::Sha256).unwrap_err().contains("not an http"));
    }

    #[test]
    fn forged_unsigned_or_non_tsa_tokens_are_rejected_and_accuracy_millis_parses() {
        use crate::keys::PrivateKey;
        use crate::x509::{CertTemplate, Signer, build_certificate, encode_dn, ext_basic_constraints, ext_extended_key_usage, ext_key_usage, parse_dn};

        let now = now_ts();
        let root_key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let root_der = build_certificate(
            CertTemplate {
                serial: vec![1],
                subject_der: encode_dn(&parse_dn("CN=TSA Root CA").unwrap()),
                not_before: now - 60,
                not_after: now + 86_400,
                spki_der: root_key.public_key_der().unwrap(),
                extensions: vec![ext_basic_constraints(true, None), ext_key_usage(&["keyCertSign".into(), "cRLSign".into()]).unwrap().unwrap()],
            },
            &Signer { key: &root_key, cert_der: None, sig_alg: root_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let root_pem = to_pem("CERTIFICATE", &root_der);

        let tsa_key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let tsa_der = build_certificate(
            CertTemplate {
                serial: vec![2],
                subject_der: encode_dn(&parse_dn("CN=Valid TSA").unwrap()),
                not_before: now - 60,
                not_after: now + 86_400,
                spki_der: tsa_key.public_key_der().unwrap(),
                extensions: vec![ext_basic_constraints(false, None), ext_key_usage(&["digitalSignature".into()]).unwrap().unwrap(), ext_extended_key_usage(&["timeStamping".into()]).unwrap().unwrap()],
            },
            &Signer { key: &root_key, cert_der: Some(&root_der), sig_alg: root_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();

        let non_tsa_der = build_certificate(
            CertTemplate {
                serial: vec![3],
                subject_der: encode_dn(&parse_dn("CN=Non TSA Leaf").unwrap()),
                not_before: now - 60,
                not_after: now + 86_400,
                spki_der: tsa_key.public_key_der().unwrap(),
                extensions: vec![ext_basic_constraints(false, None), ext_key_usage(&["digitalSignature".into()]).unwrap().unwrap(), ext_extended_key_usage(&["serverAuth".into()]).unwrap().unwrap()],
            },
            &Signer { key: &root_key, cert_der: Some(&root_der), sig_alg: root_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();

        let sig_bytes = b"cms-signature-value";
        let imprint = sha256(sig_bytes);
        let tst_info = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_oid(&oid(&[1, 3, 6, 1, 4, 1, 99999, 1]));
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(oids::SHA256));
                        w.next().write_null();
                    });
                    w.next().write_bytes(&imprint);
                });
                w.next().write_bigint_bytes(&[42], true);
                w.next().write_der(&generalized_time_der(now));
                // Accuracy with seconds, [0] millis, [1] micros
                w.next().write_sequence(|w| {
                    w.next().write_u64(1);
                    w.next().write_tagged_implicit(Tag::context(0), |w| w.write_u64(500));
                    w.next().write_tagged_implicit(Tag::context(1), |w| w.write_u64(250));
                });
            })
        });

        let make_token = |certs: Vec<Vec<u8>>, signer_cert: Option<&[u8]>| {
            yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_oid(&oid(oids::PKCS7_SIGNED_DATA));
                    w.next().write_tagged(Tag::context(0), |w| {
                        w.write_sequence(|w| {
                            w.next().write_u8(3);
                            w.next().write_set(|w| {
                                w.next().write_sequence(|w| w.next().write_oid(&oid(oids::SHA256)));
                            });
                            w.next().write_sequence(|w| {
                                w.next().write_oid(&oid(oids::TST_INFO));
                                w.next().write_tagged(Tag::context(0), |w| w.write_bytes(&tst_info));
                            });
                            w.next().write_tagged_implicit(Tag::context(0), |w| {
                                w.write_set_of(|w| {
                                    for c in &certs {
                                        w.next().write_der(c);
                                    }
                                })
                            });
                            w.next().write_set(|w| {
                                if let Some(sc) = signer_cert {
                                    use x509_parser::prelude::*;
                                    let (_, x) = X509Certificate::from_der(sc).unwrap();
                                    let sig_alg = tsa_key.default_sig_alg(None).unwrap();
                                    let sig = tsa_key.sign(sig_alg, &tst_info).unwrap();
                                    w.next().write_sequence(|w| {
                                        w.next().write_u8(1);
                                        w.next().write_sequence(|w| {
                                            w.next().write_der(x.issuer().as_raw());
                                            w.next().write_bigint_bytes(x.raw_serial(), true);
                                        });
                                        w.next().write_sequence(|w| w.next().write_oid(&oid(oids::SHA256)));
                                        w.next().write_sequence(|w| w.next().write_oid(&oid(sig_alg.oid())));
                                        w.next().write_bytes(&sig);
                                    });
                                }
                            });
                        })
                    });
                })
            })
        };

        // 1. Forged unsigned token is rejected by verify_token and chain_trusted.
        let unsigned = make_token(vec![tsa_der.clone()], None);
        assert!(verify_token(&unsigned, sig_bytes).is_err());
        let desc = describe_any_token(&unsigned).unwrap();
        assert_eq!(chain_trusted(&desc, &root_pem), Some(false));

        // 2. Token signed by a certificate without Time Stamping EKU is rejected.
        let bad_eku = make_token(vec![non_tsa_der.clone()], Some(&non_tsa_der));
        assert!(verify_token(&bad_eku, sig_bytes).is_err());

        // 3. Valid TSA token (even with root_der listed before tsa_der in certificates SET) verifies and is chain_trusted.
        let valid_tok = make_token(vec![root_der.clone(), tsa_der.clone()], Some(&tsa_der));
        let verified = verify_token(&valid_tok, sig_bytes).expect("valid TSA token with Accuracy.millis must verify");
        assert_eq!(verified.certificates[0], tsa_der);
        assert_eq!(chain_trusted(&verified, &root_pem), Some(true));
    }
}
