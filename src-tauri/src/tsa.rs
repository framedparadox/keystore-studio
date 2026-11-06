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
        }
    }
}

/// Reads a token's fields without binding it to any signature, for display when the binding check
/// has already failed.
pub fn describe_any_token(token: &[u8]) -> Res<Timestamp> {
    describe_token(token, None, None)
}

/// Reads a timestamp token found in a SignerInfo's unsigned attributes and checks that it really
/// covers `signature`.
///
/// This confirms the token belongs to this signature. It does not validate the TSA's own
/// certificate chain, so the result says "this token covers this signature and the TSA claims this
/// time", not "a trusted authority vouches for it".
pub fn verify_token(token: &[u8], signature: &[u8]) -> Res<Timestamp> {
    // The imprint hash is the TSA's choice, so read the token first and recompute with that hash.
    let described = describe_token(token, None, None)?;
    let hash = [HashAlg::Sha1, HashAlg::Sha224, HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
        .into_iter()
        .find(|h| h.name() == described.hash_algorithm)
        .ok_or_else(|| format!("the timestamp uses an unsupported digest ({})", described.hash_algorithm))?;
    describe_token(token, Some(&hash.digest(signature)), None)
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

/// The fields of `TSTInfo` we show to the user, read from inside the token's SignedData.
///
/// `expected_digest` and `expected_nonce` are checked when supplied. Passing `None` reads the
/// token without binding it to a particular signature, which is how the imprint hash is discovered
/// before it can be recomputed.
fn describe_token(token: &[u8], expected_digest: Option<&[u8]>, expected_nonce: Option<&[u8]>) -> Res<Timestamp> {
    // The token is a CMS SignedData whose encapsulated content is the DER TSTInfo.
    let (tst_info, certificates) = yasna::parse_ber(token, |r| {
        r.read_sequence(|r| {
            let _ct = r.next().read_oid()?;
            r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let _version = r.next().read_u8()?;
                    r.next().read_set_of(|r| r.read_der().map(|_| ()))?;
                    let content = r.next().read_sequence(|r| {
                        let _ct = r.next().read_oid()?;
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
                    // [1] crls, then the mandatory signerInfos. Both are read and discarded: the
                    // TSA's own signature is checked by a verifier that has its trust anchors, not
                    // here. Skipping them would leave trailing data and fail the parse.
                    if r.next().lookahead_tag()? == Tag::context(1) {
                        r.next().read_der()?;
                    }
                    r.next().read_der()?;
                    Ok((content, certificates))
                })
            })
        })
    })
    .map_err(|err| format!("the timestamp token is not a valid CMS structure: {err}"))?;

    let tst_info = tst_info.ok_or("the timestamp token carries no TSTInfo content")?;
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
            // accuracy, ordering, nonce, tsa and extensions are all optional.
            let _accuracy = r.read_optional(|r| r.read_sequence(|r| r.read_optional(|r| r.read_u64()).map(|_| ())))?;
            let _ordering = r.read_optional(|r| r.read_bool())?;
            let nonce = r.read_optional(|r| r.read_bigint_bytes().map(|(b, _)| b))?;
            let tsa_name = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
            Ok((policy, hash_oid, digest, serial, gen_time, nonce, tsa_name))
        })
    })
    .map_err(|err| format!("the timestamp token contains a malformed TSTInfo: {err}"))?;

    // These checks are what make the token ours rather than a replayed or unrelated one.
    if let Some(expected) = expected_digest {
        if digest != expected {
            return Err("the timestamp covers different data than this signature".into());
        }
    }
    if let (Some(nonce), Some(expected)) = (&nonce, expected_nonce) {
        if trim_leading_zeros(nonce) != trim_leading_zeros(expected) {
            return Err("the timestamp response carries the wrong nonce, so it may be a replayed token".into());
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
    })
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

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("xkeystore/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut response = agent
        .post(trimmed)
        .content_type(REQUEST_TYPE)
        .send(&request[..])
        .map_err(|err| format!("cannot reach the timestamp authority at {trimmed}: {}", tidy_network_error(&err.to_string())))?;

    let status = response.status();
    let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|err| format!("cannot read the timestamp authority's reply: {err}"))?;

    if !status.is_success() {
        return Err(format!("the timestamp authority answered HTTP {status}{}", http_body_hint(&body)));
    }
    // Some authorities omit or mislabel the content type, so this is a hint, not a hard check: a
    // response that parses is accepted whatever it claims to be.
    if !content_type.is_empty() && !content_type.starts_with(RESPONSE_TYPE) && body.first() != Some(&0x30) {
        return Err(format!("{trimmed} replied with '{content_type}' instead of a timestamp; check the URL"));
    }
    let token = parse_response(&body)?;
    describe_token(&token, Some(&digest), Some(&nonce))
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

    #[test]
    fn urls_are_checked_before_any_network_call() {
        assert!(request_timestamp("", b"x", HashAlg::Sha256).unwrap_err().contains("enter the URL"));
        assert!(request_timestamp("tsa.example.test", b"x", HashAlg::Sha256).unwrap_err().contains("not an http"));
    }
}
