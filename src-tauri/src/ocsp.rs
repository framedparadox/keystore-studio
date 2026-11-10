//! RFC 6960 OCSP: live revocation checking against a certificate's AIA OCSP responder.
//!
//! A CRL (`x509::parse_crl`, `ops::generate_crl`) is a periodic, signed list the issuer publishes;
//! OCSP answers one question — "is this exact certificate revoked?" — against a responder's
//! current state, which is what browsers and `openssl ocsp` check in real time. This module builds
//! the request, POSTs it to a URL from the certificate's `ocsp_urls` (or one the caller supplies),
//! and verifies the responder's signature the same way `tsa.rs` verifies a timestamp token: against
//! the responder's own certificate when the response carries one, falling back to the issuer when
//! it signs responses itself.
//!
//! This is the second outbound network request the app makes, after RFC 3161 timestamping; same
//! `ureq` + `rustls` agent, same one-shot blocking POST, no retries.

use crate::keys::{self, SigAlg};
use crate::oids::{self, oid};
use crate::util::*;
use crate::x509;
use std::time::Duration;
use yasna::Tag;

/// Media types fixed by RFC 6960 appendix A.1/A.2.
const REQUEST_TYPE: &str = "application/ocsp-request";
const MAX_RESPONSE: u64 = 256 * 1024;

/// What the responder said about one certificate, for display.
#[derive(Debug, Clone)]
pub struct OcspResult {
    /// "good", "revoked" or "unknown" (RFC 6960 §4.2.1 `CertStatus`).
    pub status: String,
    pub responder: String,
    pub produced_at: String,
    pub this_update: String,
    pub next_update: Option<String>,
    pub revocation_time: Option<String>,
    pub revocation_reason: Option<String>,
    /// True once the responder's signature was checked against a certificate we trust for it.
    pub signature_valid: bool,
    /// Set when the signature could not be checked (no responder certificate available).
    pub signature_warning: Option<String>,
    pub url: String,
}

impl OcspResult {
    pub fn info(&self) -> crate::model::OcspInfo {
        crate::model::OcspInfo {
            status: self.status.clone(),
            responder: self.responder.clone(),
            produced_at: self.produced_at.clone(),
            this_update: self.this_update.clone(),
            next_update: self.next_update.clone(),
            revocation_time: self.revocation_time.clone(),
            revocation_reason: self.revocation_reason.clone(),
            signature_valid: self.signature_valid,
            signature_warning: self.signature_warning.clone(),
            url: self.url.clone(),
        }
    }
}

/// `CertID`: issuer name hash, issuer key hash and the serial number being asked about.
struct CertId {
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial: Vec<u8>,
}

fn build_cert_id(subject_der: &[u8], issuer_der: &[u8]) -> Res<CertId> {
    let subject = x509::cert_summary(subject_der)?;
    let issuer = x509::cert_summary(issuer_der)?;
    // RFC 6960 §4.1.1: issuerKeyHash is the SHA-1 of the issuer's subjectPublicKey BIT STRING
    // contents (not the whole SubjectPublicKeyInfo), matching every CA and responder in practice.
    let key_bits = yasna::parse_der(&issuer.spki, |r| r.read_sequence(|r| { r.next().read_der()?; r.next().read_bitvec_bytes().map(|(b, _)| b) }))
        .map_err(|err| format!("cannot read the issuer's public key: {err}"))?;
    Ok(CertId { issuer_name_hash: sha1(&issuer.subject_raw), issuer_key_hash: sha1(&key_bits), serial: subject.serial })
}

/// Writes one `Request ::= SEQUENCE { reqCert CertID }` into a `requestList` writer.
fn write_request(w: &mut yasna::DERWriterSeq, id: &CertId) {
    w.next().write_sequence(|w| {
        // reqCert: CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
        w.next().write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::SHA1));
                w.next().write_null();
            });
            w.next().write_bytes(&id.issuer_name_hash);
            w.next().write_bytes(&id.issuer_key_hash);
            w.next().write_bigint_bytes(&id.serial, true);
        });
    });
}

/// Builds a DER `OCSPRequest` for one certificate, with a random nonce extension (RFC 8954) so a
/// replayed response is detected when we check it back.
fn build_request(id: &CertId, nonce: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // TBSRequest
            w.next().write_sequence(|w| {
                // requestList: one Request, no requestorName, no singleRequestExtensions.
                w.next().write_sequence_of(|w| write_request(w, id));
                // requestExtensions [2]: the nonce (id-pkix-ocsp-nonce).
                w.next().write_tagged(Tag::context(2), |w| {
                    w.write_sequence_of(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(oids::OCSP_NONCE));
                            w.next().write_bytes(&yasna::construct_der(|w| w.write_bytes(nonce)));
                        });
                    });
                });
            });
            // optionalSignature: omitted (anonymous request, which every public responder accepts).
        })
    })
}

/// `OCSPResponseStatus` (RFC 6960 §4.2.1).
fn response_status_text(code: u8) -> &'static str {
    match code {
        0 => "successful",
        1 => "malformed request",
        2 => "internal error",
        3 => "try later",
        5 => "signature required",
        6 => "unauthorized",
        _ => "unknown status",
    }
}

/// GeneralizedTime content octets (no tag/length) as `"YYYY-MM-DD HH:MM:SS UTC"`.
fn parse_generalized_time(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let trimmed = text.trim_end_matches('Z');
    let whole = trimmed.split('.').next()?;
    let dt = chrono::NaiveDateTime::parse_from_str(whole, "%Y%m%d%H%M%S").ok()?;
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Reads a `Time` (GeneralizedTime, tag+length included) and formats it, or "" if unreadable.
fn read_time(der: &[u8]) -> String {
    parse_generalized_time(der.get(2..).unwrap_or(&[])).unwrap_or_default()
}

fn read_cert_id(r: &mut yasna::BERReaderSeq) -> yasna::ASN1Result<CertId> {
    r.next().read_sequence(|r| {
        r.next().read_oid()?;
        r.next().read_null()
    })?;
    let issuer_name_hash = r.next().read_bytes()?;
    let issuer_key_hash = r.next().read_bytes()?;
    let serial = r.next().read_bigint_bytes()?.0;
    Ok(CertId { issuer_name_hash, issuer_key_hash, serial })
}

/// One `SingleResponse`; `matches` is set when its `CertId` is the one we asked about.
struct SingleResponse {
    matches: bool,
    status: String,
    revocation_time: Option<String>,
    revocation_reason: Option<String>,
    this_update: String,
    next_update: Option<String>,
}

fn read_single_response(r: yasna::BERReader, want: &CertId) -> yasna::ASN1Result<SingleResponse> {
    r.read_sequence(|r| {
        let got_id = r.next().read_sequence(read_cert_id)?;
        let matches = got_id.issuer_name_hash == want.issuer_name_hash
            && got_id.issuer_key_hash == want.issuer_key_hash
            && trim_leading_zeros(&got_id.serial) == trim_leading_zeros(&want.serial);
        // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
        //                         unknown [2] IMPLICIT UnknownInfo }
        let tag = r.next().lookahead_tag()?.tag_number;
        let (status, revocation_time, revocation_reason) = match tag {
            0 => {
                r.next().read_tagged_implicit(Tag::context(0), |r| r.read_null())?;
                ("good".to_string(), None, None)
            }
            1 => {
                // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
                //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
                // The outer [1] on RevokedInfo is IMPLICIT (read_sequence works directly on a
                // constructed IMPLICIT tag's content), but revocationReason's [0] is EXPLICIT.
                let (time, reason) = r.next().read_tagged_implicit(Tag::context(1), |r| {
                    r.read_sequence(|r| {
                        let time = r.next().read_der()?;
                        let reason = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_enum()))?;
                        Ok((time, reason))
                    })
                })?;
                ("revoked".to_string(), Some(read_time(&time)), reason.map(|c| x509::reason_name(c as u8).to_string()))
            }
            _ => {
                r.next().read_tagged_implicit(Tag::context(2), |r| r.read_der())?;
                ("unknown".to_string(), None, None)
            }
        };
        let this_update = r.next().read_der()?;
        // nextUpdate [0] EXPLICIT GeneralizedTime: an explicit tag wraps a nested TLV, so this
        // reads the [0] wrapper itself (read_tagged) rather than treating [0] as the GeneralizedTime
        // tag in place of 0x18 (which read_tagged_implicit would, and silently misread the bytes).
        let next_update = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
        if r.read_optional(|r| r.read_tagged(Tag::context(1), |r| r.read_der()))?.is_some() {
            // singleExtensions [1]: read and discarded above, not needed for display.
        }
        Ok(SingleResponse { matches, status, revocation_time, revocation_reason, this_update: read_time(&this_update), next_update: next_update.map(|d| read_time(&d)) })
    })
}

/// A parsed `BasicOCSPResponse`, with only the single response that answers about our certificate.
struct Parsed {
    tbs_raw: Vec<u8>,
    responder: String,
    produced_at: String,
    matched: Option<SingleResponse>,
    nonce_echoed: Option<Vec<u8>>,
    sig_oid: Vec<u64>,
    signature: Vec<u8>,
    certs: Vec<Vec<u8>>,
}

fn read_responder_id(r: yasna::BERReader) -> yasna::ASN1Result<String> {
    // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }
    match r.lookahead_tag()?.tag_number {
        1 => r.read_tagged(Tag::context(1), |r| r.read_der()).map(|d| x509::name_der_to_string(&d)),
        _ => r.read_tagged_implicit(Tag::context(2), |r| r.read_bytes()).map(|_| "(identified by key hash)".to_string()),
    }
}

fn parse_basic_response(basic_der: &[u8], want: &CertId) -> Res<Parsed> {
    yasna::parse_ber(basic_der, |r| {
        r.read_sequence(|r| {
            let tbs_raw = r.next().read_der()?;
            let (responder, produced_at, matched, nonce_echoed) = yasna::parse_ber(&tbs_raw, |r| {
                r.read_sequence(|r| {
                    // version [0] DEFAULT v1
                    if r.next().lookahead_tag()?.tag_number == 0 {
                        r.next().read_der()?;
                    }
                    let responder = read_responder_id(r.next())?;
                    let produced_at = read_time(&r.next().read_der()?);
                    let mut matched = None;
                    r.next().read_sequence_of(|r| {
                        let single = read_single_response(r, want)?;
                        if single.matches && matched.is_none() {
                            matched = Some(single);
                        }
                        Ok(())
                    })?;
                    let mut nonce_echoed = None;
                    r.read_optional(|r| {
                        r.read_tagged(Tag::context(1), |r| {
                            r.read_sequence_of(|r| {
                                r.read_sequence(|r| {
                                    let oid = r.next().read_oid()?;
                                    let value = r.next().read_bytes()?;
                                    if oid.components().as_slice() == oids::OCSP_NONCE {
                                        nonce_echoed = yasna::parse_der(&value, |r| r.read_bytes()).ok();
                                    }
                                    Ok(())
                                })
                            })
                        })
                    })?;
                    Ok((responder, produced_at, matched, nonce_echoed))
                })
            })
            .map_err(|_| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?;
            let sig_oid = r.next().read_sequence(|r| {
                let oid = r.next().read_oid()?.components().to_vec();
                let _ = r.read_optional(|r| r.read_der());
                Ok(oid)
            })?;
            let signature = r.next().read_bitvec_bytes().map(|(b, _)| b)?;
            let mut certs = Vec::new();
            r.read_optional(|r| {
                r.read_tagged(Tag::context(0), |r| {
                    r.read_sequence_of(|r| {
                        certs.push(r.read_der()?);
                        Ok(())
                    })
                })
            })?;
            Ok(Parsed { tbs_raw, responder, produced_at, matched, nonce_echoed, sig_oid, signature, certs })
        })
    })
    .map_err(|err| format!("the OCSP response body is malformed: {err}"))
}

/// Requests revocation status for `subject_der`, issued by `issuer_der`, from `url`.
pub fn check(url: &str, subject_der: &[u8], issuer_der: &[u8]) -> Res<OcspResult> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("this certificate carries no OCSP responder URL".into());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(format!("'{trimmed}' is not an http:// or https:// OCSP URL"));
    }
    let id = build_cert_id(subject_der, issuer_der)?;
    let nonce = random_bytes(16);
    let request = build_request(&id, &nonce);

    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(20))).user_agent(concat!("keystore-studio/", env!("CARGO_PKG_VERSION"))).build().into();
    let mut response =
        agent.post(trimmed).content_type(REQUEST_TYPE).send(&request[..]).map_err(|err| format!("cannot reach the OCSP responder at {trimmed}: {}", tidy_network_error(&err.to_string())))?;

    let status = response.status();
    let body = response.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(|err| format!("cannot read the OCSP responder's reply: {err}"))?;
    if !status.is_success() {
        return Err(format!("the OCSP responder answered HTTP {status}{}", http_body_hint(&body)));
    }

    let (resp_status, basic_der) = yasna::parse_ber(&body, |r| {
        r.read_sequence(|r| {
            let status = r.next().read_enum()? as u8;
            let basic = r.read_optional(|r| {
                r.read_tagged(Tag::context(0), |r| {
                    r.read_sequence(|r| {
                        let oid = r.next().read_oid()?;
                        if oid.components().as_slice() != oids::PKIX_OCSP_BASIC {
                            return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                        }
                        r.next().read_bytes()
                    })
                })
            })?;
            Ok((status, basic))
        })
    })
    .map_err(|err| format!("the OCSP responder returned a malformed response: {err}"))?;

    if resp_status != 0 {
        return Err(format!("the OCSP responder declined the request: {}", response_status_text(resp_status)));
    }
    let basic_der = basic_der.ok_or("the OCSP responder reported success but included no response data")?;

    let parsed = parse_basic_response(&basic_der, &id)?;
    let single = parsed.matched.ok_or("the OCSP response does not answer about this certificate")?;
    if let Some(echoed) = &parsed.nonce_echoed
        && echoed != &nonce
    {
        return Err("the OCSP response echoed a different nonce than the one sent; discarding a possibly replayed response".into());
    }

    let sig_alg = SigAlg::from_oid(&parsed.sig_oid).ok_or_else(|| format!("the OCSP response uses an unsupported signature algorithm ({})", oids::signature_algorithm_name(&parsed.sig_oid)))?;

    // The signer is the certificate the response carries, when it is either the issuer itself or
    // a certificate the issuer issued (the usual delegated OCSP-signing certificate), falling back
    // to the issuer's own key when the responder sent no certificate and signed directly.
    let issuer_summary = x509::cert_summary(issuer_der).ok();
    let signer_spki = parsed
        .certs
        .iter()
        .find(|c| x509::issued_by(c, issuer_der) || x509::cert_summary(c).ok().map(|s| s.subject_raw) == issuer_summary.as_ref().map(|s| s.subject_raw.clone()))
        .and_then(|c| x509::cert_summary(c).ok())
        .map(|s| s.spki);
    let (signature_valid, signature_warning) = match signer_spki.or_else(|| issuer_summary.map(|s| s.spki)) {
        Some(spki) => match keys::verify(&spki, sig_alg, &parsed.tbs_raw, &parsed.signature) {
            Ok(true) => (true, None),
            Ok(false) => (false, Some("the responder's signature does not match any available responder or issuer certificate".to_string())),
            Err(err) => (false, Some(err)),
        },
        None => (false, Some("no certificate was available to check the responder's signature against".to_string())),
    };

    Ok(OcspResult {
        status: single.status,
        responder: parsed.responder,
        produced_at: parsed.produced_at,
        this_update: single.this_update,
        next_update: single.next_update,
        revocation_time: single.revocation_time,
        revocation_reason: single.revocation_reason,
        signature_valid,
        signature_warning,
        url: trimmed.to_string(),
    })
}

fn http_body_hint(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(120).collect();
    if snippet.trim().is_empty() { String::new() } else { format!(": {snippet}") }
}

fn tidy_network_error(err: &str) -> String {
    let lower = err.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "the request timed out after 20 seconds".into()
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
    fn request_has_the_shape_rfc6960_requires() {
        let id = CertId { issuer_name_hash: sha1(b"issuer"), issuer_key_hash: sha1(b"key"), serial: vec![0x01, 0x02, 0x03] };
        let nonce = random_bytes(8);
        let req = build_request(&id, &nonce);
        // TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request, requestExtensions [2] ... }
        let (cert_id, nonce_ext_present) = yasna::parse_der(&req, |r| {
            r.read_sequence(|r| {
                r.next().read_sequence(|r| {
                    let mut cert_id = None;
                    r.next().read_sequence_of(|r| {
                        r.read_sequence(|r| {
                            cert_id = Some(r.next().read_sequence(read_cert_id)?);
                            Ok(())
                        })
                    })?;
                    let ext = r.next().read_tagged(Tag::context(2), |r| r.read_der())?;
                    Ok((cert_id.take().unwrap(), !ext.is_empty()))
                })
            })
        })
        .expect("request must be valid DER");
        assert_eq!(cert_id.issuer_name_hash, id.issuer_name_hash);
        assert_eq!(cert_id.issuer_key_hash, id.issuer_key_hash);
        assert_eq!(cert_id.serial, id.serial);
        assert!(nonce_ext_present);
    }

    #[test]
    fn response_status_text_covers_rfc_values() {
        assert_eq!(response_status_text(0), "successful");
        assert_eq!(response_status_text(6), "unauthorized");
        assert_eq!(response_status_text(99), "unknown status");
    }

    /// Manual, one-off check against a real `openssl ocsp` responder (not run in CI): start
    ///   cd /tmp/ocsp-live && openssl ocsp -port 38080 -index index.txt -CA root.pem -rkey root.key -rsigner root.pem -nmin 60 -text
    /// signing for the leaf whose AIA points at 127.0.0.1:38080 (index.txt's first column, `V` or
    /// `R`, decides whether the answer is "good" or "revoked"), then run with
    ///   cargo test --lib ocsp::tests::live_responder_round_trip -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_responder_round_trip() {
        let leaf = std::fs::read_to_string("/tmp/ocsp-live/leaf.pem").expect("leaf.pem (see docstring for setup)");
        let root = std::fs::read_to_string("/tmp/ocsp-live/root.pem").expect("root.pem");
        let leaf_der = x509::certificates_from_bytes(leaf.as_bytes()).unwrap().remove(0);
        let root_der = x509::certificates_from_bytes(root.as_bytes()).unwrap().remove(0);
        let result = check("http://127.0.0.1:38080", &leaf_der, &root_der).expect("the live responder answered");
        println!("{result:#?}");
        assert!(matches!(result.status.as_str(), "good" | "revoked"), "unexpected status {}", result.status);
        assert!(result.next_update.as_deref().is_some_and(|t| !t.is_empty()), "nextUpdate should parse to a real timestamp, not empty");
        if result.status == "revoked" {
            assert!(result.revocation_time.as_deref().is_some_and(|t| !t.is_empty()));
            assert_eq!(result.revocation_reason.as_deref(), Some("keyCompromise"));
        }
        assert!(result.signature_valid, "responder signature should verify against the root CA");
        assert!(result.signature_warning.is_none());
    }
}
