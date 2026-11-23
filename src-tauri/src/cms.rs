//! CMS / PKCS#7 SignedData (RFC 5652): signing (attached or detached, with signed attributes),
//! verification, and certificates-only bundles (.p7b). Verified against `openssl cms` and
//! `jarsigner`.

use crate::keys::{self, PrivateKey, SigAlg};
use crate::model::{CertificateInfo, CmsSignerInfo, CmsVerifyResult};
use crate::oids::{self, oid};
use crate::pbe::{HashAlg, read_algorithm_id};
use crate::util::*;
use crate::x509;
use x509_parser::prelude::*;
use yasna::Tag;

fn write_digest_alg(w: yasna::DERWriter, hash: HashAlg) {
    w.write_sequence(|w| w.next().write_oid(&oid(hash.digest_oid())));
}

/// Signature algorithm identifier written into SignerInfo. RSA uses plain rsaEncryption, which is
/// what OpenSSL and jarsigner emit and what every verifier accepts.
fn write_signer_sig_alg(w: yasna::DERWriter, alg: SigAlg) {
    w.write_sequence(|w| match alg {
        SigAlg::Rsa(_) => {
            w.next().write_oid(&oid(oids::RSA_ENCRYPTION));
            w.next().write_null();
        }
        other => w.next().write_oid(&oid(other.oid())),
    });
}

/// The digest/signature pair CMS uses for a key: SHA-256 for RSA and P-256, the curve's hash for
/// P-384/P-521, SHA-512 for Ed25519 (RFC 8419).
pub fn cms_algorithms(key: &PrivateKey) -> Res<(HashAlg, SigAlg)> {
    let alg = key.default_sig_alg(Some(HashAlg::Sha256))?;
    Ok((alg.hash(), alg))
}

fn attribute(arcs: &[u64], value_der: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(arcs));
            w.next().write_set(|w| w.next().write_der(value_der));
        })
    })
}

/// DER SET OF attributes, sorted as DER requires.
fn signed_attributes_set(content_digest: &[u8], signing_time: i64) -> Vec<u8> {
    let mut attrs = [
        attribute(oids::ATTR_CONTENT_TYPE, &yasna::construct_der(|w| w.write_oid(&oid(oids::PKCS7_DATA)))),
        attribute(oids::ATTR_SIGNING_TIME, &asn1_time_der(signing_time)),
        attribute(oids::ATTR_MESSAGE_DIGEST, &yasna::construct_der(|w| w.write_bytes(content_digest))),
    ];
    attrs.sort();
    let body: Vec<u8> = attrs.concat();
    let mut out = vec![0x31];
    out.extend(der_length(body.len()));
    out.extend(body);
    out
}

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = trim_leading_zeros(&(len as u64).to_be_bytes()).to_vec();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

/// Creates a CMS SignedData. `signer_chain` is the signer certificate followed by its issuers.
pub fn sign(content: &[u8], key: &PrivateKey, signer_chain: &[Vec<u8>], detached: bool) -> Res<Vec<u8>> {
    sign_timestamped(content, key, signer_chain, detached, None).map(|(der, _)| der)
}

/// Creates a CMS SignedData, optionally timestamped by the TSA at `tsa_url`.
///
/// The RFC 3161 token goes into the SignerInfo's *unsigned* attributes, so it covers the signature
/// without being covered by it. That is what lets the token be fetched after signing, and it is
/// where `jarsigner -verify` and `openssl ts` look for it.
pub fn sign_timestamped(content: &[u8], key: &PrivateKey, signer_chain: &[Vec<u8>], detached: bool, tsa_url: Option<&str>) -> Res<(Vec<u8>, Option<crate::tsa::Timestamp>)> {
    let signer_cert = signer_chain.first().ok_or("the signing entry has no certificate")?;
    let summary = x509::cert_summary(signer_cert)?;
    if !keys::key_matches_spki(key, &summary.spki) {
        return Err("the private key does not match the signer certificate".into());
    }
    let (_, cert) = X509Certificate::from_der(signer_cert).map_err(e)?;
    let issuer_raw = cert.issuer().as_raw().to_vec();
    let serial = cert.raw_serial().to_vec();
    let (hash, sig_alg) = cms_algorithms(key)?;
    let digest = hash.digest(content);
    let attrs = signed_attributes_set(&digest, now_ts());
    let signature = key.sign(sig_alg, &attrs)?;

    // Fetch the token before building the structure, so a TSA failure aborts signing with a clear
    // error instead of silently producing an untimestamped file the user believes is timestamped.
    let timestamp = match tsa_url.map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => Some(crate::tsa::request_timestamp(url, &signature, hash)?),
        None => None,
    };
    let unsigned_attrs = timestamp.as_ref().map(|ts| {
        let mut set = attribute(oids::ATTR_TIMESTAMP_TOKEN, &ts.token);
        // SET OF for a single attribute: wrap it and retag as [1] IMPLICIT.
        let mut out = vec![0xA1];
        out.extend(der_length(set.len()));
        out.append(&mut set);
        out
    });

    let signed_data = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(1);
            w.next().write_set(|w| write_digest_alg(w.next(), hash));
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::PKCS7_DATA));
                if !detached {
                    w.next().write_tagged(Tag::context(0), |w| w.write_bytes(content));
                }
            });
            w.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set_of(|w| {
                    for c in signer_chain {
                        w.next().write_der(c);
                    }
                })
            });
            w.next().write_set(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_u8(1);
                    w.next().write_sequence(|w| {
                        w.next().write_der(&issuer_raw);
                        w.next().write_bigint_bytes(&serial, true);
                    });
                    write_digest_alg(w.next(), hash);
                    // [0] IMPLICIT: same content as the SET we signed, with the context tag.
                    let mut tagged = attrs.clone();
                    tagged[0] = 0xA0;
                    w.next().write_der(&tagged);
                    write_signer_sig_alg(w.next(), sig_alg);
                    w.next().write_bytes(&signature);
                    if let Some(unsigned) = &unsigned_attrs {
                        w.next().write_der(unsigned);
                    }
                });
            });
        })
    });
    Ok((content_info(oids::PKCS7_SIGNED_DATA, &signed_data), timestamp))
}

fn content_info(content_type: &[u64], content: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(content_type));
            w.next().write_tagged(Tag::context(0), |w| w.write_der(content));
        })
    })
}

/// Degenerate SignedData carrying only certificates (the .p7b / .p7c format).
pub fn certs_only(certs: &[Vec<u8>]) -> Vec<u8> {
    let signed_data = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(1);
            w.next().write_set(|_| {});
            w.next().write_sequence(|w| w.next().write_oid(&oid(oids::PKCS7_DATA)));
            w.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set_of(|w| {
                    for c in certs {
                        w.next().write_der(c);
                    }
                })
            });
            w.next().write_set(|_| {});
        })
    });
    content_info(oids::PKCS7_SIGNED_DATA, &signed_data)
}

struct ParsedSigner {
    issuer_raw: Option<Vec<u8>>,
    serial: Option<Vec<u8>>,
    ski: Option<Vec<u8>>,
    digest_oid: Vec<u64>,
    signed_attrs_raw: Option<Vec<u8>>,
    sig_oid: Vec<u64>,
    signature: Vec<u8>,
    unsigned_attrs_raw: Option<Vec<u8>>,
}

struct ParsedSignedData {
    e_content_type: Vec<u64>,
    content: Option<Vec<u8>>,
    certificates: Vec<Vec<u8>>,
    signers: Vec<ParsedSigner>,
}

fn parse_signed_data(der: &[u8]) -> Res<ParsedSignedData> {
    yasna::parse_ber(der, |r| {
        r.read_sequence(|r| {
            let ct = r.next().read_oid()?;
            if ct.components().as_slice() != oids::PKCS7_SIGNED_DATA {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let _version = r.next().read_u8()?;
                    r.next().read_set_of(|r| read_algorithm_id(r).map(|_| ()))?;
                    let (e_content_type, content) = r.next().read_sequence(|r| {
                        let ect = r.next().read_oid()?.components().to_vec();
                        let data = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_bytes()))?;
                        Ok((ect, data))
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
                            let digest_oid = read_algorithm_id(r.next())?.oid;
                            let signed_attrs_raw = if r.next().lookahead_tag()? == Tag::context(0) { Some(r.next().read_der()?) } else { None };
                            let sig_oid = read_algorithm_id(r.next())?.oid;
                            let signature = r.next().read_bytes()?;
                            // [1] IMPLICIT unsignedAttrs, where the RFC 3161 token lives.
                            let unsigned_attrs_raw = if r.next().lookahead_tag().ok() == Some(Tag::context(1)) { Some(r.next().read_der()?) } else { None };
                            signers.push(ParsedSigner { issuer_raw, serial, ski, digest_oid, signed_attrs_raw, sig_oid, signature, unsigned_attrs_raw });
                            Ok(())
                        })
                    })?;
                    Ok(ParsedSignedData { e_content_type, content, certificates, signers })
                })
            })
        })
    })
    .map_err(|err| format!("not a valid PKCS#7/CMS SignedData structure: {err}"))
}

/// Certificates contained in a PKCS#7 structure (PEM-decoded DER input).
pub fn certificates_from_pkcs7(der: &[u8]) -> Res<Vec<Vec<u8>>> {
    Ok(parse_signed_data(der)?.certificates)
}

fn find_attr(set_der: &[u8], arcs: &[u64]) -> Option<Vec<u8>> {
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

fn parse_time_der(der: &[u8]) -> Option<String> {
    let (tag, body) = (*der.first()?, std::str::from_utf8(der.get(2..)?).ok()?);
    let full = if tag == 0x17 {
        let yy: u32 = body.get(0..2)?.parse().ok()?;
        format!("{}{}", if yy >= 50 { "19" } else { "20" }, body)
    } else {
        body.to_string()
    };
    Some(crate::util::parse_compact(full.trim_end_matches('Z'))?.display())
}

/// Reads the RFC 3161 token from a signer's unsigned attributes, if it carries one, and checks it
/// against that signer's signature.
fn timestamp_of(s: &ParsedSigner, tsa_trust_pem: Option<&str>) -> Option<crate::model::TimestampInfo> {
    let mut set = s.unsigned_attrs_raw.clone()?;
    set[0] = 0x31; // [1] IMPLICIT -> SET OF, so the generic attribute reader can walk it.
    let token = find_attr(&set, oids::ATTR_TIMESTAMP_TOKEN)?;
    match crate::tsa::verify_token(&token, &s.signature) {
        Ok(ts) => {
            let mut info = ts.info(true, None);
            if let Some(pem) = tsa_trust_pem {
                info.chain_trusted = crate::tsa::chain_trusted(&ts, pem);
            }
            Some(info)
        }
        // A token that does not match is worth reporting, not hiding: it means the file was
        // assembled from parts, so read what we can and mark it invalid.
        Err(err) => match crate::tsa::describe_any_token(&token) {
            Ok(ts) => Some(ts.info(false, Some(err))),
            Err(_) => Some(crate::model::TimestampInfo {
                time: String::new(),
                authority: String::new(),
                serial_number: String::new(),
                hash_algorithm: String::new(),
                policy: None,
                valid: false,
                error: Some(err),
                chain_trusted: None,
            }),
        },
    }
}

/// Verifies every SignerInfo in `cms_der`. `detached_content` supplies the data for detached
/// signatures; `extra_certs` (e.g. a keystore entry's chain) are used to find signers whose
/// certificate is not embedded.
pub fn verify(cms_der: &[u8], detached_content: Option<&[u8]>, extra_certs: &[Vec<u8>]) -> Res<CmsVerifyResult> {
    verify_with_trust(cms_der, detached_content, extra_certs, None)
}

pub fn verify_with_trust(cms_der: &[u8], detached_content: Option<&[u8]>, extra_certs: &[Vec<u8>], tsa_trust_pem: Option<&str>) -> Res<CmsVerifyResult> {
    check_der_lengths(cms_der)?;
    let parsed = parse_signed_data(cms_der)?;
    let detached = parsed.content.is_none();
    let content = parsed.content.clone().or_else(|| detached_content.map(|c| c.to_vec()));
    let certificates: Vec<CertificateInfo> = parsed.certificates.iter().filter_map(|c| x509::parse_certificate(c).ok()).collect();
    let mut pool = parsed.certificates.clone();
    pool.extend(extra_certs.iter().cloned());

    if parsed.signers.is_empty() {
        return Ok(CmsVerifyResult {
            valid: false,
            detached,
            content_available: content.is_some(),
            content_text: None,
            content_sha256: None,
            signers: vec![],
            certificates,
            message: "This PKCS#7 structure contains no signatures (certificates-only bundle).".into(),
        });
    }

    let mut signers = Vec::new();
    for s in &parsed.signers {
        let cert = pool.iter().find(|c| {
            let Ok((_, x)) = X509Certificate::from_der(c) else { return false };
            if let (Some(issuer), Some(serial)) = (&s.issuer_raw, &s.serial) {
                x.issuer().as_raw() == issuer.as_slice() && trim_leading_zeros(x.raw_serial()) == trim_leading_zeros(serial)
            } else if let Some(ski) = &s.ski {
                x.iter_extensions().any(|e| matches!(e.parsed_extension(), ParsedExtension::SubjectKeyIdentifier(k) if k.0 == ski.as_slice()))
            } else {
                false
            }
        });
        let hash = HashAlg::from_digest_oid(&s.digest_oid);
        let mut info = CmsSignerInfo {
            subject: String::new(),
            issuer: s.issuer_raw.as_deref().map(x509::name_der_to_string).unwrap_or_default(),
            serial_number: s.serial.as_deref().map(|b| upper_hex(trim_leading_zeros(b))).unwrap_or_default(),
            digest_algorithm: hash.map(|h| h.name().to_string()).unwrap_or_else(|| oids::oid_str(&s.digest_oid)),
            signature_algorithm: oids::signature_algorithm_name(&s.sig_oid),
            signing_time: None,
            signature_valid: false,
            content_digest_valid: None,
            timestamp: timestamp_of(s, tsa_trust_pem),
            error: None,
        };
        let Some(cert) = cert else {
            info.error = Some("the signer's certificate is not included; select the signer entry to verify".into());
            signers.push(info);
            continue;
        };
        let summary = x509::cert_summary(cert)?;
        let cert_info = x509::parse_certificate(cert)?;
        info.subject = x509::name_der_to_string(&summary.subject_raw);
        let Some(hash) = hash else {
            info.error = Some(format!("unsupported digest algorithm {}", oids::oid_str(&s.digest_oid)));
            signers.push(info);
            continue;
        };
        let sig_alg = match s.sig_oid.as_slice() {
            a if a == oids::RSA_ENCRYPTION => Some(SigAlg::Rsa(hash)),
            a if a == oids::EC_PUBLIC_KEY => Some(SigAlg::Ecdsa(hash)),
            a => SigAlg::from_oid(a),
        };
        let Some(sig_alg) = sig_alg else {
            info.error = Some(format!("unsupported signature algorithm {}", info.signature_algorithm));
            signers.push(info);
            continue;
        };
        match (&s.signed_attrs_raw, &content) {
            (Some(raw), _) => {
                let mut set = raw.clone();
                set[0] = 0x31;
                info.signing_time = find_attr(&set, oids::ATTR_SIGNING_TIME).and_then(|t| parse_time_der(&t));
                let ct_ok = find_attr(&set, oids::ATTR_CONTENT_TYPE)
                    .and_then(|v| yasna::parse_der(&v, |r| r.read_oid()).ok())
                    .is_some_and(|oid| oid.components().as_slice() == parsed.e_content_type.as_slice());
                if !ct_ok {
                    info.signature_valid = false;
                    info.error = Some("signed content-type attribute is missing or does not match encapsulated content type".into());
                } else {
                    info.signature_valid = keys::verify(&summary.spki, sig_alg, &set, &s.signature).unwrap_or(false);
                }
                if let Some(content) = &content {
                    let md = find_attr(&set, oids::ATTR_MESSAGE_DIGEST).and_then(|v| yasna::parse_der(&v, |r| r.read_bytes()).ok());
                    info.content_digest_valid = Some(md.as_deref() == Some(hash.digest(content).as_slice()));
                }
            }
            (None, Some(content)) => {
                info.signature_valid = keys::verify(&summary.spki, sig_alg, content, &s.signature).unwrap_or(false);
                info.content_digest_valid = Some(info.signature_valid);
            }
            (None, None) => info.error = Some("detached signature: provide the original content to verify".into()),
        }
        if info.signature_valid {
            if let Some(expected_leaf) = extra_certs.first() {
                let matches_selected = cert.as_slice() == expected_leaf.as_slice() || x509::cert_summary(expected_leaf).is_ok_and(|ex| ex.spki == summary.spki);
                if !matches_selected {
                    info.signature_valid = false;
                    info.error = Some("the signature was not created by the selected keystore entry".into());
                }
            }
            let now = now_ts();
            if info.signature_valid && now < cert_info.not_before {
                info.signature_valid = false;
                info.error = Some(format!("signer certificate '{}' is not valid until {}", cert_info.subject, cert_info.valid_from));
            } else if info.signature_valid && now > cert_info.not_after {
                let covered_by_ts = info.timestamp.as_ref().is_some_and(|ts| {
                    ts.valid
                        && crate::util::parse_naive_datetime(ts.time.trim_end_matches(" UTC"))
                            .map(|dt| dt.ts())
                            .is_some_and(|t| t >= cert_info.not_before && t <= cert_info.not_after)
                });
                if !covered_by_ts {
                    info.signature_valid = false;
                    info.error = Some(format!("signer certificate '{}' expired on {}", cert_info.subject, cert_info.valid_to));
                }
            }
        }
        if !info.signature_valid && info.error.is_none() {
            info.error = Some("signature does not verify with the signer's public key".into());
        } else if info.content_digest_valid == Some(false) {
            info.error = Some("content was modified after signing (message digest mismatch)".into());
        }
        signers.push(info);
    }

    let all_ok = signers.iter().all(|s| s.signature_valid && s.content_digest_valid == Some(true));
    let message = if content.is_none() {
        "Detached signature — provide the signed content to complete verification.".to_string()
    } else if all_ok {
        format!("Valid: {} signature(s) verified and the content is intact.", signers.len())
    } else {
        signers.iter().find_map(|s| s.error.clone()).unwrap_or_else(|| "Signature verification failed.".into())
    };
    let content_text = content.as_ref().and_then(|c| std::str::from_utf8(c).ok().map(|s| s.chars().take(20_000).collect()));
    Ok(CmsVerifyResult {
        valid: all_ok && content.is_some(),
        detached,
        content_available: content.is_some(),
        content_text,
        content_sha256: content.as_ref().map(|c| upper_hex(&sha256(c))),
        signers,
        certificates,
        message,
    })
}

/// Accepts CMS as PEM ("PKCS7"/"CMS") or DER.
pub fn cms_der_from_bytes(data: &[u8]) -> Res<Vec<u8>> {
    if looks_textual(data) {
        let text = String::from_utf8_lossy(data);
        for block in pem_blocks(&text) {
            if block.tag == "PKCS7" || block.tag == "CMS" {
                return Ok(block.der);
            }
        }
        if let Ok(der) = unb64(text.trim()) {
            return Ok(der);
        }
        return Err("no PKCS#7/CMS structure found (expected -----BEGIN PKCS7----- or DER)".into());
    }
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{CertTemplate, Signer, build_certificate, encode_dn, parse_dn};

    fn self_signed(key: &PrivateKey) -> Vec<u8> {
        let now = now_ts();
        build_certificate(
            CertTemplate {
                serial: random_serial(),
                subject_der: encode_dn(&parse_dn("CN=Signer, O=Test").unwrap()),
                not_before: now,
                not_after: now + 86_400,
                spki_der: key.public_key_der().unwrap(),
                extensions: vec![],
            },
            &Signer { key, cert_der: None, sig_alg: key.default_sig_alg(None).unwrap() },
        )
        .unwrap()
    }

    #[test]
    fn sign_and_verify_all_key_types() {
        for key in [
            PrivateKey::generate("RSA", 2048, None).unwrap(),
            PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap(),
            PrivateKey::generate("ECDSA", 0, Some("P-521")).unwrap(),
            PrivateKey::generate("Ed25519", 0, None).unwrap(),
        ] {
            let cert = self_signed(&key);
            let attached = sign(b"hello world", &key, std::slice::from_ref(&cert), false).unwrap();
            let r = verify(&attached, None, &[]).unwrap();
            assert!(r.valid, "{}", r.message);
            assert_eq!(r.content_text.as_deref(), Some("hello world"));

            let detached = sign(b"payload", &key, std::slice::from_ref(&cert), true).unwrap();
            assert!(!verify(&detached, None, &[]).unwrap().valid);
            assert!(verify(&detached, Some(b"payload"), &[]).unwrap().valid);
            let tampered = verify(&detached, Some(b"payloaD"), &[]).unwrap();
            assert!(!tampered.valid);
        }
    }

    #[test]
    fn certs_only_bundle_round_trips() {
        let key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let cert = self_signed(&key);
        let p7 = certs_only(std::slice::from_ref(&cert));
        assert_eq!(certificates_from_pkcs7(&p7).unwrap(), vec![cert]);
    }

    #[test]
    fn verify_rejects_expired_signer_and_mismatched_selected_entry() {
        let key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let cert = self_signed(&key);
        let other_key = PrivateKey::generate("ECDSA", 0, Some("P-256")).unwrap();
        let other_cert = self_signed(&other_key);

        let attached = sign(b"hello", &key, std::slice::from_ref(&cert), false).unwrap();
        assert!(verify(&attached, None, std::slice::from_ref(&cert)).unwrap().valid);
        let mismatch = verify(&attached, None, std::slice::from_ref(&other_cert)).unwrap();
        assert!(!mismatch.valid);
        assert!(mismatch.message.contains("selected keystore entry"), "{}", mismatch.message);

        let past = now_ts() - 86_400 * 10;
        let expired_cert = build_certificate(
            CertTemplate {
                serial: random_serial(),
                subject_der: encode_dn(&parse_dn("CN=Expired Signer").unwrap()),
                not_before: past - 86_400,
                not_after: past,
                spki_der: key.public_key_der().unwrap(),
                extensions: vec![],
            },
            &Signer { key: &key, cert_der: None, sig_alg: key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let expired_sig = sign(b"hello", &key, std::slice::from_ref(&expired_cert), false).unwrap();
        let expired_res = verify(&expired_sig, None, &[]).unwrap();
        assert!(!expired_res.valid);
        assert!(expired_res.message.contains("expired"), "{}", expired_res.message);
    }
}
