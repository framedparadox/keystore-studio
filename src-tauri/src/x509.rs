//! X.509: distinguished names, certificate / CSR / CRL parsing into display models, and DER
//! builders for certificates, PKCS#10 requests and v2 CRLs signed with real keys.

use crate::keys::{self, PrivateKey, SigAlg};
use crate::model::{CertificateInfo, CrlInfo, CsrInfo, RevokedCertEntry, X509ExtensionInfo};
use crate::oids::{self, oid};
use crate::util::*;
use x509_parser::prelude::*;
use yasna::{DERWriter, Tag};

// =============================================================================================
// Distinguished names
// =============================================================================================

/// One attribute of an RDN: OID arcs and string value.
pub type DnAttr = (Vec<u64>, String);
/// RDNs in display (RFC 4514) order — most specific first, e.g. CN before C.
pub type Dn = Vec<Vec<DnAttr>>;

/// Parses an RFC 4514 / Java-style DN string ("CN=web, OU=Ops, O=Acme\, Inc., C=US").
pub fn parse_dn(input: &str) -> Res<Dn> {
    let input = input.trim();
    if input.is_empty() {
        return Err("the distinguished name is empty".into());
    }
    let mut rdns: Dn = Vec::new();
    let mut current_rdn: Vec<DnAttr> = Vec::new();
    let mut chars = input.chars().peekable();
    loop {
        // attribute type
        let mut attr_type = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            attr_type.push(c);
            chars.next();
        }
        if chars.next() != Some('=') {
            return Err(format!("expected '=' after '{}' in the distinguished name", attr_type.trim()));
        }
        let oid_arcs = oids::dn_attribute_oid(&attr_type).ok_or_else(|| format!("unknown DN attribute '{}'", attr_type.trim()))?;
        // value
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        let mut value = String::new();
        let mut trailing_spaces = 0usize;
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => value.push(chars.next().ok_or("unterminated escape in DN")?),
                    Some(c) => value.push(c),
                    None => return Err("unterminated quoted value in DN".into()),
                }
            }
            while chars.peek() == Some(&' ') {
                chars.next();
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' || c == ';' || c == '+' {
                    break;
                }
                chars.next();
                if c == '\\' {
                    let next = chars.next().ok_or("unterminated escape in DN")?;
                    if next.is_ascii_hexdigit() && chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                        // \XX hex escape: collect UTF-8 bytes.
                        let mut bytes = vec![u8::from_str_radix(&format!("{next}{}", chars.next().unwrap()), 16).unwrap()];
                        while chars.peek() == Some(&'\\') {
                            let mut look = chars.clone();
                            look.next();
                            match (look.next(), look.next()) {
                                (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                                    chars.next();
                                    chars.next();
                                    chars.next();
                                    bytes.push(u8::from_str_radix(&format!("{a}{b}"), 16).unwrap());
                                }
                                _ => break,
                            }
                        }
                        value.push_str(&String::from_utf8_lossy(&bytes));
                    } else {
                        value.push(next);
                    }
                    trailing_spaces = 0;
                } else {
                    value.push(c);
                    trailing_spaces = if c == ' ' { trailing_spaces + 1 } else { 0 };
                }
            }
            value.truncate(value.len() - trailing_spaces);
        }
        if value.is_empty() {
            return Err(format!("DN attribute '{}' has an empty value", attr_type.trim()));
        }
        if oid_arcs.as_slice() == oids::AT_C && (value.len() != 2 || !value.chars().all(|c| c.is_ascii_alphabetic())) {
            return Err(format!("country (C) must be a two-letter ISO code, got '{value}'"));
        }
        current_rdn.push((oid_arcs, value));
        match chars.next() {
            Some('+') => continue,
            Some(',') | Some(';') => {
                rdns.push(std::mem::take(&mut current_rdn));
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
            }
            None => {
                rdns.push(current_rdn);
                break;
            }
            Some(c) => return Err(format!("unexpected '{c}' in DN")),
        }
    }
    Ok(rdns)
}

/// Builds a DN from the classic form fields, skipping empty ones.
pub fn dn_from_fields(cn: &str, ou: &str, o: &str, l: &str, st: &str, c: &str, email: &str) -> Res<Dn> {
    let mut dn: Dn = Vec::new();
    for (arcs, v) in [
        (oids::AT_CN, cn),
        (oids::EMAIL_ADDRESS, email),
        (oids::AT_OU, ou),
        (oids::AT_O, o),
        (oids::AT_L, l),
        (oids::AT_ST, st),
        (oids::AT_C, c),
    ] {
        let v = v.trim();
        if !v.is_empty() {
            if arcs == oids::AT_C && (v.len() != 2 || !v.chars().all(|c| c.is_ascii_alphabetic())) {
                return Err(format!("country (C) must be a two-letter ISO code, got '{v}'"));
            }
            dn.push(vec![(arcs.to_vec(), v.to_string())]);
        }
    }
    if dn.is_empty() {
        return Err("enter at least a common name (CN)".into());
    }
    Ok(dn)
}

fn write_attr_value(w: DERWriter, arcs: &[u64], value: &str) {
    let printable = value.chars().all(|c| c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c));
    if arcs == oids::AT_C || (arcs == oids::AT_SERIAL_NUMBER && printable) {
        w.write_printable_string(value);
    } else if (arcs == oids::EMAIL_ADDRESS || arcs == oids::AT_DC) && value.is_ascii() {
        w.write_ia5_string(value);
    } else {
        w.write_utf8_string(value);
    }
}

/// DER `Name` for `dn` (written in ASN.1 order, i.e. reversed display order).
pub fn encode_dn(dn: &Dn) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for rdn in dn.iter().rev() {
                w.next().write_set_of(|w| {
                    for (arcs, value) in rdn {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(arcs));
                            write_attr_value(w.next(), arcs, value);
                        });
                    }
                });
            }
        });
    })
}

fn escape_dn_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, c) in v.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == v.chars().count() - 1 => out.push_str("\\ "),
            _ => out.push(c),
        }
    }
    out
}

/// Renders a parsed `X509Name` in RFC 4514 order ("CN=…, O=…, C=…").
pub fn name_to_string(name: &X509Name) -> String {
    let rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|atv| {
                    let arcs: Vec<u64> = atv.attr_type().iter().map(|i| i.collect()).unwrap_or_default();
                    let key = oids::dn_attribute_name(&arcs);
                    let value = match atv.as_str() {
                        Ok(s) => escape_dn_value(s),
                        Err(_) => match atv.attr_value().as_bmpstring() {
                            Ok(s) => escape_dn_value(s.string().as_str()),
                            Err(_) => format!("#{}", hex::encode(atv.attr_value().data)),
                        },
                    };
                    format!("{key}={value}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(", ")
}

pub fn name_der_to_string(der: &[u8]) -> String {
    match X509Name::from_der(der) {
        Ok((_, name)) => name_to_string(&name),
        Err(_) => format!("#{}", hex::encode(der)),
    }
}

/// Extracts the CN from an RFC 4514 string, falling back to the whole string.
pub fn cn_of(dn: &str) -> String {
    for part in dn.split(',') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("CN=") {
            return v.replace("\\", "");
        }
    }
    dn.to_string()
}

// =============================================================================================
// Subject alternative names
// =============================================================================================

pub enum San {
    Dns(String),
    Ip(std::net::IpAddr),
    Email(String),
    Uri(String),
}

pub fn parse_san(input: &str) -> Res<San> {
    let s = input.trim();
    let (kind, value) = match s.split_once(':') {
        Some((k, v)) if matches!(k.to_ascii_lowercase().as_str(), "dns" | "ip" | "email" | "uri" | "rfc822") => (k.to_ascii_lowercase(), v.trim()),
        _ => (String::new(), s),
    };
    if value.is_empty() {
        return Err("empty subject alternative name".into());
    }
    let check_ascii = |v: &str| -> Res<String> {
        if v.is_ascii() {
            Ok(v.to_string())
        } else {
            Err(format!("'{v}' contains non-ASCII characters; use its punycode (xn--) form"))
        }
    };
    match kind.as_str() {
        "ip" => value.parse().map(San::Ip).map_err(|_| format!("'{value}' is not a valid IP address")),
        "email" | "rfc822" => Ok(San::Email(check_ascii(value)?)),
        "uri" => Ok(San::Uri(check_ascii(value)?)),
        "dns" => validate_dns(value).map(San::Dns),
        _ => {
            if let Ok(ip) = value.parse() {
                Ok(San::Ip(ip))
            } else if value.contains("://") {
                Ok(San::Uri(check_ascii(value)?))
            } else if value.contains('@') {
                Ok(San::Email(check_ascii(value)?))
            } else {
                validate_dns(value).map(San::Dns)
            }
        }
    }
}

fn validate_dns(v: &str) -> Res<String> {
    let ok = v.is_ascii()
        && !v.is_empty()
        && v.len() <= 253
        && v.split('.').enumerate().all(|(i, label)| {
            (label == "*" && i == 0)
                || (!label.is_empty() && label.len() <= 63 && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        });
    if ok {
        Ok(v.to_ascii_lowercase())
    } else {
        Err(format!("'{v}' is not a valid DNS name"))
    }
}

pub fn san_to_string(san: &San) -> String {
    match san {
        San::Dns(v) => format!("DNS:{v}"),
        San::Ip(v) => format!("IP:{v}"),
        San::Email(v) => format!("email:{v}"),
        San::Uri(v) => format!("URI:{v}"),
    }
}

// =============================================================================================
// Extension builders
// =============================================================================================

pub struct Extension {
    pub oid: Vec<u64>,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl Extension {
    fn new(arcs: &[u64], critical: bool, value: Vec<u8>) -> Self {
        Extension { oid: arcs.to_vec(), critical, value }
    }
}

pub fn ext_basic_constraints(is_ca: bool, path_len: Option<u32>) -> Extension {
    let value = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            if is_ca {
                w.next().write_bool(true);
                if let Some(p) = path_len {
                    w.next().write_u32(p);
                }
            }
        })
    });
    Extension::new(oids::EXT_BASIC_CONSTRAINTS, true, value)
}

const KEY_USAGE_BITS: &[(&str, usize)] = &[
    ("digitalSignature", 0),
    ("nonRepudiation", 1),
    ("contentCommitment", 1),
    ("keyEncipherment", 2),
    ("dataEncipherment", 3),
    ("keyAgreement", 4),
    ("keyCertSign", 5),
    ("cRLSign", 6),
    ("encipherOnly", 7),
    ("decipherOnly", 8),
];

pub fn ext_key_usage(usages: &[String]) -> Res<Option<Extension>> {
    let mut bits = [0u8; 2];
    let mut highest = None;
    for u in usages {
        let (_, bit) = KEY_USAGE_BITS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(u.trim()))
            .ok_or_else(|| format!("unknown key usage '{u}'"))?;
        bits[bit / 8] |= 0x80 >> (bit % 8);
        highest = Some(highest.map_or(*bit, |h: usize| h.max(*bit)));
    }
    let Some(highest) = highest else { return Ok(None) };
    let bit_len = highest + 1;
    let value = yasna::construct_der(|w| w.write_bitvec_bytes(&bits[..bit_len.div_ceil(8)], bit_len));
    Ok(Some(Extension::new(oids::EXT_KEY_USAGE, true, value)))
}

pub fn ext_extended_key_usage(ids: &[String]) -> Res<Option<Extension>> {
    if ids.is_empty() {
        return Ok(None);
    }
    let mut arcs_list = Vec::new();
    for id in ids {
        let arcs = oids::eku_from_id(id)
            .map(|a| a.to_vec())
            .or_else(|| oids::parse_oid_str(id))
            .ok_or_else(|| format!("unknown extended key usage '{id}'"))?;
        if !arcs_list.contains(&arcs) {
            arcs_list.push(arcs);
        }
    }
    let value = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for a in &arcs_list {
                w.next().write_oid(&oid(a));
            }
        })
    });
    Ok(Some(Extension::new(oids::EXT_EXTENDED_KEY_USAGE, false, value)))
}

pub fn ext_subject_alt_name(sans: &[San]) -> Option<Extension> {
    if sans.is_empty() {
        return None;
    }
    let value = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for san in sans {
                match san {
                    San::Email(v) => w.next().write_tagged_implicit(Tag::context(1), |w| w.write_ia5_string(v)),
                    San::Dns(v) => w.next().write_tagged_implicit(Tag::context(2), |w| w.write_ia5_string(v)),
                    San::Uri(v) => w.next().write_tagged_implicit(Tag::context(6), |w| w.write_ia5_string(v)),
                    San::Ip(ip) => {
                        let bytes = match ip {
                            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                        };
                        w.next().write_tagged_implicit(Tag::context(7), |w| w.write_bytes(&bytes))
                    }
                }
            }
        })
    });
    Some(Extension::new(oids::EXT_SUBJECT_ALT_NAME, false, value))
}

/// RFC 5280 method 1 key identifier: SHA-1 of the subjectPublicKey BIT STRING contents.
pub fn key_identifier(spki: &[u8]) -> Res<Vec<u8>> {
    let (_, _, bits) = keys::split_spki(spki)?;
    Ok(sha1(&bits))
}

pub fn ext_subject_key_id(ski: &[u8]) -> Extension {
    Extension::new(oids::EXT_SUBJECT_KEY_ID, false, yasna::construct_der(|w| w.write_bytes(ski)))
}

pub fn ext_authority_key_id(keyid: &[u8]) -> Extension {
    let value = yasna::construct_der(|w| {
        w.write_sequence(|w| w.next().write_tagged_implicit(Tag::context(0), |w| w.write_bytes(keyid)))
    });
    Extension::new(oids::EXT_AUTHORITY_KEY_ID, false, value)
}

fn write_extensions(w: DERWriter, exts: &[Extension]) {
    w.write_sequence(|w| {
        for ext in exts {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(&ext.oid));
                if ext.critical {
                    w.next().write_bool(true);
                }
                w.next().write_bytes(&ext.value);
            });
        }
    });
}

// =============================================================================================
// Certificate builder
// =============================================================================================

pub struct CertTemplate {
    pub serial: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub spki_der: Vec<u8>,
    pub extensions: Vec<Extension>,
}

/// The CA that signs a certificate/CRL: its key and its own certificate (absent when self-signing).
pub struct Signer<'a> {
    pub key: &'a PrivateKey,
    pub cert_der: Option<&'a [u8]>,
    pub sig_alg: SigAlg,
}

impl Signer<'_> {
    /// (issuer Name DER, authority key identifier)
    fn issuer_name_and_keyid(&self, self_subject: &[u8], self_spki: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
        match self.cert_der {
            None => Ok((self_subject.to_vec(), key_identifier(self_spki)?)),
            Some(der) => {
                let (_, cert) = X509Certificate::from_der(der).map_err(|err| format!("invalid CA certificate: {err}"))?;
                let ski = cert
                    .iter_extensions()
                    .find_map(|ext| match ext.parsed_extension() {
                        ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                        _ => None,
                    })
                    .map(Ok)
                    .unwrap_or_else(|| key_identifier(cert.public_key().raw))?;
                Ok((cert.subject().as_raw().to_vec(), ski))
            }
        }
    }
}

/// Signs `tbs` (DER) and wraps it into the outer SIGNED{} structure.
fn sign_structure(tbs: &[u8], signer: &Signer) -> Res<Vec<u8>> {
    let signature = signer.key.sign(signer.sig_alg, tbs)?;
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(tbs);
            signer.sig_alg.write_algorithm_id(w.next());
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        })
    }))
}

/// Builds and signs an X.509 v3 certificate. Adds SKI and AKI automatically.
pub fn build_certificate(mut t: CertTemplate, signer: &Signer) -> Res<Vec<u8>> {
    if t.not_after <= t.not_before {
        return Err("validity must be at least one day".into());
    }
    let (issuer_der, aki) = signer.issuer_name_and_keyid(&t.subject_der, &t.spki_der)?;
    let ski = key_identifier(&t.spki_der)?;
    t.extensions.retain(|e| e.oid != oids::EXT_SUBJECT_KEY_ID && e.oid != oids::EXT_AUTHORITY_KEY_ID);
    t.extensions.push(ext_subject_key_id(&ski));
    t.extensions.push(ext_authority_key_id(&aki));
    let tbs = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_tagged(Tag::context(0), |w| w.write_u8(2));
            w.next().write_bigint_bytes(&t.serial, true);
            signer.sig_alg.write_algorithm_id(w.next());
            w.next().write_der(&issuer_der);
            w.next().write_sequence(|w| {
                w.next().write_der(&asn1_time_der(t.not_before));
                w.next().write_der(&asn1_time_der(t.not_after));
            });
            w.next().write_der(&t.subject_der);
            w.next().write_der(&t.spki_der);
            w.next().write_tagged(Tag::context(3), |w| write_extensions(w, &t.extensions));
        })
    });
    sign_structure(&tbs, signer)
}

/// Builds a PKCS#10 certificate signing request.
pub fn build_csr(subject_der: &[u8], key: &PrivateKey, sig_alg: SigAlg, extensions: &[Extension]) -> Res<Vec<u8>> {
    let spki = key.public_key_der()?;
    let info = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_der(subject_der);
            w.next().write_der(&spki);
            w.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set(|w| {
                    if !extensions.is_empty() {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(oids::EXTENSION_REQUEST));
                            w.next().write_set(|w| write_extensions(w.next(), extensions));
                        });
                    }
                })
            });
        })
    });
    sign_structure(&info, &Signer { key, cert_der: None, sig_alg })
}

fn reason_code(reason: &str) -> Res<Option<i64>> {
    Ok(match reason.trim() {
        "" | "unspecified" => None,
        "keyCompromise" => Some(1),
        "cACompromise" => Some(2),
        "affiliationChanged" => Some(3),
        "superseded" => Some(4),
        "cessationOfOperation" => Some(5),
        "certificateHold" => Some(6),
        "privilegeWithdrawn" => Some(9),
        "aACompromise" => Some(10),
        other => return Err(format!("unknown revocation reason '{other}'")),
    })
}

fn reason_name(code: u8) -> &'static str {
    match code {
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unspecified",
    }
}

fn parse_day(date: &str) -> Res<i64> {
    let d = chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d").map_err(|_| format!("'{date}' is not a YYYY-MM-DD date"))?;
    Ok(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp())
}

/// Builds and signs an X.509 v2 CRL with CRL Number and Authority Key Identifier extensions.
pub fn build_crl(signer: &Signer, this_update: i64, next_update: i64, crl_number: u64, revoked: &[RevokedCertEntry]) -> Res<Vec<u8>> {
    let ca_der = signer.cert_der.ok_or("a CRL must be signed by a CA certificate")?;
    let (issuer_der, aki) = signer.issuer_name_and_keyid(&[], &[])?;
    let _ = ca_der;
    let mut entries = Vec::new();
    for r in revoked {
        let serial = parse_hex_serial(&r.serial_number)?;
        let when = parse_day(&r.revocation_date)?;
        entries.push((serial, when, reason_code(&r.reason)?));
    }
    let tbs = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(1);
            signer.sig_alg.write_algorithm_id(w.next());
            w.next().write_der(&issuer_der);
            w.next().write_der(&asn1_time_der(this_update));
            w.next().write_der(&asn1_time_der(next_update));
            if !entries.is_empty() {
                w.next().write_sequence(|w| {
                    for (serial, when, reason) in &entries {
                        w.next().write_sequence(|w| {
                            w.next().write_bigint_bytes(serial, true);
                            w.next().write_der(&asn1_time_der(*when));
                            if let Some(code) = reason {
                                w.next().write_sequence(|w| {
                                    w.next().write_sequence(|w| {
                                        w.next().write_oid(&oid(oids::EXT_CRL_REASON));
                                        w.next().write_bytes(&yasna::construct_der(|w| w.write_enum(*code)));
                                    });
                                });
                            }
                        });
                    }
                });
            }
            w.next().write_tagged(Tag::context(0), |w| {
                write_extensions(
                    w,
                    &[
                        ext_authority_key_id(&aki),
                        Extension::new(oids::EXT_CRL_NUMBER, false, yasna::construct_der(|w| w.write_u64(crl_number))),
                    ],
                )
            });
        })
    });
    sign_structure(&tbs, signer)
}

// =============================================================================================
// Parsing
// =============================================================================================

fn arcs_of(oid: &x509_parser::der_parser::oid::Oid) -> Vec<u64> {
    oid.iter().map(|i| i.collect()).unwrap_or_default()
}

fn general_name_to_string(gn: &GeneralName) -> String {
    match gn {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::IPAddress(b) => match b.len() {
            4 => format!("IP:{}", std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            16 => {
                let arr: [u8; 16] = (*b).try_into().unwrap();
                format!("IP:{}", std::net::Ipv6Addr::from(arr))
            }
            _ => format!("IP:{}", hex::encode(b)),
        },
        GeneralName::DirectoryName(n) => format!("DirName:{}", name_to_string(n)),
        GeneralName::RegisteredID(o) => format!("RID:{o}"),
        GeneralName::OtherName(o, _) => format!("othername:{o}"),
        other => format!("{other:?}"),
    }
}

fn key_usage_names(ku: &KeyUsage) -> Vec<String> {
    let mut v = Vec::new();
    let pairs: [(bool, &str); 9] = [
        (ku.digital_signature(), "Digital Signature"),
        (ku.non_repudiation(), "Non Repudiation"),
        (ku.key_encipherment(), "Key Encipherment"),
        (ku.data_encipherment(), "Data Encipherment"),
        (ku.key_agreement(), "Key Agreement"),
        (ku.key_cert_sign(), "Certificate Sign"),
        (ku.crl_sign(), "CRL Sign"),
        (ku.encipher_only(), "Encipher Only"),
        (ku.decipher_only(), "Decipher Only"),
    ];
    for (set, name) in pairs {
        if set {
            v.push(name.to_string());
        }
    }
    v
}

fn eku_names(eku: &ExtendedKeyUsage) -> Vec<String> {
    let mut v = Vec::new();
    if eku.any {
        v.push(oids::eku_name(oids::ANY_EXTENDED_KEY_USAGE));
    }
    for (set, arcs) in [
        (eku.server_auth, oids::EKU_SERVER_AUTH),
        (eku.client_auth, oids::EKU_CLIENT_AUTH),
        (eku.code_signing, oids::EKU_CODE_SIGNING),
        (eku.email_protection, oids::EKU_EMAIL_PROTECTION),
        (eku.time_stamping, oids::EKU_TIME_STAMPING),
        (eku.ocsp_signing, oids::EKU_OCSP_SIGNING),
    ] {
        if set {
            v.push(oids::eku_name(arcs));
        }
    }
    for o in &eku.other {
        v.push(oids::eku_name(&arcs_of(o)));
    }
    v
}

fn describe_extension(ext: &X509Extension) -> X509ExtensionInfo {
    let arcs = arcs_of(&ext.oid);
    let value = match ext.parsed_extension() {
        ParsedExtension::BasicConstraints(bc) => {
            if bc.ca {
                match bc.path_len_constraint {
                    Some(p) => format!("CA:TRUE, pathlen:{p}"),
                    None => "CA:TRUE".into(),
                }
            } else {
                "CA:FALSE".into()
            }
        }
        ParsedExtension::KeyUsage(ku) => key_usage_names(ku).join(", "),
        ParsedExtension::ExtendedKeyUsage(eku) => eku_names(eku).join(", "),
        ParsedExtension::SubjectAlternativeName(san) => san.general_names.iter().map(general_name_to_string).collect::<Vec<_>>().join(", "),
        ParsedExtension::IssuerAlternativeName(ian) => ian.general_names.iter().map(general_name_to_string).collect::<Vec<_>>().join(", "),
        ParsedExtension::SubjectKeyIdentifier(k) => colon_hex(k.0),
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            let mut parts = Vec::new();
            if let Some(k) = &aki.key_identifier {
                parts.push(format!("keyid:{}", colon_hex(k.0)));
            }
            if let Some(names) = &aki.authority_cert_issuer {
                parts.push(names.iter().map(general_name_to_string).collect::<Vec<_>>().join(", "));
            }
            if let Some(serial) = aki.authority_cert_serial {
                parts.push(format!("serial:{}", colon_hex(serial)));
            }
            parts.join(", ")
        }
        ParsedExtension::CRLDistributionPoints(dps) => dps
            .points
            .iter()
            .flat_map(|p| match &p.distribution_point {
                Some(DistributionPointName::FullName(names)) => names.iter().map(general_name_to_string).collect::<Vec<_>>(),
                Some(DistributionPointName::NameRelativeToCRLIssuer(_)) => vec!["(relative name)".into()],
                None => vec![],
            })
            .collect::<Vec<_>>()
            .join(", "),
        ParsedExtension::AuthorityInfoAccess(aia) => aia
            .accessdescs
            .iter()
            .map(|ad| {
                let method = match arcs_of(&ad.access_method).as_slice() {
                    [1, 3, 6, 1, 5, 5, 7, 48, 1] => "OCSP".to_string(),
                    [1, 3, 6, 1, 5, 5, 7, 48, 2] => "CA Issuers".to_string(),
                    other => oids::oid_str(other),
                };
                format!("{method} - {}", general_name_to_string(&ad.access_location))
            })
            .collect::<Vec<_>>()
            .join(", "),
        ParsedExtension::CertificatePolicies(policies) => policies
            .iter()
            .map(|p| oids::oid_str(&arcs_of(&p.policy_id)))
            .collect::<Vec<_>>()
            .join(", "),
        ParsedExtension::CRLNumber(n) => n.to_string(),
        ParsedExtension::ReasonCode(r) => reason_name(r.0).to_string(),
        ParsedExtension::NSCertType(t) => format!("{t}"),
        ParsedExtension::NsCertComment(c) => c.to_string(),
        ParsedExtension::SCT(scts) => format!("{} signed certificate timestamp(s)", scts.len()),
        ParsedExtension::NameConstraints(nc) => {
            let fmt = |subtrees: &Option<Vec<GeneralSubtree>>| {
                subtrees
                    .as_ref()
                    .map(|s| s.iter().map(|t| general_name_to_string(&t.base)).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()
            };
            format!("Permitted: [{}] Excluded: [{}]", fmt(&nc.permitted_subtrees), fmt(&nc.excluded_subtrees))
        }
        _ => {
            let shown = &ext.value[..ext.value.len().min(48)];
            format!("{}{}", colon_hex(shown), if ext.value.len() > 48 { "…" } else { "" })
        }
    };
    X509ExtensionInfo { oid: oids::oid_str(&arcs), name: oids::extension_name(&arcs).to_string(), critical: ext.critical, value }
}

/// Parses a DER certificate into the display model, with real SHA-256/SHA-1/MD5 fingerprints.
pub fn parse_certificate(der: &[u8]) -> Res<CertificateInfo> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|err| format!("not a valid X.509 certificate: {err}"))?;
    let spki = cert.public_key().raw;
    let pk = keys::public_key_info(spki).unwrap_or(keys::PublicKeyInfo {
        algorithm: "unknown".into(),
        key_size: 0,
        curve: None,
        is_post_quantum: false,
    });
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let mut info = CertificateInfo {
        version: (cert.version().0 + 1) as u8,
        serial_number: upper_hex(cert.raw_serial()),
        signature_algorithm: oids::signature_algorithm_name(&arcs_of(&cert.signature_algorithm.algorithm)),
        subject: name_to_string(cert.subject()),
        issuer: name_to_string(cert.issuer()),
        valid_from: fmt_ts(not_before),
        valid_to: fmt_ts(not_after),
        not_before,
        not_after,
        days_remaining: (not_after - now_ts()).div_euclid(86_400),
        public_key_algorithm: pk.algorithm,
        key_size: pk.key_size,
        curve: pk.curve,
        sha256_fingerprint: colon_hex(&sha256(der)),
        sha1_fingerprint: colon_hex(&sha1(der)),
        md5_fingerprint: colon_hex(&md5(der)),
        pem: to_pem("CERTIFICATE", der),
        ..Default::default()
    };
    for ext in cert.iter_extensions() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                info.is_ca = bc.ca;
                info.path_len = bc.path_len_constraint;
            }
            ParsedExtension::KeyUsage(ku) => info.key_usage = key_usage_names(ku),
            ParsedExtension::ExtendedKeyUsage(eku) => info.extended_key_usage = eku_names(eku),
            ParsedExtension::SubjectAlternativeName(san) => {
                info.sans = san.general_names.iter().map(general_name_to_string).collect();
            }
            ParsedExtension::SubjectKeyIdentifier(k) => info.subject_key_id = Some(colon_hex(k.0)),
            ParsedExtension::AuthorityKeyIdentifier(aki) => info.authority_key_id = aki.key_identifier.as_ref().map(|k| colon_hex(k.0)),
            _ => {}
        }
        info.extensions.push(describe_extension(ext));
    }
    // v1 certificates have no BasicConstraints; treat self-signed v1 roots as CAs.
    let same_name = cert.subject().as_raw() == cert.issuer().as_raw();
    info.self_signed = same_name && verify_certificate_signature(der, spki).unwrap_or(false);
    if info.version == 1 && info.self_signed {
        info.is_ca = true;
    }
    Ok(info)
}

/// Verifies that the certificate `der` was signed by the key in `issuer_spki`.
pub fn verify_certificate_signature(der: &[u8], issuer_spki: &[u8]) -> Res<bool> {
    let (_, cert) = X509Certificate::from_der(der).map_err(e)?;
    let alg = SigAlg::from_oid(&arcs_of(&cert.signature_algorithm.algorithm))
        .ok_or_else(|| format!("unsupported signature algorithm {}", cert.signature_algorithm.algorithm))?;
    keys::verify(issuer_spki, alg, cert.tbs_certificate.as_ref(), &cert.signature_value.data)
}

pub struct CertSummary {
    pub subject_raw: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    pub spki: Vec<u8>,
}

pub fn cert_summary(der: &[u8]) -> Res<CertSummary> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|err| format!("not a valid X.509 certificate: {err}"))?;
    Ok(CertSummary {
        subject_raw: cert.subject().as_raw().to_vec(),
        issuer_raw: cert.issuer().as_raw().to_vec(),
        spki: cert.public_key().raw.to_vec(),
    })
}

/// True if `child` was issued by `parent` (name match plus signature check when possible).
pub fn issued_by(child: &[u8], parent: &[u8]) -> bool {
    match (cert_summary(child), cert_summary(parent)) {
        (Ok(c), Ok(p)) => c.issuer_raw == p.subject_raw && verify_certificate_signature(child, &p.spki).unwrap_or(true),
        _ => false,
    }
}

/// Orders a set of certificates into chains: picks the leaf (the cert that is nobody's issuer,
/// or the one matching `leaf_hint`), then walks issuers upward. Unused certs are returned too.
pub fn build_chain(leaf: &[u8], pool: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut chain = vec![leaf.to_vec()];
    let mut used = vec![false; pool.len()];
    loop {
        let current = chain.last().unwrap().clone();
        let Ok(cur) = cert_summary(&current) else { break };
        if cur.issuer_raw == cur.subject_raw {
            break; // self-signed root
        }
        let next = pool
            .iter()
            .enumerate()
            .find(|(i, c)| !used[*i] && c.as_slice() != current.as_slice() && !chain.contains(c) && issued_by(&current, c));
        match next {
            Some((i, c)) => {
                used[i] = true;
                chain.push(c.clone());
            }
            None => break,
        }
        if chain.len() > 16 {
            break;
        }
    }
    chain
}

/// Orders an unordered bundle so that it starts at the leaf.
pub fn order_bundle(certs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if certs.len() <= 1 {
        return certs.to_vec();
    }
    let leaf = certs
        .iter()
        .find(|c| !certs.iter().any(|other| other.as_slice() != c.as_slice() && issued_by(other, c)))
        .unwrap_or(&certs[0]);
    let mut chain = build_chain(leaf, certs);
    for c in certs {
        if !chain.contains(c) {
            chain.push(c.clone());
        }
    }
    chain
}

/// Extracts certificates from PEM text (one or many), a DER certificate, or a PKCS#7 bundle.
pub fn certificates_from_bytes(data: &[u8]) -> Res<Vec<Vec<u8>>> {
    if looks_textual(data) {
        let text = String::from_utf8_lossy(data);
        let mut out = Vec::new();
        for block in pem_blocks(&text) {
            match block.tag.as_str() {
                "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => out.push(block.der),
                "PKCS7" | "CMS" => out.extend(crate::cms::certificates_from_pkcs7(&block.der)?),
                _ => {}
            }
        }
        if out.is_empty() {
            // Bare base64 of a DER certificate.
            if let Ok(der) = unb64(text.trim())
                && X509Certificate::from_der(&der).is_ok() {
                    return Ok(vec![der]);
                }
            return Err("no certificate found in the data".into());
        }
        return Ok(out);
    }
    if X509Certificate::from_der(data).is_ok() {
        return Ok(vec![data.to_vec()]);
    }
    let certs = crate::cms::certificates_from_pkcs7(data)?;
    if certs.is_empty() {
        return Err("no certificate found in the data".into());
    }
    Ok(certs)
}

/// Parses a PKCS#10 CSR (DER) and verifies its proof-of-possession signature.
pub fn parse_csr(der: &[u8]) -> Res<CsrInfo> {
    let (_, csr) = X509CertificationRequest::from_der(der).map_err(|err| format!("not a valid PKCS#10 request: {err}"))?;
    let info = &csr.certification_request_info;
    let spki = info.subject_pki.raw;
    let pk = keys::public_key_info(spki)?;
    let alg = SigAlg::from_oid(&arcs_of(&csr.signature_algorithm.algorithm));
    let signature_valid = match alg {
        Some(alg) => keys::verify(spki, alg, info.raw, &csr.signature_value.data).unwrap_or(false),
        None => false,
    };
    let mut sans = Vec::new();
    let mut extensions = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                sans = san.general_names.iter().map(general_name_to_string).collect();
            }
        }
    }
    for attr in info.iter_attributes() {
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(req) = attr.parsed_attribute() {
            for ext in &req.extensions {
                extensions.push(describe_extension(ext));
            }
        }
    }
    Ok(CsrInfo {
        subject: name_to_string(&info.subject),
        public_key_algorithm: pk.algorithm,
        key_size: pk.key_size,
        curve: pk.curve,
        signature_algorithm: oids::signature_algorithm_name(&arcs_of(&csr.signature_algorithm.algorithm)),
        signature_valid,
        sans,
        extensions,
        public_key_sha256: colon_hex(&sha256(spki)),
        pem: to_pem("CERTIFICATE REQUEST", der),
    })
}

/// Raw pieces of a CSR needed to issue a certificate from it.
pub struct CsrParts {
    pub subject_der: Vec<u8>,
    pub spki: Vec<u8>,
    pub sans: Vec<String>,
}

pub fn csr_parts(der: &[u8]) -> Res<CsrParts> {
    let info = parse_csr(der)?;
    if !info.signature_valid {
        return Err("the CSR signature is invalid (the request was altered or is corrupt)".into());
    }
    let (_, csr) = X509CertificationRequest::from_der(der).map_err(e)?;
    Ok(CsrParts {
        subject_der: csr.certification_request_info.subject.as_raw().to_vec(),
        spki: csr.certification_request_info.subject_pki.raw.to_vec(),
        sans: info.sans,
    })
}

/// Accepts a CSR as PEM or DER bytes and returns the DER.
pub fn csr_der_from_bytes(data: &[u8]) -> Res<Vec<u8>> {
    if looks_textual(data) {
        let text = String::from_utf8_lossy(data);
        for block in pem_blocks(&text) {
            if block.tag.contains("CERTIFICATE REQUEST") {
                return Ok(block.der);
            }
        }
        if let Ok(der) = unb64(text.trim())
            && X509CertificationRequest::from_der(&der).is_ok() {
                return Ok(der);
            }
        return Err("no PKCS#10 certificate request found (expected -----BEGIN CERTIFICATE REQUEST-----)".into());
    }
    Ok(data.to_vec())
}

/// Parses a CRL; if `issuer_spki` is given its signature is verified.
pub fn parse_crl(der: &[u8], issuer_spki: Option<&[u8]>) -> Res<CrlInfo> {
    let (_, crl) = CertificateRevocationList::from_der(der).map_err(|err| format!("not a valid X.509 CRL: {err}"))?;
    let revoked = crl
        .iter_revoked_certificates()
        .map(|r| RevokedCertEntry {
            serial_number: upper_hex(r.raw_serial()),
            revocation_date: fmt_date(r.revocation_date.timestamp()),
            reason: r.reason_code().map(|(_, c)| reason_name(c.0).to_string()).unwrap_or_else(|| "unspecified".into()),
        })
        .collect();
    let signature_valid = issuer_spki.map(|spki| {
        SigAlg::from_oid(&arcs_of(&crl.signature_algorithm.algorithm))
            .map(|alg| keys::verify(spki, alg, crl.tbs_cert_list.as_ref(), &crl.signature_value.data).unwrap_or(false))
            .unwrap_or(false)
    });
    Ok(CrlInfo {
        issuer: name_to_string(crl.issuer()),
        this_update: fmt_ts(crl.last_update().timestamp()),
        next_update: crl.next_update().map(|t| fmt_ts(t.timestamp())).unwrap_or_else(|| "—".into()),
        crl_number: crl.crl_number().map(|n| n.to_string()),
        signature_algorithm: oids::signature_algorithm_name(&arcs_of(&crl.signature_algorithm.algorithm)),
        revoked_entries: revoked,
        extensions: crl.extensions().iter().map(describe_extension).collect(),
        sha256_fingerprint: colon_hex(&sha256(der)),
        pem: to_pem("X509 CRL", der),
        signature_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_round_trip_with_escapes_and_multivalue() {
        let dn = parse_dn(r#"CN=Acme\, Inc.+UID=42, OU=Ops, OU=Edge, DC=example, DC=com, C=US"#).unwrap();
        assert_eq!(dn.len(), 6);
        assert_eq!(dn[0].len(), 2);
        assert_eq!(dn[0][0].1, "Acme, Inc.");
        let der = encode_dn(&dn);
        let rendered = name_der_to_string(&der);
        // DER sorts the attributes of a multi-valued RDN, so UID precedes CN.
        assert_eq!(rendered, r"UID=42+CN=Acme\, Inc., OU=Ops, OU=Edge, DC=example, DC=com, C=US");
        assert!(parse_dn("CN").is_err());
        assert!(parse_dn("C=USA").is_err());
        assert!(parse_dn("FOO=bar").is_err());
        assert_eq!(parse_dn(r#"CN="quoted, value""#).unwrap()[0][0].1, "quoted, value");
    }

    #[test]
    fn san_parsing() {
        assert!(matches!(parse_san("10.0.0.1").unwrap(), San::Ip(_)));
        assert!(matches!(parse_san("DNS:*.example.com").unwrap(), San::Dns(_)));
        assert!(matches!(parse_san("ops@example.com").unwrap(), San::Email(_)));
        assert!(matches!(parse_san("https://example.com/x").unwrap(), San::Uri(_)));
        assert!(parse_san("bad host!").is_err());
        assert!(parse_san("bücher.de").is_err());
    }

    #[test]
    fn self_signed_and_ca_issued_certificates_verify() {
        let ca_key = PrivateKey::generate("ECDSA", 0, Some("P-384")).unwrap();
        let ca_spki = ca_key.public_key_der().unwrap();
        let ca_dn = encode_dn(&parse_dn("CN=Test Root, OU=A, OU=B, O=Acme, C=US").unwrap());
        let now = now_ts();
        let ca_der = build_certificate(
            CertTemplate {
                serial: random_serial(),
                subject_der: ca_dn.clone(),
                not_before: now,
                not_after: now + 86_400 * 365,
                spki_der: ca_spki.clone(),
                extensions: vec![ext_basic_constraints(true, Some(1)), ext_key_usage(&["keyCertSign".into(), "cRLSign".into()]).unwrap().unwrap()],
            },
            &Signer { key: &ca_key, cert_der: None, sig_alg: ca_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let ca_info = parse_certificate(&ca_der).unwrap();
        assert!(ca_info.self_signed && ca_info.is_ca);
        assert_eq!(ca_info.path_len, Some(1));
        assert_eq!(ca_info.subject, "CN=Test Root, OU=A, OU=B, O=Acme, C=US");
        assert_eq!(ca_info.key_usage, vec!["Certificate Sign", "CRL Sign"]);

        let leaf_key = PrivateKey::generate("RSA", 2048, None).unwrap();
        let sans = vec![parse_san("example.com").unwrap(), parse_san("127.0.0.1").unwrap()];
        let leaf_der = build_certificate(
            CertTemplate {
                serial: random_serial(),
                subject_der: encode_dn(&parse_dn("CN=example.com").unwrap()),
                not_before: now,
                not_after: now + 86_400 * 30,
                spki_der: leaf_key.public_key_der().unwrap(),
                extensions: vec![
                    ext_basic_constraints(false, None),
                    ext_extended_key_usage(&["serverAuth".into()]).unwrap().unwrap(),
                    ext_subject_alt_name(&sans).unwrap(),
                ],
            },
            &Signer { key: &ca_key, cert_der: Some(&ca_der), sig_alg: ca_key.default_sig_alg(None).unwrap() },
        )
        .unwrap();
        let leaf = parse_certificate(&leaf_der).unwrap();
        assert_eq!(leaf.issuer, ca_info.subject);
        assert_eq!(leaf.sans, vec!["DNS:example.com", "IP:127.0.0.1"]);
        assert_eq!(leaf.authority_key_id, ca_info.subject_key_id);
        assert!(!leaf.self_signed);
        assert!(verify_certificate_signature(&leaf_der, &ca_spki).unwrap());
        assert_eq!(build_chain(&leaf_der, std::slice::from_ref(&ca_der)).len(), 2);
        assert_eq!(order_bundle(&[ca_der.clone(), leaf_der.clone()])[0], leaf_der);

        // CSR round trip
        let csr = build_csr(&encode_dn(&parse_dn("CN=req").unwrap()), &leaf_key, SigAlg::Rsa(crate::pbe::HashAlg::Sha256), &[ext_subject_alt_name(&sans).unwrap()]).unwrap();
        let csr_info = parse_csr(&csr).unwrap();
        assert!(csr_info.signature_valid);
        assert_eq!(csr_info.sans.len(), 2);

        // CRL round trip
        let crl = build_crl(
            &Signer { key: &ca_key, cert_der: Some(&ca_der), sig_alg: ca_key.default_sig_alg(None).unwrap() },
            now,
            now + 86_400,
            7,
            &[RevokedCertEntry { serial_number: "0A:0B".into(), revocation_date: "2026-01-02".into(), reason: "keyCompromise".into() }],
        )
        .unwrap();
        let crl_info = parse_crl(&crl, Some(&ca_spki)).unwrap();
        assert_eq!(crl_info.signature_valid, Some(true));
        assert_eq!(crl_info.crl_number.as_deref(), Some("7"));
        assert_eq!(crl_info.revoked_entries[0].serial_number, "0A0B");
        assert_eq!(crl_info.revoked_entries[0].reason, "keyCompromise");
    }
}
