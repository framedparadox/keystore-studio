//! PKCS#12 / PFX (RFC 7292) codec compatible with OpenSSL 1.x/3.x, Java keytool and Windows.
//!
//! Reading accepts BER, SHA-1/SHA-2 MACs, PBES2 and the legacy PKCS#12 PBE ciphers (3DES, RC2),
//! key bags, shrouded key bags, certificate bags, Java secret bags and nested safe contents.
//! Keys are matched to certificates by public key (falling back to localKeyId/friendlyName).
//!
//! Writing follows modern keytool/OpenSSL 3 defaults: certificates in a PBES2/AES-256-CBC
//! encrypted safe, keys as PBES2-shrouded bags, HMAC-SHA256 MAC, 10 000 iterations. Trusted
//! certificates carry Oracle's trustedKeyUsage attribute so keytool lists them as
//! `trustedCertEntry`; secret keys use Java's SecretBag layout.

use crate::entry;
use crate::keys::{self, PrivateKey};
use crate::model::KeystoreEntry;
use crate::oids::{self, oid};
use crate::pbe::{self, HashAlg};
use crate::util::*;
use crate::x509;
use yasna::{DERWriter, Tag};

const WRONG_PASSWORD: &str = "keystore password incorrect or file corrupt";

#[derive(Default, Clone)]
struct Attrs {
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
    trusted: bool,
}

struct RawBag {
    bag_id: Vec<u64>,
    value: Vec<u8>,
    attrs: Attrs,
}

#[derive(Default)]
struct Collected {
    keys: Vec<(Vec<u8>, Attrs)>,
    certs: Vec<(Vec<u8>, Attrs)>,
    secrets: Vec<(String, Vec<u8>, Attrs)>,
}

/// Cheap structural check: SEQUENCE { INTEGER 3, SEQUENCE { OID pkcs7-data | signedData … } }.
pub fn looks_like_pkcs12(bytes: &[u8]) -> bool {
    yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            let v = r.next().read_u8()?;
            let ct = r.next().read_sequence(|r| {
                let o = r.next().read_oid()?;
                r.next().read_der()?;
                Ok(o)
            })?;
            let _ = r.read_optional(|r| r.read_der())?;
            Ok(v == 3 && (ct.components().as_slice() == oids::PKCS7_DATA || ct.components().as_slice() == oids::PKCS7_SIGNED_DATA))
        })
    })
    .unwrap_or(false)
}

fn read_attrs(r: yasna::BERReader) -> yasna::ASN1Result<Attrs> {
    let mut attrs = Attrs::default();
    r.read_set_of(|r| {
        r.read_sequence(|r| {
            let id = r.next().read_oid()?;
            let id = id.components().as_slice().to_vec();
            r.next().read_set_of(|r| {
                if id == oids::FRIENDLY_NAME {
                    attrs.friendly_name = Some(r.read_bmp_string()?);
                } else if id == oids::LOCAL_KEY_ID {
                    attrs.local_key_id = Some(r.read_bytes()?);
                } else {
                    if id == oids::ORACLE_TRUSTED_KEY_USAGE {
                        attrs.trusted = true;
                    }
                    r.read_der()?;
                }
                Ok(())
            })
        })
    })?;
    Ok(attrs)
}

fn read_safe_contents(der: &[u8]) -> Res<Vec<RawBag>> {
    yasna::parse_ber(der, |r| {
        let mut bags = Vec::new();
        r.read_sequence_of(|r| {
            r.read_sequence(|r| {
                let bag_id = r.next().read_oid()?.components().to_vec();
                let value = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
                let attrs = r.read_optional(read_attrs)?.unwrap_or_default();
                bags.push(RawBag { bag_id, value, attrs });
                Ok(())
            })
        })?;
        Ok(bags)
    })
    .map_err(|err| format!("malformed PKCS#12 SafeContents: {err}"))
}

fn secret_algorithm_name(arcs: &[u64]) -> String {
    match arcs {
        a if a == oids::AES || a.starts_with(oids::AES) => "AES".into(),
        a if a == oids::HMAC_SHA1 => "HmacSHA1".into(),
        a if a == oids::HMAC_SHA224 => "HmacSHA224".into(),
        a if a == oids::HMAC_SHA256 => "HmacSHA256".into(),
        a if a == oids::HMAC_SHA384 => "HmacSHA384".into(),
        a if a == oids::HMAC_SHA512 => "HmacSHA512".into(),
        a if a == oids::DES_EDE3_CBC => "DESede".into(),
        other => oids::oid_str(other),
    }
}

fn secret_algorithm_oid(name: &str) -> Res<&'static [u64]> {
    Ok(match entry::canonical_secret_algorithm(name).as_str() {
        "AES" => oids::AES,
        "HmacSHA1" => oids::HMAC_SHA1,
        "HmacSHA224" => oids::HMAC_SHA224,
        "HmacSHA256" => oids::HMAC_SHA256,
        "HmacSHA384" => oids::HMAC_SHA384,
        "HmacSHA512" => oids::HMAC_SHA512,
        "DESede" => oids::DES_EDE3_CBC,
        other => return Err(format!("PKCS#12 cannot store '{other}' secret keys (supported: AES, HmacSHA*, DESede)")),
    })
}

fn collect_bags(bags: Vec<RawBag>, password: &str, out: &mut Collected, depth: usize) -> Res<()> {
    if depth > 4 {
        return Err("PKCS#12 safe contents nested too deeply".into());
    }
    for bag in bags {
        let id = bag.bag_id.as_slice();
        if id == oids::KEY_BAG {
            out.keys.push((bag.value, bag.attrs));
        } else if id == oids::SHROUDED_KEY_BAG {
            let pkcs8 = pbe::decrypt_pkcs8(password, &bag.value).map_err(|_| WRONG_PASSWORD.to_string())?;
            out.keys.push((pkcs8, bag.attrs));
        } else if id == oids::CERT_BAG {
            let (cert_type, cert) = yasna::parse_ber(&bag.value, |r| {
                r.read_sequence(|r| {
                    let t = r.next().read_oid()?.components().to_vec();
                    let c = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
                    Ok((t, c))
                })
            })
            .map_err(|err| format!("malformed PKCS#12 CertBag: {err}"))?;
            if cert_type == oids::X509_CERT_TYPE {
                out.certs.push((cert, bag.attrs));
            }
        } else if id == oids::SECRET_BAG {
            let (secret_type, value) = yasna::parse_ber(&bag.value, |r| {
                r.read_sequence(|r| {
                    let t = r.next().read_oid()?.components().to_vec();
                    let v = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
                    Ok((t, v))
                })
            })
            .map_err(|err| format!("malformed PKCS#12 SecretBag: {err}"))?;
            if secret_type == oids::SHROUDED_KEY_BAG {
                // Java wraps the EncryptedPrivateKeyInfo in an OCTET STRING.
                let encrypted = yasna::parse_ber(&value, |r| r.read_bytes()).unwrap_or(value);
                let info = pbe::decrypt_pkcs8(password, &encrypted).map_err(|_| WRONG_PASSWORD.to_string())?;
                let (alg, key) = yasna::parse_ber(&info, |r| {
                    r.read_sequence(|r| {
                        let _v = r.next().read_u8()?;
                        let alg = pbe::read_algorithm_id(r.next())?;
                        let key = r.next().read_bytes()?;
                        let _ = r.read_optional(|r| r.read_der())?;
                        Ok((alg.oid, key))
                    })
                })
                .map_err(|err| format!("malformed secret key: {err}"))?;
                out.secrets.push((secret_algorithm_name(&alg), key, bag.attrs));
            }
        } else if id == oids::SAFE_CONTENTS_BAG {
            collect_bags(read_safe_contents(&bag.value)?, password, out, depth + 1)?;
        }
        // CRL bags and unknown bags are ignored.
    }
    Ok(())
}

pub fn decode(bytes: &[u8], password: &str) -> Res<Vec<KeystoreEntry>> {
    struct Mac {
        hash_oid: Vec<u64>,
        digest: Vec<u8>,
        salt: Vec<u8>,
        iterations: u64,
    }
    let (auth_safe, mac) = yasna::parse_ber(bytes, |r| {
        r.read_sequence(|r| {
            let _version = r.next().read_u8()?;
            let (ct, content) = r.next().read_sequence(|r| {
                let ct = r.next().read_oid()?.components().to_vec();
                let content = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
                Ok((ct, content))
            })?;
            if ct != oids::PKCS7_DATA {
                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
            }
            let mac = r.read_optional(|r| {
                r.read_sequence(|r| {
                    let (alg, digest) = r.next().read_sequence(|r| {
                        let alg = pbe::read_algorithm_id(r.next())?;
                        let d = r.next().read_bytes()?;
                        Ok((alg, d))
                    })?;
                    let salt = r.next().read_bytes()?;
                    let iterations = r.read_optional(|r| r.read_u64())?.unwrap_or(1);
                    Ok(Mac { hash_oid: alg.oid, digest, salt, iterations })
                })
            })?;
            Ok((content, mac))
        })
    })
    .map_err(|_| "not a valid PKCS#12 file (public-key-signed PFX files are not supported)".to_string())?;

    if let Some(mac) = &mac {
        if mac.hash_oid == [1, 2, 840, 113549, 1, 5, 14] {
            return Err("PBMAC1-protected PKCS#12 files (OpenSSL 3.4+ -pbmac1_pbkdf2) are not supported yet".into());
        }
        let hash = HashAlg::from_digest_oid(&mac.hash_oid).ok_or_else(|| format!("unsupported PKCS#12 MAC algorithm {}", oids::oid_str(&mac.hash_oid)))?;
        let key = pbe::pkcs12_kdf(hash, password, &mac.salt, mac.iterations, 3, hash.output_len());
        if hash.hmac(&key, &auth_safe) != mac.digest {
            return Err(WRONG_PASSWORD.into());
        }
    }

    enum Ci {
        Data(Vec<u8>),
        Encrypted(pbe::AlgorithmId, Vec<u8>),
        Enveloped,
    }
    let infos: Vec<Ci> = yasna::parse_ber(&auth_safe, |r| {
        let mut out = Vec::new();
        r.read_sequence_of(|r| {
            r.read_sequence(|r| {
                let ct = r.next().read_oid()?.components().to_vec();
                if ct == oids::PKCS7_DATA {
                    out.push(Ci::Data(r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?));
                } else if ct == oids::PKCS7_ENCRYPTED_DATA {
                    let (alg, data) = r.next().read_tagged(Tag::context(0), |r| {
                        r.read_sequence(|r| {
                            let _v = r.next().read_u8()?;
                            let res = r.next().read_sequence(|r| {
                                let _ct = r.next().read_oid()?;
                                let alg = pbe::read_algorithm_id(r.next())?;
                                let data = r.next().read_tagged_implicit(Tag::context(0), |r| r.read_bytes())?;
                                Ok((alg, data))
                            })?;
                            let _ = r.read_optional(|r| r.read_der())?;
                            Ok(res)
                        })
                    })?;
                    out.push(Ci::Encrypted(alg, data));
                } else {
                    r.next().read_der()?;
                    out.push(Ci::Enveloped);
                }
                Ok(())
            })
        })?;
        Ok(out)
    })
    .map_err(|err| format!("malformed PKCS#12 AuthenticatedSafe: {err}"))?;

    let mut collected = Collected::default();
    for ci in infos {
        let safe = match ci {
            Ci::Data(d) => d,
            Ci::Encrypted(alg, data) => pbe::decrypt(&alg, password, &data).map_err(|err| {
                if err.contains("not supported") || err.contains("unsupported") { err } else { WRONG_PASSWORD.to_string() }
            })?,
            Ci::Enveloped => return Err("PKCS#12 files with public-key encrypted contents are not supported".into()),
        };
        collect_bags(read_safe_contents(&safe)?, password, &mut collected, 0)?;
    }
    assemble(collected)
}

fn unique_alias(base: &str, used: &mut std::collections::HashSet<String>) -> String {
    let base = if base.trim().is_empty() { "entry" } else { base.trim() };
    let mut alias = base.to_string();
    let mut n = 2;
    while used.contains(&alias.to_lowercase()) {
        alias = format!("{base}-{n}");
        n += 1;
    }
    used.insert(alias.to_lowercase());
    alias
}

fn assemble(c: Collected) -> Res<Vec<KeystoreEntry>> {
    let pool: Vec<Vec<u8>> = c.certs.iter().map(|(d, _)| d.clone()).collect();
    let mut leaf_used = vec![false; c.certs.len()];
    let mut in_chain = vec![false; c.certs.len()];
    let mut used_aliases = std::collections::HashSet::new();
    let mut entries = Vec::new();

    for (idx, (pkcs8, attrs)) in c.keys.iter().enumerate() {
        let key = PrivateKey::from_pkcs8_der(pkcs8)?;
        let by_key = c.certs.iter().position(|(d, _)| x509::cert_summary(d).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(false));
        let by_id = || attrs.local_key_id.as_ref().and_then(|id| c.certs.iter().position(|(_, a)| a.local_key_id.as_ref() == Some(id)));
        let by_name = || attrs.friendly_name.as_ref().and_then(|n| c.certs.iter().position(|(_, a)| a.friendly_name.as_ref() == Some(n)));
        // localKeyId pairs a key with its exact certificate bag; fall back to the public key
        // (some tools omit localKeyId) and finally to the friendly name.
        let by_id_key = attrs.local_key_id.as_ref().and_then(|id| {
            c.certs.iter().position(|(d, a)| a.local_key_id.as_ref() == Some(id) && x509::cert_summary(d).map(|s| keys::key_matches_spki(&key, &s.spki)).unwrap_or(true))
        });
        let leaf_idx = by_id_key.or(by_key).or_else(by_id).or_else(by_name);
        let chain = match leaf_idx {
            Some(i) => {
                leaf_used[i] = true;
                let chain = x509::build_chain(&c.certs[i].0, &pool);
                // A CA shared by several chains may be stored more than once: mark every copy.
                for (j, p) in pool.iter().enumerate() {
                    if chain.contains(p) {
                        in_chain[j] = true;
                    }
                }
                chain
            }
            None => Vec::new(),
        };
        let name = attrs
            .friendly_name
            .clone()
            .or_else(|| leaf_idx.and_then(|i| c.certs[i].1.friendly_name.clone()))
            .or_else(|| chain.first().and_then(|d| x509::parse_certificate(d).ok()).map(|i| x509::cn_of(&i.subject).to_lowercase().replace(' ', "-")))
            .unwrap_or_else(|| format!("key-{}", idx + 1));
        let alias = unique_alias(&name, &mut used_aliases);
        entries.push(entry::key_pair_entry(&alias, pkcs8, &chain, None)?);
    }

    let mut emitted: Vec<&Vec<u8>> = Vec::new();
    for (i, (der, attrs)) in c.certs.iter().enumerate() {
        if leaf_used[i] {
            continue;
        }
        // Identical certificates stored more than once become a single entry.
        let is_some_keys_leaf = c.certs.iter().enumerate().any(|(j, (d, _))| leaf_used[j] && d == der);
        if emitted.contains(&der) || (is_some_keys_leaf && !attrs.trusted) {
            continue;
        }
        // A CA certificate that only exists to complete a key's chain is not a separate entry
        // unless it was explicitly stored as one (friendly name / trusted attribute).
        if in_chain[i] && attrs.friendly_name.is_none() && !attrs.trusted {
            continue;
        }
        let name = attrs
            .friendly_name
            .clone()
            .or_else(|| x509::parse_certificate(der).ok().map(|i| x509::cn_of(&i.subject).to_lowercase().replace(' ', "-")))
            .unwrap_or_else(|| format!("cert-{}", i + 1));
        let alias = unique_alias(&name, &mut used_aliases);
        entries.push(entry::trusted_cert_entry(&alias, der, None)?);
        emitted.push(der);
    }

    for (i, (alg, key, attrs)) in c.secrets.iter().enumerate() {
        let alias = unique_alias(attrs.friendly_name.as_deref().unwrap_or(&format!("secret-{}", i + 1)), &mut used_aliases);
        entries.push(entry::secret_key_entry(&alias, alg, key, None));
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

fn write_attrs(w: DERWriter, alias: Option<&str>, key_id: Option<&[u8]>, trusted: bool) {
    w.write_set_of(|w| {
        if let Some(alias) = alias {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::FRIENDLY_NAME));
                w.next().write_set_of(|w| w.next().write_bmp_string(alias));
            });
        }
        if let Some(id) = key_id {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::LOCAL_KEY_ID));
                w.next().write_set_of(|w| w.next().write_bytes(id));
            });
        }
        if trusted {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::ORACLE_TRUSTED_KEY_USAGE));
                w.next().write_set_of(|w| w.next().write_oid(&oid(oids::ANY_EXTENDED_KEY_USAGE)));
            });
        }
    });
}

fn cert_bag(cert: &[u8], alias: Option<&str>, key_id: Option<&[u8]>, trusted: bool) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(oids::CERT_BAG));
            w.next().write_tagged(Tag::context(0), |w| {
                w.write_sequence(|w| {
                    w.next().write_oid(&oid(oids::X509_CERT_TYPE));
                    w.next().write_tagged(Tag::context(0), |w| w.write_bytes(cert));
                })
            });
            if alias.is_some() || key_id.is_some() || trusted {
                write_attrs(w.next(), alias, key_id, trusted);
            }
        })
    })
}

fn safe_contents(bags: &[Vec<u8>]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for b in bags {
                w.next().write_der(b);
            }
        })
    })
}

pub fn encode(entries: &[KeystoreEntry], password: &str) -> Res<Vec<u8>> {
    let iterations = pbe::DEFAULT_ITERATIONS;
    let mut cert_bags = Vec::new();
    let mut key_bags = Vec::new();
    let mut aliases = std::collections::HashSet::new();

    for (n, entry) in entries.iter().enumerate() {
        if !aliases.insert(entry.alias.to_lowercase()) {
            return Err(format!("duplicate alias '{}'", entry.alias));
        }
        match entry.entry_type.as_str() {
            "KeyPair" => {
                if entry.locked {
                    return Err(format!("'{}' is locked by a separate key password; unlock it before saving as PKCS#12", entry.alias));
                }
                let pkcs8 = entry::private_key_der(entry)?;
                let chain = entry::chain_der(entry)?;
                let key_id = chain.first().map(|c| sha1(c)).unwrap_or_else(|| sha1(&pkcs8));
                let shrouded = pbe::encrypt_pkcs8(password, &pkcs8, iterations)?;
                key_bags.push(yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_oid(&oid(oids::SHROUDED_KEY_BAG));
                        w.next().write_tagged(Tag::context(0), |w| w.write_der(&shrouded));
                        write_attrs(w.next(), Some(&entry.alias), Some(&key_id), false);
                    })
                }));
                for (i, cert) in chain.iter().enumerate() {
                    if i == 0 {
                        cert_bags.push(cert_bag(cert, Some(&entry.alias), Some(&key_id), false));
                    } else {
                        cert_bags.push(cert_bag(cert, None, None, false));
                    }
                }
            }
            "TrustedCertificate" => {
                let chain = entry::chain_der(entry)?;
                let cert = chain.first().ok_or_else(|| format!("'{}' has no certificate", entry.alias))?;
                cert_bags.push(cert_bag(cert, Some(&entry.alias), None, true));
            }
            "SecretKey" => {
                if entry.locked {
                    return Err(format!("'{}' is locked; unlock it before saving as PKCS#12", entry.alias));
                }
                let key = entry::secret_bytes(entry)?;
                let alg = secret_algorithm_oid(&entry.algorithm)?;
                let info = yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_u8(0);
                        w.next().write_sequence(|w| w.next().write_oid(&oid(alg)));
                        w.next().write_bytes(&key);
                    })
                });
                let encrypted = pbe::encrypt_pkcs8(password, &info, iterations)?;
                let key_id = format!("Time {}", chrono::Utc::now().timestamp_millis() + n as i64);
                key_bags.push(yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_oid(&oid(oids::SECRET_BAG));
                        w.next().write_tagged(Tag::context(0), |w| {
                            w.write_sequence(|w| {
                                w.next().write_oid(&oid(oids::SHROUDED_KEY_BAG));
                                w.next().write_tagged(Tag::context(0), |w| w.write_bytes(&encrypted));
                            })
                        });
                        write_attrs(w.next(), Some(&entry.alias), Some(key_id.as_bytes()), false);
                    })
                }));
            }
            other => return Err(format!("unsupported entry type '{other}'")),
        }
    }

    let mut infos = Vec::new();
    if !cert_bags.is_empty() {
        let (alg, ciphertext) = pbe::pbes2_encrypt(password, &safe_contents(&cert_bags), iterations)?;
        infos.push(yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(oids::PKCS7_ENCRYPTED_DATA));
                w.next().write_tagged(Tag::context(0), |w| {
                    w.write_sequence(|w| {
                        w.next().write_u8(0);
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(oids::PKCS7_DATA));
                            w.next().write_der(&alg);
                            pbe::write_implicit_octets(w.next(), 0, &ciphertext);
                        });
                    })
                });
            })
        }));
    }
    if !key_bags.is_empty() {
        let sc = safe_contents(&key_bags);
        infos.push(yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_oid(&oid(oids::PKCS7_DATA));
                w.next().write_tagged(Tag::context(0), |w| w.write_bytes(&sc));
            })
        }));
    }
    let auth_safe = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for i in &infos {
                w.next().write_der(i);
            }
        })
    });
    let mac_salt = random_bytes(20);
    let mac_key = pbe::pkcs12_kdf(HashAlg::Sha256, password, &mac_salt, iterations, 3, 32);
    let mac = HashAlg::Sha256.hmac(&mac_key, &auth_safe);
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(3);
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(oids::PKCS7_DATA));
                w.next().write_tagged(Tag::context(0), |w| w.write_bytes(&auth_safe));
            });
            w.next().write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(oids::SHA256));
                        w.next().write_null();
                    });
                    w.next().write_bytes(&mac);
                });
                w.next().write_bytes(&mac_salt);
                w.next().write_u64(iterations);
            });
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair(alias: &str, alg: &str) -> KeystoreEntry {
        let input = crate::model::GenerateKeyPairInput {
            alias: alias.into(),
            algorithm: alg.into(),
            key_size: 2048,
            curve: Some("P-256".into()),
            signature_hash: None,
            subject_dn: format!("CN={alias}.example"),
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
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            labels: vec![],
        };
        crate::ops::generate_key_pair(&input, None).unwrap()
    }

    #[test]
    fn round_trip_all_entry_types() {
        let kp = key_pair("web", "RSA");
        let ed = key_pair("signer", "Ed25519");
        let ca_der = entry::chain_der(&key_pair("root", "ECDSA")).unwrap();
        let trusted = entry::trusted_cert_entry("root", &ca_der[0], None).unwrap();
        let secret = entry::secret_key_entry("aes", "AES", &[3u8; 32], None);
        let entries = vec![kp.clone(), ed.clone(), trusted.clone(), secret.clone()];
        let bytes = encode(&entries, "s3cret").unwrap();
        assert!(looks_like_pkcs12(&bytes));
        let back = decode(&bytes, "s3cret").unwrap();
        assert_eq!(back.len(), 4);
        let find = |a: &str| back.iter().find(|e| e.alias == a).unwrap();
        assert_eq!(find("web").private_key_pem, kp.private_key_pem);
        assert_eq!(find("web").sha256_fingerprint, kp.sha256_fingerprint);
        assert_eq!(find("signer").algorithm, "Ed25519");
        assert_eq!(find("root").entry_type, "TrustedCertificate");
        assert_eq!(find("aes").secret_key_hex, secret.secret_key_hex);
        assert_eq!(decode(&bytes, "nope").unwrap_err(), WRONG_PASSWORD);
    }

    #[test]
    fn shared_ca_in_several_chains_does_not_create_extra_entries() {
        let ca = crate::ops::generate_key_pair(&{ let mut i = crate::ops::tests_support::input("ca", "ECDSA", true); i.subject_dn = "CN=Shared CA".into(); i }, None).unwrap();
        let a = crate::ops::generate_key_pair(&crate::ops::tests_support::input("a", "ECDSA", false), Some(&ca)).unwrap();
        let b = crate::ops::generate_key_pair(&crate::ops::tests_support::input("b", "RSA", false), Some(&ca)).unwrap();
        // Both orders: chains that mention the CA before and after the CA's own entry.
        for entries in [vec![a.clone(), ca.clone(), b.clone()], vec![ca.clone(), a.clone(), b.clone()], vec![a.clone(), b.clone(), ca.clone()]] {
            let bytes = encode(&entries, "pw").unwrap();
            let back = decode(&bytes, "pw").unwrap();
            let mut aliases: Vec<_> = back.iter().map(|e| e.alias.as_str()).collect();
            aliases.sort();
            assert_eq!(aliases, vec!["a", "b", "ca"]);
            assert!(back.iter().filter(|e| e.alias != "ca").all(|e| e.chain_length == 2));
            assert!(back.iter().all(|e| e.entry_type == "KeyPair"));
        }
    }

    #[test]
    fn empty_keystore_round_trips() {
        let bytes = encode(&[], "pw").unwrap();
        assert!(decode(&bytes, "pw").unwrap().is_empty());
    }
}
