//! JSON Web Tokens (RFC 7519) signed with real keystore keys: RS256/384/512, ES256/384/512,
//! EdDSA and HS256/384/512 (secret key entries).

use crate::entry;
use crate::keys::{self, SigAlg};
use crate::model::{JwtInfo, JwtVerifyResult, KeystoreEntry};
use crate::pbe::HashAlg;
use crate::util::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde_json::{Map, Value};

enum Jws {
    Asym(SigAlg),
    Hmac(HashAlg),
}

fn jws_for(name: &str) -> Res<Jws> {
    Ok(match name {
        "RS256" => Jws::Asym(SigAlg::Rsa(HashAlg::Sha256)),
        "RS384" => Jws::Asym(SigAlg::Rsa(HashAlg::Sha384)),
        "RS512" => Jws::Asym(SigAlg::Rsa(HashAlg::Sha512)),
        "ES256" => Jws::Asym(SigAlg::Ecdsa(HashAlg::Sha256)),
        "ES384" => Jws::Asym(SigAlg::Ecdsa(HashAlg::Sha384)),
        "ES512" => Jws::Asym(SigAlg::Ecdsa(HashAlg::Sha512)),
        "EdDSA" => Jws::Asym(SigAlg::Ed25519),
        "HS256" => Jws::Hmac(HashAlg::Sha256),
        "HS384" => Jws::Hmac(HashAlg::Sha384),
        "HS512" => Jws::Hmac(HashAlg::Sha512),
        other => return Err(format!("unsupported JWS algorithm '{other}'")),
    })
}

/// The JWS algorithms an entry can produce; the first is the default.
pub fn algorithms_for(e: &KeystoreEntry) -> Vec<&'static str> {
    match (e.entry_type.as_str(), e.algorithm.as_str(), e.curve.as_deref()) {
        ("SecretKey", a, _) if a.starts_with("Hmac") || a == "AES" || a == "Generic" => match a {
            "HmacSHA384" => vec!["HS384", "HS256", "HS512"],
            "HmacSHA512" => vec!["HS512", "HS256", "HS384"],
            _ => vec!["HS256", "HS384", "HS512"],
        },
        ("SecretKey", _, _) => vec![],
        (_, "RSA", _) => vec!["RS256", "RS384", "RS512"],
        (_, "ECDSA", Some("P-256")) => vec!["ES256"],
        (_, "ECDSA", Some("P-384")) => vec!["ES384"],
        (_, "ECDSA", Some("P-521")) => vec!["ES512"],
        (_, "Ed25519", _) => vec!["EdDSA"],
        _ => vec![],
    }
}

pub struct JwtClaims<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub validity_minutes: u32,
    pub custom_claims_json: &'a str,
}

pub fn sign(claims: &JwtClaims, signer: &KeystoreEntry, algorithm: Option<&str>) -> Res<String> {
    let supported = algorithms_for(signer);
    let alg = match algorithm.filter(|a| !a.is_empty()) {
        Some(a) if supported.contains(&a) => a,
        Some(a) => return Err(format!("'{}' cannot sign {a} tokens (supported: {})", signer.alias, supported.join(", "))),
        None => supported.first().copied().ok_or_else(|| format!("'{}' ({}) cannot sign JWTs", signer.alias, signer.algorithm))?,
    };
    if claims.validity_minutes == 0 {
        return Err("validity must be at least one minute".into());
    }
    let mut payload = Map::new();
    let custom = claims.custom_claims_json.trim();
    if !custom.is_empty() {
        match serde_json::from_str::<Value>(custom) {
            Ok(Value::Object(map)) => payload.extend(map),
            Ok(_) => return Err("custom claims must be a JSON object, e.g. {\"scope\":\"read\"}".into()),
            Err(err) => return Err(format!("custom claims are not valid JSON: {err}")),
        }
    }
    let now = now_ts();
    for (k, v) in [("iss", claims.issuer), ("sub", claims.subject), ("aud", claims.audience)] {
        if !v.trim().is_empty() {
            payload.insert(k.into(), Value::String(v.trim().into()));
        }
    }
    payload.insert("iat".into(), now.into());
    payload.insert("nbf".into(), now.into());
    payload.insert("exp".into(), (now + claims.validity_minutes as i64 * 60).into());
    payload.entry("jti").or_insert_with(|| Value::String(uuid::Uuid::new_v4().to_string()));
    let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": signer.alias });
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).map_err(e)?),
        B64URL.encode(serde_json::to_vec(&Value::Object(payload)).map_err(e)?)
    );
    let sig = match jws_for(alg)? {
        Jws::Hmac(hash) => hash.hmac(&entry::secret_bytes(signer)?, signing_input.as_bytes()),
        Jws::Asym(sig_alg) => entry::private_key(signer)?.sign_jws(sig_alg, signing_input.as_bytes())?,
    };
    Ok(format!("{signing_input}.{}", B64URL.encode(sig)))
}

fn split(token: &str) -> Res<(&str, &str, &str)> {
    let mut parts = token.trim().split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err("a JWT has three dot-separated parts (header.payload.signature)".into()),
    }
}

fn b64url_json(part: &str, what: &str) -> Res<Value> {
    let bytes = B64URL.decode(part.trim_end_matches('=')).map_err(|_| format!("the JWT {what} is not valid base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("the JWT {what} is not valid JSON"))
}

pub fn decode(token: &str) -> Res<JwtInfo> {
    let (h, p, s) = split(token)?;
    let header = b64url_json(h, "header")?;
    let payload = b64url_json(p, "payload")?;
    let time = |k: &str| payload.get(k).and_then(Value::as_i64);
    let now = now_ts();
    Ok(JwtInfo {
        header_json: serde_json::to_string_pretty(&header).unwrap_or_default(),
        payload_json: serde_json::to_string_pretty(&payload).unwrap_or_default(),
        algorithm: header.get("alg").and_then(Value::as_str).unwrap_or("none").to_string(),
        key_id: header.get("kid").and_then(Value::as_str).map(String::from),
        issued_at: time("iat").map(fmt_ts),
        not_before: time("nbf").map(fmt_ts),
        expires_at: time("exp").map(fmt_ts),
        expired: time("exp").map(|exp| exp < now),
        signature_b64url: s.to_string(),
    })
}

pub fn verify(token: &str, key: &KeystoreEntry) -> Res<JwtVerifyResult> {
    let info = decode(token)?;
    let (h, p, s) = split(token)?;
    let signing_input = format!("{h}.{p}");
    let sig = B64URL.decode(s.trim_end_matches('=')).map_err(|_| "the JWT signature is not valid base64url".to_string())?;
    if info.algorithm == "none" {
        return Ok(JwtVerifyResult { valid: false, message: "Unsigned token (alg \"none\") — rejected.".into(), info });
    }
    let valid = match jws_for(&info.algorithm)? {
        Jws::Hmac(hash) => {
            let expected = hash.hmac(&entry::secret_bytes(key).map_err(|_| format!("{} tokens need a secret key entry", info.algorithm))?, signing_input.as_bytes());
            expected == sig
        }
        Jws::Asym(alg) => {
            let spki = match &key.public_key_pem {
                Some(pem_text) => pem::parse(pem_text.as_bytes()).map_err(e)?.contents().to_vec(),
                None => return Err(format!("'{}' has no public key", key.alias)),
            };
            keys::verify_jws(&spki, alg, signing_input.as_bytes(), &sig)?
        }
    };
    let now = now_ts();
    let payload: Value = b64url_json(p, "payload")?;
    let nbf_ok = payload.get("nbf").and_then(Value::as_i64).is_none_or(|nbf| nbf <= now + 60);
    let message = if !valid {
        format!("Invalid signature: the token was not signed by '{}' or was modified.", key.alias)
    } else if info.expired == Some(true) {
        format!("Signature valid, but the token expired at {}.", info.expires_at.clone().unwrap_or_default())
    } else if !nbf_ok {
        "Signature valid, but the token is not valid yet (nbf in the future).".to_string()
    } else {
        format!("Valid {} signature by '{}'.", info.algorithm, key.alias)
    };
    Ok(JwtVerifyResult { valid: valid && info.expired != Some(true) && nbf_ok, message, info })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GenerateKeyPairInput;

    fn kp(alg: &str, curve: &str) -> KeystoreEntry {
        crate::ops::generate_key_pair(
            &GenerateKeyPairInput {
                alias: "jwt".into(),
                algorithm: alg.into(),
                key_size: 2048,
                curve: Some(curve.into()),
                signature_hash: None,
                subject_dn: "CN=jwt".into(),
                common_name: String::new(),
                organization: String::new(),
                organizational_unit: String::new(),
                locality: String::new(),
                state: String::new(),
                country: String::new(),
                email: String::new(),
                validity_days: 10,
                is_ca: false,
                path_len: None,
                sans: vec![],
                key_usage: vec![],
                extended_key_usage: vec![],
                labels: vec![],
            },
            None,
        )
        .unwrap()
    }

    #[test]
    fn sign_verify_every_key_type() {
        let claims = JwtClaims { issuer: "iss", subject: "sub", audience: "aud", validity_minutes: 5, custom_claims_json: r#"{"scope":"read"}"# };
        let hmac = entry::secret_key_entry("h", "HmacSHA256", &[1u8; 32], None);
        for e in [kp("RSA", ""), kp("ECDSA", "P-256"), kp("ECDSA", "P-384"), kp("ECDSA", "P-521"), kp("Ed25519", ""), hmac] {
            let token = sign(&claims, &e, None).unwrap();
            let r = verify(&token, &e).unwrap();
            assert!(r.valid, "{} {}", e.algorithm, r.message);
            assert!(r.info.payload_json.contains("\"scope\""));
            let mut tampered = token.clone();
            tampered.push('A');
            assert!(!verify(&tampered, &e).map(|r| r.valid).unwrap_or(false));
        }
        assert!(sign(&JwtClaims { custom_claims_json: "[1]", ..claims }, &kp("Ed25519", ""), None).is_err());
    }
}
