//! Object identifiers used across the crate, as `yasna`-friendly `&[u64]` arcs.

use yasna::models::ObjectIdentifier;

pub fn oid(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(arcs)
}

pub fn oid_str(arcs: &[u64]) -> String {
    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

pub fn parse_oid_str(s: &str) -> Option<Vec<u64>> {
    let arcs: Result<Vec<u64>, _> = s.trim().split('.').map(|p| p.parse::<u64>()).collect();
    arcs.ok().filter(|a| a.len() >= 2)
}

// Public key algorithms
pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
pub const RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
pub const ED25519: &[u64] = &[1, 3, 101, 112];
pub const ED448: &[u64] = &[1, 3, 101, 113];
pub const X25519: &[u64] = &[1, 3, 101, 110];
pub const X448: &[u64] = &[1, 3, 101, 111];
pub const DSA: &[u64] = &[1, 2, 840, 10040, 4, 1];

// Named curves
pub const SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
pub const SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
pub const SECP521R1: &[u64] = &[1, 3, 132, 0, 35];
pub const SECP256K1: &[u64] = &[1, 3, 132, 0, 10];

// Signature algorithms
pub const SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
pub const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
pub const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
pub const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
pub const SHA224_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 14];
pub const MD5_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 4];
pub const MD2_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 2];
pub const ECDSA_SHA1: &[u64] = &[1, 2, 840, 10045, 4, 1];
pub const ECDSA_SHA224: &[u64] = &[1, 2, 840, 10045, 4, 3, 1];
pub const ECDSA_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
pub const ECDSA_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
pub const ECDSA_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];
pub const DSA_SHA1: &[u64] = &[1, 2, 840, 10040, 4, 3];
pub const DSA_SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 1];
pub const DSA_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 2];
pub const DSA_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 3];
pub const DSA_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 4];
/// The mask generation function of RSASSA-PSS.
pub const MGF1: &[u64] = &[1, 2, 840, 113549, 1, 1, 8];

// Digests
pub const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
pub const SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 4];
pub const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
pub const SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
pub const SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
pub const MD5: &[u64] = &[1, 2, 840, 113549, 2, 5];

// HMAC (PBKDF2 PRFs and secret-key algorithm identifiers)
pub const HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
pub const HMAC_SHA224: &[u64] = &[1, 2, 840, 113549, 2, 8];
pub const HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
pub const HMAC_SHA384: &[u64] = &[1, 2, 840, 113549, 2, 10];
pub const HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];
pub const HMAC_SHA512_224: &[u64] = &[1, 2, 840, 113549, 2, 12];
pub const HMAC_SHA512_256: &[u64] = &[1, 2, 840, 113549, 2, 13];
pub const HMAC_SHA3_512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 16];

// Symmetric ciphers
pub const AES: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1];
pub const AES128_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 2];
pub const AES192_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 22];
pub const AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
pub const AES128_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 6];
pub const AES192_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 26];
pub const AES256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];
pub const AES128_CCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 7];
pub const AES192_CCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 27];
pub const AES256_CCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 47];
/// AES key wrap with padding (RFC 5649).
pub const AES128_WRAP_PAD: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 8];
pub const AES192_WRAP_PAD: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 28];
pub const AES256_WRAP_PAD: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 48];
pub const DES_EDE3_CBC: &[u64] = &[1, 2, 840, 113549, 3, 7];
/// DESede as OIW names it, the OID Bouncy Castle stores triple-DES secret keys under.
pub const DES_EDE_OIW: &[u64] = &[1, 3, 14, 3, 2, 17];
pub const DES_CBC: &[u64] = &[1, 3, 14, 3, 2, 7];
pub const RC2_CBC: &[u64] = &[1, 2, 840, 113549, 3, 2];

// Password-based encryption
pub const PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
pub const PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
/// scrypt as a PBES2 key derivation function (RFC 7914).
pub const SCRYPT: &[u64] = &[1, 3, 6, 1, 4, 1, 11591, 4, 11];
// PBES1 (PKCS#5 v1.5): PBKDF1 with a single-DES or 64-bit RC2 key.
pub const PBE_MD5_DES: &[u64] = &[1, 2, 840, 113549, 1, 5, 3];
pub const PBE_MD5_RC2: &[u64] = &[1, 2, 840, 113549, 1, 5, 6];
pub const PBE_SHA1_DES: &[u64] = &[1, 2, 840, 113549, 1, 5, 10];
pub const PBE_SHA1_RC2: &[u64] = &[1, 2, 840, 113549, 1, 5, 11];
/// PBMAC1 (RFC 9579), the modern PKCS#12 integrity protection.
pub const PBMAC1: &[u64] = &[1, 2, 840, 113549, 1, 5, 14];
pub const PBE_SHA1_RC4_128: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 1];
pub const PBE_SHA1_RC4_40: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 2];
pub const PBE_SHA1_3DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
pub const PBE_SHA1_2DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 4];
pub const PBE_SHA1_RC2_128: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 5];
pub const PBE_SHA1_RC2_40: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 6];
/// Sun JKS proprietary key protection.
pub const JKS_KEY_PROTECTOR: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1];
/// Sun JCEKS PBEWithMD5AndTripleDES.
pub const PBE_MD5_3DES: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 19, 1];

// PKCS#7 / CMS
pub const PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
pub const PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
pub const PKCS7_ENVELOPED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 3];
pub const PKCS7_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];
pub const ATTR_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
pub const ATTR_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
pub const ATTR_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];
/// id-aa-timeStampToken: the RFC 3161 timestamp, an *unsigned* attribute of a SignerInfo.
pub const ATTR_TIMESTAMP_TOKEN: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 2, 14];
/// id-ct-TSTInfo, the eContentType of a timestamp token.
pub const TST_INFO: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];

// PKCS#9 / PKCS#12
pub const EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];
pub const EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
pub const FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
pub const LOCAL_KEY_ID: &[u64] = &[1, 2, 840, 113549, 1, 9, 21];
pub const X509_CERT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];
pub const KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
pub const SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
pub const CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
pub const CRL_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 4];
pub const SECRET_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 5];
pub const SAFE_CONTENTS_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 6];
/// Oracle/Java attribute marking a PKCS#12 certificate bag as a trusted certificate entry.
pub const ORACLE_TRUSTED_KEY_USAGE: &[u64] = &[2, 16, 840, 1, 113894, 746875, 1, 1];

// X.509 extensions
pub const EXT_SUBJECT_KEY_ID: &[u64] = &[2, 5, 29, 14];
pub const EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
pub const EXT_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
pub const EXT_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
pub const EXT_CRL_NUMBER: &[u64] = &[2, 5, 29, 20];
pub const EXT_CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];
pub const EXT_AUTHORITY_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
pub const AD_OCSP: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
pub const AD_CA_ISSUERS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
pub const EXT_CRL_REASON: &[u64] = &[2, 5, 29, 21];
pub const EXT_AUTHORITY_KEY_ID: &[u64] = &[2, 5, 29, 35];
pub const EXT_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
pub const ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];

// Extended key usages
pub const EKU_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
pub const EKU_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
pub const EKU_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
pub const EKU_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
pub const EKU_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
pub const EKU_OCSP_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 9];

// RFC 6960 OCSP
pub const PKIX_OCSP_BASIC: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];
pub const OCSP_NONCE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

// Distinguished name attributes
pub const AT_CN: &[u64] = &[2, 5, 4, 3];
pub const AT_SURNAME: &[u64] = &[2, 5, 4, 4];
pub const AT_SERIAL_NUMBER: &[u64] = &[2, 5, 4, 5];
pub const AT_C: &[u64] = &[2, 5, 4, 6];
pub const AT_L: &[u64] = &[2, 5, 4, 7];
pub const AT_ST: &[u64] = &[2, 5, 4, 8];
pub const AT_STREET: &[u64] = &[2, 5, 4, 9];
pub const AT_O: &[u64] = &[2, 5, 4, 10];
pub const AT_OU: &[u64] = &[2, 5, 4, 11];
pub const AT_TITLE: &[u64] = &[2, 5, 4, 12];
pub const AT_POSTAL_CODE: &[u64] = &[2, 5, 4, 17];
pub const AT_GIVEN_NAME: &[u64] = &[2, 5, 4, 42];
pub const AT_INITIALS: &[u64] = &[2, 5, 4, 43];
pub const AT_DN_QUALIFIER: &[u64] = &[2, 5, 4, 46];
pub const AT_DC: &[u64] = &[0, 9, 2342, 19200300, 100, 1, 25];
pub const AT_UID: &[u64] = &[0, 9, 2342, 19200300, 100, 1, 1];

/// Short attribute names for DN rendering/parsing (RFC 4514 plus Java's EMAILADDRESS).
pub const DN_ATTRIBUTES: &[(&str, &[u64])] = &[
    ("CN", AT_CN),
    ("C", AT_C),
    ("L", AT_L),
    ("ST", AT_ST),
    ("O", AT_O),
    ("OU", AT_OU),
    ("STREET", AT_STREET),
    ("DC", AT_DC),
    ("UID", AT_UID),
    ("EMAILADDRESS", EMAIL_ADDRESS),
    ("SERIALNUMBER", AT_SERIAL_NUMBER),
    ("SURNAME", AT_SURNAME),
    ("GIVENNAME", AT_GIVEN_NAME),
    ("TITLE", AT_TITLE),
    ("INITIALS", AT_INITIALS),
    ("POSTALCODE", AT_POSTAL_CODE),
    ("DNQUALIFIER", AT_DN_QUALIFIER),
];

pub fn dn_attribute_name(arcs: &[u64]) -> String {
    DN_ATTRIBUTES.iter().find(|(_, a)| *a == arcs).map(|(n, _)| n.to_string()).unwrap_or_else(|| oid_str(arcs))
}

pub fn dn_attribute_oid(name: &str) -> Option<Vec<u64>> {
    let upper = name.trim().to_ascii_uppercase();
    let alias = match upper.as_str() {
        "S" => "ST",
        "E" | "EMAIL" => "EMAILADDRESS",
        "SN" => "SURNAME",
        "GN" => "GIVENNAME",
        "T" => "TITLE",
        "SERIAL" => "SERIALNUMBER",
        other => other,
    };
    DN_ATTRIBUTES.iter().find(|(n, _)| *n == alias).map(|(_, a)| a.to_vec()).or_else(|| parse_oid_str(name))
}

pub fn extension_name(arcs: &[u64]) -> &'static str {
    match arcs {
        [2, 5, 29, 14] => "Subject Key Identifier",
        [2, 5, 29, 15] => "Key Usage",
        [2, 5, 29, 16] => "Private Key Usage Period",
        [2, 5, 29, 17] => "Subject Alternative Name",
        [2, 5, 29, 18] => "Issuer Alternative Name",
        [2, 5, 29, 19] => "Basic Constraints",
        [2, 5, 29, 20] => "CRL Number",
        [2, 5, 29, 21] => "CRL Reason",
        [2, 5, 29, 24] => "Invalidity Date",
        [2, 5, 29, 27] => "Delta CRL Indicator",
        [2, 5, 29, 28] => "Issuing Distribution Point",
        [2, 5, 29, 30] => "Name Constraints",
        [2, 5, 29, 31] => "CRL Distribution Points",
        [2, 5, 29, 32] => "Certificate Policies",
        [2, 5, 29, 33] => "Policy Mappings",
        [2, 5, 29, 35] => "Authority Key Identifier",
        [2, 5, 29, 36] => "Policy Constraints",
        [2, 5, 29, 37] => "Extended Key Usage",
        [2, 5, 29, 46] => "Freshest CRL",
        [2, 5, 29, 54] => "Inhibit Any Policy",
        [1, 3, 6, 1, 5, 5, 7, 1, 1] => "Authority Information Access",
        [1, 3, 6, 1, 5, 5, 7, 1, 11] => "Subject Information Access",
        [1, 3, 6, 1, 5, 5, 7, 1, 24] => "TLS Feature (OCSP Must-Staple)",
        [1, 3, 6, 1, 4, 1, 11129, 2, 4, 2] => "Signed Certificate Timestamps",
        [1, 3, 6, 1, 4, 1, 11129, 2, 4, 3] => "CT Precertificate Poison",
        [2, 16, 840, 1, 113730, 1, 1] => "Netscape Cert Type",
        [2, 16, 840, 1, 113730, 1, 13] => "Netscape Comment",
        [1, 3, 6, 1, 4, 1, 311, 20, 2] => "Microsoft Certificate Template Name",
        [1, 3, 6, 1, 4, 1, 311, 21, 7] => "Microsoft Certificate Template",
        [1, 3, 6, 1, 4, 1, 311, 21, 10] => "Microsoft Application Policies",
        _ => "Unknown extension",
    }
}

pub fn eku_name(arcs: &[u64]) -> String {
    match arcs {
        [1, 3, 6, 1, 5, 5, 7, 3, 1] => "TLS Web Server Authentication".into(),
        [1, 3, 6, 1, 5, 5, 7, 3, 2] => "TLS Web Client Authentication".into(),
        [1, 3, 6, 1, 5, 5, 7, 3, 3] => "Code Signing".into(),
        [1, 3, 6, 1, 5, 5, 7, 3, 4] => "E-mail Protection".into(),
        [1, 3, 6, 1, 5, 5, 7, 3, 8] => "Time Stamping".into(),
        [1, 3, 6, 1, 5, 5, 7, 3, 9] => "OCSP Signing".into(),
        [2, 5, 29, 37, 0] => "Any Extended Key Usage".into(),
        [1, 3, 6, 1, 4, 1, 311, 10, 3, 3] => "Microsoft Server Gated Crypto".into(),
        [1, 3, 6, 1, 4, 1, 311, 20, 2, 2] => "Microsoft Smartcard Login".into(),
        [2, 16, 840, 1, 113730, 4, 1] => "Netscape Server Gated Crypto".into(),
        other => oid_str(other),
    }
}

/// Maps the identifiers accepted by the generators to EKU OIDs.
pub fn eku_from_id(id: &str) -> Option<&'static [u64]> {
    match id.trim() {
        "serverAuth" => Some(EKU_SERVER_AUTH),
        "clientAuth" => Some(EKU_CLIENT_AUTH),
        "codeSigning" => Some(EKU_CODE_SIGNING),
        "emailProtection" => Some(EKU_EMAIL_PROTECTION),
        "timeStamping" => Some(EKU_TIME_STAMPING),
        "OCSPSigning" | "ocspSigning" => Some(EKU_OCSP_SIGNING),
        "anyExtendedKeyUsage" => Some(ANY_EXTENDED_KEY_USAGE),
        _ => None,
    }
}

/// Post-quantum algorithm identifiers (NIST FIPS 203/204/205) recognised when importing keys.
pub fn post_quantum_name(arcs: &[u64]) -> Option<&'static str> {
    match arcs {
        [2, 16, 840, 1, 101, 3, 4, 3, 17] => Some("ML-DSA-44"),
        [2, 16, 840, 1, 101, 3, 4, 3, 18] => Some("ML-DSA-65"),
        [2, 16, 840, 1, 101, 3, 4, 3, 19] => Some("ML-DSA-87"),
        [2, 16, 840, 1, 101, 3, 4, 3, n] if (20..=31).contains(n) => Some("SLH-DSA"),
        [2, 16, 840, 1, 101, 3, 4, 4, 1] => Some("ML-KEM-512"),
        [2, 16, 840, 1, 101, 3, 4, 4, 2] => Some("ML-KEM-768"),
        [2, 16, 840, 1, 101, 3, 4, 4, 3] => Some("ML-KEM-1024"),
        _ => None,
    }
}

pub fn signature_algorithm_name(arcs: &[u64]) -> String {
    match arcs {
        [1, 2, 840, 113549, 1, 1, 2] => "MD2withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 4] => "MD5withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 5] => "SHA1withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 10] => "RSASSA-PSS".into(),
        [1, 2, 840, 113549, 1, 1, 11] => "SHA256withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 12] => "SHA384withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 13] => "SHA512withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 14] => "SHA224withRSA".into(),
        [1, 2, 840, 113549, 1, 1, 1] => "RSA".into(),
        [1, 2, 840, 10045, 4, 1] => "SHA1withECDSA".into(),
        [1, 2, 840, 10045, 4, 3, 1] => "SHA224withECDSA".into(),
        [1, 2, 840, 10045, 4, 3, 2] => "SHA256withECDSA".into(),
        [1, 2, 840, 10045, 4, 3, 3] => "SHA384withECDSA".into(),
        [1, 2, 840, 10045, 4, 3, 4] => "SHA512withECDSA".into(),
        [1, 2, 840, 10040, 4, 3] => "SHA1withDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 1] => "SHA224withDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 2] => "SHA256withDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 3] => "SHA384withDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 4] => "SHA512withDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 9] => "SHA3-224withECDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 10] => "SHA3-256withECDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 11] => "SHA3-384withECDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 12] => "SHA3-512withECDSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 13] => "SHA3-224withRSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 14] => "SHA3-256withRSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 15] => "SHA3-384withRSA".into(),
        [2, 16, 840, 1, 101, 3, 4, 3, 16] => "SHA3-512withRSA".into(),
        [1, 2, 156, 10197, 1, 501] => "SM3withSM2".into(),
        [1, 3, 101, 112] => "Ed25519".into(),
        [1, 3, 101, 113] => "Ed448".into(),
        other => post_quantum_name(other).map(String::from).unwrap_or_else(|| oid_str(other)),
    }
}
