//! Certificate issuance (self-signed, CA-signed, from a CSR) and inspection
//! of arbitrary imported certificates.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::error::{CoreError, Result};
use crate::keys::KeyMaterial;

/// A human-chosen "what is this certificate for" preset. This is what the
/// mockup's wizard/CA workspace call a "template": picking one sets Key
/// Usage, Extended Key Usage and the CA/path-length bits correctly instead
/// of leaving a user to assemble OID lists by hand (the way `openssl req`
/// and raw `keytool` both require today).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertTemplate {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    RootCa,
    IntermediateCa,
}

impl CertTemplate {
    pub fn label(&self) -> &'static str {
        match self {
            CertTemplate::ServerAuth => "TLS Server",
            CertTemplate::ClientAuth => "TLS Client / mTLS",
            CertTemplate::CodeSigning => "Code Signing",
            CertTemplate::EmailProtection => "Email (S/MIME)",
            CertTemplate::RootCa => "Root CA",
            CertTemplate::IntermediateCa => "Issuing CA",
        }
    }

    pub fn is_ca(&self) -> bool {
        matches!(self, CertTemplate::RootCa | CertTemplate::IntermediateCa)
    }
}

/// Identity-document fields. Only `common_name` is required; the rest follow
/// standard X.501 attribute types.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Subject {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

impl Subject {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            ..Default::default()
        }
    }

    fn to_distinguished_name(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, self.common_name.as_str());
        if let Some(o) = &self.organization {
            dn.push(DnType::OrganizationName, o.as_str());
        }
        if let Some(ou) = &self.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou.as_str());
        }
        if let Some(c) = &self.country {
            dn.push(DnType::CountryName, c.as_str());
        }
        if let Some(st) = &self.state {
            dn.push(DnType::StateOrProvinceName, st.as_str());
        }
        if let Some(l) = &self.locality {
            dn.push(DnType::LocalityName, l.as_str());
        }
        dn
    }
}

/// Everything needed to mint one certificate.
#[derive(Debug, Clone)]
pub struct CertSpec {
    pub subject: Subject,
    /// DNS names and IP addresses; each entry is auto-classified.
    pub sans: Vec<String>,
    pub validity_days: i64,
    pub template: CertTemplate,
    /// Only meaningful for CA templates. `None` means unconstrained.
    pub path_len_constraint: Option<u8>,
}

impl CertSpec {
    fn build_params(&self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(self.sans.clone())?;
        params.distinguished_name = self.subject.to_distinguished_name();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5); // clock-skew tolerance
        params.not_after = now + Duration::days(self.validity_days.max(1));

        match self.template {
            CertTemplate::ServerAuth => {
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            }
            CertTemplate::ClientAuth => {
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            }
            CertTemplate::CodeSigning => {
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
            }
            CertTemplate::EmailProtection => {
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            }
            CertTemplate::RootCa | CertTemplate::IntermediateCa => {
                params.is_ca = match self.path_len_constraint {
                    Some(n) => IsCa::Ca(rcgen::BasicConstraints::Constrained(n)),
                    None => IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
                };
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::CrlSign,
                ];
            }
        }
        Ok(params)
    }
}

/// A freshly issued certificate.
pub struct IssuedCert {
    der: Vec<u8>,
}

impl IssuedCert {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.der.clone()))
    }
}

/// Create a self-signed certificate (root CA, or a standalone leaf such as a
/// local-dev TLS cert) from `spec` using `key`.
pub fn self_signed(spec: &CertSpec, key: &KeyMaterial) -> Result<IssuedCert> {
    let params = spec.build_params()?;
    let kp = key.to_rcgen_keypair()?;
    let cert = params.self_signed(&kp)?;
    Ok(IssuedCert {
        der: cert.der().to_vec(),
    })
}

/// Issue a new certificate for `subject_key`, signed by `issuer_key` whose
/// certificate is `issuer_cert_pem`. Used for "issuing CA signs a leaf (or a
/// subordinate CA)" without going through a CSR, e.g. the CA workspace's
/// "Issuing CA" creation step.
pub fn issue_leaf(
    spec: &CertSpec,
    subject_key: &KeyMaterial,
    issuer_cert_pem: &str,
    issuer_key: &KeyMaterial,
) -> Result<IssuedCert> {
    let params = spec.build_params()?;
    let subject_kp = subject_key.to_rcgen_keypair()?;
    let issuer_kp = issuer_key.to_rcgen_keypair()?;
    let issuer = Issuer::from_ca_cert_pem(issuer_cert_pem, issuer_kp)
        .map_err(|e| CoreError::CertGeneration(format!("invalid CA certificate: {e}")))?;
    let cert = params.signed_by(&subject_kp, &issuer)?;
    Ok(IssuedCert {
        der: cert.der().to_vec(),
    })
}

/// Issue a certificate from a PEM-encoded CSR, applying `template` and
/// `validity_days` chosen by the operator (the CSR itself only supplies the
/// subject/SANs/public key; the CA decides policy). This is the "sign a
/// pending CSR" action in the CA workspace.
pub fn issue_from_csr(
    csr_pem: &str,
    template: CertTemplate,
    validity_days: i64,
    issuer_cert_pem: &str,
    issuer_key: &KeyMaterial,
) -> Result<IssuedCert> {
    let mut params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| CoreError::CsrParse(e.to_string()))?
        .params;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(validity_days.max(1));

    let spec_like = CertSpec {
        subject: Subject::default(),
        sans: vec![],
        validity_days,
        template,
        path_len_constraint: None,
    };
    // Re-apply the template's usage bits over whatever the requester asked
    // for; the CA's policy wins, never the CSR's own (possibly attacker
    // controlled) extension requests.
    let templated = spec_like.build_params()?;
    params.is_ca = templated.is_ca;
    params.key_usages = templated.key_usages;
    params.extended_key_usages = templated.extended_key_usages;

    let issuer_kp = issuer_key.to_rcgen_keypair()?;
    let issuer = Issuer::from_ca_cert_pem(issuer_cert_pem, issuer_kp)
        .map_err(|e| CoreError::CertGeneration(format!("invalid CA certificate: {e}")))?;

    let csr_params = rcgen::CertificateSigningRequestParams {
        params,
        public_key: rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| CoreError::CsrParse(e.to_string()))?
            .public_key,
    };
    let cert = csr_params.signed_by(&issuer)?;
    Ok(IssuedCert {
        der: cert.der().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Inspecting arbitrary (possibly foreign) certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub sans: Vec<String>,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub signature_algorithm_oid: String,
    pub public_key_kind: String,
    pub public_key_bits: Option<usize>,
    pub sha1_fingerprint_hex: String,
    pub sha256_fingerprint_hex: String,
    pub is_self_signed: bool,
}

pub fn parse_cert_info(der: &[u8]) -> Result<CertInfo> {
    use sha1::{Digest as _, Sha1};
    use sha2::Sha256;

    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| CoreError::CertParse(e.to_string()))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let is_self_signed = subject == issuer;

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                x509_parser::extensions::GeneralName::DNSName(s) => {
                    sans.push(format!("DNS:{s}"))
                }
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    sans.push(format!("IP:{}", format_ip(bytes)))
                }
                x509_parser::extensions::GeneralName::RFC822Name(s) => {
                    sans.push(format!("EMAIL:{s}"))
                }
                x509_parser::extensions::GeneralName::URI(s) => sans.push(format!("URI:{s}")),
                other => sans.push(format!("{other:?}")),
            }
        }
    }

    let (is_ca, path_len_constraint) = match cert.basic_constraints() {
        Ok(Some(bc)) => (bc.value.ca, bc.value.path_len_constraint),
        _ => (false, None),
    };

    let mut key_usage = Vec::new();
    if let Ok(Some(ku)) = cert.key_usage() {
        let ku = ku.value;
        for (flag, name) in [
            (ku.digital_signature(), "digitalSignature"),
            (ku.non_repudiation(), "nonRepudiation"),
            (ku.key_encipherment(), "keyEncipherment"),
            (ku.data_encipherment(), "dataEncipherment"),
            (ku.key_agreement(), "keyAgreement"),
            (ku.key_cert_sign(), "keyCertSign"),
            (ku.crl_sign(), "cRLSign"),
            (ku.encipher_only(), "encipherOnly"),
            (ku.decipher_only(), "decipherOnly"),
        ] {
            if flag {
                key_usage.push(name.to_string());
            }
        }
    }

    let mut eku = Vec::new();
    if let Ok(Some(e)) = cert.extended_key_usage() {
        let e = e.value;
        if e.any {
            eku.push("anyExtendedKeyUsage".to_string());
        }
        if e.server_auth {
            eku.push("serverAuth".to_string());
        }
        if e.client_auth {
            eku.push("clientAuth".to_string());
        }
        if e.code_signing {
            eku.push("codeSigning".to_string());
        }
        if e.email_protection {
            eku.push("emailProtection".to_string());
        }
        if e.time_stamping {
            eku.push("timeStamping".to_string());
        }
        if e.ocsp_signing {
            eku.push("ocspSigning".to_string());
        }
    }

    let (public_key_kind, public_key_bits) = match cert.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            ("RSA".to_string(), Some(rsa.key_size()))
        }
        Ok(x509_parser::public_key::PublicKey::EC(point)) => {
            ("EC".to_string(), Some(point.key_size()))
        }
        Ok(x509_parser::public_key::PublicKey::Unknown(_)) => ("Unknown".to_string(), None),
        _ => ("Unknown".to_string(), None),
    };

    Ok(CertInfo {
        subject,
        issuer,
        serial_hex: cert.raw_serial_as_string(),
        not_before_unix: cert.validity().not_before.timestamp(),
        not_after_unix: cert.validity().not_after.timestamp(),
        sans,
        is_ca,
        path_len_constraint,
        key_usage,
        extended_key_usage: eku,
        signature_algorithm_oid: cert.signature_algorithm.algorithm.to_string(),
        public_key_kind,
        public_key_bits,
        sha1_fingerprint_hex: hex::encode(Sha1::digest(der)),
        sha256_fingerprint_hex: hex::encode(Sha256::digest(der)),
        is_self_signed,
    })
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex::encode(bytes),
    }
}

/// Tiny local hex helper so we don't need another crate dependency just for
/// fingerprint formatting.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyAlg, KeyMaterial};

    fn root_spec() -> CertSpec {
        CertSpec {
            subject: Subject::new("xkeystore Test Root CA"),
            sans: vec![],
            validity_days: 3650,
            template: CertTemplate::RootCa,
            path_len_constraint: None,
        }
    }

    fn leaf_spec(cn: &str) -> CertSpec {
        CertSpec {
            subject: Subject::new(cn),
            sans: vec![cn.to_string(), "127.0.0.1".to_string()],
            validity_days: 365,
            template: CertTemplate::ServerAuth,
            path_len_constraint: None,
        }
    }

    #[test]
    fn self_signed_root_parses_back() {
        let key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let root = self_signed(&root_spec(), &key).unwrap();
        let info = parse_cert_info(root.der()).unwrap();
        assert!(info.is_ca);
        assert!(info.is_self_signed);
        assert!(info.subject.contains("xkeystore Test Root CA"));
        assert_eq!(info.public_key_kind, "EC");
    }

    #[test]
    fn ca_issues_leaf_and_chain_links_up() {
        let root_key = KeyMaterial::generate(KeyAlg::EcP384).unwrap();
        let root = self_signed(&root_spec(), &root_key).unwrap();

        let leaf_key = KeyMaterial::generate(KeyAlg::Rsa2048).unwrap();
        let leaf = issue_leaf(&leaf_spec("svc.example.test"), &leaf_key, &root.pem(), &root_key)
            .unwrap();

        let leaf_info = parse_cert_info(leaf.der()).unwrap();
        assert_eq!(leaf_info.issuer, parse_cert_info(root.der()).unwrap().subject);
        assert!(!leaf_info.is_ca);
        assert!(leaf_info.sans.iter().any(|s| s == "DNS:svc.example.test"));
        assert!(leaf_info.sans.iter().any(|s| s == "IP:127.0.0.1"));
        assert_eq!(leaf_info.public_key_kind, "RSA");
        assert_eq!(leaf_info.public_key_bits, Some(2048));
        assert!(
            leaf_info
                .extended_key_usage
                .iter()
                .any(|e| e == "serverAuth")
        );
    }

    #[test]
    fn csr_is_issued_with_ca_policy_not_requester_policy() {
        let root_key = KeyMaterial::generate(KeyAlg::Ed25519).unwrap();
        let root = self_signed(&root_spec(), &root_key).unwrap();

        // Build a CSR as an untrusted requester would: ask to be a CA, which
        // the issuing CA's own template must override.
        let subject_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let mut csr_params = CertificateParams::new(vec!["requester.example.test".to_string()])
            .unwrap();
        csr_params.distinguished_name = Subject::new("requester").to_distinguished_name();
        csr_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let subject_kp = subject_key.to_rcgen_keypair().unwrap();
        let csr = csr_params.serialize_request(&subject_kp).unwrap();

        let issued = issue_from_csr(
            &csr.pem().unwrap(),
            CertTemplate::ServerAuth,
            90,
            &root.pem(),
            &root_key,
        )
        .unwrap();

        let info = parse_cert_info(issued.der()).unwrap();
        assert!(!info.is_ca, "CA policy must win over the CSR's own request to be a CA");
        assert!(info.sans.iter().any(|s| s == "DNS:requester.example.test"));
    }
}
