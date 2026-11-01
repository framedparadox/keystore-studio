use xks_core::chain::Finding;
use xks_core::identity::IdentityStatus;
use xks_core::keys::KeyMaterial;

/// The GUI's in-memory workspace entry. Wraps `xks_core::identity::Identity`
/// plus a cached diagnosis so the dashboard table doesn't re-run chain
/// validation (including real signature checks) on every single frame.
pub struct IdentityRecord {
    pub alias: String,
    pub key: Option<KeyMaterial>,
    pub leaf_der: Option<Vec<u8>>,
    pub chain_der: Vec<Vec<u8>>,
    pub status: IdentityStatus,
    pub findings: Vec<Finding>,
}

impl IdentityRecord {
    pub fn new(alias: impl Into<String>, key: Option<KeyMaterial>, leaf_der: Option<Vec<u8>>, chain_der: Vec<Vec<u8>>) -> Self {
        let mut rec = Self {
            alias: alias.into(),
            key,
            leaf_der,
            chain_der,
            status: IdentityStatus::Invalid,
            findings: Vec::new(),
        };
        rec.refresh();
        rec
    }

    pub fn refresh(&mut self) {
        let identity = xks_core::identity::Identity {
            alias: self.alias.clone(),
            key: self.key.clone(),
            leaf_der: self.leaf_der.clone(),
            chain_der: self.chain_der.clone(),
        };
        match identity.diagnose() {
            Ok((status, findings)) => {
                self.status = status;
                self.findings = findings;
            }
            Err(e) => {
                self.status = IdentityStatus::Invalid;
                self.findings = vec![Finding {
                    severity: xks_core::chain::Severity::Error,
                    code: "parse-error",
                    message: e.to_string(),
                    fix_hint: None,
                }];
            }
        }
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            IdentityStatus::Complete => "Complete",
            IdentityStatus::Incomplete => "Incomplete",
            IdentityStatus::Invalid => "Invalid",
            IdentityStatus::CertificateOnly => "Certificate-only",
        }
    }

    pub fn subject_line(&self) -> String {
        match &self.leaf_der {
            Some(der) => xks_core::cert::parse_cert_info(der)
                .map(|i| i.subject)
                .unwrap_or_else(|_| "(unparseable certificate)".to_string()),
            None => "(no certificate)".to_string(),
        }
    }
}
