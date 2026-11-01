//! Certificate Revocation List (CRL) generation for the CA workspace. The
//! rest of "being a CA" — creating a root, creating an issuing CA under
//! it, signing a CSR — is already `cert::self_signed` / `cert::issue_leaf`
//! / `cert::issue_from_csr`; this module adds the one CA-only operation
//! those don't cover.

pub use rcgen::RevocationReason;
use rcgen::{CertificateRevocationListParams, Issuer, RevokedCertParams, SerialNumber};
use time::{Duration, OffsetDateTime};

use crate::error::{CoreError, Result};
use crate::keys::KeyMaterial;

/// One entry in a CRL being built.
pub struct RevokedEntry {
    /// Raw (DER) serial number bytes of the revoked certificate.
    pub serial: Vec<u8>,
    pub reason: Option<RevocationReason>,
    pub revoked_at_unix: i64,
}

/// Issue a new CRL signed by the CA identified by `ca_cert_pem`/`ca_key`,
/// listing every entry in `revoked`. `crl_number` must increase on every
/// CRL this CA issues (it's how clients tell a newer CRL from an older
/// one); `validity_days` controls how long until `next_update`.
pub fn build_crl(
    ca_cert_pem: &str,
    ca_key: &KeyMaterial,
    crl_number: u64,
    validity_days: i64,
    revoked: &[RevokedEntry],
) -> Result<Vec<u8>> {
    let now = OffsetDateTime::now_utc();
    let revoked_certs = revoked
        .iter()
        .map(|r| -> Result<RevokedCertParams> {
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from(r.serial.clone()),
                revocation_time: OffsetDateTime::from_unix_timestamp(r.revoked_at_unix)
                    .map_err(|e| CoreError::Other(format!("bad revocation timestamp: {e}")))?,
                reason_code: r.reason,
                invalidity_date: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + Duration::days(validity_days.max(1)),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let ca_kp = ca_key.to_rcgen_keypair()?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_kp)
        .map_err(|e| CoreError::CertGeneration(format!("invalid CA certificate: {e}")))?;
    let crl = params
        .signed_by(&issuer)
        .map_err(|e| CoreError::CertGeneration(format!("could not sign CRL: {e}")))?;
    Ok(crl.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{self, CertSpec, CertTemplate, Subject};
    use crate::keys::KeyAlg;

    #[test]
    fn crl_lists_every_revoked_serial() {
        let root_key = KeyMaterial::generate(KeyAlg::EcP256).unwrap();
        let root = cert::self_signed(
            &CertSpec {
                subject: Subject::new("Root"),
                sans: vec![],
                validity_days: 3650,
                template: CertTemplate::RootCa,
                path_len_constraint: None,
            },
            &root_key,
        )
        .unwrap();

        let revoked = vec![
            RevokedEntry {
                serial: vec![0x01, 0x02, 0x03],
                reason: Some(RevocationReason::KeyCompromise),
                revoked_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            },
            RevokedEntry {
                serial: vec![0x0a, 0x0b],
                reason: None,
                revoked_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            },
        ];

        let crl_der = build_crl(&root.pem(), &root_key, 1, 7, &revoked).unwrap();
        use x509_parser::prelude::FromDer;
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&crl_der).unwrap();
        let listed: Vec<_> = crl.iter_revoked_certificates().collect();
        assert_eq!(listed.len(), 2);
    }
}
