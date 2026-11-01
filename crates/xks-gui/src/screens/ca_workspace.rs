use eframe::egui;
use xks_core::ca::{self, RevokedEntry};
use xks_core::cert;

use crate::app::AppState;

#[derive(Default)]
pub struct CaState {
    pub csr_path: Option<std::path::PathBuf>,
    pub csr_issuer: Option<usize>,
    pub csr_days: String,
    pub crl_issuer: Option<usize>,
    pub crl_number: String,
    pub crl_days: String,
    pub crl_revoke: String,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("CA workspace");
    ui.label("Root and issuing CAs in your workspace, plus CSR signing and CRL publishing.");
    ui.add_space(8.0);

    ui.label(egui::RichText::new("CA hierarchy").strong());
    let mut any_ca = false;
    for rec in &state.identities {
        let is_ca = rec
            .leaf_der
            .as_ref()
            .and_then(|d| cert::parse_cert_info(d).ok())
            .map(|i| i.is_ca)
            .unwrap_or(false);
        if is_ca {
            any_ca = true;
            ui.label(format!("• {} — {}", rec.alias, rec.subject_line()));
        }
    }
    if !any_ca {
        ui.label("No CA identities yet. Use \"Create keystore\" with the Root CA or Issuing CA template to make one.");
    }

    ui.add_space(16.0);
    ui.separator();
    ui.label(egui::RichText::new("Sign a pending CSR").strong());
    if ui.button("Open CSR file…").clicked() {
        state.ca.csr_path = rfd::FileDialog::new().pick_file();
    }
    if let Some(p) = &state.ca.csr_path {
        ui.label(format!("CSR: {}", p.display()));
    }
    ca_issuer_picker(ui, state, true);
    ui.horizontal(|ui| {
        ui.label("Validity (days):");
        ui.text_edit_singleline(&mut state.ca.csr_days);
    });
    if ui.button("Sign CSR & save certificate…").clicked() {
        sign_csr(state);
    }

    ui.add_space(16.0);
    ui.separator();
    ui.label(egui::RichText::new("Certificate Revocation List").strong());
    ca_issuer_picker(ui, state, false);
    ui.horizontal(|ui| {
        ui.label("CRL number:");
        ui.text_edit_singleline(&mut state.ca.crl_number);
    });
    ui.horizontal(|ui| {
        ui.label("Valid for (days):");
        ui.text_edit_singleline(&mut state.ca.crl_days);
    });
    ui.horizontal(|ui| {
        ui.label("Revoke serials (hex, comma-separated):");
        ui.text_edit_singleline(&mut state.ca.crl_revoke);
    });
    if ui.button("Publish CRL…").clicked() {
        publish_crl(state);
    }
}

fn ca_issuer_picker(ui: &mut egui::Ui, state: &mut AppState, for_csr: bool) {
    let selected = if for_csr { state.ca.csr_issuer } else { state.ca.crl_issuer };
    let label = selected
        .and_then(|i| state.identities.get(i))
        .map(|r| r.alias.clone())
        .unwrap_or_else(|| "(choose a CA)".to_string());
    ui.horizontal(|ui| {
        ui.label("Issuing CA:");
        egui::ComboBox::from_id_salt(if for_csr { "csr_ca_picker" } else { "crl_ca_picker" })
            .selected_text(label)
            .show_ui(ui, |ui| {
                for i in 0..state.identities.len() {
                    if state.identities[i].key.is_none() {
                        continue;
                    }
                    let alias = state.identities[i].alias.clone();
                    let target = if for_csr { &mut state.ca.csr_issuer } else { &mut state.ca.crl_issuer };
                    ui.selectable_value(target, Some(i), alias);
                }
            });
    });
}

fn sign_csr(state: &mut AppState) {
    let Some(csr_path) = state.ca.csr_path.clone() else {
        state.notify("choose a CSR file first");
        return;
    };
    let Some(issuer_idx) = state.ca.csr_issuer else {
        state.notify("choose an issuing CA first");
        return;
    };
    let days: i64 = state.ca.csr_days.trim().parse().unwrap_or(365);

    let csr_pem = match std::fs::read_to_string(&csr_path) {
        Ok(s) => s,
        Err(e) => {
            state.notify(format!("could not read CSR: {e}"));
            return;
        }
    };
    let Some(issuer) = state.identities.get(issuer_idx) else { return };
    let (Some(issuer_key), Some(issuer_leaf)) = (issuer.key.clone(), issuer.leaf_der.clone()) else {
        state.notify("selected CA has no usable key/certificate");
        return;
    };
    let issuer_pem = pem::encode(&pem::Pem::new("CERTIFICATE", issuer_leaf));

    match cert::issue_from_csr(&csr_pem, cert::CertTemplate::ServerAuth, days, &issuer_pem, &issuer_key) {
        Ok(issued) => {
            if let Some(path) = rfd::FileDialog::new().set_file_name("issued.crt").save_file() {
                if std::fs::write(&path, issued.pem()).is_ok() {
                    state.log("ca.issue", None, format!("signed CSR {}", csr_path.display()));
                    state.notify(format!("wrote {}", path.display()));
                }
            }
        }
        Err(e) => state.notify(format!("signing failed: {e}")),
    }
}

fn publish_crl(state: &mut AppState) {
    let Some(issuer_idx) = state.ca.crl_issuer else {
        state.notify("choose a CA first");
        return;
    };
    let Ok(crl_number) = state.ca.crl_number.trim().parse::<u64>() else {
        state.notify("CRL number must be a positive integer");
        return;
    };
    let days: i64 = state.ca.crl_days.trim().parse().unwrap_or(7);

    let mut revoked = Vec::new();
    for hex in state.ca.crl_revoke.split(',') {
        let hex = hex.trim();
        if hex.is_empty() {
            continue;
        }
        match decode_hex(hex) {
            Ok(serial) => revoked.push(RevokedEntry {
                serial,
                reason: None,
                revoked_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
            }),
            Err(_) => {
                state.notify(format!("'{hex}' is not valid hex"));
                return;
            }
        }
    }

    let Some(issuer) = state.identities.get(issuer_idx) else { return };
    let (Some(issuer_key), Some(issuer_leaf)) = (issuer.key.clone(), issuer.leaf_der.clone()) else {
        state.notify("selected CA has no usable key/certificate");
        return;
    };
    let issuer_pem = pem::encode(&pem::Pem::new("CERTIFICATE", issuer_leaf));

    match ca::build_crl(&issuer_pem, &issuer_key, crl_number, days, &revoked) {
        Ok(der) => {
            if let Some(path) = rfd::FileDialog::new().set_file_name("ca.crl").save_file() {
                let pem_text = pem::encode(&pem::Pem::new("X509 CRL", der));
                if std::fs::write(&path, pem_text).is_ok() {
                    state.notify(format!("wrote {}", path.display()));
                }
            }
        }
        Err(e) => state.notify(format!("CRL generation failed: {e}")),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
