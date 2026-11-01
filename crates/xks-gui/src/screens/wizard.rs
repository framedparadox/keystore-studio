use eframe::egui;
use xks_core::cert::{self, CertSpec, CertTemplate, Subject};
use xks_core::keys::{KeyAlg, KeyMaterial};

use crate::app::AppState;
use crate::identity_record::IdentityRecord;

pub struct WizardState {
    pub alg: KeyAlg,
    pub common_name: String,
    pub organization: String,
    pub sans: String,
    pub days: i64,
    pub template: CertTemplate,
    pub path_len: String,
    pub issuer: Option<usize>,
    pub alias: String,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            alg: KeyAlg::EcP256,
            common_name: String::new(),
            organization: String::new(),
            sans: String::new(),
            days: 365,
            template: CertTemplate::ServerAuth,
            path_len: String::new(),
            issuer: None,
            alias: String::new(),
        }
    }
}

const ALGS: &[(KeyAlg, &str)] = &[
    (KeyAlg::EcP256, "ECDSA P-256 (recommended)"),
    (KeyAlg::EcP384, "ECDSA P-384"),
    (KeyAlg::Ed25519, "Ed25519"),
    (KeyAlg::Rsa2048, "RSA 2048"),
    (KeyAlg::Rsa3072, "RSA 3072"),
    (KeyAlg::Rsa4096, "RSA 4096"),
];

const TEMPLATES: &[(CertTemplate, &str)] = &[
    (CertTemplate::ServerAuth, "TLS Server"),
    (CertTemplate::ClientAuth, "TLS Client / mTLS"),
    (CertTemplate::CodeSigning, "Code Signing"),
    (CertTemplate::EmailProtection, "Email (S/MIME)"),
    (CertTemplate::RootCa, "Root CA"),
    (CertTemplate::IntermediateCa, "Issuing CA"),
];

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Create keystore");
    ui.label("Generate a key, issue a certificate for it, and add the result to your workspace.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Key algorithm:");
        egui::ComboBox::from_id_salt("wizard_alg")
            .selected_text(label_for(&state.wizard.alg, ALGS))
            .show_ui(ui, |ui| {
                for (alg, label) in ALGS {
                    ui.selectable_value(&mut state.wizard.alg, *alg, *label);
                }
            });
    });

    ui.horizontal(|ui| {
        ui.label("Common name (CN):");
        ui.text_edit_singleline(&mut state.wizard.common_name);
    });
    ui.horizontal(|ui| {
        ui.label("Organization (optional):");
        ui.text_edit_singleline(&mut state.wizard.organization);
    });
    ui.horizontal(|ui| {
        ui.label("SANs (comma-separated DNS/IP):");
        ui.text_edit_singleline(&mut state.wizard.sans);
    });
    ui.horizontal(|ui| {
        ui.label("Validity (days):");
        ui.add(egui::DragValue::new(&mut state.wizard.days).range(1..=36500));
    });
    ui.horizontal(|ui| {
        ui.label("Template:");
        egui::ComboBox::from_id_salt("wizard_template")
            .selected_text(label_for(&state.wizard.template, TEMPLATES))
            .show_ui(ui, |ui| {
                for (t, label) in TEMPLATES {
                    ui.selectable_value(&mut state.wizard.template, *t, *label);
                }
            });
    });
    if matches!(state.wizard.template, CertTemplate::RootCa | CertTemplate::IntermediateCa) {
        ui.horizontal(|ui| {
            ui.label("Path length constraint (blank = unconstrained):");
            ui.text_edit_singleline(&mut state.wizard.path_len);
        });
    }

    ui.add_space(8.0);
    ui.label("Issue with:");
    ui.radio_value(&mut state.wizard.issuer, None, "Self-signed");
    for i in 0..state.identities.len() {
        let is_ca = state.identities[i]
            .leaf_der
            .as_ref()
            .and_then(|d| cert::parse_cert_info(d).ok())
            .map(|info| info.is_ca)
            .unwrap_or(false);
        if is_ca && state.identities[i].key.is_some() {
            let alias = state.identities[i].alias.clone();
            ui.radio_value(&mut state.wizard.issuer, Some(i), format!("Signed by: {alias}"));
        }
    }

    ui.horizontal(|ui| {
        ui.label("Alias for the new identity:");
        ui.text_edit_singleline(&mut state.wizard.alias);
    });

    ui.add_space(12.0);
    if ui.button("Generate").clicked() {
        generate(state);
    }
}

fn label_for<T: PartialEq + Copy>(value: &T, options: &[(T, &str)]) -> String {
    options.iter().find(|(v, _)| v == value).map(|(_, l)| l.to_string()).unwrap_or_default()
}

fn generate(state: &mut AppState) {
    if state.wizard.common_name.trim().is_empty() {
        state.notify("a common name (CN) is required");
        return;
    }
    let path_len = if state.wizard.path_len.trim().is_empty() {
        None
    } else {
        match state.wizard.path_len.trim().parse::<u8>() {
            Ok(v) => Some(v),
            Err(_) => {
                state.notify("path length must be a small positive number");
                return;
            }
        }
    };

    let key = match KeyMaterial::generate(state.wizard.alg) {
        Ok(k) => k,
        Err(e) => {
            state.notify(format!("key generation failed: {e}"));
            return;
        }
    };

    let mut subject = Subject::new(state.wizard.common_name.trim());
    if !state.wizard.organization.trim().is_empty() {
        subject.organization = Some(state.wizard.organization.trim().to_string());
    }
    let sans: Vec<String> = state
        .wizard
        .sans
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let spec = CertSpec {
        subject,
        sans,
        validity_days: state.wizard.days,
        template: state.wizard.template,
        path_len_constraint: path_len,
    };

    let issued = match state.wizard.issuer {
        None => cert::self_signed(&spec, &key),
        Some(idx) => {
            let Some(issuer_rec) = state.identities.get(idx) else {
                state.notify("selected issuer no longer exists");
                return;
            };
            let (Some(issuer_key), Some(issuer_leaf)) = (issuer_rec.key.clone(), issuer_rec.leaf_der.clone()) else {
                state.notify("selected issuer has no usable key/certificate");
                return;
            };
            let issuer_pem = pem::encode(&pem::Pem::new("CERTIFICATE", issuer_leaf));
            cert::issue_leaf(&spec, &key, &issuer_pem, &issuer_key)
        }
    };

    match issued {
        Ok(issued) => {
            let alias = if state.wizard.alias.trim().is_empty() {
                state.wizard.common_name.trim().to_string()
            } else {
                state.wizard.alias.trim().to_string()
            };
            let chain = match state.wizard.issuer {
                Some(idx) => {
                    let mut c = vec![state.identities[idx].leaf_der.clone().unwrap_or_default()];
                    c.extend(state.identities[idx].chain_der.clone());
                    c
                }
                None => Vec::new(),
            };
            let record = IdentityRecord::new(alias, Some(key), Some(issued.der().to_vec()), chain);
            state.add_identity(record);
            state.notify("identity created");
        }
        Err(e) => state.notify(format!("issuance failed: {e}")),
    }
}
