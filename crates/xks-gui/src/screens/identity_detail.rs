use eframe::egui::{self, RichText};
use xks_core::chain::Severity;
use xks_core::{jks, pem as pem_mod, pkcs12};

use crate::app::AppState;
use crate::theme;

#[derive(Default)]
pub struct DetailState {
    pub export_open: bool,
    pub export_format: ExportFormat,
    pub password: String,
    pub legacy: bool,
}

#[derive(Default, PartialEq, Clone, Copy)]
pub enum ExportFormat {
    #[default]
    Pkcs12,
    Jks,
    PemBundle,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(idx) = state.selected else {
        ui.heading("Identity detail");
        ui.label("Select an identity from the Workspace screen first.");
        return;
    };
    if idx >= state.identities.len() {
        state.selected = None;
        return;
    }

    let palette = theme::palette(state.dark);
    let (alias, status_label, findings, leaf_der, chain_der, has_key) = {
        let rec = &state.identities[idx];
        (
            rec.alias.clone(),
            rec.status_label(),
            rec.findings.clone(),
            rec.leaf_der.clone(),
            rec.chain_der.clone(),
            rec.key.is_some(),
        )
    };

    ui.heading(format!("Identity: {alias}"));
    ui.label(format!("Status: {status_label}"));
    ui.add_space(8.0);

    if let Some(leaf) = &leaf_der {
        ui.group(|ui| {
            ui.label(RichText::new("Chain").strong());
            render_cert_card(ui, palette, leaf, "leaf");
            for (i, c) in chain_der.iter().enumerate() {
                render_cert_card(ui, palette, c, &format!("chain #{i}"));
            }
        });
    }

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.label(RichText::new("Validation report").strong());
        if findings.is_empty() {
            ui.colored_label(palette.success, "No issues found.");
        }
        for f in &findings {
            let color = match f.severity {
                Severity::Error => palette.danger,
                Severity::Warning => palette.warning,
                Severity::Info => palette.text_dim,
            };
            ui.colored_label(color, format!("[{:?}] {}", f.severity, f.message));
            if let Some(hint) = &f.fix_hint {
                ui.label(RichText::new(format!("   fix: {hint}")).italics());
            }
        }
    });

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.label(RichText::new("Private key").strong());
        if has_key {
            ui.label("A private key is present. It is never displayed; export requires a password.");
        } else {
            ui.label("No private key — this identity is certificate-only and cannot be exported as a PKCS#12/JKS with a key.");
        }
    });

    ui.add_space(12.0);
    if ui.button("Export…").clicked() {
        state.detail.export_open = true;
    }

    if state.detail.export_open {
        let mut open = true;
        egui::Window::new(format!("Export {alias}")).open(&mut open).show(ui.ctx(), |ui| {
            ui.radio_value(&mut state.detail.export_format, ExportFormat::Pkcs12, "PKCS#12 (.p12/.pfx)");
            ui.radio_value(&mut state.detail.export_format, ExportFormat::Jks, "JKS (.jks)");
            ui.radio_value(&mut state.detail.export_format, ExportFormat::PemBundle, "PEM bundle");
            if state.detail.export_format != ExportFormat::PemBundle {
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut state.detail.password).password(true));
                });
                if state.detail.export_format == ExportFormat::Pkcs12 {
                    ui.checkbox(&mut state.detail.legacy, "Legacy 3DES (old Java / hardware compatibility)");
                }
                let assessment = xks_core::password::assess(&state.detail.password, &[alias.as_str()]);
                ui.label(format!("strength: {}", assessment.strength.label()));
            }

            if ui.button("Save as…").clicked() {
                do_export(idx, state, &alias, leaf_der.clone(), chain_der.clone());
            }
        });
        state.detail.export_open = open;
    }
}

fn do_export(
    idx: usize,
    state: &mut AppState,
    alias: &str,
    leaf_der: Option<Vec<u8>>,
    chain_der: Vec<Vec<u8>>,
) {
    let Some(leaf) = leaf_der else {
        state.notify("no certificate to export");
        return;
    };
    let key = state.identities[idx].key.clone();

    let (default_ext, bytes_result): (&str, anyhow::Result<Vec<u8>>) = match state.detail.export_format {
        ExportFormat::Pkcs12 => {
            let Some(key) = key else {
                state.notify("this identity has no private key; use the Converter for a truststore-only export");
                return;
            };
            let enc = if state.detail.legacy { pkcs12::PfxEncryption::LegacyCompatible } else { pkcs12::PfxEncryption::Modern };
            ("p12", pkcs12::export_pfx(&state.detail.password, alias, &key, &leaf, &chain_der, enc).map_err(Into::into))
        }
        ExportFormat::Jks => {
            let Some(key) = key else {
                state.notify("this identity has no private key");
                return;
            };
            ("jks", jks::export_jks(&state.detail.password, alias, &key, &leaf, &chain_der).map_err(Into::into))
        }
        ExportFormat::PemBundle => {
            let bundle = pem_mod::export_bundle(key.as_ref(), &leaf, &chain_der);
            ("pem", Ok(bundle.into_bytes()))
        }
    };

    match bytes_result {
        Ok(bytes) => {
            if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{alias}.{default_ext}")).save_file() {
                if let Err(e) = std::fs::write(&path, &bytes) {
                    state.notify(format!("could not write file: {e}"));
                } else {
                    state.log("export", Some(alias), format!("{:?} -> {}", state.detail.export_format_label(), path.display()));
                    state.notify(format!("wrote {}", path.display()));
                    state.detail.export_open = false;
                }
            }
        }
        Err(e) => state.notify(format!("export failed: {e}")),
    }
}

impl DetailState {
    fn export_format_label(&self) -> &'static str {
        match self.export_format {
            ExportFormat::Pkcs12 => "pkcs12",
            ExportFormat::Jks => "jks",
            ExportFormat::PemBundle => "pem",
        }
    }
}

fn render_cert_card(ui: &mut egui::Ui, palette: &theme::Palette, der: &[u8], label: &str) {
    match xks_core::cert::parse_cert_info(der) {
        Ok(info) => {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).weak());
                ui.label(&info.subject);
                if info.is_ca {
                    ui.colored_label(palette.ember_text, "CA");
                }
            });
        }
        Err(e) => {
            ui.colored_label(palette.danger, format!("{label}: could not parse ({e})"));
        }
    }
}
