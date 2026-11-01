use eframe::egui;
use xks_core::classify::{self, DetectedKind};
use xks_core::keys::KeyMaterial;
use xks_core::{jks, pem as pem_mod, pkcs12};

use crate::app::AppState;

#[derive(Default)]
pub struct ConverterState {
    pub loaded_path: Option<std::path::PathBuf>,
    pub kind: Option<DetectedKind>,
    pub password_in: String,
    pub needs_password: bool,
    pub key: Option<KeyMaterial>,
    pub leaf: Option<Vec<u8>>,
    pub chain: Vec<Vec<u8>>,
    pub out_format: OutFormat,
    pub alias: String,
    pub password_out: String,
    pub legacy: bool,
}

#[derive(Default, PartialEq, Clone, Copy)]
pub enum OutFormat {
    #[default]
    Pkcs12,
    Jks,
    PemBundle,
    PemSeparate,
    Der,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Converter");
    ui.label("Open any certificate/key/keystore file and re-export it in another format.");
    ui.add_space(8.0);

    if ui.button("Open file…").clicked() {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            load_file(state, path);
        }
    }

    if let Some(kind) = state.converter.kind {
        ui.label(format!("detected: {kind:?}"));
        if state.converter.needs_password {
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(egui::TextEdit::singleline(&mut state.converter.password_in).password(true));
                if ui.button("Unlock").clicked() {
                    unlock(state);
                }
            });
        } else {
            ui.label(format!(
                "{} private key(s), {} certificate(s) loaded",
                state.converter.key.is_some() as usize,
                1 + state.converter.chain.len()
            ));

            ui.add_space(8.0);
            ui.label("Convert to:");
            ui.radio_value(&mut state.converter.out_format, OutFormat::Pkcs12, "PKCS#12 (.p12/.pfx)");
            ui.radio_value(&mut state.converter.out_format, OutFormat::Jks, "JKS (.jks)");
            ui.radio_value(&mut state.converter.out_format, OutFormat::PemBundle, "PEM bundle");
            ui.radio_value(&mut state.converter.out_format, OutFormat::PemSeparate, "PEM (separate files)");
            ui.radio_value(&mut state.converter.out_format, OutFormat::Der, "DER (leaf certificate only)");

            if matches!(state.converter.out_format, OutFormat::Pkcs12 | OutFormat::Jks) {
                ui.horizontal(|ui| {
                    ui.label("Alias:");
                    ui.text_edit_singleline(&mut state.converter.alias);
                });
                ui.horizontal(|ui| {
                    ui.label("New password:");
                    ui.add(egui::TextEdit::singleline(&mut state.converter.password_out).password(true));
                });
                if state.converter.out_format == OutFormat::Pkcs12 {
                    ui.checkbox(&mut state.converter.legacy, "Legacy 3DES (old Java / hardware compatibility)");
                }
            }

            if ui.button("Convert & save as…").clicked() {
                convert_and_save(state);
            }
        }
    }
}

fn load_file(state: &mut AppState, path: std::path::PathBuf) {
    match std::fs::read(&path) {
        Ok(data) => {
            let kind = classify::detect_kind(&data);
            state.converter.loaded_path = Some(path);
            state.converter.kind = Some(kind);
            state.converter.needs_password = matches!(kind, DetectedKind::Pkcs12 | DetectedKind::Jks);
            state.converter.key = None;
            state.converter.leaf = None;
            state.converter.chain.clear();
            if !state.converter.needs_password {
                apply_classified(state, &data, None);
            }
        }
        Err(e) => state.notify(format!("could not read file: {e}")),
    }
}

fn unlock(state: &mut AppState) {
    let Some(path) = state.converter.loaded_path.clone() else { return };
    let Ok(data) = std::fs::read(&path) else { return };
    let pw = state.converter.password_in.clone();
    apply_classified(state, &data, Some(&pw));
}

fn apply_classified(state: &mut AppState, data: &[u8], password: Option<&str>) {
    match classify::classify(data, password) {
        Ok(result) if result.needs_password => {
            state.converter.needs_password = true;
            if password.is_some() {
                state.notify("wrong password");
            }
        }
        Ok(result) => {
            state.converter.needs_password = false;
            state.converter.key = result.keys.into_iter().next();
            let mut certs = result.certs.into_iter();
            state.converter.leaf = certs.next();
            state.converter.chain = certs.collect();
        }
        Err(e) => state.notify(format!("could not classify file: {e}")),
    }
}

fn convert_and_save(state: &mut AppState) {
    let Some(leaf) = state.converter.leaf.clone() else {
        state.notify("no certificate loaded");
        return;
    };
    let key = state.converter.key.clone();
    let chain = state.converter.chain.clone();
    let alias = if state.converter.alias.trim().is_empty() { "xkeystore".to_string() } else { state.converter.alias.trim().to_string() };

    let (ext, bytes): (&str, anyhow::Result<Vec<u8>>) = match state.converter.out_format {
        OutFormat::Pkcs12 => {
            let Some(key) = key else { state.notify("a private key is required for PKCS#12"); return };
            let enc = if state.converter.legacy { pkcs12::PfxEncryption::LegacyCompatible } else { pkcs12::PfxEncryption::Modern };
            ("p12", pkcs12::export_pfx(&state.converter.password_out, &alias, &key, &leaf, &chain, enc).map_err(Into::into))
        }
        OutFormat::Jks => {
            let Some(key) = key else { state.notify("a private key is required for JKS"); return };
            ("jks", jks::export_jks(&state.converter.password_out, &alias, &key, &leaf, &chain).map_err(Into::into))
        }
        OutFormat::PemBundle => ("pem", Ok(pem_mod::export_bundle(key.as_ref(), &leaf, &chain).into_bytes())),
        OutFormat::PemSeparate => {
            let sep = pem_mod::export_separate(key.as_ref(), &leaf, &chain);
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                let mut ok = true;
                if let Some(k) = &sep.key_pem {
                    ok &= std::fs::write(dir.join(format!("{alias}.key")), k).is_ok();
                }
                ok &= std::fs::write(dir.join(format!("{alias}.crt")), &sep.cert_pem).is_ok();
                if !chain.is_empty() {
                    ok &= std::fs::write(dir.join(format!("{alias}.chain.crt")), &sep.chain_pem).is_ok();
                }
                state.notify(if ok { format!("wrote files to {}", dir.display()) } else { "some files failed to write".to_string() });
            }
            return;
        }
        OutFormat::Der => ("der", Ok(leaf.clone())),
    };

    match bytes {
        Ok(bytes) => {
            if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{alias}.{ext}")).save_file() {
                match std::fs::write(&path, &bytes) {
                    Ok(_) => state.notify(format!("wrote {}", path.display())),
                    Err(e) => state.notify(format!("could not write file: {e}")),
                }
            }
        }
        Err(e) => state.notify(format!("conversion failed: {e}")),
    }
}
