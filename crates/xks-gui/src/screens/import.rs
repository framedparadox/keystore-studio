use std::path::PathBuf;

use eframe::egui;
use xks_core::classify::{self, DetectedKind};
use xks_core::keys::KeyMaterial;

use crate::app::AppState;
use crate::identity_record::IdentityRecord;

pub struct QueuedFile {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub kind: DetectedKind,
    pub password_input: String,
    pub needs_password: bool,
    pub resolved: bool,
    pub keys: Vec<KeyMaterial>,
    pub certs: Vec<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct ImportState {
    pub queue: Vec<QueuedFile>,
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Import & classify");
    ui.label("Drop in certificates, keys, CSRs, PKCS#12 or JKS files; encrypted ones get a password prompt right here.");
    ui.add_space(8.0);

    if ui.button("Add files…").clicked() {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            for path in paths {
                match std::fs::read(&path) {
                    Ok(data) => {
                        let kind = classify::detect_kind(&data);
                        let needs_password = matches!(kind, DetectedKind::Pkcs12 | DetectedKind::Jks);
                        let mut qf = QueuedFile {
                            path,
                            data,
                            kind,
                            password_input: String::new(),
                            needs_password,
                            resolved: false,
                            keys: Vec::new(),
                            certs: Vec::new(),
                            error: None,
                        };
                        if !needs_password {
                            resolve(&mut qf, None);
                        }
                        state.import.queue.push(qf);
                    }
                    Err(e) => state.notify(format!("could not read file: {e}")),
                }
            }
        }
    }

    ui.add_space(12.0);
    let mut to_remove = None;
    for (i, qf) in state.import.queue.iter_mut().enumerate() {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(qf.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
                ui.label(format!("{:?}", qf.kind));
                if ui.small_button("remove").clicked() {
                    to_remove = Some(i);
                }
            });

            if qf.needs_password && !qf.resolved {
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut qf.password_input).password(true));
                    if ui.button("Unlock").clicked() {
                        let pw = qf.password_input.clone();
                        resolve(qf, Some(&pw));
                    }
                });
            }
            if let Some(err) = &qf.error {
                ui.colored_label(egui::Color32::from_rgb(0xE0, 0x5A, 0x5A), err);
            }
            if qf.resolved {
                ui.label(format!("{} key(s), {} certificate(s) found", qf.keys.len(), qf.certs.len()));
            }
        });
    }
    if let Some(i) = to_remove {
        state.import.queue.remove(i);
    }

    ui.add_space(12.0);
    let any_resolved = state.import.queue.iter().any(|q| q.resolved && (!q.keys.is_empty() || !q.certs.is_empty()));
    if any_resolved && ui.button("Pair & add to workspace").clicked() {
        pair_and_commit(state);
    }
}

fn resolve(qf: &mut QueuedFile, password: Option<&str>) {
    match classify::classify(&qf.data, password) {
        Ok(result) => {
            if result.needs_password {
                qf.error = if password.is_some() {
                    Some("wrong password".to_string())
                } else {
                    None
                };
                qf.resolved = false;
            } else {
                qf.keys = result.keys;
                qf.certs = result.certs;
                qf.resolved = true;
                qf.error = None;
            }
        }
        Err(e) => {
            qf.error = Some(e.to_string());
        }
    }
}

fn pair_and_commit(state: &mut AppState) {
    let mut all_keys = Vec::new();
    let mut all_certs = Vec::new();
    for qf in state.import.queue.drain(..) {
        if qf.resolved {
            all_keys.extend(qf.keys);
            all_certs.extend(qf.certs);
        }
    }

    let (pairs, leftover_keys, leftover_certs) = match classify::pair_orphans(all_keys, all_certs) {
        Ok(v) => v,
        Err(e) => {
            state.notify(format!("pairing failed: {e}"));
            return;
        }
    };

    let added = pairs.len() + leftover_certs.len();
    for (n, (key, leaf_der)) in pairs.into_iter().enumerate() {
        let alias = format!("imported-{}", state.identities.len() + n);
        let record = IdentityRecord::new(alias, Some(key), Some(leaf_der), leftover_certs.clone());
        state.add_identity(record);
    }
    for cert_der in leftover_certs {
        let alias = xks_core::cert::parse_cert_info(&cert_der)
            .map(|i| i.subject)
            .unwrap_or_else(|_| "imported-cert".to_string());
        let record = IdentityRecord::new(alias, None, Some(cert_der), Vec::new());
        state.add_identity(record);
    }
    if !leftover_keys.is_empty() {
        state.notify(format!("{} private key(s) had no matching certificate and were not added", leftover_keys.len()));
    }
    state.notify(format!("added {added} identity(ies) to the workspace"));
}
