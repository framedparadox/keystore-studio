use eframe::egui::{self, RichText};
use xks_core::identity::IdentityStatus;

use crate::app::{AppState, Screen};
use crate::theme;

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    let palette = theme::palette(state.dark);
    ui.heading("Workspace");
    ui.label("Everything you've imported or created this session, with its health at a glance.");
    ui.add_space(12.0);

    let complete = state.identities.iter().filter(|i| i.status == IdentityStatus::Complete).count();
    let incomplete = state.identities.iter().filter(|i| i.status == IdentityStatus::Incomplete).count();
    let invalid = state.identities.iter().filter(|i| i.status == IdentityStatus::Invalid).count();
    let cert_only = state.identities.iter().filter(|i| i.status == IdentityStatus::CertificateOnly).count();

    ui.horizontal(|ui| {
        stat_tile(ui, "Complete", complete, palette.success);
        stat_tile(ui, "Incomplete", incomplete, palette.warning);
        stat_tile(ui, "Invalid", invalid, palette.danger);
        stat_tile(ui, "Certificate-only", cert_only, palette.text_dim);
    });

    ui.add_space(16.0);
    if ui.button("Import files…").clicked() {
        state.screen = Screen::Import;
    }
    ui.add_space(8.0);

    egui::Grid::new("identity_table").striped(true).min_col_width(120.0).show(ui, |ui| {
        ui.label(RichText::new("Alias").strong());
        ui.label(RichText::new("Subject").strong());
        ui.label(RichText::new("Status").strong());
        ui.label("");
        ui.end_row();

        for i in 0..state.identities.len() {
            let (alias, subject, status_label, color) = {
                let rec = &state.identities[i];
                let color = status_color(palette, rec.status);
                (rec.alias.clone(), rec.subject_line(), rec.status_label(), color)
            };
            ui.label(alias);
            ui.label(subject);
            ui.colored_label(color, status_label);
            if ui.button("Open").clicked() {
                state.selected = Some(i);
                state.screen = Screen::IdentityDetail;
            }
            ui.end_row();
        }
    });

    let attention: Vec<usize> = state
        .identities
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.status, IdentityStatus::Invalid | IdentityStatus::Incomplete))
        .map(|(i, _)| i)
        .collect();
    if !attention.is_empty() {
        ui.add_space(16.0);
        ui.colored_label(palette.warning, format!("Needs attention ({})", attention.len()));
        for i in attention {
            let rec = &state.identities[i];
            ui.label(format!("• {} — {}", rec.alias, rec.findings.first().map(|f| f.message.as_str()).unwrap_or("see detail")));
        }
    }

    ui.add_space(16.0);
    ui.separator();
    ui.label(RichText::new("Local audit log").strong());
    if let Ok(entries) = state.audit.read_all() {
        for entry in entries.iter().rev().take(8) {
            ui.label(format!("{} — {} {}", entry.timestamp_unix, entry.action, entry.alias.as_deref().unwrap_or("")));
        }
    }
}

fn stat_tile(ui: &mut egui::Ui, label: &str, count: usize, color: egui::Color32) {
    ui.group(|ui| {
        ui.set_min_width(120.0);
        ui.vertical(|ui| {
            ui.colored_label(color, RichText::new(count.to_string()).size(28.0).strong());
            ui.label(label);
        });
    });
}

fn status_color(palette: &theme::Palette, status: IdentityStatus) -> egui::Color32 {
    match status {
        IdentityStatus::Complete => palette.success,
        IdentityStatus::Incomplete => palette.warning,
        IdentityStatus::Invalid => palette.danger,
        IdentityStatus::CertificateOnly => palette.text_dim,
    }
}
