use eframe::egui;
use xks_core::audit::AuditLog;

use crate::identity_record::IdentityRecord;
use crate::screens::{ca_workspace, converter, dashboard, identity_detail, import, wizard};
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Import,
    IdentityDetail,
    Wizard,
    Converter,
    CaWorkspace,
}

pub struct AppState {
    pub identities: Vec<IdentityRecord>,
    pub selected: Option<usize>,
    pub dark: bool,
    pub screen: Screen,
    pub status_message: Option<String>,
    pub audit: AuditLog,

    pub import: import::ImportState,
    pub detail: identity_detail::DetailState,
    pub wizard: wizard::WizardState,
    pub converter: converter::ConverterState,
    pub ca: ca_workspace::CaState,
}

impl AppState {
    fn new() -> Self {
        let audit_path = dirs_audit_path();
        Self {
            identities: Vec::new(),
            selected: None,
            dark: true,
            screen: Screen::Dashboard,
            status_message: None,
            audit: AuditLog::open(audit_path),
            import: Default::default(),
            detail: Default::default(),
            wizard: wizard::WizardState::default(),
            converter: Default::default(),
            ca: Default::default(),
        }
    }

    pub fn log(&self, action: &str, alias: Option<&str>, detail: impl Into<String>) {
        let entry = xks_core::audit::AuditEntry::now(action, alias, detail);
        let _ = self.audit.record(&entry);
    }

    pub fn add_identity(&mut self, record: IdentityRecord) {
        self.log("identity.add", Some(&record.alias), record.subject_line());
        self.identities.push(record);
        self.selected = Some(self.identities.len() - 1);
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }
}

fn dirs_audit_path() -> std::path::PathBuf {
    let base = std::env::var_os("XKS_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".xkeystore")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("audit.jsonl")
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

pub struct XksApp {
    pub state: AppState,
}

impl Default for XksApp {
    fn default() -> Self {
        Self { state: AppState::new() }
    }
}

impl eframe::App for XksApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        theme::apply(ui.ctx(), self.state.dark);

        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("xkeystore");
                ui.label(egui::RichText::new("certificates, keys & keystores — no Java, no OpenSSL").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if self.state.dark { "☀ Light" } else { "🌙 Dark" };
                    if ui.button(label).clicked() {
                        self.state.dark = !self.state.dark;
                    }
                });
            });
        });

        egui::Panel::left("nav").resizable(false).show(ui, |ui| {
            ui.add_space(8.0);
            nav_button(ui, &mut self.state, Screen::Dashboard, "Workspace");
            nav_button(ui, &mut self.state, Screen::Import, "Import & classify");
            nav_button(ui, &mut self.state, Screen::IdentityDetail, "Identity detail");
            nav_button(ui, &mut self.state, Screen::Wizard, "Create keystore");
            nav_button(ui, &mut self.state, Screen::Converter, "Converter");
            nav_button(ui, &mut self.state, Screen::CaWorkspace, "CA workspace");
        });

        if let Some(msg) = self.state.status_message.clone() {
            egui::Panel::bottom("status").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(msg);
                    if ui.small_button("dismiss").clicked() {
                        self.state.status_message = None;
                    }
                });
            });
        }

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.state.screen {
                Screen::Dashboard => dashboard::show(ui, &mut self.state),
                Screen::Import => import::show(ui, &mut self.state),
                Screen::IdentityDetail => identity_detail::show(ui, &mut self.state),
                Screen::Wizard => wizard::show(ui, &mut self.state),
                Screen::Converter => converter::show(ui, &mut self.state),
                Screen::CaWorkspace => ca_workspace::show(ui, &mut self.state),
            });
        });
    }
}

fn nav_button(ui: &mut egui::Ui, state: &mut AppState, screen: Screen, label: &str) {
    let selected = state.screen == screen;
    if ui.selectable_label(selected, label).clicked() {
        state.screen = screen;
    }
}
