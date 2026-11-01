//! Color tokens for the two themes from the design mockup: dark graphite
//! surfaces with an ember accent, and a light counterpart that keeps the
//! same accent (darkened for contrast on white).

use eframe::egui::{self, Color32};

pub struct Palette {
    pub ember: Color32,
    pub ember_text: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub surface: Color32,
    pub surface_alt: Color32,
    pub text: Color32,
    pub text_dim: Color32,
}

pub const DARK: Palette = Palette {
    ember: Color32::from_rgb(0xE8, 0x6A, 0x4C),
    ember_text: Color32::from_rgb(0xFF, 0x9A, 0x7A),
    success: Color32::from_rgb(0x5E, 0xC2, 0x8A),
    warning: Color32::from_rgb(0xE8, 0xB4, 0x4C),
    danger: Color32::from_rgb(0xE0, 0x5A, 0x5A),
    surface: Color32::from_rgb(0x1C, 0x1B, 0x1A),
    surface_alt: Color32::from_rgb(0x27, 0x25, 0x24),
    text: Color32::from_rgb(0xEC, 0xE9, 0xE6),
    text_dim: Color32::from_rgb(0x9A, 0x96, 0x92),
};

pub const LIGHT: Palette = Palette {
    ember: Color32::from_rgb(0xC9, 0x4E, 0x32),
    ember_text: Color32::from_rgb(0xA8, 0x3A, 0x22),
    success: Color32::from_rgb(0x2E, 0x8B, 0x57),
    warning: Color32::from_rgb(0x9A, 0x6B, 0x0A),
    danger: Color32::from_rgb(0xB3, 0x2B, 0x2B),
    surface: Color32::from_rgb(0xFA, 0xF9, 0xF7),
    surface_alt: Color32::from_rgb(0xF0, 0xEE, 0xEB),
    text: Color32::from_rgb(0x23, 0x21, 0x1F),
    text_dim: Color32::from_rgb(0x6B, 0x66, 0x62),
};

pub fn apply(ctx: &egui::Context, dark: bool) {
    let palette = if dark { &DARK } else { &LIGHT };
    let mut visuals = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    visuals.override_text_color = Some(palette.text);
    visuals.panel_fill = palette.surface;
    visuals.window_fill = palette.surface;
    visuals.extreme_bg_color = palette.surface_alt;
    visuals.widgets.noninteractive.bg_fill = palette.surface_alt;
    visuals.widgets.inactive.bg_fill = palette.surface_alt;
    visuals.selection.bg_fill = palette.ember.linear_multiply(0.5);
    visuals.hyperlink_color = palette.ember_text;
    ctx.set_visuals(visuals);
}

pub fn palette(dark: bool) -> &'static Palette {
    if dark {
        &DARK
    } else {
        &LIGHT
    }
}
