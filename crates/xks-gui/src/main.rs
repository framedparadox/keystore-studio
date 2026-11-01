mod app;
mod identity_record;
mod screens;
mod theme;

use app::XksApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1100.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "xkeystore",
        options,
        Box::new(|_cc| Ok(Box::new(XksApp::default()))),
    )
}
