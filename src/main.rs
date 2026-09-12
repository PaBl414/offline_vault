//! Binary entry point for `offline-vault`.
//!
//! All application logic lives in the `offline_vault` library crate. This
//! file only wires the library's GUI into an `eframe` native window.

use eframe::egui;
use offline_vault::ui;

fn main() -> eframe::Result<()> {
    install_release_panic_hook();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("offline-vault"),
        persist_window: false,
        ..Default::default()
    };

    eframe::run_native(
        "offline-vault",
        native_options,
        Box::new(|cc| Box::new(ui::VaultApp::new(cc)) as Box<dyn eframe::App>),
    )
}

fn install_release_panic_hook() {
    #[cfg(not(debug_assertions))]
    {
        std::panic::set_hook(Box::new(|_info| {
            eprintln!("offline-vault: internal error");
        }));
    }
}
