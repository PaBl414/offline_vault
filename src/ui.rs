//! Native GUI built on `eframe`/`egui`.
//!
//! This module owns all presentation and all transient dialog state. It never
//! sees a master password, a Master Key, a KEK, a Vault Key, or a decrypted
//! payload: it interacts with [`App`], which hides those.
//!
//! ## What is displayed where
//!
//!   * **Unlock screen** — master password field, masked, plus the message
//!     from [`App::error`] if unlocking failed.
//!   * **No-vault screen** — two master-password fields with masking, and a
//!     Create button. The error message from vault creation is shown here.
//!   * **Main window** — search bar, entry table (Title / Username / URL
//!     only), and a toolbar with Add / Edit / Delete / Copy Password / Copy
//!     Username / Lock. Passwords and TOTP secrets are **never** drawn in the
//!     list.
//!   * **Entry dialog** — Title, Username, Password (masked), URL, TOTP
//!     Secret (masked), Notes. The Password field has a Generate… button that
//!     opens the generator sub-window.
//!   * **Generator sub-window** — length slider, four class checkboxes, a
//!     Generate button, the generated value, and a Use This Password button.
//!
//! ## Borrowing strategy
//!
//! egui closures capture `self` for the duration of a frame. To keep the
//! borrow checker happy while still mutating `self`, the list of entries is
//! snapshotted into cheap display-only values at the start of each frame, and
//! every deferred action is recorded in a local `Pending` value that is
//! applied after the closure has returned. No secret is ever placed into the
//! snapshot.

use eframe::egui;
use zeroize::Zeroize;

use crate::app::{App, AppState, MIN_MASTER_PASSWORD_LEN};
use crate::error::Result as AppResult;
use crate::password_generator;
use crate::vault::Entry;

// ---------------------------------------------------------------------------
// VaultApp
// ---------------------------------------------------------------------------

/// The egui application object.
pub struct VaultApp {
    /// The domain state. `None` only if `App::new` failed at startup, in
    /// which case an initialization error is shown instead of any vault UI.
    app: Option<App>,

    /// Set only when `App::new` failed. Rendered verbatim (it is one of the
    /// fixed strings from `Error`'s `Display` and contains no secret).
    init_error: Option<String>,

    // -- Unlock / create screen state ---------------------------------------
    unlock_password: String,
    create_password: String,
    create_confirm: String,

    // -- Main window state --------------------------------------------------
    search: String,
    selected_id: Option<String>,

    // -- Entry dialog -------------------------------------------------------
    draft: Option<EntryDraft>,

    // -- Transient error to show at the bottom of the main panel -----------
    op_error: Option<String>,
}

impl VaultApp {
    /// Construct the application object. Called from `main.rs`.
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (app, init_error) = match App::new() {
            Ok(a) => (Some(a), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self {
            app,
            init_error,
            unlock_password: String::new(),
            create_password: String::new(),
            create_confirm: String::new(),
            search: String::new(),
            selected_id: None,
            draft: None,
            op_error: None,
        }
    }
}

impl Drop for VaultApp {
    fn drop(&mut self) {
        // Best-effort wipe of any still-populated password fields. `App`
        // (and its `UnlockedVault`) wipe themselves.
        self.unlock_password.zeroize();
        self.create_password.zeroize();
        self.create_confirm.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Screen selector
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Screen {
    NoVault,
    Locked,
    Unlocked,
}

// ---------------------------------------------------------------------------
// Deferred actions from the main window
// ---------------------------------------------------------------------------

enum Pending {
    None,
    Add,
    Edit,
    Delete,
    CopyPassword,
    CopyUsername,
    Lock,
}

// ---------------------------------------------------------------------------
// EntryDraft
// ---------------------------------------------------------------------------

/// Editable state of the entry dialog. Sensitive fields are wiped on drop.
struct EntryDraft {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    totp: String,
    notes: String,
    is_new: bool,
    error: Option<String>,

    // -- Generator sub-window state ----------------------------------------
    show_generator: bool,
    gen_length: usize,
    gen_uppercase: bool,
    gen_lowercase: bool,
    gen_digits: bool,
    gen_symbols: bool,
    gen_result: String,
    gen_error: Option<String>,
}

impl EntryDraft {
    fn new_blank() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            totp: String::new(),
            notes: String::new(),
            is_new: true,
            error: None,
            show_generator: false,
            gen_length: password_generator::DEFAULT_LENGTH,
            gen_uppercase: true,
            gen_lowercase: true,
            gen_digits: true,
            gen_symbols: true,
            gen_result: String::new(),
            gen_error: None,
        }
    }

    fn from_entry(e: &Entry, is_new: bool) -> Self {
        Self {
            id: e.id.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.clone(),
            url: e.url.clone(),
            totp: e.totp.clone(),
            notes: e.notes.clone(),
            is_new,
            error: None,
            show_generator: false,
            gen_length: password_generator::DEFAULT_LENGTH,
            gen_uppercase: true,
            gen_lowercase: true,
            gen_digits: true,
            gen_symbols: true,
            gen_result: String::new(),
            gen_error: None,
        }
    }

    fn to_entry(&self) -> AppResult<Entry> {
        if self.is_new {
            Entry::new(
                self.title.clone(),
                self.username.clone(),
                self.password.clone(),
                self.url.clone(),
                self.totp.clone(),
                self.notes.clone(),
            )
        } else {
            // For edits we preserve the id chosen at creation. Field
            // validation still runs in `App::update_entry`.
            Ok(Entry {
                id: self.id.clone(),
                title: self.title.clone(),
                username: self.username.clone(),
                password: self.password.clone(),
                url: self.url.clone(),
                totp: self.totp.clone(),
                notes: self.notes.clone(),
            })
        }
    }
}

impl Drop for EntryDraft {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp.zeroize();
        self.notes.zeroize();
        self.gen_result.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Display rows
// ---------------------------------------------------------------------------

/// The non-secret fields of an entry, snapshotted for display.
///
/// Passwords and TOTP secrets deliberately do not appear here: the list is
/// physically incapable of rendering them.
struct Row {
    id: String,
    title: String,
    username: String,
    url: String,
}

// ---------------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------------

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. If startup failed, show the init error and stop.
        if self.app.is_none() {
            self.show_init_error(ctx);
            return;
        }

        // 2. Drive the clipboard and auto-lock timers. This runs regardless
        //    of lock state because a copied secret may still be pending
        //    clear after the vault locks.
        if let Some(app) = self.app.as_mut() {
            ctx.input(|i| app.tick(i));
        }

        // 3. Pick the screen to draw.
        let screen = match self.app.as_ref().map(|a| a.state()) {
            Some(AppState::NoVault) => Screen::NoVault,
            Some(AppState::Locked { .. }) => Screen::Locked,
            Some(AppState::Unlocked { .. }) => Screen::Unlocked,
            None => return,
        };

        match screen {
            Screen::NoVault => self.show_no_vault(ctx),
            Screen::Locked => self.show_unlock(ctx),
            Screen::Unlocked => self.show_main(ctx),
        }

        // 4. Overlays (entry dialog, generator sub-window).
        self.show_entry_dialog(ctx);

        // 5. Transient operation error at the bottom, if any.
        self.show_op_error(ctx);
    }
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

impl VaultApp {
    fn show_init_error(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("offline-vault");
                ui.add_space(20.0);
                ui.colored_label(egui::Color32::RED, "The application could not start.");
                if let Some(e) = &self.init_error {
                    ui.add_space(8.0);
                    ui.label(e);
                }
            });
        });
    }

    fn show_no_vault(&mut self, ctx: &egui::Context) {
        let path_display = self
            .app
            .as_ref()
            .map(|a| a.vault_path().display().to_string())
            .unwrap_or_default();
        let error = self
            .app
            .as_ref()
            .and_then(|a| a.error().map(|s| s.to_string()));

        let mut do_create = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading("offline-vault");
                ui.add_space(12.0);
                ui.label(format!("No vault found at: {path_display}"));
                ui.add_space(24.0);
                ui.label("Create a new vault");
                ui.add_space(8.0);
                ui.label(format!(
                    "Master password (at least {MIN_MASTER_PASSWORD_LEN} characters):"
                ));
                ui.add(
                    egui::TextEdit::singleline(&mut self.create_password)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.label("Confirm master password:");
                let r2 = ui.add(
                    egui::TextEdit::singleline(&mut self.create_confirm)
                        .password(true)
                        .desired_width(320.0),
                );
                let enter = r2.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(12.0);
                if ui.button("Create Vault").clicked() || enter {
                    do_create = true;
                }
                if let Some(err) = &error {
                    ui.add_space(12.0);
                    ui.colored_label(egui::Color32::RED, err);
                }
            });
        });

        if do_create {
            let mut pw = std::mem::take(&mut self.create_password);
            let mut cf = std::mem::take(&mut self.create_confirm);
            if let Some(app) = self.app.as_mut() {
                // Error is stored inside `App` and shown above on the next
                // frame.
                let _ = app.create_vault(&pw, &cf);
            }
            pw.zeroize();
            cf.zeroize();
        }
    }

    fn show_unlock(&mut self, ctx: &egui::Context) {
        let error = self
            .app
            .as_ref()
            .and_then(|a| a.error().map(|s| s.to_string()));

        let mut do_unlock = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("offline-vault");
                ui.add_space(24.0);
                ui.label("Master password:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.unlock_password)
                        .password(true)
                        .desired_width(320.0),
                );
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(12.0);
                if ui.button("Unlock").clicked() || enter {
                    do_unlock = true;
                }
                if let Some(err) = &error {
                    ui.add_space(12.0);
                    ui.colored_label(egui::Color32::RED, err);
                }
            });
        });

        if do_unlock {
            let mut pw = std::mem::take(&mut self.unlock_password);
            if let Some(app) = self.app.as_mut() {
                let _ = app.unlock(&pw);
            }
            pw.zeroize();
        }
    }

    fn show_main(&mut self, ctx: &egui::Context) {
        // Snapshot non-secret display fields. Passwords and TOTP secrets are
        // intentionally not copied into `Row`.
        let rows = self.display_rows();

        let has_sel = self.selected_id.is_some();
        let mut pending = Pending::None;

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Search:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text("title, username, url")
                        .desired_width(280.0),
                );
                ui.separator();
                if ui.button("Add").clicked() {
                    pending = Pending::Add;
                }
                if ui.add_enabled(has_sel, egui::Button::new("Edit")).clicked() {
                    pending = Pending::Edit;
                }
                if ui
                    .add_enabled(has_sel, egui::Button::new("Delete"))
                    .clicked()
                {
                    pending = Pending::Delete;
                }
                if ui
                    .add_enabled(has_sel, egui::Button::new("Copy Password"))
                    .clicked()
                {
                    pending = Pending::CopyPassword;
                }
                if ui
                    .add_enabled(has_sel, egui::Button::new("Copy Username"))
                    .clicked()
                {
                    pending = Pending::CopyUsername;
                }
                ui.separator();
                if ui.button("Lock").clicked() {
                    pending = Pending::Lock;
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if rows.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label("No entries yet. Click Add to create one.");
                });
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for row in &rows {
                    ui.horizontal(|ui| {
                        let selected = self.selected_id.as_deref() == Some(row.id.as_str());
                        let label = format!(
                            "{:<32}   {:<24}   {}",
                            truncate(&row.title, 32),
                            truncate(&row.username, 24),
                            row.url,
                        );
                        if ui.selectable_label(selected, label).clicked() {
                            self.selected_id = Some(row.id.clone());
                        }
                    });
                }
            });
        });

        // Apply the deferred action now that the UI borrows are done.
        match pending {
            Pending::None => {}
            Pending::Add => {
                self.draft = Some(EntryDraft::new_blank());
            }
            Pending::Edit => {
                if let Some(id) = self.selected_id.clone() {
                    let snapshot = self.app.as_ref().and_then(|a| {
                        a.entries()
                            .iter()
                            .find(|e| e.id == id)
                            .map(|e| EntryDraft::from_entry(e, false))
                    });
                    self.draft = snapshot;
                }
            }
            Pending::Delete => {
                if let Some(id) = self.selected_id.clone() {
                    let res = self
                        .app
                        .as_mut()
                        .map(|a| a.remove_entry(&id))
                        .unwrap_or(Ok(false));
                    match res {
                        Ok(_) => {
                            self.selected_id = None;
                        }
                        Err(e) => {
                            self.op_error = Some(e.to_string());
                        }
                    }
                }
            }
            Pending::CopyPassword => {
                if let Some(id) = self.selected_id.clone() {
                    let res = self
                        .app
                        .as_mut()
                        .map(|a| a.copy_password(&id))
                        .unwrap_or(Ok(()));
                    if let Err(e) = res {
                        self.op_error = Some(e.to_string());
                    }
                }
            }
            Pending::CopyUsername => {
                if let Some(id) = self.selected_id.clone() {
                    let res = self
                        .app
                        .as_mut()
                        .map(|a| a.copy_username(&id))
                        .unwrap_or(Ok(()));
                    if let Err(e) = res {
                        self.op_error = Some(e.to_string());
                    }
                }
            }
            Pending::Lock => {
                if let Some(app) = self.app.as_mut() {
                    app.lock();
                }
                self.selected_id = None;
                self.draft = None;
                self.op_error = None;
            }
        }
    }

    fn show_op_error(&mut self, ctx: &egui::Context) {
        let Some(err) = self.op_error.clone() else {
            return;
        };
        let mut dismiss = false;
        egui::TopBottomPanel::bottom("op_error").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::RED, &err);
                if ui.button("Dismiss").clicked() {
                    dismiss = true;
                }
            });
        });
        if dismiss {
            self.op_error = None;
        }
    }

    // -- Entry dialog -------------------------------------------------------

    fn show_entry_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut draft) = self.draft.take() else {
            return;
        };

        let mut window_open = true;
        let mut apply = false;
        let mut cancel = false;

        let title = if draft.is_new {
            "New Entry"
        } else {
            "Edit Entry"
        };
        egui::Window::new(title)
            .open(&mut window_open)
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                egui::Grid::new("entry_fields")
                    .num_columns(2)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Title");
                        ui.text_edit_singleline(&mut draft.title);
                        ui.end_row();

                        ui.label("Username");
                        ui.text_edit_singleline(&mut draft.username);
                        ui.end_row();

                        ui.label("Password");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.password)
                                    .password(true)
                                    .desired_width(280.0),
                            );
                            if ui.button("Generate…").clicked() {
                                draft.show_generator = true;
                            }
                        });
                        ui.end_row();

                        ui.label("URL");
                        ui.text_edit_singleline(&mut draft.url);
                        ui.end_row();

                        ui.label("TOTP Secret");
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.totp)
                                .password(true)
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("Notes");
                        ui.text_edit_multiline(&mut draft.notes);
                        ui.end_row();
                    });

                if let Some(err) = &draft.error {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::RED, err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        apply = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if !window_open || cancel {
            // draft is dropped, wiping sensitive fields.
            return;
        }

        if apply {
            match draft.to_entry() {
                Ok(entry) => {
                    let is_new = draft.is_new;
                    let result = self.app.as_mut().map(|app| {
                        if is_new {
                            app.add_entry(entry)
                        } else {
                            app.update_entry(entry).map(|_| ())
                        }
                    });
                    match result {
                        Some(Ok(())) => {
                            // Success: drop draft and return.
                        }
                        Some(Err(e)) => {
                            self.op_error = Some(e.to_string());
                            self.draft = Some(draft);
                            return;
                        }
                        None => {
                            self.op_error = Some("application not available".into());
                            self.draft = Some(draft);
                            return;
                        }
                    }
                }
                Err(e) => {
                    draft.error = Some(e.to_string());
                    self.draft = Some(draft);
                    return;
                }
            }
            return;
        }

        // Not applying or cancelling: show generator sub-window if requested,
        // then put the draft back.
        if draft.show_generator {
            Self::show_generator_window(ctx, &mut draft);
        }
        self.draft = Some(draft);
    }

    fn show_generator_window(ctx: &egui::Context, draft: &mut EntryDraft) {
        let mut open = true;
        egui::Window::new("Password Generator")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(400.0)
            .show(ctx, |ui| {
                ui.add(egui::Slider::new(&mut draft.gen_length, 8..=128).text("Length"));
                ui.checkbox(&mut draft.gen_uppercase, "Uppercase (A-Z)");
                ui.checkbox(&mut draft.gen_lowercase, "Lowercase (a-z)");
                ui.checkbox(&mut draft.gen_digits, "Digits (0-9)");
                ui.checkbox(&mut draft.gen_symbols, "Symbols (!@#...)");

                ui.add_space(6.0);
                if ui.button("Generate").clicked() {
                    let opts = password_generator::Options {
                        length: draft.gen_length,
                        uppercase: draft.gen_uppercase,
                        lowercase: draft.gen_lowercase,
                        digits: draft.gen_digits,
                        symbols: draft.gen_symbols,
                    };
                    match password_generator::generate(&opts) {
                        Ok(p) => {
                            draft.gen_result = p;
                            draft.gen_error = None;
                        }
                        Err(_) => {
                            draft.gen_result.zeroize();
                            draft.gen_error =
                                Some("Select at least one character type.".to_string());
                        }
                    }
                }

                ui.add_space(6.0);
                ui.label("Generated password:");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.gen_result).desired_width(f32::INFINITY),
                );

                if let Some(err) = &draft.gen_error {
                    ui.colored_label(egui::Color32::RED, err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    let can_use = !draft.gen_result.is_empty();
                    if ui
                        .add_enabled(can_use, egui::Button::new("Use This Password"))
                        .clicked()
                    {
                        // Move the generated value into the entry's password
                        // field. There is no intermediate copy: the old field
                        // is zeroized first, and the generated buffer is
                        // taken (leaving an empty String behind).
                        draft.password.zeroize();
                        draft.password = std::mem::take(&mut draft.gen_result);
                        draft.show_generator = false;
                        draft.gen_error = None;
                    }
                    if ui.button("Close").clicked() {
                        draft.show_generator = false;
                    }
                });
            });
        if !open {
            draft.show_generator = false;
        }
    }

    // -- Helpers ------------------------------------------------------------

    fn display_rows(&self) -> Vec<Row> {
        let query = self.search.trim().to_lowercase();
        let entries = match self.app.as_ref() {
            Some(a) => a.entries(),
            None => return Vec::new(),
        };
        entries
            .iter()
            .filter(|e| {
                query.is_empty()
                    || e.title.to_lowercase().contains(&query)
                    || e.username.to_lowercase().contains(&query)
                    || e.url.to_lowercase().contains(&query)
            })
            .map(|e| Row {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
            })
            .collect()
    }
}

/// Truncate a string to at most `max` characters, appending an ellipsis if
/// truncation occurred. Used only for list display; the underlying entry is
/// never modified.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_shortens_long_strings() {
        assert_eq!(truncate("hello", 10), "hello");
        let t = truncate("abcdefghij", 5);
        assert_eq!(t.chars().count(), 5);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn entry_draft_from_entry_roundtrips() {
        let e = Entry::new(
            "Title",
            "alice",
            "the-password",
            "https://example.com",
            "JBSWY3DPEHPK3PXP",
            "notes",
        )
        .unwrap();
        let d = EntryDraft::from_entry(&e, false);
        let rebuilt = d.to_entry().unwrap();
        assert_eq!(rebuilt.id, e.id);
        assert_eq!(rebuilt.title, e.title);
        assert_eq!(rebuilt.username, e.username);
        assert_eq!(rebuilt.password, e.password);
        assert_eq!(rebuilt.url, e.url);
        assert_eq!(rebuilt.totp, e.totp);
        assert_eq!(rebuilt.notes, e.notes);
    }

    #[test]
    fn entry_draft_new_generates_fresh_id() {
        let mut d = EntryDraft::new_blank();
        d.title = "T".into();
        d.username = "u".into();
        d.password = "p".into();
        let e = d.to_entry().unwrap();
        assert!(!e.id.is_empty());
    }

    #[test]
    fn row_snapshot_never_contains_secrets() {
        // Structural check: `Row` has no field that could carry a password or
        // a TOTP secret. This test asserts the shape of the struct, not the
        // runtime data, so it cannot itself leak anything.
        let r = Row {
            id: "id".into(),
            title: "t".into(),
            username: "u".into(),
            url: "url".into(),
        };
        // Reference every field so adding a new one requires updating this
        // test (and therefore prompting a review).
        let _ = (&r.id, &r.title, &r.username, &r.url);
    }
}
