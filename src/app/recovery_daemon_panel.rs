use super::*;
use crate::recovery_daemon::{self, Consent, Notices, Settings};
pub(super) struct RecoveryDaemonState {
    selected: Option<Uuid>,
    user: String,
    password: String,
    hours: u32,
    drill: bool,
    confirmed: bool,
    notice: String,
    worker: Option<std::sync::mpsc::Receiver<Result<usize, String>>>,
}
impl Default for RecoveryDaemonState {
    fn default() -> Self {
        Self {
            selected: None,
            user: String::new(),
            password: String::new(),
            hours: 24,
            drill: false,
            confirmed: false,
            notice: String::new(),
            worker: None,
        }
    }
}
impl AivanaApp {
    pub(super) fn recovery_daemon_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Background work & scheduled rehearsals");
        ui.label("Checks for due contracts every five minutes, even when the app is closed. Runs only while this Windows user is signed in. Production is read-only.");
        ui.label("Clone rehearsals require existing running Hyper-V clones, PowerShell Direct privileges, and guest credentials. The task does not elevate privileges. HTTP checks with additional secrets still require a manual rehearsal.");
        ui.label("Before each new rehearsal, the clone must show the matching failure state again. Healthy clones provide no repair evidence; automatic rollback or failure injection is not configured.");
        let state = &mut self.recovery_daemon;
        if let Some(rx) = &state.worker {
            match rx.try_recv() {
                Ok(result) => {
                    state.notice = match result {
                        Ok(n) => format!("Background run completed: {n} operations"),
                        Err(e) => e,
                    };
                    state.worker = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    state.notice = "Background worker ended unexpectedly".into();
                    state.worker = None;
                }
                Err(_) => {
                    ui.spinner();
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(300));
                }
            }
        }
        let mut settings = match Settings::load() {
            Ok(s) => s,
            Err(_) => {
                ui.colored_label(
                    egui::Color32::RED,
                    "Cannot read background storage; configuration locked",
                );
                return;
            }
        };
        ui.label(if settings.enabled {
            "Saved background approvals active (install the task separately)"
        } else {
            "Background work disabled"
        });
        if ui
            .checkbox(
                &mut settings.windows_hints,
                "Local Windows notifications for new messages (even when the app is closed)",
            )
            .changed()
        {
            state.notice = settings.save().map_or_else(
                |e| e.to_string(),
                |_| "Notification setting saved".into(),
            );
        }
        ui.horizontal(|ui| {
            if ui
                .button("Install / update Windows task")
                .clicked()
            {
                state.notice = match recovery_daemon::install_task() {
                    Ok(()) => "Task installed for this user".into(),
                    Err(e) => e.to_string(),
                };
            }
            if ui
                .button("Disable everything & remove task")
                .clicked()
            {
                state.notice = match recovery_daemon::remove_task() {
                    Ok(()) => "Disabled; guest credentials removed; task deleted".into(),
                    Err(e) => format!("Check removal: {e}"),
                };
            }
            if ui
                .add_enabled(
                    state.worker.is_none() && settings.enabled,
                    egui::Button::new("Start approved run"),
                )
                .clicked()
            {
                let (tx, rx) = std::sync::mpsc::channel();
                state.worker = Some(rx);
                std::thread::spawn(move || {
                    let _ = tx.send(recovery_daemon::run_once().map_err(|_| {
                        "Run failed; check messages and storage".into()
                    }));
                });
            }
        });
        let book = match app_data_file("relayne-recovery-contracts.dpapi")
            .and_then(|p| crate::recovery_contracts::Book::load(&p))
        {
            Ok(b) => b,
            Err(_) => {
                ui.colored_label(
                    egui::Color32::RED,
                    "Contract storage locked or unreadable",
                );
                return;
            }
        };
        ui.separator();
        egui::ComboBox::from_id_salt("background-contract")
            .selected_text(
                book.contracts
                    .iter()
                    .find(|c| Some(c.id) == state.selected)
                    .map_or("Select contract", |c| c.name.as_str()),
            )
            .show_ui(ui, |ui| {
                for c in &book.contracts {
                    if ui
                        .selectable_value(&mut state.selected, Some(c.id), &c.name)
                        .changed()
                    {
                        state.confirmed = false;
                    }
                }
            });
        if let Some(c) = book.contracts.iter().find(|c| Some(c.id) == state.selected) {
            ui.label(format!(
                "Service: {} · Desired state: {} · Plan: {}",
                c.plan.service,
                c.plan.desired.label(),
                c.plan.hash().unwrap_or_default()
            ));
            for m in &c.plan.mappings {
                ui.label(format!(
                    "Production (read-only): {} → Clone: {} / VM {}",
                    m.production.host, m.staging.profile_id, m.staging.host
                ));
            }
            if let Some(existing) = settings.consents.iter().find(|s| s.contract_id == c.id) {
                ui.label(format!(
                    "Approved until {} · Clone rehearsals: {}",
                    existing
                        .expires
                        .with_timezone(&chrono::Local)
                        .format("%m/%d/%Y %H:%M"),
                    existing.drill
                ));
                if ui
                    .button("Disable this contract / delete guest credentials")
                    .clicked()
                {
                    settings.consents.retain(|s| s.contract_id != c.id);
                    state.notice = settings
                        .save()
                        .map_or_else(|e| e.to_string(), |_| "Approval removed".into());
                }
            }
            if ui
                .checkbox(
                    &mut state.drill,
                    "Also schedule actual service changes exclusively in these clones",
                )
                .changed()
            {
                state.confirmed = false;
            }
            ui.horizontal(|ui| {
                ui.label("Approval duration in hours");
                if ui
                    .add(egui::DragValue::new(&mut state.hours).range(1..=168))
                    .changed()
                {
                    state.confirmed = false;
                }
            });
            if state.drill {
                ui.label("Guest account for all selected clones (DOMAIN\\user or user)");
                if ui.text_edit_singleline(&mut state.user).changed() {
                    state.confirmed = false;
                }
                ui.label("Guest password · stored encrypted with CurrentUser DPAPI");
                if ui
                    .add(egui::TextEdit::singleline(&mut state.password).password(true))
                    .changed()
                {
                    state.confirmed = false;
                }
            }
            ui.checkbox(&mut state.confirmed, "I authorize exactly this plan, these targets, and the selected duration; for clone rehearsals, also their service changes and credential storage.");
            if ui
                .add_enabled(
                    state.confirmed,
                    egui::Button::new("Save and activate approval"),
                )
                .clicked()
            {
                let result = (|| -> anyhow::Result<()> {
                    anyhow::ensure!(
                        !state.drill
                            || (!state.user.trim().is_empty() && !state.password.is_empty()),
                        "Guest account and password missing"
                    );
                    let consent = Consent {
                        contract_id: c.id,
                        plan_hash: c.plan.hash()?,
                        expires: Utc::now()
                            + chrono::Duration::hours(i64::from(state.hours.clamp(1, 168))),
                        drill: state.drill,
                        user: if state.drill {
                            state.user.clone()
                        } else {
                            String::new()
                        },
                        password: if state.drill {
                            state.password.clone()
                        } else {
                            String::new()
                        },
                    };
                    settings.consents.retain(|s| s.contract_id != c.id);
                    settings.consents.push(consent);
                    settings.enabled = true;
                    settings.save()
                })();
                state.notice = result.map_or_else(
                    |e| e.to_string(),
                    |_| {
                        "Approval saved. Install the Windows task above if needed.".into()
                    },
                );
                state.password.clear();
                state.confirmed = false;
            }
        }
        ui.label(&state.notice);
        ui.separator();
        ui.heading("Persistent notifications");
        if ui.button("Mark all as read").clicked() {
            if let Err(e) = Notices::mark_read() {
                state.notice = e.to_string();
            }
        }
        match Notices::load() {
            Ok(notices) => {
                for n in notices.items.iter().rev().take(64) {
                    ui.label(format!(
                        "{} {} · {} · {}",
                        if n.read { "" } else { "●" },
                        n.at.with_timezone(&chrono::Local).format("%m/%d %H:%M"),
                        n.contract_id,
                        n.message
                    ));
                }
            }
            Err(_) => {
                ui.colored_label(egui::Color32::RED, "Cannot read notification storage");
            }
        }
    }
}
