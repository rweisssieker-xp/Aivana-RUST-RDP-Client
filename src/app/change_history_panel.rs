use super::*;
use crate::change_history::{self as history, Entry, Phase, Target};
use std::sync::mpsc;

enum Work {
    Loaded(Vec<Entry>),
    Template(String),
    Prepared(Entry),
    Completed(Entry),
}
fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Prepared => "Prepared",
        Phase::Applied => "Applied",
        Phase::RestorePending => "Restore pending",
        Phase::Restored => "Restored",
    }
}
fn comparison_label(entry: &Entry) -> String {
    entry
        .comparison()
        .replace("Before:", "Before:")
        .replace("After:", "After:")
        .replace(" bytes", " Bytes")
}
pub struct ChangeHistoryState {
    host: String,
    profile_id: Option<uuid::Uuid>,
    path: String,
    registry: bool,
    registry_kind: history::RegistryKind,
    permissions: bool,
    value_name: String,
    replacement: String,
    prepared: Option<Entry>,
    entries: Vec<Entry>,
    reviewed: bool,
    restore_reviewed: Option<uuid::Uuid>,
    reveal: bool,
    pending: Option<mpsc::Receiver<Result<Work, String>>>,
    message: String,
    loaded: bool,
}
impl Default for ChangeHistoryState {
    fn default() -> Self {
        Self {
            host: String::new(),
            profile_id: None,
            path: String::new(),
            registry: false,
            registry_kind: history::RegistryKind::String,
            permissions: false,
            value_name: String::new(),
            replacement: String::new(),
            prepared: None,
            entries: Vec::new(),
            reviewed: false,
            restore_reviewed: None,
            reveal: false,
            pending: None,
            message: String::new(),
            loaded: false,
        }
    }
}
impl ChangeHistoryState {
    fn start(&mut self, work: impl FnOnce() -> anyhow::Result<Work> + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.reviewed = false;
        self.restore_reviewed = None;
        self.message.clear();
        std::thread::spawn(move || {
            let _ = tx.send(work().map_err(|e| e.to_string()));
        });
    }
    fn reload(&mut self) {
        self.start(|| Ok(Work::Loaded(history::load(&history::journal_directory()?)?)));
    }
}
impl AivanaApp {
    pub(super) fn poll_change_history(&mut self) {
        let state = &mut self.change_history;
        let Some(rx) = &state.pending else {
            return;
        };
        match rx.try_recv() {
            Ok(result) => {
                state.pending = None;
                match result {
                    Ok(Work::Template(text)) => {
                        state.replacement = text;
                        state.prepared = None;
                        state.message = "Current content loaded as a template. Enter your changes, then capture a new comparison.".into();
                    }
                    Ok(Work::Loaded(entries)) => {
                        state.entries = entries;
                        state.loaded = true;
                        state.message = "Encrypted journal loaded.".into();
                    }
                    Ok(Work::Prepared(entry)) => {
                        state.prepared = Some(entry);
                        state.message =
                            "State captured. Review the target and before-and-after comparison."
                                .into();
                    }
                    Ok(Work::Completed(entry)) => {
                        state.entries.retain(|e| e.id != entry.id);
                        state.message =
                            format!("{}: Target content verified.", phase_label(entry.phase));
                        state.entries.insert(0, entry);
                        state.prepared = None;
                    }
                    Err(error) => {
                        state.message = error;
                        state.prepared = None;
                    }
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                state.pending = None;
                state.prepared = None;
                state.message = "Processing ended. Reload the journal and check the target before trying again.".into();
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }
    pub(super) fn change_history_incident_records(&self) -> Vec<crate::incident::Record> {
        let mut records = Vec::new();
        for entry in &self.change_history.entries {
            if let Some(at) = entry.applied_at {
                records.push(crate::incident::Record {
                    id: format!("change-history-{}-applied", entry.id),
                    profile: entry.profile_id,
                    endpoint: entry.endpoint_key.clone(),
                    at,
                    kind: crate::incident::Kind::Change,
                    title: "Change history: applied and verified".into(),
                    evidence: vec![
                        format!("Target: {}", entry.target.label()),
                        comparison_label(entry),
                    ],
                });
            }
            if entry.applied_at.is_some() && entry.phase == Phase::Applied {
                continue;
            }
            records.push(crate::incident::Record {
                id: format!("change-history-{}", entry.id),
                profile: entry.profile_id,
                endpoint: entry.endpoint_key.clone(),
                at: entry.updated_at,
                kind: match entry.phase {
                    Phase::Restored => crate::incident::Kind::Recovery,
                    Phase::Applied => crate::incident::Kind::Change,
                    _ => crate::incident::Kind::Observation,
                },
                title: format!("Change history: {}", phase_label(entry.phase)),
                evidence: vec![
                    format!("Target: {}", entry.target.label()),
                    comparison_label(entry),
                    format!("State captured: {}", entry.at.to_rfc3339()),
                ],
            });
        }
        records
    }
    pub(super) fn change_history_view(&mut self, ui: &mut Ui) {
        ui.heading("Change time machine");
        ui.label("Files up to 1 MiB · six registry types · file ACLs · 128 encrypted entries");
        ui.small("Local and WinRM Negotiate: current Windows account, no elevation. File snapshots capture owner/group/DACL and parent folders for verified restoration of deleted files. Services, registry trees, and SACLs are outside the scope.");
        let state = &mut self.change_history;
        if !state.loaded && state.pending.is_none() {
            state.loaded = true;
            state.reload();
        }
        let busy = state.pending.is_some();
        ui.add_enabled_ui(!busy, |ui| {
            ui.horizontal(|ui| {
                ui.label("Computer (blank = local)"); ui.text_edit_singleline(&mut state.host);
                if ui.button("Associate the selected direct RDP profile").clicked() {
                    if let Some(profile) = self.profiles.iter().find(|p| Some(p.id) == self.selected_profile) {
                        if profile.options.gateway.enabled || profile.protocol != Protocol::Rdp { state.message = "Only direct RDP profiles without a gateway can be associated with WinRM jobs.".into(); }
                        else { state.host = profile.host.clone(); state.profile_id = Some(profile.id); }
                    }
                }
            });
            if state.profile_id.is_some_and(|id| !self.profiles.iter().any(|p| p.id == id && p.host == state.host && !state.host.is_empty() && p.protocol == Protocol::Rdp && !p.options.gateway.enabled)) { state.profile_id = None; }
            if let Some(id) = state.profile_id { ui.small(format!("Associated profile: {id} · direct WinRM")); }
            ui.checkbox(&mut state.registry, "Registry value");
            if state.registry {
                state.permissions = false;
                egui::ComboBox::from_label("Existing value type").selected_text(state.registry_kind.label()).show_ui(ui, |ui| {
                    for kind in [history::RegistryKind::String, history::RegistryKind::ExpandString, history::RegistryKind::DWord, history::RegistryKind::QWord, history::RegistryKind::MultiString, history::RegistryKind::Binary] {
                        ui.selectable_value(&mut state.registry_kind, kind, kind.label());
                    }
                });
                ui.small("DWORD/QWORD: unsigned decimal. MULTI_SZ: JSON string array. BINARY: Base64. The existing type must match.");
            } else { ui.checkbox(&mut state.permissions, "File permissions instead of content (canonical owner/group/DACL SDDL)"); }
            ui.label(if state.registry { "Existing key: HKCU:\\... or HKLM:\\..." } else { "Existing file: absolute Windows path with a drive letter" });
            ui.add(egui::TextEdit::singleline(&mut state.path).char_limit(2048));
            if state.registry { ui.label("Value name (blank = default value)"); ui.add(egui::TextEdit::singleline(&mut state.value_name).char_limit(256)); }
            ui.label("Complete new content (UTF-8, including all line breaks)");
            ui.add(egui::TextEdit::multiline(&mut state.replacement).desired_rows(5).char_limit(history::CONTENT_LIMIT));
            let target = Target { host: state.host.trim().to_owned(), path: state.path.clone(), registry: state.registry, value_name: if state.registry { state.value_name.clone() } else { String::new() }, registry_kind: state.registry_kind, permissions: state.permissions };
            let endpoint_key = state.profile_id.and_then(|id| self.profiles.iter().find(|p| p.id == id))
                .map(|profile| crate::incident::endpoint_key(&crate::mission::Target::from_profile(profile)));
            if ui.button("Read current content / SDDL as an editing template").clicked() {
                let template_target = target.clone();
                state.start(move || {
                    use history::Backend;
                    let bytes = history::WindowsBackend.read(&template_target)?;
                    Ok(Work::Template(String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("Binary file: no UTF-8 editing template available"))?))
                });
            }
            if state.prepared.as_ref().is_some_and(|e| e.target != target || history::normalize_replacement(&target, state.replacement.as_bytes()).ok().as_deref() != Some(e.after.as_slice()) || e.profile_id != state.profile_id || e.endpoint_key != endpoint_key) {
                state.prepared = None; state.reviewed = false;
            }
            if ui.button("1. Capture state and prepare comparison").clicked() {
                let replacement = state.replacement.as_bytes().to_vec();
                let profile_id = state.profile_id;
                state.prepared = None;
                state.start(move || {
                    let mut entry = history::prepare(&mut history::WindowsBackend, target, replacement)?;
                    entry.profile_id = profile_id;
                    entry.endpoint_key = endpoint_key;
                    Ok(Work::Prepared(entry))
                });
            }
            if let Some(entry) = state.prepared.clone() {
                ui.strong(entry.target.label()); ui.monospace(comparison_label(&entry));
                if entry.file_context.is_some() { ui.small("File ACL and parent folders captured. Subsequent restore approval also covers a file deleted in the meantime at the exact same path, provided the parent folder permissions are unchanged."); }
                ui.checkbox(&mut state.reveal, "Show content here (may contain secrets)");
                if state.reveal {
                    ui.columns(2, |columns| {
                        columns[0].label("Before"); columns[0].monospace(String::from_utf8_lossy(&entry.before));
                        columns[1].label("After"); columns[1].monospace(String::from_utf8_lossy(&entry.after));
                    });
                }
                ui.checkbox(&mut state.reviewed, "Target and new content reviewed; explicitly approve this change");
                if ui.add_enabled(state.reviewed && state.pending.is_none(), egui::Button::new("2. Save journal and apply reviewed change")).clicked() {
                    state.start(move || Ok(Work::Completed(history::apply(&history::journal_directory()?, &mut history::WindowsBackend, entry)?)));
                }
            }
            ui.separator();
            if ui.add_enabled(state.pending.is_none(), egui::Button::new("Reload journal")).clicked() { state.reload(); }
            ui.small("Prepared or pending entries may come from interrupted actions. Restoration checks the target: after state → restore before state; already in before state → mark complete; other content → reject.");
            ui.small("Registry values cannot be locked against other writers. Pause other applications that write during the change. Interrupted file writes may leave partial content; these differences require manual restoration.");
            let entries = state.entries.clone();
            egui::ScrollArea::vertical().id_salt("change-history-list").max_height(380.0).show(ui, |ui| {
                for entry in entries {
                    egui::CollapsingHeader::new(format!("{} · {} · {}", entry.at.format("%Y-%m-%d %H:%M:%S UTC"), phase_label(entry.phase), entry.target.label())).id_salt(entry.id).show(ui, |ui| {
                        ui.monospace(comparison_label(&entry));
                        ui.small(format!("Journal ID {} · last updated {}", entry.id, entry.updated_at));
                        if entry.phase != Phase::Restored {
                            let mut reviewed = state.restore_reviewed == Some(entry.id);
                            if ui.checkbox(&mut reviewed, "Reviewed: approve restoration of this before state").changed() { state.restore_reviewed = if reviewed { Some(entry.id) } else { None }; }
                            if ui.add_enabled(reviewed && state.pending.is_none(), egui::Button::new("Restore if target content matches")).clicked() {
                                state.start(move || Ok(Work::Completed(history::restore(&history::journal_directory()?, &mut history::WindowsBackend, entry)?)));
                            }
                        }
                    });
                }
            });
        });
        if !state.message.is_empty() {
            ui.label(&state.message);
        }
        if state.pending.is_some() {
            ui.spinner();
            ui.label("Job running; transfer timeout: 120 seconds per step.");
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
