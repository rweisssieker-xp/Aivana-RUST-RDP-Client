use super::*;
use crate::teaching::{self, Step, Teacher};

struct AnchorJob {
    index: usize,
    x: u16,
    y: u16,
    frame: FrameUpdate,
}
struct AnchorResult {
    index: usize,
    x: u16,
    y: u16,
    target: Result<crate::transferable::LogicalTarget, String>,
    icon: Option<teaching::icons::IconAnchor>,
}

/// Called directly at the remote canvas input boundary with its displayed frame.
pub(super) fn send_teaching_manual_input(
    engine: &mut NativeRdpEngine,
    teaching: &mut TeachingState,
    frame: &FrameUpdate,
    session: Uuid,
    action: InputAction,
) -> anyhow::Result<()> {
    if teaching.run.is_some() {
        teaching.cancel_run("Manuelle Eingabe hat Gesamtablauf angehalten");
        engine.release_inputs(session);
    }
    engine.send_manual_input(session, action.clone())?;
    teaching.observe_frame(session, &action, Some(frame), std::time::Instant::now());
    Ok(())
}

#[derive(Default)]
pub(super) struct TeachingState {
    pub teacher: Teacher,
    compiler: CompilerState,
    cursor: usize,
    target: Option<Uuid>,
    approved: bool,
    approved_frame: Option<(Uuid, u64, chrono::DateTime<chrono::Utc>)>,
    text: String,
    awaiting_evidence: bool,
    history: Vec<String>,
    source: Option<Uuid>,
    library: Vec<teaching::Procedure>,
    anchor_tx: Option<std::sync::mpsc::SyncSender<AnchorJob>>,
    anchor_rx: Option<std::sync::mpsc::Receiver<AnchorResult>>,
    anchors: Vec<AnchorResult>,
    icon_proposals: Vec<(usize, u16, u16, teaching::icons::IconAnchor)>,
    press_frame: Option<FrameUpdate>,
    evidence_frame: Option<(Uuid, u64, chrono::DateTime<chrono::Utc>)>,
    evidence_started: Option<std::time::Instant>,
    evidence_attempts: u8,
    evidence_last_scan: Option<(Uuid, u64, chrono::DateTime<chrono::Utc>)>,
    evidence_notice: String,
    final_verified: Option<(Uuid, u64, chrono::DateTime<chrono::Utc>)>,
    run: Option<crate::transferable::RunApproval>,
    parameters: std::collections::BTreeMap<String, String>,
    whole_reviewed: bool,
    queue: Vec<Uuid>,
    target_results: Vec<String>,
    dispatch_scan: Option<(Uuid, u64, chrono::DateTime<chrono::Utc>)>,
    dispatch_wait: Option<std::time::Instant>,
    workflow_run: Option<(Uuid, Option<Result<(), String>>)>,
}
impl TeachingState {
    pub(super) fn cancel_run(&mut self, reason: &str) {
        if self.run.take().is_some() {
            if let Some((_, result)) = &mut self.workflow_run {
                *result = Some(if self.final_verified.is_some() {
                    Ok(())
                } else {
                    Err(reason.to_owned())
                });
            }
            self.teacher.notice = reason.to_owned();
            if self.target_results.len() >= 32 {
                self.target_results.remove(0);
            }
            self.target_results
                .push(format!("Ziel {:?}: {reason}", self.target));
        }
        self.parameters.clear();
        self.whole_reviewed = false;
        self.dispatch_scan = None;
        self.dispatch_wait = None;
    }
    fn start_anchors(&mut self) {
        let (tx, jobs) = std::sync::mpsc::sync_channel::<AnchorJob>(2);
        let (results, rx) = std::sync::mpsc::channel();
        self.anchor_tx = Some(tx);
        self.anchor_rx = Some(rx);
        self.anchors.clear();
        self.icon_proposals.clear();
        self.press_frame = None;
        std::thread::spawn(move || {
            while let Ok(job) = jobs.recv() {
                let screen = crate::vision::recognize(&job.frame);
                let icon = screen.as_ref().ok().and_then(|s| {
                    teaching::icons::IconAnchor::capture(&job.frame, s, job.x, job.y).ok()
                });
                let target = screen
                    .and_then(|screen| {
                        crate::vision::redact(&job.frame, &screen).map(|(_, clean)| clean)
                    })
                    .and_then(|screen| {
                        crate::transferable::LogicalTarget::propose(&screen, job.x, job.y)
                    })
                    .map_err(|e| e.to_string());
                if results
                    .send(AnchorResult {
                        index: job.index,
                        x: job.x,
                        y: job.y,
                        target,
                        icon,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    pub fn observe_frame(
        &mut self,
        id: Uuid,
        action: &InputAction,
        frame: Option<&FrameUpdate>,
        at: std::time::Instant,
    ) {
        if self.teacher.session != Some(id) {
            return;
        }
        let before = self.teacher.procedure.steps.len();
        let last_before = self.teacher.procedure.steps.last().cloned();
        let bounded =
            frame.filter(|f| f.session_id == id && f.pixels_rgba.len() <= 32 * 1024 * 1024);
        if matches!(action, InputAction::PointerButton { pressed: true, .. }) {
            self.press_frame = bounded.cloned();
        }
        self.teacher
            .observe_at(id, action, frame.map(|f| (f.width, f.height)), at);
        let index = if self.teacher.procedure.steps.len() > before {
            Some(before)
        } else if matches!(action, InputAction::PointerButton { pressed: false, .. }) {
            self.teacher
                .procedure
                .steps
                .len()
                .checked_sub(1)
                .filter(|i| {
                    matches!(last_before, Some(Step::Click { double: false, .. }))
                        && matches!(
                            self.teacher.procedure.steps[*i],
                            Step::Click { double: true, .. }
                        )
                })
        } else {
            None
        };
        let captured = match action {
            InputAction::PointerButton { pressed: false, .. } => self.press_frame.take(),
            InputAction::Click { .. } | InputAction::DoubleClick { .. } => bounded.cloned(),
            _ => None,
        };
        if let Some(index) = index {
            if let Some(Step::Click { x, y, .. }) = self.teacher.procedure.steps.get(index) {
                let queued = if let (Some(frame), Some(tx)) = (captured, &self.anchor_tx) {
                    tx.try_send(AnchorJob {
                        index,
                        x: *x,
                        y: *y,
                        frame,
                    })
                    .is_ok()
                } else {
                    false
                };
                if !queued {
                    self.teacher.notice="OCR ausgelastet oder exaktes Bild fehlt: Klick benötigt manuelle Verankerung".into();
                }
            }
        }
    }
    fn poll_anchors(&mut self) {
        if !self.teacher.is_recording() {
            self.anchor_tx = None;
            self.press_frame = None;
        }
        let mut disconnected = false;
        if let Some(rx) = &self.anchor_rx {
            loop {
                match rx.try_recv() {
                    Ok(result) => self.anchors.push(result),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            }
        }
        if disconnected {
            self.anchor_rx = None;
        }
        if !self.teacher.is_recording() && self.anchor_rx.is_none() {
            for result in self.anchors.drain(..) {
                if let Some(step) = self.teacher.procedure.steps.get_mut(result.index) {
                    if let Step::Click {
                        x,
                        y,
                        button,
                        double,
                    } = step
                    {
                        if *x == result.x && *y == result.y {
                            match result.target {
                                Ok(target) => {
                                    *step = Step::TransferClick {
                                        target,
                                        button: *button,
                                        double: *double,
                                    }
                                }
                                Err(e) => {
                                    if let Some(icon) = result.icon {
                                        self.icon_proposals.push((
                                            result.index,
                                            result.x,
                                            result.y,
                                            icon,
                                        ));
                                    }
                                    self.teacher.notice =
                                        format!("Schritt {} benötigt Anker: {e}", result.index + 1)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pub fn cancel_approval(&mut self) {
        self.approved = false;
        self.approved_frame = None;
        self.text.clear();
    }
    pub fn observe_at(
        &mut self,
        id: Uuid,
        action: &InputAction,
        size: Option<(u16, u16)>,
        at: std::time::Instant,
    ) {
        self.teacher.observe_at(id, action, size, at);
    }
    fn reset_replay(&mut self) {
        self.cancel_run("Gesamtablauf zurückgesetzt; Freigabe verworfen");
        self.cursor = 0;
        self.target = None;
        self.approved = false;
        self.approved_frame = None;
        self.text.clear();
        self.awaiting_evidence = false;
        self.history.clear();
        self.evidence_frame = None;
        self.reset_evidence();
        self.final_verified = None;
    }
    fn reset_evidence(&mut self) {
        self.evidence_started = None;
        self.evidence_attempts = 0;
        self.evidence_last_scan = None;
        self.evidence_notice.clear();
    }
}
impl AivanaApp {
    /// Called only after the workflow UI reviewed this exact procedure, target and values.
    pub(super) fn start_workflow_procedure(
        &mut self,
        host: &str,
        procedure: teaching::Procedure,
        values: std::collections::BTreeMap<String, String>,
        binding: Option<crate::mission::Target>,
    ) -> anyhow::Result<Uuid> {
        teaching::validate_workflow_procedure(&procedure)?;
        crate::transferable::validate_run(&procedure, &values)?;
        anyhow::ensure!(
            !self.teaching.teacher.is_recording()
                && self.teaching.run.is_none()
                && !self.teaching.awaiting_evidence
                && self.teaching.anchor_rx.is_none(),
            "Demonstration oder Wiedergabe bereits aktiv"
        );
        let candidates: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|s| {
                s.status == SessionStatus::Connected
                    && self.profiles.iter().any(|p| {
                        p.id == s.profile_id
                            && p.protocol == Protocol::Rdp
                            && !p.options.gateway.enabled
                            && p.host.eq_ignore_ascii_case(host)
                    })
            })
            .map(|s| s.id)
            .collect();
        let [id] = candidates.as_slice() else {
            anyhow::bail!(
                "Workflow benötigt genau eine verbundene direkte RDP-Sitzung für dieses Ziel"
            );
        };
        let id = *id;
        if let Some(binding) = binding {
            anyhow::ensure!(
                self.session_sources
                    .get(&id)
                    .is_some_and(|source| source.same_endpoint(&binding)),
                "Workflow-Zielidentität wurde seit Freigabe verändert"
            );
        }
        anyhow::ensure!(
            self.latest_frames.contains_key(&id),
            "Aktuelles RDP-Zielbild fehlt"
        );
        let identity = self.teaching_profile_identity(id)?;
        let approval = crate::transferable::RunApproval::new(
            id,
            &procedure,
            &values,
            &identity,
            std::time::Instant::now(),
        )?;
        if let Some(previous) = self.teaching.target {
            self.engine.release_inputs(previous);
        }
        self.teaching.reset_replay();
        self.teaching.teacher.procedure = procedure;
        self.teaching.parameters = values;
        self.teaching.target = Some(id);
        self.selected_session = Some(id);
        self.teaching.run = Some(approval);
        let token = Uuid::new_v4();
        self.teaching.workflow_run = Some((token, None));
        Ok(token)
    }
    pub(super) fn workflow_procedure_status(&self, token: Uuid) -> Option<Result<(), String>> {
        match &self.teaching.workflow_run {
            Some((id, result)) if *id == token => result.clone(),
            _ => Some(Err("RDP-Ablaufzuordnung fehlt oder wurde ersetzt".into())),
        }
    }
    pub(super) fn cancel_workflow_procedure(&mut self, token: Uuid) {
        if self
            .teaching
            .workflow_run
            .as_ref()
            .is_some_and(|(id, _)| *id == token)
        {
            if let Some(id) = self.teaching.target {
                self.engine.release_inputs(id);
            }
            self.teaching
                .cancel_run("Workflow hat den RDP-Ablauf angehalten");
        }
    }
    pub(super) fn poll_teaching(&mut self) {
        self.teaching.poll_anchors();
        if self.teaching.approved_frame.is_some_and(|(id, hash, at)| {
            self.latest_frames
                .get(&id)
                .is_none_or(|f| f.frame_hash != hash || f.captured_at != at)
        }) {
            self.teaching.cancel_approval();
        }

        if let Some(id) = self.teaching.teacher.session {
            if !self
                .sessions
                .iter()
                .any(|s| s.id == id && s.status == SessionStatus::Connected)
                || self.latest_frames.get(&id).map(|f| (f.width, f.height))
                    != Some(self.teaching.teacher.procedure.dimensions)
            {
                self.teaching.teacher.stop();
                self.engine.release_inputs(id);
                self.teaching.teacher.notice =
                    "Aufnahme gestoppt: Verbindung oder Bildgröße geändert".into();
            }
        }
        if let Some(id) = self.teaching.target {
            let valid = self.selected_session == Some(id)
                && self
                    .sessions
                    .iter()
                    .any(|s| s.id == id && s.status == SessionStatus::Connected)
                && self.latest_frames.contains_key(&id);
            if !valid {
                self.engine.release_inputs(id);
                self.teaching.reset_replay();
                self.teaching.teacher.notice =
                    "Wiedergabe zurückgesetzt: Ziel oder Verbindung geändert".into();
            }
        }
        self.poll_teaching_assertions();
        self.poll_teaching_run();
    }
    fn teaching_profile_identity(&self, id: Uuid) -> anyhow::Result<Vec<u8>> {
        let session = self
            .sessions
            .iter()
            .find(|s| s.id == id && s.status == SessionStatus::Connected)
            .ok_or_else(|| anyhow::anyhow!("Zielsitzung nicht verbunden"))?;
        let profile = self
            .profiles
            .iter()
            .find(|p| p.id == session.profile_id)
            .ok_or_else(|| anyhow::anyhow!("Zielprofil fehlt"))?;
        if !self
            .session_sources
            .get(&id)
            .is_some_and(|source| source.matches(profile))
        {
            anyhow::bail!(
                "Zielprofil stimmt nicht mehr mit der tatsächlich verbundenen Sitzung überein"
            );
        }
        Ok(serde_json::to_vec(&(profile, session.connected_at))?)
    }
    fn poll_teaching_run(&mut self) {
        let Some(run) = self.teaching.run.as_ref() else {
            return;
        };
        let id = run.target;
        let valid = self.selected_session == Some(id)
            && self.teaching.target == Some(id)
            && self.teaching_profile_identity(id).is_ok_and(|identity| {
                run.matches(
                    id,
                    &self.teaching.teacher.procedure,
                    &self.teaching.parameters,
                    &identity,
                    std::time::Instant::now(),
                )
            });
        if !valid {
            self.teaching
                .cancel_run("Freigabe abgelaufen oder Ziel/Profil/Ablauf/Parameter geändert");
            self.engine.release_inputs(id);
            return;
        }
        if self.teaching.final_verified.is_some() {
            self.teaching
                .cancel_run("Abgeschlossen: konfigurierte sichtbare Endbedingung nachgewiesen");
            self.engine.release_inputs(id);
            return;
        }
        if self.teaching.awaiting_evidence
            || self.teaching.cursor >= self.teaching.teacher.procedure.steps.len()
        {
            return;
        }
        let Some(frame) = self.latest_frames.get(&id) else {
            self.teaching.cancel_run("Zielbild fehlt");
            return;
        };
        let stamp = (id, frame.frame_hash, frame.captured_at);
        if !self
            .vision
            .screen
            .as_ref()
            .is_some_and(|s| s.matches(frame))
        {
            let since = self
                .teaching
                .dispatch_wait
                .get_or_insert_with(std::time::Instant::now);
            if since.elapsed() > std::time::Duration::from_secs(20) {
                self.teaching
                    .cancel_run("Frische OCR vor Eingabe nicht verfügbar; Gesamtablauf angehalten");
                return;
            }
            if !self.vision.is_busy() && self.teaching.dispatch_scan != Some(stamp) {
                self.teaching.dispatch_scan = Some(stamp);
                self.request_vision();
            }
            return;
        }
        let step = &self.teaching.teacher.procedure.steps[self.teaching.cursor];
        let value = if let Step::Parameter { name } = step {
            self.teaching
                .parameters
                .get(name)
                .map(String::as_str)
                .unwrap_or("")
        } else {
            ""
        };
        let actions = self.teaching.teacher.procedure.actions_on_frame(
            step,
            frame,
            self.vision.screen.as_ref(),
            value,
        );
        let result = (|| -> anyhow::Result<()> {
            let actions = actions?;
            if actions
                .iter()
                .any(|a| crate::policy::PolicyEngine.decision_for(a) == PolicyDecision::Deny)
            {
                anyhow::bail!("Richtlinie sperrt Schritt");
            }
            // Resolve and send in this same UI turn; no cached source coordinates or frame approval.
            if self
                .latest_frames
                .get(&id)
                .map(|f| (f.session_id, f.frame_hash, f.captured_at))
                != Some(stamp)
            {
                anyhow::bail!("Zielbild während Auflösung geändert");
            }
            for action in actions {
                self.engine.send_input(id, action)?;
            }
            Ok(())
        })();
        self.engine.release_inputs(id);
        match result {
            Ok(()) => {
                self.teaching.evidence_frame = Some((id, stamp.1, chrono::Utc::now()));
                self.teaching.awaiting_evidence = true;
                self.teaching.reset_evidence();
                self.teaching.evidence_started = Some(std::time::Instant::now());
                self.teaching.dispatch_scan = None;
                self.teaching.dispatch_wait = None;
            }
            Err(e) => self.teaching.cancel_run(&format!(
                "Schritt {} angehalten: {e}",
                self.teaching.cursor + 1
            )),
        }
    }
    fn poll_teaching_assertions(&mut self) {
        let Some(id) = self.teaching.target else {
            return;
        };
        if self.selected_session != Some(id) || self.teaching.teacher.is_recording() {
            return;
        }
        let final_check = !self.teaching.awaiting_evidence
            && self.teaching.cursor == self.teaching.teacher.procedure.steps.len();
        let expected = if self.teaching.awaiting_evidence {
            self.teaching
                .teacher
                .procedure
                .expected_after
                .get(&self.teaching.cursor)
                .cloned()
        } else if final_check && self.teaching.final_verified.is_none() {
            self.teaching.teacher.procedure.expected_final.clone()
        } else {
            None
        };
        let (Some(expected), Some(after)) = (expected, self.teaching.evidence_frame) else {
            return;
        };
        let Some(frame) = self.latest_frames.get(&id) else {
            return;
        };
        match teaching::verify_visible_assertion(
            frame,
            self.vision.screen.as_ref(),
            &expected,
            after,
        ) {
            Ok(bounds) => {
                let stamp = (id, frame.frame_hash, frame.captured_at);
                let scope = if final_check {
                    "Endbedingung".to_owned()
                } else {
                    format!("Schritt {}", self.teaching.cursor + 1)
                };
                let entry = format!(
                    "{scope}: erwartetes Wort '{}' sichtbar bei {:?} · Bild {:016x} · {} (OCR; kein Backend-Nachweis)",
                    expected.label,
                    bounds.center(),
                    frame.frame_hash,
                    frame.captured_at
                );
                self.teaching.history.push(entry);
                self.teaching.reset_evidence();
                if final_check {
                    self.teaching.final_verified = Some(stamp);
                } else {
                    self.teaching.cursor += 1;
                    self.teaching.awaiting_evidence = false;
                }
                self.status =
                    "Erwarteter sichtbarer Zustand im aktuellen Zielbild nachgewiesen".into();
                return;
            }
            Err(e) => {
                self.teaching.evidence_notice = e.to_string();
                // Missing status can be a loading transition: wait without dispatching input.
                // Ambiguity and other completed-current-OCR errors cannot authorize continuation.
                if self.teaching.run.is_some()
                    && frame.captured_at > after.2
                    && self
                        .vision
                        .screen
                        .as_ref()
                        .is_some_and(|s| s.matches(frame))
                    && !matches!(
                        e.downcast_ref::<crate::vision::AnchorResolutionError>(),
                        Some(crate::vision::AnchorResolutionError::Missing)
                    )
                {
                    self.teaching.cancel_run(&format!(
                        "Erwarteter sichtbarer Zustand fehlt oder ist mehrdeutig: {e}"
                    ));
                    self.engine.release_inputs(id);
                    return;
                }
            }
        }
        let started = self
            .teaching
            .evidence_started
            .get_or_insert_with(std::time::Instant::now);
        if started.elapsed() > std::time::Duration::from_secs(30)
            || self.teaching.evidence_attempts >= 8
        {
            self.teaching.evidence_notice="Ergebnisprüfung angehalten (30 Sekunden / 8 Bilder). Zustand prüfen und nur die OCR-Prüfung erneut starten.".into();
            if self.teaching.run.is_some() {
                self.teaching
                    .cancel_run("Ergebnisprüfung abgelaufen; Gesamtablauf angehalten");
                self.engine.release_inputs(id);
            }
            return;
        }
        let stamp = (id, frame.frame_hash, frame.captured_at);
        if frame.captured_at > after.2
            && self.teaching.evidence_last_scan != Some(stamp)
            && !self.vision.is_busy()
            && !self
                .vision
                .screen
                .as_ref()
                .is_some_and(|s| s.matches(frame))
        {
            self.teaching.evidence_last_scan = Some(stamp);
            self.teaching.evidence_attempts += 1;
            self.request_vision();
        }
    }
    pub(super) fn teaching_view(&mut self, ui: &mut Ui) {
        ui.heading("Vormachen → wiederverwendbarer Ablauf");
        ui.label("Bis zu 200 Schritte aus manuellen Eingaben einer Sitzung. Texte, normale Tasten und Tastenkombinationen werden nur als Platzhalter gespeichert. Zwischenablage, Mausbewegungen und Ziehen werden ausgelassen.");
        let session = self.selected_session().cloned();
        let size = session
            .as_ref()
            .and_then(|s| self.latest_frames.get(&s.id))
            .map(|f| (f.width, f.height));
        let connected = session
            .as_ref()
            .is_some_and(|s| s.status == SessionStatus::Connected)
            && size.is_some();
        if let Some(s) = &session {
            ui.label(format!("Ausgewähltes Ziel: {}", s.title));
        } else {
            ui.label("Bitte zuerst eine Sitzung auswählen.");
        }
        let recording = self.teaching.teacher.session.is_some();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    connected && !recording && self.teaching.anchor_rx.is_none(),
                    egui::Button::new("Neue Demonstration starten"),
                )
                .clicked()
            {
                self.teaching.reset_replay();
                self.engine.release_inputs(session.as_ref().unwrap().id);
                self.teaching
                    .teacher
                    .start(session.as_ref().unwrap().id, size.unwrap());
                self.teaching.source = session.as_ref().map(|s| s.id);
                self.teaching.start_anchors();
                self.status =
                    "Demonstration aktiv: manuelle Eingaben im Remote-Desktop werden erfasst"
                        .into();
            }
            if ui
                .add_enabled(recording, egui::Button::new("Demonstration stoppen"))
                .clicked()
            {
                if let Some(id) = self.teaching.teacher.session {
                    self.engine.release_inputs(id);
                }
                self.teaching.teacher.stop();
            }
            if ui
                .add_enabled(
                    !recording && self.teaching.anchor_rx.is_none(),
                    egui::Button::new("Gespeicherten Ablauf laden"),
                )
                .clicked()
            {
                match teaching::load() {
                    Ok(p) => {
                        self.teaching.reset_replay();
                        self.teaching.source = None;
                        self.teaching.teacher.procedure = p;
                        self.status =
                            "Verschlüsselten Ablauf geladen; vor jedem Schritt prüfen".into();
                    }
                    Err(e) => self.status = format!("Ablauf laden: {e:#}"),
                }
            }
        });
        if recording {
            ui.colored_label(
                tw::RED_600,
                "● Demonstration aktiv – nur die beim Start gewählte Sitzung wird erfasst",
            );
        }
        ui.label(&self.teaching.teacher.notice);
        if self.teaching.anchor_rx.is_some() {
            ui.label(
                "Lokale OCR der Demonstration läuft; maximal ein Worker und zwei wartende Bilder.",
            );
        }
        let editable = !recording
            && !self.teaching.awaiting_evidence
            && self.teaching.anchor_rx.is_none()
            && self.teaching.run.is_none();
        let mut changed = false;
        ui.add_enabled_ui(editable, |ui| {
            let p = &mut self.teaching.teacher.procedure;
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut p.title)
                        .char_limit(256)
                        .hint_text("Titel"),
                )
                .changed();
            ui.label(format!(
                "Aufgezeichnetes Bild: {} × {} · {} Schritte",
                p.dimensions.0,
                p.dimensions.1,
                p.steps.len()
            ));
            ui.label("Erfolgskriterium (im Remote-Bild manuell zu prüfen):");
            changed |= ui
                .add(
                    egui::TextEdit::multiline(&mut p.success)
                        .char_limit(4096)
                        .desired_rows(2),
                )
                .changed();
            ui.label("Wiederherstellung bei Abweichung (keine Zugangsdaten eintragen):");
            changed |= ui
                .add(
                    egui::TextEdit::multiline(&mut p.recovery)
                        .char_limit(4096)
                        .desired_rows(2),
                )
                .changed();
            ui.label("OCR-Nachbedingungen prüfen ein sichtbares Wort samt optionalem Kontext. Sie beweisen keine Backend-Transaktion; wählen Sie einen aussagekräftigen Status.");
            let mut final_enabled=p.expected_final.is_some();
            if ui.checkbox(&mut final_enabled,"Sichtbare Endbedingung automatisch prüfen").changed() {
                p.expected_final=final_enabled.then(||crate::vision::Anchor{label:String::new(),context:String::new()});changed=true;
            }
            if let Some(anchor)=&mut p.expected_final {
                changed |= ui.add(egui::TextEdit::singleline(&mut anchor.label).char_limit(256).hint_text("Erwartetes Endstatus-Wort")).changed();
                changed |= ui.add(egui::TextEdit::singleline(&mut anchor.context).char_limit(256).hint_text("Kontext der Endbedingung")).changed();
            }
            let mut remove = None;
            let mut up = None;
            ScrollArea::vertical()
                .id_salt("teaching-review")
                .max_height(240.0)
                .show(ui, |ui| {
                    for (i, step) in p.steps.iter_mut().enumerate() {
                        ui.push_id(i, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!("{}. {}", i + 1, step_label(step)));
                                match step {
                                    Step::TextRequired => {
                                        if ui.small_button("Parameter benennen").clicked() {
                                            *step = Step::Parameter {
                                                name: format!("eingabe_{}", i + 1),
                                            };
                                            changed = true;
                                        }
                                    }
                                    Step::Parameter { name } => {
                                        changed |= ui
                                            .add(egui::TextEdit::singleline(name).char_limit(64))
                                            .changed();
                                    }
                                    Step::Click { x, y, .. } | Step::Scroll { x, y, .. } => {
                                        changed |=
                                            ui.add(egui::DragValue::new(x).prefix("X ")).changed();
                                        changed |=
                                            ui.add(egui::DragValue::new(y).prefix("Y ")).changed();
                                    }
                                    _ => {}
                                }
                                if ui.small_button("Entfernen").clicked() {
                                    remove = Some(i);
                                }
                                if i > 0 && ui.small_button("↑").clicked() {
                                    up = Some(i);
                                }
                            });
                            let mut enabled=p.expected_after.contains_key(&i);
                            if ui.checkbox(&mut enabled,"Sichtbaren Zustand nach diesem Schritt automatisch prüfen").changed() {
                                if enabled {p.expected_after.insert(i,crate::vision::Anchor{label:String::new(),context:String::new()});}
                                else {p.expected_after.remove(&i);}
                                changed=true;
                            }
                            if let Some(anchor)=p.expected_after.get_mut(&i) {
                                ui.horizontal(|ui| {
                                    changed |=ui.add(egui::TextEdit::singleline(&mut anchor.label).char_limit(256).hint_text("Erwartetes Statuswort")).changed();
                                    changed |=ui.add(egui::TextEdit::singleline(&mut anchor.context).char_limit(256).hint_text("Kontext (optional)")).changed();
                                });
                            }
                        });
                    }
                });
            if let Some(i) = remove {
                p.steps.remove(i);
                p.expected_after=std::mem::take(&mut p.expected_after).into_iter().filter_map(|(index,a)| {
                    if index==i {None} else {Some((if index>i {index-1} else {index},a))}
                }).collect();
                changed = true;
            }
            if let Some(i) = up {
                if i < p.steps.len() {
                    p.steps.swap(i, i - 1);
                    let a=p.expected_after.remove(&i);let b=p.expected_after.remove(&(i-1));
                    if let Some(a)=a {p.expected_after.insert(i-1,a);}
                    if let Some(b)=b {p.expected_after.insert(i,b);}
                    changed = true;
                }
            }
        });
        if changed {
            self.teaching.icon_proposals.clear();
            self.teaching.reset_replay();
        }
        for (index, x, y, icon) in self.teaching.icon_proposals.clone() {
            ui.horizontal(|ui| {
                let image = egui::ColorImage::from_rgb([24,24], &icon.rgb);
                let texture = ui.ctx().load_texture(format!("icon-proposal-{index}"), image, egui::TextureOptions::NEAREST);
                ui.image((texture.id(), egui::vec2(72.0,72.0)));
                ui.label(format!("Schritt {}: lokales 24×24-Pixeltemplate. Nur ein textloses, nicht vertrauliches Icon übernehmen. OCR kann Text übersehen. Gleiche Größe/Farben erforderlich; Treffer <97,5 % oder mehrdeutig werden abgelehnt.", index + 1));
                if ui.add_enabled(editable, egui::Button::new("Dieses textlose Icon geprüft übernehmen")).clicked() {
                    if let Some(step) = self.teaching.teacher.procedure.steps.get_mut(index) {
                        if let Step::Click { x: sx, y: sy, button, double } = step {
                            if *sx == x && *sy == y { *step = Step::IconClick { anchor: icon.clone(), button: *button, double: *double }; }
                        }
                    }
                    self.teaching.icon_proposals.retain(|p| p.0 != index);
                    self.teaching.reset_replay();
                }
            });
        }
        let mut compiled = None;
        ui.add_enabled_ui(editable, |ui| {
            compiled = self.teaching.compiler.show(
                ui,
                &self.teaching.teacher.procedure,
                &self.autopilot.settings.openai_model,
            );
        });
        if let Some(procedure) = compiled {
            self.teaching.reset_replay();
            self.teaching.queue.clear();
            self.teaching.teacher.procedure = procedure;
            self.status = "Compiler-Entwurf übernommen; bisherige Freigaben verworfen. Speichern oder Workflow vorbereiten.".into();
        }
        if ui
            .add_enabled(
                editable,
                egui::Button::new("Geprüften Ablauf verschlüsselt speichern"),
            )
            .clicked()
        {
            self.status = match teaching::save_named(&self.teaching.teacher.procedure) {
                Ok(()) => "Benannter Ablauf per Windows DPAPI gespeichert".into(),
                Err(e) => format!("Ablauf speichern: {e:#}"),
            };
        }
        ui.small("Bis zu 32 benannte Abläufe; gleicher Name ersetzt die vorige Fassung. Parameterwerte werden nie gespeichert.");
        if ui
            .add_enabled(
                editable && connected,
                egui::Button::new("Als Workflow vorbereiten"),
            )
            .clicked()
        {
            let prepared = session
                .as_ref()
                .and_then(|s| self.profiles.iter().find(|p| p.id == s.profile_id))
                .filter(|p| p.protocol == Protocol::Rdp && !p.options.gateway.enabled)
                .map(|p| (p.host.clone(), self.teaching.teacher.procedure.clone()));
            if let Some((host, procedure)) = prepared {
                match teaching::validate_workflow_procedure(&procedure) {
                    Ok(()) => self.prepare_teaching_workflow(host, procedure),
                    Err(e) => self.status = format!("Workflow vorbereiten: {e}"),
                }
            } else {
                self.status = "Workflow benötigt ein direktes RDP-Ziel ohne Gateway.".into();
            }
        }
        if ui
            .add_enabled(
                editable,
                egui::Button::new("Ablaufbibliothek öffnen / aktualisieren"),
            )
            .clicked()
        {
            match teaching::load_library() {
                Ok(library) => self.teaching.library = library,
                Err(e) => self.status = e.to_string(),
            }
        }
        let mut load_index = None;
        for (index, procedure) in self.teaching.library.iter().enumerate() {
            if ui
                .add_enabled(
                    editable,
                    egui::Button::new(format!(
                        "Laden: {} · {} Schritte",
                        procedure.title,
                        procedure.steps.len()
                    )),
                )
                .clicked()
            {
                load_index = Some(index);
            }
        }
        if let Some(index) = load_index {
            self.teaching.reset_replay();
            self.teaching.source = None;
            self.teaching.teacher.procedure = self.teaching.library[index].clone();
        }
        ui.separator();
        ui.label("Übertragung: Quellablauf oben prüfen, gewünschte Zielsitzung im Sitzungsbereich wählen und ausdrücklich übernehmen.");
        if let Some(source) = self.teaching.source {
            ui.small(format!(
                "Demonstrationsquelle: {}",
                self.sessions
                    .iter()
                    .find(|s| s.id == source)
                    .map(|s| s.title.as_str())
                    .unwrap_or("frühere Sitzung")
            ));
        }
        if ui
            .add_enabled(
                connected && editable,
                egui::Button::new(
                    "Ausgewählte Sitzung als Wiedergabeziel übernehmen / bei Schritt 1 starten",
                ),
            )
            .clicked()
        {
            self.teaching.reset_replay();
            self.teaching.target = session.as_ref().map(|s| s.id);
        }
        let target_ready = self.teaching.target.is_some()
            && self.teaching.target == session.as_ref().map(|s| s.id);
        ui.label(if target_ready {
            "Ziel übernommen; jeder Schritt wird am aktuellen Zielbild geprüft."
        } else {
            "Noch kein Wiedergabeziel übernommen."
        });
        ui.collapsing("Gesamtablauf freigeben · Warteschlange verbundener Ziele",|ui| {
            ui.label("Eine Freigabe gilt fünf Minuten für genau dieses Ziel, diese Profilfassung, diesen vollständigen Ablauf und die hier eingegebenen Parameter. Jeder Schritt erhält aktuelle OCR und eine sichtbare Nachbedingung. Abweichungen stoppen weitere Eingaben.");
            let names:std::collections::BTreeSet<String>=self.teaching.teacher.procedure.steps.iter().filter_map(|s|if let Step::Parameter{name}=s {Some(name.clone())} else {None}).collect();
            ui.add_enabled_ui(editable,|ui| {
                for name in names {
                    ui.label(format!("Parameter {{{name}}} für dieses Ziel (nur Arbeitsspeicher):"));
                    let value=self.teaching.parameters.entry(name).or_default();
                    if ui.add(egui::TextEdit::singleline(value).password(true).char_limit(4096)).changed() {self.teaching.whole_reviewed=false;}
                }
            });
            ScrollArea::vertical().id_salt("whole-procedure-review").max_height(200.0).show(ui,|ui| {
                for (index,step) in self.teaching.teacher.procedure.steps.iter().enumerate() {
                    let condition=self.teaching.teacher.procedure.expected_after.get(&index).map(|a|format!("{} / {}",a.label,a.context)).unwrap_or_else(||"FEHLT".into());
                    ui.label(format!("{}. {} → erwartet: {condition}",index+1,step_label(step)));
                }
                ui.label(format!("Endbedingung: {}",self.teaching.teacher.procedure.expected_final.as_ref().map(|a|format!("{} / {}",a.label,a.context)).unwrap_or_else(||"FEHLT".into())));
            });
            let eligibility=crate::transferable::validate_run(&self.teaching.teacher.procedure,&self.teaching.parameters);
            if let Err(e)=&eligibility {ui.label(format!("Gesamtfreigabe gesperrt: {e}"));}
            ui.add_enabled(editable && target_ready && eligibility.is_ok(),egui::Checkbox::new(&mut self.teaching.whole_reviewed,"Vollständige Schrittfolge, alle Parameterwerte, erwartete Zustände und dieses Ziel geprüft"));
            if ui.add_enabled(editable && target_ready && connected && eligibility.is_ok() && self.teaching.whole_reviewed,
                egui::Button::new("Ablauf für dieses Ziel freigeben")).clicked() {
                let id=session.as_ref().unwrap().id;
                let approval=self.teaching_profile_identity(id).and_then(|identity|crate::transferable::RunApproval::new(id,&self.teaching.teacher.procedure,&self.teaching.parameters,&identity,std::time::Instant::now()));
                match approval {
                    Ok(approval)=>{
                        self.engine.release_inputs(id);self.teaching.cursor=0;self.teaching.approved=false;self.teaching.approved_frame=None;
                        self.teaching.text.clear();self.teaching.awaiting_evidence=false;self.teaching.evidence_frame=None;self.teaching.final_verified=None;
                        self.teaching.reset_evidence();self.teaching.history.clear();self.teaching.run=Some(approval);
                        self.status="Vollständiger Ablauf für genau dieses Ziel freigegeben; aktuelle OCR vor jedem Schritt".into();
                    }
                    Err(e)=>self.status=e.to_string(),
                }
            }
            if self.teaching.run.is_some() {
                ui.colored_label(tw::RED_600,"Gesamtablauf aktiv – Abbrechen stoppt weitere Eingaben sofort");
                if ui.button("Gesamtablauf jetzt anhalten").clicked() {
                    if let Some(id)=self.teaching.target {self.engine.release_inputs(id);}
                    self.teaching.cancel_run("Durch Benutzer angehalten");
                }
            }
            ui.separator();ui.label("Weitere bereits verbundene Ziele auswählen (maximal 16). Jedes nächste Ziel benötigt neue Parameter und eine eigene Gesamtfreigabe.");
            ui.add_enabled_ui(self.teaching.run.is_none(),|ui| {
                for destination in self.sessions.iter().filter(|s|s.status==SessionStatus::Connected) {
                    let mut queued=self.teaching.queue.contains(&destination.id);
                    if ui.checkbox(&mut queued,&destination.title).changed() {
                        if queued && self.teaching.queue.len()<16 {self.teaching.queue.push(destination.id);}
                        else if !queued {self.teaching.queue.retain(|id|*id!=destination.id);}
                    }
                }
            });
            if ui.add_enabled(self.teaching.run.is_none() && !recording && !self.teaching.queue.is_empty(),egui::Button::new("Nächstes verbundenes Ziel aus Warteschlange übernehmen")).clicked() {
                let id=self.teaching.queue.remove(0);
                if self.sessions.iter().any(|s|s.id==id && s.status==SessionStatus::Connected) {
                    if let Some(old)=self.teaching.target {self.engine.release_inputs(old);}
                    self.teaching.reset_replay();self.selected_session=Some(id);self.teaching.target=Some(id);
                    self.status="Nächstes Ziel übernommen; Parameter und Ablauf für dieses Ziel prüfen und freigeben".into();
                } else {self.status="Warteschlangenziel nicht mehr verbunden; keine Verbindung aufgebaut".into();}
            }
            for result in self.teaching.target_results.iter().rev().take(16) {ui.small(result);}
        });
        if self.teaching.awaiting_evidence {
            let assertion = self
                .teaching
                .teacher
                .procedure
                .expected_after
                .get(&self.teaching.cursor)
                .cloned();
            if let Some(anchor) = &assertion {
                ui.label(format!("Warte auf sichtbaren Zustand: '{}' · Kontext '{}'. Frische OCR prüft automatisch; es wird keine weitere Eingabe gesendet.",anchor.label,anchor.context));
                ui.label(&self.teaching.evidence_notice);
                if ui
                    .button("Nur OCR-Ergebnisprüfung erneut starten")
                    .clicked()
                {
                    self.teaching.reset_evidence();
                }
            } else {
                ui.label("Schritt gesendet. Keine OCR-Nachbedingung hinterlegt. Das neue Bild allein beweist keinen Erfolg; Wirkung gegen das Erfolgskriterium prüfen.");
            }
            let fresh_evidence = session
                .as_ref()
                .and_then(|s| self.latest_frames.get(&s.id))
                .is_some_and(|frame| {
                    self.teaching
                        .evidence_frame
                        .is_some_and(|(id, _, at)| id == frame.session_id && frame.captured_at > at)
                });
            if ui
                .add_enabled(
                    fresh_evidence && assertion.is_none(),
                    egui::Button::new(
                        "Wirkung im neuen Remote-Bild manuell bestätigt → nächster Schritt",
                    ),
                )
                .clicked()
            {
                self.teaching.history.push(format!(
                    "Schritt {}: Wirkung manuell bestätigt",
                    self.teaching.cursor + 1
                ));
                self.teaching.cursor += 1;
                self.teaching.awaiting_evidence = false;
                self.teaching.reset_evidence();
            }
        } else if let Some(step) = self
            .teaching
            .teacher
            .procedure
            .steps
            .get(self.teaching.cursor)
            .cloned()
        {
            ui.label(format!(
                "Nächster Schritt {}: {}",
                self.teaching.cursor + 1,
                step_label(&step)
            ));
            if matches!(
                step,
                Step::Click { .. } | Step::SemanticClick { .. } | Step::TransferClick { .. }
            ) {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Bild für OCR-Anker neu lesen").clicked() {
                        self.request_vision();
                        self.teaching.cancel_approval();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vision.label)
                            .char_limit(256)
                            .hint_text("Zielwort"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vision.context)
                            .char_limit(256)
                            .hint_text("Kontextwort (optional)"),
                    );
                    if ui.button("Diesen Klick an Zielwort binden").clicked() {
                        let anchor = crate::vision::Anchor {
                            label: self.vision.label.clone(),
                            context: self.vision.context.clone(),
                        };
                        let resolved = self
                            .vision
                            .screen
                            .as_ref()
                            .filter(|s| {
                                session
                                    .as_ref()
                                    .and_then(|r| self.latest_frames.get(&r.id))
                                    .is_some_and(|f| s.matches(f))
                            })
                            .ok_or_else(|| anyhow::anyhow!("Frische OCR fehlt"))
                            .and_then(|s| s.resolve(&anchor));
                        match resolved {
                            Ok(_) => {
                                if let Step::Click { button, double, .. }
                                | Step::SemanticClick { button, double, .. }
                                | Step::TransferClick { button, double, .. } = &step
                                {
                                    self.teaching.teacher.procedure.steps[self.teaching.cursor] =
                                        Step::SemanticClick {
                                            anchor,
                                            button: *button,
                                            double: *double,
                                        };
                                    self.teaching.cancel_approval();
                                    self.status =
                                        "Semantisches Ziel gebunden; erneut prüfen".into();
                                }
                            }
                            Err(e) => self.status = e.to_string(),
                        }
                    }
                });
            }
            if matches!(step, Step::TextRequired | Step::Parameter { .. }) {
                ui.label("Text für diesen einzelnen Schritt neu eingeben; nur im Arbeitsspeicher:");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.teaching.text)
                            .password(true)
                            .char_limit(4096),
                    )
                    .changed()
                {
                    self.teaching.approved = false;
                }
            }
            let preview=session.as_ref().and_then(|s|self.latest_frames.get(&s.id)).map(|frame| {
                if matches!(step,Step::Click{..}|Step::Scroll{..}) {return Err(anyhow::anyhow!("Koordinatenschritt benötigt semantischen Anker; bei Scrollen Ziel manuell bedienen und Schritt entfernen"));}
                self.teaching.teacher.procedure.actions_on_frame(&step,frame,self.vision.screen.as_ref(),&self.teaching.text)
            });
            match &preview {
                Some(Ok(actions)) => {
                    if let Some(
                        InputAction::Click { x, y, .. } | InputAction::DoubleClick { x, y, .. },
                    ) = actions.first()
                    {
                        ui.label(format!("Vorschau: Ziel im aktuellen Bild bei {x}, {y}"));
                    } else {
                        ui.label(
                            "Vorschau: Navigation oder Parameter an die ausgewählte Zielsitzung.",
                        );
                    }
                }
                Some(Err(e)) => {
                    ui.colored_label(tw::RED_600, format!("Blockiert: {e}"));
                }
                None => {
                    ui.label("Zielbild fehlt.");
                }
            }
            let preview_ready = preview.as_ref().is_some_and(|r| r.is_ok());
            if ui
                .add_enabled(target_ready && preview_ready && editable,egui::Checkbox::new(
                    &mut self.teaching.approved,
                    "Ziel, sichtbares Element und Wirkung geprüft; diesen einen Schritt freigeben",
                ))
                .changed()
            {
                self.teaching.approved_frame = session
                    .as_ref()
                    .and_then(|s| self.latest_frames.get(&s.id))
                    .map(|f| (f.session_id, f.frame_hash, f.captured_at));
            }
            let enabled = editable
                && target_ready
                && preview_ready
                && connected
                && self.teaching.approved
                && (!matches!(step, Step::TextRequired | Step::Parameter { .. })
                    || !self.teaching.text.is_empty());
            if ui
                .add_enabled(enabled, egui::Button::new("Genau diesen Schritt ausführen"))
                .clicked()
            {
                let id = session.as_ref().unwrap().id;
                let result = (|| -> anyhow::Result<()> {
                    self.teaching.teacher.procedure.validate()?;
                    let frame = self
                        .latest_frames
                        .get(&id)
                        .ok_or_else(|| anyhow::anyhow!("Bild fehlt"))?;
                    if self.teaching.approved_frame
                        != Some((id, frame.frame_hash, frame.captured_at))
                    {
                        anyhow::bail!("Bild seit Freigabe geändert: neu prüfen und freigeben");
                    }
                    if self.teaching.target != Some(id)
                        || matches!(step, Step::Click { .. } | Step::Scroll { .. })
                    {
                        anyhow::bail!(
                            "Ziel nicht übernommen oder Koordinatenschritt nicht verankert"
                        );
                    }
                    self.teaching.evidence_frame = Some((id, frame.frame_hash, frame.captured_at));
                    let actions = self.teaching.teacher.procedure.actions_on_frame(
                        &step,
                        frame,
                        self.vision.screen.as_ref(),
                        &self.teaching.text,
                    )?;
                    let policy = crate::policy::PolicyEngine;
                    if actions
                        .iter()
                        .any(|a| policy.decision_for(a) == PolicyDecision::Deny)
                    {
                        anyhow::bail!("Schritt durch Sicherheitsrichtlinie gesperrt");
                    }
                    for action in actions {
                        self.engine.send_input(id, action)?;
                    }
                    // Exclude frames captured while the action was still being sent.
                    self.teaching.evidence_frame = Some((id, frame.frame_hash, chrono::Utc::now()));
                    Ok(())
                })();
                self.engine.release_inputs(id);
                self.teaching.approved = false;
                self.teaching.text.clear();
                match result {
                    Ok(()) => {
                        self.teaching.target = Some(id);
                        self.teaching.awaiting_evidence = true;
                        self.teaching.reset_evidence();
                        self.teaching.evidence_started = Some(std::time::Instant::now());
                        self.teaching.final_verified = None;
                        self.status = "Ein Schritt gesendet; Wirkung manuell prüfen".into();
                    }
                    Err(e) => {
                        if self.teaching.history.len() >= 200 {
                            self.teaching.history.remove(0);
                        }
                        self.teaching.history.push(format!(
                            "Schritt {}: Versand abgebrochen; Wirkung unklar",
                            self.teaching.cursor + 1
                        ));
                        self.status = format!("Schritt gestoppt: {e:#}");
                    }
                }
            }
        } else if !self.teaching.teacher.procedure.steps.is_empty() {
            if self.teaching.teacher.procedure.expected_final.is_some() {
                if let Some((_, hash, at)) = self.teaching.final_verified {
                    ui.label(format!("Konfigurierte sichtbare Endbedingung per OCR nachgewiesen · Bild {hash:016x} · {at}. Kein Nachweis einer Backend-Transaktion."));
                } else {
                    ui.label("Schritte geprüft; sichtbare Endbedingung noch nicht nachgewiesen.");
                    ui.label(&self.teaching.evidence_notice);
                    if ui.button("Nur OCR-Endprüfung erneut starten").clicked() {
                        self.teaching.reset_evidence();
                    }
                }
            } else {
                ui.label(
                    "Alle Schritte einzeln geprüft. Keine automatische Endbedingung konfiguriert.",
                );
            }
        }
        if ui.button("Wiedergabe abbrechen / zurücksetzen").clicked() {
            if let Some(id) = self.teaching.target {
                self.engine.release_inputs(id);
            }
            self.teaching.reset_replay();
        }
        for entry in self.teaching.history.iter().rev().take(10) {
            ui.small(entry);
        }
    }
}
fn step_label(step: &Step) -> String {
    match step {
        Step::IconClick { .. } => {
            "Textloses Icon · Pixeltemplate 24×24 · Mindestkonfidenz 97,5 %".into()
        }
        Step::TransferClick { target, .. } => format!(
            "Übertragbares OCR-Ziel: {} · relativer Kontext: {}",
            target.anchor.label, target.anchor.context
        ),
        Step::Parameter { name } => format!("Parameter {{{name}}} · Wert je Ziel neu eingeben"),
        Step::Click { button, double, .. } => format!(
            "{} {button:?} · benötigt semantischen Anker vor Übertragung",
            if *double { "Doppelklick" } else { "Klick" }
        ),
        Step::Scroll { delta, .. } => format!("Scrollen {delta}"),
        Step::Navigation { code } => format!("Navigationstaste {code:#x} (Drücken + Loslassen)"),
        Step::SemanticClick { anchor, .. } => {
            format!("OCR-Ziel: {} · Kontext: {}", anchor.label, anchor.context)
        }
        Step::TextRequired => "Eingabe-Platzhalter – Inhalt wurde nicht aufgezeichnet".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_reset_drops_approval_values_and_evidence() {
        let mut state = TeachingState::default();
        state.target = Some(Uuid::new_v4());
        state.cursor = 4;
        state.text = "ephemeral".into();
        state.approved = true;
        state.awaiting_evidence = true;
        state.approved_frame = Some((state.target.unwrap(), 1, chrono::Utc::now()));
        state.evidence_frame = state.approved_frame;
        state
            .parameters
            .insert("service".into(), "ephemeral-value".into());
        state.whole_reviewed = true;
        state.reset_replay();
        assert_eq!(state.cursor, 0);
        assert!(state.target.is_none());
        assert!(state.text.is_empty());
        assert!(!state.approved);
        assert!(!state.awaiting_evidence);
        assert!(state.approved_frame.is_none());
        assert!(state.evidence_frame.is_none());
        assert!(state.parameters.is_empty());
        assert!(!state.whole_reviewed);
    }
    #[test]
    fn missing_exact_frame_never_creates_a_semantic_target() {
        let mut state = TeachingState::default();
        let id = Uuid::new_v4();
        state.teacher.start(id, (800, 600));
        state.observe_frame(
            id,
            &InputAction::Click {
                x: 10,
                y: 10,
                button: crate::models::MouseButton::Left,
            },
            None,
            std::time::Instant::now(),
        );
        assert!(!state.teacher.is_recording());
        assert!(state.teacher.procedure.steps.is_empty());
        assert!(state.anchor_tx.is_none());
    }
    #[test]
    fn completed_ocr_binds_only_its_original_click() {
        let mut state = TeachingState::default();
        state.teacher.procedure.steps = vec![Step::Click {
            x: 50,
            y: 50,
            button: crate::models::MouseButton::Left,
            double: false,
        }];
        state.anchors.push(AnchorResult {
            index: 0,
            x: 10,
            y: 10,
            target: Ok(crate::transferable::LogicalTarget {
                anchor: crate::vision::Anchor {
                    label: "Save".into(),
                    context: String::new(),
                },
                context_offset: None,
            }),
            icon: None,
        });
        state.poll_anchors();
        assert!(matches!(
            state.teacher.procedure.steps[0],
            Step::Click { x: 50, .. }
        ));
    }
}

#[derive(Default)]
struct CompilerState {
    explanation: String,
    context: Option<crate::procedure_compiler::Context>,
    consent: bool,
    reviewed: bool,
    model: String,
    proposal: Option<crate::procedure_compiler::Proposal>,
    pending: Option<std::sync::mpsc::Receiver<Result<crate::procedure_compiler::Proposal, String>>>,
    notice: String,
}
impl CompilerState {
    fn sync(&mut self, source: &teaching::Procedure, model: &str) {
        if self.model != model
            || self
                .context
                .as_ref()
                .is_some_and(|c| !c.matches(source, &self.explanation))
        {
            self.context = None;
            self.proposal = None;
            self.pending = None;
            self.consent = false;
            self.reviewed = false;
        }
        self.model = model.into();
    }
    fn show(
        &mut self,
        ui: &mut Ui,
        source: &teaching::Procedure,
        model: &str,
    ) -> Option<teaching::Procedure> {
        self.sync(source, model);
        let mut adopted = None;
        egui::CollapsingHeader::new("Expertenverfahren mit KI kompilieren").show(ui,|ui| {
            ui.label("Die Demonstration fachlich erklären: Welche Eingaben variieren, welcher sichtbare Zustand bestätigt jeden Schritt? Keine Geheimnisse eingeben.");
            ui.add(egui::TextEdit::multiline(&mut self.explanation).desired_rows(3).desired_width(720.0).char_limit(4096));
            self.sync(source,model);
            if self.context.is_none() {
                match crate::procedure_compiler::Context::new(source,&self.explanation) {
                    Ok(context)=>self.context=Some(context),
                    Err(error)=>{ui.label(error.to_string()); return;}
                }
            }
            let context=self.context.clone().unwrap();
            ui.label(format!("Modell: {model}. Exakter Versandinhalt (nur diese Metadaten und Erklärung):"));
            egui::ScrollArea::vertical().id_salt("compiler_visible_input").max_height(180.0).show(ui,|ui| {ui.monospace(serde_json::to_string_pretty(&context).unwrap_or_default());});
            ui.small("Keine Bilder, Parameterwerte, Profile oder Sitzungsdaten. Der Vorschlag ergänzt ausschließlich benannte Eingabeplätze und bekannte sichtbare Prüfanker; vorhandene Aktionen bleiben erhalten.");
            ui.checkbox(&mut self.consent,"Diesen sichtbaren Inhalt für diesen Vorschlag an OpenAI senden");
            if ui.add_enabled(self.consent && self.pending.is_none(),egui::Button::new("Verfahrensvorschlag erstellen")).clicked() {
                let (tx,rx)=std::sync::mpsc::channel(); self.pending=Some(rx); self.proposal=None; self.reviewed=false; self.consent=false;
                self.notice="KI erstellt einen ungeprüften Vorschlag …".into();
                let model=model.to_owned(); let context=context.clone();
                std::thread::spawn(move || {let _=tx.send(crate::procedure_compiler::cloud_suggest(&context,&model).map_err(|e|e.to_string()));});
            }
            if let Some(rx)=&self.pending {
                match rx.try_recv() {
                    Ok(result)=>{self.pending=None;match result {Ok(p)=>{self.proposal=Some(p);self.notice="Vorschlag fachlich prüfen; keine Ausführung erfolgt.".into();},Err(e)=>self.notice=e}},
                    Err(std::sync::mpsc::TryRecvError::Disconnected)=>{self.pending=None;self.notice="KI-Compiler unterbrochen".into();},
                    Err(std::sync::mpsc::TryRecvError::Empty)=>{ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));}
                }
            }
            ui.label(&self.notice);
            if let Some(proposal)=&mut self.proposal {
                let mut changed=false;
                for parameter in &mut proposal.parameters {
                    ui.horizontal(|ui| {ui.label(format!("Schritt {}: Eingabeplatz → Parameter",parameter.step.saturating_add(1))); changed |= ui.text_edit_singleline(&mut parameter.name).changed();});
                    ui.small(&parameter.reason);
                }
                for assertion in &proposal.assertions {
                    let phase=assertion.after.map(|i|format!("nach Schritt {}",i.saturating_add(1))).unwrap_or_else(||"am Ende".into());
                    let anchor=context.anchors.get(assertion.anchor).map(|a|format!("{} / {}",a.label,a.context)).unwrap_or_else(||"UNBEKANNTER ANKER".into());
                    ui.label(format!("Prüfen {phase}: {anchor} — {}",assertion.reason));
                }
                for assumption in &proposal.assumptions { ui.label(format!("Annahme: {assumption}")); }
                for missing in &proposal.missing { ui.colored_label(Color32::YELLOW,format!("Fehlt: {missing}")); }
                if changed {self.reviewed=false;}
                let preview=proposal.adopt(&context,source,true);
                if let Err(error)=&preview {ui.colored_label(Color32::YELLOW,error.to_string());}
                ui.add_enabled(preview.is_ok(),egui::Checkbox::new(&mut self.reviewed,"Alle Änderungen, Prüfbedingungen und Annahmen fachlich geprüft"));
                if ui.add_enabled(self.reviewed && preview.is_ok(),egui::Button::new("Geprüften Entwurf in Lernablauf übernehmen")).clicked() {
                    adopted=proposal.adopt(&context,source,self.reviewed).ok();
                }
                ui.small("Danach unten verschlüsselt speichern oder als Workflow vorbereiten. Ausführung benötigt neue Ziel- und Ablaufprüfung.");
            }
        });
        if adopted.is_some() {
            self.proposal = None;
            self.context = None;
            self.reviewed = false;
            self.consent = false;
        }
        adopted
    }
}

#[cfg(test)]
mod compiler_panel_tests {
    use super::*;
    #[test]
    fn compiler_source_explanation_or_model_changes_drop_consent_and_review() {
        let source = teaching::Procedure {
            dimensions: (800, 600),
            steps: vec![Step::TextRequired],
            success: "Ready".into(),
            recovery: "Cancel".into(),
            ..Default::default()
        };
        for change in 0..3 {
            let mut state = CompilerState {
                explanation: "Kunde eingeben".into(),
                model: "gpt-5".into(),
                consent: true,
                reviewed: true,
                ..Default::default()
            };
            state.context =
                Some(crate::procedure_compiler::Context::new(&source, &state.explanation).unwrap());
            let mut current = source.clone();
            if change == 0 {
                current.title = "changed".into();
            }
            if change == 1 {
                state.explanation = "Anderer Zweck".into();
            }
            state.sync(&current, if change == 2 { "gpt-6" } else { "gpt-5" });
            assert!(!state.consent && !state.reviewed && state.context.is_none());
        }
    }
}
