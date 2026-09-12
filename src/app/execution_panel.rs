use super::*;
use crate::execution::{ExecutionPlan, HealthCheck, HealthEvidence, Journal, Mapping, Phase, Run};
use crate::intelligence::{self, ServiceState};
use crate::mission::Target;
use crate::operations::{JobQueue, JobStatus};
use std::sync::mpsc;

pub(super) fn edit_http_steps(ui: &mut Ui, steps: &mut Vec<crate::execution::HttpGetStep>) {
    let mut remove = None;
    for (index, step) in steps.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("Schritt {}", index + 2));
            ui.add(egui::TextEdit::singleline(&mut step.path).char_limit(1024));
            ui.label("Status");
            ui.add(egui::DragValue::new(&mut step.status).range(200..=599));
            if ui.small_button("Entfernen").clicked() {
                remove = Some(index);
            }
        });
        ui.horizontal(|ui| {
            ui.label("Antwort enthält");
            ui.add(egui::TextEdit::singleline(&mut step.contains).char_limit(1024));
        });
        use crate::execution::http_health::Method;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut step.options.method, Method::Get, "GET");
            ui.selectable_value(&mut step.options.method, Method::Post, "POST");
        });
        if step.options.method == Method::Post {
            edit_http_fields(ui, &mut step.options.form, "Öffentliches Formularfeld", 32);
            edit_http_fields(
                ui,
                &mut step.options.secret_fields,
                "Secret-Feld → Laufzeit-Slot",
                32,
            );
        }
        ui.collapsing(format!("JSON-Assertions Schritt {}", index + 2), |ui| {
            let mut revised = std::collections::BTreeMap::new();
            for (pointer, value) in &step.options.json_equals {
                let mut pointer = pointer.clone();
                let mut value = value.clone();
                let mut remove = false;
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut pointer).char_limit(512));
                    match &mut value {
                        serde_json::Value::String(v) => {
                            ui.text_edit_singleline(v);
                        }
                        serde_json::Value::Bool(v) => {
                            ui.checkbox(v, "true");
                        }
                        _ => {
                            ui.label("null");
                        }
                    }
                    remove = ui.small_button("×").clicked();
                });
                if !remove {
                    revised.insert(pointer, value);
                }
            }
            step.options.json_equals = revised;
            ui.horizontal(|ui| {
                for (label, value) in [
                    ("String", serde_json::json!("ok")),
                    ("Bool", serde_json::json!(true)),
                    ("null", serde_json::Value::Null),
                ] {
                    if ui
                        .add_enabled(
                            step.options.json_equals.len() < 16,
                            egui::Button::new(label),
                        )
                        .clicked()
                    {
                        let key = format!("/status{}", step.options.json_equals.len() + 1);
                        step.options.json_equals.insert(key, value);
                    }
                }
            });
        });
    }
    if let Some(index) = remove {
        steps.remove(index);
    }
    if ui
        .add_enabled(
            steps.len() < 3,
            egui::Button::new("Weiteren HTTP-Prüfschritt hinzufügen"),
        )
        .clicked()
    {
        steps.push(crate::execution::HttpGetStep {
            path: "/health".into(),
            status: 200,
            contains: String::new(),
            options: Default::default(),
        });
    }
    ui.small("Bis zu vier Prüfungen: erster GET, danach GET/POST mit hosteigenen Path=/-Session-Cookies. JSON-Pointer: String/Bool/null. Secret-Slots nur über HTTPS; niemals Passwörter in feste Formularwerte eintragen.");
    ui.small("POST kann Anwendungsdaten ändern. Automatische Wiederherstellung betrifft den Dienstzustand, nicht diese Anwendungsänderungen.");
}
fn edit_http_fields(
    ui: &mut Ui,
    fields: &mut crate::execution::http_health::Values,
    label: &str,
    limit: usize,
) {
    ui.collapsing(label, |ui| {
        let mut revised = Default::default();
        for (key, value) in fields.iter() {
            let mut key = key.clone();
            let mut value = value.clone();
            let mut remove = false;
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut key).char_limit(128));
                ui.add(egui::TextEdit::singleline(&mut value).char_limit(4096));
                remove = ui.small_button("×").clicked();
            });
            if !remove {
                std::collections::BTreeMap::insert(&mut revised, key, value);
            }
        }
        *fields = revised;
        if ui
            .add_enabled(fields.len() < limit, egui::Button::new("Feld hinzufügen"))
            .clicked()
        {
            fields.insert(format!("field{}", fields.len() + 1), String::new());
        }
    });
}

pub(super) struct ExecutionState {
    book: Journal,
    error: Option<String>,
    selected: Option<usize>,
    queue: JobQueue,
    remote: Option<u64>,
    health: Option<mpsc::Receiver<HealthEvidence>>,
    service: String,
    desired: ServiceState,
    http: bool,
    port: u16,
    tls: bool,
    path: String,
    status: u16,
    contains: String,
    followups: Vec<crate::execution::HttpGetStep>,
    http_values: String,
    http_runtime: Option<(Uuid, crate::execution::http_health::Values)>,
    mappings: Vec<(Uuid, Uuid)>,
    production: Option<Uuid>,
    staging: Option<Uuid>,
    reviewed: bool,
    distinct: bool,
}
impl Default for ExecutionState {
    fn default() -> Self {
        let (book, error) =
            match app_data_file("relayne-execution.dpapi").and_then(|p| Journal::load(&p)) {
                Ok(b) => (b, None),
                Err(e) => (
                    Journal::default(),
                    Some(format!(
                        "Journal nicht lesbar; Datei bleibt unverändert: {e}"
                    )),
                ),
            };
        Self {
            selected: book.runs.len().checked_sub(1),
            book,
            error,
            queue: JobQueue::default(),
            remote: None,
            health: None,
            service: String::new(),
            desired: ServiceState::Running,
            http: true,
            port: 80,
            tls: false,
            path: "/health".into(),
            status: 200,
            contains: String::new(),
            followups: vec![],
            http_values: "{}".into(),
            http_runtime: None,
            mappings: vec![],
            production: None,
            staging: None,
            reviewed: false,
            distinct: false,
        }
    }
}
impl AivanaApp {
    pub(super) fn recovery_execution_runs(&self) -> &[Run] {
        &self.execution.book.runs
    }
    pub(super) fn select_recovery_execution(&mut self, id: Uuid) -> anyhow::Result<()> {
        self.execution.select_recovery(id)
    }
    pub(super) fn prepare_lab_production(
        &mut self,
        plan: ExecutionPlan,
        references: Vec<String>,
        recovery_case: Option<Uuid>,
    ) -> anyhow::Result<()> {
        if let Some(id) = recovery_case {
            self.validate_recovery_case(id, &plan.service)?;
            anyhow::ensure!(
                plan.desired == ServiceState::Running,
                "Recovery unterstützt ausschließlich Dienststart"
            );
        }
        anyhow::ensure!(
            self.execution.error.is_none(),
            "Ausführungsjournal gesperrt"
        );
        anyhow::ensure!(
            !self
                .execution
                .selected
                .is_some_and(|i| self.execution.book.runs[i].finished.is_none()),
            "Zuerst laufenden Auftrag abschließen oder abbrechen"
        );
        crate::promotion::check_receipts(&plan, &references, Utc::now())?;
        anyhow::ensure!(
            plan.mappings
                .iter()
                .all(|m| self.profiles.iter().any(|p| m.production.matches(p))),
            "Produktionsprofil geändert oder entfernt"
        );
        let mut run = Run::new(plan, false)?;
        run.lab_receipts = references;
        run.recovery_case = recovery_case;
        self.execution.book.runs.push(run);
        self.execution.selected = Some(self.execution.book.runs.len() - 1);
        self.execution.reviewed = false;
        anyhow::ensure!(
            self.execution_save(),
            "Auftrag konnte nicht dauerhaft gespeichert werden"
        );
        self.view = View::Execution;
        self.execution_drive();
        Ok(())
    }
    fn execution_has_proof(&self, run: &Run) -> bool {
        if run
            .plan
            .mappings
            .iter()
            .any(|m| m.staging.protocol == crate::promotion::LAB_PROTOCOL)
        {
            crate::promotion::check_receipts(&run.plan, &run.lab_receipts, Utc::now()).is_ok()
        } else {
            self.execution
                .book
                .runs
                .iter()
                .any(|proof| proof.proof_for(&run.plan, Utc::now()))
        }
    }
    pub(super) fn execution_incident_records(&self) -> Vec<crate::incident::Record> {
        use crate::incident::{Kind, Record};
        let mut records = Vec::new();
        for run in &self.execution.book.runs {
            for target in &run.targets {
                if let Some(at) = target.captured {
                    records.push(Record {
                        id: format!("execution:{}:{}:capture", run.id, target.target.profile_id),
                        profile: Some(target.target.profile_id),
                        endpoint: Some(crate::incident::endpoint_key(&target.target)),
                        at,
                        kind: Kind::Observation,
                        title: format!(
                            "{} · {}: Ausgangszustand {:?}{}",
                            target.target.name,
                            run.plan.service,
                            target.before,
                            if run.rehearsal { " (Testlauf)" } else { "" }
                        ),
                        evidence: vec![run.id.to_string(), run.hash.clone()],
                    });
                }
                if let Some(health) = &target.health {
                    records.push(Record {
                        id: format!("execution:{}:{}:health", run.id, target.target.profile_id),
                        profile: Some(target.target.profile_id),
                        endpoint: Some(crate::incident::endpoint_key(&target.target)),
                        at: health.at,
                        kind: if health.passed {
                            Kind::Observation
                        } else {
                            Kind::Failure
                        },
                        title: format!(
                            "{} · {}: {}",
                            target.target.name, run.plan.service, health.detail
                        ),
                        evidence: vec![run.id.to_string(), run.hash.clone()],
                    });
                }
            }
        }
        records
    }
    pub(super) fn execution_lessons(&self) -> Vec<crate::execution::ExecutionLesson> {
        if self.execution.error.is_some() {
            return vec![];
        }
        self.execution.book.lessons()
    }
    pub(super) fn use_execution_lesson(&mut self, lesson: &crate::execution::ExecutionLesson) {
        if self
            .execution
            .selected
            .is_some_and(|i| self.execution.book.runs[i].finished.is_none())
        {
            self.status =
                "Zuerst den laufenden Ausführungsauftrag abschließen oder abbrechen.".into();
            return;
        }
        self.execution.service = lesson.service.clone();
        self.execution.desired = lesson.desired;
        match &lesson.health {
            HealthCheck::Tcp { port } => {
                self.execution.http = false;
                self.execution.port = *port;
                self.execution.tls = false;
                self.execution.path = "/health".into();
                self.execution.status = 200;
                self.execution.contains.clear();
                self.execution.followups.clear();
            }
            HealthCheck::Http {
                port,
                tls,
                path,
                status,
                contains,
                followups,
            } => {
                self.execution.http = true;
                self.execution.port = *port;
                self.execution.tls = *tls;
                self.execution.path = path.clone();
                self.execution.status = *status;
                self.execution.contains = contains.clone();
                self.execution.followups = followups.clone();
            }
        }
        self.execution.mappings.clear();
        self.execution.production = None;
        self.execution.staging = None;
        self.execution.reviewed = false;
        self.execution.distinct = false;
        self.status = "Lösung als Entwurf übernommen. Neue Produktions-/Testziele zuordnen und Testlauf prüfen.".into();
    }
    fn execution_save(&mut self) -> bool {
        if self.execution.error.is_some() {
            return false;
        }
        if let Err(e) =
            app_data_file("relayne-execution.dpapi").and_then(|p| self.execution.book.save(&p))
        {
            self.execution.error = Some(format!(
                "Journal konnte nicht gesichert werden. Ausführung gesperrt; laufenden Host manuell prüfen: {e}"
            ));
            return false;
        }
        true
    }
    fn execution_plan(&self) -> anyhow::Result<ExecutionPlan> {
        let mut mappings = vec![];
        for (p, s) in &self.execution.mappings {
            let production = self
                .profiles
                .iter()
                .find(|v| v.id == *p)
                .ok_or_else(|| anyhow::anyhow!("Produktionsprofil fehlt"))?;
            let staging = self
                .profiles
                .iter()
                .find(|v| v.id == *s)
                .ok_or_else(|| anyhow::anyhow!("Testprofil fehlt"))?;
            mappings.push(Mapping {
                production: Target::from_profile(production),
                staging: Target::from_profile(staging),
            });
        }
        let e = &self.execution;
        let plan = ExecutionPlan {
            service: e.service.trim().into(),
            desired: e.desired,
            mappings,
            health: if e.http {
                HealthCheck::Http {
                    port: e.port,
                    tls: e.tls,
                    path: e.path.clone(),
                    status: e.status,
                    contains: e.contains.clone(),
                    followups: e.followups.clone(),
                }
            } else {
                HealthCheck::Tcp { port: e.port }
            },
        };
        plan.validate()?;
        Ok(plan)
    }
    fn execution_fail(&mut self, message: String) {
        if let Some(i) = self.execution.selected {
            let r = &mut self.execution.book.runs[i];
            let t = &mut r.targets[r.current];
            t.phase = Phase::Unknown;
            t.evidence.push(message);
            r.advance();
        }
        self.execution_save();
    }
    pub(super) fn poll_execution(&mut self) {
        self.execution.queue.poll();
        // Cancelled jobs may finish after their run has been detached.
        if self.execution.remote.is_none() {
            self.execution.queue.clear_finished();
        }
        let Some(i) = self.execution.selected else {
            return;
        };
        if let Some(id) = self.execution.remote {
            let Some(job) = self.execution.queue.jobs.iter().find(|j| j.id == id) else {
                return;
            };
            if !job.status.terminal() {
                return;
            }
            let result = job.result.clone();
            self.execution.remote = None;
            self.execution.queue.clear_finished();
            let Some(result) = result.filter(|r| r.status == JobStatus::Completed && !r.truncated)
            else {
                self.execution_fail("Job fehlgeschlagen/abgebrochen: entfernter Zustand unbekannt, keine Wiederholung".into());
                return;
            };
            let r = &mut self.execution.book.runs[i];
            let phase = r.targets[r.current].phase;
            let result = if phase == Phase::Capture {
                intelligence::captured_state(&result.stdout, &r.plan.service).map(|before| {
                    let t = &mut r.targets[r.current];
                    t.before = Some(before);
                    t.captured = Some(Utc::now());
                    t.evidence
                        .push(crate::security::redact_secret_text(&result.stdout));
                    t.phase = Phase::Baseline;
                })
            } else {
                r.assess_mutation(&result.stdout, phase == Phase::Restore)
            };
            if let Err(e) = result {
                self.execution_fail(e.to_string());
                return;
            }
            self.execution.book.runs[i].advance();
            if !self.execution_save() {
                return;
            }
        }
        if let Some(rx) = &self.execution.health {
            let result = match rx.try_recv() {
                Ok(e) => Some(e),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => Some(HealthEvidence {
                    at: Utc::now(),
                    passed: false,
                    detail: "Healthcheck-Worker unterbrochen".into(),
                }),
            };
            self.execution.health = None;
            let r = &mut self.execution.book.runs[i];
            let evidence = result.unwrap();
            if let Err(e) = r.finish_health(evidence) {
                self.execution_fail(e.to_string());
                return;
            }
            self.execution.reviewed = false;
            if !self.execution_save() {
                return;
            }
        }
        self.execution_drive();
    }
    fn execution_drive(&mut self) {
        if self.execution.error.is_some()
            || self.execution.remote.is_some()
            || self.execution.health.is_some()
        {
            return;
        }
        let Some(i) = self.execution.selected else {
            return;
        };
        let r = &self.execution.book.runs[i];
        if r.finished.is_some() {
            self.execution.http_runtime = None;
            return;
        }
        let t = &r.targets[r.current];
        let phase = t.phase;
        if matches!(
            phase,
            Phase::Review | Phase::Unknown | Phase::Failed | Phase::Restored | Phase::Passed
        ) {
            return;
        }
        // Bind ephemeral values once to this run before any remote change. Keep through verification/restore.
        if phase != Phase::Restore
            && self
                .execution
                .http_runtime
                .as_ref()
                .is_none_or(|(id, _)| *id != r.id)
        {
            let values: crate::execution::http_health::Values = match serde_json::from_str(
                &self.execution.http_values,
            ) {
                Ok(values) => values,
                Err(_) => {
                    self.execution_fail("HTTP-Laufzeitwerte benötigen ein JSON-Objekt aus Strings; Ausführung nicht gestartet".into());
                    return;
                }
            };
            if r.plan.health.validate_values(&values).is_err() {
                self.execution_fail(
                    "HTTP-Secret-Slots fehlen oder sind ungültig; Ausführung nicht gestartet"
                        .into(),
                );
                return;
            }
            self.execution.http_runtime = Some((r.id, values));
            self.execution.http_values = "{}".into();
        }
        if phase == Phase::Apply
            && (t.before.is_none()
                || t.baseline.is_none()
                || !t
                    .captured
                    .is_some_and(|at| (0..120).contains(&(Utc::now() - at).num_seconds())))
        {
            self.execution_fail("Ausgangsbefund fehlt oder ist veraltet; Änderung gesperrt".into());
            return;
        }
        if phase == Phase::Restore && t.before.is_none() {
            self.execution_fail(
                "Ausgangszustand unbekannt; Wiederherstellung benötigt manuelle Prüfung".into(),
            );
            return;
        }
        // Rehearsal proof authorizes initial production run; each mutation also checks freshness.
        if phase == Phase::Apply && !r.rehearsal && !self.execution_has_proof(r) {
            self.execution_fail(
                "Testnachweis abgelaufen oder verändert; kein Produktionsstart".into(),
            );
            return;
        }
        if phase != Phase::Restore && !self.profiles.iter().any(|p| t.target.matches(p)) {
            self.execution_fail(
                "Profil geändert oder entfernt; unveränderlicher Ziel-Snapshot passt nicht mehr"
                    .into(),
            );
            return;
        }
        if matches!(phase, Phase::Baseline | Phase::Verify) {
            let check = r.plan.health.clone();
            let target = t.target.clone();
            let values = self
                .execution
                .http_runtime
                .as_ref()
                .filter(|(id, _)| *id == r.id)
                .map(|(_, values)| values.clone())
                .unwrap_or_default();
            if !self.execution_save() {
                return;
            }
            let (tx, rx) = mpsc::channel();
            self.execution.health = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(check.probe_with_values(&target, &values));
            });
            return;
        }
        let change = match phase {
            Phase::Apply => Some((t.before.unwrap(), r.plan.desired)),
            Phase::Restore => Some((r.plan.desired, t.before.unwrap())),
            _ => None,
        };
        let spec = intelligence::service_spec(&t.target, &r.plan.service, change);
        match spec {
            Ok(spec) => {
                if !self.execution_save() {
                    return;
                }
                match self.execution.queue.enqueue(spec) {
                    Ok(id) => self.execution.remote = Some(id),
                    Err(e) => self.execution_fail(e),
                }
            }
            Err(e) => self.execution_fail(e.to_string()),
        }
    }
    pub(super) fn execution_view(&mut self, ui: &mut Ui) {
        self.execution_content(ui, false);
    }
    pub(super) fn execution_recovery_view(&mut self, ui: &mut Ui) {
        self.execution_content(ui, true);
    }
    fn execution_content(&mut self, ui: &mut Ui, recovery_only: bool) {
        ui.heading("Geprüfte Ausführung & Testlauf");
        ui.label("HTTP-Laufzeit-Slots als JSON (nur Arbeitsspeicher, für Produktionszugang erneut eingeben)");
        let runtime_editable = self.execution.http_runtime.is_none()
            && self.execution.remote.is_none()
            && self.execution.health.is_none();
        ui.add_enabled(
            runtime_editable,
            egui::TextEdit::singleline(&mut self.execution.http_values)
                .password(true)
                .char_limit(32768),
        );
        if ui
            .add_enabled(
                runtime_editable,
                egui::Button::new("HTTP-Laufzeitwerte löschen"),
            )
            .clicked()
        {
            self.execution.http_values = "{}".into();
        }
        if self.execution.http_runtime.is_some() {
            ui.small("Laufzeitwerte unveränderlich an diesen Auftrag gebunden; verbleiben bis Abschluss im Arbeitsspeicher.");
        }
        ui.label("Diagnose → geprüfte Dienständerung → Funktionstest → Wiederherstellung bei Fehler. Erst Testumgebung, dann ein Pilot und einzeln freigegebene weitere Ziele.");
        ui.small("WinRM verwendet die aktuelle Windows-Identität. Healthchecks laufen vom Relayne-Rechner aus. Testlauf verändert echte, selbst ausgewählte Testsysteme.");
        if let Some(e) = &self.execution.error {
            ui.colored_label(tw::RED_600, e);
        }
        if !recovery_only {
            let busy = self
                .execution
                .selected
                .is_some_and(|i| self.execution.book.runs[i].finished.is_none());
            ui.add_enabled_ui(!busy, |ui| {
            ui.horizontal(|ui| {
                ui.label("Dienst"); ui.text_edit_singleline(&mut self.execution.service);
                ui.selectable_value(&mut self.execution.desired, ServiceState::Running, "Running");
                ui.selectable_value(&mut self.execution.desired, ServiceState::Stopped, "Stopped");
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.execution.http, "HTTP-Funktionstest (sonst TCP)");
                ui.label("Port"); ui.add(egui::DragValue::new(&mut self.execution.port).range(1..=65535));
                if self.execution.http { ui.checkbox(&mut self.execution.tls, "HTTPS"); ui.label("Status"); ui.add(egui::DragValue::new(&mut self.execution.status).range(200..=599)); }
            });
            if self.execution.http {
                ui.horizontal(|ui| { ui.label("Pfad"); ui.text_edit_singleline(&mut self.execution.path); });
                edit_http_steps(ui, &mut self.execution.followups);
                ui.horizontal(|ui| { ui.label("Antwort enthält (öffentliches Muster)"); ui.text_edit_singleline(&mut self.execution.contains); });
                ui.small("Keine Zugangsdaten in feste Werte. GET/POST und Sitzungscookies, keine Redirects oder Antwortspeicherung, 64 KiB Antwortlimit. Laufzeit-Slots benötigen HTTPS.");
            }
            for (label, slot) in [("Produktion", &mut self.execution.production), ("Test/Staging", &mut self.execution.staging)] {
                egui::ComboBox::from_id_salt(label).selected_text(slot.and_then(|id| self.profiles.iter().find(|p| p.id==id)).map(|p| p.name.as_str()).unwrap_or(label))
                    .show_ui(ui, |ui| { for p in &self.profiles { if p.protocol == Protocol::Rdp { ui.selectable_value(slot, Some(p.id), format!("{} · {}",p.name,p.host)); } } });
            }
            if ui.button("Zielzuordnung hinzufügen").clicked() {
                if let (Some(p),Some(s))=(self.execution.production,self.execution.staging) { self.execution.mappings.push((p,s)); self.execution.reviewed=false; }
            }
            let mut remove=None;
            for (i,(p,s)) in self.execution.mappings.iter().enumerate() {
                let name=|id| self.profiles.iter().find(|p| p.id==id).map(|p|format!("{} ({})",p.name,p.host)).unwrap_or_else(||"Profil fehlt".into());
                ui.horizontal(|ui| { ui.label(format!("{}: {} → {}", if i==0 {"Pilot"} else {"Rollout"},name(*p),name(*s))); if ui.small_button("Entfernen").clicked(){remove=Some(i);} });
            }
            if let Some(i)=remove {self.execution.mappings.remove(i);self.execution.reviewed=false;}
            ui.checkbox(&mut self.execution.distinct,"Ich habe geprüft: Testhosts sind eigene Systeme, keine DNS-Aliase der Produktion; dort sind echte Änderungen erlaubt.");
        });
            let plan = self.execution_plan();
            if let Ok(p) = &plan {
                ui.monospace(format!("Plan SHA-256: {}", p.hash().unwrap_or_default()));
                let proof = self
                    .execution
                    .book
                    .runs
                    .iter()
                    .any(|r| r.proof_for(p, Utc::now()));
                ui.label(if proof {
                    "Passender erfolgreicher Testlauf vorhanden (maximal 1 Stunde)."
                } else {
                    "Kein gültiger Testnachweis für genau diesen Plan und diese Zielzuordnungen."
                });
                let mut start = None;
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !busy && self.execution.error.is_none() && self.execution.distinct,
                            egui::Button::new("Testlauf vorbereiten"),
                        )
                        .clicked()
                    {
                        start = Some(true);
                    }
                    if ui
                        .add_enabled(
                            !busy
                                && proof
                                && self.execution.error.is_none()
                                && self.execution.distinct,
                            egui::Button::new("Produktionspilot vorbereiten"),
                        )
                        .clicked()
                    {
                        start = Some(false);
                    }
                });
                if let Some(rehearsal) = start {
                    match Run::new(p.clone(), rehearsal) {
                        Ok(r) => {
                            self.execution.book.runs.push(r);
                            self.execution.selected = Some(self.execution.book.runs.len() - 1);
                            self.execution.reviewed = false;
                            if self.execution_save() {
                                self.execution_drive();
                            }
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            } else if let Err(e) = plan {
                ui.small(e.to_string());
            }
        }
        ui.separator();
        let Some(i) = self.execution.selected else {
            return;
        };
        let run = self.execution.book.runs[i].clone();
        ui.label(format!(
            "{} · {}",
            if run.rehearsal {
                "Testlauf"
            } else {
                "Produktion"
            },
            run.id
        ));
        if !run.lab_receipts.is_empty() {
            ui.label("Dieser Produktionsauftrag basiert auf einer gebundenen Klon-Generalprobe. Jede Dienständerung prüft die verschlüsselten Nachweise erneut; Produktion verwendet eigene aktuelle Ausgangsbefunde.");
            for reference in &run.lab_receipts {
                ui.small(format!("Klonnachweis: {reference}"));
            }
            ui.label(if self.execution_has_proof(&run){"Klonnachweise aktuell und passend."}else{"Klonnachweise fehlen, sind verändert oder abgelaufen; weitere Änderungen sind gesperrt."});
        }
        for (n, t) in run.targets.iter().enumerate() {
            ui.collapsing(format!("{} · {} · {:?}",n+1,t.target.name,t.phase),|ui| {
                ui.label(format!("Host {} · Domain {} · Profilbenutzer {} · Auth: aktuelle Windows-Identität",t.target.host,t.target.domain,t.target.username));
                ui.label(format!("Dienst: {:?} → {}",t.before,run.plan.desired.label()));
                if let Some(b)=&t.baseline{ui.label(format!("Vorher: {} · {} · {}",b.passed,b.detail,b.at));}
                if let Some(b)=&t.health{ui.label(format!("Nachher: {} · {} · {}",b.passed,b.detail,b.at));}
                for e in &t.evidence {ui.monospace(e);}
            });
        }
        let t = &run.targets[run.current];
        if t.phase == Phase::Review && run.finished.is_none() {
            ui.label(format!("Änderung prüfen: {} / {} / {:?} → {}. Bei Funktionsfehler Wiederherstellung auf {:?}.",t.target.host,run.plan.service,t.before,run.plan.desired.label(),t.before));
            if let Some(before) = t.before {
                if let Ok(spec) = intelligence::service_spec(
                    &t.target,
                    &run.plan.service,
                    Some((before, run.plan.desired)),
                ) {
                    ui.collapsing("Exakter Befehl mit Schutzprüfungen und Rückweg", |ui| {
                        ui.monospace(spec.preview());
                    });
                }
            }
            ui.checkbox(&mut self.execution.reviewed,"Dieses Ziel, Ausgangslage, Funktionstest und automatische Wiederherstellung geprüft und freigegeben");
            let fresh = t
                .captured
                .is_some_and(|at| (0..120).contains(&(Utc::now() - at).num_seconds()));
            let change = t.before != Some(run.plan.desired);
            if !fresh {
                ui.label(
                    "Vorprüfung älter als 120 Sekunden: abbrechen und neuen Lauf vorbereiten.",
                );
            }
            if run.rehearsal && !change {
                ui.label("Test benötigt einen echten Zustandswechsel. Testsystem manuell vorbereiten und neuen Lauf starten.");
            }
            if ui
                .add_enabled(
                    self.execution.reviewed
                        && fresh
                        && (!run.rehearsal || change)
                        && (run.recovery_case.is_none() || self.recovery_actions_allowed())
                        && self.execution.error.is_none(),
                    egui::Button::new(if run.current == 0 {
                        "Pilot freigeben und prüfen"
                    } else {
                        "Nächstes Rolloutziel freigeben"
                    }),
                )
                .clicked()
            {
                self.execution.book.runs[i].targets[run.current].phase =
                    if change { Phase::Apply } else { Phase::Verify };
                self.execution.reviewed = false;
                if self.execution_save() {
                    self.execution_drive();
                }
            }
        }
        if run.finished.is_none()
            && ui
                .button("Abbrechen; entfernten Zustand als unbekannt markieren")
                .clicked()
        {
            if let Some(id) = self.execution.remote.take() {
                if let Some(job) = self.execution.queue.jobs.iter().find(|j| j.id == id) {
                    job.cancel();
                }
            }
            self.execution.health = None;
            self.execution_fail("Vom Operator abgebrochen. Kein automatischer Neustart; entfernte Ausführung kann weiterlaufen.".into());
        }
        if run.successful() && !recovery_only {
            ui.label("Alle Ziele funktional bestätigt. Testlauf behält den angezeigten geänderten Dienstzustand bei.");
        }
        if matches!(t.phase, Phase::Unknown | Phase::Restored | Phase::Failed) {
            ui.label("Rollout angehalten. Befunde prüfen und Infrastruktur bei Bedarf manuell wiederherstellen. Dieser Lauf wird nicht wiederholt.");
        }
        ui.collapsing("Frühere Läufe", |ui| {
            for r in self.execution.book.runs.iter().rev().skip(1).take(20) {
                ui.label(format!(
                    "{} · {} · Erfolg {}",
                    r.id,
                    if r.rehearsal { "Test" } else { "Produktion" },
                    r.successful()
                ));
                for t in &r.targets {
                    ui.label(format!("{} · {:?}", t.target.name, t.phase));
                }
            }
        });
    }
}

impl ExecutionState {
    fn select_recovery(&mut self, case: Uuid) -> anyhow::Result<()> {
        let index = self.book.runs.iter().rposition(|r| r.recovery_case == Some(case) && !r.rehearsal)
            .ok_or_else(|| anyhow::anyhow!("Noch kein Produktionslauf für diesen Fall. Zuerst Generalprobe abschließen und Produktion vorbereiten."))?;
        if self.selected == Some(index) {
            return Ok(());
        }
        anyhow::ensure!(
            self.remote.is_none()
                && self.health.is_none()
                && !self.book.runs.iter().any(|r| r.finished.is_none())
                && self.queue.jobs.iter().all(|j| j.status.terminal()),
            "Ein anderer Auftrag läuft. Dort zuerst abschließen oder abbrechen."
        );
        self.selected = Some(index);
        self.reviewed = false;
        self.http_values = "{}".into();
        self.http_runtime = None;
        Ok(())
    }
}

#[cfg(test)]
mod recovery_selection_tests {
    use super::*;
    fn run(case: Uuid, finished: bool) -> Run {
        let target = |host: &str| Target {
            profile_id: Uuid::new_v4(),
            name: host.into(),
            host: host.into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        };
        let mut run = Run::new(
            ExecutionPlan {
                service: "AppService".into(),
                desired: ServiceState::Running,
                health: HealthCheck::Tcp { port: 80 },
                mappings: vec![Mapping {
                    production: target("production"),
                    staging: target("staging"),
                }],
            },
            false,
        )
        .unwrap();
        run.recovery_case = Some(case);
        if finished {
            run.finished = Some(Utc::now());
        }
        run
    }
    #[test]
    fn selecting_recovery_uses_exact_case_and_clears_approval_and_runtime_values() {
        let case = Uuid::new_v4();
        let mut state = ExecutionState::default();
        state.book = Journal {
            runs: vec![run(case, true), run(Uuid::new_v4(), true)],
        };
        state.selected = Some(1);
        state.reviewed = true;
        state.http_values = "old-secrets".into();
        state.select_recovery(case).unwrap();
        assert_eq!(state.selected, Some(0));
        assert!(!state.reviewed);
        assert_eq!(state.http_values, "{}");
        assert!(state.remote.is_none() && state.health.is_none() && state.queue.jobs.is_empty());
        assert!(state.select_recovery(Uuid::new_v4()).is_err());
        assert_eq!(state.selected, Some(0));
    }
    #[test]
    fn selecting_recovery_never_redirects_a_running_job_to_another_case() {
        let case = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut state = ExecutionState::default();
        state.book = Journal {
            runs: vec![run(case, true), run(other, false)],
        };
        state.selected = Some(1);
        assert!(state.select_recovery(case).is_err());
        assert_eq!(state.selected, Some(1));
        assert!(state.select_recovery(other).is_ok());
    }
}
