use super::*;
use crate::integrations::{self, GroupRule, InventoryReview, VaultRequest};
use crate::operations::{JobQueue, JobStatus};

#[derive(Default)]
pub(super) struct IntegrationsState {
    path: String,
    review: Option<InventoryReview>,
    selected: Vec<bool>,
    notice: String,
    jobs: JobQueue,
    ad_job: Option<u64>,
    vault_item: String,
    vault_target: Option<Uuid>,
    vault_replace: bool,
    vault: Option<(ConnectionProfile, VaultRequest)>,
    rules: Vec<GroupRule>,
    rule: GroupRule,
    rules_loaded: bool,
}

impl AivanaApp {
    pub(super) fn poll_integrations(&mut self) {
        self.integrations.jobs.poll();
        if let Some(id) = self.integrations.ad_job {
            if let Some(job) = self.integrations.jobs.jobs.iter().find(|job| job.id == id) {
                if job.status.terminal() {
                    let parsed = match &job.result {
                        Some(result) if result.status == JobStatus::Completed && !result.truncated => {
                            integrations::parse_inventory(&result.stdout, false)
                        }
                        _ => Err("AD-Inventar nicht verfügbar: ActiveDirectory-Modul, Domänenzugriff und Leserechte prüfen; maximal 500 Computer und 128 KiB Antwort. Bei größeren Domänen JSON/CSV importieren.".into()),
                    };
                    match parsed {
                        Ok(rows) => self.set_inventory_review(rows),
                        Err(error) => self.integrations.notice = error,
                    }
                    self.integrations.ad_job = None;
                    self.integrations.jobs.clear_finished();
                }
            }
        }
        let completed = self
            .integrations
            .vault
            .as_ref()
            .and_then(|(profile, request)| request.poll().map(|result| (profile.clone(), result)));
        if let Some((reviewed_profile, result)) = completed {
            self.integrations.vault = None;
            match result {
                Ok(mut secret) => {
                    if let Some(index) = self.profiles.iter().position(|p| p.id==reviewed_profile.id && p.updated_at==reviewed_profile.updated_at && p.credential_id==reviewed_profile.credential_id && crate::mission::Target::from_profile(&reviewed_profile).matches(p)) {
                        let mut profile = self.profiles[index].clone();
                        secret.domain = profile.domain.clone();
                        profile.username = secret.username.clone();
                        // Use a fresh record: profile persistence must never alter the old login on failure.
                        profile.credential_id=None;
                        match self.credentials.save(&mut profile, secret) {
                            Ok(reference) => {
                                profile.updated_at = Utc::now();
                                let mut profiles = self.profiles.clone();
                                profiles[index] = profile;
                                match self.store.as_ref().map(|store| store.save(&profiles)) {
                                    Some(Ok(())) => {
                                        self.profiles = profiles;
                                        self.integrations.notice = "Vault-Login geschützt gespeichert und Profil aktualisiert.".into();
                                    }
                                    _ => {let _=self.credentials.delete(reference.id);self.integrations.notice = "Profilverknüpfung konnte nicht gespeichert werden. Bestehendes Profil und bisheriger Login bleiben unverändert.".into();},
                                }
                            }
                            Err(_) => self.integrations.notice = "Lokales geschütztes Speichern fehlgeschlagen; Profil nicht geändert.".into(),
                        }
                    } else {
                        self.integrations.notice =
                            "Zielprofil wurde entfernt oder geändert; Vault-Login verworfen.".into();
                    }
                }
                Err(error) => self.integrations.notice = error,
            }
        }
    }

    fn set_inventory_review(&mut self, rows: Vec<ConnectionProfile>) {
        let review = integrations::review_inventory(rows, &self.profiles);
        self.integrations.selected = vec![true; review.candidates.len()];
        self.integrations.notice = format!(
            "{} neue Profile zur Prüfung; {} doppelte Endpunkte oder Identitätskonflikte übersprungen. Bestehende Profile werden nicht überschrieben.",
            review.candidates.len(),
            review.conflicts
        );
        self.integrations.review = Some(review);
    }

    pub(super) fn integrations_view(&mut self, ui: &mut Ui) {
        if !self.integrations.rules_loaded {
            self.integrations.rules_loaded = true;
            if let Ok(path) = app_data_file("inventory-rules.json") {
                if let Ok(file) = std::fs::File::open(path) {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    if file.take(65537).read_to_end(&mut bytes).is_ok() && bytes.len() <= 65536 {
                        match serde_json::from_slice::<Vec<GroupRule>>(&bytes) {
                            Ok(rules) if rules.len() <= 100 => self.integrations.rules = rules,
                            _ => {
                                self.integrations.notice =
                                    "Gespeicherte Gruppenregeln ungültig oder zu umfangreich."
                                        .into()
                            }
                        }
                    }
                }
            }
        }
        if self.integrations.ad_job.is_some() || self.integrations.vault.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
        ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Inventar & Vault");
            ui.label("Quellen bewusst abrufen, Kandidaten prüfen und ausgewählte Verbindungen speichern.");
            ui.separator();
            ui.strong("Active Directory");
            ui.label("Voraussetzung: Windows PowerShell mit installiertem ActiveDirectory-Modul (RSAT), Domänenzugriff und aktuelle Windows-Identität mit Leserechten. Keine automatische Anmeldung.");
            ui.horizontal(|ui| {
                if ui.add_enabled(self.integrations.ad_job.is_none(), egui::Button::new("AD-Computer jetzt lesen")).clicked() {
                    match self.integrations.jobs.enqueue(integrations::ad_inventory_command()) {
                        Ok(id) => { self.integrations.ad_job = Some(id); self.integrations.notice = "AD-Abfrage gestartet …".into(); }
                        Err(error) => self.integrations.notice = error,
                    }
                }
                if self.integrations.ad_job.is_some() && ui.button("AD-Abfrage abbrechen").clicked() {
                    for job in &self.integrations.jobs.jobs { job.cancel(); }
                }
            });
            ui.label("Entra ID: kein Live-Connector implementiert. Ein extern erstelltes Inventar kann unten importiert werden.");
            ui.separator();
            ui.strong("JSON / CSV importieren");
            ui.label("JSON: Array mit name, host; optional port, protocol (rdp/ssh/vnc), username, domain, group. CSV: dieselben Spalten. Kennwörter, IDs und Credential-Referenzen werden nicht übernommen. Maximal 2 MiB / 2000 Zeilen.");
            ui.horizontal(|ui| {
                ui.label("Dateipfad");
                ui.text_edit_singleline(&mut self.integrations.path);
                if ui.button("Datei prüfen").clicked() {
                    use std::io::Read;
                    let path = std::path::Path::new(self.integrations.path.trim());
                    let csv = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("csv"));
                    let result = std::fs::File::open(path).map_err(|_| "Inventardatei nicht lesbar.".to_string()).and_then(|file| {
                        let mut text = String::new();
                        file.take(integrations::INVENTORY_LIMIT as u64 + 1).read_to_string(&mut text).map_err(|_| "Inventar muss UTF-8 sein.".to_string())?;
                        integrations::parse_inventory(&text, csv)
                    });
                    match result { Ok(rows) => self.set_inventory_review(rows), Err(error) => { self.integrations.review = None; self.integrations.notice = error; } }
                }
            });
            if let Some(review) = &self.integrations.review {
                ui.label(format!("Prüfung: {} Kandidaten, {} Konflikte ausgeschlossen", review.candidates.len(), review.conflicts));
                ScrollArea::vertical().id_salt("inventory_review").max_height(220.0).show(ui, |ui| {
                    for (index, profile) in review.candidates.iter().enumerate() {
                        ui.checkbox(&mut self.integrations.selected[index], format!("{} · {}:{} · {} · {} · {}", profile.name, profile.host, profile.port, profile.protocol.label(), profile.username, profile.group));
                    }
                });
            }
            if ui.add_enabled(self.store.is_some() && self.integrations.review.is_some(), egui::Button::new("Ausgewählte Profile speichern")).clicked() {
                let review = self.integrations.review.take().unwrap();
                let rows = review.candidates.into_iter().zip(&self.integrations.selected).filter_map(|(p, selected)| selected.then_some(p)).collect();
                let review = integrations::review_inventory(rows, &self.profiles);
                let count = review.candidates.len();
                let mut profiles = self.profiles.clone(); profiles.extend(review.candidates);
                match self.store.as_ref().unwrap().save(&profiles) {
                    Ok(()) => { self.profiles = profiles; self.integrations.notice = format!("{count} Profile gespeichert; {} neue Konflikte übersprungen.", review.conflicts); }
                    Err(_) => self.integrations.notice = "Profile konnten nicht gespeichert werden. Datei erneut prüfen und importieren.".into(),
                }
            }
            ui.separator();
            ui.strong("Dynamische Gruppen");
            ui.label("Lokale Ansichten: Host enthält UND optional exaktes Tag. Keine Änderung der Profilgruppen.");
            ui.horizontal(|ui| {
                ui.label("Name"); ui.text_edit_singleline(&mut self.integrations.rule.name);
                ui.label("Host enthält"); ui.text_edit_singleline(&mut self.integrations.rule.host_contains);
                ui.label("Tag"); ui.text_edit_singleline(&mut self.integrations.rule.tag);
            });
            let mut remove = None;
            for (index, rule) in self.integrations.rules.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.collapsing(&rule.name, |ui| {
                        for profile in self.profiles.iter().filter(|p| rule.matches(p)) { ui.label(format!("{} · {}", profile.name, profile.host)); }
                    });
                    if ui.small_button("Entfernen").clicked() { remove = Some(index); }
                });
            }
            let add = ui.add_enabled(!self.integrations.rule.name.trim().is_empty() && self.integrations.rules.len() < 100, egui::Button::new("Gruppenregel speichern")).clicked();
            if add || remove.is_some() {
                let mut rules = self.integrations.rules.clone();
                if let Some(index) = remove { rules.remove(index); }
                if add { rules.push(self.integrations.rule.clone()); }
                let result = app_data_file("inventory-rules.json").and_then(|path| {
                    let bytes = serde_json::to_vec_pretty(&rules)?;
                    anyhow::ensure!(bytes.len() <= 65536, "Regeln zu groß");
                    std::fs::write(path, bytes)?; Ok(())
                });
                match result {
                    Ok(()) => { self.integrations.rules = rules; self.integrations.rule = GroupRule::default(); self.integrations.notice = "Gruppenregeln gespeichert.".into(); }
                    Err(_) => self.integrations.notice = "Gruppenregeln konnten nicht gespeichert werden.".into(),
                }
            }
            ui.separator();
            ui.strong("Bitwarden → lokaler Credential Store");
            ui.label("Offizielle bw.exe im PATH und extern entsperrtes Vault erforderlich. Aivana muss BW_SESSION erben. Abgerufen wird ausschließlich die angegebene Eintrag-ID; keine Vault-Auflistung. Der nächste Schritt übernimmt Login und Passwort in den lokalen DPAPI-Speicher.");
            ui.add_enabled_ui(self.integrations.vault.is_none(), |ui| {
                ui.horizontal(|ui| { ui.label("Eintrag-ID"); ui.text_edit_singleline(&mut self.integrations.vault_item); });
                let selected = self.profiles.iter().find(|p| Some(p.id) == self.integrations.vault_target);
                egui::ComboBox::from_id_salt("vault_profile").selected_text(selected.map(|p| format!("{} · {}", p.name, p.host)).unwrap_or("Zielprofil wählen".into())).show_ui(ui, |ui| {
                    for profile in &self.profiles {
                        if ui.selectable_value(&mut self.integrations.vault_target, Some(profile.id), format!("{} · {} · {}", profile.name, profile.host, profile.username)).changed() { self.integrations.vault_replace = false; }
                    }
                });
                ui.checkbox(&mut self.integrations.vault_replace, "Login dem gewählten Ziel zuordnen; vorhandene Zugangsdaten ersetzen");
                if ui.add_enabled(self.store.is_some() && self.integrations.vault_target.is_some() && self.integrations.vault_replace, egui::Button::new("Vault-Login abrufen und geschützt speichern")).clicked() {
                    match VaultRequest::start(self.integrations.vault_item.trim()) {
                        Ok(request) => { if let Some(profile)=self.profiles.iter().find(|p|Some(p.id)==self.integrations.vault_target).cloned(){self.integrations.vault = Some((profile, request));} self.integrations.vault_replace = false; self.integrations.notice = "Vault-Abruf läuft …".into(); }
                        Err(error) => self.integrations.notice = error,
                    }
                }
            });
            if self.integrations.vault.is_some() && ui.button("Vault-Abruf abbrechen").clicked() {
                self.integrations.vault = None;
                self.integrations.notice = "Vault-Abruf abgebrochen; Ergebnis wird verworfen.".into();
            }
            ui.separator();
            ui.label(&self.integrations.notice);
        });
    }
}
