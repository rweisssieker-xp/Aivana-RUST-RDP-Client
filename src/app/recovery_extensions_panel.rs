use super::*;
use crate::{recovery_tickets as tickets, repair_catalog as catalog};
use anyhow::Context as _;
use std::sync::mpsc;
enum RemoteResult {
    Ticket(String, Result<tickets::Ticket, String>),
    Delivery(Uuid, Result<(), String>),
}
pub(super) struct ExtensionsState {
    tickets: tickets::Book,
    catalog: catalog::Catalog,
    error: Option<String>,
    notice: String,
    selected: Option<usize>,
    tab: usize,
    origin: String,
    key: String,
    email: String,
    token: String,
    import_text: String,
    preview: Option<tickets::Ticket>,
    service: String,
    report: Option<(usize, String, String)>,
    confirm: bool,
    pending: Option<mpsc::Receiver<RemoteResult>>,
    contract: Option<Uuid>,
    package: String,
}
impl Default for ExtensionsState {
    fn default() -> Self {
        let mut s = Self {
            tickets: Default::default(),
            catalog: Default::default(),
            error: None,
            notice: String::new(),
            selected: None,
            tab: 0,
            origin: String::new(),
            key: String::new(),
            email: String::new(),
            token: String::new(),
            import_text: String::new(),
            preview: None,
            service: String::new(),
            report: None,
            confirm: false,
            pending: None,
            contract: None,
            package: String::new(),
        };
        s.reload();
        s
    }
}
impl ExtensionsState {
    fn reload(&mut self) {
        let result = (|| -> anyhow::Result<()> {
            self.tickets = tickets::Book::load(&app_data_file("recovery-tickets.dpapi")?)?;
            self.catalog = catalog::Catalog::load(&app_data_file("repair-catalog.dpapi")?)?;
            Ok(())
        })();
        self.error = result.err().map(|e| e.to_string());
        self.report = None;
        self.confirm = false;
    }
    fn save_tickets(&mut self) -> anyhow::Result<()> {
        let result = app_data_file("recovery-tickets.dpapi").and_then(|p| self.tickets.save(&p));
        if let Err(e) = &result {
            self.error = Some(e.to_string());
        }
        result
    }
}
fn ticket_binding(ticket: &tickets::Ticket) -> String {
    serde_json::to_string(ticket).unwrap_or_default()
}
impl AivanaApp {
    pub(super) fn recovery_extensions_view(&mut self, ui: &mut Ui) {
        let event = self
            .recovery_extensions
            .pending
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(r) => Some(r),
                Err(mpsc::TryRecvError::Disconnected) => Some(RemoteResult::Ticket(
                    String::new(),
                    Err("Adapter beendet; Zustelljournal prüfen".into()),
                )),
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(event) = event {
            self.recovery_extensions.pending = None;
            match event {
                RemoteResult::Ticket(binding, result) => {
                    if binding
                        == format!(
                            "{}|{}",
                            self.recovery_extensions.origin, self.recovery_extensions.key
                        )
                    {
                        match result {
                            Ok(ticket) => self.recovery_extensions.preview = Some(ticket),
                            Err(e) => self.recovery_extensions.notice = e,
                        }
                    } else {
                        self.recovery_extensions.notice="Adapterantwort verworfen; Auswahl geändert. Ein eventuell offener Versand bleibt gesperrt.".into();
                    }
                }
                RemoteResult::Delivery(id, result) => {
                    let ok = result.is_ok();
                    self.recovery_extensions.notice = result
                        .map(|_| "Bericht als Jira-Kommentar zugestellt.".into())
                        .unwrap_or_else(|e| e);
                    if self.recovery_extensions.tickets.finish(id, ok).is_ok() {
                        let _ = self.recovery_extensions.save_tickets();
                    }
                    self.recovery_extensions.report = None;
                    self.recovery_extensions.confirm = false;
                }
            }
        }
        ui.heading("Recovery-Anbindungen");
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut self.recovery_extensions.tab,
                0,
                "Tickets & Ergebnisberichte",
            );
            ui.selectable_value(
                &mut self.recovery_extensions.tab,
                1,
                "Kompatibilitätskatalog",
            );
            if ui
                .add_enabled(
                    self.recovery_extensions.pending.is_none(),
                    egui::Button::new("Speicher neu laden"),
                )
                .clicked()
            {
                self.recovery_extensions.reload();
            }
        });
        if let Some(error) = &self.recovery_extensions.error {
            ui.colored_label(tw::RED_600, error);
        }
        ui.add_enabled_ui(
            self.recovery_extensions.error.is_none() && self.recovery_extensions.pending.is_none(),
            |ui| {
                if self.recovery_extensions.tab == 0 {
                    self.ticket_view(ui)
                } else {
                    self.catalog_view(ui)
                }
            },
        );
        ui.separator();
        ui.label(&self.recovery_extensions.notice);
        if self.recovery_extensions.pending.is_some() {
            ui.spinner();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
    fn ticket_view(&mut self, ui: &mut Ui) {
        let s = &mut self.recovery_extensions;
        ui.label("Ticket lesen → Inhalt prüfen → Recovery-Fall zuordnen → Ergebnisbericht prüfen und separat zustellen.");
        ui.collapsing("Jira-Verbindung (API v3)",|ui|{
            ui.label("HTTPS-Ursprung, z. B. https://team.atlassian.net");ui.text_edit_singleline(&mut s.origin);
            ui.horizontal_wrapped(|ui|{ui.label("Ticket");ui.text_edit_singleline(&mut s.key);ui.label("E-Mail");ui.text_edit_singleline(&mut s.email);});
            ui.add(egui::TextEdit::singleline(&mut s.token).password(true).hint_text("API-Token, nur Arbeitsspeicher").char_limit(8192));
            if ui.button("Dieses Ticket jetzt aus Jira lesen").clicked(){
                match tickets::jira_origin(&s.origin){Ok(origin)=>{s.origin=origin;let binding=format!("{}|{}",s.origin,s.key);let key=s.key.clone();let origin=s.origin.clone();let email=s.email.clone();let token=std::mem::take(&mut s.token);let(tx,rx)=mpsc::channel();s.pending=Some(rx);s.preview=None;std::thread::spawn(move||{let result=tickets::fetch(&origin,&key,&email,&token).map_err(|e|e.to_string());let _=tx.send(RemoteResult::Ticket(binding,result));});},Err(e)=>s.notice=e.to_string()}
            }
            ui.small("Lesen sendet die Ticketkennung an diesen Jira-Ursprung. Kein automatischer Import, keine Reparatur. Token nach jeder Anfrage erneut eingeben.");
        });
        ui.collapsing("Ticket als JSON importieren",|ui|{
            ui.small(r#"Schema: {"origin":"local","key":"SUPPORT-1","title":"Störung","description":"Beschreibung","revision":"1"}"#);
            ui.add(egui::TextEdit::multiline(&mut s.import_text).desired_rows(3).desired_width(720.0).char_limit(8192));
            if ui.button("Importvorschau prüfen").clicked(){match tickets::parse_import(&s.import_text){Ok(t)=>s.preview=Some(t),Err(e)=>s.notice=e.to_string()}}
        });
        if let Some(preview) = s.preview.clone() {
            ui.group(|ui|{ui.strong(format!("{} · {}",preview.key,preview.title));ui.label(&preview.origin);ui.label(&preview.description);ui.small("Ungeprüfter externer Inhalt. Aktualisierte Tickets verlieren ihre bisherige Fallzuordnung.");if ui.button("Geprüftes Ticket lokal übernehmen").clicked(){match s.tickets.import(preview).and_then(|i|{s.save_tickets()?;Ok(i)}){Ok(i)=>{s.selected=Some(i);s.preview=None;s.report=None;s.confirm=false;},Err(e)=>s.notice=e.to_string()}}});
        }
        egui::ComboBox::from_id_salt("recovery_ticket_select")
            .selected_text(
                s.selected
                    .and_then(|i| s.tickets.records.get(i))
                    .map(|r| r.ticket.key.as_str())
                    .unwrap_or("Ticket wählen"),
            )
            .show_ui(ui, |ui| {
                for (i, r) in s.tickets.records.iter().enumerate() {
                    if ui
                        .selectable_value(
                            &mut s.selected,
                            Some(i),
                            format!("{} · {}", r.ticket.key, r.ticket.origin),
                        )
                        .changed()
                    {
                        s.report = None;
                        s.confirm = false;
                    }
                }
            });
        let Some(index) = s.selected else { return };
        let Some(record) = s.tickets.records.get(index).cloned() else {
            return;
        };
        ui.strong(&record.ticket.title);
        ui.label(&record.ticket.description);
        let mut create = None;
        let mut make_report = None;
        if record.case.is_none() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Geprüfter Windows-Dienst");
                ui.text_edit_singleline(&mut s.service);
            });
            if ui.button("Neuen Recovery-Fall vorbereiten").clicked() {
                create = Some((record.ticket.objective(), s.service.clone()));
            }
        } else {
            ui.small(format!("Zugeordneter Fall: {}", record.case.unwrap()));
            if ui.button("Aktuellen Ergebnisbericht erstellen").clicked() {
                make_report = record.case;
            }
        }
        for d in &record.deliveries {
            ui.small(format!("Zustellung {} · {} · {}", d.id, d.state, d.at));
            if matches!(d.state.as_str(), "sending" | "unknown") {
                ui.small("Vor einer Freigabe die Zustell-ID direkt im Jira-Ticket prüfen. Nach zwei Minuten kann das Ergebnis hier dokumentiert werden.");
                let mut resolved = None;
                ui.add_enabled_ui(Utc::now() >= d.at + chrono::Duration::minutes(2), |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("In Jira geprüft: zugestellt").clicked() {
                            resolved = Some(true);
                        }
                        if ui.button("In Jira geprüft: nicht zugestellt").clicked() {
                            resolved = Some(false);
                        }
                    });
                });
                if let Some(delivered) = resolved {
                    let result = s
                        .tickets
                        .resolve_delivery(d.id, delivered, Utc::now())
                        .and_then(|_| s.save_tickets());
                    s.notice = result
                        .map(|_| "Manuelle Zustellprüfung dokumentiert.".into())
                        .unwrap_or_else(|e| e.to_string());
                }
            }
        }
        if let Some((objective, service)) = create {
            let result = objective
                .and_then(|o| self.import_ticket_case(&ticket_binding(&record.ticket), o, service));
            match result {
                Ok(id) => {
                    self.recovery_extensions.tickets.records[index].case = Some(id);
                    let result = self.recovery_extensions.save_tickets();
                    self.recovery_extensions.notice = result
                        .map(|_| {
                            "Recovery-Fall vorbereitet. Generalprobe im Recovery Agent öffnen."
                                .into()
                        })
                        .unwrap_or_else(|e| e.to_string());
                }
                Err(e) => self.recovery_extensions.notice = e.to_string(),
            }
        }
        if let Some(id) = make_report {
            match self.recovery_ticket_report(id) {
                Ok(text) => {
                    self.recovery_extensions.report =
                        Some((index, ticket_binding(&record.ticket), text));
                    self.recovery_extensions.confirm = false;
                }
                Err(e) => self.recovery_extensions.notice = e.to_string(),
            }
        }
        if let Some((i, binding, report)) = self.recovery_extensions.report.clone() {
            if i != index || binding != ticket_binding(&record.ticket) {
                self.recovery_extensions.report = None;
                self.recovery_extensions.confirm = false;
                return;
            }
            ui.separator();
            ui.strong("Vorschau des Ergebnisberichts");
            ui.label(&report);
            if ui.button("Bericht kopieren").clicked() {
                ui.ctx().copy_text(report.clone());
            }
            if record.ticket.origin != "local" {
                ui.checkbox(
                    &mut self.recovery_extensions.confirm,
                    format!(
                        "Diesen Bericht als Kommentar an {} / {} senden",
                        record.ticket.origin, record.ticket.key
                    ),
                );
                if ui
                    .add_enabled(
                        self.recovery_extensions.confirm
                            && !self.recovery_extensions.token.is_empty(),
                        egui::Button::new("Geprüften Bericht jetzt an Jira senden"),
                    )
                    .clicked()
                {
                    let result = (|| -> anyhow::Result<Uuid> {
                        anyhow::ensure!(
                            self.recovery_extensions.origin == record.ticket.origin,
                            "Jira-Verbindung stimmt nicht mit Ticket-Ursprung überein"
                        );
                        let current =
                            self.recovery_ticket_report(record.case.context("Fall fehlt")?)?;
                        anyhow::ensure!(
                            current == report,
                            "Ergebnis geändert; neue Berichtsvorschau erstellen"
                        );
                        let id = self.recovery_extensions.tickets.reserve(index, &report)?;
                        self.recovery_extensions.save_tickets()?;
                        Ok(id)
                    })();
                    match result {
                        Ok(id) => {
                            let email = self.recovery_extensions.email.clone();
                            let token = std::mem::take(&mut self.recovery_extensions.token);
                            let (tx, rx) = mpsc::channel();
                            self.recovery_extensions.pending = Some(rx);
                            self.recovery_extensions.confirm = false;
                            std::thread::spawn(move || {
                                let result = tickets::post_report(
                                    &record.ticket,
                                    &email,
                                    &token,
                                    &report,
                                    id,
                                )
                                .map_err(|e| e.to_string());
                                let _ = tx.send(RemoteResult::Delivery(id, result));
                            });
                        }
                        Err(e) => self.recovery_extensions.notice = e.to_string(),
                    }
                }
                ui.small("Bei unterbrochener oder ungeklärter Zustellung wird nicht automatisch erneut gesendet. Jira anhand der Zustell-ID prüfen.");
            }
        }
    }
    fn catalog_view(&mut self, ui: &mut Ui) {
        let result = app_data_file("relayne-recovery-contracts.dpapi")
            .and_then(|p| crate::recovery_contracts::Book::load(&p));
        let contracts = match result {
            Ok(b) => b,
            Err(e) => {
                ui.label(e.to_string());
                return;
            }
        };
        let trust = match crate::package_trust::TrustStore::load() {
            Ok(t) => t,
            Err(e) => {
                ui.label(e.to_string());
                return;
            }
        };
        ui.label("Signierte Reparaturpakete mit tatsächlich geprobten Dienst-/HTTP-Plänen und Umgebungsfingerprints verbinden.");
        ui.small("Lokaler kuratierter Katalog. Kompatibilität ist keine Produktionsfreigabe; jede Übernahme führt in eine neue Generalprobe.");
        let s = &mut self.recovery_extensions;
        egui::ComboBox::from_id_salt("catalog_contract")
            .selected_text(
                s.contract
                    .and_then(|id| contracts.contracts.iter().find(|c| c.id == id))
                    .map(|c| c.name.as_str())
                    .unwrap_or("Geprobten Plan wählen"),
            )
            .show_ui(ui, |ui| {
                for c in &contracts.contracts {
                    ui.selectable_value(&mut s.contract, Some(c.id), &c.name);
                }
            });
        if let Some(contract) = s
            .contract
            .and_then(|id| contracts.contracts.iter().find(|c| c.id == id))
        {
            if ui
                .button("Passendes Paket erzeugen und mit lokalem Herausgeberschlüssel signieren")
                .clicked()
            {
                match catalog::candidate(contract).and_then(|p| crate::package_trust::sign(&p)) {
                    Ok(text) => s.package = text,
                    Err(e) => s.notice = e.to_string(),
                }
            }
            ui.small("Herausgeberschlüssel und Vertrauen werden im Bereich Workflows verwaltet.");
            ui.add(
                egui::TextEdit::multiline(&mut s.package)
                    .desired_rows(4)
                    .desired_width(720.0)
                    .char_limit(524288),
            );
            if ui
                .button("Signatur und frische Belege prüfen; in Katalog aufnehmen")
                .clicked()
            {
                let result =
                    catalog::Entry::create(s.package.clone(), contract, &trust).and_then(|entry| {
                        anyhow::ensure!(
                            !s.catalog
                                .entries
                                .iter()
                                .any(|e| e.signed_package == entry.signed_package
                                    && e.contract == entry.contract),
                            "Paket bereits im Katalog"
                        );
                        let mut next = s.catalog.clone();
                        next.entries.push(entry);
                        next.save(&app_data_file("repair-catalog.dpapi")?)?;
                        s.catalog = next;
                        Ok(())
                    });
                s.notice = result
                    .map(|_| "Paket mit tatsächlichem Generalprobenbeleg registriert.".into())
                    .unwrap_or_else(|e| e.to_string());
            }
        }
        let mut prepare = None;
        for entry in &s.catalog.entries {
            let contract = contracts.contracts.iter().find(|c| c.id == entry.contract);
            let status = entry.compatibility(contract, &trust);
            ui.group(|ui| {
                let name = trust
                    .verify(&entry.signed_package)
                    .map(|p| p.plan.name)
                    .unwrap_or_else(|_| "Signatur nicht mehr vertraut".into());
                ui.strong(name);
                ui.label(match status {
                    catalog::Compatibility::Verified => {
                        "Umgebung stimmt mit geprobtem Paket überein"
                    }
                    catalog::Compatibility::Changed => {
                        "Nicht kompatibel: Plan oder Umgebung geändert"
                    }
                    catalog::Compatibility::Unknown => {
                        "Unbekannt: Nachweis abgelaufen, Plan fehlt oder Vertrauen widerrufen"
                    }
                });
                ui.small(format!(
                    "Belegaufnahme {} · Plan {}",
                    entry.recorded_at, entry.plan_hash
                ));
                if ui.button("Signiertes Paket kopieren").clicked() {
                    ui.ctx().copy_text(entry.signed_package.clone());
                }
                if ui
                    .add_enabled(
                        status == catalog::Compatibility::Verified,
                        egui::Button::new("Als neue Generalprobe vorbereiten"),
                    )
                    .clicked()
                {
                    prepare = contract.map(|c| c.plan.clone());
                }
            });
        }
        if let Some(plan) = prepare {
            match self.prepare_contract_rehearsal(&plan) {
                Ok(()) => self.view = View::Promotion,
                Err(e) => self.recovery_extensions.notice = e.to_string(),
            }
        }
    }
}
