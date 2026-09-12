use super::*;
use crate::incident::{self, Kind, Record};

pub(super) struct IncidentState {
    profile: Option<Uuid>,
    minutes: i64,
    query: String,
    export_status: String,
}
impl Default for IncidentState {
    fn default() -> Self {
        Self {
            profile: None,
            minutes: 30,
            query: String::new(),
            export_status: String::new(),
        }
    }
}
impl AivanaApp {
    fn incident_records(&self) -> Vec<Record> {
        let mut records = incident::telemetry_records(&self.insights.store);
        records.extend(self.change_history_incident_records());
        records.extend(self.workflow_incident_records());
        records.extend(self.execution_incident_records());
        for (session, target) in &self.session_sources {
            for e in self.timeline.events_for_session(*session) {
                records.push(Record {
                    id: format!("session:{}", e.id),
                    profile: Some(target.profile_id),
                    endpoint: Some(incident::endpoint_key(target)),
                    at: e.created_at,
                    kind: match e.kind {
                        SessionEventKind::Error => Kind::Failure,
                        SessionEventKind::UserAction | SessionEventKind::AiAction => Kind::Action,
                        _ => Kind::Observation,
                    },
                    title: format!("{} · {}", target.name, e.message),
                    evidence: vec![e.id.to_string(), session.to_string()],
                });
            }
        }
        incident::normalize(records)
    }
    pub(super) fn incident_view(&mut self, ui: &mut Ui) {
        ui.heading("Störung rekonstruieren");
        ui.label("Sitzungsaktionen, Änderungen, Telemetrie und Prüfresultate in einer gemeinsamen Zeitleiste. Zeitliche Nähe ist kein Kausalitätsnachweis.");
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("incident-profile")
                .selected_text(
                    self.incident
                        .profile
                        .and_then(|id| {
                            self.profiles
                                .iter()
                                .find(|p| p.id == id)
                                .map(|p| p.name.as_str())
                        })
                        .unwrap_or("Alle Rechner"),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.incident.profile, None, "Alle Rechner");
                    for p in &self.profiles {
                        ui.selectable_value(&mut self.incident.profile, Some(p.id), &p.name);
                    }
                });
            ui.label("Suchfenster vor Fehler:");
            ui.add(
                egui::DragValue::new(&mut self.incident.minutes)
                    .range(1..=120)
                    .suffix(" min"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.incident.query)
                    .hint_text("Zeitleiste durchsuchen")
                    .desired_width(220.0),
            );
        });
        let records = self.incident_records();
        let candidates =
            incident::hypotheses(&records, &self.insights.store.edges, self.incident.minutes);
        ui.separator();
        ui.strong(format!(
            "{} belegte Ereignisse · {} zeitliche Zusammenhänge",
            records.len(),
            candidates.len()
        ));
        ui.label("Dienständerungen aus Telemetrie sind nur auf das Intervall zwischen Erfassungen eingrenzbar. Ereignisprotokolle verwenden Rechnerzeiten; abweichende Uhren können die Reihenfolge beeinflussen.");
        if ui
            .button("Metadatenbericht verschlüsselt speichern")
            .clicked()
        {
            let result = (|| -> anyhow::Result<std::path::PathBuf> {
                let path = app_data_file("relayne-incident-report.dpapi")?;
                let bytes = serde_json::to_vec_pretty(
                    &serde_json::json!({"schema":1,"generated":Utc::now(),"note":"Zeitliche Zusammenhänge, keine bestätigten Ursachen", "records":records,"hypotheses":candidates}),
                )?;
                crate::security::atomic_write(&path, &crate::security::protect_secret(&bytes)?)?;
                Ok(path)
            })();
            self.incident.export_status = match result {
                Ok(p) => format!("Gespeichert: {}", p.display()),
                Err(e) => format!("Nicht gespeichert: {e}"),
            };
        }
        ui.label(&self.incident.export_status);
        ui.collapsing("Ursachenhypothesen mit Belegen",|ui|{
            if candidates.is_empty(){ui.label("Keine passende vorangegangene Änderung belegt.");}
            for h in candidates.iter().filter(|h|self.incident.profile.is_none_or(|p|records.iter().any(|r|r.id==h.failure && r.profile==Some(p)))) {
                let change=records.iter().find(|r|r.id==h.change);let failure=records.iter().find(|r|r.id==h.failure);
                if let (Some(c),Some(f))=(change,failure){ui.group(|ui|{ui.label(format!("{} Sekunden zuvor: {}",h.seconds_before,c.title));ui.label(format!("Danach: {}",f.title));ui.label(&h.relationship);ui.label("Nächster Schritt: betroffene Funktion und Abhängigkeit gezielt prüfen; weitere Änderungen als Gegenhypothese vergleichen.");ui.small(format!("Belege: {}",h.evidence.join(" · ")));});}
            }
        });
        let query = self.incident.query.to_lowercase();
        for r in records
            .iter()
            .rev()
            .filter(|r| {
                self.incident.profile.is_none_or(|p| r.profile == Some(p))
                    && r.title.to_lowercase().contains(&query)
            })
            .take(250)
        {
            ui.group(|ui| {
                ui.label(format!(
                    "{} · {:?}",
                    r.at.format("%d.%m.%Y %H:%M:%S UTC"),
                    r.kind
                ));
                ui.label(&r.title);
                ui.small(format!("{} · Belege: {}", r.id, r.evidence.join(" · ")));
            });
        }
        if records.is_empty() {
            ui.label(
                "Noch keine Befunde. Erfasse Telemetrie oder führe einen geprüften Auftrag aus.",
            );
        }
    }
}
