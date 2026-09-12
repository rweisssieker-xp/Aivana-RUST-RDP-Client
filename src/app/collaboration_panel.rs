use super::*;
use crate::team_client::TeamClient;
use crate::team_server::collaboration_session::{Command, Proposal, Reply, Room};
use std::sync::mpsc;
#[derive(Default)]
pub(super) struct CollaborationState {
    room: Option<Room>,
    join: String,
    members: String,
    target: String,
    note: String,
    pending: Option<mpsc::Receiver<Result<Reply, String>>>,
    pending_command: Option<Command>,
    consent: Option<Uuid>,
    message: String,
    texture: Option<egui::TextureHandle>,
    last_poll: Option<std::time::Instant>,
}
impl CollaborationState {
    fn send(&mut self, client: TeamClient, command: Command) {
        if self.pending.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.pending_command = Some(command.clone());
        std::thread::spawn(move || {
            let _ = tx.send(client.collaborate(&command).map_err(|e| e.to_string()));
        });
    }
}
impl AivanaApp {
    pub(super) fn collaboration_view(&mut self, ui: &mut Ui) {
        ui.separator();
        ui.heading("Live Co-Working");
        ui.label("Explizite Bildfreigabe · maskierte Live-Bilder · Klicks und Einzeltasten nach zwei Identitäten und lokaler Prüfung");
        let client = match TeamClient::new(&self.team.endpoint, &self.team.token) {
            Ok(c) => c,
            Err(_) => return,
        };
        let actor = self
            .team
            .snapshot
            .as_ref()
            .map(|s| s.actor.clone())
            .unwrap_or_default();
        let result = self
            .team
            .live
            .pending
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(r) => Some(r),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("Verbindung abgebrochen".into())),
                Err(_) => None,
            });
        let mut execute: Option<Proposal> = None;
        if let Some(result) = result {
            self.team.live.pending = None;
            let request = self.team.live.pending_command.take();
            match result {
                Ok(reply) => {
                    let binding_valid = match (&request, &reply.room) {
                        (Some(Command::Create { session, .. }), Some(r)) => {
                            r.session == *session && r.owner == actor
                        }
                        (Some(Command::Create { .. }), None) => false,
                        (Some(command), Some(r)) => match command {
                            Command::Create { .. } => false,
                            Command::Poll { room }
                            | Command::Close { room }
                            | Command::Leave { room }
                            | Command::Publish { room, .. }
                            | Command::Annotate { room, .. }
                            | Command::Grant { room, .. }
                            | Command::Revoke { room }
                            | Command::Propose { room, .. }
                            | Command::Approve { room, .. }
                            | Command::Consume { room, .. } => *room == r.id,
                        },
                        (Some(Command::Close { .. } | Command::Leave { .. }), None) => true,
                        _ => false,
                    };
                    let frame_valid = reply
                        .room
                        .as_ref()
                        .and_then(|r| r.frame.as_ref())
                        .is_none_or(|f| {
                            f.width > 0
                                && f.width <= 640
                                && f.height > 0
                                && f.height <= 360
                                && f.rgb.len() == usize::from(f.width) * usize::from(f.height) * 3
                        });
                    if !binding_valid || !frame_valid {
                        self.team.live = Default::default();
                        self.team.live.message = "Ungültige Bildantwort".into();
                        return;
                    }
                    if let (Some(Command::Consume { room, id, digest }), Some(p), Some(r)) =
                        (&request, &reply.execute, &reply.room)
                    {
                        if r.id == *room
                            && p.id == *id
                            && p.digest == *digest
                            && p.session == r.session
                            && p.generation == r.generation
                            && r.owner == actor
                            && self.team.live.consent == Some(r.session)
                            && self.selected_session == Some(r.session)
                            && r.expires > chrono::Utc::now().timestamp()
                            && r.lease.as_ref().is_some_and(|l| {
                                l.generation == p.generation
                                    && l.expires > chrono::Utc::now().timestamp()
                            })
                        {
                            execute = Some(p.clone());
                        }
                    }
                    self.team.live.room = reply.room;
                    self.team.live.texture = None;
                    self.team.live.message.clear();
                    if let Some(frame) = self.team.live.room.as_ref().and_then(|r| r.frame.as_ref())
                    {
                        let image = egui::ColorImage::from_rgb(
                            [frame.width as usize, frame.height as usize],
                            &frame.rgb,
                        );
                        self.team.live.texture = Some(ui.ctx().load_texture(
                            "live-collaboration",
                            image,
                            egui::TextureOptions::LINEAR,
                        ));
                    }
                }
                Err(e) => {
                    self.team.live.message = e;
                    self.team.live.consent = None;
                    self.team.live.room = None;
                    self.team.live.texture = None;
                }
            }
        }
        if let Some(p) = execute {
            self.execute_collaboration_click(p);
        }
        ui.label(&self.team.live.message);
        let busy = self.team.live.pending.is_some();
        if let Some(room) = self.team.live.room.clone() {
            let owner = room.owner == actor;
            let consenting_owner = owner
                && self.team.live.consent == Some(room.session)
                && self.selected_session == Some(room.session);
            ui.label(format!(
                "Raum {} · Host {} · Generation {}",
                room.id, room.owner, room.generation
            ));
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new("Raum verlassen / Freigabe beenden"),
                    )
                    .clicked()
                {
                    self.team.live.consent = None;
                    self.team
                        .live
                        .send(client.clone(), Command::Leave { room: room.id });
                }
                if owner
                    && ui
                        .add_enabled(!busy, egui::Button::new("Steuerung sofort widerrufen"))
                        .clicked()
                {
                    self.team
                        .live
                        .send(client.clone(), Command::Revoke { room: room.id });
                }
            });
            if consenting_owner {
                ui.horizontal(|ui| {
                    ui.label("Steuerung an Mitglied (20 s)");
                    ui.text_edit_singleline(&mut self.team.live.target);
                    if ui
                        .add_enabled(!busy, egui::Button::new("Übergeben"))
                        .clicked()
                    {
                        self.team.live.send(
                            client.clone(),
                            Command::Grant {
                                room: room.id,
                                actor: self.team.live.target.trim().into(),
                            },
                        );
                    }
                });
            }
            if let Some(lease) = &room.lease {
                ui.label(format!(
                    "Exklusive Steuerung: {} · Ablauf {}",
                    lease.actor, lease.expires
                ));
            }
            ui.horizontal(|ui| {
                ui.label("Annotation (Bild anklicken)");
                ui.text_edit_singleline(&mut self.team.live.note);
            });
            if let Some(texture) = &self.team.live.texture {
                let response = ui.add(
                    egui::Image::new(texture)
                        .max_width(640.0)
                        .sense(egui::Sense::click()),
                );
                for mark in &room.annotations {
                    let pos = response.rect.min
                        + egui::vec2(
                            response.rect.width() * mark.x as f32 / 10000.0,
                            response.rect.height() * mark.y as f32 / 10000.0,
                        );
                    ui.painter().circle_stroke(
                        pos,
                        7.0,
                        egui::Stroke::new(2.0, egui::Color32::YELLOW),
                    );
                    ui.painter().text(
                        pos,
                        egui::Align2::LEFT_BOTTOM,
                        &mark.text,
                        egui::FontId::proportional(13.0),
                        egui::Color32::YELLOW,
                    );
                }
                if !busy && response.clicked() {
                    if let Some(pos) = response.interact_pointer_pos() {
                        let x = ((pos.x - response.rect.left()) / response.rect.width() * 10000.0)
                            .clamp(0.0, 10000.0) as u16;
                        let y = ((pos.y - response.rect.top()) / response.rect.height() * 10000.0)
                            .clamp(0.0, 10000.0) as u16;
                        let command = if self.team.live.note.trim().is_empty() {
                            room.lease
                                .as_ref()
                                .filter(|l| l.actor == actor)
                                .and_then(|l| {
                                    room.frame.as_ref().map(|f| Command::Propose {
                                        key: None,
                                        room: room.id,
                                        generation: l.generation,
                                        frame_hash: f.source_hash,
                                        x,
                                        y,
                                    })
                                })
                        } else {
                            Some(Command::Annotate {
                                room: room.id,
                                x,
                                y,
                                text: self.team.live.note.clone(),
                            })
                        };
                        if let Some(c) = command {
                            self.team.live.send(client.clone(), c);
                        }
                    }
                }
            }
            ui.label(
                "Bildklicks und einzelne Tasten benötigen zwei Identitäten und lokale Ausführung.",
            );
            ui.horizontal_wrapped(|ui| {
                use crate::team_server::collaboration_session::SharedKey;
                for key in [
                    SharedKey::Enter,
                    SharedKey::Tab,
                    SharedKey::Escape,
                    SharedKey::Up,
                    SharedKey::Down,
                    SharedKey::Left,
                    SharedKey::Right,
                    SharedKey::Home,
                    SharedKey::End,
                    SharedKey::PageUp,
                    SharedKey::PageDown,
                    SharedKey::F5,
                ] {
                    if ui
                        .add_enabled(
                            !busy
                                && room.lease.as_ref().is_some_and(|l| l.actor == actor)
                                && room.frame.is_some(),
                            egui::Button::new(format!("{key:?}")),
                        )
                        .clicked()
                    {
                        if let (Some(lease), Some(frame)) = (&room.lease, &room.frame) {
                            self.team.live.send(
                                client.clone(),
                                Command::Propose {
                                    room: room.id,
                                    generation: lease.generation,
                                    frame_hash: frame.source_hash,
                                    x: 0,
                                    y: 0,
                                    key: Some(key),
                                },
                            );
                        }
                    }
                }
            });
            for p in &room.proposals {
                if p.consumed {
                    continue;
                }
                ui.label(format!(
                    "{} · Sitzung {} · Freigaben {:?}",
                    p.key
                        .map(|k| format!("Taste {k:?}"))
                        .unwrap_or_else(|| format!("Klick ({},{})", p.x, p.y)),
                    p.session,
                    p.approvals
                ));
                ui.small(format!("SHA-256 {}", p.digest));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !busy && !p.approvals.contains(&actor),
                            egui::Button::new("Diesen unveränderlichen Antrag genehmigen"),
                        )
                        .clicked()
                    {
                        self.team.live.send(
                            client.clone(),
                            Command::Approve {
                                room: room.id,
                                id: p.id,
                                digest: p.digest.clone(),
                            },
                        );
                    }
                    if consenting_owner
                        && ui
                            .add_enabled(
                                !busy && p.approvals.len() >= 2,
                                egui::Button::new("Lokal prüfen und einmal ausführen"),
                            )
                            .clicked()
                    {
                        self.team.live.send(
                            client.clone(),
                            Command::Consume {
                                room: room.id,
                                id: p.id,
                                digest: p.digest.clone(),
                            },
                        );
                    }
                });
            }
            if self.team.live.pending.is_none()
                && self
                    .team
                    .live
                    .last_poll
                    .is_none_or(|t| t.elapsed() >= std::time::Duration::from_millis(200))
            {
                self.team.live.last_poll = Some(std::time::Instant::now());
                let command = if owner && self.team.live.consent.is_some() {
                    if !consenting_owner {
                        self.team.live.consent = None;
                        Command::Close { room: room.id }
                    } else {
                        match self.collaboration_frame() {
                            Some((session, frame)) if session == room.session => Command::Publish {
                                room: room.id,
                                frame,
                            },
                            _ => {
                                self.team.live.consent = None;
                                Command::Close { room: room.id }
                            }
                        }
                    }
                } else {
                    Command::Poll { room: room.id }
                };
                self.team.live.send(client, command);
            }
        } else {
            ui.horizontal(|ui| {
                ui.label("Mitglieder: exakte Akteurnamen, durch Komma getrennt");
                ui.text_edit_singleline(&mut self.team.live.members);
            });
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new("Ausgewählte RDP-Sitzung maskiert live freigeben"),
                )
                .clicked()
            {
                if let Some((session, _)) = self.collaboration_frame() {
                    self.team.live.consent = Some(session);
                    let members = self
                        .team
                        .live
                        .members
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                    self.team
                        .live
                        .send(client.clone(), Command::Create { session, members });
                } else {
                    self.team.live.message =
                        "Keine verbundene RDP-Sitzung mit sicher maskierbarem Bild verfügbar"
                            .into();
                }
            }
            ui.horizontal(|ui| {
                ui.label("Raum-ID");
                ui.text_edit_singleline(&mut self.team.live.join);
                if ui
                    .add_enabled(!busy, egui::Button::new("Beitreten"))
                    .clicked()
                {
                    match Uuid::parse_str(self.team.live.join.trim()) {
                        Ok(room) => {
                            self.team.live.consent = None;
                            self.team.live.send(client, Command::Poll { room })
                        }
                        Err(_) => self.team.live.message = "Ungültige Raum-ID".into(),
                    }
                }
            });
        }
        if self.team.live.room.is_some() || self.team.live.pending.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}
