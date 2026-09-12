use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{BlackboxSnapshot, FrameUpdate, SessionEvent, SessionEventKind};
use crate::security::redact_secret_text;

pub trait TimelineStore {
    fn append_event(
        &mut self,
        session_id: Uuid,
        workspace_id: Option<Uuid>,
        kind: SessionEventKind,
        message: String,
    );
    fn events_for_session(&self, session_id: Uuid) -> Vec<SessionEvent>;
    fn append_snapshot(&mut self, reason: String, frame: &FrameUpdate);
    fn snapshots_for_session(&self, session_id: Uuid) -> Vec<BlackboxSnapshot>;
    fn export_incident_markdown(&self, session_id: Uuid) -> String;
    fn export_evidence_json(&self, session_id: Uuid) -> String;
}

pub struct InMemoryTimelineStore {
    path: Option<PathBuf>,
    events: HashMap<Uuid, Vec<SessionEvent>>,
    snapshots: HashMap<Uuid, Vec<BlackboxSnapshot>>,
}

impl Default for InMemoryTimelineStore {
    fn default() -> Self {
        Self {
            path: None,
            events: HashMap::new(),
            snapshots: HashMap::new(),
        }
    }
}

impl InMemoryTimelineStore {
    pub fn new() -> Result<Self> {
        Self::at(crate::security::app_data_file("timeline.json")?)
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create timeline store directory")?;
        }
        if !path.exists() {
            return Ok(Self {
                path: Some(path),
                events: HashMap::new(),
                snapshots: HashMap::new(),
            });
        }

        let json = fs::read_to_string(&path).context("read timeline store")?;
        let persisted: PersistedTimelineStore =
            serde_json::from_str(&json).context("parse timeline store")?;
        Ok(Self {
            path: Some(path),
            events: persisted
                .events
                .into_iter()
                .fold(HashMap::new(), |mut acc, event| {
                    acc.entry(event.session_id).or_default().push(event);
                    acc
                }),
            snapshots: persisted
                .snapshots
                .into_iter()
                .fold(HashMap::new(), |mut acc, snapshot| {
                    acc.entry(snapshot.session_id).or_default().push(snapshot);
                    acc
                }),
        })
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = PersistedTimelineStore {
            events: self.events.values().flatten().cloned().collect(),
            snapshots: self.snapshots.values().flatten().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).context("serialize timeline")?;
        fs::write(path, json).context("write timeline store")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedTimelineStore {
    events: Vec<SessionEvent>,
    snapshots: Vec<BlackboxSnapshot>,
}

impl TimelineStore for InMemoryTimelineStore {
    fn append_event(
        &mut self,
        session_id: Uuid,
        workspace_id: Option<Uuid>,
        kind: SessionEventKind,
        message: String,
    ) {
        let redacted_message = redact_secret_text(&message);
        self.events
            .entry(session_id)
            .or_default()
            .push(SessionEvent {
                id: Uuid::new_v4(),
                session_id,
                workspace_id,
                kind,
                redacted: redacted_message != message,
                message: redacted_message,
                created_at: Utc::now(),
            });
        let _ = self.persist();
    }

    fn events_for_session(&self, session_id: Uuid) -> Vec<SessionEvent> {
        self.events.get(&session_id).cloned().unwrap_or_default()
    }

    fn append_snapshot(&mut self, reason: String, frame: &FrameUpdate) {
        self.snapshots
            .entry(frame.session_id)
            .or_default()
            .push(BlackboxSnapshot {
                id: Uuid::new_v4(),
                session_id: frame.session_id,
                reason: redact_secret_text(&reason),
                frame_hash: frame.frame_hash,
                width: frame.width,
                height: frame.height,
                captured_at: Utc::now(),
            });
        let _ = self.persist();
    }

    fn snapshots_for_session(&self, session_id: Uuid) -> Vec<BlackboxSnapshot> {
        self.snapshots.get(&session_id).cloned().unwrap_or_default()
    }

    fn export_incident_markdown(&self, session_id: Uuid) -> String {
        let mut out = format!("# Relayne Incident Report\n\nSession: `{session_id}`\n\n");
        for event in self.events_for_session(session_id) {
            out.push_str(&format!(
                "- {} [{:?}] {}\n",
                event.created_at.format("%Y-%m-%d %H:%M:%S"),
                event.kind,
                event.message
            ));
        }
        let snapshots = self.snapshots_for_session(session_id);
        if !snapshots.is_empty() {
            out.push_str("\n## Blackbox Snapshots\n\n");
            for snapshot in snapshots {
                out.push_str(&format!(
                    "- {} frame={} {}x{} reason={}\n",
                    snapshot.captured_at.format("%Y-%m-%d %H:%M:%S"),
                    snapshot.frame_hash,
                    snapshot.width,
                    snapshot.height,
                    snapshot.reason
                ));
            }
        }
        out
    }

    fn export_evidence_json(&self, session_id: Uuid) -> String {
        serde_json::json!({
            "session_id": session_id,
            "events": self.events_for_session(session_id),
            "snapshots": self.snapshots_for_session(session_id),
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::models::DirtyRegion;

    #[test]
    fn evidence_json_contains_snapshots() {
        let mut store = InMemoryTimelineStore::default();
        let session_id = Uuid::new_v4();
        let frame = FrameUpdate {
            session_id,
            width: 100,
            height: 80,
            pixels_rgba: Vec::new(),
            dirty_regions: vec![DirtyRegion {
                left: 0,
                top: 0,
                right: 10,
                bottom: 10,
            }],
            frame_hash: 7,
            captured_at: Utc::now(),
        };

        store.append_snapshot("password=hidden".to_owned(), &frame);
        let json = store.export_evidence_json(session_id);
        assert!(json.contains("snapshots"));
        assert!(json.contains("[REDACTED]"));
    }
}
