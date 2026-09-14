use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{HostMemory, WorkspaceMemory};
use crate::security::{app_data_file, redact_secret_text};

pub struct MemoryStore {
    path: Option<PathBuf>,
    hosts: HashMap<String, HostMemory>,
    workspaces: HashMap<Uuid, WorkspaceMemory>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            path: None,
            hosts: HashMap::new(),
            workspaces: HashMap::new(),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Result<Self> {
        Self::at(app_data_file("memory.json")?)
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create memory store directory")?;
        }
        if !path.exists() {
            return Ok(Self {
                path: Some(path),
                hosts: HashMap::new(),
                workspaces: HashMap::new(),
            });
        }

        let json = fs::read_to_string(&path).context("read memory store")?;
        let persisted: PersistedMemoryStore =
            serde_json::from_str(&json).context("parse memory store")?;
        Ok(Self {
            path: Some(path),
            hosts: persisted
                .hosts
                .into_iter()
                .map(|memory| (memory.host.to_lowercase(), memory))
                .collect(),
            workspaces: persisted
                .workspaces
                .into_iter()
                .map(|memory| (memory.workspace_id, memory))
                .collect(),
        })
    }

    pub fn record_known_issue(&mut self, host: &str, workspace_id: Option<Uuid>, issue: &str) {
        self.host_memory_mut(host, workspace_id)
            .known_issues
            .push(redact_secret_text(issue));
        let _ = self.persist();
    }

    pub fn record_successful_fix(&mut self, host: &str, workspace_id: Option<Uuid>, fix: &str) {
        self.host_memory_mut(host, workspace_id)
            .successful_fixes
            .push(redact_secret_text(fix));
        let _ = self.persist();
    }

    pub fn record_runbook_result(&mut self, host: &str, workspace_id: Option<Uuid>, result: &str) {
        self.host_memory_mut(host, workspace_id)
            .runbook_results
            .push(redact_secret_text(result));
        let _ = self.persist();
    }

    pub fn host_memory(&self, host: &str) -> Option<HostMemory> {
        self.hosts.get(&host.to_lowercase()).cloned()
    }

    pub fn recommended_next_step(&self, host: &str) -> String {
        match self.host_memory(host) {
            Some(memory) if !memory.successful_fixes.is_empty() => {
                format!(
                    "Review the last successful fix: {}",
                    memory.successful_fixes.last().unwrap()
                )
            }
            Some(memory) if !memory.known_issues.is_empty() => {
                format!(
                    "Review the known issue: {}",
                    memory.known_issues.last().unwrap()
                )
            }
            _ => "Start Evidence Mode and collect safe diagnostic evidence.".to_owned(),
        }
    }

    pub fn workspace_memory_mut(&mut self, workspace_id: Uuid) -> &mut WorkspaceMemory {
        self.workspaces
            .entry(workspace_id)
            .or_insert_with(|| WorkspaceMemory {
                workspace_id,
                notes: Vec::new(),
                updated_at: Utc::now(),
            })
    }

    pub fn record_workspace_note(&mut self, workspace_id: Uuid, note: &str) {
        let memory = self.workspace_memory_mut(workspace_id);
        memory.notes.push(redact_secret_text(note));
        memory.updated_at = Utc::now();
        let _ = self.persist();
    }

    pub fn workspace_note_count(&self, workspace_id: Uuid) -> usize {
        self.workspaces
            .get(&workspace_id)
            .map(|memory| memory.notes.len())
            .unwrap_or(0)
    }

    fn host_memory_mut(&mut self, host: &str, workspace_id: Option<Uuid>) -> &mut HostMemory {
        let now = Utc::now();
        self.hosts
            .entry(host.to_lowercase())
            .or_insert_with(|| HostMemory {
                id: Uuid::new_v4(),
                host: host.to_owned(),
                workspace_id,
                known_issues: Vec::new(),
                successful_fixes: Vec::new(),
                certificate_changes: Vec::new(),
                login_notes: Vec::new(),
                disconnect_patterns: Vec::new(),
                maintenance_notes: Vec::new(),
                runbook_results: Vec::new(),
                updated_at: now,
            })
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = PersistedMemoryStore {
            hosts: self.hosts.values().cloned().collect(),
            workspaces: self.workspaces.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).context("serialize memory store")?;
        fs::write(path, json).context("write memory store")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedMemoryStore {
    hosts: Vec<HostMemory>,
    workspaces: Vec<WorkspaceMemory>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_redacts_secrets() {
        let mut store = MemoryStore::default();
        store.record_known_issue("host", None, "password=secret failed");
        let memory = store.host_memory("host").unwrap();
        assert_eq!(memory.known_issues[0], "password=[REDACTED] failed");
    }

    #[test]
    fn memory_persists() {
        let path = std::env::temp_dir().join(format!("aivana-memory-{}.json", Uuid::new_v4()));
        let mut store = MemoryStore::at(path.clone()).unwrap();
        store.record_successful_fix("host", None, "restarted service");
        let reloaded = MemoryStore::at(path.clone()).unwrap();
        assert!(
            reloaded
                .recommended_next_step("host")
                .contains("restarted service")
        );
        let _ = fs::remove_file(path);
    }
}
