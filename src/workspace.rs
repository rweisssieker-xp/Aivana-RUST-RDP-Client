use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::Workspace;
use crate::security::app_data_file;

pub struct WorkspaceStore {
    path: Option<PathBuf>,
    workspaces: HashMap<Uuid, Workspace>,
}

impl Default for WorkspaceStore {
    fn default() -> Self {
        Self {
            path: None,
            workspaces: HashMap::new(),
        }
    }
}

impl WorkspaceStore {
    pub fn new() -> Result<Self> {
        Self::at(app_data_file("workspaces.json")?)
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create workspace store directory")?;
        }
        if !path.exists() {
            return Ok(Self {
                path: Some(path),
                workspaces: HashMap::new(),
            });
        }

        let json = fs::read_to_string(&path).context("read workspace store")?;
        let persisted: PersistedWorkspaceStore =
            serde_json::from_str(&json).context("parse workspace store")?;
        Ok(Self {
            path: Some(path),
            workspaces: persisted
                .workspaces
                .into_iter()
                .map(|workspace| (workspace.id, workspace))
                .collect(),
        })
    }

    pub fn ensure_default(&mut self) -> Uuid {
        if let Some(id) = self.workspaces.keys().next().copied() {
            return id;
        }

        let now = Utc::now();
        let id = Uuid::new_v4();
        self.workspaces.insert(
            id,
            Workspace {
                id,
                name: "Default Workspace".to_owned(),
                notes: "Local-first Relayne workspace".to_owned(),
                created_at: now,
                updated_at: now,
            },
        );
        let _ = self.persist();
        id
    }

    pub fn all(&self) -> Vec<Workspace> {
        self.workspaces.values().cloned().collect()
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = PersistedWorkspaceStore {
            workspaces: self.workspaces.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).context("serialize workspaces")?;
        fs::write(path, json).context("write workspace store")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedWorkspaceStore {
    workspaces: Vec<Workspace>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workspace_persists() {
        let path = std::env::temp_dir().join(format!("aivana-workspaces-{}.json", Uuid::new_v4()));
        let mut store = WorkspaceStore::at(path.clone()).unwrap();
        let id = store.ensure_default();
        let loaded = WorkspaceStore::at(path.clone()).unwrap();
        assert!(loaded.all().iter().any(|workspace| workspace.id == id));
        let _ = fs::remove_file(path);
    }
}
