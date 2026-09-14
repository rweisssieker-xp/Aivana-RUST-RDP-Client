use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::models::{
    InputAction, RiskLevel, Runbook, RunbookCategory, RunbookExecution, RunbookRecommendation,
    RunbookStatus, RunbookStep,
};

#[derive(Default)]
pub struct RunbookEngine {
    runbooks: Vec<Runbook>,
    executions: HashMap<Uuid, RunbookExecution>,
}

impl RunbookEngine {
    pub fn with_defaults() -> Self {
        Self {
            runbooks: default_runbooks(),
            executions: HashMap::new(),
        }
    }

    pub fn list_runbooks(&self) -> &[Runbook] {
        &self.runbooks
    }

    pub fn recommend(&self, context: &str) -> Option<RunbookRecommendation> {
        let lower = context.to_lowercase();
        self.runbooks
            .iter()
            .find(|runbook| lower.contains(&runbook.name.to_lowercase()))
            .or_else(|| self.runbooks.first())
            .map(|runbook| RunbookRecommendation {
                runbook_id: runbook.id,
                name: runbook.name.clone(),
                reason: "Local runbook rule matches the current diagnostic context.".to_owned(),
                confidence: 0.74,
            })
    }

    pub fn start(&mut self, session_id: Uuid, runbook_id: Uuid) -> Option<RunbookExecution> {
        self.runbooks.iter().find(|r| r.id == runbook_id)?;
        let execution = RunbookExecution {
            id: Uuid::new_v4(),
            session_id,
            runbook_id,
            current_step: 0,
            status: RunbookStatus::Running,
            started_at: Utc::now(),
        };
        self.executions.insert(execution.id, execution.clone());
        Some(execution)
    }

    pub fn next_step(&mut self, execution_id: Uuid) -> Option<RunbookStep> {
        let execution = self.executions.get_mut(&execution_id)?;
        let runbook = self
            .runbooks
            .iter()
            .find(|r| r.id == execution.runbook_id)?;
        let step = runbook.steps.get(execution.current_step)?.clone();
        if step.requires_approval {
            execution.status = RunbookStatus::WaitingForApproval;
        } else {
            execution.current_step += 1;
            if execution.current_step >= runbook.steps.len() {
                execution.status = RunbookStatus::Completed;
            }
        }
        Some(step)
    }

    pub fn pause(&mut self, execution_id: Uuid) {
        if let Some(execution) = self.executions.get_mut(&execution_id) {
            execution.status = RunbookStatus::Paused;
        }
    }

    pub fn resume(&mut self, execution_id: Uuid) {
        if let Some(execution) = self.executions.get_mut(&execution_id) {
            execution.status = RunbookStatus::Running;
        }
    }

    pub fn abort(&mut self, execution_id: Uuid) {
        if let Some(execution) = self.executions.get_mut(&execution_id) {
            execution.status = RunbookStatus::Aborted;
        }
    }
}

fn default_runbooks() -> Vec<Runbook> {
    [
        ("RDP sign-in hangs", RunbookCategory::Authentication),
        ("DNS/TCP/RDP port diagnostics", RunbookCategory::Connectivity),
        ("NLA/CredSSP issue", RunbookCategory::Authentication),
        (
            "Certificate Changed Investigation",
            RunbookCategory::Certificate,
        ),
        ("Slow Login / Black Screen", RunbookCategory::Performance),
        ("Repeated Disconnects", RunbookCategory::Connectivity),
        ("Event Viewer Evidence Gathering", RunbookCategory::Evidence),
        ("Disk Full Evidence Gathering", RunbookCategory::Evidence),
        ("Service Down Evidence Gathering", RunbookCategory::Services),
    ]
    .into_iter()
    .map(|(name, category)| Runbook {
        id: Uuid::new_v4(),
        name: name.to_owned(),
        category,
        risk: RiskLevel::ReadOnly,
        steps: vec![
            RunbookStep {
                id: Uuid::new_v4(),
                title: "Capture screenshot".to_owned(),
                action: InputAction::Screenshot,
                risk: RiskLevel::ReadOnly,
                requires_approval: false,
            },
            RunbookStep {
                id: Uuid::new_v4(),
                title: "Verify current screen state".to_owned(),
                action: InputAction::Verify {
                    expectation: name.to_owned(),
                },
                risk: RiskLevel::ReadOnly,
                requires_approval: false,
            },
        ],
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runbooks_are_available() {
        let engine = RunbookEngine::with_defaults();
        assert!(engine.list_runbooks().len() >= 9);
    }
}
