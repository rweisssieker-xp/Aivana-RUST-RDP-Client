//! Local archive evidence becomes reviewed native RDP checkpoints, never inferred actions.
use crate::{
    models::{ConnectionProfile, Protocol},
    recording::Recording,
    teaching::Procedure,
    workflow::{Action, Plan, Step},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub frame: usize,
    pub at: DateTime<Utc>,
    pub word: String,
}
#[derive(Clone)]
pub struct Derived {
    pub source: Recording,
    pub candidates: Vec<Candidate>,
}
#[derive(Clone)]
pub struct Review {
    binding: String,
    at: DateTime<Utc>,
}

pub fn derive(recording: &Recording) -> Result<Derived> {
    ensure!(
        recording.finished && !recording.id.is_nil() && !recording.profile.is_nil(),
        "Select a finished recording with a target profile"
    );
    ensure!(
        !recording.frames.is_empty() && recording.frames.len() <= 600,
        "Recording has no bounded keyframe evidence"
    );
    let mut seen = BTreeSet::new();
    let mut candidates = vec![];
    let mut previous = recording.created;
    for (frame, key) in recording.frames.iter().enumerate() {
        ensure!(
            key.at >= previous && key.at <= Utc::now(),
            "Recording timestamps are inconsistent"
        );
        previous = key.at;
        ensure!(
            key.ocr.len() <= 32768,
            "Recorded OCR exceeds the import limit"
        );
        let lower = key.ocr.to_ascii_lowercase();
        // A deliberately narrow vocabulary is safer than surfacing arbitrary OCR.
        // Skip whole frames with secret-field hints; notes and image bytes are not used.
        if [
            "password",
            "passwd",
            "secret",
            "token",
            "credential",
            "api_key",
            "authorization",
            "username",
            "passwort",
        ]
        .iter()
        .any(|hint| lower.contains(hint))
        {
            continue;
        }
        for word in key.ocr.split_whitespace() {
            let folded = word.to_ascii_lowercase();
            if [
                "login",
                "welcome",
                "dashboard",
                "ready",
                "success",
                "connected",
                "home",
                "complete",
                "completed",
                "settings",
                "reports",
                "healthy",
            ]
            .contains(&folded.as_str())
                && seen.insert(folded)
            {
                candidates.push(Candidate {
                    frame,
                    at: key.at,
                    word: word.into(),
                });
            }
        }
    }
    ensure!(
        !candidates.is_empty(),
        "No supported nonsecret visible-state words were recorded; no assertions inferred"
    );
    Ok(Derived {
        source: recording.clone(),
        candidates,
    })
}

fn build(
    recording: &Recording,
    profile: &ConnectionProfile,
    chosen: &BTreeSet<usize>,
    procedure: Option<&Procedure>,
) -> Result<Plan> {
    ensure!(
        profile.id == recording.profile
            && profile.protocol == Protocol::Rdp
            && !profile.options.gateway.enabled,
        "Recording requires its exact original direct RDP profile"
    );
    let derived = derive(recording)?;
    ensure!(
        (1..=4).contains(&chosen.len()),
        "Choose one to four observed checkpoints"
    );
    let mut checks = vec![];
    for index in chosen {
        let candidate = derived
            .candidates
            .get(*index)
            .context("Recorded candidate changed")?;
        checks.push(Step {
            name: format!("Verify recorded visible state: {}", candidate.word),
            action: Action::RdpCheckpoint {
                target: profile.id.to_string(),
                expected: candidate.word.clone(),
            },
        });
    }
    let steps = if let Some(procedure) = procedure {
        crate::teaching::validate_workflow_procedure(procedure)?;
        let parameters = procedure
            .steps
            .iter()
            .filter_map(|step| match step {
                crate::teaching::Step::Parameter { name } => Some((name.clone(), name.clone())),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        vec![Step {
            name: "Replay separately reviewed demonstration".into(),
            action: Action::RdpProcedure {
                target: profile.id.to_string(),
                procedure: procedure.clone(),
                parameters,
            },
        }]
    } else {
        ensure!(
            checks.len() >= 2,
            "Checkpoint-only plans need an initial and final observed state; select two words or include a validated demonstration"
        );
        vec![checks.remove(0)]
    };
    let plan = Plan {
        name: "Recorded application checks".into(),
        preconditions: vec![],
        steps,
        verification: checks,
        restore: vec![],
    };
    crate::workflow::validate(&plan).map_err(anyhow::Error::msg)?;
    Ok(plan)
}

fn binding(
    recording: &Recording,
    profile: &ConnectionProfile,
    chosen: &BTreeSet<usize>,
    procedure: Option<&Procedure>,
) -> Result<String> {
    build(recording, profile, chosen, procedure)?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            recording, profile, chosen, procedure
        ))?)
    ))
}
pub fn review(
    recording: &Recording,
    profile: &ConnectionProfile,
    chosen: &BTreeSet<usize>,
    procedure: Option<&Procedure>,
    now: DateTime<Utc>,
) -> Result<Review> {
    Ok(Review {
        binding: binding(recording, profile, chosen, procedure)?,
        at: now,
    })
}
pub fn prepare(
    recording: &Recording,
    profile: &ConnectionProfile,
    chosen: &BTreeSet<usize>,
    procedure: Option<&Procedure>,
    review: &Review,
    now: DateTime<Utc>,
) -> Result<Plan> {
    ensure!(
        review.at <= now && now.signed_duration_since(review.at) <= chrono::Duration::minutes(5),
        "Recording review expired; review again"
    );
    ensure!(
        review.binding == binding(recording, profile, chosen, procedure)?,
        "Recording, target profile, selected assertions, or demonstration changed; review again"
    );
    build(recording, profile, chosen, procedure)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Recording, ConnectionProfile) {
        let profile = ConnectionProfile::sample("Fixture", "fixture.example.invalid", "", false);
        let at = Utc::now() - chrono::Duration::seconds(10);
        let recording = Recording {
            id: uuid::Uuid::new_v4(),
            profile: profile.id,
            title: "Fixture".into(),
            created: at,
            finished: true,
            masks: vec![],
            frames: vec![
                crate::recording::Keyframe {
                    file: "000000.dpapi".into(),
                    at,
                    note: "password=never-show-notes".into(),
                    ocr: "Login".into(),
                },
                crate::recording::Keyframe {
                    file: "000001.dpapi".into(),
                    at: at + chrono::Duration::seconds(1),
                    note: String::new(),
                    ocr: "Dashboard Ready".into(),
                },
            ],
        };
        (recording, profile)
    }
    #[test]
    fn archive_observations_prepare_existing_checkpoint_runner_without_execution() {
        let (recording, profile) = fixture();
        let chosen = BTreeSet::from([0, 1]);
        let now = Utc::now();
        let reviewed = review(&recording, &profile, &chosen, None, now).unwrap();
        let plan = prepare(&recording, &profile, &chosen, None, &reviewed, now).unwrap();
        assert!(
            matches!(&plan.steps[0].action,Action::RdpCheckpoint{target,expected} if target==&profile.id.to_string() && expected=="Login")
        );
        assert!(
            matches!(&plan.verification[0].action,Action::RdpCheckpoint{expected,..} if expected=="Dashboard")
        );
    }
    #[test]
    fn changed_source_target_selection_or_expired_review_is_rejected() {
        let (mut recording, mut profile) = fixture();
        let original_profile=profile.clone();
        let chosen = BTreeSet::from([0, 1]);
        let now = Utc::now();
        let reviewed = review(&recording, &profile, &chosen, None, now).unwrap();
        assert!(
            prepare(
                &recording,
                &profile,
                &BTreeSet::from([0, 2]),
                None,
                &reviewed,
                now
            )
            .is_err()
        );
        profile.host = "changed.example.invalid".into();
        assert!(prepare(&recording, &profile, &chosen, None, &reviewed, now).is_err());
        profile.id = uuid::Uuid::new_v4();
        assert!(review(&recording, &profile, &chosen, None, now).is_err());
        let matching=original_profile;
        recording.frames[0].note.push_str("changed");
        assert!(prepare(&recording, &matching, &chosen, None, &reviewed, now).is_err());
        assert!(
            prepare(
                &recording,
                &matching,
                &chosen,
                None,
                &reviewed,
                now + chrono::Duration::minutes(6)
            )
            .is_err()
        );
    }
    #[test]
    fn no_ocr_no_inference_and_sensitive_frames_never_become_candidates() {
        let (mut recording, _) = fixture();
        for frame in &mut recording.frames {
            frame.ocr.clear();
        }
        assert!(derive(&recording).is_err());
        recording.frames[0].ocr = "password Ready token abc123 Dashboard".into();
        assert!(derive(&recording).is_err());
        recording.frames[0].ocr = "alice@example.com 123456 abcXYZ Welcome".into();
        let derived = derive(&recording).unwrap();
        assert_eq!(derived.candidates.len(), 1);
        assert_eq!(derived.candidates[0].word, "Welcome");
        recording.finished = false;
        assert!(derive(&recording).is_err());
    }
    #[test]
    fn validated_demonstration_reuses_native_procedure_runner_and_is_review_bound() {
        let (recording, profile) = fixture();
        let anchor = crate::vision::Anchor {
            label: "Dashboard".into(),
            context: String::new(),
        };
        let mut procedure = Procedure {
            title: "Demonstrated application input".into(),
            dimensions: (800, 600),
            steps: vec![crate::teaching::Step::Parameter {
                name: "test_user".into(),
            }],
            success: "Dashboard is visible".into(),
            recovery: "Stop and return to initial screen".into(),
            expected_after: BTreeMap::from([(0, anchor.clone())]),
            expected_final: Some(anchor),
        };
        let chosen = BTreeSet::from([1]);
        let now = Utc::now();
        let reviewed = review(&recording, &profile, &chosen, Some(&procedure), now).unwrap();
        let plan = prepare(
            &recording,
            &profile,
            &chosen,
            Some(&procedure),
            &reviewed,
            now,
        )
        .unwrap();
        assert!(
            matches!(&plan.steps[0].action,Action::RdpProcedure{target,parameters,..} if target==&profile.id.to_string() && parameters["test_user"]=="test_user")
        );
        procedure.success = "Changed expected outcome".into();
        assert!(
            prepare(
                &recording,
                &profile,
                &chosen,
                Some(&procedure),
                &reviewed,
                now
            )
            .is_err()
        );
        procedure.expected_after.clear();
        assert!(review(&recording, &profile, &chosen, Some(&procedure), now).is_err());
    }
}
