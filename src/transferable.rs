//! Portable OCR targets contain no source session or absolute destination coordinate.
use crate::vision::{Anchor, Bounds, Screen};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct RunApproval {
    pub target: uuid::Uuid,
    fingerprint: [u8; 32],
    expires: std::time::Instant,
}
impl RunApproval {
    pub fn new(
        target: uuid::Uuid,
        procedure: &crate::teaching::Procedure,
        parameters: &BTreeMap<String, String>,
        profile_identity: &[u8],
        now: std::time::Instant,
    ) -> Result<Self> {
        validate_run(procedure, parameters)?;
        Ok(Self {
            target,
            fingerprint: run_fingerprint(procedure, parameters, profile_identity)?,
            expires: now + std::time::Duration::from_secs(300),
        })
    }
    pub fn matches(
        &self,
        target: uuid::Uuid,
        procedure: &crate::teaching::Procedure,
        parameters: &BTreeMap<String, String>,
        profile_identity: &[u8],
        now: std::time::Instant,
    ) -> bool {
        self.target == target
            && now < self.expires
            && run_fingerprint(procedure, parameters, profile_identity)
                .is_ok_and(|f| f == self.fingerprint)
    }
}
fn run_fingerprint(
    procedure: &crate::teaching::Procedure,
    parameters: &BTreeMap<String, String>,
    profile_identity: &[u8],
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(&(
        procedure,
        parameters,
        profile_identity,
    ))?)
    .into())
}
pub fn validate_run(
    procedure: &crate::teaching::Procedure,
    parameters: &BTreeMap<String, String>,
) -> Result<()> {
    use crate::teaching::Step;
    procedure.validate()?;
    let names: std::collections::BTreeSet<_> = procedure
        .steps
        .iter()
        .filter_map(|s| {
            if let Step::Parameter { name } = s {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    if parameters.keys().any(|name| !names.contains(name)) {
        bail!("Unknown workflow parameter");
    }
    if procedure.expected_final.is_none() {
        bail!("The complete workflow requires a visible final condition");
    }
    for (index, step) in procedure.steps.iter().enumerate() {
        if !procedure.expected_after.contains_key(&index) {
            bail!("Step {} requires an OCR postcondition", index + 1);
        }
        let action = match step {
            Step::TransferClick { button, double, .. }
            | Step::IconClick { button, double, .. }
            | Step::SemanticClick { button, double, .. } => {
                if *double {
                    crate::models::InputAction::DoubleClick {
                        x: 0,
                        y: 0,
                        button: *button,
                    }
                } else {
                    crate::models::InputAction::Click {
                        x: 0,
                        y: 0,
                        button: *button,
                    }
                }
            }
            Step::Parameter { name } => {
                validate_parameter(name)?;
                let value = parameters
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("Parameter {name} is missing"))?;
                if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                    bail!("Parameter {name} requires bounded text without control characters");
                }
                crate::models::InputAction::TypeText {
                    text: value.clone(),
                }
            }
            _ => bail!(
                "The complete workflow permits only semantic clicks and named parameters; review step {}",
                index + 1
            ),
        };
        if crate::policy::PolicyEngine.decision_for(&action) == crate::models::PolicyDecision::Deny
        {
            bail!("Step {} is blocked by policy", index + 1);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LogicalTarget {
    pub anchor: Anchor,
    /// Context displacement measured in target-word heights, robust to uniform scaling.
    pub context_offset: Option<(f32, f32)>,
}
impl LogicalTarget {
    pub fn propose(screen: &Screen, x: u16, y: u16) -> Result<Self> {
        let hits: Vec<_> = screen
            .words
            .iter()
            .filter(|w| {
                let b = w.bounds;
                x >= b.x
                    && y >= b.y
                    && u32::from(x) < u32::from(b.x) + u32::from(b.w)
                    && u32::from(y) < u32::from(b.y) + u32::from(b.h)
            })
            .collect();
        let [word] = hits.as_slice() else {
            bail!("Click requires an anchor: no unique visible word was selected");
        };
        if !crate::vision::safe_anchor_text(&word.text) {
            bail!("Anchor text may be sensitive; bind it manually");
        }
        let mut target = Self {
            anchor: Anchor {
                label: word.text.clone(),
                context: String::new(),
            },
            context_offset: None,
        };
        // Prefer nearby non-sensitive context; never guess the meaning of an icon.
        let center = word.bounds.center();
        let context = screen
            .words
            .iter()
            .filter(|c| {
                c.bounds != word.bounds
                    && c.text.to_lowercase() != word.text.to_lowercase()
                    && crate::vision::safe_anchor_text(&c.text)
                    && c.bounds.center().0.abs_diff(center.0) < 400
                    && c.bounds.center().1.abs_diff(center.1) < 100
            })
            .min_by_key(|c| {
                u32::from(c.bounds.center().0.abs_diff(center.0))
                    + 3 * u32::from(c.bounds.center().1.abs_diff(center.1))
            });
        if let Some(c) = context {
            target.anchor.context = c.text.clone();
            target.context_offset = Some(offset(word.bounds, c.bounds));
        }
        if target.resolve(screen)? != word.bounds {
            bail!("Automatic anchor is not unique");
        }
        Ok(target)
    }
    pub fn resolve(&self, screen: &Screen) -> Result<Bounds> {
        if self.anchor.label.trim().is_empty()
            || self.anchor.label.len() > 256
            || self.anchor.context.len() > 256
        {
            bail!("Invalid target anchor");
        }
        let found: Vec<_> = screen
            .words
            .iter()
            .filter(|w| w.text.trim().eq_ignore_ascii_case(self.anchor.label.trim()))
            .filter(|w| match self.context_offset {
                None => self.anchor.context.is_empty(),
                Some((dx, dy)) if dx.is_finite() && dy.is_finite() => {
                    screen.words.iter().any(|c| {
                        if !c
                            .text
                            .trim()
                            .eq_ignore_ascii_case(self.anchor.context.trim())
                        {
                            return false;
                        }
                        let (x, y) = offset(w.bounds, c.bounds);
                        (x - dx).abs() <= 2.0 && (y - dy).abs() <= 1.0
                    })
                }
                _ => false,
            })
            .collect();
        match found.as_slice() {
            [w] if w.bounds.w > 0
                && w.bounds.h > 0
                && u32::from(w.bounds.x) + u32::from(w.bounds.w) <= u32::from(screen.width)
                && u32::from(w.bounds.y) + u32::from(w.bounds.h) <= u32::from(screen.height) =>
            {
                Ok(w.bounds)
            }
            [] => bail!("Target or relative context is missing: anchor again"),
            _ => bail!("Target is ambiguous or geometry is invalid: no action"),
        }
    }
}
fn offset(target: Bounds, context: Bounds) -> (f32, f32) {
    let (x, y) = target.center();
    let (cx, cy) = context.center();
    let scale = f32::from(target.h.max(1));
    (
        (f32::from(cx) - f32::from(x)) / scale,
        (f32::from(cy) - f32::from(y)) / scale,
    )
}
pub fn validate_parameter(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!("Parameter name: 1–64 letters, digits, or underscores");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn approved_procedure() -> crate::teaching::Procedure {
        let expected = Anchor {
            label: "Completed".into(),
            context: String::new(),
        };
        crate::teaching::Procedure {
            title: "Named workflow".into(),
            dimensions: (800, 600),
            steps: vec![crate::teaching::Step::Parameter {
                name: "service".into(),
            }],
            success: "Completed is visible".into(),
            recovery: "Review status".into(),
            expected_after: BTreeMap::from([(0, expected.clone())]),
            expected_final: Some(expected),
        }
    }
    #[test]
    fn approval_is_bound_to_target_definition_parameters_profile_and_expiry() {
        let procedure = approved_procedure();
        let values = BTreeMap::from([("service".into(), "Spooler".into())]);
        let target = uuid::Uuid::new_v4();
        let now = std::time::Instant::now();
        let approval = RunApproval::new(target, &procedure, &values, b"profile-v1", now).unwrap();
        assert!(approval.matches(target, &procedure, &values, b"profile-v1", now));
        assert!(!approval.matches(
            uuid::Uuid::new_v4(),
            &procedure,
            &values,
            b"profile-v1",
            now
        ));
        assert!(!approval.matches(target, &procedure, &values, b"profile-v2", now));
        assert!(!approval.matches(
            target,
            &procedure,
            &values,
            b"profile-v1",
            now + std::time::Duration::from_secs(300)
        ));
        let mut changed = procedure.clone();
        changed.expected_final.as_mut().unwrap().label = "Other".into();
        assert!(!approval.matches(target, &changed, &values, b"profile-v1", now));
        let mut changed_values = values;
        changed_values.insert("service".into(), "OtherService".into());
        assert!(!approval.matches(target, &procedure, &changed_values, b"profile-v1", now));
    }
    #[test]
    fn whole_approval_rejects_unanchored_missing_assertion_and_denied_parameters() {
        let values = BTreeMap::from([("service".into(), "Spooler".into())]);
        let mut p = approved_procedure();
        p.expected_after.clear();
        assert!(validate_run(&p, &values).is_err());
        p = approved_procedure();
        p.expected_final = None;
        assert!(validate_run(&p, &values).is_err());
        p = approved_procedure();
        p.steps[0] = crate::teaching::Step::Click {
            x: 10,
            y: 10,
            button: crate::models::MouseButton::Left,
            double: false,
        };
        assert!(validate_run(&p, &values).is_err());
        p = approved_procedure();
        assert!(validate_run(&p, &BTreeMap::new()).is_err());
        assert!(
            validate_run(
                &p,
                &BTreeMap::from([
                    ("service".into(), "Spooler".into()),
                    ("unexpected".into(), "value".into())
                ])
            )
            .is_err()
        );
        assert!(crate::teaching::validate_workflow_procedure(&p).is_ok());
        assert!(
            validate_run(
                &p,
                &BTreeMap::from([("service".into(), "Remove-Item -Recurse C:\\data".into())])
            )
            .is_err()
        );
        assert!(
            validate_run(
                &p,
                &BTreeMap::from([("service".into(), "value\r\n".into())])
            )
            .is_err()
        );
    }
    fn screen(x: u16, y: u16, scale: u16) -> Screen {
        Screen {
            session: uuid::Uuid::new_v4(),
            width: 1600,
            height: 1200,
            frame_hash: 1,
            captured_at: chrono::Utc::now(),
            words: vec![
                crate::vision::Word {
                    text: "Save".into(),
                    bounds: Bounds {
                        x,
                        y,
                        w: 80 * scale,
                        h: 20 * scale,
                    },
                },
                crate::vision::Word {
                    text: "Settings".into(),
                    bounds: Bounds {
                        x,
                        y: y - 40 * scale,
                        w: 80 * scale,
                        h: 20 * scale,
                    },
                },
            ],
        }
    }
    #[test]
    fn moves_scales_and_changes_host() {
        let source = screen(20, 100, 1);
        let target = LogicalTarget::propose(&source, 30, 110).unwrap();
        let destination = screen(500, 400, 2);
        assert_ne!(source.session, destination.session);
        assert_eq!(target.resolve(&destination).unwrap().center(), (580, 420));
    }
    #[test]
    fn ambiguous_and_icons_block() {
        let source = screen(20, 100, 1);
        let target = LogicalTarget::propose(&source, 30, 110).unwrap();
        assert!(LogicalTarget::propose(&source, 500, 500).is_err());
        let mut destination = screen(500, 400, 1);
        destination.words.extend(screen(800, 400, 1).words);
        assert!(target.resolve(&destination).is_err());
        destination.words.retain(|w| w.text != "Settings");
        assert!(target.resolve(&destination).is_err());
    }
    #[test]
    fn parameter_identifiers_are_bounded() {
        assert!(validate_parameter("server_name").is_ok());
        assert!(validate_parameter("${password}").is_err());
        assert!(validate_parameter("").is_err());
        assert!(validate_parameter(&"x".repeat(65)).is_err());
    }
}
