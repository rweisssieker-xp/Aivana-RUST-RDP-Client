//! Inspectable ranking of reusable solutions; no invented success probabilities.
use crate::{
    mission::{Mission, MissionBook, Status, Step, Target},
    security,
    telemetry::Observation,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Requirements {
    pub protocol: String,
    pub os_prefix: String,
    pub services: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recipe {
    pub id: Uuid,
    pub title: String,
    pub objective: String,
    pub steps: Vec<Step>,
    pub requirements: Requirements,
    pub source: Uuid,
    pub plan_hash: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Library {
    pub recipes: Vec<Recipe>,
}
pub fn plan_hash(steps: &[Step]) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(steps).unwrap_or_default())
    )
}
#[derive(Clone, Debug)]
pub struct Recommendation {
    pub recipe: Uuid,
    pub score: i32,
    pub successes: usize,
    pub failures: usize,
    pub interrupted: usize,
    pub matches: Vec<String>,
    pub missing: Vec<String>,
    pub conflicts: Vec<String>,
    pub evidence: Vec<Uuid>,
}
impl Recommendation {
    pub fn eligible(&self) -> bool {
        self.conflicts.is_empty() && self.missing.is_empty() && self.successes > 0
    }
}
fn words(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| {
            s.len() >= 3
                && !matches!(
                    *s,
                    "und"
                        | "der"
                        | "die"
                        | "das"
                        | "auf"
                        | "mit"
                        | "für"
                        | "den"
                        | "von"
                        | "the"
                        | "and"
                )
        })
        .map(str::to_string)
        .collect()
}
impl Library {
    pub fn remember(&mut self, m: &Mission, requirements: Requirements) -> Result<Uuid> {
        if self.recipes.len() >= 256 || m.objective.trim().is_empty() || m.steps.is_empty() {
            bail!("The solution library is full or the job is incomplete");
        }
        if requirements.services.len() > 32
            || requirements.os_prefix.len() > 128
            || requirements.services.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            bail!("Invalid prerequisites");
        }
        let hash = plan_hash(&m.steps);
        if self
            .recipes
            .iter()
            .any(|r| r.source == m.id && r.plan_hash == hash)
        {
            bail!("This job revision is already in the library");
        }
        let id = Uuid::new_v4();
        self.recipes.push(Recipe {
            id,
            title: security::redact_secret_text(&m.objective),
            objective: security::redact_secret_text(&m.objective),
            steps: m.steps.clone(),
            requirements,
            source: m.id,
            plan_hash: hash,
        });
        Ok(id)
    }
    pub fn recommend(
        &self,
        query: &str,
        target: &Target,
        observation: Option<&Observation>,
        book: &MissionBook,
    ) -> Vec<Recommendation> {
        let query = words(query);
        let mut ranked = vec![];
        for recipe in &self.recipes {
            let terms = words(&format!("{} {}", recipe.title, recipe.objective));
            let overlap = query.intersection(&terms).count();
            if !query.is_empty() && overlap == 0 {
                continue;
            }
            let mut r = Recommendation {
                recipe: recipe.id,
                score: (overlap * 15) as i32,
                successes: 0,
                failures: 0,
                interrupted: 0,
                matches: vec![],
                missing: vec![],
                conflicts: vec![],
                evidence: vec![],
            };
            if recipe.requirements.protocol == target.protocol {
                r.matches.push(format!("Protokoll {}", target.protocol));
                r.score += 10;
            } else {
                r.conflicts
                    .push(format!("Erfordert {}", recipe.requirements.protocol));
            }
            let observation = observation.filter(|o| o.target.same_endpoint(target) && o.fresh());
            if !recipe.requirements.os_prefix.is_empty() {
                match observation {
                    Some(o)
                        if o.payload
                            .os_version
                            .starts_with(&recipe.requirements.os_prefix) =>
                    {
                        r.matches.push(format!("OS {}", o.payload.os_version))
                    }
                    Some(o) => r.conflicts.push(format!(
                        "OS {} does not match {}",
                        o.payload.os_version, recipe.requirements.os_prefix
                    )),
                    None => r.missing.push("Fresh OS telemetry is missing".into()),
                }
            }
            for service in &recipe.requirements.services {
                match observation {
                    Some(o)
                        if o.payload
                            .services
                            .iter()
                            .any(|s| s.name.eq_ignore_ascii_case(service)) =>
                    {
                        r.matches.push(format!("Service {service} is present"))
                    }
                    Some(o) if !o.payload.truncated => {
                        r.conflicts.push(format!("Service {service} is missing"))
                    }
                    _ => r
                        .missing
                        .push(format!("The presence of {service} has not been checked")),
                }
            }
            for m in &book.missions {
                if plan_hash(&m.steps) != recipe.plan_hash {
                    continue;
                }
                for t in &m.targets {
                    let outcomes: Vec<_> = m
                        .outcomes
                        .iter()
                        .filter(|o| o.target == t.profile_id)
                        .collect();
                    if outcomes.iter().any(|o| o.status == Status::Failed) {
                        r.failures += 1;
                    } else if outcomes.iter().any(|o| o.status == Status::Interrupted) {
                        r.interrupted += 1;
                    } else if outcomes.len() == m.steps.len()
                        && outcomes.iter().all(|o| {
                            o.status == Status::Passed
                                && !o.evidence.is_empty()
                                && o.evidence.iter().all(|id| {
                                    m.evidence
                                        .iter()
                                        .any(|e| e.id == *id && e.target.same_endpoint(t))
                                })
                        })
                    {
                        r.successes += 1;
                    }
                    for o in outcomes {
                        r.evidence.extend(
                            o.evidence
                                .iter()
                                .copied()
                                .filter(|id| m.evidence.iter().any(|e| e.id == *id)),
                        );
                    }
                }
            }
            r.evidence.sort();
            r.evidence.dedup();
            r.score += (r.successes.min(5) * 5) as i32
                - (r.failures.min(5) * 8) as i32
                - (r.interrupted.min(5) * 4) as i32;
            r.score -= 30 * r.missing.len() as i32 + 100 * r.conflicts.len() as i32;
            ranked.push(r);
        }
        ranked.sort_by(|a, b| {
            b.eligible()
                .cmp(&a.eligible())
                .then(b.score.cmp(&a.score))
                .then(a.recipe.cmp(&b.recipe))
        });
        ranked
    }
    pub fn save(&self, p: &Path) -> Result<()> {
        if !cfg!(windows) {
            bail!("Windows DPAPI is required");
        }
        let raw = serde_json::to_vec(self)?;
        if raw.len() > 8 * 1024 * 1024 {
            bail!("Solution library too large");
        }
        security::atomic_write(p, &security::protect_secret(&raw)?)
    }
    pub fn load(p: &Path) -> Result<Self> {
        if !p.exists() {
            return Ok(Self::default());
        }
        if std::fs::metadata(p)?.len() > 10 * 1024 * 1024 {
            bail!("Solution library too large");
        }
        Ok(serde_json::from_slice(&security::unprotect_secret(
            &std::fs::read(p)?,
        )?)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mission::{Evidence, Outcome};
    fn target() -> Target {
        Target {
            profile_id: Uuid::new_v4(),
            name: "test".into(),
            host: "test.invalid".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        }
    }
    #[test]
    fn evidence_and_requirements_gate_reuse() {
        let t = target();
        let mut m =
            Mission::new("Druckdienst prüfen", vec![t.clone()], vec![Step::default()]).unwrap();
        let evidence = Evidence::new(t.clone(), "fixture", Default::default(), "state");
        m.evidence.push(evidence.clone());
        m.outcomes = vec![Outcome {
            target: t.profile_id,
            step: 0,
            status: Status::Passed,
            evidence: vec![evidence.id],
            verification: "confirmed".into(),
        }];
        let mut lib = Library::default();
        lib.remember(
            &m,
            Requirements {
                protocol: "RDP".into(),
                os_prefix: String::new(),
                services: vec![],
            },
        )
        .unwrap();
        let mut book = MissionBook {
            missions: vec![m],
            ..Default::default()
        };
        let r = lib.recommend("Druckdienst", &t, None, &book);
        assert_eq!(r[0].successes, 1);
        assert!(r[0].eligible());
        book.missions[0].evidence.clear();
        assert!(!lib.recommend("Druckdienst", &t, None, &book)[0].eligible());
        lib.recipes[0].requirements.services.push("Spooler".into());
        assert!(
            !lib.recommend("Druckdienst", &t, None, &book)[0]
                .missing
                .is_empty()
        );
    }
    #[test]
    fn changed_step_content_is_not_counted_as_same_solution() {
        let a = vec![Step::default()];
        let mut b = a.clone();
        b[0].expectation = "different".into();
        assert_ne!(plan_hash(&a), plan_hash(&b));
    }
}
