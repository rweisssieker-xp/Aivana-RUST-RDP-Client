//! Deterministic historical ranking; no inference calls, execution or new evidence store.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub const WINDOW_DAYS: i64 = 90;

#[derive(Clone, Debug)]
pub struct RankedLesson {
    pub lesson: ExecutionLesson,
    pub excluded: usize,
    pub latest_success: Option<DateTime<Utc>>,
    pub latest_adverse: Option<DateTime<Utc>>,
    pub score: i32,
    pub gaps: Vec<&'static str>,
}
impl RankedLesson {
    pub fn eligible(&self) -> bool {
        self.lesson.production.successes > 0
            && self
                .latest_success
                .is_some_and(|success| self.latest_adverse.is_none_or(|failure| success > failure))
    }
}

pub fn rank(journal: &Journal, selected: &Target, now: DateTime<Utc>) -> Vec<RankedLesson> {
    let mut groups = BTreeMap::<String, RankedLesson>::new();
    let mut identities = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for run in &journal.runs {
        for target in &run.targets {
            if !identities.insert((run.id, target.target.profile_id)) {
                duplicates.insert((run.id, target.target.profile_id));
            }
        }
    }
    for run in &journal.runs {
        let Ok(lesson) = ExecutionLesson::from_plan(&run.plan) else {
            continue;
        };
        if run.plan.desired != ServiceState::Running {
            continue;
        }
        let group = groups
            .entry(lesson.key.clone())
            .or_insert_with(|| RankedLesson {
                lesson,
                excluded: 0,
                latest_success: None,
                latest_adverse: None,
                score: 0,
                gaps: vec![],
            });
        for (index, target) in run.targets.iter().enumerate() {
            let mapping = run.plan.mappings.get(index);
            let bound = run.plan.hash().is_ok_and(|hash| hash == run.hash)
                && run.targets.len() == run.plan.mappings.len()
                && mapping.is_some_and(|m| {
                    m.production.same_endpoint(selected)
                        && target.target.same_endpoint(if run.rehearsal {
                            &m.staging
                        } else {
                            &m.production
                        })
                });
            let Some(finished) = run
                .finished
                .filter(|at| *at <= now && *at >= now - chrono::Duration::days(WINDOW_DAYS))
            else {
                group.excluded += 1;
                continue;
            };
            if !bound || duplicates.contains(&(run.id, target.target.profile_id)) {
                group.excluded += 1;
                continue;
            }
            let counts = if run.rehearsal {
                &mut group.lesson.rehearsal
            } else {
                &mut group.lesson.production
            };
            // A healthy no-op is not a successful repair. HTTP evidence is required here.
            let repaired = matches!(run.plan.health, HealthCheck::Http { .. })
                && target.baseline.as_ref().is_some_and(|b| !b.passed)
                && (run.plan.restart
                    || target
                        .before
                        .is_some_and(|before| before != run.plan.desired))
                && evidenced_success(run, target);
            let phase = match target.phase {
                Phase::Passed if repaired => {
                    counts.successes += 1;
                    Phase::Passed
                }
                Phase::Failed => {
                    counts.failures += 1;
                    Phase::Failed
                }
                Phase::Restored => {
                    counts.restored += 1;
                    Phase::Restored
                }
                _ => {
                    counts.unknown += 1;
                    Phase::Unknown
                }
            };
            if !run.rehearsal {
                if phase == Phase::Unknown {
                    for (missing, key) in [
                        (
                            !matches!(run.plan.health, HealthCheck::Http { .. }),
                            "gap_http",
                        ),
                        (
                            !target.baseline.as_ref().is_some_and(|b| !b.passed),
                            "gap_baseline",
                        ),
                        (
                            !(run.plan.restart
                                || target
                                    .before
                                    .is_some_and(|before| before != run.plan.desired)),
                            "gap_transition",
                        ),
                        (!evidenced_success(run, target), "gap_evidence"),
                    ] {
                        if missing && !group.gaps.contains(&key) {
                            group.gaps.push(key);
                        }
                    }
                }
                if phase == Phase::Passed {
                    group.latest_success = Some(
                        group
                            .latest_success
                            .map_or(finished, |old| old.max(finished)),
                    );
                } else {
                    group.latest_adverse = Some(
                        group
                            .latest_adverse
                            .map_or(finished, |old| old.max(finished)),
                    );
                }
            }
            group.lesson.evidence.push(LessonEvidence {
                run_id: run.id,
                target_profile_id: target.target.profile_id,
                rehearsal: run.rehearsal,
                phase,
            });
        }
    }
    let mut rows = groups.into_values().collect::<Vec<_>>();
    for row in &mut rows {
        let c = &row.lesson.production;
        row.score = 5 * c.successes.min(5) as i32
            - 8 * (c.failures + c.restored).min(5) as i32
            - 4 * c.unknown.min(5) as i32;
    }
    rows.sort_by(|a, b| {
        b.eligible()
            .cmp(&a.eligible())
            .then(b.score.cmp(&a.score))
            .then(a.lesson.key.cmp(&b.lesson.key))
    });
    rows
}
