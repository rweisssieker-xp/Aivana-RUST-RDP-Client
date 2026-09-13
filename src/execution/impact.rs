//! Auditable observed outcomes. No manual baseline, labor savings, MTTR or ROI claims.
use super::*;

#[derive(Default, Debug, Serialize)]
pub struct Cohort {
    pub repaired: usize,
    pub failed: usize,
    pub restored: usize,
    pub unverified: usize,
    pub duration_samples: usize,
    pub median_observation_to_health_ms: Option<f64>,
}
#[derive(Debug, Serialize)]
pub struct Sample {
    pub run: Uuid,
    pub target: Uuid,
    pub rehearsal: bool,
    pub observed_at: DateTime<Utc>,
    pub healthy_at: DateTime<Utc>,
    pub interval_ms: i64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub selected_profile: Uuid,
    pub schema: &'static str,
    pub as_of: DateTime<Utc>,
    pub window_days: i64,
    pub production: Cohort,
    pub rehearsal: Cohort,
    pub excluded_results: usize,
    pub samples: Vec<Sample>,
    pub labor_savings_measured: bool,
    pub roi_measured: bool,
    pub not_execution_authorization: bool,
}
fn median(values: &mut [i64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let m = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        values[m - 1] as f64 / 2.0 + values[m] as f64 / 2.0
    } else {
        values[m] as f64
    })
}
pub fn report(journal: &Journal, target: &Target, now: DateTime<Utc>) -> Report {
    let mut result = Report {
        selected_profile: target.profile_id,
        schema: "relayne-outcome-impact-v1",
        as_of: now,
        window_days: learning::WINDOW_DAYS,
        production: Cohort::default(),
        rehearsal: Cohort::default(),
        excluded_results: 0,
        samples: vec![],
        labor_savings_measured: false,
        roi_measured: false,
        not_execution_authorization: true,
    };
    for row in learning::rank(journal, target, now) {
        result.excluded_results += row.excluded;
        for (counts, cohort) in [
            (&row.lesson.production, &mut result.production),
            (&row.lesson.rehearsal, &mut result.rehearsal),
        ] {
            cohort.repaired += counts.successes;
            cohort.failed += counts.failures;
            cohort.restored += counts.restored;
            cohort.unverified += counts.unknown;
        }
        for evidence in row
            .lesson
            .evidence
            .iter()
            .filter(|e| e.phase == Phase::Passed)
        {
            let Some(run) = journal.runs.iter().find(|r| r.id == evidence.run_id) else {
                continue;
            };
            let Some(target) = run
                .targets
                .iter()
                .find(|t| t.target.profile_id == evidence.target_profile_id)
            else {
                continue;
            };
            let (Some(start), Some(health)) = (target.captured, target.health.as_ref()) else {
                continue;
            };
            // End at this target's health check, not the later completion of a multi-target run.
            if health.at < start || health.at > now {
                continue;
            }
            result.samples.push(Sample {
                run: run.id,
                target: target.target.profile_id,
                rehearsal: run.rehearsal,
                observed_at: start,
                healthy_at: health.at,
                interval_ms: (health.at - start).num_milliseconds(),
            });
        }
    }
    result
        .samples
        .sort_by_key(|s| (s.observed_at, s.run, s.target));
    for (rehearsal, cohort) in [
        (false, &mut result.production),
        (true, &mut result.rehearsal),
    ] {
        let mut durations = result
            .samples
            .iter()
            .filter(|s| s.rehearsal == rehearsal)
            .map(|s| s.interval_ms)
            .collect::<Vec<_>>();
        cohort.duration_samples = durations.len();
        cohort.median_observation_to_health_ms = median(&mut durations);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn impact_median_handles_empty_even_odd_and_extreme_values() {
        assert_eq!(median(&mut []), None);
        assert_eq!(median(&mut [9, 1, 3]), Some(3.0));
        assert_eq!(median(&mut [9, 1]), Some(5.0));
        assert!(median(&mut [i64::MAX, i64::MAX]).unwrap().is_finite());
    }
}
