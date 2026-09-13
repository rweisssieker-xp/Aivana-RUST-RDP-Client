//! Explainable retrospective heuristics, not outage predictions or automated actions.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Kind {
    RepeatedRepairs,
    SlowerVerification,
}
#[derive(Debug, Serialize)]
pub struct Signal {
    pub kind: Kind,
    pub procedure_key: String,
    pub service: String,
    pub restart: bool,
    pub source_runs: Vec<Uuid>,
    pub baseline_median_ms: Option<f64>,
    pub recent_median_ms: Option<f64>,
    pub rule: &'static str,
    pub predicts_outage: bool,
}
fn days(samples: &[&Sample]) -> usize {
    samples
        .iter()
        .map(|s| s.healthy_at.date_naive())
        .collect::<BTreeSet<_>>()
        .len()
}
pub fn detect(samples: &[Sample], now: DateTime<Utc>) -> Vec<Signal> {
    let mut groups = BTreeMap::<&str, Vec<&Sample>>::new();
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for sample in samples {
        if !seen.insert(sample.run) {
            duplicates.insert(sample.run);
        }
    }
    for s in samples {
        if s.rehearsal
            || s.healthy_at > now
            || s.observed_at > s.healthy_at
            || s.healthy_at < now - chrono::Duration::days(30)
            || s.interval_ms < 0
            || s.interval_ms != (s.healthy_at - s.observed_at).num_milliseconds()
            || duplicates.contains(&s.run)
        {
            continue;
        }
        groups.entry(&s.procedure_key).or_default().push(s);
    }
    let mut result = Vec::new();
    for (key, mut group) in groups {
        group.sort_by_key(|s| (s.healthy_at, s.run));
        let first = group[0];
        let signal = |kind, source: &[&Sample], baseline, recent, rule| Signal {
            kind,
            procedure_key: key.into(),
            service: first.service.clone(),
            restart: first.restart,
            source_runs: source.iter().map(|s| s.run).collect(),
            baseline_median_ms: baseline,
            recent_median_ms: recent,
            rule,
            predicts_outage: false,
        };
        let week = group
            .iter()
            .copied()
            .filter(|s| s.healthy_at >= now - chrono::Duration::days(7))
            .collect::<Vec<_>>();
        if week.len() >= 3 && days(&week) >= 2 {
            result.push(signal(
                Kind::RepeatedRepairs,
                &week,
                None,
                None,
                "at least 3 distinct production repairs across 2 UTC dates within 7 days",
            ));
        }
        if group.len() >= 6 {
            let six = &group[group.len() - 6..];
            let previous = &six[..3];
            let recent = &six[3..];
            if days(previous) < 2
                || days(recent) < 2
                || recent[0].healthy_at < now - chrono::Duration::days(7)
            {
                continue;
            }
            let before =
                median(&mut previous.iter().map(|s| s.interval_ms).collect::<Vec<_>>()).unwrap();
            let after =
                median(&mut recent.iter().map(|s| s.interval_ms).collect::<Vec<_>>()).unwrap();
            if before > 0.0 && after >= before * 2.0 && after - before >= 5_000.0 {
                result.push(signal(Kind::SlowerVerification,six,Some(before),Some(after),"last 3 vs preceding 3 successes; each across 2 UTC dates; >=2x and >=5000ms increase; 30-day history, recent 3 within 7 days"));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(now: DateTime<Utc>, days: i64, ms: i64, key: &str) -> Sample {
        let end = now - chrono::Duration::days(days);
        Sample {
            procedure_key: key.into(),
            service: "ExampleService".into(),
            restart: false,
            run: Uuid::new_v4(),
            target: Uuid::nil(),
            rehearsal: false,
            observed_at: end - chrono::Duration::milliseconds(ms),
            healthy_at: end,
            interval_ms: ms,
        }
    }
    #[test]
    fn radar_explains_repetition_and_slowdown_with_exact_references() {
        let now = Utc::now();
        let samples = (0..6)
            .map(|d| sample(now, d, if d < 3 { 20_000 } else { 5_000 }, "a"))
            .collect::<Vec<_>>();
        let signals = detect(&samples, now);
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].kind, Kind::RepeatedRepairs);
        assert_eq!(signals[0].source_runs.len(), 6);
        assert_eq!(signals[1].kind, Kind::SlowerVerification);
        assert_eq!(signals[1].baseline_median_ms, Some(5_000.0));
        assert_eq!(signals[1].recent_median_ms, Some(20_000.0));
        assert!(signals.iter().all(|s| !s.predicts_outage));
    }
    #[test]
    fn radar_excludes_rehearsal_future_stale_duplicate_and_invalid_intervals() {
        let now = Utc::now();
        let mut samples = vec![sample(now, 0, 10_000, "a"), sample(now, 1, 10_000, "a")];
        let mut rehearsal = sample(now, 2, 10_000, "a");
        rehearsal.rehearsal = true;
        samples.push(rehearsal);
        samples.push(sample(now, -1, 10_000, "a"));
        samples.push(sample(now, 31, 10_000, "a"));
        let mut invalid = sample(now, 2, 10_000, "a");
        invalid.interval_ms = 1;
        samples.push(invalid);
        let mut duplicate = sample(now, 2, 10_000, "a");
        duplicate.run = samples[0].run;
        samples.push(duplicate);
        assert!(detect(&samples, now).is_empty());
    }
    #[test]
    fn radar_requires_distinct_days_comparable_procedures_and_minimum_change() {
        let now = Utc::now();
        let samples = (0..6)
            .map(|_| sample(now, 0, 20_000, "a"))
            .collect::<Vec<_>>();
        assert!(detect(&samples, now).is_empty());
        let split = (0..6)
            .map(|d| sample(now, d, 20_000, &format!("procedure-{d}")))
            .collect::<Vec<_>>();
        assert!(detect(&split, now).is_empty());
        let ratio = (0..6)
            .map(|d| sample(now, d, if d < 3 { 15_000 } else { 10_000 }, "a"))
            .collect::<Vec<_>>();
        assert!(
            !detect(&ratio, now)
                .iter()
                .any(|s| s.kind == Kind::SlowerVerification)
        );
        let small = (0..6)
            .map(|d| sample(now, d, if d < 3 { 2_000 } else { 1_000 }, "a"))
            .collect::<Vec<_>>();
        assert!(
            !detect(&small, now)
                .iter()
                .any(|s| s.kind == Kind::SlowerVerification)
        );
    }
}
