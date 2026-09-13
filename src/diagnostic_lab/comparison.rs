//! Fixed, in-memory development fixtures. Never connects to a target or stores evidence.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Outcome {
    ModelMatch(Probe),
    ModelGap,
    InsufficientEvidence,
}

impl Outcome {
    pub fn label(self) -> String {
        match self {
            Self::ModelMatch(probe) => format!("Modell passt: {}", probe.cause()),
            Self::ModelGap => "Modelllücke / Widerspruch".into(),
            Self::InsufficientEvidence => "Datenlage unzureichend".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Step {
    pub probe: Probe,
    pub value: Value,
    pub distinguished_pairs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    pub scenario: Scenario,
    pub expected: Outcome,
    pub actual: Outcome,
    pub steps: Vec<Step>,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub kind: &'static str,
    pub model_version: &'static str,
    pub generated_at: DateTime<Utc>,
    pub simulation_only: bool,
    pub not_a_causal_or_repair_proof: bool,
    pub rows: Vec<Row>,
}

impl Report {
    pub fn passed(&self) -> usize {
        self.rows.iter().filter(|r| r.passed).count()
    }
}

fn outcome(a: &Assessment) -> Outcome {
    let compatible = a.compatible();
    if compatible.is_empty() {
        Outcome::ModelGap
    } else if compatible.len() == 1 && a.known == Probe::ALL.len() {
        Outcome::ModelMatch(compatible[0].cause)
    } else {
        Outcome::InsufficientEvidence
    }
}

/// The clock is fixed throughout each bounded run so fixture evidence cannot age mid-run.
pub fn run(now: DateTime<Utc>) -> Result<Report> {
    let mut rows = Vec::new();
    for scenario in Scenario::ALL {
        let expected = match scenario {
            Scenario::Service => Outcome::ModelMatch(Probe::Service),
            Scenario::Dns => Outcome::ModelMatch(Probe::Dns),
            Scenario::Tls => Outcome::ModelMatch(Probe::Tls),
            Scenario::Dependency => Outcome::ModelMatch(Probe::Dependency),
            Scenario::Multiple | Scenario::Healthy => Outcome::ModelGap,
            Scenario::Unavailable => Outcome::InsufficientEvidence,
        };
        let mut case = Case::new(
            Config {
                mode: Mode::Simulation,
                scenario: Some(scenario),
                target: None,
                incident: "Fester Dev-Szenariovergleich".into(),
                service: "ExampleService".into(),
                application: "https://app.example.invalid/".into(),
                dependency: "https://dependency.example.invalid/health".into(),
            },
            now,
        )?;
        let mut steps = Vec::new();
        for _ in 0..12 {
            let assessment = case.assess(now);
            let Some(probe) = assessment.next else { break };
            case.simulate(probe, now)?;
            steps.push(Step {
                probe,
                value: case
                    .observations
                    .last()
                    .context("Simulation ohne Ergebnis")?
                    .value,
                distinguished_pairs: assessment.pairs,
            });
        }
        let assessment = case.assess(now);
        ensure!(
            assessment.next.is_none(),
            "Szenario überschreitet das Prüflimit"
        );
        let actual = outcome(&assessment);
        rows.push(Row {
            scenario,
            expected,
            actual,
            steps,
            passed: expected == actual,
        });
    }
    Ok(Report {
        kind: "diagnostic-dev-scenario-comparison",
        model_version: "single-dominant-fault-v1",
        generated_at: now,
        simulation_only: true,
        not_a_causal_or_repair_proof: true,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_checks_all_expected_outcomes_and_attempt_limits() {
        let report = run(Utc::now()).unwrap();
        assert_eq!(report.rows.len(), 7);
        assert_eq!(report.passed(), 7);
        for row in &report.rows[..4] {
            assert_eq!(row.steps.len(), 4);
            assert_eq!(
                row.steps.iter().filter(|s| s.value == Value::Fail).count(),
                1
            );
        }
        assert_eq!(report.rows[4].actual, Outcome::ModelGap);
        assert_eq!(report.rows[4].steps.len(), 2);
        assert_eq!(report.rows[5].actual, Outcome::ModelGap);
        assert_eq!(report.rows[5].steps.len(), 4);
        let missing = &report.rows[6];
        assert_eq!(missing.actual, Outcome::InsufficientEvidence);
        assert_eq!(missing.steps.len(), 12);
        for probe in Probe::ALL {
            assert_eq!(missing.steps.iter().filter(|s| s.probe == probe).count(), 3);
        }
    }

    #[test]
    fn comparison_is_reproducible_and_export_has_no_target_or_case_evidence() {
        let now = Utc::now();
        let first = run(now).unwrap();
        let second = run(now + chrono::Duration::days(1)).unwrap();
        assert_eq!(first.rows, second.rows);
        let json = serde_json::to_value(first).unwrap();
        assert_eq!(json["simulation_only"], true);
        assert_eq!(json["not_a_causal_or_repair_proof"], true);
        assert!(json.get("target").is_none());
        assert!(json.get("cases").is_none());
        assert_eq!(json["rows"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn comparison_does_not_call_a_partial_match_complete() {
        let assessment = Assessment {
            candidates: vec![Candidate {
                cause: Probe::Dns,
                supports: vec![Probe::Dns],
                contradicts: vec![],
                missing: vec![Probe::Service, Probe::Tls, Probe::Dependency],
            }],
            next: Some(Probe::Service),
            pairs: 0,
            known: 1,
        };
        assert_eq!(outcome(&assessment), Outcome::InsufficientEvidence);
    }
}
