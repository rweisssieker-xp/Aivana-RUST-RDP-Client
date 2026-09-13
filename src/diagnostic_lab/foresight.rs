//! Counterfactual outcomes only; no observations or executable requests leave this module.
use super::*;

#[derive(Clone, Debug)]
pub struct Branch {
    pub assumed: Value,
    pub compatible: Vec<Probe>,
    pub known: usize,
    pub next: Option<Probe>,
    pub conclusion: &'static str,
}

impl Case {
    /// Apply each possible value to an ephemeral copy, respecting current freshness
    /// and attempt limits. The original case is borrowed immutably and never saved.
    pub fn preview(&self, probe: Probe, now: DateTime<Utc>) -> Result<Vec<Branch>> {
        let request = self.request(probe, now)?;
        [Value::Pass, Value::Fail, Value::Unknown]
            .into_iter()
            .map(|assumed| {
                let mut hypothetical = self.clone();
                hypothetical.record(&request, assumed, now)?;
                let assessment = hypothetical.assess(now);
                Ok(Branch {
                    assumed,
                    compatible: assessment.compatible().iter().map(|c| c.cause).collect(),
                    known: assessment.known,
                    next: assessment.next,
                    conclusion: assessment.conclusion(),
                })
            })
            .collect()
    }
}
