//! Binding from isolated Hyper-V service rehearsal to an explicitly reviewed production run.
use crate::{
    execution::{ExecutionPlan, HealthCheck},
    mission::Target,
    test_lab::{HealthProbe, Journal, LabReceipt},
};
use anyhow::{Result, bail, ensure};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const LAB_PROTOCOL: &str = "Hyper-V";
pub fn lab_target(lab: &Journal) -> Result<Target> {
    let profile_id = Uuid::parse_str(&lab.id)?;
    let vm = Uuid::parse_str(&lab.vm_id)?;
    ensure!(
        !profile_id.is_nil() && !vm.is_nil(),
        "Lab und VM benötigen eindeutige Identitäten"
    );
    ensure!(
        matches!(
            lab.phase.as_str(),
            "running" | "test_passed" | "test_failed"
        ),
        "Lab muss gestartet und für eine neue Prüfung verfügbar sein"
    );
    Ok(Target {
        profile_id,
        name: lab.name.clone(),
        host: vm.to_string(),
        port: 0,
        protocol: LAB_PROTOCOL.into(),
        username: String::new(),
        domain: String::new(),
        route: "PowerShellDirect/private-switch".into(),
    })
}
pub fn valid_lab_target(t: &Target) -> bool {
    t.protocol == LAB_PROTOCOL
        && !t.profile_id.is_nil()
        && Uuid::parse_str(&t.host).is_ok_and(|id| !id.is_nil())
        && t.port == 0
        && t.username.is_empty()
        && t.domain.is_empty()
        && t.route == "PowerShellDirect/private-switch"
}
pub fn health(plan: &ExecutionPlan) -> Result<HealthProbe> {
    match &plan.health {
        HealthCheck::Http {
            port,
            tls,
            path,
            status,
            contains,
            followups,
        } => {
            let h = HealthProbe {
                url: format!(
                    "{}://{}:{port}{path}",
                    if *tls { "https" } else { "http" },
                    if *tls { "localhost" } else { "127.0.0.1" }
                ),
                expected_status: *status,
                body_marker: contains.clone(),
                followups: followups.clone(),
            };
            h.validate()?;
            Ok(h)
        }
        _ => bail!("Klonfreigabe benötigt eine HTTP- oder HTTPS-Prüfung"),
    }
}
pub fn validate(plan: &ExecutionPlan) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.mappings.iter().all(|m| valid_lab_target(&m.staging)),
        "Alle Produktionsziele benötigen eindeutig zugeordnete Hyper-V-Labs"
    );
    health(plan)?;
    Ok(())
}
pub(crate) fn check_evidence(
    plan: &ExecutionPlan,
    receipts: &[LabReceipt],
    now: DateTime<Utc>,
) -> Result<()> {
    validate(plan)?;
    ensure!(
        receipts.len() == plan.mappings.len(),
        "Für jedes Ziel wird genau ein Klonnachweis benötigt"
    );
    let hash = plan.hash()?;
    let health = health(plan)?;
    let desired = plan.desired.label();
    let mut seen = std::collections::BTreeSet::new();
    for mapping in &plan.mappings {
        let receipt = receipts
            .iter()
            .find(|r| {
                r.lab_id == mapping.staging.profile_id.to_string()
                    && r.vm_id == mapping.staging.host
            })
            .ok_or_else(|| anyhow::anyhow!("Passender Lab-/VM-Nachweis fehlt"))?;
        receipt.verify_integrity()?;
        ensure!(
            seen.insert(receipt.id),
            "Nachweis darf nicht doppelt verwendet werden"
        );
        ensure!(
            receipt.binding == hash
                && receipt.service == plan.service
                && receipt.desired_running == (desired == "Running"),
            "Nachweis gehört zu einem anderen Auftrag"
        );
        ensure!(receipt.health == health, "HTTP-Prüfung wurde geändert");
        ensure!(
            receipt.passed
                && !receipt.restored
                && receipt.after == desired
                && receipt.before != receipt.after
                && matches!(receipt.before.as_str(), "Running" | "Stopped"),
            "Kein erfolgreicher tatsächlicher Zustandswechsel im Klon nachgewiesen"
        );
        ensure!(
            receipt.started <= receipt.finished
                && receipt.finished <= now
                && (now - receipt.finished).num_seconds() <= 3600,
            "Klonnachweis fehlt, liegt in der Zukunft oder ist älter als eine Stunde"
        );
    }
    Ok(())
}
pub fn check_receipts(
    plan: &ExecutionPlan,
    references: &[String],
    now: DateTime<Utc>,
) -> Result<()> {
    ensure!(references.len() <= 32, "Zu viele Nachweise");
    let receipts = references
        .iter()
        .map(|reference| crate::test_lab::load_receipt(reference))
        .collect::<Result<Vec<_>>>()?;
    check_evidence(plan, &receipts, now)?;
    for receipt in &receipts {
        crate::equivalence::check(plan, receipt, now)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execution::Mapping, intelligence::ServiceState};
    pub fn plan() -> ExecutionPlan {
        let lab = Journal {
            id: Uuid::new_v4().to_string(),
            name: "Lab".into(),
            template: "fixture.vhdx".into(),
            directory: String::new(),
            vm_id: Uuid::new_v4().to_string(),
            switch_id: Uuid::new_v4().to_string(),
            phase: "running".into(),
            detail: String::new(),
        };
        ExecutionPlan {
            service: "Spooler".into(),
            desired: ServiceState::Running,
            health: HealthCheck::Http {
                port: 8080,
                tls: false,
                path: "/health".into(),
                status: 200,
                contains: "ready".into(),
                followups: vec![],
            },
            mappings: vec![Mapping {
                production: Target {
                    profile_id: Uuid::new_v4(),
                    name: "Production".into(),
                    host: "prod.example.invalid".into(),
                    port: 3389,
                    protocol: "RDP".into(),
                    username: String::new(),
                    domain: String::new(),
                    route: String::new(),
                },
                staging: lab_target(&lab).unwrap(),
            }],
        }
    }
    #[test]
    fn lab_plan_has_no_winrm_staging_endpoint_and_cannot_start_staging_run() {
        let plan = plan();
        assert!(validate(&plan).is_ok());
        assert_eq!(health(&plan).unwrap().url, "http://127.0.0.1:8080/health");
        assert!(crate::execution::Run::new(plan, true).is_err());
    }
    #[test]
    fn missing_proofs_and_duplicate_labs_fail_closed() {
        let mut plan = plan();
        assert!(check_receipts(&plan, &[], Utc::now()).is_err());
        let mut second = plan.mappings[0].clone();
        second.production.host = "second.example.invalid".into();
        second.production.profile_id = Uuid::new_v4();
        plan.mappings.push(second);
        assert!(validate(&plan).is_err());
    }
    #[test]
    fn https_preserves_health_semantics_with_guest_certificate_validation() {
        let mut plan = plan();
        if let HealthCheck::Http { tls, .. } = &mut plan.health {
            *tls = true;
        }
        let probe = health(&plan).unwrap();
        assert_eq!(probe.url, "https://localhost:8080/health");
        assert_eq!(probe.expected_status, 200);
        assert_eq!(probe.body_marker, "ready");
        assert!(validate(&plan).is_ok());
    }
    #[test]
    fn changed_target_health_and_lab_change_approval_digest() {
        let plan = plan();
        let digest = plan.hash().unwrap();
        for kind in 0..3 {
            let mut changed = plan.clone();
            match kind {
                0 => changed.mappings[0].production.host = "elsewhere.example.invalid".into(),
                1 => changed.mappings[0].staging.host = Uuid::new_v4().to_string(),
                _ => changed.service = "Other".into(),
            };
            assert_ne!(changed.hash().unwrap(), digest);
        }
    }
    #[test]
    fn followup_assertions_are_bounded_and_invalidate_existing_proof() {
        let base = plan();
        let mut changed = base.clone();
        if let HealthCheck::Http { followups, .. } = &mut changed.health {
            followups.push(crate::execution::HttpGetStep {
                path: "/ready".into(),
                status: 201,
                contains: "ready".into(),
                options: Default::default(),
            });
        }
        assert!(validate(&changed).is_ok());
        assert_ne!(base.hash().unwrap(), changed.hash().unwrap());
        assert_eq!(health(&changed).unwrap().followups.len(), 1);
        assert!(check_evidence(&changed, &[receipt(&base, Utc::now())], Utc::now()).is_err());
        if let HealthCheck::Http { followups, .. } = &mut changed.health {
            followups[0].path = "//evil.invalid/".into();
        }
        assert!(validate(&changed).is_err());
        if let HealthCheck::Http { followups, .. } = &mut changed.health {
            followups[0].path = "/ready".into();
            let step = followups[0].clone();
            *followups = vec![step; 4];
        }
        assert!(validate(&changed).is_err());
    }
    fn seal(mut r: LabReceipt) -> LabReceipt {
        use sha2::{Digest, Sha256};
        r.proof_hash.clear();
        r.proof_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&r).unwrap()));
        r
    }
    fn receipt(plan: &ExecutionPlan, now: DateTime<Utc>) -> LabReceipt {
        seal(LabReceipt {
            id: Uuid::new_v4(),
            lab_id: plan.mappings[0].staging.profile_id.to_string(),
            vm_id: plan.mappings[0].staging.host.clone(),
            binding: plan.hash().unwrap(),
            service: plan.service.clone(),
            desired_running: true,
            health: health(plan).unwrap(),
            started: now - chrono::Duration::seconds(20),
            finished: now,
            before: "Stopped".into(),
            after: "Running".into(),
            passed: true,
            restored: false,
            proof_hash: String::new(),
        })
    }
    #[test]
    fn fresh_evidence_authorizes_only_exact_plan_and_transition() {
        let plan = plan();
        let now = Utc::now();
        let proof = receipt(&plan, now);
        assert!(check_evidence(&plan, &[proof.clone()], now).is_ok());
        for kind in 0..7 {
            let mut changed = proof.clone();
            match kind {
                0 => changed.finished = now - chrono::Duration::hours(2),
                1 => changed.finished = now + chrono::Duration::seconds(1),
                2 => changed.binding = "0".repeat(64),
                3 => changed.before = "Running".into(),
                4 => changed.restored = true,
                5 => changed.health.expected_status = 201,
                _ => changed.vm_id = Uuid::new_v4().to_string(),
            };
            let changed = seal(changed);
            assert!(
                check_evidence(&plan, &[changed], now).is_err(),
                "kind {kind}"
            );
        }
        let mut changed = plan.clone();
        if let HealthCheck::Http { contains, .. } = &mut changed.health {
            *contains = "different".into()
        };
        assert!(check_evidence(&changed, &[proof], now).is_err());
    }
    #[test]
    fn persisted_proof_is_reloaded_before_production_and_restart_never_replays() {
        use crate::security::{atomic_write, protect_secret};
        let plan = plan();
        let now = Utc::now();
        let proof = receipt(&plan, now);
        let dir = crate::test_lab::root().unwrap().join(&proof.lab_id);
        std::fs::create_dir_all(dir.join("receipts")).unwrap();
        let lab = Journal {
            id: proof.lab_id.clone(),
            name: format!("Relayne-Lab-{}", proof.lab_id),
            template: "fixture.vhdx".into(),
            directory: dir.to_string_lossy().into(),
            vm_id: proof.vm_id.clone(),
            switch_id: Uuid::new_v4().to_string(),
            phase: "test_passed".into(),
            detail: String::new(),
        };
        let save = |path: &std::path::Path, bytes: Vec<u8>| {
            atomic_write(path, &protect_secret(&bytes).unwrap()).unwrap()
        };
        save(
            &dir.join("journal.dpapi"),
            serde_json::to_vec(&lab).unwrap(),
        );
        let receipt_path = dir.join("receipts").join(format!("{}.dpapi", proof.id));
        save(&receipt_path, serde_json::to_vec(&proof).unwrap());
        save(&dir.join("receipts").join(format!("{}.pending.dpapi",proof.id)),serde_json::to_vec(&serde_json::json!({"id":proof.id,"lab_id":proof.lab_id,"vm_id":proof.vm_id,"binding":proof.binding,"service":proof.service,"desired_running":proof.desired_running,"health":proof.health,"started":proof.started})).unwrap());
        let refs = vec![proof.reference()];
        assert!(
            check_receipts(&plan, &refs, now).is_err(),
            "Checkbox and receipt alone cannot prove equivalence"
        );
        crate::equivalence::tests::save_fixture(&plan, &proof);
        assert!(check_receipts(&plan, &refs, now).is_ok());
        let mut run = crate::execution::Run::new(plan.clone(), false).unwrap();
        run.lab_receipts = refs.clone();
        let journal = crate::execution::Journal { runs: vec![run] };
        let path = dir.join("production.dpapi");
        journal.save(&path).unwrap();
        let resumed = crate::execution::Journal::load(&path).unwrap();
        assert_eq!(
            resumed.runs[0].targets[0].phase,
            crate::execution::Phase::Unknown
        );
        assert_eq!(resumed.runs[0].lab_receipts, refs);
        let mut cleaned = lab;
        cleaned.phase = "cleaned".into();
        cleaned.vm_id.clear();
        cleaned.switch_id.clear();
        save(
            &dir.join("journal.dpapi"),
            serde_json::to_vec(&cleaned).unwrap(),
        );
        assert!(
            check_receipts(&plan, &refs, now).is_ok(),
            "Aufräumen darf einen unveränderlichen historischen Nachweis nicht verwerfen"
        );
        assert!(check_receipts(&plan, &refs, now + chrono::Duration::seconds(3601)).is_err());
        let mut altered = proof;
        altered.service = "tampered".into();
        save(&receipt_path, serde_json::to_vec(&altered).unwrap());
        assert!(check_receipts(&plan, &refs, now).is_err());
    }
}
