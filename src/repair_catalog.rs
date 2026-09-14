//! Local curated compatibility catalog. Environment similarity is never execution approval.
use crate::{
    recovery_contracts::{Contract, Readiness},
    workflow::{Action, WinOperation},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
const LIMIT: usize = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: uuid::Uuid,
    pub signed_package: String,
    pub contract: uuid::Uuid,
    pub plan_hash: String,
    pub fingerprints: Vec<crate::equivalence::Fingerprint>,
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub entries: Vec<Entry>,
    #[serde(skip)]
    source: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Compatibility {
    Verified,
    Changed,
    Unknown,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
/// Verify exact supported workflow semantics against the actually rehearsed service/HTTP plan.
pub fn matches_plan(package: &crate::workflow::Package, c: &Contract) -> Result<()> {
    ensure!(
        c.plan.mappings.len() == 1,
        "The catalog supports one unambiguous target mapping per package"
    );
    let host = &c.plan.mappings[0].production.host;
    let same = |t: &crate::workflow::Target| {
        t.host.eq_ignore_ascii_case(host) && t.port == 5985 && t.user.is_empty()
    };
    ensure!(
        package.plan.restore.is_empty() && package.plan.steps.len() == 1,
        "The package must contain exactly one bound service operation and no additional restore steps"
    );
    for s in &package.plan.preconditions {
        ensure!(
            matches!(&s.action,Action::WinRm{target,operation:WinOperation::Inventory|WinOperation::Services|WinOperation::Processes|WinOperation::Events,..} if same(target)),
            "The package prerequisite is not read-only or has a different binding"
        );
    }
    let restart = serde_json::to_value(&c.plan)?["restart"].as_bool() == Some(true);
    let valid = match &package.plan.steps[0].action {
        Action::WinRm {
            target,
            operation: WinOperation::Start { service },
            ..
        } => {
            same(target)
                && service == &c.plan.service
                && !restart
                && c.plan.desired == crate::intelligence::ServiceState::Running
        }
        Action::WinRm {
            target,
            operation: WinOperation::Restart { service },
            ..
        } => same(target) && service == &c.plan.service && restart,
        Action::WinRm {
            target,
            operation: WinOperation::Stop { service },
            ..
        } => {
            same(target)
                && service == &c.plan.service
                && !restart
                && c.plan.desired == crate::intelligence::ServiceState::Stopped
        }
        _ => false,
    };
    ensure!(
        valid,
        "The package operation does not match the rehearsed service change"
    );
    let crate::execution::HealthCheck::Http {
        port,
        tls,
        path,
        status,
        contains,
        followups,
    } = &c.plan.health
    else {
        anyhow::bail!("HTTP evidence is required")
    };
    let mut checks = vec![(path, *status, contains)];
    for step in followups {
        ensure!(
            step.options == Default::default(),
            "Catalog evidence requires public GET checks"
        );
        checks.push((&step.path, step.status, &step.contains));
    }
    ensure!(
        package.plan.verification.len() == checks.len(),
        "Package checks do not match clone evidence"
    );
    let target = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    for (step, (path, status, contains)) in package.plan.verification.iter().zip(checks) {
        let expected = format!(
            "{}://{}:{}{}",
            if *tls { "https" } else { "http" },
            target,
            port,
            path
        );
        ensure!(
            matches!(&step.action,Action::Http{url,method:crate::workflow::HttpMethod::Get,form,secret_fields,status:s,body_contains,json_equals} if url==&expected && *s==status && form.is_empty()&&secret_fields.is_empty()&&json_equals.is_empty()&&body_contains.as_deref().unwrap_or_default()==contains),
            "The package HTTP check differs from the actual evidence"
        );
    }
    Ok(())
}
impl Entry {
    pub fn create(
        signed: String,
        c: &Contract,
        trust: &crate::package_trust::TrustStore,
    ) -> Result<Self> {
        let p = trust.verify(&signed)?;
        matches_plan(&p, c)?;
        ensure!(
            c.readiness(chrono::Utc::now()) == Readiness::Ready,
            "The recovery plan is not current"
        );
        crate::promotion::check_receipts(&c.plan, &c.references, chrono::Utc::now())?;
        let baseline =
            crate::equivalence::rehearsal_baseline(&c.plan, &c.references, chrono::Utc::now())?;
        Ok(Self {
            id: uuid::Uuid::new_v4(),
            signed_package: signed,
            contract: c.id,
            plan_hash: c.plan.hash()?,
            fingerprints: baseline.fingerprints,
            recorded_at: chrono::Utc::now(),
        })
    }
    pub fn compatibility(
        &self,
        c: Option<&Contract>,
        trust: &crate::package_trust::TrustStore,
    ) -> Compatibility {
        let Ok(p) = trust.verify(&self.signed_package) else {
            return Compatibility::Unknown;
        };
        let Some(c) = c else {
            return Compatibility::Unknown;
        };
        if c.id != self.contract
            || c.plan.hash().ok().as_ref() != Some(&self.plan_hash)
            || matches_plan(&p, c).is_err()
        {
            return Compatibility::Changed;
        }
        if c.invalidated.is_some() {
            return Compatibility::Changed;
        }
        if c.readiness(chrono::Utc::now()) != Readiness::Ready {
            return Compatibility::Unknown;
        }
        let current = c
            .last_check
            .as_ref()
            .filter(|v| v.error.is_none())
            .map(|v| &v.fingerprints)
            .unwrap_or(&c.baseline.fingerprints);
        if current != &self.fingerprints {
            Compatibility::Changed
        } else {
            Compatibility::Verified
        }
    }
}
impl Catalog {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match read(path) {
            Ok(b) => b,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(Self::default());
            }
            Err(e) => return Err(e),
        };
        let clear = crate::security::unprotect_secret(&bytes)?;
        ensure!(clear.len() <= LIMIT, "Catalog too large");
        let mut c: Self = serde_json::from_slice(&clear)?;
        c.validate()?;
        c.source = Some(digest(&bytes));
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.entries.len() <= 64, "At most 64 catalog entries are allowed");
        let mut ids = std::collections::BTreeSet::new();
        for e in &self.entries {
            ensure!(
                ids.insert(e.id)
                    && !e.id.is_nil()
                    && e.signed_package.len() <= 512 * 1024
                    && e.plan_hash.len() == 64
                    && e.fingerprints.len() == 1,
                "Invalid catalog entry"
            );
            for fp in &e.fingerprints {
                fp.validate()?;
            }
        }
        Ok(())
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        #[cfg(windows)]
        let _lock = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .share_mode(0)
                .open(path.with_extension("lock"))?
        };
        let current = match read(path) {
            Ok(bytes) => Some(digest(&bytes)),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        ensure!(
            current == self.source,
            "The catalog changed concurrently; reload it"
        );
        let raw = serde_json::to_vec(self)?;
        ensure!(raw.len() <= LIMIT, "Catalog too large");
        let enc = crate::security::protect_secret(&raw)?;
        ensure!(enc.len() <= LIMIT, "Catalog too large");
        crate::security::atomic_write(path, &enc)?;
        self.source = Some(digest(&enc));
        Ok(())
    }
}
fn read(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut b = vec![];
    std::fs::File::open(path)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut b)?;
    ensure!(b.len() <= LIMIT, "Catalog too large");
    Ok(b)
}
/// Produce an inert package candidate directly from a supported proved plan; signing is explicit.
pub fn candidate(c: &Contract) -> Result<crate::workflow::Package> {
    ensure!(
        c.plan.mappings.len() == 1,
        "One target is required per catalog package"
    );
    let host = c.plan.mappings[0].production.host.clone();
    let restart = serde_json::to_value(&c.plan)?["restart"].as_bool() == Some(true);
    let op = if restart {
        WinOperation::Restart {
            service: c.plan.service.clone(),
        }
    } else if c.plan.desired == crate::intelligence::ServiceState::Running {
        WinOperation::Start {
            service: c.plan.service.clone(),
        }
    } else {
        WinOperation::Stop {
            service: c.plan.service.clone(),
        }
    };
    let crate::execution::HealthCheck::Http {
        port,
        tls,
        path,
        status,
        contains,
        followups,
    } = &c.plan.health
    else {
        anyhow::bail!("HTTP is required")
    };
    let mut checks = vec![(path, *status, contains)];
    for s in followups {
        ensure!(
            s.options == Default::default(),
            "Only public GET requests are allowed in the catalog"
        );
        checks.push((&s.path, s.status, &s.contains));
    }
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let verification = checks
        .into_iter()
        .enumerate()
        .map(|(i, (path, status, contains))| crate::workflow::Step {
            name: format!("Anwendungstest {}", i + 1),
            action: Action::Http {
                url: format!("{}://{h}:{port}{path}", if *tls { "https" } else { "http" }),
                method: crate::workflow::HttpMethod::Get,
                form: Default::default(),
                secret_fields: Default::default(),
                status,
                body_contains: Some(contains.clone()),
                json_equals: Default::default(),
            },
        })
        .collect();
    let p = crate::workflow::Package::new(
        crate::workflow::Plan {
            name: c.name.clone(),
            preconditions: vec![],
            steps: vec![crate::workflow::Step {
                name: "Geprobte Dienstoperation".into(),
                action: Action::WinRm {
                    target: crate::workflow::Target {
                        host,
                        user: String::new(),
                        port: 5985,
                    },
                    operation: op,
                    stdout_contains: c.plan.desired.label().into(),
                },
            }],
            verification,
            restore: vec![],
        },
        format!("Recovery contract {}", c.id),
    )
    .map_err(anyhow::Error::msg)?;
    matches_plan(&p, c)?;
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn contract() -> Contract {
        let fp = crate::equivalence::Fingerprint {
            os_version: "10".into(),
            os_build: "20348".into(),
            architecture: "64".into(),
            executable_hash: "a".repeat(64),
            executable_version: "1".into(),
            configuration_hash: "b".repeat(64),
            start_mode: "Auto".into(),
            dependencies: vec![],
        };
        Contract::new(
            "Test".into(),
            crate::promotion::tests::plan(),
            vec!["fixture".into()],
            crate::equivalence::RehearsalBaseline {
                observed_at: chrono::Utc::now() - chrono::Duration::minutes(1),
                rehearsed_at: chrono::Utc::now(),
                fingerprints: vec![fp],
            },
            chrono::Utc::now(),
        )
        .unwrap()
    }
    #[test]
    fn catalog_store_rejects_unreadable_and_concurrent_updates() {
        let path = std::env::temp_dir().join(format!("catalog-{}.dpapi", uuid::Uuid::new_v4()));
        let mut first = Catalog::load(&path).unwrap();
        first.save(&path).unwrap();
        let mut stale = Catalog::load(&path).unwrap();
        first.save(&path).unwrap();
        assert!(stale.save(&path).is_err());
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(Catalog::load(&path).is_err());
        assert!(first.save(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn catalog_matching_requires_current_trust_and_exact_fingerprints() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use ring::signature::KeyPair;
        let c = contract();
        let package = candidate(&c).unwrap().export().unwrap();
        let pk = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap();
        let mut msg = b"Relayne signed repair package v1\0".to_vec();
        msg.extend(package.as_bytes());
        let bundle = crate::package_trust::SignedPackage {
            schema: 1,
            public_key: STANDARD.encode(pair.public_key().as_ref()),
            signature: STANDARD.encode(pair.sign(&msg).as_ref()),
            package,
        };
        let entry = Entry {
            id: uuid::Uuid::new_v4(),
            signed_package: serde_json::to_string(&bundle).unwrap(),
            contract: c.id,
            plan_hash: c.plan.hash().unwrap(),
            fingerprints: c.baseline.fingerprints.clone(),
            recorded_at: chrono::Utc::now(),
        };
        let mut trust = crate::package_trust::TrustStore::default();
        assert_eq!(
            entry.compatibility(Some(&c), &trust),
            Compatibility::Unknown
        );
        trust.enroll(&bundle.public_key).unwrap();
        assert_eq!(
            entry.compatibility(Some(&c), &trust),
            Compatibility::Verified
        );
        let mut changed = c.clone();
        changed.baseline.fingerprints[0].os_build = "new".into();
        assert_eq!(
            entry.compatibility(Some(&changed), &trust),
            Compatibility::Changed
        );
        let mut expired = c.clone();
        expired.baseline.observed_at = chrono::Utc::now() - chrono::Duration::hours(2);
        assert_eq!(
            entry.compatibility(Some(&expired), &trust),
            Compatibility::Unknown
        );
        assert_eq!(entry.compatibility(None, &trust), Compatibility::Unknown);
    }
    #[test]
    fn catalog_candidate_matches_exact_rehearsal_semantics() {
        let c = contract();
        let mut p = candidate(&c).unwrap();
        matches_plan(&p, &c).unwrap();
        if let Action::WinRm { target, .. } = &mut p.plan.steps[0].action {
            target.host = "other.invalid".into();
        }
        assert!(matches_plan(&p, &c).is_err());
    }
    #[test]
    fn catalog_rejects_extra_actions_or_weakened_assertions() {
        let c = contract();
        let mut p = candidate(&c).unwrap();
        p.plan.steps.push(p.plan.steps[0].clone());
        assert!(matches_plan(&p, &c).is_err());
        let mut p = candidate(&c).unwrap();
        p.plan.verification.clear();
        assert!(matches_plan(&p, &c).is_err());
    }
}
