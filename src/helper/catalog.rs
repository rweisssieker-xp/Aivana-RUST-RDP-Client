//! Trusted recipes and inert proposal review. No dispatch or approval API is reachable here.
use super::{
    case::{Comparator, HelperCase, SuccessCriterion},
    evidence::{Eligibility, EvidenceEnvelope},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use crate::helper_action::{
    self, CriterionComparator, CriterionRequirement, Digest, RequiredCheck, RestorationSpec,
    SqlAction, SqlEngine, VerificationSpec, VerifiedSqlMetadata,
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::path::Path;
use uuid::Uuid;

const RECIPE_DOMAIN: &[u8] = b"relayne-helper-recipe-v1";
const REVIEW_DOMAIN: &[u8] = b"relayne-helper-proposal-review-v1";

fn criterion_matches(requirement: &CriterionRequirement, criterion: &SuccessCriterion) -> bool {
    criterion.complete()
        && requirement.measure == criterion.measure
        && requirement.comparator
            == match criterion.comparator {
                Comparator::AtMost => CriterionComparator::AtMost,
                Comparator::AtLeast => CriterionComparator::AtLeast,
                Comparator::Equal => CriterionComparator::Equal,
            }
        && requirement.threshold_bits == criterion.threshold.to_bits()
        && requirement.unit == criterion.unit
        && requirement.window == criterion.window
}

fn check_gaps(
    case: &HelperCase,
    verification: &VerificationSpec,
    object: &helper_action::VerifiedSqlObject,
) -> Vec<String> {
    let mut gaps = Vec::new();
    let criteria = case
        .intake()
        .success_criteria
        .iter()
        .filter(|c| c.reviewed)
        .collect::<Vec<_>>();
    if criteria.len() != verification.criteria.len()
        || !criteria.iter().all(|c| c.complete())
        || !verification
            .criteria
            .iter()
            .all(|r| criteria.iter().filter(|c| criterion_matches(r, c)).count() == 1)
        || !criteria.iter().all(|c| {
            verification
                .criteria
                .iter()
                .filter(|r| criterion_matches(r, c))
                .count()
                == 1
        })
    {
        gaps.push("Signed check criteria differ from current reviewed case criteria".into());
    }
    for check in &verification.checks {
        match check {
            RequiredCheck::SqlFunctional {
                scope_sha256,
                object_id,
                ..
            } => {
                if scope_sha256 != &object.scope_sha256 || object_id != &object.object_id {
                    gaps.push("SQL functional check targets another change object".into());
                }
            }
            RequiredCheck::HttpFunctional { scope_sha256, .. } => {
                if !case.scopes().iter().any(|s| {
                    matches!(s, BoundScope::Http { .. })
                        && s.digest().ok().as_deref() == Some(scope_sha256)
                }) {
                    gaps.push("HTTP functional check lacks its current reviewed scope".into());
                }
            }
            RequiredCheck::Performance {
                scope_sha256,
                object_id,
                workload_sha256,
                ..
            } => {
                let same_resource = case.scopes().iter().any(|s| {
                    matches!(s, BoundScope::Database { .. })
                        && s.digest().ok().as_deref() == Some(scope_sha256)
                        && s.resource_digest().ok()
                            == case
                                .scopes()
                                .iter()
                                .find(|change| {
                                    change.digest().ok().as_deref()
                                        == Some(object.scope_sha256.as_str())
                                })
                                .and_then(|change| change.resource_digest().ok())
                });
                let plan_step = case.plan().is_some_and(|p| p.steps.iter().any(|step| {
                    step.scope_sha256 == *scope_sha256
                && matches!(&step.params, super::manifest::ProbeParams::SqlWorkload { workload_digest, .. } if workload_digest == workload_sha256)
                        && matches!(step.capability_id, super::manifest::CapabilityId::SqlWorkloadBaseline | super::manifest::CapabilityId::SqlWorkloadRehearsal)
                }));
                if object_id != &object.object_id || !same_resource || !plan_step {
                    gaps.push(
                        "Performance check lacks the current same-object workload plan".into(),
                    );
                }
            }
        }
    }
    gaps
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CatalogAction {
    /// Reference only; the existing signed-package/v1 service path retains execution authority.
    ExistingServiceRecipe {
        catalog_entry_id: Uuid,
        signed_package_sha256: Digest,
    },
    Sql {
        action: SqlAction,
        metadata: VerifiedSqlMetadata,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prerequisite {
    FreshLiveMetadata,
    CurrentChangeCredential,
    TableAlterPrivilege,
    IndexOwnershipMarkerPrivilege,
    ReviewedFunctionalCheck,
    ReviewedPerformanceCheck,
    IsolatedRehearsal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBody {
    pub version: u16,
    pub action_version: u16,
    pub id: Uuid,
    pub revision: u64,
    pub problem_family: String,
    pub action: CatalogAction,
    pub prerequisites: Vec<Prerequisite>,
    pub verification: VerificationSpec,
    pub restoration: RestorationSpec,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub body: RecipeBody,
    /// Explicitly enrolled Ed25519 publisher key and signature over the entire typed body.
    pub publisher_key: String,
    pub signature: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Default)]
pub struct CatalogTrust {
    pub enrolled_keys: Vec<String>,
    source_digest: Option<[u8; 32]>,
}

fn protected_digest(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}
fn protected_bytes(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            ensure!(bytes.len() <= limit, "Protected recipe file too large");
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn protected_lock(path: &Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

impl CatalogTrust {
    pub fn enroll(&mut self, public_key: &str) -> Result<String> {
        let bytes = STANDARD.decode(public_key.trim())?;
        ensure!(bytes.len() == 32, "Recipe publisher key must be Ed25519");
        let canonical = STANDARD.encode(&bytes);
        ensure!(
            !self.enrolled_keys.contains(&canonical),
            "Publisher already enrolled"
        );
        ensure!(
            self.enrolled_keys.len() < 128,
            "Recipe publisher capacity reached"
        );
        self.enrolled_keys.push(canonical);
        self.validate()?;
        Ok(format!("{:x}", sha2::Sha256::digest(&bytes)))
    }
    pub fn load_protected(path: &std::path::Path) -> Result<Self> {
        let Some(bytes) = protected_bytes(path, 32 * 1024)? else {
            return Ok(Self::default());
        };
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            schema: u16,
            enrolled_keys: Vec<String>,
        }
        let saved: Saved = serde_json::from_slice(&crate::security::unprotect_secret(&bytes)?)?;
        ensure!(saved.schema == 1, "Unsupported recipe trust schema");
        let trust = Self {
            enrolled_keys: saved.enrolled_keys,
            source_digest: Some(protected_digest(&bytes)),
        };
        trust.validate()?;
        Ok(trust)
    }
    pub fn save_protected(&self, path: &std::path::Path) -> Result<()> {
        self.validate()?;
        #[derive(Serialize)]
        struct Saved<'a> {
            schema: u16,
            enrolled_keys: &'a [String],
        }
        let clear = serde_json::to_vec(&Saved {
            schema: 1,
            enrolled_keys: &self.enrolled_keys,
        })?;
        ensure!(clear.len() <= 32 * 1024, "Recipe trust store too large");
        let _guard = protected_lock(path)?;
        ensure!(
            protected_bytes(path, 32 * 1024)?
                .as_deref()
                .map(protected_digest)
                == self.source_digest,
            "Recipe trust changed concurrently; reload"
        );
        crate::security::atomic_write(path, &crate::security::protect_secret(&clear)?)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.enrolled_keys.len() <= 128,
            "Too many trusted recipe publishers"
        );
        let mut unique = std::collections::BTreeSet::new();
        for key in &self.enrolled_keys {
            ensure!(
                STANDARD.decode(key)?.len() == 32 && unique.insert(key),
                "Invalid or duplicate recipe publisher key"
            );
        }
        Ok(())
    }
}

impl CatalogEntry {
    pub fn validate(&self) -> Result<()> {
        let b = &self.body;
        ensure!(
            b.version == 1
                && b.action_version == helper_action::SQL_ACTION_VERSION
                && !b.id.is_nil()
                && b.revision > 0,
            "Unknown or invalid recipe version"
        );
        ensure!(
            !b.problem_family.trim().is_empty()
                && b.problem_family.len() <= 128
                && !b.problem_family.chars().any(char::is_control),
            "Invalid problem family"
        );
        ensure!(
            !self.provenance.trim().is_empty()
                && self.provenance.len() <= 256
                && !self.provenance.chars().any(char::is_control),
            "Missing recipe provenance"
        );
        ensure!(
            b.issued_at < b.expires_at && b.expires_at - b.issued_at <= Duration::days(365),
            "Invalid recipe validity window"
        );
        ensure!(
            !b.prerequisites.is_empty() && b.prerequisites.len() <= 12,
            "Missing/oversized prerequisites"
        );
        ensure!(
            b.prerequisites
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == b.prerequisites.len(),
            "Duplicate prerequisites"
        );
        b.verification.validate()?;
        match &b.action {
            CatalogAction::Sql { action, metadata } => {
                action.validate(metadata)?;
                b.restoration.validate_for(action)?;
                for required in [
                    Prerequisite::FreshLiveMetadata,
                    Prerequisite::CurrentChangeCredential,
                    Prerequisite::TableAlterPrivilege,
                    Prerequisite::ReviewedFunctionalCheck,
                    Prerequisite::ReviewedPerformanceCheck,
                    Prerequisite::IsolatedRehearsal,
                ] {
                    ensure!(
                        b.prerequisites.contains(&required),
                        "Missing SQL prerequisite"
                    );
                }
                if !action.is_statistics() {
                    ensure!(
                        b.prerequisites
                            .contains(&Prerequisite::IndexOwnershipMarkerPrivilege),
                        "Missing index-marker privilege prerequisite"
                    );
                }
            }
            CatalogAction::ExistingServiceRecipe {
                catalog_entry_id,
                signed_package_sha256,
            } => {
                ensure!(
                    !catalog_entry_id.is_nil()
                        && helper_action::valid_digest(signed_package_sha256),
                    "Invalid existing service reference"
                );
                // Service restoration and execution continue through its original contract.
            }
        }
        ensure!(
            STANDARD.decode(&self.publisher_key)?.len() == 32
                && STANDARD.decode(&self.signature)?.len() == 64,
            "Invalid recipe signature encoding"
        );
        Ok(())
    }
    pub fn verify(&self, trust: &CatalogTrust) -> Result<()> {
        self.validate()?;
        trust.validate()?;
        ensure!(
            trust.enrolled_keys.contains(&self.publisher_key),
            "Publisher is not trusted"
        );
        let signature = STANDARD.decode(&self.signature)?;
        let key = STANDARD.decode(&self.publisher_key)?;
        let bytes = recipe_bytes(&self.body, &self.provenance)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(&bytes, &signature)
            .map_err(|_| anyhow::anyhow!("Invalid recipe signature"))
    }
    pub fn identity(&self) -> Result<Digest> {
        self.validate()?;
        helper_action::digest(b"relayne-helper-recipe-identity-v1", self)
    }
}

fn recipe_bytes(body: &RecipeBody, provenance: &str) -> Result<Vec<u8>> {
    let mut bytes = RECIPE_DOMAIN.to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(&(body, provenance))?);
    Ok(bytes)
}

/// A fresh, explicitly enrolled lab publisher for the ignored guest fixture only.
/// Admission still verifies the ordinary protected trust and signed catalog entry.
#[cfg(test)]
pub(crate) fn guest_sign_lab_recipe(body: RecipeBody) -> Result<CatalogEntry> {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("Guest lab recipe key generation failed"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("Guest lab recipe key invalid"))?;
    let provenance = "ActorTest: isolated Task 15 guest fixture".to_owned();
    let entry = CatalogEntry {
        publisher_key: STANDARD.encode(key.public_key().as_ref()),
        signature: STANDARD.encode(key.sign(&recipe_bytes(&body, &provenance)?).as_ref()),
        body,
        provenance,
    };
    entry.validate()?;
    Ok(entry)
}

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    pub entries: Vec<CatalogEntry>,
    pub trust: CatalogTrust,
    source_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applicability {
    /// Context matches, but launch privileges and rehearsal remain unproved.
    Candidate(Vec<Prerequisite>),
    Gaps(Vec<String>),
}

impl Catalog {
    pub fn import_signed(&mut self, entry: CatalogEntry) -> Result<()> {
        entry.verify(&self.trust)?;
        if let Some(existing) = self.entries.iter_mut().find(|e| e.body.id == entry.body.id) {
            ensure!(
                entry.body.revision > existing.body.revision,
                "Recipe revision must increase"
            );
            *existing = entry;
        } else {
            ensure!(self.entries.len() < 64, "Catalog capacity reached");
            self.entries.push(entry);
        }
        self.validate()
    }
    pub fn load_protected(path: &std::path::Path, trust: CatalogTrust) -> Result<Self> {
        let Some(bytes) = protected_bytes(path, 512 * 1024)? else {
            return Ok(Self {
                entries: Vec::new(),
                trust,
                source_digest: None,
            });
        };
        let clear = crate::security::unprotect_secret(&bytes)?;
        ensure!(clear.len() <= 512 * 1024, "Catalog exceeds cleartext limit");
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            schema: u16,
            entries: Vec<CatalogEntry>,
        }
        let saved: Saved = serde_json::from_slice(&clear)?;
        ensure!(saved.schema == 1, "Unsupported catalog schema");
        let catalog = Self {
            entries: saved.entries,
            trust,
            source_digest: Some(protected_digest(&bytes)),
        };
        catalog.validate()?;
        Ok(catalog)
    }
    pub fn save_protected(&self, path: &std::path::Path) -> Result<()> {
        self.validate()?;
        #[derive(Serialize)]
        struct Saved<'a> {
            schema: u16,
            entries: &'a [CatalogEntry],
        }
        let clear = serde_json::to_vec(&Saved {
            schema: 1,
            entries: &self.entries,
        })?;
        ensure!(
            clear.len() <= 512 * 1024,
            "Catalog exceeds protected save limit"
        );
        let _guard = protected_lock(path)?;
        ensure!(
            protected_bytes(path, 512 * 1024)?
                .as_deref()
                .map(protected_digest)
                == self.source_digest,
            "Recipe catalog changed concurrently; reload"
        );
        crate::security::atomic_write(path, &crate::security::protect_secret(&clear)?)
    }
    pub fn entry(&self, id: Uuid) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.body.id == id)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.entries.len() <= 64, "Catalog capacity exceeded");
        self.trust.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.verify(&self.trust)?;
            ensure!(ids.insert(entry.body.id), "Duplicate recipe ID");
        }
        Ok(())
    }
    pub fn applicability(
        &self,
        case: &HelperCase,
        entry: &CatalogEntry,
        evidence: &[EvidenceEnvelope],
        now: DateTime<Utc>,
    ) -> Applicability {
        let mut gaps = Vec::new();
        if entry.verify(&self.trust).is_err()
            || !self
                .entries
                .iter()
                .any(|e| e.identity().ok() == entry.identity().ok())
        {
            gaps.push("Recipe trust or exact catalog identity changed".into());
        }
        if now < entry.body.issued_at || now >= entry.body.expires_at {
            gaps.push("Recipe expired or not yet valid".into());
        }
        if !case.plan().is_some_and(|plan| {
            plan.case_id == case.id()
                && plan.case_revision == case.revision()
                && plan.evidence_revision == case.evidence_revision()
        }) {
            gaps.push("Current case plan is missing or stale".into());
        }
        if matches!(
            &entry.body.action,
            CatalogAction::ExistingServiceRecipe { .. }
        ) {
            gaps.push("Use the existing signed service package and v1 contract review".into());
        }
        if let CatalogAction::Sql { action, metadata } = &entry.body.action {
            let object = action.object();
            let matching_scope = case.scopes().iter().find(|scope| {
                if let BoundScope::Database {
                    engine,
                    database,
                    schema,
                    object: table,
                    credential,
                    ..
                } = scope
                {
                    let expected_engine = match object.engine {
                        helper_action::SqlEngine::Postgres => DatabaseEngine::Postgres,
                        helper_action::SqlEngine::SqlServer => DatabaseEngine::SqlServer,
                    };
                    *engine == expected_engine
                        && database == &object.database
                        && schema.as_deref() == Some(object.schema.as_str())
                        && table.as_deref() == Some(object.table.as_str())
                        && credential
                            .as_ref()
                            .is_some_and(|c| c.purpose == CredentialPurpose::ControlledChange)
                        && scope.digest().ok().as_deref() == Some(object.scope_sha256.as_str())
                } else {
                    false
                }
            });
            if matching_scope.is_none() {
                gaps.push("Current change scope, object or credential differs".into());
            }
            let resource = matching_scope.and_then(|s| s.resource_digest().ok());
            let read_scopes = case
                .scopes()
                .iter()
                .filter(|s| {
                    s.credential()
                        .is_some_and(|c| c.purpose == CredentialPurpose::Read)
                        && s.resource_digest().ok() == resource
                        && resource.is_some()
                })
                .filter_map(|s| s.digest().ok())
                .collect::<Vec<_>>();
            let read_evidence = case.evidence().iter().any(|e| {
                evidence.iter().any(|supplied| {
                    supplied.id == e.id && supplied.content_sha256 == e.content_sha256
                }) && e.binding.case_id == case.id()
                    && e.binding.case_revision == case.revision()
                    && e.content_sha256 == metadata.source_evidence_sha256
                    && read_scopes.contains(&e.binding.scope_sha256)
                    && e.eligibility(now, Duration::minutes(5)) == Eligibility::Eligible
                    && e.capability_id == super::manifest::CapabilityId::SqlRead
                    && exact_metadata_in_evidence(e, metadata)
            });
            if !read_evidence {
                gaps.push("Fresh live verified object metadata is missing".into());
            }
            gaps.extend(check_gaps(case, &entry.body.verification, object));
        }
        if gaps.is_empty() {
            let mut unverified = vec![
                Prerequisite::TableAlterPrivilege,
                Prerequisite::IsolatedRehearsal,
            ];
            if matches!(&entry.body.action, CatalogAction::Sql { action, .. } if !action.is_statistics())
            {
                unverified.push(Prerequisite::IndexOwnershipMarkerPrivilege);
            }
            Applicability::Candidate(unverified)
        } else {
            Applicability::Gaps(gaps)
        }
    }
    pub fn propose(
        &self,
        case: &HelperCase,
        entry: &CatalogEntry,
        params: ProposalParams,
    ) -> Result<HelperProposal> {
        let now = Utc::now();
        let Applicability::Candidate(unverified_prerequisites) =
            self.applicability(case, entry, case.evidence(), now)
        else {
            anyhow::bail!("Recipe identity, scope, or live metadata have gaps");
        };
        ensure!(
            !params.plan_sha256.is_empty()
                && helper_action::valid_digest(&params.plan_sha256)
                && params.evidence_ids.len() > 0
                && params.evidence_ids.len() <= 16,
            "Missing reviewed plan/evidence"
        );
        ensure!(
            case.plan().is_some_and(|plan| plan.case_id == case.id()
                && plan.case_revision == case.revision()
                && plan.evidence_revision == case.evidence_revision()
                && helper_action::digest(b"relayne-helper-reviewed-plan-v1", plan)
                    .ok()
                    .as_deref()
                    == Some(params.plan_sha256.as_str())),
            "Current exact case plan is missing or changed"
        );
        ensure!(
            params
                .evidence_ids
                .iter()
                .all(|id| case.evidence().iter().any(|e| e.id == *id)),
            "Proposal references missing evidence"
        );
        if let CatalogAction::Sql { metadata, .. } = &entry.body.action {
            ensure!(
                params
                    .evidence_ids
                    .iter()
                    .any(|id| case.evidence().iter().any(
                        |e| e.id == *id && e.content_sha256 == metadata.source_evidence_sha256
                    )),
                "Proposal omits live SQL metadata evidence"
            );
        }
        let action = entry.body.action.clone();
        let limits_acknowledged = params.statistics_limit_acknowledged;
        ensure!(
            !matches!(&action, CatalogAction::Sql { action, .. } if action.is_statistics())
                || limits_acknowledged,
            "Acknowledge that prior statistics cannot be restored exactly"
        );
        Ok(HelperProposal {
            case_id: case.id(),
            case_revision: case.revision(),
            recipe_id: entry.body.id,
            recipe_revision: entry.body.revision,
            action_version: entry.body.action_version,
            recipe_identity: entry.identity()?,
            catalog_generation_sha256: helper_action::digest(
                b"relayne-helper-catalog-generation-v1",
                &self.entries,
            )?,
            action,
            verification: entry.body.verification.clone(),
            restoration: entry.body.restoration.clone(),
            prerequisites: entry.body.prerequisites.clone(),
            unverified_prerequisites,
            plan_sha256: params.plan_sha256,
            criteria_sha256: helper_action::digest(
                b"relayne-helper-reviewed-criteria-v1",
                &case.intake().success_criteria,
            )?,
            evidence_ids: params.evidence_ids,
            statistics_limit_acknowledged: limits_acknowledged,
        })
    }
}

/// Bridge to the bounded native SQL projections. Unknown/old observation variants
/// cannot attest object identity; this remains closed until those adapters land.
fn exact_metadata_in_evidence(e: &EvidenceEnvelope, metadata: &VerifiedSqlMetadata) -> bool {
    let Ok(values) = e
        .sql_observations
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
    else {
        return false;
    };
    exact_metadata_values(values, metadata)
}

fn exact_metadata_values(values: Vec<serde_json::Value>, metadata: &VerifiedSqlMetadata) -> bool {
    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Attested {
        PostgresObject {
            schema: String,
            name: String,
            object_id: u64,
            column_count: u32,
        },
        PostgresColumn {
            object_id: u64,
            column_id: u32,
            name: String,
            plain: bool,
        },
        SqlServerObject {
            schema: String,
            name: String,
            object_id: u64,
            column_count: u32,
        },
        SqlServerColumn {
            object_id: u64,
            column_id: u32,
            name: String,
            plain: bool,
        },
    }
    let mut object_rows = 0usize;
    let mut found_columns = std::collections::BTreeMap::new();
    for value in values {
        let relevant_kind = match metadata.object.engine {
            SqlEngine::Postgres => ["postgres_object", "postgres_column"],
            SqlEngine::SqlServer => ["sql_server_object", "sql_server_column"],
        };
        let kind = value.get("kind").and_then(serde_json::Value::as_str);
        if !kind.is_some_and(|k| relevant_kind.contains(&k)) {
            continue;
        }
        let Ok(attested) = serde_json::from_value::<Attested>(value) else {
            return false;
        };
        match attested {
            Attested::PostgresObject {
                schema,
                name,
                object_id,
                column_count,
            } if metadata.object.engine == SqlEngine::Postgres => {
                if object_id == metadata.object.object_id
                    || (schema == metadata.object.schema && name == metadata.object.table)
                {
                    object_rows += 1;
                    if schema != metadata.object.schema
                        || name != metadata.object.table
                        || object_id != metadata.object.object_id
                        || column_count as usize != metadata.columns.len()
                    {
                        return false;
                    }
                }
            }
            Attested::SqlServerObject {
                schema,
                name,
                object_id,
                column_count,
            } if metadata.object.engine == SqlEngine::SqlServer => {
                if object_id == metadata.object.object_id
                    || (schema == metadata.object.schema && name == metadata.object.table)
                {
                    object_rows += 1;
                    if schema != metadata.object.schema
                        || name != metadata.object.table
                        || object_id != metadata.object.object_id
                        || column_count as usize != metadata.columns.len()
                    {
                        return false;
                    }
                }
            }
            Attested::PostgresColumn {
                object_id,
                column_id,
                name,
                plain,
            } if metadata.object.engine == SqlEngine::Postgres => {
                if object_id == metadata.object.object_id {
                    if !metadata
                        .columns
                        .iter()
                        .any(|c| c.column_id == column_id && c.name == name && c.plain == plain)
                        || found_columns.insert(column_id, (name, plain)).is_some()
                    {
                        return false;
                    }
                }
            }
            Attested::SqlServerColumn {
                object_id,
                column_id,
                name,
                plain,
            } if metadata.object.engine == SqlEngine::SqlServer => {
                if object_id == metadata.object.object_id {
                    if !metadata
                        .columns
                        .iter()
                        .any(|c| c.column_id == column_id && c.name == name && c.plain == plain)
                        || found_columns.insert(column_id, (name, plain)).is_some()
                    {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    object_rows == 1 && found_columns.len() == metadata.columns.len()
}

#[derive(Clone, Debug)]
pub struct ProposalParams {
    pub plan_sha256: Digest,
    pub evidence_ids: Vec<Uuid>,
    pub statistics_limit_acknowledged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperProposal {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub recipe_id: Uuid,
    pub recipe_revision: u64,
    pub action_version: u16,
    pub recipe_identity: Digest,
    pub catalog_generation_sha256: Digest,
    pub action: CatalogAction,
    pub verification: VerificationSpec,
    pub restoration: RestorationSpec,
    pub prerequisites: Vec<Prerequisite>,
    /// Must be discharged by later independent authority/executor proof.
    pub unverified_prerequisites: Vec<Prerequisite>,
    pub plan_sha256: Digest,
    pub criteria_sha256: Digest,
    pub evidence_ids: Vec<Uuid>,
    pub statistics_limit_acknowledged: bool,
}
/// Reopen the protected trust and catalog while their write locks are held.
/// Callers hold the case lock first; the closure retains both locks through
/// the journal operation so a publisher withdrawal cannot race admission.
pub fn with_current_proposal<T>(
    case: &HelperCase,
    proposal: &HelperProposal,
    use_current: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let trust_path = crate::security::app_data_file("helper-recipe-trust.dpapi")?;
    let catalog_path = crate::security::app_data_file("helper-recipes.dpapi")?;
    with_current_proposal_at(&trust_path, &catalog_path, case, proposal, use_current)
}

fn with_current_proposal_at<T>(
    trust_path: &Path,
    catalog_path: &Path,
    case: &HelperCase,
    proposal: &HelperProposal,
    use_current: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let _trust_lock = protected_lock(&trust_path)?;
    let _catalog_lock = protected_lock(&catalog_path)?;
    let trust = CatalogTrust::load_protected(&trust_path)?;
    let catalog = Catalog::load_protected(&catalog_path, trust)?;
    let entry = catalog
        .entries
        .iter()
        .find(|entry| {
            entry.body.id == proposal.recipe_id && entry.body.revision == proposal.recipe_revision
        })
        .ok_or_else(|| anyhow::anyhow!("Current signed recipe missing or replaced"))?;
    ensure!(
        entry.identity()? == proposal.recipe_identity,
        "Signed recipe identity changed"
    );
    let current = catalog.propose(
        case,
        entry,
        ProposalParams {
            plan_sha256: proposal.plan_sha256.clone(),
            evidence_ids: proposal.evidence_ids.clone(),
            statistics_limit_acknowledged: proposal.statistics_limit_acknowledged,
        },
    )?;
    ensure!(
        current == *proposal && current.review_digest()? == proposal.review_digest()?,
        "Current trusted recipe review differs"
    );
    use_current()
}

impl HelperProposal {
    pub fn review_digest(&self) -> Result<Digest> {
        ensure!(
            !self.case_id.is_nil()
                && self.case_revision > 0
                && !self.recipe_id.is_nil()
                && self.recipe_revision > 0
                && self.action_version == helper_action::SQL_ACTION_VERSION
                && helper_action::valid_digest(&self.recipe_identity)
                && helper_action::valid_digest(&self.catalog_generation_sha256)
                && helper_action::valid_digest(&self.plan_sha256)
                && helper_action::valid_digest(&self.criteria_sha256)
                && !self.evidence_ids.is_empty(),
            "Invalid proposal binding"
        );
        self.verification.validate()?;
        ensure!(
            !self.unverified_prerequisites.is_empty(),
            "Inert proposal must declare unresolved launch prerequisites"
        );
        if let CatalogAction::Sql { action, metadata } = &self.action {
            action.validate(metadata)?;
            self.restoration.validate_for(action)?;
            ensure!(
                !action.is_statistics() || self.statistics_limit_acknowledged,
                "Statistics restoration limit not acknowledged"
            );
        }
        helper_action::digest(REVIEW_DOMAIN, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper_action::{
        RequiredCheck, SqlEngine, StatisticsLimitation, VerifiedSqlColumn, VerifiedSqlObject,
    };
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    fn d() -> String {
        "a".repeat(64)
    }
    fn entry() -> (CatalogEntry, CatalogTrust) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let object = VerifiedSqlObject {
            engine: SqlEngine::Postgres,
            database: "db".into(),
            schema: "public".into(),
            table: "orders".into(),
            object_id: 42,
            scope_sha256: d(),
        };
        let metadata = VerifiedSqlMetadata {
            object: object.clone(),
            columns: vec![VerifiedSqlColumn {
                name: "status".into(),
                column_id: 1,
                plain: true,
            }],
            existing_indexes: vec![],
            base_table: true,
            source_evidence_sha256: d(),
        };
        let body = RecipeBody {
            version: 1,
            action_version: 1,
            id: Uuid::new_v4(),
            revision: 1,
            problem_family: "Slow orders lookup".into(),
            action: CatalogAction::Sql {
                action: SqlAction::PostgresAnalyze { object },
                metadata,
            },
            prerequisites: vec![
                Prerequisite::FreshLiveMetadata,
                Prerequisite::CurrentChangeCredential,
                Prerequisite::TableAlterPrivilege,
                Prerequisite::ReviewedFunctionalCheck,
                Prerequisite::ReviewedPerformanceCheck,
                Prerequisite::IsolatedRehearsal,
            ],
            verification: VerificationSpec {
                checks: vec![
                    RequiredCheck::HttpFunctional {
                        scope_sha256: d(),
                        expected_status: 200,
                        body_sha256: None,
                        window: "after change".into(),
                    },
                    RequiredCheck::Performance {
                        scope_sha256: d(),
                        object_id: 42,
                        workload_sha256: d(),
                        maximum_median_ms: 100,
                        maximum_p95_ms: 200,
                        minimum_warmups: 3,
                        minimum_samples: 15,
                        window: "after change".into(),
                    },
                ],
                criteria: vec![
                    CriterionRequirement {
                        measure: "HTTP status".into(),
                        comparator: CriterionComparator::AtLeast,
                        threshold_bits: 200f64.to_bits(),
                        unit: "status".into(),
                        window: "after change".into(),
                    },
                    CriterionRequirement {
                        measure: "Median latency".into(),
                        comparator: CriterionComparator::AtMost,
                        threshold_bits: 100f64.to_bits(),
                        unit: "ms".into(),
                        window: "after change".into(),
                    },
                ],
            },
            restoration: RestorationSpec::ManualOrUnavailable {
                limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
            },
            issued_at: Utc::now() - Duration::minutes(1),
            expires_at: Utc::now() + Duration::days(1),
        };
        let provenance = "Reviewed local recipe".to_string();
        let entry = CatalogEntry {
            publisher_key: STANDARD.encode(key.public_key().as_ref()),
            signature: STANDARD.encode(
                key.sign(&recipe_bytes(&body, &provenance).unwrap())
                    .as_ref(),
            ),
            body,
            provenance,
        };
        let trust = CatalogTrust {
            enrolled_keys: vec![entry.publisher_key.clone()],
            source_digest: None,
        };
        (entry, trust)
    }

    #[test]
    fn signed_recipe_rejects_tampering_revocation_and_unknown_versions() {
        let (entry, trust) = entry();
        entry.verify(&trust).unwrap();
        let mut tampered = entry.clone();
        tampered.body.problem_family.push('!');
        assert!(tampered.verify(&trust).is_err());
        let mut provenance = entry.clone();
        provenance.provenance.push('!');
        assert!(provenance.verify(&trust).is_err());
        assert!(entry.verify(&CatalogTrust::default()).is_err());
        let mut unknown = entry;
        unknown.body.version = 2;
        assert!(unknown.validate().is_err());
    }
    #[test]
    fn import_never_enrolls_recipe_supplied_publisher() {
        let (entry, trust) = entry();
        let mut catalog = Catalog::default();
        assert!(catalog.import_signed(entry.clone()).is_err());
        assert!(catalog.entries.is_empty());
        assert_eq!(
            catalog.trust.enroll(&entry.publisher_key).unwrap().len(),
            64
        );
        catalog.import_signed(entry.clone()).unwrap();
        assert!(catalog.import_signed(entry).is_err());
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.trust.enrolled_keys, trust.enrolled_keys);
    }
    #[test]
    fn protected_catalog_rejects_tampered_storage_and_revoked_key() {
        let (entry, trust) = entry();
        let path = std::env::temp_dir().join(format!("relayne-recipes-{}.dpapi", Uuid::new_v4()));
        let catalog = Catalog {
            entries: vec![entry],
            trust,
            source_digest: None,
        };
        catalog.save_protected(&path).unwrap();
        Catalog::load_protected(&path, catalog.trust.clone()).unwrap();
        assert!(Catalog::load_protected(&path, CatalogTrust::default()).is_err());
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(Catalog::load_protected(&path, catalog.trust.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn stale_revision_two_cannot_replace_saved_revision_three() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let (mut first, _) = entry();
        first.publisher_key = STANDARD.encode(key.public_key().as_ref());
        let sign = |e: &mut CatalogEntry| {
            e.signature = STANDARD.encode(
                key.sign(&recipe_bytes(&e.body, &e.provenance).unwrap())
                    .as_ref(),
            );
        };
        sign(&mut first);
        let trust = CatalogTrust {
            enrolled_keys: vec![first.publisher_key.clone()],
            source_digest: None,
        };
        let path =
            std::env::temp_dir().join(format!("relayne-recipe-cas-{}.dpapi", Uuid::new_v4()));
        Catalog {
            entries: vec![first.clone()],
            trust: trust.clone(),
            source_digest: None,
        }
        .save_protected(&path)
        .unwrap();
        let mut writer_three = Catalog::load_protected(&path, trust.clone()).unwrap();
        let mut writer_two = Catalog::load_protected(&path, trust.clone()).unwrap();
        let mut third = first.clone();
        third.body.revision = 3;
        sign(&mut third);
        writer_three.import_signed(third).unwrap();
        writer_three.save_protected(&path).unwrap();
        let mut second = first;
        second.body.revision = 2;
        sign(&mut second);
        writer_two.import_signed(second).unwrap();
        assert!(
            writer_two
                .save_protected(&path)
                .unwrap_err()
                .to_string()
                .contains("reload")
        );
        assert_eq!(
            Catalog::load_protected(&path, trust).unwrap().entries[0]
                .body
                .revision,
            3
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("lock"));
    }
    #[test]
    fn competing_trust_enrollments_cannot_erase_one_another() {
        let path = std::env::temp_dir().join(format!("relayne-trust-cas-{}.dpapi", Uuid::new_v4()));
        CatalogTrust::default().save_protected(&path).unwrap();
        let mut first = CatalogTrust::load_protected(&path).unwrap();
        let mut stale = CatalogTrust::load_protected(&path).unwrap();
        let key_a = STANDARD.encode([1u8; 32]);
        let key_b = STANDARD.encode([2u8; 32]);
        first.enroll(&key_a).unwrap();
        first.save_protected(&path).unwrap();
        stale.enroll(&key_b).unwrap();
        assert!(
            stale
                .save_protected(&path)
                .unwrap_err()
                .to_string()
                .contains("reload")
        );
        assert_eq!(
            CatalogTrust::load_protected(&path).unwrap().enrolled_keys,
            vec![key_a]
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("lock"));
    }
    #[test]
    fn statistics_acknowledgement_and_checks_are_bound_to_review_digest() {
        let (entry, _) = entry();
        let mut p = HelperProposal {
            case_id: Uuid::new_v4(),
            case_revision: 3,
            recipe_id: entry.body.id,
            recipe_revision: 1,
            action_version: 1,
            recipe_identity: entry.identity().unwrap(),
            catalog_generation_sha256: d(),
            action: entry.body.action.clone(),
            verification: entry.body.verification.clone(),
            restoration: entry.body.restoration.clone(),
            prerequisites: entry.body.prerequisites.clone(),
            unverified_prerequisites: vec![
                Prerequisite::TableAlterPrivilege,
                Prerequisite::IsolatedRehearsal,
            ],
            plan_sha256: d(),
            criteria_sha256: d(),
            evidence_ids: vec![Uuid::new_v4()],
            statistics_limit_acknowledged: false,
        };
        assert!(p.review_digest().is_err());
        p.statistics_limit_acknowledged = true;
        let original = p.review_digest().unwrap();
        p.verification.checks.pop();
        assert!(p.review_digest().is_err());
        p.verification = entry.body.verification;
        p.evidence_ids.push(Uuid::new_v4());
        assert_ne!(p.review_digest().unwrap(), original);
    }
    #[test]
    fn native_object_and_column_ids_are_required_for_applicability() {
        let (entry, _) = entry();
        let CatalogAction::Sql { metadata, .. } = &entry.body.action else {
            unreachable!()
        };
        let object = serde_json::json!({"kind":"postgres_object","schema":"public",
            "name":"orders","object_id":42,"column_count":1});
        let column = serde_json::json!({"kind":"postgres_column","object_id":42,
            "column_id":1,"name":"status","plain":true});
        assert!(exact_metadata_values(
            vec![object.clone(), column.clone()],
            metadata
        ));
        assert!(!exact_metadata_values(
            vec![serde_json::json!({"kind":"object",
            "schema":"public","name":"orders","columns":1})],
            metadata
        ));
        assert!(!exact_metadata_values(vec![object.clone()], metadata));
        assert!(!exact_metadata_values(
            vec![
                object.clone(),
                serde_json::json!({"kind":"postgres_column",
            "object_id":43,"column_id":1,"name":"status","plain":true})
            ],
            metadata
        ));
        assert!(!exact_metadata_values(
            vec![
                object,
                serde_json::json!({"kind":"postgres_column",
            "object_id":42,"column_id":1,"name":"status","plain":false})
            ],
            metadata
        ));
        let object = serde_json::json!({"kind":"postgres_object","schema":"public",
            "name":"orders","object_id":42,"column_count":1});
        let column = serde_json::json!({"kind":"postgres_column","object_id":42,
            "column_id":1,"name":"status","plain":true});
        assert!(!exact_metadata_values(
            vec![
                object.clone(),
                column.clone(),
                serde_json::json!({"kind":"postgres_column","object_id":42,"column_id":2,"name":"extra","plain":true})
            ],
            metadata
        ));
        assert!(!exact_metadata_values(
            vec![object.clone(), column.clone(), column.clone()],
            metadata
        ));
        assert!(!exact_metadata_values(
            vec![
                object.clone(),
                column.clone(),
                serde_json::json!({"kind":"postgres_object","schema":"public","name":"orders","object_id":43,"column_count":1})
            ],
            metadata
        ));
        assert!(!exact_metadata_values(
            vec![
                object.clone(),
                column.clone(),
                serde_json::json!({"kind":"postgres_object","schema":"public","name":"other","object_id":42,"column_count":1})
            ],
            metadata
        ));
        let mut sql_server = (*metadata).clone();
        sql_server.object.engine = SqlEngine::SqlServer;
        let server_object = serde_json::json!({"kind":"sql_server_object","schema":"public",
            "name":"orders","object_id":42,"column_count":1});
        let server_column = serde_json::json!({"kind":"sql_server_column","object_id":42,
            "column_id":1,"name":"status","plain":true});
        assert!(exact_metadata_values(
            vec![server_object.clone(), server_column.clone()],
            &sql_server
        ));
        assert!(!exact_metadata_values(
            vec![
                server_object,
                server_column,
                serde_json::json!({"kind":"sql_server_object","schema":"other","name":"orders","object_id":42,"column_count":1})
            ],
            &sql_server
        ));
        assert!(!exact_metadata_values(
            vec![
                object,
                column,
                serde_json::json!({"kind":"postgres_column","object_id":42,"column_id":"bad","name":"status","plain":true})
            ],
            metadata
        ));
    }
    #[test]
    fn signed_check_selectors_reject_changed_criteria_and_unrelated_scopes() {
        let (entry, _) = entry();
        let CatalogAction::Sql { action, .. } = &entry.body.action else {
            unreachable!()
        };
        let mut case = HelperCase::new(Default::default()).unwrap();
        for requirement in &entry.body.verification.criteria {
            let criterion = SuccessCriterion {
                measure: requirement.measure.clone(),
                comparator: match requirement.comparator {
                    CriterionComparator::AtMost => Comparator::AtMost,
                    CriterionComparator::AtLeast => Comparator::AtLeast,
                    CriterionComparator::Equal => Comparator::Equal,
                },
                threshold: f64::from_bits(requirement.threshold_bits),
                unit: requirement.unit.clone(),
                window: requirement.window.clone(),
                reviewed: true,
            };
            let index = case.intake().success_criteria.len();
            case.revise(
                case.revision(),
                super::super::case::CaseEdit::SuccessCriterion(index, Some(criterion)),
            )
            .unwrap();
        }
        let gaps = check_gaps(&case, &entry.body.verification, action.object());
        assert!(!gaps.iter().any(|g| g.contains("criteria")));
        assert!(gaps.iter().any(|g| g.contains("HTTP")));
        assert!(gaps.iter().any(|g| g.contains("Performance")));
        let mut wrong = entry.body.verification.clone();
        wrong.checks[0] = RequiredCheck::SqlFunctional {
            scope_sha256: d(),
            object_id: 43,
            expected_row_count: 1,
            window: "after change".into(),
        };
        assert!(
            check_gaps(&case, &wrong, action.object())
                .iter()
                .any(|g| g.contains("SQL functional"))
        );
        let mut wrong = entry.body.verification.clone();
        if let RequiredCheck::Performance { object_id, .. } = &mut wrong.checks[1] {
            *object_id = 43;
        }
        assert!(
            check_gaps(&case, &wrong, action.object())
                .iter()
                .any(|g| g.contains("Performance"))
        );
        wrong = entry.body.verification.clone();
        wrong.criteria[0].threshold_bits = 201f64.to_bits();
        assert!(
            check_gaps(&case, &wrong, action.object())
                .iter()
                .any(|g| g.contains("criteria"))
        );
        wrong = entry.body.verification.clone();
        wrong.criteria.pop();
        assert!(
            check_gaps(&case, &wrong, action.object())
                .iter()
                .any(|g| g.contains("criteria"))
        );
    }
    #[test]
    fn signed_catalog_never_proposes_from_unbound_case_or_revoked_trust() {
        let (entry, trust) = entry();
        let case = HelperCase::new(Default::default()).unwrap();
        let mut catalog = Catalog {
            entries: vec![entry.clone()],
            trust,
            source_digest: None,
        };
        assert!(matches!(
            catalog.applicability(&case, &entry, case.evidence(), Utc::now()),
            Applicability::Gaps(_)
        ));
        assert!(
            catalog
                .propose(
                    &case,
                    &entry,
                    ProposalParams {
                        plan_sha256: d(),
                        evidence_ids: vec![Uuid::new_v4()],
                        statistics_limit_acknowledged: true
                    }
                )
                .is_err()
        );
        catalog.trust = CatalogTrust::default();
        assert!(
            matches!(catalog.applicability(&case, &entry, case.evidence(), Utc::now()),
            Applicability::Gaps(gaps) if gaps.iter().any(|g| g.contains("trust")))
        );
    }

    #[test]
    fn current_protected_recipe_is_rederived_and_rejects_revocation_or_replacement() {
        use crate::helper::{
            evidence::{
                Coverage, EVIDENCE_SCHEMA, EvidenceBinding, EvidenceEnvelope, EvidenceStatus,
                NormalizedRecord, Observation, Origin, RecordKind, TimeQuality,
            },
            manifest::{CapabilityId, CapabilityManifest, ProbeParams},
            planner::{HelperPlan, HelperPlanStep},
            scope::{BoundScope, CredentialPurpose, CredentialScope, DatabaseEngine},
            sql::types::SqlObservation,
        };
        use crate::mission::Target;
        let (mut entry, _) = entry();
        let profile = Uuid::new_v4();
        let target = Target {
            profile_id: profile,
            name: "test".into(),
            host: "example.test".into(),
            port: 5432,
            protocol: "RDP".into(),
            username: "tester".into(),
            domain: "example".into(),
            route: "direct".into(),
        };
        let db = |purpose| {
            BoundScope::Database {
                target: target.clone(),
                engine: DatabaseEngine::Postgres,
                port: 5432,
                database: "db".into(),
                schema: Some("public".into()),
                object: Some("orders".into()),
                credential: Some(CredentialScope {
                    reference: Uuid::new_v4(),
                    purpose,
                    generation: 1,
                    principal: "test".into(),
                    context: "test".into(),
                    context_digest: d(),
                }),
            }
            .bind_credential_context()
            .unwrap()
        };
        let read = db(CredentialPurpose::Read);
        let change = db(CredentialPurpose::ControlledChange);
        let http = BoundScope::Http {
            target: target.clone(),
            port: 443,
            tls: true,
            path: "/health".into(),
        };
        let change_sha = change.digest().unwrap();
        let read_sha = read.digest().unwrap();
        let read_credential_sha = read.credential_scope_digest().unwrap();
        if let CatalogAction::Sql { action, metadata } = &mut entry.body.action {
            metadata.object.scope_sha256 = change_sha.clone();
            if let SqlAction::PostgresAnalyze { object } = action {
                object.scope_sha256 = change_sha.clone();
            }
        }
        if let RequiredCheck::HttpFunctional { scope_sha256, .. } =
            &mut entry.body.verification.checks[0]
        {
            *scope_sha256 = http.digest().unwrap();
        }
        if let RequiredCheck::Performance { scope_sha256, .. } =
            &mut entry.body.verification.checks[1]
        {
            *scope_sha256 = change_sha.clone();
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        entry.publisher_key = STANDARD.encode(key.public_key().as_ref());
        entry.signature = STANDARD.encode(
            key.sign(&recipe_bytes(&entry.body, &entry.provenance).unwrap())
                .as_ref(),
        );
        let trust = CatalogTrust {
            enrolled_keys: vec![entry.publisher_key.clone()],
            source_digest: None,
        };
        entry.verify(&trust).unwrap();

        let mut intake = super::super::case::ProblemIntake::default();
        intake.success_criteria = entry
            .body
            .verification
            .criteria
            .iter()
            .map(|criterion| super::super::case::SuccessCriterion {
                measure: criterion.measure.clone(),
                comparator: match criterion.comparator {
                    CriterionComparator::AtMost => super::super::case::Comparator::AtMost,
                    CriterionComparator::AtLeast => super::super::case::Comparator::AtLeast,
                    CriterionComparator::Equal => super::super::case::Comparator::Equal,
                },
                threshold: f64::from_bits(criterion.threshold_bits),
                unit: criterion.unit.clone(),
                window: criterion.window.clone(),
                reviewed: true,
            })
            .collect();
        let case = HelperCase::new(intake).unwrap();
        let now = Utc::now();
        let evidence = EvidenceEnvelope {
            schema: EVIDENCE_SCHEMA,
            id: Uuid::new_v4(),
            binding: EvidenceBinding {
                case_id: case.id(),
                case_revision: case.revision(),
                request_id: Uuid::new_v4(),
                scope_sha256: read_sha,
                credential_scope_sha256: read_credential_sha,
                run_id: None,
            },
            request_intent_sha256: None,
            capability_id: CapabilityId::SqlRead,
            capability_version: 1,
            parser_version: 1,
            origin: Origin::Live,
            source_id: d(),
            source_observed_at: now,
            retrieved_at: now,
            time_quality: TimeQuality::Trusted,
            status: EvidenceStatus::Complete,
            coverage: Coverage {
                observed: 1,
                expected: 1,
                truncated: false,
            },
            content_sha256: d(),
            records: vec![NormalizedRecord {
                kind: RecordKind::SqlRead,
                observation: Observation::Healthy,
                subject_sha256: d(),
                detail: None,
            }],
            metrics: vec![],
            sql_observations: vec![
                SqlObservation::PostgresObject {
                    schema: "public".into(),
                    name: "orders".into(),
                    object_id: 42,
                    column_count: 1,
                },
                SqlObservation::PostgresColumn {
                    object_id: 42,
                    column_id: 1,
                    name: "status".into(),
                    plain: true,
                },
            ],
            sql_artifacts: vec![],
            evidence_refs: vec![],
        };
        let mut value = serde_json::to_value(case).unwrap();
        value["profile_ids"] = serde_json::json!([profile]);
        value["scopes"] = serde_json::to_value([read, change, http]).unwrap();
        value["evidence"] = serde_json::to_value([evidence.clone()]).unwrap();
        value["evidence_revision"] = serde_json::json!(1);
        let mut case: HelperCase = serde_json::from_value(value).unwrap();
        let manifest = CapabilityManifest::built_in();
        let declaration = manifest
            .declarations
            .iter()
            .find(|d| d.id == CapabilityId::SqlWorkloadBaseline)
            .unwrap();
        let plan = HelperPlan {
            case_id: case.id(),
            case_revision: case.revision(),
            evidence_revision: case.evidence_revision(),
            generated_at: now,
            hypotheses: vec![],
            steps: vec![HelperPlanStep {
                capability_id: declaration.id,
                version: declaration.version,
                role: declaration.role,
                prerequisites: declaration.prerequisites.clone(),
                params: ProbeParams::SqlWorkload {
                    workload_digest: d(),
                    review_evidence_id: Uuid::nil(),
                    review_content_sha256: String::new(),
                },
                scope_sha256: change_sha,
                evidence_refs: vec![],
            }],
            rationale: "Synthetic reviewed workload fixture".into(),
        };
        case.refresh_plan(plan).unwrap();
        case.validate().unwrap();
        let catalog = Catalog {
            entries: vec![entry.clone()],
            trust: trust.clone(),
            source_digest: None,
        };
        let CatalogAction::Sql { metadata, .. } = &entry.body.action else {
            unreachable!()
        };
        assert_eq!(
            case.evidence()[0].eligibility(Utc::now(), Duration::minutes(5)),
            Eligibility::Eligible
        );
        assert!(
            exact_metadata_in_evidence(&case.evidence()[0], metadata),
            "exact metadata projection did not match"
        );
        assert!(
            matches!(
                catalog.applicability(&case, &entry, case.evidence(), Utc::now()),
                Applicability::Candidate(_)
            ),
            "synthetic fixture gaps: {:?}",
            catalog.applicability(&case, &entry, case.evidence(), Utc::now())
        );
        let proposal = catalog
            .propose(
                &case,
                &entry,
                ProposalParams {
                    plan_sha256: helper_action::digest(
                        b"relayne-helper-reviewed-plan-v1",
                        case.plan().unwrap(),
                    )
                    .unwrap(),
                    evidence_ids: vec![evidence.id],
                    statistics_limit_acknowledged: true,
                },
            )
            .unwrap();
        let dir = std::env::temp_dir().join(format!("relayne-current-catalog-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let trust_path = dir.join("trust.dpapi");
        let catalog_path = dir.join("catalog.dpapi");
        trust.save_protected(&trust_path).unwrap();
        catalog.save_protected(&catalog_path).unwrap();
        assert!(
            with_current_proposal_at(&trust_path, &catalog_path, &case, &proposal, || Ok(()))
                .is_ok()
        );
        let mut withdrawn = CatalogTrust::load_protected(&trust_path).unwrap();
        withdrawn.enrolled_keys.clear();
        withdrawn.save_protected(&trust_path).unwrap();
        assert!(
            with_current_proposal_at(&trust_path, &catalog_path, &case, &proposal, || Ok(()))
                .is_err()
        );
        let mut restored = CatalogTrust::load_protected(&trust_path).unwrap();
        restored.enroll(&entry.publisher_key).unwrap();
        restored.save_protected(&trust_path).unwrap();
        let mut replacement = Catalog::load_protected(&catalog_path, restored.clone()).unwrap();
        let mut extra = entry.clone();
        extra.body.id = Uuid::new_v4();
        extra.signature = STANDARD.encode(
            key.sign(&recipe_bytes(&extra.body, &extra.provenance).unwrap())
                .as_ref(),
        );
        replacement.import_signed(extra).unwrap();
        replacement.save_protected(&catalog_path).unwrap();
        assert!(
            with_current_proposal_at(&trust_path, &catalog_path, &case, &proposal, || Ok(()))
                .is_err()
        );
        let mut replacement = Catalog::load_protected(&catalog_path, restored).unwrap();
        let mut newer = entry.clone();
        newer.body.revision = 2;
        newer.signature = STANDARD.encode(
            key.sign(&recipe_bytes(&newer.body, &newer.provenance).unwrap())
                .as_ref(),
        );
        replacement.import_signed(newer).unwrap();
        replacement.save_protected(&catalog_path).unwrap();
        assert!(
            with_current_proposal_at(&trust_path, &catalog_path, &case, &proposal, || Ok(()))
                .is_err()
        );
    }
}
