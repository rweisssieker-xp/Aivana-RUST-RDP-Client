//! Ignored, guest-only Task 15 component witness. The normal protected case,
//! signed recipe, Team v2 and native SQL paths own every capability used here.
use super::*;
use crate::helper::{
    approval::{
        NativeDispatchProof, authorize_and_record_intent, authorize_and_start_dispatch,
        production_request_binding, record_local_review, staged_request_binding,
        withdraw_local_review,
    },
    capability::{ProbeAdapter, ProbeRequest},
    case::{CaseEdit, Comparator, ProblemIntake, SuccessCriterion},
    catalog::{
        Catalog, CatalogAction, CatalogTrust, Prerequisite as RecipePrerequisite, ProposalParams,
        RecipeBody, guest_sign_lab_recipe,
    },
    credentials::{PersistentSecretResolver, save_scoped_at},
    evidence::{EvidenceBinding, EvidenceStatus},
    manifest::{CapabilityId, CheckRole, Prerequisite as ProbePrerequisite, ProbeParams},
    planner::{HelperPlan, HelperPlanStep},
    scope::{CredentialPurpose, CredentialScope, DatabaseEngine},
    sql::{
        changes::{
            GuestPgBoundaryCounts, GuestPgReadback, guest_pg_assert_isolated_owned,
            guest_pg_boundary_counts, guest_pg_prepare_isolated_fixture,
            guest_pg_read_only_witness, guest_pg_require_isolated_absent,
            reset_guest_pg_boundary_counts,
        },
        postgres::PostgresAdapter,
        rehearsal::{SqlTrialMapping, load_sql_rehearsal, run_sql_rehearsal},
        restoration::{RestorationOutcome, load_production_receipt, restore_index},
        templates::{ReviewedSelectTemplate, TASK15_TABLE},
        types::SqlObservation,
    },
    store::HelperStore,
};
use crate::helper_action::{
    CriterionComparator, CriterionRequirement, PlainIndexColumn, RequiredCheck, RestorationSpec,
    SortDirection, SqlAction, SqlEngine, VerificationSpec, VerifiedSqlColumn, VerifiedSqlMetadata,
    VerifiedSqlObject, digest,
};
use crate::helper_approval::{
    ActionApprovalStateV2, ActionBindingV2, ActionDecisionV2, ConsumeActionApprovalV2,
    CreateActionApprovalV2, DecideActionApprovalV2,
};
use crate::mission::Target;
use crate::models::SecretCredential;
use crate::team_client::{TeamClient, VerifiedConsumeV2};
use crate::team_server::{Role, TokenRequest};
use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration as StdDuration,
};

const SANDBOX_ID: &str = "962f0738-9ae2-4709-bc18-b3820ac4b273";
const PRODUCTION_ROOT: &str = r"C:\RelayneHelperAcceptance";
const STAGING_ROOT: &str = r"C:\RelayneHelperRehearsal";
const TEAM_ORIGIN: &str = "http://127.0.0.1:47839";

#[derive(Clone, Copy, Serialize)]
enum TraceStage {
    Preflight,
    RehearsalAdmission,
    RehearsalNative,
    RehearsalReceipt,
    NegativeGate,
    ProductionAdmission,
    ProductionNative,
    ProductionProof,
    RestorationClaim,
    RestorationNative,
    RestorationDurable,
    Readback,
    Complete,
    Intervention,
}

#[derive(Clone, Copy, Serialize)]
enum TraceBoundary {
    Before,
    After,
}

struct GuestTrace {
    dir: PathBuf,
    next: u8,
    complete: bool,
}

impl GuestTrace {
    fn new() -> Result<Self> {
        let dir = Path::new(PRODUCTION_ROOT)
            .join("evidence")
            .join(format!("task15-native-trace-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let mut trace = Self {
            dir,
            next: 0,
            complete: false,
        };
        trace.mark(
            TraceStage::Preflight,
            "Package",
            TraceBoundary::After,
            None,
            None,
        )?;
        Ok(trace)
    }

    fn mark(
        &mut self,
        stage: TraceStage,
        operation: &'static str,
        boundary: TraceBoundary,
        case_id: Option<Uuid>,
        run_id: Option<Uuid>,
    ) -> Result<()> {
        ensure!(self.next < 128, "Guest trace capacity reached");
        let file = self.dir.join(format!("{:02}.json", self.next));
        self.next += 1;
        let witness = serde_json::json!({
            "Stage": stage,
            "Operation": operation,
            "Boundary": boundary,
            "CaseId": case_id,
            "RunId": run_id,
            "TimeUtc": Utc::now(),
            "BoundaryCounts": guest_pg_boundary_counts(),
            "ProductAcceptance": false,
        });
        let bytes = serde_json::to_vec(&witness)?;
        ensure!(bytes.len() <= 4096, "Guest trace entry exceeds bound");
        use std::io::Write as _;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(file)?;
        writer.write_all(&bytes)?;
        writer.sync_all()?;
        Ok(())
    }

    fn track<T>(
        &mut self,
        stage: TraceStage,
        operation: &'static str,
        case_id: Option<Uuid>,
        run_id: Option<Uuid>,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.mark(stage, operation, TraceBoundary::Before, case_id, run_id)?;
        let value = action()?;
        self.mark(stage, operation, TraceBoundary::After, case_id, run_id)?;
        Ok(value)
    }
}

impl Drop for GuestTrace {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.mark(
                TraceStage::Intervention,
                "HaltWithoutRetry",
                TraceBoundary::After,
                None,
                None,
            );
        }
    }
}

struct GuestTeam {
    child: Child,
    requester: TeamClient,
    stage_approver: TeamClient,
    production_approver: TeamClient,
    organization: String,
    db: PathBuf,
}

impl GuestTeam {
    fn start(trace: &mut GuestTrace) -> Result<Self> {
        let exe = PathBuf::from(std::env::var("RELAYNE_GUEST_TEAM_EXE")?);
        ensure!(
            exe.is_file() && exe.starts_with(r"C:\FixtureProductTest"),
            "Reviewed guest Team binary missing"
        );
        let db = Path::new(PRODUCTION_ROOT)
            .join("team")
            .join(format!("task15-{}.sqlite", Uuid::new_v4()));
        std::fs::create_dir_all(db.parent().unwrap())?;
        ensure!(!db.exists(), "Guest Team DB path already exists");
        let bootstrap = trace.track(TraceStage::Preflight, "TeamBootstrap", None, None, || {
            Ok(Command::new(&exe)
                .args([
                    "bootstrap",
                    db.to_str().context("Team DB path invalid")?,
                    "task15-admin",
                ])
                .output()?)
        })?;
        ensure!(bootstrap.status.success(), "Guest Team bootstrap failed");
        let output = std::str::from_utf8(&bootstrap.stdout)?;
        let admin_token = output
            .lines()
            .find_map(|line| line.strip_prefix("Bearer token (shown once): "))
            .context("Guest Team bootstrap token absent")?;
        let admin = TeamClient::new(TEAM_ORIGIN, admin_token)?;
        let mut child = Command::new(&exe)
            .args([
                "serve",
                db.to_str().context("Team DB path invalid")?,
                "127.0.0.1:47839",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let capabilities = (|| {
            for _ in 0..50 {
                if child.try_wait()?.is_some() {
                    anyhow::bail!("Guest Team process exited before readiness");
                }
                if let Ok(caps) = admin.helper_capabilities() {
                    ensure!(caps.authority_version == 2, "Guest Team lacks v2 authority");
                    return Ok(caps);
                }
                std::thread::sleep(StdDuration::from_millis(100));
            }
            anyhow::bail!("Guest Team readiness timed out")
        })();
        let capabilities = match capabilities {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let clients = trace.track(
            TraceStage::Preflight,
            "TeamIssueActors",
            None,
            None,
            || -> Result<(TeamClient, TeamClient, TeamClient)> {
                let requester_token = admin.issue(&TokenRequest {
                    actor: "task15-requester".into(),
                    role: Role::Operator,
                })?;
                let stage_token = admin.issue(&TokenRequest {
                    actor: "task15-stage-approver".into(),
                    role: Role::Operator,
                })?;
                let production_token = admin.issue(&TokenRequest {
                    actor: "task15-production-approver".into(),
                    role: Role::Operator,
                })?;
                Ok((
                    TeamClient::new(TEAM_ORIGIN, &requester_token.token)?,
                    TeamClient::new(TEAM_ORIGIN, &stage_token.token)?,
                    TeamClient::new(TEAM_ORIGIN, &production_token.token)?,
                ))
            },
        );
        let (requester, stage_approver, production_approver) = match clients {
            Ok(clients) => clients,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            requester,
            stage_approver,
            production_approver,
            organization: capabilities.organization_sha256,
            db,
        })
    }

    fn approve_once(
        &self,
        trace: &mut GuestTrace,
        binding: ActionBindingV2,
        production: bool,
    ) -> Result<VerifiedConsumeV2> {
        let stage = if production {
            TraceStage::ProductionAdmission
        } else {
            TraceStage::RehearsalAdmission
        };
        let case_id = Some(binding.case_id);
        let run_id = Some(binding.run_id);
        let item = trace.track(stage, "TeamRequest", case_id, run_id, || {
            self.requester.request_action_v2(&CreateActionApprovalV2 {
                request_id: Uuid::new_v4(),
                binding: binding.clone(),
            })
        })?;
        ensure!(
            item.state == ActionApprovalStateV2::Pending && item.requester == "task15-requester",
            "Guest Team request actor differs"
        );
        let approver = if production {
            &self.production_approver
        } else {
            &self.stage_approver
        };
        let decided = trace.track(stage, "TeamDecision", case_id, run_id, || {
            approver.decide_action_v2(
                item.id,
                &DecideActionApprovalV2 {
                    decision: ActionDecisionV2::Approve,
                },
            )
        })?;
        ensure!(
            decided.state == ActionApprovalStateV2::Approved
                && decided.approver.as_deref()
                    == Some(if production {
                        "task15-production-approver"
                    } else {
                        "task15-stage-approver"
                    }),
            "Guest Team independent decision absent"
        );
        trace.track(stage, "TeamConsume", case_id, run_id, || {
            self.requester
                .consume_action_v2(item.id, &ConsumeActionApprovalV2 { binding })
        })
    }
}

impl Drop for GuestTeam {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Deliberately retain the guest-local SQLite authority witness.
        let _ = &self.db;
    }
}

fn guest_scope(
    trace: &mut GuestTrace,
    operation: &'static str,
    target: &Target,
    port: u16,
    database: &str,
    table: &str,
    purpose: CredentialPurpose,
    principal: &str,
    password: &str,
) -> Result<BoundScope> {
    let mut scope = BoundScope::Database {
        target: target.clone(),
        engine: DatabaseEngine::Postgres,
        port,
        database: database.into(),
        schema: Some("fixture".into()),
        object: Some(table.into()),
        credential: None,
    };
    let vault = crate::security::app_data_file("credentials.scoped.dpapi")?;
    let resource = scope.resource_digest()?;
    let reference = trace.track(TraceStage::Preflight, operation, None, None, || {
        save_scoped_at(
            &vault,
            &resource,
            purpose,
            SecretCredential {
                username: principal.into(),
                password: password.into(),
                domain: String::new(),
            },
        )
    })?;
    if let BoundScope::Database { credential, .. } = &mut scope {
        *credential = Some(CredentialScope {
            reference: reference.id,
            purpose: reference.purpose,
            generation: reference.generation,
            principal: reference.principal,
            context: reference.context,
            context_digest: reference.scope_digest,
        });
    }
    Ok(scope)
}

fn guest_secret<'a>(contents: &'a str, key: &str) -> Result<&'a str> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .ok_or_else(|| anyhow::anyhow!("Guest fixture credential role absent"))
}

struct GuestFixture {
    case: HelperCase,
    proposal: HelperProposal,
    production_change: BoundScope,
    production_read: BoundScope,
    staging_change: BoundScope,
    staging_read: BoundScope,
    shared_production_change: BoundScope,
    shared_production_read: BoundScope,
    shared_staging_change: BoundScope,
    shared_staging_read: BoundScope,
    shared_production_before: GuestPgReadback,
    shared_staging_before: GuestPgReadback,
    isolated_run_id: Uuid,
    baseline: GuestPgReadback,
    staging_baseline: GuestPgReadback,
    case_path: PathBuf,
    journal_path: PathBuf,
}

fn validate_shared_sources(production: &GuestPgReadback, staging: &GuestPgReadback) -> Result<()> {
    ensure!(
        production.physical_sha256 != staging.physical_sha256
            && production.row_count == 75_000
            && staging.row_count == 75_000
            && production.row_sha256 == staging.row_sha256
            && production.object_id > 0
            && staging.object_id > 0
            && !production.indexes.is_empty()
            && !staging.indexes.is_empty(),
        "Existing shared fixture copies differ; no isolated table may be created"
    );
    Ok(())
}

fn assert_shared_source_preserved(before: &GuestPgReadback, after: &GuestPgReadback) -> Result<()> {
    ensure!(
        before.physical_sha256 == after.physical_sha256
            && before.database_id == after.database_id
            && before.object_id == after.object_id
            && before.row_count == after.row_count
            && before.row_sha256 == after.row_sha256
            && before.index_set_sha256 == after.index_set_sha256
            && before.index_identity_sha256 == after.index_identity_sha256,
        "Original shared fixture rows or index identities changed"
    );
    Ok(())
}

#[test]
fn existing_customer_index_is_preserved_by_isolated_fixture_gate() {
    let baseline = GuestPgReadback {
        physical_sha256: "a".repeat(64),
        database_id: 1,
        object_id: 16_386,
        row_count: 75_000,
        row_sha256: "b".repeat(64),
        index_set_sha256: "c".repeat(64),
        index_identity_sha256: "d".repeat(64),
        indexes: vec![crate::helper::sql::changes::GuestPgIndexWitness {
            id: 42,
            name: "existing_customer_id_index".into(),
            definition_sha256: "e".repeat(64),
            marker_sha256: None,
            valid: true,
        }],
        customer_id_index_present: true,
    };
    let mut staging = baseline.clone();
    staging.physical_sha256 = "f".repeat(64);
    assert!(validate_shared_sources(&baseline, &staging).is_ok());
    assert!(assert_shared_source_preserved(&baseline, &baseline).is_ok());
    let mut altered = baseline.clone();
    altered.indexes[0].id += 1;
    altered.index_identity_sha256 = "0".repeat(64);
    assert!(assert_shared_source_preserved(&baseline, &altered).is_err());
    staging.row_sha256 = "1".repeat(64);
    assert!(validate_shared_sources(&baseline, &staging).is_err());
}

async fn prepare_guest_fixture(trace: &mut GuestTrace) -> Result<GuestFixture> {
    let production_secrets =
        std::fs::read_to_string(Path::new(PRODUCTION_ROOT).join("credentials.txt"))?;
    let staging_secrets = std::fs::read_to_string(Path::new(STAGING_ROOT).join("credentials.txt"))?;
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "Task 15 isolated synthetic fixture".into(),
        host: "127.0.0.1".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: "operator".into(),
        domain: String::new(),
        route: String::new(),
    };
    let production_change = guest_scope(
        trace,
        "ProductionChangeCredential",
        &target,
        55433,
        "relayne_helper_acceptance",
        "orders",
        CredentialPurpose::ControlledChange,
        "relayne_fixture_owner",
        guest_secret(&production_secrets, "owner")?,
    )?;
    let production_read = guest_scope(
        trace,
        "ProductionReadCredential",
        &target,
        55433,
        "relayne_helper_acceptance",
        "orders",
        CredentialPurpose::Read,
        "relayne_fixture_reader",
        guest_secret(&production_secrets, "reader")?,
    )?;
    let staging_change = guest_scope(
        trace,
        "StagingChangeCredential",
        &target,
        55434,
        "relayne_helper_rehearsal",
        "orders",
        CredentialPurpose::ControlledChange,
        "relayne_rehearsal_owner",
        guest_secret(&staging_secrets, "owner")?,
    )?;
    let staging_read = guest_scope(
        trace,
        "StagingReadCredential",
        &target,
        55434,
        "relayne_helper_rehearsal",
        "orders",
        CredentialPurpose::Read,
        "relayne_rehearsal_reader",
        guest_secret(&staging_secrets, "reader")?,
    )?;
    trace.mark(
        TraceStage::Preflight,
        "NativeReadOnlyBaseline",
        TraceBoundary::Before,
        None,
        None,
    )?;
    let shared_production_before = guest_pg_read_only_witness(
        &production_change,
        &production_read,
        CancellationToken::new(),
    )
    .await?;
    let shared_staging_before =
        guest_pg_read_only_witness(&staging_change, &staging_read, CancellationToken::new())
            .await?;
    trace.mark(
        TraceStage::Preflight,
        "NativeReadOnlyBaseline",
        TraceBoundary::After,
        None,
        None,
    )?;
    validate_shared_sources(&shared_production_before, &shared_staging_before)?;
    // Check both clusters before creating either table. A previous run-owned
    // table is preserved for investigation and is never silently reused.
    guest_pg_require_isolated_absent(&production_change).await?;
    guest_pg_require_isolated_absent(&staging_change).await?;
    let isolated_run_id = Uuid::new_v4();
    trace.mark(
        TraceStage::Preflight,
        "CreateIsolatedFixtureTables",
        TraceBoundary::Before,
        None,
        Some(isolated_run_id),
    )?;
    guest_pg_prepare_isolated_fixture(
        &staging_change,
        &shared_staging_before,
        isolated_run_id,
        CancellationToken::new(),
    )
    .await?;
    guest_pg_prepare_isolated_fixture(
        &production_change,
        &shared_production_before,
        isolated_run_id,
        CancellationToken::new(),
    )
    .await?;
    trace.mark(
        TraceStage::Preflight,
        "CreateIsolatedFixtureTables",
        TraceBoundary::After,
        None,
        Some(isolated_run_id),
    )?;
    let shared_production_change = production_change;
    let shared_production_read = production_read;
    let shared_staging_change = staging_change;
    let shared_staging_read = staging_read;
    let production_change = guest_scope(
        trace,
        "IsolatedProductionChangeCredential",
        &target,
        55433,
        "relayne_helper_acceptance",
        TASK15_TABLE,
        CredentialPurpose::ControlledChange,
        "relayne_fixture_owner",
        guest_secret(&production_secrets, "owner")?,
    )?;
    let production_read = guest_scope(
        trace,
        "IsolatedProductionReadCredential",
        &target,
        55433,
        "relayne_helper_acceptance",
        TASK15_TABLE,
        CredentialPurpose::Read,
        "relayne_fixture_reader",
        guest_secret(&production_secrets, "reader")?,
    )?;
    let staging_change = guest_scope(
        trace,
        "IsolatedStagingChangeCredential",
        &target,
        55434,
        "relayne_helper_rehearsal",
        TASK15_TABLE,
        CredentialPurpose::ControlledChange,
        "relayne_rehearsal_owner",
        guest_secret(&staging_secrets, "owner")?,
    )?;
    let staging_read = guest_scope(
        trace,
        "IsolatedStagingReadCredential",
        &target,
        55434,
        "relayne_helper_rehearsal",
        TASK15_TABLE,
        CredentialPurpose::Read,
        "relayne_rehearsal_reader",
        guest_secret(&staging_secrets, "reader")?,
    )?;
    guest_pg_assert_isolated_owned(&production_change, isolated_run_id).await?;
    guest_pg_assert_isolated_owned(&staging_change, isolated_run_id).await?;
    let baseline = guest_pg_read_only_witness(
        &production_change,
        &production_read,
        CancellationToken::new(),
    )
    .await?;
    let staging_baseline =
        guest_pg_read_only_witness(&staging_change, &staging_read, CancellationToken::new())
            .await?;
    ensure!(
        baseline.physical_sha256 == shared_production_before.physical_sha256
            && staging_baseline.physical_sha256 == shared_staging_before.physical_sha256
            && baseline.row_count == 75_000
            && staging_baseline.row_count == 75_000
            && baseline.row_sha256 == shared_production_before.row_sha256
            && staging_baseline.row_sha256 == shared_staging_before.row_sha256
            && baseline.row_sha256 == staging_baseline.row_sha256
            && !baseline.customer_id_index_present
            && !staging_baseline.customer_id_index_present,
        "Task 15 test-owned fixture copy differs before any native product action"
    );
    let shared_production_after_seed = guest_pg_read_only_witness(
        &shared_production_change,
        &shared_production_read,
        CancellationToken::new(),
    )
    .await?;
    let shared_staging_after_seed = guest_pg_read_only_witness(
        &shared_staging_change,
        &shared_staging_read,
        CancellationToken::new(),
    )
    .await?;
    assert_shared_source_preserved(&shared_production_before, &shared_production_after_seed)?;
    assert_shared_source_preserved(&shared_staging_before, &shared_staging_after_seed)?;
    let case_path = HelperStore::path()?;
    let journal_path = ActionJournal::path()?;
    let mut store = HelperStore::load(&case_path)?;
    let mut intake = ProblemIntake::default();
    intake.success_criteria = vec![
        SuccessCriterion {
            measure: "SQL row count".into(),
            comparator: Comparator::Equal,
            threshold: 75_000.0,
            unit: "rows".into(),
            window: "after change".into(),
            reviewed: true,
        },
        SuccessCriterion {
            measure: "Median latency".into(),
            comparator: Comparator::AtMost,
            threshold: 15_000.0,
            unit: "ms".into(),
            window: "after change".into(),
            reviewed: true,
        },
    ];
    let case_id = store.create(intake)?;
    let revision = store.case(case_id).context("New case absent")?.revision();
    store.revise(
        case_id,
        revision,
        CaseEdit::Profiles(vec![target.profile_id]),
    )?;
    let revision = store.case(case_id).context("New case absent")?.revision();
    store.revise(
        case_id,
        revision,
        CaseEdit::Scopes(vec![
            production_change.clone(),
            production_read.clone(),
            staging_change.clone(),
            staging_read.clone(),
        ]),
    )?;
    let case = store.case(case_id).context("New case absent")?.clone();
    let template = ReviewedSelectTemplate::Task15CustomerOrders {
        customer_id: 424242,
    };
    let workload_digest = template.fingerprint(&production_read)?;
    let plan = HelperPlan {
        case_id,
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        generated_at: Utc::now(),
        hypotheses: vec![],
        steps: vec![HelperPlanStep {
            capability_id: CapabilityId::SqlWorkloadBaseline,
            version: 1,
            params: ProbeParams::SqlWorkload {
                workload_digest: workload_digest.clone(),
                review_evidence_id: Uuid::nil(),
                review_content_sha256: String::new(),
            },
            scope_sha256: production_read.digest()?,
            evidence_refs: vec![],
            prerequisites: vec![
                ProbePrerequisite::ReviewedScope,
                ProbePrerequisite::ReadCredential,
                ProbePrerequisite::NetworkAccess,
                ProbePrerequisite::DeclaredWorkload,
            ],
            role: CheckRole::Performance,
        }],
        rationale: "ActorTest reviewed synthetic PostgreSQL fixture workload".into(),
    };
    store.revise(case_id, case.revision(), CaseEdit::PlanIntent(plan))?;
    trace.track(
        TraceStage::Preflight,
        "PersistNewCasePlan",
        Some(case_id),
        None,
        || store.save(&case_path),
    )?;
    let case = store.case(case_id).context("New case absent")?.clone();
    let request = ProbeRequest {
        binding: EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id: Uuid::new_v4(),
            scope_sha256: production_read.digest()?,
            credential_scope_sha256: production_read.credential_scope_digest()?,
            run_id: None,
        },
        scope: production_read.clone(),
        capability_id: CapabilityId::SqlRead,
        capability_version: 1,
        params: ProbeParams::SqlRead {
            query_digest: super::super::postgres::template_digest(),
        },
        requested_at: Utc::now(),
        deadline_secs: Some(15),
    };
    let output = PostgresAdapter
        .collect(
            &request,
            &PersistentSecretResolver::new()?,
            CancellationToken::new(),
        )
        .await?;
    ensure!(
        output.status == EvidenceStatus::Complete,
        "Guest native SQL read evidence incomplete"
    );
    let evidence = crate::helper::worker::normalize(&request, output)?;
    let object_id = evidence
        .sql_observations
        .iter()
        .find_map(|observation| match observation {
            SqlObservation::PostgresObject {
                schema,
                name,
                object_id,
                ..
            } if schema == "fixture" && name == TASK15_TABLE => Some(*object_id),
            _ => None,
        })
        .context("Guest PostgreSQL object identity absent")?;
    ensure!(
        object_id == baseline.object_id,
        "Guest PostgreSQL table identity drifted"
    );
    let mut columns = evidence
        .sql_observations
        .iter()
        .filter_map(|observation| match observation {
            SqlObservation::PostgresColumn {
                object_id: id,
                column_id,
                name,
                plain,
                ..
            } if *id == object_id => Some(VerifiedSqlColumn {
                name: name.clone(),
                column_id: *column_id,
                plain: *plain,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    columns.sort_by_key(|column| column.column_id);
    let existing_indexes = evidence
        .sql_observations
        .iter()
        .filter_map(|observation| match observation {
            SqlObservation::Index { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let source_id = evidence.id;
    let source_sha256 = evidence.content_sha256.clone();
    store.attach_evidence(case_id, evidence)?;
    let case = store.case(case_id).context("New case absent")?.clone();
    let mut plan = case.plan().context("Guest plan absent")?.clone();
    plan.evidence_revision = case.evidence_revision();
    plan.generated_at = Utc::now();
    store.refresh_derived_plan(case_id, plan)?;
    trace.track(
        TraceStage::Preflight,
        "PersistCurrentEvidencePlan",
        Some(case_id),
        None,
        || store.save(&case_path),
    )?;
    let case = store.case(case_id).context("New case absent")?.clone();
    let metadata = VerifiedSqlMetadata {
        object: VerifiedSqlObject {
            engine: SqlEngine::Postgres,
            database: "relayne_helper_acceptance".into(),
            schema: "fixture".into(),
            table: TASK15_TABLE.into(),
            object_id,
            scope_sha256: production_change.digest()?,
        },
        columns,
        existing_indexes,
        base_table: true,
        source_evidence_sha256: source_sha256,
    };
    let index = format!("idx_task15_{}", Uuid::new_v4().simple());
    let action = SqlAction::PostgresCreateIndex {
        object: metadata.object.clone(),
        index,
        columns: vec![PlainIndexColumn {
            name: "customer_id".into(),
            direction: SortDirection::Asc,
        }],
    };
    action.validate(&metadata)?;
    let verification = VerificationSpec {
        checks: vec![
            RequiredCheck::SqlFunctional {
                scope_sha256: production_read.digest()?,
                object_id,
                expected_row_count: 75_000,
                window: "after change".into(),
            },
            RequiredCheck::Performance {
                scope_sha256: production_read.digest()?,
                object_id,
                workload_sha256: workload_digest,
                maximum_median_ms: 15_000,
                maximum_p95_ms: 15_000,
                minimum_warmups: 3,
                minimum_samples: 15,
                window: "after change".into(),
            },
        ],
        criteria: vec![
            CriterionRequirement {
                measure: "SQL row count".into(),
                comparator: CriterionComparator::Equal,
                threshold_bits: 75_000f64.to_bits(),
                unit: "rows".into(),
                window: "after change".into(),
            },
            CriterionRequirement {
                measure: "Median latency".into(),
                comparator: CriterionComparator::AtMost,
                threshold_bits: 15_000f64.to_bits(),
                unit: "ms".into(),
                window: "after change".into(),
            },
        ],
    };
    verification.validate()?;
    let body = RecipeBody {
        version: 1,
        action_version: crate::helper_action::SQL_ACTION_VERSION,
        id: Uuid::new_v4(),
        revision: 1,
        problem_family: "ActorTest synthetic PostgreSQL indexing".into(),
        action: CatalogAction::Sql {
            action: action.clone(),
            metadata,
        },
        prerequisites: vec![
            RecipePrerequisite::FreshLiveMetadata,
            RecipePrerequisite::CurrentChangeCredential,
            RecipePrerequisite::TableAlterPrivilege,
            RecipePrerequisite::IndexOwnershipMarkerPrivilege,
            RecipePrerequisite::ReviewedFunctionalCheck,
            RecipePrerequisite::ReviewedPerformanceCheck,
            RecipePrerequisite::IsolatedRehearsal,
        ],
        verification,
        restoration: RestorationSpec::VerifiedReversible {
            exact_index_sha256: digest(b"relayne-helper-exact-index-intent-v1", &action)?,
            ownership_scheme_sha256: digest(
                b"relayne-helper-index-ownership-scheme-v1",
                &"run-bound-index-comment",
            )?,
        },
        issued_at: Utc::now() - Duration::minutes(1),
        expires_at: Utc::now() + Duration::hours(1),
    };
    let entry = guest_sign_lab_recipe(body)?;
    let trust_path = crate::security::app_data_file("helper-recipe-trust.dpapi")?;
    let catalog_path = crate::security::app_data_file("helper-recipes.dpapi")?;
    let mut trust = CatalogTrust::load_protected(&trust_path)?;
    trust.enroll(&entry.publisher_key)?;
    trace.track(
        TraceStage::Preflight,
        "EnrollLabRecipeTrust",
        Some(case_id),
        None,
        || trust.save_protected(&trust_path),
    )?;
    let mut catalog = Catalog::load_protected(&catalog_path, trust)?;
    catalog.import_signed(entry.clone())?;
    trace.track(
        TraceStage::Preflight,
        "ImportSignedLabRecipe",
        Some(case_id),
        None,
        || catalog.save_protected(&catalog_path),
    )?;
    let proposal = catalog.propose(
        &case,
        &entry,
        ProposalParams {
            plan_sha256: digest(
                b"relayne-helper-reviewed-plan-v1",
                case.plan().context("Guest plan absent")?,
            )?,
            evidence_ids: vec![source_id],
            statistics_limit_acknowledged: false,
        },
    )?;
    trace.track(
        TraceStage::Preflight,
        "RecordLocalReview",
        Some(case_id),
        None,
        || record_local_review(&case_path, &journal_path, &case, &proposal),
    )?;
    Ok(GuestFixture {
        case,
        proposal,
        production_change,
        production_read,
        staging_change,
        staging_read,
        shared_production_change,
        shared_production_read,
        shared_staging_change,
        shared_staging_read,
        shared_production_before,
        shared_staging_before,
        isolated_run_id,
        baseline,
        staging_baseline,
        case_path,
        journal_path,
    })
}

fn assert_no_production_or_restore_contact(before: GuestPgBoundaryCounts) -> Result<()> {
    let after = guest_pg_boundary_counts();
    ensure!(
        after.production_executor_contacts == before.production_executor_contacts
            && after.production_executor_opens == before.production_executor_opens
            && after.production_mutation_attempts == before.production_mutation_attempts
            && after.restoration_executor_contacts == before.restoration_executor_contacts
            && after.restoration_executor_opens == before.restoration_executor_opens
            && after.restoration_drop_attempts == before.restoration_drop_attempts,
        "Negative admission contacted a native executor"
    );
    Ok(())
}

async fn reject_rotated_vault_generation_at_final_start(
    trace: &mut GuestTrace,
    fixture: &GuestFixture,
    team: &GuestTeam,
    rehearsal: &crate::helper::sql::rehearsal::SqlRehearsalReceipt,
    previous_run_id: Uuid,
    previous_approval_id: Uuid,
) -> Result<()> {
    use crate::helper::approval::DispatchContext;

    let native =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let journal = ActionJournal::load(&fixture.journal_path)?;
    let binding = production_request_binding(
        &fixture.case,
        &fixture.proposal,
        team.organization.clone(),
        &native,
        rehearsal,
        &journal,
    )?;
    ensure!(
        binding.run_id != previous_run_id,
        "Rotated-vault run reused production run"
    );
    let consumed = team.approve_once(trace, binding.clone(), true)?;
    ensure!(
        consumed.receipt().approval_id != previous_approval_id,
        "Rotated-vault run reused consumed approval"
    );
    let current = DispatchContext {
        case: &fixture.case,
        proposal: &fixture.proposal,
        journal: &journal,
        observation: native.observation(),
    };
    check_sql_promotion(
        &fixture.case,
        &fixture.proposal,
        rehearsal,
        &binding,
        &current,
        Utc::now(),
    )?;

    let before = guest_pg_boundary_counts();
    let intent_id = trace.track(
        TraceStage::NegativeGate,
        "PersistRotatedVaultPreparedIntent",
        Some(fixture.case.id()),
        Some(binding.run_id),
        || {
            authorize_and_record_intent(
                &fixture.case_path,
                &fixture.journal_path,
                &fixture.proposal,
                &binding,
                &consumed,
                &native,
            )
        },
    )?;
    ensure!(
        ActionJournal::load(&fixture.journal_path)?
            .intents()
            .iter()
            .any(|intent| {
                intent.run_id == binding.run_id
                    && intent.state == crate::helper::journal::IntentState::Prepared
            }),
        "Rotated-vault negative lacks durable prepared intent"
    );
    assert_no_production_or_restore_contact(before)?;

    let case_before = std::fs::read(&fixture.case_path)?;
    let vault = crate::security::app_data_file("credentials.scoped.dpapi")?;
    let old_generation = fixture
        .production_change
        .credential()
        .context("Controlled-change scope absent")?
        .generation;
    let rotated = save_scoped_at(
        &vault,
        &fixture.production_change.resource_digest()?,
        CredentialPurpose::ControlledChange,
        SecretCredential {
            username: "relayne_fixture_owner".into(),
            password: Uuid::new_v4().to_string(),
            domain: String::new(),
        },
    )?;
    ensure!(
        rotated.generation > old_generation && std::fs::read(&fixture.case_path)? == case_before,
        "Vault rotation changed reviewed case or failed to advance generation"
    );
    trace.mark(
        TraceStage::NegativeGate,
        "RejectRotatedVaultFinalStart",
        TraceBoundary::Before,
        Some(fixture.case.id()),
        Some(binding.run_id),
    )?;
    let error = match authorize_and_start_dispatch(
        &fixture.case_path,
        &fixture.journal_path,
        intent_id,
        &fixture.proposal,
        &binding,
        &consumed,
        &native,
    ) {
        Err(error) => error,
        Ok(_) => {
            anyhow::bail!("Rotated protected vault generation reached production dispatch start")
        }
    };
    ensure!(
        format!("{error:#}").contains("Credential scope mismatch"),
        "Final dispatch start rejected for a reason other than protected vault generation"
    );
    ensure!(
        ActionJournal::load(&fixture.journal_path)?
            .intents()
            .iter()
            .any(|intent| {
                intent.run_id == binding.run_id
                    && intent.state == crate::helper::journal::IntentState::Prepared
            }),
        "Rejected final start did not preserve the conservative prepared intent"
    );
    assert_no_production_or_restore_contact(before)?;
    trace.mark(
        TraceStage::NegativeGate,
        "RejectRotatedVaultFinalStart",
        TraceBoundary::After,
        Some(fixture.case.id()),
        Some(binding.run_id),
    )?;
    Ok(())
}

fn negative_rehearsal_and_production_admission(
    trace: &mut GuestTrace,
    fixture: &GuestFixture,
    mapping: &SqlTrialMapping,
    rehearsal: &crate::helper::sql::rehearsal::SqlRehearsalReceipt,
    binding: &ActionBindingV2,
    native: &NativeDispatchProof,
) -> Result<()> {
    use crate::helper::approval::DispatchContext;
    trace.mark(
        TraceStage::NegativeGate,
        "AdmissionMatrix",
        TraceBoundary::Before,
        Some(fixture.case.id()),
        Some(binding.run_id),
    )?;
    let before = guest_pg_boundary_counts();
    let mut wrong_mapping = mapping.clone();
    wrong_mapping.staging_physical_sha256 = "f".repeat(64);
    ensure!(
        staged_request_binding(
            &fixture.case,
            &fixture.proposal,
            binding.organization_sha256.clone(),
            native,
            &wrong_mapping
        )
        .is_err(),
        "Wrong physical staging mapping admitted"
    );
    let journal = ActionJournal::load(&fixture.journal_path)?;
    let current = DispatchContext {
        case: &fixture.case,
        proposal: &fixture.proposal,
        journal: &journal,
        observation: native.observation(),
    };
    let mut wrong_action = fixture.proposal.clone();
    if let CatalogAction::Sql {
        action: SqlAction::PostgresCreateIndex { index, .. },
        ..
    } = &mut wrong_action.action
    {
        index.push_str("_altered");
    }
    ensure!(
        check_sql_promotion(
            &fixture.case,
            &wrong_action,
            rehearsal,
            binding,
            &current,
            Utc::now()
        )
        .is_err(),
        "Changed SQL action admitted"
    );
    let mut wrong_check = fixture.proposal.clone();
    wrong_check.verification.criteria[0].threshold_bits = 74_999f64.to_bits();
    ensure!(
        check_sql_promotion(
            &fixture.case,
            &wrong_check,
            rehearsal,
            binding,
            &current,
            Utc::now()
        )
        .is_err(),
        "Changed review criterion admitted"
    );
    let mut missing_coverage = fixture.proposal.clone();
    missing_coverage.verification.checks.pop();
    ensure!(
        check_sql_promotion(
            &fixture.case,
            &missing_coverage,
            rehearsal,
            binding,
            &current,
            Utc::now()
        )
        .is_err(),
        "Missing check coverage admitted"
    );
    let mut stale_before = binding.clone();
    stale_before.before_sha256 = "f".repeat(64);
    ensure!(
        check_sql_promotion(
            &fixture.case,
            &fixture.proposal,
            rehearsal,
            &stale_before,
            &current,
            Utc::now()
        )
        .is_err(),
        "Stale original before-state admitted"
    );
    ensure!(
        check_sql_promotion(
            &fixture.case,
            &fixture.proposal,
            rehearsal,
            binding,
            &current,
            Utc::now() + Duration::days(1)
        )
        .is_err(),
        "Expired rehearsal or approval timing admitted"
    );
    let copy_path = Path::new(PRODUCTION_ROOT)
        .join("evidence")
        .join(format!("task15-tampered-receipt-{}.dpapi", Uuid::new_v4()));
    std::fs::create_dir_all(copy_path.parent().unwrap())?;
    let mut bytes = std::fs::read(rehearsal.path()?)?;
    ensure!(!bytes.is_empty(), "Protected rehearsal receipt empty");
    bytes[0] ^= 1;
    std::fs::write(&copy_path, bytes)?;
    ensure!(
        load_sql_rehearsal(&copy_path).is_err(),
        "Tampered protected rehearsal receipt loaded"
    );
    let old_path = rehearsal
        .path()?
        .parent()
        .context("Protected receipt directory absent")?
        .read_dir()?
        .take(1000)
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("relayne-helper-sql-rehearsal-c5b14ce5")
                        && name.ends_with(".dpapi")
                })
        })
        .context("Historical Task 14 staging receipt absent")?;
    let old_bytes = std::fs::read(&old_path)?;
    ensure!(
        old_bytes.len() <= 64 * 1024,
        "Historical receipt exceeds bound"
    );
    let old_clear = crate::security::unprotect_secret(&old_bytes)?;
    let old_fields: serde_json::Value = serde_json::from_slice(&old_clear)?;
    ensure!(
        old_fields
            .get("production_before_sha256")
            .is_none_or(serde_json::Value::is_null),
        "Historical receipt unexpectedly has production-before proof"
    );
    if let Ok(old_receipt) = load_sql_rehearsal(&old_path) {
        ensure!(
            production_request_binding(
                &fixture.case,
                &fixture.proposal,
                binding.organization_sha256.clone(),
                native,
                &old_receipt,
                &journal
            )
            .is_err(),
            "Historical staging receipt admitted production"
        );
    }
    assert_no_production_or_restore_contact(before)?;
    trace.mark(
        TraceStage::NegativeGate,
        "AdmissionMatrix",
        TraceBoundary::After,
        Some(fixture.case.id()),
        Some(binding.run_id),
    )
}

async fn run_guest_pg_task15() -> Result<()> {
    reset_guest_pg_boundary_counts();
    let mut trace = GuestTrace::new()?;
    let fixture = prepare_guest_fixture(&mut trace).await?;
    let case_id = Some(fixture.case.id());
    let team = GuestTeam::start(&mut trace)?;
    let initial_native =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    ensure!(
        initial_native.physical_sha256() == fixture.baseline.physical_sha256,
        "Production physical cluster changed"
    );
    let mapping = SqlTrialMapping::review(
        &fixture.case,
        &fixture.proposal,
        &initial_native,
        &fixture.staging_change.digest()?,
        "ActorTest isolated synthetic staging cluster; reviewed new index and readback",
        CancellationToken::new(),
    )
    .await?;
    let staging_binding = staged_request_binding(
        &fixture.case,
        &fixture.proposal,
        team.organization.clone(),
        &initial_native,
        &mapping,
    )?;
    let staging_consumed = team.approve_once(&mut trace, staging_binding.clone(), false)?;
    let staging_native =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let staging_intent = trace.track(
        TraceStage::RehearsalAdmission,
        "PersistStagingIntent",
        case_id,
        Some(staging_binding.run_id),
        || {
            authorize_and_record_intent(
                &fixture.case_path,
                &fixture.journal_path,
                &fixture.proposal,
                &staging_binding,
                &staging_consumed,
                &staging_native,
            )
        },
    )?;
    let staging_fresh =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let staging_permit = trace.track(
        TraceStage::RehearsalAdmission,
        "PersistStagingDispatchStarted",
        case_id,
        Some(staging_binding.run_id),
        || {
            authorize_and_start_dispatch(
                &fixture.case_path,
                &fixture.journal_path,
                staging_intent,
                &fixture.proposal,
                &staging_binding,
                &staging_consumed,
                &staging_fresh,
            )
        },
    )?;
    trace.mark(
        TraceStage::RehearsalNative,
        "NativeRehearsal",
        TraceBoundary::Before,
        case_id,
        Some(staging_binding.run_id),
    )?;
    let rehearsal = run_sql_rehearsal(
        &mapping,
        staging_permit,
        staging_intent,
        &fixture.case,
        &fixture.proposal,
        &fixture.journal_path,
        CancellationToken::new(),
    )
    .await?;
    trace.mark(
        TraceStage::RehearsalNative,
        "NativeRehearsal",
        TraceBoundary::After,
        case_id,
        Some(staging_binding.run_id),
    )?;
    let rehearsal = load_sql_rehearsal(&rehearsal.path()?)?;
    ensure!(
        rehearsal.run_id() == staging_binding.run_id
            && rehearsal.guest_production_before_sha256()
                == Some(initial_native.native().before_sha256()),
        "Protected new rehearsal lacks original production before-state"
    );
    let staging_journal = ActionJournal::load(&fixture.journal_path)?;
    ensure!(
        staging_journal.intents().iter().any(|intent| {
            intent.run_id == staging_binding.run_id
                && intent.state == crate::helper::journal::IntentState::Verified
                && intent.approval_id == staging_consumed.receipt().approval_id
                && intent.consume_id == staging_consumed.receipt().consume_id
        }),
        "New rehearsal has no verified protected journal result"
    );
    trace.mark(
        TraceStage::RehearsalReceipt,
        "StagingReadback",
        TraceBoundary::Before,
        case_id,
        Some(staging_binding.run_id),
    )?;
    let staging_readback = guest_pg_read_only_witness(
        &fixture.staging_change,
        &fixture.staging_read,
        CancellationToken::new(),
    )
    .await?;
    trace.mark(
        TraceStage::RehearsalReceipt,
        "StagingReadback",
        TraceBoundary::After,
        case_id,
        Some(staging_binding.run_id),
    )?;
    let index_name = match &fixture.proposal.action {
        CatalogAction::Sql {
            action: SqlAction::PostgresCreateIndex { index, .. },
            ..
        } => index,
        _ => anyhow::bail!("Reviewed Task 15 index action changed"),
    };
    ensure!(
        staging_readback.row_sha256 == fixture.staging_baseline.row_sha256
            && staging_readback
                .indexes
                .iter()
                .any(|index| &index.name == index_name && index.valid)
            && fixture
                .staging_baseline
                .indexes
                .iter()
                .all(|old| staging_readback
                    .indexes
                    .iter()
                    .any(|index| index.id == old.id && index.name == old.name)),
        "Staging rows or old indexes changed, or new index absent"
    );

    let production_native =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let journal = ActionJournal::load(&fixture.journal_path)?;
    let probe_binding = production_request_binding(
        &fixture.case,
        &fixture.proposal,
        team.organization.clone(),
        &production_native,
        &rehearsal,
        &journal,
    )?;
    negative_rehearsal_and_production_admission(
        &mut trace,
        &fixture,
        &mapping,
        &rehearsal,
        &probe_binding,
        &production_native,
    )?;

    // Withdrawal and a faulted local intent each consume real, distinct Team approvals.
    // Neither can reach the SQL executor; a fresh approval is needed afterwards.
    trace.track(
        TraceStage::NegativeGate,
        "WithdrawLocalReview",
        case_id,
        None,
        || withdraw_local_review(&fixture.case_path, &fixture.journal_path, fixture.case.id()),
    )?;
    let withdrawn_consume = team.approve_once(&mut trace, probe_binding.clone(), true)?;
    let before = guest_pg_boundary_counts();
    trace.mark(
        TraceStage::NegativeGate,
        "RejectWithdrawnIntent",
        TraceBoundary::Before,
        case_id,
        Some(probe_binding.run_id),
    )?;
    ensure!(
        authorize_and_record_intent(
            &fixture.case_path,
            &fixture.journal_path,
            &fixture.proposal,
            &probe_binding,
            &withdrawn_consume,
            &production_native,
        )
        .is_err(),
        "Withdrawn local review admitted production intent"
    );
    assert_no_production_or_restore_contact(before)?;
    trace.mark(
        TraceStage::NegativeGate,
        "RejectWithdrawnIntent",
        TraceBoundary::After,
        case_id,
        Some(probe_binding.run_id),
    )?;
    trace.track(
        TraceStage::NegativeGate,
        "RestoreLocalReview",
        case_id,
        None,
        || {
            record_local_review(
                &fixture.case_path,
                &fixture.journal_path,
                &fixture.case,
                &fixture.proposal,
            )
        },
    )?;

    let fault_native =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let fault_binding = production_request_binding(
        &fixture.case,
        &fixture.proposal,
        team.organization.clone(),
        &fault_native,
        &rehearsal,
        &ActionJournal::load(&fixture.journal_path)?,
    )?;
    let fault_consume = team.approve_once(&mut trace, fault_binding.clone(), true)?;
    crate::helper::journal::arm_guest_persistence_fault(1);
    let before = guest_pg_boundary_counts();
    trace.mark(
        TraceStage::NegativeGate,
        "RejectFaultedIntentSave",
        TraceBoundary::Before,
        case_id,
        Some(fault_binding.run_id),
    )?;
    ensure!(
        authorize_and_record_intent(
            &fixture.case_path,
            &fixture.journal_path,
            &fixture.proposal,
            &fault_binding,
            &fault_consume,
            &fault_native,
        )
        .is_err(),
        "Faulted durable intent unexpectedly persisted"
    );
    ensure!(
        !ActionJournal::load(&fixture.journal_path)?
            .intents()
            .iter()
            .any(|intent| intent.run_id == fault_binding.run_id),
        "Faulted intent leaked into protected journal"
    );
    assert_no_production_or_restore_contact(before)?;
    trace.mark(
        TraceStage::NegativeGate,
        "RejectFaultedIntentSave",
        TraceBoundary::After,
        case_id,
        Some(fault_binding.run_id),
    )?;

    let (production_binding, production_consumed, final_native) = {
        let mut selected = None;
        for _ in 0..2 {
            let native = NativeDispatchProof::collect(
                &fixture.case,
                &fixture.proposal,
                CancellationToken::new(),
            )
            .await?;
            let binding = production_request_binding(
                &fixture.case,
                &fixture.proposal,
                team.organization.clone(),
                &native,
                &rehearsal,
                &ActionJournal::load(&fixture.journal_path)?,
            )?;
            let consumed = team.approve_once(&mut trace, binding.clone(), true)?;
            let refreshed = NativeDispatchProof::collect(
                &fixture.case,
                &fixture.proposal,
                CancellationToken::new(),
            )
            .await?;
            if refreshed.native().observed_at() < Utc::now() - Duration::seconds(119)
                || refreshed.native().before_sha256() != binding.before_sha256
                || refreshed.physical_sha256() != fixture.baseline.physical_sha256
            {
                continue;
            }
            selected = Some((binding, consumed, refreshed));
            break;
        }
        selected.context("Fresh production observation unavailable after new Team approval")?
    };
    let production_intent = trace.track(
        TraceStage::ProductionAdmission,
        "PersistProductionIntent",
        case_id,
        Some(production_binding.run_id),
        || {
            authorize_and_record_intent(
                &fixture.case_path,
                &fixture.journal_path,
                &fixture.proposal,
                &production_binding,
                &production_consumed,
                &final_native,
            )
        },
    )?;
    let production_fresh =
        NativeDispatchProof::collect(&fixture.case, &fixture.proposal, CancellationToken::new())
            .await?;
    let permit = trace.track(
        TraceStage::ProductionAdmission,
        "PersistProductionDispatchStarted",
        case_id,
        Some(production_binding.run_id),
        || {
            authorize_and_start_dispatch(
                &fixture.case_path,
                &fixture.journal_path,
                production_intent,
                &fixture.proposal,
                &production_binding,
                &production_consumed,
                &production_fresh,
            )
        },
    )?;
    let launch = ProductionLaunch::from_authorized(
        &fixture.case,
        &fixture.proposal,
        &rehearsal,
        production_fresh,
        permit,
        production_intent,
        &fixture.journal_path,
    )?;
    let mut journal = ActionJournal::load(&fixture.journal_path)?;
    let before_production = guest_pg_boundary_counts();
    trace.mark(
        TraceStage::ProductionNative,
        "NativeProduction",
        TraceBoundary::Before,
        case_id,
        Some(production_binding.run_id),
    )?;
    let produced = apply_sql_production(launch, &mut journal, CancellationToken::new()).await?;
    trace.mark(
        TraceStage::ProductionNative,
        "NativeProduction",
        TraceBoundary::After,
        case_id,
        Some(production_binding.run_id),
    )?;
    let receipt = produced
        .receipt
        .context("Production result lacks protected receipt")?;
    let receipt = load_production_receipt(receipt.run_id())?;
    trace.mark(
        TraceStage::ProductionProof,
        "ProtectedProductionReceiptReload",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    let after_production = guest_pg_boundary_counts();
    ensure!(
        after_production.production_executor_contacts
            == before_production.production_executor_contacts + 1
            && after_production.production_executor_opens
                == before_production.production_executor_opens + 1
            && after_production.production_mutation_attempts
                == before_production.production_mutation_attempts + 1,
        "Production executor did not make exactly one native mutation attempt"
    );
    let owned = receipt
        .index()
        .context("Production receipt lacks owned index")?;
    trace.mark(
        TraceStage::Readback,
        "ProductionAfterCreate",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    let after_create = guest_pg_read_only_witness(
        &fixture.production_change,
        &fixture.production_read,
        CancellationToken::new(),
    )
    .await?;
    trace.mark(
        TraceStage::Readback,
        "ProductionAfterCreate",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    ensure!(
        after_create.row_sha256 == fixture.baseline.row_sha256
            && after_create.database_id == fixture.baseline.database_id
            && after_create.object_id == fixture.baseline.object_id
            && after_create.indexes.iter().any(|index| {
                index.id == owned.id
                    && index.name == owned.name
                    && index.valid
                    && index.definition_sha256 == owned.definition_sha256
                    && index.marker_sha256.as_deref() == Some(owned.marker_sha256.as_str())
            })
            && fixture.baseline.indexes.iter().all(|old| after_create
                .indexes
                .iter()
                .any(|index| index.id == old.id && index.name == old.name)),
        "Production exact-run readback changed old rows/indexes or exact created index proof"
    );

    crate::helper::journal::arm_guest_persistence_fault(2);
    let before_claim = guest_pg_boundary_counts();
    trace.mark(
        TraceStage::RestorationClaim,
        "RejectFaultedClaimSave",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    ensure!(
        restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
            .await
            .is_err(),
        "Faulted restoration claim unexpectedly persisted"
    );
    assert_no_production_or_restore_contact(before_claim)?;
    trace.mark(
        TraceStage::RestorationClaim,
        "RejectFaultedClaimSave",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    ensure!(
        !ActionJournal::load(&fixture.journal_path)?
            .intents()
            .iter()
            .find(|intent| intent.run_id == receipt.run_id())
            .context("Production journal intent absent")?
            .restoration_pending,
        "Faulted restoration claim became durable"
    );
    trace.mark(
        TraceStage::RestorationNative,
        "ExactIndexRestore",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    let restored = restore_index(receipt.run_id(), &mut journal, CancellationToken::new()).await?;
    trace.mark(
        TraceStage::RestorationNative,
        "ExactIndexRestore",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    ensure!(
        restored == RestorationOutcome::Restored,
        "Exact owned index restoration unresolved"
    );
    let after_restore = guest_pg_boundary_counts();
    ensure!(
        after_restore.restoration_executor_contacts
            == before_claim.restoration_executor_contacts + 1
            && after_restore.restoration_executor_opens
                == before_claim.restoration_executor_opens + 1
            && after_restore.restoration_drop_attempts
                == before_claim.restoration_drop_attempts + 1,
        "Restoration did not make exactly one DROP attempt"
    );
    ensure!(
        restore_index(receipt.run_id(), &mut journal, CancellationToken::new()).await?
            == RestorationOutcome::Restored
            && guest_pg_boundary_counts() == after_restore,
        "One-shot restoration lookup repeated native SQL"
    );
    trace.mark(
        TraceStage::Readback,
        "AfterExactRestore",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    let after_readback = guest_pg_read_only_witness(
        &fixture.production_change,
        &fixture.production_read,
        CancellationToken::new(),
    )
    .await?;
    trace.mark(
        TraceStage::Readback,
        "AfterExactRestore",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    ensure!(
        after_readback.row_sha256 == fixture.baseline.row_sha256
            && after_readback.index_set_sha256 == fixture.baseline.index_set_sha256
            && after_readback.index_identity_sha256 == fixture.baseline.index_identity_sha256
            && !after_readback
                .indexes
                .iter()
                .any(|index| index.id == owned.id || index.name == owned.name),
        "Final readback differs old rows/index set or retains exact new index"
    );
    let final_journal = ActionJournal::load(&fixture.journal_path)?;
    let original = final_journal
        .intents()
        .iter()
        .find(|intent| intent.run_id == receipt.run_id())
        .context("Production journal result absent")?;
    ensure!(
        original.restoration_outcome == Some(RestorationOutcome::Restored)
            && original.approval_id == production_consumed.receipt().approval_id
            && original.consume_id == production_consumed.receipt().consume_id,
        "Protected production journal is not restored and exact authority-bound"
    );
    trace.mark(
        TraceStage::RestorationDurable,
        "ProtectedTerminalJournal",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    guest_pg_assert_isolated_owned(&fixture.production_change, fixture.isolated_run_id).await?;
    guest_pg_assert_isolated_owned(&fixture.staging_change, fixture.isolated_run_id).await?;
    trace.mark(
        TraceStage::Readback,
        "SharedSourcePreservation",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    let shared_production_after = guest_pg_read_only_witness(
        &fixture.shared_production_change,
        &fixture.shared_production_read,
        CancellationToken::new(),
    )
    .await?;
    let shared_staging_after = guest_pg_read_only_witness(
        &fixture.shared_staging_change,
        &fixture.shared_staging_read,
        CancellationToken::new(),
    )
    .await?;
    assert_shared_source_preserved(&fixture.shared_production_before, &shared_production_after)?;
    assert_shared_source_preserved(&fixture.shared_staging_before, &shared_staging_after)?;
    trace.mark(
        TraceStage::Readback,
        "SharedSourcePreservation",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    reject_rotated_vault_generation_at_final_start(
        &mut trace,
        &fixture,
        &team,
        &rehearsal,
        receipt.run_id(),
        production_consumed.receipt().approval_id,
    )
    .await?;
    trace.mark(
        TraceStage::Complete,
        "BoundedHostWitness",
        TraceBoundary::Before,
        case_id,
        Some(receipt.run_id()),
    )?;
    write_success_witness(
        &fixture,
        &team,
        &rehearsal,
        &receipt,
        &after_create,
        &after_readback,
        &shared_production_after,
        &shared_staging_after,
    )?;
    trace.mark(
        TraceStage::Complete,
        "BoundedHostWitness",
        TraceBoundary::After,
        case_id,
        Some(receipt.run_id()),
    )?;
    trace.complete = true;
    Ok(())
}

fn required_hex_env(key: &str, length: usize) -> Result<String> {
    let value = std::env::var(key)?;
    ensure!(
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Reviewed guest package identity missing"
    );
    Ok(value.to_ascii_lowercase())
}

fn validate_guest_package_before_mutation() -> Result<()> {
    ensure!(
        std::env::var("RELAYNE_GUEST_PG_NATIVE")?.as_str() == "1",
        "Guest native gate absent"
    );
    ensure!(
        std::env::var("RELAYNE_GUEST_SANDBOX_ID")?.as_str() == SANDBOX_ID,
        "Unexpected Sandbox identity"
    );
    ensure!(
        std::env::var("USERNAME")?.as_str() == "WDAGUtilityAccount",
        "Unexpected guest account"
    );
    let source = required_hex_env("RELAYNE_GUEST_SOURCE_COMMIT", 40)?;
    required_hex_env("RELAYNE_GUEST_SOURCE_TREE", 40)?;
    required_hex_env("RELAYNE_GUEST_BINARY_SHA256", 64)?;
    required_hex_env("RELAYNE_GUEST_TEAM_SHA256", 64)?;
    required_hex_env("RELAYNE_GUEST_DRIVER_SHA256", 64)?;
    for root in [
        PRODUCTION_ROOT,
        STAGING_ROOT,
        r"C:\FixtureProductTest",
        r"C:\FixtureEvidence",
    ] {
        let metadata = std::fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Guest fixture root unavailable or redirected"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "Guest fixture root is a reparse point"
            );
        }
    }
    for credential_file in [
        Path::new(PRODUCTION_ROOT).join("credentials.txt"),
        Path::new(STAGING_ROOT).join("credentials.txt"),
    ] {
        ensure!(
            credential_file.is_file(),
            "Guest fixture credentials absent"
        );
    }
    let team_exe = PathBuf::from(std::env::var("RELAYNE_GUEST_TEAM_EXE")?);
    ensure!(
        team_exe.starts_with(r"C:\FixtureProductTest") && team_exe.is_file(),
        "Reviewed Team binary unavailable"
    );
    let hash8 = &source[..8];
    ensure!(
        !Path::new(PRODUCTION_ROOT)
            .join("evidence")
            .join(format!("task15-native-pg-{hash8}.json"))
            .exists()
            && !Path::new(r"C:\FixtureEvidence")
                .join(format!("task15-native-pg-{hash8}.json"))
                .exists(),
        "Guest output already exists"
    );
    let probe = std::net::TcpListener::bind("127.0.0.1:47839")?;
    drop(probe);
    Ok(())
}

fn write_success_witness(
    fixture: &GuestFixture,
    team: &GuestTeam,
    rehearsal: &crate::helper::sql::rehearsal::SqlRehearsalReceipt,
    receipt: &crate::helper::sql::restoration::ProductionReceipt,
    after_create: &GuestPgReadback,
    after_restore: &GuestPgReadback,
    shared_production_after: &GuestPgReadback,
    shared_staging_after: &GuestPgReadback,
) -> Result<()> {
    let source = required_hex_env("RELAYNE_GUEST_SOURCE_COMMIT", 40)?;
    let tree = required_hex_env("RELAYNE_GUEST_SOURCE_TREE", 40)?;
    let binary = required_hex_env("RELAYNE_GUEST_BINARY_SHA256", 64)?;
    let team_binary = required_hex_env("RELAYNE_GUEST_TEAM_SHA256", 64)?;
    let driver = required_hex_env("RELAYNE_GUEST_DRIVER_SHA256", 64)?;
    let case = fixture.case.id();
    let hash8 = &source[..8];
    let owned = receipt
        .index()
        .context("Production receipt lacks owned index")?;
    let observed = after_create
        .indexes
        .iter()
        .find(|index| index.id == owned.id && index.name == owned.name)
        .context("Created index absent from independent readback")?;
    ensure!(
        observed.valid
            && observed.definition_sha256 == owned.definition_sha256
            && observed.marker_sha256.as_deref() == Some(owned.marker_sha256.as_str()),
        "Independent created index proof differs from protected receipt"
    );
    let witness = serde_json::json!({
        "Stage": "Complete", "ProductAcceptance": false, "ExactlyOneTestPassed": true,
        "ActorTest": "task15-requester / task15-stage-approver / task15-production-approver",
        "SandboxId": SANDBOX_ID, "Account": "WDAGUtilityAccount",
        "SourceCommit": source, "SourceTree": tree, "BinarySha256": binary,
        "TeamBinarySha256": team_binary, "DriverSha256": driver,
        "CaseId": case, "StagingRunId": rehearsal.run_id(), "ProductionRunId": receipt.run_id(),
        "IsolatedFixtureRunId": fixture.isolated_run_id,
        "TeamDb": team.db.file_name().and_then(|name| name.to_str()),
        "ProductionPhysicalSha256": fixture.baseline.physical_sha256,
        "ProductionDatabaseId": fixture.baseline.database_id,
        "ProductionObjectId": fixture.baseline.object_id,
        "OriginalRowSha256": fixture.baseline.row_sha256,
        "OriginalIndexSetSha256": fixture.baseline.index_set_sha256,
        "OriginalIndexIdentitySha256": fixture.baseline.index_identity_sha256,
        "ProductionAfterCreateIndexSetSha256": after_create.index_set_sha256,
        "ProductionCreatedIndexOid": observed.id,
        "ProductionCreatedIndexDefinitionSha256": observed.definition_sha256,
        "ProductionCreatedIndexMarkerSha256": observed.marker_sha256,
        "AfterRestoreRowSha256": after_restore.row_sha256,
        "AfterRestoreIndexSetSha256": after_restore.index_set_sha256,
        "AfterRestoreIndexIdentitySha256": after_restore.index_identity_sha256,
        "SharedProductionBeforeIndexIdentitySha256": fixture.shared_production_before.index_identity_sha256,
        "SharedProductionAfterIndexIdentitySha256": shared_production_after.index_identity_sha256,
        "SharedStagingBeforeIndexIdentitySha256": fixture.shared_staging_before.index_identity_sha256,
        "SharedStagingAfterIndexIdentitySha256": shared_staging_after.index_identity_sha256,
        "StagingReceiptSha256": rehearsal.content_sha256(),
        "ProductionReceiptSha256": receipt.content_sha256(),
        "BoundaryCounts": guest_pg_boundary_counts(),
    });
    let bytes = serde_json::to_vec_pretty(&witness)?;
    ensure!(
        bytes.len() <= 32 * 1024,
        "Guest witness exceeds export bound"
    );
    let local = Path::new(PRODUCTION_ROOT)
        .join("evidence")
        .join(format!("task15-native-pg-{hash8}.json"));
    let export = Path::new(r"C:\FixtureEvidence").join(format!("task15-native-pg-{hash8}.json"));
    std::fs::create_dir_all(local.parent().unwrap())?;
    ensure!(
        !local.exists() && !export.exists(),
        "Guest witness output path already exists"
    );
    std::fs::write(&local, &bytes)?;
    std::fs::write(&export, bytes)?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires reviewed Task 15 binary package and existing isolated Windows Sandbox"]
async fn guest_pg_task15_production_restore_api() {
    validate_guest_package_before_mutation()
        .expect("Reviewed Task 15 guest package preflight failed");
    run_guest_pg_task15().await.expect("Task 15 guest native component witness failed; preserve protected state and do not retry SQL");
}
