use super::*;
use crate::helper::{
    capability::ProbeRequest,
    credentials::{PersistentSecretResolver, save_scoped_at},
    evidence::EvidenceBinding,
    scope::{CredentialPurpose, CredentialScope},
    sql::templates::{FIXTURE_DATABASE, ReviewedSelectTemplate},
};
use crate::mission::Target;
use crate::models::SecretCredential;
use uuid::Uuid;

struct FakeWorkloadSession {
    identity: Vec<SqlObservation>,
    metadata: Vec<SqlObservation>,
    calls: Vec<&'static str>,
    changed_result_at: Option<usize>,
    stall_at: Option<usize>,
    compatibility: Option<[String; 2]>,
    snapshots: usize,
}

impl WorkloadSession for FakeWorkloadSession {
    fn compatibility_snapshot<'a>(
        &'a mut self,
        _statement: &'a TemplateStatement,
    ) -> TdsFuture<'a, String> {
        Box::pin(async move {
            let index = self.snapshots;
            self.snapshots += 1;
            self.compatibility
                .as_ref()
                .and_then(|digests| digests.get(index))
                .cloned()
                .ok_or(Failure::Unavailable)
        })
    }
    fn identity<'a>(&'a mut self) -> TdsFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            self.calls.push("identity");
            Ok(self.identity.clone())
        })
    }

    fn read_object<'a>(
        &'a mut self,
        _schema: &'a str,
        _object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            self.calls.push("metadata");
            Ok(self.metadata.clone())
        })
    }

    fn run_once<'a>(&'a mut self, statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<i64>> {
        Box::pin(async move {
            if statement.sql
                != "SELECT TOP (100) [order_id] FROM [fixture].[orders] WHERE [customer_id] = @P1 ORDER BY [order_id]"
            {
                return Err(Failure::InvalidProjection);
            }
            self.calls.push("sample");
            let count = self.calls.iter().filter(|call| **call == "sample").count();
            if self.stall_at == Some(count) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(if self.changed_result_at == Some(count) {
                vec![9]
            } else {
                vec![1, 2]
            })
        })
    }
}

fn fixture_scope() -> BoundScope {
    let mut scope = BoundScope::Database {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "fixture".into(),
            host: "127.0.0.1".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: String::new(),
            route: String::new(),
        },
        engine: DatabaseEngine::SqlServer,
        port: crate::helper::sql::templates::TDS_FIXTURE_PORT,
        database: FIXTURE_DATABASE.into(),
        schema: Some(FIXTURE_SCHEMA.into()),
        object: Some("orders".into()),
        credential: None,
    };
    let resource = scope.resource_digest().unwrap();
    if let BoundScope::Database { credential, .. } = &mut scope {
        *credential = Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::Read,
            generation: 1,
            principal: "reader".into(),
            context: "fixture".into(),
            context_digest: resource,
        });
    }
    scope
}

#[test]
fn tds_v2_rehearsal_template_has_only_two_fixed_fixture_endpoints() {
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let production = fixture_scope();
    assert!(template.reviewed_statement(&production).is_ok());
    let mut stage = production.clone();
    let stage_credential = if let BoundScope::Database { credential, .. } = &mut stage {
        credential.take()
    } else {
        None
    };
    if let BoundScope::Database { port, database, .. } = &mut stage {
        *port = crate::helper::sql::templates::TDS_REHEARSAL_PORT;
        *database = crate::helper::sql::templates::REHEARSAL_DATABASE.into();
    }
    let resource = stage.resource_digest().unwrap();
    if let (
        BoundScope::Database {
            credential: slot, ..
        },
        Some(mut credential),
    ) = (&mut stage, stage_credential)
    {
        credential.context_digest = resource;
        *slot = Some(credential);
    }
    assert!(template.reviewed_statement(&stage).is_ok());
    if let BoundScope::Database { port, .. } = &mut stage {
        *port = 1433;
    }
    assert!(template.reviewed_statement(&stage).is_err());
    assert_eq!(
        crate::helper::sql::templates::REHEARSAL_TEMPLATE_MAPPING_VERSION,
        2
    );
}

#[test]
fn sort_fixture_group_id_only_drift_changes_bounded_digest() {
    let reviewed = ReviewedSelectTemplate::OrderSort;
    for column in reviewed.expected_columns() {
        assert!(
            TDS_SORT_DATA_SQL.contains(&format!("t.[{column}]")),
            "TDS sort data digest omits reviewed column {column}"
        );
    }
    let digest_for_group = |group_id| {
        let mut hasher = benchmark::BoundedFixtureHasher::new();
        hasher
            .push(&format!(
                r#"{{"event_id":7,"group_id":{group_id},"payload":"stable"}}"#
            ))
            .unwrap();
        hasher.finish().unwrap().sha256
    };
    assert_ne!(digest_for_group(3), digest_for_group(4));
}

fn reviewed() -> (ReviewedWorkload, TemplateStatement) {
    let scope = fixture_scope();
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let statement = template.sql_server_statement(&scope).unwrap();
    (
        ReviewedWorkload {
            scope,
            template,
            case_id: Uuid::new_v4(),
            case_revision: 3,
            review_evidence_id: Uuid::new_v4(),
            review_content_sha256: "a".repeat(64),
            reviewed_at: chrono::Utc::now(),
        },
        statement,
    )
}

fn fake() -> FakeWorkloadSession {
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let expected = template.expected_columns();
    let mut metadata = vec![SqlObservation::SqlServerObject {
        schema: FIXTURE_SCHEMA.into(),
        name: "orders".into(),
        object_id: 42,
        column_count: expected.len() as u32,
    }];
    for (index, name) in expected.iter().enumerate() {
        metadata.push(SqlObservation::SqlServerColumn {
            object_id: 42,
            column_id: (index + 1) as u32,
            name: (*name).into(),
            plain: true,
        });
    }
    FakeWorkloadSession {
        identity: vec![SqlObservation::SqlServerIdentity {
            database: FIXTURE_DATABASE.into(),
            principal: "reader".into(),
            effective_principal: "reader".into(),
            database_principal: "reader".into(),
            product_version: "16.0.1000.6".into(),
            server_ip: "127.0.0.1".into(),
            server_port: crate::helper::sql::templates::TDS_FIXTURE_PORT,
            tls_required: true,
            server_state_access: None,
            server_performance_access: None,
        }],
        metadata,
        calls: vec![],
        changed_result_at: None,
        stall_at: None,
        compatibility: None,
        snapshots: 0,
    }
}

fn expected_identity() -> (&'static str, &'static str, &'static str, u16) {
    (
        FIXTURE_DATABASE,
        "reader",
        "127.0.0.1",
        crate::helper::sql::templates::TDS_FIXTURE_PORT,
    )
}

#[tokio::test]
async fn repeated_fixed_samples_have_bound_provenance_and_statistics() {
    let (review, statement) = reviewed();
    let mut session = fake();
    let result = collect_with_session(
        &mut session,
        &review,
        &statement,
        &SamplingPolicy::default(),
        expected_identity(),
        &CancellationToken::new(),
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(result.warmups, 3);
    assert_eq!(result.milliseconds.len(), 15);
    assert!(result.median_ms > 0.0 && result.p95_ms >= result.median_ms);
    assert_eq!(result.workload_fingerprint, statement.fingerprint);
    assert_eq!(result.review_evidence_id, review.review_evidence_id);
    assert_eq!(result.review_content_sha256, review.review_content_sha256);
    assert_eq!(result.result_sha256.len(), 64);
    assert_eq!(result.environment_fingerprint.len(), 64);
    assert_eq!(result.live_metadata_sha256.len(), 64);
    assert!(!result.compatibility.is_complete());
    assert!(
        result
            .compatibility
            .missing()
            .contains(&benchmark::CompatibilityGap::ColumnTypes)
    );
    assert!(
        result
            .compatibility
            .missing()
            .contains(&benchmark::CompatibilityGap::PostSampleState)
    );
    assert_eq!(session.calls.len(), 20);
    assert!(!result.can_prove_repair());
}

#[tokio::test]
async fn admitted_postcommit_read_keeps_native_guards_after_review_expiry() {
    let (mut review, statement) = reviewed();
    let now = chrono::Utc::now();
    review.reviewed_at = now - chrono::Duration::minutes(6);
    assert!(benchmark::admit_postcommit_workload_at(&review, now).is_err());
    let admission =
        benchmark::admit_postcommit_workload_at(&review, now - chrono::Duration::minutes(2))
            .unwrap();
    assert_eq!(admission.request().reviewed_at, review.reviewed_at);

    let policy = SamplingPolicy::default();
    let cancel = CancellationToken::new();
    let mut stale_without_admission = fake();
    assert!(
        collect_with_session(
            &mut stale_without_admission,
            &review,
            &statement,
            &policy,
            expected_identity(),
            &cancel,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .is_err()
    );

    let mut accepted = fake();
    accepted.compatibility = Some(["a".repeat(64), "a".repeat(64)]);
    let samples = collect_with_session_inner(
        &mut accepted,
        admission.request(),
        &statement,
        &policy,
        expected_identity(),
        &cancel,
        Instant::now() + Duration::from_secs(5),
        false,
    )
    .await
    .unwrap();
    assert!(samples.compatibility.is_complete());

    let mut foreign_identity = fake();
    if let SqlObservation::SqlServerIdentity {
        database_principal, ..
    } = &mut foreign_identity.identity[0]
    {
        *database_principal = "foreign".into();
    }
    assert!(
        collect_with_session_inner(
            &mut foreign_identity,
            admission.request(),
            &statement,
            &policy,
            expected_identity(),
            &cancel,
            Instant::now() + Duration::from_secs(5),
            false,
        )
        .await
        .is_err()
    );
    assert!(!foreign_identity.calls.contains(&"sample"));

    let canceled = CancellationToken::new();
    canceled.cancel();
    assert!(
        collect_with_session_inner(
            &mut fake(),
            admission.request(),
            &statement,
            &policy,
            expected_identity(),
            &canceled,
            Instant::now() + Duration::from_secs(5),
            false,
        )
        .await
        .is_err()
    );
    let mut slow = fake();
    slow.stall_at = Some(1);
    assert!(
        collect_with_session_inner(
            &mut slow,
            admission.request(),
            &statement,
            &policy,
            expected_identity(),
            &cancel,
            Instant::now() + Duration::from_millis(1),
            false,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn native_snapshots_must_match_across_same_session_samples() {
    let (review, statement) = reviewed();
    for (after, complete) in [("a".repeat(64), true), ("b".repeat(64), false)] {
        let mut session = fake();
        session.compatibility = Some(["a".repeat(64), after]);
        let result = collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(session.snapshots, 2);
        assert_eq!(result.compatibility.is_complete(), complete);
    }
}

#[tokio::test]
async fn identity_or_metadata_mismatch_stops_before_any_select() {
    let (review, statement) = reviewed();
    let mut session = fake();
    if let SqlObservation::SqlServerIdentity {
        database_principal, ..
    } = &mut session.identity[0]
    {
        *database_principal = "other".into();
    }
    assert!(
        collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert_eq!(session.calls, ["identity"]);

    let mut session = fake();
    if let SqlObservation::SqlServerColumn { plain, .. } = &mut session.metadata[1] {
        *plain = false;
    }
    assert!(
        collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert_eq!(session.calls, ["identity", "metadata"]);
}

#[tokio::test]
async fn result_drift_cancellation_and_deadline_do_not_publish_samples() {
    let (review, statement) = reviewed();
    let mut session = fake();
    session.changed_result_at = Some(5);
    assert!(
        collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert_eq!(
        session
            .calls
            .iter()
            .filter(|call| **call == "sample")
            .count(),
        5
    );

    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut session = fake();
    assert!(
        collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &cancel,
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert!(session.calls.is_empty());

    let mut session = fake();
    session.stall_at = Some(1);
    assert!(
        collect_with_session(
            &mut session,
            &review,
            &statement,
            &SamplingPolicy::default(),
            expected_identity(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(1)
        )
        .await
        .is_err()
    );
    assert_eq!(
        session
            .calls
            .iter()
            .filter(|call| **call == "sample")
            .count(),
        1
    );
}

#[tokio::test]
async fn domain_credential_is_rejected_before_native_workload_connect() {
    let (mut review, statement) = reviewed();
    let path = std::env::temp_dir().join(format!("relayne-tds-workload-{}.dpapi", Uuid::new_v4()));
    let resource = review.scope.resource_digest().unwrap();
    let saved = save_scoped_at(
        &path,
        &resource,
        CredentialPurpose::Read,
        SecretCredential {
            username: "reader".into(),
            password: "secret-marker".into(),
            domain: "UNREVIEWED".into(),
        },
    )
    .unwrap();
    if let BoundScope::Database { credential, .. } = &mut review.scope {
        *credential = Some(CredentialScope {
            reference: saved.id,
            purpose: saved.purpose,
            generation: saved.generation,
            principal: saved.principal,
            context: saved.context,
            context_digest: saved.scope_digest,
        });
    }
    let probe = ProbeRequest {
        binding: EvidenceBinding {
            case_id: review.case_id,
            case_revision: review.case_revision,
            request_id: Uuid::new_v4(),
            scope_sha256: review.scope.digest().unwrap(),
            credential_scope_sha256: review.scope.credential_scope_digest().unwrap(),
            run_id: None,
        },
        scope: review.scope.clone(),
        capability_id: CapabilityId::SqlWorkloadBaseline,
        capability_version: 1,
        params: ProbeParams::SqlWorkload {
            workload_digest: statement.fingerprint,
            review_evidence_id: review.review_evidence_id,
            review_content_sha256: review.review_content_sha256.clone(),
        },
        requested_at: chrono::Utc::now(),
        deadline_secs: Some(1),
    };
    let resolver = PersistentSecretResolver::at(path.clone());
    let mut mismatched = probe.clone();
    mismatched.binding.scope_sha256 = "0".repeat(64);
    let mismatch = run_sandbox_workload(
        &mismatched,
        &review,
        &SamplingPolicy::default(),
        &resolver,
        CancellationToken::new(),
    )
    .await;
    assert!(format!("{}", mismatch.unwrap_err()).contains("binding mismatch"));
    let result = run_sandbox_workload(
        &probe,
        &review,
        &SamplingPolicy::default(),
        &resolver,
        CancellationToken::new(),
    )
    .await;
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("SQL login principal mismatch"));
    std::fs::remove_file(path).unwrap();
}
