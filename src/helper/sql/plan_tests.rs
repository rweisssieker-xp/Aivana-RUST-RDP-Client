use super::{
    benchmark::{
        Comparison, CompatibilityEngine, CompatibilityEvidence, SamplingPolicy, WorkloadSamples,
        compare,
    },
    plans::{self, ImportSource, PlanImportFormat, Spill},
    templates::{OrderStatus, ReviewedSelectTemplate},
};
use crate::{
    helper::scope::{BoundScope, CredentialPurpose, CredentialScope, DatabaseEngine},
    mission::Target,
};
use uuid::Uuid;

#[test]
fn workload_review_requires_complete_object_column_identity() {
    use crate::helper::sql::types::SqlObservation;
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let mut rows = vec![SqlObservation::PostgresObject {
        schema: "fixture".into(),
        name: "orders".into(),
        object_id: 42,
        column_count: 6,
    }];
    for (index, name) in [
        "order_id",
        "customer_id",
        "status",
        "amount",
        "created_at",
        "detail",
    ]
    .iter()
    .enumerate()
    {
        rows.push(SqlObservation::PostgresColumn {
            object_id: 42,
            column_id: (index + 1) as u32,
            name: (*name).into(),
            plain: true,
        });
    }
    assert!(super::benchmark::metadata_matches(&rows, template));
    if let SqlObservation::PostgresColumn { plain, .. } = &mut rows[2] {
        *plain = false;
    }
    assert!(!super::benchmark::metadata_matches(&rows, template));
    rows.pop();
    assert!(!super::benchmark::metadata_matches(&rows, template));
}

const PG_ESTIMATE: &str = r#"[{"Plan":{"Node Type":"Seq Scan","Plan Rows":10,"Total Cost":12.5,"Filter":"password = 'secret-literal'"}}]"#;
const PG_ACTUAL: &str = r#"[{"Plan":{"Node Type":"Sort","Plan Rows":10,"Actual Rows":25,"Actual Loops":1,"Sort Space Type":"Disk","Sort Key":["secret-literal"],"Plans":[{"Node Type":"Seq Scan","Plan Rows":10,"Actual Rows":25,"Temp Written Blocks":2}]}}]"#;
const XML_ESTIMATE: &str = r#"<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan"><BatchSequence><Batch><Statements><StmtSimple StatementText="SELECT secret"><QueryPlan><RelOp NodeId="0" PhysicalOp="Table Scan" EstimateRows="12" EstimatedTotalSubtreeCost="0.4"/></QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>"#;
const XML_ACTUAL: &str = r#"<ShowPlanXML><BatchSequence><Batch><Statements><StmtSimple><QueryPlan><RelOp NodeId="0" PhysicalOp="Sort" EstimateRows="12"><RunTimeInformation><RunTimeCountersPerThread ActualRows="20" ActualExecutions="1" ActualElapsedms="7"/></RunTimeInformation><Warnings><SpillToTempDb SpillLevel="1"/></Warnings><RelOp NodeId="1" PhysicalOp="Index Scan" EstimateRows="12"/></RelOp></QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>"#;

#[test]
fn plan_import_normalizes_psql_bom_and_redacts_literals() {
    let report = plans::parse_import(
        PlanImportFormat::PostgresJson,
        PG_ESTIMATE.as_bytes(),
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(!report.has_actuals && !report.has_spill_evidence && !report.can_prove_live());
    assert!(!format!("{report:?}").contains("secret-literal"));
    let aligned = format!(
        "SET\n QUERY PLAN\n ----------\n [ +\n {{ +\n \"Plan\": {{ \"Node Type\": \"Sort\", \"Plan Rows\": 1 }} +\n }} +\n ]\n (1 row)\n"
    );
    let utf16: Vec<u8> = [
        vec![0xff, 0xfe],
        aligned.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    ]
    .concat();
    let result = plans::parse_import(
        PlanImportFormat::PsqlAlignedExplainJson,
        &utf16,
        ImportSource::ExternalExport,
    )
    .unwrap();
    assert_eq!(result.roots[0].operator, "Sort");
    let utf16_be: Vec<u8> = [
        vec![0xfe, 0xff],
        aligned.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    ]
    .concat();
    assert!(
        plans::parse_import(
            PlanImportFormat::PsqlAlignedExplainJson,
            &utf16_be,
            ImportSource::ExternalExport
        )
        .is_ok()
    );
    assert!(
        plans::parse_import(
            PlanImportFormat::PsqlAlignedExplainJson,
            format!("{aligned}(1 row)\n").as_bytes(),
            ImportSource::OperatorFile
        )
        .is_err()
    );
    assert!(
        plans::parse_import(
            PlanImportFormat::PsqlAlignedExplainJson,
            format!("\u{feff}{aligned}").as_bytes(),
            ImportSource::OperatorFile
        )
        .is_ok()
    );
    let actual = plans::parse_import(
        PlanImportFormat::PostgresJson,
        PG_ACTUAL.as_bytes(),
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(actual.has_actuals && actual.has_spill_evidence);
    assert_eq!(actual.roots[0].spill, Some(Spill::DiskSort));
    assert!(!format!("{actual:?}").contains("secret-literal"));
    let temp_only = br#"[{"Plan":{"Node Type":"Seq Scan","Temp Written Blocks":2}}]"#;
    let temp_report = plans::parse_import(
        PlanImportFormat::PostgresJson,
        temp_only,
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(temp_report.has_temp_io && !temp_report.has_spill_evidence);
}

#[test]
fn genuine_synthetic_psql_export_remains_imported_and_redacted() {
    let raw = include_bytes!("../../../tests/fixtures/helper/sql/reference-sort-before.psql");
    let report = plans::parse_import(
        PlanImportFormat::PsqlAlignedExplainJson,
        raw,
        ImportSource::ExternalExport,
    )
    .unwrap();
    assert!(report.has_actuals && report.has_spill_evidence && !report.can_prove_live());
    assert_eq!(report.roots[0].operator, "Sort");
    assert_eq!(report.roots[0].spill, Some(Spill::DiskSort));
    assert!(!format!("{report:?}").contains("Sort Key"));
}

#[test]
fn plan_import_sql_server_distinguishes_estimates_and_actuals() {
    let estimate = plans::parse_import(
        PlanImportFormat::SqlServerShowplanXml,
        XML_ESTIMATE.as_bytes(),
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(!estimate.has_actuals && !estimate.has_spill_evidence && !estimate.can_prove_live());
    assert!(!format!("{estimate:?}").contains("SELECT secret"));
    let actual = plans::parse_import(
        PlanImportFormat::SqlServerShowplanXml,
        XML_ACTUAL.as_bytes(),
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(actual.has_actuals && actual.has_spill_evidence);
    assert_eq!(actual.operators(), 2);
    assert_eq!(actual.roots[0].actual_rows, Some(20.0));
    assert_eq!(actual.roots[0].spill, Some(Spill::SqlServerSpill));
    let grant_warning =
        XML_ACTUAL.replace("<SpillToTempDb SpillLevel=\"1\"/>", "<MemoryGrantWarning/>");
    let warning_only = plans::parse_import(
        PlanImportFormat::SqlServerShowplanXml,
        grant_warning.as_bytes(),
        ImportSource::OperatorFile,
    )
    .unwrap();
    assert!(!warning_only.has_spill_evidence);
}

#[test]
fn plan_import_rejects_bombs_ambiguous_wrappers_and_wrong_roots() {
    assert!(
        plans::parse_import(
            PlanImportFormat::PostgresJson,
            &vec![b' '; plans::MAX_PLAN_BYTES + 1],
            ImportSource::OperatorFile
        )
        .is_err()
    );
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(
        plans::parse_import(
            PlanImportFormat::PostgresJson,
            deep.as_bytes(),
            ImportSource::OperatorFile
        )
        .is_err()
    );
    let many = format!(
        "[{{\"Plan\":{{\"Node Type\":\"Append\",\"Plans\":[{}]}}}}]",
        vec!["{\"Node Type\":\"Seq Scan\"}"; 4097].join(",")
    );
    assert!(
        plans::parse_import(
            PlanImportFormat::PostgresJson,
            many.as_bytes(),
            ImportSource::OperatorFile
        )
        .is_err()
    );
    let many_xml = format!(
        "<ShowPlanXML><BatchSequence><Batch><Statements><StmtSimple><QueryPlan><RelOp PhysicalOp=\"Sort\"/>{}</QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>",
        "<Other/>".repeat(4097)
    );
    assert!(
        plans::parse_import(
            PlanImportFormat::SqlServerShowplanXml,
            many_xml.as_bytes(),
            ImportSource::OperatorFile
        )
        .is_err()
    );
    let deep_xml = format!(
        "<ShowPlanXML><BatchSequence><Batch><Statements><StmtSimple><QueryPlan>{}<RelOp PhysicalOp=\"Sort\"/>{}</QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>",
        "<Other>".repeat(65),
        "</Other>".repeat(65)
    );
    assert!(
        plans::parse_import(
            PlanImportFormat::SqlServerShowplanXml,
            deep_xml.as_bytes(),
            ImportSource::OperatorFile
        )
        .is_err()
    );
    let duplicate = br#"[{"Plan":{"Node Type":"Seq Scan","Node Type":"Index Scan"}}]"#;
    assert!(
        plans::parse_import(
            PlanImportFormat::PostgresJson,
            duplicate,
            ImportSource::OperatorFile
        )
        .is_err()
    );
    for invalid in [
        "<!DOCTYPE a><ShowPlanXML/>",
        "<?evil x?><ShowPlanXML/>",
        "<ShowPlanXML>&x;</ShowPlanXML>",
        "<wrong/>",
        "<ShowPlanXML>",
    ] {
        assert!(
            plans::parse_import(
                PlanImportFormat::SqlServerShowplanXml,
                invalid.as_bytes(),
                ImportSource::OperatorFile
            )
            .is_err(),
            "{invalid}"
        );
    }
    for invalid in [
        "SET\nnoise\n[{}]",
        "[{}]\n[{}]",
        "QUERY PLAN\n----\nnot json",
        "[{}]",
    ] {
        assert!(
            plans::parse_import(
                PlanImportFormat::PsqlAlignedExplainJson,
                invalid.as_bytes(),
                ImportSource::OperatorFile
            )
            .is_err()
        );
    }
}

fn fixture_scope(object: &str) -> BoundScope {
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
        engine: DatabaseEngine::Postgres,
        port: 55433,
        database: "relayne_helper_acceptance".into(),
        schema: Some("fixture".into()),
        object: Some(object.into()),
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

fn sqlserver_fixture_scope(object: &str) -> BoundScope {
    let mut scope = fixture_scope(object);
    if let BoundScope::Database {
        engine,
        port,
        credential,
        ..
    } = &mut scope
    {
        *engine = DatabaseEngine::SqlServer;
        *port = 1433;
        *credential = None;
    }
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
fn sql_server_showplan_templates_are_fixed_bound_and_loopback_only() {
    let scope = sqlserver_fixture_scope("orders");
    let customer = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let statement = customer.sql_server_statement(&scope).unwrap();
    assert!(statement.sql.contains("[fixture].[orders]"));
    assert!(statement.sql.contains("@P1") && statement.sql.contains("TOP (100)"));
    assert!(!statement.sql.contains("424242") && !statement.sql.contains("EXPLAIN"));
    assert_eq!(customer.fingerprint(&scope).unwrap(), statement.fingerprint);
    assert_eq!(
        ReviewedSelectTemplate::from_fingerprint(&scope, &statement.fingerprint),
        Some(customer)
    );
    let status = ReviewedSelectTemplate::StatusCount {
        status: OrderStatus::Pending,
    };
    assert!(
        status
            .sql_server_statement(&scope)
            .unwrap()
            .sql
            .contains("COUNT_BIG(*)")
    );
    let sort = ReviewedSelectTemplate::OrderSort;
    assert!(
        sort.sql_server_statement(&sqlserver_fixture_scope("spill_events"))
            .unwrap()
            .sql
            .contains("ORDER BY [payload], [event_id]")
    );
    let mut remote = scope.clone();
    if let BoundScope::Database {
        target, credential, ..
    } = &mut remote
    {
        target.host = "192.0.2.42".into();
        *credential = None;
    }
    let resource = remote.resource_digest().unwrap();
    if let BoundScope::Database { credential, .. } = &mut remote {
        *credential = Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::Read,
            generation: 1,
            principal: "reader".into(),
            context: "fixture".into(),
            context_digest: resource,
        });
    }
    assert!(remote.validate().is_ok());
    assert!(customer.sql_server_statement(&remote).is_err());
    assert!(
        customer
            .sql_server_statement(&fixture_scope("orders"))
            .is_err()
    );
}

#[test]
fn reviewed_templates_are_closed_bound_and_fixture_only() {
    let customer = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let scope = fixture_scope("orders");
    let statement = customer.reviewed_statement(&scope).unwrap();
    assert!(
        statement
            .explain_sql
            .starts_with("EXPLAIN (FORMAT JSON) SELECT ")
    );
    assert!(!statement.explain_sql.contains("ANALYZE"));
    assert!(statement.sql.contains("$1") && statement.sql.contains("\"fixture\".\"orders\""));
    assert!(!statement.sql.contains("424242"));
    assert!(
        ReviewedSelectTemplate::StatusCount {
            status: OrderStatus::Pending
        }
        .reviewed_statement(&scope)
        .is_ok()
    );
    assert!(
        ReviewedSelectTemplate::OrderSort
            .reviewed_statement(&fixture_scope("spill_events"))
            .is_ok()
    );
    let mut wrong = scope.clone();
    if let BoundScope::Database { object, .. } = &mut wrong {
        *object = Some("orders; DROP TABLE x".into());
    }
    assert!(customer.reviewed_statement(&wrong).is_err());
    let mut wrong = scope.clone();
    if let BoundScope::Database { engine, .. } = &mut wrong {
        *engine = DatabaseEngine::SqlServer;
    }
    assert!(customer.reviewed_statement(&wrong).is_err());
}

#[tokio::test]
async fn canceled_estimate_stops_before_credentials_or_network() {
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let result = plans::estimated_plan(
        &fixture_scope("orders"),
        &ReviewedSelectTemplate::CustomerOrders {
            customer_id: 424242,
        },
        cancel,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("canceled"));
}

fn sample(times: Vec<f64>) -> WorkloadSamples {
    WorkloadSamples {
        policy_version: 1,
        case_id: Uuid::new_v4(),
        case_revision: 1,
        review_evidence_id: Uuid::new_v4(),
        review_content_sha256: "a".repeat(64),
        scope_sha256: "b".repeat(64),
        workload_fingerprint: "c".repeat(64),
        result_sha256: "d".repeat(64),
        environment_fingerprint: "e".repeat(64),
        live_metadata_sha256: "f".repeat(64),
        compatibility: CompatibilityEvidence::incomplete(
            CompatibilityEngine::Postgres,
            Some("e".repeat(64)),
            None,
        ),
        warmups: 3,
        milliseconds: times,
        median_ms: 100.0,
        p95_ms: 100.0,
        mad_ms: 0.0,
        approved_change_sha256: None,
    }
}

#[test]
fn workload_comparison_requires_repeated_compatible_samples_and_change_receipt() {
    assert!(SamplingPolicy::default().validate().is_ok());
    assert!(
        SamplingPolicy {
            warmups: 0,
            samples: 1,
            deadline_secs: 30
        }
        .validate()
        .is_err()
    );
    let before = sample(vec![100.0; 15]);
    let mut after = sample(vec![50.0; 15]);
    after.case_id = before.case_id;
    let change = "f".repeat(64);
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
    after.approved_change_sha256 = Some(change.clone());
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
    after.result_sha256 = "0".repeat(64);
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
    after.result_sha256 = before.result_sha256.clone();
    after.milliseconds = vec![50.0];
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
}

#[test]
fn result_and_approved_change_cannot_invent_environment_completeness() {
    let before = sample(vec![100.0; 15]);
    let mut after = sample(vec![50.0; 15]);
    after.case_id = before.case_id;
    let change = "f".repeat(64);
    after.approved_change_sha256 = Some(change.clone());

    // The SELECT result and legacy environment hash can match while an index,
    // optimizer setting, or other unobserved data state changes.
    after.compatibility = CompatibilityEvidence::incomplete(
        CompatibilityEngine::Postgres,
        Some("1".repeat(64)),
        None,
    );
    assert_eq!(before.result_sha256, after.result_sha256);
    assert_eq!(
        before.environment_fingerprint,
        after.environment_fingerprint
    );
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);

    // A missing post-sample snapshot cannot establish stability. Hand-building
    // equal-looking digests also leaves the native coverage gaps unresolved.
    after.compatibility = CompatibilityEvidence::incomplete(
        CompatibilityEngine::Postgres,
        Some("e".repeat(64)),
        None,
    );
    assert!(!after.compatibility.is_complete());
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
    after.compatibility = CompatibilityEvidence::incomplete(
        CompatibilityEngine::Postgres,
        Some("e".repeat(64)),
        Some("e".repeat(64)),
    );
    assert!(!after.compatibility.is_complete());
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
    after.compatibility = CompatibilityEvidence::incomplete(
        CompatibilityEngine::Postgres,
        Some("e".repeat(64)),
        Some("2".repeat(64)),
    );
    assert_eq!(compare(&before, &after, &change), Comparison::Inconclusive);
}

#[test]
fn persisted_workload_compatibility_defaults_incomplete_for_legacy_artifacts() {
    use super::artifacts::{SqlArtifact, WorkloadArtifact};
    let artifact = WorkloadArtifact::from_samples(&sample(vec![100.0; 15])).unwrap();
    let mut value = serde_json::to_value(&artifact).unwrap();
    assert!(value["compatibility"]["missing"].is_array());
    assert_eq!(value["compatibility"]["status"], "incomplete");
    let mut forged = value.clone();
    forged["compatibility"]["status"] = serde_json::json!("native_complete");
    forged["compatibility"]["missing"] = serde_json::json!([]);
    forged["compatibility"]["observed_post_sha256"] = serde_json::json!("e".repeat(64));
    let forged: WorkloadArtifact = serde_json::from_value(forged).unwrap();
    assert!(SqlArtifact::Workload(forged).validate().is_err());
    value.as_object_mut().unwrap().remove("compatibility");
    let legacy: WorkloadArtifact = serde_json::from_value(value).unwrap();
    assert!(!legacy.compatibility.is_complete());
    SqlArtifact::Workload(legacy).validate().unwrap();
}
