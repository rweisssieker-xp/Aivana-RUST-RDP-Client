use super::*;

const XML_ESTIMATE: &str = r#"<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan"><BatchSequence><Batch><Statements><StmtSimple StatementText="SELECT secret"><QueryPlan><RelOp NodeId="0" PhysicalOp="Table Scan" EstimateRows="12" EstimatedTotalSubtreeCost="0.4"/></QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>"#;

struct FakePlanSession {
    metadata: Vec<SqlObservation>,
    calls: Vec<&'static str>,
    fail_explain: bool,
}

impl PlanSession for FakePlanSession {
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
    fn showplan<'a>(&'a mut self, enabled: bool) -> TdsFuture<'a, ()> {
        Box::pin(async move {
            self.calls.push(if enabled { "on" } else { "off" });
            Ok(())
        })
    }
    fn explain<'a>(&'a mut self, _statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.calls.push("explain");
            if self.fail_explain {
                Err(Failure::Unavailable)
            } else {
                Ok(XML_ESTIMATE.as_bytes().to_vec())
            }
        })
    }
}

fn metadata() -> Vec<SqlObservation> {
    let expected = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    }
    .expected_columns();
    let mut rows = vec![SqlObservation::SqlServerObject {
        schema: FIXTURE_SCHEMA.into(),
        name: "orders".into(),
        object_id: 42,
        column_count: expected.len() as u32,
    }];
    for (index, name) in expected.iter().enumerate() {
        rows.push(SqlObservation::SqlServerColumn {
            object_id: 42,
            column_id: (index + 1) as u32,
            name: (*name).into(),
            plain: true,
        });
    }
    rows
}

fn statement() -> TemplateStatement {
    TemplateStatement {
        sql: "SELECT TOP (100) [order_id] FROM [fixture].[orders] WHERE [customer_id] = @P1 ORDER BY [order_id]",
        explain_sql: "SELECT TOP (100) [order_id] FROM [fixture].[orders] WHERE [customer_id] = @P1 ORDER BY [order_id]",
        bind: TemplateBind::Integer(424242),
        fingerprint: "a".repeat(64),
        object: "orders",
    }
}

#[tokio::test]
async fn showplan_collects_estimate_on_dedicated_session_then_turns_it_off() {
    let mut fake = FakePlanSession {
        metadata: metadata(),
        calls: vec![],
        fail_explain: false,
    };
    let (xml, metadata_sha256) = collect_with_session(
        &mut fake,
        ReviewedSelectTemplate::CustomerOrders {
            customer_id: 424242,
        },
        &statement(),
        &"b".repeat(64),
        &CancellationToken::new(),
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(fake.calls, ["metadata", "on", "explain", "off"]);
    let report = plans::parse_live_estimate(PlanImportFormat::SqlServerShowplanXml, &xml)
        .unwrap()
        .with_live_metadata(metadata_sha256)
        .unwrap();
    assert!(report.can_prove_live());
    assert!(!report.can_prove_execution());
    assert!(!format!("{report:?}").contains("SELECT secret"));
}

#[tokio::test]
async fn metadata_mismatch_stops_before_showplan_and_failure_cleans_up() {
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let mut wrong = metadata();
    if let SqlObservation::SqlServerColumn { plain, .. } = &mut wrong[1] {
        *plain = false;
    }
    let mut fake = FakePlanSession {
        metadata: wrong,
        calls: vec![],
        fail_explain: false,
    };
    assert!(
        collect_with_session(
            &mut fake,
            template,
            &statement(),
            &"b".repeat(64),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert_eq!(fake.calls, ["metadata"]);

    let mut fake = FakePlanSession {
        metadata: metadata(),
        calls: vec![],
        fail_explain: true,
    };
    assert!(
        collect_with_session(
            &mut fake,
            template,
            &statement(),
            &"b".repeat(64),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert_eq!(fake.calls, ["metadata", "on", "explain", "off"]);
}
