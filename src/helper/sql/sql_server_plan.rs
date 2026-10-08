//! Dedicated, passive SHOWPLAN collection on the verified native TDS session.
//! The transport trait is private and accepts only a closed fixture statement.

use super::*;
use crate::helper::sql::{
    plans::{self, PlanImportFormat, PlanReport},
    templates::{FIXTURE_SCHEMA, ReviewedSelectTemplate, TemplateBind, TemplateStatement},
};
use tiberius::xml::XmlData;

trait PlanSession: Send {
    fn read_object<'a>(
        &'a mut self,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>>;
    fn showplan<'a>(&'a mut self, enabled: bool) -> TdsFuture<'a, ()>;
    fn explain<'a>(&'a mut self, statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<u8>>;
}

impl PlanSession for NativeSession {
    fn read_object<'a>(
        &'a mut self,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>> {
        <Self as Session>::read(self, SqlServerReadProbe::Objects, schema, object)
    }

    fn showplan<'a>(&'a mut self, enabled: bool) -> TdsFuture<'a, ()> {
        Box::pin(async move {
            let statement = if enabled {
                "SET SHOWPLAN_XML ON"
            } else {
                "SET SHOWPLAN_XML OFF"
            };
            let mut stream = self
                .client
                .simple_query(statement)
                .await
                .map_err(driver_error)?;
            while let Some(item) = stream.next().await {
                if matches!(item.map_err(driver_error)?, QueryItem::Row(_)) {
                    return Err(Failure::InvalidProjection);
                }
            }
            Ok(())
        })
    }

    fn explain<'a>(&'a mut self, statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let mut query = Query::new(statement.sql);
            match statement.bind {
                TemplateBind::None => {}
                TemplateBind::Integer(value) => {
                    query.bind(value);
                }
                TemplateBind::Status(value) => {
                    query.bind(value.as_str());
                }
            }
            let mut stream = query.query(&mut self.client).await.map_err(driver_error)?;
            let mut result = None;
            while let Some(item) = stream.next().await {
                if let QueryItem::Row(row) = item.map_err(driver_error)? {
                    if result.is_some() {
                        return Err(Failure::InvalidProjection);
                    }
                    let xml = if let Ok(Some(xml)) = row.try_get::<&XmlData, _>(0) {
                        xml.as_ref()
                    } else {
                        row.try_get::<&str, _>(0)
                            .map_err(|_| Failure::InvalidProjection)?
                            .ok_or(Failure::InvalidProjection)?
                    };
                    if xml.as_bytes().len() > plans::MAX_PLAN_BYTES {
                        return Err(Failure::InvalidProjection);
                    }
                    result = Some(xml.as_bytes().to_vec());
                }
            }
            result.ok_or(Failure::InvalidProjection)
        })
    }
}

fn fixture_metadata_matches(rows: &[SqlObservation], template: ReviewedSelectTemplate) -> bool {
    let expected = template.expected_columns();
    if rows.len() != expected.len() + 1 {
        return false;
    }
    let Some(SqlObservation::SqlServerObject {
        schema,
        name,
        object_id,
        column_count,
    }) = rows.first()
    else {
        return false;
    };
    if schema != FIXTURE_SCHEMA
        || name != template.object()
        || *object_id == 0
        || *column_count as usize != expected.len()
    {
        return false;
    }
    let mut names = std::collections::BTreeSet::new();
    let mut column_ids = std::collections::BTreeSet::new();
    for row in rows.iter().skip(1) {
        let SqlObservation::SqlServerColumn {
            object_id: id,
            column_id,
            name,
            plain,
        } = row
        else {
            return false;
        };
        if id != object_id
            || *column_id == 0
            || !plain
            || !expected.contains(&name.as_str())
            || !names.insert(name.as_str())
            || !column_ids.insert(*column_id)
        {
            return false;
        }
    }
    names.len() == expected.len()
}

async fn collect_with_session(
    session: &mut dyn PlanSession,
    template: ReviewedSelectTemplate,
    statement: &TemplateStatement,
    scope_sha256: &str,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<(Vec<u8>, String)> {
    ensure!(!cancel.is_cancelled(), "SQL Server plan canceled");
    let metadata = gated(
        cancel,
        deadline,
        session.read_object(FIXTURE_SCHEMA, statement.object),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server fixture metadata unavailable"))?;
    ensure!(
        fixture_metadata_matches(&metadata, template),
        "SQL Server fixture object or columns mismatch"
    );
    let mut hash = Sha256::new();
    hash.update(b"relayne-sqlserver-plan-metadata-v1\0");
    hash.update(scope_sha256.as_bytes());
    hash.update(serde_json::to_vec(&metadata)?);
    let metadata_sha256 = format!("{:x}", hash.finalize());

    gated(cancel, deadline, session.showplan(true))
        .await
        .map_err(|_| anyhow::anyhow!("SQL Server SHOWPLAN unavailable"))?;
    let plan = gated(cancel, deadline, session.explain(statement)).await;
    // SHOWPLAN is connection state. Try OFF even after cancellation; the dedicated
    // connection is dropped immediately if either collection or cleanup fails.
    let cleanup = tokio::time::timeout(Duration::from_secs(1), session.showplan(false)).await;
    let bytes = plan.map_err(|_| anyhow::anyhow!("SQL Server plan collection incomplete"))?;
    ensure!(
        matches!(cleanup, Ok(Ok(()))),
        "SQL Server SHOWPLAN cleanup failed"
    );
    Ok((bytes, metadata_sha256))
}

pub(in crate::helper::sql) async fn estimated_plan(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<PlanReport> {
    let ProbeParams::SqlPlan { query_digest } = &request.params else {
        anyhow::bail!("SQL Server plan request mismatch")
    };
    let template = ReviewedSelectTemplate::from_fingerprint(&request.scope, query_digest)
        .ok_or_else(|| anyhow::anyhow!("Unregistered SQL Server fixture template"))?;
    let statement = template.sql_server_statement(&request.scope)?;
    let verified = open_verified_native(request, secrets, cancel).await?;
    let VerifiedNativeSession {
        client,
        deadline,
        cancel,
    } = verified;
    let mut native = NativeSession { client };
    let (bytes, metadata) = collect_with_session(
        &mut native,
        template,
        &statement,
        &request.binding.scope_sha256,
        &cancel,
        deadline,
    )
    .await?;
    plans::parse_live_estimate(PlanImportFormat::SqlServerShowplanXml, &bytes)?
        .with_live_metadata(metadata)
}

#[cfg(test)]
#[path = "sql_server_plan_tests.rs"]
mod tests;
