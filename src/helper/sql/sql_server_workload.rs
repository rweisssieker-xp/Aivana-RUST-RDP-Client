//! Repeated, bounded execution of the closed SQL Server fixture SELECTs.

use super::*;
use crate::helper::credentials::{PersistentSecretResolver, SecretResolver};
use crate::helper::sql::{
    benchmark::{
        self, CompatibilityEngine, CompatibilityEvidence, POLICY_VERSION, ReviewedWorkload,
        SamplingPolicy, WorkloadSamples,
    },
    templates::{FIXTURE_SCHEMA, TemplateBind, TemplateStatement},
};
use anyhow::Context;

trait WorkloadSession: Send {
    fn compatibility_snapshot<'a>(
        &'a mut self,
        statement: &'a TemplateStatement,
    ) -> TdsFuture<'a, String>;
    fn identity<'a>(&'a mut self) -> TdsFuture<'a, Vec<SqlObservation>>;
    fn read_object<'a>(
        &'a mut self,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>>;
    fn run_once<'a>(&'a mut self, statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<i64>>;
}

impl WorkloadSession for NativeSession {
    fn compatibility_snapshot<'a>(
        &'a mut self,
        statement: &'a TemplateStatement,
    ) -> TdsFuture<'a, String> {
        Box::pin(async move { NativeSession::compatibility_snapshot(self, statement).await })
    }
    fn identity<'a>(&'a mut self) -> TdsFuture<'a, Vec<SqlObservation>> {
        <Self as Session>::read(self, SqlServerReadProbe::Identity, "", "")
    }

    fn read_object<'a>(
        &'a mut self,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>> {
        <Self as Session>::read(self, SqlServerReadProbe::Objects, schema, object)
    }

    fn run_once<'a>(&'a mut self, statement: &'a TemplateStatement) -> TdsFuture<'a, Vec<i64>> {
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
            let mut values = Vec::new();
            while let Some(item) = stream.next().await {
                if let QueryItem::Row(row) = item.map_err(driver_error)? {
                    if row.columns().len() != 1 || values.len() == 100 {
                        return Err(Failure::InvalidProjection);
                    }
                    let value = row
                        .try_get::<i64, _>(0)
                        .ok()
                        .flatten()
                        .or_else(|| row.try_get::<i32, _>(0).ok().flatten().map(i64::from))
                        .ok_or(Failure::InvalidProjection)?;
                    values.push(value);
                }
            }
            Ok(values)
        })
    }
}

async fn collect_with_session(
    session: &mut dyn WorkloadSession,
    request: &ReviewedWorkload,
    statement: &TemplateStatement,
    policy: &SamplingPolicy,
    expected_identity: (&str, &str, &str, u16),
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<WorkloadSamples> {
    policy.validate()?;
    ensure!(!cancel.is_cancelled(), "SQL Server workload canceled");
    ensure!(
        chrono::Utc::now().signed_duration_since(request.reviewed_at)
            < chrono::Duration::minutes(5),
        "SQL Server workload review expired"
    );
    let identity = gated(cancel, deadline, session.identity())
        .await
        .map_err(|_| anyhow::anyhow!("SQL Server workload identity unavailable"))?;
    verify_identity(
        &identity,
        expected_identity.0,
        expected_identity.1,
        expected_identity.2,
        expected_identity.3,
    )?;
    let metadata = gated(
        cancel,
        deadline,
        session.read_object(FIXTURE_SCHEMA, statement.object),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server workload metadata unavailable"))?;
    ensure!(
        metadata.len() == request.template.expected_columns().len() + 1
            && benchmark::sql_server_metadata_matches(&metadata, request.template),
        "SQL Server workload fixture object or columns mismatch"
    );
    let mut metadata_hash = Sha256::new();
    metadata_hash.update(b"relayne-sqlserver-workload-metadata-v1\0");
    metadata_hash.update(request.scope.digest()?.as_bytes());
    metadata_hash.update(serde_json::to_vec(&metadata)?);
    let metadata_sha256 = format!("{:x}", metadata_hash.finalize());
    let compatibility_before = gated(cancel, deadline, session.compatibility_snapshot(statement))
        .await
        .ok();

    let mut samples = Vec::with_capacity(policy.samples as usize);
    let mut result_digest: Option<String> = None;
    for index in 0..usize::from(policy.warmups + policy.samples) {
        let started = Instant::now();
        let values = gated(cancel, deadline, session.run_once(statement))
            .await
            .map_err(|_| anyhow::anyhow!("SQL Server workload incomplete"))?;
        ensure!(
            values.len() <= 100,
            "SQL Server workload result exceeds row limit"
        );
        let mut result_hash = Sha256::new();
        result_hash.update(b"relayne-workload-result-v1\0");
        result_hash.update((values.len() as u32).to_be_bytes());
        for value in values {
            result_hash.update(value.to_be_bytes());
        }
        let current = format!("{:x}", result_hash.finalize());
        if let Some(previous) = &result_digest {
            ensure!(previous == &current, "SQL Server workload results changed");
        } else {
            result_digest = Some(current);
        }
        if index >= usize::from(policy.warmups) {
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            ensure!(
                elapsed_ms.is_finite() && elapsed_ms > 0.0,
                "Invalid workload clock sample"
            );
            samples.push(elapsed_ms);
        }
    }
    let compatibility_after = gated(cancel, deadline, session.compatibility_snapshot(statement))
        .await
        .ok();
    let compatibility = match (&compatibility_before, &compatibility_after) {
        (Some(before), Some(after)) if before == after => CompatibilityEvidence::native_complete(
            CompatibilityEngine::SqlServer,
            before.clone(),
            after.clone(),
        )?,
        _ => CompatibilityEvidence::incomplete(
            CompatibilityEngine::SqlServer,
            compatibility_before,
            compatibility_after,
        ),
    };
    let (median_ms, p95_ms, mad_ms) = benchmark::summary(&samples)?;
    let mut environment = Sha256::new();
    environment.update(b"relayne-sqlserver-fixture-workload-v1\0");
    environment.update(request.scope.resource_digest()?.as_bytes());
    environment.update(serde_json::to_vec(&identity)?);
    environment.update(metadata_sha256.as_bytes());
    environment.update(env!("CARGO_PKG_VERSION").as_bytes());
    environment.update(if cfg!(debug_assertions) {
        &b"debug"[..]
    } else {
        &b"release"[..]
    });
    let environment_fingerprint = format!("{:x}", environment.finalize());
    Ok(WorkloadSamples {
        policy_version: POLICY_VERSION,
        case_id: request.case_id,
        case_revision: request.case_revision,
        review_evidence_id: request.review_evidence_id,
        review_content_sha256: request.review_content_sha256.clone(),
        scope_sha256: request.scope.digest()?,
        workload_fingerprint: statement.fingerprint.clone(),
        result_sha256: result_digest.ok_or_else(|| anyhow::anyhow!("Missing workload result"))?,
        environment_fingerprint: environment_fingerprint.clone(),
        live_metadata_sha256: metadata_sha256,
        compatibility,
        warmups: policy.warmups,
        milliseconds: samples,
        median_ms,
        p95_ms,
        mad_ms,
        approved_change_sha256: None,
    })
}

pub(in crate::helper::sql) async fn run_sandbox_workload(
    probe: &ProbeRequest,
    request: &ReviewedWorkload,
    policy: &SamplingPolicy,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<WorkloadSamples> {
    policy.validate()?;
    let scope_sha256 = request.scope.digest()?;
    ensure!(
        probe.scope.digest()? == scope_sha256
            && probe.binding.scope_sha256 == scope_sha256
            && probe.binding.credential_scope_sha256 == request.scope.credential_scope_digest()?
            && probe.binding.case_id == request.case_id
            && probe.binding.case_revision == request.case_revision,
        "SQL Server workload binding mismatch"
    );
    let BoundScope::Database {
        target,
        engine: DatabaseEngine::SqlServer,
        database,
        port,
        credential: Some(credential),
        ..
    } = &request.scope
    else {
        anyhow::bail!("SQL Server workload fixture scope required")
    };
    let statement = request.template.sql_server_statement(&request.scope)?;
    ensure!(
        probe.capability_id == CapabilityId::SqlWorkloadBaseline
            && matches!(&probe.params, ProbeParams::SqlWorkload { workload_digest, review_evidence_id, review_content_sha256 }
                if workload_digest == &statement.fingerprint
                    && review_evidence_id == &request.review_evidence_id
                    && review_content_sha256 == &request.review_content_sha256),
        "SQL Server reviewed workload mismatch"
    );
    let verified = open_verified_native(probe, secrets, cancel).await?;
    let VerifiedNativeSession {
        client,
        deadline,
        cancel,
    } = verified;
    let mut native = NativeSession { client };
    collect_with_session(
        &mut native,
        request,
        &statement,
        policy,
        (database, &credential.principal, &target.host, *port),
        &cancel,
        deadline,
    )
    .await
}

async fn open_rehearsal_fixture(
    scope: &BoundScope,
    template: crate::helper::sql::templates::ReviewedSelectTemplate,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<NativeSession> {
    template.sql_server_statement(scope)?;
    let BoundScope::Database {
        target,
        port,
        database,
        credential: Some(credential),
        ..
    } = scope
    else {
        anyhow::bail!("Attested SQL Server fixture scope required")
    };
    ensure!(
        credential.purpose == CredentialPurpose::Read,
        "SQL Server read credential required"
    );
    let secret = PersistentSecretResolver::new()?
        .resolve(credential, CredentialPurpose::Read)
        .context("SQL Server fixture credential unavailable")?;
    ensure!(
        secret.username() == credential.principal && secret.domain().is_empty(),
        "SQL Server fixture principal changed"
    );
    let session = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("SQL Server fixture canceled"),
        result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            NativeTransport::open_session(
                &target.host,
                *port,
                database,
                &credential.principal,
                secret.password(),
            ),
        ) => result.context("SQL Server fixture connection timed out")?
            .map_err(|_| anyhow::anyhow!("SQL Server fixture connection unavailable"))?,
    };
    drop(secret);
    Ok(session)
}

pub(in crate::helper::sql) async fn run_rehearsal_workload(
    request: &ReviewedWorkload,
    policy: &SamplingPolicy,
    cancel: CancellationToken,
) -> Result<WorkloadSamples> {
    policy.validate()?;
    let statement = request.template.sql_server_statement(&request.scope)?;
    let BoundScope::Database {
        target,
        port,
        database,
        credential: Some(credential),
        ..
    } = &request.scope
    else {
        anyhow::bail!("SQL Server rehearsal scope required")
    };
    let deadline = Instant::now() + Duration::from_secs(u64::from(policy.deadline_secs));
    let mut session =
        open_rehearsal_fixture(&request.scope, request.template, &cancel, deadline).await?;
    collect_with_session(
        &mut session,
        request,
        &statement,
        policy,
        (database, &credential.principal, &target.host, *port),
        &cancel,
        deadline,
    )
    .await
}

const TDS_ORDER_DATA_SQL: &str = "SELECT TOP (100001) CASE WHEN DATALENGTH(j.json_row) <= 16384 THEN j.json_row END FROM [fixture].[orders] AS t CROSS APPLY (SELECT (SELECT t.[order_id], t.[customer_id], t.[status], t.[amount], t.[created_at], t.[detail] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS json_row) AS j ORDER BY t.[order_id]";
const TDS_SORT_DATA_SQL: &str = "SELECT TOP (100001) CASE WHEN DATALENGTH(j.json_row) <= 16384 THEN j.json_row END FROM [fixture].[spill_events] AS t CROSS APPLY (SELECT (SELECT t.[event_id], t.[payload] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS json_row) AS j ORDER BY t.[event_id]";

pub(in crate::helper::sql) async fn fixture_data_observation(
    scope: &BoundScope,
    template: crate::helper::sql::templates::ReviewedSelectTemplate,
    cancel: CancellationToken,
) -> Result<benchmark::FixtureDataObservation> {
    let statement = template.sql_server_statement(scope)?;
    let BoundScope::Database {
        target,
        port,
        database,
        credential: Some(credential),
        ..
    } = scope
    else {
        anyhow::bail!("SQL Server rehearsal scope required")
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut session = open_rehearsal_fixture(scope, template, &cancel, deadline).await?;
    let identity = gated(
        &cancel,
        deadline,
        session.read(SqlServerReadProbe::Identity, "", ""),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server fixture identity unavailable"))?;
    verify_identity(
        &identity,
        database,
        &credential.principal,
        &target.host,
        *port,
    )?;
    let object = gated(
        &cancel,
        deadline,
        session.read(
            SqlServerReadProbe::Objects,
            FIXTURE_SCHEMA,
            statement.object,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server fixture metadata unavailable"))?;
    ensure!(
        benchmark::sql_server_metadata_matches(&object, template),
        "SQL Server fixture column identity changed"
    );
    let sql = if matches!(
        template,
        crate::helper::sql::templates::ReviewedSelectTemplate::OrderSort
    ) {
        TDS_SORT_DATA_SQL
    } else {
        TDS_ORDER_DATA_SQL
    };
    let mut stream = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("SQL Server data digest canceled"),
        result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Query::new(sql).query(&mut session.client),
        ) => result.context("SQL Server data digest timed out")?
            .map_err(|_| anyhow::anyhow!("SQL Server data digest unavailable"))?,
    };
    let mut bounded = benchmark::BoundedFixtureHasher::new();
    loop {
        let item = tokio::select! {
            _ = cancel.cancelled() => anyhow::bail!("SQL Server data digest canceled"),
            result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                stream.next(),
            ) => result.context("SQL Server data digest timed out")?,
        };
        let Some(item) = item else { break };
        if let QueryItem::Row(row) =
            item.map_err(|_| anyhow::anyhow!("SQL Server data digest unavailable"))?
        {
            let value = row
                .try_get::<&str, _>(0)
                .map_err(|_| anyhow::anyhow!("SQL Server data row invalid"))?
                .context("SQL Server data row exceeds field bound")?;
            bounded.push(value)?;
        }
    }
    bounded.finish()
}

#[cfg(test)]
#[path = "sql_server_workload_tests.rs"]
mod tests;
