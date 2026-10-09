//! Explicit, reviewed sandbox workload execution and conservative comparison.
use super::templates::{connect_fixture, ReviewedSelectTemplate, TemplateBind};
use crate::helper::{
    case::HelperCase,
    evidence::Eligibility,
    manifest::CapabilityId,
    scope::{BoundScope, DatabaseEngine},
    sql::types::SqlObservation,
};
use anyhow::{ensure, Context, Result};
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const POLICY_VERSION: u16 = 1;
#[derive(Clone, Copy, Debug)]
pub struct SamplingPolicy {
    pub warmups: u8,
    pub samples: u8,
    pub deadline_secs: u8,
}
impl Default for SamplingPolicy {
    fn default() -> Self {
        Self {
            warmups: 3,
            samples: 15,
            deadline_secs: 30,
        }
    }
}
impl SamplingPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.warmups == 3
                && (15..=30).contains(&self.samples)
                && (1..=30).contains(&self.deadline_secs),
            "unsupported sampling policy"
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ReviewedWorkload {
    pub(super) scope: BoundScope,
    pub(super) template: ReviewedSelectTemplate,
    pub(super) case_id: Uuid,
    pub(super) case_revision: u64,
    pub(super) review_evidence_id: Uuid,
    pub(super) review_content_sha256: String,
    pub(super) reviewed_at: chrono::DateTime<chrono::Utc>,
}

/// Captures the exact reviewed read before the native action starts. The same
/// read can be repeated after commit even if its five-minute admission window
/// has elapsed; native identity, metadata, data and deadline checks still run.
pub(super) struct PostcommitWorkloadAdmission(ReviewedWorkload);

impl PostcommitWorkloadAdmission {
    pub(super) fn request(&self) -> &ReviewedWorkload {
        &self.0
    }
}

pub(super) fn admit_postcommit_workload(
    request: &ReviewedWorkload,
) -> Result<PostcommitWorkloadAdmission> {
    admit_postcommit_workload_at(request, chrono::Utc::now())
}

fn admit_postcommit_workload_at(
    request: &ReviewedWorkload,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PostcommitWorkloadAdmission> {
    ensure_review_freshness_at(request, now)?;
    request.fingerprint()?;
    Ok(PostcommitWorkloadAdmission(request.clone()))
}

#[cfg(test)]
pub(super) fn test_admit_postcommit_workload_at(
    request: &ReviewedWorkload,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PostcommitWorkloadAdmission> {
    admit_postcommit_workload_at(request, now)
}

fn ensure_review_freshness(request: &ReviewedWorkload) -> Result<()> {
    ensure_review_freshness_at(request, chrono::Utc::now())
}

fn ensure_review_freshness_at(
    request: &ReviewedWorkload,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure!(
        now >= request.reviewed_at
            && now.signed_duration_since(request.reviewed_at) < chrono::Duration::minutes(5),
        "workload review expired"
    );
    Ok(())
}
impl ReviewedWorkload {
    pub(crate) fn identity_sha256(&self) -> Result<String> {
        crate::helper_action::digest(
            b"relayne-reviewed-workload-identity-v1",
            &(
                &self.scope,
                self.template,
                self.case_id,
                self.case_revision,
                self.review_evidence_id,
                &self.review_content_sha256,
                self.reviewed_at,
            ),
        )
    }
    pub(crate) fn scope_digest(&self) -> Result<String> {
        self.scope.digest()
    }
    pub(crate) fn case_binding(&self) -> (Uuid, u64) {
        (self.case_id, self.case_revision)
    }
    pub(crate) fn from_validated_request(
        request: &crate::helper::capability::ProbeRequest,
        template: ReviewedSelectTemplate,
        review_evidence_id: Uuid,
        review_content_sha256: String,
    ) -> Self {
        Self {
            scope: request.scope.clone(),
            template,
            case_id: request.binding.case_id,
            case_revision: request.binding.case_revision,
            review_evidence_id,
            review_content_sha256,
            reviewed_at: request.requested_at,
        }
    }
    pub(crate) fn review_content_sha256(&self) -> &str {
        &self.review_content_sha256
    }
    /// A UI action may create this only from a fresh live SQL-read capture for the exact case scope.
    pub fn review(
        case: &HelperCase,
        scope: &BoundScope,
        template: ReviewedSelectTemplate,
        evidence_id: Uuid,
    ) -> Result<Self> {
        match scope {
            BoundScope::Database {
                engine: crate::helper::scope::DatabaseEngine::Postgres,
                ..
            } => {
                template.reviewed_statement(scope)?;
            }
            BoundScope::Database {
                engine: crate::helper::scope::DatabaseEngine::SqlServer,
                ..
            } => {
                template.sql_server_statement(scope)?;
            }
            _ => anyhow::bail!("Reviewed database fixture required"),
        }
        let digest = scope.digest()?;
        ensure!(
            case.scopes()
                .iter()
                .any(|s| s.digest().ok() == Some(digest.clone())),
            "scope not in reviewed case"
        );
        let evidence = case
            .evidence()
            .iter()
            .find(|e| e.id == evidence_id)
            .ok_or_else(|| anyhow::anyhow!("review evidence missing"))?;
        ensure!(
            evidence.capability_id == CapabilityId::SqlRead
                && evidence.binding.case_id == case.id()
                && evidence.binding.case_revision == case.revision()
                && evidence.binding.scope_sha256 == digest
                && evidence.binding.credential_scope_sha256 == scope.credential_scope_digest()?
                && evidence.eligibility(chrono::Utc::now(), chrono::Duration::minutes(5))
                    == Eligibility::Eligible,
            "fresh live SQL-read review evidence required"
        );
        ensure!(
            match scope {
                BoundScope::Database {
                    engine: crate::helper::scope::DatabaseEngine::SqlServer,
                    ..
                } => sql_server_metadata_matches(&evidence.sql_observations, template),
                _ => metadata_matches(&evidence.sql_observations, template),
            },
            "reviewed live object/column identity missing"
        );
        Ok(Self {
            scope: scope.clone(),
            template,
            case_id: case.id(),
            case_revision: case.revision(),
            review_evidence_id: evidence_id,
            review_content_sha256: evidence.content_sha256.clone(),
            reviewed_at: chrono::Utc::now(),
        })
    }
    pub fn fingerprint(&self) -> Result<String> {
        self.template.fingerprint(&self.scope)
    }
}

/// Executes one fixed, reviewed SELECT for post-action row-count proof.
/// The caller must bind this native observation to the production run.
pub(crate) async fn run_functional_row_count(
    request: &ReviewedWorkload,
    cancel: CancellationToken,
) -> Result<u64> {
    ensure_review_freshness(request)?;
    if matches!(
        &request.scope,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ) {
        return super::sql_server::functional_row_count(request, cancel).await;
    }
    let statement = request.template.reviewed_statement(&request.scope)?;
    let session = connect_fixture(&request.scope, request.template, &cancel).await?;
    let run = async {
        session.client.batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '1000ms'").await?;
        ensure!(!cancel.is_cancelled(), "SQL functional check canceled");
        let rows = match statement.bind {
            TemplateBind::None => session.client.query(statement.sql, &[]).await?,
            TemplateBind::Integer(value) => session.client.query(statement.sql, &[&value]).await?,
            TemplateBind::Status(status) => session.client.query(statement.sql, &[&status.as_str()]).await?,
        };
        ensure!(rows.len() <= 100, "SQL functional result exceeds fixed bound");
        if matches!(request.template, ReviewedSelectTemplate::StatusCount { .. }) {
            ensure!(rows.len() == 1, "SQL count projection missing");
            let count: i64 = rows[0].try_get(0)?;
            ensure!(count >= 0, "Invalid SQL count");
            Ok(count as u64)
        } else { Ok(rows.len() as u64) }
    }.await;
    let _ = session.client.batch_execute("ROLLBACK").await;
    run
}

pub(crate) async fn capture_typed_compatibility(
    request: &ReviewedWorkload,
    cancel: CancellationToken,
) -> Result<TypedCompatibilitySnapshot> {
    ensure_review_freshness(request)?;
    if matches!(
        &request.scope,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ) {
        return super::sql_server::capture_typed_compatibility(request, cancel).await;
    }
    ensure!(
        matches!(
            &request.scope,
            BoundScope::Database {
                engine: DatabaseEngine::Postgres,
                ..
            }
        ),
        "Typed native context unavailable for this engine"
    );
    let statement = request.template.reviewed_statement(&request.scope)?;
    let session = connect_fixture(&request.scope, request.template, &cancel).await?;
    ensure!(!cancel.is_cancelled(), "Compatibility capture canceled");
    let setting_names = [
        "default_statistics_target",
        "effective_cache_size",
        "enable_indexscan",
        "enable_seqscan",
        "jit",
        "max_parallel_workers_per_gather",
        "random_page_cost",
        "search_path",
        "work_mem",
    ];
    let mut settings = Vec::with_capacity(setting_names.len());
    for name in setting_names {
        let row = session
            .client
            .query_one("SELECT current_setting($1)", &[&name])
            .await?;
        let value: String = row.try_get(0)?;
        ensure!(
            value.len() <= 128 && !value.chars().any(char::is_control),
            "Optimizer setting unavailable"
        );
        settings.push((name.to_owned(), value));
    }
    let index_rows = session.client.query(
        "SELECT ic.oid, ic.relname::text, pg_get_indexdef(ic.oid)::text, am.amname::text, i.indisunique, i.indisprimary, i.indpred IS NULL, i.indexprs IS NULL, i.indnkeyatts::int, i.indnatts::int, obj_description(ic.oid,'pg_class')::text FROM pg_index i JOIN pg_class ic ON ic.oid=i.indexrelid JOIN pg_am am ON am.oid=ic.relam JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='fixture' AND t.relname=$1 ORDER BY ic.relname LIMIT 21",
        &[&statement.object],
    ).await?;
    ensure!(index_rows.len() <= 20, "Index set truncated");
    let mut indexes = Vec::with_capacity(index_rows.len());
    for row in index_rows {
        let oid: u32 = row.try_get(0)?;
        let name: String = row.try_get(1)?;
        let definition: String = row.try_get(2)?;
        ensure!(definition.len() <= 2048, "Index definition exceeds bound");
        let access_method: String = row.try_get(3)?;
        let unique: bool = row.try_get(4)?;
        let primary: bool = row.try_get(5)?;
        let no_predicate: bool = row.try_get(6)?;
        let no_expression: bool = row.try_get(7)?;
        let key_count: i32 = row.try_get(8)?;
        let total_count: i32 = row.try_get(9)?;
        let marker: Option<String> = row.try_get(10)?;
        ensure!(
            marker.as_ref().is_none_or(|value| value.len() <= 256),
            "Index marker exceeds bound"
        );
        let plain = access_method == "btree"
            && !unique
            && !primary
            && no_predicate
            && no_expression
            && key_count == total_count
            && (1..=4).contains(&key_count);
        let columns = if plain {
            let rows = session.client.query(
                "SELECT a.attname::text, ((i.indoption[k - 1]::int & 1) = 1) AS descending FROM pg_index i CROSS JOIN generate_series(1, i.indnkeyatts) AS k LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=i.indkey[k - 1] WHERE i.indexrelid=$1 ORDER BY k",
                &[&oid],
            ).await?;
            ensure!(
                rows.len() == key_count as usize,
                "Index key coverage incomplete"
            );
            let mut keys = Vec::with_capacity(rows.len());
            for key in rows {
                let column: Option<String> = key.try_get(0)?;
                let column = column.ok_or_else(|| anyhow::anyhow!("Expression index not plain"))?;
                let descending: bool = key.try_get(1)?;
                keys.push(crate::helper_action::PlainIndexColumn {
                    name: column,
                    direction: if descending {
                        crate::helper_action::SortDirection::Desc
                    } else {
                        crate::helper_action::SortDirection::Asc
                    },
                });
            }
            keys
        } else {
            Vec::new()
        };
        indexes.push(TypedIndexDefinition {
            name,
            definition_sha256: crate::helper_action::digest(
                b"relayne-helper-created-index-definition-v1",
                &definition,
            )?,
            marker_sha256: marker
                .as_ref()
                .map(|value| {
                    crate::helper_action::digest(b"relayne-helper-created-index-marker-v1", value)
                })
                .transpose()?,
            plain_nonunique_btree: plain,
            columns,
        });
    }
    let stats_rows = session.client.query(
        "SELECT attname::text, md5(row_to_json(s)::text)::text FROM pg_stats s WHERE schemaname='fixture' AND tablename=$1 ORDER BY attname LIMIT 21",
        &[&statement.object],
    ).await?;
    ensure!(stats_rows.len() <= 20, "Statistics coverage incomplete");
    let mut stats_hash = Sha256::new();
    stats_hash.update(b"relayne-typed-pg-statistics-v1\0");
    let mut statistics = Vec::with_capacity(stats_rows.len());
    for row in stats_rows {
        let name: String = row.try_get(0)?;
        let hash: String = row.try_get(1)?;
        ensure!(
            name.len() <= 128 && hash.len() == 32,
            "Statistics projection invalid"
        );
        stats_hash.update(name.as_bytes());
        stats_hash.update(hash.as_bytes());
        statistics.push((name, hash));
    }
    let data = fixture_data_observation(&request.scope, request.template, cancel).await?;
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    statistics.sort_by(|left, right| left.0.cmp(&right.0));
    let snapshot = TypedCompatibilitySnapshot {
        engine: CompatibilityEngine::Postgres,
        schema_sha256: session.metadata_sha256.clone(),
        settings,
        indexes,
        statistics,
        statistics_sha256: format!("{:x}", stats_hash.finalize()),
        data_sha256: data.sha256,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

pub(super) fn metadata_matches(
    observations: &[SqlObservation],
    template: ReviewedSelectTemplate,
) -> bool {
    let expected = template.expected_columns();
    let objects: Vec<_> = observations
        .iter()
        .filter_map(|o| match o {
            SqlObservation::PostgresObject {
                schema,
                name,
                object_id,
                column_count,
            } if schema == "fixture"
                && name == template.object()
                && *object_id > 0
                && *column_count == expected.len() as u32 =>
            {
                Some(*object_id)
            }
            _ => None,
        })
        .collect();
    if objects.len() != 1 {
        return false;
    }
    let mut columns: Vec<_> = observations
        .iter()
        .filter_map(|o| match o {
            SqlObservation::PostgresColumn {
                object_id,
                column_id,
                name,
                plain,
            } if *object_id == objects[0] && *column_id > 0 && *plain => {
                Some((*column_id, name.as_str()))
            }
            _ => None,
        })
        .collect();
    columns.sort_by_key(|(id, _)| *id);
    columns.len() == expected.len()
        && columns
            .iter()
            .zip(expected)
            .all(|((_, actual), wanted)| actual == wanted)
        && columns.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

pub(super) fn sql_server_metadata_matches(
    observations: &[SqlObservation],
    template: ReviewedSelectTemplate,
) -> bool {
    let expected = template.expected_columns();
    let objects: Vec<_> = observations
        .iter()
        .filter_map(|item| match item {
            SqlObservation::SqlServerObject {
                schema,
                name,
                object_id,
                column_count,
            } if schema == "fixture"
                && name == template.object()
                && *object_id > 0
                && *column_count as usize == expected.len() =>
            {
                Some(*object_id)
            }
            _ => None,
        })
        .collect();
    if objects.len() != 1 {
        return false;
    }
    let mut columns: Vec<_> = observations
        .iter()
        .filter_map(|item| match item {
            SqlObservation::SqlServerColumn {
                object_id,
                column_id,
                name,
                plain,
            } if *object_id == objects[0] && *column_id > 0 && *plain => {
                Some((*column_id, name.as_str()))
            }
            _ => None,
        })
        .collect();
    columns.sort_by_key(|(id, _)| *id);
    columns.len() == expected.len()
        && columns
            .iter()
            .zip(expected)
            .all(|((_, actual), wanted)| actual == wanted)
        && columns.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

#[derive(Clone, Debug)]
pub struct WorkloadSamples {
    pub policy_version: u16,
    pub case_id: Uuid,
    pub case_revision: u64,
    pub review_evidence_id: Uuid,
    pub review_content_sha256: String,
    pub scope_sha256: String,
    pub workload_fingerprint: String,
    pub result_sha256: String,
    pub environment_fingerprint: String,
    pub live_metadata_sha256: String,
    /// Native observations and explicit gaps; a digest alone is never a proof
    /// that two optimizer/data environments are comparable.
    pub compatibility: CompatibilityEvidence,
    pub warmups: u8,
    pub milliseconds: Vec<f64>,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub mad_ms: f64,
    /// An intended schema/index/session-setting change must be supplied by a future approved action receipt.
    pub approved_change_sha256: Option<String>,
}

/// Bounded native context used by production verification. OIDs are excluded
/// from index definitions; object identity is retained separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedCompatibilitySnapshot {
    pub engine: CompatibilityEngine,
    pub schema_sha256: String,
    pub settings: Vec<(String, String)>,
    pub indexes: Vec<TypedIndexDefinition>,
    pub statistics: Vec<(String, String)>,
    pub statistics_sha256: String,
    pub data_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedIndexDefinition {
    pub name: String,
    pub definition_sha256: String,
    pub marker_sha256: Option<String>,
    pub plain_nonunique_btree: bool,
    pub columns: Vec<crate::helper_action::PlainIndexColumn>,
}

impl TypedCompatibilitySnapshot {
    pub fn validate(&self) -> Result<()> {
        use crate::helper::evidence::is_digest;
        ensure!(
            self.engine != CompatibilityEngine::Unknown
                && is_digest(&self.schema_sha256)
                && is_digest(&self.statistics_sha256)
                && is_digest(&self.data_sha256),
            "Typed compatibility context incomplete"
        );
        ensure!(
            self.settings.len() == 9
                && self.settings.iter().all(|(name, value)| !name.is_empty()
                    && name.len() <= 48
                    && value.len() <= 128
                    && !value.chars().any(char::is_control))
                && self.settings.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "Optimizer setting coverage incomplete"
        );
        ensure!(
            self.indexes.len() <= 20
                && self
                    .indexes
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name),
            "Index coverage incomplete"
        );
        ensure!(
            self.statistics.len() <= 20
                && self.statistics.iter().all(|(name, hash)| !name.is_empty()
                    && name.len() <= 128
                    && !hash.is_empty()
                    && hash.len() <= 64
                    && hash.chars().all(|c| c.is_ascii_hexdigit()))
                && self.statistics.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "Statistics coverage incomplete"
        );
        for index in &self.indexes {
            ensure!(
                !index.name.is_empty()
                    && index.name.len() <= 128
                    && !index.name.chars().any(char::is_control)
                    && is_digest(&index.definition_sha256)
                    && index.marker_sha256.as_deref().is_none_or(is_digest)
                    && index.columns.len() <= 4,
                "Index definition invalid"
            );
            ensure!(
                !index.plain_nonunique_btree || !index.columns.is_empty(),
                "Plain index columns missing"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityGap {
    ColumnTypes,
    SessionOptimizerSettings,
    IndexDefinitions,
    StatisticsState,
    DataState,
    PlanFingerprint,
    PostSampleState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityEngine {
    Unknown,
    Postgres,
    SqlServer,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    #[default]
    Incomplete,
    NativeComplete,
}

/// Descriptive native observations are deliberately separate from a trusted
/// completeness proof. The latter has no constructor until a native producer
/// can attest every required dimension and a stable post-sample snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    #[serde(default)]
    status: CompatibilityStatus,
    engine: CompatibilityEngine,
    observed_pre_sha256: Option<String>,
    observed_post_sha256: Option<String>,
    missing: Vec<CompatibilityGap>,
    #[serde(skip)]
    verified_complete: bool,
}

impl Default for CompatibilityEvidence {
    fn default() -> Self {
        Self::incomplete(CompatibilityEngine::Unknown, None, None)
    }
}

impl CompatibilityEvidence {
    pub(crate) fn engine(&self) -> CompatibilityEngine {
        self.engine
    }
    /// Called only after native pre/post observations in one live session.
    /// Imported JSON never restores verified_complete.
    pub(crate) fn native_complete(
        engine: CompatibilityEngine,
        before: String,
        after: String,
    ) -> Result<Self> {
        ensure!(
            engine != CompatibilityEngine::Unknown
                && crate::helper::evidence::is_digest(&before)
                && before == after,
            "Native compatibility observations differ or are incomplete"
        );
        Ok(Self {
            status: CompatibilityStatus::NativeComplete,
            engine,
            observed_pre_sha256: Some(before),
            observed_post_sha256: Some(after),
            missing: Vec::new(),
            verified_complete: true,
        })
    }
    pub(crate) fn incomplete(
        engine: CompatibilityEngine,
        observed_pre_sha256: Option<String>,
        observed_post_sha256: Option<String>,
    ) -> Self {
        let mut missing = vec![
            CompatibilityGap::SessionOptimizerSettings,
            CompatibilityGap::IndexDefinitions,
            CompatibilityGap::StatisticsState,
            CompatibilityGap::DataState,
            CompatibilityGap::PlanFingerprint,
            CompatibilityGap::PostSampleState,
        ];
        if engine != CompatibilityEngine::Postgres {
            missing.push(CompatibilityGap::ColumnTypes);
        }
        missing.sort_unstable();
        Self {
            status: CompatibilityStatus::Incomplete,
            engine,
            observed_pre_sha256,
            observed_post_sha256,
            missing,
            verified_complete: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == CompatibilityStatus::NativeComplete
            && self.verified_complete
            && self.missing.is_empty()
            && self.observed_pre_sha256.is_some()
            && self.observed_pre_sha256 == self.observed_post_sha256
    }

    fn comparable_with(&self, other: &Self) -> bool {
        self.is_complete()
            && other.is_complete()
            && self.engine == other.engine
            && self.observed_pre_sha256 == other.observed_pre_sha256
    }

    pub fn missing(&self) -> &[CompatibilityGap] {
        &self.missing
    }

    pub(crate) fn validate(&self) -> Result<()> {
        use crate::helper::evidence::is_digest;
        ensure!(
            self.observed_pre_sha256.as_deref().is_none_or(is_digest)
                && self.observed_post_sha256.as_deref().is_none_or(is_digest)
                && (self.observed_post_sha256.is_none() || self.observed_pre_sha256.is_some()),
            "invalid compatibility observation digest"
        );
        ensure!(
            self.missing.len() <= 7
                && self.missing.windows(2).all(|pair| pair[0] < pair[1])
                && match self.status {
                    CompatibilityStatus::Incomplete => {
                        !self.missing.is_empty() && !self.verified_complete
                    }
                    CompatibilityStatus::NativeComplete => self.is_complete(),
                },
            "invalid compatibility coverage"
        );
        Ok(())
    }
}

struct BoundedPlanJson(Vec<u8>);
impl<'a> tokio_postgres::types::FromSql<'a> for BoundedPlanJson {
    fn from_sql(
        _ty: &tokio_postgres::types::Type,
        raw: &'a [u8],
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if raw.len() > 1024 * 1024 {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "plan exceeds bound").into(),
            );
        }
        Ok(Self(raw.to_vec()))
    }
    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        *ty == tokio_postgres::types::Type::JSON
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixtureDataObservation {
    pub sha256: String,
    pub row_count: u64,
}

pub(in crate::helper::sql) struct BoundedFixtureHasher {
    hash: Sha256,
    row_count: u64,
    byte_count: u64,
    row_limit: u64,
    field_limit: usize,
    byte_limit: u64,
}

impl BoundedFixtureHasher {
    pub(in crate::helper::sql) fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"relayne-helper-fixture-full-data-v2\0");
        Self {
            hash,
            row_count: 0,
            byte_count: 0,
            row_limit: 100_000,
            field_limit: 16 * 1024,
            byte_limit: 128 * 1024 * 1024,
        }
    }

    #[cfg(test)]
    fn with_test_limits(row_limit: u64, field_limit: usize, byte_limit: u64) -> Self {
        let mut bounded = Self::new();
        bounded.row_limit = row_limit;
        bounded.field_limit = field_limit;
        bounded.byte_limit = byte_limit;
        bounded
    }

    pub(in crate::helper::sql) fn push(&mut self, value: &str) -> Result<()> {
        let next_row_count = self
            .row_count
            .checked_add(1)
            .context("Data row count overflow")?;
        ensure!(
            next_row_count <= self.row_limit,
            "Data coverage exceeds row bound"
        );
        ensure!(
            value.len() <= self.field_limit,
            "Data row exceeds field bound"
        );
        let next_byte_count = self
            .byte_count
            .checked_add(value.len() as u64)
            .context("Data byte count overflow")?;
        ensure!(
            next_byte_count <= self.byte_limit,
            "Data digest exceeds byte bound"
        );
        self.row_count = next_row_count;
        self.byte_count = next_byte_count;
        self.hash.update(value.len().to_be_bytes());
        self.hash.update(value.as_bytes());
        Ok(())
    }

    pub(in crate::helper::sql) fn finish(mut self) -> Result<FixtureDataObservation> {
        ensure!(self.row_count > 0, "Data coverage incomplete");
        self.hash.update(self.row_count.to_be_bytes());
        Ok(FixtureDataObservation {
            sha256: format!("{:x}", self.hash.finalize()),
            row_count: self.row_count,
        })
    }
}

#[cfg(test)]
mod streamed_fixture_tests {
    use super::*;
    use futures_util::stream;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn running_field_and_aggregate_bounds_fail_before_hash_completion() {
        let mut field = BoundedFixtureHasher::with_test_limits(3, 4, 8);
        assert!(field.push("12345").is_err());
        let mut total = BoundedFixtureHasher::with_test_limits(3, 4, 8);
        total.push("1234").unwrap();
        total.push("5678").unwrap();
        assert!(total.push("x").is_err());
        let mut rows = BoundedFixtureHasher::with_test_limits(2, 4, 12);
        rows.push("a").unwrap();
        rows.push("b").unwrap();
        assert!(rows.push("c").is_err());
    }

    #[tokio::test]
    async fn lazy_stream_stops_at_row_bound_without_collecting_all_rows() {
        let read = Arc::new(AtomicUsize::new(0));
        let counter = read.clone();
        let values = stream::unfold(counter, |counter| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Some((Ok(Some("x".to_owned())), counter))
        });
        assert!(hash_bounded_stream(
            values,
            &CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .is_err());
        assert_eq!(read.load(Ordering::SeqCst), 100_001);
    }

    #[tokio::test]
    async fn pending_stream_honors_cancel_and_deadline() {
        let pending = || stream::pending::<Result<Option<String>>>();
        let canceled = CancellationToken::new();
        canceled.cancel();
        assert!(hash_bounded_stream(
            pending(),
            &canceled,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .is_err());
        assert!(hash_bounded_stream(
            pending(),
            &CancellationToken::new(),
            tokio::time::Instant::now(),
        )
        .await
        .is_err());
    }
}

async fn hash_bounded_stream<S>(
    stream: S,
    cancel: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<FixtureDataObservation>
where
    S: Stream<Item = Result<Option<String>>>,
{
    futures_util::pin_mut!(stream);
    let mut bounded = BoundedFixtureHasher::new();
    loop {
        let row = tokio::select! {
            _ = cancel.cancelled() => anyhow::bail!("Data digest canceled"),
            result = tokio::time::timeout_at(deadline, stream.next()) => result.context("Data digest timed out")?,
        };
        let Some(row) = row else { break };
        bounded.push(&row?.context("Data row exceeds field bound")?)?;
    }
    bounded.finish()
}

async fn native_pg_data_digest(
    session: &super::templates::VerifiedPgSession,
    template: ReviewedSelectTemplate,
    cancel: &CancellationToken,
) -> Result<FixtureDataObservation> {
    let data_sql = match template {
        ReviewedSelectTemplate::OrderSort => {
            "SELECT CASE WHEN octet_length(convert_to(to_jsonb(t)::text, 'UTF8')) <= 16384 THEN to_jsonb(t)::text END FROM fixture.spill_events t ORDER BY event_id LIMIT 100001"
        }
        #[cfg(test)]
        ReviewedSelectTemplate::Task15CustomerOrders { .. } => {
            "SELECT CASE WHEN octet_length(convert_to(to_jsonb(t)::text, 'UTF8')) <= 16384 THEN to_jsonb(t)::text END FROM fixture.task15_orders t ORDER BY order_id LIMIT 100001"
        }
        _ => {
            "SELECT CASE WHEN octet_length(convert_to(to_jsonb(t)::text, 'UTF8')) <= 16384 THEN to_jsonb(t)::text END FROM fixture.orders t ORDER BY order_id LIMIT 100001"
        }
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let rows = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("Data digest canceled"),
        result = tokio::time::timeout_at(deadline, session.client.query_raw(data_sql, std::iter::empty::<i32>())) => {
            result.context("Data digest timed out")??
        }
    };
    hash_bounded_stream(
        rows.map(|row| Ok(row?.try_get::<_, Option<String>>(0)?)),
        cancel,
        deadline,
    )
    .await
}

pub(crate) async fn fixture_data_observation(
    scope: &BoundScope,
    template: ReviewedSelectTemplate,
    cancel: CancellationToken,
) -> Result<FixtureDataObservation> {
    if matches!(
        scope,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ) {
        return super::sql_server::fixture_data_observation(scope, template, cancel).await;
    }
    let session = connect_fixture(scope, template, &cancel).await?;
    session
        .client
        .batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = '15000ms'")
        .await?;
    let value = native_pg_data_digest(&session, template, &cancel).await;
    let _ = session.client.batch_execute("ROLLBACK").await;
    value
}

pub(crate) async fn fixture_data_digest(
    scope: &BoundScope,
    template: ReviewedSelectTemplate,
    cancel: CancellationToken,
) -> Result<String> {
    Ok(fixture_data_observation(scope, template, cancel)
        .await?
        .sha256)
}

async fn native_pg_compatibility_snapshot(
    session: &super::templates::VerifiedPgSession,
    template: ReviewedSelectTemplate,
    statement: &super::templates::TemplateStatement,
    cancel: &CancellationToken,
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"relayne-helper-native-pg-compatibility-v2\0");
    // The verified connection attests exact column name/type/order and object OID.
    hash.update(session.metadata_sha256.as_bytes());
    let settings = session.client.query_one(
        "SELECT current_setting('work_mem'), current_setting('enable_seqscan'), current_setting('enable_indexscan'), current_setting('random_page_cost'), current_setting('effective_cache_size'), current_setting('max_parallel_workers_per_gather'), current_setting('search_path'), current_setting('default_statistics_target'), current_setting('jit')",
        &[],
    ).await?;
    for i in 0..9 {
        let value: String = settings.try_get(i)?;
        ensure!(value.len() <= 128, "Optimizer setting exceeds bound");
        hash.update(value.len().to_be_bytes());
        hash.update(value.as_bytes());
    }
    let indexes = session.client.query(
        "SELECT pg_get_indexdef(ic.oid)::text FROM pg_index i JOIN pg_class ic ON ic.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='fixture' AND t.relname=$1 ORDER BY ic.relname LIMIT 21",
        &[&template.object()],
    ).await?;
    ensure!(indexes.len() <= 20, "Index coverage incomplete");
    for row in indexes {
        let definition: String = row.try_get(0)?;
        ensure!(definition.len() <= 2048, "Index definition exceeds bound");
        hash.update(definition.len().to_be_bytes());
        hash.update(definition.as_bytes());
    }
    let stats = session.client.query(
        "SELECT attname::text, COALESCE(null_frac::text,''), COALESCE(avg_width::text,''), COALESCE(n_distinct::text,''), \
         most_common_vals IS NULL, octet_length(convert_to(COALESCE(most_common_vals::text,''),'UTF8'))::bigint, \
         encode(sha256(convert_to(COALESCE(most_common_vals::text,''),'UTF8')),'hex')::text, \
         histogram_bounds IS NULL, octet_length(convert_to(COALESCE(histogram_bounds::text,''),'UTF8'))::bigint, \
         encode(sha256(convert_to(COALESCE(histogram_bounds::text,''),'UTF8')),'hex')::text \
         FROM pg_stats WHERE schemaname='fixture' AND tablename=$1 ORDER BY attname LIMIT 21",
        &[&template.object()],
    ).await?;
    ensure!(
        !stats.is_empty() && stats.len() <= 20,
        "Statistics coverage incomplete"
    );
    hash.update((stats.len() as u64).to_be_bytes());
    let mut total_statistics_bytes = 0_u64;
    let mut previous_column: Option<String> = None;
    for row in stats {
        for i in 0..4 {
            let value: String = row.try_get(i)?;
            ensure!(
                value.len() <= 128,
                "Statistics scalar projection exceeds bound"
            );
            total_statistics_bytes = total_statistics_bytes
                .checked_add(value.len() as u64)
                .context("Statistics projection length overflow")?;
            ensure!(
                total_statistics_bytes <= 128 * 1024,
                "Statistics aggregate exceeds bound"
            );
            if i == 0 {
                ensure!(
                    previous_column
                        .as_deref()
                        .is_none_or(|name| name < value.as_str()),
                    "Statistics column coverage not unique"
                );
                previous_column = Some(value.clone());
            }
            hash.update(value.len().to_be_bytes());
            hash.update(value.as_bytes());
        }
        for (null_at, length_at, digest_at) in [(4, 5, 6), (7, 8, 9)] {
            add_native_statistics_field(
                &mut hash,
                row.try_get(null_at)?,
                row.try_get(length_at)?,
                &row.try_get::<_, String>(digest_at)?,
                &mut total_statistics_bytes,
            )?;
        }
    }
    hash.update(
        native_pg_data_digest(session, template, cancel)
            .await?
            .sha256
            .as_bytes(),
    );
    let plan = match statement.bind {
        TemplateBind::None => session.client.query_one(statement.explain_sql, &[]).await?,
        TemplateBind::Integer(value) => {
            session
                .client
                .query_one(statement.explain_sql, &[&value])
                .await?
        }
        TemplateBind::Status(value) => {
            session
                .client
                .query_one(statement.explain_sql, &[&value.as_str()])
                .await?
        }
    };
    let bytes: BoundedPlanJson = plan.try_get(0)?;
    hash.update(bytes.0.len().to_be_bytes());
    hash.update(&bytes.0);
    Ok(format!("{:x}", hash.finalize()))
}

fn add_native_statistics_field(
    hash: &mut Sha256,
    is_null: bool,
    length: i64,
    digest: &str,
    total_bytes: &mut u64,
) -> Result<()> {
    let length = u64::try_from(length).context("Negative statistics field length")?;
    ensure!(length <= 64 * 1024, "Statistics field exceeds bound");
    *total_bytes = total_bytes
        .checked_add(length)
        .context("Statistics projection length overflow")?;
    ensure!(
        *total_bytes <= 128 * 1024,
        "Statistics aggregate exceeds bound"
    );
    ensure!(
        crate::helper::evidence::is_digest(digest)
            && (!is_null
                || (length == 0
                    && digest
                        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
        "Invalid native statistics digest projection"
    );
    hash.update([u8::from(is_null)]);
    hash.update(length.to_be_bytes());
    hash.update(digest.as_bytes());
    Ok(())
}

#[cfg(test)]
mod native_stats_projection_tests {
    use super::*;

    #[test]
    fn complete_large_field_is_hashed_with_its_declared_length() {
        let digest = format!("{:x}", Sha256::digest(vec![b'x'; 9798]));
        let mut first = Sha256::new();
        let mut total = 0;
        add_native_statistics_field(&mut first, false, 9798, &digest, &mut total).unwrap();
        assert_eq!(total, 9798);

        let mut changed_length = Sha256::new();
        let mut changed_total = 0;
        add_native_statistics_field(
            &mut changed_length,
            false,
            9797,
            &digest,
            &mut changed_total,
        )
        .unwrap();
        assert_ne!(
            first.finalize().as_slice(),
            changed_length.finalize().as_slice()
        );
    }

    #[test]
    fn field_and_aggregate_limits_fail_closed() {
        let digest = format!("{:x}", Sha256::digest(b"value"));
        let mut hash = Sha256::new();
        let mut total = 0;
        assert!(
            add_native_statistics_field(&mut hash, false, 65_537, &digest, &mut total).is_err()
        );
        let mut total = 128 * 1024;
        assert!(add_native_statistics_field(&mut hash, false, 1, &digest, &mut total).is_err());
        let mut total = 0;
        assert!(add_native_statistics_field(&mut hash, true, 0, &digest, &mut total).is_err());
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Improvement,
    Regression,
    Inconclusive,
}
impl WorkloadSamples {
    pub fn can_prove_repair(&self) -> bool {
        false
    }
}
pub(crate) fn summary(values: &[f64]) -> Result<(f64, f64, f64)> {
    ensure!(
        values.len() >= 15
            && values.len() <= 30
            && values.iter().all(|v| v.is_finite() && *v > 0.0),
        "invalid repeated samples"
    );
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = (sorted[(sorted.len() - 1) / 2] + sorted[sorted.len() / 2]) / 2.0;
    let p95_index = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    let p95 = sorted[p95_index];
    let mut deviations: Vec<f64> = sorted.iter().map(|v| (v - median).abs()).collect();
    deviations.sort_by(f64::total_cmp);
    let mad = (deviations[(deviations.len() - 1) / 2] + deviations[deviations.len() / 2]) / 2.0;
    Ok((median, p95, mad))
}
pub fn compare(
    before: &WorkloadSamples,
    after: &WorkloadSamples,
    approved_change_sha256: &str,
) -> Comparison {
    use crate::helper::evidence::is_digest;
    if !is_digest(approved_change_sha256)
        || !is_digest(&before.review_content_sha256)
        || !is_digest(&after.review_content_sha256)
        || before.compatibility.validate().is_err()
        || after.compatibility.validate().is_err()
        || !before.compatibility.comparable_with(&after.compatibility)
        || before.policy_version != POLICY_VERSION
        || after.policy_version != POLICY_VERSION
        || before.warmups < 3
        || after.warmups < 3
        || before.milliseconds.len() < 15
        || after.milliseconds.len() < 15
        || before.case_id != after.case_id
        || before.scope_sha256 != after.scope_sha256
        || before.workload_fingerprint != after.workload_fingerprint
        || before.result_sha256 != after.result_sha256
        || before.environment_fingerprint != after.environment_fingerprint
        || before.live_metadata_sha256 != after.live_metadata_sha256
        || before.approved_change_sha256.is_some()
        || after.approved_change_sha256.as_deref() != Some(approved_change_sha256)
        || summary(&before.milliseconds).is_err()
        || summary(&after.milliseconds).is_err()
    {
        return Comparison::Inconclusive;
    }
    let Ok((before_median, _, before_mad)) = summary(&before.milliseconds) else {
        return Comparison::Inconclusive;
    };
    let Ok((after_median, _, after_mad)) = summary(&after.milliseconds) else {
        return Comparison::Inconclusive;
    };
    let width_before = (before_median * 0.1).max(3.0 * before_mad);
    let width_after = (after_median * 0.1).max(3.0 * after_mad);
    if after_median + width_after < before_median - width_before {
        Comparison::Improvement
    } else if before_median + width_before < after_median - width_after {
        Comparison::Regression
    } else {
        Comparison::Inconclusive
    }
}

pub async fn run_sandbox_workload(
    request: &ReviewedWorkload,
    policy: &SamplingPolicy,
    cancel: CancellationToken,
) -> Result<WorkloadSamples> {
    if matches!(
        &request.scope,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ) {
        return super::sql_server::run_rehearsal_workload(request, policy, cancel).await;
    }
    run_sandbox_workload_inner(request, policy, cancel, true).await
}

pub(super) async fn run_admitted_postcommit_workload(
    admission: &PostcommitWorkloadAdmission,
    policy: &SamplingPolicy,
    cancel: CancellationToken,
) -> Result<WorkloadSamples> {
    if matches!(
        &admission.request().scope,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ) {
        return super::sql_server::run_admitted_rehearsal_workload(admission, policy, cancel).await;
    }
    run_sandbox_workload_inner(admission.request(), policy, cancel, false).await
}

async fn run_sandbox_workload_inner(
    request: &ReviewedWorkload,
    policy: &SamplingPolicy,
    cancel: CancellationToken,
    require_fresh_review: bool,
) -> Result<WorkloadSamples> {
    policy.validate()?;
    ensure!(!cancel.is_cancelled(), "workload canceled");
    if require_fresh_review {
        ensure_review_freshness(request)?;
    }
    let statement = request.template.reviewed_statement(&request.scope)?;
    let session = connect_fixture(&request.scope, request.template, &cancel).await?;
    let run = async {
        session.client.batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '1000ms'").await?;
        let compatibility_before =
            native_pg_compatibility_snapshot(&session, request.template, &statement, &cancel)
                .await?;
        let mut samples = Vec::with_capacity(policy.samples as usize);
        let mut result_digest: Option<String> = None;
        for i in 0..usize::from(policy.warmups + policy.samples) {
            if cancel.is_cancelled() {
                anyhow::bail!("workload canceled");
            }
            let start = Instant::now();
            let rows = match statement.bind {
                TemplateBind::None => session.client.query(statement.sql, &[]).await?,
                TemplateBind::Integer(n) => session.client.query(statement.sql, &[&n]).await?,
                TemplateBind::Status(s) => {
                    session.client.query(statement.sql, &[&s.as_str()]).await?
                }
            };
            ensure!(rows.len() <= 100, "workload result exceeds fixed row limit");
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            let mut hash = Sha256::new();
            hash.update(b"relayne-workload-result-v1\0");
            hash.update((rows.len() as u32).to_be_bytes());
            for row in &rows {
                let id: i64 = row.try_get(0)?;
                hash.update(id.to_be_bytes());
            }
            let current = format!("{:x}", hash.finalize());
            if let Some(expected) = &result_digest {
                ensure!(
                    expected == &current,
                    "workload results changed across samples"
                );
            } else {
                result_digest = Some(current);
            }
            if i >= usize::from(policy.warmups) {
                ensure!(
                    elapsed.is_finite() && elapsed > 0.0,
                    "invalid workload clock sample"
                );
                samples.push(elapsed);
            }
        }
        let (median_ms, p95_ms, mad_ms) = summary(&samples)?;
        let compatibility_after =
            native_pg_compatibility_snapshot(&session, request.template, &statement, &cancel)
                .await?;
        let mut environment = Sha256::new();
        environment.update(b"relayne-pg-disposable-fixture-v1\0");
        environment.update(request.scope.resource_digest()?.as_bytes());
        environment.update(session.server_version.to_be_bytes());
        environment.update(session.work_mem.as_bytes());
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
            workload_fingerprint: statement.fingerprint,
            result_sha256: result_digest
                .ok_or_else(|| anyhow::anyhow!("missing workload result"))?,
            environment_fingerprint: environment_fingerprint.clone(),
            live_metadata_sha256: session.metadata_sha256.clone(),
            compatibility: CompatibilityEvidence::native_complete(
                CompatibilityEngine::Postgres,
                compatibility_before,
                compatibility_after,
            )?,
            warmups: policy.warmups,
            milliseconds: samples,
            median_ms,
            p95_ms,
            mad_ms,
            approved_change_sha256: None,
        })
    };
    let outcome = tokio::select! {
        _ = cancel.cancelled() => Err(anyhow::anyhow!("workload canceled")),
        result = tokio::time::timeout(Duration::from_secs(u64::from(policy.deadline_secs)), run) => result.map_err(|_| anyhow::anyhow!("workload deadline exceeded"))?,
    };
    if outcome.is_err() {
        session.cancel_query().await;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        session.client.batch_execute("ROLLBACK"),
    )
    .await;
    outcome
}
