//! Native PostgreSQL, fixed read templates, and exact scoped identity verification.

use super::types::{ReadState, SqlObservation};
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
    manifest::{CapabilityId, ProbeParams},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use anyhow::{Result, ensure};
use chrono::Utc;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};
use tokio_postgres::{Client, Row, error::SqlState};
use tokio_util::sync::CancellationToken;

pub const MAX_ROWS: usize = 20;
const PROBE_COUNT: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgReadProbe {
    Identity,
    Activity,
    Blocking,
    Objects,
    Indexes,
    Statistics,
    Permissions,
}
impl PgReadProbe {
    const ALL: [Self; 7] = [
        Self::Identity,
        Self::Activity,
        Self::Blocking,
        Self::Objects,
        Self::Indexes,
        Self::Statistics,
        Self::Permissions,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Activity => "activity",
            Self::Blocking => "blocking",
            Self::Objects => "objects",
            Self::Indexes => "indexes",
            Self::Statistics => "statistics",
            Self::Permissions => "permissions",
        }
    }
    pub fn sql(self) -> &'static str {
        match self {
            Self::Identity => {
                "SELECT current_database()::text, session_user::text, current_user::text, current_setting('server_version_num')::integer, s.ssl, inet_server_addr()::text, inet_server_port()::integer FROM pg_stat_ssl AS s WHERE s.pid = pg_backend_pid()"
            }
            Self::Activity => {
                "SELECT pid, state::text, wait_event_type::text, wait_event::text, (EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)) * 1000)::bigint FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() ORDER BY pid LIMIT 21"
            }
            Self::Blocking => {
                "SELECT a.pid, blocker.pid, b.state::text FROM pg_stat_activity AS a CROSS JOIN LATERAL unnest(pg_blocking_pids(a.pid)) AS blocker(pid) LEFT JOIN pg_stat_activity AS b ON b.pid = blocker.pid WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() ORDER BY a.pid, blocker.pid LIMIT 21"
            }
            Self::Objects => {
                "SELECT n.nspname::text, c.relname::text, (SELECT count(*)::integer FROM pg_attribute AS a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), c.reltuples::float8 FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r','p') LIMIT 1"
            }
            Self::Indexes => {
                "SELECT i.relname::text, am.amname::text, x.indisvalid, s.idx_scan::bigint FROM pg_class AS t JOIN pg_namespace AS n ON n.oid = t.relnamespace JOIN pg_index AS x ON x.indrelid = t.oid JOIN pg_class AS i ON i.oid = x.indexrelid JOIN pg_am AS am ON am.oid = i.relam LEFT JOIN pg_stat_user_indexes AS s ON s.indexrelid = i.oid WHERE n.nspname = $1 AND t.relname = $2 AND t.relkind IN ('r','p') ORDER BY i.oid LIMIT 21"
            }
            Self::Statistics => {
                "SELECT s.n_live_tup::bigint, s.n_dead_tup::bigint, s.analyze_count::bigint FROM pg_class AS t JOIN pg_namespace AS n ON n.oid = t.relnamespace LEFT JOIN pg_stat_all_tables AS s ON s.relid = t.oid WHERE n.nspname = $1 AND t.relname = $2 AND t.relkind IN ('r','p') LIMIT 1"
            }
            Self::Permissions => {
                "SELECT has_database_privilege(current_user, current_database(), 'CONNECT'), has_schema_privilege(current_user, n.oid, 'USAGE'), has_table_privilege(current_user, t.oid, 'SELECT') FROM pg_namespace AS n LEFT JOIN pg_class AS t ON t.relnamespace = n.oid AND t.relname = $2 AND t.relkind IN ('r','p') WHERE n.nspname = $1 LIMIT 1"
            }
        }
    }
    fn needs_object(self) -> bool {
        !matches!(self, Self::Identity | Self::Activity | Self::Blocking)
    }
}
pub fn template_digest() -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-postgresql-fixed-read-v1\0");
    for probe in PgReadProbe::ALL {
        hash.update(probe.sql().as_bytes());
    }
    format!("{:x}", hash.finalize())
}
pub fn probe_subject_digest(resource_digest: &str, probe: PgReadProbe) -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-pg-read-v1\0");
    hash.update(resource_digest.as_bytes());
    hash.update(probe.label().as_bytes());
    format!("{:x}", hash.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PgFailure {
    Denied,
    Unavailable,
    InvalidProjection,
    Canceled,
    TimedOut,
}
type PgFuture<'a, T> = Pin<Box<dyn Future<Output = std::result::Result<T, PgFailure>> + Send + 'a>>;
trait PgSession: Send {
    fn begin<'a>(&'a mut self, timeout_ms: u64) -> PgFuture<'a, ()>;
    fn read<'a>(
        &'a mut self,
        probe: PgReadProbe,
        schema: &'a str,
        object: &'a str,
    ) -> PgFuture<'a, Vec<SqlObservation>>;
    fn rollback<'a>(&'a mut self) -> PgFuture<'a, ()>;
    fn cancel<'a>(&'a mut self) -> PgFuture<'a, ()>;
}
trait PgTransport: Send + Sync {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> PgFuture<'a, Box<dyn PgSession>>;
}
struct NativeTransport;
struct NativeSession {
    client: Client,
    driver: tokio::task::JoinHandle<()>,
    tls: MakeTlsConnector,
}
impl Drop for NativeSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn tls() -> std::result::Result<MakeTlsConnector, PgFailure> {
    // OS trust and hostname verification stay enabled. PostgreSQL SSL is required.
    TlsConnector::builder()
        .build()
        .map(MakeTlsConnector::new)
        .map_err(|_| PgFailure::Unavailable)
}
impl PgTransport for NativeTransport {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> PgFuture<'a, Box<dyn PgSession>> {
        Box::pin(async move {
            let mut config = tokio_postgres::Config::new();
            config
                .host(host)
                .port(port)
                .dbname(database)
                .user(principal)
                .password(password)
                .ssl_mode(tokio_postgres::config::SslMode::Require)
                .connect_timeout(Duration::from_secs(5));
            let tls = tls()?;
            let (client, connection) = config
                .connect(tls.clone())
                .await
                .map_err(|_| PgFailure::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Box::new(NativeSession {
                client,
                driver,
                tls,
            }) as Box<dyn PgSession>)
        })
    }
}
fn pg_error(error: tokio_postgres::Error) -> PgFailure {
    if error.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) {
        PgFailure::Denied
    } else {
        PgFailure::Unavailable
    }
}
fn verified_principal(
    session: String,
    effective: String,
) -> std::result::Result<String, PgFailure> {
    if session != effective {
        Err(PgFailure::InvalidProjection)
    } else {
        Ok(session)
    }
}
fn canonical_server(raw: &str, port: i32) -> std::result::Result<(String, u16), PgFailure> {
    let ip: std::net::IpAddr = raw
        .split('/')
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| PgFailure::InvalidProjection)?;
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or(PgFailure::InvalidProjection)?;
    Ok((ip.to_string(), port))
}
impl PgSession for NativeSession {
    fn begin<'a>(&'a mut self, timeout_ms: u64) -> PgFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .batch_execute("BEGIN READ ONLY")
                .await
                .map_err(pg_error)?;
            self.client.query_one("SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', '1000ms', true)", &[&format!("{timeout_ms}ms")]).await.map_err(pg_error)?;
            Ok(())
        })
    }
    fn read<'a>(
        &'a mut self,
        probe: PgReadProbe,
        schema: &'a str,
        object: &'a str,
    ) -> PgFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            let rows = if probe.needs_object() {
                self.client.query(probe.sql(), &[&schema, &object]).await
            } else {
                self.client.query(probe.sql(), &[]).await
            }
            .map_err(pg_error)?;
            if rows.len() > MAX_ROWS + 1 {
                return Err(PgFailure::InvalidProjection);
            }
            rows.iter().map(|r| project(probe, r)).collect()
        })
    }
    fn rollback<'a>(&'a mut self) -> PgFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .batch_execute("ROLLBACK")
                .await
                .map_err(pg_error)
        })
    }
    fn cancel<'a>(&'a mut self) -> PgFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .cancel_token()
                .cancel_query(self.tls.clone())
                .await
                .map_err(pg_error)
        })
    }
}
fn project(probe: PgReadProbe, row: &Row) -> std::result::Result<SqlObservation, PgFailure> {
    let bad = |_| PgFailure::InvalidProjection;
    let value = match probe {
        PgReadProbe::Identity => {
            let principal =
                verified_principal(row.try_get(1).map_err(bad)?, row.try_get(2).map_err(bad)?)?;
            let raw_ip: String = row.try_get(5).map_err(bad)?;
            let (server_ip, server_port) = canonical_server(&raw_ip, row.try_get(6).map_err(bad)?)?;
            SqlObservation::Identity {
                database: row.try_get(0).map_err(bad)?,
                principal,
                version: row.try_get(3).map_err(bad)?,
                tls: row.try_get(4).map_err(bad)?,
                server_ip,
                server_port,
            }
        }
        PgReadProbe::Activity => SqlObservation::Activity {
            pid: row.try_get(0).map_err(bad)?,
            state: row
                .try_get::<_, Option<String>>(1)
                .map_err(bad)?
                .filter(|s| SqlObservation::pg_state(s)),
            wait_kind: row
                .try_get::<_, Option<String>>(2)
                .map_err(bad)?
                .filter(|s| SqlObservation::pg_wait_kind(s)),
            wait_name: row
                .try_get::<_, Option<String>>(3)
                .map_err(bad)?
                .filter(|s| SqlObservation::token(s)),
            age_ms: row.try_get(4).map_err(bad)?,
        },
        PgReadProbe::Blocking => SqlObservation::Blocking {
            waiting_pid: row.try_get(0).map_err(bad)?,
            blocking_pid: row.try_get(1).map_err(bad)?,
            blocker_state: row
                .try_get::<_, Option<String>>(2)
                .map_err(bad)?
                .filter(|s| SqlObservation::pg_state(s)),
        },
        PgReadProbe::Objects => SqlObservation::Object {
            schema: row.try_get(0).map_err(bad)?,
            name: row.try_get(1).map_err(bad)?,
            columns: row.try_get(2).map_err(bad)?,
            estimated_rows: row.try_get(3).map_err(bad)?,
        },
        PgReadProbe::Indexes => SqlObservation::Index {
            name: row.try_get(0).map_err(bad)?,
            method: row.try_get(1).map_err(bad)?,
            valid: row.try_get(2).map_err(bad)?,
            scans: row.try_get(3).map_err(bad)?,
        },
        PgReadProbe::Statistics => SqlObservation::Statistics {
            live_rows: row.try_get(0).map_err(bad)?,
            dead_rows: row.try_get(1).map_err(bad)?,
            analyze_count: row.try_get(2).map_err(bad)?,
        },
        PgReadProbe::Permissions => SqlObservation::Permission {
            database_connect: row.try_get(0).map_err(bad)?,
            schema_usage: row.try_get(1).map_err(bad)?,
            table_select: row.try_get(2).map_err(bad)?,
        },
    };
    if !value.bounded() {
        return Err(PgFailure::InvalidProjection);
    }
    Ok(value)
}

fn classify_rows(probe: PgReadProbe, rows: &[SqlObservation]) -> ReadState {
    if rows.is_empty() {
        return if matches!(
            probe,
            PgReadProbe::Objects | PgReadProbe::Statistics | PgReadProbe::Permissions
        ) {
            ReadState::Unknown
        } else {
            ReadState::Empty
        };
    }
    // A known denied grant must remain visible even when another grant is unknown.
    if rows.iter().any(|r| {
        matches!(
            r,
            SqlObservation::Permission {
                database_connect: Some(false),
                ..
            } | SqlObservation::Permission {
                schema_usage: Some(false),
                ..
            } | SqlObservation::Permission {
                table_select: Some(false),
                ..
            }
        )
    }) {
        return ReadState::Denied;
    }
    if rows.iter().any(|r| {
        matches!(
            r,
            SqlObservation::Activity { state: None, .. }
                | SqlObservation::Blocking {
                    blocker_state: None,
                    ..
                }
                | SqlObservation::Index { scans: None, .. }
                | SqlObservation::Object {
                    estimated_rows: None,
                    ..
                }
                | SqlObservation::Statistics {
                    live_rows: None,
                    ..
                }
                | SqlObservation::Permission {
                    database_connect: None,
                    ..
                }
                | SqlObservation::Permission {
                    schema_usage: None,
                    ..
                }
                | SqlObservation::Permission {
                    table_select: None,
                    ..
                }
        )
    }) || rows.iter().any(|r| {
        matches!(r,
            SqlObservation::Object { estimated_rows: Some(v), .. } if *v < 0.0
        )
    }) {
        return ReadState::Unknown;
    }
    ReadState::Observed
}

pub struct PostgresAdapter;
impl ProbeAdapter for PostgresAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { collect_with(&NativeTransport, request, secrets, cancel).await })
    }
}

async fn collect_with(
    transport: &dyn PgTransport,
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<ProbeOutput> {
    let BoundScope::Database {
        target,
        engine: DatabaseEngine::Postgres,
        port,
        database,
        schema,
        object,
        credential,
    } = &request.scope
    else {
        anyhow::bail!("PostgreSQL scope required")
    };
    ensure!(
        request.capability_id == CapabilityId::SqlRead
            && matches!(&request.params, ProbeParams::SqlRead { query_digest } if query_digest == &template_digest()),
        "Fixed SQL read template required"
    );
    request.scope.validate()?;
    let credential = credential
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Read credential missing"))?;
    ensure!(
        credential.purpose == CredentialPurpose::Read,
        "Read credential required"
    );
    let secret = secrets
        .resolve(credential, CredentialPurpose::Read)
        .map_err(|_| anyhow::anyhow!("Read credential unavailable"))?;
    ensure!(
        secret.username() == credential.principal,
        "Credential principal mismatch"
    );
    let remaining = (request.requested_at
        + chrono::Duration::seconds(request.deadline_secs.unwrap_or(15).min(30) as i64))
    .signed_duration_since(Utc::now())
    .num_milliseconds();
    ensure!(remaining > 0, "SQL deadline elapsed");
    let deadline = Instant::now() + Duration::from_millis(remaining as u64);
    let mut session = gated(
        &cancel,
        deadline,
        transport.open(
            &target.host,
            *port,
            database,
            &credential.principal,
            secret.password(),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("PostgreSQL connection unavailable"))?;
    // Drop the plaintext secret before any observations are assembled.
    drop(secret);
    let transaction = gated(&cancel, deadline, session.begin(remaining as u64)).await;
    if transaction.is_err() {
        let _ = cleanup(&mut *session).await;
        anyhow::bail!("PostgreSQL read transaction unavailable");
    }
    let mut states = Vec::with_capacity(PROBE_COUNT as usize);
    let mut observations = Vec::with_capacity(super::types::MAX_SQL_OBSERVATIONS);
    let mut seen = 0u32;
    let mut truncated = false;
    let mut failure = None;
    let mut transaction_aborted = false;
    let mut object_present = false;
    for probe in PgReadProbe::ALL {
        if transaction_aborted {
            states.push((probe, ReadState::Unknown, 0));
            continue;
        }
        if probe.needs_object() && (schema.is_none() || object.is_none()) {
            states.push((probe, ReadState::Unknown, 0));
            continue;
        }
        if matches!(probe, PgReadProbe::Indexes | PgReadProbe::Statistics) && !object_present {
            states.push((probe, ReadState::Unknown, 0));
            continue;
        }
        let rows = gated(
            &cancel,
            deadline,
            session.read(
                probe,
                schema.as_deref().unwrap_or(""),
                object.as_deref().unwrap_or(""),
            ),
        )
        .await;
        match rows {
            Ok(rows) => {
                if probe == PgReadProbe::Objects {
                    object_present = !rows.is_empty();
                }
                if probe == PgReadProbe::Identity {
                    let Some(SqlObservation::Identity {
                        database: actual_db,
                        principal,
                        version,
                        tls,
                        server_ip,
                        server_port,
                    }) = rows.first()
                    else {
                        failure = Some(PgFailure::InvalidProjection);
                        break;
                    };
                    if actual_db != database
                        || principal != &credential.principal
                        || !tls
                        || *version < 120000
                        || server_port != port
                        || target
                            .host
                            .parse::<std::net::IpAddr>()
                            .ok()
                            .is_some_and(|expected| {
                                server_ip.parse::<std::net::IpAddr>().ok() != Some(expected)
                            })
                    {
                        failure = Some(PgFailure::InvalidProjection);
                        break;
                    }
                }
                let count = rows.len().min(MAX_ROWS) as u32;
                observations.extend(rows.iter().take(MAX_ROWS).cloned());
                let state = if rows.len() > MAX_ROWS {
                    truncated = true;
                    ReadState::Truncated
                } else {
                    classify_rows(probe, &rows)
                };
                if state == ReadState::Observed || state == ReadState::Empty {
                    seen += 1;
                }
                states.push((probe, state, count));
            }
            Err(PgFailure::Denied) if probe != PgReadProbe::Identity => {
                states.push((probe, ReadState::Denied, 0));
                transaction_aborted = true;
            }
            Err(PgFailure::Unavailable) if probe != PgReadProbe::Identity => {
                states.push((probe, ReadState::Unknown, 0));
                transaction_aborted = true;
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    if matches!(failure, Some(PgFailure::Canceled | PgFailure::TimedOut)) {
        let _ = tokio::time::timeout(Duration::from_millis(500), session.cancel()).await;
    }
    let rollback = cleanup(&mut *session).await;
    if failure.is_some() || rollback.is_err() {
        anyhow::bail!("PostgreSQL collection incomplete");
    }
    let digest = request.scope.resource_digest()?;
    let records = states
        .iter()
        .map(|(probe, state, _)| NormalizedRecord {
            kind: RecordKind::SqlRead,
            observation: match state {
                ReadState::Observed | ReadState::Empty => Observation::Healthy,
                ReadState::Denied => Observation::Unavailable,
                ReadState::Truncated => Observation::Degraded,
                ReadState::Unknown => Observation::Unknown,
            },
            subject_sha256: probe_subject_digest(&digest, *probe),
            detail: None,
        })
        .collect();
    Ok(ProbeOutput {
        status: if seen == PROBE_COUNT && !truncated {
            EvidenceStatus::Complete
        } else if truncated {
            EvidenceStatus::Truncated
        } else {
            EvidenceStatus::Partial
        },
        coverage: Coverage {
            observed: seen,
            expected: PROBE_COUNT,
            truncated,
        },
        records,
        metrics: Vec::new(),
        sql_observations: observations,
        evidence_refs: Vec::new(),
        source_id: format!("postgres:{}:{}:{}", target.host, port, database).into_bytes(),
        source_observed_at: Utc::now(),
        parser_version: 1,
    })
}
async fn gated<T>(
    cancel: &CancellationToken,
    deadline: Instant,
    op: PgFuture<'_, T>,
) -> std::result::Result<T, PgFailure> {
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(PgFailure::Canceled),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), op) => result.unwrap_or(Err(PgFailure::TimedOut)),
    }
}
async fn cleanup(session: &mut dyn PgSession) -> std::result::Result<(), PgFailure> {
    tokio::time::timeout(Duration::from_millis(500), session.rollback())
        .await
        .unwrap_or(Err(PgFailure::TimedOut))
}

#[cfg(test)]
#[path = "postgres_tests.rs"]
mod tests;
