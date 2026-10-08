//! Fixed, bounded SQL Server reads over a fresh OS-trusted TLS TDS connection.

use super::types::{ReadState, SqlObservation, SqlServerIndexKind};
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
    manifest::{CapabilityId, ProbeParams},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use anyhow::{Result, ensure};
use chrono::Utc;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, Query, QueryItem, Row};
use tokio::net::TcpStream;
use tokio_util::{
    compat::{Compat, TokioAsyncWriteCompatExt},
    sync::CancellationToken,
};

const MAX_ROWS: usize = 20;
const PROBE_COUNT: u32 = 8;
type TdsClient = Client<Compat<TcpStream>>;
type TdsFuture<'a, T> = Pin<Box<dyn Future<Output = std::result::Result<T, Failure>> + Send + 'a>>;

#[path = "sql_server_plan.rs"]
mod plan;
pub(super) use plan::estimated_plan;

#[path = "sql_server_workload.rs"]
mod workload;
pub(super) use workload::run_sandbox_workload;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlServerReadProbe {
    Identity,
    Requests,
    Waits,
    Blocking,
    Objects,
    Indexes,
    Statistics,
    Permissions,
}
impl SqlServerReadProbe {
    const ALL: [Self; 8] = [
        Self::Identity,
        Self::Requests,
        Self::Waits,
        Self::Blocking,
        Self::Objects,
        Self::Indexes,
        Self::Statistics,
        Self::Permissions,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Requests => "requests",
            Self::Waits => "waits",
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
                "SELECT DB_NAME(), ORIGINAL_LOGIN(), SUSER_SNAME(), USER_NAME(), CONVERT(nvarchar(32), SERVERPROPERTY('ProductVersion')), CONVERT(varchar(48), CONNECTIONPROPERTY('local_net_address')), CONVERT(int, CONNECTIONPROPERTY('local_tcp_port')), CONVERT(bit, HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE')), CONVERT(bit, HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER PERFORMANCE STATE'))"
            }
            Self::Requests => {
                "SELECT TOP (21) session_id, status, wait_type, CONVERT(bigint, total_elapsed_time) FROM sys.dm_exec_requests WHERE database_id = DB_ID() AND session_id <> @@SPID ORDER BY session_id"
            }
            Self::Waits => {
                "SELECT TOP (21) w.session_id, w.wait_type, CONVERT(bigint, w.wait_duration_ms) FROM sys.dm_os_waiting_tasks AS w JOIN sys.dm_exec_requests AS r ON r.session_id = w.session_id WHERE r.database_id = DB_ID() AND w.session_id <> @@SPID ORDER BY w.session_id, w.wait_duration_ms DESC"
            }
            Self::Blocking => {
                "SELECT TOP (21) session_id, blocking_session_id FROM sys.dm_exec_requests WHERE database_id = DB_ID() AND session_id <> @@SPID AND blocking_session_id > 0 ORDER BY session_id"
            }
            Self::Objects => {
                "SELECT TOP (21) s.name, t.name, CONVERT(bigint, t.object_id), CONVERT(int, (SELECT COUNT(*) FROM sys.columns AS x WHERE x.object_id = t.object_id)), CONVERT(int, c.column_id), c.name, CONVERT(bit, CASE WHEN c.is_computed = 0 AND c.is_identity = 0 AND c.encryption_type IS NULL AND c.is_sparse = 0 AND c.is_filestream = 0 AND c.generated_always_type = 0 AND c.max_length BETWEEN 1 AND 900 AND c.system_type_id IN (48,52,56,127,104,106,108,167,175,231,239,40,41,42,43,58,61,62,59) THEN 1 ELSE 0 END) FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.columns AS c ON c.object_id = t.object_id WHERE s.name = @P1 AND t.name = @P2 ORDER BY c.column_id"
            }
            Self::Indexes => {
                "SELECT TOP (21) i.name, i.type_desc, CONVERT(bit, CASE WHEN i.is_disabled = 0 AND i.is_hypothetical = 0 THEN 1 ELSE 0 END), CONVERT(bigint, u.user_seeks + u.user_scans + u.user_lookups) FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.indexes AS i ON i.object_id = t.object_id LEFT JOIN sys.dm_db_index_usage_stats AS u ON u.database_id = DB_ID() AND u.object_id = i.object_id AND u.index_id = i.index_id WHERE s.name = @P1 AND t.name = @P2 AND i.name IS NOT NULL ORDER BY i.index_id"
            }
            Self::Statistics => {
                "SELECT TOP (1) CONVERT(bigint, p.rows), CONVERT(bigint, p.modification_counter), CONVERT(bigint, p.steps) FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id OUTER APPLY sys.dm_db_stats_properties(t.object_id, 1) AS p WHERE s.name = @P1 AND t.name = @P2"
            }
            Self::Permissions => {
                "SELECT TOP (1) CONVERT(bit, HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONNECT')), CONVERT(bit, HAS_PERMS_BY_NAME(QUOTENAME(@P1), 'SCHEMA', 'SELECT')), CONVERT(bit, HAS_PERMS_BY_NAME(QUOTENAME(@P1) + '.' + QUOTENAME(@P2), 'OBJECT', 'SELECT')), CONVERT(bit, HAS_PERMS_BY_NAME(QUOTENAME(@P1) + '.' + QUOTENAME(@P2), 'OBJECT', 'ALTER')), CONVERT(bit, HAS_PERMS_BY_NAME(QUOTENAME(@P1) + '.' + QUOTENAME(@P2), 'OBJECT', 'CONTROL'))"
            }
        }
    }
    fn needs_object(self) -> bool {
        matches!(
            self,
            Self::Objects | Self::Indexes | Self::Statistics | Self::Permissions
        )
    }
}

pub fn template_digest() -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-sqlserver-fixed-read-v1\0");
    for probe in SqlServerReadProbe::ALL {
        hash.update(probe.sql().as_bytes());
    }
    format!("{:x}", hash.finalize())
}
pub fn probe_subject_digest(resource_digest: &str, probe: SqlServerReadProbe) -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-sqlserver-read-v1\0");
    hash.update(resource_digest.as_bytes());
    hash.update(probe.label().as_bytes());
    format!("{:x}", hash.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Denied,
    Unavailable,
    InvalidProjection,
    Canceled,
    TimedOut,
}
trait Session: Send {
    fn read<'a>(
        &'a mut self,
        probe: SqlServerReadProbe,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>>;
}
trait Transport: Send + Sync {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> TdsFuture<'a, Box<dyn Session>>;
}
struct NativeTransport;
struct NativeSession {
    client: TdsClient,
}
impl NativeTransport {
    async fn open_session(
        host: &str,
        port: u16,
        database: &str,
        principal: &str,
        password: &str,
    ) -> std::result::Result<NativeSession, Failure> {
        let mut config = Config::new();
        config.host(host);
        config.port(port);
        config.database(database);
        config.authentication(AuthMethod::sql_server(principal, password));
        config.encryption(EncryptionLevel::Required);
        let tcp = TcpStream::connect(config.get_addr())
            .await
            .map_err(|_| Failure::Unavailable)?;
        tcp.set_nodelay(true).map_err(|_| Failure::Unavailable)?;
        let client = Client::connect(config, tcp.compat_write())
            .await
            .map_err(|_| Failure::Unavailable)?;
        Ok(NativeSession { client })
    }
}
impl Transport for NativeTransport {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> TdsFuture<'a, Box<dyn Session>> {
        Box::pin(async move {
            Ok(
                Box::new(Self::open_session(host, port, database, principal, password).await?)
                    as Box<dyn Session>,
            )
        })
    }
}
fn driver_error(error: tiberius::error::Error) -> Failure {
    match error {
        tiberius::error::Error::Server(server)
            if server.code() == 229 || server.code() == 297 || server.code() == 300 =>
        {
            Failure::Denied
        }
        _ => Failure::Unavailable,
    }
}
impl Session for NativeSession {
    fn read<'a>(
        &'a mut self,
        probe: SqlServerReadProbe,
        schema: &'a str,
        object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            let mut query = Query::new(probe.sql());
            if probe.needs_object() {
                query.bind(schema);
                query.bind(object);
            }
            let mut stream = query.query(&mut self.client).await.map_err(driver_error)?;
            let mut values = Vec::new();
            while let Some(item) = stream.next().await {
                let item = item.map_err(driver_error)?;
                if let QueryItem::Row(row) = item {
                    if values.len()
                        >= MAX_ROWS + 1 + usize::from(probe == SqlServerReadProbe::Objects)
                    {
                        return Err(Failure::InvalidProjection);
                    }
                    if probe == SqlServerReadProbe::Objects && values.is_empty() {
                        let object_id = positive_id(
                            row.try_get::<i64, _>(2)
                                .map_err(|_| Failure::InvalidProjection)?,
                        )?;
                        let column_count = u32::try_from(
                            row.try_get::<i32, _>(3)
                                .map_err(|_| Failure::InvalidProjection)?
                                .ok_or(Failure::InvalidProjection)?,
                        )
                        .map_err(|_| Failure::InvalidProjection)?;
                        let object = SqlObservation::SqlServerObject {
                            schema: row
                                .try_get::<&str, _>(0)
                                .map_err(|_| Failure::InvalidProjection)?
                                .ok_or(Failure::InvalidProjection)?
                                .to_owned(),
                            name: row
                                .try_get::<&str, _>(1)
                                .map_err(|_| Failure::InvalidProjection)?
                                .ok_or(Failure::InvalidProjection)?
                                .to_owned(),
                            object_id,
                            column_count,
                        };
                        if !object.bounded() {
                            return Err(Failure::InvalidProjection);
                        }
                        values.push(object);
                    }
                    values.push(project(probe, &row)?);
                }
            }
            Ok(values)
        })
    }
}
fn project(probe: SqlServerReadProbe, row: &Row) -> std::result::Result<SqlObservation, Failure> {
    let get_str = |i| {
        row.try_get::<&str, _>(i)
            .map_err(|_| Failure::InvalidProjection)
            .map(|v| v.map(str::to_owned))
    };
    let required = |i| get_str(i)?.ok_or(Failure::InvalidProjection);
    let value = match probe {
        SqlServerReadProbe::Identity => SqlObservation::SqlServerIdentity {
            database: required(0)?,
            principal: required(1)?,
            effective_principal: required(2)?,
            database_principal: required(3)?,
            product_version: required(4)?,
            server_ip: required(5)?,
            server_port: u16::try_from(
                row.try_get::<i32, _>(6)
                    .map_err(|_| Failure::InvalidProjection)?
                    .ok_or(Failure::InvalidProjection)?,
            )
            .map_err(|_| Failure::InvalidProjection)?,
            tls_required: true,
            server_state_access: row
                .try_get::<bool, _>(7)
                .map_err(|_| Failure::InvalidProjection)?,
            server_performance_access: row
                .try_get::<bool, _>(8)
                .map_err(|_| Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Requests => SqlObservation::SqlServerRequest {
            session_id: row
                .try_get::<i32, _>(0)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
            state: get_str(1)?.filter(|v| SqlObservation::tds_state(v)),
            wait_type: get_str(2)?.filter(|v| SqlObservation::token(v)),
            elapsed_ms: row
                .try_get::<i64, _>(3)
                .map_err(|_| Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Waits => SqlObservation::SqlServerWait {
            session_id: row
                .try_get::<i32, _>(0)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
            wait_type: get_str(1)?.filter(|v| SqlObservation::token(v)),
            wait_ms: row
                .try_get::<i64, _>(2)
                .map_err(|_| Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Blocking => SqlObservation::SqlServerBlocking {
            waiting_session_id: row
                .try_get::<i32, _>(0)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
            blocking_session_id: row
                .try_get::<i32, _>(1)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Objects => SqlObservation::SqlServerColumn {
            object_id: positive_id(
                row.try_get::<i64, _>(2)
                    .map_err(|_| Failure::InvalidProjection)?,
            )?,
            column_id: u32::try_from(
                row.try_get::<i32, _>(4)
                    .map_err(|_| Failure::InvalidProjection)?
                    .ok_or(Failure::InvalidProjection)?,
            )
            .map_err(|_| Failure::InvalidProjection)?,
            name: required(5)?,
            plain: row
                .try_get::<bool, _>(6)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Indexes => SqlObservation::SqlServerIndex {
            name: required(0)?,
            index_kind: SqlServerIndexKind::from_type_desc(&required(1)?)
                .ok_or(Failure::InvalidProjection)?,
            enabled: row
                .try_get::<bool, _>(2)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?,
            usage_count: row
                .try_get::<i64, _>(3)
                .map_err(|_| Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Statistics => SqlObservation::SqlServerStatistics {
            rows: row
                .try_get::<i64, _>(0)
                .map_err(|_| Failure::InvalidProjection)?,
            modification_counter: row
                .try_get::<i64, _>(1)
                .map_err(|_| Failure::InvalidProjection)?,
            histogram_steps: row
                .try_get::<i64, _>(2)
                .map_err(|_| Failure::InvalidProjection)?,
        },
        SqlServerReadProbe::Permissions => SqlObservation::SqlServerPermission {
            database_connect: row
                .try_get::<bool, _>(0)
                .map_err(|_| Failure::InvalidProjection)?,
            schema_select: row
                .try_get::<bool, _>(1)
                .map_err(|_| Failure::InvalidProjection)?,
            object_select: row
                .try_get::<bool, _>(2)
                .map_err(|_| Failure::InvalidProjection)?,
            object_alter: row
                .try_get::<bool, _>(3)
                .map_err(|_| Failure::InvalidProjection)?,
            object_control: row
                .try_get::<bool, _>(4)
                .map_err(|_| Failure::InvalidProjection)?,
        },
    };
    if !value.bounded() {
        return Err(Failure::InvalidProjection);
    }
    Ok(value)
}
fn positive_id(value: Option<i64>) -> std::result::Result<u64, Failure> {
    u64::try_from(value.ok_or(Failure::InvalidProjection)?)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(Failure::InvalidProjection)
}

fn verify_identity(
    identity: &[SqlObservation],
    database: &str,
    principal: &str,
    host: &str,
    port: u16,
) -> Result<bool> {
    let [
        SqlObservation::SqlServerIdentity {
            database: actual_db,
            principal: actual_principal,
            effective_principal,
            database_principal,
            product_version,
            server_ip,
            server_port,
            tls_required,
            server_state_access,
            server_performance_access,
        },
    ] = identity
    else {
        anyhow::bail!("SQL Server identity invalid")
    };
    ensure!(
        actual_db == database
            && actual_principal == principal
            && effective_principal == principal
            // The reviewed scope has no separately approved database-user mapping.
            // Fail closed if the current database execution principal differs.
            && database_principal == principal
            && *server_port == port
            && *tls_required
            && SqlObservation::version_token(product_version),
        "SQL Server identity mismatch"
    );
    if let Ok(expected) = host.parse::<std::net::IpAddr>() {
        ensure!(
            server_ip.parse::<std::net::IpAddr>().ok() == Some(expected),
            "SQL Server endpoint mismatch"
        );
    }
    Ok(*server_state_access == Some(true) || *server_performance_access == Some(true))
}

/// Fresh, verified SQL Server session for a closed Task 8 SHOWPLAN operation.
/// The client remains private here so callers cannot submit arbitrary SQL.
#[allow(dead_code)] // Consumed by the next SQL plan wave after branch integration.
pub(super) struct VerifiedNativeSession {
    client: TdsClient,
    deadline: Instant,
    cancel: CancellationToken,
}

pub(super) async fn open_verified_native(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<VerifiedNativeSession> {
    let BoundScope::Database {
        target,
        engine: DatabaseEngine::SqlServer,
        port,
        database,
        credential,
        ..
    } = &request.scope
    else {
        anyhow::bail!("SQL Server scope required")
    };
    ensure!(
        matches!(
            request.capability_id,
            CapabilityId::SqlPlan
                | CapabilityId::SqlWorkloadBaseline
                | CapabilityId::SqlWorkloadRehearsal
        ),
        "SQL plan capability required"
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
        secret.username() == credential.principal && secret.domain().is_empty(),
        "SQL login principal mismatch"
    );
    let remaining = (request.requested_at
        + chrono::Duration::seconds(request.deadline_secs.unwrap_or(15).min(30) as i64))
    .signed_duration_since(Utc::now())
    .num_milliseconds();
    ensure!(remaining > 0, "SQL Server deadline elapsed");
    let deadline = Instant::now() + Duration::from_millis(remaining as u64);
    let mut session = gated(
        &cancel,
        deadline,
        Box::pin(NativeTransport::open_session(
            &target.host,
            *port,
            database,
            &credential.principal,
            secret.password(),
        )),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server connection unavailable"))?;
    drop(secret);
    let identity = gated(
        &cancel,
        deadline,
        session.read(SqlServerReadProbe::Identity, "", ""),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server identity unavailable"))?;
    verify_identity(
        &identity,
        database,
        &credential.principal,
        &target.host,
        *port,
    )?;
    Ok(VerifiedNativeSession {
        client: session.client,
        deadline,
        cancel,
    })
}

fn classify(probe: SqlServerReadProbe, rows: &[SqlObservation]) -> ReadState {
    if rows.is_empty() {
        return if probe.needs_object() && probe != SqlServerReadProbe::Indexes {
            ReadState::Unknown
        } else {
            ReadState::Empty
        };
    }
    if rows.iter().any(|v| {
        matches!(
            v,
            SqlObservation::SqlServerPermission {
                database_connect: Some(false),
                ..
            } | SqlObservation::SqlServerPermission {
                schema_select: Some(false),
                ..
            } | SqlObservation::SqlServerPermission {
                object_select: Some(false),
                ..
            }
        )
    }) {
        return ReadState::Denied;
    }
    if rows.iter().any(|v| {
        matches!(
            v,
            SqlObservation::SqlServerRequest { state: None, .. }
                | SqlObservation::SqlServerRequest {
                    elapsed_ms: None,
                    ..
                }
                | SqlObservation::SqlServerWait {
                    wait_type: None,
                    ..
                }
                | SqlObservation::SqlServerWait { wait_ms: None, .. }
                | SqlObservation::SqlServerIndex {
                    usage_count: None,
                    ..
                }
                | SqlObservation::SqlServerStatistics { rows: None, .. }
                | SqlObservation::SqlServerStatistics {
                    modification_counter: None,
                    ..
                }
                | SqlObservation::SqlServerStatistics {
                    histogram_steps: None,
                    ..
                }
                | SqlObservation::SqlServerPermission {
                    database_connect: None,
                    ..
                }
                | SqlObservation::SqlServerPermission {
                    schema_select: None,
                    ..
                }
                | SqlObservation::SqlServerPermission {
                    object_select: None,
                    ..
                }
        )
    }) {
        return ReadState::Unknown;
    }
    ReadState::Observed
}

pub struct SqlServerAdapter;
impl ProbeAdapter for SqlServerAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { collect_with(&NativeTransport, request, secrets, cancel).await })
    }
}
async fn gated<T>(
    cancel: &CancellationToken,
    deadline: Instant,
    future: TdsFuture<'_, T>,
) -> std::result::Result<T, Failure> {
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(Failure::Canceled),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future) => result.unwrap_or(Err(Failure::TimedOut)),
    }
}
async fn collect_with(
    transport: &dyn Transport,
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<ProbeOutput> {
    let BoundScope::Database {
        target,
        engine: DatabaseEngine::SqlServer,
        port,
        database,
        schema,
        object,
        credential,
    } = &request.scope
    else {
        anyhow::bail!("SQL Server scope required")
    };
    ensure!(
        request.capability_id == CapabilityId::SqlRead
            && matches!(&request.params, ProbeParams::SqlRead { query_digest } if query_digest == &template_digest()),
        "Fixed SQL Server template required"
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
        secret.username() == credential.principal && secret.domain().is_empty(),
        "SQL login principal mismatch"
    );
    let remaining = (request.requested_at
        + chrono::Duration::seconds(request.deadline_secs.unwrap_or(15).min(30) as i64))
    .signed_duration_since(Utc::now())
    .num_milliseconds();
    ensure!(remaining > 0, "SQL Server deadline elapsed");
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
    .map_err(|_| anyhow::anyhow!("SQL Server connection unavailable"))?;
    drop(secret);
    let identity = gated(
        &cancel,
        deadline,
        session.read(SqlServerReadProbe::Identity, "", ""),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SQL Server identity unavailable"))?;
    let dmv_visible = verify_identity(
        &identity,
        database,
        &credential.principal,
        &target.host,
        *port,
    )?;
    let mut observations = identity;
    let mut states = vec![(SqlServerReadProbe::Identity, ReadState::Observed)];
    let mut observed = 1u32;
    let mut truncated = false;
    let mut object_present = false;
    for probe in SqlServerReadProbe::ALL.into_iter().skip(1) {
        if matches!(
            probe,
            SqlServerReadProbe::Requests | SqlServerReadProbe::Waits | SqlServerReadProbe::Blocking
        ) && !dmv_visible
        {
            states.push((probe, ReadState::Unknown));
            continue;
        }
        if probe.needs_object()
            && (schema.is_none()
                || object.is_none()
                || (matches!(
                    probe,
                    SqlServerReadProbe::Indexes | SqlServerReadProbe::Statistics
                ) && !object_present))
        {
            states.push((probe, ReadState::Unknown));
            continue;
        }
        match gated(
            &cancel,
            deadline,
            session.read(
                probe,
                schema.as_deref().unwrap_or(""),
                object.as_deref().unwrap_or(""),
            ),
        )
        .await
        {
            Ok(rows) => {
                if probe == SqlServerReadProbe::Objects {
                    object_present = !rows.is_empty();
                }
                let remaining_capacity =
                    super::types::MAX_SQL_OBSERVATIONS.saturating_sub(observations.len());
                let exceeds_probe_cap = if probe == SqlServerReadProbe::Objects {
                    rows.first()
                        .and_then(|v| {
                            if let SqlObservation::SqlServerObject { column_count, .. } = v {
                                Some(
                                    *column_count as usize > MAX_ROWS
                                        || *column_count as usize != rows.len().saturating_sub(1),
                                )
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false)
                } else {
                    rows.len() > MAX_ROWS
                };
                let state = if exceeds_probe_cap || rows.len() > remaining_capacity {
                    truncated = true;
                    ReadState::Truncated
                } else {
                    classify(probe, &rows)
                };
                if matches!(state, ReadState::Observed | ReadState::Empty) {
                    observed += 1;
                }
                observations.extend(
                    rows.into_iter().take(
                        (MAX_ROWS + usize::from(probe == SqlServerReadProbe::Objects))
                            .min(remaining_capacity),
                    ),
                );
                states.push((probe, state));
            }
            Err(Failure::Denied) => states.push((probe, ReadState::Denied)),
            Err(Failure::Unavailable) => states.push((probe, ReadState::Unknown)),
            Err(Failure::InvalidProjection) if probe == SqlServerReadProbe::Indexes => {
                states.push((probe, ReadState::Unknown));
            }
            Err(_) => anyhow::bail!("SQL Server collection interrupted"),
        }
    }
    ensure!(
        observations.len() <= super::types::MAX_SQL_OBSERVATIONS,
        "SQL Server output limit"
    );
    let digest = request.scope.resource_digest()?;
    let records = states
        .into_iter()
        .map(|(probe, state)| NormalizedRecord {
            kind: RecordKind::SqlRead,
            observation: match state {
                ReadState::Observed | ReadState::Empty => Observation::Healthy,
                ReadState::Denied => Observation::Unavailable,
                ReadState::Truncated => Observation::Degraded,
                ReadState::Unknown => Observation::Unknown,
            },
            subject_sha256: probe_subject_digest(&digest, probe),
            detail: None,
        })
        .collect();
    Ok(ProbeOutput {
        status: if truncated {
            EvidenceStatus::Truncated
        } else if observed == PROBE_COUNT {
            EvidenceStatus::Complete
        } else {
            EvidenceStatus::Partial
        },
        coverage: Coverage {
            observed,
            expected: PROBE_COUNT,
            truncated,
        },
        records,
        metrics: Vec::new(),
        sql_observations: observations,
        sql_artifacts: Vec::new(),
        evidence_refs: Vec::new(),
        source_id: format!("sqlserver:{}:{}:{}", target.host, port, database).into_bytes(),
        source_observed_at: Utc::now(),
        parser_version: 1,
    })
}

#[cfg(test)]
#[path = "sql_server_tests.rs"]
mod tests;
