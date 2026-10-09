//! Native, closed SQL change plans. No caller can submit SQL text.
use crate::helper::approval::DispatchPermit;
use crate::helper::journal::{ActionJournal, IntentId, IntentState};
use crate::helper::{
    credentials::{PersistentSecretResolver, SecretResolver},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use crate::helper_action::{
    SortDirection, SqlAction, SqlEngine, VerifiedSqlColumn, VerifiedSqlMetadata, digest,
};
use crate::helper_approval::RunKind;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use serde::Serialize;
use std::{path::Path, time::Duration};
use tiberius::{
    AuthMethod, Client as TdsClient, Config as TdsConfig, EncryptionLevel, Query, QueryItem, Row,
};
use tokio::net::TcpStream;
use tokio_postgres::{Client as PgClient, Config as PgConfig};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;

const MAX_ACTION_COLUMNS: usize = 20;
const MAX_ACTION_INDEXES: usize = 20;
const CONNECT_LIMIT: Duration = Duration::from_secs(5);
const ACTION_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize)]
struct NativeColumn {
    id: u32,
    name: String,
    data_type: String,
    plain: bool,
}

#[derive(Clone, Debug, Serialize)]
struct NativeIndex {
    id: u64,
    name: String,
    definition: String,
    valid: bool,
    ownership: Option<String>,
}

/// The raw physical identity stays in memory. Only its digest crosses a
/// protected persistence boundary.
#[derive(Clone, Debug, Serialize)]
struct NativeState {
    engine: SqlEngine,
    physical_instance: String,
    database: String,
    database_id: u64,
    schema: String,
    schema_id: u64,
    table: String,
    object_id: u64,
    principal: String,
    version: String,
    columns: Vec<NativeColumn>,
    indexes: Vec<NativeIndex>,
    statistics: String,
    grants: Vec<bool>,
    configuration: Vec<String>,
}

/// Collected only by a real native connection; fields cannot be caller filled.
pub struct NativePreflight {
    state: NativeState,
    metadata_sha256: String,
    before_sha256: String,
    credential_scope_sha256: String,
    observed_at: DateTime<Utc>,
}

impl NativePreflight {
    pub(crate) fn object_id(&self) -> u64 {
        self.state.object_id
    }
    pub(crate) fn database_id(&self) -> u64 {
        self.state.database_id
    }
    pub(crate) fn restoration_guard_digest(&self) -> Result<String> {
        self.state.restoration_guard_digest()
    }
    pub(crate) fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }
    pub(crate) fn before_sha256(&self) -> &str {
        &self.before_sha256
    }
    pub(crate) fn credential_scope_sha256(&self) -> &str {
        &self.credential_scope_sha256
    }
    pub(crate) fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub(crate) fn physical_digest(&self) -> Result<String> {
        digest(
            b"relayne-helper-physical-database-v1",
            &(
                self.state.engine,
                &self.state.physical_instance,
                &self.state.database,
                self.state.database_id,
            ),
        )
    }
}

impl NativeState {
    fn physical_digest(&self) -> Result<String> {
        digest(
            b"relayne-helper-physical-database-v1",
            &(
                self.engine,
                &self.physical_instance,
                &self.database,
                self.database_id,
            ),
        )
    }

    fn restoration_guard_digest(&self) -> Result<String> {
        digest(
            b"relayne-helper-sql-restoration-guard-v1",
            &(
                self.engine,
                &self.physical_instance,
                &self.database,
                self.database_id,
                &self.schema,
                self.schema_id,
                &self.table,
                self.object_id,
                &self.principal,
                &self.version,
                &self.columns,
                &self.grants,
                &self.configuration,
            ),
        )
    }
}

pub(crate) struct NativeTrialTarget {
    pub(crate) preflight: NativePreflight,
    pub(crate) action: SqlAction,
    pub(crate) metadata: VerifiedSqlMetadata,
}

/// Stage object identity is collected independently; the proposal's object ID
/// is never copied to the isolated database.
pub(crate) async fn collect_trial_target(
    production: &NativePreflight,
    production_action: &SqlAction,
    production_metadata: &VerifiedSqlMetadata,
    stage_scope: &BoundScope,
    cancel: CancellationToken,
) -> Result<NativeTrialTarget> {
    ensure!(!cancel.is_cancelled(), "Trial collection canceled");
    let stage_state = match production.state.engine {
        SqlEngine::Postgres => {
            #[cfg(test)]
            READ_ONLY_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (client, driver, _) = pg_connection(stage_scope).await?;
            #[cfg(test)]
            READ_ONLY_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let observed = tokio::time::timeout(CONNECT_LIMIT, pg_state(&client, stage_scope))
                .await
                .context("Staging metadata timed out")?;
            driver.abort();
            observed?
        }
        SqlEngine::SqlServer => tds_state_for_change(stage_scope, cancel).await?,
    };
    ensure!(
        stage_state.engine == production.state.engine
            && stage_state.physical_instance != production.state.physical_instance,
        "Staging target is same or unproven physical database"
    );
    ensure!(
        stage_state.schema == production.state.schema
            && stage_state.table == production.state.table
            && stage_state.columns.len() == production.state.columns.len()
            && stage_state
                .columns
                .iter()
                .zip(&production.state.columns)
                .all(|(a, b)| a.id == b.id
                    && a.name == b.name
                    && a.data_type == b.data_type
                    && a.plain == b.plain),
        "Staging schema/column identity differs"
    );
    let mut object = production_action.object().clone();
    object.database = stage_state.database.clone();
    object.scope_sha256 = stage_scope.digest()?;
    object.object_id = stage_state.object_id;
    let action = match production_action {
        SqlAction::PostgresCreateIndex { index, columns, .. } => SqlAction::PostgresCreateIndex {
            object: object.clone(),
            index: index.clone(),
            columns: columns.clone(),
        },
        SqlAction::PostgresAnalyze { .. } => SqlAction::PostgresAnalyze {
            object: object.clone(),
        },
        SqlAction::SqlServerCreateIndex { index, columns, .. } => SqlAction::SqlServerCreateIndex {
            object: object.clone(),
            index: index.clone(),
            columns: columns.clone(),
        },
        SqlAction::SqlServerUpdateStatistics { .. } => SqlAction::SqlServerUpdateStatistics {
            object: object.clone(),
        },
    };
    let metadata = VerifiedSqlMetadata {
        object,
        columns: stage_state
            .columns
            .iter()
            .map(|c| VerifiedSqlColumn {
                name: c.name.clone(),
                column_id: c.id,
                plain: c.plain,
            })
            .collect(),
        existing_indexes: stage_state.indexes.iter().map(|i| i.name.clone()).collect(),
        base_table: true,
        source_evidence_sha256: production_metadata.source_evidence_sha256.clone(),
    };
    action.validate(&metadata)?;
    let preflight = NativePreflight {
        before_sha256: digest(b"relayne-helper-native-sql-before-v1", &stage_state)?,
        metadata_sha256: digest(b"relayne-helper-sql-metadata-v2", &metadata)?,
        credential_scope_sha256: stage_scope.credential_scope_digest()?,
        observed_at: Utc::now(),
        state: stage_state,
    };
    Ok(NativeTrialTarget {
        preflight,
        action,
        metadata,
    })
}

pub(crate) struct PreparedSqlChange {
    operation: PreparedOperation,
    action_sha256: String,
}

enum PreparedOperation {
    PgCreate {
        statement: String,
        schema: String,
        index: String,
    },
    PgAnalyze {
        statement: String,
    },
    TdsCreate {
        statement: String,
        schema: String,
        table: String,
        index: String,
    },
    TdsUpdate {
        statement: String,
    },
}

fn pg_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn tds_ident(value: &str) -> String {
    format!("[{}]", value.replace(']', "]]"))
}

/// The sole SQL builder; SQL text is never a public input.
pub(crate) fn prepare_sql_change(
    action: &SqlAction,
    scope: &BoundScope,
    metadata: &VerifiedSqlMetadata,
) -> Result<PreparedSqlChange> {
    action.validate(metadata)?;
    ensure!(
        metadata.columns.len() <= MAX_ACTION_COLUMNS
            && metadata.existing_indexes.len() <= MAX_ACTION_INDEXES,
        "Native metadata coverage exceeds supported exact bound"
    );
    ensure!(
        scope.digest()? == action.object().scope_sha256,
        "SQL action scope differs"
    );
    let BoundScope::Database {
        engine,
        database,
        schema,
        object,
        credential: Some(credential),
        ..
    } = scope
    else {
        anyhow::bail!("Exact database scope and change credential required")
    };
    ensure!(
        credential.purpose == CredentialPurpose::ControlledChange,
        "Controlled-change credential required"
    );
    ensure!(
        database == &action.object().database
            && schema.as_deref() == Some(action.object().schema.as_str())
            && object.as_deref() == Some(action.object().table.as_str()),
        "SQL action object differs from scope"
    );
    ensure!(
        matches!(
            (engine, action.object().engine),
            (DatabaseEngine::Postgres, SqlEngine::Postgres)
                | (DatabaseEngine::SqlServer, SqlEngine::SqlServer)
        ),
        "SQL engine differs"
    );
    let obj = action.object();
    let operation = match action {
        SqlAction::PostgresCreateIndex { index, columns, .. } => {
            let keys = columns
                .iter()
                .map(|c| {
                    format!(
                        "{} {}",
                        pg_ident(&c.name),
                        if c.direction == SortDirection::Asc {
                            "ASC"
                        } else {
                            "DESC"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            PreparedOperation::PgCreate {
                statement: format!(
                    "CREATE INDEX {} ON {}.{} USING btree ({keys})",
                    pg_ident(index),
                    pg_ident(&obj.schema),
                    pg_ident(&obj.table)
                ),
                schema: obj.schema.clone(),
                index: index.clone(),
            }
        }
        SqlAction::PostgresAnalyze { .. } => PreparedOperation::PgAnalyze {
            statement: format!("ANALYZE {}.{}", pg_ident(&obj.schema), pg_ident(&obj.table)),
        },
        SqlAction::SqlServerCreateIndex { index, columns, .. } => {
            let keys = columns
                .iter()
                .map(|c| {
                    format!(
                        "{} {}",
                        tds_ident(&c.name),
                        if c.direction == SortDirection::Asc {
                            "ASC"
                        } else {
                            "DESC"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            PreparedOperation::TdsCreate {
                statement: format!(
                    "CREATE NONCLUSTERED INDEX {} ON {}.{} ({keys})",
                    tds_ident(index),
                    tds_ident(&obj.schema),
                    tds_ident(&obj.table)
                ),
                schema: obj.schema.clone(),
                table: obj.table.clone(),
                index: index.clone(),
            }
        }
        SqlAction::SqlServerUpdateStatistics { .. } => PreparedOperation::TdsUpdate {
            statement: format!(
                "UPDATE STATISTICS {}.{}",
                tds_ident(&obj.schema),
                tds_ident(&obj.table)
            ),
        },
    };
    Ok(PreparedSqlChange {
        operation,
        action_sha256: digest(b"relayne-helper-sql-action-v1", action)?,
    })
}

fn exact_scope<'a>(
    scope: &'a BoundScope,
    engine: DatabaseEngine,
) -> Result<(
    &'a str,
    u16,
    &'a str,
    &'a str,
    &'a str,
    &'a crate::helper::scope::CredentialScope,
)> {
    scope.validate()?;
    let BoundScope::Database {
        target,
        engine: actual,
        port,
        database,
        schema: Some(schema),
        object: Some(object),
        credential: Some(credential),
    } = scope
    else {
        anyhow::bail!("Exact scoped database object and credential required")
    };
    ensure!(
        *actual == engine && credential.purpose == CredentialPurpose::ControlledChange,
        "Wrong engine or credential purpose"
    );
    Ok((&target.host, *port, database, schema, object, credential))
}

async fn pg_connection(
    scope: &BoundScope,
) -> Result<(PgClient, tokio::task::JoinHandle<()>, MakeTlsConnector)> {
    let (host, port, database, _, _, credential) = exact_scope(scope, DatabaseEngine::Postgres)?;
    let secret = PersistentSecretResolver::new()?
        .resolve(credential, CredentialPurpose::ControlledChange)?;
    ensure!(
        secret.username() == credential.principal,
        "Credential principal changed"
    );
    let tls = MakeTlsConnector::new(TlsConnector::builder().build()?);
    let mut cfg = PgConfig::new();
    cfg.host(host)
        .port(port)
        .dbname(database)
        .user(&credential.principal)
        .password(secret.password())
        .ssl_mode(tokio_postgres::config::SslMode::Require)
        .connect_timeout(CONNECT_LIMIT);
    let (client, connection) = tokio::time::timeout(CONNECT_LIMIT, cfg.connect(tls.clone()))
        .await
        .context("Native PostgreSQL connection timed out")?
        .context("Native PostgreSQL connection unavailable")?;
    drop(cfg);
    drop(secret);
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((client, driver, tls))
}

async fn pg_state(client: &PgClient, scope: &BoundScope) -> Result<NativeState> {
    let (host, port, database, schema, table, credential) =
        exact_scope(scope, DatabaseEngine::Postgres)?;
    let row = client.query_one(
        "SELECT current_database()::text, d.oid::bigint, (SELECT system_identifier::text FROM pg_control_system()), host(inet_server_addr())::text, inet_server_port()::integer, session_user::text, current_user::text, current_setting('server_version_num')::text, s.ssl, current_setting('search_path')::text FROM pg_database d JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE d.datname=current_database()",
        &[],
    ).await.context("PostgreSQL identity unavailable")?;
    let db: String = row.try_get(0)?;
    let db_id: i64 = row.try_get(1)?;
    let system_id: String = row.try_get(2)?;
    let server_ip: String = row.try_get(3)?;
    let server_port: i32 = row.try_get(4)?;
    let session_user: String = row.try_get(5)?;
    let current_user: String = row.try_get(6)?;
    let version: String = row.try_get(7)?;
    let tls: bool = row.try_get(8)?;
    let search_path: String = row.try_get(9)?;
    ensure!(
        db == database && db_id > 0,
        "PostgreSQL database identity differs"
    );
    ensure!(
        !system_id.is_empty() && system_id.len() <= 32,
        "PostgreSQL cluster identity unavailable"
    );
    ensure!(
        server_ip == host,
        "PostgreSQL server IP differs: {server_ip}"
    );
    ensure!(
        server_port == i32::from(port),
        "PostgreSQL server port differs"
    );
    ensure!(tls, "PostgreSQL native TLS unavailable");
    ensure!(
        session_user == credential.principal && current_user == session_user,
        "PostgreSQL principal differs"
    );
    let row = client.query_opt(
        "SELECT n.oid::bigint, c.oid::bigint, c.relkind::text, c.relpersistence::text, pg_has_role(current_user,c.relowner,'USAGE'), has_database_privilege(current_user,current_database(),'CONNECT'), has_schema_privilege(current_user,n.oid,'USAGE'), has_schema_privilege(current_user,n.oid,'CREATE'), has_table_privilege(current_user,c.oid,'MAINTAIN') FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r'",
        &[&schema, &table],
    ).await.context("PostgreSQL object unavailable")?.context("PostgreSQL base table missing")?;
    let schema_id: i64 = row.try_get(0)?;
    let object_id: i64 = row.try_get(1)?;
    let relkind: String = row.try_get(2)?;
    let persistence: String = row.try_get(3)?;
    let owner: bool = row.try_get(4)?;
    let db_connect: bool = row.try_get(5)?;
    let schema_usage: bool = row.try_get(6)?;
    let schema_create: bool = row.try_get(7)?;
    let maintain: bool = row.try_get(8)?;
    ensure!(
        schema_id > 0 && object_id > 0 && relkind == "r" && persistence == "p",
        "PostgreSQL object identity incomplete"
    );
    let columns = client.query(
        "SELECT a.attnum::integer, a.attname::text, format_type(a.atttypid,a.atttypmod)::text, a.attgenerated::text, a.attisdropped FROM pg_attribute a WHERE a.attrelid=$1::oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum LIMIT 21",
        &[&(object_id as u32)],
    ).await.context("PostgreSQL columns unavailable")?;
    ensure!(
        !columns.is_empty() && columns.len() <= MAX_ACTION_COLUMNS,
        "PostgreSQL column coverage incomplete"
    );
    let columns = columns
        .iter()
        .map(|r| -> Result<NativeColumn> {
            let id: i32 = r.try_get(0)?;
            let name: String = r.try_get(1)?;
            let data_type: String = r.try_get(2)?;
            let generated: String = r.try_get(3)?;
            let dropped: bool = r.try_get(4)?;
            ensure!(
                id > 0 && name.len() <= 63 && data_type.len() <= 128 && !dropped,
                "Invalid PostgreSQL column"
            );
            Ok(NativeColumn {
                id: id as u32,
                name,
                data_type,
                plain: generated.is_empty(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let indexes = client.query(
        "SELECT ic.oid::bigint, ic.relname::text, pg_get_indexdef(ic.oid)::text, i.indisvalid, obj_description(ic.oid,'pg_class')::text FROM pg_index i JOIN pg_class ic ON ic.oid=i.indexrelid WHERE i.indrelid=$1::oid ORDER BY ic.oid LIMIT 21",
        &[&(object_id as u32)],
    ).await.context("PostgreSQL index metadata unavailable")?;
    ensure!(
        indexes.len() <= MAX_ACTION_INDEXES,
        "PostgreSQL index coverage incomplete"
    );
    let indexes = indexes
        .iter()
        .map(|r| -> Result<NativeIndex> {
            let id: i64 = r.try_get(0)?;
            let name: String = r.try_get(1)?;
            let definition: String = r.try_get(2)?;
            ensure!(
                id > 0 && name.len() <= 63 && definition.len() <= 2048,
                "Invalid PostgreSQL index"
            );
            Ok(NativeIndex {
                id: id as u64,
                name,
                definition,
                valid: r.try_get(3)?,
                ownership: r.try_get(4)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let stat = client.query_one(
        "SELECT COALESCE(s.last_analyze::text,''), COALESCE(s.last_autoanalyze::text,''), COALESCE(s.analyze_count,0)::bigint, COALESCE(s.autoanalyze_count,0)::bigint FROM pg_stat_all_tables s WHERE s.relid=$1::oid",
        &[&(object_id as u32)],
    ).await.context("PostgreSQL statistics unavailable")?;
    let statistics = format!(
        "{}:{}:{}:{}",
        stat.try_get::<_, String>(0)?,
        stat.try_get::<_, String>(1)?,
        stat.try_get::<_, i64>(2)?,
        stat.try_get::<_, i64>(3)?
    );
    Ok(NativeState {
        engine: SqlEngine::Postgres,
        physical_instance: system_id,
        database: db,
        database_id: db_id as u64,
        schema: schema.to_owned(),
        schema_id: schema_id as u64,
        table: table.to_owned(),
        object_id: object_id as u64,
        principal: current_user,
        version,
        columns,
        indexes,
        statistics,
        grants: vec![db_connect, schema_usage, schema_create, owner, maintain],
        configuration: vec![search_path],
    })
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuestPgIndexWitness {
    pub id: u64,
    pub name: String,
    pub definition_sha256: String,
    pub marker_sha256: Option<String>,
    pub valid: bool,
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuestPgReadback {
    pub physical_sha256: String,
    pub database_id: u64,
    pub object_id: u64,
    pub row_count: usize,
    pub row_sha256: String,
    pub index_set_sha256: String,
    pub indexes: Vec<GuestPgIndexWitness>,
    pub customer_id_index_present: bool,
}

/// Fixed, read-only synthetic fixture witness. No SQL text is accepted from a caller.
#[cfg(test)]
pub(crate) async fn guest_pg_read_only_witness(
    change_scope: &BoundScope,
    read_scope: &BoundScope,
    cancel: CancellationToken,
) -> Result<GuestPgReadback> {
    use sha2::Digest as _;
    ensure!(
        change_scope
            .credential()
            .is_some_and(|credential| credential.purpose == CredentialPurpose::ControlledChange)
            && read_scope
                .credential()
                .is_some_and(|credential| credential.purpose == CredentialPurpose::Read)
            && change_scope.resource_digest()? == read_scope.resource_digest()?
            && matches!(read_scope, BoundScope::Database { engine: DatabaseEngine::Postgres, schema: Some(schema), object: Some(table), .. } if schema == "fixture" && table == "orders"),
        "Guest witness requires exact fixture change and reader scopes"
    );
    ensure!(!cancel.is_cancelled(), "Guest readback canceled");
    READ_ONLY_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let (client, driver, _) = pg_connection(change_scope).await?;
    READ_ONLY_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    READ_ONLY_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let (reader, reader_driver) = match guest_pg_reader_connection(read_scope, &cancel).await {
        Ok(connection) => connection,
        Err(error) => {
            driver.abort();
            return Err(error);
        }
    };
    READ_ONLY_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let result = async {
        let state = pg_state(&client, change_scope).await?;
        let rows = tokio::select! {
            _ = cancel.cancelled() => anyhow::bail!("Guest readback canceled"),
            result = tokio::time::timeout(
                ACTION_LIMIT,
                reader.query(
                    "SELECT row_to_json(t)::text FROM fixture.orders AS t ORDER BY t.order_id LIMIT 100001",
                    &[],
                ),
            ) => result.context("Fixture row witness timed out")??,
        };
        ensure!(rows.len() <= 100_000, "Fixture row witness exceeds bound");
        let mut row_hash = sha2::Sha256::new();
        for row in &rows {
            let text: String = row.try_get(0)?;
            row_hash.update((text.len() as u64).to_le_bytes());
            row_hash.update(text.as_bytes());
        }
        let indexes = state
            .indexes
            .iter()
            .map(|index| {
                Ok(GuestPgIndexWitness {
                    id: index.id,
                    name: index.name.clone(),
                    definition_sha256: digest(b"relayne-guest-pg-index-definition-v1", &index.definition)?,
                    marker_sha256: index
                        .ownership
                        .as_ref()
                        .map(|marker| digest(b"relayne-guest-pg-index-marker-v1", marker))
                        .transpose()?,
                    valid: index.valid,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(GuestPgReadback {
            physical_sha256: digest(
                b"relayne-helper-physical-database-v1",
                &(state.engine, &state.physical_instance, &state.database, state.database_id),
            )?,
            database_id: state.database_id,
            object_id: state.object_id,
            row_count: rows.len(),
            row_sha256: format!("{:x}", row_hash.finalize()),
            index_set_sha256: digest(b"relayne-guest-pg-index-set-v1", &state.indexes)?,
            indexes,
            customer_id_index_present: state
                .indexes
                .iter()
                .any(|index| index.definition.to_ascii_lowercase().contains("customer_id")),
        })
    }
    .await;
    driver.abort();
    reader_driver.abort();
    result
}

#[cfg(test)]
async fn guest_pg_reader_connection(
    scope: &BoundScope,
    cancel: &CancellationToken,
) -> Result<(PgClient, tokio::task::JoinHandle<()>)> {
    scope.validate()?;
    let BoundScope::Database {
        target,
        engine: DatabaseEngine::Postgres,
        port,
        database,
        credential: Some(credential),
        ..
    } = scope
    else {
        anyhow::bail!("Fixed guest PostgreSQL reader scope required")
    };
    ensure!(
        credential.purpose == CredentialPurpose::Read,
        "Guest readback cannot use change credential"
    );
    let secret = PersistentSecretResolver::new()?.resolve(credential, CredentialPurpose::Read)?;
    ensure!(
        secret.username() == credential.principal,
        "Guest reader principal changed"
    );
    let tls = MakeTlsConnector::new(TlsConnector::builder().build()?);
    let mut cfg = PgConfig::new();
    cfg.host(&target.host)
        .port(*port)
        .dbname(database)
        .user(&credential.principal)
        .password(secret.password())
        .ssl_mode(tokio_postgres::config::SslMode::Require)
        .connect_timeout(CONNECT_LIMIT);
    let (client, connection) = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("Guest reader canceled"),
        result = tokio::time::timeout(CONNECT_LIMIT, cfg.connect(tls)) => result.context("Guest reader connection timed out")??,
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((client, driver))
}

fn check_against_metadata(
    state: &NativeState,
    action: &SqlAction,
    metadata: &VerifiedSqlMetadata,
) -> Result<()> {
    ensure!(
        state.engine == action.object().engine
            && state.database == action.object().database
            && state.schema == action.object().schema
            && state.table == action.object().table
            && state.object_id == action.object().object_id,
        "Native SQL object differs from reviewed action"
    );
    ensure!(
        state.columns.len() == metadata.columns.len(),
        "Column coverage differs reviewed metadata"
    );
    for (actual, reviewed) in state.columns.iter().zip(&metadata.columns) {
        ensure!(
            actual.id == reviewed.column_id
                && actual.name == reviewed.name
                && actual.plain == reviewed.plain,
            "Column identity differs reviewed metadata"
        );
    }
    let mut names = state
        .indexes
        .iter()
        .map(|i| i.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = metadata.existing_indexes.clone();
    expected.sort();
    ensure!(names == expected, "Index set differs reviewed metadata");
    let permitted = match state.engine {
        SqlEngine::Postgres => {
            state.grants.first() == Some(&true)
                && state.grants.get(1) == Some(&true)
                && if action.is_statistics() {
                    state.grants.get(4) == Some(&true)
                } else {
                    state.grants.get(2) == Some(&true) && state.grants.get(3) == Some(&true)
                }
        }
        SqlEngine::SqlServer => state.grants.iter().all(|v| *v),
    };
    ensure!(permitted, "Current native SQL grants insufficient");
    Ok(())
}

pub(crate) async fn collect_native_preflight(
    action: &SqlAction,
    scope: &BoundScope,
    metadata: &VerifiedSqlMetadata,
    cancel: CancellationToken,
) -> Result<NativePreflight> {
    let _prepared = prepare_sql_change(action, scope, metadata)?;
    ensure!(!cancel.is_cancelled(), "SQL preflight canceled");
    let state = match action.object().engine {
        SqlEngine::Postgres => {
            #[cfg(test)]
            READ_ONLY_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (client, driver, _) = pg_connection(scope).await?;
            #[cfg(test)]
            READ_ONLY_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = tokio::select! {
                _ = cancel.cancelled() => anyhow::bail!("SQL preflight canceled"),
                result = tokio::time::timeout(CONNECT_LIMIT, pg_state(&client, scope)) =>
                    result.context("PostgreSQL metadata timed out")?,
            };
            driver.abort();
            result?
        }
        SqlEngine::SqlServer => tds_state_for_change(scope, cancel.clone()).await?,
    };
    check_against_metadata(&state, action, metadata)?;
    let before_sha256 = digest(b"relayne-helper-native-sql-before-v1", &state)?;
    Ok(NativePreflight {
        state,
        metadata_sha256: digest(b"relayne-helper-sql-metadata-v2", metadata)?,
        before_sha256,
        credential_scope_sha256: scope.credential_scope_digest()?,
        observed_at: Utc::now(),
    })
}

type TdsWire = TdsClient<Compat<TcpStream>>;

async fn tds_connection(scope: &BoundScope) -> Result<TdsWire> {
    let (host, port, database, _, _, credential) = exact_scope(scope, DatabaseEngine::SqlServer)?;
    let secret = PersistentSecretResolver::new()?
        .resolve(credential, CredentialPurpose::ControlledChange)?;
    ensure!(
        secret.username() == credential.principal && secret.domain().is_empty(),
        "SQL Server login principal changed"
    );
    let mut cfg = TdsConfig::new();
    cfg.host(host);
    cfg.port(port);
    cfg.database(database);
    cfg.authentication(AuthMethod::sql_server(
        &credential.principal,
        secret.password(),
    ));
    cfg.encryption(EncryptionLevel::Required);
    let tcp = tokio::time::timeout(CONNECT_LIMIT, TcpStream::connect(cfg.get_addr()))
        .await
        .context("SQL Server connection timed out")?
        .context("SQL Server connection unavailable")?;
    tcp.set_nodelay(true)?;
    let client = tokio::time::timeout(CONNECT_LIMIT, TdsClient::connect(cfg, tcp.compat_write()))
        .await
        .context("SQL Server login timed out")?
        .context("SQL Server login unavailable")?;
    drop(secret);
    Ok(client)
}

async fn tds_rows(
    client: &mut TdsWire,
    sql: &'static str,
    binds: &[&str],
    cap: usize,
) -> Result<Vec<Row>> {
    let mut query = Query::new(sql);
    for value in binds {
        query.bind(*value);
    }
    let mut stream = query
        .query(client)
        .await
        .context("SQL Server metadata unavailable")?;
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        if let QueryItem::Row(row) = item.context("SQL Server metadata unavailable")? {
            ensure!(rows.len() < cap, "SQL Server metadata coverage incomplete");
            rows.push(row);
        }
    }
    Ok(rows)
}

fn tds_text(row: &Row, index: usize) -> Result<String> {
    Ok(row
        .try_get::<&str, _>(index)?
        .context("SQL Server metadata field missing")?
        .to_owned())
}

async fn tds_state(client: &mut TdsWire, scope: &BoundScope) -> Result<NativeState> {
    let (host, port, database, schema, table, credential) =
        exact_scope(scope, DatabaseEngine::SqlServer)?;
    let identity = tds_rows(client,
        "SELECT DB_NAME(), CONVERT(bigint, DB_ID()), CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')), COALESCE(CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')), N'MSSQLSERVER'), CONVERT(varchar(36), r.database_guid), ORIGINAL_LOGIN(), SUSER_SNAME(), CONVERT(nvarchar(32), SERVERPROPERTY('ProductVersion')), CONVERT(varchar(48), CONNECTIONPROPERTY('local_net_address')), CONVERT(int, CONNECTIONPROPERTY('local_tcp_port')) FROM sys.database_recovery_status AS r WHERE r.database_id=DB_ID()",
        &[], 1).await?;
    ensure!(
        identity.len() == 1,
        "SQL Server durable database identity unavailable"
    );
    let row = &identity[0];
    let db = tds_text(row, 0)?;
    let db_id: i64 = row.try_get(1)?.context("SQL Server DB_ID missing")?;
    let machine = tds_text(row, 2)?;
    let instance = tds_text(row, 3)?;
    let database_guid = tds_text(row, 4)?;
    let original_login = tds_text(row, 5)?;
    let effective_login = tds_text(row, 6)?;
    let version = tds_text(row, 7)?;
    let local_ip = tds_text(row, 8)?;
    let local_port: i32 = row
        .try_get(9)?
        .context("SQL Server connection port missing")?;
    ensure!(
        db == database
            && db_id > 0
            && !machine.is_empty()
            && !instance.is_empty()
            && uuid::Uuid::parse_str(&database_guid).is_ok()
            && original_login == credential.principal
            && effective_login == original_login
            && local_ip == host
            && local_port == i32::from(port),
        "SQL Server physical connection or principal differs"
    );
    let object = tds_rows(client,
        "SELECT CONVERT(bigint,s.schema_id), CONVERT(bigint,t.object_id), CONVERT(nvarchar(2),t.type), CONVERT(bit,HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','CONNECT')), CONVERT(bit,HAS_PERMS_BY_NAME(QUOTENAME(@P1),'SCHEMA','SELECT')), CONVERT(bit,HAS_PERMS_BY_NAME(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'OBJECT','ALTER')) FROM sys.schemas s JOIN sys.tables t ON t.schema_id=s.schema_id WHERE s.name=@P1 AND t.name=@P2",
        &[schema, table], 1).await?;
    ensure!(object.len() == 1, "SQL Server base table unavailable");
    let row = &object[0];
    let schema_id: i64 = row.try_get(0)?.context("Schema ID unavailable")?;
    let object_id: i64 = row.try_get(1)?.context("Object ID unavailable")?;
    let kind = tds_text(row, 2)?;
    let grants = (3..=5)
        .map(|i| -> Result<bool> {
            row.try_get::<bool, _>(i)?
                .context("SQL Server grant unavailable")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        schema_id > 0 && object_id > 0 && kind == "U",
        "SQL Server base object identity invalid"
    );
    let columns = tds_rows(client,
        "SELECT TOP (21) CONVERT(int,c.column_id), c.name, ty.name, CONVERT(bit,CASE WHEN c.is_computed=0 AND c.is_identity=0 AND c.encryption_type IS NULL AND c.is_sparse=0 AND c.is_filestream=0 AND c.generated_always_type=0 THEN 1 ELSE 0 END) FROM sys.columns c JOIN sys.types ty ON ty.user_type_id=c.user_type_id WHERE c.object_id=OBJECT_ID(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'U') ORDER BY c.column_id",
        &[schema, table], MAX_ACTION_COLUMNS + 1).await?;
    ensure!(
        !columns.is_empty() && columns.len() <= MAX_ACTION_COLUMNS,
        "SQL Server column coverage incomplete"
    );
    let columns = columns
        .iter()
        .map(|r| -> Result<NativeColumn> {
            let id: i32 = r.try_get(0)?.context("Column ID missing")?;
            let name = tds_text(r, 1)?;
            let data_type = tds_text(r, 2)?;
            let plain: bool = r.try_get(3)?.context("Column shape missing")?;
            ensure!(
                id > 0 && name.len() <= 128 && data_type.len() <= 128,
                "SQL Server column invalid"
            );
            Ok(NativeColumn {
                id: id as u32,
                name,
                data_type,
                plain,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let indexes = tds_rows(client,
        "SELECT TOP (21) CONVERT(bigint,i.index_id), i.name, CONCAT(i.type_desc,':',i.is_unique,':',i.has_filter,':',i.is_disabled,':',i.is_hypothetical,':',i.fill_factor), CONVERT(bit,CASE WHEN i.is_disabled=0 AND i.is_hypothetical=0 THEN 1 ELSE 0 END), CONVERT(nvarchar(256),ep.value) FROM sys.indexes i LEFT JOIN sys.extended_properties ep ON ep.class=7 AND ep.major_id=i.object_id AND ep.minor_id=i.index_id AND ep.name=N'Relayne.CreatedByRunV1' WHERE i.object_id=OBJECT_ID(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'U') AND i.name IS NOT NULL ORDER BY i.index_id",
        &[schema, table], MAX_ACTION_INDEXES + 1).await?;
    ensure!(
        indexes.len() <= MAX_ACTION_INDEXES,
        "SQL Server index coverage incomplete"
    );
    let mut index_state = Vec::with_capacity(indexes.len());
    for row in &indexes {
        let id: i64 = row.try_get(0)?.context("Index ID missing")?;
        let name = tds_text(row, 1)?;
        let mut definition = tds_text(row, 2)?;
        let keys = tds_rows(client,
            "SELECT TOP (33) c.name, CONVERT(bit,ic.is_descending_key), CONVERT(int,ic.key_ordinal), CONVERT(bit,ic.is_included_column) FROM sys.index_columns ic JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id WHERE ic.object_id=OBJECT_ID(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'U') AND ic.index_id=(SELECT i.index_id FROM sys.indexes i WHERE i.object_id=OBJECT_ID(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'U') AND i.name=@P3) ORDER BY ic.index_column_id",
            &[schema, table, &name], 33).await?;
        ensure!(keys.len() <= 32, "SQL Server index key coverage incomplete");
        for key in keys {
            definition.push_str(&format!(
                ":{}:{}:{}:{}",
                tds_text(&key, 0)?,
                key.try_get::<bool, _>(1)?
                    .context("Index direction missing")?,
                key.try_get::<i32, _>(2)?.context("Index ordinal missing")?,
                key.try_get::<bool, _>(3)?
                    .context("Index inclusion missing")?
            ));
        }
        ensure!(
            id > 0 && name.len() <= 128 && definition.len() <= 4096,
            "SQL Server index definition incomplete"
        );
        index_state.push(NativeIndex {
            id: id as u64,
            name,
            definition,
            valid: row.try_get::<bool, _>(3)?.context("Index state missing")?,
            ownership: row.try_get::<&str, _>(4)?.map(str::to_owned),
        });
    }
    let stats = tds_rows(client,
        "SELECT TOP (21) CONVERT(bigint,st.stats_id), st.name, CONVERT(bigint,sp.rows), CONVERT(bigint,sp.modification_counter), CONVERT(nvarchar(48),sp.last_updated,126) FROM sys.stats st OUTER APPLY sys.dm_db_stats_properties(st.object_id,st.stats_id) sp WHERE st.object_id=OBJECT_ID(QUOTENAME(@P1)+'.'+QUOTENAME(@P2),'U') ORDER BY st.stats_id",
        &[schema, table], 21).await?;
    ensure!(
        stats.len() <= 20,
        "SQL Server statistics coverage incomplete"
    );
    let statistics = digest(
        b"relayne-helper-tds-stats-v1",
        &stats
            .iter()
            .map(|r| -> Result<_> {
                Ok((
                    r.try_get::<i64, _>(0)?,
                    tds_text(r, 1)?,
                    r.try_get::<i64, _>(2)?,
                    r.try_get::<i64, _>(3)?,
                    r.try_get::<&str, _>(4)?.map(str::to_owned),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    Ok(NativeState {
        engine: SqlEngine::SqlServer,
        physical_instance: format!("{machine}/{instance}/{database_guid}"),
        database: db,
        database_id: db_id as u64,
        schema: schema.to_owned(),
        schema_id: schema_id as u64,
        table: table.to_owned(),
        object_id: object_id as u64,
        principal: original_login,
        version,
        columns,
        indexes: index_state,
        statistics,
        grants,
        configuration: vec![format!("{local_ip}:{local_port}")],
    })
}

async fn tds_state_for_change(
    scope: &BoundScope,
    cancel: CancellationToken,
) -> Result<NativeState> {
    ensure!(!cancel.is_cancelled(), "SQL Server preflight canceled");
    let mut client = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("SQL Server preflight canceled"),
        result = tds_connection(scope) => result?,
    };
    tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("SQL Server preflight canceled"),
        result = tokio::time::timeout(CONNECT_LIMIT, tds_state(&mut client, scope)) =>
            result.context("SQL Server metadata timed out")?,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeActionState {
    Verified,
    Failed,
    OutcomeUnknown,
    NeedsIntervention,
}

/// A sealed report of an actual native attempt. No public success constructor.
#[derive(Clone)]
pub(crate) struct NativeActionIdentity {
    run_id: uuid::Uuid,
    case_id: uuid::Uuid,
    approval_id: uuid::Uuid,
    consume_id: uuid::Uuid,
    binding_fingerprint: String,
    scope_sha256: String,
    action_sha256: String,
}

impl NativeActionIdentity {
    pub(crate) fn from_permit(permit: &DispatchPermit) -> Result<Self> {
        Ok(Self {
            run_id: permit.binding().run_id,
            case_id: permit.binding().case_id,
            approval_id: permit.receipt().approval_id,
            consume_id: permit.receipt().consume_id,
            binding_fingerprint: permit.binding().fingerprint()?,
            scope_sha256: permit.binding().scope_sha256.clone(),
            action_sha256: digest(b"relayne-helper-sql-action-v1", &permit.binding().action)?,
        })
    }

    pub(crate) fn run_id(&self) -> uuid::Uuid {
        self.run_id
    }
    pub(crate) fn case_id(&self) -> uuid::Uuid {
        self.case_id
    }
    pub(crate) fn approval_id(&self) -> uuid::Uuid {
        self.approval_id
    }
    pub(crate) fn consume_id(&self) -> uuid::Uuid {
        self.consume_id
    }
    pub(crate) fn binding_fingerprint(&self) -> &str {
        &self.binding_fingerprint
    }
    pub(crate) fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }
    pub(crate) fn action_sha256(&self) -> &str {
        &self.action_sha256
    }
}

pub struct NativeActionProof {
    identity: NativeActionIdentity,
    state: NativeActionState,
    before_sha256: String,
    after_sha256: Option<String>,
    created_index_id: Option<u64>,
    created_index_definition_sha256: Option<String>,
    ownership_marker_sha256: Option<String>,
    ownership_marker: Option<String>,
}

impl NativeActionProof {
    #[cfg(test)]
    pub(crate) fn test_verified_from_permit(
        permit: &DispatchPermit,
        before_sha256: String,
        after_sha256: String,
    ) -> Result<Self> {
        Ok(Self {
            identity: NativeActionIdentity::from_permit(permit)?,
            state: NativeActionState::Verified,
            before_sha256,
            after_sha256: Some(after_sha256),
            created_index_id: None,
            created_index_definition_sha256: None,
            ownership_marker_sha256: None,
            ownership_marker: None,
        })
    }

    pub(crate) fn needs_intervention(&mut self) {
        if self.state == NativeActionState::Verified {
            self.state = NativeActionState::NeedsIntervention;
        }
    }
    /// A dispatch intent exists, but the executor could not establish that no
    /// mutation was sent. Preserve the uncertainty rather than retrying SQL.
    pub(crate) fn uncertain(identity: NativeActionIdentity, before_sha256: String) -> Self {
        Self {
            identity,
            state: NativeActionState::OutcomeUnknown,
            before_sha256,
            after_sha256: None,
            created_index_id: None,
            created_index_definition_sha256: None,
            ownership_marker_sha256: None,
            ownership_marker: None,
        }
    }
    pub(crate) fn run_id(&self) -> uuid::Uuid {
        self.identity.run_id
    }
    pub(crate) fn identity(&self) -> &NativeActionIdentity {
        &self.identity
    }
    pub(crate) fn state(&self) -> NativeActionState {
        self.state
    }
    pub(crate) fn before_sha256(&self) -> &str {
        &self.before_sha256
    }
    pub(crate) fn after_sha256(&self) -> Option<&str> {
        self.after_sha256.as_deref()
    }
    pub(crate) fn created_index_id(&self) -> Option<u64> {
        self.created_index_id
    }
    pub(crate) fn created_index_definition_sha256(&self) -> Option<&str> {
        self.created_index_definition_sha256.as_deref()
    }
    pub(crate) fn ownership_marker_sha256(&self) -> Option<&str> {
        self.ownership_marker_sha256.as_deref()
    }
    pub(crate) fn ownership_marker(&self) -> Option<&str> {
        self.ownership_marker.as_deref()
    }
    pub(crate) fn intent_state(&self) -> IntentState {
        match self.state {
            NativeActionState::Verified => IntentState::Verified,
            NativeActionState::Failed => IntentState::Failed,
            NativeActionState::OutcomeUnknown => IntentState::OutcomeUnknown,
            NativeActionState::NeedsIntervention => IntentState::NeedsIntervention,
        }
    }
}

fn ownership_marker(permit: &DispatchPermit, action_sha256: &str) -> Result<String> {
    let binding = permit.binding();
    let nonce = uuid::Uuid::new_v4();
    let content = (
        binding.run_id,
        permit.receipt().approval_id,
        permit.receipt().consume_id,
        &binding.scope_sha256,
        action_sha256,
        nonce,
    );
    Ok(format!(
        "Relayne.CreatedByRunV1:{}",
        digest(b"relayne-helper-created-index-v1", &content)?
    ))
}

fn index_postcondition(
    state: &NativeState,
    action: &SqlAction,
    marker: &str,
) -> Result<(u64, String, String)> {
    let index = match action {
        SqlAction::PostgresCreateIndex { index, .. }
        | SqlAction::SqlServerCreateIndex { index, .. } => index,
        _ => anyhow::bail!("Index postcondition on statistics action"),
    };
    let found = state
        .indexes
        .iter()
        .filter(|i| i.name == *index)
        .collect::<Vec<_>>();
    ensure!(
        found.len() == 1 && found[0].valid && found[0].ownership.as_deref() == Some(marker),
        "Created index identity/ownership postcondition failed"
    );
    Ok((
        found[0].id,
        digest(
            b"relayne-helper-created-index-definition-v1",
            &found[0].definition,
        )?,
        digest(b"relayne-helper-created-index-marker-v1", &marker)?,
    ))
}

fn failed_native_outcome(commit_attempted: bool, rollback_acknowledged: bool) -> NativeActionState {
    if !commit_attempted && rollback_acknowledged {
        NativeActionState::Failed
    } else {
        NativeActionState::OutcomeUnknown
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum NativeFaultPhase {
    PgMarker = 1,
    PgCommittedReadback = 2,
    TdsMarker = 3,
    TdsCommittedReadback = 4,
}

#[cfg(test)]
static ARMED_NATIVE_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
fn arm_guest_native_fault(phase: NativeFaultPhase) {
    ARMED_NATIVE_FAULT.store(phase as u8, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn inject_guest_native_fault(phase: NativeFaultPhase) -> Result<()> {
    if std::env::var("USERNAME").ok().as_deref() == Some("WDAGUtilityAccount")
        && ARMED_NATIVE_FAULT
            .compare_exchange(
                phase as u8,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    {
        anyhow::bail!("Injected native transaction fault");
    }
    Ok(())
}

async fn pg_execute(
    scope: &BoundScope,
    action: &SqlAction,
    prepared: &PreparedSqlChange,
    before: &NativePreflight,
    permit: &DispatchPermit,
    identity: NativeActionIdentity,
    cancel: CancellationToken,
) -> NativeActionProof {
    let mut proof = NativeActionProof {
        identity,
        state: NativeActionState::OutcomeUnknown,
        before_sha256: before.before_sha256.clone(),
        after_sha256: None,
        created_index_id: None,
        created_index_definition_sha256: None,
        ownership_marker_sha256: None,
        ownership_marker: None,
    };
    #[cfg(test)]
    if permit.binding().run_kind == RunKind::Production {
        PRODUCTION_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let connection = pg_connection(scope).await;
    #[cfg(test)]
    if connection.is_ok() && permit.binding().run_kind == RunKind::Production {
        PRODUCTION_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let Ok((client, driver, _)) = connection else {
        proof.state = NativeActionState::Failed;
        return proof;
    };
    let mut commit_attempted = false;
    let transaction = async {
        client.batch_execute("BEGIN").await?;
        client
            .batch_execute("SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s'")
            .await?;
        let fresh = pg_state(&client, scope).await?;
        ensure!(
            digest(b"relayne-helper-native-sql-before-v1", &fresh)? == before.before_sha256,
            "Native before-state changed before SQL transaction"
        );
        let marker = match &prepared.operation {
            PreparedOperation::PgCreate {
                statement,
                schema,
                index,
            } => {
                #[cfg(test)]
                if permit.binding().run_kind == RunKind::Production {
                    PRODUCTION_PG_MUTATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                client.batch_execute(statement).await?;
                #[cfg(test)]
                inject_guest_native_fault(NativeFaultPhase::PgMarker)?;
                let marker = ownership_marker(permit, &prepared.action_sha256)?;
                let literal = marker.replace('\'', "''");
                client
                    .batch_execute(&format!(
                        "COMMENT ON INDEX {}.{} IS '{}'",
                        pg_ident(schema),
                        pg_ident(index),
                        literal
                    ))
                    .await?;
                Some(marker)
            }
            PreparedOperation::PgAnalyze { statement } => {
                client.batch_execute(statement).await?;
                None
            }
            _ => anyhow::bail!("Prepared PostgreSQL operation mismatch"),
        };
        let staged_after = pg_state(&client, scope).await?;
        ensure!(
            staged_after.physical_instance == before.state.physical_instance
                && staged_after.database_id == before.state.database_id
                && staged_after.object_id == before.state.object_id,
            "PostgreSQL target changed within transaction"
        );
        let index_proof = if let Some(marker) = &marker {
            Some(index_postcondition(&staged_after, action, marker)?)
        } else {
            None
        };
        commit_attempted = true;
        client.batch_execute("COMMIT").await?;
        #[cfg(test)]
        inject_guest_native_fault(NativeFaultPhase::PgCommittedReadback)?;
        let committed_after = pg_state(&client, scope).await?;
        ensure!(
            committed_after.physical_instance == before.state.physical_instance
                && committed_after.object_id == before.state.object_id,
            "PostgreSQL committed readback target changed"
        );
        if let Some(marker) = &marker {
            let readback = index_postcondition(&committed_after, action, marker)?;
            ensure!(
                Some(&readback) == index_proof.as_ref(),
                "PostgreSQL index readback changed"
            );
        }
        Ok::<_, anyhow::Error>((committed_after, index_proof, marker))
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => Err(anyhow::anyhow!("SQL action canceled")),
        result = tokio::time::timeout(ACTION_LIMIT, transaction) =>
            result.unwrap_or_else(|_| Err(anyhow::anyhow!("SQL action deadline elapsed"))),
    };
    match result {
        Ok((after, index, marker)) => {
            proof.state = NativeActionState::Verified;
            proof.ownership_marker = marker;
            proof.after_sha256 = digest(b"relayne-helper-native-sql-after-v1", &after).ok();
            if let Some((id, definition, marker)) = index {
                proof.created_index_id = Some(id);
                proof.created_index_definition_sha256 = Some(definition);
                proof.ownership_marker_sha256 = Some(marker);
            }
        }
        Err(_) => {
            // A rollback response proves only uncommitted effects were removed.
            // If COMMIT may have been sent, readback/reconciliation is required.
            let rollback_acknowledged = !commit_attempted
                && tokio::time::timeout(Duration::from_secs(2), client.batch_execute("ROLLBACK"))
                    .await
                    .ok()
                    .is_some_and(|r| r.is_ok());
            proof.state = failed_native_outcome(commit_attempted, rollback_acknowledged);
        }
    }
    driver.abort();
    proof
}

async fn tds_execute_sql(client: &mut TdsWire, sql: &str) -> Result<()> {
    let mut stream = client
        .simple_query(sql)
        .await
        .context("SQL Server action unavailable")?;
    while let Some(item) = stream.next().await {
        item.context("SQL Server action unavailable")?;
    }
    Ok(())
}

async fn tds_execute(
    scope: &BoundScope,
    action: &SqlAction,
    prepared: &PreparedSqlChange,
    before: &NativePreflight,
    permit: &DispatchPermit,
    identity: NativeActionIdentity,
    cancel: CancellationToken,
) -> NativeActionProof {
    let mut proof = NativeActionProof {
        identity,
        state: NativeActionState::OutcomeUnknown,
        before_sha256: before.before_sha256.clone(),
        after_sha256: None,
        created_index_id: None,
        created_index_definition_sha256: None,
        ownership_marker_sha256: None,
        ownership_marker: None,
    };
    let Ok(mut client) = tds_connection(scope).await else {
        proof.state = NativeActionState::Failed;
        return proof;
    };
    let mut commit_attempted = false;
    let operation = async {
        tds_execute_sql(
            &mut client,
            "SET XACT_ABORT ON; SET LOCK_TIMEOUT 5000; BEGIN TRAN",
        )
        .await?;
        let fresh = tds_state(&mut client, scope).await?;
        ensure!(
            digest(b"relayne-helper-native-sql-before-v1", &fresh)? == before.before_sha256,
            "SQL Server before-state changed before transaction"
        );
        let marker = match &prepared.operation {
            PreparedOperation::TdsCreate {
                statement,
                schema,
                table,
                index,
            } => {
                tds_execute_sql(&mut client, statement).await?;
                #[cfg(test)]
                inject_guest_native_fault(NativeFaultPhase::TdsMarker)?;
                let marker = ownership_marker(permit, &prepared.action_sha256)?;
                let mut q = Query::new(
                    "EXEC sys.sp_addextendedproperty @name=N'Relayne.CreatedByRunV1', @value=@P1, @level0type=N'SCHEMA', @level0name=@P2, @level1type=N'TABLE', @level1name=@P3, @level2type=N'INDEX', @level2name=@P4",
                );
                q.bind(marker.as_str());
                q.bind(schema.as_str());
                q.bind(table.as_str());
                q.bind(index.as_str());
                let mut stream = q.query(&mut client).await?;
                while let Some(item) = stream.next().await {
                    item?;
                }
                Some(marker)
            }
            PreparedOperation::TdsUpdate { statement } => {
                tds_execute_sql(&mut client, statement).await?;
                None
            }
            _ => anyhow::bail!("Prepared SQL Server operation mismatch"),
        };
        let staged_after = tds_state(&mut client, scope).await?;
        ensure!(
            staged_after.physical_instance == before.state.physical_instance
                && staged_after.object_id == before.state.object_id,
            "SQL Server target changed"
        );
        let index_proof = if let Some(marker) = &marker {
            Some(index_postcondition(&staged_after, action, marker)?)
        } else {
            None
        };
        commit_attempted = true;
        tds_execute_sql(&mut client, "COMMIT TRAN").await?;
        #[cfg(test)]
        inject_guest_native_fault(NativeFaultPhase::TdsCommittedReadback)?;
        let committed_after = tds_state(&mut client, scope).await?;
        ensure!(
            committed_after.physical_instance == before.state.physical_instance
                && committed_after.object_id == before.state.object_id,
            "SQL Server committed target changed"
        );
        if let Some(marker) = &marker {
            ensure!(
                Some(&index_postcondition(&committed_after, action, marker)?)
                    == index_proof.as_ref(),
                "SQL Server index readback changed"
            );
        }
        Ok::<_, anyhow::Error>((committed_after, index_proof, marker))
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => Err(anyhow::anyhow!("SQL action canceled")),
        result = tokio::time::timeout(ACTION_LIMIT, operation) =>
            result.unwrap_or_else(|_| Err(anyhow::anyhow!("SQL action deadline elapsed"))),
    };
    match result {
        Ok((after, index, marker)) => {
            proof.state = NativeActionState::Verified;
            proof.ownership_marker = marker;
            proof.after_sha256 = digest(b"relayne-helper-native-sql-after-v1", &after).ok();
            if let Some((id, definition, marker)) = index {
                proof.created_index_id = Some(id);
                proof.created_index_definition_sha256 = Some(definition);
                proof.ownership_marker_sha256 = Some(marker);
            }
        }
        Err(_) => {
            let rollback_acknowledged = !commit_attempted
                && tokio::time::timeout(
                    Duration::from_secs(2),
                    tds_execute_sql(&mut client, "ROLLBACK TRAN"),
                )
                .await
                .ok()
                .is_some_and(|r| r.is_ok());
            proof.state = failed_native_outcome(commit_attempted, rollback_acknowledged);
        }
    }
    proof
}

/// Rehearsal-only entry. The staged action is re-derived from native target
/// metadata and never inherits the production object's OID.
pub(crate) async fn execute_sql_change(
    permit: DispatchPermit,
    intent_id: IntentId,
    journal_path: &Path,
    stage_scope: &BoundScope,
    trial: &NativeTrialTarget,
    cancel: CancellationToken,
) -> Result<NativeActionProof> {
    ActionJournal::require_durable_started(journal_path, intent_id, &permit)?;
    ensure!(
        permit.binding().run_kind == RunKind::Rehearsal
            && matches!(
                permit.binding().proof,
                crate::helper_approval::ActionProof::StagingReviewProof { .. }
            ),
        "Production or non-staging permit cannot run rehearsal"
    );
    ensure!(
        trial.preflight.observed_at <= Utc::now()
            && Utc::now().signed_duration_since(trial.preflight.observed_at)
                < chrono::Duration::seconds(120),
        "Staging metadata expired"
    );
    ensure!(
        trial.preflight.credential_scope_sha256 == stage_scope.credential_scope_digest()?,
        "Staging credential changed"
    );
    let prepared = prepare_sql_change(&trial.action, stage_scope, &trial.metadata)?;
    let identity = NativeActionIdentity::from_permit(&permit)?;
    let proof = match trial.action.object().engine {
        SqlEngine::Postgres => {
            pg_execute(
                stage_scope,
                &trial.action,
                &prepared,
                &trial.preflight,
                &permit,
                identity,
                cancel,
            )
            .await
        }
        SqlEngine::SqlServer => {
            tds_execute(
                stage_scope,
                &trial.action,
                &prepared,
                &trial.preflight,
                &permit,
                identity,
                cancel,
            )
            .await
        }
    };
    ensure!(
        proof.run_id() == permit.binding().run_id,
        "Native run identity changed"
    );
    Ok(proof)
}

/// The production path uses the same closed builder and transactional native
/// executors as rehearsal. Its caller must have obtained a started intent from
/// the shared final case/review gate; no SQL text or target is accepted here.
pub(crate) async fn execute_sql_production(
    permit: &DispatchPermit,
    intent_id: IntentId,
    journal_path: &Path,
    scope: &BoundScope,
    metadata: &VerifiedSqlMetadata,
    before: &NativePreflight,
    production_physical_sha256: &str,
    cancel: CancellationToken,
) -> Result<NativeActionProof> {
    ActionJournal::require_durable_started(journal_path, intent_id, permit)?;
    let binding = permit.binding();
    ensure!(
        binding.run_kind == RunKind::Production
            && matches!(
                binding.proof,
                crate::helper_approval::ActionProof::SqlRehearsalReceipt { .. }
            ),
        "Only protected SQL rehearsal receipt can authorize production"
    );
    ensure!(
        before.observed_at <= Utc::now()
            && Utc::now().signed_duration_since(before.observed_at)
                < chrono::Duration::seconds(120),
        "Production native before-state expired"
    );
    ensure!(
        scope.digest()? == binding.scope_sha256
            && scope.credential_scope_digest()? == binding.credential_scope_sha256
            && before.credential_scope_sha256 == binding.credential_scope_sha256
            && before.metadata_sha256 == binding.metadata_sha256
            && before.before_sha256 == binding.before_sha256
            && before.physical_digest()? == production_physical_sha256,
        "Production target, credential, metadata, or before-state changed"
    );
    let prepared = prepare_sql_change(&binding.action, scope, metadata)?;
    let identity = NativeActionIdentity::from_permit(permit)?;
    let proof = match binding.action.object().engine {
        SqlEngine::Postgres => {
            pg_execute(
                scope,
                &binding.action,
                &prepared,
                before,
                permit,
                identity,
                cancel,
            )
            .await
        }
        SqlEngine::SqlServer => {
            tds_execute(
                scope,
                &binding.action,
                &prepared,
                before,
                permit,
                identity,
                cancel,
            )
            .await
        }
    };
    ensure!(
        proof.run_id() == binding.run_id,
        "Production native run identity changed"
    );
    Ok(proof)
}

fn exact_original_index(
    state: &NativeState,
    receipt: &super::restoration::ProductionReceipt,
) -> Result<()> {
    let observed = state
        .indexes
        .iter()
        .map(|index| super::restoration::ObservedIndex {
            id: index.id,
            name: &index.name,
            definition: &index.definition,
            valid: index.valid,
            marker: index.ownership.as_deref(),
        })
        .collect::<Vec<_>>();
    super::restoration::verify_original_index(
        receipt,
        &state.physical_digest()?,
        state.database_id,
        state.object_id,
        &state.restoration_guard_digest()?,
        &observed,
    )
}

fn original_index_absent(
    state: &NativeState,
    receipt: &super::restoration::ProductionReceipt,
) -> Result<()> {
    let index = receipt
        .index()
        .ok_or_else(|| anyhow::anyhow!("Index restoration proof missing"))?;
    ensure!(
        state.physical_digest()? == receipt.physical_sha256()
            && state.object_id == receipt.object_id()
            && state.restoration_guard_digest()? == receipt.guard_sha256()
            && state
                .indexes
                .iter()
                .all(|candidate| candidate.id != index.id && candidate.name != index.name),
        "Restored original index readback incomplete"
    );
    Ok(())
}

/// Called only after a durable one-shot restoration intent. Every native
/// failure, including an ambiguous COMMIT, is intervention and never retried.
pub(crate) async fn restore_exact_production_index(
    receipt: &super::restoration::ProductionReceipt,
    cancel: CancellationToken,
) -> super::restoration::RestorationOutcome {
    use super::restoration::RestorationOutcome;
    if receipt.validate().is_err() || receipt.index().is_none() || cancel.is_cancelled() {
        return RestorationOutcome::NeedsIntervention;
    }
    #[cfg(test)]
    {
        RESTORE_TEST_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let delay = RESTORE_TEST_DELAY_MS.load(std::sync::atomic::Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
    let scope = receipt.scope();
    let action = receipt.action();
    let result: Result<()> = match action {
        SqlAction::PostgresCreateIndex { object, index, .. } => {
            async {
                #[cfg(test)]
                RESTORATION_PG_CONTACTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (client, driver, _) = pg_connection(scope).await?;
                #[cfg(test)]
                RESTORATION_PG_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let transaction = async {
                    client.batch_execute("BEGIN").await?;
                    client
                        .batch_execute(
                            "SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s'",
                        )
                        .await?;
                    let fresh = pg_state(&client, scope).await?;
                    exact_original_index(&fresh, receipt)?;
                    #[cfg(test)]
                    RESTORATION_PG_DROPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    client
                        .batch_execute(&format!(
                            "DROP INDEX {}.{}",
                            pg_ident(&object.schema),
                            pg_ident(index)
                        ))
                        .await?;
                    let after = pg_state(&client, scope).await?;
                    original_index_absent(&after, receipt)?;
                    client.batch_execute("COMMIT").await?;
                    let committed = pg_state(&client, scope).await?;
                    original_index_absent(&committed, receipt)
                };
                let outcome = tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Restoration canceled"),
                    value = tokio::time::timeout(ACTION_LIMIT, transaction) =>
                        value.context("Restoration deadline elapsed")?,
                };
                driver.abort();
                outcome
            }
            .await
        }
        SqlAction::SqlServerCreateIndex { object, index, .. } => {
            async {
                let mut client = tds_connection(scope).await?;
                let transaction = async {
                    tds_execute_sql(&mut client, "SET LOCK_TIMEOUT 5000; BEGIN TRAN").await?;
                    let fresh = tds_state(&mut client, scope).await?;
                    exact_original_index(&fresh, receipt)?;
                    tds_execute_sql(
                        &mut client,
                        &format!(
                            "DROP INDEX {} ON {}.{}",
                            tds_ident(index),
                            tds_ident(&object.schema),
                            tds_ident(&object.table)
                        ),
                    )
                    .await?;
                    let after = tds_state(&mut client, scope).await?;
                    original_index_absent(&after, receipt)?;
                    tds_execute_sql(&mut client, "COMMIT TRAN").await?;
                    let committed = tds_state(&mut client, scope).await?;
                    original_index_absent(&committed, receipt)
                };
                tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Restoration canceled"),
                    value = tokio::time::timeout(ACTION_LIMIT, transaction) =>
                        value.context("Restoration deadline elapsed")?,
                }
            }
            .await
        }
        _ => Err(anyhow::anyhow!(
            "Statistics cannot be restored to prior state"
        )),
    };
    if result.is_ok() {
        RestorationOutcome::Restored
    } else {
        RestorationOutcome::NeedsIntervention
    }
}

#[cfg(test)]
static READ_ONLY_PG_CONTACTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static READ_ONLY_PG_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PRODUCTION_PG_CONTACTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PRODUCTION_PG_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PRODUCTION_PG_MUTATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RESTORATION_PG_CONTACTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RESTORATION_PG_OPENS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RESTORATION_PG_DROPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct GuestPgBoundaryCounts {
    pub read_only_contacts: usize,
    pub read_only_opens: usize,
    pub production_executor_contacts: usize,
    pub production_executor_opens: usize,
    pub production_mutation_attempts: usize,
    pub restoration_executor_contacts: usize,
    pub restoration_executor_opens: usize,
    pub restoration_drop_attempts: usize,
}

#[cfg(test)]
pub(crate) fn guest_pg_boundary_counts() -> GuestPgBoundaryCounts {
    use std::sync::atomic::Ordering::SeqCst;
    GuestPgBoundaryCounts {
        read_only_contacts: READ_ONLY_PG_CONTACTS.load(SeqCst),
        read_only_opens: READ_ONLY_PG_OPENS.load(SeqCst),
        production_executor_contacts: PRODUCTION_PG_CONTACTS.load(SeqCst),
        production_executor_opens: PRODUCTION_PG_OPENS.load(SeqCst),
        production_mutation_attempts: PRODUCTION_PG_MUTATIONS.load(SeqCst),
        restoration_executor_contacts: RESTORATION_PG_CONTACTS.load(SeqCst),
        restoration_executor_opens: RESTORATION_PG_OPENS.load(SeqCst),
        restoration_drop_attempts: RESTORATION_PG_DROPS.load(SeqCst),
    }
}

#[cfg(test)]
pub(crate) fn reset_guest_pg_boundary_counts() {
    use std::sync::atomic::Ordering::SeqCst;
    READ_ONLY_PG_CONTACTS.store(0, SeqCst);
    READ_ONLY_PG_OPENS.store(0, SeqCst);
    PRODUCTION_PG_CONTACTS.store(0, SeqCst);
    PRODUCTION_PG_OPENS.store(0, SeqCst);
    PRODUCTION_PG_MUTATIONS.store(0, SeqCst);
    RESTORATION_PG_CONTACTS.store(0, SeqCst);
    RESTORATION_PG_OPENS.store(0, SeqCst);
    RESTORATION_PG_DROPS.store(0, SeqCst);
}

#[cfg(test)]
static RESTORE_TEST_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RESTORE_TEST_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn set_restore_test_delay(delay_ms: u64) -> usize {
    RESTORE_TEST_DELAY_MS.store(delay_ms, std::sync::atomic::Ordering::SeqCst);
    RESTORE_TEST_ATTEMPTS.swap(0, std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn restore_test_attempts() -> usize {
    RESTORE_TEST_ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
#[path = "change_tests.rs"]
mod tests;
