//! Versioned SELECTs for the disposable, attested fixture only.
use crate::helper::scope::{BoundScope, CredentialPurpose, DatabaseEngine};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

pub const FIXTURE_DATABASE: &str = "relayne_helper_acceptance";
pub const FIXTURE_SCHEMA: &str = "fixture";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStatus {
    Pending,
    Fulfilled,
}
impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Fulfilled => "fulfilled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedSelectTemplate {
    CustomerOrders { customer_id: i32 },
    StatusCount { status: OrderStatus },
    OrderSort,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateBind {
    None,
    Integer(i32),
    Status(OrderStatus),
}
#[derive(Clone, Debug)]
pub struct TemplateStatement {
    pub sql: &'static str,
    pub explain_sql: &'static str,
    pub bind: TemplateBind,
    pub fingerprint: String,
    pub object: &'static str,
}
impl ReviewedSelectTemplate {
    /// The executable registry recognizes only these immutable fixture bindings.
    pub fn from_fingerprint(scope: &BoundScope, digest: &str) -> Option<Self> {
        [
            Self::CustomerOrders {
                customer_id: 424242,
            },
            Self::StatusCount {
                status: OrderStatus::Pending,
            },
            Self::OrderSort,
        ]
        .into_iter()
        .find(|template| template.fingerprint(scope).ok().as_deref() == Some(digest))
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::CustomerOrders { .. } => "CustomerOrders/v1",
            Self::StatusCount { .. } => "StatusCount/v1",
            Self::OrderSort => "OrderSort/v1",
        }
    }
    pub fn object(self) -> &'static str {
        match self {
            Self::OrderSort => "spill_events",
            _ => "orders",
        }
    }
    pub fn bind(self) -> TemplateBind {
        match self {
            Self::CustomerOrders { customer_id } => TemplateBind::Integer(customer_id),
            Self::StatusCount { status } => TemplateBind::Status(status),
            Self::OrderSort => TemplateBind::None,
        }
    }
    pub fn fingerprint(self, scope: &BoundScope) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"relayne-reviewed-select-v1\0");
        hash.update(scope.resource_digest()?.as_bytes());
        hash.update(self.label().as_bytes());
        match self.bind() {
            TemplateBind::None => {}
            TemplateBind::Integer(n) => hash.update(n.to_be_bytes()),
            TemplateBind::Status(s) => hash.update(s.as_str().as_bytes()),
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    pub fn reviewed_statement(self, scope: &BoundScope) -> Result<TemplateStatement> {
        scope.validate()?;
        let BoundScope::Database {
            engine,
            database,
            schema,
            object,
            credential,
            ..
        } = scope
        else {
            anyhow::bail!("database scope required")
        };
        ensure!(
            *engine == DatabaseEngine::Postgres,
            "no attested SQL Server fixture; live templates unavailable"
        );
        ensure!(
            database == FIXTURE_DATABASE
                && schema.as_deref() == Some(FIXTURE_SCHEMA)
                && object.as_deref() == Some(self.object()),
            "template object is not the attested same-database fixture"
        );
        ensure!(
            credential
                .as_ref()
                .is_some_and(|c| c.purpose == CredentialPurpose::Read),
            "read credential required"
        );
        let (sql, explain_sql) = match self {
            Self::CustomerOrders { .. } => (
                "SELECT order_id FROM \"fixture\".\"orders\" WHERE customer_id = $1 ORDER BY order_id LIMIT 100",
                "EXPLAIN (FORMAT JSON) SELECT order_id FROM \"fixture\".\"orders\" WHERE customer_id = $1 ORDER BY order_id LIMIT 100",
            ),
            Self::StatusCount { .. } => (
                "SELECT count(*)::bigint FROM \"fixture\".\"orders\" WHERE status = $1",
                "EXPLAIN (FORMAT JSON) SELECT count(*)::bigint FROM \"fixture\".\"orders\" WHERE status = $1",
            ),
            Self::OrderSort => (
                "SELECT event_id FROM \"fixture\".\"spill_events\" ORDER BY payload, event_id LIMIT 100",
                "EXPLAIN (FORMAT JSON) SELECT event_id FROM \"fixture\".\"spill_events\" ORDER BY payload, event_id LIMIT 100",
            ),
        };
        Ok(TemplateStatement {
            sql,
            explain_sql,
            bind: self.bind(),
            fingerprint: self.fingerprint(scope)?,
            object: self.object(),
        })
    }

    /// Closed SQL Server SELECTs are only available against the disposable loopback fixture.
    /// SHOWPLAN mode is established on a separate verified session by sql_server.rs.
    pub fn sql_server_statement(self, scope: &BoundScope) -> Result<TemplateStatement> {
        scope.validate()?;
        let BoundScope::Database {
            target,
            engine: DatabaseEngine::SqlServer,
            database,
            schema,
            object,
            credential,
            ..
        } = scope
        else {
            anyhow::bail!("SQL Server database scope required")
        };
        ensure!(
            target
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            "SQL Server fixture requires literal loopback endpoint"
        );
        ensure!(
            database == FIXTURE_DATABASE
                && schema.as_deref() == Some(FIXTURE_SCHEMA)
                && object.as_deref() == Some(self.object()),
            "SQL Server fixture database/object mismatch"
        );
        ensure!(
            credential
                .as_ref()
                .is_some_and(|c| c.purpose == CredentialPurpose::Read),
            "SQL Server read credential required"
        );
        let sql = match self {
            Self::CustomerOrders { .. } => {
                "SELECT TOP (100) [order_id] FROM [fixture].[orders] WHERE [customer_id] = @P1 ORDER BY [order_id]"
            }
            Self::StatusCount { .. } => {
                "SELECT COUNT_BIG(*) FROM [fixture].[orders] WHERE [status] = @P1"
            }
            Self::OrderSort => {
                "SELECT TOP (100) [event_id] FROM [fixture].[spill_events] ORDER BY [payload], [event_id]"
            }
        };
        Ok(TemplateStatement {
            sql,
            explain_sql: sql,
            bind: self.bind(),
            fingerprint: self.fingerprint(scope)?,
            object: self.object(),
        })
    }

    pub fn expected_columns(self) -> &'static [&'static str] {
        match self {
            Self::OrderSort => &["event_id", "group_id", "payload"],
            _ => &[
                "order_id",
                "customer_id",
                "status",
                "amount",
                "created_at",
                "detail",
            ],
        }
    }
}

pub(crate) struct VerifiedPgSession {
    pub client: tokio_postgres::Client,
    pub metadata_sha256: String,
    pub server_version: i32,
    pub work_mem: String,
    cancel_tls: postgres_native_tls::MakeTlsConnector,
    driver: tokio::task::JoinHandle<()>,
}
impl Drop for VerifiedPgSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub(crate) async fn connect_fixture(
    scope: &BoundScope,
    template: ReviewedSelectTemplate,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<VerifiedPgSession> {
    ensure!(!cancel.is_cancelled(), "collection canceled");
    use crate::helper::credentials::{PersistentSecretResolver, SecretResolver};
    use native_tls::TlsConnector;
    use postgres_native_tls::MakeTlsConnector;
    use std::time::Duration;
    let BoundScope::Database {
        target,
        port,
        database,
        credential: Some(credential),
        ..
    } = scope
    else {
        anyhow::bail!("scoped read credential required")
    };
    ensure!(
        target.host == "127.0.0.1" && *port == 55433 && database == FIXTURE_DATABASE,
        "only the disposable guest fixture is attested for reviewed workloads"
    );
    let resolver = PersistentSecretResolver::new()?;
    let secret = resolver.resolve(credential, CredentialPurpose::Read)?;
    ensure!(
        secret.username() == credential.principal,
        "credential principal changed"
    );
    let tls = MakeTlsConnector::new(TlsConnector::builder().build()?);
    let mut config = tokio_postgres::Config::new();
    config
        .host(&target.host)
        .port(*port)
        .dbname(database)
        .user(&credential.principal)
        .password(secret.password())
        .ssl_mode(tokio_postgres::config::SslMode::Require)
        .connect_timeout(Duration::from_secs(5));
    let (client, connection) = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("collection canceled"),
        result = tokio::time::timeout(Duration::from_secs(5), config.connect(tls.clone())) => result??,
    };
    drop(config);
    drop(secret);
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut session = VerifiedPgSession {
        client,
        driver,
        metadata_sha256: String::new(),
        server_version: 0,
        work_mem: String::new(),
        cancel_tls: tls,
    };
    let row = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("collection canceled"),
        result = tokio::time::timeout(Duration::from_secs(5), session.client.query_one(
            "SELECT current_database()::text, session_user::text, current_user::text, s.ssl, inet_server_addr()::text, inet_server_port()::integer, current_setting('server_version_num')::integer, current_setting('work_mem')::text FROM pg_stat_ssl AS s WHERE s.pid = pg_backend_pid()", &[])) => result??,
    };
    let actual_db: String = row.try_get(0)?;
    let session_user: String = row.try_get(1)?;
    let current_user: String = row.try_get(2)?;
    let tls: bool = row.try_get(3)?;
    let server_ip: Option<String> = row.try_get(4)?;
    let server_port: Option<i32> = row.try_get(5)?;
    session.server_version = row.try_get(6)?;
    session.work_mem = row.try_get(7)?;
    ensure!(
        actual_db == *database
            && session_user == credential.principal
            && current_user == credential.principal
            && tls
            && server_ip.as_deref() == Some("127.0.0.1")
            && server_port == Some(i32::from(*port))
            && session.server_version >= 180000
            && !session.work_mem.is_empty()
            && session.work_mem.len() <= 64,
        "database session identity differs from reviewed fixture"
    );
    // The exact same session observes the base-table OID and every expected plain column.
    // Names/count from an earlier read cannot attest this object's current identity.
    let fixture_schema = FIXTURE_SCHEMA;
    let fixture_object = template.object();
    let metadata_params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] =
        [&fixture_schema, &fixture_object];
    let rows = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("metadata attestation canceled"),
        result = tokio::time::timeout(Duration::from_secs(5), session.client.query(
            "SELECT c.oid::bigint, a.attnum::integer, a.attname::text, format_type(a.atttypid, a.atttypmod)::text, a.attgenerated::text FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace JOIN pg_attribute AS a ON a.attrelid = c.oid WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum LIMIT 16",
            &metadata_params)) => result??,
    };
    let expected: &[(&str, &str)] = match template {
        ReviewedSelectTemplate::OrderSort => &[
            ("event_id", "bigint"),
            ("group_id", "integer"),
            ("payload", "text"),
        ],
        _ => &[
            ("order_id", "bigint"),
            ("customer_id", "integer"),
            ("status", "text"),
            ("amount", "numeric(12,2)"),
            ("created_at", "timestamp with time zone"),
            ("detail", "text"),
        ],
    };
    ensure!(rows.len() == expected.len(), "fixture columns changed");
    let mut hash = Sha256::new();
    hash.update(b"relayne-fixture-object-columns-v1\0");
    hash.update(database.as_bytes());
    hash.update(template.object().as_bytes());
    let mut object_id = None;
    for (i, row) in rows.iter().enumerate() {
        let oid: i64 = row.try_get(0)?;
        let attnum: i32 = row.try_get(1)?;
        let name: String = row.try_get(2)?;
        let data_type: String = row.try_get(3)?;
        let generated: String = row.try_get(4)?;
        ensure!(
            oid > 0
                && attnum > 0
                && name == expected[i].0
                && data_type == expected[i].1
                && generated.is_empty(),
            "fixture column identity changed"
        );
        if let Some(previous) = object_id {
            ensure!(previous == oid, "mixed object identity");
        }
        object_id = Some(oid);
        hash.update(oid.to_be_bytes());
        hash.update(attnum.to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(data_type.as_bytes());
    }
    session.metadata_sha256 = format!("{:x}", hash.finalize());
    Ok(session)
}

impl VerifiedPgSession {
    pub async fn cancel_query(&self) {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.client
                .cancel_token()
                .cancel_query(self.cancel_tls.clone()),
        )
        .await;
    }
}
