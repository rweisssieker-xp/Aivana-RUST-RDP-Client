//! Typed, bounded projections. No provider errors, SQL text, or arbitrary result columns.
use serde::{Deserialize, Serialize};

pub const MAX_SQL_OBSERVATIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadState {
    Observed,
    Empty,
    Unknown,
    Denied,
    Truncated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlServerIndexKind {
    Clustered,
    Nonclustered,
    Xml,
    Spatial,
    ClusteredColumnstore,
    NonclusteredColumnstore,
    NonclusteredHash,
    Json,
}

impl SqlServerIndexKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clustered => "CLUSTERED",
            Self::Nonclustered => "NONCLUSTERED",
            Self::Xml => "XML",
            Self::Spatial => "SPATIAL",
            Self::ClusteredColumnstore => "CLUSTERED COLUMNSTORE",
            Self::NonclusteredColumnstore => "NONCLUSTERED COLUMNSTORE",
            Self::NonclusteredHash => "NONCLUSTERED HASH",
            Self::Json => "JSON",
        }
    }

    pub fn from_type_desc(value: &str) -> Option<Self> {
        Some(match value {
            "CLUSTERED" => Self::Clustered,
            "NONCLUSTERED" => Self::Nonclustered,
            "XML" => Self::Xml,
            "SPATIAL" => Self::Spatial,
            "CLUSTERED COLUMNSTORE" => Self::ClusteredColumnstore,
            "NONCLUSTERED COLUMNSTORE" => Self::NonclusteredColumnstore,
            "NONCLUSTERED HASH" => Self::NonclusteredHash,
            "JSON" => Self::Json,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlObservation {
    SqlServerIdentity {
        database: String,
        principal: String,
        effective_principal: String,
        database_principal: String,
        product_version: String,
        server_ip: String,
        server_port: u16,
        tls_required: bool,
        server_state_access: Option<bool>,
        server_performance_access: Option<bool>,
    },
    SqlServerRequest {
        session_id: i32,
        state: Option<String>,
        wait_type: Option<String>,
        elapsed_ms: Option<i64>,
    },
    SqlServerWait {
        session_id: i32,
        wait_type: Option<String>,
        wait_ms: Option<i64>,
    },
    SqlServerBlocking {
        waiting_session_id: i32,
        blocking_session_id: i32,
    },
    SqlServerStatistics {
        rows: Option<i64>,
        modification_counter: Option<i64>,
        histogram_steps: Option<i64>,
    },
    SqlServerObject {
        schema: String,
        name: String,
        object_id: u64,
        column_count: u32,
    },
    SqlServerColumn {
        object_id: u64,
        column_id: u32,
        name: String,
        plain: bool,
    },
    SqlServerIndex {
        name: String,
        index_kind: SqlServerIndexKind,
        enabled: bool,
        usage_count: Option<i64>,
    },
    SqlServerPermission {
        database_connect: Option<bool>,
        schema_select: Option<bool>,
        object_select: Option<bool>,
        object_alter: Option<bool>,
        object_control: Option<bool>,
    },
    Identity {
        database: String,
        principal: String,
        version: i32,
        tls: bool,
        server_ip: String,
        server_port: u16,
    },
    Activity {
        pid: i32,
        state: Option<String>,
        wait_kind: Option<String>,
        wait_name: Option<String>,
        age_ms: Option<i64>,
    },
    Blocking {
        waiting_pid: i32,
        blocking_pid: i32,
        blocker_state: Option<String>,
    },
    Object {
        schema: String,
        name: String,
        columns: i32,
        estimated_rows: Option<f64>,
    },
    /// Observed from pg_class in the same read transaction as the column projection.
    PostgresObject {
        schema: String,
        name: String,
        object_id: u64,
        column_count: u32,
    },
    /// Positive pg_attribute.attnum for a non-dropped ordinary table column.
    PostgresColumn {
        object_id: u64,
        column_id: u32,
        name: String,
        plain: bool,
    },
    Index {
        name: String,
        method: String,
        valid: bool,
        scans: Option<i64>,
    },
    Statistics {
        live_rows: Option<i64>,
        dead_rows: Option<i64>,
        analyze_count: Option<i64>,
    },
    Permission {
        database_connect: Option<bool>,
        schema_usage: Option<bool>,
        table_select: Option<bool>,
    },
}

impl SqlObservation {
    pub fn tds_state(value: &str) -> bool {
        matches!(
            value,
            "background" | "running" | "runnable" | "sleeping" | "suspended"
        )
    }
    pub fn pg_state(value: &str) -> bool {
        matches!(
            value,
            "active"
                | "idle"
                | "idle in transaction"
                | "idle in transaction (aborted)"
                | "fastpath function call"
                | "disabled"
        )
    }
    pub fn pg_wait_kind(value: &str) -> bool {
        matches!(
            value,
            "Activity"
                | "BufferPin"
                | "Client"
                | "Extension"
                | "IO"
                | "IPC"
                | "Lock"
                | "LWLock"
                | "Timeout"
        )
    }
    pub fn token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }
    pub fn bounded(&self) -> bool {
        fn field(value: &str) -> bool {
            value.len() <= 256 && !value.chars().any(char::is_control)
        }
        match self {
            Self::SqlServerIdentity {
                database,
                principal,
                effective_principal,
                database_principal,
                product_version,
                server_ip,
                server_port,
                tls_required,
                ..
            } => {
                field(database)
                    && field(principal)
                    && field(effective_principal)
                    && field(database_principal)
                    && Self::version_token(product_version)
                    && server_ip.parse::<std::net::IpAddr>().is_ok()
                    && *server_port > 0
                    && *tls_required
            }
            Self::SqlServerRequest {
                session_id,
                state,
                wait_type,
                elapsed_ms,
            } => {
                *session_id > 0
                    && state.as_deref().is_none_or(Self::tds_state)
                    && wait_type.as_deref().is_none_or(Self::token)
                    && elapsed_ms.is_none_or(|v| v >= 0)
            }
            Self::SqlServerWait {
                session_id,
                wait_type,
                wait_ms,
            } => {
                *session_id > 0
                    && wait_type.as_deref().is_none_or(Self::token)
                    && wait_ms.is_none_or(|v| v >= 0)
            }
            Self::SqlServerBlocking {
                waiting_session_id,
                blocking_session_id,
            } => *waiting_session_id > 0 && *blocking_session_id > 0,
            Self::SqlServerStatistics {
                rows,
                modification_counter,
                histogram_steps,
            } => {
                rows.is_none_or(|v| v >= 0)
                    && modification_counter.is_none_or(|v| v >= 0)
                    && histogram_steps.is_none_or(|v| v >= 0)
            }
            Self::SqlServerObject {
                schema,
                name,
                object_id,
                column_count,
            } => field(schema) && field(name) && *object_id > 0 && *column_count > 0,
            Self::SqlServerColumn {
                object_id,
                column_id,
                name,
                ..
            } => *object_id > 0 && *column_id > 0 && field(name),
            Self::SqlServerIndex {
                name, usage_count, ..
            } => field(name) && usage_count.is_none_or(|value| value >= 0),
            Self::SqlServerPermission { .. } => true,
            Self::Identity {
                database,
                principal,
                server_ip,
                server_port,
                ..
            } => {
                field(database)
                    && field(principal)
                    && server_ip.parse::<std::net::IpAddr>().is_ok()
                    && *server_port > 0
            }
            Self::Activity {
                state,
                wait_kind,
                wait_name,
                ..
            } => {
                state.as_deref().is_none_or(Self::pg_state)
                    && wait_kind.as_deref().is_none_or(Self::pg_wait_kind)
                    && wait_name.as_deref().is_none_or(Self::token)
            }
            Self::Blocking { blocker_state, .. } => {
                blocker_state.as_deref().is_none_or(Self::pg_state)
            }
            Self::Object {
                schema,
                name,
                estimated_rows,
                ..
            } => field(schema) && field(name) && estimated_rows.is_none_or(f64::is_finite),
            Self::PostgresObject {
                schema,
                name,
                object_id,
                column_count,
            } => {
                field(schema)
                    && field(name)
                    && *object_id > 0
                    && *column_count > 0
                    && *column_count <= 64
            }
            Self::PostgresColumn {
                object_id,
                column_id,
                name,
                ..
            } => *object_id > 0 && *column_id > 0 && field(name),
            Self::Index { name, method, .. } => field(name) && Self::token(method),
            Self::Statistics { .. } | Self::Permission { .. } => true,
        }
    }

    pub fn version_token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 32
            && value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    }
}
