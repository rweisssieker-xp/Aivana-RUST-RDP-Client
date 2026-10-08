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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlObservation {
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
            Self::Index { name, method, .. } => field(name) && Self::token(method),
            Self::Statistics { .. } | Self::Permission { .. } => true,
        }
    }
}
