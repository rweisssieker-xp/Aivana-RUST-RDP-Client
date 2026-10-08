//! Closed, native database readers. Engines share the normalized observation vocabulary.

pub mod postgres;
pub mod types;

use super::{
    capability::{ProbeAdapter, ProbeFuture, ProbeRequest},
    credentials::SecretResolver,
    scope::{BoundScope, DatabaseEngine},
};
use tokio_util::sync::CancellationToken;

/// Registry entry for the SQL-read capability. Task 7 adds the TDS branch here.
pub struct SqlReadAdapter;

impl ProbeAdapter for SqlReadAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        match &request.scope {
            BoundScope::Database {
                engine: DatabaseEngine::Postgres,
                ..
            } => postgres::PostgresAdapter.collect(request, secrets, cancel),
            _ => Box::pin(async { anyhow::bail!("SQL engine has no native reader") }),
        }
    }
}
