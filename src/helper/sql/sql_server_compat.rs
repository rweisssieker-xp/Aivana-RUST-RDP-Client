//! Native, bounded compatibility evidence from one verified TDS connection.

use super::*;
use crate::helper::sql::templates::TemplateStatement;
use serde_json::Value;

const MAX_METADATA_BYTES: usize = 128 * 1024;
const MAX_DATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_FIXTURE_ROWS: i64 = 100_000;

// TOP 21 exposes overflow beyond the declared 20-record metadata bound.
const COLUMNS: &str = "SELECT TOP (21) c.column_id, c.name, ty.name AS type_name, c.max_length, c.precision, c.scale, c.collation_name, c.is_nullable, c.is_computed, c.is_identity FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id=t.schema_id JOIN sys.columns AS c ON c.object_id=t.object_id JOIN sys.types AS ty ON ty.user_type_id=c.user_type_id WHERE s.name=@P1 AND t.name=@P2 ORDER BY c.column_id FOR JSON PATH, INCLUDE_NULL_VALUES";
const SETTINGS: &str = "SELECT TOP (21) @@OPTIONS AS session_options, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS product_version, d.compatibility_level, d.is_auto_create_stats_on, d.is_auto_update_stats_on, d.is_auto_update_stats_async_on, c.name AS configuration_name, CONVERT(nvarchar(128),c.value) AS configuration_value FROM sys.databases AS d CROSS JOIN sys.database_scoped_configurations AS c WHERE d.database_id=DB_ID() ORDER BY c.name FOR JSON PATH, INCLUDE_NULL_VALUES";
const INDEXES: &str = "SELECT TOP (21) i.index_id, i.name, i.type_desc, i.is_unique, i.is_disabled, i.is_hypothetical, i.has_filter, i.filter_definition, (SELECT ic.key_ordinal, ic.index_column_id, ic.is_descending_key, ic.is_included_column, col.name FROM sys.index_columns AS ic JOIN sys.columns AS col ON col.object_id=ic.object_id AND col.column_id=ic.column_id WHERE ic.object_id=i.object_id AND ic.index_id=i.index_id ORDER BY ic.index_column_id FOR JSON PATH) AS column_definition FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id=t.schema_id JOIN sys.indexes AS i ON i.object_id=t.object_id WHERE s.name=@P1 AND t.name=@P2 AND i.name IS NOT NULL ORDER BY i.index_id FOR JSON PATH, INCLUDE_NULL_VALUES";
const STATISTICS: &str = "SELECT TOP (21) st.stats_id, st.name, st.auto_created, st.user_created, st.no_recompute, CONVERT(nvarchar(40),p.last_updated,126) AS last_updated, p.rows, p.rows_sampled, p.steps, p.modification_counter, (SELECT sc.stats_column_id, c.name FROM sys.stats_columns AS sc JOIN sys.columns AS c ON c.object_id=sc.object_id AND c.column_id=sc.column_id WHERE sc.object_id=st.object_id AND sc.stats_id=st.stats_id ORDER BY sc.stats_column_id FOR JSON PATH) AS column_definition FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id=t.schema_id JOIN sys.stats AS st ON st.object_id=t.object_id OUTER APPLY sys.dm_db_stats_properties(st.object_id,st.stats_id) AS p WHERE s.name=@P1 AND t.name=@P2 ORDER BY st.stats_id FOR JSON PATH, INCLUDE_NULL_VALUES";
const ORDER_DATA: &str = "SELECT TOP (100001) order_id, customer_id, status, amount, CONVERT(nvarchar(40),created_at,126) AS created_at, detail FROM [fixture].[orders] ORDER BY order_id FOR JSON PATH, INCLUDE_NULL_VALUES";
const SORT_DATA: &str = "SELECT TOP (100001) event_id, group_id, payload FROM [fixture].[spill_events] ORDER BY event_id FOR JSON PATH, INCLUDE_NULL_VALUES";

async fn json_query(
    session: &mut NativeSession,
    sql: &'static str,
    object: Option<&str>,
    max_bytes: usize,
) -> std::result::Result<String, Failure> {
    let mut query = Query::new(sql);
    if let Some(object) = object {
        query.bind("fixture");
        query.bind(object);
    }
    let mut stream = query
        .query(&mut session.client)
        .await
        .map_err(driver_error)?;
    let mut value = String::new();
    while let Some(item) = stream.next().await {
        if let QueryItem::Row(row) = item.map_err(driver_error)? {
            if row.columns().len() != 1 {
                return Err(Failure::InvalidProjection);
            }
            let chunk = row
                .try_get::<&str, _>(0)
                .map_err(|_| Failure::InvalidProjection)?
                .ok_or(Failure::InvalidProjection)?;
            if value.len().saturating_add(chunk.len()) > max_bytes {
                return Err(Failure::InvalidProjection);
            }
            value.push_str(chunk);
        }
    }
    if value.is_empty() {
        return Err(Failure::InvalidProjection);
    }
    Ok(value)
}

async fn metadata_json(
    session: &mut NativeSession,
    sql: &'static str,
    object: Option<&str>,
    max_rows: usize,
) -> std::result::Result<Vec<Value>, Failure> {
    let text = json_query(session, sql, object, MAX_METADATA_BYTES).await?;
    let Value::Array(rows) =
        serde_json::from_str::<Value>(&text).map_err(|_| Failure::InvalidProjection)?
    else {
        return Err(Failure::InvalidProjection);
    };
    if rows.is_empty() || rows.len() > max_rows || rows.iter().any(|row| !row.is_object()) {
        return Err(Failure::InvalidProjection);
    }
    Ok(rows)
}

async fn fixture_row_count(
    session: &mut NativeSession,
    object: &str,
) -> std::result::Result<i64, Failure> {
    let sql = match object {
        "orders" => "SELECT COUNT_BIG(*) FROM [fixture].[orders]",
        "spill_events" => "SELECT COUNT_BIG(*) FROM [fixture].[spill_events]",
        _ => return Err(Failure::InvalidProjection),
    };
    let mut stream = session
        .client
        .simple_query(sql)
        .await
        .map_err(driver_error)?;
    let mut count = None;
    while let Some(item) = stream.next().await {
        if let QueryItem::Row(row) = item.map_err(driver_error)? {
            if count.is_some() || row.columns().len() != 1 {
                return Err(Failure::InvalidProjection);
            }
            count = row
                .try_get::<i64, _>(0)
                .map_err(|_| Failure::InvalidProjection)?;
        }
    }
    let count = count.ok_or(Failure::InvalidProjection)?;
    if !(1..=MAX_FIXTURE_ROWS).contains(&count) {
        return Err(Failure::InvalidProjection);
    }
    Ok(count)
}

impl NativeSession {
    pub(super) async fn compatibility_snapshot(
        &mut self,
        statement: &TemplateStatement,
    ) -> std::result::Result<String, Failure> {
        let object = statement.object;
        let columns = metadata_json(self, COLUMNS, Some(object), MAX_ROWS).await?;
        let settings = metadata_json(self, SETTINGS, None, MAX_ROWS).await?;
        let indexes = metadata_json(self, INDEXES, Some(object), MAX_ROWS).await?;
        let statistics = metadata_json(self, STATISTICS, Some(object), MAX_ROWS).await?;
        // A null statistics property means the state was not observable.
        if statistics.iter().any(|row| {
            row.get("rows").is_none_or(Value::is_null)
                || row.get("modification_counter").is_none_or(Value::is_null)
        }) {
            return Err(Failure::InvalidProjection);
        }
        let expected_count = fixture_row_count(self, object).await?;
        let data_sql = match object {
            "orders" => ORDER_DATA,
            "spill_events" => SORT_DATA,
            _ => return Err(Failure::InvalidProjection),
        };
        let data = json_query(self, data_sql, None, MAX_DATA_BYTES).await?;
        let Value::Array(data_rows) =
            serde_json::from_str::<Value>(&data).map_err(|_| Failure::InvalidProjection)?
        else {
            return Err(Failure::InvalidProjection);
        };
        if data_rows.len() as i64 != expected_count {
            return Err(Failure::InvalidProjection);
        }

        use super::plan::PlanSession;
        self.showplan(true).await?;
        let plan = self.explain(statement).await;
        // A failed cleanup poisons this session and therefore the snapshot.
        let cleanup = self.showplan(false).await;
        let plan = plan?;
        cleanup?;

        let mut hash = Sha256::new();
        hash.update(b"relayne-helper-native-tds-compatibility-v1\0");
        for value in [
            serde_json::to_vec(&columns).map_err(|_| Failure::InvalidProjection)?,
            serde_json::to_vec(&settings).map_err(|_| Failure::InvalidProjection)?,
            serde_json::to_vec(&indexes).map_err(|_| Failure::InvalidProjection)?,
            serde_json::to_vec(&statistics).map_err(|_| Failure::InvalidProjection)?,
            data.into_bytes(),
            plan,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}
