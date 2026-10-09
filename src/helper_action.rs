//! Portable, inert action vocabulary shared with the team binary.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub type Digest = String;
pub const SQL_ACTION_VERSION: u16 = 1;

pub fn valid_digest(d: &str) -> bool {
    d.len() == 64
        && d.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.chars().any(char::is_control)
        && !s.contains('.')
        && !s.contains('\0')
}

fn new_index_identifier(s: &str, max: usize) -> bool {
    identifier(s, max)
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlEngine {
    Postgres,
    SqlServer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSqlObject {
    pub engine: SqlEngine,
    pub database: String,
    pub schema: String,
    pub table: String,
    /// Engine-native object identity observed in the reviewed database.
    pub object_id: u64,
    pub scope_sha256: Digest,
}

impl VerifiedSqlObject {
    pub fn validate(&self) -> Result<()> {
        let max = if self.engine == SqlEngine::Postgres {
            63
        } else {
            128
        };
        ensure!(
            identifier(&self.database, max)
                && identifier(&self.schema, max)
                && identifier(&self.table, max)
                && self.object_id > 0
                && valid_digest(&self.scope_sha256),
            "Invalid verified SQL object"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSqlMetadata {
    pub object: VerifiedSqlObject,
    pub columns: Vec<VerifiedSqlColumn>,
    pub existing_indexes: Vec<String>,
    pub base_table: bool,
    pub source_evidence_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSqlColumn {
    pub name: String,
    /// PostgreSQL attnum or SQL Server column_id for the exact table identity.
    pub column_id: u32,
    pub plain: bool,
}

impl VerifiedSqlMetadata {
    pub fn validate(&self) -> Result<()> {
        self.object.validate()?;
        let max = if self.object.engine == SqlEngine::Postgres {
            63
        } else {
            128
        };
        ensure!(
            self.base_table
                && !self.columns.is_empty()
                && self.columns.len() <= 512
                && self.existing_indexes.len() <= 512
                && valid_digest(&self.source_evidence_sha256),
            "Missing verified base-table metadata"
        );
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for column in &self.columns {
            ensure!(
                identifier(&column.name, max)
                    && column.column_id > 0
                    && names.insert(&column.name)
                    && ids.insert(column.column_id),
                "Invalid/duplicate plain column"
            );
        }
        for name in &self.existing_indexes {
            ensure!(identifier(name, max), "Invalid index metadata");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainIndexColumn {
    pub name: String,
    pub direction: SortDirection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlAction {
    PostgresCreateIndex {
        object: VerifiedSqlObject,
        index: String,
        columns: Vec<PlainIndexColumn>,
    },
    PostgresAnalyze {
        object: VerifiedSqlObject,
    },
    SqlServerCreateIndex {
        object: VerifiedSqlObject,
        index: String,
        columns: Vec<PlainIndexColumn>,
    },
    SqlServerUpdateStatistics {
        object: VerifiedSqlObject,
    },
}

impl SqlAction {
    pub fn object(&self) -> &VerifiedSqlObject {
        match self {
            Self::PostgresCreateIndex { object, .. }
            | Self::PostgresAnalyze { object }
            | Self::SqlServerCreateIndex { object, .. }
            | Self::SqlServerUpdateStatistics { object } => object,
        }
    }
    pub fn is_statistics(&self) -> bool {
        matches!(
            self,
            Self::PostgresAnalyze { .. } | Self::SqlServerUpdateStatistics { .. }
        )
    }
    pub fn validate(&self, metadata: &VerifiedSqlMetadata) -> Result<()> {
        metadata.validate()?;
        ensure!(
            self.object() == &metadata.object,
            "SQL object differs from verified metadata"
        );
        let engine = match self {
            Self::PostgresCreateIndex { .. } | Self::PostgresAnalyze { .. } => SqlEngine::Postgres,
            _ => SqlEngine::SqlServer,
        };
        ensure!(self.object().engine == engine, "SQL engine mismatch");
        if let Self::PostgresCreateIndex { index, columns, .. }
        | Self::SqlServerCreateIndex { index, columns, .. } = self
        {
            let max = if engine == SqlEngine::Postgres {
                63
            } else {
                128
            };
            ensure!(
                new_index_identifier(index, max)
                    && !metadata.existing_indexes.iter().any(|v| {
                        if engine == SqlEngine::SqlServer {
                            v.eq_ignore_ascii_case(index)
                        } else {
                            v == index
                        }
                    }),
                "Invalid or existing index name"
            );
            ensure!(
                (1..=4).contains(&columns.len()),
                "Index needs 1–4 plain columns"
            );
            let mut unique = std::collections::BTreeSet::new();
            for col in columns {
                ensure!(
                    metadata
                        .columns
                        .iter()
                        .any(|c| c.name == col.name && c.plain)
                        && unique.insert(&col.name),
                    "Index column is unverified or repeated"
                );
            }
        }
        Ok(())
    }
    /// Review text only. The executor in Task 14 independently builds and validates SQL.
    pub fn operation_preview(&self) -> String {
        fn quoted(engine: SqlEngine, value: &str) -> String {
            match engine {
                SqlEngine::Postgres => format!("\"{}\"", value.replace('"', "\"\"")),
                SqlEngine::SqlServer => format!("[{}]", value.replace(']', "]]")),
            }
        }
        match self {
            Self::PostgresCreateIndex {
                object,
                index,
                columns,
            }
            | Self::SqlServerCreateIndex {
                object,
                index,
                columns,
            } => {
                let engine = object.engine;
                let table = format!(
                    "{}.{}",
                    quoted(engine, &object.schema),
                    quoted(engine, &object.table)
                );
                let columns = columns
                    .iter()
                    .map(|c| {
                        format!(
                            "{} {}",
                            quoted(engine, &c.name),
                            if c.direction == SortDirection::Asc {
                                "ASC"
                            } else {
                                "DESC"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                match engine {
                    SqlEngine::Postgres => format!(
                        "CREATE INDEX {} ON {} USING btree ({})",
                        quoted(engine, index),
                        table,
                        columns
                    ),
                    SqlEngine::SqlServer => format!(
                        "CREATE NONCLUSTERED INDEX {} ON {} ({})",
                        quoted(engine, index),
                        table,
                        columns
                    ),
                }
            }
            Self::PostgresAnalyze { object } => format!(
                "ANALYZE {}.{}",
                quoted(SqlEngine::Postgres, &object.schema),
                quoted(SqlEngine::Postgres, &object.table)
            ),
            Self::SqlServerUpdateStatistics { object } => format!(
                "UPDATE STATISTICS {}.{}",
                quoted(SqlEngine::SqlServer, &object.schema),
                quoted(SqlEngine::SqlServer, &object.table)
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestorationSpec {
    VerifiedReversible {
        exact_index_sha256: Digest,
        ownership_scheme_sha256: Digest,
    },
    ManualOrUnavailable {
        limitation: StatisticsLimitation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatisticsLimitation {
    PriorStatisticsCannotBeRestoredExactly,
}

impl RestorationSpec {
    pub fn validate_for(&self, action: &SqlAction) -> Result<()> {
        match (self, action.is_statistics()) {
            (
                Self::VerifiedReversible {
                    exact_index_sha256,
                    ownership_scheme_sha256,
                },
                false,
            ) => ensure!(
                valid_digest(exact_index_sha256) && valid_digest(ownership_scheme_sha256),
                "Missing index ownership proof"
            ),
            (
                Self::ManualOrUnavailable {
                    limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
                },
                true,
            ) => {}
            _ => anyhow::bail!("Restoration differs from action"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequiredCheck {
    HttpFunctional {
        scope_sha256: Digest,
        expected_status: u16,
        body_sha256: Option<Digest>,
        window: String,
    },
    SqlFunctional {
        scope_sha256: Digest,
        object_id: u64,
        expected_row_count: u64,
        window: String,
    },
    Performance {
        scope_sha256: Digest,
        object_id: u64,
        workload_sha256: Digest,
        maximum_median_ms: u64,
        maximum_p95_ms: u64,
        minimum_warmups: u8,
        minimum_samples: u8,
        window: String,
    },
}

impl RequiredCheck {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::HttpFunctional {
                scope_sha256,
                expected_status,
                body_sha256,
                window,
            } => ensure!(
                valid_digest(scope_sha256)
                    && (100..=599).contains(expected_status)
                    && body_sha256.as_deref().is_none_or(valid_digest)
                    && valid_criterion_field(window),
                "Invalid HTTP check"
            ),
            Self::SqlFunctional {
                scope_sha256,
                object_id,
                window,
                ..
            } => ensure!(
                valid_digest(scope_sha256) && *object_id > 0 && valid_criterion_field(window),
                "Invalid SQL check"
            ),
            Self::Performance {
                scope_sha256,
                object_id,
                workload_sha256,
                maximum_median_ms,
                maximum_p95_ms,
                minimum_warmups,
                minimum_samples,
                window,
            } => ensure!(
                valid_digest(scope_sha256)
                    && *object_id > 0
                    && valid_digest(workload_sha256)
                    && *maximum_median_ms > 0
                    && *maximum_p95_ms >= *maximum_median_ms
                    && *minimum_warmups >= 3
                    && *minimum_samples >= 15
                    && valid_criterion_field(window),
                "Invalid performance check"
            ),
        }
        Ok(())
    }
    pub fn functional(&self) -> bool {
        !matches!(self, Self::Performance { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriterionComparator {
    AtMost,
    AtLeast,
    Equal,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriterionRequirement {
    pub measure: String,
    pub comparator: CriterionComparator,
    /// Exact IEEE-754 finite threshold from the reviewed case criterion.
    pub threshold_bits: u64,
    pub unit: String,
    pub window: String,
}

fn valid_criterion_field(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control)
}

fn exact_u64(value: u64) -> Option<f64> {
    (value <= 9_007_199_254_740_992).then_some(value as f64)
}

fn exact_value_satisfies(value: f64, criterion: &CriterionRequirement) -> bool {
    let threshold = f64::from_bits(criterion.threshold_bits);
    threshold.is_finite()
        && match criterion.comparator {
            CriterionComparator::AtMost => value <= threshold,
            CriterionComparator::AtLeast => value >= threshold,
            CriterionComparator::Equal => value == threshold,
        }
}

impl RequiredCheck {
    pub fn implies_criterion(&self, criterion: &CriterionRequirement) -> bool {
        match self {
            Self::HttpFunctional {
                expected_status,
                window,
                ..
            } => {
                criterion.measure == "HTTP status"
                    && criterion.unit == "status"
                    && criterion.window == *window
                    && f64::from_bits(criterion.threshold_bits) > 0.0
                    && exact_value_satisfies(f64::from(*expected_status), criterion)
            }
            Self::SqlFunctional {
                expected_row_count,
                window,
                ..
            } => {
                criterion.measure == "SQL row count"
                    && criterion.unit == "rows"
                    && criterion.window == *window
                    && exact_u64(*expected_row_count)
                        .is_some_and(|v| exact_value_satisfies(v, criterion))
            }
            Self::Performance {
                maximum_median_ms,
                maximum_p95_ms,
                window,
                ..
            } => {
                let upper_bound = match criterion.measure.as_str() {
                    "Median latency" => *maximum_median_ms,
                    "P95 latency" => *maximum_p95_ms,
                    _ => return false,
                };
                criterion.unit == "ms"
                    && criterion.window == *window
                    && criterion.comparator == CriterionComparator::AtMost
                    && f64::from_bits(criterion.threshold_bits) > 0.0
                    && exact_u64(upper_bound)
                        .is_some_and(|v| v <= f64::from_bits(criterion.threshold_bits))
            }
        }
    }
}

impl CriterionRequirement {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_criterion_field(&self.measure)
                && valid_criterion_field(&self.unit)
                && valid_criterion_field(&self.window)
                && f64::from_bits(self.threshold_bits).is_finite(),
            "Invalid criterion requirement"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSpec {
    pub checks: Vec<RequiredCheck>,
    /// One exact reviewed criterion selector for each check, in the same order.
    pub criteria: Vec<CriterionRequirement>,
}
impl VerificationSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.checks.is_empty()
                && self.checks.len() <= 16
                && self.criteria.len() == self.checks.len()
                && self.checks.iter().any(RequiredCheck::functional),
            "At least one functional check is required"
        );
        for (check, criterion) in self.checks.iter().zip(&self.criteria) {
            check.validate()?;
            criterion.validate()?;
            ensure!(
                check.implies_criterion(criterion),
                "Required check cannot prove paired criterion"
            );
        }
        let unique = self
            .criteria
            .iter()
            .collect::<std::collections::HashSet<_>>();
        ensure!(
            unique.len() == self.criteria.len(),
            "Duplicate criterion requirement"
        );
        Ok(())
    }
}

pub fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(serde_json::to_vec(value)?);
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d() -> String {
        "a".repeat(64)
    }
    #[test]
    fn typed_checks_only_claim_criteria_they_prove() {
        let http = RequiredCheck::HttpFunctional {
            scope_sha256: d(),
            expected_status: 200,
            body_sha256: None,
            window: "after change".into(),
        };
        let performance = RequiredCheck::Performance {
            scope_sha256: d(),
            object_id: 42,
            workload_sha256: d(),
            maximum_median_ms: 100,
            maximum_p95_ms: 200,
            minimum_warmups: 3,
            minimum_samples: 15,
            window: "after change".into(),
        };
        let status = CriterionRequirement {
            measure: "HTTP status".into(),
            comparator: CriterionComparator::Equal,
            threshold_bits: 200f64.to_bits(),
            unit: "status".into(),
            window: "after change".into(),
        };
        let latency = CriterionRequirement {
            measure: "Median latency".into(),
            comparator: CriterionComparator::AtMost,
            threshold_bits: 100f64.to_bits(),
            unit: "ms".into(),
            window: "after change".into(),
        };
        let mut spec = VerificationSpec {
            checks: vec![http, performance],
            criteria: vec![status, latency],
        };
        spec.validate().unwrap();
        VerificationSpec {
            checks: vec![spec.checks[0].clone()],
            criteria: vec![spec.criteria[0].clone()],
        }
        .validate()
        .unwrap();
        assert!(
            VerificationSpec {
                checks: vec![spec.checks[1].clone()],
                criteria: vec![spec.criteria[1].clone()],
            }
            .validate()
            .is_err()
        );
        spec.criteria.swap(0, 1);
        assert!(spec.validate().is_err());
        spec.criteria.swap(0, 1);
        spec.criteria[1].threshold_bits = 99f64.to_bits();
        assert!(spec.validate().is_err());
        spec.criteria[1].threshold_bits = 100f64.to_bits();
        spec.criteria[1].window = "before change".into();
        assert!(spec.validate().is_err());
        spec.criteria[1].window = "after change".into();
        spec.criteria[1].unit = "s".into();
        assert!(spec.validate().is_err());
        spec.criteria[1].unit = "ms".into();
        spec.criteria[1].comparator = CriterionComparator::AtLeast;
        assert!(spec.validate().is_err());
        spec.criteria[1].comparator = CriterionComparator::AtMost;
        spec.criteria[1].threshold_bits = f64::NAN.to_bits();
        assert!(spec.validate().is_err());
        spec.criteria[1].threshold_bits = 0f64.to_bits();
        assert!(spec.validate().is_err());
    }
    fn metadata(engine: SqlEngine) -> VerifiedSqlMetadata {
        VerifiedSqlMetadata {
            object: VerifiedSqlObject {
                engine,
                database: "db".into(),
                schema: "public".into(),
                table: "orders".into(),
                object_id: 42,
                scope_sha256: d(),
            },
            columns: ["customer", "date", "status", "amount"]
                .into_iter()
                .enumerate()
                .map(|(i, name)| VerifiedSqlColumn {
                    name: name.into(),
                    column_id: (i + 1) as u32,
                    plain: true,
                })
                .collect(),
            existing_indexes: vec![],
            base_table: true,
            source_evidence_sha256: d(),
        }
    }
    fn cols(n: usize) -> Vec<PlainIndexColumn> {
        (0..n)
            .map(|i| PlainIndexColumn {
                name: ["customer", "date", "status", "amount"][i.min(3)].into(),
                direction: if i % 2 == 0 {
                    SortDirection::Asc
                } else {
                    SortDirection::Desc
                },
            })
            .collect()
    }
    #[test]
    fn four_sql_forms_and_one_to_four_plain_columns() {
        for engine in [SqlEngine::Postgres, SqlEngine::SqlServer] {
            let m = metadata(engine);
            for n in 1..=4 {
                let a = if engine == SqlEngine::Postgres {
                    SqlAction::PostgresCreateIndex {
                        object: m.object.clone(),
                        index: "idx_orders".into(),
                        columns: cols(n),
                    }
                } else {
                    SqlAction::SqlServerCreateIndex {
                        object: m.object.clone(),
                        index: "idx_orders".into(),
                        columns: cols(n),
                    }
                };
                a.validate(&m).unwrap();
                assert!(a.operation_preview().contains("DESC") || n == 1);
                if n == 1 {
                    assert_eq!(
                        a.operation_preview(),
                        if engine == SqlEngine::Postgres {
                            "CREATE INDEX \"idx_orders\" ON \"public\".\"orders\" USING btree (\"customer\" ASC)"
                        } else {
                            "CREATE NONCLUSTERED INDEX [idx_orders] ON [public].[orders] ([customer] ASC)"
                        }
                    );
                }
            }
            let stats = if engine == SqlEngine::Postgres {
                SqlAction::PostgresAnalyze {
                    object: m.object.clone(),
                }
            } else {
                SqlAction::SqlServerUpdateStatistics {
                    object: m.object.clone(),
                }
            };
            stats.validate(&m).unwrap();
            assert_eq!(
                stats.operation_preview(),
                if engine == SqlEngine::Postgres {
                    "ANALYZE \"public\".\"orders\""
                } else {
                    "UPDATE STATISTICS [public].[orders]"
                }
            );
            assert!(
                RestorationSpec::ManualOrUnavailable {
                    limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly
                }
                .validate_for(&stats)
                .is_ok()
            );
            assert!(
                RestorationSpec::VerifiedReversible {
                    exact_index_sha256: d(),
                    ownership_scheme_sha256: d()
                }
                .validate_for(&stats)
                .is_err()
            );
        }
    }
    #[test]
    fn rejects_expressions_options_duplicates_and_cross_database() {
        let m = metadata(SqlEngine::Postgres);
        let action = |columns| SqlAction::PostgresCreateIndex {
            object: m.object.clone(),
            index: "ix".into(),
            columns,
        };
        assert!(action(vec![]).validate(&m).is_err());
        assert!(
            action(vec![PlainIndexColumn {
                name: "lower(customer)".into(),
                direction: SortDirection::Asc
            }])
            .validate(&m)
            .is_err()
        );
        assert!(
            action(vec![PlainIndexColumn {
                name: "customer INCLUDE amount".into(),
                direction: SortDirection::Asc
            }])
            .validate(&m)
            .is_err()
        );
        assert!(action(vec![cols(1)[0].clone(); 2]).validate(&m).is_err());
        assert!(
            action(cols(4).into_iter().chain(cols(1)).collect())
                .validate(&m)
                .is_err()
        );
        let mut other = m.object.clone();
        other.database = "other".into();
        assert!(
            SqlAction::PostgresCreateIndex {
                object: m.object.clone(),
                index: "ix;DROP TABLE orders".into(),
                columns: cols(1)
            }
            .validate(&m)
            .is_err()
        );
        assert!(
            SqlAction::PostgresAnalyze { object: other }
                .validate(&m)
                .is_err()
        );
        assert!(
            serde_json::from_str::<SqlAction>(
                r#"{"kind":"postgres_analyze","object":{},"sql":"DROP TABLE x"}"#
            )
            .is_err()
        );
    }
}
