use crate::helper::{
    case::HelperCase,
    evidence::{Eligibility, EvidenceEnvelope, EvidenceStatus, Observation},
    manifest::CapabilityId,
    scope::{BoundScope, DatabaseEngine},
    sql::types::SqlObservation,
    sql::{
        postgres::{PgReadProbe, probe_subject_digest},
        sql_server::{SqlServerReadProbe, probe_subject_digest as tds_subject_digest},
    },
};
use eframe::egui;

pub(super) fn show(ui: &mut egui::Ui, case: &HelperCase) {
    for scope in case.scopes() {
        if matches!(
            scope,
            BoundScope::Database {
                engine: DatabaseEngine::SqlServer,
                ..
            }
        ) {
            show_sql_server(ui, case, scope);
            continue;
        }
        let BoundScope::Database {
            engine: DatabaseEngine::Postgres,
            schema,
            object,
            ..
        } = scope
        else {
            continue;
        };
        ui.separator();
        ui.heading("PostgreSQL diagnostics");
        ui.label("Native TLS read of the reviewed database. Object checks require an exact schema and table.");
        if schema.is_none() || object.is_none() {
            ui.label("Object, index, statistics and permission coverage pending: select a schema and table.");
        }
        let Ok(scope_digest) = scope.digest() else {
            continue;
        };
        let Some(latest) = case.evidence().iter().rev().find(|e| {
            e.capability_id == CapabilityId::SqlRead && e.binding.scope_sha256 == scope_digest
        }) else {
            ui.label("No PostgreSQL read capture yet.");
            continue;
        };
        let eligibility = eligibility_for_context(latest, case.revision(), chrono::Utc::now());
        ui.label(format!(
            "Capture: {:?}; readiness: {:?}; coverage {}/{}{}",
            latest.status,
            eligibility,
            latest.coverage.observed,
            latest.coverage.expected,
            if latest.coverage.truncated {
                " (truncated)"
            } else {
                ""
            }
        ));
        if latest.status != EvidenceStatus::Complete || eligibility != Eligibility::Eligible {
            ui.label(
                "Coverage gaps or denied metadata require review before relying on this capture.",
            );
        }
        let Ok(resource_digest) = scope.resource_digest() else {
            continue;
        };
        for probe in [
            PgReadProbe::Identity,
            PgReadProbe::Activity,
            PgReadProbe::Blocking,
            PgReadProbe::Objects,
            PgReadProbe::Indexes,
            PgReadProbe::Statistics,
            PgReadProbe::Permissions,
        ] {
            let key = probe_subject_digest(&resource_digest, probe);
            let status = latest
                .records
                .iter()
                .find(|r| r.subject_sha256 == key)
                .map(|r| r.observation);
            let label = match status {
                Some(Observation::Healthy) => "observed",
                Some(Observation::Degraded) => "truncated",
                Some(Observation::Unavailable) => "denied or unavailable",
                Some(Observation::Unknown) => "unknown",
                None => "not collected",
            };
            ui.label(format!("{}: {label}", probe.label()));
        }
        ui.collapsing("Sessions and blockers", |ui| {
            for observation in &latest.sql_observations {
                match observation {
                    SqlObservation::Activity {
                        pid,
                        state,
                        wait_kind,
                        wait_name,
                        age_ms,
                    } => {
                        ui.label(format!(
                            "Session {pid}: {} / {} {} · transaction age {} ms",
                            state.as_deref().unwrap_or("unknown"),
                            wait_kind.as_deref().unwrap_or("no wait"),
                            wait_name.as_deref().unwrap_or(""),
                            optional_count(*age_ms)
                        ));
                    }
                    SqlObservation::Blocking {
                        waiting_pid,
                        blocking_pid,
                        blocker_state,
                    } => {
                        ui.label(format!(
                            "Session {waiting_pid} waits for {blocking_pid} · blocker {}",
                            blocker_state.as_deref().unwrap_or("unknown")
                        ));
                    }
                    _ => {}
                }
            }
        });
        ui.collapsing("Table, indexes and statistics", |ui| {
            for observation in &latest.sql_observations {
                match observation {
                    SqlObservation::Object {
                        schema,
                        name,
                        columns,
                        estimated_rows,
                    } => {
                        ui.label(format!(
                            "{schema}.{name}: {columns} columns; estimated rows {}",
                            estimated_rows.map_or("unknown".into(), |n| n.to_string())
                        ));
                    }
                    SqlObservation::Index {
                        name,
                        method,
                        valid,
                        scans,
                    } => {
                        ui.label(format!(
                            "Index {name}: {method}; valid {valid}; scans {}",
                            optional_count(*scans)
                        ));
                    }
                    SqlObservation::Statistics {
                        live_rows,
                        dead_rows,
                        analyze_count,
                    } => {
                        ui.label(format!(
                            "Estimated live/dead rows: {} / {}; analyses: {}",
                            optional_count(*live_rows),
                            optional_count(*dead_rows),
                            optional_count(*analyze_count)
                        ));
                    }
                    _ => {}
                }
            }
        });
        ui.collapsing("Identity and permissions", |ui| {
            for observation in &latest.sql_observations {
                match observation {
                    SqlObservation::Identity { database, principal, version, tls, server_ip, server_port } => {
                        ui.label(format!("Database {database}; signed-in principal {principal}; version {version}; TLS {tls}; server {server_ip}:{server_port}"));
                    }
                    SqlObservation::Permission { database_connect, schema_usage, table_select } => {
                        ui.label(format!("CONNECT {}; schema USAGE {}; table SELECT {}",
                            privilege(*database_connect), privilege(*schema_usage), privilege(*table_select)));
                    }
                    _ => {}
                }
            }
        });
    }
}

fn show_sql_server(ui: &mut egui::Ui, case: &HelperCase, scope: &BoundScope) {
    ui.separator();
    ui.heading("SQL Server diagnostics");
    ui.label("Native TLS SQL login read of the reviewed database. DMV visibility depends on server permissions.");
    let Ok(scope_digest) = scope.digest() else {
        return;
    };
    let Some(latest) = case.evidence().iter().rev().find(|e| {
        e.capability_id == CapabilityId::SqlRead && e.binding.scope_sha256 == scope_digest
    }) else {
        ui.label("No SQL Server read capture yet.");
        return;
    };
    let eligibility = eligibility_for_context(latest, case.revision(), chrono::Utc::now());
    ui.label(format!(
        "Capture: {:?}; readiness: {:?}; coverage {}/{}{}",
        latest.status,
        eligibility,
        latest.coverage.observed,
        latest.coverage.expected,
        if latest.coverage.truncated {
            " (truncated)"
        } else {
            ""
        }
    ));
    if latest.status != EvidenceStatus::Complete || eligibility != Eligibility::Eligible {
        ui.label(
            "Denied or incomplete DMV and metadata reads cannot establish absence of blockers.",
        );
    }
    let Ok(resource_digest) = scope.resource_digest() else {
        return;
    };
    for probe in [
        SqlServerReadProbe::Identity,
        SqlServerReadProbe::Requests,
        SqlServerReadProbe::Waits,
        SqlServerReadProbe::Blocking,
        SqlServerReadProbe::Objects,
        SqlServerReadProbe::Indexes,
        SqlServerReadProbe::Statistics,
        SqlServerReadProbe::Permissions,
    ] {
        let key = tds_subject_digest(&resource_digest, probe);
        let label = match latest
            .records
            .iter()
            .find(|r| r.subject_sha256 == key)
            .map(|r| r.observation)
        {
            Some(Observation::Healthy) => "observed",
            Some(Observation::Degraded) => "truncated",
            Some(Observation::Unavailable) => "denied or unavailable",
            Some(Observation::Unknown) => "unknown",
            None => "not collected",
        };
        ui.label(format!("{}: {label}", probe.label()));
    }
    ui.collapsing("SQL Server observations", |ui| {
        for value in &latest.sql_observations {
            match value {
                SqlObservation::SqlServerIdentity { database, principal, product_version, server_ip, server_port, tls_required, server_state_access, server_performance_access } => ui.label(format!("Database {database}; principal {principal}; SQL Server {product_version}; TLS required {tls_required}; server {server_ip}:{server_port}; DMV permissions {} / {}", privilege(*server_state_access), privilege(*server_performance_access))),
                SqlObservation::SqlServerRequest { session_id, state, wait_type, elapsed_ms } => ui.label(format!("Request {session_id}: {} / {} · {} ms", state.as_deref().unwrap_or("unknown"), wait_type.as_deref().unwrap_or("unknown"), optional_count(*elapsed_ms))),
                SqlObservation::SqlServerWait { session_id, wait_type, wait_ms } => ui.label(format!("Wait {session_id}: {} · {} ms", wait_type.as_deref().unwrap_or("unknown"), optional_count(*wait_ms))),
                SqlObservation::SqlServerBlocking { waiting_session_id, blocking_session_id } => ui.label(format!("Session {waiting_session_id} waits for {blocking_session_id}")),
                SqlObservation::SqlServerObject { schema, name, object_id, column_count } => ui.label(format!("{schema}.{name}: object ID {object_id}; {column_count} columns")),
                SqlObservation::SqlServerColumn { object_id, column_id, name, plain } => ui.label(format!("Object {object_id}, column {column_id} {name}; plain {plain}")),
                SqlObservation::Object { schema, name, columns, estimated_rows } => ui.label(format!("{schema}.{name}: {columns} columns; estimated rows {}", estimated_rows.map_or("unknown".into(), |v| v.to_string()))),
                SqlObservation::Index { name, method, valid, scans } => ui.label(format!("Index {name}: {method}; valid {valid}; scans {}", optional_count(*scans))),
                SqlObservation::SqlServerStatistics { rows, modification_counter, histogram_steps } => ui.label(format!("Rows {}; modifications {}; histogram steps {}", optional_count(*rows), optional_count(*modification_counter), optional_count(*histogram_steps))),
                SqlObservation::SqlServerPermission { database_connect, schema_select, object_select, object_alter, object_control } => ui.label(format!("CONNECT {}; schema SELECT {}; object SELECT {}; object ALTER {}; object CONTROL {}", privilege(*database_connect), privilege(*schema_select), privilege(*object_select), privilege(*object_alter), privilege(*object_control))),
                _ => continue,
            };
        }
    });
}

fn eligibility_for_context(
    evidence: &EvidenceEnvelope,
    case_revision: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Eligibility {
    if evidence.binding.case_revision != case_revision {
        Eligibility::Stale
    } else {
        evidence.eligibility(now, chrono::Duration::minutes(5))
    }
}

fn optional_count(value: Option<i64>) -> String {
    value.map_or("unknown".into(), |n| n.to_string())
}
fn privilege(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "granted",
        Some(false) => "denied",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::evidence::{
        Coverage, EvidenceBinding, NormalizedRecord, Origin, RecordKind, TimeQuality,
    };
    use uuid::Uuid;

    #[test]
    fn context_revision_change_marks_sql_capture_stale() {
        let now = chrono::Utc::now();
        let evidence = EvidenceEnvelope {
            schema: crate::helper::evidence::EVIDENCE_SCHEMA,
            id: Uuid::new_v4(),
            binding: EvidenceBinding {
                case_id: Uuid::new_v4(),
                case_revision: 2,
                request_id: Uuid::new_v4(),
                scope_sha256: "a".repeat(64),
                credential_scope_sha256: "b".repeat(64),
                run_id: None,
            },
            capability_id: CapabilityId::SqlRead,
            capability_version: 1,
            parser_version: 1,
            origin: Origin::Live,
            source_id: "c".repeat(64),
            source_observed_at: now,
            retrieved_at: now,
            time_quality: TimeQuality::Trusted,
            status: EvidenceStatus::Complete,
            coverage: Coverage {
                observed: 1,
                expected: 1,
                truncated: false,
            },
            content_sha256: "d".repeat(64),
            records: vec![NormalizedRecord {
                kind: RecordKind::SqlRead,
                observation: Observation::Healthy,
                subject_sha256: "e".repeat(64),
            }],
            metrics: vec![],
            sql_observations: vec![],
            evidence_refs: vec![],
        };
        assert_eq!(
            eligibility_for_context(&evidence, 2, now),
            Eligibility::Eligible
        );
        assert_eq!(
            eligibility_for_context(&evidence, 3, now),
            Eligibility::Stale
        );
    }
}
