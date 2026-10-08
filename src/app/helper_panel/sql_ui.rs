use crate::helper::{
    case::HelperCase,
    evidence::{Eligibility, EvidenceStatus, Observation},
    manifest::CapabilityId,
    scope::{BoundScope, DatabaseEngine},
    sql::postgres::{PgReadProbe, probe_subject_digest},
    sql::types::SqlObservation,
};
use eframe::egui;

pub(super) fn show(ui: &mut egui::Ui, case: &HelperCase) {
    for scope in case.scopes() {
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
        let eligibility = latest.eligibility(chrono::Utc::now(), chrono::Duration::minutes(5));
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
