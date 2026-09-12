//! Evidence-linked reconstruction; temporal association never proves causation.
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Action,
    Change,
    Failure,
    Observation,
    Recovery,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub profile: Option<Uuid>,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub at: DateTime<Utc>,
    pub kind: Kind,
    pub title: String,
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Hypothesis {
    pub change: String,
    pub failure: String,
    pub seconds_before: i64,
    pub relationship: String,
    pub evidence: Vec<String>,
}
pub fn endpoint_key(t: &crate::mission::Target) -> String {
    use sha2::{Digest, Sha256};
    let identity = serde_json::to_vec(&(
        t.profile_id,
        &t.host,
        t.port,
        &t.protocol,
        &t.username,
        &t.domain,
        &t.route,
    ))
    .expect("serialize endpoint");
    format!("{:x}", Sha256::digest(identity))
}
pub fn normalize(records: Vec<Record>) -> Vec<Record> {
    let mut unique = BTreeMap::new();
    for mut r in records {
        r.title = crate::security::redact_secret_text(&r.title)
            .chars()
            .take(512)
            .collect();
        r.evidence.truncate(16);
        unique.entry(r.id.clone()).or_insert(r);
    }
    let mut rows: Vec<_> = unique.into_values().collect();
    rows.sort_by(|a, b| a.at.cmp(&b.at).then(a.id.cmp(&b.id)));
    if rows.len() > 5000 {
        rows.drain(..rows.len() - 5000);
    }
    rows
}
pub fn hypotheses(
    rows: &[Record],
    edges: &[crate::telemetry::Edge],
    window_minutes: i64,
) -> Vec<Hypothesis> {
    let window = Duration::minutes(window_minutes.clamp(1, 120));
    let mut results = Vec::new();
    for failure in rows.iter().filter(|r| r.kind == Kind::Failure) {
        let Some(affected) = failure.profile else {
            continue;
        };
        let Some(affected_endpoint) = failure.endpoint.as_deref() else {
            continue;
        };
        for change in rows.iter().filter(|r| r.kind == Kind::Change) {
            let delta = failure.at - change.at;
            if delta < Duration::zero() || delta > window {
                continue;
            }
            let Some(changed) = change.profile else {
                continue;
            };
            let Some(changed_endpoint) = change.endpoint.as_deref() else {
                continue;
            };
            let edge = edges.iter().find(|e| {
                e.source.profile_id == affected
                    && e.destination.profile_id == changed
                    && endpoint_key(&e.source) == affected_endpoint
                    && endpoint_key(&e.destination) == changed_endpoint
                    && e.observed <= change.at
                    && change.at - e.observed <= Duration::minutes(15)
            });
            let same = changed == affected && changed_endpoint == affected_endpoint;
            if !same && edge.is_none() {
                continue;
            }
            let mut evidence = vec![change.id.clone(), failure.id.clone()];
            if let Some(e) = edge {
                evidence.extend(e.evidence.iter().map(ToString::to_string));
            }
            results.push(Hypothesis {
                change: change.id.clone(),
                failure: failure.id.clone(),
                seconds_before: delta.num_seconds(),
                relationship: if same {
                    "Gleicher dokumentierter Endpunkt"
                } else {
                    "Zuvor beobachtete Abhängigkeit; Zuordnung erneut prüfen"
                }
                .into(),
                evidence,
            });
        }
    }
    results.sort_by_key(|h| h.seconds_before);
    results.truncate(100);
    results
}
pub fn telemetry_records(store: &crate::telemetry::Store) -> Vec<Record> {
    let mut records = Vec::new();
    let mut previous: BTreeMap<Uuid, &crate::telemetry::Observation> = BTreeMap::new();
    let mut observations: Vec<_> = store.observations.iter().collect();
    observations.sort_by_key(|o| o.received);
    for o in observations {
        records.push(Record {
            id: format!("observation:{}", o.id),
            profile: Some(o.target.profile_id),
            endpoint: Some(endpoint_key(&o.target)),
            at: o.received,
            kind: Kind::Observation,
            title: format!(
                "{}: Telemetrie erfasst{}",
                o.target.name,
                if o.payload.truncated {
                    " (unvollständig)"
                } else {
                    ""
                }
            ),
            evidence: vec![o.id.to_string()],
        });
        if let Some(before) = previous
            .get(&o.target.profile_id)
            .filter(|p| p.target.same_endpoint(&o.target))
        {
            for s in &o.payload.services {
                if let Some(old) = before.payload.services.iter().find(|p| p.name == s.name) {
                    if old.state != s.state || old.start_mode != s.start_mode {
                        records.push(Record {id:format!("drift:{}:{}",o.id,s.name),profile:Some(o.target.profile_id),endpoint:Some(endpoint_key(&o.target)),at:o.received,kind:Kind::Change,
                            title:format!("{} · {}: {} / {} → {} / {}; zwischen zwei Erfassungen festgestellt",o.target.name,s.name,old.state,old.start_mode,s.state,s.start_mode),
                            evidence:vec![before.id.to_string(),o.id.to_string()]});
                    }
                }
            }
        }
        previous.insert(o.target.profile_id, o);
        for e in &o.payload.events {
            let Ok(at) = DateTime::parse_from_rfc3339(&e.at) else {
                continue;
            };
            let at = at.with_timezone(&Utc);
            // Remote timestamps outside the collection interval are not ordered as local facts.
            if at > o.received + Duration::minutes(5) || at < o.received - Duration::hours(2) {
                continue;
            }
            records.push(Record {
                id: format!(
                    "event:{}:{}:{}:{}",
                    endpoint_key(&o.target),
                    e.at,
                    e.provider,
                    e.id
                ),
                profile: Some(o.target.profile_id),
                endpoint: Some(endpoint_key(&o.target)),
                at,
                kind: if e.level <= 2 {
                    Kind::Failure
                } else {
                    Kind::Observation
                },
                title: format!(
                    "{} · {} · Ereignis {} (Rechnerzeit)",
                    o.target.name, e.provider, e.id
                ),
                evidence: vec![o.id.to_string()],
            });
        }
    }
    for p in &store.probes {
        records.push(Record {
            id: format!("probe:{}", p.id),
            profile: Some(p.edge.source.profile_id),
            endpoint: Some(endpoint_key(&p.edge.source)),
            at: p.at,
            kind: if p.reachable {
                Kind::Observation
            } else {
                Kind::Failure
            },
            title: format!(
                "{} → {}:{}: TCP {}",
                p.edge.source.name,
                p.edge.destination.name,
                p.edge.port,
                if p.reachable {
                    "erreichbar"
                } else {
                    "nicht erreichbar"
                }
            ),
            evidence: vec![p.id.to_string()],
        });
    }
    normalize(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(id: &str, p: Option<Uuid>, at: DateTime<Utc>, kind: Kind) -> Record {
        Record {
            id: id.into(),
            profile: p,
            endpoint: p.map(|id| endpoint_key(&target(id))),
            at,
            kind,
            title: id.into(),
            evidence: vec![],
        }
    }
    #[test]
    fn only_preceding_changes_on_known_same_target_are_candidates() {
        let p = Uuid::new_v4();
        let now = Utc::now();
        let rows = vec![
            row("past", Some(p), now - Duration::seconds(10), Kind::Change),
            row("future", Some(p), now + Duration::seconds(1), Kind::Change),
            row("other", Some(Uuid::new_v4()), now, Kind::Change),
            row("unknown", None, now, Kind::Change),
            row("fail", Some(p), now, Kind::Failure),
        ];
        let h = hypotheses(&rows, &[], 30);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].change, "past");
        assert_eq!(h[0].seconds_before, 10);
    }
    #[test]
    fn repeated_evidence_is_deduplicated_and_window_is_respected() {
        let p = Uuid::new_v4();
        let now = Utc::now();
        let r = row("same", Some(p), now, Kind::Failure);
        assert_eq!(normalize(vec![r.clone(), r]).len(), 1);
        assert!(
            hypotheses(
                &[
                    row("old", Some(p), now - Duration::minutes(31), Kind::Change),
                    row("fail", Some(p), now, Kind::Failure)
                ],
                &[],
                30
            )
            .is_empty()
        );
    }
    fn target(id: Uuid) -> crate::mission::Target {
        crate::mission::Target {
            profile_id: id,
            name: "Test".into(),
            host: "localhost".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        }
    }
    #[test]
    fn cross_host_candidate_requires_prior_recent_directed_dependency() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let now = Utc::now();
        let rows = vec![
            row("change", Some(b), now - Duration::seconds(30), Kind::Change),
            row("failure", Some(a), now, Kind::Failure),
        ];
        let mut edge = crate::telemetry::Edge {
            source: target(a),
            destination: target(b),
            address: "127.0.0.1".into(),
            port: 80,
            services: vec![],
            evidence: vec![Uuid::new_v4()],
            observed: now - Duration::minutes(1),
        };
        assert_eq!(hypotheses(&rows, &[edge.clone()], 30).len(), 1);
        edge.observed = now;
        assert!(hypotheses(&rows, &[edge.clone()], 30).is_empty());
        edge.observed = now - Duration::hours(1);
        assert!(hypotheses(&rows, &[edge.clone()], 30).is_empty());
        edge.observed = now - Duration::minutes(1);
        std::mem::swap(&mut edge.source, &mut edge.destination);
        assert!(hypotheses(&rows, &[edge], 30).is_empty());
    }
    #[test]
    fn reusing_profile_uuid_for_another_endpoint_does_not_join_incidents() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let changed = row(
            "change",
            Some(id),
            now - Duration::seconds(10),
            Kind::Change,
        );
        let mut failure = row("failure", Some(id), now, Kind::Failure);
        let mut other = target(id);
        other.host = "retargeted.example".into();
        failure.endpoint = Some(endpoint_key(&other));
        assert!(hypotheses(&[changed.clone(), failure.clone()], &[], 30).is_empty());
        failure.endpoint = None;
        assert!(hypotheses(&[changed, failure], &[], 30).is_empty());
    }
    #[test]
    fn drift_uses_matching_endpoints_and_remote_events_are_deduplicated() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let payload = serde_json::json!({"machine":"fixture","os_version":"10","observed_at":now.to_rfc3339(),"addresses":[],"services":[{"name":"Spooler","state":"Running","pid":1,"start_mode":"Auto"}],"sockets":[],"events":[{"at":now.to_rfc3339(),"provider":"fixture","id":7,"level":2}],"events_available":true,"truncated":false});
        let mut first =
            crate::telemetry::Observation::parse(target(id), &payload.to_string()).unwrap();
        first.received = now;
        let mut second = first.clone();
        second.id = Uuid::new_v4();
        second.received = now + Duration::seconds(30);
        second.payload.services[0].state = "Stopped".into();
        let mut store = crate::telemetry::Store::default();
        store.observations = vec![second.clone(), first];
        let records = telemetry_records(&store);
        assert_eq!(records.iter().filter(|r| r.kind == Kind::Change).count(), 1);
        assert_eq!(
            records.iter().filter(|r| r.kind == Kind::Failure).count(),
            1
        );
        store.observations[0].target.host = "different-host".into();
        assert!(
            !telemetry_records(&store)
                .iter()
                .any(|r| r.kind == Kind::Change)
        );
    }
}
