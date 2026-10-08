//! Joined read model. Each relationship retains its own provenance and uncertainty.
use crate::{mission::Target, models::ConnectionProfile, telemetry};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryFreshness {
    Recent,
    Outdated,
    Unknown,
}

#[derive(Clone, Debug)]
pub enum InventoryEntry {
    SavedProfile {
        target: Target,
    },
    DirectCapture {
        id: Uuid,
        target: Target,
        freshness: InventoryFreshness,
        partial: bool,
    },
    InferredNetwork {
        source: Target,
        destination: Target,
        address: String,
        port: u16,
        freshness: InventoryFreshness,
        profile_drift: bool,
        evidence: Vec<Uuid>,
    },
}

pub fn derive_inventory(
    profiles: &[ConnectionProfile],
    telemetry: &telemetry::Store,
    now: DateTime<Utc>,
) -> Vec<InventoryEntry> {
    let mut entries = Vec::new();
    for profile in profiles {
        entries.push(InventoryEntry::SavedProfile {
            target: Target::from_profile(profile),
        });
    }
    for observation in telemetry::latest(&telemetry.observations) {
        let bound = profiles.iter().any(|p| observation.target.matches(p));
        let fresh = observation.received <= now
            && now
                .signed_duration_since(observation.received)
                .num_seconds()
                < 900;
        // A capture can be recent yet incomplete; absence of data never means healthy.
        let partial = !observation.payload.events_available || observation.payload.truncated;
        entries.push(InventoryEntry::DirectCapture {
            id: observation.id,
            target: observation.target.clone(),
            freshness: if !bound || partial {
                InventoryFreshness::Unknown
            } else if fresh {
                InventoryFreshness::Recent
            } else {
                InventoryFreshness::Outdated
            },
            partial,
        });
    }
    let targets: Vec<Target> = profiles.iter().map(Target::from_profile).collect();
    for edge in &telemetry.edges {
        let status = telemetry.dependency_status(edge, &targets, now);
        let profile_drift = !status.source_matches || !status.destination_matches;
        let captures_complete = match edge.evidence.as_slice() {
            [source_id, destination_id] => {
                let source = telemetry
                    .observations
                    .iter()
                    .find(|o| o.id == *source_id && o.target.same_endpoint(&edge.source));
                let destination = telemetry
                    .observations
                    .iter()
                    .find(|o| o.id == *destination_id && o.target.same_endpoint(&edge.destination));
                matches!(source, Some(o) if o.payload.events_available && !o.payload.truncated)
                    && matches!(destination, Some(o) if o.payload.events_available && !o.payload.truncated)
            }
            _ => false,
        };
        let freshness = if profile_drift || !captures_complete {
            InventoryFreshness::Unknown
        } else {
            match status.observation_freshness {
                telemetry::ObservationFreshness::Recent => InventoryFreshness::Recent,
                telemetry::ObservationFreshness::Outdated => InventoryFreshness::Outdated,
                telemetry::ObservationFreshness::Unknown => InventoryFreshness::Unknown,
            }
        };
        entries.push(InventoryEntry::InferredNetwork {
            source: edge.source.clone(),
            destination: edge.destination.clone(),
            address: edge.address.clone(),
            port: edge.port,
            freshness,
            profile_drift,
            evidence: edge.evidence.clone(),
        });
    }
    entries
}
