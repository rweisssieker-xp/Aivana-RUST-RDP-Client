//! Explicit, read-only host observations. An observed TCP relationship is not causal proof.
use crate::{
    mission::Target,
    operations::{CommandSpec, Endpoint},
    security,
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub state: String,
    pub pid: u32,
    pub start_mode: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socket {
    pub local: String,
    pub local_port: u16,
    pub remote: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at: String,
    pub provider: String,
    pub id: u32,
    pub level: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub machine: String,
    pub os_version: String,
    pub observed_at: String,
    pub addresses: Vec<String>,
    pub services: Vec<Service>,
    pub sockets: Vec<Socket>,
    pub events: Vec<Event>,
    pub events_available: bool,
    pub truncated: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub id: Uuid,
    pub target: Target,
    pub received: DateTime<Utc>,
    pub payload: Payload,
}
impl Observation {
    pub fn parse(target: Target, stdout: &str) -> Result<Self> {
        if stdout.len() > 128 * 1024 {
            bail!("Telemetry response exceeds the size limit");
        }
        let p: Payload = serde_json::from_str(stdout.trim())?;
        if p.addresses.len() > 64
            || p.services.len() > 400
            || p.sockets.len() > 512
            || p.events.len() > 64
            || p.machine.len() > 255
            || p.os_version.len() > 128
        {
            bail!("Telemetry limits exceeded");
        }
        if p.addresses.iter().any(|s| s.parse::<IpAddr>().is_err())
            || p.sockets
                .iter()
                .any(|s| s.local.parse::<IpAddr>().is_err() || s.remote.parse::<IpAddr>().is_err())
        {
            bail!("Invalid network address in telemetry");
        }
        if p.services
            .iter()
            .any(|s| s.name.len() > 256 || s.state.len() > 64 || s.start_mode.len() > 64)
            || p.events
                .iter()
                .any(|e| e.provider.len() > 256 || e.at.len() > 64)
        {
            bail!("Invalid telemetry fields");
        }
        Ok(Self {
            id: Uuid::new_v4(),
            target,
            received: Utc::now(),
            payload: p,
        })
    }
    pub fn fresh(&self) -> bool {
        let age = Utc::now() - self.received;
        age.num_seconds() >= 0 && age.num_minutes() < 15
    }
}
pub fn collect_spec(target: &Target) -> Result<CommandSpec> {
    if target.protocol != "RDP" || !target.route.is_empty() {
        bail!(
            "Telemetry requires a direct Windows target with WinRM and the current Windows identity"
        );
    }
    let endpoint = Endpoint::new(&target.host, "", target.port).map_err(anyhow::Error::msg)?;
    let body = r#"$services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object -First 401); $tcp=@(Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 513); $addresses=@(Get-NetIPAddress -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -Unique | Select-Object -First 64); $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $available=$true; $events=@(); try {$events=@(Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 64 -ErrorAction Stop)} catch {$available=$false}; [pscustomobject]@{machine=$env:COMPUTERNAME;os_version=$os.Version;observed_at=[DateTime]::UtcNow.ToString('o');addresses=$addresses;services=@($services | Select-Object -First 400 | ForEach-Object {[pscustomobject]@{name=$_.Name;state=$_.State;pid=[uint32]$_.ProcessId;start_mode=$_.StartMode}});sockets=@($tcp | Select-Object -First 512 | ForEach-Object {[pscustomobject]@{local=$_.LocalAddress;local_port=[uint16]$_.LocalPort;remote=$_.RemoteAddress;remote_port=[uint16]$_.RemotePort;state=$_.State.ToString();pid=[uint32]$_.OwningProcess}});events=@($events | ForEach-Object {[pscustomobject]@{at=$_.TimeCreated.ToUniversalTime().ToString('o');provider=$_.ProviderName;id=[uint32]$_.Id;level=[byte]$_.Level}});events_available=$available;truncated=($services.Count -gt 400 -or $tcp.Count -gt 512)}"#;
    let mut spec = CommandSpec {
        program: String::new(),
        args: vec![],
        stdin: String::new(),
        source: format!("Relayne Telemetrie · {}", target.host),
    };
    crate::operations::winrm(&mut spec, &endpoint, body);
    Ok(spec)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub source: Target,
    pub destination: Target,
    pub address: String,
    pub port: u16,
    pub services: Vec<String>,
    pub evidence: Vec<Uuid>,
    pub observed: DateTime<Utc>,
}
impl Edge {
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.source.profile_id, self.destination.profile_id, self.address, self.port
        )
    }
}
fn ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(|a| match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
        x => x,
    })
}
pub fn discover(observations: &[Observation]) -> Vec<Edge> {
    let latest = latest(observations);
    let mut edges: BTreeMap<String, Edge> = BTreeMap::new();
    for source in &latest {
        for socket in &source.payload.sockets {
            if socket.state != "Established" || socket.remote_port == 0 {
                continue;
            }
            let Some(remote) = ip(&socket.remote) else {
                continue;
            };
            if remote.is_loopback() || remote.is_unspecified() {
                continue;
            }
            // Ambiguous addresses across inventories cannot identify an upstream machine.
            let hosts: Vec<_> = latest
                .iter()
                .filter(|o| {
                    o.target.profile_id != source.target.profile_id
                        && o.payload.addresses.iter().any(|a| ip(a) == Some(remote))
                })
                .collect();
            if hosts.len() != 1 {
                continue;
            };
            let dest = hosts[0];
            if (source.received - dest.received).num_seconds().abs() > 300 {
                continue;
            }
            let pids: BTreeSet<_> = dest
                .payload
                .sockets
                .iter()
                .filter(|s| {
                    s.state == "Listen"
                        && s.local_port == socket.remote_port
                        && (ip(&s.local) == Some(remote)
                            || ip(&s.local).is_some_and(|a| a.is_unspecified()))
                })
                .map(|s| s.pid)
                .filter(|p| *p != 0)
                .collect();
            if pids.is_empty() {
                continue;
            }
            let services = dest
                .payload
                .services
                .iter()
                .filter(|s| pids.contains(&s.pid))
                .map(|s| s.name.clone())
                .collect();
            let edge = Edge {
                source: source.target.clone(),
                destination: dest.target.clone(),
                address: socket.remote.clone(),
                port: socket.remote_port,
                services,
                evidence: vec![source.id, dest.id],
                observed: source.received,
            };
            edges.insert(edge.key(), edge);
        }
    }
    edges.into_values().collect()
}
pub fn latest(observations: &[Observation]) -> Vec<&Observation> {
    let mut map = BTreeMap::new();
    for o in observations {
        let slot = map.entry(o.target.profile_id).or_insert(o);
        if o.received > slot.received {
            *slot = o;
        }
    }
    map.into_values().collect()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Probe {
    pub id: Uuid,
    pub edge: Edge,
    pub at: DateTime<Utc>,
    pub reachable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEvidence {
    ProfileChanged,
    NotRun,
    Reachable { id: Uuid, at: DateTime<Utc> },
    Unreachable { id: Uuid, at: DateTime<Utc> },
    Outdated { id: Uuid, at: DateTime<Utc> },
    InvalidTime { id: Uuid, at: DateTime<Utc> },
}

#[derive(Clone, Debug)]
pub struct DependencyStatus {
    pub source_matches: bool,
    pub destination_matches: bool,
    pub observation_fresh: bool,
    pub path: PathEvidence,
}

impl DependencyStatus {
    pub fn can_probe(&self) -> bool {
        self.source_matches && self.destination_matches
    }
}

fn fresh_at(at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let age = now - at;
    age >= chrono::Duration::zero() && age < chrono::Duration::minutes(15)
}

pub fn probe_spec(edge: &Edge) -> Result<CommandSpec> {
    let addr: IpAddr = edge.address.parse()?;
    if edge.port == 0 {
        bail!("Destination port is missing");
    }
    let endpoint =
        Endpoint::new(&edge.source.host, "", edge.source.port).map_err(anyhow::Error::msg)?;
    let body = format!(
        r#"$c=[System.Net.Sockets.TcpClient]::new(); $ok=$false; try {{$task=$c.ConnectAsync('{addr}',{}); if ($task.Wait(5000)) {{$ok=$c.Connected}}}} catch {{$ok=$false}} finally {{$c.Dispose()}}; [pscustomobject]@{{address='{addr}';port={};reachable=$ok}}"#,
        edge.port, edge.port
    );
    let mut spec = CommandSpec {
        program: String::new(),
        args: vec![],
        stdin: String::new(),
        source: format!(
            "Check dependency · {} → {addr}:{}",
            edge.source.name, edge.port
        ),
    };
    crate::operations::winrm(&mut spec, &endpoint, &body);
    Ok(spec)
}
pub fn parse_probe(edge: Edge, stdout: &str) -> Result<Probe> {
    let v: serde_json::Value = serde_json::from_str(stdout)?;
    if v["address"].as_str().and_then(ip) != ip(&edge.address)
        || v["port"].as_u64() != Some(edge.port as u64)
    {
        bail!("Probe response does not belong to the dependency");
    }
    let reachable = v["reachable"]
        .as_bool()
        .ok_or_else(|| anyhow::anyhow!("Probe result is missing"))?;
    Ok(Probe {
        id: Uuid::new_v4(),
        edge,
        at: Utc::now(),
        reachable,
    })
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Store {
    pub observations: Vec<Observation>,
    pub edges: Vec<Edge>,
    pub probes: Vec<Probe>,
}
impl Store {
    pub fn dependency_status(
        &self,
        edge: &Edge,
        current_targets: &[Target],
        now: DateTime<Utc>,
    ) -> DependencyStatus {
        let source_matches = current_targets.iter().any(|t| edge.source.same_endpoint(t));
        let destination_matches = current_targets
            .iter()
            .any(|t| edge.destination.same_endpoint(t));
        let path = if !source_matches || !destination_matches {
            PathEvidence::ProfileChanged
        } else {
            self.probes
                .iter()
                .filter(|p| {
                    p.edge.key() == edge.key()
                        && p.edge.source.same_endpoint(&edge.source)
                        && p.edge.destination.same_endpoint(&edge.destination)
                })
                .max_by_key(|p| p.at)
                .map_or(PathEvidence::NotRun, |p| {
                    if p.at > now {
                        PathEvidence::InvalidTime { id: p.id, at: p.at }
                    } else if !fresh_at(p.at, now) {
                        PathEvidence::Outdated { id: p.id, at: p.at }
                    } else if p.reachable {
                        PathEvidence::Reachable { id: p.id, at: p.at }
                    } else {
                        PathEvidence::Unreachable { id: p.id, at: p.at }
                    }
                })
        };
        DependencyStatus {
            source_matches,
            destination_matches,
            observation_fresh: fresh_at(edge.observed, now),
            path,
        }
    }

    pub fn add(&mut self, o: Observation) {
        self.observations.push(o);
        if self.observations.len() > 128 {
            self.observations.remove(0);
        }
        for e in discover(&self.observations) {
            self.edges.retain(|old| old.key() != e.key());
            self.edges.push(e);
        }
        if self.edges.len() > 1024 {
            self.edges.drain(..self.edges.len() - 1024);
        }
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if !cfg!(windows) {
            bail!("Windows DPAPI is required");
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 * 1024 {
            bail!("Telemetriespeicher voll");
        }
        security::atomic_write(path, &security::protect_secret(&bytes)?)
    }
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        if std::fs::metadata(path)?.len() > 20 * 1024 * 1024 {
            bail!("Telemetry store exceeds the size limit");
        }
        Ok(serde_json::from_slice(&security::unprotect_secret(
            &std::fs::read(path)?,
        )?)?)
    }
    pub fn current(&self, t: &Target) -> Option<&Observation> {
        self.observations
            .iter()
            .rev()
            .find(|o| o.target.same_endpoint(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge_for(source: &Observation, destination: &Observation, now: DateTime<Utc>) -> Edge {
        Edge {
            source: source.target.clone(),
            destination: destination.target.clone(),
            address: destination.payload.addresses[0].clone(),
            port: 1433,
            services: vec![],
            evidence: vec![source.id, destination.id],
            observed: now,
        }
    }

    #[test]
    fn dependency_status_separates_stale_observation_from_probe_freshness() {
        let now = Utc::now();
        let source = obs("app", "10.1.0.1");
        let destination = obs("db", "10.1.0.2");
        let edge = edge_for(&source, &destination, now - chrono::Duration::minutes(20));
        let targets = [source.target.clone(), destination.target.clone()];
        let mut store = Store::default();
        assert_eq!(
            store.dependency_status(&edge, &targets, now).path,
            PathEvidence::NotRun
        );
        assert!(
            !store
                .dependency_status(&edge, &targets, now)
                .observation_fresh
        );

        let id = Uuid::new_v4();
        store.probes.push(Probe {
            id,
            edge: edge.clone(),
            at: now - chrono::Duration::minutes(16),
            reachable: true,
        });
        assert_eq!(
            store.dependency_status(&edge, &targets, now).path,
            PathEvidence::Outdated {
                id,
                at: now - chrono::Duration::minutes(16)
            }
        );
        store.probes.push(Probe {
            id,
            edge: edge.clone(),
            at: now + chrono::Duration::seconds(1),
            reachable: true,
        });
        assert_eq!(
            store.dependency_status(&edge, &targets, now).path,
            PathEvidence::InvalidTime {
                id,
                at: now + chrono::Duration::seconds(1)
            }
        );
    }

    #[test]
    fn dependency_status_rejects_changed_source_or_destination_profile() {
        let now = Utc::now();
        let source = obs("app", "10.1.0.1");
        let destination = obs("db", "10.1.0.2");
        let edge = edge_for(&source, &destination, now);
        let mut store = Store::default();
        store.probes.push(Probe {
            id: Uuid::new_v4(),
            edge: edge.clone(),
            at: now,
            reachable: true,
        });
        let mut source_changed = source.target.clone();
        source_changed.host = "replacement.example".into();
        let status =
            store.dependency_status(&edge, &[source_changed, destination.target.clone()], now);
        assert!(!status.can_probe());
        assert_eq!(status.path, PathEvidence::ProfileChanged);
        let mut destination_changed = destination.target.clone();
        destination_changed.port += 1;
        let status =
            store.dependency_status(&edge, &[source.target.clone(), destination_changed], now);
        assert!(!status.can_probe());
        assert_eq!(status.path, PathEvidence::ProfileChanged);
    }

    #[test]
    fn shared_destination_probe_remains_bound_to_its_source_and_address() {
        let now = Utc::now();
        let first = obs("app-a", "10.1.0.1");
        let second = obs("app-b", "10.1.0.3");
        let destination = obs("db", "10.1.0.2");
        let first_edge = edge_for(&first, &destination, now);
        let second_edge = edge_for(&second, &destination, now);
        let mut store = Store::default();
        let id = Uuid::new_v4();
        store.probes.push(Probe {
            id,
            edge: first_edge.clone(),
            at: now,
            reachable: false,
        });
        let targets = [
            first.target.clone(),
            second.target.clone(),
            destination.target.clone(),
        ];
        assert_eq!(
            store.dependency_status(&first_edge, &targets, now).path,
            PathEvidence::Unreachable { id, at: now }
        );
        assert_eq!(
            store.dependency_status(&second_edge, &targets, now).path,
            PathEvidence::NotRun
        );
        let mut other_address = first_edge.clone();
        other_address.address = "10.1.0.9".into();
        assert_eq!(
            store.dependency_status(&other_address, &targets, now).path,
            PathEvidence::NotRun
        );
    }
    fn obs(host: &str, address: &str) -> Observation {
        Observation {
            id: Uuid::new_v4(),
            target: Target {
                profile_id: Uuid::new_v4(),
                name: host.into(),
                host: host.into(),
                port: 3389,
                protocol: "RDP".into(),
                username: String::new(),
                domain: String::new(),
                route: String::new(),
            },
            received: Utc::now(),
            payload: Payload {
                machine: host.into(),
                os_version: "10.0".into(),
                observed_at: String::new(),
                addresses: vec![address.into()],
                services: vec![],
                sockets: vec![],
                events: vec![],
                events_available: true,
                truncated: false,
            },
        }
    }
    #[test]
    fn discovers_direction_and_service_without_guessing_duplicate_ips() {
        let mut a = obs("app", "10.1.0.1");
        let mut b = obs("db", "10.1.0.2");
        a.payload.sockets.push(Socket {
            local: "10.1.0.1".into(),
            local_port: 51000,
            remote: "10.1.0.2".into(),
            remote_port: 1433,
            state: "Established".into(),
            pid: 23,
        });
        b.payload.sockets.push(Socket {
            local: "0.0.0.0".into(),
            local_port: 1433,
            remote: "0.0.0.0".into(),
            remote_port: 0,
            state: "Listen".into(),
            pid: 42,
        });
        b.payload.services.push(Service {
            name: "Database".into(),
            state: "Running".into(),
            pid: 42,
            start_mode: "Auto".into(),
        });
        b.payload.sockets.push(Socket {
            local: "10.1.0.2".into(),
            local_port: 1433,
            remote: "10.1.0.1".into(),
            remote_port: 51000,
            state: "Established".into(),
            pid: 42,
        });
        let e = discover(&[a.clone(), b.clone()]);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].services, vec!["Database"]);
        assert_eq!(e[0].source.host, "app");
        let c = obs("ambiguous", "10.1.0.2");
        assert!(discover(&[a, b, c]).is_empty());
    }
    #[cfg(windows)]
    #[test]
    fn generated_collection_script_roundtrips_typed_metadata() {
        use std::{
            io::Write,
            os::windows::process::CommandExt,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let target = obs("fixture.invalid", "10.0.0.1").target;
        let spec = collect_spec(&target).unwrap();
        let body = spec
            .stdin
            .split_once("-ScriptBlock { $ErrorActionPreference='Stop'; ")
            .unwrap()
            .1
            .rsplit_once(" } -ErrorAction Stop | ConvertTo-Json")
            .unwrap()
            .0;
        assert!(!body.contains("Invoke-Command"));
        let prefix = r#"
$ErrorActionPreference='Stop'
function Get-CimInstance {param($ClassName,$ErrorAction) if($ClassName -eq 'Win32_Service'){[pscustomobject]@{Name='Database';State='Running';ProcessId=42;StartMode='Auto'}}else{[pscustomobject]@{Version='10.0'}}}
function Get-NetTCPConnection {param($ErrorAction) [pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=1433;RemoteAddress='0.0.0.0';RemotePort=0;State='Listen';OwningProcess=42}}
function Get-NetIPAddress {param($ErrorAction) [pscustomobject]@{IPAddress='10.0.0.1'}}
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction) [pscustomobject]@{TimeCreated=[DateTime]::Now;ProviderName='Fixture';Id=42;Level=2}}
foreach($name in @('Get-CimInstance','Get-NetTCPConnection','Get-NetIPAddress','Get-WinEvent')){if((Get-Command $name).CommandType -ne 'Function'){throw 'fixture guard'}}
"#;
        let script = format!("{prefix}\n& {{ {body} }} | ConvertTo-Json -Depth 6 -Compress\n");
        let mut child = Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"])
            .creation_flags(0x08000000)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Local fixture timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let o = Observation::parse(target, &String::from_utf8_lossy(&output.stdout)).unwrap();
        assert_eq!(o.payload.services[0].name, "Database");
        assert_eq!(o.payload.sockets[0].local_port, 1433);
        assert_eq!(o.payload.events[0].id, 42);
        assert!(!o.payload.truncated);
    }
    #[test]
    fn rejects_injected_hosts_and_incomplete_probe() {
        let a = obs("bad';Invoke-X", "10.0.0.1");
        assert!(collect_spec(&a.target).is_err());
        let b = obs("b", "10.0.0.2");
        let e = Edge {
            source: a.target,
            destination: b.target,
            address: "10.0.0.2".into(),
            port: 80,
            services: vec![],
            evidence: vec![],
            observed: Utc::now(),
        };
        assert!(parse_probe(e, r#"{"address":"10.0.0.2","port":80}"#).is_err());
    }
}
