//! Fixed read-only probes. No model output is interpolated into executable code.
use super::*;
use crate::operations::{CommandSpec, Endpoint, JobResult, JobStatus};

pub fn build(case: &Case, request: &Request) -> Result<CommandSpec> {
    case.validate()?;
    ensure!(
        case.config.mode == Mode::ReadOnly
            && request.mode == Mode::ReadOnly
            && request.binding == case.binding()?,
        "Realer Leseauftrag ist nicht an diesen Fall gebunden"
    );
    let target = case.config.target.as_ref().context("Ziel fehlt")?;
    let app = checked_url(&case.config.application)?;
    let payload = serde_json::json!({"request":request.id,"binding":request.binding,"probe":request.probe,"service":case.config.service,"host":app.host_str(),"port":app.port_or_known_default(),"dependency":case.config.dependency});
    let json = serde_json::to_string(&payload)?.replace('\'', "''");
    let body = format!(
        "$p=ConvertFrom-Json -InputObject '{json}';\n{}",
        include_str!("probes.ps1")
    );
    let mut spec = CommandSpec {
        program: String::new(),
        args: vec![],
        stdin: String::new(),
        source: format!(
            "Diagnose · {} · {} · {}",
            target.name,
            request.probe.label(),
            request.id
        ),
    };
    let endpoint = Endpoint::new(&target.host, "", target.port).map_err(anyhow::Error::msg)?;
    crate::operations::winrm(&mut spec, &endpoint, &body);
    spec.stdin.push('\n');
    Ok(spec)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    request: Uuid,
    binding: String,
    probe: Probe,
    value: Value,
}

pub fn value(request: &Request, result: &JobResult) -> Result<Value> {
    ensure!(
        result.status == JobStatus::Completed && !result.truncated && result.stdout.len() <= 4096,
        "Leseprüfung fehlgeschlagen, abgebrochen oder abgeschnitten"
    );
    let response: Response = serde_json::from_str(result.stdout.trim())?;
    ensure!(
        response.request == request.id
            && response.binding == request.binding
            && response.probe == request.probe,
        "Fremde oder veraltete Prüfantwort"
    );
    let finished: DateTime<Utc> = result.finished.into();
    ensure!(
        finished >= request.started
            && finished.signed_duration_since(request.started) <= chrono::Duration::seconds(180),
        "Prüfantwort außerhalb des Zeitfensters"
    );
    Ok(response.value)
}
