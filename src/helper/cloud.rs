//! Exact, read-only cloud collection. Provider payloads and secrets never enter evidence.
use super::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
    manifest::CapabilityId,
    process::{FixedToolOperation, run_aws_tool},
    scope::{BoundScope, CredentialPurpose},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::Value;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct AzureVmAdapter;
pub struct AwsEc2Adapter;

fn output(request: &ProbeRequest, observation: Observation, complete: bool) -> Result<ProbeOutput> {
    let now = Utc::now();
    Ok(ProbeOutput {
        status: if complete {
            EvidenceStatus::Complete
        } else {
            EvidenceStatus::Partial
        },
        coverage: Coverage {
            observed: u32::from(complete),
            expected: 1,
            truncated: false,
        },
        records: vec![NormalizedRecord {
            kind: RecordKind::CloudInstance,
            observation,
            subject_sha256: request.scope.resource_digest()?,
            detail: None,
        }],
        metrics: Vec::new(),
        sql_observations: Vec::new(),
        sql_artifacts: vec![],
        evidence_refs: Vec::new(),
        source_id: format!(
            "cloud:{:?}:{}",
            request.capability_id,
            request.scope.resource_digest()?
        )
        .into_bytes(),
        source_observed_at: now,
        parser_version: 1,
    })
}

fn denied(request: &ProbeRequest) -> Result<ProbeOutput> {
    let mut result = output(request, Observation::Unknown, false)?;
    result.status = EvidenceStatus::Denied;
    Ok(result)
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Missing provider field"))
}

pub(crate) fn token_tenant(token: &str, tenant: &str, principal: &str) -> Result<()> {
    ensure!(
        token.len() <= 16 * 1024 && !token.chars().any(char::is_control),
        "Invalid token"
    );
    let mut parts = token.split('.');
    let _header = parts.next();
    let body = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid token"))?;
    ensure!(
        parts.next().is_some() && parts.next().is_none() && body.len() <= 8192,
        "Invalid token"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| anyhow::anyhow!("Invalid token"))?;
    let claims: Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid token"))?;
    ensure!(
        required(&claims, "tid")?.eq_ignore_ascii_case(tenant),
        "Tenant mismatch"
    );
    ensure!(
        required(&claims, "aud")? == "https://management.azure.com/",
        "Token audience mismatch"
    );
    ensure!(
        claims
            .get("exp")
            .and_then(Value::as_i64)
            .is_some_and(|exp| exp > Utc::now().timestamp()),
        "Token expired"
    );
    ensure!(
        ["oid", "appid", "upn", "preferred_username"]
            .iter()
            .any(|key| claims.get(*key).and_then(Value::as_str) == Some(principal)),
        "Principal mismatch"
    );
    Ok(())
}

async fn arm_get(
    client: &reqwest::Client,
    token: &str,
    url: &str,
    cancel: &CancellationToken,
) -> Result<Option<Value>> {
    let response = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("Canceled"),
        response = client.get(url).bearer_auth(token).send() => response.map_err(|_| anyhow::anyhow!("ARM unavailable"))?,
    };
    if response.status() == reqwest::StatusCode::FORBIDDEN
        || response.status() == reqwest::StatusCode::UNAUTHORIZED
    {
        return Ok(None);
    }
    ensure!(response.status().is_success(), "ARM unavailable");
    ensure!(
        response.content_length().is_none_or(|n| n <= 128 * 1024),
        "ARM output limit"
    );
    let mut response = response;
    let mut bytes = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancel.cancelled() => anyhow::bail!("Canceled"),
            chunk = response.chunk() => chunk.map_err(|_| anyhow::anyhow!("ARM unavailable"))?,
        };
        let Some(chunk) = chunk else { break };
        ensure!(bytes.len() + chunk.len() <= 128 * 1024, "ARM output limit");
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("ARM schema"))?,
    ))
}

fn azure_identity(value: &Value, subscription: &str) -> Result<()> {
    ensure!(
        required(value, "subscriptionId")?.eq_ignore_ascii_case(subscription),
        "Subscription mismatch"
    );
    Ok(())
}

fn azure_vm(value: &Value, resource_id: &str) -> Result<()> {
    ensure!(
        required(value, "id")?.eq_ignore_ascii_case(resource_id),
        "VM mismatch"
    );
    Ok(())
}

fn azure_health(value: &Value, resource_id: &str) -> Result<Option<Observation>> {
    let id = required(value, "id")?;
    ensure!(
        id.eq_ignore_ascii_case(&format!(
            "{resource_id}/providers/Microsoft.ResourceHealth/availabilityStatuses/current"
        )),
        "Health resource mismatch"
    );
    let status = value
        .pointer("/properties/availabilityState")
        .and_then(Value::as_str);
    Ok(match status {
        Some("Available") => Some(Observation::Healthy),
        Some("Unavailable") => Some(Observation::Unavailable),
        Some("Degraded") => Some(Observation::Degraded),
        _ => None,
    })
}

impl ProbeAdapter for AzureVmAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::AzureVm {
                tenant,
                subscription,
                resource_id,
                credential: Some(scope),
            } = &request.scope
            else {
                anyhow::bail!("Azure credential required")
            };
            ensure!(
                matches!(
                    request.capability_id,
                    CapabilityId::AzureVmIdentity | CapabilityId::AzureVmResourceHealth
                ),
                "Azure capability mismatch"
            );
            let secret = secrets.resolve(scope, CredentialPurpose::Read)?;
            ensure!(secret.username() == scope.principal, "Principal mismatch");
            token_tenant(secret.password(), tenant, &scope.principal)?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(12))
                .build()
                .map_err(|_| anyhow::anyhow!("ARM unavailable"))?;
            let sub_url = format!(
                "https://management.azure.com/subscriptions/{subscription}?api-version=2022-12-01"
            );
            let Some(sub) = arm_get(&client, secret.password(), &sub_url, &cancel).await? else {
                return denied(request);
            };
            azure_identity(&sub, subscription)?;
            if request.capability_id == CapabilityId::AzureVmIdentity {
                return output(request, Observation::Unknown, true);
            }
            let vm_url =
                format!("https://management.azure.com{resource_id}?api-version=2024-07-01");
            let Some(vm) = arm_get(&client, secret.password(), &vm_url, &cancel).await? else {
                return denied(request);
            };
            azure_vm(&vm, resource_id)?;
            let health_url = format!(
                "https://management.azure.com{resource_id}/providers/Microsoft.ResourceHealth/availabilityStatuses/current?api-version=2024-02-01"
            );
            let Some(health) = arm_get(&client, secret.password(), &health_url, &cancel).await?
            else {
                return denied(request);
            };
            let state = azure_health(&health, resource_id)?;
            output(
                request,
                state.unwrap_or(Observation::Unknown),
                state.is_some(),
            )
        })
    }
}

fn aws_identity(value: &Value, account: &str, principal: &str) -> Result<()> {
    ensure!(required(value, "Account")? == account, "Account mismatch");
    ensure!(required(value, "Arn")? == principal, "Principal mismatch");
    Ok(())
}

// Vault principal is the exact STS ARN. The vault's domain field carries the
// access-key ID, optionally followed by a session token separated by '|'.
pub(crate) fn aws_key_material(value: &str) -> Result<(&str, &str)> {
    ensure!(
        value.len() <= 4117 && !value.chars().any(char::is_control),
        "Invalid AWS key material"
    );
    let (key, token) = value.split_once('|').unwrap_or((value, ""));
    ensure!(
        key.len() == 20
            && key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()),
        "Invalid AWS access key"
    );
    ensure!(
        !token.contains('|') && token.len() <= 4096 && token.is_ascii(),
        "Invalid AWS session token"
    );
    Ok((key, token))
}

fn aws_inventory(value: &Value, instance_id: &str) -> Result<()> {
    let reservations = value
        .get("Reservations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Inventory schema"))?;
    let instances: Vec<&Value> = reservations
        .iter()
        .flat_map(|reservation| {
            reservation
                .get("Instances")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect();
    ensure!(
        instances.len() == 1 && required(instances[0], "InstanceId")? == instance_id,
        "Inventory mismatch"
    );
    Ok(())
}

fn aws_status(value: &Value, instance_id: &str) -> Result<Option<Observation>> {
    let rows = value
        .get("InstanceStatuses")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Status schema"))?;
    if rows.is_empty() {
        return Ok(None);
    }
    ensure!(
        rows.len() == 1 && required(&rows[0], "InstanceId")? == instance_id,
        "Status mismatch"
    );
    let instance = rows[0]
        .pointer("/InstanceStatus/Status")
        .and_then(Value::as_str);
    let system = rows[0]
        .pointer("/SystemStatus/Status")
        .and_then(Value::as_str);
    Ok(match (instance, system) {
        (Some("ok"), Some("ok")) => Some(Observation::Healthy),
        (Some("impaired"), _) | (_, Some("impaired")) => Some(Observation::Degraded),
        _ => None,
    })
}

impl ProbeAdapter for AwsEc2Adapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::AwsEc2 {
                account,
                region,
                instance_id,
                credential: Some(scope),
            } = &request.scope
            else {
                anyhow::bail!("AWS credential required")
            };
            ensure!(
                matches!(
                    request.capability_id,
                    CapabilityId::AwsEc2Inventory | CapabilityId::AwsEc2Status
                ),
                "AWS capability mismatch"
            );
            let secret = secrets.resolve(scope, CredentialPurpose::Read)?;
            let partition = if region.starts_with("cn-") {
                "arn:aws-cn:"
            } else if region.starts_with("us-gov-") {
                "arn:aws-us-gov:"
            } else {
                "arn:aws:"
            };
            ensure!(
                secret.username() == scope.principal && scope.principal.starts_with(partition),
                "Principal mismatch"
            );
            let (access_key, session_token) = aws_key_material(secret.domain())?;
            let call = |operation, token: CancellationToken| {
                run_aws_tool(
                    operation,
                    access_key,
                    secret.password(),
                    session_token,
                    token,
                    Duration::from_secs(8),
                )
            };
            let identity = call(
                FixedToolOperation::AwsCallerIdentity {
                    region: region.clone(),
                },
                cancel.clone(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("AWS unavailable"))?;
            let identity: Value = serde_json::from_slice(&identity.stdout)
                .map_err(|_| anyhow::anyhow!("AWS identity schema"))?;
            aws_identity(&identity, account, &scope.principal)?;
            let inventory = call(
                FixedToolOperation::AwsEc2Describe {
                    region: region.clone(),
                    instance_id: instance_id.clone(),
                },
                cancel.clone(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("AWS unavailable"))?;
            let inventory: Value = serde_json::from_slice(&inventory.stdout)
                .map_err(|_| anyhow::anyhow!("AWS inventory schema"))?;
            aws_inventory(&inventory, instance_id)?;
            if request.capability_id == CapabilityId::AwsEc2Inventory {
                return output(request, Observation::Unknown, true);
            }
            let status = call(
                FixedToolOperation::AwsEc2Status {
                    region: region.clone(),
                    instance_id: instance_id.clone(),
                },
                cancel,
            )
            .await
            .map_err(|_| anyhow::anyhow!("AWS unavailable"))?;
            let status: Value = serde_json::from_slice(&status.stdout)
                .map_err(|_| anyhow::anyhow!("AWS status schema"))?;
            let state = aws_status(&status, instance_id)?;
            output(
                request,
                state.unwrap_or(Observation::Unknown),
                state.is_some(),
            )
        })
    }
}

#[cfg(test)]
#[path = "cloud_tests.rs"]
mod tests;
