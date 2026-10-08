use super::*;
use serde_json::json;

#[test]
fn azure_identity_and_health_reject_cross_resource_or_unknown_schema() {
    let subscription = "11111111-1111-1111-1111-111111111111";
    let resource = format!(
        "/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    );
    assert!(azure_identity(&json!({"subscriptionId": subscription}), subscription).is_ok());
    assert!(azure_identity(&json!({"subscriptionId": "other"}), subscription).is_err());
    assert!(azure_vm(&json!({"id": resource}), &resource).is_ok());
    assert!(azure_vm(&json!({"id": "other"}), &resource).is_err());
    let id = format!("{resource}/providers/Microsoft.ResourceHealth/availabilityStatuses/current");
    assert_eq!(
        azure_health(
            &json!({"id": id, "properties": {"availabilityState": "Available"}}),
            &resource
        )
        .unwrap(),
        Some(Observation::Healthy)
    );
    assert_eq!(
        azure_health(&json!({"id": id, "properties": {}}), &resource).unwrap(),
        None
    );
    assert!(
        azure_health(
            &json!({"id": "other", "properties": {"availabilityState": "Available"}}),
            &resource
        )
        .is_err()
    );
}

#[test]
fn aws_identity_inventory_and_status_require_exact_single_resource() {
    let id = "i-0123456789abcdef0";
    assert_eq!(
        aws_key_material("AKIA1234567890123456|session").unwrap(),
        ("AKIA1234567890123456", "session")
    );
    assert!(aws_key_material("--profile|session").is_err());
    assert!(aws_key_material("AKIA1234567890123456|session|extra").is_err());
    let stored = crate::models::SecretCredential {
        username: "arn:aws:iam::123456789012:user/read".into(),
        password: "secret-sentinel".into(),
        domain: "AKIA1234567890123456|session-sentinel".into(),
    };
    let debug = format!("{stored:?}");
    assert!(!debug.contains("secret-sentinel") && !debug.contains("session-sentinel"));
    assert!(
        aws_identity(
            &json!({"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/read"}),
            "123456789012",
            "arn:aws:iam::123456789012:user/read"
        )
        .is_ok()
    );
    assert!(
        aws_identity(
            &json!({"Account":"123456789013","Arn":"arn:aws:iam::123456789012:user/read"}),
            "123456789012",
            "arn:aws:iam::123456789012:user/read"
        )
        .is_err()
    );
    assert!(
        aws_inventory(
            &json!({"Reservations":[{"Instances":[{"InstanceId":id}]}]}),
            id
        )
        .is_ok()
    );
    assert!(aws_inventory(&json!({"Reservations":[{"Instances":[]}]}), id).is_err());
    assert!(
        aws_inventory(
            &json!({"Reservations":[{"Instances":[{"InstanceId":id},{"InstanceId":id}]}]}),
            id
        )
        .is_err()
    );
    assert_eq!(
        aws_status(&json!({"InstanceStatuses":[]}), id).unwrap(),
        None
    );
    assert_eq!(aws_status(&json!({"InstanceStatuses":[{"InstanceId":id,"InstanceStatus":{"Status":"ok"},"SystemStatus":{"Status":"ok"}}]}), id).unwrap(), Some(Observation::Healthy));
    assert!(aws_status(&json!({"InstanceStatuses":[{"InstanceId":"other"}]}), id).is_err());
}

#[test]
fn jwt_claims_reject_wrong_tenant_audience_and_principal() {
    let payload = json!({"tid":"11111111-1111-1111-1111-111111111111","aud":"https://management.azure.com/","oid":"principal","exp":Utc::now().timestamp()+600});
    let token = format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    assert!(token_tenant(&token, "11111111-1111-1111-1111-111111111111", "principal").is_ok());
    assert!(token_tenant(&token, "22222222-2222-2222-2222-222222222222", "principal").is_err());
    assert!(token_tenant(&token, "11111111-1111-1111-1111-111111111111", "other").is_err());
}

#[test]
fn cloud_scope_rejects_endpoint_and_query_injection() {
    let tenant = "11111111-1111-1111-1111-111111111111";
    let subscription = "22222222-2222-2222-2222-222222222222";
    let resource = format!(
        "/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    );
    assert!(
        BoundScope::AzureVm {
            tenant: tenant.into(),
            subscription: subscription.into(),
            resource_id: resource.clone(),
            credential: None
        }
        .validate()
        .is_ok()
    );
    assert!(
        BoundScope::AzureVm {
            tenant: tenant.into(),
            subscription: subscription.into(),
            resource_id: format!("{resource}?api-version=evil"),
            credential: None
        }
        .validate()
        .is_err()
    );
    assert!(
        BoundScope::AwsEc2 {
            account: "123456789012".into(),
            region: "--endpoint-url".into(),
            instance_id: "i-0123456789abcdef0".into(),
            credential: None
        }
        .validate()
        .is_err()
    );
}
