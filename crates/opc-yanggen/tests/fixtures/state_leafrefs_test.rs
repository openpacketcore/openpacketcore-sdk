use generated_config_false_test::{leafref_traversal, leafref_u32, leafref_u64};
use opc_config_model::{
    CommitMode, ConfigOperation, OpcConfig, RequestId, RequestSource, TransportType,
    TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
};
use serde_json::json;

fn context<C: OpcConfig>() -> ValidationContext<C> {
    ValidationContext {
        request_id: RequestId::new(),
        principal: TrustedPrincipal::new(
            WorkloadIdentity::Internal("test".into()),
            opc_types::TenantId::new("example").unwrap(),
        ),
        transport: TransportType::Internal,
        source: RequestSource::Northbound,
        operation: ConfigOperation::Replace,
        mode: CommitMode::Commit,
        base_version: opc_types::ConfigVersion::INITIAL,
        previous: None,
    }
}

#[test]
fn uint64_state_leafref_keys_validate_observed_membership() {
    let valid: leafref_u64::types::State = serde_json::from_value(json!({
        "target": "18446744073709551615", "row": [{"id": "18446744073709551615"}]
    }))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    for body in [
        json!({"target": "18446744073709551615", "row": [{"id": "7"}]}),
        json!({"row": [{"id": "18446744073709551615"}]}),
    ] {
        let invalid: leafref_u64::types::State = serde_json::from_value(body).unwrap();
        assert_eq!(
            invalid.validate_semantics(&context()),
            Err(ValidationError::semantics(
                "Value not found in target path /ls:state/ls:target"
            ))
        );
    }
}

#[test]
fn uint32_state_leafref_keys_validate_without_extended_scalars() {
    let valid: leafref_u32::types::State = serde_json::from_value(json!({
        "target": u32::MAX, "row": [{"id": u32::MAX}]
    }))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    for body in [
        json!({"target": u32::MAX, "row": [{"id": 7}]}),
        json!({"row": [{"id": u32::MAX}]}),
    ] {
        let invalid: leafref_u32::types::State = serde_json::from_value(body).unwrap();
        assert_eq!(
            invalid.validate_semantics(&context()),
            Err(ValidationError::semantics(
                "Value not found in target path /ls:state/ls:target"
            ))
        );
    }
}

#[test]
fn chained_copy_targets_validate_configuration_and_state_membership() {
    let valid: leafref_traversal::types::Root = serde_json::from_value(json!({
        "number": "18446744073709551615", "number-alias": "18446744073709551615",
        "state": {"linked-number": [{"id": "18446744073709551615"}]}
    }))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    for (body, target) in [
        (
            json!({"number": "9", "number-alias": "7"}),
            "/st:root/st:number",
        ),
        (
            json!({"number": "9", "number-alias": "9", "state": {"linked-number": [{"id": "7"}]}}),
            "/st:root/st:number-alias",
        ),
    ] {
        let invalid: leafref_traversal::types::Root = serde_json::from_value(body).unwrap();
        assert_eq!(
            invalid.validate_semantics(&context()),
            Err(ValidationError::semantics(format!(
                "Value not found in target path {target}"
            )))
        );
    }
}

#[test]
fn owned_targets_in_keyed_lists_validate_all_referencing_rows() {
    let valid: leafref_traversal::types::Root = serde_json::from_value(json!({
        "state": {
            "target": [{"name": "present"}, {"name": "second"}],
            "reference": [{"id": "second"}, {"id": "present"}]
        }
    }))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    let invalid: leafref_traversal::types::Root = serde_json::from_value(json!({
        "state": {
            "target": [{"name": "present"}],
            "reference": [{"id": "present"}, {"id": "synthetic-secret"}]
        }
    }))
    .unwrap();
    let error = invalid.validate_semantics(&context()).unwrap_err();
    assert_eq!(
        error,
        ValidationError::semantics(
            "Value not found in target path /st:root/st:state/st:target/st:name"
        )
    );
    assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
}

#[test]
fn keyless_target_and_reference_lists_keep_element_iteration() {
    let valid: leafref_traversal::types::Root = serde_json::from_value(json!({
        "state": {
            "sample": [{"flag": true}, {"flag": false}],
            "sample-reference": [{"value": false}, {"value": true}, {}]
        }
    }))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    let invalid: leafref_traversal::types::Root = serde_json::from_value(json!({
        "state": {
            "sample": [{"flag": true}, {}],
            "sample-reference": [{"value": true}, {"value": false}]
        }
    }))
    .unwrap();
    assert_eq!(
        invalid.validate_semantics(&context()),
        Err(ValidationError::semantics(
            "Value not found in target path /st:root/st:state/st:sample/st:flag"
        ))
    );
}
