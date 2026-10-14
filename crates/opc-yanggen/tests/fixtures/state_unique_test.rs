use generated_config_false_test::{expanded_unique, state_unique};
use opc_config_model::{
    CommitMode, ConfigOperation, OpcConfig, RequestId, RequestSource, TransportType,
    TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
};
use serde_json::{json, Value};

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

fn validate(body: Value) -> Result<(), ValidationError> {
    let root: state_unique::types::Root = serde_json::from_value(body).unwrap();
    root.validate_semantics(&context())
}

fn duplicate_error() -> ValidationError {
    ValidationError::semantics("duplicate entry found in list unique constraint")
}

#[test]
fn config_unique_values_reject_duplicates_and_ignore_absent_values() {
    validate(json!({"service": [
        {"name": "one", "port": 80}, {"name": "two", "port": 443},
        {"name": "unobserved-one"}, {"name": "unobserved-two"}
    ]}))
    .unwrap();
    assert_eq!(
        validate(json!({"service": [
            {"name": "one", "port": 443}, {"name": "two", "port": 443}
        ]})),
        Err(duplicate_error())
    );
}

#[test]
fn nested_state_unique_counts_are_scoped_to_each_parent() {
    validate(json!({"service": [
        {"name": "one", "state": {"counter": [
            {"name": "a", "count": 1}, {"name": "b", "count": u32::MAX},
            {"name": "unobserved-one"}, {"name": "unobserved-two"}
        ]}},
        {"name": "two", "state": {"counter": [{"name": "a", "count": 1}]}}
    ]}))
    .unwrap();
    assert_eq!(
        validate(json!({"service": [{"name": "one", "state": {"counter": [
            {"name": "a", "count": u32::MAX}, {"name": "b", "count": u32::MAX}
        ]}}]})),
        Err(duplicate_error())
    );
}

#[test]
fn sensitive_copy_unique_counts_compare_values_without_exposing_them() {
    validate(json!({"service": [{"name": "one", "state": {"counter": [
        {"name": "a", "secret-count": 11}, {"name": "b", "secret-count": 12}
    ]}}]}))
    .unwrap();
    let error = validate(json!({"service": [{"name": "one", "state": {"counter": [
        {"name": "a", "secret-count": 918273}, {"name": "b", "secret-count": 918273}
    ]}}]}))
    .unwrap_err();
    assert_eq!(error, duplicate_error());
    assert!(!format!("{error:?} {error}").contains("918273"));
}

#[test]
fn owned_unique_strings_retain_ordinary_and_sensitive_values() {
    for field in ["value", "secret-value"] {
        validate(json!({"service": [{"name": "one", "state": {"label": [
            {"name": "z", (field): "first"}, {"name": "a", (field): "second"},
            {"name": "unobserved-one"}, {"name": "unobserved-two"}
        ]}}]}))
        .unwrap();
        let error = validate(json!({"service": [{"name": "one", "state": {"label": [
            {"name": "z", (field): "synthetic-secret"},
            {"name": "a", (field): "synthetic-secret"}
        ]}}]}))
        .unwrap_err();
        assert_eq!(error, duplicate_error());
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
}

#[test]
fn keyless_unique_lists_keep_element_iteration() {
    validate(json!({"service": [{"name": "one", "state": {"sample": [
        {"count": 1}, {"count": 2}, {}, {}
    ]}}]}))
    .unwrap();
    assert_eq!(
        validate(json!({"service": [{"name": "one", "state": {"sample": [
            {"count": 1}, {"count": 1}
        ]}}]})),
        Err(duplicate_error())
    );
}

#[test]
fn keyless_ancestors_keep_each_nested_unique_set_separate() {
    validate(json!({"service": [{"name": "one", "state": {"group": [
        {"observation": [{"name": "a", "count": 1}]},
        {"observation": [{"name": "a", "count": 1}]}
    ]}}]}))
    .unwrap();
    assert_eq!(
        validate(json!({"service": [{"name": "one", "state": {"group": [
            {"observation": [{"name": "a", "count": 1}]},
            {"observation": [{"name": "b", "count": 2}, {"name": "c", "count": 2}]}
        ]}}]})),
        Err(duplicate_error())
    );
}

#[test]
fn expanded_config_unique_values_preserve_full_integer_precision() {
    let valid: expanded_unique::types::Root = serde_json::from_value(json!({"service": [
        {"name": "one", "port": "18446744073709551615"},
        {"name": "two", "port": "9223372036854775808"},
        {"name": "unobserved-one"}, {"name": "unobserved-two"}
    ]}))
    .unwrap();
    valid.validate_semantics(&context()).unwrap();
    let invalid: expanded_unique::types::Root = serde_json::from_value(json!({"service": [
        {"name": "one", "port": "18446744073709551615"},
        {"name": "two", "port": "18446744073709551615"}
    ]}))
    .unwrap();
    assert_eq!(
        invalid.validate_semantics(&context()),
        Err(duplicate_error())
    );
}
