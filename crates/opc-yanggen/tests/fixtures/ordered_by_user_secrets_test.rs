use generated_ordered_test::secrets as model;
use model::redaction::Redactable;
use model::types::{Root, SecretLeaf};
use opc_config_model::{OpcConfig, ValidationError};
use serde_json::json;

#[test]
fn sensitive_user_ordered_leaf_list_compiles_roundtrips_and_redacts() {
    let original: Root =
        serde_json::from_value(json!({"api-token": ["private-z", "private-a"]})).unwrap();
    assert_eq!(original.api_token.get(), &["private-z", "private-a"]);
    let encoded = serde_json::to_vec(&original).unwrap();
    let decoded: Root = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(format!("{:?}", original.api_token), "<REDACTED>");
    let mut redacted = original;
    redacted.redact_sensitive();
    assert!(redacted.api_token.get().is_empty());
    assert_eq!(serde_json::to_value(redacted).unwrap(), json!({}));

    let error = serde_json::from_value::<Root>(json!({"api-token":["private-z", "private-z"]}))
        .unwrap_err();
    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert_eq!(
        error.to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    let invalid = Root {
        api_token: SecretLeaf::new(vec!["private-z".into(), "private-z".into()]),
    };
    assert_eq!(
        invalid.validate_syntax(),
        Err(ValidationError::syntax(
            "duplicate leaf-list value at /os:root/os:api-token"
        ))
    );
    assert_eq!(
        serde_json::to_string(&invalid).unwrap_err().to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
}
