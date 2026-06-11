use opc_config_model::{
    CommitError, CommitErrorCode, CommitMode, CommitRequest, CommitResult, CommitStatus,
    ConfigError, ConfigOperation, IdempotencyKey, OpcConfig, RequestId, RequestSource,
    RollbackTarget, TransportType, TrustedPrincipal, ValidationContext, ValidationError,
    WorkloadIdentity, YangPath,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use std::{str::FromStr, time::Instant};

#[derive(Clone)]
struct ExampleConfig {
    revision: u32,
}

impl OpcConfig for ExampleConfig {
    type Delta = &'static str;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self.revision == previous.revision {
            Ok(Vec::new())
        } else {
            Ok(vec!["replace:/example"])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(vec![YangPath::new("/example").expect("static path")])
        }
    }

    fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
        self.revision += 1;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_semantics(
        &self,
        _ctx: &ValidationContext<ExampleConfig>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("system".into()),
        TenantId::new("tenant-a").expect("tenant"),
    )
}

#[test]
fn request_builders_track_modes_and_candidates() {
    let path = YangPath::new("/system/hostname").expect("path");
    let deadline = Instant::now();

    let commit = CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        ExampleConfig { revision: 2 },
        vec![path.clone()],
        deadline,
    )
    .with_base_version(ConfigVersion::new(4))
    .with_idempotency_key(IdempotencyKey::new("req-1").expect("key"));

    assert!(matches!(commit.mode, CommitMode::Commit));
    assert_eq!(commit.base_version, ConfigVersion::new(4));
    assert_eq!(commit.changed_paths, vec![path.clone()]);
    assert!(commit.candidate.is_some());
    assert_eq!(
        commit.idempotency_key.as_ref().map(IdempotencyKey::as_str),
        Some("req-1")
    );

    let validate_only = CommitRequest::validate_only(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Patch,
        ExampleConfig { revision: 3 },
        vec![path],
        deadline,
    );

    assert!(matches!(validate_only.mode, CommitMode::ValidateOnly));
    assert!(validate_only.candidate.is_some());

    let rollback_path = YangPath::new("/system/hostname").expect("rollback path");
    let rollback = CommitRequest::<ExampleConfig>::rollback(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        RollbackTarget::Label("checkpoint-a".into()),
        vec![rollback_path.clone()],
        deadline,
    );

    assert!(matches!(rollback.mode, CommitMode::Rollback { .. }));
    assert_eq!(rollback.operation, ConfigOperation::Rollback);
    assert_eq!(rollback.changed_paths, vec![rollback_path]);
    assert!(rollback.candidate.is_none());
}

#[test]
fn public_types_round_trip_through_serde() {
    let tx_id = TxId::new();
    let result = CommitResult {
        tx_id,
        base_version: ConfigVersion::new(7),
        new_version: Some(ConfigVersion::new(8)),
        status: CommitStatus::Committed,
        changed_paths: vec![YangPath::new("/interfaces/interface[name='n1']").expect("path")],
    };

    let json = serde_json::to_string(&result).expect("serialize commit result");
    let round: CommitResult = serde_json::from_str(&json).expect("deserialize commit result");

    assert_eq!(round, result);
}

#[test]
fn path_and_idempotency_value_objects_validate() {
    assert!(YangPath::new("interfaces/interface").is_err());
    assert!(YangPath::new("").is_err());
    assert!(IdempotencyKey::new(" ").is_err());

    let request_id = RequestId::from_str("123e4567-e89b-12d3-a456-426614174000").expect("uuid");
    assert_eq!(
        request_id.to_string(),
        "123e4567-e89b-12d3-a456-426614174000"
    );
}

#[test]
fn commit_errors_redact_client_visible_validation_and_diff_messages() {
    let secret = "password=super-secret";

    let syntax = CommitError::syntax_validation(ValidationError::syntax(secret));
    assert_eq!(syntax.code, CommitErrorCode::SyntaxValidationFailed);
    assert_eq!(syntax.message, "candidate config failed syntax validation");
    assert!(!syntax.message.contains(secret));

    let semantics = CommitError::semantic_validation(ValidationError::semantics(secret));
    assert_eq!(semantics.code, CommitErrorCode::SemanticValidationFailed);
    assert_eq!(
        semantics.message,
        "candidate config failed semantic validation"
    );
    assert!(!semantics.message.contains(secret));

    let diff = CommitError::diff_failed(ConfigError::new("diff", secret));
    assert_eq!(diff.code, CommitErrorCode::DiffFailed);
    assert_eq!(diff.message, "candidate config diff generation failed");
    assert!(!diff.message.contains(secret));
}
