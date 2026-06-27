use opc_config_model::{
    ApplyPlan, ApplyPlanChange, ChangeImpact, ChangeImpactClass, CommitError, CommitErrorCode,
    CommitMode, CommitRequest, CommitResult, CommitStatus, ConfigError, ConfigOperation,
    ConfigWorkflowRequirement, IdempotencyKey, OpcConfig, RequestId, RequestSource, RollbackTarget,
    TransportType, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
    YangPath, FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW,
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
        apply_plan: None,
    };

    let json = serde_json::to_string(&result).expect("serialize commit result");
    let round: CommitResult = serde_json::from_str(&json).expect("deserialize commit result");

    assert_eq!(round, result);
}

#[test]
fn apply_plan_default_hot_uses_authoritative_paths() {
    let path = YangPath::new("/system/hostname").expect("path");
    let plan = ApplyPlan::default_hot(vec![path.clone()], None);

    assert_eq!(plan.class, ChangeImpactClass::Hot);
    assert_eq!(plan.strongest_class(), ChangeImpactClass::Hot);
    assert!(plan.commit_allowed());
    assert!(!plan.blocks_traffic_until_workflow());
    assert_eq!(plan.changes[0].path, path);
    assert_eq!(plan.changes[0].reason_code, "config_changed");
}

#[test]
fn apply_plan_strongest_class_and_estimates_are_canonicalized() {
    let warm_path = YangPath::new("/aaa/peer").expect("path");
    let restart_path = YangPath::new("/platform/listener").expect("path");
    let plan = ApplyPlan {
        class: ChangeImpactClass::Hot,
        changes: vec![
            ApplyPlanChange {
                path: warm_path,
                class: ChangeImpactClass::Warm,
                reason_code: "aaa_peer_added".into(),
                affected_sessions_estimate: Some(7),
            },
            ApplyPlanChange {
                path: restart_path.clone(),
                class: ChangeImpactClass::RestartRequired,
                reason_code: "listener_changed".into(),
                affected_sessions_estimate: Some(u64::MAX),
            },
        ],
        impact: ChangeImpact {
            class: ChangeImpactClass::Hot,
            affected_sessions_estimate: None,
            requires_external_workflow: false,
        },
        rollback_target: None,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    }
    .normalize();

    assert_eq!(plan.class, ChangeImpactClass::RestartRequired);
    assert_eq!(plan.impact.class, ChangeImpactClass::RestartRequired);
    assert_eq!(plan.impact.affected_sessions_estimate, Some(u64::MAX));
    assert!(plan.impact.requires_external_workflow);
    assert!(plan.blocks_traffic_until_workflow());

    let requirement =
        ConfigWorkflowRequirement::from_apply_plan(&plan).expect("workflow requirement");
    assert_eq!(requirement.class, ChangeImpactClass::RestartRequired);
    assert_eq!(requirement.reason_code, "listener_changed");
    assert_eq!(requirement.affected_paths, vec![restart_path]);
}

#[test]
fn forbidden_live_normalization_adds_hard_error() {
    let plan = ApplyPlan {
        class: ChangeImpactClass::ForbiddenLive,
        changes: vec![ApplyPlanChange {
            path: YangPath::new("/session-store/backend").expect("path"),
            class: ChangeImpactClass::ForbiddenLive,
            reason_code: "session_store_backend_changed".into(),
            affected_sessions_estimate: None,
        }],
        impact: ChangeImpact {
            class: ChangeImpactClass::Hot,
            affected_sessions_estimate: None,
            requires_external_workflow: false,
        },
        rollback_target: None,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    }
    .normalize();

    assert!(!plan.commit_allowed());
    assert_eq!(plan.hard_errors.len(), 1);
    assert_eq!(
        plan.hard_errors[0].code,
        FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW
    );

    let error = CommitError::apply_plan_rejected(plan.clone());
    assert_eq!(error.code, CommitErrorCode::ApplyPlanRejected);
    assert_eq!(error.apply_plan.as_deref(), Some(&plan));
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

#[test]
fn transport_type_netconf_tls_is_distinct_and_serde_stable() {
    // NETCONF over TLS must be a transport distinct from SSH so audit,
    // authorization, and idempotency-fingerprint matching attribute a request to
    // the transport it actually arrived on (the spec forbids mapping TLS onto SSH).
    assert_ne!(TransportType::NetconfTls, TransportType::NetconfSsh);

    // Every transport must serde round-trip: the variant is embedded in persisted
    // commit/audit/idempotency records, so a serialization that did not round-trip
    // would corrupt them or break idempotent-replay matching.
    for transport in [
        TransportType::Gnmi,
        TransportType::NetconfSsh,
        TransportType::NetconfTls,
        TransportType::RestconfHttps,
        TransportType::Internal,
    ] {
        let json = serde_json::to_string(&transport).expect("serialize transport");
        let round: TransportType = serde_json::from_str(&json).expect("deserialize transport");
        assert_eq!(round, transport);
    }

    // NetconfTls is usable as a CommitRequest transport and is preserved verbatim
    // (the field the config bus copies into the authorization context and the
    // stored request fingerprint).
    let request = CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::NetconfTls,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        ExampleConfig { revision: 1 },
        vec![YangPath::new("/system/hostname").expect("path")],
        Instant::now(),
    );
    assert_eq!(request.transport, TransportType::NetconfTls);
}

#[test]
fn auth_strength_serde_round_trips_all_variants() {
    for strength in [
        opc_config_model::AuthStrength::MutualTls,
        opc_config_model::AuthStrength::Jwt,
        opc_config_model::AuthStrength::SshPublicKey,
        opc_config_model::AuthStrength::LocalProcess,
    ] {
        let json = serde_json::to_string(&strength).expect("serialize auth strength");
        let round: opc_config_model::AuthStrength =
            serde_json::from_str(&json).expect("deserialize auth strength");
        assert_eq!(round, strength);
    }
}
