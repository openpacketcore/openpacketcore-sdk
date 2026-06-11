//! Integration test exercising the config-bus validate/commit/readback path
//! with a generated-like toy config and NACM-protected changed paths.

use async_trait::async_trait;
use opc_config_bus::{
    ConfigBus, ConfigEvent, ConfigSnapshot, MockManagedDatastore, SubscriberLagPolicy,
};
use opc_config_fixture::{ToyConfig, ToyDelta};
use opc_config_model::{
    CommitRequest, ConfigOperation, OpcConfig, RequestId, RequestSource, TransportType,
    TrustedPrincipal, WorkloadIdentity, YangPath as ModelYangPath,
};
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, NacmRule, PolicyVersion};
use opc_types::{ConfigVersion, Redacted, TenantId};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("system".into()),
        TenantId::new("tenant-a").expect("tenant"),
    )
}

fn security_admin_principal() -> TrustedPrincipal {
    principal().with_roles(["security-admin"])
}

/// Build a NACM module registry with the toy-system module registered.
fn toy_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry
        .register_module("toy-system", "toy")
        .expect("register toy module");
    registry
}

/// Convert a set of deltas into the config-model YangPaths used by
/// `CommitRequest.changed_paths`, preserving order.
fn deltas_to_changed_paths(deltas: &[ToyDelta]) -> Vec<ModelYangPath> {
    deltas
        .iter()
        .map(|d| ModelYangPath::new(d.yang_path()).expect("canonical path"))
        .collect()
}

struct NacmAuthorizer {
    evaluator: std::sync::Mutex<NacmEvaluator>,
    policy: NacmPolicy,
    registry: ModuleRegistry,
}

#[async_trait]
impl opc_config_bus::ConfigAuthorizer for NacmAuthorizer {
    async fn authorize(
        &self,
        ctx: &opc_config_bus::AuthorizationContext,
    ) -> Result<(), opc_config_bus::AuthorizationError> {
        let mut evaluator = self.evaluator.lock().unwrap();
        let action = match ctx.operation {
            ConfigOperation::Replace | ConfigOperation::Patch => NacmAction::Update,
            ConfigOperation::Delete => NacmAction::Delete,
            ConfigOperation::Rollback => NacmAction::Update,
        };

        for path in &ctx.changed_paths {
            let path_str = path.as_str();
            let nacm_path = opc_nacm::YangPath::parse(path_str, &self.registry).map_err(|e| {
                opc_config_bus::AuthorizationError::new(format!("invalid path: {}", e.message()))
            })?;
            let decision = evaluator.evaluate(&self.policy, &nacm_path, action);
            if !decision.is_allowed() {
                return Err(opc_config_bus::AuthorizationError::new(format!(
                    "permission denied for {}",
                    path_str
                )));
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn toy_config_commit() {
    let registry = toy_registry();

    // NACM policy: allow updates to hostname and domain-name, deny updates
    // to secret fields (admin-password, tls-pre-shared-key).
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(
            NacmAction::Update,
            opc_nacm::YangPathPattern::parse("/toy:system/toy:hostname", &registry)
                .expect("pattern"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Update,
            opc_nacm::YangPathPattern::parse("/toy:system/toy:domain-name", &registry)
                .expect("pattern"),
        ))
        .add_rule(NacmRule::deny(
            NacmAction::Update,
            opc_nacm::YangPathPattern::parse("/toy:system/toy:admin-password", &registry)
                .expect("pattern"),
        ))
        .add_rule(NacmRule::deny(
            NacmAction::Update,
            opc_nacm::YangPathPattern::parse("/toy:system/toy:tls-pre-shared-key", &registry)
                .expect("pattern"),
        ))
        .build();

    let nacm_auth = Arc::new(NacmAuthorizer {
        evaluator: std::sync::Mutex::new(NacmEvaluator::new()),
        policy: policy.clone(),
        registry: registry.clone(),
    });

    // Initial config with empty secrets so startup validation passes.
    let initial = ToyConfig::new("router-1")
        .with_domain_name("example.com")
        .with_max_sessions(10);

    // Build config bus with mock store and authorizer.
    let store = MockManagedDatastore::new();
    let bus = ConfigBus::new(initial.clone(), store, nacm_auth.clone())
        .await
        .expect("bus startup");

    // Subscribe to changes.
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 4);

    // ------------------------------------------------------------------
    // 1) NACM-protected changed paths: secret-field change is rejected at
    //    the bus admission boundary even if the caller omits changed_paths.
    // ------------------------------------------------------------------
    let secret_cand = ToyConfig::from_previous(
        &initial,
        vec![ToyDelta::AdminPassword(Redacted::new("hunter2".into()))],
    )
    .expect("from_previous");
    let nacm_denied = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            secret_cand,
            Vec::new(),
            Instant::now() + Duration::from_secs(5),
        ))
        .await;

    assert!(
        nacm_denied.is_err(),
        "NACM should deny admin-password updates at config-bus admission"
    );
    assert_eq!(
        nacm_denied.unwrap_err().code,
        opc_config_model::CommitErrorCode::AuthorizationDenied,
        "error code must be AuthorizationDenied"
    );

    // ------------------------------------------------------------------
    // 2) NACM-protected changed paths: public-field change is allowed.
    // ------------------------------------------------------------------
    let public_deltas = vec![ToyDelta::Hostname("router-2".into())];
    let candidate =
        ToyConfig::from_previous(&initial, public_deltas.clone()).expect("from_previous");
    let paths = deltas_to_changed_paths(candidate.applied_deltas().unwrap_or(&[]));
    let result = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            candidate,
            paths,
            Instant::now() + Duration::from_secs(5),
        ))
        .await
        .expect("NACM should allow hostname updates");

    assert_eq!(result.status, opc_config_model::CommitStatus::Committed);
    assert_eq!(result.new_version, Some(ConfigVersion::new(1)));

    // Derive changed_paths from delta metadata (not hard-coded).
    let changed_paths = deltas_to_changed_paths(&public_deltas);
    assert_eq!(changed_paths.len(), 1);
    assert_eq!(changed_paths[0].as_str(), "/toy:system/toy:hostname");

    // Readback: verify published snapshot reflects the committed config.
    let snapshot = bus.load();
    assert_eq!(snapshot.hostname(), "router-2");
    assert_eq!(snapshot.domain_name(), Some("example.com"));
    assert_eq!(snapshot.max_sessions(), 10);

    // Version advanced.
    assert_eq!(bus.version().get(), 1);

    // ------------------------------------------------------------------
    // 3) Subscriber fanout: verify change event carries deltas + paths.
    // ------------------------------------------------------------------
    let event = subscriber.try_recv().expect("subscriber event");
    match event {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(1));
            assert_eq!(change.current.hostname(), "router-2");
            assert_eq!(change.previous.hostname(), "router-1");
            // Deltas should include the hostname change.
            assert!(change.deltas.iter().any(|d| {
                matches!(d, opc_config_fixture::ToyDelta::Hostname(ref h) if h == "router-2")
            }));
            // Changed paths preserved.
            assert_eq!(change.changed_paths.len(), 1);
            assert_eq!(change.changed_paths[0].as_str(), "/toy:system/toy:hostname");
        }
        _other => panic!("expected Change event, got non-Change ConfigEvent"),
    }

    // ------------------------------------------------------------------
    // 4) Regression: public edit succeeds even when running config has
    //    existing secrets (no security-admin required for non-secret
    //    changes).
    // ------------------------------------------------------------------
    let store2 = MockManagedDatastore::new();
    let initial_with_secrets = ToyConfig::new("router-1")
        .with_admin_password("existing-secret")
        .with_max_sessions(10);
    let bus2 = ConfigBus::new_dev_only(initial_with_secrets.clone(), store2)
        .await
        .expect("bus2 startup");

    // Operator (no security-admin) changes only hostname.
    let op_candidate = ToyConfig::from_previous(
        &initial_with_secrets,
        vec![ToyDelta::Hostname("router-3".into())],
    )
    .expect("from_previous");
    let op_paths = deltas_to_changed_paths(op_candidate.applied_deltas().unwrap_or(&[]));
    let operator_result = bus2
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            op_candidate,
            op_paths,
            Instant::now() + Duration::from_secs(5),
        ))
        .await
        .expect("operator commit succeeds");

    assert_eq!(
        operator_result.status,
        opc_config_model::CommitStatus::Committed
    );
    assert_eq!(bus2.load().hostname(), "router-3");

    // ------------------------------------------------------------------
    // 5) End-to-end secret write requires security-admin role.
    //
    // We bypass the NACM gate here so that the config bus's own semantic
    // validator is the rejecting layer.  This proves that even if NACM were
    // to allow the path, the secret-change policy embedded in the config
    // model still blocks unauthorized writes.
    // ------------------------------------------------------------------
    let secret_candidate = ToyConfig::from_previous(
        &initial_with_secrets,
        vec![ToyDelta::AdminPassword(Redacted::new("new-secret".into()))],
    )
    .expect("from_previous");
    let secret_paths = deltas_to_changed_paths(secret_candidate.applied_deltas().unwrap_or(&[]));

    let secret_result = bus2
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(), // no security-admin
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            secret_candidate,
            secret_paths,
            Instant::now() + Duration::from_secs(5),
        ))
        .await;

    assert!(
        secret_result.is_err(),
        "secret write by non-security-admin must be rejected"
    );
    assert_eq!(
        secret_result.unwrap_err().code,
        opc_config_model::CommitErrorCode::SemanticValidationFailed
    );

    // ------------------------------------------------------------------
    // 6) Security-admin can write secrets end-to-end.
    // ------------------------------------------------------------------
    let admin_candidate = ToyConfig::from_previous(
        &initial_with_secrets,
        vec![ToyDelta::AdminPassword(Redacted::new(
            "admin-secret".into(),
        ))],
    )
    .expect("from_previous");
    let admin_paths = deltas_to_changed_paths(admin_candidate.applied_deltas().unwrap_or(&[]));

    let admin_result = bus2
        .submit(CommitRequest::commit(
            RequestId::new(),
            security_admin_principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            admin_candidate,
            admin_paths,
            Instant::now() + Duration::from_secs(5),
        ))
        .await
        .expect("security-admin secret write succeeds");

    assert_eq!(
        admin_result.status,
        opc_config_model::CommitStatus::Committed
    );
    assert_eq!(bus2.load().admin_password().expose(), "admin-secret");

    // ------------------------------------------------------------------
    // 7) Verify schema digest is stable across commits.
    // ------------------------------------------------------------------
    let latest = bus.load().schema_digest();
    assert_eq!(
        latest.to_string(),
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    );

    // ------------------------------------------------------------------
    // 8) Regression: direct apply_delta on a cloned snapshot must NOT bypass
    //    semantic validation.  The attacker path is:
    //      1. clone bus.load()       → applied_deltas = Some([]) (empty)
    //      2. apply_delta(secret)   → applied_deltas must become None
    //      3. submit                → validate_semantics sees None or
    //                                   non-empty secret → demands security-admin
    //    This was the round-4/5 blocking finding; the fix is at the top of
    //    ToyConfig::apply_delta (lib.rs line ~322).
    // ------------------------------------------------------------------
    let running = bus2.load();
    let mut cloned = (*running).clone(); // applied_deltas = Some([]) after Clone

    // Simulate the attack: apply a secret delta directly (not via from_previous).
    cloned
        .apply_delta(ToyDelta::AdminPassword(Redacted::new("evil".into())))
        .expect("apply_delta must not fail");
    let bypass_paths = deltas_to_changed_paths(cloned.applied_deltas().unwrap_or(&[]));

    let bypass_result = bus2
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(), // no security-admin
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            cloned,
            bypass_paths,
            Instant::now() + Duration::from_secs(5),
        ))
        .await;

    assert!(
        bypass_result.is_err(),
        "direct apply_delta bypass must be rejected by semantic validation"
    );
    assert_eq!(
        bypass_result.unwrap_err().code,
        opc_config_model::CommitErrorCode::SemanticValidationFailed,
        "error must be SemanticValidationFailed, not NACM — proving the\n\
         apply_delta invalidation closes the clone-and-mutate bypass"
    );
}
