#![allow(unused_imports)]
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::{sync::Notify, time::timeout};

use opc_alarm::{Alarm, AlarmState, ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{
    ConfigBus, ConfigEvent, ConfigSnapshot, DriftState, ManagedDatastore, MockManagedDatastore,
    StoreError, StoreErrorCode, StoredConfig, SubscriberLagPolicy,
};
use opc_config_model::{
    CommitErrorCode, CommitMode, CommitRequest, ConfigError, ConfigOperation, IdempotencyKey,
    OpcConfig, RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal,
    ValidationContext, ValidationError, WorkloadIdentity, YangPath,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp};

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_idempotency_key_replays_without_duplicate_commit_or_publication() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 2);
    let key = IdempotencyKey::new("req-1").expect("key");

    let first = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key.clone()),
        )
        .await
        .expect("first commit succeeds");

    let second = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key),
        )
        .await
        .expect("idempotent replay succeeds");

    assert_eq!(second, first);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
    assert_eq!(subscriber.len(), 1);
    match subscriber.recv().await.expect("single event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(1));
            assert_eq!(change.current.name, "next");
        }
        ConfigEvent::ResyncRequired { .. } => panic!("expected direct change event"),
    }
    assert!(timeout(Duration::from_millis(25), subscriber.recv())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_idempotency_key_replays_with_reordered_roles() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-roles").expect("key");
    let first_principal = principal_with_roles_and_groups(["config-admin", "auditor"], ["ops"]);
    let second_principal = principal_with_roles_and_groups(["auditor", "config-admin"], ["ops"]);

    let first = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                first_principal,
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("first commit succeeds");

    let second = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                second_principal,
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect("reordered roles should still replay");

    assert_eq!(second, first);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_idempotency_key_replays_with_reordered_groups() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-groups").expect("key");
    let first_principal = principal_with_roles_and_groups(["config-admin"], ["ops", "blue"]);
    let second_principal = principal_with_roles_and_groups(["config-admin"], ["blue", "ops"]);

    let first = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                first_principal,
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("first commit succeeds");

    let second = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                second_principal,
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect("reordered groups should still replay");

    assert_eq!(second, first);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_principal_role_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(ContextBoundConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-authz-role").expect("key");
    let candidate = ContextBoundConfig::new("next").with_authz(
        "config-admin",
        TransportType::Internal,
        RequestSource::Northbound,
    );

    let first = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["config-admin"]),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                candidate.clone(),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("authorized commit succeeds");

    let err = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["auditor"]),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                candidate,
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("mismatched principal roles should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_transport_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(ContextBoundConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-authz-transport").expect("key");
    let candidate = ContextBoundConfig::new("next").with_authz(
        "config-admin",
        TransportType::Internal,
        RequestSource::Northbound,
    );

    let first = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["config-admin"]),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                candidate.clone(),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("authorized commit succeeds");

    let err = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["config-admin"]),
                TransportType::RestconfHttps,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                candidate,
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("mismatched transport should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_source_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(ContextBoundConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-authz-source").expect("key");
    let candidate = ContextBoundConfig::new("next").with_authz(
        "config-admin",
        TransportType::Internal,
        RequestSource::Northbound,
    );

    let first = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["config-admin"]),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                candidate.clone(),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("authorized commit succeeds");

    let err = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal_with_roles(["config-admin"]),
                TransportType::Internal,
                RequestSource::Internal,
                ConfigOperation::Replace,
                candidate,
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("mismatched source should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, first.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_different_commit_payload() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-1").expect("key");

    bus.submit(
        commit_request("next", Instant::now() + Duration::from_secs(1))
            .with_idempotency_key(key.clone()),
    )
    .await
    .expect("first commit succeeds");

    let err = bus
        .submit(
            commit_request("different", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key),
        )
        .await
        .expect_err("different payload should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_different_request_mode() {
    let store = Arc::new(MockManagedDatastore::new());
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::INITIAL,
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-1").expect("key");

    bus.submit(
        commit_request("next", Instant::now() + Duration::from_secs(1))
            .with_idempotency_key(key.clone()),
    )
    .await
    .expect("first commit succeeds");

    let err = bus
        .submit(
            CommitRequest::rollback(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                RollbackTarget::Version(ConfigVersion::INITIAL),
                vec![changed_path(), domain_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("different mode should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    assert_eq!(store.history().await.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_rejects_duplicate_claim_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-dup-claims").expect("key");
    let first_principal = principal_with_roles_and_groups(["admin", "admin"], ["ops"]);
    let second_principal = principal_with_roles_and_groups(["admin"], ["ops"]);

    bus.submit(
        CommitRequest::commit(
            RequestId::new(),
            first_principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("next"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        )
        .with_idempotency_key(key.clone()),
    )
    .await
    .expect("first commit succeeds");

    let err = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                second_principal,
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("duplicate claim collapse should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_idempotency_key_ignores_caller_changed_path_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("req-1").expect("key");

    bus.submit(
        commit_request("next", Instant::now() + Duration::from_secs(1))
            .with_idempotency_key(key.clone()),
    )
    .await
    .expect("first commit succeeds");

    let result = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("next"),
                vec![domain_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect("caller-supplied changed path mismatch is ignored");

    assert_eq!(result.status, opc_config_model::CommitStatus::Committed);
    assert_eq!(result.changed_paths, vec![changed_path()]);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(store.history().await.len(), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_idempotent_replay_uses_persisted_base_version() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup");

    let id_key = IdempotencyKey::new("id-key-exact-base").unwrap();

    let req1 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone());
    let res1 = bus.submit(req1).await.expect("first commit");
    assert_eq!(res1.base_version, ConfigVersion::INITIAL);
    assert_eq!(res1.new_version, Some(ConfigVersion::new(1)));

    let req2 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone());
    let res2 = bus.submit(req2).await.expect("second commit (replay)");
    assert_eq!(res2.base_version, ConfigVersion::INITIAL);
    assert_eq!(res2.new_version, Some(ConfigVersion::new(1)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_idempotent_replay_legacy_fallback() {
    let store = Arc::new(MockManagedDatastore::new());
    let stored_version = ConfigVersion::new(3);
    let expected_base = ConfigVersion::new(2);
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        stored_version,
        principal(),
        RequestSource::Northbound,
        TestConfig::new("idempotent"),
    );
    let id_key = IdempotencyKey::new("id-key-legacy-replay").unwrap();
    stored.idempotency_key = Some(id_key.clone());
    stored.request_fingerprint = Some(opc_config_bus::StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: opc_config_bus::StoredRequestMode::Commit,
        transport: TransportType::Internal,
        changed_paths: vec![changed_path()],
        base_version: None,
    });
    store.seed(stored).await;

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("restore");

    let req = commit_request("idempotent", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key);
    let res = bus.submit(req).await.expect("replay commit");

    assert_eq!(res.base_version, expected_base);
    assert_eq!(res.new_version, Some(stored_version));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotency_lookup_failures_surface_state_machine_fault() {
    let secret = "dsn=postgres://user:secret@db/internal";
    let bus = ConfigBus::new_dev_only(
        TestConfig::new("initial"),
        Arc::new(ErrorStore::idempotency_lookup_fails(secret)),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(IdempotencyKey::new("lookup-failure").expect("key")),
        )
        .await
        .expect_err("lookup error should surface to caller");

    assert_eq!(err.code, CommitErrorCode::StateMachineFault);
    assert_eq!(err.message, "idempotency key lookup failed");
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
}
