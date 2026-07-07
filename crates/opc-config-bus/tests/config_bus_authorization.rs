#![allow(unused_imports)]
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{
    AuthorizationContext, AuthorizationError, ConfigAuthorizer, ConfigBus, StoredConfig,
};
use opc_config_model::{
    CommitErrorCode, CommitMode, CommitRequest, ConfigOperation, IdempotencyKey, OpcConfig,
    RequestId, RequestSource, RollbackTarget, TransportType,
};
use opc_types::{ConfigVersion, TenantId};

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authorization_seam() {
    #[derive(Debug)]
    struct DenyAuth;
    #[async_trait::async_trait]
    impl ConfigAuthorizer for DenyAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            Err(AuthorizationError::new(
                "secret policy details: principal lacks privilege X",
            ))
        }
    }

    #[derive(Debug, Clone)]
    struct CaptureAuth {
        calls: Arc<Mutex<Vec<AuthorizationContext>>>,
    }
    #[async_trait::async_trait]
    impl ConfigAuthorizer for CaptureAuth {
        async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            self.calls.lock().unwrap().push(ctx.clone());
            Ok(())
        }
    }

    let store_allow = Arc::new(MockManagedDatastore::new());

    let bus_allow = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store_allow))
        .await
        .expect("startup");
    let res = bus_allow
        .submit(commit_request(
            "allow-1",
            Instant::now() + Duration::from_secs(1),
        ))
        .await;
    assert!(res.is_ok(), "default allow-all authorizer must succeed");

    let bad_config = TestConfig::panic_on_validate("panics");
    let store_deny = Arc::new(MockManagedDatastore::new());
    let bus_deny = ConfigBus::new(
        TestConfig::new("initial"),
        Arc::clone(&store_deny),
        Arc::new(DenyAuth),
    )
    .await
    .expect("startup");

    let sub = bus_deny.subscribe(SubscriberLagPolicy::DropOldest, 4);

    let submit_req = CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        bad_config,
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    );

    let res_deny = bus_deny.submit(submit_req).await;

    let err = res_deny.expect_err("deny authorizer must reject commit");
    assert_eq!(err.code, CommitErrorCode::AuthorizationDenied);
    assert_eq!(err.message, "authorization denied");

    assert_eq!(bus_deny.load().name, "initial");

    assert_eq!(store_deny.history().await.len(), 0);

    assert!(sub.try_recv().is_none());

    let validate_req = CommitRequest::validate_only(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        TestConfig::new("validate"),
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    );
    let res_val = bus_deny.submit(validate_req).await;
    let err_val = res_val.expect_err("validate-only request must be denied");
    assert_eq!(err_val.code, CommitErrorCode::AuthorizationDenied);
    assert_eq!(err_val.message, "authorization denied");

    let rollback_req = CommitRequest::rollback(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        RollbackTarget::Version(ConfigVersion::INITIAL),
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    );
    let res_roll = bus_deny.submit(rollback_req).await;
    let err_roll = res_roll.expect_err("rollback request must be denied");
    assert_eq!(err_roll.code, CommitErrorCode::AuthorizationDenied);
    assert_eq!(err_roll.message, "authorization denied");

    let calls = Arc::new(Mutex::new(Vec::new()));
    let capture_auth = CaptureAuth {
        calls: calls.clone(),
    };
    let store_capture = Arc::new(MockManagedDatastore::new());
    let bus_capture = ConfigBus::new(
        TestConfig::new("initial"),
        Arc::clone(&store_capture),
        Arc::new(capture_auth),
    )
    .await
    .expect("startup");

    let req_id = RequestId::new();
    let cap_req = CommitRequest::commit(
        req_id,
        principal().with_roles(["operator"]),
        TransportType::RestconfHttps,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        TestConfig::new("capture"),
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    );

    bus_capture.submit(cap_req).await.expect("submit succeeds");

    let captured = calls.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let ctx = &captured[0];
    assert_eq!(ctx.principal.roles, vec!["operator".to_string()]);
    assert_eq!(ctx.transport, TransportType::RestconfHttps);
    assert_eq!(ctx.source, RequestSource::Northbound);
    assert_eq!(ctx.operation, ConfigOperation::Replace);
    assert!(matches!(ctx.mode, CommitMode::Commit));
    assert_eq!(ctx.changed_paths, vec![changed_path()]);
    assert_eq!(ctx.running_version, ConfigVersion::INITIAL);
    assert_eq!(ctx.request_id, req_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorizer_uses_computed_paths_not_request_paths() {
    #[derive(Debug)]
    struct DenyHostnameAuth {
        seen_paths: Arc<Mutex<Vec<Vec<YangPath>>>>,
    }

    #[async_trait::async_trait]
    impl ConfigAuthorizer for DenyHostnameAuth {
        async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            self.seen_paths
                .lock()
                .expect("seen paths mutex poisoned")
                .push(ctx.changed_paths.clone());
            if ctx.changed_paths == vec![changed_path()] {
                Err(AuthorizationError::new("hostname denied"))
            } else {
                Ok(())
            }
        }
    }

    let seen_paths = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new(
        TestConfig::new("initial"),
        Arc::clone(&store),
        Arc::new(DenyHostnameAuth {
            seen_paths: Arc::clone(&seen_paths),
        }),
    )
    .await
    .expect("startup");

    let err = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("changed"),
            Vec::new(),
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("computed hostname path must be denied");

    assert_eq!(err.code, CommitErrorCode::AuthorizationDenied);
    assert_eq!(
        seen_paths
            .lock()
            .expect("seen paths mutex poisoned")
            .as_slice(),
        &[vec![changed_path()]]
    );
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_noop_commit_with_empty_computed_paths_is_rejected_before_authorizer() {
    #[derive(Clone)]
    struct EmptyPathMutationConfig {
        name: String,
    }

    impl EmptyPathMutationConfig {
        fn new(name: impl Into<String>) -> Self {
            Self { name: name.into() }
        }
    }

    impl OpcConfig for EmptyPathMutationConfig {
        type Delta = String;

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("digest")
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            if self.name == previous.name {
                Ok(Vec::new())
            } else {
                Ok(vec![format!("changed:{}", self.name)])
            }
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
            self.name = delta;
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<EmptyPathMutationConfig>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    struct CountAuth {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConfigAuthorizer for CountAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let store = Arc::new(MockManagedDatastore::new());
    let auth = Arc::new(CountAuth {
        calls: AtomicUsize::new(0),
    });
    let bus = ConfigBus::new(
        EmptyPathMutationConfig::new("initial"),
        Arc::clone(&store),
        auth.clone(),
    )
    .await
    .expect("startup");

    let err = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            EmptyPathMutationConfig::new("changed"),
            Vec::new(),
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("non-noop with empty changed paths must fail closed");

    assert_eq!(err.code, CommitErrorCode::DiffFailed);
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authorizer_idempotency() {
    let store = Arc::new(MockManagedDatastore::new());

    struct CountAuth {
        count: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl ConfigAuthorizer for CountAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let auth = Arc::new(CountAuth {
        count: AtomicUsize::new(0),
    });
    let bus = ConfigBus::new(TestConfig::new("initial"), Arc::clone(&store), auth.clone())
        .await
        .expect("startup");

    let id_key = IdempotencyKey::new("id-key-authz").unwrap();

    let req1 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone());
    let res1 = bus.submit(req1).await;
    assert!(res1.is_ok());
    assert_eq!(auth.count.load(Ordering::SeqCst), 1);

    let req2 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone());
    let res2 = bus.submit(req2).await;
    assert!(res2.is_ok());
    assert_eq!(auth.count.load(Ordering::SeqCst), 2);

    let req3 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone())
        .with_base_version(ConfigVersion::INITIAL);
    let mut req3 = req3;
    req3.principal = principal_with_roles(["different-role"]);

    let res3 = bus.submit(req3).await;
    let err3 = res3.expect_err("mismatched principal must be rejected");
    assert_eq!(err3.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err3.message,
        "idempotency key is already bound to a different commit request"
    );
    assert_eq!(auth.count.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authorizer_idempotency_denied() {
    let store = Arc::new(MockManagedDatastore::new());

    struct PolicyChangingAuth {
        allow: AtomicBool,
    }
    #[async_trait::async_trait]
    impl ConfigAuthorizer for PolicyChangingAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            if self.allow.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(AuthorizationError::new("policy denied"))
            }
        }
    }

    let auth = Arc::new(PolicyChangingAuth {
        allow: AtomicBool::new(false),
    });
    let bus = ConfigBus::new(TestConfig::new("initial"), Arc::clone(&store), auth.clone())
        .await
        .expect("startup");

    let id_key = IdempotencyKey::new("id-key-policy").unwrap();
    let req1 = commit_request("val1", Instant::now() + Duration::from_secs(1))
        .with_idempotency_key(id_key.clone());

    let res1 = bus.submit(req1.clone()).await;
    assert_eq!(res1.unwrap_err().code, CommitErrorCode::AuthorizationDenied);

    let res2 = bus.submit(req1.clone()).await;
    assert_eq!(res2.unwrap_err().code, CommitErrorCode::AuthorizationDenied);

    auth.allow.store(true, Ordering::SeqCst);
    let res3 = bus.submit(req1.clone()).await;
    assert!(res3.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authorization_failure_alarm() {
    #[derive(Debug)]
    struct DenyAuth;
    #[async_trait::async_trait]
    impl ConfigAuthorizer for DenyAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            Err(AuthorizationError::new("unauthorized"))
        }
    }

    let store = Arc::new(MockManagedDatastore::new());
    let alarm_manager = SharedAlarmManager::default();

    let bus = ConfigBus::new_with_alarm_manager(
        TestConfig::new("initial"),
        Arc::clone(&store),
        Arc::new(DenyAuth),
        alarm_manager.clone(),
    )
    .await
    .expect("startup");

    let req = commit_request("alarm", Instant::now() + Duration::from_secs(1));
    let res = bus.submit(req).await;
    assert_eq!(res.unwrap_err().code, CommitErrorCode::AuthorizationDenied);

    let alarm = wait_for_single_active_alarm(&alarm_manager, "config-bus.commit.failure").await;
    assert_alarm_details_code(&alarm, "authorization_denied");
}

#[tokio::test]
async fn test_production_constructor_requires_authorizer() {
    struct CustomAuth;
    #[async_trait::async_trait]
    impl ConfigAuthorizer for CustomAuth {
        async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            Ok(())
        }
    }

    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new(
        TestConfig::new("initial"),
        Arc::clone(&store),
        Arc::new(CustomAuth),
    )
    .await;
    assert!(bus.is_ok());

    let bus_restore = ConfigBus::restore_or_new(
        TestConfig::new("initial"),
        Arc::clone(&store),
        Arc::new(CustomAuth),
    )
    .await;
    assert!(bus_restore.is_ok());
}
