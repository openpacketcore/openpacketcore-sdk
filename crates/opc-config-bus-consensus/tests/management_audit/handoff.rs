//! A protocol Intent and its encrypted configuration effect need one authority.
use super::*;
use opc_persist::audit_authority::{AuditAdmission, AuditCaller, AuditOperationState};
use opc_persist::{
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standalone_protocol_intent_cannot_authorize_a_different_configuration_effect() {
    let checkpoints = Arc::new(checkpoint::CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints)).await;
    let store = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
    store
        .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(30, 10).unwrap())
        .await
        .unwrap();
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&store), Arc::clone(&privacy));
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .unwrap();
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .unwrap();
    let request_id = RequestId::new();
    let principal = principal();
    let descriptor = opc_mgmt_audit::principal_descriptor(&principal);
    let caller =
        AuditCaller::project(privacy.as_ref(), principal.tenant.as_str(), &descriptor).unwrap();
    let time = opc_mgmt_audit::AuditInstant::now();
    let event = ManagementAuditEventRecord::try_new(
        *request_id.as_uuid().as_bytes(),
        ManagementAuditInstant::try_new(
            time.utc_seconds(),
            time.nanosecond(),
            time.monotonic_sequence(),
            ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        principal.tenant.as_str(),
        descriptor,
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Replace,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/test:system/test:name"],
        None::<&str>,
    )
    .unwrap();
    assert!(store
        .prepare_audit_observation(privacy.as_ref(), &event, Duration::from_secs(60))
        .is_err());
    let handle = store
        .prepare_audit_intent(
            privacy.as_ref(),
            &event,
            bus.version(),
            b"protocol-replace",
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(
        matches!(store.admit_audit_operation_local(&handle, caller).await,
        AuditAdmission::Applied(receipt) if receipt.state() == AuditOperationState::Intent)
    );
    let request = |request_id| {
        CommitRequest::commit(
            request_id,
            principal.clone(),
            TransportType::Gnmi,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig {
                name: "revision-2".into(),
            },
            vec![YangPath::new("/system/name").unwrap()],
            Instant::now() + Duration::from_secs(5),
        )
        .with_base_version(ConfigVersion::new(1))
    };
    let result = bus.submit(request(request_id)).await;
    if result.is_err() {
        assert_eq!(bus.version(), ConfigVersion::new(1));
        assert_eq!(
            store
                .lookup_audit_operation(&handle, caller)
                .await
                .unwrap()
                .unwrap()
                .state(),
            AuditOperationState::Intent
        );
        let duplicate = store
            .prepare_audit_intent(
                privacy.as_ref(),
                &event,
                bus.version(),
                b"protocol-replace",
                Duration::from_secs(60),
            )
            .unwrap();
        assert!(matches!(
            store.admit_audit_operation_local(&duplicate, caller).await,
            AuditAdmission::Rejected(
                opc_persist::audit_authority::AuditAuthorityError::BindingMismatch
            )
        ));
        bus.submit(request(RequestId::new()))
            .await
            .expect("identical fresh-ID control");
    }
    cluster.shutdown().await;
    result.expect_err("a standalone intent must never authorize a configuration effect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_intent_hands_off_to_the_same_required_configuration_request() {
    let checkpoints = Arc::new(checkpoint::CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
    let store = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
    store
        .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(30, 10).unwrap())
        .await
        .unwrap();
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&store), privacy);
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .unwrap();
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        source.clone(),
    )
    .await
    .unwrap();
    let audit = bus
        .required_config_audit()
        .expect("required encrypted datastore capability");
    assert!(audit.belongs_to(&bus.clone()));
    let request = checkpoint::next_checkpointed_request();
    let request_id = request.request_id;
    let event = opc_mgmt_audit::AuditEvent::new(
        request_id,
        &request.principal,
        request.transport,
        opc_mgmt_audit::AuditOperation::Replace,
        opc_mgmt_audit::AuditOutcome::Intent,
    )
    .with_paths([opc_mgmt_audit::SchemaNodePath::new("/test:system/test:name").unwrap()]);
    // The observation port cannot silently acknowledge the required Intent.
    audit
        .observation_sink()
        .record_async(&event)
        .await
        .expect_err("Intent needs an effect");
    let mut wrong_request = event.clone();
    wrong_request.request_id = RequestId::new();
    let mut wrong_caller = event.clone();
    wrong_caller.principal = "foreign-private-principal".into();
    let mut wrong_tenant = event.clone();
    wrong_tenant.tenant = "foreign-private-tenant".into();
    let mut wrong_transport = event.clone();
    wrong_transport.transport = TransportType::Internal;
    let mut wrong_operation = event.clone();
    wrong_operation.operation = opc_mgmt_audit::AuditOperation::Delete;
    let mut wrong_outcome = event.clone();
    wrong_outcome.outcome = opc_mgmt_audit::AuditOutcome::Success;
    for mismatched in [
        wrong_request,
        wrong_caller,
        wrong_tenant,
        wrong_transport,
        wrong_operation,
        wrong_outcome,
    ] {
        let error = audit
            .submit(request.clone(), mismatched)
            .await
            .expect_err("foreign event cannot be handed off");
        assert_eq!(
            error.code,
            opc_config_model::CommitErrorCode::AdmissionRejected
        );
        assert!(!format!("{error:?}").contains("private"));
    }
    assert_eq!(checkpoints.sequence(), 3);
    let original = request.clone();
    let committed = audit
        .submit(request, event.clone())
        .await
        .expect("protocol intent must hand off to the same required configuration operation");
    assert_eq!(committed.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(checkpoints.sequence(), 6);
    let stored = source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.request_id, Some(request_id));
    assert_eq!(stored.tx_id, committed.tx_id);
    audit
        .submit(original, event.clone())
        .await
        .expect_err("stale duplicate cannot apply twice");
    assert_eq!(checkpoints.sequence(), 6);
    let stale = checkpoint::next_checkpointed_request();
    let mut stale_event = event;
    stale_event.request_id = stale.request_id;
    audit
        .submit(stale, stale_event)
        .await
        .expect_err("stale base is refused");
    assert_eq!(
        checkpoints.sequence(),
        7,
        "stale-base refusal remains an observation"
    );
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(
        store
            .reconcile_audit_obligations(10)
            .await
            .unwrap()
            .inspected,
        0
    );
    cluster.shutdown().await;
}
