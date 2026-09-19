//! A protocol Intent and its encrypted configuration effect need one authority.
use super::*;
use opc_persist::audit_authority::{AuditAdmission, AuditCaller, AuditOperationState};
use opc_persist::{
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_intent_hands_off_to_the_same_required_configuration_request() {
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
        TestConfig { name: "initial".into() },
        Arc::clone(&source),
    )
    .await
    .unwrap();
    let request_id = RequestId::new();
    let principal = principal();
    let descriptor = opc_mgmt_audit::principal_descriptor(&principal);
    let caller = AuditCaller::project(privacy.as_ref(), principal.tenant.as_str(), &descriptor)
        .unwrap();
    let time = opc_mgmt_audit::AuditInstant::now();
    let event = ManagementAuditEventRecord::try_new(
        *request_id.as_uuid().as_bytes(),
        ManagementAuditInstant::try_new(time.utc_seconds(), time.nanosecond(),
            time.monotonic_sequence(), ManagementAuditTimeSourceCode::NodeClock).unwrap(),
        principal.tenant.as_str(), descriptor, ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Replace, ManagementAuditOutcomeCode::Intent,
        None::<&str>, ["/system/name"], None::<&str>,
    ).unwrap();
    assert!(store.prepare_audit_observation(privacy.as_ref(), &event,
        Duration::from_secs(60)).is_err());
    let handle = store.prepare_audit_intent(privacy.as_ref(), &event, bus.version(),
        b"protocol-replace", Duration::from_secs(60)).unwrap();
    assert!(matches!(store.admit_audit_operation_local(&handle, caller).await,
        AuditAdmission::Applied(receipt) if receipt.state() == AuditOperationState::Intent));
    let request = |request_id| CommitRequest::commit(
        request_id, principal.clone(), TransportType::Gnmi, RequestSource::Northbound,
        ConfigOperation::Replace, TestConfig { name: "revision-2".into() },
        vec![YangPath::new("/system/name").unwrap()],
        Instant::now() + Duration::from_secs(5),
    ).with_base_version(ConfigVersion::new(1));
    let result = bus.submit(request(request_id)).await;
    if result.is_err() {
        assert_eq!(bus.version(), ConfigVersion::new(1));
        assert_eq!(store.lookup_audit_operation(&handle, caller).await.unwrap().unwrap().state(),
            AuditOperationState::Intent);
        let duplicate = store.prepare_audit_intent(privacy.as_ref(), &event, bus.version(),
            b"protocol-replace", Duration::from_secs(60)).unwrap();
        assert!(matches!(store.admit_audit_operation_local(&duplicate, caller).await,
            AuditAdmission::Rejected(opc_persist::audit_authority::AuditAuthorityError::BindingMismatch)));
        bus.submit(request(RequestId::new())).await.expect("identical fresh-ID control");
    }
    cluster.shutdown().await;
    result.expect("protocol intent must hand off to the same required configuration operation");
}
