//! Strict retained reopening of the actual NETCONF encrypted effect owner.
//! This covers orderly owner replacement, not process-crash or quorum failover.

use super::*;
use opc_config_bus::{AuthorizationContext, AuthorizationError, ConfigAuthorizer};
use opc_persist::{
    ConfigConsensusOpenError, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};

fn topology() -> ConfigConsensusTopology {
    let node = ConfigConsensusNodeId::new(1).unwrap();
    ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("netconf-required-audit-fixture").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        ),
        node,
        BTreeSet::from([node]),
    )
    .unwrap()
}

async fn open_authority(
    directory: &std::path::Path,
    checkpoints: Arc<Checkpoints>,
    provision: bool,
) -> Result<ConsensusConfigStore, ConfigConsensusOpenError> {
    let options = RetainedConfigOptions::new(
        directory.join("config.sqlite"),
        RetainedConfigBinding::new(topology(), [0x72; 32], [0x73; 32]).unwrap(),
        RetainedConfigDurability::Durable {
            min_free_bytes: 16 * 1024 * 1024,
        },
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    let key = AuditKey::new([0x71; 32]).unwrap();
    let backend = if provision {
        SqliteBackend::provision_config_authority(options, key).await
    } else {
        // No create/repair fallback: keep the exact retained authority.
        SqliteBackend::reopen_config_authority(options, key).await
    }
    .unwrap();
    ConsensusConfigStore::open_with_audit_continuity(
        topology(),
        backend,
        directory.join("snapshots"),
        BTreeMap::new(),
        AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap(),
            checkpoints,
            1,
            1,
        )
        .unwrap(),
    )
    .await
}

// Development-only authorization, matching Harness::start. The drop notice
// proves the sequenced worker released its final owner before strict reopening;
// no sleep or new shutdown API is needed to guess at that lifetime.
struct WorkerLifetime(Arc<tokio::sync::Notify>);

#[async_trait::async_trait]
impl ConfigAuthorizer for WorkerLifetime {
    async fn authorize(&self, _: &AuthorizationContext) -> Result<(), AuthorizationError> {
        Ok(())
    }
}

impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

async fn open_harness(
    directory: tempfile::TempDir,
    checkpoints: Arc<Checkpoints>,
    provision: bool,
) -> (Harness, Arc<tokio::sync::Notify>) {
    let authority = Arc::new(
        open_authority(directory.path(), checkpoints.clone(), provision)
            .await
            .unwrap(),
    );
    authority.initialize_cluster().await.unwrap();
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
    if provision {
        authority
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(90, 30).unwrap())
            .await
            .unwrap();
    }
    authority.probe_durable_readiness().await.unwrap();
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("netconf-fixture-key").unwrap(),
            KeyPurpose::Config,
            principal().tenant,
            Zeroizing::new([0x6b; AES_256_GCM_SIV_KEY_LEN]),
        )
        .unwrap();
    let source = Arc::new(EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::new_audited_local_authority(
            authority.clone(),
            ConfigAuditPolicy::new(privacy, Duration::from_secs(60)).unwrap(),
        )),
        provider,
    ));
    let initial = DemoConfig {
        hostname: "fixture-initial".into(),
        secret: "synthetic-secret".into(),
    };
    if provision {
        source
            .append_commit(StoredConfig::new(
                opc_types::TxId::new(),
                ConfigVersion::new(1),
                principal(),
                RequestSource::Internal,
                initial.clone(),
            ))
            .await
            .unwrap();
    }
    let stopped = Arc::new(tokio::sync::Notify::new());
    let bus = Arc::new(
        ConfigBus::restore_or_new(
            initial,
            source.clone(),
            Arc::new(WorkerLifetime(stopped.clone())),
        )
        .await
        .unwrap(),
    );
    (
        Harness {
            _directory: directory,
            authority,
            source,
            bus,
            checkpoints,
        },
        stopped,
    )
}

async fn close_harness(
    h: Harness,
    stopped: Arc<tokio::sync::Notify>,
) -> (tempfile::TempDir, Arc<Checkpoints>) {
    let Harness {
        _directory: directory,
        authority,
        source,
        bus,
        checkpoints,
    } = h;
    drop(bus);
    tokio::time::timeout(Duration::from_secs(5), stopped.notified())
        .await
        .unwrap();
    drop(source);
    authority.shutdown().await.unwrap();
    drop(authority);
    (directory, checkpoints)
}

fn edit(hostname: &str) -> String {
    edit_config_rpc_to(
        "running",
        &format!(
            r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{hostname}</sys:hostname></sys:system>"#
        ),
        "merge",
    )
}

#[tokio::test]
async fn required_running_commit_and_terminal_fence_survive_retained_reopen() {
    let (h, stopped) = open_harness(
        tempfile::tempdir().unwrap(),
        Arc::new(Checkpoints::default()),
        true,
    )
    .await;
    let original_request = RequestId::new();
    h.checkpoints.refuse_from.store(6, Ordering::Release);
    let server = running::required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    let reply = server
        .handle_rpc_for_session_async(
            original_request,
            &principal(),
            &edit("fixture-retained"),
            &MgmtLimits::default(),
            1,
            &sessions,
        )
        .await;
    assert!(reply.reply_xml.contains("<ok/>"));
    let committed = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(committed.version, ConfigVersion::new(2));
    assert!(
        committed.request_id == Some(original_request),
        "retained effect changed request"
    );
    assert_eq!(h.checkpoints.sequence(), 4);
    drop(registration);
    drop(server);
    let (directory, checkpoints) = close_harness(h, stopped).await;

    // The independent checkpoint retains the original reservation and remains
    // unavailable for completion throughout reopening and a later write.
    let (h, stopped) = open_harness(directory, checkpoints, false).await;
    let exact = h
        .bus
        .resolve_request_id(original_request)
        .await
        .unwrap()
        .unwrap();
    assert!(exact.tx_id == committed.tx_id, "reopen changed transaction");
    assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
    let server = running::required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(2).unwrap();
    let later_request = RequestId::new();
    let refused = server
        .handle_rpc_for_session_async(
            later_request,
            &principal(),
            &edit("fixture-later"),
            &MgmtLimits::default(),
            2,
            &sessions,
        )
        .await;
    assert!(refused.reply_xml.contains("operation-failed"));
    assert!(h
        .bus
        .resolve_request_id(later_request)
        .await
        .unwrap()
        .is_none());
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert!(
        latest.tx_id == committed.tx_id,
        "reopen lost the write fence"
    );
    assert_eq!(latest.config.hostname, "fixture-retained");
    let debt = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!((debt.completed, debt.pending, debt.unknown), (0, 0, 1));

    h.checkpoints.refuse_from.store(0, Ordering::Release);
    let recovered = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(h.checkpoints.sequence(), 6);
    let exact = h
        .bus
        .resolve_request_id(original_request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == committed.tx_id,
        "recovery changed transaction"
    );
    let permitted = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &edit("fixture-after-recovery"),
            &MgmtLimits::default(),
            2,
            &sessions,
        )
        .await;
    assert!(permitted.reply_xml.contains("<ok/>"));
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(latest.version, ConfigVersion::new(3));
    assert_eq!(latest.config.hostname, "fixture-after-recovery");
    assert!(
        latest.tx_id != committed.tx_id,
        "later write reused recovery"
    );
    assert_eq!(h.checkpoints.sequence(), 9);
    drop(registration);
    drop(server);
    close_harness(h, stopped).await;
}

#[tokio::test]
async fn ambiguous_checkpointed_intent_blocks_reopen_without_a_configuration_effect() {
    let (h, stopped) = open_harness(
        tempfile::tempdir().unwrap(),
        Arc::new(Checkpoints::default()),
        true,
    )
    .await;
    h.checkpoints.unknown_from.store(4, Ordering::Release);
    let server = running::required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    let request_id = RequestId::new();
    let refused = server
        .handle_rpc_for_session_async(
            request_id,
            &principal(),
            &edit("fixture-unadmitted"),
            &MgmtLimits::default(),
            1,
            &sessions,
        )
        .await;
    assert!(refused.reply_xml.contains("operation-failed"));
    h.checkpoints
        .readback_unavailable
        .store(false, Ordering::Release);
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(latest.version, ConfigVersion::new(1));
    assert_eq!(latest.config.hostname, "fixture-initial");
    assert!(h
        .bus
        .resolve_request_id(request_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(h.checkpoints.sequence(), 4);
    drop(registration);
    drop(server);
    let (directory, checkpoints) = close_harness(h, stopped).await;
    checkpoints.unknown_from.store(0, Ordering::Release);
    // Preserve #925: a new owner cannot tell an unsubmitted effect from a
    // checkpointed intent whose commit suffix was rolled back. Reopening must
    // fail closed, never reject that possible commit or initialize new history.
    let reopened = open_authority(directory.path(), checkpoints.clone(), false).await;
    let refused = matches!(
        &reopened,
        Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
    );
    if let Ok(unprotected) = reopened {
        unprotected.shutdown().await.unwrap();
    }
    assert!(refused, "ambiguous retained intent permitted reopening");
    assert_eq!(checkpoints.sequence(), 4);
}
