//! SDK #958: real encrypted configuration and replicated audit authority.
//! No successful AuditSink is supplied by this fixture.
use super::*;
use opc_config_bus::ManagedDatastore;
use opc_config_bus_consensus::{ConfigAuditPolicy, RaftManagedDatastore};
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditContinuityPolicy,
    AuditKeyRing, AuditSigningKey,
};
use opc_persist::audit_authority::{AuditAuthorityError, AuditLedgerLimits, AuditPrivacyKey};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConsensusConfigStore, SqliteBackend,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64};

// Separately owned synthetic monotonic checkpoint authority. This is not a
// production provider and carries no configuration signing material.
#[derive(Default)]
struct Checkpoints {
    value: Mutex<Option<AuditCheckpoint>>,
    refuse_from: AtomicU64,
    unknown_from: AtomicU64,
    readback_unavailable: AtomicBool,
}

#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoints {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if self.readback_unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(self.value.lock().unwrap().clone())
    }

    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let refuse_from = self.refuse_from.load(Ordering::Acquire);
        if refuse_from != 0 && next.sequence() >= refuse_from {
            return Err(AuditAuthorityError::Unavailable);
        }
        let mut current = self.value.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        let unknown_from = self.unknown_from.load(Ordering::Acquire);
        let unknown = unknown_from != 0 && next.sequence() >= unknown_from;
        *current = Some(next);
        if unknown {
            // The exact CAS applied but its acknowledgement and independent
            // readback are unavailable. This is not a definitive rejection.
            self.readback_unavailable.store(true, Ordering::Release);
            Ok(AuditCheckpointAdvance::Unknown)
        } else {
            Ok(AuditCheckpointAdvance::Applied)
        }
    }
}

impl Checkpoints {
    fn sequence(&self) -> u64 {
        self.value.lock().unwrap().as_ref().unwrap().sequence()
    }
}

fn exact_replace(request_id: RequestId, version: u64) -> (CommitRequest<DemoConfig>, AuditEvent) {
    let request = CommitRequest::commit(
        request_id,
        principal(),
        TransportType::NetconfTls,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        DemoConfig {
            hostname: "fixture-control".into(),
            secret: "synthetic-secret".into(),
        },
        Vec::new(),
        Instant::now() + Duration::from_secs(30),
    )
    .with_base_version(ConfigVersion::new(version));
    let intent = AuditEvent::new(
        request_id,
        &principal(),
        TransportType::NetconfTls,
        AuditOperation::Replace,
        AuditOutcome::Intent,
    );
    (request, intent)
}

type Source =
    EncryptingManagedDatastore<DemoConfig, MemoryKeyProvider, RaftManagedDatastore<DemoConfig>>;
type Server =
    ReadOnlyNetconfServer<DemoConfig, GeneratedEditBinding, FixedPolicy, Arc<dyn AuditSink>>;

struct Harness {
    _directory: tempfile::TempDir,
    authority: Arc<ConsensusConfigStore>,
    source: Arc<Source>,
    bus: Arc<ConfigBus<DemoConfig>>,
    checkpoints: Arc<Checkpoints>,
}

impl Harness {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = ConfigConsensusNodeId::new(1).unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("netconf-required-audit-fixture").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join("config.sqlite"),
            true,
            0,
            AuditKey::new([0x71; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoints = Arc::new(Checkpoints::default());
        let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap();
        let authority = Arc::new(
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                directory.path().join("snapshots"),
                BTreeMap::new(),
                AuditContinuityPolicy::new(keys, checkpoints.clone(), 1, 1).unwrap(),
            )
            .await
            .unwrap(),
        );
        authority.initialize_cluster().await.unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
        authority
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(90, 30).unwrap())
            .await
            .unwrap();
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
        let bus = Arc::new(
            ConfigBus::restore_or_new_dev_only(initial, source.clone())
                .await
                .unwrap(),
        );
        assert_eq!(checkpoints.sequence(), 3);
        Self {
            _directory: directory,
            authority,
            source,
            bus,
            checkpoints,
        }
    }

    fn server(&self) -> Server {
        self.server_with_startup(None)
    }

    fn server_with_startup(&self, startup: Option<Arc<MemoryStartupDatastore>>) -> Server {
        let audit = self.bus.required_config_audit().unwrap();
        ReadOnlyNetconfServer::new(
            GeneratedEditBinding {
                bus: self.bus.clone(),
                startup,
            },
            FixedPolicy(policy_allow_system_with_secret_writes()),
            audit.observation_sink(),
            TransportType::NetconfTls,
        )
        .unwrap()
    }

    async fn shutdown(self) {
        drop(self.bus);
        drop(self.source);
        self.authority.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn replicated_observations_alone_cannot_enable_advertised_netconf_mutations() {
    let h = Harness::start().await;
    let edit = r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-edited</sys:hostname></sys:system>"#;
    let rpcs = [
        edit_config_rpc_to("running", edit, "merge"),
        edit_data_rpc("running", edit, "merge"),
        edit_config_rpc_to("candidate", edit, "merge"),
        edit_data_rpc("candidate", edit, "merge"),
        edit_config_rpc_to("startup", edit, "merge"),
        edit_data_rpc("startup", edit, "merge"),
        copy_config_rpc("running", "candidate"),
        copy_config_rpc("candidate", "running"),
        copy_config_rpc("startup", "running"),
        discard_changes_rpc(),
        delete_config_rpc("startup"),
        commit_rpc(),
        confirmed_commit_rpc(30),
    ];
    for (index, rpc) in rpcs.into_iter().enumerate() {
        let initial = DemoConfig {
            hostname: "fixture-startup".into(),
            secret: "synthetic-secret".into(),
        };
        let startup = Arc::new(MemoryStartupDatastore::new(Some(initial.clone()), true));
        let server = h.server_with_startup(Some(startup.clone()));
        // Establish only the local fixture precondition. This is not evidence
        // that a candidate can be staged through the required protocol path.
        server.candidate.lock().unwrap().replace(
            DemoConfig {
                hostname: "fixture-staged".into(),
                secret: "synthetic-secret".into(),
            },
            ConfigVersion::new(1),
        );
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(1).unwrap();
        let reply = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &rpc,
                &MgmtLimits::default(),
                1,
                &sessions,
            )
            .await;
        assert!(
            reply
                .reply_xml
                .contains("<error-tag>operation-failed</error-tag>"),
            "mutation case {index}: {}",
            reply.reply_xml
        );
        assert_eq!(h.checkpoints.sequence(), 3, "mutation case {index}");
        assert_eq!(
            server
                .candidate
                .lock()
                .unwrap()
                .snapshot()
                .unwrap()
                .config
                .hostname,
            "fixture-staged",
            "mutation case {index}"
        );
        assert_eq!(startup.current().unwrap().hostname, initial.hostname);
        assert!(server.confirmed_commit.lock().unwrap().pending.is_none());
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(1));
        assert_eq!(stored.config.hostname, "fixture-initial");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn exact_bus_control_admits_one_encrypted_effect_without_a_standalone_intent() {
    let h = Harness::start().await;
    let request_id = RequestId::new();
    let (request, intent) = exact_replace(request_id, 1);
    let audit = h.bus.required_config_audit().unwrap();
    assert!(audit
        .observation_sink()
        .record_async(&intent)
        .await
        .is_err());
    audit.submit(request, intent).await.unwrap();
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.request_id, Some(request_id));
    assert_eq!(stored.version, ConfigVersion::new(2));
    assert_eq!(stored.config.hostname, "fixture-control");
    assert_eq!(h.checkpoints.sequence(), 6);
    drop(audit);
    h.shutdown().await;
}

#[tokio::test]
async fn exact_bus_control_fences_unavailable_and_ambiguous_intent_checkpoint() {
    for unknown in [false, true] {
        let h = Harness::start().await;
        if unknown {
            h.checkpoints.unknown_from.store(4, Ordering::Release);
        } else {
            h.checkpoints.refuse_from.store(4, Ordering::Release);
        }
        let audit = h.bus.required_config_audit().unwrap();
        let (request, intent) = exact_replace(RequestId::new(), 1);
        assert!(audit.submit(request, intent).await.is_err());
        assert_eq!(h.bus.version(), ConfigVersion::new(1));
        assert_eq!(h.checkpoints.sequence(), if unknown { 4 } else { 3 });

        // Restore read availability only after submission returned. Recovering
        // the checkpoint must not retroactively authorize the unsubmitted effect.
        h.checkpoints
            .readback_unavailable
            .store(false, Ordering::Release);
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(1));
        assert_eq!(stored.config.hostname, "fixture-initial");
        let debt = h.authority.reconcile_audit_obligations(30).await.unwrap();
        assert_eq!(debt.pending, 1);
        drop(audit);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn exact_bus_control_preserves_known_commit_and_recovers_only_its_terminal_debt() {
    let h = Harness::start().await;
    h.checkpoints.refuse_from.store(6, Ordering::Release);
    let audit = h.bus.required_config_audit().unwrap();
    let request_id = RequestId::new();
    let (request, intent) = exact_replace(request_id, 1);
    audit.submit(request, intent).await.unwrap();
    let committed = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(committed.request_id, Some(request_id));
    assert_eq!(committed.version, ConfigVersion::new(2));
    assert_eq!(h.checkpoints.sequence(), 4);

    let (mut later_request, later_intent) = exact_replace(RequestId::new(), 2);
    later_request.candidate.as_mut().unwrap().hostname = "fixture-fenced".into();
    assert!(audit.submit(later_request, later_intent).await.is_err());
    let debt = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!((debt.completed, debt.pending, debt.unknown), (0, 0, 1));
    h.checkpoints.refuse_from.store(0, Ordering::Release);
    let recovered = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(h.checkpoints.sequence(), 6);
    let exact = h.bus.resolve_request_id(request_id).await.unwrap().unwrap();
    assert_eq!(exact.tx_id, committed.tx_id);
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(latest.tx_id, committed.tx_id);
    assert_eq!(latest.version, ConfigVersion::new(2));
    drop(audit);
    h.shutdown().await;
}

#[tokio::test]
async fn authenticated_netconf_running_edit_reaches_the_exact_required_audit_effect() {
    let h = Harness::start().await;
    let server = h.server();
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    let request_id = RequestId::new();
    let reply = server
        .handle_rpc_for_session_async(
            request_id,
            &principal(),
            &edit_config_rpc_to(
                "running",
                r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-edited</sys:hostname></sys:system>"#,
                "merge",
            ),
            &MgmtLimits::default(),
            1,
            &sessions,
        )
        .await;
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    let checkpoint = h.checkpoints.sequence();
    drop(registration);
    drop(server);
    h.shutdown().await;

    // This is the desired behavior detector, not an assertion that the
    // current standalone-Intent refusal constitutes a successful handoff.
    assert!(reply.reply_xml.contains("<ok/>"), "{}", reply.reply_xml);
    assert_eq!(stored.request_id, Some(request_id));
    assert_eq!(stored.principal, principal());
    assert_eq!(stored.version, ConfigVersion::new(2));
    assert_eq!(stored.config.hostname, "fixture-edited");
    assert_eq!(
        checkpoint, 6,
        "one intent, result and terminal for the effect"
    );
}
