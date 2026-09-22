//! NETCONF's exact worker and terminal fence across a real three-voter election.
//! Native Durable stores with public RPCs; no process-crash or TLS claim.

use super::*;
use opc_config_bus::{AuthorizationContext, AuthorizationError, ConfigAuthorizer};
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcHandler, ConsensusWireRequest,
    ConsensusWireResponse, DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_persist::{
    ConfigLocalAuthorityOutcome, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};

mod authenticated;

// Same election/operation envelope as the persistence quorum qualification.
// No sleeps, accelerated elections, or altered engine/operation deadlines.
const TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("netconf-required-quorum-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

struct Peer {
    target: ConfigConsensusNodeId,
    handler: tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>,
    enabled: AtomicBool,
    activity: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntheticAuditPeer").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ConsensusPeer for Peer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        let response = handler.handle(request.sender, request).await;
        self.activity.notify_one();
        Ok(response)
    }
}

struct Quorum {
    _directory: tempfile::TempDir,
    stores: Vec<Arc<ConsensusConfigStore>>,
    paths: BTreeMap<(usize, usize), Arc<Peer>>,
    checkpoints: Arc<Checkpoints>,
    activity: Arc<tokio::sync::Notify>,
}

impl Quorum {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let nodes = [1, 2, 3].map(|value| ConfigConsensusNodeId::new(value).unwrap());
        let activity = Arc::new(tokio::sync::Notify::new());
        let checkpoints = Arc::new(Checkpoints::default());
        let mut paths = BTreeMap::new();
        for source in 0..3 {
            for (target, node) in nodes.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(Peer {
                            target: node,
                            handler: tokio::sync::RwLock::new(None),
                            enabled: AtomicBool::new(true),
                            activity: activity.clone(),
                        }),
                    );
                }
            }
        }
        let mut stores = Vec::new();
        for (index, node) in nodes.iter().copied().enumerate() {
            let topology =
                ConfigConsensusTopology::try_new(identity(), node, nodes.into_iter().collect())
                    .unwrap();
            let options = RetainedConfigOptions::new(
                directory.path().join(format!("node-{index}.sqlite")),
                RetainedConfigBinding::new(topology.clone(), [0x72; 32], [0x73; 32]).unwrap(),
                RetainedConfigDurability::Durable {
                    min_free_bytes: 16 * 1024 * 1024,
                },
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap();
            let backend = SqliteBackend::provision_config_authority(
                options,
                AuditKey::new([0x71; 32]).unwrap(),
            )
            .await
            .unwrap();
            let peers = (0..3)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn ConsensusPeer> = paths[&(index, target)].clone();
                    (nodes[target], peer)
                })
                .collect();
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap();
            let store = ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                directory.path().join(format!("snapshots-{index}")),
                peers,
                AuditContinuityPolicy::new(keys, checkpoints.clone(), 1, 1).unwrap(),
            )
            .await
            .unwrap();
            stores.push(Arc::new(store));
        }
        for ((_, target), path) in &paths {
            *path.handler.write().await = Some(stores[*target].rpc_handler());
        }
        let quorum = Self {
            _directory: directory,
            stores,
            paths,
            checkpoints,
            activity,
        };
        let (one, two, three) = tokio::join!(
            quorum.stores[0].initialize_cluster(),
            quorum.stores[1].initialize_cluster(),
            quorum.stores[2].initialize_cluster(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        quorum
    }

    async fn leader_except(&self, excluded: Option<usize>) -> usize {
        tokio::time::timeout(TRANSITION_TIMEOUT, async {
            loop {
                // Register before observing status, so a completed RPC between
                // inspection and awaiting the next engine event is not lost.
                let activity = self.activity.notified();
                tokio::pin!(activity);
                activity.as_mut().enable();
                for (index, store) in self.stores.iter().enumerate() {
                    if Some(index) == excluded {
                        continue;
                    }
                    let status = store.status();
                    if status.leader_id == Some(status.node_id)
                        && matches!(
                            store.ensure_local_authority().await,
                            ConfigLocalAuthorityOutcome::LocalAuthority
                        )
                    {
                        return index;
                    }
                }
                activity.await;
            }
        })
        .await
        .expect("quorum did not establish fresh local authority")
    }

    fn isolate(&self, node: usize) {
        for ((source, target), path) in &self.paths {
            if *source == node || *target == node {
                path.enabled.store(false, Ordering::Release);
            }
        }
    }

    async fn shutdown(self) {
        let (one, two, three) = tokio::join!(
            self.stores[0].shutdown(),
            self.stores[1].shutdown(),
            self.stores[2].shutdown(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
    }
}

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

struct Owner {
    source: Arc<Source>,
    bus: Arc<ConfigBus<DemoConfig>>,
    stopped: Arc<tokio::sync::Notify>,
}

impl Owner {
    async fn open(authority: Arc<ConsensusConfigStore>, bootstrap: bool) -> Self {
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("netconf-fixture-key").unwrap(),
                KeyPurpose::Config,
                principal().tenant,
                Zeroizing::new([0x6b; AES_256_GCM_SIV_KEY_LEN]),
            )
            .unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
        let source = Arc::new(EncryptingManagedDatastore::new(
            Arc::new(RaftManagedDatastore::new_audited_local_authority(
                authority,
                ConfigAuditPolicy::new(privacy, Duration::from_secs(60)).unwrap(),
            )),
            provider,
        ));
        let initial = DemoConfig {
            hostname: "fixture-initial".into(),
            secret: "synthetic-secret".into(),
        };
        if bootstrap {
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
        Self {
            source,
            bus,
            stopped,
        }
    }

    async fn close(self) {
        drop(self.bus);
        tokio::time::timeout(Duration::from_secs(5), self.stopped.notified())
            .await
            .unwrap();
        drop(self.source);
    }
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

async fn assert_original_terminal(
    authority: &ConsensusConfigStore,
    consensus_identity: ConfigConsensusIdentity,
    request_id: RequestId,
    committed: &StoredConfig<DemoConfig>,
) {
    use opc_persist::audit_authority::continuity::AuditExportVerifier;
    use opc_persist::audit_authority::{AuditCaller, AuditPrivacyProjection, AuditPrivacyPurpose};

    let privacy = AuditPrivacyKey::new([0x81; 32]).unwrap();
    let principal = principal();
    let descriptor = opc_mgmt_audit::principal_descriptor(&principal);
    let caller = AuditCaller::project(&privacy, principal.tenant.as_str(), &descriptor).unwrap();
    let export = authority
        .freeze_audit_export(caller, 0, Duration::from_secs(60))
        .await
        .unwrap();
    let page = export.page(None, 256, caller).unwrap();
    assert!(page.next_cursor().is_none());
    // Trusted authority-side inspection with authority signing material. This
    // is not recipient-only offline verification and supplies no #959 claim.
    let mut verifier = AuditExportVerifier::new(
        Arc::new(AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap()),
        export.manifest().clone(),
        consensus_identity,
        caller,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    verifier.accept(&page).unwrap();
    verifier.finish().unwrap();
    let encoded = page.encode().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let rows = value["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let request = privacy
        .project(
            AuditPrivacyPurpose::Request,
            &[
                principal.tenant.as_str().as_bytes(),
                descriptor.as_bytes(),
                request_id.as_uuid().as_bytes(),
            ],
        )
        .unwrap();
    let request = serde_json::to_value(request).unwrap();
    let matched: Vec<_> = rows
        .iter()
        .filter(|row| row["entry"]["payload"]["intent"]["body"]["event"]["request"] == request)
        .collect();
    assert_eq!(matched.len(), 1, "election duplicated the original intent");
    let handle = &matched[0]["entry"]["payload"]["intent"];
    let transaction = privacy
        .project(
            AuditPrivacyPurpose::Transaction,
            &[
                principal.tenant.as_str().as_bytes(),
                descriptor.as_bytes(),
                committed.tx_id.to_string().as_bytes(),
            ],
        )
        .unwrap();
    assert!(
        handle["body"]["event"]["caller"] == serde_json::to_value(caller).unwrap(),
        "recovery changed the projected caller"
    );
    assert!(
        handle["body"]["event"]["transaction"] == serde_json::to_value(transaction).unwrap(),
        "recovery changed the projected effect"
    );
    for terminal in ["outcome", "terminal"] {
        assert_eq!(
            rows.iter()
                .filter(|row| row["entry"]["payload"][terminal]["operation"] == handle["mac"])
                .count(),
            1,
            "recovery lost or duplicated an exact completion row"
        );
    }
}

#[tokio::test]
async fn required_running_terminal_debt_survives_leadership_change_and_fences_stale_owner() {
    let quorum = Quorum::start().await;
    let old_leader = quorum.leader_except(None).await;
    quorum.stores[old_leader]
        .initialize_audit_authority(
            &AuditPrivacyKey::new([0x81; 32]).unwrap(),
            AuditLedgerLimits::new(90, 30).unwrap(),
        )
        .await
        .unwrap();
    let old_owner = Owner::open(quorum.stores[old_leader].clone(), true).await;
    assert_eq!(quorum.checkpoints.sequence(), 3);
    let old_server = running::required_server_for_bus(old_owner.bus.clone());
    let old_sessions = SessionRegistry::new();
    let old_registration = old_sessions.register(1).unwrap();
    let request_id = RequestId::new();
    quorum.checkpoints.refuse_from.store(6, Ordering::Release);
    let reply = old_server
        .handle_rpc_for_session_async(
            request_id,
            &principal(),
            &edit("fixture-before-election"),
            &MgmtLimits::default(),
            1,
            &old_sessions,
        )
        .await;
    assert!(reply.reply_xml.contains("<ok/>"));
    let committed = old_owner
        .source
        .load_committed_latest()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.version, ConfigVersion::new(2));
    assert!(
        committed.request_id == Some(request_id),
        "effect lost request"
    );
    assert_eq!(quorum.checkpoints.sequence(), 4);

    quorum.isolate(old_leader);
    let new_leader = quorum.leader_except(Some(old_leader)).await;
    assert_ne!(old_leader, new_leader);
    let new_owner = Owner::open(quorum.stores[new_leader].clone(), false).await;
    let exact = new_owner
        .bus
        .resolve_request_id(request_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == committed.tx_id,
        "election changed exact result"
    );
    assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
    let new_server = running::required_server_for_bus(new_owner.bus.clone());
    let new_sessions = SessionRegistry::new();
    let new_registration = new_sessions.register(2).unwrap();

    // A new authority must retain the obligation, and the old isolated worker
    // must not turn its stale projection into a separate configuration effect.
    for (server, sessions, session_id) in [
        (&new_server, &new_sessions, 2),
        (&old_server, &old_sessions, 1),
    ] {
        let refused_request = RequestId::new();
        let refused = server
            .handle_rpc_for_session_async(
                refused_request,
                &principal(),
                &edit("fixture-fenced"),
                &MgmtLimits::default(),
                session_id,
                sessions,
            )
            .await;
        assert!(refused.reply_xml.contains("operation-failed"));
        assert!(new_owner
            .bus
            .resolve_request_id(refused_request)
            .await
            .unwrap()
            .is_none());
        let latest = new_owner
            .source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap();
        assert!(
            latest.tx_id == committed.tx_id,
            "fenced write changed effect"
        );
        assert_eq!(latest.version, ConfigVersion::new(2));
        assert_eq!(latest.config.hostname, "fixture-before-election");
        assert_eq!(quorum.checkpoints.sequence(), 4);
    }
    let pending = quorum.stores[new_leader]
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!(
        (pending.completed, pending.pending, pending.unknown),
        (0, 0, 1)
    );
    quorum.checkpoints.refuse_from.store(0, Ordering::Release);
    let settled = quorum.stores[new_leader]
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!(
        (settled.completed, settled.pending, settled.unknown),
        (1, 0, 0)
    );
    assert_eq!(quorum.checkpoints.sequence(), 6);
    let exact = new_owner
        .bus
        .resolve_request_id(request_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == committed.tx_id,
        "recovery replaced original effect"
    );
    assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
    assert_original_terminal(
        quorum.stores[new_leader].as_ref(),
        identity(),
        request_id,
        &committed,
    )
    .await;

    let later_request = RequestId::new();
    let permitted = new_server
        .handle_rpc_for_session_async(
            later_request,
            &principal(),
            &edit("fixture-after-election"),
            &MgmtLimits::default(),
            2,
            &new_sessions,
        )
        .await;
    assert!(permitted.reply_xml.contains("<ok/>"));
    let latest = new_owner
        .source
        .load_committed_latest()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.version, ConfigVersion::new(3));
    assert_eq!(latest.config.hostname, "fixture-after-election");
    assert!(
        latest.request_id == Some(later_request),
        "later request changed"
    );
    assert!(
        latest.tx_id != committed.tx_id,
        "later write reused recovery"
    );
    assert_eq!(quorum.checkpoints.sequence(), 9);
    drop(old_registration);
    drop(new_registration);
    drop(old_server);
    drop(new_server);
    old_owner.close().await;
    new_owner.close().await;
    quorum.shutdown().await;
}
