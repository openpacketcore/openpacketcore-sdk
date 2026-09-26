//! Actual protocol-future final drop against a native retained session authority.
use super::*;
use opc_config_bus::{
    CommitWrite, EncryptingManagedDatastore, ManagedDatastore, NetconfAuditStore,
    NetconfWorkerExit, SealedConfig, StoreError, StoredConfig,
};
use opc_config_model::RequestId;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use opc_persist::{
    audit_authority::{continuity::*, *},
    *,
};

#[derive(Default)]
pub(super) struct Checkpoint {
    value: Mutex<Option<AuditCheckpoint>>,
    pub(super) unavailable: AtomicBool,
    pub(super) pause: AtomicBool,
    pub(super) fail_completion: AtomicBool,
    pub(super) pause_completion: AtomicBool,
    pub(super) advances_since_arm: AtomicUsize,
    pub(super) entered: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
    advanced: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if self.pause.swap(false, Ordering::AcqRel) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if self.unavailable.load(Ordering::Acquire) {
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
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        if (self.fail_completion.load(Ordering::Acquire)
            || self.pause_completion.load(Ordering::Acquire))
            && self.advances_since_arm.fetch_add(1, Ordering::AcqRel) >= 1
        {
            if self.pause_completion.swap(false, Ordering::AcqRel) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if self.fail_completion.load(Ordering::Acquire) {
                return Err(AuditAuthorityError::Unavailable);
            }
        }
        let mut current = self.value.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        self.advanced.notify_one();
        Ok(AuditCheckpointAdvance::Applied)
    }
}

pub(super) struct Fixture {
    pub(super) store: Arc<ConsensusConfigStore>,
    pub(super) port: NetconfAuditStore,
    pub(super) checkpoint: Arc<Checkpoint>,
    device: NetconfDeviceOwner,
    privacy: Arc<AuditPrivacyKey>,
    caller: AuditCaller,
    observations: Arc<dyn AuditSink>,
    path: PathBuf,
}
impl Fixture {
    pub(super) async fn new(principal: &TrustedPrincipal) -> Self {
        let path = std::env::temp_dir().join(format!("opc-session-{}", RequestId::new()));
        std::fs::create_dir(&path).unwrap();
        let node = ConfigConsensusNodeId::new(1).unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("synthetic-session").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let binding = RetainedConfigBinding::new(topology.clone(), [0x31; 32], [0x61; 32])
            .unwrap()
            .with_profile(RetainedConfigProfile::NetconfTargetsV1);
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                path.join("authority.sqlite"),
                binding,
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x55; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoint = Arc::new(Checkpoint::default());
        let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x71; 32]).unwrap()]).unwrap();
        let policy = AuditContinuityPolicy::new(keys, checkpoint.clone(), 1, 1).unwrap();
        let store = Arc::new(
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                path.join("snapshots"),
                BTreeMap::new(),
                policy,
            )
            .await
            .expect("single-member retained target runtime must open with independent continuity"),
        );
        store.initialize_cluster().await.unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0xa9; 32]).unwrap());
        store
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(96, 32).unwrap())
            .await
            .unwrap();
        let caller = AuditCaller::project(
            privacy.as_ref(),
            principal.tenant.as_str(),
            &opc_mgmt_audit::principal_descriptor(principal),
        )
        .unwrap();
        let event = ManagementAuditEventRecord::try_new(
            *RequestId::new().as_uuid().as_bytes(),
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            principal.tenant.as_str(),
            opc_mgmt_audit::principal_descriptor(principal),
            ManagementAuditTransportCode::Internal,
            ManagementAuditOperationCode::Exec,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            std::iter::empty::<&str>(),
            None::<&str>,
        )
        .unwrap();
        let prepared = store
            .prepare_netconf_device(privacy.as_ref(), &event, Duration::from_secs(60))
            .await
            .unwrap();
        let intent = applied(
            store
                .admit_netconf_target_local(prepared.mutation(), caller)
                .await,
        );
        let known = applied(
            store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller)
                .await,
        );
        store
            .complete_required_audit_outcome(&known, caller)
            .await
            .unwrap();
        let device = store
            .claim_netconf_device_owner(&prepared, &known, caller)
            .await
            .unwrap();
        let port = NetconfAuditStore::new(
            store.clone(),
            privacy.clone(),
            Duration::from_secs(60),
            device.clone(),
        )
        .await
        .unwrap();
        let adapter =
            opc_config_bus_consensus::RaftManagedDatastore::<()>::new_audited_local_authority(
                store.clone(),
                opc_config_bus_consensus::ConfigAuditPolicy::new(
                    privacy.clone(),
                    Duration::from_secs(60),
                )
                .unwrap(),
            );
        let observations = adapter.required_audit_observations().unwrap();
        Self {
            store,
            port,
            checkpoint,
            device,
            privacy,
            caller,
            observations,
            path,
        }
    }
    pub(super) async fn close(self) {
        self.store.shutdown().await.unwrap();
        drop(self.store);
        std::fs::remove_dir_all(self.path).unwrap();
    }
}

type LockServer = ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>;

fn lock_policy(allow_lock: bool, allow_unlock: bool) -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("ietf-netconf", "nc").unwrap();
    let mut policy = NacmPolicy::builder(PolicyVersion::new(1));
    for (path, allowed) in [
        ("/nc:lock", allow_lock),
        ("/nc:unlock", allow_unlock),
        ("/nc:close-session", true),
    ] {
        if allowed {
            policy = policy.add_rule(NacmRule::allow(
                NacmAction::Exec,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
    }
    policy.build()
}

fn lock_server(bus: Arc<ConfigBus<DemoConfig>>, policy: NacmPolicy) -> Arc<LockServer> {
    let audit = bus.required_netconf_audit().unwrap();
    Arc::new(
        ReadOnlyNetconfServer::new(
            TestBinding { bus },
            FixedPolicy(policy),
            CapturingAudit::default(),
            opc_config_model::TransportType::NetconfTls,
        )
        .unwrap()
        .with_retained_session_lifecycle(audit)
        .unwrap(),
    )
}

struct Client {
    stream: tokio::io::DuplexStream,
    runner: tokio::task::JoinHandle<Result<SessionResult, SessionError>>,
}
impl Client {
    async fn start<B: NetconfConfigBinding<DemoConfig> + 'static>(
        server: Arc<ReadOnlyNetconfServer<DemoConfig, B, FixedPolicy, CapturingAudit>>,
        sessions: SessionRegistry,
        id: u64,
    ) -> Self {
        let (mut stream, client) = tokio::io::duplex(8192);
        let runner = tokio::spawn(async move {
            run_read_only_session_with_registry(
                &server,
                &principal(),
                &mut stream,
                SessionConfig::default(),
                id,
                &sessions,
            )
            .await
        });
        let mut client = Self {
            stream: client,
            runner,
        };
        let hello = client.reply().await;
        assert!(hello.contains("<hello"));
        assert!(!hello.contains(":candidate"));
        assert!(!hello.contains(":writable-running"));
        client.send(&client_hello(&[NETCONF_BASE_1_0])).await;
        client
    }
    async fn send(&mut self, xml: &str) {
        write_message(
            &mut self.stream,
            SessionFraming::Base10,
            xml.as_bytes(),
            &SessionConfig::default(),
        )
        .await
        .unwrap();
    }
    async fn reply(&mut self) -> String {
        let bytes = tokio::time::timeout(
            Duration::from_secs(10),
            read_message(
                &mut self.stream,
                SessionFraming::Base10,
                &SessionConfig::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        String::from_utf8(bytes).unwrap()
    }
    async fn lock(&mut self, release: bool) -> String {
        let operation = if release { "unlock" } else { "lock" };
        self.send(&format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="1"><{operation}><target><running/></target></{operation}></rpc>"#)).await;
        self.reply().await
    }
    async fn close(mut self) {
        self.send(&close_session_rpc("close")).await;
        assert!(self.reply().await.contains("<ok/>"));
        self.runner.await.unwrap().unwrap();
    }
    async fn cancel(self) {
        self.runner.abort();
        assert!(self.runner.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn native_runner_running_lock_unlock_use_sdk_lease_and_contend_across_sessions() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let server = lock_server(bus.clone(), lock_policy(true, true));
    let registry = SessionRegistry::new();
    let mut first = Client::start(server.clone(), registry.clone(), 41).await;
    let mut second = Client::start(server.clone(), registry.clone(), 42).await;
    assert!(fixture.running_available().await);
    let raw_lock = format!(
        r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="raw"><lock><target><running/></target></lock></rpc>"#
    );
    // A valid numeric registration and equal principal cannot replace the
    // actual runner-held SDK owner, including on legacy dispatch entrypoints.
    let raw_reply = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &raw_lock,
            &SessionConfig::default().limits,
            41,
            &registry,
        )
        .await;
    assert!(raw_reply.reply_xml.contains("operation-failed"));
    let raw_reply = server.handle_rpc_for_session(
        RequestId::new(),
        &principal(),
        &raw_lock,
        &SessionConfig::default().limits,
        41,
        &registry,
    );
    assert!(raw_reply.reply_xml.contains("operation-failed"));
    assert!(fixture.running_available().await);
    assert!(first.lock(false).await.contains("<ok/>"));
    assert!(
        !fixture.running_available().await,
        "wire lock must reach the retained SDK authority"
    );
    assert_eq!(
        registry.running_lock_owner_for_test(),
        None,
        "numeric registry is never retained lock authority"
    );
    assert!(second.lock(false).await.contains("operation-failed"));
    assert!(second.lock(true).await.contains("operation-failed"));
    assert!(!fixture.running_available().await);
    assert!(first.lock(true).await.contains("<ok/>"));
    assert!(
        fixture.running_available().await,
        "wire unlock must release the actual SDK lease"
    );
    assert!(second.lock(false).await.contains("<ok/>"));
    assert!(second.lock(true).await.contains("<ok/>"));
    first.close().await;
    second.close().await;
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, server, bus));
    fixture.close().await;
}

#[tokio::test]
async fn native_runner_nacm_denial_is_audited_before_lock_or_unlock_effect() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let server = lock_server(bus.clone(), lock_policy(false, false));
    let mut denied = Client::start(server, SessionRegistry::new(), 51).await;
    let before = fixture.checkpoint.value.lock().unwrap().clone();
    assert!(denied.lock(false).await.contains("access-denied"));
    assert_ne!(
        *fixture.checkpoint.value.lock().unwrap(),
        before,
        "denial must use the real mandatory audit port"
    );
    assert!(fixture.running_available().await);
    denied.close().await;
    let server = lock_server(bus.clone(), lock_policy(true, false));
    let mut owner = Client::start(server, SessionRegistry::new(), 52).await;
    assert!(owner.lock(false).await.contains("<ok/>"));
    assert!(owner.lock(true).await.contains("access-denied"));
    assert!(!fixture.running_available().await);
    owner.cancel().await;
    fixture.wait_released(&audit).await;
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, bus));
    fixture.close().await;
}

#[tokio::test]
async fn native_runner_cancelled_after_lock_effect_before_reply_releases_sdk_ownership() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let server = lock_server(bus.clone(), lock_policy(true, true));
    let mut client = Client::start(server, SessionRegistry::new(), 61).await;
    fixture
        .checkpoint
        .advances_since_arm
        .store(0, Ordering::Release);
    fixture
        .checkpoint
        .pause_completion
        .store(true, Ordering::Release);
    client.send(&format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="lost"><lock><target><running/></target></lock></rpc>"#)).await;
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.checkpoint.entered.notified(),
    )
    .await
    .unwrap();
    // The effect is known, but completion and reply are still outstanding. The
    // queued SDK reference must not keep the actual transport owner alive.
    client.cancel().await;
    fixture.checkpoint.release.notify_one();
    fixture.wait_released(&audit).await;
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, bus));
    fixture.close().await;
}

#[tokio::test]
async fn native_runner_mandatory_checkpoint_outage_never_acknowledges_lock_or_unlock() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let server = lock_server(bus.clone(), lock_policy(true, true));
    let mut client = Client::start(server, SessionRegistry::new(), 71).await;
    for release in [false, true] {
        fixture
            .checkpoint
            .advances_since_arm
            .store(0, Ordering::Release);
        fixture
            .checkpoint
            .fail_completion
            .store(true, Ordering::Release);
        let response = client.lock(release).await;
        assert!(
            response.contains("operation-failed"),
            "owed terminal checkpoint cannot return success: {response}"
        );
        assert!(!response.contains("<ok/>"));
        assert!(
            fixture
                .checkpoint
                .advances_since_arm
                .load(Ordering::Acquire)
                >= 2,
            "outage must hit the post-effect terminal checkpoint"
        );
        fixture
            .checkpoint
            .fail_completion
            .store(false, Ordering::Release);
        // A read-only worker message wakes original recovery; it cannot mint a
        // fresh operation or fabricate a lease from the returned cache miss.
        assert!(audit
            .recover_request(RequestId::new(), &principal())
            .await
            .unwrap()
            .is_none());
        // The next reply follows that loop's recovery pass, including lease publication.
        assert!(audit
            .recover_request(RequestId::new(), &principal())
            .await
            .unwrap()
            .is_none());
        assert_eq!(fixture.running_available().await, release);
    }
    client.close().await;
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, bus));
    fixture.close().await;
}
fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected authenticated result: {other:?}"),
    }
}

// Only the running snapshot is synthetic. Every session mint, local revocation,
// lifecycle effect, receipt and checkpoint in this detector uses the real store.
struct SessionStore<C: OpcConfig> {
    inner: MockManagedDatastore<C>,
    port: NetconfAuditStore,
    observations: Arc<dyn AuditSink>,
}
#[async_trait::async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for SessionStore<C> {
    fn required_netconf_audit_store(&self) -> Option<NetconfAuditStore> {
        Some(self.port.clone())
    }
    fn required_audit_observations(&self) -> Option<Arc<dyn AuditSink>> {
        Some(self.observations.clone())
    }
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }
    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }
    async fn load_by_idempotency_key(
        &self,
        key: &opc_config_model::IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(key).await
    }
    async fn append_commit_write(&self, write: CommitWrite<C>) -> Result<(), StoreError> {
        self.inner.append_commit_write(write).await
    }
    async fn clear_recovery_required(&self, tx: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx).await
    }
}

#[tokio::test]
async fn native_cancelled_actual_runner_revokes_without_shutdown_or_explicit_close() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let server = ReadOnlyNetconfServer::new(
        TestBinding { bus },
        FixedPolicy(allow_all_policy()),
        CapturingAudit::default(),
        opc_config_model::TransportType::NetconfTls,
    )
    .unwrap()
    .with_retained_session_lifecycle(audit.clone())
    .unwrap();
    let (mut stream, mut client) = tokio::io::duplex(8192);
    let actor = principal();
    let config = SessionConfig::default();
    let mut runner = Box::pin(run_read_only_session(
        &server,
        &actor,
        &mut stream,
        config,
        31,
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = runner.as_mut() => panic!("runner exited before hello: {result:?}"),
            hello = read_message(&mut client, SessionFraming::Base10, &config) => {
                assert!(String::from_utf8(hello.unwrap().unwrap()).unwrap().contains("<hello"));
            }
        }
    })
    .await
    .unwrap();
    let before = fixture.checkpoint.value.lock().unwrap().clone();
    drop(runner);
    // No worker shutdown here: that would revoke on its own and mask a missing
    // runner Drop. A real EndSession must advance its independent checkpoint.
    tokio::time::timeout(Duration::from_secs(10), async {
        while *fixture.checkpoint.value.lock().unwrap() == before {
            fixture.checkpoint.advanced.notified().await;
        }
    })
    .await
    .expect("cancelled runner must enqueue cleanup through final transport drop");
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop(server);
    drop(audit);
    fixture.close().await;
}

impl Fixture {
    async fn bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        let encrypted = EncryptingManagedDatastore::new(
            Arc::new(SessionStore::<SealedConfig<()>> {
                inner: MockManagedDatastore::new(),
                port: self.port.clone(),
                observations: self.observations.clone(),
            }),
            Arc::new(opc_key::MemoryKeyProvider::new()),
        )
        .with_required_netconf_audit()
        .await
        .unwrap();
        let port = <_ as ManagedDatastore<()>>::required_netconf_audit_store(&encrypted).unwrap();
        Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "synthetic-session".into(),
                },
                SessionStore {
                    inner: MockManagedDatastore::new(),
                    port,
                    observations: self.observations.clone(),
                },
            )
            .await
            .unwrap(),
        )
    }

    async fn running_available(&self) -> bool {
        let owner = self
            .store
            .open_netconf_session(&self.device, self.caller)
            .await
            .unwrap();
        let event = ManagementAuditEventRecord::try_new(
            *RequestId::new().as_uuid().as_bytes(),
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            principal().tenant.as_str(),
            opc_mgmt_audit::principal_descriptor(&principal()),
            ManagementAuditTransportCode::NetconfTls,
            ManagementAuditOperationCode::Exec,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            std::iter::empty::<&str>(),
            None::<&str>,
        )
        .unwrap();
        let result = self
            .store
            .prepare_netconf_lock_acquisition(
                &owner,
                NetconfLockDatastore::Running,
                self.privacy.as_ref(),
                &event,
                Duration::from_secs(60),
            )
            .await;
        owner.invalidate();
        match result {
            Ok(_) => true,
            Err(AuditAuthorityError::BindingMismatch) => false,
            Err(error) => panic!("SDK readback unavailable: {error:?}"),
        }
    }

    async fn wait_released(&self, audit: &opc_config_bus::RequiredNetconfAudit<DemoConfig>) {
        // A read-only barrier runs after the owning worker's cleanup pass. It
        // neither revokes a session nor starts shutdown, and cannot manufacture
        // a release. Reading during an outstanding checkpoint is correctly
        // RecoveryRequired; only settled SDK readback may assert availability.
        tokio::time::timeout(Duration::from_secs(10), async {
            assert!(audit
                .recover_request(RequestId::new(), &principal())
                .await
                .unwrap()
                .is_none());
            assert!(audit
                .recover_request(RequestId::new(), &principal())
                .await
                .unwrap()
                .is_none());
            assert!(
                self.running_available().await,
                "real EndSession must release the SDK lock without shutdown"
            );
        })
        .await
        .unwrap();
    }
}

// An application binding may change its capability report after construction.
// Such a change cannot activate an unsupported local effect owner.
struct MutableProfileBinding {
    inner: TestBinding,
    profile: Arc<AtomicUsize>,
}
impl NetconfConfigBinding<DemoConfig> for MutableProfileBinding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.inner.config_bus()
    }
    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        self.inner.schema_registry()
    }
    fn render_running_config(
        &self,
        config: &DemoConfig,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        self.inner.render_running_config(config, selection)
    }
    fn writable_running_capability(&self) -> bool {
        self.profile.load(Ordering::Acquire) == 1
    }
    fn candidate_datastore_capability(&self) -> bool {
        self.profile.load(Ordering::Acquire) == 2
    }
    fn startup_datastore_capability(&self) -> bool {
        self.profile.load(Ordering::Acquire) == 3
    }
    fn confirmed_commit_capability(&self) -> bool {
        self.profile.load(Ordering::Acquire) == 4
    }
}

#[tokio::test]
async fn native_runner_retained_attachment_refuses_unsupported_and_changed_profiles() {
    let fixture = Fixture::new(&principal()).await;
    let bus = fixture.bus().await;
    let audit = bus.required_netconf_audit().unwrap();
    let profile = Arc::new(AtomicUsize::new(0));
    let make_server = || {
        ReadOnlyNetconfServer::new(
            MutableProfileBinding {
                inner: TestBinding { bus: bus.clone() },
                profile: profile.clone(),
            },
            FixedPolicy(lock_policy(true, true)),
            CapturingAudit::default(),
            opc_config_model::TransportType::NetconfTls,
        )
    };
    for unsupported in 1..=4 {
        profile.store(unsupported, Ordering::Release);
        let result =
            make_server().and_then(|server| server.with_retained_session_lifecycle(audit.clone()));
        assert!(result.is_err(), "unsupported profile must never attach");
    }
    profile.store(0, Ordering::Release);
    let server = Arc::new(
        make_server()
            .unwrap()
            .with_retained_session_lifecycle(audit.clone())
            .unwrap(),
    );
    let mut client = Client::start(server, SessionRegistry::new(), 81).await;
    profile.store(1, Ordering::Release);
    client.send(&format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="closed"><edit-config><target><running/></target><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>changed</sys:hostname></sys:system></config></edit-config></rpc>"#)).await;
    let response = client.reply().await;
    assert!(
        response.contains("operation-failed"),
        "changed profile must fail at the attachment guard: {response}"
    );
    assert!(fixture.running_available().await);
    profile.store(0, Ordering::Release);
    client.close().await;
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, bus));
    fixture.close().await;
}
