//! Real authenticated protocol composition, with no successful test AuditSink.
use super::*;
use opc_config_bus::{AuthorizationContext, AuthorizationError, ConfigAuthorizer};
use opc_gnmi_server::proto::gnmi::{self, g_nmi_server::GNmi};
use opc_gnmi_server::proto::gnmi_ext;
use opc_gnmi_server::{
    AuthenticatedGnmiPrincipal, CapabilityProfile, CommitConfirmedExtension, ExtensionRegistry,
    GnmiArbitrationConfig, GnmiConfigBinding, GnmiError, GnmiPatchApplicator, GnmiServer,
    GnmiService, GnmiVersion, NormalizedSet, GNMI_VERSION, OPC_COMMIT_CONFIRMED_EXTENSION_ID,
};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
};
use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};

struct Registry;
impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:required-audit-test"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "test-system",
            revision: "2026-09-19",
            namespace: "urn:opc:test:system",
            prefix: "sys",
        }]
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[OriginEntry {
            origin: "",
            modules: &["test-system"],
        }]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        &[NodeMeta {
            path: "/sys:system",
            module: "test-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        }]
    }
}

struct Policy {
    allowed: bool,
}
impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let mut modules = ModuleRegistry::new();
        modules.register_module("test-system", "sys").unwrap();
        let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
        if self.allowed {
            builder = builder.add_rule(NacmRule::allow(
                NacmAction::Replace,
                YangPathPattern::parse("/sys:system", &modules).unwrap(),
            ));
            builder = builder.add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system", &modules).unwrap(),
            ));
        }
        Ok(Arc::new(builder.build()))
    }
}

struct Patcher;
impl GnmiPatchApplicator<TestConfig> for Patcher {
    fn apply_set(&self, _: &TestConfig, set: &NormalizedSet) -> Result<TestConfig, GnmiError> {
        serde_json::from_str(
            set.replaces
                .first()
                .ok_or_else(|| GnmiError::invalid("replace required"))?
                .1
                .json(),
        )
        .map_err(|_| GnmiError::invalid("invalid synthetic config"))
    }
}
struct Operational;
impl OperationalStateProvider for Operational {
    fn get(&self, _: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        Ok(OperationalResponse::default())
    }
}

#[derive(Clone)]
struct Binding {
    bus: Arc<ConfigBus<TestConfig>>,
    allowed: bool,
}
impl GnmiConfigBinding<TestConfig> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<TestConfig>> {
        self.bus.clone()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        &Registry
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<TestConfig>> {
        Arc::new(Patcher)
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        Arc::new(Operational)
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        Arc::new(Policy {
            allowed: self.allowed,
        })
    }

    fn render_running_json(
        &self,
        config: &TestConfig,
        _: opc_gnmi_server::ReadSelection<'_>,
    ) -> Result<Vec<opc_gnmi_server::GnmiJsonUpdate>, opc_gnmi_server::GnmiJsonProjectionError>
    {
        Ok(vec![opc_gnmi_server::GnmiJsonUpdate::new(
            YangPath::new("/sys:system").unwrap(),
            serde_json::to_string(config).unwrap(),
        )?])
    }
}

#[derive(Default)]
struct Writer {
    denied: AtomicBool,
    requests: std::sync::Mutex<Vec<RequestId>>,
}
#[async_trait::async_trait]
impl ConfigAuthorizer for Writer {
    async fn authorize(&self, context: &AuthorizationContext) -> Result<(), AuthorizationError> {
        self.requests.lock().unwrap().push(context.request_id);
        if self.denied.load(Ordering::Acquire) {
            return Err(AuthorizationError::new("synthetic revoked writer"));
        }
        Ok(())
    }
}

type Source =
    EncryptingManagedDatastore<TestConfig, MemoryKeyProvider, RaftManagedDatastore<TestConfig>>;
struct Harness {
    cluster: ProjectionCluster,
    store: Arc<ConsensusConfigStore>,
    source: Arc<Source>,
    bus: Arc<ConfigBus<TestConfig>>,
    checkpoints: Arc<checkpoint::CheckpointFixture>,
    writer: Arc<Writer>,
}
impl Harness {
    async fn start() -> Self {
        let checkpoints = Arc::new(checkpoint::CheckpointFixture::default());
        let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
        let store = cluster.stores[cluster.leader()].clone();
        let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
        store
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(90, 30).unwrap())
            .await
            .unwrap();
        cluster.wait_ready().await;
        let source = audited_source(store.clone(), privacy);
        source
            .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
            .await
            .unwrap();
        let writer = Arc::new(Writer::default());
        let bus = Arc::new(
            ConfigBus::restore_or_new(
                TestConfig {
                    name: "initial".into(),
                },
                source.clone(),
                writer.clone(),
            )
            .await
            .unwrap(),
        );
        Self {
            cluster,
            store,
            source,
            bus,
            checkpoints,
            writer,
        }
    }

    fn server(&self, required: bool, allowed: bool) -> GnmiServer<TestConfig, Binding> {
        let audit = self.bus.required_config_audit().unwrap();
        let server = GnmiServer::new(
            Binding {
                bus: self.bus.clone(),
                allowed,
            },
            MgmtLimits::default(),
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            audit.observation_sink(),
        )
        .unwrap();
        if required {
            server.with_required_config_audit(audit).unwrap()
        } else {
            server
        }
    }
}

fn request(name: &str) -> tonic::Request<gnmi::SetRequest> {
    let mut request = tonic::Request::new(gnmi::SetRequest {
        replace: vec![gnmi::Update {
            path: Some(gnmi::Path {
                elem: vec![gnmi::PathElem {
                    name: "sys:system".into(),
                    key: Default::default(),
                }],
                ..Default::default()
            }),
            val: Some(gnmi::TypedValue {
                value: Some(gnmi::typed_value::Value::JsonIetfVal(
                    serde_json::to_vec(&TestConfig { name: name.into() }).unwrap(),
                )),
            }),
            ..Default::default()
        }],
        ..Default::default()
    });
    request
        .extensions_mut()
        .insert(AuthenticatedGnmiPrincipal::new(
            principal().with_auth_strength(opc_config_model::AuthStrength::MutualTls),
        ));
    request
}

fn read_request() -> tonic::Request<gnmi::GetRequest> {
    let mut read = tonic::Request::new(gnmi::GetRequest {
        encoding: gnmi::Encoding::JsonIetf as i32,
        r#type: gnmi::get_request::DataType::Config as i32,
        path: vec![gnmi::Path {
            elem: vec![gnmi::PathElem {
                name: "sys:system".into(),
                key: Default::default(),
            }],
            ..Default::default()
        }],
        ..Default::default()
    });
    read.extensions_mut()
        .insert(AuthenticatedGnmiPrincipal::new(
            principal().with_auth_strength(opc_config_model::AuthStrength::MutualTls),
        ));
    read
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_set_requires_the_exact_audited_bus_and_preserves_request_identity() {
    let h = Harness::start().await;
    let legacy = GnmiService::new(h.server(false, true));
    legacy
        .set(request("must-not-apply"))
        .await
        .expect_err("missing handoff cannot acknowledge Intent");
    assert_eq!(h.bus.version(), ConfigVersion::new(1));
    assert_eq!(h.checkpoints.sequence(), 3);

    let plain = ConfigBus::new_dev_only(
        TestConfig {
            name: "plain".into(),
        },
        opc_config_bus::MockManagedDatastore::new(),
    )
    .await
    .unwrap();
    assert!(plain.required_config_audit().is_err());
    let unaudited = Arc::new(EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<TestConfig>::new_local_authority(
            h.store.clone(),
        )),
        provider(),
    ));
    assert!(unaudited.required_audit_observations().is_none());
    let other_bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        h.source.clone(),
    )
    .await
    .unwrap();
    assert!(h
        .server(false, true)
        .with_required_config_audit(other_bus.required_config_audit().unwrap())
        .is_err());

    let service = GnmiService::new(h.server(true, true));
    service
        .set(request("revision-2"))
        .await
        .expect("real authenticated protocol commits");
    assert_eq!(h.bus.version(), ConfigVersion::new(2));
    assert_eq!(
        h.checkpoints.sequence(),
        6,
        "exactly one intent/result/terminal per config effect"
    );
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(
        stored.request_id,
        h.writer.requests.lock().unwrap().last().copied()
    );
    assert_eq!(stored.config.name, "revision-2");
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_protocol_confirm_and_cancel_bind_the_exact_configuration_operation() {
    let h = Harness::start().await;
    let audit = h.bus.required_config_audit().unwrap();
    let server = GnmiServer::new_with_arbitration(
        Binding {
            bus: h.bus.clone(),
            allowed: true,
        },
        MgmtLimits::default(),
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
        ExtensionRegistry::with_commit_confirmed().unwrap(),
        GnmiArbitrationConfig::required(),
        audit.observation_sink(),
    )
    .unwrap()
    .with_required_config_audit(audit)
    .unwrap();
    let service = GnmiService::new(server);
    let with_control = |name, control: CommitConfirmedExtension| {
        let mut request = request(name);
        if name.is_empty() {
            request.get_mut().replace.clear();
        }
        request.get_mut().extension = vec![
            gnmi_ext::Extension {
                ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
                    gnmi_ext::MasterArbitration {
                        role: None,
                        election_id: Some(gnmi_ext::Uint128 { high: 1, low: 0 }),
                    },
                )),
            },
            gnmi_ext::Extension {
                ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                    gnmi_ext::RegisteredExtension {
                        id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                        msg: control.encode_payload(),
                    },
                )),
            },
        ];
        request
    };
    for (name, control, version, operation) in [
        (
            "confirmed-value",
            CommitConfirmedExtension::confirm(),
            3,
            ConfigOperation::Patch,
        ),
        (
            "cancelled-value",
            CommitConfirmedExtension::cancel(),
            5,
            ConfigOperation::Rollback,
        ),
    ] {
        service
            .set(with_control(
                name,
                CommitConfirmedExtension::begin(Duration::from_secs(60)).unwrap(),
            ))
            .await
            .expect("audited confirmed begin");
        service
            .set(with_control("", control))
            .await
            .expect("audited exact pending control");
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(version));
        assert_eq!(stored.config.name, "confirmed-value");
        assert!(stored.confirmed_deadline.is_none());
        assert_eq!(stored.request_fingerprint.unwrap().operation, operation);
        assert_eq!(
            stored.request_id,
            h.writer.requests.lock().unwrap().last().copied()
        );
        assert_eq!(h.checkpoints.sequence(), 3 * version);
    }
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_and_worker_refusals_remain_durable_observations_without_config_effect() {
    let h = Harness::start().await;
    GnmiService::new(h.server(true, false))
        .set(request("denied"))
        .await
        .expect_err("NACM denial");
    assert_eq!(h.checkpoints.sequence(), 4);
    let service = GnmiService::new(h.server(true, true));
    h.writer.denied.store(true, Ordering::Release);
    service
        .set(request("revoked"))
        .await
        .expect_err("bus authorizer still enforced");
    assert_eq!(h.checkpoints.sequence(), 5);
    h.writer.denied.store(false, Ordering::Release);
    service
        .set(request("invalid-test-candidate"))
        .await
        .expect_err("candidate validation still enforced");
    assert_eq!(h.checkpoints.sequence(), 6);
    service
        .get(read_request())
        .await
        .expect("read shares the required authority observation port");
    assert_eq!(h.checkpoints.sequence(), 7);
    assert_eq!(h.bus.version(), ConfigVersion::new(1));
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_protocol_read_finishes_the_same_retained_observation() {
    let h = Harness::start().await;
    h.checkpoints.pause_at_sequence.store(4, Ordering::Release);
    let service = GnmiService::new(h.server(true, true));
    let task = tokio::spawn(async move { service.get(read_request()).await });
    tokio::time::timeout(Duration::from_secs(5), h.checkpoints.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(h.checkpoints.sequence(), 3);
    h.checkpoints.pause_at_sequence.store(0, Ordering::Release);
    h.checkpoints.resume.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while h.checkpoints.sequence() != 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(h.bus.version(), ConfigVersion::new(1));
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_intent_checkpoint_prevents_protocol_configuration_effect() {
    let h = Harness::start().await;
    h.checkpoints
        .advance_unavailable
        .store(true, Ordering::Release);
    GnmiService::new(h.server(true, true))
        .set(request("must-not-apply"))
        .await
        .expect_err("intent checkpoint unavailable");
    assert_eq!(h.bus.version(), ConfigVersion::new(1));
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    assert_eq!(h.checkpoints.sequence(), 3);
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .pending,
        1
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_after_retained_intent_does_not_retract_or_duplicate_the_config_effect() {
    let h = Harness::start().await;
    h.checkpoints.pause_at_sequence.store(4, Ordering::Release);
    let service = GnmiService::new(h.server(true, true));
    let task = tokio::spawn(async move { service.set(request("revision-2")).await });
    tokio::time::timeout(Duration::from_secs(5), h.checkpoints.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .pending,
        1
    );
    let request_id = h.writer.requests.lock().unwrap().last().copied().unwrap();
    h.checkpoints.pause_at_sequence.store(0, Ordering::Release);
    h.checkpoints.resume.notify_one();
    let stored = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if h.checkpoints.sequence() == 6 && h.bus.version() == ConfigVersion::new(2) {
                // The live snapshot precedes clearing the durable publication
                // fence. Observe that last worker step after the caller is gone.
                let stored = h.source.load_committed_latest().await.unwrap().unwrap();
                if stored.version == ConfigVersion::new(2) {
                    break stored;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(stored.request_id, Some(request_id));
    assert_eq!(
        h.bus
            .resolve_request_id(request_id)
            .await
            .unwrap()
            .unwrap()
            .tx_id,
        stored.tx_id
    );
    assert_eq!(
        h.store
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    h.cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_known_commit_survives_terminal_checkpoint_debt_and_exact_recovery() {
    let h = Harness::start().await;
    let service = GnmiService::new(h.server(true, true));
    h.checkpoints
        .refuse_from_sequence
        .store(6, Ordering::Release);
    service
        .set(request("revision-2"))
        .await
        .expect("known commit must stay successful");
    let tx_id = h
        .source
        .load_committed_latest()
        .await
        .unwrap()
        .unwrap()
        .tx_id;
    assert_eq!(h.checkpoints.sequence(), 4);
    service
        .set(request("fenced"))
        .await
        .expect_err("outstanding exact debt fences new writes");
    assert_eq!(h.bus.version(), ConfigVersion::new(2));
    let debt = h.store.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!((debt.completed, debt.pending, debt.unknown), (0, 0, 1));
    h.checkpoints
        .refuse_from_sequence
        .store(0, Ordering::Release);
    let recovered = h.store.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(h.checkpoints.sequence(), 6);
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .tx_id,
        tx_id
    );
    service.set(request("revision-3")).await.unwrap();
    assert_eq!(h.checkpoints.sequence(), 9);
    h.cluster.shutdown().await;
}
