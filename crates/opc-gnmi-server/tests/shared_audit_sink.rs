use std::sync::{Arc, Mutex};

use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{
    AuthStrength, RequestId, TransportType, TrustedPrincipal, WorkloadIdentity,
};
use opc_gnmi_server::proto::gnmi::{self, g_nmi_server::GNmi};
use opc_gnmi_server::{
    AuthenticatedGnmiPrincipal, CapabilityProfile, ExtensionRegistry, GnmiConfigBinding, GnmiError,
    GnmiPatchApplicator, GnmiServer, GnmiService, GnmiVersion, GNMI_VERSION,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
};
use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};
use opc_nacm::{NacmPolicy, PolicyVersion};
use opc_netconf_server::{NetconfConfigBinding, ReadOnlyNetconfServer, NETCONF_BASE_NS};
use opc_types::TenantId;
use tonic::Request;

struct TestRegistry;

static MODELS: &[ModelData] = &[ModelData {
    name: "test-system",
    revision: "2026-07-27",
    namespace: "urn:opc:test:system",
    prefix: "sys",
}];

static ORIGINS: &[OriginEntry] = &[OriginEntry {
    origin: "",
    modules: &["test-system"],
}];

static NODES: &[NodeMeta] = &[NodeMeta {
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
}];

impl SchemaRegistry for TestRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:shared-audit-test"
    }

    fn served_models(&self) -> &'static [ModelData] {
        MODELS
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        NODES
    }

    fn origins(&self) -> &'static [OriginEntry] {
        ORIGINS
    }
}

#[derive(Clone)]
struct TestBinding {
    bus: Arc<ConfigBus<()>>,
}

impl NetconfConfigBinding<()> for TestBinding {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        Arc::clone(&self.bus)
    }

    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        &TestRegistry
    }
}

impl GnmiConfigBinding<()> for TestBinding {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        Arc::clone(&self.bus)
    }

    fn schema(&self) -> &'static dyn SchemaRegistry {
        &TestRegistry
    }

    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<()>> {
        Arc::new(UnitPatcher)
    }

    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        Arc::new(EmptyOperationalState)
    }

    fn policy_source(&self) -> Arc<dyn PolicySource> {
        Arc::new(EmptyPolicy)
    }
}

struct UnitPatcher;

impl GnmiPatchApplicator<()> for UnitPatcher {
    fn apply_set(
        &self,
        _running: &(),
        _set: &opc_gnmi_server::NormalizedSet,
    ) -> Result<(), GnmiError> {
        Ok(())
    }
}

struct EmptyOperationalState;

impl OperationalStateProvider for EmptyOperationalState {
    fn get(&self, _request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        Ok(OperationalResponse::default())
    }
}

struct EmptyPolicy;

impl PolicySource for EmptyPolicy {
    fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        Ok(Arc::new(NacmPolicy::empty(PolicyVersion::new(1))))
    }
}

#[derive(Default)]
struct CapturingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditSink for CapturingAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .expect("audit event mutex")
            .push(event.clone());
        Ok(())
    }
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("operator".to_string()),
        TenantId::from_static("test"),
    )
    .with_auth_strength(AuthStrength::MutualTls)
}

#[tokio::test]
async fn one_arc_trait_object_sink_receives_events_from_both_server_cores() {
    let bus = Arc::new(
        ConfigBus::new_dev_only((), MockManagedDatastore::new())
            .await
            .expect("config bus"),
    );
    let binding = TestBinding { bus };
    let captured = Arc::new(CapturingAudit::default());
    let audit: Arc<dyn AuditSink> = captured.clone();

    let netconf = ReadOnlyNetconfServer::new(
        binding.clone(),
        EmptyPolicy,
        Arc::clone(&audit),
        TransportType::NetconfTls,
    )
    .expect("NETCONF server accepts Arc<dyn AuditSink>");
    let gnmi = GnmiServer::new_with_audit(
        binding,
        MgmtLimits::default(),
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("gNMI version")),
        ExtensionRegistry::default(),
        Arc::clone(&audit),
    )
    .expect("gNMI server accepts the same Arc<dyn AuditSink>");

    let netconf_reply = netconf.handle_rpc_xml(
        RequestId::new(),
        &principal(),
        &format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="shared-audit"><get-config><source><running/></source></get-config></rpc>"#
        ),
        &MgmtLimits::default(),
    );
    assert!(netconf_reply.contains("<data/>"));

    let service = GnmiService::new(gnmi);
    let mut request = Request::new(gnmi::CapabilityRequest {
        extension: Vec::new(),
    });
    request
        .extensions_mut()
        .insert(AuthenticatedGnmiPrincipal::new(principal()));
    service
        .capabilities(request)
        .await
        .expect("gNMI Capabilities");

    let events = captured.events.lock().expect("audit event mutex");
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| {
        event.transport == TransportType::NetconfTls
            && event.operation == AuditOperation::Read
            && event.outcome == AuditOutcome::Success
    }));
    assert!(events.iter().any(|event| {
        event.transport == TransportType::Gnmi
            && event.operation == AuditOperation::Capabilities
            && event.outcome == AuditOutcome::Success
    }));
}
