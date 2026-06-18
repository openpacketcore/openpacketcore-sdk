//! Generated gNMI service skeleton.

use std::{pin::Pin, sync::Arc};

use opc_config_model::{AuthStrength, OpcConfig, RequestId, TrustedPrincipal};
use opc_mgmt_audit::AuditOperation;
use tonic::{Request, Response, Status};

use crate::{
    audit::{outcome_for_error, record_audit},
    confirmed_commit::reject_set_only_extension,
    encoding_to_proto,
    get::handle_get,
    metrics::{
        record_extension, record_rpc_error, record_rpc_success, ExtensionMetricOutcome,
        GnmiOperation,
    },
    proto::{gnmi, gnmi_ext},
    set::handle_set,
    subscribe::{send_subscribe_error, serve_subscribe_stream},
    GnmiConfigBinding, GnmiError, GnmiServer,
};

type SubscribeStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<Item = Result<gnmi::SubscribeResponse, Status>>
            + Send
            + 'static,
    >,
>;

/// Authenticated gNMI principal attached to each request by the TLS listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGnmiPrincipal {
    principal: TrustedPrincipal,
}

impl AuthenticatedGnmiPrincipal {
    /// Wraps a grant-free, transport-authenticated principal for request
    /// extensions.
    pub fn new(principal: TrustedPrincipal) -> Self {
        Self { principal }
    }

    /// Returns the authenticated management principal.
    pub const fn principal(&self) -> &TrustedPrincipal {
        &self.principal
    }
}

/// Tonic service implementation over the protocol-neutral [`GnmiServer`]
/// foundation.
#[derive(Clone)]
pub struct GnmiService<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    server: Arc<GnmiServer<C, B>>,
    require_principal: bool,
}

impl<C, B> GnmiService<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    /// Wraps a validated gNMI foundation handle in the generated service.
    pub fn new(server: GnmiServer<C, B>) -> Self {
        Self {
            server: Arc::new(server),
            require_principal: false,
        }
    }

    /// Wraps a validated gNMI foundation handle and requires every RPC to carry
    /// an authenticated principal extension supplied by the transport listener.
    pub fn new_authenticated(server: GnmiServer<C, B>) -> Self {
        Self {
            server: Arc::new(server),
            require_principal: true,
        }
    }

    pub(crate) fn new_authenticated_shared(server: Arc<GnmiServer<C, B>>) -> Self {
        Self {
            server,
            require_principal: true,
        }
    }

    /// Returns the underlying foundation handle.
    pub fn server(&self) -> &GnmiServer<C, B> {
        &self.server
    }

    fn validate_authenticated_request<T>(&self, request: &Request<T>) -> Result<(), GnmiError> {
        if !self.require_principal {
            return Ok(());
        }
        let principal = request_principal(request)?;
        if principal.principal().auth_strength != AuthStrength::MutualTls {
            return Err(GnmiError::PermissionDenied);
        }
        if !principal.principal().roles.is_empty() || !principal.principal().groups.is_empty() {
            return Err(GnmiError::PermissionDenied);
        }
        Ok(())
    }
}

fn request_principal<T>(request: &Request<T>) -> Result<&AuthenticatedGnmiPrincipal, GnmiError> {
    request
        .extensions()
        .get::<AuthenticatedGnmiPrincipal>()
        .ok_or(GnmiError::Unauthenticated)
}

#[tonic::async_trait]
impl<C, B> gnmi::g_nmi_server::GNmi for GnmiService<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C> + 'static,
{
    type SubscribeStream = SubscribeStream;

    async fn capabilities(
        &self,
        request: Request<gnmi::CapabilityRequest>,
    ) -> Result<Response<gnmi::CapabilityResponse>, Status> {
        let start = std::time::Instant::now();
        if let Err(err) = self.validate_authenticated_request(&request) {
            record_rpc_error(GnmiOperation::Capabilities, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }
        if let Err(err) = validate_extensions_for_operation(
            self.server.extensions(),
            &request.get_ref().extension,
            ExtensionOperation::Capabilities,
        ) {
            record_rpc_error(GnmiOperation::Capabilities, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }

        let caps = self.server.capabilities();
        if let Err(err) = caps.validate() {
            record_rpc_error(GnmiOperation::Capabilities, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }

        let mut response_extensions = caps
            .extensions
            .into_iter()
            .map(capability_extension)
            .collect::<Vec<_>>();
        if self.server.arbitration().advertised() {
            response_extensions.push(master_arbitration_capability_extension());
        }

        let response = gnmi::CapabilityResponse {
            supported_models: caps
                .models
                .into_iter()
                .map(|model| gnmi::ModelData {
                    name: model.name,
                    organization: model.organization.unwrap_or_default(),
                    version: model.version,
                })
                .collect(),
            supported_encodings: caps.encodings.into_iter().map(encoding_to_proto).collect(),
            g_nmi_version: caps.gnmi_version,
            extension: response_extensions,
        };
        record_rpc_success(GnmiOperation::Capabilities, start.elapsed());
        Ok(Response::new(response))
    }

    async fn get(
        &self,
        request: Request<gnmi::GetRequest>,
    ) -> Result<Response<gnmi::GetResponse>, Status> {
        let start = std::time::Instant::now();
        if let Err(err) = self.validate_authenticated_request(&request) {
            record_rpc_error(GnmiOperation::Get, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }
        let principal = match request_principal(&request) {
            Ok(principal) => principal,
            Err(err) => {
                record_rpc_error(GnmiOperation::Get, err.status(), start.elapsed());
                return Err(status_from_error(err));
            }
        };
        if let Err(err) = validate_extensions_for_operation(
            self.server.extensions(),
            &request.get_ref().extension,
            ExtensionOperation::Get,
        ) {
            let final_err = record_audit(
                self.server.audit(),
                RequestId::new(),
                principal.principal(),
                AuditOperation::Read,
                outcome_for_error(&err),
                Vec::new(),
            )
            .err()
            .unwrap_or(err);
            record_rpc_error(GnmiOperation::Get, final_err.status(), start.elapsed());
            return Err(status_from_error(final_err));
        }
        match handle_get(&self.server, principal.principal(), request.get_ref()) {
            Ok(response) => {
                record_rpc_success(GnmiOperation::Get, start.elapsed());
                Ok(Response::new(response))
            }
            Err(err) => {
                record_rpc_error(GnmiOperation::Get, err.status(), start.elapsed());
                Err(status_from_error(err))
            }
        }
    }

    async fn set(
        &self,
        request: Request<gnmi::SetRequest>,
    ) -> Result<Response<gnmi::SetResponse>, Status> {
        let start = std::time::Instant::now();
        if let Err(err) = self.validate_authenticated_request(&request) {
            record_rpc_error(GnmiOperation::Set, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }
        let principal = match request_principal(&request) {
            Ok(principal) => principal,
            Err(err) => {
                record_rpc_error(GnmiOperation::Set, err.status(), start.elapsed());
                return Err(status_from_error(err));
            }
        };
        if let Err(err) = validate_extensions_for_operation(
            self.server.extensions(),
            &request.get_ref().extension,
            ExtensionOperation::Set,
        ) {
            let final_err = record_audit(
                self.server.audit(),
                RequestId::new(),
                principal.principal(),
                AuditOperation::Update,
                outcome_for_error(&err),
                Vec::new(),
            )
            .err()
            .unwrap_or(err);
            record_rpc_error(GnmiOperation::Set, final_err.status(), start.elapsed());
            return Err(status_from_error(final_err));
        }
        match handle_set(&self.server, principal.principal(), request.get_ref()).await {
            Ok(response) => {
                record_rpc_success(GnmiOperation::Set, start.elapsed());
                Ok(Response::new(response))
            }
            Err(err) => {
                record_rpc_error(GnmiOperation::Set, err.status(), start.elapsed());
                Err(status_from_error(err))
            }
        }
    }

    async fn subscribe(
        &self,
        request: Request<tonic::Streaming<gnmi::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let start = std::time::Instant::now();
        if let Err(err) = self.validate_authenticated_request(&request) {
            record_rpc_error(GnmiOperation::Subscribe, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }
        let principal = match request_principal(&request) {
            Ok(principal) => principal.principal().clone(),
            Err(err) => {
                record_rpc_error(GnmiOperation::Subscribe, err.status(), start.elapsed());
                return Err(status_from_error(err));
            }
        };
        let capacity = subscribe_response_queue_capacity(self.server.limits());
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        let server = Arc::clone(&self.server);
        tokio::spawn(async move {
            if let Err(err) =
                serve_subscribe_stream(server, principal, request.into_inner(), tx.clone()).await
            {
                send_subscribe_error(&tx, err).await;
            }
        });
        record_rpc_success(GnmiOperation::Subscribe, start.elapsed());
        Ok(Response::new(Box::pin(
            tonic::codegen::tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

fn subscribe_response_queue_capacity(limits: &opc_mgmt_limits::MgmtLimits) -> usize {
    (limits.max_subscriber_queue_bytes / 4096).clamp(1, 1024)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionOperation {
    Capabilities,
    Get,
    Set,
    Subscribe,
}

pub(crate) fn validate_extensions_for_operation(
    registry: &crate::ExtensionRegistry,
    extensions: &[gnmi_ext::Extension],
    operation: ExtensionOperation,
) -> Result<(), GnmiError> {
    let mut normalized = Vec::new();
    for extension in extensions {
        match extension.ext.as_ref() {
            Some(gnmi_ext::extension::Ext::RegisteredExt(registered)) => {
                let id = u32::try_from(registered.id)
                    .map_err(|_| GnmiError::invalid("invalid registered gNMI extension id"))?;
                normalized.push(crate::Extension::new(id, true, registered.msg.clone()));
            }
            Some(gnmi_ext::extension::Ext::MasterArbitration(_)) => {
                if !matches!(operation, ExtensionOperation::Set) {
                    return Err(GnmiError::unimplemented(
                        "gNMI master-arbitration extension is only supported on Set",
                    ));
                }
            }
            Some(gnmi_ext::extension::Ext::History(_)) => {
                record_extension("history", ExtensionMetricOutcome::Rejected);
                return Err(GnmiError::unimplemented(
                    "gNMI history extension is not implemented",
                ));
            }
            None => return Err(GnmiError::invalid("gNMI extension is empty")),
        }
    }
    registry.validate_request(&normalized)?;
    if !matches!(operation, ExtensionOperation::Set) {
        reject_set_only_extension(extensions)?;
    }
    Ok(())
}

fn capability_extension(id: u32) -> gnmi_ext::Extension {
    gnmi_ext::Extension {
        ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
            gnmi_ext::RegisteredExtension {
                id: id as i32,
                msg: Vec::new(),
            },
        )),
    }
}

fn master_arbitration_capability_extension() -> gnmi_ext::Extension {
    gnmi_ext::Extension {
        ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
            gnmi_ext::MasterArbitration {
                role: None,
                election_id: None,
            },
        )),
    }
}

/// Converts a gNMI foundation error into a tonic status without surfacing local
/// diagnostic detail.
pub fn status_from_error(err: GnmiError) -> Status {
    Status::new(code_from_status(err.status()), err.to_string())
}

/// Maps the shared gRPC-aligned management status taxonomy to tonic codes.
pub const fn code_from_status(status: opc_mgmt_errors::MgmtStatus) -> tonic::Code {
    use opc_mgmt_errors::MgmtStatus;
    match status {
        MgmtStatus::Ok => tonic::Code::Ok,
        MgmtStatus::InvalidArgument => tonic::Code::InvalidArgument,
        MgmtStatus::NotFound => tonic::Code::NotFound,
        MgmtStatus::PermissionDenied => tonic::Code::PermissionDenied,
        MgmtStatus::Unauthenticated => tonic::Code::Unauthenticated,
        MgmtStatus::Unimplemented => tonic::Code::Unimplemented,
        MgmtStatus::Unavailable => tonic::Code::Unavailable,
        MgmtStatus::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        MgmtStatus::FailedPrecondition => tonic::Code::FailedPrecondition,
        MgmtStatus::Internal => tonic::Code::Internal,
        _ => tonic::Code::Internal,
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use opc_config_bus::{
        AuthorizationContext, AuthorizationError, ConfigAuthorizer, ConfigBus, MockManagedDatastore,
    };
    use opc_config_model::{
        AuthStrength, ConfigError, RequestId, TrustedPrincipal, ValidationContext, ValidationError,
        WorkloadIdentity as ConfigWorkloadIdentity, YangPath,
    };
    use opc_mgmt_audit::{
        AuditError, AuditEvent, AuditOutcome, AuditReasonCode, AuditSink, SchemaNodePath,
    };
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_limits::MgmtLimits;
    use opc_mgmt_opstate::{
        operational_event_channel, OperationalError, OperationalEvent, OperationalEventReceiver,
        OperationalEventSource, OperationalRequest, OperationalResponse, OperationalStateProvider,
        OperationalSubscriptionRequest, OperationalValue,
    };
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, YangPathPattern};
    use opc_redaction::metrics::METRICS;
    use prost::Message;
    use tonic::codec::Codec;
    use tonic::Code;

    use super::*;
    use crate::proto::gnmi::g_nmi_server::GNmi;
    use crate::subscribe::{
        render_snapshot_responses, send_operational_event, serve_subscribe_stream, SubscribePlan,
    };
    use crate::{
        CapabilityProfile, CommitConfirmedExtension, ExtensionRegistry, GnmiArbitrationConfig,
        GnmiJsonProjectionError, GnmiJsonUpdate, GnmiPatchApplicator, GnmiVersion, ReadSelection,
        GNMI_VERSION, OPC_COMMIT_CONFIRMED_EXTENSION_ID,
    };
    use opc_types::{SchemaDigest, TenantId};

    struct TestRegistry;

    static MODELS: &[ModelData] = &[
        ModelData {
            name: "demo-system",
            revision: "2026-06-15",
            namespace: "urn:demo",
            prefix: "sys",
        },
        ModelData {
            name: "demo-if",
            revision: "2026-06-14",
            namespace: "urn:if",
            prefix: "if",
        },
    ];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-if", "demo-system"],
    }];

    static NODES: &[NodeMeta] = &[
        NodeMeta {
            path: "/sys:system",
            module: "demo-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:contact",
                "/sys:system/sys:hostname",
                "/sys:system/sys:uptime",
                "/sys:system/sys:user",
            ],
        },
        NodeMeta {
            path: "/sys:system/sys:contact",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:hostname",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:uptime",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: false,
            leaf_type: Some(LeafType::Uint32),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:user",
            module: "demo-system",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: &["name"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:user/sys:name",
                "/sys:system/sys:user/sys:role",
            ],
        },
        NodeMeta {
            path: "/sys:system/sys:user/sys:name",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:user/sys:role",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
    ];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:test"
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

    struct FixedPolicy(NacmPolicy);

    impl PolicySource for FixedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<opc_nacm::NacmPolicy, AuthzError> {
            Ok(self.0.clone())
        }
    }

    struct TestOperationalState;

    impl OperationalStateProvider for TestOperationalState {
        fn get(
            &self,
            request: &OperationalRequest,
        ) -> Result<OperationalResponse, OperationalError> {
            let path = opc_config_model::YangPath::new("/sys:system/sys:uptime")
                .expect("static state path");
            if request.paths().contains(&path) {
                Ok(OperationalResponse::new([OperationalValue::new(
                    path, "123",
                )
                .expect("state json")]))
            } else {
                Ok(OperationalResponse::default())
            }
        }
    }

    #[derive(Default)]
    struct TestOperationalEvents {
        requests: Mutex<Vec<OperationalSubscriptionRequest>>,
    }

    impl OperationalEventSource for TestOperationalEvents {
        fn subscribe(
            &self,
            request: &OperationalSubscriptionRequest,
        ) -> Result<OperationalEventReceiver, OperationalError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            let (_tx, rx) = operational_event_channel(request.max_queued_events());
            Ok(rx)
        }
    }

    struct FailingOperationalState;

    impl OperationalStateProvider for FailingOperationalState {
        fn get(
            &self,
            _request: &OperationalRequest,
        ) -> Result<OperationalResponse, OperationalError> {
            Err(OperationalError::unavailable(
                "secret-operational-backend-detail",
            ))
        }
    }

    #[derive(Clone, Default)]
    struct CapturingAudit {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for CapturingAudit {
        fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events.lock().expect("audit mutex").push(event.clone());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FailingAudit;

    impl AuditSink for FailingAudit {
        fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::unavailable(
                "failed writing audit for /sys:system/sys:user[sys:name='secret-admin']",
            ))
        }
    }

    struct BrokenPolicy;

    impl PolicySource for BrokenPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Err(AuthzError::PolicyUnavailable)
        }
    }

    struct UnitPatcher;

    #[derive(Clone, PartialEq, Eq)]
    struct DemoUser {
        role: String,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct DemoConfig {
        hostname: String,
        users: BTreeMap<String, DemoUser>,
    }

    impl OpcConfig for DemoConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([2u8; 32])
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            if self == previous {
                Ok(Vec::new())
            } else {
                Ok(vec![()])
            }
        }

        fn changed_paths(
            &self,
            previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            let mut paths = Vec::new();
            if self.hostname != previous.hostname {
                paths.push(YangPath::new("/sys:system/sys:hostname").expect("static path"));
            }
            for (name, current) in &self.users {
                match previous.users.get(name) {
                    Some(previous) if previous.role == current.role => {}
                    _ => paths.push(user_role_yang_path(name)),
                }
            }
            for name in previous.users.keys() {
                if !self.users.contains_key(name) {
                    paths.push(user_entry_yang_path(name));
                }
            }
            paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            paths.dedup();
            Ok(paths)
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            if self.hostname == "invalid-syntax-secret" {
                return Err(ValidationError::syntax(
                    "hostname contains forbidden syntax",
                ));
            }
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    impl GnmiPatchApplicator<DemoConfig> for UnitPatcher {
        fn apply_set(
            &self,
            running: &DemoConfig,
            set: &crate::NormalizedSet,
        ) -> Result<DemoConfig, GnmiError> {
            let mut candidate = running.clone();
            for path in &set.deletes {
                apply_demo_delete(&mut candidate, path)?;
            }
            for (path, value) in &set.replaces {
                apply_demo_value(&mut candidate, path, value)?;
            }
            for (path, value) in &set.updates {
                apply_demo_value(&mut candidate, path, value)?;
            }
            for (path, value) in &set.union_replaces {
                apply_demo_value(&mut candidate, path, value)?;
            }
            Ok(candidate)
        }
    }

    struct BlockingOncePatcher {
        blocked: AtomicBool,
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl BlockingOncePatcher {
        fn new(
            started: tokio::sync::oneshot::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        ) -> Self {
            Self {
                blocked: AtomicBool::new(false),
                started: Mutex::new(Some(started)),
                release: Mutex::new(Some(release)),
            }
        }
    }

    impl GnmiPatchApplicator<DemoConfig> for BlockingOncePatcher {
        fn apply_set(
            &self,
            running: &DemoConfig,
            set: &crate::NormalizedSet,
        ) -> Result<DemoConfig, GnmiError> {
            let candidate = UnitPatcher.apply_set(running, set)?;
            if !self.blocked.swap(true, Ordering::SeqCst) {
                if let Some(started) = self.started.lock().expect("started mutex").take() {
                    let _ = started.send(());
                }
                let release = self
                    .release
                    .lock()
                    .expect("release mutex")
                    .take()
                    .expect("release receiver present");
                release.recv().expect("release stale Set");
            }
            Ok(candidate)
        }
    }

    fn apply_demo_value(
        candidate: &mut DemoConfig,
        path: &YangPath,
        value: &crate::NormalizedValue,
    ) -> Result<(), GnmiError> {
        let path = path.as_str();
        if path == "/sys:system/sys:hostname" {
            candidate.hostname = serde_json::from_str::<String>(value.json())
                .map_err(|_| GnmiError::invalid("invalid hostname value"))?;
            return Ok(());
        }
        if let Some(name) = role_user_name(path) {
            let role = serde_json::from_str::<String>(value.json())
                .map_err(|_| GnmiError::invalid("invalid role value"))?;
            candidate
                .users
                .entry(name.to_string())
                .or_insert_with(|| DemoUser {
                    role: String::new(),
                })
                .role = role;
            return Ok(());
        }
        Err(GnmiError::invalid("unsupported demo Set path"))
    }

    fn apply_demo_delete(candidate: &mut DemoConfig, path: &YangPath) -> Result<(), GnmiError> {
        let path = path.as_str();
        if path == "/sys:system/sys:hostname" {
            candidate.hostname.clear();
            return Ok(());
        }
        if let Some(name) = entry_user_name(path) {
            candidate.users.remove(name);
            return Ok(());
        }
        if let Some(name) = role_user_name(path) {
            if let Some(user) = candidate.users.get_mut(name) {
                user.role.clear();
            }
            return Ok(());
        }
        Err(GnmiError::invalid("unsupported demo Set path"))
    }

    fn user_entry_yang_path(name: &str) -> YangPath {
        YangPath::new(format!(
            "/sys:system/sys:user[sys:name='{}']",
            name.replace('\\', "\\\\").replace('\'', "\\'")
        ))
        .expect("static user path")
    }

    fn user_role_yang_path(name: &str) -> YangPath {
        YangPath::new(format!("{}/sys:role", user_entry_yang_path(name).as_str()))
            .expect("static user role path")
    }

    fn entry_user_name(path: &str) -> Option<&str> {
        let rest = path.strip_prefix("/sys:system/sys:user[sys:name='")?;
        let (name, suffix) = rest.split_once("']")?;
        suffix.is_empty().then_some(name)
    }

    fn role_user_name(path: &str) -> Option<&str> {
        let rest = path.strip_prefix("/sys:system/sys:user[sys:name='")?;
        let (name, suffix) = rest.split_once("']")?;
        (suffix == "/sys:role").then_some(name)
    }

    fn initial_config() -> DemoConfig {
        let mut users = BTreeMap::new();
        users.insert(
            "admin".to_string(),
            DemoUser {
                role: "superuser".to_string(),
            },
        );
        users.insert(
            "guest".to_string(),
            DemoUser {
                role: "readonly".to_string(),
            },
        );
        DemoConfig {
            hostname: "amf-1".to_string(),
            users,
        }
    }

    #[derive(Clone)]
    struct TestBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
        policy: Arc<dyn PolicySource>,
        operational: Arc<dyn OperationalStateProvider>,
        events: Option<Arc<dyn OperationalEventSource>>,
        patcher: Arc<dyn GnmiPatchApplicator<DemoConfig>>,
    }

    impl GnmiConfigBinding<DemoConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema(&self) -> &'static dyn SchemaRegistry {
            &TestRegistry
        }

        fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<DemoConfig>> {
            Arc::clone(&self.patcher)
        }

        fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
            Arc::clone(&self.operational)
        }

        fn operational_events(&self) -> Option<Arc<dyn OperationalEventSource>> {
            self.events.clone()
        }

        fn policy_source(&self) -> Arc<dyn PolicySource> {
            Arc::clone(&self.policy)
        }

        fn render_running_json(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
            let mut updates = Vec::new();
            if selection.contains("/sys:system/sys:hostname") {
                updates.push(GnmiJsonUpdate::new(
                    opc_config_model::YangPath::new("/sys:system/sys:hostname")
                        .expect("static config path"),
                    serde_json::to_string(&config.hostname)
                        .map_err(|_| GnmiJsonProjectionError::projection("hostname JSON"))?,
                )?);
            }
            if selection.contains("/sys:system/sys:contact") {
                updates.push(GnmiJsonUpdate::new(
                    opc_config_model::YangPath::new("/sys:system/sys:contact")
                        .expect("static config path"),
                    r#""ops""#,
                )?);
            }
            for (name, user) in &config.users {
                let role_path = opc_config_model::YangPath::new(format!(
                    "/sys:system/sys:user[sys:name='{}']/sys:role",
                    name.replace('\\', "\\\\").replace('\'', "\\'")
                ))
                .expect("static user role path");
                if selection.contains_path("/sys:system/sys:user/sys:role", &role_path) {
                    updates.push(GnmiJsonUpdate::new(
                        role_path,
                        serde_json::to_string(&user.role)
                            .map_err(|_| GnmiJsonProjectionError::projection("role JSON"))?,
                    )?);
                }
            }
            Ok(updates)
        }
    }

    async fn service() -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication(false).await
    }

    fn unit_patcher() -> Arc<dyn GnmiPatchApplicator<DemoConfig>> {
        Arc::new(UnitPatcher)
    }

    async fn authenticated_service() -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication(true).await
    }

    async fn service_with_authentication(
        authenticated: bool,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_and_limits(authenticated, MgmtLimits::default()).await
    }

    async fn authenticated_service_with_limits(
        limits: MgmtLimits,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_and_limits(true, limits).await
    }

    async fn service_with_authentication_and_limits(
        authenticated: bool,
        limits: MgmtLimits,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_limits_extensions(
            authenticated,
            limits,
            ExtensionRegistry::default(),
        )
        .await
    }

    async fn service_with_authentication_limits_extensions(
        authenticated: bool,
        limits: MgmtLimits,
        extensions: ExtensionRegistry,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_limits_extensions_arbitration(
            authenticated,
            limits,
            extensions,
            GnmiArbitrationConfig::disabled(),
        )
        .await
    }

    async fn authenticated_service_with_arbitration(
        arbitration: GnmiArbitrationConfig,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_limits_extensions_arbitration(
            true,
            MgmtLimits::default(),
            ExtensionRegistry::default(),
            arbitration,
        )
        .await
    }

    async fn authenticated_service_with_extensions_and_arbitration(
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
    ) -> GnmiService<DemoConfig, TestBinding> {
        service_with_authentication_limits_extensions_arbitration(
            true,
            MgmtLimits::default(),
            extensions,
            arbitration,
        )
        .await
    }

    async fn service_with_authentication_limits_extensions_arbitration(
        authenticated: bool,
        limits: MgmtLimits,
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
    ) -> GnmiService<DemoConfig, TestBinding> {
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new_with_arbitration(
            TestBinding {
                bus,
                policy: Arc::new(FixedPolicy(allow_all_read_policy())),
                operational: Arc::new(TestOperationalState),
                events: None,
                patcher: unit_patcher(),
            },
            limits,
            profile,
            extensions,
            arbitration,
        )
        .expect("server");
        if authenticated {
            GnmiService::new_authenticated(server)
        } else {
            GnmiService::new(server)
        }
    }

    fn authenticated_principal() -> AuthenticatedGnmiPrincipal {
        authenticated_principal_for("gnmi-client", "test")
    }

    fn authenticated_principal_for(user: &str, tenant: &'static str) -> AuthenticatedGnmiPrincipal {
        AuthenticatedGnmiPrincipal::new(
            TrustedPrincipal::new(
                ConfigWorkloadIdentity::User(user.to_string()),
                TenantId::from_static(tenant),
            )
            .with_auth_strength(AuthStrength::MutualTls),
        )
    }

    fn module_registry() -> ModuleRegistry {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("demo-system module");
        modules
            .register_module("demo-if", "if")
            .expect("demo-if module");
        modules
    }

    fn allow_all_read_policy() -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system", &modules).expect("root pattern"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("subtree pattern"),
            ))
            .build()
    }

    fn allow_all_subscribe_policy() -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Subscribe,
                YangPathPattern::parse("/sys:system", &modules).expect("root pattern"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Subscribe,
                YangPathPattern::parse("/sys:system/**", &modules).expect("subtree pattern"),
            ))
            .build()
    }

    fn allow_all_read_and_subscribe_policy() -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system", &modules).expect("root read pattern"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("subtree read pattern"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Subscribe,
                YangPathPattern::parse("/sys:system", &modules).expect("root subscribe pattern"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Subscribe,
                YangPathPattern::parse("/sys:system/**", &modules)
                    .expect("subtree subscribe pattern"),
            ))
            .build()
    }

    fn deny_hostname_policy() -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/sys:hostname", &modules)
                    .expect("deny hostname"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("allow subtree"),
            ))
            .build()
    }

    async fn authenticated_service_with_policy(
        policy: NacmPolicy,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events(
            policy,
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            None,
            MgmtLimits::default(),
        )
        .await
    }

    async fn authenticated_service_with_write_authorizer_and_audit(
        authorizer: Arc<dyn ConfigAuthorizer>,
        audit: Arc<dyn AuditSink>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        let bus = Arc::new(
            ConfigBus::new(initial_config(), MockManagedDatastore::new(), authorizer)
                .await
                .expect("bus"),
        );
        authenticated_service_with_policy_bus_events_audit(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            bus,
            None,
            MgmtLimits::default(),
            audit,
            Arc::new(TestOperationalState),
        )
        .await
    }

    async fn authenticated_service_with_policy_and_event_source(
        policy: NacmPolicy,
        events: Arc<dyn OperationalEventSource>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_limits_events(policy, MgmtLimits::default(), Some(events))
            .await
    }

    async fn authenticated_service_with_policy_and_audit(
        policy: NacmPolicy,
        audit: Arc<dyn AuditSink>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_source_operational_audit(
            Arc::new(FixedPolicy(policy)),
            Arc::new(TestOperationalState),
            audit,
        )
        .await
    }

    async fn authenticated_service_with_policy_source_operational_audit(
        policy: Arc<dyn PolicySource>,
        operational: Arc<dyn OperationalStateProvider>,
        audit: Arc<dyn AuditSink>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_source_operational_limits_audit(
            policy,
            operational,
            MgmtLimits::default(),
            audit,
        )
        .await
    }

    async fn authenticated_service_with_policy_source_operational_limits_audit(
        policy: Arc<dyn PolicySource>,
        operational: Arc<dyn OperationalStateProvider>,
        limits: MgmtLimits,
        audit: Arc<dyn AuditSink>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events_audit(
            policy,
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            None,
            limits,
            audit,
            operational,
        )
        .await
    }

    async fn authenticated_service_with_policy_limits_events(
        policy: NacmPolicy,
        limits: MgmtLimits,
        events: Option<Arc<dyn OperationalEventSource>>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events(
            policy,
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            events,
            limits,
        )
        .await
    }

    async fn authenticated_service_with_policy_bus_events(
        policy: NacmPolicy,
        bus: Arc<ConfigBus<DemoConfig>>,
        events: Option<Arc<dyn OperationalEventSource>>,
        limits: MgmtLimits,
    ) -> GnmiService<DemoConfig, TestBinding> {
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new(
            TestBinding {
                bus,
                policy: Arc::new(FixedPolicy(policy)),
                operational: Arc::new(TestOperationalState),
                events,
                patcher: unit_patcher(),
            },
            limits,
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server");
        GnmiService::new_authenticated(server)
    }

    async fn authenticated_service_with_policy_bus_events_audit(
        policy: Arc<dyn PolicySource>,
        bus: Arc<ConfigBus<DemoConfig>>,
        events: Option<Arc<dyn OperationalEventSource>>,
        limits: MgmtLimits,
        audit: Arc<dyn AuditSink>,
        operational: Arc<dyn OperationalStateProvider>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events_audit_extensions(
            policy,
            bus,
            events,
            limits,
            audit,
            operational,
            ExtensionRegistry::default(),
        )
        .await
    }

    async fn authenticated_service_with_policy_bus_events_audit_extensions(
        policy: Arc<dyn PolicySource>,
        bus: Arc<ConfigBus<DemoConfig>>,
        events: Option<Arc<dyn OperationalEventSource>>,
        limits: MgmtLimits,
        audit: Arc<dyn AuditSink>,
        operational: Arc<dyn OperationalStateProvider>,
        extensions: ExtensionRegistry,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events_audit_extensions_arbitration(
            policy,
            bus,
            events,
            limits,
            audit,
            operational,
            TestProtocolOptions::new(extensions, GnmiArbitrationConfig::disabled()),
        )
        .await
    }

    struct TestProtocolOptions {
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
    }

    impl TestProtocolOptions {
        fn new(extensions: ExtensionRegistry, arbitration: GnmiArbitrationConfig) -> Self {
            Self {
                extensions,
                arbitration,
            }
        }
    }

    async fn authenticated_service_with_policy_bus_events_audit_extensions_arbitration(
        policy: Arc<dyn PolicySource>,
        bus: Arc<ConfigBus<DemoConfig>>,
        events: Option<Arc<dyn OperationalEventSource>>,
        limits: MgmtLimits,
        audit: Arc<dyn AuditSink>,
        operational: Arc<dyn OperationalStateProvider>,
        protocol: TestProtocolOptions,
    ) -> GnmiService<DemoConfig, TestBinding> {
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new_with_audit_and_arbitration(
            TestBinding {
                bus,
                policy,
                operational,
                events,
                patcher: unit_patcher(),
            },
            limits,
            profile,
            protocol.extensions,
            protocol.arbitration,
            audit,
        )
        .expect("server");
        GnmiService::new_authenticated(server)
    }

    async fn authenticated_service_with_extensions_arbitration_and_audit(
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
        audit: Arc<dyn AuditSink>,
    ) -> GnmiService<DemoConfig, TestBinding> {
        authenticated_service_with_policy_bus_events_audit_extensions_arbitration(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            None,
            MgmtLimits::default(),
            audit,
            Arc::new(TestOperationalState),
            TestProtocolOptions::new(extensions, arbitration),
        )
        .await
    }

    struct DenyWriteAuthorizer;

    #[async_trait::async_trait]
    impl ConfigAuthorizer for DenyWriteAuthorizer {
        async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            assert_eq!(ctx.transport, opc_config_model::TransportType::Gnmi);
            assert_eq!(ctx.source, opc_config_model::RequestSource::Northbound);
            assert_eq!(ctx.operation, opc_config_model::ConfigOperation::Replace);
            assert_eq!(
                ctx.changed_paths,
                vec![YangPath::new("/sys:system/sys:hostname").expect("static path")]
            );
            Err(AuthorizationError::new("secret-authorizer-detail"))
        }
    }

    fn path_elem(name: &str) -> gnmi::PathElem {
        gnmi::PathElem {
            name: name.to_string(),
            key: Default::default(),
        }
    }

    fn keyed_path_elem(name: &str, key: &str, value: &str) -> gnmi::PathElem {
        gnmi::PathElem {
            name: name.to_string(),
            key: [(key.to_string(), value.to_string())].into_iter().collect(),
        }
    }

    fn gnmi_path(elems: Vec<gnmi::PathElem>) -> gnmi::Path {
        gnmi::Path {
            element: Vec::new(),
            origin: String::new(),
            elem: elems,
            target: String::new(),
        }
    }

    fn hostname_path() -> gnmi::Path {
        gnmi_path(vec![path_elem("system"), path_elem("hostname")])
    }

    fn uptime_path() -> gnmi::Path {
        gnmi_path(vec![path_elem("system"), path_elem("uptime")])
    }

    fn user_path(name: &str) -> gnmi::Path {
        gnmi_path(vec![
            path_elem("system"),
            keyed_path_elem("user", "name", name),
        ])
    }

    fn user_role_path(name: &str) -> gnmi::Path {
        gnmi_path(vec![
            path_elem("system"),
            keyed_path_elem("user", "name", name),
            path_elem("role"),
        ])
    }

    fn json_update(path: gnmi::Path, json: impl Into<Vec<u8>>) -> gnmi::Update {
        gnmi::Update {
            path: Some(path),
            value: None,
            val: Some(gnmi::TypedValue {
                value: Some(gnmi::typed_value::Value::JsonIetfVal(json.into())),
            }),
            duplicates: 0,
        }
    }

    fn authenticated_set_request(set: gnmi::SetRequest) -> Request<gnmi::SetRequest> {
        authenticated_set_request_for(set, authenticated_principal())
    }

    fn authenticated_set_request_for(
        set: gnmi::SetRequest,
        principal: AuthenticatedGnmiPrincipal,
    ) -> Request<gnmi::SetRequest> {
        let mut request = Request::new(set);
        request.extensions_mut().insert(principal);
        request
    }

    fn authenticated_get_request(get: gnmi::GetRequest) -> Request<gnmi::GetRequest> {
        let mut request = Request::new(get);
        request.extensions_mut().insert(authenticated_principal());
        request
    }

    fn commit_confirmed_extension(payload: CommitConfirmedExtension) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                gnmi_ext::RegisteredExtension {
                    id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                    msg: payload.encode_payload(),
                },
            )),
        }
    }

    fn fenced_commit_confirmed_extensions(
        payload: CommitConfirmedExtension,
    ) -> Vec<gnmi_ext::Extension> {
        vec![
            master_arbitration_extension(Some("commit-confirmed"), 1, 0),
            commit_confirmed_extension(payload),
        ]
    }

    fn malformed_commit_confirmed_extension(payload: impl Into<Vec<u8>>) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                gnmi_ext::RegisteredExtension {
                    id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                    msg: payload.into(),
                },
            )),
        }
    }

    fn token_like_commit_confirmed_extension(
        payload: CommitConfirmedExtension,
        token: &[u8],
    ) -> gnmi_ext::Extension {
        let mut encoded = payload.encode_payload();
        encoded.push((3 << 3) | 2);
        encoded.push(u8::try_from(token.len()).expect("test token length"));
        encoded.extend_from_slice(token);
        malformed_commit_confirmed_extension(encoded)
    }

    fn master_arbitration_extension(
        role_id: Option<&str>,
        high: u64,
        low: u64,
    ) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
                gnmi_ext::MasterArbitration {
                    role: role_id.map(|id| gnmi_ext::Role { id: id.to_string() }),
                    election_id: Some(gnmi_ext::Uint128 { high, low }),
                },
            )),
        }
    }

    fn history_extension() -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::History(gnmi_ext::History {
                request: Some(gnmi_ext::history::Request::Range(gnmi_ext::TimeRange {
                    start: 1,
                    end: 2,
                })),
            })),
        }
    }

    fn malformed_master_arbitration_extension(role_id: Option<&str>) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
                gnmi_ext::MasterArbitration {
                    role: role_id.map(|id| gnmi_ext::Role { id: id.to_string() }),
                    election_id: None,
                },
            )),
        }
    }

    fn hostname_set(hostname: &str, extension: Vec<gnmi_ext::Extension>) -> gnmi::SetRequest {
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(
                hostname_path(),
                serde_json::to_vec(hostname).expect("hostname json"),
            )],
            union_replace: Vec::new(),
            extension,
        }
    }

    async fn wait_for_hostname(service: &GnmiService<DemoConfig, TestBinding>, expected: &str) {
        for _ in 0..50 {
            if service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname
                == expected
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            expected
        );
    }

    async fn commit_hostname(service: &GnmiService<DemoConfig, TestBinding>, hostname: &str) {
        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    serde_json::to_vec(hostname).expect("hostname json"),
                )],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("commit hostname");
    }

    fn gnmi_rpc_request_count(operation: &str, outcome: &str) -> u64 {
        METRICS
            .gnmi_rpc_requests_total
            .lock()
            .expect("metrics")
            .get(&(operation.to_string(), outcome.to_string()))
            .copied()
            .unwrap_or_default()
    }

    fn gnmi_rpc_error_count(operation: &str, status: &str) -> u64 {
        METRICS
            .gnmi_rpc_errors_total
            .lock()
            .expect("metrics")
            .get(&(operation.to_string(), status.to_string()))
            .copied()
            .unwrap_or_default()
    }

    fn gnmi_set_commit_count(operation: &str) -> u64 {
        METRICS
            .gnmi_set_commit_seconds
            .lock()
            .expect("metrics")
            .get(operation)
            .map(|hist| hist.count.load(Ordering::Relaxed))
            .unwrap_or_default()
    }

    fn gnmi_extension_count(extension: &str, outcome: &str) -> u64 {
        METRICS
            .gnmi_extensions_total
            .lock()
            .expect("metrics")
            .get(&(extension.to_string(), outcome.to_string()))
            .copied()
            .unwrap_or_default()
    }

    fn schema_node_path(path: &'static str) -> SchemaNodePath {
        SchemaNodePath::new(path).expect("valid schema node path")
    }

    fn audit_failed(code: AuditReasonCode) -> AuditOutcome {
        AuditOutcome::failed_code(code)
    }

    fn audit_denied(code: AuditReasonCode) -> AuditOutcome {
        AuditOutcome::denied_code(code)
    }

    fn subscribe_list(
        mode: gnmi::subscription_list::Mode,
        path: gnmi::Path,
        subscription_mode: gnmi::SubscriptionMode,
    ) -> gnmi::SubscriptionList {
        gnmi::SubscriptionList {
            prefix: None,
            subscription: vec![gnmi::Subscription {
                path: Some(path),
                mode: subscription_mode as i32,
                sample_interval: 1_000_000,
                suppress_redundant: false,
                heartbeat_interval: 0,
            }],
            qos: None,
            mode: mode as i32,
            allow_aggregation: false,
            use_models: Vec::new(),
            encoding: gnmi::Encoding::JsonIetf as i32,
            updates_only: false,
        }
    }

    fn subscribe_request(list: gnmi::SubscriptionList) -> gnmi::SubscribeRequest {
        gnmi::SubscribeRequest {
            request: Some(gnmi::subscribe_request::Request::Subscribe(list)),
            extension: Vec::new(),
        }
    }

    fn subscribe_stream_from(
        request: gnmi::SubscribeRequest,
    ) -> tonic::Streaming<gnmi::SubscribeRequest> {
        let mut payload = Vec::new();
        request.encode(&mut payload).expect("encode request");
        let mut frame = Vec::with_capacity(payload.len() + 5);
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let body = tonic::body::Body::new(http_body_util::Full::new(bytes::Bytes::from(frame)));
        let mut codec =
            tonic::codec::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
        tonic::Streaming::new_request(codec.decoder(), body, None, None)
    }

    #[tokio::test]
    async fn capabilities_are_schema_backed_and_honest() {
        let service = service().await;
        let response = service
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .expect("capabilities")
            .into_inner();

        assert_eq!(response.g_nmi_version, "0.10.0");
        assert_eq!(
            response.supported_encodings,
            vec![gnmi::Encoding::JsonIetf as i32, gnmi::Encoding::Json as i32]
        );
        assert_eq!(response.extension, Vec::<gnmi_ext::Extension>::new());
        assert_eq!(response.supported_models.len(), 2);
        assert_eq!(response.supported_models[0].name, "demo-if");
        assert_eq!(response.supported_models[0].version, "2026-06-14");
        assert_eq!(response.supported_models[0].organization, "");
    }

    #[tokio::test]
    async fn capabilities_advertises_commit_confirmed_only_when_registered() {
        let service = service_with_authentication_limits_extensions_arbitration(
            false,
            MgmtLimits::default(),
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        let response = service
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .expect("capabilities")
            .into_inner();

        let extension = response
            .extension
            .iter()
            .find_map(|extension| match extension.ext.as_ref() {
                Some(gnmi_ext::extension::Ext::RegisteredExt(extension)) => Some(extension),
                _ => None,
            })
            .expect("expected registered extension");
        assert_eq!(extension.id, OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32);
        assert!(extension.msg.is_empty());
    }

    #[tokio::test]
    async fn commit_confirmed_registry_requires_arbitration_config() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));

        let err = match GnmiServer::new(
            TestBinding {
                bus,
                policy: Arc::new(FixedPolicy(allow_all_read_policy())),
                operational: Arc::new(TestOperationalState),
                events: None,
                patcher: unit_patcher(),
            },
            MgmtLimits::default(),
            profile,
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
        ) {
            Ok(_) => panic!("commit-confirmed without arbitration must fail closed"),
            Err(err) => err,
        };

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert!(!err.to_string().contains("commit-confirmed.v1"));
    }

    #[tokio::test]
    async fn capabilities_advertises_master_arbitration_only_when_configured() {
        let disabled = service().await;
        let disabled_response = disabled
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .expect("capabilities")
            .into_inner();
        assert!(
            !disabled_response.extension.iter().any(|extension| matches!(
                extension.ext.as_ref(),
                Some(gnmi_ext::extension::Ext::MasterArbitration(_))
            ))
        );

        let enabled =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::optional()).await;
        let mut request = Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());
        let enabled_response = enabled
            .capabilities(request)
            .await
            .expect("capabilities")
            .into_inner();
        assert!(enabled_response.extension.iter().any(|extension| matches!(
            extension.ext.as_ref(),
            Some(gnmi_ext::extension::Ext::MasterArbitration(_))
        )));
    }

    #[tokio::test]
    async fn capabilities_does_not_advertise_history_without_replay_source() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        let mut request = Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());
        let response = service
            .capabilities(request)
            .await
            .expect("capabilities")
            .into_inner();

        assert!(response.extension.iter().any(|extension| matches!(
            extension.ext.as_ref(),
            Some(gnmi_ext::extension::Ext::RegisteredExt(_))
        )));
        assert!(response.extension.iter().any(|extension| matches!(
            extension.ext.as_ref(),
            Some(gnmi_ext::extension::Ext::MasterArbitration(_))
        )));
        assert!(!response.extension.iter().any(|extension| matches!(
            extension.ext.as_ref(),
            Some(gnmi_ext::extension::Ext::History(_))
        )));
    }

    #[tokio::test]
    async fn capabilities_reject_unknown_registered_extension_without_payload_leak() {
        let service = service().await;
        let status = service
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: vec![gnmi_ext::Extension {
                    ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                        gnmi_ext::RegisteredExtension {
                            id: gnmi_ext::ExtensionId::EidExperimental as i32,
                            msg: b"secret-extension-payload".to_vec(),
                        },
                    )),
                }],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "gNMI operation is not supported");
        assert!(!status.message().contains("secret-extension-payload"));
    }

    #[tokio::test]
    async fn capabilities_rejects_set_only_commit_confirmed_extension() {
        let service = service_with_authentication_limits_extensions_arbitration(
            false,
            MgmtLimits::default(),
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        let status = service
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: vec![commit_confirmed_extension(
                    CommitConfirmedExtension::confirm(),
                )],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "gNMI operation is not supported");
    }

    #[tokio::test]
    async fn authenticated_capabilities_requires_transport_principal() {
        let service = authenticated_service().await;
        let status = service
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(status.message(), "gNMI authentication required");
    }

    #[tokio::test]
    async fn authenticated_capabilities_accepts_grant_free_principal() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service
            .capabilities(request)
            .await
            .expect("capabilities")
            .into_inner();

        assert_eq!(response.g_nmi_version, "0.10.0");
    }

    #[tokio::test]
    async fn authenticated_capabilities_rejects_non_mtls_principal() {
        let service = authenticated_service().await;
        let principal = TrustedPrincipal::new(
            ConfigWorkloadIdentity::User("gnmi-client".to_string()),
            TenantId::from_static("test"),
        );
        let mut request = Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        });
        request
            .extensions_mut()
            .insert(AuthenticatedGnmiPrincipal::new(principal));

        let status = service.capabilities(request).await.unwrap_err();

        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "gNMI access denied");
    }

    #[tokio::test]
    async fn authenticated_capabilities_rejects_transport_derived_grants() {
        let service = authenticated_service().await;
        let principal = TrustedPrincipal::new(
            ConfigWorkloadIdentity::User("gnmi-client".to_string()),
            TenantId::from_static("test"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
        .with_roles(["admin"]);
        let mut request = Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        });
        request
            .extensions_mut()
            .insert(AuthenticatedGnmiPrincipal::new(principal));

        let status = service.capabilities(request).await.unwrap_err();

        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "gNMI access denied");
    }

    #[tokio::test]
    async fn authenticated_get_config_reads_authorized_running_json() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![
                    gnmi::PathElem {
                        name: "system".to_string(),
                        key: Default::default(),
                    },
                    gnmi::PathElem {
                        name: "hostname".to_string(),
                        key: Default::default(),
                    },
                ],
                target: String::new(),
            }],
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();

        let update = &response.notification[0].update[0];
        assert_eq!(
            update.path.as_ref().expect("path").elem[1].name,
            "sys:hostname"
        );
        assert_eq!(
            update.val.as_ref().and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(
                br#""amf-1""#.to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn authenticated_get_state_reads_operational_provider() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![
                    gnmi::PathElem {
                        name: "system".to_string(),
                        key: Default::default(),
                    },
                    gnmi::PathElem {
                        name: "uptime".to_string(),
                        key: Default::default(),
                    },
                ],
                target: String::new(),
            }],
            r#type: gnmi::get_request::DataType::State as i32,
            encoding: gnmi::Encoding::Json as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();

        let update = &response.notification[0].update[0];
        assert_eq!(
            update.val.as_ref().and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonVal(b"123".to_vec()))
        );
    }

    #[tokio::test]
    async fn authenticated_get_prefix_only_reads_prefix_subtree_not_whole_datastore() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: Some(gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![
                    gnmi::PathElem {
                        name: "system".to_string(),
                        key: Default::default(),
                    },
                    gnmi::PathElem {
                        name: "hostname".to_string(),
                        key: Default::default(),
                    },
                ],
                target: String::new(),
            }),
            path: Vec::new(),
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();
        let updates = &response.notification[0].update;

        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].path.as_ref().expect("path").elem[1].name,
            "sys:hostname"
        );
        assert_eq!(
            updates[0]
                .val
                .as_ref()
                .and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(
                br#""amf-1""#.to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn authenticated_get_keyed_list_predicate_reads_only_selected_instance() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![
                    gnmi::PathElem {
                        name: "system".to_string(),
                        key: Default::default(),
                    },
                    gnmi::PathElem {
                        name: "user".to_string(),
                        key: [("name".to_string(), "admin".to_string())]
                            .into_iter()
                            .collect(),
                    },
                    gnmi::PathElem {
                        name: "role".to_string(),
                        key: Default::default(),
                    },
                ],
                target: String::new(),
            }],
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();

        assert_eq!(response.notification[0].update.len(), 1);
        let update = &response.notification[0].update[0];
        assert_eq!(
            update.path.as_ref().expect("path").elem[1]
                .key
                .get("sys:name"),
            Some(&"admin".to_string())
        );
        assert_eq!(
            update.val.as_ref().and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(
                br#""superuser""#.to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn authenticated_get_success_is_audited_without_values_or_key_predicates() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        let response = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![user_role_path("admin")],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("get")
            .into_inner();

        assert_eq!(response.notification[0].update.len(), 1);
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:user/sys:role")]
        );
        let audit_debug = format!("{:?}", events);
        assert!(!audit_debug.contains("admin"));
        assert!(!audit_debug.contains("superuser"));
        assert!(!audit_debug.contains("sys:name"));
    }

    #[tokio::test]
    async fn authenticated_get_all_merges_config_and_state() {
        let service = authenticated_service().await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: Vec::new(),
            r#type: gnmi::get_request::DataType::All as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();
        let values = response.notification[0]
            .update
            .iter()
            .filter_map(|update| update.val.as_ref())
            .filter_map(|value| value.value.as_ref())
            .collect::<Vec<_>>();

        assert!(values.contains(&&gnmi::typed_value::Value::JsonIetfVal(
            br#""amf-1""#.to_vec()
        )));
        assert!(values.contains(&&gnmi::typed_value::Value::JsonIetfVal(b"123".to_vec())));
    }

    #[tokio::test]
    async fn authenticated_get_omits_nacm_denied_paths() {
        let service = authenticated_service_with_policy(deny_hostname_policy()).await;
        let mut request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![
                    gnmi::PathElem {
                        name: "system".to_string(),
                        key: Default::default(),
                    },
                    gnmi::PathElem {
                        name: "hostname".to_string(),
                        key: Default::default(),
                    },
                ],
                target: String::new(),
            }],
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        request.extensions_mut().insert(authenticated_principal());

        let response = service.get(request).await.expect("get").into_inner();

        assert!(response.notification.is_empty());
    }

    #[tokio::test]
    async fn authenticated_get_all_denied_is_audited_as_empty_success() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            NacmPolicy::empty(opc_nacm::PolicyVersion::new(100)),
            Arc::new(audit.clone()),
        )
        .await;

        let response = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("get")
            .into_inner();

        assert!(response.notification.is_empty());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn authenticated_get_partial_nacm_suppression_audits_allowed_paths_only() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            deny_hostname_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        let response = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![gnmi_path(vec![path_elem("system")])],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("get")
            .into_inner();

        let response_debug = format!("{:?}", response);
        assert!(!response_debug.contains("amf-1"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0]
            .schema_paths
            .contains(&schema_node_path("/sys:system/sys:contact")));
        assert!(!events[0]
            .schema_paths
            .contains(&schema_node_path("/sys:system/sys:hostname")));
    }

    #[tokio::test]
    async fn authenticated_get_extension_rejection_is_audited_without_payload() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: vec![gnmi_ext::Extension {
                    ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                        gnmi_ext::RegisteredExtension {
                            id: gnmi_ext::ExtensionId::EidExperimental as i32,
                            msg: b"secret-get-extension".to_vec(),
                        },
                    )),
                }],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert!(!status.message().contains("secret-get-extension"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-get-extension"));
    }

    #[tokio::test]
    async fn authenticated_get_invalid_inputs_are_audited_without_request_values() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        let unsupported_encoding = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: Vec::new(),
                r#type: gnmi::get_request::DataType::All as i32,
                encoding: gnmi::Encoding::Proto as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(unsupported_encoding.code(), Code::Unimplemented);

        let unknown_model = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: Vec::new(),
                r#type: gnmi::get_request::DataType::All as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: vec![gnmi::ModelData {
                    name: "secret-model".to_string(),
                    organization: String::new(),
                    version: String::new(),
                }],
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(unknown_model.code(), Code::InvalidArgument);

        let invalid_keyed_path = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![gnmi::Path {
                    element: Vec::new(),
                    origin: String::new(),
                    elem: vec![gnmi::PathElem {
                        name: "user".to_string(),
                        key: [("name".to_string(), "secret-admin".to_string())]
                            .into_iter()
                            .collect(),
                    }],
                    target: String::new(),
                }],
                r#type: gnmi::get_request::DataType::All as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid_keyed_path.code(), Code::InvalidArgument);
        assert!(!invalid_keyed_path.message().contains("secret-admin"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert_eq!(
            events[1].outcome,
            audit_failed(AuditReasonCode::INVALID_VALUE)
        );
        assert_eq!(
            events[2].outcome,
            audit_failed(AuditReasonCode::INVALID_VALUE)
        );
        assert!(events.iter().all(|event| event.schema_paths.is_empty()));
        let audit_debug = format!("{:?}", events);
        assert!(!audit_debug.contains("secret-model"));
        assert!(!audit_debug.contains("secret-admin"));
    }

    #[tokio::test]
    async fn authenticated_get_path_limit_failure_is_audited_without_request_values() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_source_operational_limits_audit(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(TestOperationalState),
            MgmtLimits {
                max_paths_per_request: 1,
                ..MgmtLimits::default()
            },
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![
                    hostname_path(),
                    gnmi_path(vec![path_elem("system"), path_elem("contact")]),
                ],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(!status.message().contains("hostname"));
        assert!(!status.message().contains("contact"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, audit_failed(AuditReasonCode::TOO_BIG));
        assert!(events[0].schema_paths.is_empty());
        let audit_debug = format!("{:?}", events);
        assert!(!audit_debug.contains("hostname"));
        assert!(!audit_debug.contains("contact"));
    }

    #[tokio::test]
    async fn authenticated_get_policy_source_failure_is_audited_with_schema_path() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_source_operational_audit(
            Arc::new(BrokenPolicy),
            Arc::new(TestOperationalState),
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unavailable);
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::RESOURCE_DENIED)
        );
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:hostname")]
        );
    }

    #[tokio::test]
    async fn authenticated_get_operational_provider_failure_is_audited_without_detail() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_source_operational_audit(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(FailingOperationalState),
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![uptime_path()],
                r#type: gnmi::get_request::DataType::State as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unavailable);
        assert!(!status.message().contains("secret-operational"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::RESOURCE_DENIED)
        );
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:uptime")]
        );
        assert!(!format!("{:?}", events).contains("secret-operational"));
    }

    #[tokio::test]
    async fn authenticated_get_value_limit_failure_is_audited_without_value() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_source_operational_limits_audit(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(TestOperationalState),
            MgmtLimits {
                max_value_bytes: 2,
                ..MgmtLimits::default()
            },
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![uptime_path()],
                r#type: gnmi::get_request::DataType::State as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(!status.message().contains("123"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, audit_failed(AuditReasonCode::TOO_BIG));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:uptime")]
        );
        assert!(!format!("{:?}", events).contains("123"));
    }

    #[tokio::test]
    async fn authenticated_get_success_audit_failure_is_generic_without_data() {
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(FailingAudit),
        )
        .await;

        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "gNMI internal error");
        assert!(!status.message().contains("amf-1"));
        assert!(!status.message().contains("secret-admin"));
    }

    #[tokio::test]
    async fn authenticated_get_rejects_unsupported_encoding_and_unknown_keyed_paths_without_leak() {
        let service = authenticated_service().await;
        let mut unsupported_encoding = Request::new(gnmi::GetRequest {
            prefix: None,
            path: Vec::new(),
            r#type: gnmi::get_request::DataType::All as i32,
            encoding: gnmi::Encoding::Proto as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        unsupported_encoding
            .extensions_mut()
            .insert(authenticated_principal());
        let status = service.get(unsupported_encoding).await.unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented);

        let mut keyed = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![gnmi::Path {
                element: Vec::new(),
                origin: String::new(),
                elem: vec![gnmi::PathElem {
                    name: "user".to_string(),
                    key: [("name".to_string(), "secret-admin".to_string())]
                        .into_iter()
                        .collect(),
                }],
                target: String::new(),
            }],
            r#type: gnmi::get_request::DataType::All as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        keyed.extensions_mut().insert(authenticated_principal());
        let status = service.get(keyed).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(!status.message().contains("secret-admin"));
    }

    #[tokio::test]
    async fn authenticated_set_update_commits_running_and_returns_result() {
        let service = authenticated_service().await;
        let response = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""amf-2""#.to_vec())],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("set")
            .into_inner();

        assert_eq!(response.response.len(), 1);
        assert_eq!(
            response.response[0].op,
            gnmi::update_result::Operation::Update as i32
        );
        assert_eq!(
            response.response[0].path.as_ref().unwrap().elem[1].name,
            "sys:hostname"
        );
        assert!(response.timestamp > 0);
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-2"
        );
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_missing_extension_policy_is_honest() {
        let optional =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::optional()).await;
        optional
            .set(authenticated_set_request(hostname_set(
                "optional-host",
                Vec::new(),
            )))
            .await
            .expect("optional arbitration does not require extension");
        assert_eq!(
            optional
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "optional-host"
        );

        let audit = CapturingAudit::default();
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let required = authenticated_service_with_policy_bus_events_audit_extensions_arbitration(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            bus,
            None,
            MgmtLimits::default(),
            Arc::new(audit.clone()),
            Arc::new(TestOperationalState),
            TestProtocolOptions::new(
                ExtensionRegistry::default(),
                GnmiArbitrationConfig::required(),
            ),
        )
        .await;
        let rejected = required
            .set(authenticated_set_request(hostname_set(
                "required-denied",
                Vec::new(),
            )))
            .await
            .unwrap_err();
        assert_eq!(rejected.code(), Code::PermissionDenied);
        assert_eq!(rejected.message(), "gNMI access denied");
        assert_eq!(
            required
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(
            events[0].outcome,
            audit_denied(AuditReasonCode::ACCESS_DENIED)
        );
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_rejects_when_disabled_or_malformed() {
        let disabled = authenticated_service().await;
        let disabled_status = disabled
            .set(authenticated_set_request(hostname_set(
                "disabled-arbitration",
                vec![master_arbitration_extension(Some("ops"), 1, 0)],
            )))
            .await
            .unwrap_err();
        assert_eq!(disabled_status.code(), Code::Unimplemented);
        assert_eq!(disabled_status.message(), "gNMI operation is not supported");
        assert_eq!(
            disabled
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );

        let enabled =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::required()).await;
        let malformed = enabled
            .set(authenticated_set_request(hostname_set(
                "malformed-arbitration",
                vec![malformed_master_arbitration_extension(Some("secret-role"))],
            )))
            .await
            .unwrap_err();
        assert_eq!(malformed.code(), Code::InvalidArgument);
        assert_eq!(malformed.message(), "invalid gNMI request");
        assert!(!malformed.message().contains("secret-role"));
        assert_eq!(
            enabled
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_election_rules_are_enforced() {
        let service =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::required()).await;
        let principal_a = authenticated_principal_for("gnmi-a", "test");
        let principal_b = authenticated_principal_for("gnmi-b", "test");

        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "first-master",
                    vec![master_arbitration_extension(Some("ops"), 1, 0)],
                ),
                principal_a.clone(),
            ))
            .await
            .expect("first writer");
        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "higher-master",
                    vec![master_arbitration_extension(Some("ops"), 2, 0)],
                ),
                principal_b.clone(),
            ))
            .await
            .expect("higher takeover");

        let stale = service
            .set(authenticated_set_request_for(
                hostname_set(
                    "stale-writer",
                    vec![master_arbitration_extension(Some("ops"), 1, u64::MAX)],
                ),
                principal_a.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), Code::PermissionDenied);
        assert_eq!(stale.message(), "gNMI access denied");
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "higher-master"
        );

        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "same-principal",
                    vec![master_arbitration_extension(Some("ops"), 2, 0)],
                ),
                principal_b,
            ))
            .await
            .expect("same election same principal accepted");

        let same_different = service
            .set(authenticated_set_request_for(
                hostname_set(
                    "same-different",
                    vec![master_arbitration_extension(Some("ops"), 2, 0)],
                ),
                principal_a,
            ))
            .await
            .unwrap_err();
        assert_eq!(same_different.code(), Code::PermissionDenied);
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "same-principal"
        );
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_tenant_role_and_default_role_fences() {
        let service =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::required()).await;

        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "tenant-a-ops",
                    vec![master_arbitration_extension(Some("ops"), 9, 0)],
                ),
                authenticated_principal_for("gnmi-a", "tenant-a"),
            ))
            .await
            .expect("tenant a ops master");
        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "tenant-b-ops",
                    vec![master_arbitration_extension(Some("ops"), 1, 0)],
                ),
                authenticated_principal_for("gnmi-b", "tenant-b"),
            ))
            .await
            .expect("tenant b independent");
        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "tenant-a-readonly",
                    vec![master_arbitration_extension(Some("readonly"), 1, 0)],
                ),
                authenticated_principal_for("gnmi-a", "tenant-a"),
            ))
            .await
            .expect("role independent");
        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "tenant-a-default-role",
                    vec![master_arbitration_extension(None, 1, 0)],
                ),
                authenticated_principal_for("gnmi-a", "tenant-a"),
            ))
            .await
            .expect("missing role defaults to empty role");

        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "tenant-a-default-role"
        );
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_denials_do_not_leak_or_mutate() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_bus_events_audit_extensions_arbitration(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            None,
            MgmtLimits::default(),
            Arc::new(audit.clone()),
            Arc::new(TestOperationalState),
            TestProtocolOptions::new(
                ExtensionRegistry::default(),
                GnmiArbitrationConfig::required(),
            ),
        )
        .await;
        let principal_a = authenticated_principal_for("gnmi-a", "test");
        let principal_b = authenticated_principal_for("gnmi-b", "test");
        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "secret-master-host",
                    vec![master_arbitration_extension(Some("secret-role"), 5, 0)],
                ),
                principal_a,
            ))
            .await
            .expect("first master");
        let rejected_before = gnmi_extension_count("master-arbitration", "rejected");
        let status = service
            .set(authenticated_set_request_for(
                hostname_set(
                    "secret-stale-host",
                    vec![master_arbitration_extension(Some("secret-role"), 4, 0)],
                ),
                principal_b,
            ))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "gNMI access denied");
        assert!(!status.message().contains("secret-role"));
        assert!(!status.message().contains("secret-stale-host"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "secret-master-host"
        );
        assert!(gnmi_extension_count("master-arbitration", "rejected") > rejected_before);
        let metrics_debug = format!(
            "{:?}",
            METRICS.gnmi_extensions_total.lock().expect("metrics")
        );
        assert!(!metrics_debug.contains("secret-role"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].operation, AuditOperation::Update);
        assert_eq!(
            events[1].outcome,
            audit_denied(AuditReasonCode::ACCESS_DENIED)
        );
        assert!(events[1].schema_paths.is_empty());
        let audit_debug = format!("{:?}", events);
        assert!(!audit_debug.contains("secret-role"));
        assert!(!audit_debug.contains("secret-stale-host"));
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_rolls_back_on_timeout() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        commit_hostname(&service, "rollback-parent").await;
        let response = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""pending-host""#.to_vec())],
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(
                    CommitConfirmedExtension::begin(std::time::Duration::from_millis(50))
                        .expect("payload"),
                ),
            }))
            .await
            .expect("confirmed set")
            .into_inner();

        assert_eq!(response.response.len(), 1);
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "pending-host"
        );

        wait_for_hostname(&service, "rollback-parent").await;
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_can_be_confirmed() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        commit_hostname(&service, "rollback-parent").await;
        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""confirmed-host""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(
                    CommitConfirmedExtension::begin(std::time::Duration::from_millis(120))
                        .expect("payload"),
                ),
            }))
            .await
            .expect("begin confirmed");

        let confirm = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(CommitConfirmedExtension::confirm()),
            }))
            .await
            .expect("confirm")
            .into_inner();
        assert!(confirm.response.is_empty());

        tokio::time::sleep(std::time::Duration::from_millis(180)).await;
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "confirmed-host"
        );
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_can_be_cancelled() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        commit_hostname(&service, "rollback-parent").await;
        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""cancelled-host""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(
                    CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                        .expect("payload"),
                ),
            }))
            .await
            .expect("begin confirmed");

        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(CommitConfirmedExtension::cancel()),
            }))
            .await
            .expect("cancel");

        wait_for_hostname(&service, "rollback-parent").await;
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_control_shapes_fail_closed() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        let confirm_with_update = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""bad-shape""#.to_vec())],
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(CommitConfirmedExtension::confirm()),
            }))
            .await
            .unwrap_err();
        assert_eq!(confirm_with_update.code(), Code::InvalidArgument);

        let begin_without_update = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(
                    CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                        .expect("payload"),
                ),
            }))
            .await
            .unwrap_err();
        assert_eq!(begin_without_update.code(), Code::InvalidArgument);

        let confirm_without_pending = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(CommitConfirmedExtension::confirm()),
            }))
            .await
            .unwrap_err();
        assert_eq!(confirm_without_pending.code(), Code::InvalidArgument);
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_requires_master_arbitration() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;

        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""unfenced-pending""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: vec![commit_confirmed_extension(
                    CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                        .expect("payload"),
                )],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "gNMI access denied");
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_rejects_token_like_payload_without_confirming() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_extensions_arbitration_and_audit(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
            Arc::new(audit.clone()),
        )
        .await;
        commit_hostname(&service, "rollback-parent").await;
        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""pending-token-host""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(
                    CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                        .expect("payload"),
                ),
            }))
            .await
            .expect("begin confirmed");

        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: {
                    let mut extensions =
                        vec![master_arbitration_extension(Some("commit-confirmed"), 1, 0)];
                    extensions.push(token_like_commit_confirmed_extension(
                        CommitConfirmedExtension::confirm(),
                        b"secret-persist-token",
                    ));
                    extensions
                },
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        assert!(!status.message().contains("secret-persist-token"));

        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: fenced_commit_confirmed_extensions(CommitConfirmedExtension::cancel()),
            }))
            .await
            .expect("pending commit remains cancellable");
        wait_for_hostname(&service, "rollback-parent").await;

        let events = audit.events.lock().expect("audit mutex");
        assert!(events.iter().any(|event| {
            event.operation == AuditOperation::Update
                && event.outcome == audit_failed(AuditReasonCode::INVALID_VALUE)
                && event.schema_paths.is_empty()
        }));
        assert!(!format!("{:?}", events).contains("secret-persist-token"));
    }

    #[tokio::test]
    async fn authenticated_set_master_arbitration_fences_commit_confirmed_control() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::required(),
        )
        .await;
        let master = authenticated_principal_for("gnmi-master", "test");
        let stale = authenticated_principal_for("gnmi-stale", "test");

        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "master-host",
                    vec![master_arbitration_extension(Some("ops"), 10, 0)],
                ),
                master.clone(),
            ))
            .await
            .expect("master acquired");

        let stale_begin = service
            .set(authenticated_set_request_for(
                hostname_set(
                    "stale-begin",
                    vec![
                        master_arbitration_extension(Some("ops"), 9, 0),
                        commit_confirmed_extension(
                            CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                                .expect("payload"),
                        ),
                    ],
                ),
                stale.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(stale_begin.code(), Code::PermissionDenied);
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "master-host"
        );

        service
            .set(authenticated_set_request_for(
                hostname_set(
                    "pending-host",
                    vec![
                        master_arbitration_extension(Some("ops"), 10, 0),
                        commit_confirmed_extension(
                            CommitConfirmedExtension::begin(std::time::Duration::from_secs(30))
                                .expect("payload"),
                        ),
                    ],
                ),
                master.clone(),
            ))
            .await
            .expect("master begin confirmed");

        for extension in [
            commit_confirmed_extension(CommitConfirmedExtension::confirm()),
            commit_confirmed_extension(CommitConfirmedExtension::cancel()),
        ] {
            let status = service
                .set(authenticated_set_request_for(
                    gnmi::SetRequest {
                        prefix: None,
                        delete: Vec::new(),
                        replace: Vec::new(),
                        update: Vec::new(),
                        union_replace: Vec::new(),
                        extension: vec![master_arbitration_extension(Some("ops"), 9, 0), extension],
                    },
                    stale.clone(),
                ))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied);
            assert_eq!(
                service
                    .server()
                    .binding()
                    .config_bus()
                    .current_snapshot()
                    .config
                    .hostname,
                "pending-host"
            );
        }

        service
            .set(authenticated_set_request_for(
                gnmi::SetRequest {
                    prefix: None,
                    delete: Vec::new(),
                    replace: Vec::new(),
                    update: Vec::new(),
                    union_replace: Vec::new(),
                    extension: vec![
                        master_arbitration_extension(Some("ops"), 10, 0),
                        commit_confirmed_extension(CommitConfirmedExtension::cancel()),
                    ],
                },
                master,
            ))
            .await
            .expect("master can cancel");
        wait_for_hostname(&service, "master-host").await;
    }

    #[tokio::test]
    async fn authenticated_set_commit_confirmed_malformed_payload_is_audited_without_leak() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_extensions_arbitration_and_audit(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
            Arc::new(audit.clone()),
        )
        .await;
        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""ignored-host""#.to_vec())],
                union_replace: Vec::new(),
                extension: vec![malformed_commit_confirmed_extension(
                    b"secret-extension-payload".to_vec(),
                )],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        assert!(!status.message().contains("secret-extension-payload"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::INVALID_VALUE)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-extension-payload"));
    }

    #[tokio::test]
    async fn authenticated_get_rejects_set_only_commit_confirmed_extension() {
        let service = authenticated_service_with_extensions_and_arbitration(
            ExtensionRegistry::with_commit_confirmed().expect("registry"),
            GnmiArbitrationConfig::optional(),
        )
        .await;
        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: vec![commit_confirmed_extension(
                    CommitConfirmedExtension::confirm(),
                )],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "gNMI operation is not supported");
    }

    #[tokio::test]
    async fn authenticated_get_rejects_master_arbitration_extension() {
        let service =
            authenticated_service_with_arbitration(GnmiArbitrationConfig::optional()).await;
        let status = service
            .get(authenticated_get_request(gnmi::GetRequest {
                prefix: None,
                path: vec![hostname_path()],
                r#type: gnmi::get_request::DataType::Config as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: vec![master_arbitration_extension(Some("secret-role"), 1, 0)],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "gNMI operation is not supported");
        assert!(!status.message().contains("secret-role"));
    }

    #[tokio::test]
    async fn authenticated_set_success_is_audited_without_values_or_key_predicates() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""amf-audit""#.to_vec())],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("set");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:hostname")]
        );
        let audit_debug = format!("{:?}", events);
        assert!(!audit_debug.contains("amf-audit"));
    }

    #[tokio::test]
    async fn authenticated_set_empty_request_is_audited_without_paths() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;

        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::INVALID_VALUE)
        );
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn authenticated_set_records_success_and_commit_metrics() {
        let rpc_success_before = gnmi_rpc_request_count("Set", "success");
        let patch_commit_before = gnmi_set_commit_count("patch");
        let service = authenticated_service().await;

        service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""amf-metrics""#.to_vec())],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .expect("set");

        assert!(gnmi_rpc_request_count("Set", "success") > rpc_success_before);
        assert!(gnmi_set_commit_count("patch") > patch_commit_before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_set_rejects_stale_candidate_after_intervening_commit() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new(
            TestBinding {
                bus: Arc::clone(&bus),
                policy: Arc::new(FixedPolicy(allow_all_read_policy())),
                operational: Arc::new(TestOperationalState),
                events: None,
                patcher: Arc::new(BlockingOncePatcher::new(started_tx, release_rx)),
            },
            MgmtLimits::default(),
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server");
        let service = Arc::new(GnmiService::new_authenticated(server));

        let stale_service = Arc::clone(&service);
        let stale = tokio::spawn(async move {
            stale_service
                .set(authenticated_set_request(hostname_set(
                    "stale-candidate-host",
                    Vec::new(),
                )))
                .await
        });
        started_rx.await.expect("first Set reached patcher");

        service
            .set(authenticated_set_request(hostname_set(
                "intervening-host",
                Vec::new(),
            )))
            .await
            .expect("intervening Set commits");
        release_tx.send(()).expect("release first Set");

        let status = stale
            .await
            .expect("stale Set task completed")
            .expect_err("stale Set should be rejected");
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(status.message(), "gNMI service unavailable");
        assert!(!status.message().contains("stale-candidate-host"));
        assert_eq!(bus.current_snapshot().config.hostname, "intervening-host");
        assert_eq!(
            bus.current_snapshot().version,
            opc_types::ConfigVersion::new(1)
        );
    }

    #[tokio::test]
    async fn authenticated_set_delete_replace_and_union_replace_are_atomic() {
        let service = authenticated_service().await;
        let response = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: vec![user_path("guest")],
                replace: vec![json_update(hostname_path(), br#""amf-3""#.to_vec())],
                update: Vec::new(),
                union_replace: vec![json_update(
                    user_role_path("admin"),
                    br#""operator""#.to_vec(),
                )],
                extension: Vec::new(),
            }))
            .await
            .expect("set")
            .into_inner();

        let ops = response
            .response
            .iter()
            .map(|result| result.op)
            .collect::<Vec<_>>();
        assert_eq!(
            ops,
            vec![
                gnmi::update_result::Operation::Delete as i32,
                gnmi::update_result::Operation::Replace as i32,
                gnmi::update_result::Operation::UnionReplace as i32,
            ]
        );

        let snapshot = service.server().binding().config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-3");
        assert_eq!(
            snapshot
                .config
                .users
                .get("admin")
                .map(|user| user.role.as_str()),
            Some("operator")
        );
        assert!(!snapshot.config.users.contains_key("guest"));
    }

    #[tokio::test]
    async fn authenticated_set_enforces_path_and_value_limits_without_mutation() {
        let path_limited = authenticated_service_with_limits(MgmtLimits {
            max_paths_per_request: 1,
            ..MgmtLimits::default()
        })
        .await;
        let error_before = gnmi_rpc_error_count("Set", "INVALID_ARGUMENT");
        let too_many_paths = path_limited
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![
                    json_update(hostname_path(), br#""amf-4""#.to_vec()),
                    json_update(user_role_path("admin"), br#""operator""#.to_vec()),
                ],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(too_many_paths.code(), Code::InvalidArgument);
        assert_eq!(too_many_paths.message(), "invalid gNMI request");
        assert_eq!(
            path_limited
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );

        let value_limited = authenticated_service_with_limits(MgmtLimits {
            max_value_bytes: 8,
            ..MgmtLimits::default()
        })
        .await;
        let too_large_value = value_limited
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""secret-too-long""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(too_large_value.code(), Code::InvalidArgument);
        assert_eq!(too_large_value.message(), "invalid gNMI request");
        assert!(!too_large_value.message().contains("secret-too-long"));
        assert_eq!(
            value_limited
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
        assert!(gnmi_rpc_error_count("Set", "INVALID_ARGUMENT") > error_before);
    }

    #[tokio::test]
    async fn authenticated_set_rejects_readonly_and_malformed_values_without_leak() {
        let service = authenticated_service().await;
        let readonly = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(uptime_path(), b"10".to_vec())],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(readonly.code(), Code::InvalidArgument);

        let malformed = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), b"\"secret-host".to_vec())],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(malformed.code(), Code::InvalidArgument);
        assert_eq!(malformed.message(), "invalid gNMI request");
        assert!(!malformed.message().contains("secret-host"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_commit_validation_error_is_mapped_without_leak() {
        let service = authenticated_service().await;
        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: vec![json_update(
                    hostname_path(),
                    br#""invalid-syntax-secret""#.to_vec(),
                )],
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        assert!(!status.message().contains("invalid-syntax-secret"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_commit_authorization_denial_is_generic_and_atomic() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_write_authorizer_and_audit(
            Arc::new(DenyWriteAuthorizer),
            Arc::new(audit.clone()),
        )
        .await;
        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: vec![json_update(hostname_path(), br#""secret-host""#.to_vec())],
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "gNMI access denied");
        assert!(!status.message().contains("secret-host"));
        assert!(!status.message().contains("secret-authorizer-detail"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Replace);
        assert_eq!(
            events[0].outcome,
            audit_denied(AuditReasonCode::ACCESS_DENIED)
        );
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:hostname")]
        );
        assert!(!format!("{:?}", events).contains("secret-host"));
    }

    #[tokio::test]
    async fn authenticated_set_rejects_unknown_extension_before_mutation_without_leak() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(hostname_path(), br#""amf-4""#.to_vec())],
                union_replace: Vec::new(),
                extension: vec![gnmi_ext::Extension {
                    ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                        gnmi_ext::RegisteredExtension {
                            id: gnmi_ext::ExtensionId::EidExperimental as i32,
                            msg: b"secret-extension-payload".to_vec(),
                        },
                    )),
                }],
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "gNMI operation is not supported");
        assert!(!status.message().contains("secret-extension-payload"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-extension-payload"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-1"
        );
    }

    #[tokio::test]
    async fn authenticated_set_success_audit_failure_is_generic_after_commit() {
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_policy(),
            Arc::new(FailingAudit),
        )
        .await;

        let status = service
            .set(authenticated_set_request(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: vec![json_update(
                    hostname_path(),
                    br#""amf-after-audit""#.to_vec(),
                )],
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "gNMI internal error");
        assert!(!status.message().contains("secret-admin"));
        assert_eq!(
            service
                .server()
                .binding()
                .config_bus()
                .current_snapshot()
                .config
                .hostname,
            "amf-after-audit"
        );
    }

    #[tokio::test]
    async fn subscribe_once_snapshot_uses_subscribe_nacm_and_renders_config() {
        let service =
            authenticated_service_with_policy(allow_all_read_and_subscribe_policy()).await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Once,
                hostname_path(),
                gnmi::SubscriptionMode::Sample,
            ),
        )
        .expect("subscribe plan");
        let principal = authenticated_principal();

        let responses = render_snapshot_responses(service.server(), principal.principal(), &plan)
            .expect("snapshot");

        assert_eq!(responses.len(), 1);
        let notification = match responses[0].response.as_ref().expect("response") {
            gnmi::subscribe_response::Response::Update(notification) => notification,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(notification.update.len(), 1);
        assert_eq!(
            notification.update[0]
                .val
                .as_ref()
                .and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(
                br#""amf-1""#.to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn subscribe_action_is_distinct_from_read_nacm() {
        let service = authenticated_service_with_policy(allow_all_read_policy()).await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Once,
                hostname_path(),
                gnmi::SubscriptionMode::Sample,
            ),
        )
        .expect("subscribe plan");
        let principal = authenticated_principal();

        let responses = render_snapshot_responses(service.server(), principal.principal(), &plan)
            .expect("snapshot");

        assert!(responses.is_empty());
    }

    #[tokio::test]
    async fn subscribe_sample_can_read_operational_state() {
        let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::Sample,
            ),
        )
        .expect("subscribe plan");
        let principal = authenticated_principal();

        let responses = render_snapshot_responses(service.server(), principal.principal(), &plan)
            .expect("snapshot");

        assert_eq!(responses.len(), 1);
        let notification = match responses[0].response.as_ref().expect("response") {
            gnmi::subscribe_response::Response::Update(notification) => notification,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(
            notification.update[0]
                .val
                .as_ref()
                .and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(b"123".to_vec()))
        );
    }

    #[tokio::test]
    async fn subscribe_on_change_rejects_operational_paths_without_event_source() {
        let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
        let err = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .unwrap_err();

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert_eq!(err.to_string(), "gNMI operation is not supported");
    }

    #[tokio::test]
    async fn subscribe_on_change_accepts_operational_paths_with_event_source() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let service = authenticated_service_with_policy_and_event_source(
            allow_all_subscribe_policy(),
            events,
        )
        .await;

        SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("operational on-change plan");
    }

    #[tokio::test]
    async fn subscribe_on_change_accepts_mixed_config_and_operational_paths() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let service = authenticated_service_with_policy_and_event_source(
            allow_all_read_and_subscribe_policy(),
            events,
        )
        .await;
        let mut list = subscribe_list(
            gnmi::subscription_list::Mode::Stream,
            hostname_path(),
            gnmi::SubscriptionMode::OnChange,
        );
        list.subscription.push(gnmi::Subscription {
            path: Some(uptime_path()),
            mode: gnmi::SubscriptionMode::OnChange as i32,
            sample_interval: 1_000_000,
            suppress_redundant: false,
            heartbeat_interval: 0,
        });

        SubscribePlan::from_subscription_list(service.server(), list)
            .expect("mixed on-change plan");
    }

    #[tokio::test]
    async fn subscribe_operational_event_sends_authorized_update() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let service = authenticated_service_with_policy_and_event_source(
            allow_all_subscribe_policy(),
            events,
        )
        .await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("plan");
        let principal = authenticated_principal();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        let sent = send_operational_event(
            service.server(),
            RequestId::new(),
            principal.principal(),
            &plan,
            OperationalEvent::Update(
                OperationalValue::new(
                    YangPath::new("/sys:system/sys:uptime").expect("static path"),
                    "321",
                )
                .expect("json"),
            ),
            &tx,
        )
        .await
        .expect("send event");

        assert!(sent);
        let response = rx.recv().await.expect("response").expect("ok response");
        let notification = match response.response.expect("response") {
            gnmi::subscribe_response::Response::Update(notification) => notification,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(notification.update.len(), 1);
        assert_eq!(
            notification.update[0]
                .val
                .as_ref()
                .and_then(|value| value.value.as_ref()),
            Some(&gnmi::typed_value::Value::JsonIetfVal(b"321".to_vec()))
        );
        assert_eq!(
            notification.update[0]
                .path
                .as_ref()
                .expect("path")
                .elem
                .iter()
                .map(|elem| elem.name.as_str())
                .collect::<Vec<_>>(),
            vec!["sys:system", "sys:uptime"]
        );
    }

    #[tokio::test]
    async fn subscribe_operational_event_sends_authorized_delete() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let service = authenticated_service_with_policy_and_event_source(
            allow_all_subscribe_policy(),
            events,
        )
        .await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("plan");
        let principal = authenticated_principal();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        send_operational_event(
            service.server(),
            RequestId::new(),
            principal.principal(),
            &plan,
            OperationalEvent::Delete {
                path: YangPath::new("/sys:system/sys:uptime").expect("static path"),
            },
            &tx,
        )
        .await
        .expect("send event");

        let response = rx.recv().await.expect("response").expect("ok response");
        let notification = match response.response.expect("response") {
            gnmi::subscribe_response::Response::Update(notification) => notification,
            other => panic!("unexpected response: {other:?}"),
        };
        assert!(notification.update.is_empty());
        assert_eq!(notification.delete.len(), 1);
        assert_eq!(
            notification.delete[0]
                .elem
                .iter()
                .map(|elem| elem.name.as_str())
                .collect::<Vec<_>>(),
            vec!["sys:system", "sys:uptime"]
        );
    }

    #[tokio::test]
    async fn subscribe_operational_event_omits_nacm_denied_update() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_bus_events_audit(
            Arc::new(FixedPolicy(allow_all_read_policy())),
            Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .expect("bus"),
            ),
            Some(events),
            MgmtLimits::default(),
            Arc::new(audit.clone()),
            Arc::new(TestOperationalState),
        )
        .await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("plan");
        let principal = authenticated_principal();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        let sent = send_operational_event(
            service.server(),
            RequestId::new(),
            principal.principal(),
            &plan,
            OperationalEvent::Update(
                OperationalValue::new(
                    YangPath::new("/sys:system/sys:uptime").expect("static path"),
                    "321",
                )
                .expect("json"),
            ),
            &tx,
        )
        .await
        .expect("send event");

        assert!(sent);
        assert!(rx.try_recv().is_err());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_denied(AuditReasonCode::ACCESS_DENIED)
        );
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:uptime")]
        );
    }

    #[tokio::test]
    async fn subscribe_operational_event_rejects_unrequested_path_without_leak() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let service = authenticated_service_with_policy_and_event_source(
            allow_all_subscribe_policy(),
            events,
        )
        .await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("plan");
        let principal = authenticated_principal();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = send_operational_event(
            service.server(),
            RequestId::new(),
            principal.principal(),
            &plan,
            OperationalEvent::Update(
                OperationalValue::new(
                    YangPath::new("/sys:system/sys:user[sys:name='secret-admin']/sys:role")
                        .expect("secret path"),
                    r#""secret-role""#,
                )
                .expect("json"),
            ),
            &tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "INTERNAL");
        assert_eq!(err.to_string(), "gNMI internal error");
        assert!(!err.to_string().contains("secret-admin"));
        assert!(!err.detail().unwrap_or_default().contains("secret-admin"));
        assert!(!err.detail().unwrap_or_default().contains("secret-role"));
    }

    #[tokio::test]
    async fn subscribe_operational_event_enforces_value_limit_without_leak() {
        let events: Arc<dyn OperationalEventSource> = Arc::new(TestOperationalEvents::default());
        let limits = MgmtLimits {
            max_value_bytes: 2,
            ..MgmtLimits::default()
        };
        let service = authenticated_service_with_policy_limits_events(
            allow_all_subscribe_policy(),
            limits,
            Some(events),
        )
        .await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            ),
        )
        .expect("plan");
        let principal = authenticated_principal();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = send_operational_event(
            service.server(),
            RequestId::new(),
            principal.principal(),
            &plan,
            OperationalEvent::Update(
                OperationalValue::new(
                    YangPath::new("/sys:system/sys:uptime").expect("static path"),
                    "321",
                )
                .expect("json"),
            ),
            &tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "INVALID_ARGUMENT");
        assert_eq!(err.to_string(), "invalid gNMI request");
        assert!(!err.to_string().contains("321"));
    }

    #[tokio::test]
    async fn subscribe_plan_audit_paths_are_schema_only_without_key_values() {
        let service =
            authenticated_service_with_policy(allow_all_read_and_subscribe_policy()).await;
        let plan = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Once,
                user_role_path("secret-admin"),
                gnmi::SubscriptionMode::Sample,
            ),
        )
        .expect("plan");

        assert_eq!(plan.audit_paths().len(), 1);
        assert_eq!(
            plan.audit_paths()[0],
            schema_node_path("/sys:system/sys:user/sys:role")
        );
        let debug = format!("{:?}", plan.audit_paths());
        assert!(!debug.contains("secret-admin"));
        assert!(!debug.contains("[sys:name"));
    }

    #[tokio::test]
    async fn subscribe_empty_stream_setup_failure_is_audited() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_and_subscribe_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let mut codec =
            tonic::codec::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
        let stream = tonic::Streaming::new_empty(codec.decoder(), tonic::body::Body::empty());
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = serve_subscribe_stream(
            Arc::clone(&service.server),
            authenticated_principal().principal().clone(),
            stream,
            tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "INVALID_ARGUMENT");
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::INVALID_VALUE)
        );
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn subscribe_operational_event_source_absence_is_audited() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_subscribe_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let stream = subscribe_stream_from(subscribe_request(subscribe_list(
            gnmi::subscription_list::Mode::Stream,
            uptime_path(),
            gnmi::SubscriptionMode::OnChange,
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = serve_subscribe_stream(
            Arc::clone(&service.server),
            authenticated_principal().principal().clone(),
            stream,
            tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn subscribe_unsupported_shape_is_audited_without_path_values() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_and_subscribe_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let mut list = subscribe_list(
            gnmi::subscription_list::Mode::Once,
            user_role_path("secret-admin"),
            gnmi::SubscriptionMode::Sample,
        );
        list.qos = Some(gnmi::QosMarking { marking: 46 });
        let stream = subscribe_stream_from(subscribe_request(list));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = serve_subscribe_stream(
            Arc::clone(&service.server),
            authenticated_principal().principal().clone(),
            stream,
            tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-admin"));
    }

    #[tokio::test]
    async fn subscribe_unsupported_encoding_is_audited_without_path_values() {
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_and_subscribe_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let mut list = subscribe_list(
            gnmi::subscription_list::Mode::Once,
            user_role_path("secret-admin"),
            gnmi::SubscriptionMode::Sample,
        );
        list.encoding = gnmi::Encoding::Bytes as i32;
        let stream = subscribe_stream_from(subscribe_request(list));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = serve_subscribe_stream(
            Arc::clone(&service.server),
            authenticated_principal().principal().clone(),
            stream,
            tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert_eq!(err.to_string(), "gNMI operation is not supported");
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-admin"));
    }

    #[tokio::test]
    async fn subscribe_history_extension_fails_closed_without_replay_source() {
        let rejected_before = gnmi_extension_count("history", "rejected");
        let audit = CapturingAudit::default();
        let service = authenticated_service_with_policy_and_audit(
            allow_all_read_and_subscribe_policy(),
            Arc::new(audit.clone()),
        )
        .await;
        let mut request = subscribe_request(subscribe_list(
            gnmi::subscription_list::Mode::Once,
            user_role_path("secret-admin"),
            gnmi::SubscriptionMode::Sample,
        ));
        request.extension = vec![history_extension()];
        let stream = subscribe_stream_from(request);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);

        let err = serve_subscribe_stream(
            Arc::clone(&service.server),
            authenticated_principal().principal().clone(),
            stream,
            tx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert_eq!(err.to_string(), "gNMI operation is not supported");
        assert!(gnmi_extension_count("history", "rejected") > rejected_before);
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Subscribe);
        assert_eq!(
            events[0].outcome,
            audit_failed(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        );
        assert!(events[0].schema_paths.is_empty());
        assert!(!format!("{:?}", events).contains("secret-admin"));
    }

    #[tokio::test]
    async fn subscribe_plan_rejects_unsupported_shapes_without_payload_leak() {
        let service =
            authenticated_service_with_policy(allow_all_read_and_subscribe_policy()).await;

        let target_defined = SubscribePlan::from_subscription_list(
            service.server(),
            subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                hostname_path(),
                gnmi::SubscriptionMode::TargetDefined,
            ),
        )
        .unwrap_err();
        assert_eq!(target_defined.status().as_str(), "UNIMPLEMENTED");

        let mut qos = subscribe_list(
            gnmi::subscription_list::Mode::Once,
            hostname_path(),
            gnmi::SubscriptionMode::Sample,
        );
        qos.qos = Some(gnmi::QosMarking { marking: 46 });
        let qos_err = SubscribePlan::from_subscription_list(service.server(), qos).unwrap_err();
        assert_eq!(qos_err.status().as_str(), "UNIMPLEMENTED");

        let mut aggregation = subscribe_list(
            gnmi::subscription_list::Mode::Once,
            user_role_path("secret-admin"),
            gnmi::SubscriptionMode::Sample,
        );
        aggregation.allow_aggregation = true;
        let aggregation_err =
            SubscribePlan::from_subscription_list(service.server(), aggregation).unwrap_err();
        assert_eq!(aggregation_err.status().as_str(), "UNIMPLEMENTED");
        assert!(!aggregation_err.to_string().contains("secret-admin"));
    }

    #[tokio::test]
    async fn unauthenticated_get_set_and_subscribe_are_rejected() {
        let service = service().await;

        let get = service
            .get(Request::new(gnmi::GetRequest {
                prefix: None,
                path: Vec::new(),
                r#type: gnmi::get_request::DataType::All as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(get.code(), Code::Unauthenticated);

        let set = service
            .set(Request::new(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                union_replace: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(set.code(), Code::Unauthenticated);

        let mut codec =
            tonic::codec::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
        let subscribe_stream =
            tonic::Streaming::new_empty(codec.decoder(), tonic::body::Body::empty());
        let subscribe = match service.subscribe(Request::new(subscribe_stream)).await {
            Ok(_) => panic!("subscribe should require authentication"),
            Err(status) => status,
        };
        assert_eq!(subscribe.code(), Code::Unauthenticated);
    }

    #[test]
    fn status_mapping_uses_tonic_codes_and_no_detail() {
        let status = status_from_error(GnmiError::invalid("local detail with /secret:path"));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        assert!(!status.message().contains("/secret:path"));
    }
}
