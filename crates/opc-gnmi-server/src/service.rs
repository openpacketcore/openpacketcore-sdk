//! Generated gNMI service skeleton.

use std::{pin::Pin, sync::Arc};

use opc_config_model::{AuthStrength, OpcConfig, RequestId, TrustedPrincipal};
use opc_mgmt_audit::AuditOperation;
use tonic::{Request, Response, Status};

use crate::{
    audit::{outcome_for_error, record_audit},
    encoding_to_proto,
    get::handle_get,
    metrics::{record_rpc_error, record_rpc_success, GnmiOperation},
    proto::{gnmi, gnmi_ext},
    proto_adapter::extension_from_proto,
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
        if let Err(err) =
            validate_extensions(self.server.extensions(), &request.get_ref().extension)
        {
            record_rpc_error(GnmiOperation::Capabilities, err.status(), start.elapsed());
            return Err(status_from_error(err));
        }

        let caps = self.server.capabilities();
        if let Err(err) = caps.validate() {
            record_rpc_error(GnmiOperation::Capabilities, err.status(), start.elapsed());
            return Err(status_from_error(err));
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
            extension: Vec::new(),
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
        if let Err(err) =
            validate_extensions(self.server.extensions(), &request.get_ref().extension)
        {
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
        if let Err(err) =
            validate_extensions(self.server.extensions(), &request.get_ref().extension)
        {
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

pub(crate) fn validate_extensions(
    registry: &crate::ExtensionRegistry,
    extensions: &[gnmi_ext::Extension],
) -> Result<(), GnmiError> {
    let normalized = extensions
        .iter()
        .map(extension_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    registry.validate_request(&normalized)?;
    Ok(())
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
    use std::sync::atomic::Ordering;
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
        CapabilityProfile, ExtensionRegistry, GnmiJsonProjectionError, GnmiJsonUpdate,
        GnmiPatchApplicator, GnmiVersion, ReadSelection, GNMI_VERSION,
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
    }

    impl GnmiConfigBinding<DemoConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema(&self) -> &'static dyn SchemaRegistry {
            &TestRegistry
        }

        fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<DemoConfig>> {
            Arc::new(UnitPatcher)
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
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new(
            TestBinding {
                bus,
                policy: Arc::new(FixedPolicy(allow_all_read_policy())),
                operational: Arc::new(TestOperationalState),
                events: None,
            },
            limits,
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server");
        if authenticated {
            GnmiService::new_authenticated(server)
        } else {
            GnmiService::new(server)
        }
    }

    fn authenticated_principal() -> AuthenticatedGnmiPrincipal {
        AuthenticatedGnmiPrincipal::new(
            TrustedPrincipal::new(
                ConfigWorkloadIdentity::User("gnmi-client".to_string()),
                TenantId::from_static("test"),
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
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        let server = GnmiServer::new_with_audit(
            TestBinding {
                bus,
                policy,
                operational,
                events,
            },
            limits,
            profile,
            ExtensionRegistry::default(),
            audit,
        )
        .expect("server");
        GnmiService::new_authenticated(server)
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
        let mut request = Request::new(set);
        request.extensions_mut().insert(authenticated_principal());
        request
    }

    fn authenticated_get_request(get: gnmi::GetRequest) -> Request<gnmi::GetRequest> {
        let mut request = Request::new(get);
        request.extensions_mut().insert(authenticated_principal());
        request
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
