//! Generated gNMI service skeleton.

use std::{pin::Pin, sync::Arc};

use opc_config_model::{AuthStrength, OpcConfig, TrustedPrincipal};
use tonic::{Request, Response, Status};

use crate::{
    encoding_to_proto,
    get::handle_get,
    metrics::{record_rpc_error, record_rpc_success, GnmiOperation},
    proto::{gnmi, gnmi_ext},
    proto_adapter::extension_from_proto,
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
            record_rpc_error(GnmiOperation::Get, err.status(), start.elapsed());
            return Err(status_from_error(err));
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
        if let Err(err) = self.validate_authenticated_request(&request) {
            return Err(status_from_error(err));
        }
        Err(unsupported_rpc_status(GnmiOperation::Set))
    }

    async fn subscribe(
        &self,
        request: Request<tonic::Streaming<gnmi::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        if let Err(err) = self.validate_authenticated_request(&request) {
            return Err(status_from_error(err));
        }
        Err(unsupported_rpc_status(GnmiOperation::Subscribe))
    }
}

fn unsupported_rpc_status(operation: GnmiOperation) -> Status {
    Status::unimplemented(format!("gNMI {} is not implemented", operation.as_str()))
}

fn validate_extensions(
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
    use std::sync::Arc;

    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_config_model::{
        AuthStrength, ConfigError, TrustedPrincipal, ValidationContext, ValidationError,
        WorkloadIdentity as ConfigWorkloadIdentity, YangPath,
    };
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_limits::MgmtLimits;
    use opc_mgmt_opstate::{
        OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
        OperationalValue,
    };
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, YangPathPattern};
    use tonic::codec::Codec;
    use tonic::Code;

    use super::*;
    use crate::proto::gnmi::g_nmi_server::GNmi;
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

    struct UnitPatcher;

    #[derive(Clone)]
    struct DemoUser {
        role: String,
    }

    #[derive(Clone)]
    struct DemoConfig {
        hostname: String,
        users: BTreeMap<String, DemoUser>,
    }

    impl OpcConfig for DemoConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([2u8; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(vec![
                YangPath::new("/sys:system/sys:hostname").expect("static path")
            ])
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
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
            _running: &DemoConfig,
            _set: &crate::NormalizedSet,
        ) -> Result<DemoConfig, GnmiError> {
            Ok(initial_config())
        }
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
            },
            MgmtLimits::default(),
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
                policy: Arc::new(FixedPolicy(policy)),
                operational: Arc::new(TestOperationalState),
            },
            MgmtLimits::default(),
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server");
        GnmiService::new_authenticated(server)
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
    async fn unauthenticated_get_is_rejected_and_set_subscribe_are_unimplemented() {
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
        assert_eq!(set.code(), Code::Unimplemented);

        let mut codec =
            tonic::codec::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
        let subscribe_stream =
            tonic::Streaming::new_empty(codec.decoder(), tonic::body::Body::empty());
        let subscribe = match service.subscribe(Request::new(subscribe_stream)).await {
            Ok(_) => panic!("subscribe should be unimplemented"),
            Err(status) => status,
        };
        assert_eq!(subscribe.code(), Code::Unimplemented);
    }

    #[test]
    fn status_mapping_uses_tonic_codes_and_no_detail() {
        let status = status_from_error(GnmiError::invalid("local detail with /secret:path"));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "invalid gNMI request");
        assert!(!status.message().contains("/secret:path"));
    }
}
