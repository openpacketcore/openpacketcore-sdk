//! gNMI server foundation for the OpenPacketCore management plane.
//!
//! ADR 0016 permits `tonic`/`prost` only inside `opc-gnmi-server`; this crate is
//! the only workspace crate that may carry the OpenConfig gNMI protobuf service.
//! It provides the protocol-neutral contracts that generated protobuf handlers
//! must use:
//!
//! - CNF binding traits over `C: OpcConfig`;
//! - capability data derived from the generated schema registry;
//! - gNMI-shaped path normalization through `opc-mgmt-path`;
//! - bounded JSON value normalization for `TypedValue` adapters;
//! - fail-safe registered-extension handling;
//! - low-cardinality gNMI metrics helpers.
//!
//! The current protobuf service is intentionally capability-honest:
//! [`Capabilities`](proto::gnmi::g_nmi_server::GNmi::capabilities) is served from
//! the generated schema registry, authenticated `Get` supports read-only
//! JSON/JSON_IETF config and operational data through explicit binding hooks,
//! authenticated `Set` applies generated patches through `opc-config-bus`, and
//! authenticated `Subscribe` supports ONCE/POLL snapshots plus STREAM sample and
//! config on-change delivery.
//!
//! [`GnmiServer::with_config_authority`] is the explicit HA profile: Set and
//! Get fail closed unless the injected writer-of-record port proves local
//! authority, follower hints are returned only in bounded gRPC metadata, and
//! successful Set replies carry the exact datastore-attested committed
//! revision. The default authoritative/no-port profile preserves legacy reply
//! bytes.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod arbitration;
mod audit;
pub mod binding;
pub mod capabilities;
pub mod committed_revision;
pub mod confirmed_commit;
pub mod encoding;
pub mod error;
pub mod extension;
pub mod get;
pub mod listener;
pub mod metrics;
pub mod path;
pub mod proto;
pub mod proto_adapter;
pub mod service;
pub mod set;
pub mod smoke;
pub mod subscribe;
pub mod supervision;
pub mod transport;
pub mod value;

use std::marker::PhantomData;
use std::sync::Arc;

use opc_config_bus::{ConfigAuthorityOperation, ConfigAuthorityOutcome, ConfigAuthorityPort};
use opc_config_model::OpcConfig;
use opc_mgmt_audit::{AuditSink, TracingAuditSink};
use opc_mgmt_limits::MgmtLimits;

pub use arbitration::{
    GnmiArbitrationConfig, GnmiArbitrationMode, GnmiArbitrationState, GnmiElectionId,
};
pub use binding::{
    GnmiConfigBinding, GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate,
    GnmiPatchApplicator, ReadSelection, ReadSelectionEntry,
};
pub use capabilities::{CapabilityProfile, GnmiCapabilities, GnmiModelData, GnmiVersion};
pub use committed_revision::{
    CommittedRevisionExtension, OPC_COMMITTED_REVISION_EXTENSION_ID,
    OPC_COMMITTED_REVISION_EXTENSION_NAME,
};
pub use confirmed_commit::{
    CommitConfirmedAction, CommitConfirmedExtension, DEFAULT_COMMIT_CONFIRMED_TIMEOUT,
    OPC_COMMIT_CONFIRMED_EXTENSION_ID, OPC_COMMIT_CONFIRMED_EXTENSION_NAME,
};
pub use encoding::{Encoding, EncodingRegistry};
pub use error::GnmiError;
pub use extension::{
    AcceptedExtension, Extension, ExtensionDisposition, ExtensionRegistry, RegisteredExtension,
};
pub use listener::{
    run_gnmi_tls_listener, GnmiListenerConfig, GnmiListenerError, GnmiListenerResult,
};
pub use path::{resolve_path, resolve_paths, GnmiPath, GnmiPathElem, ResolvedGnmiPath};
pub use proto::GNMI_VERSION;
pub use proto_adapter::{
    encoding_to_proto, extension_from_proto, path_from_proto, typed_value_from_proto,
};
pub use service::{AuthenticatedGnmiPrincipal, GnmiService, GNMI_LEADER_HINT_METADATA_KEY};
pub use set::{NormalizedSet, SetOperation};
pub use smoke::{
    run_gnmi_mutating_smoke, run_gnmi_smoke, GnmiSmokeCapabilitySummary, GnmiSmokeClientConfig,
    GnmiSmokeDataType, GnmiSmokeEncoding, GnmiSmokeError, GnmiSmokeErrorCode, GnmiSmokeGetOutcome,
    GnmiSmokeGetRequest, GnmiSmokeGetStatus, GnmiSmokeLeafExpectation, GnmiSmokeLeafReadback,
    GnmiSmokeModelSummary, GnmiSmokeMutationStep, GnmiSmokeMutationTranscript, GnmiSmokeReadback,
    GnmiSmokeReadbackOutcome, GnmiSmokeSetExpectation, GnmiSmokeSetOp, GnmiSmokeSetOpKind,
    GnmiSmokeSetOutcome, GnmiSmokeSetStatus, GnmiSmokeStepOutcome, GnmiSmokeTranscript,
};
pub use supervision::{spawn_gnmi_tls_listener, SupervisedGnmiTlsListenerConfig};
pub use transport::{
    principal_from_identity_state, principal_from_identity_watch, principal_from_tls_stream,
    GnmiTlsPrincipalError,
};
pub use value::{normalize_typed_value, NormalizedValue, TypedValue};

/// Protocol-neutral gNMI server foundation.
///
/// This type deliberately has no `serve` method until the ADR-gated protobuf
/// layer exists. Downstream code can still construct it to validate that a CNF
/// binding has a coherent schema, limits, capability profile, and extension
/// policy before the transport slice lands.
pub struct GnmiServer<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    binding: B,
    limits: MgmtLimits,
    profile: CapabilityProfile,
    extensions: ExtensionRegistry,
    arbitration: GnmiArbitrationState,
    config_authority: Option<Arc<dyn ConfigAuthorityPort>>,
    audit: Arc<dyn AuditSink>,
    _config: PhantomData<C>,
}

impl<C, B> GnmiServer<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    /// Builds a proto-free gNMI foundation handle with an explicit audit sink.
    ///
    /// Fails closed if limits are invalid, the schema registry self-check fails,
    /// or the capability profile would over-advertise unsupported behavior.
    pub fn new(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit(binding, limits, profile, extensions, audit)
    }

    /// Builds a proto-free gNMI foundation handle with the tracing audit sink.
    ///
    /// This constructor is intended for tests, conformance harnesses, and local
    /// development only. Production CNFs should use [`Self::new`] or
    /// [`Self::new_with_arbitration`] with a durable, tamper-evident audit sink.
    pub fn new_dev_only(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit_and_arbitration(
            binding,
            limits,
            profile,
            extensions,
            GnmiArbitrationConfig::disabled(),
            Arc::new(TracingAuditSink),
        )
    }

    /// Builds a gNMI foundation handle with explicit master-arbitration
    /// behavior and an explicit audit sink.
    pub fn new_with_arbitration(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit_and_arbitration(
            binding,
            limits,
            profile,
            extensions,
            arbitration,
            audit,
        )
    }

    /// Builds a gNMI foundation handle with explicit master-arbitration behavior
    /// and the tracing audit sink.
    ///
    /// This constructor is intended for tests, conformance harnesses, and local
    /// development only. Production CNFs should use [`Self::new_with_arbitration`]
    /// with a durable, tamper-evident audit sink.
    pub fn new_with_arbitration_dev_only(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit_and_arbitration(
            binding,
            limits,
            profile,
            extensions,
            arbitration,
            Arc::new(TracingAuditSink),
        )
    }

    /// Builds a proto-free gNMI foundation handle with an explicit audit sink.
    pub fn new_with_audit(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit_and_arbitration(
            binding,
            limits,
            profile,
            extensions,
            GnmiArbitrationConfig::disabled(),
            audit,
        )
    }

    /// Builds a gNMI foundation handle with explicit audit and
    /// master-arbitration behavior.
    pub fn new_with_audit_and_arbitration(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        arbitration: GnmiArbitrationConfig,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, GnmiError> {
        limits.validate().map_err(GnmiError::from_limits)?;
        binding
            .schema()
            .self_check()
            .map_err(|err| GnmiError::schema(format!("{err:?}")))?;
        profile.validate()?;
        extensions.validate()?;
        if extensions
            .advertised_ids()
            .contains(&OPC_COMMIT_CONFIRMED_EXTENSION_ID)
            && !arbitration.is_enabled()
        {
            return Err(GnmiError::unimplemented(
                "OpenPacketCore commit-confirmed requires gNMI master arbitration",
            ));
        }
        Ok(Self {
            binding,
            limits,
            profile,
            extensions,
            arbitration: GnmiArbitrationState::new(arbitration),
            config_authority: None,
            audit,
            _config: PhantomData,
        })
    }

    /// Returns the CNF binding.
    pub fn binding(&self) -> &B {
        &self.binding
    }

    /// Shared management-plane limits used by this server foundation.
    pub const fn limits(&self) -> &MgmtLimits {
        &self.limits
    }

    /// Capability profile supplied by the embedding CNF/proto pin.
    pub const fn profile(&self) -> &CapabilityProfile {
        &self.profile
    }

    /// Registered gNMI extension policy.
    pub const fn extensions(&self) -> &ExtensionRegistry {
        &self.extensions
    }

    /// Master-arbitration state and configured enforcement mode.
    pub const fn arbitration(&self) -> &GnmiArbitrationState {
        &self.arbitration
    }

    /// Installs the writer-of-record gate used by Set and linearizable Get.
    ///
    /// Installing this port also opts successful Set replies into the
    /// committed-revision response extension and treats every Get as a
    /// linearizable config read. Without it, an authoritative bus keeps its
    /// existing behavior and response bytes. A shadow bus without a port fails
    /// closed.
    ///
    /// Construction verifies support for exact digests on new writes. A replay
    /// of a legacy digest-less record is still rejected at response time; the
    /// server never fabricates a hash from reserialized config.
    pub fn with_config_authority(
        mut self,
        authority: Arc<dyn ConfigAuthorityPort>,
    ) -> Result<Self, GnmiError> {
        if !self.binding.config_bus().committed_revision_supported() {
            return Err(GnmiError::failed_precondition(
                "config datastore cannot attest committed revisions",
            ));
        }
        self.config_authority = Some(authority);
        Ok(self)
    }

    pub(crate) fn committed_revision_responses_enabled(&self) -> bool {
        self.config_authority.is_some()
    }

    pub(crate) async fn ensure_config_authority(
        &self,
        operation: ConfigAuthorityOperation,
    ) -> Result<(), GnmiError> {
        let outcome = match self.config_authority.as_ref() {
            Some(authority) => {
                authority
                    .ensure_local_authority(operation, self.binding.config_bus().projection_head())
                    .await
            }
            None if self
                .binding
                .config_bus()
                .authority_mode()
                .requires_external_authority() =>
            {
                ConfigAuthorityOutcome::Unavailable
            }
            None => return Ok(()),
        };
        match outcome {
            ConfigAuthorityOutcome::LocalAuthority => Ok(()),
            ConfigAuthorityOutcome::Retry { leader_hint } => {
                Err(GnmiError::not_leader(leader_hint))
            }
            ConfigAuthorityOutcome::Unavailable => Err(GnmiError::not_leader(None)),
            _ => Err(GnmiError::not_leader(None)),
        }
    }

    /// Audit sink used for management-plane operation records.
    pub fn audit(&self) -> &dyn AuditSink {
        self.audit.as_ref()
    }

    /// Renders protocol-neutral gNMI Capabilities data from the schema registry.
    pub fn capabilities(&self) -> GnmiCapabilities {
        GnmiCapabilities::from_registry(self.binding.schema(), &self.profile, &self.extensions)
    }
}
