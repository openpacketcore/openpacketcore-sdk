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

#![forbid(unsafe_code)]

mod audit;
pub mod binding;
pub mod capabilities;
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
pub mod subscribe;
pub mod transport;
pub mod value;

use std::marker::PhantomData;
use std::sync::Arc;

use opc_config_model::OpcConfig;
use opc_mgmt_audit::{AuditSink, TracingAuditSink};
use opc_mgmt_limits::MgmtLimits;

pub use binding::{
    GnmiConfigBinding, GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate,
    GnmiPatchApplicator, ReadSelection, ReadSelectionEntry,
};
pub use capabilities::{CapabilityProfile, GnmiCapabilities, GnmiModelData, GnmiVersion};
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
pub use service::{AuthenticatedGnmiPrincipal, GnmiService};
pub use set::{NormalizedSet, SetOperation};
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
    audit: Arc<dyn AuditSink>,
    _config: PhantomData<C>,
}

impl<C, B> GnmiServer<C, B>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    /// Builds a proto-free gNMI foundation handle.
    ///
    /// Fails closed if limits are invalid, the schema registry self-check fails,
    /// or the capability profile would over-advertise unsupported behavior.
    pub fn new(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
    ) -> Result<Self, GnmiError> {
        Self::new_with_audit(
            binding,
            limits,
            profile,
            extensions,
            Arc::new(TracingAuditSink),
        )
    }

    /// Builds a proto-free gNMI foundation handle with an explicit audit sink.
    ///
    /// Production CNFs should pass a durable, tamper-evident sink. The default
    /// [`Self::new`] constructor uses [`TracingAuditSink`] for compatibility and
    /// development deployments.
    pub fn new_with_audit(
        binding: B,
        limits: MgmtLimits,
        profile: CapabilityProfile,
        extensions: ExtensionRegistry,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, GnmiError> {
        limits.validate().map_err(GnmiError::from_limits)?;
        binding
            .schema()
            .self_check()
            .map_err(|err| GnmiError::schema(format!("{err:?}")))?;
        profile.validate()?;
        extensions.validate()?;
        Ok(Self {
            binding,
            limits,
            profile,
            extensions,
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

    /// Audit sink used for management-plane operation records.
    pub fn audit(&self) -> &dyn AuditSink {
        self.audit.as_ref()
    }

    /// Renders protocol-neutral gNMI Capabilities data from the schema registry.
    pub fn capabilities(&self) -> GnmiCapabilities {
        GnmiCapabilities::from_registry(self.binding.schema(), &self.profile, &self.extensions)
    }
}
