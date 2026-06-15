//! gNMI server foundation for the OpenPacketCore management plane.
//!
//! This crate is intentionally proto-free for the first gNMI slice. ADR 0016,
//! which permits `tonic`/`prost` only inside `opc-gnmi-server`, still has status
//! `Proposed`, so this crate does **not** add the gRPC stack or claim a working
//! OpenConfig service. It provides the protocol-neutral contracts that the
//! future generated protobuf service must use:
//!
//! - CNF binding traits over `C: OpcConfig`;
//! - capability data derived from the generated schema registry;
//! - gNMI-shaped path normalization through `opc-mgmt-path`;
//! - bounded JSON value normalization for future `TypedValue` adapters;
//! - fail-safe registered-extension handling;
//! - low-cardinality gNMI metrics helpers.
//!
//! The public [`GnmiServer`] type is a foundation handle, not a transport
//! listener. It validates the binding's schema and management limits up front
//! and exposes only operations that are backed by current SDK code.

#![forbid(unsafe_code)]

pub mod binding;
pub mod capabilities;
pub mod encoding;
pub mod error;
pub mod extension;
pub mod metrics;
pub mod path;
pub mod set;
pub mod value;

use std::marker::PhantomData;

use opc_config_model::OpcConfig;
use opc_mgmt_limits::MgmtLimits;

pub use binding::{GnmiConfigBinding, GnmiPatchApplicator};
pub use capabilities::{CapabilityProfile, GnmiCapabilities, GnmiModelData, GnmiVersion};
pub use encoding::{Encoding, EncodingRegistry};
pub use error::GnmiError;
pub use extension::{
    AcceptedExtension, Extension, ExtensionDisposition, ExtensionRegistry, RegisteredExtension,
};
pub use path::{resolve_path, resolve_paths, GnmiPath, GnmiPathElem, ResolvedGnmiPath};
pub use set::{NormalizedSet, SetOperation};
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

    /// Renders protocol-neutral gNMI Capabilities data from the schema registry.
    pub fn capabilities(&self) -> GnmiCapabilities {
        GnmiCapabilities::from_registry(self.binding.schema(), &self.profile, &self.extensions)
    }
}
