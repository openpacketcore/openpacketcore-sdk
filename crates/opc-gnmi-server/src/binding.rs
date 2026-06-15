//! CNF binding points for the gNMI server foundation.

use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_model::OpcConfig;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_opstate::OperationalStateProvider;
use opc_mgmt_schema::SchemaRegistry;

use crate::{GnmiError, NormalizedSet};

/// Binding supplied by the CNF embedding the gNMI server.
///
/// The future gRPC service owns protocol framing, authentication, NACM, audit,
/// metrics, and ConfigBus submission. The CNF owns model-specific set
/// application until generated gNMI patch applicators are emitted by
/// `opc-yanggen`.
pub trait GnmiConfigBinding<C: OpcConfig>: Send + Sync {
    /// The authoritative running-config bus.
    fn config_bus(&self) -> Arc<ConfigBus<C>>;

    /// Generated schema registry for the served model set.
    fn schema(&self) -> &'static dyn SchemaRegistry;

    /// Schema-aware gNMI Set applicator for this generated root config.
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<C>>;

    /// NF-supplied operational-state provider.
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider>;

    /// Active NACM policy source for read/subscribe preflight.
    fn policy_source(&self) -> Arc<dyn PolicySource>;
}

/// CNF/generated-code hook that applies a normalized gNMI Set to a running
/// snapshot and returns a complete candidate config.
///
/// The hook receives only schema-resolved paths and syntax-checked RFC 7951 JSON
/// payloads. It must not parse protobuf or trust client-provided paths directly.
pub trait GnmiPatchApplicator<C: OpcConfig>: Send + Sync {
    /// Applies the normalized Set to `running`, producing a full candidate.
    fn apply_set(&self, running: &C, set: &NormalizedSet) -> Result<C, GnmiError>;
}
