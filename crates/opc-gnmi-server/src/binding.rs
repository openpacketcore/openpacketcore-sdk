//! CNF binding points for the gNMI server foundation.

use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_authz::PolicySource;
use opc_mgmt_opstate::{OperationalResponse, OperationalStateProvider};
use opc_mgmt_schema::SchemaRegistry;

use crate::{GnmiError, NormalizedSet};

/// Authorized schema-node selection passed to gNMI JSON projection hooks.
#[derive(Debug, Clone, Copy)]
pub struct ReadSelection<'a> {
    schema_paths: &'a [&'static str],
}

impl<'a> ReadSelection<'a> {
    /// Creates a selection from predicate-free schema-node paths.
    pub const fn new(schema_paths: &'a [&'static str]) -> Self {
        Self { schema_paths }
    }

    /// Predicate-free schema-node paths the caller may read.
    pub const fn schema_paths(&self) -> &'a [&'static str] {
        self.schema_paths
    }

    /// Returns whether a schema path is selected.
    pub fn contains(&self, schema_path: &str) -> bool {
        self.schema_paths.contains(&schema_path)
    }
}

/// One JSON/RFC 7951 gNMI update produced by a CNF/generated renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmiJsonUpdate {
    path: YangPath,
    value_json: String,
}

impl GnmiJsonUpdate {
    /// Builds a JSON update and validates JSON syntax. Size limits are enforced
    /// by the server because they are deployment configuration.
    pub fn new(
        path: YangPath,
        value_json: impl Into<String>,
    ) -> Result<Self, GnmiJsonProjectionError> {
        let value_json = value_json.into();
        serde_json::from_str::<serde_json::Value>(&value_json)
            .map_err(|_| GnmiJsonProjectionError::invalid_json(path.as_str()))?;
        Ok(Self { path, value_json })
    }

    /// Canonical SDK YANG path for this value.
    pub const fn path(&self) -> &YangPath {
        &self.path
    }

    /// JSON/RFC 7951 encoded value or subtree.
    pub fn value_json(&self) -> &str {
        &self.value_json
    }
}

/// CNF/generated-code gNMI projection failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("gNMI JSON projection failed")]
pub struct GnmiJsonProjectionError {
    detail: String,
}

impl GnmiJsonProjectionError {
    /// Builds a projection error with server-local detail.
    pub fn projection(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    fn invalid_json(path: &str) -> Self {
        Self::projection(format!("invalid JSON at {path}"))
    }

    /// Server-local detail. Never send this directly to a client.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

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

    /// Renders the currently published running config as JSON/RFC 7951 gNMI
    /// updates for the authorized paths.
    ///
    /// The default fails closed. CNFs should expose a generated renderer once
    /// `opc-yanggen` emits a schema-aware gNMI JSON projection for their root
    /// config type.
    fn render_running_json(
        &self,
        _config: &C,
        _selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        Err(GnmiJsonProjectionError::projection(
            "gNMI running JSON projection is not implemented",
        ))
    }

    /// Renders gNMI `<Get>` data after server-side filtering and NACM.
    ///
    /// The default combines [`Self::render_running_json`] for config nodes with
    /// the operational-state provider's already validated JSON values. A binding
    /// may override this if it needs model-specific combined config/state
    /// projection, but it must still honor both selections exactly.
    fn render_get_json(
        &self,
        config: &C,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        operational_selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        let mut updates = Vec::new();
        if !config_selection.schema_paths().is_empty() {
            updates.extend(self.render_running_json(config, config_selection)?);
        }
        for value in &operational.values {
            if operational_selection.contains(value.path().as_str()) {
                updates.push(GnmiJsonUpdate::new(
                    value.path().clone(),
                    value.value_json().to_string(),
                )?);
            }
        }
        Ok(updates)
    }
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
