//! CNF binding points for the gNMI server foundation.

use opc_mgmt_path::canonical_path_matches;
use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_authz::PolicySource;
use opc_mgmt_opstate::{OperationalEventSource, OperationalResponse, OperationalStateProvider};
use opc_mgmt_schema::SchemaRegistry;

use crate::{GnmiError, NormalizedSet};

/// One authorized gNMI read selection entry.
///
/// `schema_path` is predicate-free and is the NACM/schema lookup key.
/// `canonical_path` is the SDK canonical read path and may carry list key
/// predicates from the client request. Generated renderers use it to restrict
/// keyed list output to the addressed instances without making NACM
/// instance-aware.
#[derive(Clone, PartialEq, Eq)]
pub struct ReadSelectionEntry {
    schema_path: &'static str,
    canonical_path: YangPath,
}

impl std::fmt::Debug for ReadSelectionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadSelectionEntry")
            .field("schema_path", &self.schema_path)
            .finish_non_exhaustive()
    }
}

impl ReadSelectionEntry {
    /// Builds a read-selection entry.
    pub const fn new(schema_path: &'static str, canonical_path: YangPath) -> Self {
        Self {
            schema_path,
            canonical_path,
        }
    }

    /// Predicate-free schema-node path.
    pub const fn schema_path(&self) -> &'static str {
        self.schema_path
    }

    /// Canonical SDK path, including any selected list key predicates.
    pub const fn canonical_path(&self) -> &YangPath {
        &self.canonical_path
    }
}

/// Authorized schema-node selection passed to gNMI JSON projection hooks.
#[derive(Debug, Clone, Copy)]
pub struct ReadSelection<'a> {
    schema_paths: &'a [&'static str],
    entries: &'a [ReadSelectionEntry],
    validated: bool,
}

impl<'a> ReadSelection<'a> {
    /// Creates a selection from predicate-free schema-node paths.
    ///
    /// This constructor preserves the original schema-only contract. Generated
    /// gNMI renderers should use [`Self::with_entries`] so keyed list instance
    /// predicates are honored.
    pub const fn new(schema_paths: &'a [&'static str]) -> Self {
        Self {
            schema_paths,
            entries: &[],
            validated: false,
        }
    }

    /// Creates a selection with both schema paths and canonical path entries.
    pub const fn with_entries(
        schema_paths: &'a [&'static str],
        entries: &'a [ReadSelectionEntry],
    ) -> Self {
        Self {
            schema_paths,
            entries,
            validated: false,
        }
    }

    /// Uses already matched concrete entries, sorted by canonical path.
    pub(crate) const fn with_validated_entries(
        schema_paths: &'a [&'static str],
        entries: &'a [ReadSelectionEntry],
    ) -> Self {
        Self {
            schema_paths,
            entries,
            validated: true,
        }
    }

    /// Predicate-free schema-node paths the caller may read.
    pub const fn schema_paths(&self) -> &'a [&'static str] {
        self.schema_paths
    }

    /// Canonical selection entries, if supplied by the server.
    pub const fn entries(&self) -> &'a [ReadSelectionEntry] {
        self.entries
    }

    /// Returns whether a schema path is selected.
    pub fn contains(&self, schema_path: &str) -> bool {
        self.schema_paths.contains(&schema_path)
    }

    /// Returns whether `path` itself or one of its descendants is selected.
    ///
    /// Generated container/list renderers use this only to decide whether to
    /// traverse structural ancestors. A selected ancestor does not authorize
    /// sibling leaves; leaves must call [`Self::contains_path`].
    pub fn is_subtree_selected(&self, schema_path: &str) -> bool {
        self.schema_paths.iter().any(|path| {
            *path == schema_path
                || path
                    .strip_prefix(schema_path)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }

    /// Returns whether an update at `canonical_path` for `schema_path` is
    /// selected.
    ///
    /// If canonical entries were not supplied, this falls back to schema-only
    /// selection for compatibility. When canonical entries exist, list key
    /// predicates in the selection are treated as a subset: a request for
    /// `/list[k='a']` matches descendants under that entry, while a request for
    /// `/list/leaf` with no predicates matches every list entry's leaf.
    /// Server-validated operational selections contain only the exact reported
    /// identities and reuse their previously established matches.
    pub fn contains_path(&self, schema_path: &str, canonical_path: &YangPath) -> bool {
        if self.validated {
            return self
                .reported_entry(canonical_path)
                .is_some_and(|entry| entry.schema_path == schema_path);
        }
        if self.entries.is_empty() {
            return self.contains(schema_path);
        }
        self.entries.iter().any(|entry| {
            entry.schema_path == schema_path
                && canonical_path_matches(entry.canonical_path.as_str(), canonical_path.as_str())
        })
    }

    /// Returns whether an externally reported canonical path is selected.
    ///
    /// This is used for operational-state provider output, where the provider
    /// already returns SDK canonical paths instead of generated-model field
    /// values.
    pub fn contains_reported_path(&self, canonical_path: &YangPath) -> bool {
        if self.validated {
            return self.reported_entry(canonical_path).is_some();
        }
        if self.entries.is_empty() {
            return self.contains(canonical_path.as_str());
        }
        self.entries.iter().any(|entry| {
            canonical_path_matches(entry.canonical_path.as_str(), canonical_path.as_str())
        })
    }

    fn reported_entry(&self, canonical_path: &YangPath) -> Option<&ReadSelectionEntry> {
        self.entries
            .binary_search_by(|entry| entry.canonical_path.as_str().cmp(canonical_path.as_str()))
            .ok()
            .and_then(|index| self.entries.get(index))
    }
}

/// Schema-backed gNMI JSON/RFC 7951 renderer for a generated config root.
pub trait GnmiJsonRenderer<C: OpcConfig>: Send + Sync {
    /// Renders authorized running-config values as gNMI JSON updates.
    fn render_running_json(
        &self,
        config: &C,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError>;
}

/// One JSON/RFC 7951 gNMI update produced by a CNF/generated renderer.
#[derive(Clone, PartialEq, Eq)]
pub struct GnmiJsonUpdate {
    path: YangPath,
    value_json: String,
}

impl std::fmt::Debug for GnmiJsonUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnmiJsonUpdate").finish_non_exhaustive()
    }
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
            .map_err(|_| GnmiJsonProjectionError::invalid_json())?;
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
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("gNMI JSON projection failed")]
pub struct GnmiJsonProjectionError {
    detail: String,
}

impl std::fmt::Debug for GnmiJsonProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnmiJsonProjectionError")
            .finish_non_exhaustive()
    }
}

impl GnmiJsonProjectionError {
    /// Builds a projection error with server-local detail.
    pub fn projection(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    fn invalid_json() -> Self {
        Self::projection("invalid gNMI projection JSON")
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

    /// Optional NF-supplied operational-state event source.
    ///
    /// The default is fail-closed. STREAM ON_CHANGE subscriptions to
    /// operational/state nodes are accepted only when a binding explicitly
    /// exposes a source here.
    fn operational_events(&self) -> Option<Arc<dyn OperationalEventSource>> {
        None
    }

    /// Active NACM policy source for read/subscribe preflight.
    fn policy_source(&self) -> Arc<dyn PolicySource>;

    /// Renders the currently published running config as JSON/RFC 7951 gNMI
    /// updates for the authorized paths.
    ///
    /// The default fails closed. CNFs should expose the schema-aware gNMI JSON
    /// renderer generated for their root config type.
    fn render_running_json(
        &self,
        _config: &C,
        _selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        Err(GnmiJsonProjectionError::projection(
            "gNMI running JSON projection is not provided by this binding",
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
            if operational_selection.contains_reported_path(value.path()) {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn read_selection_matches_key_predicate_subset_without_wildcard_leak() {
        let schema_paths = ["/sys:system/sys:user/sys:role"];
        let entries = [ReadSelectionEntry::new(
            "/sys:system/sys:user/sys:role",
            YangPath::new("/sys:system/sys:user[sys:name='admin']/sys:role").unwrap(),
        )];
        let selection = ReadSelection::with_entries(&schema_paths, &entries);

        assert!(selection.contains_path(
            "/sys:system/sys:user/sys:role",
            &YangPath::new("/sys:system/sys:user[sys:name='admin']/sys:role").unwrap()
        ));
        assert!(!selection.contains_path(
            "/sys:system/sys:user/sys:role",
            &YangPath::new("/sys:system/sys:user[sys:name='guest']/sys:role").unwrap()
        ));
        assert!(!selection.contains_path(
            "/sys:system/sys:user/sys:name",
            &YangPath::new("/sys:system/sys:user[sys:name='admin']/sys:name").unwrap()
        ));
    }

    #[test]
    fn read_selection_without_key_predicates_wildcards_list_instances() {
        let schema_paths = ["/sys:system/sys:user/sys:role"];
        let entries = [ReadSelectionEntry::new(
            "/sys:system/sys:user/sys:role",
            YangPath::new("/sys:system/sys:user/sys:role").unwrap(),
        )];
        let selection = ReadSelection::with_entries(&schema_paths, &entries);

        assert!(selection.contains_path(
            "/sys:system/sys:user/sys:role",
            &YangPath::new("/sys:system/sys:user[sys:name='admin']/sys:role").unwrap()
        ));
        assert!(selection.contains_path(
            "/sys:system/sys:user/sys:role",
            &YangPath::new("/sys:system/sys:user[sys:name='guest']/sys:role").unwrap()
        ));
    }
}
