//! CNF binding points for NETCONF config projection.

use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_model::OpcConfig;
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse};
use opc_mgmt_schema::SchemaRegistry;
use thiserror::Error;

use crate::xml::WithDefaultsMode;

/// RFC 8525 YANG Library advertisement data supplied by the embedding CNF.
///
/// The NETCONF server uses this only when a CNF can also render the
/// corresponding `/yang-library` operational tree. The content id is surfaced in
/// the `:yang-library:1.1` capability and must change whenever the library
/// contents change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangLibraryCapability {
    content_id: String,
}

impl YangLibraryCapability {
    /// Builds a capability descriptor with a non-empty, XML-safe content id.
    pub fn new(content_id: impl Into<String>) -> Result<Self, BindingError> {
        let content_id = content_id.into();
        if content_id.is_empty()
            || content_id.trim() != content_id
            || content_id.chars().any(char::is_control)
        {
            return Err(BindingError::projection(
                "invalid NETCONF YANG Library content-id",
            ));
        }
        Ok(Self { content_id })
    }

    /// RFC 8525 YANG Library content identifier.
    pub fn content_id(&self) -> &str {
        &self.content_id
    }
}

/// RFC 6022 NETCONF monitoring advertisement data supplied by the embedding CNF.
///
/// This enables both `/netconf-state` reads and the `<get-schema>` RPC. The
/// server advertises the monitoring capability only when the CNF opts in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetconfMonitoringCapability;

/// RFC 6243 with-defaults capability supplied by the embedding CNF.
///
/// This server core owns parsing, capability advertisement, NACM, audit, and
/// mode dispatch. The CNF still owns XML projection: a binding that advertises
/// this capability must implement the `*_with_defaults` rendering hooks and
/// produce XML matching the advertised modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithDefaultsCapability {
    basic_mode: WithDefaultsMode,
    also_supported: Vec<WithDefaultsMode>,
}

impl WithDefaultsCapability {
    /// Builds an RFC 6243 capability descriptor.
    pub fn new(
        basic_mode: WithDefaultsMode,
        also_supported: impl IntoIterator<Item = WithDefaultsMode>,
    ) -> Result<Self, BindingError> {
        ensure_supported_with_defaults_mode(basic_mode)?;

        let mut deduped = Vec::new();
        for mode in also_supported {
            ensure_supported_with_defaults_mode(mode)?;
            if mode != basic_mode && !deduped.contains(&mode) {
                deduped.push(mode);
            }
        }

        Ok(Self {
            basic_mode,
            also_supported: deduped,
        })
    }

    /// RFC 6243 `basic-mode`.
    pub const fn basic_mode(&self) -> WithDefaultsMode {
        self.basic_mode
    }

    /// Additional RFC 6243 modes supported by the binding.
    pub fn also_supported(&self) -> &[WithDefaultsMode] {
        &self.also_supported
    }

    /// Returns whether this capability covers a requested mode.
    pub fn supports(&self, mode: WithDefaultsMode) -> bool {
        mode != WithDefaultsMode::Unrecognized
            && (mode == self.basic_mode || self.also_supported.contains(&mode))
    }
}

fn ensure_supported_with_defaults_mode(mode: WithDefaultsMode) -> Result<(), BindingError> {
    if mode == WithDefaultsMode::Unrecognized {
        return Err(BindingError::projection(
            "invalid NETCONF with-defaults mode",
        ));
    }
    Ok(())
}

/// Parsed RFC 6022 `<get-schema>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSchemaRequest {
    /// Schema identifier.
    pub identifier: String,
    /// Optional schema version/revision.
    pub version: Option<String>,
    /// Requested schema format. Defaults to `yang`.
    pub format: String,
}

/// CNF-supplied `<get-schema>` failure. Display text is payload-free; server
/// diagnostics stay local.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GetSchemaError {
    /// No schema matches the requested identifier/version/format.
    #[error("NETCONF schema not found")]
    NotFound,
    /// More than one schema matches the request.
    #[error("NETCONF schema request is not unique")]
    NotUnique,
    /// The schema source cannot currently be retrieved.
    #[error("NETCONF schema retrieval failed")]
    Failed {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
}

impl GetSchemaError {
    /// Constructs a retrieval failure with local diagnostic detail.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: detail.into(),
        }
    }

    /// Server-side diagnostic detail, if present.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Failed { detail } => Some(detail),
            Self::NotFound | Self::NotUnique => None,
        }
    }
}

/// Authorized schema-node selection passed to the CNF XML renderer.
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

/// CNF-supplied projection failure.
///
/// The message is for local diagnostics only. The server maps this to a generic
/// NETCONF `operation-failed` response and never sends the text to the client.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("NETCONF XML projection failed: {message}")]
pub struct BindingError {
    message: String,
}

impl BindingError {
    /// Builds a projection error.
    pub fn projection(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Local diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Binding supplied by the CNF embedding the NETCONF server.
///
/// The server owns the protocol, framing, authz, audit, and datastore read path.
/// The CNF owns schema-aware XML projection until `opc-yanggen` provides a
/// generated NETCONF XML renderer. `render_running_config` must return an XML
/// fragment suitable for placement inside `<data>...</data>`.
pub trait NetconfConfigBinding<C: OpcConfig>: Send + Sync {
    /// The authoritative running-config bus.
    fn config_bus(&self) -> Arc<ConfigBus<C>>;

    /// Generated schema registry for the served model set.
    fn schema_registry(&self) -> &'static dyn SchemaRegistry;

    /// Renders the currently published running config for the authorized paths.
    fn render_running_config(
        &self,
        config: &C,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError>;

    /// Returns the advertised RFC 6243 with-defaults capability, if this
    /// binding can render every advertised mode.
    ///
    /// The default is `None`: no `:with-defaults` capability is advertised and
    /// `<with-defaults>` request parameters are rejected with
    /// `operation-not-supported`.
    fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
        None
    }

    /// Renders running config for an RFC 6243 with-defaults request.
    ///
    /// A binding that advertises [`Self::with_defaults_capability`] must
    /// implement this hook for every advertised mode. The default fails closed
    /// so a capability declaration without projection support cannot
    /// accidentally return non-default-aware XML.
    fn render_running_config_with_defaults(
        &self,
        _config: &C,
        _selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF with-defaults running projection is not implemented",
        ))
    }

    /// Reads NF-supplied operational state for NETCONF `<get>`.
    ///
    /// The default implementation returns no values. That is intentionally
    /// anti-fabrication: CNFs that do not have an operational provider simply
    /// omit state data instead of inventing it.
    fn get_operational_state(
        &self,
        _request: &OperationalRequest,
    ) -> Result<OperationalResponse, OperationalError> {
        Ok(OperationalResponse::default())
    }

    /// Renders NETCONF `<get>` data after server-side filtering and NACM.
    ///
    /// The server owns path resolution, authorization, and operational-state
    /// request validation. The CNF owns schema-aware XML projection until
    /// `opc-yanggen` grows a generated NETCONF XML renderer.
    fn render_get_data(
        &self,
        config: &C,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        _operational_selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        if !operational.values.is_empty() {
            return Err(BindingError::projection(
                "NETCONF operational XML projection is not implemented",
            ));
        }
        self.render_running_config(config, config_selection)
    }

    /// Renders NETCONF `<get>` data for an RFC 6243 with-defaults request.
    ///
    /// A binding that advertises [`Self::with_defaults_capability`] must
    /// implement this hook for every advertised mode. The default fails closed.
    fn render_get_data_with_defaults(
        &self,
        _config: &C,
        _config_selection: ReadSelection<'_>,
        _operational: &OperationalResponse,
        _operational_selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF with-defaults data projection is not implemented",
        ))
    }

    /// Returns the advertised RFC 8525 YANG Library capability, if this binding
    /// can also render the `/yang-library` operational tree.
    ///
    /// The default is `None`: no capability is advertised and `/yang-library`
    /// filters are rejected as an unknown namespace. A binding that returns
    /// `Some` must implement [`Self::render_yang_library`].
    fn yang_library_capability(&self) -> Option<YangLibraryCapability> {
        None
    }

    /// Renders the RFC 8525 `/yang-library` operational tree for the authorized
    /// schema-node paths in `selection`.
    ///
    /// This is CNF-supplied because the generic schema registry intentionally
    /// does not yet carry all discovery data required for a complete YANG
    /// Library instance: imports, features, deviations, datastore schema
    /// partitioning, and raw YANG source locations.
    fn render_yang_library(&self, _selection: ReadSelection<'_>) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF YANG Library projection is not implemented",
        ))
    }

    /// Renders the RFC 8525 `/yang-library` tree for a with-defaults request.
    ///
    /// The default fails closed. Bindings that advertise with-defaults and
    /// YANG Library together must implement this hook.
    fn render_yang_library_with_defaults(
        &self,
        _selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF YANG Library with-defaults projection is not implemented",
        ))
    }

    /// Returns whether the CNF implements RFC 6022 NETCONF monitoring.
    ///
    /// A binding that returns `Some` must also implement
    /// [`Self::render_netconf_monitoring`] and [`Self::get_schema`]. The default
    /// is `None`: no monitoring capability is advertised, `/netconf-state`
    /// filters fail closed as an unknown namespace, and `<get-schema>` returns
    /// `operation-not-supported`.
    fn netconf_monitoring_capability(&self) -> Option<NetconfMonitoringCapability> {
        None
    }

    /// Renders the RFC 6022 `/netconf-state` operational tree for the
    /// authorized schema-node paths in `selection`.
    fn render_netconf_monitoring(
        &self,
        _selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF monitoring projection is not implemented",
        ))
    }

    /// Renders the RFC 6022 `/netconf-state` tree for a with-defaults request.
    ///
    /// The default fails closed. Bindings that advertise with-defaults and
    /// NETCONF monitoring together must implement this hook.
    fn render_netconf_monitoring_with_defaults(
        &self,
        _selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        Err(BindingError::projection(
            "NETCONF monitoring with-defaults projection is not implemented",
        ))
    }

    /// Retrieves a schema source for RFC 6022 `<get-schema>`.
    ///
    /// The returned string is placed inside the `<data>` response element. YANG
    /// source text must be XML-escaped by the binding because it is not an XML
    /// element fragment. The default fails closed so an advertised monitoring
    /// capability without a source hook cannot be mistaken for an empty schema
    /// inventory.
    fn get_schema(&self, _request: &GetSchemaRequest) -> Result<String, GetSchemaError> {
        Err(GetSchemaError::failed(
            "NETCONF get-schema retrieval is not implemented",
        ))
    }
}
