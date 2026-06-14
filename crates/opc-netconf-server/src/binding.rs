//! CNF binding points for NETCONF config projection.

use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse};
use opc_mgmt_schema::{
    DefaultReport, NetconfEditError, NetconfProjectionError, NetconfXmlEditApplicator,
    NetconfXmlRenderContext, NetconfXmlRenderer, SchemaRegistry,
};
use thiserror::Error;

use crate::discovery;
use crate::xml::{EditConfigRequest, WithDefaultsMode};

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

/// Candidate returned by a CNF after translating NETCONF `<edit-config>` XML.
///
/// The generic server owns NETCONF protocol handling and `ConfigBus`
/// submission. It deliberately does not infer model-specific edits from XML:
/// generated CNF code translates the bounded `<config>` element into a full
/// candidate `C` and may provide changed-path hints. The config bus still
/// derives authoritative changed paths from `OpcConfig::changed_paths`.
#[derive(Debug, Clone)]
pub struct EditConfigCandidate<C: OpcConfig> {
    /// Complete candidate config to submit.
    pub candidate: C,
    /// Optional changed-path hint for request logging and idempotency
    /// fingerprinting; the bus recomputes authoritative paths.
    pub changed_paths: Vec<YangPath>,
}

impl<C: OpcConfig> EditConfigCandidate<C> {
    /// Builds an edit-config candidate with optional changed-path hints.
    pub fn new(candidate: C, changed_paths: impl Into<Vec<YangPath>>) -> Self {
        Self {
            candidate,
            changed_paths: changed_paths.into(),
        }
    }
}

/// CNF-supplied `<edit-config>` translation failure.
///
/// Display text is payload-free. Detailed parser/model diagnostics stay inside
/// the embedding CNF's logs and must not be returned to clients by the generic
/// NETCONF server.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EditConfigError {
    /// This binding does not implement the requested edit semantics.
    #[error("NETCONF edit-config operation is not supported")]
    Unsupported,
    /// The client-supplied config fragment is invalid for the served model.
    #[error("NETCONF edit-config value is invalid")]
    InvalidValue,
    /// Translation failed for an internal reason.
    #[error("NETCONF edit-config translation failed")]
    Failed {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
}

impl EditConfigError {
    /// Constructs an internal translation failure with local diagnostic detail.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: detail.into(),
        }
    }

    /// Server-side diagnostic detail, if present.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Failed { detail } => Some(detail),
            Self::Unsupported | Self::InvalidValue => None,
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

    /// Optional generated NETCONF XML renderer for this binding.
    ///
    /// When a CNF returns `Some`, the default read-path hooks render through the
    /// generated projection. A binding may return `None` to keep full ownership
    /// of XML rendering, in which case the default hooks fail closed. This is an
    /// explicit opt-in: the server never falls back to generated projection
    /// without the binding's knowledge.
    fn generated_xml_renderer(&self) -> Option<&dyn NetconfXmlRenderer<C>> {
        None
    }

    /// Optional generated NETCONF XML edit applicator for this binding.
    ///
    /// When a CNF returns `Some`, the default
    /// [`Self::build_edit_config_candidate`] parses the bounded `<config>` XML
    /// and applies it through the generated schema-aware applicator. A binding
    /// may return `None` to keep full ownership of edit translation, or to
    /// decline running writes even when `:writable-running` is advertised.
    fn generated_xml_edit_applicator(&self) -> Option<&dyn NetconfXmlEditApplicator<C>> {
        None
    }

    /// Renders the currently published running config for the authorized paths.
    ///
    /// The default delegates to [`Self::generated_xml_renderer`] if present. A
    /// binding that overrides this method is responsible for honoring
    /// `ReadSelection`, redacting secrets, escaping values, and failing closed.
    fn render_running_config(
        &self,
        config: &C,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        let renderer = self.generated_xml_renderer().ok_or_else(|| {
            BindingError::projection("NETCONF running XML projection is not implemented")
        })?;
        renderer
            .render_running_config(config, selection.schema_paths(), DefaultReport::Trim)
            .map_err(projection_error)
    }

    /// Returns true when this binding supports RFC 6241 running datastore
    /// writes through `<edit-config>` and [`Self::build_edit_config_candidate`].
    ///
    /// The default is `false`: no `:writable-running` capability is advertised
    /// and registry-free dispatch rejects `<edit-config>` with
    /// `operation-not-supported`. A binding that returns `true` must translate
    /// the bounded `<config>` element into a full candidate config.
    fn writable_running_capability(&self) -> bool {
        false
    }

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
    /// implement this hook for every advertised mode. The default delegates to
    /// the generated renderer for `report-all` and `trim`; other modes fail
    /// closed so a capability declaration without projection support cannot
    /// accidentally return non-default-aware XML.
    fn render_running_config_with_defaults(
        &self,
        config: &C,
        selection: ReadSelection<'_>,
        mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        let renderer = self.generated_xml_renderer().ok_or_else(|| {
            BindingError::projection("NETCONF with-defaults running projection is not implemented")
        })?;
        let report = with_defaults_mode_to_report(mode)?;
        if !renderer.supported_default_reports().contains(&report) {
            return Err(BindingError::projection(
                "NETCONF with-defaults report mode is not supported by the generated renderer",
            ));
        }
        renderer
            .render_running_config(config, selection.schema_paths(), report)
            .map_err(projection_error)
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
    /// The default renders the config portion through
    /// [`Self::generated_xml_renderer`] when present, and renders the
    /// operational portion through the generic helper
    /// [`render_operational_xml`]. When no renderer is present and no
    /// operational values are requested, it falls back to the legacy fail-closed
    /// behavior for bindings that have not yet opted into generated projection.
    fn render_get_data(
        &self,
        config: &C,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        operational_selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        let mut out = String::new();
        if let Some(renderer) = self.generated_xml_renderer() {
            out.push_str(
                &renderer
                    .render_running_config(
                        config,
                        config_selection.schema_paths(),
                        DefaultReport::Trim,
                    )
                    .map_err(projection_error)?,
            );
        } else if !operational.values.is_empty() {
            return Err(BindingError::projection(
                "NETCONF operational XML projection is not implemented",
            ));
        }
        out.push_str(&render_operational_xml(
            self.schema_registry(),
            operational_selection.schema_paths(),
            operational,
        )?);
        Ok(out)
    }

    /// Renders NETCONF `<get>` data for an RFC 6243 with-defaults request.
    ///
    /// A binding that advertises [`Self::with_defaults_capability`] must
    /// implement this hook for every advertised mode. The default delegates to
    /// the generated renderer for the config portion and the generic helper for
    /// the operational portion; unsupported modes fail closed.
    fn render_get_data_with_defaults(
        &self,
        config: &C,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        operational_selection: ReadSelection<'_>,
        mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        let renderer = self.generated_xml_renderer().ok_or_else(|| {
            BindingError::projection("NETCONF with-defaults data projection is not implemented")
        })?;
        let report = with_defaults_mode_to_report(mode)?;
        if !renderer.supported_default_reports().contains(&report) {
            return Err(BindingError::projection(
                "NETCONF with-defaults report mode is not supported by the generated renderer",
            ));
        }
        let mut out = renderer
            .render_running_config(config, config_selection.schema_paths(), report)
            .map_err(projection_error)?;
        out.push_str(&render_operational_xml(
            self.schema_registry(),
            operational_selection.schema_paths(),
            operational,
        )?);
        Ok(out)
    }

    /// Returns the advertised RFC 8525 YANG Library capability, if this binding
    /// can also render the `/yang-library` operational tree.
    ///
    /// The default is `None` when the schema registry does not carry generated
    /// discovery metadata. When it does, the default advertises
    /// `:yang-library:1.1` with the registry's schema digest as the content-id
    /// and dispatches to the generic renderer in [`Self::render_yang_library`].
    fn yang_library_capability(&self) -> Option<YangLibraryCapability> {
        let registry = self.schema_registry();
        if registry.discovery_metadata().is_empty() {
            return None;
        }
        YangLibraryCapability::new(registry.schema_digest()).ok()
    }

    /// Renders the RFC 8525 `/yang-library` operational tree for the authorized
    /// schema-node paths in `selection`.
    ///
    /// When the schema registry carries generated discovery metadata, the
    /// default renders a bounded module-set from that metadata. Otherwise it
    /// fails closed so a capability declaration without data cannot fabricate
    /// discovery XML.
    fn render_yang_library(&self, selection: ReadSelection<'_>) -> Result<String, BindingError> {
        discovery::render_yang_library(self.schema_registry(), selection)
    }

    /// Renders the RFC 8525 `/yang-library` tree for a with-defaults request.
    ///
    /// Discovery trees do not carry defaults, so the default ignores the mode
    /// and renders the ordinary tree. Bindings that need different behavior may
    /// override this hook.
    fn render_yang_library_with_defaults(
        &self,
        selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        discovery::render_yang_library(self.schema_registry(), selection)
    }

    /// Returns whether the CNF implements RFC 6022 NETCONF monitoring.
    ///
    /// The default is `None` when the schema registry does not carry generated
    /// discovery metadata. When it does, the default advertises monitoring and
    /// dispatches `/netconf-state/schemas` rendering and `<get-schema>` lookups
    /// to the generic helpers.
    fn netconf_monitoring_capability(&self) -> Option<NetconfMonitoringCapability> {
        if self.schema_registry().discovery_metadata().is_empty() {
            None
        } else {
            Some(NetconfMonitoringCapability)
        }
    }

    /// Renders the RFC 6022 `/netconf-state` operational tree for the
    /// authorized schema-node paths in `selection`.
    ///
    /// The default renders only the `schemas` inventory from generated
    /// discovery metadata; other `/netconf-state` containers are not fabricated.
    fn render_netconf_monitoring(
        &self,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        discovery::render_netconf_monitoring(self.schema_registry(), selection)
    }

    /// Renders the RFC 6022 `/netconf-state` tree for a with-defaults request.
    ///
    /// Discovery trees do not carry defaults, so the default ignores the mode.
    fn render_netconf_monitoring_with_defaults(
        &self,
        selection: ReadSelection<'_>,
        _mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        discovery::render_netconf_monitoring(self.schema_registry(), selection)
    }

    /// Retrieves a schema source for RFC 6022 `<get-schema>`.
    ///
    /// When the schema registry carries generated discovery metadata with raw
    /// YANG source text, the default looks up the source by identifier and
    /// version. Otherwise it fails closed so an advertised monitoring
    /// capability without a source hook cannot be mistaken for an empty schema
    /// inventory.
    fn get_schema(&self, request: &GetSchemaRequest) -> Result<String, GetSchemaError> {
        let registry = self.schema_registry();
        if registry.discovery_metadata().is_empty() {
            return Err(GetSchemaError::failed(
                "NETCONF get-schema source provider is not configured",
            ));
        }
        discovery::schema_source(registry, request)
    }

    /// Builds a full candidate config for a running `<edit-config>` request.
    ///
    /// The request's `config_xml` is a bounded, namespace-preserving NETCONF
    /// `<config>` element. Bindings typically decode it with generated
    /// schema-aware XML/YANG helpers or translate it into the generated
    /// `ConfigDelta` patch applicator.
    ///
    /// The default implementation delegates to
    /// [`Self::generated_xml_edit_applicator`] when the binding exposes one.
    /// This is an explicit opt-in: there is no hidden fallback to a generic
    /// translator, so adding server-side edit support does not imply every CNF
    /// can accept writes.
    fn build_edit_config_candidate(
        &self,
        running: &C,
        request: &EditConfigRequest,
    ) -> Result<EditConfigCandidate<C>, EditConfigError> {
        let applicator = self
            .generated_xml_edit_applicator()
            .ok_or(EditConfigError::Unsupported)?;
        let edit = crate::edit_xml::parse_edit_config_xml(
            &request.config_xml,
            self.schema_registry(),
            request.default_operation,
        )
        .map_err(netconf_edit_error_to_binding_error)?;
        let candidate = applicator
            .apply_edit_config(running, &edit)
            .map_err(netconf_edit_error_to_binding_error)?;
        Ok(EditConfigCandidate::new(candidate, Vec::new()))
    }
}

fn netconf_edit_error_to_binding_error(err: NetconfEditError) -> EditConfigError {
    match err {
        NetconfEditError::UnsupportedShape { .. } => EditConfigError::InvalidValue,
        NetconfEditError::OperationNotSupported { .. } => EditConfigError::InvalidValue,
        NetconfEditError::ReadOnly { .. } => EditConfigError::InvalidValue,
        NetconfEditError::UnknownPath(_) => EditConfigError::InvalidValue,
        NetconfEditError::InvalidValue { .. } => EditConfigError::InvalidValue,
        NetconfEditError::MissingKey { .. } => EditConfigError::InvalidValue,
        NetconfEditError::ExtraKey { .. } => EditConfigError::InvalidValue,
        NetconfEditError::KeyOnNonList { .. } => EditConfigError::InvalidValue,
        NetconfEditError::MalformedXml => EditConfigError::InvalidValue,
    }
}

fn projection_error(err: NetconfProjectionError) -> BindingError {
    BindingError::projection(err.to_string())
}

fn with_defaults_mode_to_report(mode: WithDefaultsMode) -> Result<DefaultReport, BindingError> {
    match mode {
        WithDefaultsMode::ReportAll => Ok(DefaultReport::ReportAll),
        WithDefaultsMode::Trim => Ok(DefaultReport::Trim),
        WithDefaultsMode::Explicit => Ok(DefaultReport::Explicit),
        WithDefaultsMode::ReportAllTagged => Ok(DefaultReport::ReportAllTagged),
        WithDefaultsMode::Unrecognized => Err(BindingError::projection(
            "NETCONF with-defaults mode is unrecognized",
        )),
    }
}

/// Renders operational-state values as NETCONF XML for the authorized state paths.
///
/// This helper is anti-fabrication: paths the provider did not report are
/// omitted, non-leaf values are skipped, and JSON payloads that are not scalar
/// fail closed rather than being silently flattened.
pub fn render_operational_xml(
    registry: &'static dyn SchemaRegistry,
    paths: &[&'static str],
    operational: &OperationalResponse,
) -> Result<String, BindingError> {
    if paths.is_empty() || operational.values.is_empty() {
        return Ok(String::new());
    }

    let ctx = NetconfXmlRenderContext::new(registry, paths, DefaultReport::Trim);
    let mut out = String::new();

    for path in paths {
        let Some(node) = registry.node(path) else {
            continue;
        };
        if node.config || node.kind != opc_mgmt_schema::NodeKind::Leaf {
            continue;
        }

        let yang_path = YangPath::new(*path).map_err(|_| {
            BindingError::projection("NETCONF operational path is not a valid YangPath")
        })?;
        let Some(value) = operational.value_for(&yang_path) else {
            continue;
        };

        let json_value: serde_json::Value = serde_json::from_str(value.value_json())
            .map_err(|_| BindingError::projection("NETCONF operational value is not valid JSON"))?;

        let raw = match json_value {
            serde_json::Value::Null => continue,
            serde_json::Value::String(s) => s,
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                return Err(BindingError::projection(
                    "NETCONF operational value is not a scalar and cannot be rendered as XML",
                ));
            }
        };

        out.push_str(&ctx.format_leaf(path, &raw).map_err(projection_error)?);
    }

    Ok(out)
}
