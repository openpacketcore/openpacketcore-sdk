//! Bounded NETCONF XML envelope parsing.

use std::collections::BTreeMap;

use opc_mgmt_errors::{NetconfError, NetconfErrorTag, NetconfErrorType};
use opc_mgmt_limits::{LimitsError, MgmtLimits};
use quick_xml::encoding::Decoder;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use thiserror::Error;

use crate::capabilities::{NETCONF_BASE_NS, NETCONF_MONITORING_NS, WITH_DEFAULTS_NS};

/// Parsed NETCONF client `<hello>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Capability URIs advertised by the client.
    pub capabilities: Vec<String>,
}

/// Parsed NETCONF RPC envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRpc {
    /// RFC 6241 message id.
    pub message_id: String,
    /// RPC operation.
    pub operation: RpcOperation,
}

/// Supported parsed RPC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcOperation {
    /// `<get-config>`.
    GetConfig(GetConfigRequest),
    /// `<get>`.
    Get(GetRequest),
    /// `<close-session>`.
    CloseSession,
    /// RFC 6022 `<get-schema>`.
    GetSchema(GetSchemaRequest),
    /// A known NETCONF operation that this read-only slice deliberately does
    /// not implement yet.
    Unsupported(UnsupportedOperation),
}

/// RFC 6022 `<get-schema>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSchemaRequest {
    /// Required schema identifier.
    pub identifier: String,
    /// Optional schema version/revision.
    pub version: Option<String>,
    /// Requested schema format. Defaults to `yang`.
    pub format: String,
}

/// Known NETCONF operations that are parsed only to reject safely with the
/// request `message-id` preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedOperation {
    /// `<edit-config>`.
    EditConfig,
    /// `<copy-config>`.
    CopyConfig,
    /// `<delete-config>`.
    DeleteConfig,
    /// `<lock>`.
    Lock,
    /// `<unlock>`.
    Unlock,
    /// `<kill-session>`.
    KillSession,
    /// `<commit>`.
    Commit,
    /// `<discard-changes>`.
    DiscardChanges,
    /// `<validate>`.
    Validate,
}

impl UnsupportedOperation {
    /// XML local name for this operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EditConfig => "edit-config",
            Self::CopyConfig => "copy-config",
            Self::DeleteConfig => "delete-config",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::KillSession => "kill-session",
            Self::Commit => "commit",
            Self::DiscardChanges => "discard-changes",
            Self::Validate => "validate",
        }
    }
}

/// RFC 6243 `<with-defaults>` retrieval mode marker.
///
/// The server advertises `:with-defaults` only when the embedding CNF supplies
/// default-aware projection hooks. This enum lets the parser recognize the
/// request shape without retaining arbitrary client text. Invalid or currently
/// unknown text is kept as [`WithDefaultsMode::Unrecognized`] and rejected at
/// the operation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithDefaultsMode {
    /// `report-all`.
    ReportAll,
    /// `report-all-tagged`.
    ReportAllTagged,
    /// `trim`.
    Trim,
    /// `explicit`.
    Explicit,
    /// A payload-free marker for any unrecognized value.
    Unrecognized,
}

impl WithDefaultsMode {
    fn parse(value: &str) -> Self {
        match value.trim() {
            "report-all" => Self::ReportAll,
            "report-all-tagged" => Self::ReportAllTagged,
            "trim" => Self::Trim,
            "explicit" => Self::Explicit,
            _ => Self::Unrecognized,
        }
    }

    /// Wire value for recognized modes. Unrecognized values are intentionally
    /// not recoverable.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReportAll => "report-all",
            Self::ReportAllTagged => "report-all-tagged",
            Self::Trim => "trim",
            Self::Explicit => "explicit",
            Self::Unrecognized => "unrecognized",
        }
    }
}

/// `<get>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRequest {
    /// Optional filter.
    pub filter: Option<Filter>,
    /// RFC 6243 `<with-defaults>` parameter. The handler accepts it only when
    /// the binding advertises a matching `WithDefaultsCapability`.
    pub with_defaults: Option<WithDefaultsMode>,
}

/// `<get-config>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetConfigRequest {
    /// Requested source datastore.
    pub source: Datastore,
    /// Optional filter.
    pub filter: Option<Filter>,
    /// RFC 6243 `<with-defaults>` parameter. The handler accepts it only when
    /// the binding advertises a matching `WithDefaultsCapability`.
    pub with_defaults: Option<WithDefaultsMode>,
}

/// NETCONF datastores recognized by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datastore {
    /// `running`, backed today by `ConfigBus::current_snapshot()`.
    Running,
    /// `candidate`, not implemented in this slice.
    Candidate,
    /// `startup`, not implemented in this slice.
    Startup,
}

/// NETCONF filter kind recognized by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    /// Subtree filter.
    Subtree,
    /// XPath filter.
    XPath,
}

/// NETCONF filter parsed from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Structural subtree filter.
    Subtree(SubtreeFilter),
    /// XPath filter. Recognized so it can be rejected honestly until a bounded
    /// evaluator exists.
    XPath,
}

/// Parsed structural subtree filter.
///
/// The parser deliberately accepts only selection nodes. NETCONF subtree
/// content-match and attribute-match forms need a schema-aware evaluator; they
/// fail closed instead of being silently widened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubtreeFilter {
    selections: Vec<SubtreeSelection>,
}

impl SubtreeFilter {
    /// Parsed selection nodes in document order.
    pub fn selections(&self) -> &[SubtreeSelection] {
        &self.selections
    }

    pub(crate) fn push(&mut self, selection: SubtreeSelection) {
        self.selections.push(selection);
    }
}

/// One subtree-filter selection path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeSelection {
    elements: Vec<FilterElement>,
    include_descendants: bool,
}

impl SubtreeSelection {
    /// Builds a parsed subtree selection.
    pub(crate) fn new(elements: Vec<FilterElement>, include_descendants: bool) -> Self {
        Self {
            elements,
            include_descendants,
        }
    }

    /// Namespace-qualified elements from the filter root to this selected node.
    pub fn elements(&self) -> &[FilterElement] {
        &self.elements
    }

    /// Whether this was an empty/terminal selection node, which selects the
    /// node's full subtree.
    pub const fn include_descendants(&self) -> bool {
        self.include_descendants
    }
}

/// Namespace-qualified filter element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterElement {
    /// Resolved XML namespace URI.
    pub namespace: String,
    /// Local element name.
    pub local: String,
}

/// XML parsing or RPC envelope validation error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum XmlError {
    /// Shared management-plane limit error.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// XML parser rejected the document.
    #[error("malformed NETCONF XML")]
    Malformed,
    /// XML DTDs are not allowed on the management plane.
    #[error("NETCONF XML DTD is not allowed")]
    DtdForbidden,
    /// XML entity references are not allowed in protocol envelopes.
    #[error("NETCONF XML entity reference is not allowed")]
    EntityForbidden,
    /// The document contained no root element.
    #[error("NETCONF XML document is empty")]
    Empty,
    /// The document contained more than one root element.
    #[error("NETCONF XML document has multiple roots")]
    MultipleRoots,
    /// A protocol element used an absent or unknown namespace.
    #[error("NETCONF protocol element has an unknown namespace")]
    UnknownNamespace,
    /// A required attribute was missing.
    #[error("NETCONF RPC missing required attribute")]
    MissingAttribute,
    /// A required element was missing.
    #[error("NETCONF RPC missing required element")]
    MissingElement,
    /// A singleton field appeared more than once.
    #[error("NETCONF RPC duplicate element")]
    DuplicateElement,
    /// The operation is not recognized by this parser.
    #[error("NETCONF RPC operation is not supported")]
    UnsupportedOperation,
    /// A filter type is not valid for this server core.
    #[error("NETCONF filter type is invalid")]
    InvalidFilterType,
    /// The subtree filter used a form this slice does not implement.
    #[error("NETCONF subtree filter content is not supported")]
    UnsupportedFilterContent,
}

impl XmlError {
    /// Maps the parser error to a NETCONF error classification.
    pub const fn classification(&self) -> NetconfError {
        use NetconfErrorTag as Tag;
        use NetconfErrorType as Ty;
        match self {
            Self::Limit(_) => NetconfError::new(Ty::Protocol, Tag::TooBig),
            Self::Malformed
            | Self::DtdForbidden
            | Self::EntityForbidden
            | Self::Empty
            | Self::MultipleRoots => NetconfError::new(Ty::Rpc, Tag::MalformedMessage),
            Self::UnknownNamespace => NetconfError::new(Ty::Protocol, Tag::UnknownNamespace),
            Self::MissingAttribute => NetconfError::new(Ty::Rpc, Tag::MissingAttribute),
            Self::MissingElement => NetconfError::new(Ty::Protocol, Tag::MissingElement),
            Self::DuplicateElement | Self::InvalidFilterType | Self::UnsupportedFilterContent => {
                NetconfError::new(Ty::Protocol, Tag::BadElement)
            }
            Self::UnsupportedOperation => {
                NetconfError::new(Ty::Protocol, Tag::OperationNotSupported)
            }
        }
    }

    /// Static, payload-free client message.
    pub const fn client_message(&self) -> &'static str {
        match self {
            Self::Limit(_) => "request is too large",
            Self::UnknownNamespace => "unknown namespace",
            Self::MissingAttribute => "missing attribute",
            Self::MissingElement => "missing element",
            Self::DuplicateElement => "duplicate element",
            Self::UnsupportedOperation => "operation not supported",
            Self::InvalidFilterType => "invalid filter type",
            Self::UnsupportedFilterContent => "unsupported filter content",
            Self::Malformed
            | Self::DtdForbidden
            | Self::EntityForbidden
            | Self::Empty
            | Self::MultipleRoots => "malformed message",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RootKind {
    Hello,
    Rpc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    local: String,
    namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FilterFrame {
    path: Vec<FilterElement>,
    child_count: usize,
}

#[derive(Debug, Clone, Default)]
struct NamespaceScope {
    default: Option<String>,
    bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct PartialGet {
    filter: Option<Filter>,
    with_defaults_seen: bool,
    with_defaults: Option<WithDefaultsMode>,
}

#[derive(Debug, Clone, Default)]
struct PartialGetConfig {
    source: Option<Datastore>,
    filter: Option<Filter>,
    with_defaults_seen: bool,
    with_defaults: Option<WithDefaultsMode>,
}

#[derive(Debug, Clone, Default)]
struct PartialGetSchema {
    identifier: Option<String>,
    version: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum GetSchemaField {
    Identifier,
    Version,
    Format,
}

#[derive(Debug, Clone, Default)]
struct ParserState {
    root: Option<RootKind>,
    stack: Vec<Element>,
    scopes: Vec<NamespaceScope>,
    message_id: Option<String>,
    capabilities: Vec<String>,
    get: Option<PartialGet>,
    get_config: Option<PartialGetConfig>,
    get_schema: Option<PartialGetSchema>,
    close_session: bool,
    unsupported_operation: Option<UnsupportedOperation>,
    filter_depth: usize,
    filter_stack: Vec<FilterFrame>,
    root_closed: bool,
}

impl ParserState {
    fn new() -> Self {
        Self {
            scopes: vec![NamespaceScope::default()],
            ..Self::default()
        }
    }

    fn push_start(
        &mut self,
        start: &BytesStart<'_>,
        decoder: Decoder,
        limits: &MgmtLimits,
    ) -> Result<(), XmlError> {
        if self.root_closed && self.stack.is_empty() {
            return Err(XmlError::MultipleRoots);
        }

        let (scope, attrs) = scoped_attributes(start, decoder, limits, self.scopes.last())?;
        let raw_name = start.name();
        let (prefix, local) = split_qname(raw_name.as_ref())?;
        let namespace = resolve_namespace(prefix, &scope)?;
        let element = Element {
            local: local.to_string(),
            namespace,
        };

        limits.check_depth(self.stack.len() + 1)?;
        self.validate_protocol_namespace(&element)?;
        self.process_start(&element, &attrs)?;
        self.stack.push(element);
        self.scopes.push(scope);
        Ok(())
    }

    fn push_empty(
        &mut self,
        start: &BytesStart<'_>,
        decoder: Decoder,
        limits: &MgmtLimits,
    ) -> Result<(), XmlError> {
        self.push_start(start, decoder, limits)?;
        self.pop_end(start.name().as_ref())
    }

    fn pop_end(&mut self, raw_name: &[u8]) -> Result<(), XmlError> {
        let scope = self.scopes.last().ok_or(XmlError::Malformed)?;
        let (prefix, local) = split_qname(raw_name)?;
        let namespace = resolve_namespace(prefix, scope)?;
        let Some(current) = self.stack.pop() else {
            return Err(XmlError::Malformed);
        };
        if current.local != local || current.namespace != namespace {
            return Err(XmlError::Malformed);
        }
        self.scopes.pop();
        if self.filter_depth > 1 {
            self.finish_filter_content_element()?;
        }
        if self.filter_depth > 0 {
            self.filter_depth -= 1;
            if self.filter_depth == 0 && !self.filter_stack.is_empty() {
                return Err(XmlError::Malformed);
            }
        }
        if self.stack.is_empty() {
            self.root_closed = true;
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), XmlError> {
        if self.filter_depth > 0 {
            if text.trim().is_empty() {
                return Ok(());
            }
            return Err(XmlError::UnsupportedFilterContent);
        }
        if self.local_path_is(&["hello", "capabilities", "capability"]) {
            self.capabilities.push(text.to_string());
        } else if self.local_path_is(&["rpc", "get-schema", "identifier"]) {
            self.set_get_schema_text(GetSchemaField::Identifier, text)?;
        } else if self.local_path_is(&["rpc", "get-schema", "version"]) {
            self.set_get_schema_text(GetSchemaField::Version, text)?;
        } else if self.local_path_is(&["rpc", "get-schema", "format"]) {
            self.set_get_schema_text(GetSchemaField::Format, text)?;
        } else if self.local_path_is(&["rpc", "get", "with-defaults"]) {
            self.set_get_with_defaults_text(text)?;
        } else if self.local_path_is(&["rpc", "get-config", "with-defaults"]) {
            self.set_get_config_with_defaults_text(text)?;
        }
        Ok(())
    }

    fn validate_protocol_namespace(&self, element: &Element) -> Result<(), XmlError> {
        if self.filter_depth > 0 || self.inside_unsupported_operation() {
            return Ok(());
        }
        if element.namespace == NETCONF_BASE_NS
            || self.get_schema_namespace_is_allowed(element)
            || self.with_defaults_namespace_is_allowed(element)
        {
            Ok(())
        } else {
            Err(XmlError::UnknownNamespace)
        }
    }

    fn process_start(
        &mut self,
        element: &Element,
        attrs: &[(String, String)],
    ) -> Result<(), XmlError> {
        if self.filter_depth > 0 {
            self.process_filter_content_start(element, attrs)?;
            self.filter_depth += 1;
            return Ok(());
        }

        if self.stack.is_empty() {
            self.root = match element.local.as_str() {
                "hello" => Some(RootKind::Hello),
                "rpc" => {
                    self.message_id = attr_value(attrs, "message-id").map(ToOwned::to_owned);
                    Some(RootKind::Rpc)
                }
                _ => return Err(XmlError::UnsupportedOperation),
            };
            return Ok(());
        }

        match self.root {
            Some(RootKind::Hello) => self.process_hello_start(element),
            Some(RootKind::Rpc) => self.process_rpc_start(element, attrs),
            None => Err(XmlError::Malformed),
        }
    }

    fn process_hello_start(&self, element: &Element) -> Result<(), XmlError> {
        if self.local_path_is(&["hello"]) && element.local == "capabilities"
            || self.local_path_is(&["hello", "capabilities"]) && element.local == "capability"
        {
            Ok(())
        } else {
            Err(XmlError::Malformed)
        }
    }

    fn process_rpc_start(
        &mut self,
        element: &Element,
        attrs: &[(String, String)],
    ) -> Result<(), XmlError> {
        if self.inside_unsupported_operation() {
            return Ok(());
        }

        if self.local_path_is(&["rpc"]) {
            match element.local.as_str() {
                "get" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.get = Some(PartialGet::default());
                }
                "get-config" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.get_config = Some(PartialGetConfig::default());
                }
                "close-session" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.close_session = true;
                }
                "get-schema" if element.namespace == NETCONF_MONITORING_NS => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.get_schema = Some(PartialGetSchema::default());
                }
                "edit-config" => self.set_unsupported(UnsupportedOperation::EditConfig)?,
                "copy-config" => self.set_unsupported(UnsupportedOperation::CopyConfig)?,
                "delete-config" => self.set_unsupported(UnsupportedOperation::DeleteConfig)?,
                "lock" => self.set_unsupported(UnsupportedOperation::Lock)?,
                "unlock" => self.set_unsupported(UnsupportedOperation::Unlock)?,
                "kill-session" => self.set_unsupported(UnsupportedOperation::KillSession)?,
                "commit" => self.set_unsupported(UnsupportedOperation::Commit)?,
                "discard-changes" => self.set_unsupported(UnsupportedOperation::DiscardChanges)?,
                "validate" => self.set_unsupported(UnsupportedOperation::Validate)?,
                _ => return Err(XmlError::UnsupportedOperation),
            }
            return Ok(());
        }

        if self.local_path_is(&["rpc", "get"]) {
            match element.local.as_str() {
                "filter" if element.namespace == NETCONF_BASE_NS => self.install_filter(attrs),
                "with-defaults" if element.namespace == WITH_DEFAULTS_NS => {
                    self.install_get_with_defaults(attrs)
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-config"]) {
            match element.local.as_str() {
                "source" if element.namespace == NETCONF_BASE_NS => Ok(()),
                "filter" if element.namespace == NETCONF_BASE_NS => self.install_filter(attrs),
                "with-defaults" if element.namespace == WITH_DEFAULTS_NS => {
                    self.install_get_config_with_defaults(attrs)
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "close-session"]) {
            Err(XmlError::Malformed)
        } else if self.local_path_is(&["rpc", "get-schema"]) {
            match element.local.as_str() {
                "identifier" | "version" | "format"
                    if element.namespace == NETCONF_MONITORING_NS =>
                {
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-schema", "identifier"])
            || self.local_path_is(&["rpc", "get-schema", "version"])
            || self.local_path_is(&["rpc", "get-schema", "format"])
            || self.local_path_is(&["rpc", "get", "with-defaults"])
            || self.local_path_is(&["rpc", "get-config", "with-defaults"])
        {
            Err(XmlError::Malformed)
        } else if self.local_path_is(&["rpc", "get-config", "source"]) {
            let datastore = match element.local.as_str() {
                "running" => Datastore::Running,
                "candidate" => Datastore::Candidate,
                "startup" => Datastore::Startup,
                _ => return Err(XmlError::Malformed),
            };
            let get_config = self
                .get_config
                .as_mut()
                .ok_or(XmlError::UnsupportedOperation)?;
            if get_config.source.replace(datastore).is_some() {
                return Err(XmlError::DuplicateElement);
            }
            Ok(())
        } else {
            Err(XmlError::Malformed)
        }
    }

    fn has_rpc_operation(&self) -> bool {
        self.get.is_some()
            || self.get_config.is_some()
            || self.get_schema.is_some()
            || self.close_session
            || self.unsupported_operation.is_some()
    }

    fn get_schema_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == NETCONF_MONITORING_NS
            && (self.local_path_is(&["rpc"])
                || self.local_path_is(&["rpc", "get-schema"])
                || self.local_path_is(&["rpc", "get-schema", "identifier"])
                || self.local_path_is(&["rpc", "get-schema", "version"])
                || self.local_path_is(&["rpc", "get-schema", "format"]))
    }

    fn with_defaults_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == WITH_DEFAULTS_NS
            && (self.local_path_is(&["rpc", "get"])
                || self.local_path_is(&["rpc", "get", "with-defaults"])
                || self.local_path_is(&["rpc", "get-config"])
                || self.local_path_is(&["rpc", "get-config", "with-defaults"]))
    }

    fn set_get_schema_text(&mut self, field: GetSchemaField, text: &str) -> Result<(), XmlError> {
        let value = text.trim();
        if value.is_empty() {
            return Ok(());
        }
        let get_schema = self
            .get_schema
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let slot = match field {
            GetSchemaField::Identifier => &mut get_schema.identifier,
            GetSchemaField::Version => &mut get_schema.version,
            GetSchemaField::Format => &mut get_schema.format,
        };
        if slot.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn install_get_with_defaults(&mut self, attrs: &[(String, String)]) -> Result<(), XmlError> {
        if !attrs.is_empty() {
            return Err(XmlError::Malformed);
        }
        let get = self.get.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        if get.with_defaults_seen {
            return Err(XmlError::DuplicateElement);
        }
        get.with_defaults_seen = true;
        Ok(())
    }

    fn install_get_config_with_defaults(
        &mut self,
        attrs: &[(String, String)],
    ) -> Result<(), XmlError> {
        if !attrs.is_empty() {
            return Err(XmlError::Malformed);
        }
        let get_config = self
            .get_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_config.with_defaults_seen {
            return Err(XmlError::DuplicateElement);
        }
        get_config.with_defaults_seen = true;
        Ok(())
    }

    fn set_get_with_defaults_text(&mut self, text: &str) -> Result<(), XmlError> {
        let get = self.get.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        if get
            .with_defaults
            .replace(WithDefaultsMode::parse(text))
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_get_config_with_defaults_text(&mut self, text: &str) -> Result<(), XmlError> {
        let get_config = self
            .get_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_config
            .with_defaults
            .replace(WithDefaultsMode::parse(text))
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_unsupported(&mut self, operation: UnsupportedOperation) -> Result<(), XmlError> {
        if self.has_rpc_operation() {
            return Err(XmlError::DuplicateElement);
        }
        self.unsupported_operation = Some(operation);
        Ok(())
    }

    fn inside_unsupported_operation(&self) -> bool {
        self.unsupported_operation.is_some() && self.stack.len() >= 2
    }

    fn install_filter(&mut self, attrs: &[(String, String)]) -> Result<(), XmlError> {
        let filter = filter_kind(attrs)?;
        let parsed_filter = match filter {
            FilterKind::Subtree => Filter::Subtree(SubtreeFilter::default()),
            FilterKind::XPath => Filter::XPath,
        };
        let duplicate = if self.local_path_is(&["rpc", "get"]) {
            self.get
                .as_mut()
                .ok_or(XmlError::UnsupportedOperation)?
                .filter
                .replace(parsed_filter)
                .is_some()
        } else {
            self.get_config
                .as_mut()
                .ok_or(XmlError::UnsupportedOperation)?
                .filter
                .replace(parsed_filter)
                .is_some()
        };
        if duplicate {
            return Err(XmlError::DuplicateElement);
        }
        self.filter_depth = 1;
        Ok(())
    }

    fn process_filter_content_start(
        &mut self,
        element: &Element,
        attrs: &[(String, String)],
    ) -> Result<(), XmlError> {
        if !attrs.is_empty() {
            return Err(XmlError::UnsupportedFilterContent);
        }

        if !matches!(self.active_filter(), Some(Filter::Subtree(_))) {
            return Err(XmlError::UnsupportedFilterContent);
        }

        if let Some(parent) = self.filter_stack.last_mut() {
            parent.child_count += 1;
        }

        let mut path = self
            .filter_stack
            .last()
            .map(|frame| frame.path.clone())
            .unwrap_or_default();
        path.push(FilterElement {
            namespace: element.namespace.clone(),
            local: element.local.clone(),
        });

        self.filter_stack.push(FilterFrame {
            path,
            child_count: 0,
        });

        Ok(())
    }

    fn finish_filter_content_element(&mut self) -> Result<(), XmlError> {
        let frame = self.filter_stack.pop().ok_or(XmlError::Malformed)?;
        let Some(Filter::Subtree(filter)) = self.active_filter_mut() else {
            return Err(XmlError::UnsupportedFilterContent);
        };
        filter.push(SubtreeSelection::new(frame.path, frame.child_count == 0));
        Ok(())
    }

    fn active_filter(&self) -> Option<&Filter> {
        self.get
            .as_ref()
            .and_then(|get| get.filter.as_ref())
            .or_else(|| {
                self.get_config
                    .as_ref()
                    .and_then(|get_config| get_config.filter.as_ref())
            })
    }

    fn active_filter_mut(&mut self) -> Option<&mut Filter> {
        if let Some(get) = self.get.as_mut() {
            return get.filter.as_mut();
        }
        self.get_config
            .as_mut()
            .and_then(|get_config| get_config.filter.as_mut())
    }

    fn finish(self) -> Result<ParsedMessage, XmlError> {
        if self.root.is_none() {
            return Err(XmlError::Empty);
        }
        if !self.stack.is_empty() {
            return Err(XmlError::Malformed);
        }

        match self.root.expect("checked root") {
            RootKind::Hello => Ok(ParsedMessage::Hello(ClientHello {
                capabilities: self.capabilities,
            })),
            RootKind::Rpc => {
                let message_id = self.message_id.ok_or(XmlError::MissingAttribute)?;
                if let Some(get) = self.get {
                    let with_defaults =
                        finish_with_defaults(get.with_defaults_seen, get.with_defaults);
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        operation: RpcOperation::Get(GetRequest {
                            filter: get.filter,
                            with_defaults,
                        }),
                    }));
                }
                if let Some(get_config) = self.get_config {
                    let source = get_config.source.ok_or(XmlError::MissingElement)?;
                    let with_defaults = finish_with_defaults(
                        get_config.with_defaults_seen,
                        get_config.with_defaults,
                    );
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        operation: RpcOperation::GetConfig(GetConfigRequest {
                            source,
                            filter: get_config.filter,
                            with_defaults,
                        }),
                    }));
                }
                if self.close_session {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        operation: RpcOperation::CloseSession,
                    }));
                }
                if let Some(get_schema) = self.get_schema {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        operation: RpcOperation::GetSchema(GetSchemaRequest {
                            identifier: get_schema.identifier.ok_or(XmlError::MissingElement)?,
                            version: get_schema.version,
                            format: get_schema.format.unwrap_or_else(|| "yang".to_string()),
                        }),
                    }));
                }
                if let Some(operation) = self.unsupported_operation {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        operation: RpcOperation::Unsupported(operation),
                    }));
                }
                Err(XmlError::UnsupportedOperation)
            }
        }
    }

    fn local_path_is(&self, path: &[&str]) -> bool {
        self.stack.len() == path.len()
            && self
                .stack
                .iter()
                .zip(path)
                .all(|(element, expected)| element.local == *expected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedMessage {
    Hello(ClientHello),
    Rpc(ParsedRpc),
}

/// Parses a NETCONF client `<hello>`.
pub fn parse_client_hello(xml: &str, limits: &MgmtLimits) -> Result<ClientHello, XmlError> {
    match parse_message(xml, limits)? {
        ParsedMessage::Hello(hello) => Ok(hello),
        ParsedMessage::Rpc(_) => Err(XmlError::Malformed),
    }
}

/// Parses a NETCONF RPC envelope.
pub fn parse_rpc(xml: &str, limits: &MgmtLimits) -> Result<ParsedRpc, XmlError> {
    match parse_message(xml, limits)? {
        ParsedMessage::Rpc(rpc) => Ok(rpc),
        ParsedMessage::Hello(_) => Err(XmlError::UnsupportedOperation),
    }
}

fn parse_message(xml: &str, limits: &MgmtLimits) -> Result<ParsedMessage, XmlError> {
    limits.validate()?;
    limits.check_request_bytes(xml.len())?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut state = ParserState::new();

    loop {
        match reader.read_event().map_err(|_| XmlError::Malformed)? {
            Event::Start(start) => {
                state.push_start(&start, reader.decoder(), limits)?;
            }
            Event::Empty(start) => {
                state.push_empty(&start, reader.decoder(), limits)?;
            }
            Event::End(end) => {
                state.pop_end(end.name().as_ref())?;
            }
            Event::Text(text) => {
                limits.check_value_bytes(text.as_ref().len())?;
                let decoded = text.decode().map_err(|_| XmlError::Malformed)?;
                state.text(decoded.as_ref())?;
            }
            Event::CData(cdata) => {
                limits.check_value_bytes(cdata.as_ref().len())?;
                return Err(XmlError::Malformed);
            }
            Event::DocType(_) => return Err(XmlError::DtdForbidden),
            Event::GeneralRef(_) => return Err(XmlError::EntityForbidden),
            Event::Decl(_) | Event::Comment(_) => {}
            Event::PI(_) => return Err(XmlError::Malformed),
            Event::Eof => break,
        }
    }

    let parsed = state.finish()?;
    if let ParsedMessage::Rpc(ParsedRpc {
        operation:
            RpcOperation::GetConfig(GetConfigRequest { filter, .. })
            | RpcOperation::Get(GetRequest { filter, .. }),
        ..
    }) = &parsed
    {
        if let Some(Filter::Subtree(filter)) = filter {
            limits.check_paths(filter.selections().len())?;
        }
    }
    Ok(parsed)
}

fn scoped_attributes(
    start: &BytesStart<'_>,
    decoder: Decoder,
    limits: &MgmtLimits,
    parent: Option<&NamespaceScope>,
) -> Result<(NamespaceScope, Vec<(String, String)>), XmlError> {
    let mut scope = parent.cloned().unwrap_or_default();
    let mut attrs = Vec::new();
    let mut attr_count = 0usize;
    let mut ns_count = 0usize;

    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| XmlError::Malformed)?;
        attr_count += 1;
        let key = qname_bytes_to_str(attr.key.as_ref())?;
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|_| XmlError::Malformed)?
            .into_owned();
        limits.check_value_bytes(value.len())?;

        if key == "xmlns" {
            ns_count += 1;
            scope.default = Some(value);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            ns_count += 1;
            if prefix.is_empty() {
                return Err(XmlError::Malformed);
            }
            scope.bindings.insert(prefix.to_string(), value);
        } else {
            attrs.push((key.to_string(), value));
        }
    }

    if attr_count > limits.max_xml_attributes_per_element {
        return Err(LimitsError::Exceeded {
            limit: "xml_attributes_per_element",
            max: limits.max_xml_attributes_per_element,
            actual: attr_count,
        }
        .into());
    }
    if ns_count > limits.max_xml_namespace_decls {
        return Err(LimitsError::Exceeded {
            limit: "xml_namespace_decls",
            max: limits.max_xml_namespace_decls,
            actual: ns_count,
        }
        .into());
    }

    Ok((scope, attrs))
}

fn attr_value<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(attr_name, _)| attr_name == name)
        .map(|(_, value)| value.as_str())
}

fn filter_kind(attrs: &[(String, String)]) -> Result<FilterKind, XmlError> {
    match attr_value(attrs, "type").unwrap_or("subtree") {
        "subtree" => {
            if attrs.iter().any(|(name, _)| name != "type") {
                return Err(XmlError::InvalidFilterType);
            }
            Ok(FilterKind::Subtree)
        }
        "xpath" => {
            if attrs
                .iter()
                .any(|(name, _)| name != "type" && name != "select")
            {
                return Err(XmlError::InvalidFilterType);
            }
            Ok(FilterKind::XPath)
        }
        _ => Err(XmlError::InvalidFilterType),
    }
}

fn split_qname(raw: &[u8]) -> Result<(Option<&str>, &str), XmlError> {
    let name = qname_bytes_to_str(raw)?;
    if name.is_empty() {
        return Err(XmlError::Malformed);
    }
    if let Some((prefix, local)) = name.split_once(':') {
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return Err(XmlError::Malformed);
        }
        Ok((Some(prefix), local))
    } else {
        Ok((None, name))
    }
}

fn qname_bytes_to_str(raw: &[u8]) -> Result<&str, XmlError> {
    std::str::from_utf8(raw).map_err(|_| XmlError::Malformed)
}

fn resolve_namespace(prefix: Option<&str>, scope: &NamespaceScope) -> Result<String, XmlError> {
    match prefix {
        Some(prefix) => scope
            .bindings
            .get(prefix)
            .cloned()
            .ok_or(XmlError::UnknownNamespace),
        None => scope.default.clone().ok_or(XmlError::UnknownNamespace),
    }
}

fn finish_with_defaults(seen: bool, mode: Option<WithDefaultsMode>) -> Option<WithDefaultsMode> {
    if seen {
        Some(mode.unwrap_or(WithDefaultsMode::Unrecognized))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use opc_mgmt_errors::{NetconfErrorTag, NetconfErrorType};
    use opc_mgmt_limits::MgmtLimits;

    use super::*;

    fn rpc(body: &str) -> String {
        format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="101">{body}</rpc>"#)
    }

    #[test]
    fn parses_get_config_running_with_default_namespace() {
        let parsed = parse_rpc(
            &rpc("<get-config><source><running/></source></get-config>"),
            &MgmtLimits::default(),
        )
        .expect("parse rpc");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(
            parsed.operation,
            RpcOperation::GetConfig(GetConfigRequest {
                source: Datastore::Running,
                filter: None,
                with_defaults: None,
            })
        );
    }

    #[test]
    fn parses_get_with_optional_subtree_filter() {
        let parsed = parse_rpc(
            &rpc(r#"<get><filter><sys:system xmlns:sys="urn:opc:test"><sys:uptime/></sys:system></filter></get>"#),
            &MgmtLimits::default(),
        )
        .expect("parse get");
        assert_eq!(parsed.message_id, "101");
        let RpcOperation::Get(request) = parsed.operation else {
            panic!("expected get operation");
        };
        let Some(Filter::Subtree(filter)) = request.filter else {
            panic!("expected subtree filter");
        };
        assert_eq!(filter.selections().len(), 2);
        assert_eq!(filter.selections()[0].elements()[1].local, "uptime");
    }

    #[test]
    fn parses_get_config_with_defaults_parameter() {
        let parsed = parse_rpc(
            &rpc(&format!(
                r#"<get-config><source><running/></source><wd:with-defaults xmlns:wd="{WITH_DEFAULTS_NS}">trim</wd:with-defaults></get-config>"#
            )),
            &MgmtLimits::default(),
        )
        .expect("parse get-config with-defaults");

        assert_eq!(
            parsed.operation,
            RpcOperation::GetConfig(GetConfigRequest {
                source: Datastore::Running,
                filter: None,
                with_defaults: Some(WithDefaultsMode::Trim),
            })
        );
    }

    #[test]
    fn parses_get_with_defaults_parameter() {
        let parsed = parse_rpc(
            &rpc(&format!(
                r#"<get><with-defaults xmlns="{WITH_DEFAULTS_NS}">report-all-tagged</with-defaults></get>"#
            )),
            &MgmtLimits::default(),
        )
        .expect("parse get with-defaults");
        let RpcOperation::Get(request) = parsed.operation else {
            panic!("expected get operation");
        };
        assert_eq!(
            request.with_defaults,
            Some(WithDefaultsMode::ReportAllTagged)
        );
    }

    #[test]
    fn unrecognized_with_defaults_value_is_payload_free() {
        let parsed = parse_rpc(
            &rpc(&format!(
                r#"<get><with-defaults xmlns="{WITH_DEFAULTS_NS}">secret-mode</with-defaults></get>"#
            )),
            &MgmtLimits::default(),
        )
        .expect("parse get with unrecognized with-defaults");
        let RpcOperation::Get(request) = parsed.operation else {
            panic!("expected get operation");
        };
        assert_eq!(request.with_defaults, Some(WithDefaultsMode::Unrecognized));
    }

    #[test]
    fn duplicate_with_defaults_is_rejected() {
        let err = parse_rpc(
            &rpc(&format!(
                r#"<get><with-defaults xmlns="{WITH_DEFAULTS_NS}">trim</with-defaults><with-defaults xmlns="{WITH_DEFAULTS_NS}">explicit</with-defaults></get>"#
            )),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate with-defaults");
        assert_eq!(err, XmlError::DuplicateElement);
    }

    #[test]
    fn with_defaults_child_content_is_rejected() {
        let err = parse_rpc(
            &rpc(&format!(
                r#"<get><with-defaults xmlns="{WITH_DEFAULTS_NS}"><mode>trim</mode></with-defaults></get>"#
            )),
            &MgmtLimits::default(),
        )
        .expect_err("with-defaults child content");
        assert_eq!(err, XmlError::Malformed);
    }

    #[test]
    fn rejects_multiple_rpc_operations() {
        let err = parse_rpc(
            &rpc("<get/><get-config><source><running/></source></get-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("two operations");
        assert_eq!(err, XmlError::DuplicateElement);
    }

    #[test]
    fn parses_close_session() {
        let parsed = parse_rpc(&rpc("<close-session/>"), &MgmtLimits::default())
            .expect("parse close-session");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(parsed.operation, RpcOperation::CloseSession);
    }

    #[test]
    fn parses_get_schema_in_monitoring_namespace() {
        let parsed = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="501"><ncm:get-schema xmlns:ncm="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><ncm:identifier>demo-system</ncm:identifier><ncm:version>2026-06-13</ncm:version><ncm:format>yang</ncm:format></ncm:get-schema></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect("parse get-schema");

        assert_eq!(parsed.message_id, "501");
        assert_eq!(
            parsed.operation,
            RpcOperation::GetSchema(GetSchemaRequest {
                identifier: "demo-system".to_string(),
                version: Some("2026-06-13".to_string()),
                format: "yang".to_string(),
            })
        );
    }

    #[test]
    fn get_schema_defaults_format_to_yang() {
        let parsed = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="502"><get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>demo-system</identifier></get-schema></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect("parse get-schema");

        assert_eq!(
            parsed.operation,
            RpcOperation::GetSchema(GetSchemaRequest {
                identifier: "demo-system".to_string(),
                version: None,
                format: "yang".to_string(),
            })
        );
    }

    #[test]
    fn get_schema_rejects_missing_or_duplicate_identifier() {
        let missing = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="503"><get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("missing identifier");
        assert_eq!(missing, XmlError::MissingElement);

        let duplicate = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="504"><get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>a</identifier><identifier>b</identifier></get-schema></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("duplicate identifier");
        assert_eq!(duplicate, XmlError::DuplicateElement);
    }

    #[test]
    fn rejects_close_session_with_content() {
        let err = parse_rpc(
            &rpc("<close-session><extra/></close-session>"),
            &MgmtLimits::default(),
        )
        .expect_err("close-session content");
        assert_eq!(err, XmlError::Malformed);
    }

    #[test]
    fn parses_known_unsupported_base_operation_with_bounded_ignored_payload() {
        let parsed = parse_rpc(
            &rpc(
                r#"<edit-config><target><running/></target><config><sys:secret xmlns:sys="urn:opc:test">do-not-leak</sys:secret></config></edit-config>"#,
            ),
            &MgmtLimits::default(),
        )
        .expect("parse unsupported edit-config");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(
            parsed.operation,
            RpcOperation::Unsupported(UnsupportedOperation::EditConfig)
        );
    }

    #[test]
    fn duplicate_known_unsupported_operation_is_rejected() {
        let err = parse_rpc(&rpc("<edit-config/><get/>"), &MgmtLimits::default())
            .expect_err("duplicate operation");
        assert_eq!(err, XmlError::DuplicateElement);
    }

    #[test]
    fn parses_prefixed_netconf_namespace() {
        let xml = format!(
            r#"<nc:rpc xmlns:nc="{NETCONF_BASE_NS}" message-id="7"><nc:get-config><nc:source><nc:running/></nc:source></nc:get-config></nc:rpc>"#
        );
        let parsed = parse_rpc(&xml, &MgmtLimits::default()).expect("parse rpc");
        assert_eq!(parsed.message_id, "7");
    }

    #[test]
    fn parses_client_hello_capabilities() {
        let xml = format!(
            r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{}</capability></capabilities></hello>"#,
            crate::capabilities::NETCONF_BASE_1_1
        );
        let hello = parse_client_hello(&xml, &MgmtLimits::default()).expect("parse hello");
        assert_eq!(hello.capabilities, [crate::capabilities::NETCONF_BASE_1_1]);
    }

    #[test]
    fn rejects_missing_namespace() {
        let err = parse_rpc(
            r#"<rpc message-id="101"><get-config><source><running/></source></get-config></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("namespace required");
        assert_eq!(err, XmlError::UnknownNamespace);
    }

    #[test]
    fn rejects_dtd_and_entities() {
        let dtd = format!(
            r#"<!DOCTYPE rpc [ <!ENTITY x "boom"> ]><rpc xmlns="{NETCONF_BASE_NS}" message-id="1"><get-config><source><running/></source></get-config></rpc>"#
        );
        assert_eq!(
            parse_rpc(&dtd, &MgmtLimits::default()).expect_err("dtd"),
            XmlError::DtdForbidden
        );

        let entity =
            rpc("<get-config><source><running/></source><filter>&x;</filter></get-config>");
        assert_eq!(
            parse_rpc(&entity, &MgmtLimits::default()).expect_err("entity"),
            XmlError::EntityForbidden
        );
    }

    #[test]
    fn enforces_depth_limit() {
        let limits = MgmtLimits {
            max_xml_depth: 3,
            ..MgmtLimits::default()
        };
        let err = parse_rpc(
            &rpc("<get-config><source><running/></source></get-config>"),
            &limits,
        )
        .expect_err("too deep");
        assert!(matches!(err, XmlError::Limit(_)));
    }

    #[test]
    fn parses_structural_subtree_filters() {
        let parsed = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="subtree"><sys:system xmlns:sys="urn:opc:test"><sys:hostname/></sys:system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect("parse");
        let RpcOperation::GetConfig(request) = parsed.operation else {
            panic!("expected get-config operation");
        };
        assert_eq!(request.source, Datastore::Running);
        let Some(Filter::Subtree(filter)) = request.filter else {
            panic!("expected subtree filter");
        };
        assert_eq!(filter.selections().len(), 2);
        assert_eq!(filter.selections()[0].elements()[0].local, "system");
        assert_eq!(filter.selections()[0].elements()[1].local, "hostname");
        assert!(filter.selections()[0].include_descendants());
        assert!(!filter.selections()[1].include_descendants());
    }

    #[test]
    fn parses_subtree_filter_namespace_wildcard() {
        let parsed = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="subtree"><system xmlns=""><hostname/></system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect("parse wildcard filter");
        let RpcOperation::GetConfig(request) = parsed.operation else {
            panic!("expected get-config operation");
        };
        let Some(Filter::Subtree(filter)) = request.filter else {
            panic!("expected subtree filter");
        };
        assert_eq!(filter.selections().len(), 2);
        assert_eq!(filter.selections()[0].elements()[0].namespace, "");
        assert_eq!(filter.selections()[0].elements()[1].namespace, "");
    }

    #[test]
    fn rejects_subtree_filter_content_match_until_supported() {
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-1</sys:hostname></sys:system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("content match not supported yet");
        assert_eq!(err, XmlError::UnsupportedFilterContent);
    }

    #[test]
    fn rejects_subtree_filter_attribute_match_until_supported() {
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test" name="amf-1"/></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("attribute match not supported yet");
        assert_eq!(err, XmlError::UnsupportedFilterContent);
    }

    #[test]
    fn maps_errors_to_netconf_classifications() {
        let nc = XmlError::DtdForbidden.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Rpc);
        assert_eq!(nc.tag, NetconfErrorTag::MalformedMessage);

        let nc = XmlError::UnknownNamespace.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Protocol);
        assert_eq!(nc.tag, NetconfErrorTag::UnknownNamespace);
    }
}
