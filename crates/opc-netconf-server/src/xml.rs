//! Bounded NETCONF XML envelope parsing.

use std::collections::{BTreeMap, BTreeSet};

use opc_mgmt_errors::{NetconfError, NetconfErrorTag, NetconfErrorType};
use opc_mgmt_limits::{LimitsError, MgmtLimits};
use quick_xml::encoding::Decoder;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use quick_xml::XmlVersion;
use thiserror::Error;

use crate::capabilities::{
    IETF_DATASTORES_NS, NETCONF_BASE_NS, NETCONF_MONITORING_NS, NETCONF_NMDA_NS,
    NETCONF_NOTIFICATION_NS, WITH_DEFAULTS_NS,
};
use crate::error::RpcReplyAttributes;
use crate::session_registry::is_valid_session_id;

const XML_NAMESPACE_URI: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE_URI: &str = "http://www.w3.org/2000/xmlns/";

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
    /// Extra request `<rpc>` attributes that must be copied onto `<rpc-reply>`.
    pub(crate) reply_attrs: RpcReplyAttributes,
}

/// RPC parse failure plus any message-id already validated from the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpcParseError {
    /// Parsed RFC 6241 message id, when the root RPC envelope was valid enough
    /// to read it before the error occurred.
    pub message_id: Option<String>,
    /// Extra request `<rpc>` attributes parsed before this failure.
    pub reply_attrs: RpcReplyAttributes,
    /// Recognized RPC operation context at the point parsing failed.
    pub operation_hint: Option<RpcOperationHint>,
    /// Payload-free parse error.
    pub error: XmlError,
}

impl RpcParseError {
    fn new(message_id: Option<String>, error: XmlError) -> Self {
        Self::with_context(message_id, RpcReplyAttributes::default(), None, error)
    }

    fn with_context(
        message_id: Option<String>,
        reply_attrs: RpcReplyAttributes,
        operation_hint: Option<RpcOperationHint>,
        error: XmlError,
    ) -> Self {
        Self {
            message_id,
            reply_attrs,
            operation_hint,
            error,
        }
    }

    fn without_message_id(error: XmlError) -> Self {
        Self::new(None, error)
    }
}

/// RPC operation context available before the full RPC can be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcOperationHint {
    /// Base NETCONF `<edit-config>`.
    EditConfig,
    /// RFC 8526 `<edit-data>`.
    EditData,
    /// Base NETCONF `<commit>`.
    Commit,
    /// Base NETCONF `<cancel-commit>`.
    CancelCommit,
    /// Base NETCONF `<discard-changes>`.
    DiscardChanges,
    /// Base NETCONF `<copy-config>`.
    CopyConfig,
    /// Base NETCONF `<delete-config>`.
    DeleteConfig,
    /// Base NETCONF `<get>`.
    Get,
    /// Base NETCONF `<get-config>`.
    GetConfig,
    /// RFC 8526 `<get-data>`.
    GetData,
    /// Base NETCONF `<lock>`.
    Lock,
    /// Base NETCONF `<unlock>`.
    Unlock,
    /// Base NETCONF `<validate>`.
    Validate,
    /// Base NETCONF `<kill-session>`.
    KillSession,
    /// RFC 5277 `<create-subscription>`.
    CreateSubscription,
}

/// Supported parsed RPC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcOperation {
    /// `<edit-config>`.
    EditConfig(EditConfigRequest),
    /// RFC 8526 `<edit-data>`.
    EditData(EditDataRequest),
    /// `<get-config>`.
    GetConfig(GetConfigRequest),
    /// `<get>`.
    Get(GetRequest),
    /// RFC 8526 `<get-data>`.
    GetData(GetDataRequest),
    /// `<close-session>`.
    CloseSession,
    /// `<lock>`.
    Lock(LockRequest),
    /// `<unlock>`.
    Unlock(UnlockRequest),
    /// `<validate>`.
    Validate(ValidateRequest),
    /// `<commit>`.
    Commit(CommitRequest),
    /// `<cancel-commit>`.
    CancelCommit(CancelCommitRequest),
    /// `<discard-changes>`.
    DiscardChanges,
    /// `<copy-config>`.
    CopyConfig(CopyConfigRequest),
    /// `<delete-config>`.
    DeleteConfig(DeleteConfigRequest),
    /// `<kill-session>`.
    KillSession(KillSessionRequest),
    /// RFC 6022 `<get-schema>`.
    GetSchema(GetSchemaRequest),
    /// RFC 5277 `<create-subscription>`.
    CreateSubscription(CreateSubscriptionRequest),
    /// A known NETCONF operation that this read-only slice deliberately does
    /// not implement yet.
    Unsupported(UnsupportedOperation),
}

/// RFC 5277 `<create-subscription>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSubscriptionRequest {
    /// Optional stream name. Omitted means the default `NETCONF` stream.
    pub stream: Option<String>,
    /// Whether a notification filter element was supplied.
    pub filter_present: bool,
    /// Optional replay start time. Unsupported until replay storage exists.
    pub start_time: Option<String>,
    /// Optional replay stop time. Unsupported until replay storage exists.
    pub stop_time: Option<String>,
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

/// RFC 6241 `<kill-session>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSessionRequest {
    /// Target NETCONF session id.
    pub session_id: u64,
}

/// RFC 6241 `<lock>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRequest {
    /// Target datastore.
    pub target: Datastore,
}

/// RFC 6241 `<unlock>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockRequest {
    /// Target datastore.
    pub target: Datastore,
}

/// RFC 6241 `<validate>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateRequest {
    /// Source datastore.
    pub source: Datastore,
}

/// RFC 6241 `<commit>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequest {
    /// Whether this is a confirmed commit.
    pub confirmed: bool,
    /// Confirmed commit timeout in seconds.
    pub confirm_timeout: Option<u32>,
    /// Persistent confirmed commit token for the new pending commit.
    pub persist: Option<String>,
    /// Token used to confirm or update an existing persistent confirmed commit.
    pub persist_id: Option<String>,
}

impl CommitRequest {
    /// Returns true for the plain `<commit/>` form.
    pub const fn is_plain(&self) -> bool {
        !self.confirmed
            && self.confirm_timeout.is_none()
            && self.persist.is_none()
            && self.persist_id.is_none()
    }
}

/// RFC 6241 `<cancel-commit>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelCommitRequest {
    /// Token used to cancel a persistent confirmed commit.
    pub persist_id: Option<String>,
}

/// RFC 6241 `<copy-config>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyConfigRequest {
    /// Target datastore.
    pub target: Datastore,
    /// Source datastore.
    pub source: Datastore,
}

/// RFC 6241 `<delete-config>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteConfigRequest {
    /// Target datastore.
    pub target: Datastore,
}

/// Known NETCONF operations that are parsed only to reject safely with the
/// request `message-id` preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedOperation {
    /// `<edit-config>`.
    EditConfig,
    /// RFC 8526 `<edit-data>`.
    EditData,
    /// `<copy-config>`.
    CopyConfig,
    /// `<delete-config>`.
    DeleteConfig,
    /// `<lock>`.
    Lock,
    /// `<unlock>`.
    Unlock,
    /// `<commit>`.
    Commit,
    /// `<cancel-commit>`.
    CancelCommit,
    /// `<discard-changes>`.
    DiscardChanges,
    /// `<validate>`.
    Validate,
    /// RFC 5277 `<create-subscription>`.
    CreateSubscription,
}

impl UnsupportedOperation {
    /// XML local name for this operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EditConfig => "edit-config",
            Self::EditData => "edit-data",
            Self::CopyConfig => "copy-config",
            Self::DeleteConfig => "delete-config",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Commit => "commit",
            Self::CancelCommit => "cancel-commit",
            Self::DiscardChanges => "discard-changes",
            Self::Validate => "validate",
            Self::CreateSubscription => "create-subscription",
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

/// RFC 8526 `<get-data>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDataRequest {
    /// NMDA datastore identity.
    pub datastore: NmdaDatastore,
    /// Optional subtree or bounded XPath filter.
    pub filter: Option<Filter>,
    /// Optional RFC 8526 config-filter.
    pub config_filter: Option<bool>,
    /// Whether an origin filter leaf was supplied.
    pub origin_filter_present: bool,
    /// Whether a non-default max-depth value was supplied.
    pub max_depth_limited: bool,
    /// Whether `<with-origin/>` was supplied.
    pub with_origin: bool,
    /// RFC 6243 `<with-defaults>` parameter.
    pub with_defaults: Option<WithDefaultsMode>,
}

/// `<edit-config>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditConfigRequest {
    /// Requested target datastore.
    pub target: Datastore,
    /// RFC 6241 default operation.
    pub default_operation: EditDefaultOperation,
    /// RFC 6241 test option.
    pub test_option: EditTestOption,
    /// Whether the client explicitly supplied `<test-option>`.
    ///
    /// RFC 6241 gates this leaf behind `:validate:1.1`. The parser records
    /// presence separately so the server can reject explicit use while
    /// `:validate` remains unadvertised.
    pub test_option_explicit: bool,
    /// RFC 6241 error option.
    pub error_option: EditErrorOption,
    /// Namespace-preserving XML for the complete `<config>` element. The
    /// generic server treats this as opaque; the CNF binding translates the
    /// bounded element payload into a full candidate config.
    pub config_xml: String,
}

/// RFC 8526 `<edit-data>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditDataRequest {
    /// Requested NMDA datastore identity.
    pub datastore: NmdaDatastore,
    /// RFC 6241-compatible default operation carried by RFC 8526.
    pub default_operation: EditDefaultOperation,
    /// Namespace-preserving XML for the complete NMDA `<config>` element when
    /// inline config input was supplied.
    pub config_xml: Option<String>,
    /// Whether the RFC 8526 `<url>` input branch was supplied.
    ///
    /// The server currently rejects URL edits at the operation boundary without
    /// retaining the client-supplied URL value.
    pub url_present: bool,
}

/// RFC 6241 `<default-operation>` value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EditDefaultOperation {
    /// `merge` (RFC default).
    #[default]
    Merge,
    /// `replace`.
    Replace,
    /// `none`.
    None,
}

impl EditDefaultOperation {
    fn parse(value: &str) -> Result<Self, XmlError> {
        match value.trim() {
            "merge" => Ok(Self::Merge),
            "replace" => Ok(Self::Replace),
            "none" => Ok(Self::None),
            _ => Err(XmlError::InvalidValue),
        }
    }
}

/// RFC 6241 `<test-option>` value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EditTestOption {
    /// `test-then-set` (RFC default when `:validate` is supported).
    #[default]
    TestThenSet,
    /// `set`.
    Set,
    /// `test-only`.
    TestOnly,
}

impl EditTestOption {
    fn parse(value: &str) -> Result<Self, XmlError> {
        match value.trim() {
            "test-then-set" => Ok(Self::TestThenSet),
            "set" => Ok(Self::Set),
            "test-only" => Ok(Self::TestOnly),
            _ => Err(XmlError::InvalidValue),
        }
    }
}

/// RFC 6241 `<error-option>` value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EditErrorOption {
    /// `stop-on-error` (RFC default).
    #[default]
    StopOnError,
    /// `continue-on-error`.
    ContinueOnError,
    /// `rollback-on-error`.
    RollbackOnError,
}

impl EditErrorOption {
    fn parse(value: &str) -> Result<Self, XmlError> {
        match value.trim() {
            "stop-on-error" => Ok(Self::StopOnError),
            "continue-on-error" => Ok(Self::ContinueOnError),
            "rollback-on-error" => Ok(Self::RollbackOnError),
            _ => Err(XmlError::InvalidValue),
        }
    }
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

/// RFC 8526 NMDA datastore identities recognized by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmdaDatastore {
    /// `ds:running`.
    Running,
    /// `ds:candidate`.
    Candidate,
    /// `ds:startup`.
    Startup,
    /// `ds:intended`.
    Intended,
    /// `ds:operational`.
    Operational,
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
    /// XPath filter.
    XPath(XPathFilter),
}

/// Parsed XPath filter envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPathFilter {
    select: String,
    namespaces: BTreeMap<String, String>,
}

impl XPathFilter {
    /// Builds a parsed XPath filter.
    pub(crate) fn new(select: String, namespaces: BTreeMap<String, String>) -> Self {
        Self { select, namespaces }
    }

    /// The bounded, non-empty `select` expression.
    pub fn select(&self) -> &str {
        &self.select
    }

    /// Prefix bindings visible on the `<filter>` element. The default XML
    /// namespace is intentionally absent because XPath 1.0 does not apply it to
    /// unprefixed element names.
    pub fn namespaces(&self) -> &BTreeMap<String, String> {
        &self.namespaces
    }
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
    /// A protocol value failed validation.
    #[error("NETCONF RPC value is invalid")]
    InvalidValue,
    /// A filter type is not valid for this server core.
    #[error("NETCONF filter type is invalid")]
    InvalidFilterType,
    /// The subtree filter used a form this slice does not implement.
    #[error("NETCONF subtree filter content is not supported")]
    UnsupportedFilterContent,
    /// A subtree filter content-match node (leaf text value) was present.
    #[error("NETCONF subtree filter content-match is not supported")]
    SubtreeFilterContentMatchNotSupported,
    /// A subtree filter attribute-match node (element attribute) was present.
    #[error("NETCONF subtree filter attribute-match is not supported")]
    SubtreeFilterAttributeMatchNotSupported,
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
            Self::SubtreeFilterContentMatchNotSupported
            | Self::SubtreeFilterAttributeMatchNotSupported => {
                NetconfError::new(Ty::Protocol, Tag::OperationNotSupported)
            }
            Self::InvalidValue => NetconfError::new(Ty::Application, Tag::InvalidValue),
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
            Self::InvalidValue => "invalid value",
            Self::InvalidFilterType => "invalid filter type",
            Self::UnsupportedFilterContent => "unsupported filter content",
            Self::SubtreeFilterContentMatchNotSupported => {
                "subtree filter content-match not supported"
            }
            Self::SubtreeFilterAttributeMatchNotSupported => {
                "subtree filter attribute-match not supported"
            }
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
    /// True when this node is a content-match or attribute-match expression that
    /// this server does not implement. Children are parsed (for bounds checking)
    /// but do not become selections.
    suppress_subtree: bool,
}

#[derive(Debug, Clone, Default)]
struct NamespaceScope {
    default: Option<String>,
    bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct ScopedAttributes {
    scope: NamespaceScope,
    attrs: Vec<(String, String)>,
    reply_attrs: Vec<(String, String)>,
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
struct PartialGetData {
    datastore_seen: bool,
    datastore: Option<NmdaDatastore>,
    filter: Option<Filter>,
    xpath_filter_seen: bool,
    xpath_filter_namespaces: BTreeMap<String, String>,
    xpath_filter: Option<String>,
    config_filter_seen: bool,
    config_filter: Option<bool>,
    origin_filter_present: bool,
    max_depth_seen: bool,
    max_depth_limited: bool,
    with_origin: bool,
    with_defaults_seen: bool,
    with_defaults: Option<WithDefaultsMode>,
}

#[derive(Debug, Clone, Default)]
struct PartialEditConfig {
    target: Option<Datastore>,
    default_operation_seen: bool,
    default_operation: Option<EditDefaultOperation>,
    test_option_seen: bool,
    test_option: Option<EditTestOption>,
    error_option_seen: bool,
    error_option: Option<EditErrorOption>,
    config_xml: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PartialEditData {
    datastore_seen: bool,
    datastore: Option<NmdaDatastore>,
    default_operation_seen: bool,
    default_operation: Option<EditDefaultOperation>,
    config_xml: Option<String>,
    url_seen: bool,
}

#[derive(Debug, Clone, Default)]
struct PartialGetSchema {
    identifier: Option<String>,
    version: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PartialCreateSubscription {
    stream_seen: bool,
    stream: Option<String>,
    filter_seen: bool,
    start_time_seen: bool,
    start_time: Option<String>,
    stop_time_seen: bool,
    stop_time: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PartialKillSession {
    session_id: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct PartialLock {
    target: Option<Datastore>,
}

#[derive(Debug, Clone, Default)]
struct PartialUnlock {
    target: Option<Datastore>,
}

#[derive(Debug, Clone, Default)]
struct PartialValidate {
    source: Option<Datastore>,
}

#[derive(Debug, Clone, Default)]
struct PartialCommit {
    confirmed: bool,
    confirm_timeout_seen: bool,
    confirm_timeout: Option<u32>,
    persist_seen: bool,
    persist: Option<String>,
    persist_id_seen: bool,
    persist_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PartialCancelCommit {
    persist_id_seen: bool,
    persist_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PartialCopyConfig {
    target: Option<Datastore>,
    source: Option<Datastore>,
}

#[derive(Debug, Clone, Default)]
struct PartialDeleteConfig {
    target: Option<Datastore>,
}

#[derive(Debug, Clone, Copy)]
enum GetSchemaField {
    Identifier,
    Version,
    Format,
}

#[derive(Default)]
struct ParserState {
    root: Option<RootKind>,
    stack: Vec<Element>,
    scopes: Vec<NamespaceScope>,
    message_id: Option<String>,
    reply_attrs: RpcReplyAttributes,
    capabilities: Vec<String>,
    hello_capabilities_seen: bool,
    edit_config: Option<PartialEditConfig>,
    edit_data: Option<PartialEditData>,
    get: Option<PartialGet>,
    get_config: Option<PartialGetConfig>,
    get_data: Option<PartialGetData>,
    get_schema: Option<PartialGetSchema>,
    create_subscription: Option<PartialCreateSubscription>,
    kill_session: Option<PartialKillSession>,
    lock: Option<PartialLock>,
    unlock: Option<PartialUnlock>,
    validate: Option<PartialValidate>,
    commit: Option<PartialCommit>,
    cancel_commit: Option<PartialCancelCommit>,
    copy_config: Option<PartialCopyConfig>,
    delete_config: Option<PartialDeleteConfig>,
    operation_hint: Option<RpcOperationHint>,
    close_session: bool,
    discard_changes: bool,
    filter_depth: usize,
    notification_filter_depth: usize,
    filter_stack: Vec<FilterFrame>,
    edit_config_capture: Option<Writer<Vec<u8>>>,
    edit_config_capture_depth: usize,
    root_closed: bool,
    xml_decl_seen: bool,
    pre_decl_misc_seen: bool,
    limits: MgmtLimits,
    filter_content_match_count: usize,
    filter_attribute_match_count: usize,
    filter_unsupported_subtree_error: Option<XmlError>,
}

impl ParserState {
    fn new(limits: MgmtLimits) -> Self {
        Self {
            scopes: vec![NamespaceScope::default()],
            limits,
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

        let scoped = scoped_attributes(start, decoder, limits, self.scopes.last())?;
        let raw_name = start.name();
        let (prefix, local) = split_qname(raw_name.as_ref())?;
        self.note_rpc_operation_hint(local);
        let namespace = resolve_namespace(prefix, &scoped.scope)?;
        let element = Element {
            local: local.to_string(),
            namespace,
        };

        limits.check_depth(self.stack.len() + 1)?;
        let capture_root =
            self.edit_config_capture.is_none() && self.is_edit_config_config_start(&element);
        let capture_start = self.edit_config_capture.is_some() || capture_root;
        self.validate_protocol_namespace(&element)?;
        self.process_start(&element, &scoped.attrs, &scoped.reply_attrs, &scoped.scope)?;
        if capture_start {
            if capture_root {
                self.capture_config_root_start(start, &scoped.scope)?;
            } else {
                self.capture_event(Event::Start(start.borrow()))?;
            }
            self.edit_config_capture_depth = self.edit_config_capture_depth.saturating_add(1);
        }
        self.stack.push(element);
        self.scopes.push(scoped.scope);
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
        let closing_config_capture_root = self.local_path_is(&["rpc", "edit-config", "config"])
            || self.local_path_is(&["rpc", "edit-data", "config"]);
        let Some(current) = self.stack.pop() else {
            return Err(XmlError::Malformed);
        };
        if current.local != local || current.namespace != namespace {
            return Err(XmlError::Malformed);
        }
        if self.edit_config_capture.is_some() {
            self.capture_event(Event::End(BytesEnd::from(QName(raw_name))))?;
            self.edit_config_capture_depth = self
                .edit_config_capture_depth
                .checked_sub(1)
                .ok_or(XmlError::Malformed)?;
            if closing_config_capture_root {
                if self.edit_config_capture_depth != 0 {
                    return Err(XmlError::Malformed);
                }
                self.finish_edit_config_capture()?;
            }
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
        if self.notification_filter_depth > 0 {
            self.notification_filter_depth -= 1;
        }
        if self.stack.is_empty() {
            self.root_closed = true;
        }
        Ok(())
    }

    fn reject_filter_text(&mut self) -> Result<(), XmlError> {
        if !matches!(self.active_filter(), Some(Filter::Subtree(_))) {
            return Err(XmlError::UnsupportedFilterContent);
        }
        if let Some(frame) = self.filter_stack.last() {
            if frame.suppress_subtree {
                // Text inside an already-suppressed attribute-match/content-match
                // subtree is ignored; the unsupported form was already counted.
                return Ok(());
            }
        }
        self.filter_content_match_count += 1;
        self.limits
            .check_subtree_filter_content_match_nodes(self.filter_content_match_count)?;
        if let Some(frame) = self.filter_stack.last_mut() {
            frame.suppress_subtree = true;
        }
        self.filter_unsupported_subtree_error =
            Some(XmlError::SubtreeFilterContentMatchNotSupported);
        Ok(())
    }

    fn record_filter_attribute_match(&mut self) -> Result<(), XmlError> {
        self.filter_attribute_match_count += 1;
        self.limits
            .check_subtree_filter_attribute_match_nodes(self.filter_attribute_match_count)?;
        self.filter_unsupported_subtree_error =
            Some(XmlError::SubtreeFilterAttributeMatchNotSupported);
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), XmlError> {
        if self.root.is_none() && self.stack.is_empty() && !self.root_closed {
            if text.trim().is_empty() {
                if !self.xml_decl_seen {
                    self.pre_decl_misc_seen = true;
                }
                return Ok(());
            }
            return Err(XmlError::Malformed);
        }

        if self.filter_depth > 0 {
            if text.trim().is_empty() {
                return Ok(());
            }
            return self.reject_filter_text();
        }
        if self.notification_filter_depth > 0 {
            return Ok(());
        }
        if self.local_path_is(&["hello", "capabilities", "capability"]) {
            let capability = text.trim();
            if !capability.is_empty() {
                self.capabilities.push(capability.to_string());
            }
        } else if self.local_path_is(&["rpc", "get-schema", "identifier"]) {
            self.set_get_schema_text(GetSchemaField::Identifier, text)?;
        } else if self.local_path_is(&["rpc", "get-schema", "version"]) {
            self.set_get_schema_text(GetSchemaField::Version, text)?;
        } else if self.local_path_is(&["rpc", "get-schema", "format"]) {
            self.set_get_schema_text(GetSchemaField::Format, text)?;
        } else if self.local_path_is(&["rpc", "kill-session", "session-id"]) {
            self.set_kill_session_id(text)?;
        } else if self.local_path_is(&["rpc", "commit", "confirm-timeout"]) {
            self.set_commit_confirm_timeout_text(text)?;
        } else if self.local_path_is(&["rpc", "commit", "persist"]) {
            self.set_commit_persist_text(text)?;
        } else if self.local_path_is(&["rpc", "commit", "persist-id"]) {
            self.set_commit_persist_id_text(text)?;
        } else if self.local_path_is(&["rpc", "cancel-commit", "persist-id"]) {
            self.set_cancel_commit_persist_id_text(text)?;
        } else if self.local_path_is(&["rpc", "create-subscription", "stream"]) {
            self.set_create_subscription_stream_text(text)?;
        } else if self.local_path_is(&["rpc", "create-subscription", "startTime"]) {
            self.set_create_subscription_start_time_text(text)?;
        } else if self.local_path_is(&["rpc", "create-subscription", "stopTime"]) {
            self.set_create_subscription_stop_time_text(text)?;
        } else if self.local_path_is(&["rpc", "get", "with-defaults"]) {
            self.set_get_with_defaults_text(text)?;
        } else if self.local_path_is(&["rpc", "get-config", "with-defaults"]) {
            self.set_get_config_with_defaults_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "datastore"]) {
            self.set_get_data_datastore_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "xpath-filter"]) {
            self.set_get_data_xpath_filter_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "config-filter"]) {
            self.set_get_data_config_filter_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "origin-filter"])
            || self.local_path_is(&["rpc", "get-data", "negated-origin-filter"])
        {
            self.set_get_data_origin_filter_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "max-depth"]) {
            self.set_get_data_max_depth_text(text)?;
        } else if self.local_path_is(&["rpc", "get-data", "with-defaults"]) {
            self.set_get_data_with_defaults_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-data", "datastore"]) {
            self.set_edit_data_datastore_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-data", "default-operation"]) {
            self.set_edit_data_default_operation_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-data", "url"]) {
            self.set_edit_data_url_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-config", "default-operation"]) {
            self.set_edit_default_operation_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-config", "test-option"]) {
            self.set_edit_test_option_text(text)?;
        } else if self.local_path_is(&["rpc", "edit-config", "error-option"]) {
            self.set_edit_error_option_text(text)?;
        } else if text.trim().is_empty() {
            return Ok(());
        } else {
            return Err(XmlError::Malformed);
        }
        Ok(())
    }

    fn xml_decl(&mut self) -> Result<(), XmlError> {
        if self.xml_decl_seen
            || self.pre_decl_misc_seen
            || self.root.is_some()
            || self.root_closed
            || !self.stack.is_empty()
        {
            return Err(XmlError::Malformed);
        }
        self.xml_decl_seen = true;
        Ok(())
    }

    fn comment(&mut self) {
        if !self.xml_decl_seen && self.root.is_none() && !self.root_closed && self.stack.is_empty()
        {
            self.pre_decl_misc_seen = true;
        }
    }

    fn validate_protocol_namespace(&self, element: &Element) -> Result<(), XmlError> {
        if self.filter_depth > 0
            || self.notification_filter_depth > 0
            || self.edit_config_capture.is_some()
        {
            return Ok(());
        }
        if element.namespace == NETCONF_BASE_NS
            || self.get_schema_namespace_is_allowed(element)
            || self.with_defaults_namespace_is_allowed(element)
            || self.nmda_namespace_is_allowed(element)
            || self.notification_namespace_is_allowed(element)
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
        reply_attrs: &[(String, String)],
        scope: &NamespaceScope,
    ) -> Result<(), XmlError> {
        if self.filter_depth > 0 {
            self.process_filter_content_start(element, attrs)?;
            self.filter_depth += 1;
            return Ok(());
        }

        if self.notification_filter_depth > 0 {
            self.notification_filter_depth += 1;
            return Ok(());
        }

        if self.edit_config_capture.is_some() {
            return Ok(());
        }

        if self.stack.is_empty() {
            self.root = match element.local.as_str() {
                "hello" => Some(RootKind::Hello),
                "rpc" => {
                    self.message_id = attr_value(attrs, "message-id").map(ToOwned::to_owned);
                    self.reply_attrs = RpcReplyAttributes::from_pairs(rpc_reply_attrs(reply_attrs));
                    Some(RootKind::Rpc)
                }
                _ => return Err(XmlError::UnsupportedOperation),
            };
            return Ok(());
        }

        match self.root {
            Some(RootKind::Hello) => self.process_hello_start(element),
            Some(RootKind::Rpc) => self.process_rpc_start(element, attrs, scope),
            None => Err(XmlError::Malformed),
        }
    }

    fn process_hello_start(&mut self, element: &Element) -> Result<(), XmlError> {
        if self.local_path_is(&["hello"]) && element.local == "capabilities" {
            if self.hello_capabilities_seen {
                return Err(XmlError::DuplicateElement);
            }
            self.hello_capabilities_seen = true;
            Ok(())
        } else if self.local_path_is(&["hello", "capabilities"]) && element.local == "capability" {
            Ok(())
        } else {
            Err(XmlError::Malformed)
        }
    }

    fn process_rpc_start(
        &mut self,
        element: &Element,
        attrs: &[(String, String)],
        scope: &NamespaceScope,
    ) -> Result<(), XmlError> {
        if self.local_path_is(&["rpc"]) {
            match element.local.as_str() {
                "get" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::Get);
                    self.get = Some(PartialGet::default());
                }
                "get-config" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::GetConfig);
                    self.get_config = Some(PartialGetConfig::default());
                }
                "get-data" if element.namespace == NETCONF_NMDA_NS => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::GetData);
                    self.get_data = Some(PartialGetData::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "edit-data" if element.namespace == NETCONF_NMDA_NS => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::EditData);
                    self.edit_data = Some(PartialEditData::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "edit-config" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::EditConfig);
                    self.edit_config = Some(PartialEditConfig::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "close-session" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.close_session = true;
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "lock" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::Lock);
                    self.lock = Some(PartialLock::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "unlock" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::Unlock);
                    self.unlock = Some(PartialUnlock::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "validate" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::Validate);
                    self.validate = Some(PartialValidate::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "get-schema" if element.namespace == NETCONF_MONITORING_NS => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.get_schema = Some(PartialGetSchema::default());
                }
                "create-subscription" if element.namespace == NETCONF_NOTIFICATION_NS => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::CreateSubscription);
                    self.create_subscription = Some(PartialCreateSubscription::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "copy-config" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::CopyConfig);
                    self.copy_config = Some(PartialCopyConfig::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "delete-config" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::DeleteConfig);
                    self.delete_config = Some(PartialDeleteConfig::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "kill-session" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.kill_session = Some(PartialKillSession::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "commit" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::Commit);
                    self.commit = Some(PartialCommit::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "cancel-commit" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::CancelCommit);
                    self.cancel_commit = Some(PartialCancelCommit::default());
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                "discard-changes" => {
                    if self.has_rpc_operation() {
                        return Err(XmlError::DuplicateElement);
                    }
                    self.operation_hint = Some(RpcOperationHint::DiscardChanges);
                    self.discard_changes = true;
                    if !attrs.is_empty() {
                        return Err(XmlError::Malformed);
                    }
                }
                _ => return Err(XmlError::UnsupportedOperation),
            }
            return Ok(());
        }

        if self.local_path_is(&["rpc", "get"]) {
            match element.local.as_str() {
                "filter" if element.namespace == NETCONF_BASE_NS => {
                    self.install_filter(attrs, scope)
                }
                "with-defaults" if element.namespace == WITH_DEFAULTS_NS => {
                    self.install_get_with_defaults(attrs)
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-config"]) {
            match element.local.as_str() {
                "source" if element.namespace == NETCONF_BASE_NS => Ok(()),
                "filter" if element.namespace == NETCONF_BASE_NS => {
                    self.install_filter(attrs, scope)
                }
                "with-defaults" if element.namespace == WITH_DEFAULTS_NS => {
                    self.install_get_config_with_defaults(attrs)
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-data"]) {
            match element.local.as_str() {
                "datastore"
                | "config-filter"
                | "origin-filter"
                | "negated-origin-filter"
                | "max-depth"
                    if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() =>
                {
                    self.install_get_data_scalar(element.local.as_str())
                }
                "with-origin" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_get_data_with_origin()
                }
                "subtree-filter" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_get_data_subtree_filter()
                }
                "xpath-filter" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_get_data_xpath_filter(scope)
                }
                "with-defaults" if element.namespace == WITH_DEFAULTS_NS => {
                    self.install_get_data_with_defaults(attrs)
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "edit-data"]) {
            match element.local.as_str() {
                "datastore" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_edit_data_datastore()
                }
                "default-operation" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_edit_data_default_operation()
                }
                "config" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_edit_data_config_capture()
                }
                "url" if element.namespace == NETCONF_NMDA_NS && attrs.is_empty() => {
                    self.install_edit_data_url()
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "edit-config"]) {
            match element.local.as_str() {
                "target" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => Ok(()),
                "default-operation" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    self.install_edit_default_operation()
                }
                "test-option" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    self.install_edit_test_option()
                }
                "error-option" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    self.install_edit_error_option()
                }
                "config" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    self.install_edit_config_capture()
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "close-session"])
            || self.local_path_is(&["rpc", "discard-changes"])
        {
            Err(XmlError::Malformed)
        } else if self.local_path_is(&["rpc", "commit"]) {
            match element.local.as_str() {
                "confirmed" | "confirm-timeout" | "persist" | "persist-id"
                    if element.namespace == NETCONF_BASE_NS && attrs.is_empty() =>
                {
                    self.install_commit_parameter(element.local.as_str())
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "cancel-commit"]) {
            match element.local.as_str() {
                "persist-id" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    self.install_cancel_commit_persist_id()
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "lock"]) || self.local_path_is(&["rpc", "unlock"]) {
            match element.local.as_str() {
                "target" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => Ok(()),
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "validate"]) {
            match element.local.as_str() {
                "source" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => Ok(()),
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "copy-config"]) {
            match element.local.as_str() {
                "target" | "source" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => {
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "delete-config"]) {
            match element.local.as_str() {
                "target" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => Ok(()),
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "lock", "target"])
            || self.local_path_is(&["rpc", "unlock", "target"])
            || self.local_path_is(&["rpc", "validate", "source"])
            || self.local_path_is(&["rpc", "edit-config", "target"])
            || self.local_path_is(&["rpc", "copy-config", "target"])
            || self.local_path_is(&["rpc", "copy-config", "source"])
            || self.local_path_is(&["rpc", "delete-config", "target"])
        {
            if element.namespace != NETCONF_BASE_NS || !attrs.is_empty() {
                return Err(XmlError::Malformed);
            }
            let datastore = datastore_from_local(&element.local)?;
            if self.local_path_is(&["rpc", "lock", "target"]) {
                let lock = self.lock.as_mut().ok_or(XmlError::UnsupportedOperation)?;
                if lock.target.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else if self.local_path_is(&["rpc", "unlock", "target"]) {
                let unlock = self.unlock.as_mut().ok_or(XmlError::UnsupportedOperation)?;
                if unlock.target.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else if self.local_path_is(&["rpc", "edit-config", "target"]) {
                let edit_config = self
                    .edit_config
                    .as_mut()
                    .ok_or(XmlError::UnsupportedOperation)?;
                if edit_config.target.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else if self.local_path_is(&["rpc", "copy-config", "target"]) {
                let copy_config = self
                    .copy_config
                    .as_mut()
                    .ok_or(XmlError::UnsupportedOperation)?;
                if copy_config.target.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else if self.local_path_is(&["rpc", "copy-config", "source"]) {
                let copy_config = self
                    .copy_config
                    .as_mut()
                    .ok_or(XmlError::UnsupportedOperation)?;
                if copy_config.source.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else if self.local_path_is(&["rpc", "delete-config", "target"]) {
                let delete_config = self
                    .delete_config
                    .as_mut()
                    .ok_or(XmlError::UnsupportedOperation)?;
                if delete_config.target.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            } else {
                let validate = self
                    .validate
                    .as_mut()
                    .ok_or(XmlError::UnsupportedOperation)?;
                if validate.source.replace(datastore).is_some() {
                    return Err(XmlError::DuplicateElement);
                }
            }
            Ok(())
        } else if self.local_path_is(&["rpc", "kill-session"]) {
            match element.local.as_str() {
                "session-id" if element.namespace == NETCONF_BASE_NS && attrs.is_empty() => Ok(()),
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-schema"]) {
            match element.local.as_str() {
                "identifier" | "version" | "format"
                    if element.namespace == NETCONF_MONITORING_NS =>
                {
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "create-subscription"]) {
            match element.local.as_str() {
                "stream" | "startTime" | "stopTime"
                    if element.namespace == NETCONF_NOTIFICATION_NS && attrs.is_empty() =>
                {
                    self.install_create_subscription_scalar(element.local.as_str())
                }
                "filter" if element.namespace == NETCONF_NOTIFICATION_NS => {
                    self.install_create_subscription_filter()
                }
                _ => Err(XmlError::Malformed),
            }
        } else if self.local_path_is(&["rpc", "get-schema", "identifier"])
            || self.local_path_is(&["rpc", "get-schema", "version"])
            || self.local_path_is(&["rpc", "get-schema", "format"])
            || self.local_path_is(&["rpc", "create-subscription", "stream"])
            || self.local_path_is(&["rpc", "create-subscription", "startTime"])
            || self.local_path_is(&["rpc", "create-subscription", "stopTime"])
            || self.local_path_is(&["rpc", "kill-session", "session-id"])
            || self.local_path_is(&["rpc", "lock", "target", "running"])
            || self.local_path_is(&["rpc", "lock", "target", "candidate"])
            || self.local_path_is(&["rpc", "lock", "target", "startup"])
            || self.local_path_is(&["rpc", "unlock", "target", "running"])
            || self.local_path_is(&["rpc", "unlock", "target", "candidate"])
            || self.local_path_is(&["rpc", "unlock", "target", "startup"])
            || self.local_path_is(&["rpc", "validate", "source", "running"])
            || self.local_path_is(&["rpc", "validate", "source", "candidate"])
            || self.local_path_is(&["rpc", "validate", "source", "startup"])
            || self.local_path_is(&["rpc", "copy-config", "target", "running"])
            || self.local_path_is(&["rpc", "copy-config", "target", "candidate"])
            || self.local_path_is(&["rpc", "copy-config", "target", "startup"])
            || self.local_path_is(&["rpc", "copy-config", "source", "running"])
            || self.local_path_is(&["rpc", "copy-config", "source", "candidate"])
            || self.local_path_is(&["rpc", "copy-config", "source", "startup"])
            || self.local_path_is(&["rpc", "delete-config", "target", "running"])
            || self.local_path_is(&["rpc", "delete-config", "target", "candidate"])
            || self.local_path_is(&["rpc", "delete-config", "target", "startup"])
            || self.local_path_is(&["rpc", "edit-config", "target", "running"])
            || self.local_path_is(&["rpc", "edit-config", "target", "candidate"])
            || self.local_path_is(&["rpc", "edit-config", "target", "startup"])
            || self.local_path_is(&["rpc", "edit-config", "default-operation"])
            || self.local_path_is(&["rpc", "edit-config", "test-option"])
            || self.local_path_is(&["rpc", "edit-config", "error-option"])
            || self.local_path_is(&["rpc", "commit", "confirmed"])
            || self.local_path_is(&["rpc", "commit", "confirm-timeout"])
            || self.local_path_is(&["rpc", "commit", "persist"])
            || self.local_path_is(&["rpc", "commit", "persist-id"])
            || self.local_path_is(&["rpc", "cancel-commit", "persist-id"])
            || self.local_path_is(&["rpc", "get", "with-defaults"])
            || self.local_path_is(&["rpc", "get-config", "with-defaults"])
            || self.local_path_is(&["rpc", "get-data", "datastore"])
            || self.local_path_is(&["rpc", "get-data", "config-filter"])
            || self.local_path_is(&["rpc", "get-data", "origin-filter"])
            || self.local_path_is(&["rpc", "get-data", "negated-origin-filter"])
            || self.local_path_is(&["rpc", "get-data", "max-depth"])
            || self.local_path_is(&["rpc", "get-data", "with-origin"])
            || self.local_path_is(&["rpc", "get-data", "xpath-filter"])
            || self.local_path_is(&["rpc", "get-data", "with-defaults"])
            || self.local_path_is(&["rpc", "edit-data", "datastore"])
            || self.local_path_is(&["rpc", "edit-data", "default-operation"])
            || self.local_path_is(&["rpc", "edit-data", "url"])
        {
            Err(XmlError::Malformed)
        } else if self.local_path_is(&["rpc", "get-config", "source"]) {
            let datastore = datastore_from_local(&element.local)?;
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
        self.edit_config.is_some()
            || self.edit_data.is_some()
            || self.get.is_some()
            || self.get_config.is_some()
            || self.get_data.is_some()
            || self.get_schema.is_some()
            || self.create_subscription.is_some()
            || self.kill_session.is_some()
            || self.lock.is_some()
            || self.unlock.is_some()
            || self.validate.is_some()
            || self.copy_config.is_some()
            || self.delete_config.is_some()
            || self.commit.is_some()
            || self.cancel_commit.is_some()
            || self.close_session
            || self.discard_changes
    }

    fn operation_hint(&self) -> Option<RpcOperationHint> {
        self.operation_hint
    }

    fn note_rpc_operation_hint(&mut self, local: &str) {
        if self.operation_hint.is_some()
            || self.has_rpc_operation()
            || !self.local_path_is(&["rpc"])
        {
            return;
        }
        match local {
            "edit-config" => self.operation_hint = Some(RpcOperationHint::EditConfig),
            "commit" => self.operation_hint = Some(RpcOperationHint::Commit),
            "cancel-commit" => self.operation_hint = Some(RpcOperationHint::CancelCommit),
            "discard-changes" => self.operation_hint = Some(RpcOperationHint::DiscardChanges),
            "copy-config" => self.operation_hint = Some(RpcOperationHint::CopyConfig),
            "delete-config" => self.operation_hint = Some(RpcOperationHint::DeleteConfig),
            "kill-session" => self.operation_hint = Some(RpcOperationHint::KillSession),
            "create-subscription" => {
                self.operation_hint = Some(RpcOperationHint::CreateSubscription)
            }
            _ => {}
        }
    }

    fn get_schema_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == NETCONF_MONITORING_NS
            && ((self.local_path_is(&["rpc"]) && element.local == "get-schema")
                || (self.local_path_is(&["rpc", "get-schema"])
                    && matches!(element.local.as_str(), "identifier" | "version" | "format"))
                || self.local_path_is(&["rpc", "get-schema", "identifier"])
                || self.local_path_is(&["rpc", "get-schema", "version"])
                || self.local_path_is(&["rpc", "get-schema", "format"]))
    }

    fn with_defaults_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == WITH_DEFAULTS_NS
            && (((self.local_path_is(&["rpc", "get"])
                || self.local_path_is(&["rpc", "get-config"])
                || self.local_path_is(&["rpc", "get-data"]))
                && element.local == "with-defaults")
                || self.local_path_is(&["rpc", "get", "with-defaults"])
                || self.local_path_is(&["rpc", "get-config", "with-defaults"])
                || self.local_path_is(&["rpc", "get-data", "with-defaults"]))
    }

    fn nmda_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == NETCONF_NMDA_NS
            && ((self.local_path_is(&["rpc"]) && element.local == "get-data")
                || (self.local_path_is(&["rpc"]) && element.local == "edit-data")
                || (self.local_path_is(&["rpc", "get-data"])
                    && matches!(
                        element.local.as_str(),
                        "datastore"
                            | "subtree-filter"
                            | "xpath-filter"
                            | "config-filter"
                            | "origin-filter"
                            | "negated-origin-filter"
                            | "max-depth"
                            | "with-origin"
                    ))
                || self.local_path_is(&["rpc", "get-data", "datastore"])
                || self.local_path_is(&["rpc", "get-data", "xpath-filter"])
                || self.local_path_is(&["rpc", "get-data", "config-filter"])
                || self.local_path_is(&["rpc", "get-data", "origin-filter"])
                || self.local_path_is(&["rpc", "get-data", "negated-origin-filter"])
                || self.local_path_is(&["rpc", "get-data", "max-depth"])
                || self.local_path_is(&["rpc", "get-data", "with-origin"])
                || (self.local_path_is(&["rpc", "edit-data"])
                    && matches!(
                        element.local.as_str(),
                        "datastore" | "default-operation" | "config" | "url"
                    ))
                || self.local_path_is(&["rpc", "edit-data", "datastore"])
                || self.local_path_is(&["rpc", "edit-data", "default-operation"])
                || self.local_path_is(&["rpc", "edit-data", "url"]))
    }

    fn notification_namespace_is_allowed(&self, element: &Element) -> bool {
        element.namespace == NETCONF_NOTIFICATION_NS
            && ((self.local_path_is(&["rpc"]) && element.local == "create-subscription")
                || (self.local_path_is(&["rpc", "create-subscription"])
                    && matches!(
                        element.local.as_str(),
                        "stream" | "filter" | "startTime" | "stopTime"
                    ))
                || self.local_path_is(&["rpc", "create-subscription", "stream"])
                || self.local_path_is(&["rpc", "create-subscription", "startTime"])
                || self.local_path_is(&["rpc", "create-subscription", "stopTime"]))
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

    fn set_kill_session_id(&mut self, text: &str) -> Result<(), XmlError> {
        let kill_session = self
            .kill_session
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        let session_id = value.parse::<u64>().map_err(|_| XmlError::InvalidValue)?;
        if !is_valid_session_id(session_id) {
            return Err(XmlError::InvalidValue);
        }
        if kill_session.session_id.replace(session_id).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn install_create_subscription_scalar(&mut self, local: &str) -> Result<(), XmlError> {
        let request = self
            .create_subscription
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let seen = match local {
            "stream" => &mut request.stream_seen,
            "startTime" => &mut request.start_time_seen,
            "stopTime" => &mut request.stop_time_seen,
            _ => return Err(XmlError::Malformed),
        };
        if *seen {
            return Err(XmlError::DuplicateElement);
        }
        *seen = true;
        Ok(())
    }

    fn install_create_subscription_filter(&mut self) -> Result<(), XmlError> {
        let request = self
            .create_subscription
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if request.filter_seen || self.notification_filter_depth > 0 {
            return Err(XmlError::DuplicateElement);
        }
        request.filter_seen = true;
        self.notification_filter_depth = 1;
        Ok(())
    }

    fn set_create_subscription_stream_text(&mut self, text: &str) -> Result<(), XmlError> {
        let request = self
            .create_subscription
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if request.stream.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_create_subscription_start_time_text(&mut self, text: &str) -> Result<(), XmlError> {
        let request = self
            .create_subscription
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if request.start_time.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_create_subscription_stop_time_text(&mut self, text: &str) -> Result<(), XmlError> {
        let request = self
            .create_subscription
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if request.stop_time.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn install_commit_parameter(&mut self, local: &str) -> Result<(), XmlError> {
        let commit = self.commit.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        match local {
            "confirmed" => {
                if commit.confirmed {
                    return Err(XmlError::DuplicateElement);
                }
                commit.confirmed = true;
            }
            "confirm-timeout" => {
                if commit.confirm_timeout_seen {
                    return Err(XmlError::DuplicateElement);
                }
                commit.confirm_timeout_seen = true;
            }
            "persist" => {
                if commit.persist_seen {
                    return Err(XmlError::DuplicateElement);
                }
                commit.persist_seen = true;
            }
            "persist-id" => {
                if commit.persist_id_seen {
                    return Err(XmlError::DuplicateElement);
                }
                commit.persist_id_seen = true;
            }
            _ => return Err(XmlError::Malformed),
        }
        Ok(())
    }

    fn install_cancel_commit_persist_id(&mut self) -> Result<(), XmlError> {
        let cancel = self
            .cancel_commit
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if cancel.persist_id_seen {
            return Err(XmlError::DuplicateElement);
        }
        cancel.persist_id_seen = true;
        Ok(())
    }

    fn set_commit_confirm_timeout_text(&mut self, text: &str) -> Result<(), XmlError> {
        let commit = self.commit.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        let seconds = value.parse::<u32>().map_err(|_| XmlError::InvalidValue)?;
        if seconds == 0 {
            return Err(XmlError::InvalidValue);
        }
        if commit.confirm_timeout.replace(seconds).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_commit_persist_text(&mut self, text: &str) -> Result<(), XmlError> {
        let commit = self.commit.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if commit.persist.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_commit_persist_id_text(&mut self, text: &str) -> Result<(), XmlError> {
        let commit = self.commit.as_mut().ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if commit.persist_id.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_cancel_commit_persist_id_text(&mut self, text: &str) -> Result<(), XmlError> {
        let cancel = self
            .cancel_commit
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        if cancel.persist_id.replace(value.to_string()).is_some() {
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

    fn install_get_data_scalar(&mut self, local: &str) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        match local {
            "datastore" => {
                if get_data.datastore_seen {
                    return Err(XmlError::DuplicateElement);
                }
                get_data.datastore_seen = true;
            }
            "config-filter" => {
                if get_data.config_filter_seen {
                    return Err(XmlError::DuplicateElement);
                }
                get_data.config_filter_seen = true;
            }
            "origin-filter" | "negated-origin-filter" => {
                get_data.origin_filter_present = true;
            }
            "max-depth" => {
                if get_data.max_depth_seen {
                    return Err(XmlError::DuplicateElement);
                }
                get_data.max_depth_seen = true;
            }
            _ => return Err(XmlError::Malformed),
        }
        Ok(())
    }

    fn install_get_data_with_origin(&mut self) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.with_origin {
            return Err(XmlError::DuplicateElement);
        }
        get_data.with_origin = true;
        Ok(())
    }

    fn install_get_data_subtree_filter(&mut self) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.filter.is_some() || get_data.xpath_filter_seen {
            return Err(XmlError::DuplicateElement);
        }
        get_data.filter = Some(Filter::Subtree(SubtreeFilter::default()));
        self.filter_depth = 1;
        Ok(())
    }

    fn install_get_data_xpath_filter(&mut self, scope: &NamespaceScope) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.filter.is_some() || get_data.xpath_filter_seen {
            return Err(XmlError::DuplicateElement);
        }
        get_data.xpath_filter_seen = true;
        get_data.xpath_filter_namespaces = scope.bindings.clone();
        Ok(())
    }

    fn install_get_data_with_defaults(
        &mut self,
        attrs: &[(String, String)],
    ) -> Result<(), XmlError> {
        if !attrs.is_empty() {
            return Err(XmlError::Malformed);
        }
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.with_defaults_seen {
            return Err(XmlError::DuplicateElement);
        }
        get_data.with_defaults_seen = true;
        Ok(())
    }

    fn set_get_data_datastore_text(&mut self, text: &str) -> Result<(), XmlError> {
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        let datastore = parse_nmda_datastore(value, self.scopes.last())?;
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.datastore.replace(datastore).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_get_data_xpath_filter_text(&mut self, text: &str) -> Result<(), XmlError> {
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        self.limits.check_xpath_filter_bytes(value.len())?;
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data.xpath_filter.replace(value.to_string()).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_get_data_config_filter_text(&mut self, text: &str) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data
            .config_filter
            .replace(parse_xml_bool(text)?)
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_get_data_origin_filter_text(&mut self, text: &str) -> Result<(), XmlError> {
        if text.trim().is_empty() {
            return Err(XmlError::InvalidValue);
        }
        Ok(())
    }

    fn set_get_data_max_depth_text(&mut self, text: &str) -> Result<(), XmlError> {
        let value = text.trim();
        if value.is_empty() {
            return Err(XmlError::InvalidValue);
        }
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        get_data.max_depth_limited = value != "unbounded";
        Ok(())
    }

    fn set_get_data_with_defaults_text(&mut self, text: &str) -> Result<(), XmlError> {
        let get_data = self
            .get_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if get_data
            .with_defaults
            .replace(WithDefaultsMode::parse(text))
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn install_edit_default_operation(&mut self) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config.default_operation_seen {
            return Err(XmlError::DuplicateElement);
        }
        edit_config.default_operation_seen = true;
        Ok(())
    }

    fn install_edit_test_option(&mut self) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config.test_option_seen {
            return Err(XmlError::DuplicateElement);
        }
        edit_config.test_option_seen = true;
        Ok(())
    }

    fn install_edit_error_option(&mut self) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config.error_option_seen {
            return Err(XmlError::DuplicateElement);
        }
        edit_config.error_option_seen = true;
        Ok(())
    }

    fn install_edit_config_capture(&mut self) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config.config_xml.is_some() || self.edit_config_capture.is_some() {
            return Err(XmlError::DuplicateElement);
        }
        self.edit_config_capture = Some(Writer::new(Vec::new()));
        self.edit_config_capture_depth = 0;
        Ok(())
    }

    fn install_edit_data_datastore(&mut self) -> Result<(), XmlError> {
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.datastore_seen {
            return Err(XmlError::DuplicateElement);
        }
        edit_data.datastore_seen = true;
        Ok(())
    }

    fn install_edit_data_default_operation(&mut self) -> Result<(), XmlError> {
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.default_operation_seen {
            return Err(XmlError::DuplicateElement);
        }
        edit_data.default_operation_seen = true;
        Ok(())
    }

    fn install_edit_data_config_capture(&mut self) -> Result<(), XmlError> {
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.config_xml.is_some()
            || edit_data.url_seen
            || self.edit_config_capture.is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        self.edit_config_capture = Some(Writer::new(Vec::new()));
        self.edit_config_capture_depth = 0;
        Ok(())
    }

    fn install_edit_data_url(&mut self) -> Result<(), XmlError> {
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.url_seen
            || edit_data.config_xml.is_some()
            || self.edit_config_capture.is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        edit_data.url_seen = true;
        Ok(())
    }

    fn set_edit_default_operation_text(&mut self, text: &str) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config
            .default_operation
            .replace(EditDefaultOperation::parse(text)?)
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_edit_test_option_text(&mut self, text: &str) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config
            .test_option
            .replace(EditTestOption::parse(text)?)
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_edit_error_option_text(&mut self, text: &str) -> Result<(), XmlError> {
        let edit_config = self
            .edit_config
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_config
            .error_option
            .replace(EditErrorOption::parse(text)?)
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_edit_data_datastore_text(&mut self, text: &str) -> Result<(), XmlError> {
        let datastore = {
            let scope = self.scopes.last().ok_or(XmlError::Malformed)?;
            parse_nmda_datastore(text.trim(), Some(scope))?
        };
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.datastore.replace(datastore).is_some() {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_edit_data_default_operation_text(&mut self, text: &str) -> Result<(), XmlError> {
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data
            .default_operation
            .replace(EditDefaultOperation::parse(text)?)
            .is_some()
        {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn set_edit_data_url_text(&mut self, text: &str) -> Result<(), XmlError> {
        if text.trim().is_empty() {
            return Err(XmlError::InvalidValue);
        }
        Ok(())
    }

    fn is_edit_config_config_start(&self, element: &Element) -> bool {
        element.local == "config"
            && ((self.local_path_is(&["rpc", "edit-config"])
                && element.namespace == NETCONF_BASE_NS)
                || (self.local_path_is(&["rpc", "edit-data"])
                    && element.namespace == NETCONF_NMDA_NS))
    }

    fn edit_config_capture_is_active(&self) -> bool {
        self.edit_config_capture.is_some()
    }

    fn notification_filter_is_active(&self) -> bool {
        self.notification_filter_depth > 0
    }

    fn capture_event<'a, E>(&mut self, event: E) -> Result<(), XmlError>
    where
        E: Into<Event<'a>>,
    {
        let Some(writer) = self.edit_config_capture.as_mut() else {
            return Err(XmlError::Malformed);
        };
        writer.write_event(event).map_err(|_| XmlError::Malformed)
    }

    fn capture_config_root_start(
        &mut self,
        start: &BytesStart<'_>,
        scope: &NamespaceScope,
    ) -> Result<(), XmlError> {
        let raw_name = start.name();
        let name = qname_bytes_to_str(raw_name.as_ref())?;
        let mut rewritten = BytesStart::new(name);
        if let Some(default) = scope.default.as_deref() {
            rewritten.push_attribute(("xmlns", default));
        }
        for (prefix, namespace) in &scope.bindings {
            let attr = format!("xmlns:{prefix}");
            rewritten.push_attribute((attr.as_str(), namespace.as_str()));
        }
        self.capture_event(Event::Start(rewritten))
    }

    fn finish_edit_config_capture(&mut self) -> Result<(), XmlError> {
        let writer = self.edit_config_capture.take().ok_or(XmlError::Malformed)?;
        let bytes = writer.into_inner();
        let config_xml = String::from_utf8(bytes).map_err(|_| XmlError::Malformed)?;
        if let Some(edit_config) = self.edit_config.as_mut() {
            if edit_config.config_xml.replace(config_xml).is_some() {
                return Err(XmlError::DuplicateElement);
            }
            return Ok(());
        }
        let edit_data = self
            .edit_data
            .as_mut()
            .ok_or(XmlError::UnsupportedOperation)?;
        if edit_data.config_xml.replace(config_xml).is_some() || edit_data.url_seen {
            return Err(XmlError::DuplicateElement);
        }
        Ok(())
    }

    fn install_filter(
        &mut self,
        attrs: &[(String, String)],
        scope: &NamespaceScope,
    ) -> Result<(), XmlError> {
        let filter = filter_kind(attrs)?;
        let parsed_filter = match filter {
            FilterKind::Subtree => Filter::Subtree(SubtreeFilter::default()),
            FilterKind::XPath => {
                let select = attr_value(attrs, "select").ok_or(XmlError::MissingAttribute)?;
                self.limits.check_xpath_filter_bytes(select.len())?;
                Filter::XPath(XPathFilter::new(select.to_string(), scope.bindings.clone()))
            }
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
        if !matches!(self.active_filter(), Some(Filter::Subtree(_))) {
            return Err(XmlError::UnsupportedFilterContent);
        }

        if let Some(mut path) = self
            .filter_stack
            .last()
            .and_then(|parent| parent.suppress_subtree.then(|| parent.path.clone()))
        {
            if !attrs.is_empty() {
                self.record_filter_attribute_match()?;
            }
            path.push(FilterElement {
                namespace: element.namespace.clone(),
                local: element.local.clone(),
            });
            self.filter_stack.push(FilterFrame {
                path,
                child_count: 0,
                suppress_subtree: true,
            });
            return Ok(());
        }

        if let Some(parent) = self.filter_stack.last_mut() {
            parent.child_count += 1;
        }

        if !attrs.is_empty() {
            self.record_filter_attribute_match()?;
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
                suppress_subtree: true,
            });
            return Ok(());
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
            suppress_subtree: false,
        });

        Ok(())
    }

    fn finish_filter_content_element(&mut self) -> Result<(), XmlError> {
        let frame = self.filter_stack.pop().ok_or(XmlError::Malformed)?;
        let Some(Filter::Subtree(filter)) = self.active_filter_mut() else {
            return Err(XmlError::UnsupportedFilterContent);
        };
        if frame.suppress_subtree {
            return Ok(());
        }
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
            .or_else(|| {
                self.get_data
                    .as_ref()
                    .and_then(|get_data| get_data.filter.as_ref())
            })
    }

    fn active_filter_mut(&mut self) -> Option<&mut Filter> {
        if let Some(get) = self.get.as_mut() {
            return get.filter.as_mut();
        }
        if let Some(get_config) = self.get_config.as_mut() {
            return get_config.filter.as_mut();
        }
        if let Some(get_data) = self.get_data.as_mut() {
            return get_data.filter.as_mut();
        }
        None
    }

    fn finish(mut self) -> Result<ParsedMessage, XmlError> {
        if self.root.is_none() {
            return Err(XmlError::Empty);
        }
        if !self.stack.is_empty() {
            return Err(XmlError::Malformed);
        }

        match self.root.expect("checked root") {
            RootKind::Hello => {
                if !self.hello_capabilities_seen || self.capabilities.is_empty() {
                    return Err(XmlError::MissingElement);
                }
                Ok(ParsedMessage::Hello(ClientHello {
                    capabilities: self.capabilities,
                }))
            }
            RootKind::Rpc => {
                let message_id = self.message_id.ok_or(XmlError::MissingAttribute)?;
                let reply_attrs = self.reply_attrs;
                if let Some(err) = self.filter_unsupported_subtree_error.take() {
                    return Err(err);
                }
                if let Some(edit_config) = self.edit_config {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::EditConfig(EditConfigRequest {
                            target: edit_config.target.ok_or(XmlError::MissingElement)?,
                            default_operation: finish_edit_option(
                                edit_config.default_operation_seen,
                                edit_config.default_operation,
                            )?,
                            test_option: finish_edit_option(
                                edit_config.test_option_seen,
                                edit_config.test_option,
                            )?,
                            test_option_explicit: edit_config.test_option_seen,
                            error_option: finish_edit_option(
                                edit_config.error_option_seen,
                                edit_config.error_option,
                            )?,
                            config_xml: edit_config.config_xml.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(edit_data) = self.edit_data {
                    if edit_data.config_xml.is_none() && !edit_data.url_seen {
                        return Err(XmlError::MissingElement);
                    }
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::EditData(EditDataRequest {
                            datastore: finish_get_data_datastore(&PartialGetData {
                                datastore_seen: edit_data.datastore_seen,
                                datastore: edit_data.datastore,
                                ..PartialGetData::default()
                            })?,
                            default_operation: finish_edit_option(
                                edit_data.default_operation_seen,
                                edit_data.default_operation,
                            )?,
                            config_xml: edit_data.config_xml,
                            url_present: edit_data.url_seen,
                        }),
                    }));
                }
                if let Some(get) = self.get {
                    let with_defaults =
                        finish_with_defaults(get.with_defaults_seen, get.with_defaults);
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
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
                        reply_attrs,
                        operation: RpcOperation::GetConfig(GetConfigRequest {
                            source,
                            filter: get_config.filter,
                            with_defaults,
                        }),
                    }));
                }
                if let Some(mut get_data) = self.get_data {
                    let filter = finish_get_data_filter(&mut get_data)?;
                    let with_defaults =
                        finish_with_defaults(get_data.with_defaults_seen, get_data.with_defaults);
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::GetData(GetDataRequest {
                            datastore: finish_get_data_datastore(&get_data)?,
                            filter,
                            config_filter: finish_get_data_config_filter(&get_data)?,
                            origin_filter_present: get_data.origin_filter_present,
                            max_depth_limited: get_data.max_depth_limited,
                            with_origin: get_data.with_origin,
                            with_defaults,
                        }),
                    }));
                }
                if self.close_session {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::CloseSession,
                    }));
                }
                if let Some(commit) = self.commit {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::Commit(finish_commit(commit)?),
                    }));
                }
                if let Some(cancel_commit) = self.cancel_commit {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::CancelCommit(finish_cancel_commit(cancel_commit)?),
                    }));
                }
                if self.discard_changes {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::DiscardChanges,
                    }));
                }
                if let Some(copy_config) = self.copy_config {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::CopyConfig(CopyConfigRequest {
                            target: copy_config.target.ok_or(XmlError::MissingElement)?,
                            source: copy_config.source.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(delete_config) = self.delete_config {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::DeleteConfig(DeleteConfigRequest {
                            target: delete_config.target.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(lock) = self.lock {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::Lock(LockRequest {
                            target: lock.target.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(unlock) = self.unlock {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::Unlock(UnlockRequest {
                            target: unlock.target.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(validate) = self.validate {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::Validate(ValidateRequest {
                            source: validate.source.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(kill_session) = self.kill_session {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::KillSession(KillSessionRequest {
                            session_id: kill_session.session_id.ok_or(XmlError::MissingElement)?,
                        }),
                    }));
                }
                if let Some(get_schema) = self.get_schema {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::GetSchema(GetSchemaRequest {
                            identifier: get_schema.identifier.ok_or(XmlError::MissingElement)?,
                            version: get_schema.version,
                            format: get_schema.format.unwrap_or_else(|| "yang".to_string()),
                        }),
                    }));
                }
                if let Some(create_subscription) = self.create_subscription {
                    return Ok(ParsedMessage::Rpc(ParsedRpc {
                        message_id,
                        reply_attrs,
                        operation: RpcOperation::CreateSubscription(CreateSubscriptionRequest {
                            stream: finish_subscription_scalar(
                                create_subscription.stream_seen,
                                create_subscription.stream,
                            )?,
                            filter_present: create_subscription.filter_seen,
                            start_time: finish_subscription_scalar(
                                create_subscription.start_time_seen,
                                create_subscription.start_time,
                            )?,
                            stop_time: finish_subscription_scalar(
                                create_subscription.stop_time_seen,
                                create_subscription.stop_time,
                            )?,
                        }),
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
    parse_rpc_with_context(xml, limits).map_err(|err| err.error)
}

/// Parses a NETCONF RPC envelope, preserving a parsed `message-id` on failure.
pub(crate) fn parse_rpc_with_context(
    xml: &str,
    limits: &MgmtLimits,
) -> Result<ParsedRpc, RpcParseError> {
    match parse_message_with_context(xml, limits)? {
        ParsedMessage::Rpc(rpc) => Ok(rpc),
        ParsedMessage::Hello(_) => Err(RpcParseError::without_message_id(
            XmlError::UnsupportedOperation,
        )),
    }
}

fn parse_message(xml: &str, limits: &MgmtLimits) -> Result<ParsedMessage, XmlError> {
    parse_message_with_context(xml, limits).map_err(|err| err.error)
}

fn parse_message_with_context(
    xml: &str,
    limits: &MgmtLimits,
) -> Result<ParsedMessage, RpcParseError> {
    limits
        .validate()
        .map_err(|err| RpcParseError::without_message_id(err.into()))?;
    limits
        .check_request_bytes(xml.len())
        .map_err(|err| RpcParseError::without_message_id(err.into()))?;
    validate_xml_decl_start(xml).map_err(RpcParseError::without_message_id)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut state = ParserState::new(*limits);

    loop {
        match reader
            .read_event()
            .map_err(|_| parse_error(&state, XmlError::Malformed))?
        {
            Event::Start(start) => {
                state
                    .push_start(&start, reader.decoder(), limits)
                    .map_err(|err| parse_error(&state, err))?;
            }
            Event::Empty(start) => {
                state
                    .push_empty(&start, reader.decoder(), limits)
                    .map_err(|err| parse_error(&state, err))?;
            }
            Event::End(end) => {
                state
                    .pop_end(end.name().as_ref())
                    .map_err(|err| parse_error(&state, err))?;
            }
            Event::Text(text) => {
                limits
                    .check_value_bytes(text.as_ref().len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                if state.edit_config_capture_is_active() {
                    state
                        .capture_event(Event::Text(text.borrow()))
                        .map_err(|err| parse_error(&state, err))?;
                    continue;
                }
                let decoded = text
                    .decode()
                    .map_err(|_| parse_error(&state, XmlError::Malformed))?;
                state
                    .text(decoded.as_ref())
                    .map_err(|err| parse_error(&state, err))?;
            }
            Event::CData(cdata) => {
                limits
                    .check_value_bytes(cdata.as_ref().len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                if state.edit_config_capture_is_active() {
                    state
                        .capture_event(Event::CData(cdata.borrow()))
                        .map_err(|err| parse_error(&state, err))?;
                    continue;
                }
                if state.notification_filter_is_active() {
                    continue;
                }
                return Err(parse_error(&state, XmlError::Malformed));
            }
            Event::DocType(doctype) => {
                limits
                    .check_value_bytes(doctype.len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                return Err(parse_error(&state, XmlError::DtdForbidden));
            }
            Event::GeneralRef(reference) => {
                limits
                    .check_value_bytes(reference.len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                return Err(parse_error(&state, XmlError::EntityForbidden));
            }
            Event::Decl(decl) => {
                limits
                    .check_value_bytes(decl.len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                state.xml_decl().map_err(|err| parse_error(&state, err))?;
            }
            Event::Comment(comment) => {
                limits
                    .check_value_bytes(comment.len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                if state.edit_config_capture_is_active() {
                    state
                        .capture_event(Event::Comment(comment.borrow()))
                        .map_err(|err| parse_error(&state, err))?;
                    continue;
                }
                state.comment();
            }
            Event::PI(pi) => {
                limits
                    .check_value_bytes(pi.len())
                    .map_err(|err| parse_error(&state, err.into()))?;
                return Err(parse_error(&state, XmlError::Malformed));
            }
            Event::Eof => break,
        }
    }

    let message_id = state.message_id.clone();
    let reply_attrs = state.reply_attrs.clone();
    let operation_hint = state.operation_hint();
    let parsed = state.finish().map_err(|err| {
        RpcParseError::with_context(message_id.clone(), reply_attrs.clone(), operation_hint, err)
    })?;
    if let ParsedMessage::Rpc(ParsedRpc {
        operation:
            RpcOperation::GetConfig(GetConfigRequest { filter, .. })
            | RpcOperation::Get(GetRequest { filter, .. }),
        message_id,
        ..
    }) = &parsed
    {
        if let Some(Filter::Subtree(filter)) = filter {
            limits
                .check_paths(filter.selections().len())
                .map_err(|err| {
                    RpcParseError::with_context(
                        Some(message_id.clone()),
                        reply_attrs.clone(),
                        None,
                        err.into(),
                    )
                })?;
        }
    }
    Ok(parsed)
}

fn parse_error(state: &ParserState, error: XmlError) -> RpcParseError {
    RpcParseError::with_context(
        state.message_id.clone(),
        state.reply_attrs.clone(),
        state.operation_hint(),
        error,
    )
}

fn validate_xml_decl_start(xml: &str) -> Result<(), XmlError> {
    if !xml.starts_with("<?xml") && xml.trim_start().starts_with("<?xml") {
        return Err(XmlError::Malformed);
    }
    Ok(())
}

fn scoped_attributes(
    start: &BytesStart<'_>,
    decoder: Decoder,
    limits: &MgmtLimits,
    parent: Option<&NamespaceScope>,
) -> Result<ScopedAttributes, XmlError> {
    let mut scope = parent.cloned().unwrap_or_default();
    let mut attrs = Vec::new();
    let mut reply_attrs = Vec::new();
    let mut attr_count = 0usize;
    let mut ns_count = 0usize;
    let mut default_declared = false;
    let mut declared_prefixes = BTreeSet::new();

    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| XmlError::Malformed)?;
        attr_count += 1;
        let key = qname_bytes_to_str(attr.key.as_ref())?;
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|_| XmlError::Malformed)?
            .into_owned();
        limits.check_value_bytes(value.len())?;
        reply_attrs.push((key.to_string(), value.clone()));

        if key == "xmlns" {
            ns_count += 1;
            if default_declared {
                return Err(XmlError::Malformed);
            }
            default_declared = true;
            validate_namespace_binding(None, &value)?;
            scope.default = Some(value);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            ns_count += 1;
            if prefix.is_empty() {
                return Err(XmlError::Malformed);
            }
            if !declared_prefixes.insert(prefix.to_string()) {
                return Err(XmlError::Malformed);
            }
            validate_namespace_binding(Some(prefix), &value)?;
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
    validate_attribute_names(&attrs, &scope)?;

    Ok(ScopedAttributes {
        scope,
        attrs,
        reply_attrs,
    })
}

fn validate_namespace_binding(prefix: Option<&str>, uri: &str) -> Result<(), XmlError> {
    match prefix {
        None if uri == XML_NAMESPACE_URI || uri == XMLNS_NAMESPACE_URI => Err(XmlError::Malformed),
        None => Ok(()),
        Some("xml") if uri == XML_NAMESPACE_URI => Ok(()),
        Some("xml") | Some("xmlns") => Err(XmlError::Malformed),
        Some(_) if uri.is_empty() || uri == XML_NAMESPACE_URI || uri == XMLNS_NAMESPACE_URI => {
            Err(XmlError::Malformed)
        }
        Some(_) => Ok(()),
    }
}

fn validate_attribute_names(
    attrs: &[(String, String)],
    scope: &NamespaceScope,
) -> Result<(), XmlError> {
    for (name, _) in attrs {
        let (prefix, _) = split_qname(name.as_bytes())?;
        if let Some(prefix) = prefix {
            if prefix != "xml" && !scope.bindings.contains_key(prefix) {
                return Err(XmlError::UnknownNamespace);
            }
        }
    }
    Ok(())
}

fn rpc_reply_attrs(attrs: &[(String, String)]) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter(|(name, value)| {
            name != "message-id" && !(name == "xmlns" && value == NETCONF_BASE_NS)
        })
        .cloned()
        .collect()
}

fn attr_value<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(attr_name, _)| attr_name == name)
        .map(|(_, value)| value.as_str())
}

fn attr_occurrences(attrs: &[(String, String)], name: &str) -> usize {
    attrs
        .iter()
        .filter(|(attr_name, _)| attr_name == name)
        .count()
}

fn datastore_from_local(local: &str) -> Result<Datastore, XmlError> {
    match local {
        "running" => Ok(Datastore::Running),
        "candidate" => Ok(Datastore::Candidate),
        "startup" => Ok(Datastore::Startup),
        _ => Err(XmlError::Malformed),
    }
}

fn parse_nmda_datastore(
    value: &str,
    scope: Option<&NamespaceScope>,
) -> Result<NmdaDatastore, XmlError> {
    let local = if let Some((prefix, local)) = value.split_once(':') {
        let namespace = scope
            .and_then(|scope| scope.bindings.get(prefix))
            .ok_or(XmlError::InvalidValue)?;
        if namespace != IETF_DATASTORES_NS {
            return Err(XmlError::InvalidValue);
        }
        local
    } else {
        value
    };
    match local {
        "running" => Ok(NmdaDatastore::Running),
        "candidate" => Ok(NmdaDatastore::Candidate),
        "startup" => Ok(NmdaDatastore::Startup),
        "intended" => Ok(NmdaDatastore::Intended),
        "operational" => Ok(NmdaDatastore::Operational),
        _ => Err(XmlError::InvalidValue),
    }
}

fn parse_xml_bool(value: &str) -> Result<bool, XmlError> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(XmlError::InvalidValue),
    }
}

fn filter_kind(attrs: &[(String, String)]) -> Result<FilterKind, XmlError> {
    if attr_occurrences(attrs, "type") > 1 {
        return Err(XmlError::InvalidFilterType);
    }
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
            if attr_occurrences(attrs, "select") > 1 {
                return Err(XmlError::InvalidFilterType);
            }
            let select = attr_value(attrs, "select").ok_or(XmlError::MissingAttribute)?;
            if select.trim().is_empty() {
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

fn finish_get_data_filter(get_data: &mut PartialGetData) -> Result<Option<Filter>, XmlError> {
    if get_data.xpath_filter_seen {
        let select = get_data.xpath_filter.take().ok_or(XmlError::InvalidValue)?;
        return Ok(Some(Filter::XPath(XPathFilter::new(
            select,
            std::mem::take(&mut get_data.xpath_filter_namespaces),
        ))));
    }
    Ok(get_data.filter.take())
}

fn finish_get_data_datastore(get_data: &PartialGetData) -> Result<NmdaDatastore, XmlError> {
    match (get_data.datastore_seen, get_data.datastore) {
        (false, None) => Err(XmlError::MissingElement),
        (true, Some(datastore)) => Ok(datastore),
        (true, None) => Err(XmlError::InvalidValue),
        (false, Some(_)) => Err(XmlError::Malformed),
    }
}

fn finish_get_data_config_filter(get_data: &PartialGetData) -> Result<Option<bool>, XmlError> {
    match (get_data.config_filter_seen, get_data.config_filter) {
        (false, None) => Ok(None),
        (true, Some(value)) => Ok(Some(value)),
        (true, None) => Err(XmlError::InvalidValue),
        (false, Some(_)) => Err(XmlError::Malformed),
    }
}

fn finish_edit_option<T: Default>(seen: bool, value: Option<T>) -> Result<T, XmlError> {
    match (seen, value) {
        (false, None) => Ok(T::default()),
        (true, Some(value)) => Ok(value),
        (true, None) => Err(XmlError::InvalidValue),
        (false, Some(_)) => Err(XmlError::Malformed),
    }
}

fn finish_subscription_scalar(
    seen: bool,
    value: Option<String>,
) -> Result<Option<String>, XmlError> {
    match (seen, value) {
        (false, None) => Ok(None),
        (true, Some(value)) => Ok(Some(value)),
        (true, None) => Err(XmlError::InvalidValue),
        (false, Some(_)) => Err(XmlError::Malformed),
    }
}

fn finish_commit(commit: PartialCommit) -> Result<CommitRequest, XmlError> {
    if commit.confirm_timeout_seen && commit.confirm_timeout.is_none() {
        return Err(XmlError::InvalidValue);
    }
    if commit.persist_seen && commit.persist.is_none() {
        return Err(XmlError::InvalidValue);
    }
    if commit.persist_id_seen && commit.persist_id.is_none() {
        return Err(XmlError::InvalidValue);
    }
    Ok(CommitRequest {
        confirmed: commit.confirmed,
        confirm_timeout: commit.confirm_timeout,
        persist: commit.persist,
        persist_id: commit.persist_id,
    })
}

fn finish_cancel_commit(cancel: PartialCancelCommit) -> Result<CancelCommitRequest, XmlError> {
    if cancel.persist_id_seen && cancel.persist_id.is_none() {
        return Err(XmlError::InvalidValue);
    }
    Ok(CancelCommitRequest {
        persist_id: cancel.persist_id,
    })
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
    fn parses_get_data_with_nmda_fields() {
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="701"><ncds:get-data xmlns:ncds="{NETCONF_NMDA_NS}" xmlns:ds="{IETF_DATASTORES_NS}" xmlns:sys="urn:opc:test"><ncds:datastore>ds:operational</ncds:datastore><ncds:config-filter>false</ncds:config-filter><ncds:xpath-filter>/sys:system/sys:uptime</ncds:xpath-filter><wd:with-defaults xmlns:wd="{WITH_DEFAULTS_NS}">trim</wd:with-defaults></ncds:get-data></rpc>"#
        );
        let parsed = parse_rpc(&xml, &MgmtLimits::default()).expect("parse get-data");

        assert_eq!(parsed.message_id, "701");
        let RpcOperation::GetData(request) = parsed.operation else {
            panic!("expected get-data operation");
        };
        assert_eq!(request.datastore, NmdaDatastore::Operational);
        assert_eq!(request.config_filter, Some(false));
        assert!(!request.origin_filter_present);
        assert!(!request.max_depth_limited);
        assert!(!request.with_origin);
        assert_eq!(request.with_defaults, Some(WithDefaultsMode::Trim));
        let Some(Filter::XPath(filter)) = request.filter else {
            panic!("expected xpath filter");
        };
        assert_eq!(filter.select(), "/sys:system/sys:uptime");
        assert_eq!(
            filter.namespaces().get("sys").map(String::as_str),
            Some("urn:opc:test")
        );
    }

    #[test]
    fn parses_edit_data_with_nmda_config() {
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="801"><ncds:edit-data xmlns:ncds="{NETCONF_NMDA_NS}" xmlns:ds="{IETF_DATASTORES_NS}"><ncds:datastore>ds:running</ncds:datastore><ncds:default-operation>replace</ncds:default-operation><ncds:config><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-2</sys:hostname></sys:system></ncds:config></ncds:edit-data></rpc>"#
        );
        let parsed = parse_rpc(&xml, &MgmtLimits::default()).expect("parse edit-data");

        assert_eq!(parsed.message_id, "801");
        let RpcOperation::EditData(request) = parsed.operation else {
            panic!("expected edit-data operation");
        };
        assert_eq!(request.datastore, NmdaDatastore::Running);
        assert_eq!(request.default_operation, EditDefaultOperation::Replace);
        let expected_config = format!(
            r#"<ncds:config xmlns="{NETCONF_BASE_NS}" xmlns:ds="{IETF_DATASTORES_NS}" xmlns:ncds="{NETCONF_NMDA_NS}"><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-2</sys:hostname></sys:system></ncds:config>"#
        );
        assert_eq!(
            request.config_xml.as_deref(),
            Some(expected_config.as_str())
        );
        assert!(!request.url_present);
    }

    #[test]
    fn parses_edit_data_url_without_retaining_url_value() {
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="802"><ncds:edit-data xmlns:ncds="{NETCONF_NMDA_NS}" xmlns:ds="{IETF_DATASTORES_NS}"><ncds:datastore>ds:running</ncds:datastore><ncds:url>https://example.invalid/do-not-leak</ncds:url></ncds:edit-data></rpc>"#
        );
        let parsed = parse_rpc(&xml, &MgmtLimits::default()).expect("parse edit-data url");

        let RpcOperation::EditData(request) = parsed.operation else {
            panic!("expected edit-data operation");
        };
        assert_eq!(request.datastore, NmdaDatastore::Running);
        assert_eq!(request.default_operation, EditDefaultOperation::Merge);
        assert!(request.config_xml.is_none());
        assert!(request.url_present);
    }

    #[test]
    fn edit_data_rejects_config_and_url_choice_collision() {
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="803"><ncds:edit-data xmlns:ncds="{NETCONF_NMDA_NS}" xmlns:ds="{IETF_DATASTORES_NS}"><ncds:datastore>ds:running</ncds:datastore><ncds:config><sys:system xmlns:sys="urn:opc:test"/></ncds:config><ncds:url>https://example.invalid/do-not-leak</ncds:url></ncds:edit-data></rpc>"#
        );
        let err = parse_rpc(&xml, &MgmtLimits::default()).expect_err("choice collision");

        assert_eq!(err, XmlError::DuplicateElement);
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
    fn parses_commit_and_discard_changes() {
        let commit = parse_rpc(&rpc("<commit/>"), &MgmtLimits::default()).expect("parse commit");
        assert_eq!(commit.message_id, "101");
        assert_eq!(
            commit.operation,
            RpcOperation::Commit(CommitRequest {
                confirmed: false,
                confirm_timeout: None,
                persist: None,
                persist_id: None,
            })
        );

        let discard = parse_rpc(&rpc("<discard-changes/>"), &MgmtLimits::default())
            .expect("parse discard-changes");
        assert_eq!(discard.operation, RpcOperation::DiscardChanges);
    }

    #[test]
    fn parses_confirmed_commit_and_cancel_commit() {
        let confirmed = parse_rpc(
            &rpc(
                "<commit><confirmed/><confirm-timeout>30</confirm-timeout><persist>token</persist></commit>",
            ),
            &MgmtLimits::default(),
        )
        .expect("parse confirmed commit");
        assert_eq!(
            confirmed.operation,
            RpcOperation::Commit(CommitRequest {
                confirmed: true,
                confirm_timeout: Some(30),
                persist: Some("token".to_string()),
                persist_id: None,
            })
        );

        let confirm_persistent = parse_rpc(
            &rpc("<commit><persist-id>token</persist-id></commit>"),
            &MgmtLimits::default(),
        )
        .expect("parse persistent confirm");
        assert_eq!(
            confirm_persistent.operation,
            RpcOperation::Commit(CommitRequest {
                confirmed: false,
                confirm_timeout: None,
                persist: None,
                persist_id: Some("token".to_string()),
            })
        );

        let cancel = parse_rpc(
            &rpc("<cancel-commit><persist-id>token</persist-id></cancel-commit>"),
            &MgmtLimits::default(),
        )
        .expect("parse cancel-commit");
        assert_eq!(
            cancel.operation,
            RpcOperation::CancelCommit(CancelCommitRequest {
                persist_id: Some("token".to_string())
            })
        );
    }

    #[test]
    fn parses_copy_config_and_delete_config_datastore_forms() {
        let copy = parse_rpc(
            &rpc(
                "<copy-config><target><startup/></target><source><running/></source></copy-config>",
            ),
            &MgmtLimits::default(),
        )
        .expect("parse copy-config");
        assert_eq!(
            copy.operation,
            RpcOperation::CopyConfig(CopyConfigRequest {
                target: Datastore::Startup,
                source: Datastore::Running,
            })
        );

        let delete = parse_rpc(
            &rpc("<delete-config><target><startup/></target></delete-config>"),
            &MgmtLimits::default(),
        )
        .expect("parse delete-config");
        assert_eq!(
            delete.operation,
            RpcOperation::DeleteConfig(DeleteConfigRequest {
                target: Datastore::Startup,
            })
        );
    }

    #[test]
    fn rejects_inline_copy_config_source_until_inline_config_is_supported() {
        let err = parse_rpc(
            &rpc("<copy-config><target><startup/></target><source><config><sys:system xmlns:sys=\"urn:opc:demo\"/></config></source></copy-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("inline source is unsupported");
        assert_eq!(err, XmlError::Malformed);
    }

    #[test]
    fn rejects_malformed_commit_and_discard_changes() {
        let commit = parse_rpc(
            &rpc("<commit><unsupported/></commit>"),
            &MgmtLimits::default(),
        )
        .expect_err("unsupported commit child");
        assert_eq!(commit, XmlError::Malformed);

        let empty_timeout = parse_rpc(
            &rpc("<commit><confirmed/><confirm-timeout/></commit>"),
            &MgmtLimits::default(),
        )
        .expect_err("empty confirm-timeout");
        assert_eq!(empty_timeout, XmlError::InvalidValue);

        let discard = parse_rpc(
            &rpc(r#"<discard-changes unexpected="value"/>"#),
            &MgmtLimits::default(),
        )
        .expect_err("discard attr");
        assert_eq!(discard, XmlError::Malformed);
    }

    #[test]
    fn parses_lock_and_unlock_running() {
        let lock = parse_rpc(
            &rpc("<lock><target><running/></target></lock>"),
            &MgmtLimits::default(),
        )
        .expect("parse lock");
        assert_eq!(
            lock.operation,
            RpcOperation::Lock(LockRequest {
                target: Datastore::Running
            })
        );

        let unlock = parse_rpc(
            &rpc("<unlock><target><running/></target></unlock>"),
            &MgmtLimits::default(),
        )
        .expect("parse unlock");
        assert_eq!(
            unlock.operation,
            RpcOperation::Unlock(UnlockRequest {
                target: Datastore::Running
            })
        );
    }

    #[test]
    fn parses_validate_running() {
        let parsed = parse_rpc(
            &rpc("<validate><source><running/></source></validate>"),
            &MgmtLimits::default(),
        )
        .expect("parse validate");
        assert_eq!(
            parsed.operation,
            RpcOperation::Validate(ValidateRequest {
                source: Datastore::Running
            })
        );
    }

    #[test]
    fn rejects_invalid_lock_unlock_shape() {
        let missing_target =
            parse_rpc(&rpc("<lock/>"), &MgmtLimits::default()).expect_err("missing lock target");
        assert_eq!(missing_target, XmlError::MissingElement);

        let unexpected_attr = parse_rpc(
            &rpc(r#"<lock xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="merge"><target><running/></target></lock>"#),
            &MgmtLimits::default(),
        )
        .expect_err("lock attr");
        assert_eq!(unexpected_attr, XmlError::Malformed);

        let duplicate_target = parse_rpc(
            &rpc("<unlock><target><running/><candidate/></target></unlock>"),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate unlock target");
        assert_eq!(duplicate_target, XmlError::DuplicateElement);

        let nested_target = parse_rpc(
            &rpc("<lock><target><running><extra/></running></target></lock>"),
            &MgmtLimits::default(),
        )
        .expect_err("nested datastore target");
        assert_eq!(nested_target, XmlError::Malformed);
    }

    #[test]
    fn rejects_invalid_validate_shape() {
        let missing_source = parse_rpc(&rpc("<validate/>"), &MgmtLimits::default())
            .expect_err("missing validate source");
        assert_eq!(missing_source, XmlError::MissingElement);

        let unexpected_attr = parse_rpc(
            &rpc(r#"<validate unexpected="value"><source><running/></source></validate>"#),
            &MgmtLimits::default(),
        )
        .expect_err("validate attr");
        assert_eq!(unexpected_attr, XmlError::Malformed);

        let duplicate_source = parse_rpc(
            &rpc("<validate><source><running/><candidate/></source></validate>"),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate validate source");
        assert_eq!(duplicate_source, XmlError::DuplicateElement);

        let inline_config = parse_rpc(
            &rpc("<validate><source><config><sys:system xmlns:sys=\"urn:opc:demo\"/></config></source></validate>"),
            &MgmtLimits::default(),
        )
        .expect_err("inline config validate not implemented");
        assert_eq!(inline_config, XmlError::Malformed);
    }

    #[test]
    fn parses_kill_session() {
        let parsed = parse_rpc(
            &rpc("<kill-session><session-id>42</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect("parse kill-session");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(
            parsed.operation,
            RpcOperation::KillSession(KillSessionRequest { session_id: 42 })
        );
    }

    #[test]
    fn parses_kill_session_yang_integer_lexical_forms() {
        let with_plus = parse_rpc(
            &rpc("<kill-session><session-id>+42</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect("parse signed lexical form");
        assert_eq!(
            with_plus.operation,
            RpcOperation::KillSession(KillSessionRequest { session_id: 42 })
        );

        let leading_zeros = parse_rpc(
            &rpc("<kill-session><session-id>00042</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect("parse leading-zero XML lexical form");
        assert_eq!(
            leading_zeros.operation,
            RpcOperation::KillSession(KillSessionRequest { session_id: 42 })
        );
    }

    #[test]
    fn rejects_invalid_kill_session_shape_or_value() {
        let missing = parse_rpc(&rpc("<kill-session/>"), &MgmtLimits::default())
            .expect_err("missing session-id");
        assert_eq!(missing, XmlError::MissingElement);

        let duplicate = parse_rpc(
            &rpc(
                "<kill-session><session-id>42</session-id><session-id>43</session-id></kill-session>",
            ),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate session-id");
        assert_eq!(duplicate, XmlError::DuplicateElement);

        let operation_attr = parse_rpc(
            &rpc(r#"<kill-session unexpected="value"><session-id>42</session-id></kill-session>"#),
            &MgmtLimits::default(),
        )
        .expect_err("unexpected kill-session attribute");
        assert_eq!(operation_attr, XmlError::Malformed);

        let session_id_attr = parse_rpc(
            &rpc(r#"<kill-session><session-id unexpected="value">42</session-id></kill-session>"#),
            &MgmtLimits::default(),
        )
        .expect_err("unexpected session-id attribute");
        assert_eq!(session_id_attr, XmlError::Malformed);

        let wrong_namespace = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ncm="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring" message-id="101"><ncm:kill-session><session-id>42</session-id></ncm:kill-session></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong kill-session namespace");
        assert_eq!(wrong_namespace, XmlError::UnknownNamespace);

        let zero = parse_rpc(
            &rpc("<kill-session><session-id>0</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect_err("zero session-id");
        assert_eq!(zero, XmlError::InvalidValue);

        let negative = parse_rpc(
            &rpc("<kill-session><session-id>-1</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect_err("negative session-id");
        assert_eq!(negative, XmlError::InvalidValue);

        let too_large = parse_rpc(
            &rpc("<kill-session><session-id>4294967296</session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect_err("session-id exceeds uint32");
        assert_eq!(too_large, XmlError::InvalidValue);

        let child = parse_rpc(
            &rpc("<kill-session><session-id><nested/></session-id></kill-session>"),
            &MgmtLimits::default(),
        )
        .expect_err("child under session-id");
        assert_eq!(child, XmlError::Malformed);
    }

    #[test]
    fn operation_hints_require_namespace_accepted_reads_but_preserve_kill_context() {
        let wrong_get = parse_rpc_with_context(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:bad="urn:example:bad" message-id="wrong-get"><bad:get/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong namespace get");
        assert_eq!(wrong_get.error, XmlError::UnknownNamespace);
        assert_eq!(wrong_get.operation_hint, None);

        let wrong_get_config = parse_rpc_with_context(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:bad="urn:example:bad" message-id="wrong-get-config"><bad:get-config/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong namespace get-config");
        assert_eq!(wrong_get_config.error, XmlError::UnknownNamespace);
        assert_eq!(wrong_get_config.operation_hint, None);

        let wrong_get_data = parse_rpc_with_context(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:bad="urn:example:bad" message-id="wrong-get-data"><bad:get-data/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong namespace get-data");
        assert_eq!(wrong_get_data.error, XmlError::UnknownNamespace);
        assert_eq!(wrong_get_data.operation_hint, None);

        let wrong_edit_data = parse_rpc_with_context(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:bad="urn:example:bad" message-id="wrong-edit-data"><bad:edit-data/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong namespace edit-data");
        assert_eq!(wrong_edit_data.error, XmlError::UnknownNamespace);
        assert_eq!(wrong_edit_data.operation_hint, None);

        let wrong_kill = parse_rpc_with_context(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:bad="urn:example:bad" message-id="wrong-kill"><bad:kill-session><session-id>42</session-id></bad:kill-session></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("wrong namespace kill-session");
        assert_eq!(wrong_kill.error, XmlError::UnknownNamespace);
        assert_eq!(
            wrong_kill.operation_hint,
            Some(RpcOperationHint::KillSession)
        );
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
    fn parses_create_subscription_default_and_explicit_stream() {
        let default_stream = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="601"><ncn:create-subscription xmlns:ncn="urn:ietf:params:xml:ns:netconf:notification:1.0"/></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect("parse default create-subscription");
        assert_eq!(
            default_stream.operation,
            RpcOperation::CreateSubscription(CreateSubscriptionRequest {
                stream: None,
                filter_present: false,
                start_time: None,
                stop_time: None,
            })
        );

        let explicit_stream = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="602"><create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><stream>NETCONF</stream></create-subscription></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect("parse explicit create-subscription");
        assert_eq!(
            explicit_stream.operation,
            RpcOperation::CreateSubscription(CreateSubscriptionRequest {
                stream: Some("NETCONF".to_string()),
                filter_present: false,
                start_time: None,
                stop_time: None,
            })
        );
    }

    #[test]
    fn create_subscription_records_unsupported_filter_and_replay_fields() {
        let parsed = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="603"><ncn:create-subscription xmlns:ncn="urn:ietf:params:xml:ns:netconf:notification:1.0"><ncn:filter><sys:system xmlns:sys="urn:opc:demo"><sys:hostname><![CDATA[amf-1]]></sys:hostname></sys:system></ncn:filter><ncn:startTime>2026-06-14T00:00:00Z</ncn:startTime><ncn:stopTime>2026-06-14T01:00:00Z</ncn:stopTime></ncn:create-subscription></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect("parse create-subscription with unsupported optional fields");

        assert_eq!(
            parsed.operation,
            RpcOperation::CreateSubscription(CreateSubscriptionRequest {
                stream: None,
                filter_present: true,
                start_time: Some("2026-06-14T00:00:00Z".to_string()),
                stop_time: Some("2026-06-14T01:00:00Z".to_string()),
            })
        );
    }

    #[test]
    fn create_subscription_rejects_empty_or_duplicate_scalars() {
        let empty_stream = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="604"><create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><stream/></create-subscription></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("empty stream");
        assert_eq!(empty_stream, XmlError::InvalidValue);

        let duplicate_stream = parse_rpc(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="605"><create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><stream>NETCONF</stream><stream>NETCONF</stream></create-subscription></rpc>"#,
            &MgmtLimits::default(),
        )
        .expect_err("duplicate stream");
        assert_eq!(duplicate_stream, XmlError::DuplicateElement);
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
    fn parses_edit_config_with_bounded_config_payload() {
        let parsed = parse_rpc(
            &rpc(
                r#"<edit-config><target><running/></target><config><sys:secret xmlns:sys="urn:opc:test">do-not-leak</sys:secret></config></edit-config>"#,
            ),
            &MgmtLimits::default(),
        )
        .expect("parse edit-config");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(
            parsed.operation,
            RpcOperation::EditConfig(EditConfigRequest {
                target: Datastore::Running,
                default_operation: EditDefaultOperation::Merge,
                test_option: EditTestOption::TestThenSet,
                test_option_explicit: false,
                error_option: EditErrorOption::StopOnError,
                config_xml: format!(
                    r#"<config xmlns="{NETCONF_BASE_NS}"><sys:secret xmlns:sys="urn:opc:test">do-not-leak</sys:secret></config>"#
                ),
            })
        );
    }

    #[test]
    fn parses_edit_config_with_bounded_cdata_payload() {
        let parsed = parse_rpc(
            &rpc(
                "<edit-config><target><running/></target><config><![CDATA[do-not-leak]]></config></edit-config>",
            ),
            &MgmtLimits::default(),
        )
        .expect("parse edit-config with CDATA");
        assert_eq!(parsed.message_id, "101");
        assert_eq!(
            parsed.operation,
            RpcOperation::EditConfig(EditConfigRequest {
                target: Datastore::Running,
                default_operation: EditDefaultOperation::Merge,
                test_option: EditTestOption::TestThenSet,
                test_option_explicit: false,
                error_option: EditErrorOption::StopOnError,
                config_xml: format!(
                    r#"<config xmlns="{NETCONF_BASE_NS}"><![CDATA[do-not-leak]]></config>"#
                ),
            })
        );
    }

    #[test]
    fn parses_edit_config_options_and_preserves_config_namespace_context() {
        let parsed = parse_rpc(
            &rpc(
                r#"<edit-config><target><running/></target><default-operation>replace</default-operation><test-option>set</test-option><error-option>continue-on-error</error-option><config xmlns:sys="urn:opc:test"><sys:system/></config></edit-config>"#,
            ),
            &MgmtLimits::default(),
        )
        .expect("parse edit-config options");

        assert_eq!(
            parsed.operation,
            RpcOperation::EditConfig(EditConfigRequest {
                target: Datastore::Running,
                default_operation: EditDefaultOperation::Replace,
                test_option: EditTestOption::Set,
                test_option_explicit: true,
                error_option: EditErrorOption::ContinueOnError,
                config_xml: format!(
                    r#"<config xmlns="{NETCONF_BASE_NS}" xmlns:sys="urn:opc:test"><sys:system></sys:system></config>"#
                ),
            })
        );
    }

    #[test]
    fn rejects_invalid_edit_config_shape() {
        let missing_target = parse_rpc(
            &rpc("<edit-config><config><sys:system xmlns:sys=\"urn:opc:test\"/></config></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("missing edit target");
        assert_eq!(missing_target, XmlError::MissingElement);

        let missing_config = parse_rpc(
            &rpc("<edit-config><target><running/></target></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("missing edit config");
        assert_eq!(missing_config, XmlError::MissingElement);

        let duplicate_target = parse_rpc(
            &rpc("<edit-config><target><running/><candidate/></target><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate edit target");
        assert_eq!(duplicate_target, XmlError::DuplicateElement);

        let duplicate_config = parse_rpc(
            &rpc("<edit-config><target><running/></target><config/><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate edit config");
        assert_eq!(duplicate_config, XmlError::DuplicateElement);

        let invalid_option = parse_rpc(
            &rpc("<edit-config><target><running/></target><error-option>do-not-leak</error-option><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("invalid edit option");
        assert_eq!(invalid_option, XmlError::InvalidValue);

        let empty_default_operation = parse_rpc(
            &rpc("<edit-config><target><running/></target><default-operation/><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("empty default-operation");
        assert_eq!(empty_default_operation, XmlError::InvalidValue);

        let empty_test_option = parse_rpc(
            &rpc("<edit-config><target><running/></target><test-option/><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("empty test-option");
        assert_eq!(empty_test_option, XmlError::InvalidValue);

        let empty_error_option = parse_rpc(
            &rpc("<edit-config><target><running/></target><error-option/><config/></edit-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("empty error-option");
        assert_eq!(empty_error_option, XmlError::InvalidValue);
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
    fn preserves_extra_rpc_reply_attributes_and_rejects_undeclared_attr_prefix() {
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:trace="urn:trace" trace:id="req&amp;1" client-tag="cli" message-id="7"><get/></rpc>"#
        );
        let parsed = parse_rpc(&xml, &MgmtLimits::default()).expect("parse rpc attributes");
        assert_eq!(parsed.message_id, "7");
        assert!(!parsed.reply_attrs.is_empty());

        let err = parse_rpc(
            &format!(
                r#"<rpc xmlns="{NETCONF_BASE_NS}" trace:id="req" message-id="7"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect_err("undeclared attribute prefix");
        assert_eq!(err, XmlError::UnknownNamespace);
    }

    #[test]
    fn parses_client_hello_capabilities() {
        let xml = format!(
            r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability> {} </capability></capabilities></hello>"#,
            crate::capabilities::NETCONF_BASE_1_1
        );
        let hello = parse_client_hello(&xml, &MgmtLimits::default()).expect("parse hello");
        assert_eq!(hello.capabilities, [crate::capabilities::NETCONF_BASE_1_1]);
    }

    #[test]
    fn rejects_structurally_invalid_client_hello_capabilities() {
        let missing = format!(r#"<hello xmlns="{NETCONF_BASE_NS}"/>"#);
        assert_eq!(
            parse_client_hello(&missing, &MgmtLimits::default()).expect_err("missing capabilities"),
            XmlError::MissingElement
        );

        let empty = format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities/></hello>"#);
        assert_eq!(
            parse_client_hello(&empty, &MgmtLimits::default()).expect_err("empty capabilities"),
            XmlError::MissingElement
        );

        let duplicate = format!(
            r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{}</capability></capabilities><capabilities><capability>{}</capability></capabilities></hello>"#,
            crate::capabilities::NETCONF_BASE_1_0,
            crate::capabilities::NETCONF_BASE_1_1
        );
        assert_eq!(
            parse_client_hello(&duplicate, &MgmtLimits::default())
                .expect_err("duplicate capabilities"),
            XmlError::DuplicateElement
        );
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
    fn parses_well_shaped_xpath_filter_envelope() {
        let get_config = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" select="/sys:system/sys:hostname"/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect("parse get-config xpath filter envelope");
        let RpcOperation::GetConfig(request) = get_config.operation else {
            panic!("expected get-config operation");
        };
        let Some(Filter::XPath(xpath)) = request.filter else {
            panic!("expected XPath filter");
        };
        assert_eq!(xpath.select(), "/sys:system/sys:hostname");

        let get = parse_rpc(
            &rpc(r#"<get><filter type="xpath" select="/sys:system/sys:hostname"/></get>"#),
            &MgmtLimits::default(),
        )
        .expect("parse get xpath filter envelope");
        let RpcOperation::Get(request) = get.operation else {
            panic!("expected get operation");
        };
        let Some(Filter::XPath(xpath)) = request.filter else {
            panic!("expected XPath filter");
        };
        assert_eq!(xpath.select(), "/sys:system/sys:hostname");

        let namespaced_select = parse_rpc(
            &rpc(r#"<get><filter xmlns:sys="urn:opc:test" type="xpath" select="/sys:system/sys:hostname"/></get>"#),
            &MgmtLimits::default(),
        )
        .expect("parse xpath filter envelope with namespace declaration");
        let RpcOperation::Get(request) = namespaced_select.operation else {
            panic!("expected get operation");
        };
        let Some(Filter::XPath(xpath)) = request.filter else {
            panic!("expected XPath filter");
        };
        assert_eq!(
            xpath.namespaces().get("sys").map(String::as_str),
            Some("urn:opc:test")
        );
    }

    #[test]
    fn xpath_filter_namespace_declarations_obey_namespace_limit() {
        let limits = MgmtLimits {
            max_xml_namespace_decls: 1,
            ..MgmtLimits::default()
        };
        let err = parse_rpc(
            &rpc(r#"<get><filter xmlns:sys="urn:opc:test" xmlns:if="urn:opc:if" type="xpath" select="/sys:system/if:interfaces"/></get>"#),
            &limits,
        )
        .expect_err("xpath namespace declarations over limit");
        assert_eq!(
            err,
            XmlError::Limit(opc_mgmt_limits::LimitsError::Exceeded {
                limit: "xml_namespace_decls",
                max: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn xpath_filter_select_obeys_byte_limit() {
        let limits = MgmtLimits {
            max_xpath_filter_bytes: 4,
            ..MgmtLimits::default()
        };
        let select = "/sys:system";
        let err = parse_rpc(
            &rpc(&format!(
                r#"<get><filter xmlns:sys="urn:opc:test" type="xpath" select="{select}"/></get>"#
            )),
            &limits,
        )
        .expect_err("xpath select over byte limit");

        assert_eq!(
            err,
            XmlError::Limit(opc_mgmt_limits::LimitsError::Exceeded {
                limit: "xpath_filter_bytes",
                max: 4,
                actual: select.len()
            })
        );
    }

    #[test]
    fn rejects_malformed_xpath_filter_shape_before_operation_dispatch() {
        let missing_select = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath"/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("missing xpath select");
        assert_eq!(missing_select, XmlError::MissingAttribute);

        let empty_select = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" select=" "/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("empty xpath select");
        assert_eq!(empty_select, XmlError::InvalidFilterType);

        let extra_attr = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" select="/sys:system" mode="all"/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("extra xpath attribute");
        assert_eq!(extra_attr, XmlError::InvalidFilterType);

        let get_missing_select = parse_rpc(
            &rpc(r#"<get><filter type="xpath"/></get>"#),
            &MgmtLimits::default(),
        )
        .expect_err("get missing xpath select");
        assert_eq!(get_missing_select, XmlError::MissingAttribute);

        let child_content = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" select="/sys:system"><sys:system xmlns:sys="urn:opc:test"/></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("xpath filter content");
        assert_eq!(child_content, XmlError::UnsupportedFilterContent);

        let duplicate_wire_type = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" type="subtree" select="/sys:system"/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate xpath type attribute");
        assert_eq!(duplicate_wire_type, XmlError::Malformed);

        let duplicate_wire_select = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter type="xpath" select="/sys:system" select="/sys:interfaces"/></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("duplicate xpath select attribute");
        assert_eq!(duplicate_wire_select, XmlError::Malformed);

        assert_eq!(
            filter_kind(&[
                ("type".to_string(), "xpath".to_string()),
                ("type".to_string(), "xpath".to_string()),
                ("select".to_string(), "/sys:system".to_string()),
            ])
            .expect_err("duplicate xpath type"),
            XmlError::InvalidFilterType
        );
        assert_eq!(
            filter_kind(&[
                ("type".to_string(), "xpath".to_string()),
                ("select".to_string(), "/sys:system".to_string()),
                ("select".to_string(), "/sys:interfaces".to_string()),
            ])
            .expect_err("duplicate xpath select"),
            XmlError::InvalidFilterType
        );
    }

    #[test]
    fn rejects_reserved_namespace_binding_misuse() {
        let xml_prefix = parse_rpc(
            &format!(
                r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:xml="urn:opc:test" message-id="101"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect_err("xml prefix rebound");
        assert_eq!(xml_prefix, XmlError::Malformed);

        let xmlns_prefix = parse_rpc(
            &format!(
                r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:xmlns="urn:opc:test" message-id="101"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect_err("xmlns prefix declared");
        assert_eq!(xmlns_prefix, XmlError::Malformed);

        let xml_namespace = parse_rpc(
            &format!(
                r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:p="{XML_NAMESPACE_URI}" message-id="101"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect_err("xml namespace on non-xml prefix");
        assert_eq!(xml_namespace, XmlError::Malformed);
    }

    #[test]
    fn rejects_unexpected_protocol_text() {
        let get_text = parse_rpc(&rpc("<get>do-not-leak</get>"), &MgmtLimits::default())
            .expect_err("unexpected get text");
        assert_eq!(get_text, XmlError::Malformed);

        let get_cdata = parse_rpc(
            &rpc("<get><![CDATA[do-not-leak]]></get>"),
            &MgmtLimits::default(),
        )
        .expect_err("unexpected get CDATA");
        assert_eq!(get_cdata, XmlError::Malformed);

        let source_text = parse_rpc(
            &rpc("<get-config><source>do-not-leak<running/></source></get-config>"),
            &MgmtLimits::default(),
        )
        .expect_err("unexpected source text");
        assert_eq!(source_text, XmlError::Malformed);

        let hello_text = parse_client_hello(
            &format!(
                r#"<hello xmlns="{NETCONF_BASE_NS}">do-not-leak<capabilities><capability>{}</capability></capabilities></hello>"#,
                crate::capabilities::NETCONF_BASE_1_1
            ),
            &MgmtLimits::default(),
        )
        .expect_err("unexpected hello text");
        assert_eq!(hello_text, XmlError::Malformed);
    }

    #[test]
    fn xml_declaration_must_be_the_first_parsed_event() {
        let valid = parse_rpc(
            &format!(
                r#"<?xml version="1.0"?><rpc xmlns="{NETCONF_BASE_NS}" message-id="101"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect("xml declaration before root");
        assert_eq!(valid.message_id, "101");

        let err = parse_rpc_with_context(
            &rpc(r#"<get><?xml version="1.0"?></get>"#),
            &MgmtLimits::default(),
        )
        .expect_err("xml declaration inside rpc");
        assert_eq!(err.message_id.as_deref(), Some("101"));
        assert_eq!(err.error, XmlError::Malformed);

        let comment_before_decl = parse_rpc(
            &format!(
                r#"<!--not-first--><?xml version="1.0"?><rpc xmlns="{NETCONF_BASE_NS}" message-id="101"><get/></rpc>"#
            ),
            &MgmtLimits::default(),
        )
        .expect_err("xml declaration after comment");
        assert_eq!(comment_before_decl, XmlError::Malformed);

        let whitespace_before_decl = parse_rpc(
            &format!(
                "\n<?xml version=\"1.0\"?><rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"101\"><get/></rpc>"
            ),
            &MgmtLimits::default(),
        )
        .expect_err("xml declaration after whitespace");
        assert_eq!(whitespace_before_decl, XmlError::Malformed);
    }

    #[test]
    fn enforces_value_limit_on_non_text_xml_events() {
        let limits = MgmtLimits {
            max_request_bytes: 1024,
            max_value_bytes: 64,
            ..MgmtLimits::default()
        };
        let oversized = "x".repeat(65);

        let comment = parse_rpc(&rpc(&format!("<get/><!--{oversized}-->")), &limits)
            .expect_err("oversized comment");
        assert!(matches!(comment, XmlError::Limit(_)));

        let pi = parse_rpc(&rpc(&format!(r#"<get/><?audit {oversized}?>"#)), &limits)
            .expect_err("oversized PI");
        assert!(matches!(pi, XmlError::Limit(_)));

        let decl = parse_rpc(
            &format!(
                r#"<?xml version="1.0" encoding="{oversized}"?><rpc xmlns="{NETCONF_BASE_NS}" message-id="101"><get/></rpc>"#
            ),
            &limits,
        )
        .expect_err("oversized XML declaration");
        assert!(matches!(decl, XmlError::Limit(_)));
    }

    #[test]
    fn rejects_subtree_filter_content_match_until_supported() {
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-1</sys:hostname></sys:system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("content match not supported yet");
        assert_eq!(err, XmlError::SubtreeFilterContentMatchNotSupported);
    }

    #[test]
    fn parse_context_preserves_message_id_after_rpc_envelope() {
        let err = parse_rpc_with_context(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-1</sys:hostname></sys:system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("content match not supported yet");
        assert_eq!(err.message_id.as_deref(), Some("101"));
        assert_eq!(err.error, XmlError::SubtreeFilterContentMatchNotSupported);

        let legacy = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>amf-1</sys:hostname></sys:system></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("legacy parse error");
        assert_eq!(legacy, XmlError::SubtreeFilterContentMatchNotSupported);
    }

    #[test]
    fn rejects_subtree_filter_attribute_match_until_supported() {
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test" name="amf-1"/></filter></get-config>"#),
            &MgmtLimits::default(),
        )
        .expect_err("attribute match not supported yet");
        assert_eq!(err, XmlError::SubtreeFilterAttributeMatchNotSupported);
    }

    #[test]
    fn subtree_filter_content_match_classification_is_operation_not_supported() {
        let nc = XmlError::SubtreeFilterContentMatchNotSupported.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Protocol);
        assert_eq!(nc.tag, NetconfErrorTag::OperationNotSupported);

        let nc = XmlError::SubtreeFilterAttributeMatchNotSupported.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Protocol);
        assert_eq!(nc.tag, NetconfErrorTag::OperationNotSupported);
    }

    #[test]
    fn subtree_filter_content_match_is_bounded() {
        let limits = MgmtLimits {
            max_subtree_filter_content_match_nodes: 1,
            ..MgmtLimits::default()
        };
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>first</sys:hostname><sys:uptime>second</sys:uptime></sys:system></filter></get-config>"#),
            &limits,
        )
        .expect_err("content match over limit");
        assert!(matches!(err, XmlError::Limit(_)));
    }

    #[test]
    fn subtree_filter_attribute_match_is_bounded() {
        let limits = MgmtLimits {
            max_subtree_filter_attribute_match_nodes: 1,
            ..MgmtLimits::default()
        };
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test" a="1"/><sys:container xmlns:sys="urn:opc:test" b="2"/></filter></get-config>"#),
            &limits,
        )
        .expect_err("attribute match over limit");
        assert!(matches!(err, XmlError::Limit(_)));
    }

    #[test]
    fn subtree_filter_attribute_match_is_bounded_inside_suppressed_content_match() {
        let limits = MgmtLimits {
            max_subtree_filter_attribute_match_nodes: 1,
            ..MgmtLimits::default()
        };
        let err = parse_rpc(
            &rpc(r#"<get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:test"><sys:hostname>content<sys:alt a="first"/><sys:alt b="second"/></sys:hostname></sys:system></filter></get-config>"#),
            &limits,
        )
        .expect_err("nested attribute match over limit");
        assert!(matches!(err, XmlError::Limit(_)));
    }

    #[test]
    fn maps_errors_to_netconf_classifications() {
        let nc = XmlError::DtdForbidden.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Rpc);
        assert_eq!(nc.tag, NetconfErrorTag::MalformedMessage);

        let nc = XmlError::UnknownNamespace.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Protocol);
        assert_eq!(nc.tag, NetconfErrorTag::UnknownNamespace);

        let nc = XmlError::InvalidValue.classification();
        assert_eq!(nc.error_type, NetconfErrorType::Application);
        assert_eq!(nc.tag, NetconfErrorTag::InvalidValue);
    }
}
