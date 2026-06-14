//! Runtime YANG schema-registry contract for the OpenPacketCore management plane.
//!
//! The gNMI and NETCONF servers are generic over the generated root config
//! `C: OpcConfig`. To resolve paths, classify config-vs-state, validate list
//! keys, decode typed values, redact secrets, authorize per RFC 8341, advertise
//! served models, and apply with-defaults, they need a single queryable view of
//! the schema — derived from the **same** canonical source `opc-yanggen` uses for
//! validation and serialization, never a hand-maintained side schema.
//!
//! This crate ships only the value types and the object-safe [`SchemaRegistry`]
//! trait. The query logic (path normalization, lookup, NACM-action derivation,
//! with-defaults selection, integrity self-check) lives in **default methods** so
//! it is implemented and tested once here; a generated registry only supplies the
//! four data accessors ([`SchemaRegistry::schema_digest`],
//! [`SchemaRegistry::served_models`], [`SchemaRegistry::nodes`],
//! [`SchemaRegistry::origins`]). A consuming CNF obtains a
//! `&'static dyn SchemaRegistry` from its generated `schema_registry::registry()`.
//!
//! This crate deliberately does **not** depend on `opc-nacm` (which transitively
//! pulls crypto): it mirrors the five datastore [`NacmAction`] variants locally so
//! generated code stays minimal, and the server maps to `opc_nacm::NacmAction`
//! (identical variant names) at its own boundary.

#![forbid(unsafe_code)]

pub use opc_data_governance::DataClass;

/// Leaf value type, a closed mirror of `opc_yanggen::ir::TypeRef` minus the
/// codegen-rejected `Choice`/`Case` kinds.
///
/// Fail-closed by construction: YANG types the generator cannot represent
/// (`uint64`, `binary`, `union`) have no variant here and never reach the IR, so
/// the registry can never label a leaf with a type the codec does not support.
/// `Custom` records a YANG typedef name verbatim but carries no wire codec — a
/// server must treat it as opaque (and may reject typed-value validation for it)
/// rather than assuming a scalar shape.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafType {
    /// `boolean`
    Boolean,
    /// `string` (and the textual fallback for enumerations/identityref bases)
    String,
    /// `uint16`
    Uint16,
    /// `uint32`
    Uint32,
    /// `int64`
    Int64,
    /// `decimal64` (generator-backed by `f64`; see opc-yanggen)
    Decimal64,
    /// `empty`
    Empty,
    /// `identityref`, with the base identity name.
    IdentityRef {
        /// The base identity the leaf references.
        base: &'static str,
    },
    /// `leafref`, with the target path it points at.
    LeafRef {
        /// The schema path of the referenced leaf.
        target_path: &'static str,
    },
    /// A custom typedef the generator lowered opaquely (no wire codec).
    Custom {
        /// The YANG typedef name.
        name: &'static str,
    },
}

/// The five datastore NACM actions (RFC 8341), mirroring the same-named variants
/// of `opc_nacm::NacmAction`. The server maps to `opc_nacm::NacmAction` at its
/// boundary; this crate stays free of the `opc-nacm` dependency.
///
/// `exec`/`subscribe`/etc. are intentionally absent: this slice models config and
/// state data nodes only (no RPC/notification/action nodes), so advertising them
/// would be an overclaim.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NacmAction {
    /// `read`
    Read,
    /// `create`
    Create,
    /// `update`
    Update,
    /// `replace`
    Replace,
    /// `delete`
    Delete,
}

/// Schema node kind (the data-node kinds the generator supports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// `container`
    Container,
    /// `list`
    List,
    /// `leaf`
    Leaf,
    /// `leaf-list`
    LeafList,
}

/// RFC 6243 with-defaults basis mode requested by a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultReport {
    /// Report all data, including values equal to their schema default.
    ReportAll,
    /// Omit values that equal their schema default.
    Trim,
    /// Report only values explicitly set by a client.
    Explicit,
    /// Report all data and tag schema-defaulted values with a
    /// with-defaults `default="true"` attribute.
    ReportAllTagged,
}

/// RFC 6243 `ietf-netconf-with-defaults` XML namespace URI.
pub const WITH_DEFAULTS_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults";

/// A served YANG module: a gNMI Capabilities `ModelData` row and a NETCONF
/// YANG-Library module entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelData {
    /// Module name.
    pub name: &'static str,
    /// Module revision (`YYYY-MM-DD`), or empty when unrevisioned.
    pub revision: &'static str,
    /// Module XML namespace URI.
    pub namespace: &'static str,
    /// Module prefix.
    pub prefix: &'static str,
}

/// Metadata for one schema (data) node.
///
/// `path` is the canonical absolute schema path as emitted by the generator
/// (prefix-qualified, **no** key predicates). `key_leaves` preserves the YANG
/// `key` order verbatim and is load-bearing for keyed-path validation — it must
/// never be reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeMeta {
    /// Canonical absolute schema path (prefix-qualified, no key predicates).
    pub path: &'static str,
    /// Owning module name.
    pub module: &'static str,
    /// Node kind.
    pub kind: NodeKind,
    /// `true` for config (`rw`) nodes; `false` for state/operational (`ro`).
    pub config: bool,
    /// Leaf value type (`Some` only for `Leaf`/`LeafList`).
    pub leaf_type: Option<LeafType>,
    /// List key leaf names, in YANG `key` order (empty for non-lists / keyless).
    pub key_leaves: &'static [&'static str],
    /// Redaction/data-governance class for this node's values.
    pub data_class: DataClass,
    /// Raw YANG default literal, if any.
    pub default: Option<&'static str>,
    /// `true` if the node declares a default (drives with-defaults).
    pub has_default: bool,
    /// `true` if this is a presence container.
    pub presence: bool,
    /// Child schema paths (sorted).
    pub child_paths: &'static [&'static str],
}

/// A gNMI origin and the module names it spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginEntry {
    /// The origin string (a module name, or `""` for the default origin).
    pub origin: &'static str,
    /// The module names this origin maps to.
    pub modules: &'static [&'static str],
}

/// Conformance of a module entry in a YANG Library module-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleConformance {
    /// The module is implemented by the server.
    Implement,
    /// The module is imported only (not implemented).
    Import,
}

/// An imported module referenced by a YANG module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleImport {
    /// Imported module name.
    pub name: &'static str,
    /// Imported module revision, if known.
    pub revision: Option<&'static str>,
}

/// Extended discovery/source metadata for one served YANG module.
///
/// This is separate from [`ModelData`] so that lightweight registries can keep
/// the small identity row while registries that carry generated discovery data
/// can expose imports/features/deviations/source text through a second table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryMetadata {
    /// Module name (must match a row in [`SchemaRegistry::served_models`]).
    pub name: &'static str,
    /// Module revision (must match the corresponding [`ModelData::revision`]).
    pub revision: &'static str,
    /// Whether the module is implemented or import-only.
    pub conformance: ModuleConformance,
    /// Modules imported by this module.
    pub imports: &'static [ModuleImport],
    /// Features advertised by this module.
    pub features: &'static [&'static str],
    /// Deviation module names applied to this module.
    pub deviations: &'static [&'static str],
    /// Raw YANG source text, available for `<get-schema>` retrieval.
    pub source: Option<&'static str>,
}

/// Failure to retrieve a YANG module source via [`SchemaRegistry::schema_source`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaSourceError {
    /// No module source matches the identifier/version/format.
    NotFound,
    /// More than one module matches the request without a version disambiguator.
    NotUnique,
    /// The requested source format is not supported.
    UnsupportedFormat,
}

impl std::fmt::Display for SchemaSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "schema source not found"),
            Self::NotUnique => write!(f, "schema identifier is ambiguous"),
            Self::UnsupportedFormat => write!(f, "schema source format is not supported"),
        }
    }
}

/// An integrity failure detected by [`SchemaRegistry::self_check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Two nodes share a path.
    DuplicatePath(&'static str),
    /// A node references a child path that no node provides.
    MissingChild {
        /// The parent node path.
        parent: &'static str,
        /// The unresolved child path.
        child: &'static str,
    },
    /// A list's `key` names a leaf that is not a declared child leaf of the list.
    KeyLeafNotChild {
        /// The list node path.
        list: &'static str,
        /// The key leaf name that is not a child leaf.
        key: &'static str,
    },
    /// `nodes()` is not sorted by `path` (the default lookups rely on the
    /// generator emitting a deterministic, sorted table).
    NotSorted(&'static str),
}

const RW_ACTIONS: &[NacmAction] = &[
    NacmAction::Read,
    NacmAction::Create,
    NacmAction::Update,
    NacmAction::Replace,
    NacmAction::Delete,
];
const RO_ACTIONS: &[NacmAction] = &[NacmAction::Read];
const NO_ACTIONS: &[NacmAction] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSchemaPath {
    stripped: String,
    prefixes: Vec<String>,
}

/// Strips a leading module prefix (`prefix:name` -> `name`) from one path segment.
fn bare_segment(seg: &str) -> &str {
    match seg.find(':') {
        Some(i) => &seg[i + 1..],
        None => seg,
    }
}

fn validate_path_token(token: &str) -> Option<()> {
    if token.is_empty()
        || token.trim() != token
        || token.contains('/')
        || token.contains('[')
        || token.contains(']')
    {
        return None;
    }
    Some(())
}

fn collect_segment_prefix(seg: &str, prefixes: &mut Vec<String>) -> Option<()> {
    if seg.is_empty() {
        return Some(());
    }
    if let Some((prefix, name)) = seg.split_once(':') {
        if name.contains(':') {
            return None;
        }
        validate_path_token(prefix)?;
        validate_path_token(name)?;
        prefixes.push(prefix.to_string());
    } else {
        validate_path_token(seg)?;
    }
    Some(())
}

fn collect_predicate_prefix(predicate: &str, prefixes: &mut Vec<String>) -> Option<()> {
    let (lhs, rhs) = predicate.split_once('=')?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    if lhs.is_empty() || rhs.len() < 2 {
        return None;
    }

    let mut rhs_chars = rhs.chars();
    let quote = rhs_chars.next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    if !rhs.ends_with(quote) {
        return None;
    }

    collect_segment_prefix(lhs, prefixes)
}

/// Parses a path and removes `[key='value']` predicates, respecting quotes and
/// escapes so a `]` inside a quoted key value does not prematurely close a
/// predicate. Malformed predicates fail closed instead of normalizing to a valid
/// schema path.
fn parse_schema_path(path: &str) -> Option<ParsedSchemaPath> {
    if !path.starts_with('/') {
        return None;
    }

    let mut out = String::with_capacity(path.len());
    let mut prefixes = Vec::new();
    let mut predicate = String::new();
    let mut in_predicate = false;
    let mut quote: Option<char> = None;
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if in_predicate {
            if let Some(q) = quote {
                predicate.push(c);
                if c == '\\' {
                    let escaped = chars.next()?;
                    predicate.push(escaped);
                } else if c == q {
                    quote = None;
                }
                continue;
            }

            match c {
                '\'' | '"' => {
                    quote = Some(c);
                    predicate.push(c);
                }
                '[' => return None,
                ']' => {
                    collect_predicate_prefix(&predicate, &mut prefixes)?;
                    predicate.clear();
                    in_predicate = false;
                }
                _ => predicate.push(c),
            }
        } else {
            match c {
                '[' => {
                    in_predicate = true;
                    predicate.clear();
                }
                ']' => return None,
                _ => out.push(c),
            }
        }
    }

    if in_predicate || quote.is_some() {
        return None;
    }

    for seg in out.split('/') {
        collect_segment_prefix(seg, &mut prefixes)?;
    }

    Some(ParsedSchemaPath {
        stripped: out,
        prefixes,
    })
}

fn normalize_stripped_path(stripped: &str) -> String {
    let mut out = String::with_capacity(stripped.len());
    for (i, seg) in stripped.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(bare_segment(seg));
    }
    out
}

/// Normalizes a path to the canonical schema-node form used for registry lookup:
/// key predicates removed and each segment stripped to its bare (prefix-free)
/// name. Returns `None` when the path or key predicates are malformed.
pub fn normalize_schema_path(path: &str) -> Option<String> {
    parse_schema_path(path).map(|parsed| normalize_stripped_path(&parsed.stripped))
}

/// Verifies an emitted node table's internal integrity. Exposed so a server may
/// call it once at startup as defense-in-depth against a hand-edited generated
/// file; the generator also runs the equivalent checks at generation time.
pub fn check_registry(nodes: &[NodeMeta]) -> Result<(), RegistryError> {
    for (i, n) in nodes.iter().enumerate() {
        if i > 0 && nodes[i - 1].path > n.path {
            return Err(RegistryError::NotSorted(n.path));
        }
        if nodes[..i].iter().any(|m| m.path == n.path) {
            return Err(RegistryError::DuplicatePath(n.path));
        }
        for &child in n.child_paths {
            if !nodes.iter().any(|m| m.path == child) {
                return Err(RegistryError::MissingChild {
                    parent: n.path,
                    child,
                });
            }
        }
        if matches!(n.kind, NodeKind::List) {
            for &key in n.key_leaves {
                let key_bare = bare_segment(key);
                let is_child_leaf = n.child_paths.iter().any(|&cp| {
                    nodes.iter().any(|m| {
                        m.path == cp
                            && matches!(m.kind, NodeKind::Leaf)
                            && bare_segment(last_segment(m.path)) == key_bare
                    })
                });
                if !is_child_leaf {
                    return Err(RegistryError::KeyLeafNotChild { list: n.path, key });
                }
            }
        }
    }
    Ok(())
}

fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Object-safe runtime view of a generated YANG schema. A server holds a
/// `&'static dyn SchemaRegistry`. Implementors supply the four data accessors;
/// the query methods are provided.
pub trait SchemaRegistry: Send + Sync {
    /// The canonical schema digest string (e.g. `"fnv1a64:...."`), returned
    /// verbatim. This is intentionally **not** parsed into a typed digest: the
    /// generator's digest format is not the 64-hex `opc_types::SchemaDigest`.
    fn schema_digest(&self) -> &'static str;

    /// The served modules (drives gNMI Capabilities and NETCONF YANG-Library).
    fn served_models(&self) -> &'static [ModelData];

    /// All schema nodes, **sorted by `path`** (the generator guarantees this).
    fn nodes(&self) -> &'static [NodeMeta];

    /// The gNMI origin map.
    fn origins(&self) -> &'static [OriginEntry];

    /// Extended discovery/source metadata for the served modules.
    ///
    /// The default empty table means the registry does not carry generated
    /// discovery artifacts; NETCONF YANG Library / monitoring rendering and
    /// `<get-schema>` must then come from a CNF-specific binding hook.
    fn discovery_metadata(&self) -> &'static [DiscoveryMetadata] {
        &[]
    }

    /// Retrieves raw YANG source text for a module identified by name and optional
    /// revision. Only the `yang` format is required; other formats may be rejected
    /// as unsupported.
    ///
    /// The default implementation returns [`SchemaSourceError::NotFound`].
    fn schema_source(
        &self,
        _identifier: &str,
        _version: Option<&str>,
        _format: &str,
    ) -> Result<&'static str, SchemaSourceError> {
        Err(SchemaSourceError::NotFound)
    }

    /// Resolves a (possibly prefixed, possibly keyed) path to its node metadata.
    fn node(&self, schema_path: &str) -> Option<&'static NodeMeta> {
        let parsed = parse_schema_path(schema_path)?;
        if !parsed
            .prefixes
            .iter()
            .all(|prefix| self.is_known_prefix(prefix))
        {
            return None;
        }

        if let Some(node) = self.nodes().iter().find(|n| n.path == parsed.stripped) {
            return Some(node);
        }

        let key = normalize_stripped_path(&parsed.stripped);
        let mut matches = self
            .nodes()
            .iter()
            .filter(|n| normalize_schema_path(n.path).as_deref() == Some(key.as_str()));
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Whether the path resolves to a known schema node.
    fn is_valid_path(&self, schema_path: &str) -> bool {
        self.node(schema_path).is_some()
    }

    /// Whether the path is a config (`rw`) node. `false` for state nodes and for
    /// unknown paths (fail-closed).
    fn is_config_path(&self, schema_path: &str) -> bool {
        self.node(schema_path).is_some_and(|n| n.config)
    }

    /// The list key leaf names, in YANG `key` order, for a list node.
    fn key_leaves(&self, schema_path: &str) -> Option<&'static [&'static str]> {
        self.node(schema_path).map(|n| n.key_leaves)
    }

    /// The leaf value type for a leaf/leaf-list node.
    fn leaf_type(&self, schema_path: &str) -> Option<LeafType> {
        self.node(schema_path).and_then(|n| n.leaf_type)
    }

    /// The redaction data class for a node's values.
    fn data_class(&self, schema_path: &str) -> Option<DataClass> {
        self.node(schema_path).map(|n| n.data_class)
    }

    /// The NACM actions applicable to a path: `read` for every valid path, plus
    /// `create`/`update`/`replace`/`delete` for config paths. Empty for unknown
    /// paths (the caller rejects).
    fn nacm_actions(&self, schema_path: &str) -> &'static [NacmAction] {
        match self.node(schema_path) {
            Some(n) if n.config => RW_ACTIONS,
            Some(_) => RO_ACTIONS,
            None => NO_ACTIONS,
        }
    }

    /// The module names an origin maps to, or `None` for an unknown origin
    /// (fail-closed: the server rejects unmapped origins).
    fn modules_for_origin(&self, origin: &str) -> Option<&'static [&'static str]> {
        self.origins()
            .iter()
            .find(|o| o.origin == origin)
            .map(|o| o.modules)
    }

    /// Whether a prefix/module-name observed in an input path belongs to a served
    /// model. Unknown prefixes fail closed instead of being stripped into a
    /// valid bare schema path.
    fn is_known_prefix(&self, prefix: &str) -> bool {
        self.served_models()
            .iter()
            .any(|model| model.prefix == prefix || model.name == prefix)
    }

    /// The schema default literal to report for a path under a with-defaults
    /// mode. `ReportAll` and `ReportAllTagged` yield the default when one
    /// exists; `Trim`/`Explicit` yield `None` (the server omits
    /// defaulted/non-explicit values).
    fn default_for(&self, schema_path: &str, report: DefaultReport) -> Option<&'static str> {
        match report {
            DefaultReport::ReportAll | DefaultReport::ReportAllTagged => {
                self.node(schema_path).and_then(|n| n.default)
            }
            DefaultReport::Trim | DefaultReport::Explicit => None,
        }
    }

    /// Defense-in-depth integrity check over the node table.
    fn self_check(&self) -> Result<(), RegistryError> {
        check_registry(self.nodes())
    }
}

// ---------------------------------------------------------------------------
// NETCONF XML projection contract
// ---------------------------------------------------------------------------

use opc_config_model::OpcConfig;
use opc_redaction::{redact, RedactionLevel};

/// Failure modes for schema-backed NETCONF XML projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetconfProjectionError {
    /// A schema shape the current generated projection cannot render correctly.
    UnsupportedShape {
        /// Schema-node path that triggered the rejection.
        path: &'static str,
        /// Kind of node that is not supported.
        kind: NodeKind,
    },
    /// A requested with-defaults report mode is not implemented.
    UnsupportedDefaultReport {
        /// The requested report mode.
        report: DefaultReport,
    },
    /// A schema path references a module that is not in the served-model set.
    MissingModule {
        /// Schema-node path that references the missing module.
        path: &'static str,
        /// Module name that has no served-model entry.
        module: &'static str,
    },
    /// Writing the XML fragment failed (e.g. invalid UTF-8).
    WriteError,
}

impl std::fmt::Display for NetconfProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedShape { path, kind } => {
                write!(
                    f,
                    "NETCONF XML projection does not support {kind:?} at {path}"
                )
            }
            Self::UnsupportedDefaultReport { report } => {
                write!(
                    f,
                    "NETCONF XML projection does not support default report {report:?}"
                )
            }
            Self::MissingModule { path, module } => {
                write!(
                    f,
                    "NETCONF XML projection cannot resolve module {module} for {path}"
                )
            }
            Self::WriteError => f.write_str("NETCONF XML projection write failed"),
        }
    }
}

impl std::error::Error for NetconfProjectionError {}

/// Schema-backed NETCONF XML renderer for a generated config root `C`.
///
/// `opc-yanggen` emits an implementation of this trait for the generated root
/// type. A CNF binding returns the renderer through
/// [`opc_netconf_server::binding::NetconfConfigBinding::generated_xml_renderer`]
/// so the server can render running config (and the config part of `<get>`)
/// without hand-written XML projection.
pub trait NetconfXmlRenderer<C: OpcConfig>: Send + Sync {
    /// Render the running-config XML fragment for the authorized `selection`.
    fn render_running_config(
        &self,
        config: &C,
        selection: &[&str],
        report: DefaultReport,
    ) -> Result<String, NetconfProjectionError>;

    /// Reports which with-defaults modes this renderer implements.
    fn supported_default_reports(&self) -> &'static [DefaultReport];
}

/// Context shared by generated NETCONF XML renderers.
///
/// The context is intentionally immutable: generated container renderers build
/// their subtree strings locally and return them, so empty containers can be
/// omitted without buffering an entire document.
#[derive(Clone, Copy)]
pub struct NetconfXmlRenderContext<'a> {
    registry: &'a dyn SchemaRegistry,
    selection: &'a [&'a str],
    report: DefaultReport,
}

impl<'a> NetconfXmlRenderContext<'a> {
    /// Build a render context for the given selection and report mode.
    pub fn new(
        registry: &'a dyn SchemaRegistry,
        selection: &'a [&'a str],
        report: DefaultReport,
    ) -> Self {
        Self {
            registry,
            selection,
            report,
        }
    }

    /// The report mode in effect for this render.
    pub const fn report(&self) -> DefaultReport {
        self.report
    }

    /// Returns whether `path` itself is in the authorized selection.
    pub fn is_selected(&self, path: &str) -> bool {
        self.selection.contains(&path)
    }

    /// Returns whether `path` itself or one of its descendants is selected.
    ///
    /// Generated container renderers use this to decide whether they need to
    /// render a structural parent for an authorized descendant. A selected
    /// ancestor does **not** cover all descendants here: `ReadSelection` is
    /// post-NACM, and structural containers must not authorize sibling leaves.
    pub fn is_subtree_selected(&self, path: &str) -> bool {
        self.selection.iter().any(|p| {
            *p == path
                || p.strip_prefix(path)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }

    /// Schema default literal for `path` under the current report mode.
    pub fn default_for(&self, path: &str) -> Option<&'static str> {
        self.registry.default_for(path, self.report)
    }

    /// Schema default literal for `path`, independent of report mode.
    ///
    /// Generated renderers need this to implement `trim`: a `Defaulted` value
    /// equals the schema default regardless of whether the request asked for
    /// `report-all` or `trim`.
    pub fn schema_default(&self, path: &str) -> Option<&'static str> {
        self.registry.node(path).and_then(|n| n.default)
    }

    /// Node metadata lookup.
    pub fn node(&self, path: &str) -> Option<&'static NodeMeta> {
        self.registry.node(path)
    }

    /// The XML-qualified name (`prefix:local`) for a schema-node path.
    pub fn qualified_name(&self, path: &'static str) -> Result<String, NetconfProjectionError> {
        let node = self
            .registry
            .node(path)
            .ok_or(NetconfProjectionError::UnsupportedShape {
                path,
                kind: NodeKind::Container,
            })?;
        let prefix = self
            .registry
            .served_models()
            .iter()
            .find(|m| m.name == node.module)
            .map(|m| m.prefix)
            .ok_or(NetconfProjectionError::MissingModule {
                path,
                module: node.module,
            })?;
        let local = last_segment(path)
            .split_once(':')
            .map(|(_, name)| name)
            .unwrap_or_else(|| last_segment(path));
        Ok(format!("{prefix}:{local}"))
    }

    /// All `(prefix, namespace)` pairs referenced by the selection, sorted by
    /// prefix so root namespace declarations are deterministic.
    ///
    /// When the report mode is [`DefaultReport::ReportAllTagged`], the RFC 6243
    /// with-defaults namespace is included under a deterministic collision-free
    /// prefix (`wd`, or `wdN` if selected data already uses `wd`).
    pub fn module_namespaces(&self) -> Vec<(String, &'static str)> {
        let mut by_prefix = std::collections::BTreeMap::<String, &'static str>::new();
        for path in self.selection {
            for seg in path.split('/') {
                if seg.is_empty() {
                    continue;
                }
                let module_or_prefix = seg.split_once(':').map(|(pfx, _)| pfx).unwrap_or(seg);
                if let Some(model) = self
                    .registry
                    .served_models()
                    .iter()
                    .find(|m| m.name == module_or_prefix || m.prefix == module_or_prefix)
                {
                    by_prefix.insert(model.prefix.to_string(), model.namespace);
                }
            }
        }
        if self.report == DefaultReport::ReportAllTagged {
            let prefix = with_defaults_prefix(by_prefix.keys().map(String::as_str));
            by_prefix.insert(prefix, WITH_DEFAULTS_NS);
        }
        by_prefix.into_iter().collect()
    }

    /// Format one leaf element with redaction and XML escaping.
    pub fn format_leaf(
        &self,
        path: &'static str,
        raw_value: &str,
    ) -> Result<String, NetconfProjectionError> {
        self.format_leaf_with_default(path, raw_value, false)
    }

    /// Format one leaf element, optionally tagging it as schema-defaulted.
    ///
    /// When `is_defaulted` is `true` and the report mode is
    /// [`DefaultReport::ReportAllTagged`], the element carries the RFC 6243
    /// `default="true"` attribute in the with-defaults namespace. The caller
    /// must ensure the selected with-defaults prefix is declared by the
    /// outermost rendered element (see
    /// [`Self::module_namespaces`]).
    pub fn format_leaf_with_default(
        &self,
        path: &'static str,
        raw_value: &str,
        is_defaulted: bool,
    ) -> Result<String, NetconfProjectionError> {
        let name = self.qualified_name(path)?;
        let data_class = self.registry.data_class(path).unwrap_or(DataClass::Public);
        let value = if data_class.allows_cleartext() {
            raw_value.to_string()
        } else {
            redact(raw_value, data_class, RedactionLevel::Mask, None, None).to_string()
        };
        let default_attr = if is_defaulted && self.report == DefaultReport::ReportAllTagged {
            let used_prefixes = self
                .module_namespaces()
                .into_iter()
                .filter_map(|(prefix, ns)| (ns != WITH_DEFAULTS_NS).then_some(prefix))
                .collect::<Vec<_>>();
            let prefix = with_defaults_prefix(used_prefixes.iter().map(String::as_str));
            format!(r#" {prefix}:default="true""#)
        } else {
            String::new()
        };
        if value.is_empty() {
            Ok(format!("<{name}{default_attr}/>"))
        } else {
            Ok(format!(
                "<{name}{default_attr}>{value}</{name}>",
                value = xml_escape_text(&value)
            ))
        }
    }
}

fn with_defaults_prefix<'a>(used_prefixes: impl IntoIterator<Item = &'a str>) -> String {
    let used = used_prefixes
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if !used.contains("wd") {
        return "wd".to_string();
    }
    for idx in 1usize.. {
        let candidate = format!("wd{idx}");
        if !used.contains(candidate.as_str()) {
            return candidate;
        }
    }
    unreachable!("unbounded prefix search must find a free with-defaults prefix")
}

/// XML-escape text content.
pub fn xml_escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// XML-escape an attribute value.
pub fn xml_escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_object_safe(_: &dyn SchemaRegistry) {}

    // A hand-built registry standing in for generated output, so the query
    // engine is fully exercised without invoking the code generator.
    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "test-system",
        revision: "2026-06-13",
        namespace: "urn:opc:test:system",
        prefix: "sys",
    }];

    // Sorted by `path`.
    static NODES: &[NodeMeta] = &[
        NodeMeta {
            path: "/sys:system",
            module: "test-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &["/sys:system/sys:hostname", "/sys:system/sys:user"],
        },
        NodeMeta {
            path: "/sys:system/sys:hostname",
            module: "test-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: Some("localhost"),
            has_default: true,
            presence: false,
            child_paths: &[],
        },
        // NB: sorted by verbatim path — "uptime" precedes "user" ('p' < 's').
        NodeMeta {
            path: "/sys:system/sys:uptime",
            module: "test-system",
            kind: NodeKind::Leaf,
            config: false,
            leaf_type: Some(LeafType::Int64),
            key_leaves: &[],
            data_class: DataClass::Operational,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:user",
            module: "test-system",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: &["name"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:user/sys:name",
                "/sys:system/sys:user/sys:secret",
            ],
        },
        NodeMeta {
            path: "/sys:system/sys:user/sys:name",
            module: "test-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:user/sys:secret",
            module: "test-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::SecuritySecret,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
    ];

    static ORIGINS: &[OriginEntry] = &[
        OriginEntry {
            origin: "",
            modules: &["test-system"],
        },
        OriginEntry {
            origin: "test-system",
            modules: &["test-system"],
        },
    ];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:0123456789abcdef"
        }
        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }
        fn nodes(&self) -> &'static [NodeMeta] {
            NODES
        }
        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    #[test]
    fn object_safe() {
        _assert_object_safe(&TestRegistry);
    }

    #[test]
    fn normalization_strips_prefixes_and_keys() {
        assert_eq!(
            normalize_schema_path("/sys:system/sys:hostname").as_deref(),
            Some("/system/hostname")
        );
        assert_eq!(
            normalize_schema_path("/sys:system/sys:user[sys:name='alice']/sys:secret").as_deref(),
            Some("/system/user/secret")
        );
        // A `]` inside a quoted key value must not end the predicate early.
        assert_eq!(
            normalize_schema_path("/sys:system/sys:user[name='a]b']/sys:name").as_deref(),
            Some("/system/user/name")
        );
    }

    #[test]
    fn malformed_paths_do_not_normalize_to_known_nodes() {
        let reg = TestRegistry;

        for path in [
            "system/hostname",
            "/sys:system/sys:user[sys:name='alice'/sys:secret",
            "/sys:system/sys:user[sys:name=alice]/sys:secret",
            "/sys:system/sys:user[sys:name='alice']/sys:secret]",
            "/sys:system/sys:user[sys:name='alice'[sys:other='x']]/sys:secret",
        ] {
            assert_eq!(normalize_schema_path(path), None, "path normalized: {path}");
            assert_eq!(reg.node(path), None, "path resolved: {path}");
        }
    }

    #[test]
    fn lookup_resolves_prefixed_and_keyed_paths() {
        let reg = TestRegistry;
        // Bare, prefixed, and keyed forms all resolve to the same node.
        assert!(reg.node("/system/hostname").is_some());
        assert!(reg.node("/sys:system/sys:hostname").is_some());
        assert!(reg
            .node("/sys:system/sys:user[name='alice']/sys:secret")
            .is_some());
        assert!(reg
            .node("/sys:system/sys:user[sys:name='alice']/sys:secret")
            .is_some());
        assert!(reg
            .node("/bogus:system/sys:user[sys:name='alice']/sys:secret")
            .is_none());
        assert!(reg
            .node("/sys:system/sys:user[bogus:name='alice']/sys:secret")
            .is_none());
        assert!(reg.node("/system/bogus").is_none());
        assert!(!reg.is_valid_path("/nope"));
    }

    #[test]
    fn config_state_and_nacm_classification() {
        let reg = TestRegistry;
        assert!(reg.is_config_path("/system/hostname"));
        assert!(!reg.is_config_path("/system/uptime")); // state
        assert!(!reg.is_config_path("/system/bogus")); // unknown -> false (fail-closed)

        // Config node: read + create/update/replace/delete.
        let cfg = reg.nacm_actions("/system/hostname");
        assert!(cfg.contains(&NacmAction::Read));
        assert!(cfg.contains(&NacmAction::Create));
        assert!(cfg.contains(&NacmAction::Delete));
        // State node: read only.
        assert_eq!(reg.nacm_actions("/system/uptime"), &[NacmAction::Read]);
        // Unknown: no actions.
        assert!(reg.nacm_actions("/system/bogus").is_empty());
    }

    #[test]
    fn key_leaves_leaf_type_data_class_and_defaults() {
        let reg = TestRegistry;
        assert_eq!(reg.key_leaves("/system/user"), Some(&["name"][..]));
        assert_eq!(reg.key_leaves("/system/hostname"), Some(&[][..]));
        assert_eq!(reg.leaf_type("/system/uptime"), Some(LeafType::Int64));
        assert_eq!(reg.leaf_type("/system/user"), None); // list has no leaf type
        assert_eq!(
            reg.data_class("/system/user/secret"),
            Some(DataClass::SecuritySecret)
        );
        assert_eq!(
            reg.default_for("/system/hostname", DefaultReport::ReportAll),
            Some("localhost")
        );
        assert_eq!(
            reg.default_for("/system/hostname", DefaultReport::Trim),
            None
        );
    }

    #[test]
    fn origins_resolve_and_fail_closed() {
        let reg = TestRegistry;
        assert_eq!(reg.modules_for_origin(""), Some(&["test-system"][..]));
        assert_eq!(
            reg.modules_for_origin("test-system"),
            Some(&["test-system"][..])
        );
        assert_eq!(reg.modules_for_origin("openconfig"), None); // unknown -> fail closed
    }

    #[test]
    fn served_models_and_digest() {
        let reg = TestRegistry;
        assert_eq!(reg.served_models().len(), 1);
        assert_eq!(reg.served_models()[0].name, "test-system");
        assert!(reg.schema_digest().starts_with("fnv1a64:"));
    }

    #[test]
    fn self_check_accepts_consistent_table() {
        assert_eq!(TestRegistry.self_check(), Ok(()));
    }

    #[test]
    fn check_registry_rejects_corrupt_tables() {
        // Duplicate path.
        static DUP: &[NodeMeta] = &[
            NodeMeta {
                path: "/a",
                module: "m",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
            NodeMeta {
                path: "/a",
                module: "m",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];
        assert_eq!(check_registry(DUP), Err(RegistryError::DuplicatePath("/a")));

        // Missing child.
        static MISSING: &[NodeMeta] = &[NodeMeta {
            path: "/a",
            module: "m",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &["/a/b"],
        }];
        assert_eq!(
            check_registry(MISSING),
            Err(RegistryError::MissingChild {
                parent: "/a",
                child: "/a/b"
            })
        );

        // List key leaf that is not a declared child leaf.
        static BAD_KEY: &[NodeMeta] = &[NodeMeta {
            path: "/l",
            module: "m",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: &["id"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        }];
        assert_eq!(
            check_registry(BAD_KEY),
            Err(RegistryError::KeyLeafNotChild {
                list: "/l",
                key: "id"
            })
        );

        // Not sorted by path.
        static UNSORTED: &[NodeMeta] = &[
            NodeMeta {
                path: "/b",
                module: "m",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
            NodeMeta {
                path: "/a",
                module: "m",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];
        assert_eq!(
            check_registry(UNSORTED),
            Err(RegistryError::NotSorted("/a"))
        );
    }

    #[test]
    fn bare_lookup_fails_closed_when_modules_collide() {
        struct CollidingRegistry;

        static MODELS: &[ModelData] = &[
            ModelData {
                name: "a",
                revision: "",
                namespace: "urn:a",
                prefix: "a",
            },
            ModelData {
                name: "b",
                revision: "",
                namespace: "urn:b",
                prefix: "b",
            },
        ];
        static NODES: &[NodeMeta] = &[
            NodeMeta {
                path: "/a:root/a:leaf",
                module: "a",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
            NodeMeta {
                path: "/b:root/b:leaf",
                module: "b",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];

        impl SchemaRegistry for CollidingRegistry {
            fn schema_digest(&self) -> &'static str {
                "fnv1a64:feedfacefeedface"
            }
            fn served_models(&self) -> &'static [ModelData] {
                MODELS
            }
            fn nodes(&self) -> &'static [NodeMeta] {
                NODES
            }
            fn origins(&self) -> &'static [OriginEntry] {
                &[]
            }
        }

        let reg = CollidingRegistry;
        assert_eq!(reg.node("/root/leaf"), None);
        assert_eq!(reg.node("/a:root/a:leaf").map(|n| n.module), Some("a"));
        assert_eq!(reg.node("/b:root/b:leaf").map(|n| n.module), Some("b"));
    }

    #[test]
    fn xml_escaping_obeys_basic_rules() {
        assert_eq!(xml_escape_text("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(
            xml_escape_attr(r#"value "quoted""#),
            "value &quot;quoted&quot;"
        );
    }

    #[test]
    fn render_context_selection_predicates() {
        static MODELS: &[ModelData] = &[ModelData {
            name: "example",
            revision: "",
            namespace: "urn:example",
            prefix: "ex",
        }];
        static NODES: &[NodeMeta] = &[
            NodeMeta {
                path: "/ex:system",
                module: "example",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &["/ex:system/ex:hostname"],
            },
            NodeMeta {
                path: "/ex:system/ex:hostname",
                module: "example",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];

        struct TestRegistry;
        impl SchemaRegistry for TestRegistry {
            fn schema_digest(&self) -> &'static str {
                "digest"
            }
            fn served_models(&self) -> &'static [ModelData] {
                MODELS
            }
            fn nodes(&self) -> &'static [NodeMeta] {
                NODES
            }
            fn origins(&self) -> &'static [OriginEntry] {
                &[]
            }
        }

        let reg = TestRegistry;
        let selection: &[&str] = &["/ex:system", "/ex:system/ex:hostname"];
        let ctx = NetconfXmlRenderContext::new(&reg, selection, DefaultReport::Trim);

        assert!(ctx.is_selected("/ex:system/ex:hostname"));
        assert!(!ctx.is_selected("/ex:system/ex:missing"));
        assert!(ctx.is_subtree_selected("/ex:system"));
        assert!(!ctx.is_subtree_selected("/ex:other"));

        // A selected ancestor is only structural; it must not authorize every
        // descendant under the same container.
        let root_ctx = NetconfXmlRenderContext::new(&reg, &["/ex:system"], DefaultReport::Trim);
        assert!(!root_ctx.is_subtree_selected("/ex:system/ex:hostname"));
        assert!(root_ctx.is_subtree_selected("/ex:system"));
        assert!(!root_ctx.is_subtree_selected("/ex:other"));
    }

    #[test]
    fn render_context_qualified_name_and_namespaces() {
        static MODELS: &[ModelData] = &[
            ModelData {
                name: "example",
                revision: "",
                namespace: "urn:example",
                prefix: "ex",
            },
            ModelData {
                name: "other",
                revision: "",
                namespace: "urn:other",
                prefix: "ot",
            },
        ];
        static NODES: &[NodeMeta] = &[
            NodeMeta {
                path: "/ex:system",
                module: "example",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &["/ex:system/ex:hostname", "/ex:system/ot:neighbor"],
            },
            NodeMeta {
                path: "/ex:system/ex:hostname",
                module: "example",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
            NodeMeta {
                path: "/ex:system/ot:neighbor",
                module: "other",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];

        struct TestRegistry;
        impl SchemaRegistry for TestRegistry {
            fn schema_digest(&self) -> &'static str {
                "digest"
            }
            fn served_models(&self) -> &'static [ModelData] {
                MODELS
            }
            fn nodes(&self) -> &'static [NodeMeta] {
                NODES
            }
            fn origins(&self) -> &'static [OriginEntry] {
                &[]
            }
        }

        let reg = TestRegistry;
        let selection: &[&str] = &["/ex:system/ex:hostname", "/ex:system/ot:neighbor"];
        let ctx = NetconfXmlRenderContext::new(&reg, selection, DefaultReport::Trim);

        assert_eq!(
            ctx.qualified_name("/ex:system/ex:hostname").unwrap(),
            "ex:hostname"
        );
        assert_eq!(
            ctx.qualified_name("/ex:system/ot:neighbor").unwrap(),
            "ot:neighbor"
        );

        let ns = ctx.module_namespaces();
        assert_eq!(
            ns,
            vec![
                ("ex".to_string(), "urn:example"),
                ("ot".to_string(), "urn:other")
            ]
        );
    }

    #[test]
    fn report_all_tagged_namespace_avoids_selected_module_prefix_collision() {
        static MODELS: &[ModelData] = &[
            ModelData {
                name: "example",
                revision: "",
                namespace: "urn:example",
                prefix: "ex",
            },
            ModelData {
                name: "with-default-prefix",
                revision: "",
                namespace: "urn:with-default-prefix",
                prefix: "wd",
            },
        ];
        static NODES: &[NodeMeta] = &[
            NodeMeta {
                path: "/ex:system",
                module: "example",
                kind: NodeKind::Container,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &["/ex:system/wd:colliding-default"],
            },
            NodeMeta {
                path: "/ex:system/wd:colliding-default",
                module: "with-default-prefix",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: Some("collision"),
                has_default: true,
                presence: false,
                child_paths: &[],
            },
        ];

        struct TestRegistry;
        impl SchemaRegistry for TestRegistry {
            fn schema_digest(&self) -> &'static str {
                "digest"
            }
            fn served_models(&self) -> &'static [ModelData] {
                MODELS
            }
            fn nodes(&self) -> &'static [NodeMeta] {
                NODES
            }
            fn origins(&self) -> &'static [OriginEntry] {
                &[]
            }
        }

        let reg = TestRegistry;
        let selection: &[&str] = &["/ex:system/wd:colliding-default"];
        let ctx = NetconfXmlRenderContext::new(&reg, selection, DefaultReport::ReportAllTagged);

        assert_eq!(
            ctx.module_namespaces(),
            vec![
                ("ex".to_string(), "urn:example"),
                ("wd".to_string(), "urn:with-default-prefix"),
                ("wd1".to_string(), WITH_DEFAULTS_NS),
            ]
        );
        assert_eq!(
            ctx.format_leaf_with_default("/ex:system/wd:colliding-default", "collision", true)
                .unwrap(),
            r#"<wd:colliding-default wd1:default="true">collision</wd:colliding-default>"#
        );
    }

    #[test]
    fn format_leaf_redacts_security_secret() {
        static MODELS: &[ModelData] = &[ModelData {
            name: "example",
            revision: "",
            namespace: "urn:example",
            prefix: "ex",
        }];
        static NODES: &[NodeMeta] = &[
            NodeMeta {
                path: "/ex:secret",
                module: "example",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::SecuritySecret,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
            NodeMeta {
                path: "/ex:hostname",
                module: "example",
                kind: NodeKind::Leaf,
                config: true,
                leaf_type: Some(LeafType::String),
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: &[],
            },
        ];

        struct TestRegistry;
        impl SchemaRegistry for TestRegistry {
            fn schema_digest(&self) -> &'static str {
                "digest"
            }
            fn served_models(&self) -> &'static [ModelData] {
                MODELS
            }
            fn nodes(&self) -> &'static [NodeMeta] {
                NODES
            }
            fn origins(&self) -> &'static [OriginEntry] {
                &[]
            }
        }

        let reg = TestRegistry;
        let ctx = NetconfXmlRenderContext::new(&reg, &[], DefaultReport::Trim);

        let public = ctx.format_leaf("/ex:hostname", "router1").unwrap();
        assert_eq!(public, "<ex:hostname>router1</ex:hostname>");

        let secret = ctx.format_leaf("/ex:secret", "hunter2").unwrap();
        assert!(!secret.contains("hunter2"));
        assert!(secret.starts_with("<ex:secret>"));
        assert!(secret.ends_with("</ex:secret>"));
    }
}
