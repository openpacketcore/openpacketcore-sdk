//! Registry-validated, instance-aware canonical YANG path construction for the
//! OpenPacketCore management plane.
//!
//! Both the gNMI and NETCONF servers must turn a northbound path into the SDK
//! canonical commit/audit form
//! `/module:container/module:list[module:key='value']/module:leaf`. [`resolve`]
//! does that once, against the generated [`SchemaRegistry`] (the single schema
//! source, never a hand-built side schema):
//!
//! - applies the request prefix before the per-request elements;
//! - validates the gNMI origin against served modules (unknown origin and a path
//!   outside the origin's modules both fail closed) and uses that origin to
//!   disambiguate otherwise-ambiguous bare paths inside the origin's module set;
//! - resolves the whole path to a real schema node (unknown paths fail closed);
//! - requires schema prefixes to resolve to served models before accepting a
//!   match, so malformed registry/input prefix pairs fail closed;
//! - requires keyed lists to carry exactly their `key` leaves (missing/extra keys
//!   fail closed) and emits them in the schema's `key` order regardless of the
//!   order the client supplied, preserving a prefix-qualified key leaf's prefix
//!   when the registry provides one;
//! - rejects key predicates on non-list segments;
//! - rejects malformed segment names before lookup, so malformed input is never
//!   echoed as an unknown path;
//! - escapes key values once, so callers never hand-concatenate paths.
//!
//! It returns the predicate-free schema path (for registry / NACM lookup) and the
//! instance-aware canonical [`YangPath`] (for commit metadata and audit).
//!
//! [`PathError`] carries node/key *names* and paths for server-side logs, never
//! key *values* (which may be sensitive); the server maps it to a generic
//! client-facing status.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use opc_config_model::YangPath;
use opc_mgmt_schema::{NodeKind, NodeMeta, SchemaRegistry};
use thiserror::Error;

/// One element of a northbound path: a node name (bare or `prefix:name`) and any
/// list-key predicates supplied for it (in arbitrary order; canonicalized here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSegment {
    /// Node name, optionally module-prefixed (`prefix:name`).
    pub name: String,
    /// List key predicates as `(key-name, value)` pairs; key names may be bare
    /// or prefixed and may be supplied in any order.
    pub keys: Vec<(String, String)>,
}

impl PathSegment {
    /// A segment with no key predicates.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            keys: Vec::new(),
        }
    }

    /// A segment carrying list key predicates.
    pub fn with_keys<K, V>(name: impl Into<String>, keys: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            name: name.into(),
            keys: keys
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }
}

/// A northbound request path: an optional gNMI origin, a prefix applied before
/// the elements, and the elements themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestPath {
    /// gNMI origin, if any. `None` for NETCONF.
    pub origin: Option<String>,
    /// Prefix segments applied before [`Self::elems`].
    pub prefix: Vec<PathSegment>,
    /// The request's own path segments.
    pub elems: Vec<PathSegment>,
}

impl RequestPath {
    /// A request path from elements only (no origin, no prefix).
    pub fn from_elems(elems: impl IntoIterator<Item = PathSegment>) -> Self {
        Self {
            origin: None,
            prefix: Vec::new(),
            elems: elems.into_iter().collect(),
        }
    }
}

/// A resolved, validated path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Predicate-free, prefix-qualified schema path (registry / NACM lookup key),
    /// e.g. `/sys:system/sys:user`.
    pub schema_path: String,
    /// Instance-aware canonical path for commit metadata and audit, e.g.
    /// `/sys:system/sys:user[sys:name='admin']`.
    pub canonical: YangPath,
    /// The resolved target node.
    pub node: &'static NodeMeta,
}

/// A path that could not be resolved or validated. Carries names/paths only,
/// never key values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// The request path had no segments.
    #[error("empty path")]
    Empty,
    /// The gNMI origin is not a served module.
    #[error("unknown origin '{0}'")]
    UnknownOrigin(String),
    /// The resolved node is not in the origin's module set.
    #[error("path module '{module}' is outside origin '{origin}'")]
    OriginModuleMismatch {
        /// The requested origin.
        origin: String,
        /// The resolved node's module.
        module: String,
    },
    /// The path does not resolve to a known schema node.
    #[error("unknown path '{0}'")]
    UnknownPath(String),
    /// Key predicates were supplied on a non-list segment.
    #[error("path segment '{path}' is not a list and cannot carry keys")]
    NotAList {
        /// The offending segment path.
        path: String,
    },
    /// A keyed list was missing one or more of its key leaves.
    #[error("list '{list}' is missing keys: {}", missing.join(", "))]
    MissingKeys {
        /// The list node path.
        list: String,
        /// The key leaf names that were not supplied.
        missing: Vec<String>,
    },
    /// A keyed list was given key names that are not its key leaves.
    #[error("list '{list}' has unexpected keys: {}", unexpected.join(", "))]
    UnexpectedKeys {
        /// The list node path.
        list: String,
        /// The supplied key names that are not key leaves.
        unexpected: Vec<String>,
    },
    /// The path was structurally malformed.
    #[error("malformed path: {0}")]
    Malformed(String),
}

/// Resolves and validates a northbound [`RequestPath`] against the schema
/// registry, producing the canonical instance-aware path.
pub fn resolve(
    registry: &dyn SchemaRegistry,
    request: &RequestPath,
) -> Result<ResolvedPath, PathError> {
    let origin_modules = match &request.origin {
        Some(origin) => Some(
            registry
                .modules_for_origin(origin)
                .ok_or_else(|| PathError::UnknownOrigin(origin.clone()))?,
        ),
        None => None,
    };

    let segments: Vec<&PathSegment> = request.prefix.iter().chain(request.elems.iter()).collect();
    if segments.is_empty() {
        return Err(PathError::Empty);
    }

    for seg in &segments {
        validate_segment_name(&seg.name)?;
    }

    let mut lookup = String::new();
    for seg in &segments {
        lookup.push('/');
        lookup.push_str(&seg.name);
    }

    let node = match resolve_node(registry, &segments, None) {
        NodeLookup::Found(node) => node,
        NodeLookup::NotFound | NodeLookup::Ambiguous => {
            match origin_modules.and_then(|modules| {
                match resolve_node(registry, &segments, Some(modules)) {
                    NodeLookup::Found(node) => Some(node),
                    NodeLookup::NotFound | NodeLookup::Ambiguous => None,
                }
            }) {
                Some(node) => node,
                None => return Err(PathError::UnknownPath(lookup.clone())),
            }
        }
    };

    // The resolved node's canonical path has one segment per input element (path
    // normalization preserves segment count), so we can align by index.
    let target_segs: Vec<&str> = node.path.trim_start_matches('/').split('/').collect();
    if target_segs.len() != segments.len() {
        return Err(PathError::UnknownPath(lookup.clone()));
    }

    if let (Some(origin), Some(modules)) = (&request.origin, origin_modules) {
        if !modules.contains(&node.module) {
            return Err(PathError::OriginModuleMismatch {
                origin: origin.clone(),
                module: node.module.to_string(),
            });
        }
    }

    let mut canonical = String::new();
    let mut ancestor = String::new();
    for (i, seg_name) in target_segs.iter().enumerate() {
        ancestor.push('/');
        ancestor.push_str(seg_name);
        canonical.push('/');
        canonical.push_str(seg_name);

        let ancestor_node = registry
            .node(&ancestor)
            .ok_or_else(|| PathError::UnknownPath(ancestor.clone()))?;
        let input_seg = segments[i];

        if matches!(ancestor_node.kind, NodeKind::List) {
            render_keys(registry, seg_name, ancestor_node, input_seg, &mut canonical)?;
        } else if !input_seg.keys.is_empty() {
            return Err(PathError::NotAList {
                path: ancestor.clone(),
            });
        }
    }

    let canonical =
        YangPath::new(canonical).map_err(|err| PathError::Malformed(err.message().to_string()))?;

    Ok(ResolvedPath {
        schema_path: node.path.to_string(),
        canonical,
        node,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeLookup {
    Found(&'static NodeMeta),
    NotFound,
    Ambiguous,
}

fn resolve_node(
    registry: &dyn SchemaRegistry,
    segments: &[&PathSegment],
    allowed_modules: Option<&[&str]>,
) -> NodeLookup {
    let mut matches = registry.nodes().iter().filter(|node| {
        allowed_modules.is_none_or(|modules| modules.contains(&node.module))
            && path_segments_match(registry, node.path, segments)
    });

    let Some(first) = matches.next() else {
        return NodeLookup::NotFound;
    };
    if matches.next().is_some() {
        return NodeLookup::Ambiguous;
    }
    NodeLookup::Found(first)
}

fn path_segments_match(
    registry: &dyn SchemaRegistry,
    schema_path: &str,
    input_segments: &[&PathSegment],
) -> bool {
    let schema_segments: Vec<&str> = schema_path.trim_start_matches('/').split('/').collect();
    schema_segments.len() == input_segments.len()
        && schema_segments
            .iter()
            .zip(input_segments)
            .all(|(schema_seg, input_seg)| segment_matches(registry, schema_seg, &input_seg.name))
}

fn segment_matches(registry: &dyn SchemaRegistry, schema_seg: &str, input_name: &str) -> bool {
    let Some((input_prefix, input_bare)) = parse_qualified_name(input_name) else {
        return false;
    };

    if input_bare != bare_segment(schema_seg) {
        return false;
    }

    let schema_module = match prefix_of(schema_seg) {
        Some(schema_prefix) => match module_for_prefix(registry, schema_prefix) {
            Some(module) => Some(module),
            None => return false,
        },
        None => None,
    };

    let Some(input_prefix) = input_prefix else {
        return true;
    };

    module_for_prefix(registry, input_prefix).is_some_and(|input_module| {
        schema_module.is_some_and(|schema_module| input_module == schema_module)
    })
}

fn validate_segment_name(name: &str) -> Result<(), PathError> {
    parse_qualified_name(name)
        .map(|_| ())
        .ok_or_else(|| PathError::Malformed("invalid path segment".to_string()))
}

/// Validates and renders a list segment's key predicates in `key` order.
fn render_keys(
    registry: &dyn SchemaRegistry,
    seg_name: &str,
    list: &NodeMeta,
    input: &PathSegment,
    out: &mut String,
) -> Result<(), PathError> {
    // Map supplied keys by bare name; reject duplicates and wrong prefixes.
    let mut provided: BTreeMap<&str, &str> = BTreeMap::new();
    for (k, v) in &input.keys {
        let (prefix, bare) = parse_qualified_name(k).ok_or_else(|| {
            PathError::Malformed(format!("invalid key name for list '{}'", list.path))
        })?;
        if !key_prefix_matches(registry, list, prefix, bare) {
            return Err(PathError::UnexpectedKeys {
                list: list.path.to_string(),
                unexpected: vec![k.clone()],
            });
        }
        if provided.insert(bare, v.as_str()).is_some() {
            return Err(PathError::Malformed(format!(
                "duplicate key '{}' for list '{}'",
                bare, list.path
            )));
        }
    }

    let missing: Vec<String> = list
        .key_leaves
        .iter()
        .filter(|kl| !provided.contains_key(bare_segment(kl)))
        .map(|kl| (*kl).to_string())
        .collect();
    if !missing.is_empty() {
        return Err(PathError::MissingKeys {
            list: list.path.to_string(),
            missing,
        });
    }

    let mut unexpected: Vec<String> = provided
        .keys()
        .filter(|name| !list.key_leaves.iter().any(|kl| bare_segment(kl) == **name))
        .map(|name| (*name).to_string())
        .collect();
    if !unexpected.is_empty() {
        unexpected.sort();
        return Err(PathError::UnexpectedKeys {
            list: list.path.to_string(),
            unexpected,
        });
    }

    // Emit in schema `key` order. Today's generator emits bare key names from
    // the YANG key statement, so fall back to the list prefix; if a future
    // registry carries prefix-qualified key leaves, preserve the key leaf's own
    // prefix in the predicate.
    let key_prefix = prefix_of(seg_name);
    for kl in list.key_leaves {
        let bare = bare_segment(kl);
        let value = provided.get(bare).expect("validated present above");
        let escaped = escape_key_value(value);
        match prefix_of(kl).or(key_prefix) {
            Some(prefix) => out.push_str(&format!("[{prefix}:{bare}='{escaped}']")),
            None => out.push_str(&format!("[{bare}='{escaped}']")),
        }
    }

    Ok(())
}

/// Strips a leading module prefix (`prefix:name` -> `name`).
fn bare_segment(seg: &str) -> &str {
    match seg.split_once(':') {
        Some((_, name)) => name,
        None => seg,
    }
}

/// Parses a bare or `prefix:name` identifier used as a path segment or key name.
fn parse_qualified_name(name: &str) -> Option<(Option<&str>, &str)> {
    if name.is_empty()
        || name.trim() != name
        || name.contains('/')
        || name.contains('[')
        || name.contains(']')
        || name.contains('=')
        || name.contains('\'')
        || name.contains('"')
        || name.chars().any(char::is_whitespace)
        || name.chars().any(char::is_control)
    {
        return None;
    }

    match name.split_once(':') {
        Some((prefix, bare)) => {
            if prefix.is_empty() || bare.is_empty() || bare.contains(':') {
                None
            } else {
                Some((Some(prefix), bare))
            }
        }
        None => Some((None, name)),
    }
}

fn key_prefix_matches(
    registry: &dyn SchemaRegistry,
    list: &NodeMeta,
    supplied_prefix: Option<&str>,
    supplied_bare: &str,
) -> bool {
    let Some(expected_key) = list
        .key_leaves
        .iter()
        .find(|key| bare_segment(key) == supplied_bare)
    else {
        return false;
    };

    let Some(supplied_prefix) = supplied_prefix else {
        return true;
    };

    let expected_module = prefix_of(expected_key)
        .and_then(|prefix| module_for_prefix(registry, prefix))
        .unwrap_or(list.module);

    module_for_prefix(registry, supplied_prefix).is_some_and(|module| module == expected_module)
}

fn module_for_prefix(
    registry: &dyn SchemaRegistry,
    prefix_or_module: &str,
) -> Option<&'static str> {
    registry
        .served_models()
        .iter()
        .find(|model| model.prefix == prefix_or_module || model.name == prefix_or_module)
        .map(|model| model.name)
}

/// Returns the module prefix of a `prefix:name` segment, if present.
fn prefix_of(seg: &str) -> Option<&str> {
    seg.split_once(':').map(|(prefix, _)| prefix)
}

/// Escapes a key value for single-quoted predicate form (`\` then `'`), so the
/// SDK path parser round-trips it.
fn escape_key_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, OriginEntry};

    struct TestReg;

    static MODELS: &[ModelData] = &[
        ModelData {
            name: "demo-system",
            revision: "2026-06-13",
            namespace: "urn:opc:demo",
            prefix: "sys",
        },
        ModelData {
            name: "other-system",
            revision: "2026-06-13",
            namespace: "urn:opc:other",
            prefix: "oth",
        },
    ];

    static ORIGINS: &[OriginEntry] = &[
        OriginEntry {
            origin: "",
            modules: &["demo-system", "other-system"],
        },
        OriginEntry {
            origin: "demo-system",
            modules: &["demo-system"],
        },
        OriginEntry {
            origin: "other-system",
            modules: &["other-system"],
        },
    ];

    const fn leaf(path: &'static str) -> NodeMeta {
        NodeMeta {
            path,
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        }
    }

    // Sorted by path.
    static NODES: &[NodeMeta] = &[
        NodeMeta {
            path: "/oth:other",
            module: "other-system",
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
            path: "/oth:system",
            module: "other-system",
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
            path: "/sys:system",
            module: "demo-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:flow",
                "/sys:system/sys:hostname",
                "/sys:system/sys:prefixed-key",
                "/sys:system/sys:user",
            ],
        },
        NodeMeta {
            path: "/sys:system/sys:flow",
            module: "demo-system",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            // Declared key order is src,dst (NOT alphabetical) - proves order
            // preservation when a client supplies them reversed.
            key_leaves: &["src", "dst"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:flow/sys:dst",
                "/sys:system/sys:flow/sys:src",
            ],
        },
        leaf("/sys:system/sys:flow/sys:dst"),
        leaf("/sys:system/sys:flow/sys:src"),
        leaf("/sys:system/sys:hostname"),
        NodeMeta {
            path: "/sys:system/sys:prefixed-key",
            module: "demo-system",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: &["oth:id"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &["/sys:system/sys:prefixed-key/oth:id"],
        },
        NodeMeta {
            path: "/sys:system/sys:prefixed-key/oth:id",
            module: "other-system",
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
            path: "/sys:system/sys:user",
            module: "demo-system",
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
                "/sys:system/sys:user/sys:role",
            ],
        },
        leaf("/sys:system/sys:user/sys:name"),
        leaf("/sys:system/sys:user/sys:role"),
    ];

    impl SchemaRegistry for TestReg {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:0"
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

    struct UnknownPrefixReg;

    static UNKNOWN_PREFIX_NODES: &[NodeMeta] = &[NodeMeta {
        path: "/bad:system",
        module: "demo-system",
        kind: NodeKind::Container,
        config: true,
        leaf_type: None,
        key_leaves: &[],
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }];

    impl SchemaRegistry for UnknownPrefixReg {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:bad"
        }
        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }
        fn nodes(&self) -> &'static [NodeMeta] {
            UNKNOWN_PREFIX_NODES
        }
        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    #[test]
    fn registry_fixture_is_consistent() {
        // Guards the hand-built fixture used by the rest of these tests.
        assert_eq!(TestReg.self_check(), Ok(()));
    }

    #[test]
    fn resolves_bare_keyed_path_to_canonical() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("user", [("name", "admin")]),
            PathSegment::new("role"),
        ]);
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(resolved.schema_path, "/sys:system/sys:user/sys:role");
        assert_eq!(
            resolved.canonical.as_str(),
            "/sys:system/sys:user[sys:name='admin']/sys:role"
        );
        assert_eq!(resolved.node.path, "/sys:system/sys:user/sys:role");
    }

    #[test]
    fn resolves_prefixed_path() {
        let req = RequestPath::from_elems([
            PathSegment::new("sys:system"),
            PathSegment::new("sys:hostname"),
        ]);
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(resolved.canonical.as_str(), "/sys:system/sys:hostname");
    }

    #[test]
    fn prefix_is_applied_before_elements() {
        let req = RequestPath {
            origin: None,
            prefix: vec![PathSegment::new("system")],
            elems: vec![PathSegment::new("hostname")],
        };
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(resolved.canonical.as_str(), "/sys:system/sys:hostname");
    }

    #[test]
    fn multi_key_emitted_in_schema_order_not_input_order() {
        // Client supplies dst then src; canonical must be src then dst.
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("flow", [("dst", "10.0.0.2"), ("src", "10.0.0.1")]),
        ]);
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(
            resolved.canonical.as_str(),
            "/sys:system/sys:flow[sys:src='10.0.0.1'][sys:dst='10.0.0.2']"
        );
    }

    #[test]
    fn key_values_are_escaped_once() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("user", [("name", "o'brien\\x")]),
        ]);
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(
            resolved.canonical.as_str(),
            "/sys:system/sys:user[sys:name='o\\'brien\\\\x']"
        );
    }

    #[test]
    fn prefix_qualified_key_leaf_prefix_is_preserved() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("prefixed-key", [("id", "remote")]),
        ]);
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(
            resolved.canonical.as_str(),
            "/sys:system/sys:prefixed-key[oth:id='remote']"
        );
    }

    #[test]
    fn missing_key_fails_closed() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("flow", [("src", "a")]),
        ]);
        match resolve(&TestReg, &req) {
            Err(PathError::MissingKeys { list, missing }) => {
                assert_eq!(list, "/sys:system/sys:flow");
                assert_eq!(missing, vec!["dst".to_string()]);
            }
            other => panic!("expected MissingKeys, got {other:?}"),
        }
    }

    #[test]
    fn extra_key_fails_closed() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("user", [("name", "a"), ("bogus", "b")]),
        ]);
        match resolve(&TestReg, &req) {
            Err(PathError::UnexpectedKeys { unexpected, .. }) => {
                assert_eq!(unexpected, vec!["bogus".to_string()]);
            }
            other => panic!("expected UnexpectedKeys, got {other:?}"),
        }
    }

    #[test]
    fn keys_on_non_list_fail_closed() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("hostname", [("name", "a")]),
        ]);
        assert!(matches!(
            resolve(&TestReg, &req),
            Err(PathError::NotAList { .. })
        ));
    }

    #[test]
    fn unknown_path_fails_closed() {
        let req = RequestPath::from_elems([PathSegment::new("system"), PathSegment::new("nope")]);
        assert!(matches!(
            resolve(&TestReg, &req),
            Err(PathError::UnknownPath(_))
        ));
    }

    #[test]
    fn malformed_segment_fails_without_echoing_values() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::new("user[name='super-secret-supi']"),
        ]);
        let err = resolve(&TestReg, &req).unwrap_err();
        assert!(matches!(err, PathError::Malformed(_)));
        assert!(!err.to_string().contains("super-secret-supi"));
    }

    #[test]
    fn malformed_key_name_fails_without_echoing_values() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("user", [("name='super-secret-supi'", "also-secret")]),
        ]);
        let err = resolve(&TestReg, &req).unwrap_err();
        assert!(matches!(err, PathError::Malformed(_)));
        assert!(!err.to_string().contains("super-secret-supi"));
        assert!(!err.to_string().contains("also-secret"));
    }

    #[test]
    fn empty_path_fails_closed() {
        assert_eq!(
            resolve(&TestReg, &RequestPath::default()),
            Err(PathError::Empty)
        );
    }

    #[test]
    fn known_origin_in_scope_resolves() {
        let req = RequestPath {
            origin: Some("demo-system".to_string()),
            prefix: vec![],
            elems: vec![PathSegment::new("system"), PathSegment::new("hostname")],
        };
        assert!(resolve(&TestReg, &req).is_ok());
    }

    #[test]
    fn origin_disambiguates_bare_path_within_its_modules() {
        let req = RequestPath {
            origin: Some("demo-system".to_string()),
            prefix: vec![],
            elems: vec![PathSegment::new("system")],
        };
        let resolved = resolve(&TestReg, &req).expect("resolve");
        assert_eq!(resolved.schema_path, "/sys:system");
        assert_eq!(resolved.canonical.as_str(), "/sys:system");
    }

    #[test]
    fn ambiguous_bare_path_without_origin_fails_closed() {
        let req = RequestPath::from_elems([PathSegment::new("system")]);
        assert!(matches!(
            resolve(&TestReg, &req),
            Err(PathError::UnknownPath(_))
        ));
    }

    #[test]
    fn unserved_schema_prefix_fails_closed() {
        let prefixed = RequestPath::from_elems([PathSegment::new("evil:system")]);
        assert!(matches!(
            resolve(&UnknownPrefixReg, &prefixed),
            Err(PathError::UnknownPath(_))
        ));

        let bare = RequestPath::from_elems([PathSegment::new("system")]);
        assert!(matches!(
            resolve(&UnknownPrefixReg, &bare),
            Err(PathError::UnknownPath(_))
        ));
    }

    #[test]
    fn default_origin_spans_all_modules() {
        let req = RequestPath {
            origin: Some("".to_string()),
            prefix: vec![],
            elems: vec![PathSegment::new("oth:other")],
        };
        assert!(resolve(&TestReg, &req).is_ok());
    }

    #[test]
    fn origin_module_mismatch_fails_closed() {
        let req = RequestPath {
            origin: Some("demo-system".to_string()),
            prefix: vec![],
            elems: vec![PathSegment::new("oth:other")],
        };
        match resolve(&TestReg, &req) {
            Err(PathError::OriginModuleMismatch { origin, module }) => {
                assert_eq!(origin, "demo-system");
                assert_eq!(module, "other-system");
            }
            other => panic!("expected OriginModuleMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unknown_origin_fails_closed() {
        let req = RequestPath {
            origin: Some("openconfig".to_string()),
            prefix: vec![],
            elems: vec![PathSegment::new("system")],
        };
        assert!(matches!(
            resolve(&TestReg, &req),
            Err(PathError::UnknownOrigin(_))
        ));
    }

    #[test]
    fn error_messages_carry_no_key_values() {
        // A value-bearing key on a wrong path must not leak the value in the error.
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("hostname", [("name", "super-secret-supi")]),
        ]);
        let err = resolve(&TestReg, &req).unwrap_err();
        assert!(!err.to_string().contains("super-secret-supi"));
    }

    #[test]
    fn wrong_key_prefix_fails_closed_without_leaking_value() {
        let req = RequestPath::from_elems([
            PathSegment::new("system"),
            PathSegment::with_keys("user", [("oth:name", "super-secret-supi")]),
        ]);
        let err = resolve(&TestReg, &req).unwrap_err();
        match &err {
            PathError::UnexpectedKeys { list, unexpected } => {
                assert_eq!(list, "/sys:system/sys:user");
                assert_eq!(unexpected, &vec!["oth:name".to_string()]);
            }
            other => panic!("expected UnexpectedKeys, got {other:?}"),
        }
        assert!(!err.to_string().contains("super-secret-supi"));
    }
}
