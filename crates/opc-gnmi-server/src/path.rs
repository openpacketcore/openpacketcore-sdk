//! gNMI-shaped path normalization through `opc-mgmt-path`.

use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_path::{PathSegment, RequestPath};
use opc_mgmt_schema::{NodeMeta, SchemaRegistry};

use crate::GnmiError;

/// One gNMI `PathElem` represented without protobuf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmiPathElem {
    /// Element name.
    pub name: String,
    /// List key predicates as `(key-name, value)` pairs.
    pub keys: Vec<(String, String)>,
}

impl GnmiPathElem {
    /// Builds a path element with no keys.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            keys: Vec::new(),
        }
    }

    /// Builds a path element with key predicates.
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

/// A gNMI `Path` represented without protobuf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GnmiPath {
    /// gNMI origin.
    pub origin: Option<String>,
    /// gNMI target. Non-empty targets are rejected until the SDK has an explicit
    /// target routing/alias contract.
    pub target: Option<String>,
    /// Path elements.
    pub elems: Vec<GnmiPathElem>,
}

impl GnmiPath {
    /// Builds a path from elements.
    pub fn from_elems(elems: impl IntoIterator<Item = GnmiPathElem>) -> Self {
        Self {
            origin: None,
            target: None,
            elems: elems.into_iter().collect(),
        }
    }

    /// Attaches an origin.
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// Attaches a target. This currently makes resolution fail closed unless the
    /// value is empty.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

/// A schema-resolved gNMI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGnmiPath {
    /// Predicate-free schema path.
    pub schema_path: String,
    /// Canonical SDK instance path with list-key predicates.
    pub canonical: opc_config_model::YangPath,
    /// Target schema node.
    pub node: &'static NodeMeta,
}

/// Resolves one path using an optional gNMI prefix.
pub fn resolve_path(
    registry: &dyn SchemaRegistry,
    prefix: Option<&GnmiPath>,
    path: &GnmiPath,
) -> Result<ResolvedGnmiPath, GnmiError> {
    let request = to_request_path(prefix, path)?;
    let resolved = opc_mgmt_path::resolve(registry, &request)
        .map_err(|err| GnmiError::invalid(err.to_string()))?;
    Ok(ResolvedGnmiPath {
        schema_path: resolved.schema_path,
        canonical: resolved.canonical,
        node: resolved.node,
    })
}

/// Resolves a batch of paths and enforces `max_paths_per_request`.
pub fn resolve_paths(
    registry: &dyn SchemaRegistry,
    limits: &MgmtLimits,
    prefix: Option<&GnmiPath>,
    paths: &[GnmiPath],
) -> Result<Vec<ResolvedGnmiPath>, GnmiError> {
    limits
        .check_paths(paths.len())
        .map_err(GnmiError::from_limits)?;
    paths
        .iter()
        .map(|path| resolve_path(registry, prefix, path))
        .collect()
}

fn to_request_path(prefix: Option<&GnmiPath>, path: &GnmiPath) -> Result<RequestPath, GnmiError> {
    reject_target(prefix)?;
    reject_target(Some(path))?;
    let origin = merge_origin(
        prefix.and_then(|p| p.origin.as_deref()),
        path.origin.as_deref(),
    )?;
    Ok(RequestPath {
        origin,
        prefix: prefix
            .map(|p| p.elems.iter().map(to_segment).collect())
            .unwrap_or_default(),
        elems: path.elems.iter().map(to_segment).collect(),
    })
}

fn reject_target(path: Option<&GnmiPath>) -> Result<(), GnmiError> {
    let Some(target) = path.and_then(|path| path.target.as_deref()) else {
        return Ok(());
    };
    if target.is_empty() {
        Ok(())
    } else {
        Err(GnmiError::unimplemented(
            "non-empty gNMI target is not supported",
        ))
    }
}

fn merge_origin(prefix: Option<&str>, path: Option<&str>) -> Result<Option<String>, GnmiError> {
    match (prefix, path) {
        (Some(a), Some(b)) if a != b => Err(GnmiError::invalid(
            "gNMI prefix origin and path origin differ",
        )),
        (Some(origin), _) | (_, Some(origin)) => Ok(Some(origin.to_string())),
        (None, None) => Ok(None),
    }
}

fn to_segment(elem: &GnmiPathElem) -> PathSegment {
    PathSegment {
        name: elem.name.clone(),
        keys: elem.keys.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeKind, OriginEntry};

    struct TestRegistry;

    static MODELS: &[ModelData] = &[
        ModelData {
            name: "demo-system",
            revision: "2026-06-14",
            namespace: "urn:demo",
            prefix: "sys",
        },
        ModelData {
            name: "other-system",
            revision: "2026-06-14",
            namespace: "urn:other",
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

    static NODES: &[NodeMeta] = &[
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
            child_paths: &["/sys:system/sys:flow", "/sys:system/sys:hostname"],
        },
        NodeMeta {
            path: "/sys:system/sys:flow",
            module: "demo-system",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: &["src", "dst"],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:flow/sys:dst",
                "/sys:system/sys:flow/sys:name",
                "/sys:system/sys:flow/sys:src",
            ],
        },
        leaf("/sys:system/sys:flow/sys:dst"),
        leaf("/sys:system/sys:flow/sys:name"),
        leaf("/sys:system/sys:flow/sys:src"),
        leaf("/sys:system/sys:hostname"),
    ];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:test"
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
    fn resolves_prefix_origin_and_schema_key_order() {
        let prefix = GnmiPath::from_elems([GnmiPathElem::new("system")]).with_origin("demo-system");
        let path = GnmiPath::from_elems([
            GnmiPathElem::with_keys("flow", [("dst", "10.0.0.2"), ("src", "10.0.0.1")]),
            GnmiPathElem::new("name"),
        ]);

        let resolved = resolve_path(&TestRegistry, Some(&prefix), &path).expect("resolved");
        assert_eq!(resolved.schema_path, "/sys:system/sys:flow/sys:name");
        assert_eq!(
            resolved.canonical.as_str(),
            "/sys:system/sys:flow[sys:src='10.0.0.1'][sys:dst='10.0.0.2']/sys:name"
        );
    }

    #[test]
    fn rejects_non_empty_target_until_routing_contract_exists() {
        let path = GnmiPath::from_elems([GnmiPathElem::new("system")]).with_target("node-a");
        let err = resolve_path(&TestRegistry, None, &path).unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
    }

    #[test]
    fn rejects_conflicting_origins_and_path_limit() {
        let prefix = GnmiPath::from_elems([GnmiPathElem::new("system")]).with_origin("demo-system");
        let path =
            GnmiPath::from_elems([GnmiPathElem::new("hostname")]).with_origin("other-system");
        assert!(resolve_path(&TestRegistry, Some(&prefix), &path).is_err());

        let limits = MgmtLimits {
            max_paths_per_request: 1,
            ..MgmtLimits::default()
        };
        let paths = vec![
            GnmiPath::from_elems([GnmiPathElem::new("system")]),
            GnmiPath::from_elems([GnmiPathElem::new("system")]),
        ];
        assert!(resolve_paths(&TestRegistry, &limits, None, &paths).is_err());
    }

    #[test]
    fn errors_do_not_include_key_values() {
        let path = GnmiPath::from_elems([GnmiPathElem::with_keys(
            "hostname",
            [("name", "super-secret")],
        )]);
        let err = resolve_path(&TestRegistry, None, &path).unwrap_err();
        assert!(!err.to_string().contains("super-secret"));
        assert!(!err.detail().unwrap_or_default().contains("super-secret"));
    }
}
