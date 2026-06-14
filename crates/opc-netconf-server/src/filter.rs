//! Schema-aware NETCONF filter projection.

use opc_mgmt_errors::{NetconfError, NetconfErrorTag, NetconfErrorType};
use opc_mgmt_schema::{
    DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};
use thiserror::Error;

use crate::capabilities::NETCONF_MONITORING_NS;
use crate::error::RpcError;
use crate::xml::{Filter, SubtreeFilter, SubtreeSelection};

/// RFC 8525 `ietf-yang-library` XML namespace.
pub const YANG_LIBRARY_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-yang-library";
/// RFC 8525 `ietf-yang-library` module name.
pub const YANG_LIBRARY_MODULE: &str = "ietf-yang-library";
/// Conventional prefix used by the built-in YANG Library registry.
pub const YANG_LIBRARY_PREFIX: &str = "yanglib";
/// RFC 6022 `ietf-netconf-monitoring` module name.
pub const NETCONF_MONITORING_MODULE: &str = "ietf-netconf-monitoring";
/// Conventional prefix used by the built-in NETCONF monitoring registry.
pub const NETCONF_MONITORING_PREFIX: &str = "ncm";

const YANG_LIBRARY_MODEL: &[ModelData] = &[ModelData {
    name: YANG_LIBRARY_MODULE,
    revision: "2019-01-04",
    namespace: YANG_LIBRARY_NS,
    prefix: YANG_LIBRARY_PREFIX,
}];

const YANG_LIBRARY_ORIGINS: &[OriginEntry] = &[OriginEntry {
    origin: "",
    modules: &[YANG_LIBRARY_MODULE],
}];

const fn yang_library_node(
    path: &'static str,
    kind: NodeKind,
    leaf_type: Option<LeafType>,
    key_leaves: &'static [&'static str],
    child_paths: &'static [&'static str],
) -> NodeMeta {
    NodeMeta {
        path,
        module: YANG_LIBRARY_MODULE,
        kind,
        config: false,
        leaf_type,
        key_leaves,
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths,
    }
}

static YANG_LIBRARY_NODES: &[NodeMeta] = &[
    yang_library_node(
        "/yanglib:yang-library",
        NodeKind::Container,
        None,
        &[],
        &[
            "/yanglib:yang-library/yanglib:content-id",
            "/yanglib:yang-library/yanglib:datastore",
            "/yanglib:yang-library/yanglib:module-set",
            "/yanglib:yang-library/yanglib:schema",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:content-id",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:datastore",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:datastore/yanglib:name",
            "/yanglib:yang-library/yanglib:datastore/yanglib:schema",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:datastore/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::IdentityRef { base: "datastore" }),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:datastore/yanglib:schema",
        NodeKind::Leaf,
        Some(LeafType::LeafRef {
            target_path: "/yanglib:yang-library/yanglib:schema/yanglib:name",
        }),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module",
            "/yanglib:yang-library/yanglib:module-set/yanglib:name",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module",
        NodeKind::List,
        None,
        &["name", "revision"],
        &[
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:location",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:name",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:namespace",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:revision",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:location",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:namespace",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:revision",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:location",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:name",
            "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:revision",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:location",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:submodule/yanglib:revision",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:deviation",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:feature",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:location",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:name",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:namespace",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:revision",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:deviation",
        NodeKind::LeafList,
        Some(LeafType::LeafRef {
            target_path: "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:name",
        }),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:feature",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:location",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:namespace",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:revision",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:location",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:name",
            "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:revision",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:location",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:submodule/yanglib:revision",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:module-set/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:schema",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/yanglib:yang-library/yanglib:schema/yanglib:module-set",
            "/yanglib:yang-library/yanglib:schema/yanglib:name",
        ],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:schema/yanglib:module-set",
        NodeKind::LeafList,
        Some(LeafType::LeafRef {
            target_path: "/yanglib:yang-library/yanglib:module-set/yanglib:name",
        }),
        &[],
        &[],
    ),
    yang_library_node(
        "/yanglib:yang-library/yanglib:schema/yanglib:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
];

const NETCONF_MONITORING_MODEL: &[ModelData] = &[ModelData {
    name: NETCONF_MONITORING_MODULE,
    revision: "2010-10-04",
    namespace: NETCONF_MONITORING_NS,
    prefix: NETCONF_MONITORING_PREFIX,
}];

const NETCONF_MONITORING_ORIGINS: &[OriginEntry] = &[OriginEntry {
    origin: "",
    modules: &[NETCONF_MONITORING_MODULE],
}];

const fn netconf_monitoring_node(
    path: &'static str,
    kind: NodeKind,
    leaf_type: Option<LeafType>,
    key_leaves: &'static [&'static str],
    child_paths: &'static [&'static str],
) -> NodeMeta {
    NodeMeta {
        path,
        module: NETCONF_MONITORING_MODULE,
        kind,
        config: false,
        leaf_type,
        key_leaves,
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths,
    }
}

static NETCONF_MONITORING_NODES: &[NodeMeta] = &[
    netconf_monitoring_node(
        "/ncm:netconf-state",
        NodeKind::Container,
        None,
        &[],
        &[
            "/ncm:netconf-state/ncm:capabilities",
            "/ncm:netconf-state/ncm:datastores",
            "/ncm:netconf-state/ncm:schemas",
            "/ncm:netconf-state/ncm:sessions",
            "/ncm:netconf-state/ncm:statistics",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:capabilities",
        NodeKind::Container,
        None,
        &[],
        &["/ncm:netconf-state/ncm:capabilities/ncm:capability"],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:capabilities/ncm:capability",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores",
        NodeKind::Container,
        None,
        &[],
        &["/ncm:netconf-state/ncm:datastores/ncm:datastore"],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore",
        NodeKind::List,
        None,
        &["name"],
        &[
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:name",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks",
        NodeKind::Container,
        None,
        &[],
        &[
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock",
        NodeKind::Container,
        None,
        &[],
        &[
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock/ncm:locked-by-session",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock/ncm:locked-time",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock/ncm:locked-by-session",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:global-lock/ncm:locked-time",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock",
        NodeKind::List,
        None,
        &["lock-id"],
        &[
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:lock-id",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:locked-by-session",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:locked-time",
            "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:select",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:lock-id",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:locked-by-session",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:locked-time",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:locks/ncm:partial-lock/ncm:select",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:datastores/ncm:datastore/ncm:name",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas",
        NodeKind::Container,
        None,
        &[],
        &["/ncm:netconf-state/ncm:schemas/ncm:schema"],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema",
        NodeKind::List,
        None,
        &["identifier", "version", "format"],
        &[
            "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format",
            "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier",
            "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location",
            "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace",
            "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format",
        NodeKind::Leaf,
        Some(LeafType::IdentityRef {
            base: "schema-format",
        }),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location",
        NodeKind::LeafList,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions",
        NodeKind::Container,
        None,
        &[],
        &["/ncm:netconf-state/ncm:sessions/ncm:session"],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session",
        NodeKind::List,
        None,
        &["session-id"],
        &[
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:in-bad-rpcs",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:in-rpcs",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:login-time",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:out-notifications",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:out-rpc-errors",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:session-id",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:source-host",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:transport",
            "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:username",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:in-bad-rpcs",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:in-rpcs",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:login-time",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:out-notifications",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:out-rpc-errors",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:session-id",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:source-host",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:transport",
        NodeKind::Leaf,
        Some(LeafType::IdentityRef { base: "transport" }),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:sessions/ncm:session/ncm:username",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics",
        NodeKind::Container,
        None,
        &[],
        &[
            "/ncm:netconf-state/ncm:statistics/ncm:dropped-sessions",
            "/ncm:netconf-state/ncm:statistics/ncm:in-bad-hellos",
            "/ncm:netconf-state/ncm:statistics/ncm:in-bad-rpcs",
            "/ncm:netconf-state/ncm:statistics/ncm:in-rpcs",
            "/ncm:netconf-state/ncm:statistics/ncm:in-sessions",
            "/ncm:netconf-state/ncm:statistics/ncm:netconf-start-time",
            "/ncm:netconf-state/ncm:statistics/ncm:out-notifications",
            "/ncm:netconf-state/ncm:statistics/ncm:out-rpc-errors",
        ],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:dropped-sessions",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:in-bad-hellos",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:in-bad-rpcs",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:in-rpcs",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:in-sessions",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:netconf-start-time",
        NodeKind::Leaf,
        Some(LeafType::String),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:out-notifications",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
    netconf_monitoring_node(
        "/ncm:netconf-state/ncm:statistics/ncm:out-rpc-errors",
        NodeKind::Leaf,
        Some(LeafType::Uint32),
        &[],
        &[],
    ),
];

struct YangLibraryRegistry;

impl SchemaRegistry for YangLibraryRegistry {
    fn schema_digest(&self) -> &'static str {
        "ietf-yang-library@2019-01-04"
    }

    fn served_models(&self) -> &'static [ModelData] {
        YANG_LIBRARY_MODEL
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        YANG_LIBRARY_NODES
    }

    fn origins(&self) -> &'static [OriginEntry] {
        YANG_LIBRARY_ORIGINS
    }
}

static YANG_LIBRARY_REGISTRY: YangLibraryRegistry = YangLibraryRegistry;

/// Built-in registry used for NACM/filtering of `/yang-library` discovery data.
pub fn yang_library_registry() -> &'static dyn SchemaRegistry {
    &YANG_LIBRARY_REGISTRY
}

struct NetconfMonitoringRegistry;

impl SchemaRegistry for NetconfMonitoringRegistry {
    fn schema_digest(&self) -> &'static str {
        "ietf-netconf-monitoring@2010-10-04"
    }

    fn served_models(&self) -> &'static [ModelData] {
        NETCONF_MONITORING_MODEL
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        NETCONF_MONITORING_NODES
    }

    fn origins(&self) -> &'static [OriginEntry] {
        NETCONF_MONITORING_ORIGINS
    }
}

static NETCONF_MONITORING_REGISTRY: NetconfMonitoringRegistry = NetconfMonitoringRegistry;

/// Built-in registry used for NACM/filtering of `/netconf-state` data.
pub fn netconf_monitoring_registry() -> &'static dyn SchemaRegistry {
    &NETCONF_MONITORING_REGISTRY
}

/// Schema-node paths selected from a `<get>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPathSelection {
    /// CNF model paths from the generated schema registry.
    pub data_paths: Vec<&'static str>,
    /// Built-in RFC 8525 YANG Library paths.
    pub yang_library_paths: Vec<&'static str>,
    /// Built-in RFC 6022 NETCONF monitoring paths.
    pub netconf_monitoring_paths: Vec<&'static str>,
}

/// Filter projection failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FilterError {
    /// XPath filters require a bounded evaluator, which is not implemented yet.
    #[error("NETCONF XPath filter is not supported")]
    UnsupportedXPath,
    /// A subtree filter element used a namespace that is not in the served
    /// module set.
    #[error("NETCONF subtree filter used an unknown namespace")]
    UnknownNamespace,
    /// A subtree filter addressed a node that is not in the served schema.
    #[error("NETCONF subtree filter addressed an unknown node")]
    UnknownNode,
}

impl FilterError {
    /// Client-facing NETCONF error classification.
    pub const fn rpc_error(self) -> RpcError {
        match self {
            Self::UnsupportedXPath => RpcError::operation_not_supported(),
            Self::UnknownNamespace => RpcError::new(
                NetconfError::new(
                    NetconfErrorType::Protocol,
                    NetconfErrorTag::UnknownNamespace,
                ),
                "unknown namespace",
            ),
            Self::UnknownNode => RpcError::new(
                NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::BadElement),
                "bad element",
            ),
        }
    }

    /// Stable audit reason.
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::UnsupportedXPath => "operation-not-supported",
            Self::UnknownNamespace => "unknown-namespace",
            Self::UnknownNode => "bad-element",
        }
    }
}

/// Computes the config schema-node paths addressed by a `<get-config>` filter.
///
/// `None` selects every config node in the registry. Structural subtree filters
/// are resolved through the served module namespaces and schema paths. XPath is
/// recognized but rejected until a bounded evaluator exists.
pub fn get_config_paths(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
) -> Result<Vec<&'static str>, FilterError> {
    data_paths(registry, filter, DataPathScope::ConfigOnly)
}

/// Computes every schema-node path addressed by a NETCONF `<get>` filter.
pub fn get_paths(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
) -> Result<Vec<&'static str>, FilterError> {
    data_paths(registry, filter, DataPathScope::All)
}

/// Computes schema-node paths addressed by a NETCONF `<get>` filter, including
/// the built-in `/yang-library` operational tree when it is advertised.
pub fn get_paths_with_yang_library(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
    include_yang_library: bool,
) -> Result<GetPathSelection, FilterError> {
    get_paths_with_discovery(registry, filter, include_yang_library, false)
}

/// Computes schema-node paths addressed by a NETCONF `<get>` filter, including
/// built-in discovery trees when they are advertised.
pub fn get_paths_with_discovery(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
    include_yang_library: bool,
    include_netconf_monitoring: bool,
) -> Result<GetPathSelection, FilterError> {
    match filter {
        None => {
            let mut yang_library_paths = Vec::new();
            if include_yang_library {
                yang_library_paths = all_paths(yang_library_registry(), DataPathScope::All);
            }
            let mut netconf_monitoring_paths = Vec::new();
            if include_netconf_monitoring {
                netconf_monitoring_paths =
                    all_paths(netconf_monitoring_registry(), DataPathScope::All);
            }
            Ok(GetPathSelection {
                data_paths: all_paths(registry, DataPathScope::All),
                yang_library_paths,
                netconf_monitoring_paths,
            })
        }
        Some(Filter::XPath) => Err(FilterError::UnsupportedXPath),
        Some(Filter::Subtree(filter)) => {
            let mut data_paths = Vec::new();
            let mut yang_library_paths = Vec::new();
            let mut netconf_monitoring_paths = Vec::new();
            for selection in filter.selections() {
                let mut outcome = SelectionOutcome::default();
                collect_selection_paths(
                    selection,
                    registry,
                    DataPathScope::All,
                    &mut data_paths,
                    &mut outcome,
                );
                if include_yang_library {
                    collect_selection_paths(
                        selection,
                        yang_library_registry(),
                        DataPathScope::All,
                        &mut yang_library_paths,
                        &mut outcome,
                    );
                }
                if include_netconf_monitoring {
                    collect_selection_paths(
                        selection,
                        netconf_monitoring_registry(),
                        DataPathScope::All,
                        &mut netconf_monitoring_paths,
                        &mut outcome,
                    );
                }
                outcome.finish()?;
            }
            Ok(GetPathSelection {
                data_paths: sort_dedupe_by_registry(registry, &data_paths, DataPathScope::All),
                yang_library_paths: sort_dedupe_by_registry(
                    yang_library_registry(),
                    &yang_library_paths,
                    DataPathScope::All,
                ),
                netconf_monitoring_paths: sort_dedupe_by_registry(
                    netconf_monitoring_registry(),
                    &netconf_monitoring_paths,
                    DataPathScope::All,
                ),
            })
        }
    }
}

#[derive(Debug, Default)]
struct SelectionOutcome {
    matched: bool,
    unknown_namespace: bool,
    unknown_node: bool,
}

impl SelectionOutcome {
    fn observe_error(&mut self, error: FilterError) {
        match error {
            FilterError::UnsupportedXPath => {}
            FilterError::UnknownNamespace => self.unknown_namespace = true,
            FilterError::UnknownNode => self.unknown_node = true,
        }
    }

    fn finish(self) -> Result<(), FilterError> {
        if self.matched {
            return Ok(());
        }
        if self.unknown_node {
            Err(FilterError::UnknownNode)
        } else if self.unknown_namespace {
            Err(FilterError::UnknownNamespace)
        } else {
            Err(FilterError::UnknownNode)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataPathScope {
    ConfigOnly,
    All,
}

impl DataPathScope {
    const fn includes(self, config: bool) -> bool {
        match self {
            Self::ConfigOnly => config,
            Self::All => true,
        }
    }
}

fn data_paths(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
    scope: DataPathScope,
) -> Result<Vec<&'static str>, FilterError> {
    match filter {
        None => Ok(all_paths(registry, scope)),
        Some(Filter::XPath) => Err(FilterError::UnsupportedXPath),
        Some(Filter::Subtree(filter)) => subtree_paths(registry, filter, scope),
    }
}

fn all_paths(registry: &'static dyn SchemaRegistry, scope: DataPathScope) -> Vec<&'static str> {
    registry
        .nodes()
        .iter()
        .filter_map(|node| scope.includes(node.config).then_some(node.path))
        .collect()
}

fn subtree_paths(
    registry: &'static dyn SchemaRegistry,
    filter: &SubtreeFilter,
    scope: DataPathScope,
) -> Result<Vec<&'static str>, FilterError> {
    let mut selected = Vec::new();
    for selection in filter.selections() {
        for path in resolve_selection_paths(registry, selection)? {
            add_ancestors(registry, path, scope, &mut selected);
            add_path(registry, path, scope, &mut selected);
            if selection.include_descendants() {
                add_descendants(registry, path, scope, &mut selected);
            }
        }
    }

    Ok(sort_dedupe_by_registry(registry, &selected, scope))
}

fn collect_selection_paths(
    selection: &SubtreeSelection,
    registry: &'static dyn SchemaRegistry,
    scope: DataPathScope,
    selected: &mut Vec<&'static str>,
    outcome: &mut SelectionOutcome,
) {
    match resolve_selection_paths(registry, selection) {
        Ok(paths) => {
            outcome.matched = true;
            for path in paths {
                add_ancestors(registry, path, scope, selected);
                add_path(registry, path, scope, selected);
                if selection.include_descendants() {
                    add_descendants(registry, path, scope, selected);
                }
            }
        }
        Err(error) => outcome.observe_error(error),
    }
}

fn resolve_selection_paths(
    registry: &'static dyn SchemaRegistry,
    selection: &SubtreeSelection,
) -> Result<Vec<&'static str>, FilterError> {
    if selection.elements().is_empty() {
        return Err(FilterError::UnknownNode);
    }

    let mut candidates = vec![String::new()];
    for element in selection.elements() {
        let prefixes = prefixes_for_namespace(registry, &element.namespace)?;
        let mut next = Vec::new();
        for candidate in &candidates {
            for prefix in &prefixes {
                let path = format!("{candidate}/{prefix}:{}", element.local);
                if registry.node(&path).is_some() {
                    next.push(path);
                }
            }
        }
        if next.is_empty() {
            return Err(FilterError::UnknownNode);
        }
        candidates = next;
    }

    let mut paths = Vec::new();
    for candidate in candidates {
        let path = registry
            .node(&candidate)
            .map(|node| node.path)
            .ok_or(FilterError::UnknownNode)?;
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn prefixes_for_namespace(
    registry: &'static dyn SchemaRegistry,
    namespace: &str,
) -> Result<Vec<&'static str>, FilterError> {
    if namespace.is_empty() {
        return Ok(registry
            .served_models()
            .iter()
            .map(|model| model.prefix)
            .collect());
    }

    let prefix = registry
        .served_models()
        .iter()
        .find(|model| model.namespace == namespace)
        .map(|model| model.prefix)
        .ok_or(FilterError::UnknownNamespace)?;
    Ok(vec![prefix])
}

fn add_ancestors(
    registry: &'static dyn SchemaRegistry,
    path: &'static str,
    scope: DataPathScope,
    selected: &mut Vec<&'static str>,
) {
    for node in registry.nodes() {
        if scope.includes(node.config)
            && path != node.path
            && is_descendant_or_self(path, node.path)
        {
            selected.push(node.path);
        }
    }
}

fn add_descendants(
    registry: &'static dyn SchemaRegistry,
    path: &'static str,
    scope: DataPathScope,
    selected: &mut Vec<&'static str>,
) {
    for node in registry.nodes() {
        if scope.includes(node.config)
            && path != node.path
            && is_descendant_or_self(node.path, path)
        {
            selected.push(node.path);
        }
    }
}

fn add_path(
    registry: &'static dyn SchemaRegistry,
    path: &'static str,
    scope: DataPathScope,
    selected: &mut Vec<&'static str>,
) {
    if registry
        .node(path)
        .is_some_and(|node| scope.includes(node.config))
    {
        selected.push(path);
    }
}

fn sort_dedupe_by_registry(
    registry: &'static dyn SchemaRegistry,
    selected: &[&'static str],
    scope: DataPathScope,
) -> Vec<&'static str> {
    registry
        .nodes()
        .iter()
        .filter_map(|node| {
            (scope.includes(node.config) && selected.contains(&node.path)).then_some(node.path)
        })
        .collect()
}

fn is_descendant_or_self(candidate: &str, ancestor: &str) -> bool {
    candidate == ancestor
        || candidate
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry};

    use crate::xml::{FilterElement, SubtreeFilter};

    use super::*;

    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "demo-system",
        revision: "2026-06-13",
        namespace: "urn:opc:demo",
        prefix: "sys",
    }];

    static NODES: &[NodeMeta] = &[
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
            child_paths: &["/sys:system/sys:hostname", "/sys:system/sys:uptime"],
        },
        NodeMeta {
            path: "/sys:system/sys:hostname",
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
        },
        NodeMeta {
            path: "/sys:system/sys:uptime",
            module: "demo-system",
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
    ];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-system"],
    }];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:demo"
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

    static REGISTRY: TestRegistry = TestRegistry;

    fn element(local: &str) -> FilterElement {
        FilterElement {
            namespace: "urn:opc:demo".to_string(),
            local: local.to_string(),
        }
    }

    fn wildcard_element(local: &str) -> FilterElement {
        FilterElement {
            namespace: String::new(),
            local: local.to_string(),
        }
    }

    fn subtree(elements: Vec<FilterElement>, include_descendants: bool) -> Filter {
        let mut filter = SubtreeFilter::default();
        filter.push(SubtreeSelection::new(elements, include_descendants));
        Filter::Subtree(filter)
    }

    #[test]
    fn no_filter_selects_all_config_nodes() {
        assert_eq!(
            get_config_paths(&REGISTRY, None).expect("paths"),
            ["/sys:system", "/sys:system/sys:hostname"]
        );
    }

    #[test]
    fn get_selects_config_and_state_nodes() {
        assert_eq!(
            get_paths(&REGISTRY, None).expect("paths"),
            [
                "/sys:system",
                "/sys:system/sys:hostname",
                "/sys:system/sys:uptime"
            ]
        );
    }

    #[test]
    fn terminal_subtree_selection_expands_config_descendants_only() {
        let filter = subtree(vec![element("system")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect("paths"),
            ["/sys:system", "/sys:system/sys:hostname"]
        );
        assert_eq!(
            get_paths(&REGISTRY, Some(&filter)).expect("paths"),
            [
                "/sys:system",
                "/sys:system/sys:hostname",
                "/sys:system/sys:uptime"
            ]
        );
    }

    #[test]
    fn child_selection_includes_config_ancestors() {
        let filter = subtree(vec![element("system"), element("hostname")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect("paths"),
            ["/sys:system", "/sys:system/sys:hostname"]
        );
    }

    #[test]
    fn state_child_selection_includes_state_for_get_only() {
        let filter = subtree(vec![element("system"), element("uptime")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect("paths"),
            ["/sys:system"]
        );
        assert_eq!(
            get_paths(&REGISTRY, Some(&filter)).expect("paths"),
            ["/sys:system", "/sys:system/sys:uptime"]
        );
    }

    #[test]
    fn namespace_wildcard_resolves_structural_data_selection() {
        let filter = subtree(vec![wildcard_element("system")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect("paths"),
            ["/sys:system", "/sys:system/sys:hostname"]
        );
    }

    #[test]
    fn namespace_wildcard_unknown_node_fails_closed() {
        let filter = subtree(vec![wildcard_element("missing")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect_err("missing"),
            FilterError::UnknownNode
        );
    }

    #[test]
    fn xpath_fails_closed_until_bounded_evaluator_exists() {
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&Filter::XPath)).expect_err("xpath"),
            FilterError::UnsupportedXPath
        );
    }

    #[test]
    fn unknown_namespace_fails_closed() {
        let filter = subtree(
            vec![FilterElement {
                namespace: "urn:unknown".to_string(),
                local: "system".to_string(),
            }],
            true,
        );
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect_err("namespace"),
            FilterError::UnknownNamespace
        );
    }

    #[test]
    fn unknown_node_fails_closed() {
        let filter = subtree(vec![element("system"), element("missing")], true);
        assert_eq!(
            get_config_paths(&REGISTRY, Some(&filter)).expect_err("node"),
            FilterError::UnknownNode
        );
    }

    #[test]
    fn yang_library_registry_is_consistent() {
        yang_library_registry()
            .self_check()
            .expect("built-in YANG Library registry");
    }

    #[test]
    fn netconf_monitoring_registry_is_consistent() {
        netconf_monitoring_registry()
            .self_check()
            .expect("built-in NETCONF monitoring registry");
    }

    #[test]
    fn get_can_include_yang_library_when_advertised() {
        let selected =
            get_paths_with_yang_library(&REGISTRY, None, true).expect("get path selection");

        assert_eq!(
            selected.data_paths,
            [
                "/sys:system",
                "/sys:system/sys:hostname",
                "/sys:system/sys:uptime"
            ]
        );
        assert!(selected
            .yang_library_paths
            .contains(&"/yanglib:yang-library"));
        assert!(selected
            .yang_library_paths
            .contains(&"/yanglib:yang-library/yanglib:content-id"));
    }

    #[test]
    fn yang_library_namespace_fails_closed_when_not_advertised() {
        let filter = subtree(
            vec![FilterElement {
                namespace: YANG_LIBRARY_NS.to_string(),
                local: "yang-library".to_string(),
            }],
            true,
        );

        assert_eq!(
            get_paths_with_yang_library(&REGISTRY, Some(&filter), false)
                .expect_err("not advertised"),
            FilterError::UnknownNamespace
        );
    }

    #[test]
    fn netconf_monitoring_namespace_fails_closed_when_not_advertised() {
        let filter = subtree(
            vec![FilterElement {
                namespace: NETCONF_MONITORING_NS.to_string(),
                local: "netconf-state".to_string(),
            }],
            true,
        );

        assert_eq!(
            get_paths_with_discovery(&REGISTRY, Some(&filter), false, false)
                .expect_err("not advertised"),
            FilterError::UnknownNamespace
        );
    }

    #[test]
    fn subtree_can_select_netconf_monitoring_schemas() {
        let filter = subtree(
            vec![
                FilterElement {
                    namespace: NETCONF_MONITORING_NS.to_string(),
                    local: "netconf-state".to_string(),
                },
                FilterElement {
                    namespace: NETCONF_MONITORING_NS.to_string(),
                    local: "schemas".to_string(),
                },
            ],
            true,
        );

        let selected = get_paths_with_discovery(&REGISTRY, Some(&filter), false, true)
            .expect("monitoring filter");
        assert!(selected.data_paths.is_empty());
        assert!(selected.yang_library_paths.is_empty());
        assert_eq!(
            selected.netconf_monitoring_paths,
            [
                "/ncm:netconf-state",
                "/ncm:netconf-state/ncm:schemas",
                "/ncm:netconf-state/ncm:schemas/ncm:schema",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version",
            ]
        );
    }

    #[test]
    fn namespace_wildcard_can_select_advertised_discovery_tree() {
        let filter = subtree(vec![wildcard_element("netconf-state")], true);

        let selected = get_paths_with_discovery(&REGISTRY, Some(&filter), false, true)
            .expect("monitoring wildcard filter");
        assert!(selected.data_paths.is_empty());
        assert!(selected.yang_library_paths.is_empty());
        assert!(selected
            .netconf_monitoring_paths
            .contains(&"/ncm:netconf-state"));
        assert!(selected
            .netconf_monitoring_paths
            .contains(&"/ncm:netconf-state/ncm:schemas"));
    }

    #[test]
    fn subtree_can_select_yang_library_content_id() {
        let filter = subtree(
            vec![
                FilterElement {
                    namespace: YANG_LIBRARY_NS.to_string(),
                    local: "yang-library".to_string(),
                },
                FilterElement {
                    namespace: YANG_LIBRARY_NS.to_string(),
                    local: "content-id".to_string(),
                },
            ],
            true,
        );

        let selected = get_paths_with_yang_library(&REGISTRY, Some(&filter), true)
            .expect("yang-library filter");
        assert!(selected.data_paths.is_empty());
        assert_eq!(
            selected.yang_library_paths,
            [
                "/yanglib:yang-library",
                "/yanglib:yang-library/yanglib:content-id"
            ]
        );
    }
}
