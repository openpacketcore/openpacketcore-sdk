//! Authorized NETCONF projections that retain identity until XML serialization.

use std::collections::BTreeMap;

use crate::{
    DefaultReport, NetconfKeyPredicate, NetconfProjectionError, NetconfXmlRenderContext, NodeKind,
    SchemaRegistry,
};

/// One alternative instance-selection branch. Predicates within a branch are
/// conjunctive. Its schema paths retain that branch's own descendant selection.
/// These constraints never grant permission; renderers also require the
/// operation's independently authorized schema selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetconfInstanceBranch {
    /// Expanded schema selection, including required identifying keys.
    pub schema_paths: Vec<&'static str>,
    /// Literal, schema-validated key equalities at every selected list level.
    pub predicates: Vec<NetconfKeyPredicate>,
}

/// One authorized XML data node before redaction and escaping. Keeping real
/// key-leaf values until the forest has been merged prevents masked keys from
/// combining distinct list instances. Debug never exposes stored values.
#[derive(Clone, PartialEq, Eq)]
pub struct NetconfDataNode {
    /// Qualified, predicate-free schema path.
    pub path: &'static str,
    /// Scalar text before data-class masking, if this is a leaf or leaf-list.
    pub value: Option<String>,
    /// Whether the scalar came from a schema default.
    pub defaulted: bool,
    /// Authorized children, preserving configuration instance order.
    pub children: Vec<NetconfDataNode>,
}

impl std::fmt::Debug for NetconfDataNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetconfDataNode")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl NetconfDataNode {
    /// Builds a scalar projection. Authorization precedes this operation.
    pub fn leaf(path: &'static str, value: String, defaulted: bool) -> Self {
        Self {
            path,
            value: Some(value),
            defaulted,
            children: Vec::new(),
        }
    }

    /// Builds a container or one list instance with its complete key children.
    pub fn branch(path: &'static str, children: Vec<Self>) -> Self {
        Self {
            path,
            value: None,
            defaulted: false,
            children,
        }
    }
}

fn identity(
    registry: &dyn SchemaRegistry,
    node: &NetconfDataNode,
) -> Result<(&'static str, Vec<String>), NetconfProjectionError> {
    let meta = registry
        .node(node.path)
        .ok_or(NetconfProjectionError::UnsupportedShape {
            path: node.path,
            kind: NodeKind::Container,
        })?;
    let mut values = Vec::new();
    if meta.kind == NodeKind::List {
        if meta.key_leaves.is_empty() {
            return Err(NetconfProjectionError::UnsupportedShape {
                path: node.path,
                kind: NodeKind::List,
            });
        }
        for key in meta.key_leaves {
            let value = node
                .children
                .iter()
                .find_map(|child| {
                    let name = child.path.rsplit('/').next()?;
                    let matches = if key.contains(':') {
                        name == *key
                    } else {
                        registry
                            .node(child.path)
                            .is_some_and(|child| child.module == meta.module)
                            && name.rsplit(':').next() == Some(*key)
                    };
                    matches.then_some(child.value.as_ref()).flatten()
                })
                .ok_or(NetconfProjectionError::UnsupportedShape {
                    path: node.path,
                    kind: NodeKind::List,
                })?;
            values.push(value.clone());
        }
    } else if meta.kind == NodeKind::LeafList {
        values.push(
            node.value
                .clone()
                .ok_or(NetconfProjectionError::UnsupportedShape {
                    path: node.path,
                    kind: meta.kind,
                })?,
        );
    }
    Ok((node.path, values))
}

/// Merges two authorized forests by qualified container and complete list
/// identity, before redaction. Existing configuration order is retained;
/// callers supply new operational entries in canonical path order.
pub fn merge_netconf_data(
    registry: &dyn SchemaRegistry,
    target: &mut Vec<NetconfDataNode>,
    additional: Vec<NetconfDataNode>,
) -> Result<(), NetconfProjectionError> {
    let mut indexes = BTreeMap::new();
    let mut pending_children: BTreeMap<usize, Vec<NetconfDataNode>> = BTreeMap::new();
    for (index, node) in target.iter().enumerate() {
        if indexes.insert(identity(registry, node)?, index).is_some() {
            return Err(NetconfProjectionError::UnsupportedShape {
                path: node.path,
                kind: NodeKind::List,
            });
        }
    }
    for node in additional {
        let key = identity(registry, &node)?;
        if let Some(index) = indexes.get(&key).copied() {
            let existing = &mut target[index];
            if existing.value != node.value {
                return Err(NetconfProjectionError::UnsupportedShape {
                    path: node.path,
                    kind: NodeKind::Leaf,
                });
            }
            pending_children
                .entry(index)
                .or_default()
                .extend(node.children);
        } else {
            indexes.insert(key, target.len());
            target.push(node);
        }
    }
    for (index, children) in pending_children {
        merge_netconf_data(registry, &mut target[index].children, children)?;
    }
    Ok(())
}

/// Serializes an authorized, merged forest with normal namespace handling,
/// leaf data-class masking, XML escaping and with-defaults annotations.
pub fn render_netconf_data(
    registry: &dyn SchemaRegistry,
    nodes: &[NetconfDataNode],
    report: DefaultReport,
) -> Result<String, NetconfProjectionError> {
    fn collect(node: &NetconfDataNode, paths: &mut Vec<&'static str>) {
        paths.push(node.path);
        for child in &node.children {
            collect(child, paths);
        }
    }
    fn render(
        node: &NetconfDataNode,
        ctx: &NetconfXmlRenderContext<'_>,
        root: bool,
        out: &mut String,
    ) -> Result<(), NetconfProjectionError> {
        if let Some(value) = &node.value {
            let mut leaf = ctx.format_leaf_with_default(node.path, value, node.defaulted)?;
            if root {
                let name = ctx.qualified_name(node.path)?;
                let mut namespaces = String::new();
                for (prefix, namespace) in ctx.module_namespaces() {
                    namespaces.push_str(" xmlns:");
                    namespaces.push_str(&crate::xml_escape_attr(&prefix));
                    namespaces.push_str("=\"");
                    namespaces.push_str(&crate::xml_escape_attr(namespace));
                    namespaces.push('"');
                }
                leaf.insert_str(name.len() + 1, &namespaces);
            }
            out.push_str(&leaf);
            return Ok(());
        }
        let name = ctx.qualified_name(node.path)?;
        out.push('<');
        out.push_str(&name);
        if root {
            for (prefix, namespace) in ctx.module_namespaces() {
                out.push_str(" xmlns:");
                out.push_str(&crate::xml_escape_attr(&prefix));
                out.push_str("=\"");
                out.push_str(&crate::xml_escape_attr(namespace));
                out.push('"');
            }
        }
        out.push('>');
        for child in &node.children {
            render(child, ctx, false, out)?;
        }
        out.push_str("</");
        out.push_str(&name);
        out.push('>');
        Ok(())
    }
    let mut paths = Vec::new();
    for node in nodes {
        collect(node, &mut paths);
    }
    paths.sort_unstable();
    paths.dedup();
    let ctx = NetconfXmlRenderContext::new(registry, &paths, report);
    let mut out = String::new();
    for node in nodes {
        render(node, &ctx, true, &mut out)?;
    }
    Ok(out)
}
