//! Instance-preserving XML projection trees shared by generated and state renderers.

use crate::{NetconfProjectionError, NetconfXmlRenderContext, NodeKind, SchemaRegistry};

#[cfg(test)]
mod tests;

/// One selected schema node with its original branch's list-key constraints.
/// Selectors are alternatives; all key constraints within one selector must match.
#[derive(Clone, PartialEq, Eq)]
pub struct NetconfInstanceSelector {
    /// Selected predicate-free schema path.
    pub schema_path: &'static str,
    /// Canonical key values indexed by the complete key-leaf schema path.
    pub keys: Vec<(&'static str, String)>,
}

impl std::fmt::Debug for NetconfInstanceSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetconfInstanceSelector")
            .finish_non_exhaustive()
    }
}

impl NetconfInstanceSelector {
    /// Compares an exact selected schema node and its unmasked ancestor identity.
    pub fn matches(&self, schema_path: &str, identity: &[(&str, String)]) -> bool {
        self.schema_path == schema_path && self.keys.iter().all(|key| identity.contains(key))
    }
}

/// One authorized XML data node before payload masking.
///
/// List identity is kept separately from rendered key text. Merging therefore
/// distinguishes original tuples even when their XML key values mask identically.
/// Callers must validate and authorize the node and all identifying keys first.
#[derive(Clone, PartialEq, Eq)]
pub struct NetconfXmlNode {
    /// Predicate-free schema path.
    pub schema_path: &'static str,
    /// Complete list keys in YANG key order, as `(key schema path, identity)`.
    /// Ordinary reads retain canonical text. Subtree content capture replaces
    /// non-cleartext keys with `SubtreeBudget::masked_identity` before matching;
    /// the renderer still emits those elements through their schema's mask.
    pub keys: Vec<(&'static str, String)>,
    /// Scalar payload, when this is a leaf or one leaf-list member.
    pub value: Option<String>,
    /// Whether the scalar originated from a schema default.
    pub is_defaulted: bool,
    /// Capture position of a masked leaf-list member, never serialized.
    /// Preserves distinct members without retaining their unnecessary raw text.
    pub masked_ordinal: Option<usize>,
    /// Structural children in configuration order.
    pub children: Vec<NetconfXmlNode>,
}

impl std::fmt::Debug for NetconfXmlNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetconfXmlNode").finish_non_exhaustive()
    }
}

impl NetconfXmlNode {
    /// Builds a structural node with no fabricated children or keys.
    pub fn branch(schema_path: &'static str) -> Self {
        Self {
            schema_path,
            keys: Vec::new(),
            value: None,
            is_defaulted: false,
            masked_ordinal: None,
            children: Vec::new(),
        }
    }

    /// Builds one scalar payload. Masking and escaping happen when serialized.
    pub fn scalar(schema_path: &'static str, value: impl Into<String>, is_defaulted: bool) -> Self {
        Self {
            value: Some(value.into()),
            is_defaulted,
            ..Self::branch(schema_path)
        }
    }
}

/// Merges complete identities, retaining existing configuration instance order.
/// New state instances follow the existing instances in their supplied order.
/// Inputs must already have passed schema, identity and authorization checks.
pub fn merge_netconf_nodes(
    registry: &dyn SchemaRegistry,
    existing: &mut Vec<NetconfXmlNode>,
    incoming: Vec<NetconfXmlNode>,
) -> Result<(), NetconfProjectionError> {
    for mut node in incoming {
        let metadata = registry
            .node(node.schema_path)
            .ok_or(NetconfProjectionError::WriteError)?;
        if let Some(previous) = existing.iter_mut().find(|previous| {
            previous.schema_path == node.schema_path
                && previous.keys == node.keys
                && previous.masked_ordinal == node.masked_ordinal
                && (metadata.kind != NodeKind::LeafList || previous.value == node.value)
        }) {
            if previous.value != node.value || previous.is_defaulted != node.is_defaulted {
                return Err(NetconfProjectionError::WriteError);
            }
            merge_netconf_nodes(
                registry,
                &mut previous.children,
                std::mem::take(&mut node.children),
            )?;
        } else {
            existing.push(node);
        }
    }
    // Stable ordering groups schema siblings while retaining list instance order.
    existing.sort_by_key(|node| node.schema_path);
    Ok(())
}

impl NetconfXmlRenderContext<'_> {
    /// Serializes an already authorized tree with namespaces, masking and escaping.
    /// Identifying keys are emitted once, in their declared order.
    pub fn render_nodes(&self, nodes: &[NetconfXmlNode]) -> Result<String, NetconfProjectionError> {
        fn collect<'a>(nodes: &'a [NetconfXmlNode], paths: &mut Vec<&'a str>) {
            for node in nodes {
                paths.push(node.schema_path);
                paths.extend(node.keys.iter().map(|(path, _)| *path));
                collect(&node.children, paths);
            }
        }
        let mut paths = self.selection.to_vec();
        collect(nodes, &mut paths);
        paths.sort_unstable();
        paths.dedup();
        let ctx = NetconfXmlRenderContext::new(self.registry, &paths, self.report);
        let mut output = String::new();
        for node in nodes {
            ctx.append_node(node, true, &mut output)?;
        }
        Ok(output)
    }

    fn append_node(
        &self,
        node: &NetconfXmlNode,
        namespaces: bool,
        output: &mut String,
    ) -> Result<(), NetconfProjectionError> {
        let metadata = self
            .node(node.schema_path)
            .ok_or(NetconfProjectionError::WriteError)?;
        if node.masked_ordinal.is_some() && metadata.kind != NodeKind::LeafList {
            return Err(NetconfProjectionError::WriteError);
        }
        if let Some(value) = &node.value {
            if !matches!(metadata.kind, NodeKind::Leaf | NodeKind::LeafList)
                || !node.keys.is_empty()
                || !node.children.is_empty()
            {
                return Err(NetconfProjectionError::WriteError);
            }
            let mut xml =
                self.format_leaf_with_default(node.schema_path, value, node.is_defaulted)?;
            if namespaces {
                let mut declarations = String::new();
                self.append_namespaces(&mut declarations);
                xml.insert_str(
                    self.qualified_name(node.schema_path)?.len() + 1,
                    &declarations,
                );
            }
            output.push_str(&xml);
            return Ok(());
        }
        if !matches!(metadata.kind, NodeKind::Container | NodeKind::List)
            || node.is_defaulted
            || (metadata.kind == NodeKind::Container && !node.keys.is_empty())
        {
            return Err(NetconfProjectionError::WriteError);
        }
        if metadata.kind == NodeKind::List
            && (metadata.key_leaves.is_empty() || node.keys.len() != metadata.key_leaves.len())
        {
            return Err(NetconfProjectionError::UnsupportedShape {
                path: node.schema_path,
                kind: metadata.kind,
            });
        }
        for ((path, _), declared) in node.keys.iter().zip(metadata.key_leaves) {
            let key = self.node(path).ok_or(NetconfProjectionError::WriteError)?;
            let (parent, name) = path
                .rsplit_once('/')
                .ok_or(NetconfProjectionError::WriteError)?;
            let local = name.split_once(':').map_or(name, |(_, local)| local);
            if parent != node.schema_path
                || key.kind != NodeKind::Leaf
                || key.module != metadata.module
                || (name != *declared && local != *declared)
            {
                return Err(NetconfProjectionError::WriteError);
            }
        }
        let name = self.qualified_name(node.schema_path)?;
        output.push('<');
        output.push_str(&name);
        if namespaces {
            self.append_namespaces(output);
        }
        output.push('>');
        for (path, value) in &node.keys {
            output.push_str(&self.format_leaf(path, value)?);
        }
        for child in &node.children {
            if child.schema_path.rsplit_once('/').map(|(parent, _)| parent)
                != Some(node.schema_path)
            {
                return Err(NetconfProjectionError::WriteError);
            }
            if let Some((_, key_value)) = node
                .keys
                .iter()
                .find(|(path, _)| *path == child.schema_path)
            {
                if child.value.as_ref() != Some(key_value)
                    || child.is_defaulted
                    || !child.keys.is_empty()
                    || !child.children.is_empty()
                {
                    return Err(NetconfProjectionError::WriteError);
                }
                continue;
            }
            self.append_node(child, false, output)?;
        }
        output.push_str("</");
        output.push_str(&name);
        output.push('>');
        Ok(())
    }

    fn append_namespaces(&self, output: &mut String) {
        for (prefix, namespace) in self.module_namespaces() {
            output.push_str(" xmlns:");
            output.push_str(&crate::xml_escape_attr(&prefix));
            output.push_str("=\"");
            output.push_str(&crate::xml_escape_attr(namespace));
            output.push('"');
        }
    }
}
