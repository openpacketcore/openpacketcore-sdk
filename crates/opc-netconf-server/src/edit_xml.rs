//! Schema-aware parser for the bounded NETCONF `<edit-config>` `<config>` element.
//!
//! The parser turns the captured config XML into a normalized [`EditConfigNode`]
//! tree: prefixes are resolved, namespaces are mapped to served modules, element
//! names are mapped to schema paths, `nc:operation` attributes are normalized,
//! and list keys are collected before any non-key children. The emitted tree
//! carries leaf and leaf-list entry values (which may be secrets) but never
//! logs them or echoes them in error messages.

use std::collections::BTreeMap;

use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::{
    bare_segment, EditConfigNode, EditOperation, NetconfEditError, NodeKind, SchemaRegistry,
};
use quick_xml::events::BytesStart;
use quick_xml::reader::Reader;

use crate::capabilities::{NETCONF_BASE_NS, NETCONF_NMDA_NS};
use crate::xml::{validate_namespace_binding, EditDefaultOperation, XML_NAMESPACE_URI};

/// Parses a NETCONF `<config>` element into a schema-bound edit tree.
///
/// `default_operation` is the RFC 6241 `<default-operation>` from the request.
/// Per-node `nc:operation` attributes override it. The returned tree contains
/// exactly one top-level data node (the schema root container). This
/// compatibility entry point uses [`MgmtLimits::default`]; server bindings and
/// callers with deployment-specific limits should use
/// [`parse_edit_config_xml_with_limits`].
pub fn parse_edit_config_xml(
    config_xml: &str,
    registry: &'static dyn SchemaRegistry,
    default_operation: EditDefaultOperation,
) -> Result<EditConfigNode, NetconfEditError> {
    parse_edit_config_xml_with_limits(
        config_xml,
        registry,
        default_operation,
        &MgmtLimits::default(),
    )
}

/// Parses a NETCONF `<config>` fragment with the supplied validated limits.
///
/// Direct callers must supply the limits that bound their input. Server
/// bindings use the private already-envelope-bounded parser path instead, so a
/// rewritten capture is not compared with the original wire-message size.
pub fn parse_edit_config_xml_with_limits(
    config_xml: &str,
    registry: &'static dyn SchemaRegistry,
    default_operation: EditDefaultOperation,
    limits: &MgmtLimits,
) -> Result<EditConfigNode, NetconfEditError> {
    limits
        .validate()
        .map_err(|_| NetconfEditError::MalformedXml)?;
    limits
        .check_request_bytes(config_xml.len())
        .map_err(|_| NetconfEditError::MalformedXml)?;

    parse_edit_config_xml_inner(config_xml, registry, default_operation, Some(limits))
}

/// Parses a config fragment already bounded by the NETCONF RPC envelope.
///
/// The outer parser validates the complete wire message, XML depth, attributes,
/// namespace bindings, values, and addressed-node count before it creates the
/// namespace-preserving capture passed to a binding.  This private seam must
/// not reapply the whole-message byte limit to that rewritten capture: adding
/// inherited namespace declarations or expanding an empty element can make the
/// capture longer than the original wire bytes without increasing input size.
pub(crate) fn parse_edit_config_xml_from_bounded_envelope(
    config_xml: &str,
    registry: &'static dyn SchemaRegistry,
    default_operation: EditDefaultOperation,
) -> Result<EditConfigNode, NetconfEditError> {
    parse_edit_config_xml_inner(config_xml, registry, default_operation, None)
}

fn parse_edit_config_xml_inner(
    config_xml: &str,
    registry: &'static dyn SchemaRegistry,
    default_operation: EditDefaultOperation,
    limits: Option<&MgmtLimits>,
) -> Result<EditConfigNode, NetconfEditError> {
    let mut reader = Reader::from_str(config_xml);
    reader.config_mut().trim_text(false);
    let decoder = reader.decoder();

    let mut stack: Vec<Frame> = Vec::new();
    let mut addressed_nodes = 0usize;
    let mut root = None;

    loop {
        match reader
            .read_event()
            .map_err(|_| NetconfEditError::MalformedXml)?
        {
            quick_xml::events::Event::Start(start) => {
                if root.is_some() {
                    return Err(NetconfEditError::MalformedXml);
                }
                validate_start_limits(&start, decoder, limits)?;
                check_depth(stack.len() + 1, limits)?;
                count_addressed_node(&stack, &mut addressed_nodes, limits)?;
                let frame = push_element(&start, &mut stack, registry, decoder, default_operation)?;
                stack.push(frame);
            }
            quick_xml::events::Event::Empty(start) => {
                if root.is_some() {
                    return Err(NetconfEditError::MalformedXml);
                }
                validate_start_limits(&start, decoder, limits)?;
                check_depth(stack.len() + 1, limits)?;
                count_addressed_node(&stack, &mut addressed_nodes, limits)?;
                let frame = push_element(&start, &mut stack, registry, decoder, default_operation)?;
                // Empty elements close immediately; finalize and attach to parent.
                let node = finalize_frame(frame, registry)?;
                attach_child(&mut stack, node)?;
            }
            quick_xml::events::Event::End(end) => {
                let frame = stack.last().ok_or(NetconfEditError::MalformedXml)?;
                validate_end(
                    end.name().as_ref(),
                    &frame.ns_scope,
                    &frame.local_name,
                    &frame.namespace,
                )?;
                let frame = stack.pop().ok_or(NetconfEditError::MalformedXml)?;
                let node = finalize_frame(frame, registry)?;
                if stack.is_empty() {
                    // Closing the `<config>` wrapper. Continue through EOF so
                    // trailing roots or non-whitespace data cannot be ignored.
                    let child = node
                        .children
                        .into_iter()
                        .next()
                        .ok_or(NetconfEditError::MalformedXml)?;
                    if root.replace(child).is_some() {
                        return Err(NetconfEditError::MalformedXml);
                    }
                    continue;
                }
                attach_child(&mut stack, node)?;
            }
            quick_xml::events::Event::Text(text) => {
                check_value_bytes(text.as_ref().len(), limits)?;
                let decoded = text.decode().map_err(|_| NetconfEditError::MalformedXml)?;
                if let Some(frame) = stack.last_mut() {
                    frame.text.push_str(&decoded);
                } else if !decoded.trim().is_empty() {
                    return Err(NetconfEditError::MalformedXml);
                }
            }
            quick_xml::events::Event::CData(cdata) => {
                check_value_bytes(cdata.as_ref().len(), limits)?;
                let decoded = cdata.decode().map_err(|_| NetconfEditError::MalformedXml)?;
                let frame = stack.last_mut().ok_or(NetconfEditError::MalformedXml)?;
                frame.text.push_str(&decoded);
            }
            quick_xml::events::Event::Comment(_) => {}
            quick_xml::events::Event::Eof => return root.ok_or(NetconfEditError::MalformedXml),
            _ => return Err(NetconfEditError::MalformedXml),
        }
    }
}

fn validate_start_limits(
    start: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
    limits: Option<&MgmtLimits>,
) -> Result<(), NetconfEditError> {
    let mut attribute_count = 0usize;
    let mut namespace_count = 0usize;

    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| NetconfEditError::MalformedXml)?;
        attribute_count = attribute_count.saturating_add(1);
        let key = decode_utf8(attr.key.as_ref())?;
        let value = attr
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
            .map_err(|_| NetconfEditError::MalformedXml)?;
        check_value_bytes(value.len(), limits)?;

        if key == "xmlns" {
            namespace_count = namespace_count.saturating_add(1);
            validate_namespace_binding(None, value.as_ref())
                .map_err(|_| NetconfEditError::MalformedXml)?;
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            namespace_count = namespace_count.saturating_add(1);
            if prefix.is_empty() {
                return Err(NetconfEditError::MalformedXml);
            }
            validate_namespace_binding(Some(prefix), value.as_ref())
                .map_err(|_| NetconfEditError::MalformedXml)?;
        }
    }

    let Some(limits) = limits else {
        return Ok(());
    };
    if attribute_count > limits.max_xml_attributes_per_element
        || namespace_count > limits.max_xml_namespace_decls
    {
        return Err(NetconfEditError::MalformedXml);
    }
    Ok(())
}

fn check_value_bytes(
    value_bytes: usize,
    limits: Option<&MgmtLimits>,
) -> Result<(), NetconfEditError> {
    if let Some(limits) = limits {
        limits
            .check_value_bytes(value_bytes)
            .map_err(|_| NetconfEditError::MalformedXml)?;
    }
    Ok(())
}

fn check_depth(depth: usize, limits: Option<&MgmtLimits>) -> Result<(), NetconfEditError> {
    if let Some(limits) = limits {
        limits
            .check_depth(depth)
            .map_err(|_| NetconfEditError::MalformedXml)?;
    }
    Ok(())
}

/// Counts a data node before schema resolution allocates or groups it.
///
/// The first frame is the NETCONF `<config>` wrapper and does not address a
/// configuration node; every subsequent element does. The counter uses the
/// caller's request limits, matching the enclosing RPC parser.
fn count_addressed_node(
    stack: &[Frame],
    addressed_nodes: &mut usize,
    limits: Option<&MgmtLimits>,
) -> Result<(), NetconfEditError> {
    if stack.is_empty() {
        return Ok(());
    }

    *addressed_nodes = addressed_nodes.saturating_add(1);
    if let Some(limits) = limits {
        limits
            .check_paths(*addressed_nodes)
            .map_err(|_| NetconfEditError::MalformedXml)?;
    }
    Ok(())
}

fn map_default_operation(default: EditDefaultOperation) -> EditOperation {
    match default {
        EditDefaultOperation::Merge => EditOperation::Merge,
        EditDefaultOperation::Replace => EditOperation::Replace,
        EditDefaultOperation::None => EditOperation::None,
    }
}

fn parse_operation(value: &str) -> Result<EditOperation, NetconfEditError> {
    match value.trim() {
        "merge" => Ok(EditOperation::Merge),
        "replace" => Ok(EditOperation::Replace),
        "create" => Ok(EditOperation::Create),
        "delete" => Ok(EditOperation::Delete),
        "remove" => Ok(EditOperation::Remove),
        _ => Err(NetconfEditError::MalformedXml),
    }
}

#[derive(Clone)]
struct NsScope {
    default: Option<String>,
    bindings: BTreeMap<String, String>,
}

impl Default for NsScope {
    fn default() -> Self {
        // XML 1.0 reserves this implicit binding. Keep the standalone parser
        // aligned with the envelope parser and never let a captured fragment
        // reinterpret `xml:*` through an illegal redeclaration.
        let mut bindings = BTreeMap::new();
        bindings.insert("xml".to_string(), XML_NAMESPACE_URI.to_string());
        Self {
            default: None,
            bindings,
        }
    }
}

struct Frame {
    local_name: String,
    namespace: String,
    schema_path: &'static str,
    node_kind: NodeKind,
    operation: EditOperation,
    children: Vec<EditConfigNode>,
    keys: BTreeMap<String, String>,
    key_leaves: &'static [&'static str],
    text: String,
    ns_scope: NsScope,
}

/// Starts a new element frame. For the `<config>` wrapper this returns a synthetic
/// frame with an empty schema path.
#[expect(
    clippy::expect_used,
    reason = "empty-stack case returns early at the top of push_element; schema_path was just resolved from the same static registry"
)]
fn push_element(
    start: &BytesStart<'_>,
    stack: &mut [Frame],
    registry: &'static dyn SchemaRegistry,
    decoder: quick_xml::encoding::Decoder,
    default_operation: EditDefaultOperation,
) -> Result<Frame, NetconfEditError> {
    if stack.is_empty() {
        // The first element must be the NETCONF `<config>` wrapper. The bounded
        // capture loses ancestor namespace declarations, so a bare `<config>`
        // (no explicit namespace) is accepted as the base NETCONF namespace.
        let (local, namespace, ns_scope) = resolve_config_start(start, decoder)?;
        if local != "config" {
            return Err(NetconfEditError::MalformedXml);
        }
        return Ok(Frame {
            local_name: local.to_string(),
            namespace,
            schema_path: "",
            node_kind: NodeKind::Container,
            operation: map_default_operation(default_operation),
            children: Vec::new(),
            keys: BTreeMap::new(),
            key_leaves: &[],
            text: String::new(),
            ns_scope,
        });
    }

    let parent_scope = stack.last().map(|f| &f.ns_scope);
    let (local, namespace, ns_scope, op_attr) = resolve_start(start, parent_scope, decoder)?;

    let parent = stack.last().expect("non-empty stack has a parent");
    if matches!(parent.node_kind, NodeKind::Leaf | NodeKind::LeafList) {
        return Err(NetconfEditError::MalformedXml);
    }

    let module = registry
        .module_for_namespace(&namespace)
        .ok_or_else(|| NetconfEditError::UnknownPath(namespace.to_string()))?;

    let schema_path = if parent.schema_path.is_empty() {
        find_root_schema_path(registry, module, &local)?
    } else {
        registry
            .child_schema_path(parent.schema_path, &local, module)
            .ok_or_else(|| {
                NetconfEditError::UnknownPath(format!("{}/{local}", parent.schema_path))
            })?
    };

    let node = registry
        .node(schema_path)
        .expect("resolved path must exist");
    if !node.config {
        return Err(NetconfEditError::ReadOnly { path: schema_path });
    }

    let operation = op_attr.unwrap_or(parent.operation);

    Ok(Frame {
        local_name: local,
        namespace,
        schema_path,
        node_kind: node.kind,
        operation,
        children: Vec::new(),
        keys: BTreeMap::new(),
        key_leaves: node.key_leaves,
        text: String::new(),
        ns_scope,
    })
}

fn resolve_start(
    start: &BytesStart<'_>,
    parent_scope: Option<&NsScope>,
    decoder: quick_xml::encoding::Decoder,
) -> Result<(String, String, NsScope, Option<EditOperation>), NetconfEditError> {
    let raw_name = start.name();
    let (prefix, local) = split_qname(raw_name.as_ref())?;
    let mut scope = parent_scope.cloned().unwrap_or_default();

    // Namespace declarations apply to the entire start tag rather than only
    // the attributes after their textual position. Resolve them first so a
    // legal `nc:operation` that precedes `xmlns:nc` is not rejected merely
    // because the XML parser yielded attributes in source order.
    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| NetconfEditError::MalformedXml)?;
        let key = decode_utf8(attr.key.as_ref())?;
        if key == "xmlns" {
            let value = attr
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
                .map_err(|_| NetconfEditError::MalformedXml)?;
            scope.default = Some(value.to_string());
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            let value = attr
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
                .map_err(|_| NetconfEditError::MalformedXml)?;
            scope.bindings.insert(prefix.to_string(), value.to_string());
        }
    }

    let mut operation = None;
    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| NetconfEditError::MalformedXml)?;
        let key = decode_utf8(attr.key.as_ref())?;
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        let value = attr
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
            .map_err(|_| NetconfEditError::MalformedXml)?;
        let value = value.as_ref();

        let (attr_prefix, attr_local) = split_qname(attr.key.as_ref())?;
        let attr_ns = match attr_prefix {
            Some(p) => scope.bindings.get(p).cloned(),
            // The default XML namespace never applies to attributes.
            None => None,
        };
        if attr_local == "operation" && attr_ns.as_deref() == Some(NETCONF_BASE_NS) {
            if operation.is_some() {
                return Err(NetconfEditError::MalformedXml);
            }
            operation = Some(parse_operation(value)?);
        } else {
            // Unknown non-namespace attribute; fail closed.
            return Err(NetconfEditError::MalformedXml);
        }
    }

    let namespace = match prefix {
        Some(p) => scope
            .bindings
            .get(p)
            .cloned()
            .ok_or(NetconfEditError::MalformedXml)?,
        None => scope
            .default
            .clone()
            .ok_or(NetconfEditError::MalformedXml)?,
    };

    Ok((local.to_string(), namespace, scope, operation))
}

/// Resolves the `<config>` wrapper element. Unlike ordinary data nodes, the
/// bounded config fragment may omit the base NETCONF namespace because it was
/// inherited from `<rpc>`; this helper treats a bare `<config>` as base-NS and
/// also accepts the RFC 8526 NMDA wrapper namespace.
#[expect(
    clippy::expect_used,
    reason = "scope.default is set when None immediately above"
)]
fn resolve_config_start(
    start: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
) -> Result<(String, String, NsScope), NetconfEditError> {
    let raw_name = start.name();
    let (prefix, local) = split_qname(raw_name.as_ref())?;
    let mut scope = NsScope::default();

    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| NetconfEditError::MalformedXml)?;
        let key = decode_utf8(attr.key.as_ref())?;
        let value = attr
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
            .map_err(|_| NetconfEditError::MalformedXml)?;
        let value = value.as_ref();

        if key == "xmlns" {
            scope.default = Some(value.to_string());
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            scope.bindings.insert(prefix.to_string(), value.to_string());
        } else {
            // The config wrapper must not carry operation attributes or unknown
            // foreign attributes.
            return Err(NetconfEditError::MalformedXml);
        }
    }

    if scope.default.is_none() {
        // Provide the inherited base namespace so that unprefixed children of
        // `<config>` resolve deterministically (they are NETCONF base elements
        // unless they declare their own prefix/default module namespace).
        scope.default = Some(NETCONF_BASE_NS.to_string());
    }

    let namespace = match prefix {
        Some(p) => scope
            .bindings
            .get(p)
            .cloned()
            .ok_or(NetconfEditError::MalformedXml)?,
        None => scope.default.clone().expect("default set above"),
    };

    if namespace != NETCONF_BASE_NS && namespace != NETCONF_NMDA_NS {
        return Err(NetconfEditError::MalformedXml);
    }

    Ok((local.to_string(), namespace, scope))
}

fn validate_end(
    raw_name: &[u8],
    scope: &NsScope,
    expected_local: &str,
    expected_namespace: &str,
) -> Result<(), NetconfEditError> {
    let (prefix, local) = split_qname(raw_name)?;
    if local != expected_local {
        return Err(NetconfEditError::MalformedXml);
    }

    let namespace = match prefix {
        Some(p) => scope
            .bindings
            .get(p)
            .map(String::as_str)
            .ok_or(NetconfEditError::MalformedXml)?,
        None => scope
            .default
            .as_deref()
            .ok_or(NetconfEditError::MalformedXml)?,
    };

    if namespace != expected_namespace {
        return Err(NetconfEditError::MalformedXml);
    }
    Ok(())
}

fn finalize_frame(
    frame: Frame,
    _registry: &dyn SchemaRegistry,
) -> Result<EditConfigNode, NetconfEditError> {
    match frame.node_kind {
        NodeKind::Leaf | NodeKind::LeafList => Ok(EditConfigNode {
            schema_path: frame.schema_path,
            operation: frame.operation,
            value: Some(frame.text),
            children: Vec::new(),
            list_keys: BTreeMap::new(),
        }),
        NodeKind::List => {
            for &key in frame.key_leaves {
                let key_bare = bare_segment(key);
                if !frame.keys.contains_key(key_bare) {
                    return Err(NetconfEditError::MissingKey {
                        path: frame.schema_path,
                        key,
                    });
                }
            }
            Ok(EditConfigNode {
                schema_path: frame.schema_path,
                operation: frame.operation,
                value: None,
                children: frame.children,
                list_keys: frame.keys,
            })
        }
        NodeKind::Container => Ok(EditConfigNode {
            schema_path: frame.schema_path,
            operation: frame.operation,
            value: None,
            children: frame.children,
            list_keys: BTreeMap::new(),
        }),
    }
}

fn attach_child(stack: &mut [Frame], child: EditConfigNode) -> Result<(), NetconfEditError> {
    let parent = stack.last_mut().ok_or(NetconfEditError::MalformedXml)?;

    if parent.schema_path.is_empty() {
        // Direct child of `<config>`: must be the single root data container.
        if !parent.children.is_empty() {
            return Err(NetconfEditError::MalformedXml);
        }
        parent.children.push(child);
        return Ok(());
    }

    if parent.node_kind == NodeKind::List {
        if let Some(ref value) = child.value {
            if child.children.is_empty() {
                let child_bare = bare_segment(last_segment(child.schema_path));
                if parent
                    .key_leaves
                    .iter()
                    .any(|k| bare_segment(k) == child_bare)
                {
                    if parent.keys.contains_key(child_bare) {
                        return Err(NetconfEditError::MalformedXml);
                    }
                    parent.keys.insert(child_bare.to_string(), value.clone());
                    return Ok(());
                }
            }
        }
    }

    parent.children.push(child);
    Ok(())
}

fn find_root_schema_path(
    registry: &dyn SchemaRegistry,
    module: &str,
    local: &str,
) -> Result<&'static str, NetconfEditError> {
    let mut found: Option<&'static str> = None;
    for node in registry.nodes() {
        let depth = node.path.matches('/').count();
        if depth == 1 && node.module == module && bare_segment(last_segment(node.path)) == local {
            if found.is_some() {
                return Err(NetconfEditError::UnknownPath(format!("/{local}")));
            }
            found = Some(node.path);
        }
    }
    found.ok_or_else(|| NetconfEditError::UnknownPath(format!("/{local}")))
}

fn split_qname(raw: &[u8]) -> Result<(Option<&str>, &str), NetconfEditError> {
    let name = decode_utf8(raw)?;
    if name.is_empty() {
        return Err(NetconfEditError::MalformedXml);
    }
    if let Some((prefix, local)) = name.split_once(':') {
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return Err(NetconfEditError::MalformedXml);
        }
        Ok((Some(prefix), local))
    } else {
        Ok((None, name))
    }
}

fn decode_utf8(raw: &[u8]) -> Result<&str, NetconfEditError> {
    std::str::from_utf8(raw).map_err(|_| NetconfEditError::MalformedXml)
}

fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeMeta, OriginEntry, SchemaRegistry};

    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "example",
        revision: "2026-06-14",
        namespace: "urn:example",
        prefix: "ex",
    }];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["example"],
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
            child_paths: &["/ex:system/ex:hostname", "/ex:system/ex:servers"],
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
            path: "/ex:system/ex:servers",
            module: "example",
            kind: NodeKind::LeafList,
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

    static REGISTRY: TestRegistry = TestRegistry;

    #[test]
    fn parser_preserves_string_leaf_whitespace() {
        let edit = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>  router1  </ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect("edit");

        let value = edit.children[0].value.as_deref();
        assert_eq!(value, Some("  router1  "));
    }

    #[test]
    fn parser_preserves_cdata_leaf_text() {
        let edit = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname><![CDATA[  router1  ]]></ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect("edit");

        let value = edit.children[0].value.as_deref();
        assert_eq!(value, Some("  router1  "));
    }

    #[test]
    fn default_operation_none_propagates_to_unannotated_nodes() {
        let edit = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::None,
            &MgmtLimits::default(),
        )
        .expect("edit");

        assert_eq!(edit.operation, EditOperation::None);
        assert_eq!(edit.children[0].operation, EditOperation::None);
    }

    #[test]
    fn parser_normalizes_repeated_leaf_list_entries_and_namespace_operations() {
        let edit = parse_edit_config_xml_with_limits(
            r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><ex:system xmlns:ex="urn:example" nc:operation="replace" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><ex:servers>one</ex:servers><ex:servers>two</ex:servers></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect("leaf-list edit");

        assert_eq!(edit.operation, EditOperation::Replace);
        assert_eq!(edit.children.len(), 2);
        assert!(edit.children.iter().all(|node| {
            node.schema_path == "/ex:system/ex:servers"
                && node.operation == EditOperation::Replace
                && node.children.is_empty()
                && node.list_keys.is_empty()
        }));
    }

    #[test]
    fn parser_rejects_nested_leaf_list_content() {
        let err = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:servers><ex:hostname>bad</ex:hostname></ex:servers></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("leaf-list entries must be scalar");

        assert!(matches!(err, NetconfEditError::MalformedXml));
    }

    #[test]
    fn public_parser_uses_the_caller_configured_addressed_node_limit() {
        let limits = MgmtLimits {
            max_paths_per_request: MgmtLimits::default().max_paths_per_request + 1,
            ..MgmtLimits::default()
        };
        let limit = limits.max_paths_per_request - 1;
        let mut xml = String::from(r#"<config><ex:system xmlns:ex="urn:example">"#);
        for _ in 0..limit {
            xml.push_str("<ex:servers>entry</ex:servers>");
        }
        xml.push_str("</ex:system></config>");

        let edit = parse_edit_config_xml_with_limits(
            &xml,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &limits,
        )
        .expect("explicitly raised node limit must match the envelope parser");
        assert_eq!(edit.children.len(), limit);
    }

    #[test]
    fn public_parser_rejects_trailing_roots_and_unqualified_operations() {
        let trailing_root = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config><config><ex:system xmlns:ex="urn:example"/></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("a config fragment must contain exactly one root");
        assert!(matches!(trailing_root, NetconfEditError::MalformedXml));

        let trailing_text = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>trailing"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("a config fragment must reach EOF without trailing text");
        assert!(matches!(trailing_text, NetconfEditError::MalformedXml));

        let unqualified_operation = parse_edit_config_xml_with_limits(
            r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><ex:system xmlns:ex="urn:example" operation="replace"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("the default namespace must not qualify an operation attribute");
        assert!(matches!(
            unqualified_operation,
            NetconfEditError::MalformedXml
        ));

        let pre_root_cdata = parse_edit_config_xml_with_limits(
            r#"<![CDATA[trailing]]><config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("CDATA outside the sole config root must fail");
        assert!(matches!(pre_root_cdata, NetconfEditError::MalformedXml));

        let post_root_cdata = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config><![CDATA[trailing]]>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("CDATA after the sole config root must fail");
        assert!(matches!(post_root_cdata, NetconfEditError::MalformedXml));
    }

    #[test]
    fn standalone_parser_enforces_xml_limits_and_reserved_namespaces() {
        let depth_limited = MgmtLimits {
            max_xml_depth: 2,
            ..MgmtLimits::default()
        };
        let depth = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &depth_limited,
        )
        .expect_err("the direct parser must enforce nesting limits");
        assert!(matches!(depth, NetconfEditError::MalformedXml));

        let attribute_limited = MgmtLimits {
            max_xml_attributes_per_element: 1,
            max_xml_namespace_decls: 1,
            ..MgmtLimits::default()
        };
        let attributes = parse_edit_config_xml_with_limits(
            r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ex="urn:example"><ex:system><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &attribute_limited,
        )
        .expect_err("the direct parser must bound attributes and namespace declarations");
        assert!(matches!(attributes, NetconfEditError::MalformedXml));

        let value_limited = MgmtLimits {
            max_value_bytes: 3,
            ..MgmtLimits::default()
        };
        let value = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &value_limited,
        )
        .expect_err("the direct parser must bound text values");
        assert!(matches!(value, NetconfEditError::MalformedXml));

        let rebind = parse_edit_config_xml_with_limits(
            r#"<config xmlns:xml="urn:ietf:params:xml:ns:netconf:base:1.0"><ex:system xmlns:ex="urn:example" xml:operation="merge"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("the XML reserved prefix must not be rebound as NETCONF");
        assert!(matches!(rebind, NetconfEditError::MalformedXml));
    }

    #[test]
    fn prefixed_config_requires_declared_prefix() {
        let err = parse_edit_config_xml_with_limits(
            r#"<nc:config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></nc:config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("undeclared config prefix must fail");

        assert!(matches!(err, NetconfEditError::MalformedXml));
    }

    #[test]
    fn mismatched_end_tag_fails_closed() {
        let err = parse_edit_config_xml_with_limits(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:host></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
            &MgmtLimits::default(),
        )
        .expect_err("mismatched tag must fail");

        assert!(matches!(err, NetconfEditError::MalformedXml));
    }

    #[test]
    fn legacy_public_parser_signature_remains_default_bounded() {
        let edit = parse_edit_config_xml(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
        )
        .expect("three-argument public parser remains available");
        assert_eq!(edit.schema_path, "/ex:system");
    }
}
