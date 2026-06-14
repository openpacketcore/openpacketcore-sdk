//! Schema-aware parser for the bounded NETCONF `<edit-config>` `<config>` element.
//!
//! The parser turns the captured config XML into a normalized [`EditConfigNode`]
//! tree: prefixes are resolved, namespaces are mapped to served modules, element
//! names are mapped to schema paths, `nc:operation` attributes are normalized,
//! and list keys are collected before any non-key children. The emitted tree
//! carries leaf values (which may be secrets) but never logs them or echoes them
//! in error messages.

use std::collections::BTreeMap;

use opc_mgmt_schema::{
    bare_segment, EditConfigNode, EditOperation, NetconfEditError, NodeKind, SchemaRegistry,
};
use quick_xml::events::BytesStart;
use quick_xml::reader::Reader;

use crate::capabilities::NETCONF_BASE_NS;
use crate::xml::EditDefaultOperation;

/// Parses a NETCONF `<config>` element into a schema-bound edit tree.
///
/// `default_operation` is the RFC 6241 `<default-operation>` from the request.
/// Per-node `nc:operation` attributes override it. The returned tree contains
/// exactly one top-level data node (the schema root container).
pub(crate) fn parse_edit_config_xml(
    config_xml: &str,
    registry: &'static dyn SchemaRegistry,
    default_operation: EditDefaultOperation,
) -> Result<EditConfigNode, NetconfEditError> {
    let mut reader = Reader::from_str(config_xml);
    reader.config_mut().trim_text(false);
    let decoder = reader.decoder();

    let mut stack: Vec<Frame> = Vec::new();

    loop {
        match reader
            .read_event()
            .map_err(|_| NetconfEditError::MalformedXml)?
        {
            quick_xml::events::Event::Start(start) => {
                let frame = push_element(&start, &mut stack, registry, decoder, default_operation)?;
                stack.push(frame);
            }
            quick_xml::events::Event::Empty(start) => {
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
                let frame = stack.pop().expect("validated stack has a frame");
                let node = finalize_frame(frame, registry)?;
                if stack.is_empty() {
                    // Closing the `<config>` wrapper: return its single data child.
                    return node
                        .children
                        .into_iter()
                        .next()
                        .ok_or(NetconfEditError::MalformedXml);
                }
                attach_child(&mut stack, node)?;
            }
            quick_xml::events::Event::Text(text) => {
                let decoded = text.decode().map_err(|_| NetconfEditError::MalformedXml)?;
                if let Some(frame) = stack.last_mut() {
                    frame.text.push_str(&decoded);
                }
            }
            quick_xml::events::Event::CData(cdata) => {
                let decoded = cdata.decode().map_err(|_| NetconfEditError::MalformedXml)?;
                if let Some(frame) = stack.last_mut() {
                    frame.text.push_str(&decoded);
                }
            }
            quick_xml::events::Event::Comment(_) => {}
            quick_xml::events::Event::Eof => break,
            _ => return Err(NetconfEditError::MalformedXml),
        }
    }

    Err(NetconfEditError::MalformedXml)
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

#[derive(Clone, Default)]
struct NsScope {
    default: Option<String>,
    bindings: BTreeMap<String, String>,
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
    if parent.node_kind == NodeKind::Leaf {
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
    let mut operation = None;

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
            let (attr_prefix, attr_local) = split_qname(attr.key.as_ref())?;
            let attr_ns = match attr_prefix {
                Some(p) => scope.bindings.get(p).cloned(),
                None => scope.default.clone(),
            };
            if attr_local == "operation" && attr_ns.as_deref() == Some(NETCONF_BASE_NS) {
                operation = Some(parse_operation(value)?);
            } else {
                // Unknown non-namespace attribute; fail closed.
                return Err(NetconfEditError::MalformedXml);
            }
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
/// inherited from `<rpc>`; this helper treats a bare `<config>` as base-NS.
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

    if namespace != NETCONF_BASE_NS {
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
        NodeKind::Leaf => Ok(EditConfigNode {
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
        NodeKind::LeafList => Err(NetconfEditError::UnsupportedShape {
            path: frame.schema_path,
            kind: NodeKind::LeafList,
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
        let edit = parse_edit_config_xml(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>  router1  </ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
        )
        .expect("edit");

        let value = edit.children[0].value.as_deref();
        assert_eq!(value, Some("  router1  "));
    }

    #[test]
    fn parser_preserves_cdata_leaf_text() {
        let edit = parse_edit_config_xml(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname><![CDATA[  router1  ]]></ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
        )
        .expect("edit");

        let value = edit.children[0].value.as_deref();
        assert_eq!(value, Some("  router1  "));
    }

    #[test]
    fn default_operation_none_propagates_to_unannotated_nodes() {
        let edit = parse_edit_config_xml(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::None,
        )
        .expect("edit");

        assert_eq!(edit.operation, EditOperation::None);
        assert_eq!(edit.children[0].operation, EditOperation::None);
    }

    #[test]
    fn prefixed_config_requires_declared_prefix() {
        let err = parse_edit_config_xml(
            r#"<nc:config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:hostname></ex:system></nc:config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
        )
        .expect_err("undeclared config prefix must fail");

        assert!(matches!(err, NetconfEditError::MalformedXml));
    }

    #[test]
    fn mismatched_end_tag_fails_closed() {
        let err = parse_edit_config_xml(
            r#"<config><ex:system xmlns:ex="urn:example"><ex:hostname>router1</ex:host></ex:system></config>"#,
            &REGISTRY,
            EditDefaultOperation::Merge,
        )
        .expect_err("mismatched tag must fail");

        assert!(matches!(err, NetconfEditError::MalformedXml));
    }
}
