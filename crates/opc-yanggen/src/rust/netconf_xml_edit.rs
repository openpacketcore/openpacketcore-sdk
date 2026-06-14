//! Generates a schema-backed NETCONF `<edit-config>` applicator for write paths.
//!
//! The emitted module implements [`opc_mgmt_schema::NetconfXmlEditApplicator`] for
//! the generated root config type. It applies a normalized [`EditConfigNode`]
//! tree produced by the server-side XML parser to a clone of the running config
//! and returns the full candidate. It is fail-closed for shapes whose edit
//! semantics are ambiguous in this slice (leaf-lists, keyless lists, custom
//! typedefs, choice/case).

use super::{
    clean_segment, is_sensitive_name, last_segment, to_pascal_case, to_snake_case,
    RustGenerationError,
};
use crate::emit::CanonicalInput;
use crate::ir::{AllocationStrategy, SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

/// Emits the `netconf_xml_edit` module for the generated crate.
pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut nodes_by_path = HashMap::new();
    for node in &input.nodes {
        nodes_by_path.insert(node.path.clone(), node);
    }

    let mut sorted_nodes: Vec<&SchemaNode> = input.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| a.path.cmp(&b.path));

    let root = sorted_nodes
        .iter()
        .find(|n| is_root_path(&n.path))
        .ok_or_else(|| RustGenerationError::new("netconf_xml_edit: no root container found"))?;

    let root_type = to_pascal_case(clean_segment(last_segment(&root.path)));
    let root_type_ident = format_ident!("{}", root_type);

    let mut apply_fns = Vec::new();
    for node in &sorted_nodes {
        match node.kind {
            SchemaNodeKind::Container | SchemaNodeKind::List => {
                apply_fns.push(apply_children_fn(node, &nodes_by_path, input)?);
            }
            SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => {}
            SchemaNodeKind::Choice | SchemaNodeKind::Case => {
                return Err(RustGenerationError::new(format!(
                    "netconf_xml_edit: unsupported node kind {:?} at {}",
                    node.kind, node.path
                )));
            }
        }
    }

    // Generate list applicator functions after children functions so every
    // apply_children_<list> helper is in scope.
    for node in &sorted_nodes {
        if node.kind == SchemaNodeKind::List {
            apply_fns.push(apply_list_fn(node, &nodes_by_path)?);
        }
    }

    let root_apply = apply_root_fn(root, &nodes_by_path)?;

    let tokens = quote! {
        #[allow(unused_imports)]
        use super::types::*;
        use opc_mgmt_schema::{
            EditConfigNode, EditOperation, NetconfEditError, NetconfXmlEditApplicator, NodeKind,
        };

        /// Generated NETCONF XML edit applicator for this schema.
        pub struct GeneratedNetconfXmlEditApplicator;

        impl NetconfXmlEditApplicator<super::types::#root_type_ident> for GeneratedNetconfXmlEditApplicator {
            fn apply_edit_config(
                &self,
                running: &super::types::#root_type_ident,
                edit: &EditConfigNode,
            ) -> Result<super::types::#root_type_ident, NetconfEditError> {
                let mut candidate = running.clone();
                apply_root(edit, &mut candidate)?;
                Ok(candidate)
            }
        }

        /// Returns the generated NETCONF XML edit applicator for this schema.
        pub fn applicator() -> GeneratedNetconfXmlEditApplicator {
            GeneratedNetconfXmlEditApplicator
        }

        #root_apply

        #(#apply_fns)*
    };

    Ok(tokens.to_string())
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

fn path_to_snake(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(clean_segment)
        .map(to_snake_case)
        .collect::<Vec<_>>()
        .join("_")
}

fn apply_root_fn(
    root: &SchemaNode,
    _nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let children_fn_ident = format_ident!("apply_children_{}", path_to_snake(&root.path));
    let path = &root.path;
    let root_type_ident = format_ident!(
        "{}",
        to_pascal_case(clean_segment(last_segment(&root.path)))
    );

    Ok(quote! {
        fn apply_root(
            node: &EditConfigNode,
            value: &mut super::types::#root_type_ident,
        ) -> Result<(), NetconfEditError> {
            if node.schema_path != #path {
                return Err(NetconfEditError::UnknownPath(node.schema_path.to_string()));
            }
            match node.operation {
                EditOperation::Replace => {
                    *value = super::types::#root_type_ident::default();
                    #children_fn_ident(&node.children, value)?;
                }
                EditOperation::Merge | EditOperation::None => {
                    #children_fn_ident(&node.children, value)?;
                }
                EditOperation::Create | EditOperation::Delete | EditOperation::Remove => {
                    return Err(NetconfEditError::OperationNotSupported {
                        path: node.schema_path,
                        operation: node.operation,
                        kind: NodeKind::Container,
                    });
                }
            }
            Ok(())
        }
    })
}

fn apply_children_fn(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
    input: &CanonicalInput,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("apply_children_{}", path_to_snake(&node.path));
    let type_ident = format_ident!(
        "{}",
        to_pascal_case(clean_segment(last_segment(&node.path)))
    );

    let mut arms = TokenStream::new();
    for child_path in &node.child_paths {
        let Some(child) = nodes_by_path.get(child_path) else {
            continue;
        };
        let child_name = clean_segment(last_segment(&child.path));
        let field_ident = format_ident!("{}", to_snake_case(child_name));
        let is_sensitive = is_sensitive_node(child);
        let child_path_lit = &child.path;

        let arm = match child.kind {
            SchemaNodeKind::Leaf => {
                let parse_expr = parse_leaf_value_expr(child, nodes_by_path)?;
                let assign_expr = if child.config {
                    if is_sensitive {
                        quote! {
                            match child.operation {
                                EditOperation::Delete => {
                                    if value.#field_ident.is_absent() {
                                        return Err(NetconfEditError::OperationNotSupported {
                                            path: child.schema_path,
                                            operation: child.operation,
                                            kind: NodeKind::Leaf,
                                        });
                                    }
                                    value.#field_ident = SecretLeaf::new(LeafPresence::Absent);
                                }
                                EditOperation::Remove => {
                                    if !value.#field_ident.is_absent() {
                                        value.#field_ident = SecretLeaf::new(LeafPresence::Absent);
                                    }
                                }
                                EditOperation::Create => {
                                    if !value.#field_ident.is_absent() {
                                        return Err(NetconfEditError::OperationNotSupported {
                                            path: child.schema_path,
                                            operation: child.operation,
                                            kind: NodeKind::Leaf,
                                        });
                                    }
                                    let _v = child.value.as_deref().unwrap_or("");
                                    #parse_expr
                                    value.#field_ident = SecretLeaf::new(LeafPresence::Explicit(parsed));
                                }
                                EditOperation::Replace | EditOperation::Merge => {
                                    let _v = child.value.as_deref().unwrap_or("");
                                    #parse_expr
                                    value.#field_ident = SecretLeaf::new(LeafPresence::Explicit(parsed));
                                }
                                EditOperation::None => {}
                            }
                        }
                    } else {
                        quote! {
                            match child.operation {
                                EditOperation::Delete => {
                                    if value.#field_ident.is_absent() {
                                        return Err(NetconfEditError::OperationNotSupported {
                                            path: child.schema_path,
                                            operation: child.operation,
                                            kind: NodeKind::Leaf,
                                        });
                                    }
                                    value.#field_ident = LeafPresence::Absent;
                                }
                                EditOperation::Remove => {
                                    if !value.#field_ident.is_absent() {
                                        value.#field_ident = LeafPresence::Absent;
                                    }
                                }
                                EditOperation::Create => {
                                    if !value.#field_ident.is_absent() {
                                        return Err(NetconfEditError::OperationNotSupported {
                                            path: child.schema_path,
                                            operation: child.operation,
                                            kind: NodeKind::Leaf,
                                        });
                                    }
                                    let _v = child.value.as_deref().unwrap_or("");
                                    #parse_expr
                                    value.#field_ident = LeafPresence::Explicit(parsed);
                                }
                                EditOperation::Replace | EditOperation::Merge => {
                                    let _v = child.value.as_deref().unwrap_or("");
                                    #parse_expr
                                    value.#field_ident = LeafPresence::Explicit(parsed);
                                }
                                EditOperation::None => {}
                            }
                        }
                    }
                } else {
                    quote! {
                        return Err(NetconfEditError::ReadOnly { path: child.schema_path });
                    }
                };
                quote! {
                    #child_path_lit => {
                        #assign_expr
                    }
                }
            }
            SchemaNodeKind::Container => {
                let child_type_ident = format_ident!("{}", to_pascal_case(child_name));
                let is_boxed = is_boxed_container(child, input);
                let new_expr = if is_boxed {
                    quote! { Box::new(#child_type_ident::default()) }
                } else {
                    quote! { #child_type_ident::default() }
                };
                let children_fn_ident =
                    format_ident!("apply_children_{}", path_to_snake(&child.path));
                quote! {
                    #child_path_lit => {
                        match child.operation {
                            EditOperation::Delete => {
                                value.#field_ident = None;
                            }
                            EditOperation::Remove => {
                                if value.#field_ident.is_some() {
                                    value.#field_ident = None;
                                }
                            }
                            EditOperation::Create => {
                                if value.#field_ident.is_some() {
                                    return Err(NetconfEditError::OperationNotSupported {
                                        path: child.schema_path,
                                        operation: child.operation,
                                        kind: NodeKind::Container,
                                    });
                                }
                                let mut new_container = #new_expr;
                                #children_fn_ident(&child.children, &mut new_container)?;
                                value.#field_ident = Some(new_container);
                            }
                            EditOperation::Replace => {
                                let mut new_container = #new_expr;
                                #children_fn_ident(&child.children, &mut new_container)?;
                                value.#field_ident = Some(new_container);
                            }
                            EditOperation::Merge => {
                                let container = value.#field_ident.get_or_insert_with(|| #new_expr);
                                #children_fn_ident(&child.children, container)?;
                            }
                            EditOperation::None => {
                                if let Some(container) = value.#field_ident.as_mut() {
                                    #children_fn_ident(&child.children, container)?;
                                } else if child.children.iter().any(|nested| nested.operation != EditOperation::None) {
                                    let mut new_container = #new_expr;
                                    #children_fn_ident(&child.children, &mut new_container)?;
                                    let baseline = #new_expr;
                                    if new_container != baseline {
                                        value.#field_ident = Some(new_container);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            SchemaNodeKind::List => {
                let list_fn_ident = format_ident!("apply_{}", path_to_snake(&child.path));
                quote! {
                    #child_path_lit => {
                        #list_fn_ident(child, &mut value.#field_ident)?;
                    }
                }
            }
            SchemaNodeKind::LeafList => {
                quote! {
                    #child_path_lit => {
                        return Err(NetconfEditError::UnsupportedShape {
                            path: child.schema_path,
                            kind: NodeKind::LeafList,
                        });
                    }
                }
            }
            SchemaNodeKind::Choice | SchemaNodeKind::Case => quote! {},
        };
        arms.extend(arm);
    }

    Ok(quote! {
        fn #fn_ident(
            children: &[EditConfigNode],
            value: &mut #type_ident,
        ) -> Result<(), NetconfEditError> {
            for child in children {
                match child.schema_path {
                    #arms
                    _ => {
                        return Err(NetconfEditError::UnknownPath(
                            child.schema_path.to_string(),
                        ));
                    }
                }
            }
            Ok(())
        }
    })
}

fn apply_list_fn(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("apply_{}", path_to_snake(&node.path));
    let children_fn_ident = format_ident!("apply_children_{}", path_to_snake(&node.path));
    let entry_type_ident = format_ident!(
        "{}",
        to_pascal_case(clean_segment(last_segment(&node.path)))
    );
    let path = &node.path;

    if node.key_leaves.is_empty() {
        return Ok(quote! {
            fn #fn_ident(
                node: &EditConfigNode,
                _map: &mut Vec<#entry_type_ident>,
            ) -> Result<(), NetconfEditError> {
                Err(NetconfEditError::UnsupportedShape {
                    path: node.schema_path,
                    kind: NodeKind::List,
                })
            }
        });
    }

    let key_type = list_key_type(node, nodes_by_path);

    let mut parse_keys = Vec::new();
    let mut key_assigns = Vec::new();
    let mut key_struct_fields = Vec::new();

    if node.key_leaves.len() == 1 {
        let key_leaf = &node.key_leaves[0];
        let key_bare = clean_segment(key_leaf);
        let key_field_ident = format_ident!("{}", to_snake_case(key_bare));
        let key_leaf_node = find_key_leaf_node(node, key_leaf, nodes_by_path).ok_or_else(|| {
            RustGenerationError::new(format!(
                "netconf_xml_edit: list {} key leaf {} not found",
                node.path, key_leaf
            ))
        })?;
        let parse = parse_leaf_value_expr(key_leaf_node, nodes_by_path)?;
        parse_keys.push(quote! {
            let key_val = node.list_keys.get(#key_bare).ok_or(NetconfEditError::MissingKey {
                path: node.schema_path,
                key: #key_leaf,
            })?;
            let _v = key_val.as_str();
            #parse
        });
        let is_sensitive = is_sensitive_node(key_leaf_node);
        let assign = if is_sensitive {
            quote! { entry.#key_field_ident = SecretLeaf::new(LeafPresence::Explicit(parsed_key.clone())); }
        } else {
            quote! { entry.#key_field_ident = LeafPresence::Explicit(parsed_key.clone()); }
        };
        key_assigns.push(assign);
    } else {
        for key_leaf in &node.key_leaves {
            let key_bare = clean_segment(key_leaf);
            let key_field_ident = format_ident!("{}", to_snake_case(key_bare));
            let key_leaf_node =
                find_key_leaf_node(node, key_leaf, nodes_by_path).ok_or_else(|| {
                    RustGenerationError::new(format!(
                        "netconf_xml_edit: list {} key leaf {} not found",
                        node.path, key_leaf
                    ))
                })?;
            let parse = parse_leaf_value_expr(key_leaf_node, nodes_by_path)?;
            parse_keys.push(quote! {
                let key_val = node.list_keys.get(#key_bare).ok_or(NetconfEditError::MissingKey {
                    path: node.schema_path,
                    key: #key_leaf,
                })?;
                let _v = key_val.as_str();
                #parse
                let #key_field_ident = parsed;
            });
            key_struct_fields.push(quote! { #key_field_ident: #key_field_ident.clone() });
            let is_sensitive = is_sensitive_node(key_leaf_node);
            let assign = if is_sensitive {
                quote! { entry.#key_field_ident = SecretLeaf::new(LeafPresence::Explicit(#key_field_ident.clone())); }
            } else {
                quote! { entry.#key_field_ident = LeafPresence::Explicit(#key_field_ident.clone()); }
            };
            key_assigns.push(assign);
        }
    }

    let build_key = if node.key_leaves.len() == 1 {
        quote! { let parsed_key = parsed; }
    } else {
        quote! {
            let parsed_key = #key_type {
                #(#key_struct_fields),*
            };
        }
    };

    let key_leaves_lit: Vec<TokenStream> = node
        .key_leaves
        .iter()
        .map(|k| {
            let k = k.as_str();
            quote! { #k }
        })
        .collect();

    Ok(quote! {
        fn #fn_ident(
            node: &EditConfigNode,
            map: &mut std::collections::BTreeMap<#key_type, #entry_type_ident>,
        ) -> Result<(), NetconfEditError> {
            if node.schema_path != #path {
                return Err(NetconfEditError::UnknownPath(node.schema_path.to_string()));
            }
            #(#parse_keys)*
            #build_key
            let expected_keys: &[&str] = &[#(#key_leaves_lit),*];
            for key in node.list_keys.keys() {
                let bare = opc_mgmt_schema::bare_segment(key);
                if !expected_keys.iter().any(|k| opc_mgmt_schema::bare_segment(k) == bare) {
                    return Err(NetconfEditError::ExtraKey {
                        path: node.schema_path,
                        key: key.clone(),
                    });
                }
            }
            match node.operation {
                EditOperation::Delete => {
                    if map.remove(&parsed_key).is_none() {
                        return Err(NetconfEditError::OperationNotSupported {
                            path: node.schema_path,
                            operation: node.operation,
                            kind: NodeKind::List,
                        });
                    }
                }
                EditOperation::Remove => {
                    map.remove(&parsed_key);
                }
                EditOperation::Create => {
                    if map.contains_key(&parsed_key) {
                        return Err(NetconfEditError::OperationNotSupported {
                            path: node.schema_path,
                            operation: node.operation,
                            kind: NodeKind::List,
                        });
                    }
                    let mut entry = #entry_type_ident::default();
                    #(#key_assigns)*
                    #children_fn_ident(&node.children, &mut entry)?;
                    map.insert(parsed_key, entry);
                }
                EditOperation::Replace => {
                    let mut entry = #entry_type_ident::default();
                    #(#key_assigns)*
                    #children_fn_ident(&node.children, &mut entry)?;
                    map.insert(parsed_key, entry);
                }
                EditOperation::Merge => {
                    let entry = map.entry(parsed_key.clone()).or_default();
                    #(#key_assigns)*
                    #children_fn_ident(&node.children, entry)?;
                }
                EditOperation::None => {
                    if let Some(entry) = map.get_mut(&parsed_key) {
                        #children_fn_ident(&node.children, entry)?;
                    } else if node.children.iter().any(|child| child.operation != EditOperation::None) {
                        let mut entry = #entry_type_ident::default();
                        #(#key_assigns)*
                        let baseline = entry.clone();
                        #children_fn_ident(&node.children, &mut entry)?;
                        if entry != baseline {
                            map.insert(parsed_key, entry);
                        }
                    }
                }
            }
            Ok(())
        }
    })
}

fn parse_leaf_value_expr(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let path = &node.path;
    let resolved = resolved_type(node, nodes_by_path);
    let expr = match resolved {
        Some(TypeRef::Boolean) => quote! {
            let parsed = match _v.trim() {
                "true" => true,
                "false" => false,
                _ => return Err(NetconfEditError::InvalidValue { path: #path }),
            };
        },
        Some(TypeRef::Uint16) => quote! {
            let parsed = _v.trim().parse::<u16>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
        },
        Some(TypeRef::Uint32) => quote! {
            let parsed = _v.trim().parse::<u32>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
        },
        Some(TypeRef::Int64) => quote! {
            let parsed = YangInt64(_v.trim().parse::<i64>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?);
        },
        Some(TypeRef::Decimal64) => quote! {
            let parsed = YangDecimal64(_v.trim().parse::<f64>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?);
        },
        Some(TypeRef::Empty) => quote! {
            if !_v.trim().is_empty() {
                return Err(NetconfEditError::InvalidValue { path: #path });
            }
            let parsed = YangEmpty;
        },
        Some(TypeRef::String)
        | Some(TypeRef::IdentityRef { .. })
        | Some(TypeRef::LeafRef { .. }) => quote! {
            let parsed = _v.to_string();
        },
        Some(TypeRef::Custom { .. }) | None => {
            return Err(RustGenerationError::new(format!(
                "netconf_xml_edit: unsupported leaf type at {}",
                node.path
            )))
        }
    };
    Ok(expr)
}

fn resolved_type<'a>(
    node: &'a SchemaNode,
    nodes_by_path: &'a HashMap<String, &SchemaNode>,
) -> Option<&'a TypeRef> {
    let mut ty = node.type_ref.as_ref();
    if let Some(TypeRef::LeafRef { target_path }) = ty {
        if let Some(target) = nodes_by_path.get(target_path) {
            ty = target.type_ref.as_ref();
        }
    }
    ty
}

fn is_sensitive_node(node: &SchemaNode) -> bool {
    if let Some(ref dc) = node.data_class {
        dc != "public" && dc != "operational"
    } else {
        is_sensitive_name(clean_segment(last_segment(&node.path)))
    }
}

fn is_boxed_container(node: &SchemaNode, input: &CanonicalInput) -> bool {
    for shape in &input.stack_shapes {
        if shape.yang_path == node.path && shape.allocation == AllocationStrategy::Boxed {
            return true;
        }
    }
    false
}

fn list_key_type(
    list_node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> TokenStream {
    if list_node.key_leaves.len() == 1 {
        let key_name = &list_node.key_leaves[0];
        for child_path in &list_node.child_paths {
            if let Some(child) = nodes_by_path.get(child_path) {
                if clean_segment(last_segment(&child.path)) == clean_segment(key_name) {
                    return raw_type(child, nodes_by_path);
                }
            }
        }
        quote! { String }
    } else {
        let name = clean_segment(last_segment(&list_node.path));
        let struct_name = format_ident!("{}Key", to_pascal_case(name));
        quote! { #struct_name }
    }
}

fn raw_type(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    let mut visited = std::collections::HashSet::new();
    raw_type_internal(node, nodes_by_path, &mut visited)
}

fn raw_type_internal(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
    visited: &mut std::collections::HashSet<String>,
) -> TokenStream {
    if visited.contains(&node.path) {
        return quote! { String };
    }
    visited.insert(node.path.clone());
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String) => quote! { String },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Int64) => quote! { YangInt64 },
        Some(TypeRef::Decimal64) => quote! { YangDecimal64 },
        Some(TypeRef::Empty) => quote! { YangEmpty },
        Some(TypeRef::IdentityRef { .. }) | Some(TypeRef::LeafRef { .. }) => quote! { String },
        Some(TypeRef::Custom { name }) => {
            let custom_name = format_ident!("{}", to_pascal_case(name));
            quote! { #custom_name }
        }
        None => quote! { String },
    }
}

fn find_key_leaf_node<'a>(
    list_node: &SchemaNode,
    key_name: &str,
    nodes_by_path: &'a HashMap<String, &SchemaNode>,
) -> Option<&'a SchemaNode> {
    let key_bare = clean_segment(key_name);
    list_node.child_paths.iter().find_map(|cp| {
        nodes_by_path.get(cp).and_then(|child| {
            if child.kind == SchemaNodeKind::Leaf
                && clean_segment(last_segment(&child.path)) == key_bare
            {
                Some(*child)
            } else {
                None
            }
        })
    })
}
