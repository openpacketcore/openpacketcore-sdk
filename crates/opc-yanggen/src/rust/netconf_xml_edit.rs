//! Generates a schema-backed NETCONF `<edit-config>` applicator for write paths.
//!
//! The emitted module implements `opc_mgmt_schema::NetconfXmlEditApplicator` for
//! the generated root config type. It applies a normalized `EditConfigNode`
//! tree produced by the server-side XML parser to a clone of the running config
//! and returns the full candidate. It supports schema-typed leaf-list entries
//! and is fail-closed for shapes whose edit semantics remain ambiguous in this
//! slice (keyless lists, custom typedefs, choice/case).

use super::NodeIndex;
use super::{
    clean_segment, is_sensitive_name, last_segment, to_pascal_case, to_snake_case,
    RustGenerationError,
};
use crate::emit::CanonicalInput;
use crate::ir::{AllocationStrategy, SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Emits the `netconf_xml_edit` module for the generated crate.
pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let has_state_lists = super::has_state_keyed_lists(input);
    let nodes_by_path = NodeIndex::new(&input.nodes);

    let mut sorted_nodes: Vec<&SchemaNode> = input.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| a.path.cmp(&b.path));

    let root = sorted_nodes
        .iter()
        .find(|n| is_root_path(&n.path))
        .ok_or_else(|| RustGenerationError::new("netconf_xml_edit: no root container found"))?;

    let root_type = nodes_by_path.type_name(root);
    let root_type_ident = format_ident!("{}", root_type);

    let mut apply_fns = Vec::new();
    for node in &sorted_nodes {
        match node.kind {
            SchemaNodeKind::Container | SchemaNodeKind::List => {
                apply_fns.push(apply_children_fn(node, &nodes_by_path, input)?);
            }
            SchemaNodeKind::Leaf => {}
            SchemaNodeKind::LeafList => {
                apply_fns.push(apply_leaf_list_fn(node, &nodes_by_path)?);
            }
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
            apply_fns.push(apply_list_fn(node, &nodes_by_path, has_state_lists)?);
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

fn apply_root_fn(
    root: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let children_fn_ident =
        format_ident!("apply_children_{}", nodes_by_path.helper_name(&root.path));
    let path = &root.path;
    let root_type_ident = format_ident!("{}", nodes_by_path.type_name(root));

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
    nodes_by_path: &NodeIndex<'_>,
    input: &CanonicalInput,
) -> Result<TokenStream, RustGenerationError> {
    let has_state_lists = super::has_state_keyed_lists(input);
    let fn_ident = format_ident!("apply_children_{}", nodes_by_path.helper_name(&node.path));
    let type_ident = format_ident!("{}", nodes_by_path.type_name(node));

    let mut leaf_list_group_arms = TokenStream::new();
    let mut leaf_list_apply_stmts = TokenStream::new();
    let mut list_key_sets = TokenStream::new();
    let mut singleton_paths = Vec::new();
    let mut arms = TokenStream::new();
    for child_path in &node.child_paths {
        let Some(child) = nodes_by_path.get(child_path) else {
            continue;
        };
        let child_name = clean_segment(last_segment(&child.path));
        let field_ident = format_ident!("{}", to_snake_case(child_name));
        let is_sensitive = is_sensitive_node(child);
        let child_path_lit = &child.path;
        if matches!(child.kind, SchemaNodeKind::Leaf | SchemaNodeKind::Container) {
            singleton_paths.push(child_path_lit);
        }

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
                let child_type_ident = format_ident!("{}", nodes_by_path.type_name(child));
                let is_boxed = is_boxed_container(child, input);
                let new_expr = if is_boxed {
                    quote! { Box::new(#child_type_ident::default()) }
                } else {
                    quote! { #child_type_ident::default() }
                };
                let default_constructor = if has_state_lists && !is_boxed {
                    quote! { #child_type_ident::default }
                } else {
                    quote! { || #new_expr }
                };
                let children_fn_ident =
                    format_ident!("apply_children_{}", nodes_by_path.helper_name(&child.path));
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
                                let container = value.#field_ident.get_or_insert_with(#default_constructor);
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
                let list_fn_ident =
                    format_ident!("apply_{}", nodes_by_path.helper_name(&child.path));
                let key_set = if child.key_leaves.is_empty() {
                    TokenStream::new()
                } else {
                    let keys_ident =
                        format_ident!("{}_edit_keys", nodes_by_path.helper_name(&child.path));
                    list_key_sets.extend(quote! {
                        let mut #keys_ident = std::collections::BTreeSet::new();
                    });
                    quote! { , &mut #keys_ident }
                };
                quote! {
                    #child_path_lit => {
                        #list_fn_ident(child, &mut value.#field_ident #key_set)?;
                    }
                }
            }
            SchemaNodeKind::LeafList => {
                let leaf_list_fn_ident =
                    format_ident!("apply_{}", nodes_by_path.helper_name(&child.path));
                let nodes_ident =
                    format_ident!("{}_entries", nodes_by_path.helper_name(&child.path));
                let values = if is_sensitive {
                    quote! { value.#field_ident.get_mut() }
                } else {
                    quote! { &mut value.#field_ident }
                };
                leaf_list_group_arms.extend(quote! {
                    #child_path_lit => {
                        leaf_list_children
                            .entry(child.schema_path)
                            .or_default()
                            .push(child);
                    }
                });
                leaf_list_apply_stmts.extend(quote! {
                    if let Some(#nodes_ident) = leaf_list_children.get(#child_path_lit) {
                        #leaf_list_fn_ident(#nodes_ident, #values)?;
                    }
                });
                quote! {
                    #child_path_lit => {}
                }
            }
            SchemaNodeKind::Choice | SchemaNodeKind::Case => quote! {},
        };
        arms.extend(arm);
    }

    let leaf_list_grouping = if leaf_list_group_arms.is_empty() {
        TokenStream::new()
    } else {
        quote! {
            let mut leaf_list_children: std::collections::BTreeMap<
                &'static str,
                Vec<&EditConfigNode>,
            > = std::collections::BTreeMap::new();
            for child in children {
                match child.schema_path {
                    #leaf_list_group_arms
                    _ => {}
                }
            }
            #leaf_list_apply_stmts
        }
    };

    let check_singletons = if singleton_paths.is_empty() {
        TokenStream::new()
    } else {
        let singleton_arm = if has_state_lists {
            quote! {
                #(#singleton_paths)|* if !singletons.insert(child.schema_path) => {
                    return Err(NetconfEditError::InvalidValue { path: child.schema_path });
                }
            }
        } else {
            quote! {
                #(#singleton_paths)|* => {
                    if !singletons.insert(child.schema_path) {
                        return Err(NetconfEditError::InvalidValue { path: child.schema_path });
                    }
                }
            }
        };
        quote! {
            // RFC 6241 section 7.2 leaves repeated operations on one
            // conceptual node undefined. Reject them before applying children;
            // otherwise repeated containers can bypass leaf-list grouping.
            let mut singletons = std::collections::BTreeSet::new();
            for child in children {
                match child.schema_path {
                    #singleton_arm
                    _ => {}
                }
            }
        }
    };

    let rejects_every_child = !node.config
        && node.kind == SchemaNodeKind::List
        && !node.key_leaves.is_empty()
        && node.child_paths.iter().all(|path| {
            nodes_by_path
                .get(path)
                .is_some_and(|child| child.kind == SchemaNodeKind::Leaf && !child.config)
        });
    let value_param = format_ident!(
        "{}",
        if !rejects_every_child
            && (!nodes_by_path.expanded_profile
                || node
                    .child_paths
                    .iter()
                    .any(|path| { nodes_by_path.get(path).is_some_and(|child| child.config) }))
        {
            "value"
        } else {
            "_value"
        }
    );
    let apply_child = quote! {
        match child.schema_path {
            #arms
            _ => {
                return Err(NetconfEditError::UnknownPath(
                    child.schema_path.to_string(),
                ));
            }
        }
    };
    let apply_children = if rejects_every_child {
        quote! {
            if let Some(child) = children.first() {
                #apply_child
            }
        }
    } else {
        quote! {
            for child in children {
                #apply_child
            }
        }
    };

    Ok(quote! {
        fn #fn_ident(
            children: &[EditConfigNode],
            #value_param: &mut #type_ident,
        ) -> Result<(), NetconfEditError> {
            #check_singletons
            #list_key_sets
            #leaf_list_grouping
            #apply_children
            Ok(())
        }
    })
}

/// Emit an applicator for one schema leaf-list.
///
/// The parser represents each XML leaf-list element as an individual child
/// node. Applying those nodes as a group keeps the generated collection work
/// bounded and preserves their document order. Per RFC 7950 section 7.7.9, a
/// leaf-list entry `replace` is an entry upsert, not a request to clear the
/// collection. Enclosing container/root `replace` resets the `Vec` before this
/// helper is called, so a full-subtree replacement still receives exactly the
/// XML entries in document order. That preserves `ordered-by user` order and
/// provides a deterministic server order for `ordered-by system`.
fn apply_leaf_list_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("apply_{}", nodes_by_path.helper_name(&node.path));
    let key_fn_ident = format_ident!("leaf_list_key_{}", nodes_by_path.helper_name(&node.path));
    let path = &node.path;
    let element_type = raw_type(node, nodes_by_path);

    if !node.config {
        return Ok(quote! {
            fn #fn_ident(
                nodes: &[&EditConfigNode],
                _values: &mut Vec<#element_type>,
            ) -> Result<(), NetconfEditError> {
                let path = nodes.first().map_or(#path, |node| node.schema_path);
                Err(NetconfEditError::ReadOnly { path })
            }
        });
    }

    if matches!(
        resolved_type(node, nodes_by_path),
        Some(TypeRef::Custom { .. }) | None
    ) {
        return Ok(quote! {
            fn #fn_ident(
                nodes: &[&EditConfigNode],
                _values: &mut Vec<#element_type>,
            ) -> Result<(), NetconfEditError> {
                let path = nodes.first().map_or(#path, |node| node.schema_path);
                Err(NetconfEditError::UnsupportedShape {
                    path,
                    kind: NodeKind::LeafList,
                })
            }
        });
    }

    let parse_expr = parse_leaf_value_expr(node, nodes_by_path)?;
    let key_expr = leaf_list_value_key_expr(node, nodes_by_path)?;

    Ok(quote! {
        fn #key_fn_ident(value: &#element_type) -> String {
            #key_expr
        }

        fn #fn_ident(
            nodes: &[&EditConfigNode],
            values: &mut Vec<#element_type>,
        ) -> Result<(), NetconfEditError> {
            let mut edits = Vec::with_capacity(nodes.len());
            let mut edit_keys = std::collections::BTreeSet::new();
            let has_mutation = nodes
                .iter()
                .any(|node| node.operation != EditOperation::None);
            for node in nodes {
                if node.schema_path != #path {
                    return Err(NetconfEditError::UnknownPath(node.schema_path.to_string()));
                }
                if !node.children.is_empty() {
                    return Err(NetconfEditError::MalformedXml);
                }
                if !node.list_keys.is_empty() {
                    return Err(NetconfEditError::KeyOnNonList {
                        path: node.schema_path,
                    });
                }
                let _v = node
                    .value
                    .as_deref()
                    .ok_or(NetconfEditError::InvalidValue { path: #path })?;
                #parse_expr
                let key = #key_fn_ident(&parsed);
                if !edit_keys.insert(key.clone()) {
                    return Err(NetconfEditError::InvalidValue { path: #path });
                }
                edits.push((node.operation, parsed, key));
            }

            if !has_mutation {
                return Ok(());
            }

            // Refuse to mutate an invalid running collection. A complete
            // enclosing-subtree replacement starts from `Default` before this
            // helper runs, so it is still able to repair an old collection.
            let mut current_keys = std::collections::BTreeSet::new();
            for value in values.iter() {
                if !current_keys.insert(#key_fn_ident(value)) {
                    return Err(NetconfEditError::InvalidValue { path: #path });
                }
            }

            let mut removed_keys = std::collections::BTreeSet::new();
            let mut additions = Vec::new();
            for (operation, parsed, key) in edits {
                match operation {
                    // RFC 7950 section 7.7.9 defines entry-level `replace` as
                    // an upsert. The enclosing root/container handles a
                    // collection replacement by resetting the parent first.
                    EditOperation::Merge | EditOperation::Replace => {
                        if current_keys.insert(key) {
                            additions.push(parsed);
                        }
                    }
                    EditOperation::Create => {
                        if !current_keys.insert(key) {
                            return Err(NetconfEditError::OperationNotSupported {
                                path: #path,
                                operation,
                                kind: NodeKind::LeafList,
                            });
                        }
                        additions.push(parsed);
                    }
                    EditOperation::Delete => {
                        if !current_keys.remove(&key) {
                            return Err(NetconfEditError::OperationNotSupported {
                                path: #path,
                                operation,
                                kind: NodeKind::LeafList,
                            });
                        }
                        removed_keys.insert(key);
                    }
                    EditOperation::Remove => {
                        if current_keys.remove(&key) {
                            removed_keys.insert(key);
                        }
                    }
                    EditOperation::None => {}
                }
            }
            if !removed_keys.is_empty() {
                values.retain(|value| !removed_keys.contains(&#key_fn_ident(value)));
            }
            values.extend(additions);
            Ok(())
        }
    })
}

/// Emits a deterministic typed identity key for a leaf-list value.
///
/// The generated applicator needs value identity for YANG leaf-list entry
/// operations, but generated numeric wrappers deliberately expose only
/// `PartialEq`. A canonical string key avoids an O(n²) scan while preserving
/// numeric equivalence (for example, distinct lexical `uint16` spellings) and
/// does not appear in errors or logs.
fn leaf_list_value_key_expr(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean) => Ok(quote! {
            if *value { "true".to_string() } else { "false".to_string() }
        }),
        Some(TypeRef::Uint8)
        | Some(TypeRef::Int8)
        | Some(TypeRef::Int16)
        | Some(TypeRef::Int32)
        | Some(TypeRef::Uint16)
        | Some(TypeRef::Uint32) => Ok(quote! { value.to_string() }),
        Some(TypeRef::Uint64) => Ok(quote! { value.0.to_string() }),
        Some(TypeRef::Int64) => Ok(quote! { value.0.to_string() }),
        Some(TypeRef::Decimal64) => Ok(quote! {
            let bits = if value.0 == 0.0 { 0_u64 } else { value.0.to_bits() };
            bits.to_string()
        }),
        Some(TypeRef::Empty) => Ok(quote! { String::new() }),
        Some(TypeRef::String | TypeRef::RestrictedString { .. })
        | Some(TypeRef::IdentityRef { .. })
        | Some(TypeRef::LeafRef { .. })
        | Some(TypeRef::Enumeration { .. }) => Ok(quote! { value.clone() }),
        Some(TypeRef::Custom { .. }) | None => Err(RustGenerationError::new(format!(
            "netconf_xml_edit: unsupported leaf-list type at {}",
            node.path
        ))),
    }
}

fn apply_list_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
    has_state_lists: bool,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("apply_{}", nodes_by_path.helper_name(&node.path));
    let children_fn_ident =
        format_ident!("apply_children_{}", nodes_by_path.helper_name(&node.path));
    let entry_type_ident = format_ident!("{}", nodes_by_path.type_name(node));
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
    let mut key_initializers = Vec::new();
    let mut key_struct_fields = Vec::new();
    let mut single_key_is_sensitive = false;
    let mut cloned_parsed = quote! { parsed.clone() };
    let mut cloned_map_key = quote! { parsed_key.clone() };

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
        single_key_is_sensitive = is_sensitive;
        cloned_parsed = super::types::cloned_key_value(
            key_leaf_node,
            nodes_by_path,
            quote! { parsed },
            has_state_lists,
        );
        if !is_sensitive {
            cloned_map_key = super::types::cloned_key_value(
                key_leaf_node,
                nodes_by_path,
                quote! { parsed_key },
                has_state_lists,
            );
        }
        let raw_key = if is_sensitive {
            cloned_parsed.clone()
        } else {
            cloned_map_key.clone()
        };
        let key_value = super::types::explicit_leaf_value(key_leaf_node, raw_key);
        key_assigns.push(quote! { entry.#key_field_ident = #key_value; });
        key_initializers.push(quote! { #key_field_ident: #key_value, });
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
            let cloned_key = super::types::cloned_key_value(
                key_leaf_node,
                nodes_by_path,
                quote! { #key_field_ident },
                has_state_lists,
            );
            key_struct_fields.push(if cloned_key.to_string() == key_field_ident.to_string() {
                quote! { #key_field_ident }
            } else {
                quote! { #key_field_ident: #cloned_key }
            });
            let key_value = super::types::explicit_leaf_value(key_leaf_node, cloned_key);
            key_assigns.push(quote! { entry.#key_field_ident = #key_value; });
            key_initializers.push(quote! { #key_field_ident: #key_value, });
        }
    }

    let build_key = if node.key_leaves.len() == 1 && single_key_is_sensitive {
        quote! { let parsed_key = SensitiveKey::from(#cloned_parsed); }
    } else if node.key_leaves.len() == 1 {
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

    let map_type = if super::is_user_ordered(node) {
        quote! { super::serde::UserOrderedMap<#key_type, #entry_type_ident> }
    } else {
        quote! { std::collections::BTreeMap<#key_type, #entry_type_ident> }
    };
    let upsert = if super::is_user_ordered(node) {
        quote! { *map.entry(parsed_key).or_default() = entry; }
    } else {
        quote! { map.insert(parsed_key, entry); }
    };
    let new_entry = if has_state_lists {
        let remaining_fields = if node.child_paths.len() == node.key_leaves.len() {
            quote! {}
        } else {
            quote! { ..Default::default() }
        };
        quote! {
            let mut entry = #entry_type_ident {
                #(#key_initializers)*
                #remaining_fields
            };
        }
    } else {
        quote! {
            let mut entry = #entry_type_ident::default();
            #(#key_assigns)*
        }
    };

    Ok(quote! {
        fn #fn_ident(
            node: &EditConfigNode,
            map: &mut #map_type,
            edit_keys: &mut std::collections::BTreeSet<#key_type>,
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
            // Key identity must be checked after parsing: distinct XML
            // spellings can address the same typed list entry. A separate
            // set for each sibling list prevents repeated parents from
            // hiding duplicate or conflicting leaf-list entry operations.
            if !edit_keys.insert(#cloned_map_key) {
                return Err(NetconfEditError::InvalidValue { path: node.schema_path });
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
                    #new_entry
                    #children_fn_ident(&node.children, &mut entry)?;
                    #upsert
                }
                EditOperation::Replace => {
                    #new_entry
                    #children_fn_ident(&node.children, &mut entry)?;
                    #upsert
                }
                EditOperation::Merge => {
                    let entry = map.entry(#cloned_map_key).or_default();
                    #(#key_assigns)*
                    #children_fn_ident(&node.children, entry)?;
                }
                EditOperation::None => {
                    if let Some(entry) = map.get_mut(&parsed_key) {
                        #children_fn_ident(&node.children, entry)?;
                    } else if node.children.iter().any(|child| child.operation != EditOperation::None) {
                        #new_entry
                        let baseline = entry.clone();
                        #children_fn_ident(&node.children, &mut entry)?;
                        if entry != baseline {
                            #upsert
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
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let path = &node.path;
    let resolved = resolved_type(node, nodes_by_path);
    let scalar = if nodes_by_path.extended_integers {
        nodes_by_path.scalar_node(node)
    } else {
        node
    };
    let integer_type = if nodes_by_path.extended_integers {
        quote! { i128 }
    } else {
        quote! { i64 }
    };
    let signed_value = if nodes_by_path.extended_integers {
        quote! { i128::from(parsed.0) }
    } else {
        quote! { parsed.0 }
    };
    let unsigned_range_check = numeric_range_check_expr(
        scalar,
        quote! { #integer_type::from(parsed) },
        path,
        nodes_by_path.extended_integers,
    );
    let int64_range_check =
        numeric_range_check_expr(scalar, signed_value, path, nodes_by_path.extended_integers);
    let expr = match resolved {
        Some(TypeRef::Boolean) => quote! {
            let parsed = match _v.trim() {
                "true" => true,
                "false" => false,
                _ => return Err(NetconfEditError::InvalidValue { path: #path }),
            };
        },
        Some(TypeRef::Uint8) => quote! {
            let parsed = _v.trim().parse::<u8>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Int8) => quote! {
            let parsed = _v.trim().parse::<i8>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Int16) => quote! {
            let parsed = _v.trim().parse::<i16>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Int32) => quote! {
            let parsed = _v.trim().parse::<i32>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Uint16) => quote! {
            let parsed = _v.trim().parse::<u16>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Uint32) => quote! {
            let parsed = _v.trim().parse::<u32>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            #unsigned_range_check
        },
        Some(TypeRef::Uint64) => quote! {
            let parsed = YangUint64(_v.trim().parse::<u64>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?);
            #int64_range_check
        },
        Some(TypeRef::Int64) => quote! {
            let parsed = YangInt64(_v.trim().parse::<i64>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?);
            #int64_range_check
        },
        Some(TypeRef::Decimal64) => quote! {
            let decimal = _v.trim().parse::<f64>().map_err(|_| NetconfEditError::InvalidValue { path: #path })?;
            if !decimal.is_finite() {
                return Err(NetconfEditError::InvalidValue { path: #path });
            }
            let parsed = YangDecimal64(decimal);
        },
        Some(TypeRef::Empty) => quote! {
            if !_v.trim().is_empty() {
                return Err(NetconfEditError::InvalidValue { path: #path });
            }
            let parsed = YangEmpty;
        },
        Some(TypeRef::RestrictedString { .. }) => quote! {
            if !super::strings::valid(#path, _v) { return Err(NetconfEditError::InvalidValue { path: #path }); }
            let parsed = _v.to_string();
        },
        Some(TypeRef::String)
        | Some(TypeRef::IdentityRef { .. })
        | Some(TypeRef::LeafRef { .. }) => quote! {
            let parsed = _v.to_string();
        },
        Some(TypeRef::Enumeration { values }) => {
            let allowed: Vec<&String> = values.iter().map(|value| &value.name).collect();
            quote! {
                let parsed = _v.to_string();
                if ![ #(#allowed),* ].contains(&parsed.as_str()) {
                    return Err(NetconfEditError::InvalidValue { path: #path });
                }
            }
        }
        Some(TypeRef::Custom { .. }) | None => {
            return Err(RustGenerationError::new(format!(
                "netconf_xml_edit: unsupported leaf type at {}",
                node.path
            )))
        }
    };
    Ok(expr)
}

fn numeric_range_check_expr(
    node: &SchemaNode,
    value_expr: TokenStream,
    path: &str,
    extended: bool,
) -> TokenStream {
    if node.numeric_range.is_empty() {
        return TokenStream::new();
    }

    let checks = node.numeric_range.iter().map(|interval| {
        let (min, max) = if extended {
            let (min, max) = (interval.min, interval.max);
            (quote! { #min }, quote! { #max })
        } else {
            let (min, max) = (interval.min as i64, interval.max as i64);
            (quote! { #min }, quote! { #max })
        };
        quote! { (#min <= numeric_value && numeric_value <= #max) }
    });

    let integer_type = if extended {
        quote! { i128 }
    } else {
        quote! { i64 }
    };
    quote! {
        let numeric_value: #integer_type = #value_expr;
        if !(#(#checks)||*) {
            return Err(NetconfEditError::InvalidValue { path: #path });
        }
    }
}

fn resolved_type<'a>(
    node: &'a SchemaNode,
    nodes_by_path: &'a NodeIndex<'a>,
) -> Option<&'a TypeRef> {
    nodes_by_path.legacy_or_resolved(node).type_ref.as_ref()
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

fn list_key_type(list_node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    if list_node.key_leaves.len() == 1 {
        let key_name = &list_node.key_leaves[0];
        for child_path in &list_node.child_paths {
            if let Some(child) = nodes_by_path.get(child_path) {
                if clean_segment(last_segment(&child.path)) == clean_segment(key_name) {
                    let raw = raw_type(child, nodes_by_path);
                    return if is_sensitive_node(child) {
                        quote! { SensitiveKey<#raw> }
                    } else {
                        raw
                    };
                }
            }
        }
        quote! { String }
    } else {
        let struct_name = format_ident!("{}Key", nodes_by_path.type_name(list_node));
        quote! { #struct_name }
    }
}

fn raw_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    let mut visited = std::collections::HashSet::new();
    raw_type_internal(node, nodes_by_path, &mut visited)
}

fn raw_type_internal(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
    visited: &mut std::collections::HashSet<String>,
) -> TokenStream {
    if visited.contains(&node.path) {
        return quote! { String };
    }
    visited.insert(node.path.clone());
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String | TypeRef::RestrictedString { .. })
        | Some(TypeRef::Enumeration { .. }) => quote! { String },
        Some(TypeRef::Uint8) => quote! { u8 },
        Some(TypeRef::Int8) => quote! { i8 },
        Some(TypeRef::Int16) => quote! { i16 },
        Some(TypeRef::Int32) => quote! { i32 },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Uint64) => quote! { YangUint64 },
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
    nodes_by_path: &'a NodeIndex<'a>,
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
