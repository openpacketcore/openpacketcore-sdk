//! Typed configuration access for bounded, authorized subtree plans.

use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{
    clean_segment, last_segment, leaf_field_type, ordered_child_paths, resolved_type,
    sequence_field_type, to_snake_case, NodeIndex, RustGenerationError, SchemaNode, SchemaNodeKind,
    TypeRef,
};

pub(super) fn functions(
    root: &SchemaNode,
    nodes: &NodeIndex<'_>,
) -> Result<Vec<TokenStream>, RustGenerationError> {
    if !root.config {
        let function = format_ident!("content_{}", nodes.helper_name(&root.path));
        let ty = format_ident!("{}", nodes.type_name(root));
        return Ok(vec![quote! {
            fn #function(_value: &super::types::#ty, _ctx: &opc_mgmt_schema::subtree::SubtreeProjection<'_>)
                -> Result<Vec<opc_mgmt_schema::NetconfXmlNode>, opc_mgmt_schema::subtree::SubtreeError>
            { Ok(Vec::new()) }
        }]);
    }
    let mut pending = vec![root];
    let mut visited = HashSet::new();
    let mut functions = Vec::new();
    while let Some(node) = pending.pop() {
        if !node.config || !visited.insert(node.path.as_str()) {
            continue;
        }
        functions.push(project_function(node, nodes)?);
        if matches!(node.kind, SchemaNodeKind::Container | SchemaNodeKind::List)
            && !unsupported_list(node, nodes)
        {
            for path in ordered_child_paths(node).into_iter().rev() {
                let child = nodes
                    .get(path)
                    .ok_or_else(|| RustGenerationError::new("missing subtree child schema"))?;
                if !is_key(node, child) {
                    pending.push(child);
                }
            }
        }
    }
    Ok(functions)
}

fn is_key(parent: &SchemaNode, child: &SchemaNode) -> bool {
    parent
        .key_leaves
        .iter()
        .any(|key| clean_segment(key) == clean_segment(last_segment(&child.path)))
}

fn unsupported_list(node: &SchemaNode, nodes: &NodeIndex<'_>) -> bool {
    node.kind == SchemaNodeKind::List
        && (node.key_leaves.is_empty()
            || super::super::types::is_sensitive_node(node)
            || node
                .child_paths
                .iter()
                .filter_map(|path| nodes.get(path))
                .filter(|child| is_key(node, child))
                .any(|child| {
                    !child.config
                        || child.kind != SchemaNodeKind::Leaf
                        || matches!(
                            resolved_type(child, nodes),
                            Some(TypeRef::Custom { .. }) | None
                        )
                }))
}

fn project_function(
    node: &SchemaNode,
    nodes: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let name = format_ident!("content_{}", nodes.helper_name(&node.path));
    let path = &node.path;
    let (ty, body) = match node.kind {
        SchemaNodeKind::Container => {
            let ty = format_ident!("{}", nodes.type_name(node));
            let children = child_statements(node, nodes)?;
            (
                quote! { super::types::#ty },
                quote! {
                    if !ctx.enter(#path, true)? { return Ok(Vec::new()); }
                    #[allow(unused_mut)]
                    let mut children = Vec::new();
                    #(#children)*
                    if children.is_empty() && !ctx.selected(#path) { return Ok(Vec::new()); }
                    ctx.budget().charge(1)?;
                    let mut node = opc_mgmt_schema::NetconfXmlNode::branch(#path);
                    node.children = children;
                    Ok(vec![node])
                },
            )
        }
        SchemaNodeKind::List => (sequence_field_type(node, nodes), list_body(node, nodes)?),
        SchemaNodeKind::Leaf => (leaf_field_type(node, nodes), leaf_body(node, nodes)),
        SchemaNodeKind::LeafList => (
            sequence_field_type(node, nodes),
            leaf_list_body(node, nodes),
        ),
        _ => {
            return Err(RustGenerationError::new(
                "unsupported subtree projection schema",
            ))
        }
    };
    Ok(quote! {
        fn #name(value: &#ty, ctx: &opc_mgmt_schema::subtree::SubtreeProjection<'_>)
            -> Result<Vec<opc_mgmt_schema::NetconfXmlNode>, opc_mgmt_schema::subtree::SubtreeError>
        { #body }
    })
}

fn child_statements(
    node: &SchemaNode,
    nodes: &NodeIndex<'_>,
) -> Result<Vec<TokenStream>, RustGenerationError> {
    let mut statements = Vec::new();
    for path in ordered_child_paths(node) {
        let child = nodes
            .get(path)
            .ok_or_else(|| RustGenerationError::new("missing subtree child schema"))?;
        if !child.config || is_key(node, child) {
            continue;
        }
        let field = format_ident!("{}", to_snake_case(clean_segment(last_segment(path))));
        let function = format_ident!("content_{}", nodes.helper_name(path));
        statements.push(if child.kind == SchemaNodeKind::Container {
            quote! {
                if ctx.enter(#path, true)? {
                    if let Some(child) = value.#field.as_ref() { ctx.append(&mut children, #function(child, ctx)?)?; }
                }
            }
        } else { quote! { ctx.append(&mut children, #function(&value.#field, ctx)?)?; } });
    }
    Ok(statements)
}

fn scalar_ref(node: &SchemaNode, nodes: &NodeIndex<'_>, value: TokenStream) -> TokenStream {
    let kind = quote! { opc_mgmt_schema::subtree::SubtreeScalar };
    match resolved_type(node, nodes) {
        Some(TypeRef::Boolean) => quote! { #kind::Boolean(*#value) },
        Some(TypeRef::Uint8 | TypeRef::Uint16 | TypeRef::Uint32) => {
            quote! { #kind::Unsigned(u64::from(*#value)) }
        }
        Some(TypeRef::Uint64) => quote! { #kind::Unsigned(#value.0) },
        Some(TypeRef::Int8 | TypeRef::Int16 | TypeRef::Int32) => {
            quote! { #kind::Integer(i64::from(*#value)) }
        }
        Some(TypeRef::Int64) => quote! { #kind::Integer(#value.0) },
        Some(TypeRef::Decimal64) => quote! { #kind::Decimal(#value.0) },
        Some(TypeRef::Empty) => quote! { { let _ = #value; #kind::Empty } },
        _ => quote! { #kind::Text(#value.as_str()) },
    }
}

fn leaf_body(node: &SchemaNode, nodes: &NodeIndex<'_>) -> TokenStream {
    let path = &node.path;
    if matches!(
        resolved_type(node, nodes),
        Some(TypeRef::Custom { .. }) | None
    ) {
        return unsupported(path, false);
    }
    let value = if super::super::types::is_sensitive_node(node) {
        quote! { value.get() }
    } else {
        quote! { value }
    };
    let scalar = scalar_ref(node, nodes, quote! { item });
    quote! {
        if !ctx.enter(#path, false)? { return Ok(Vec::new()); }
        let leaf = match #value {
            super::types::LeafPresence::Explicit(item) => ctx.scalar(#path, #scalar, false)?,
            super::types::LeafPresence::Defaulted(item) => ctx.scalar(#path, #scalar, true)?,
            super::types::LeafPresence::Absent => match ctx.default(#path)? {
                Some(default) => ctx.scalar(#path, opc_mgmt_schema::subtree::SubtreeScalar::Text(default), true)?,
                None => None,
            },
        };
        Ok(leaf.into_iter().collect())
    }
}

fn leaf_list_body(node: &SchemaNode, nodes: &NodeIndex<'_>) -> TokenStream {
    let path = &node.path;
    if matches!(
        resolved_type(node, nodes),
        Some(TypeRef::Custom { .. }) | None
    ) {
        return unsupported(path, false);
    }
    let value = if super::super::types::is_sensitive_node(node) {
        quote! { value.get() }
    } else {
        quote! { value }
    };
    let scalar = scalar_ref(node, nodes, quote! { item });
    quote! {
        if !ctx.enter(#path, false)? { return Ok(Vec::new()); }
        let mut projected = Vec::new();
        for (ordinal, item) in #value.iter().enumerate() {
            ctx.budget().charge(1)?;
            if let Some(node) = ctx.leaf_list_scalar(#path, #scalar, ordinal)? { ctx.budget().charge(1)?; projected.push(node); }
        }
        Ok(projected)
    }
}

fn list_body(node: &SchemaNode, nodes: &NodeIndex<'_>) -> Result<TokenStream, RustGenerationError> {
    let path = &node.path;
    if unsupported_list(node, nodes) {
        return Ok(unsupported(path, true));
    }
    let mut key_paths = Vec::new();
    let mut keys = Vec::new();
    for child_path in ordered_child_paths(node) {
        let child = nodes
            .get(child_path)
            .ok_or_else(|| RustGenerationError::new("missing subtree key schema"))?;
        if !is_key(node, child) {
            continue;
        }
        if !child.config
            || child.kind != SchemaNodeKind::Leaf
            || matches!(
                resolved_type(child, nodes),
                Some(TypeRef::Custom { .. }) | None
            )
        {
            return Ok(unsupported(path, true));
        }
        key_paths.push(child_path);
        let field = format_ident!("{}", to_snake_case(clean_segment(last_segment(child_path))));
        let value = if super::super::types::is_sensitive_node(child) {
            quote! { value.#field.get() }
        } else {
            quote! { &value.#field }
        };
        let scalar = scalar_ref(child, nodes, quote! { item });
        keys.push(quote! {
            let raw = match #value {
                super::types::LeafPresence::Explicit(item) | super::types::LeafPresence::Defaulted(item) => #scalar.encode(ctx.budget())?,
                super::types::LeafPresence::Absent => return Err(opc_mgmt_schema::subtree::SubtreeError::Projection),
            };
            keys.push((#child_path, raw));
        });
    }
    if key_paths.len() != node.key_leaves.len() {
        return Err(RustGenerationError::new("incomplete subtree key schema"));
    }
    let key_count = key_paths.len();
    let children = child_statements(node, nodes)?;
    Ok(quote! {
        if !ctx.enter(#path, true)? { return Ok(Vec::new()); }
        if !(true #(&& ctx.selected(#key_paths))*) { return Err(opc_mgmt_schema::subtree::SubtreeError::Projection); }
        let mut projected = Vec::new();
        for value in value.values() {
            ctx.row(#path)?;
            ctx.budget().charge(#key_count)?;
            let mut keys = Vec::with_capacity(#key_count);
            #(#keys)*
            #[allow(unused_mut)]
            let mut children = Vec::new();
            #(#children)*
            ctx.budget().charge(1)?;
            let mut row = opc_mgmt_schema::NetconfXmlNode::branch(#path);
            row.keys = keys;
            row.children = children;
            projected.push(row);
        }
        Ok(projected)
    })
}

fn unsupported(path: &str, structural: bool) -> TokenStream {
    quote! {
        let _ = value;
        if !ctx.enter(#path, #structural)? { return Ok(Vec::new()); }
        Err(opc_mgmt_schema::subtree::SubtreeError::Unsupported)
    }
}
