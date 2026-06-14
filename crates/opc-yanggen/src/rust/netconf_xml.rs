//! Generates a schema-backed NETCONF XML projection for read paths.
//!
//! The emitted module implements [`opc_mgmt_schema::NetconfXmlRenderer`] for the
//! generated root config type. It renders deterministic XML fragments for
//! authorized schema-node paths, preserves YANG module prefixes and namespaces,
//! escapes values at the XML boundary, omits unauthorized paths, and defers
//! shapes that cannot be rendered correctly in this slice (lists, leaf-lists,
//! and custom leaf types) with an explicit error.

use super::{clean_segment, last_segment, to_pascal_case, to_snake_case, RustGenerationError};
use crate::emit::CanonicalInput;
use crate::ir::{SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

/// Emits the `netconf_xml` module for the generated crate.
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
        .ok_or_else(|| RustGenerationError::new("netconf_xml: no root container found"))?;

    let root_type = to_pascal_case(clean_segment(last_segment(&root.path)));
    let root_type_ident = format_ident!("{}", root_type);

    let mut render_fns = Vec::new();
    for node in &sorted_nodes {
        if under_unsupported_sequence(node, &nodes_by_path) {
            continue;
        }
        match node.kind {
            SchemaNodeKind::Container => {
                render_fns.push(render_container_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::Leaf => {
                render_fns.push(render_leaf_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::List | SchemaNodeKind::LeafList => {
                render_fns.push(render_unsupported_sequence_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::Choice | SchemaNodeKind::Case => {
                return Err(RustGenerationError::new(format!(
                    "netconf_xml: unsupported node kind {:?} at {}",
                    node.kind, node.path
                )));
            }
        }
    }

    let root_path = &root.path;
    let root_function = format_ident!("render_{}", path_to_snake(root_path));

    let tokens = quote! {
        use opc_mgmt_schema::{
            DefaultReport, NetconfProjectionError, NetconfXmlRenderContext, NetconfXmlRenderer,
        };

        /// Generated NETCONF XML renderer for this schema.
        pub struct GeneratedNetconfXmlRenderer;

        impl NetconfXmlRenderer<super::types::#root_type_ident> for GeneratedNetconfXmlRenderer {
            fn render_running_config(
                &self,
                config: &super::types::#root_type_ident,
                selection: &[&str],
                report: DefaultReport,
            ) -> Result<String, NetconfProjectionError> {
                match report {
                    DefaultReport::Trim | DefaultReport::ReportAll => {}
                    _ => {
                        return Err(NetconfProjectionError::UnsupportedDefaultReport { report });
                    }
                }
                let ctx = NetconfXmlRenderContext::new(
                    super::schema_registry::registry(),
                    selection,
                    report,
                );
                #root_function(config, &ctx, #root_path, true)
                    .map(|opt| opt.unwrap_or_default())
            }

            fn supported_default_reports(&self) -> &'static [DefaultReport] {
                &[DefaultReport::Trim, DefaultReport::ReportAll]
            }
        }

        #(#render_fns)*

        /// Returns the generated NETCONF XML renderer for this schema.
        pub fn renderer() -> GeneratedNetconfXmlRenderer {
            GeneratedNetconfXmlRenderer
        }
    };

    Ok(tokens.to_string())
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

fn under_unsupported_sequence(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> bool {
    let mut current = node.path.as_str();
    while let Some(parent_end) = current.rfind('/') {
        if parent_end == 0 {
            break;
        }
        let parent = &current[..parent_end];
        if let Some(parent_node) = nodes_by_path.get(parent) {
            if matches!(
                parent_node.kind,
                SchemaNodeKind::List | SchemaNodeKind::LeafList
            ) {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn path_to_snake(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(clean_segment)
        .map(to_snake_case)
        .collect::<Vec<_>>()
        .join("_")
}

fn render_container_fn(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", path_to_snake(&node.path));
    let local = clean_segment(last_segment(&node.path));
    let type_ident = format_ident!("{}", to_pascal_case(local));

    let mut child_stmts = Vec::new();
    for child_path in &node.child_paths {
        let Some(child) = nodes_by_path.get(child_path) else {
            continue;
        };
        let child_fn = format_ident!("render_{}", path_to_snake(&child.path));
        let child_local = clean_segment(last_segment(&child.path));
        let field_ident = format_ident!("{}", to_snake_case(child_local));

        let access_expr = match child.kind {
            SchemaNodeKind::Container => {
                quote! {
                    if let Some(v) = value.#field_ident.as_ref() {
                        if let Some(fragment) = #child_fn(v, ctx, #child_path, false)? {
                            children.push_str(&fragment);
                        }
                    }
                }
            }
            SchemaNodeKind::Leaf | SchemaNodeKind::List | SchemaNodeKind::LeafList => {
                quote! {
                    if let Some(fragment) = #child_fn(&value.#field_ident, ctx, #child_path)? {
                        children.push_str(&fragment);
                    }
                }
            }
            _ => continue,
        };
        child_stmts.push(access_expr);
    }

    Ok(quote! {
        fn #fn_ident(
            value: &super::types::#type_ident,
            ctx: &NetconfXmlRenderContext<'_>,
            path: &'static str,
            include_namespaces: bool,
        ) -> Result<Option<String>, NetconfProjectionError> {
            if !ctx.is_subtree_selected(path) {
                return Ok(None);
            }
            let qname = ctx.qualified_name(path)?;
            let mut children = String::new();
            #(#child_stmts)*
            if children.is_empty() && !ctx.is_selected(path) {
                return Ok(None);
            }
            let ns_decls = if include_namespaces {
                ctx.module_namespaces()
                    .into_iter()
                    .map(|(prefix, ns)| {
                        format!(
                            " xmlns:{}=\"{}\"",
                            opc_mgmt_schema::xml_escape_attr(prefix),
                            opc_mgmt_schema::xml_escape_attr(ns)
                        )
                    })
                    .collect::<String>()
            } else {
                String::new()
            };
            Ok(Some(format!("<{qname}{ns_decls}>{children}</{qname}>")))
        }
    })
}

fn render_leaf_fn(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", path_to_snake(&node.path));
    let field_type = leaf_field_type(node, nodes_by_path);

    let custom_check = if resolved_type(node, nodes_by_path)
        .is_some_and(|t| matches!(t, TypeRef::Custom { .. }))
    {
        quote! {
            return Err(NetconfProjectionError::UnsupportedShape {
                path,
                kind: opc_mgmt_schema::NodeKind::Leaf,
            });
        }
    } else {
        quote! {}
    };

    let inner_expr = leaf_inner_expr(node, nodes_by_path);

    Ok(quote! {
        fn #fn_ident(
            value: &#field_type,
            ctx: &NetconfXmlRenderContext<'_>,
            path: &'static str,
        ) -> Result<Option<String>, NetconfProjectionError> {
            if !ctx.is_selected(path) {
                return Ok(None);
            }
            #custom_check
            let (raw, is_defaulted) = match #inner_expr {
                Some(v) => v,
                None => return Ok(None),
            };
            if is_defaulted && ctx.report() == DefaultReport::Trim {
                if let Some(def) = ctx.schema_default(path) {
                    if raw == def {
                        return Ok(None);
                    }
                }
            }
            ctx.format_leaf(path, &raw).map(Some)
        }
    })
}

fn render_unsupported_sequence_fn(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", path_to_snake(&node.path));
    let kind = match node.kind {
        SchemaNodeKind::List => quote! { opc_mgmt_schema::NodeKind::List },
        SchemaNodeKind::LeafList => quote! { opc_mgmt_schema::NodeKind::LeafList },
        _ => unreachable!(),
    };
    let field_type = sequence_field_type(node, nodes_by_path);

    Ok(quote! {
        fn #fn_ident(
            _value: &#field_type,
            ctx: &NetconfXmlRenderContext<'_>,
            path: &'static str,
        ) -> Result<Option<String>, NetconfProjectionError> {
            if ctx.is_subtree_selected(path) {
                Err(NetconfProjectionError::UnsupportedShape {
                    path,
                    kind: #kind,
                })
            } else {
                Ok(None)
            }
        }
    })
}

fn leaf_field_type(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    let base = leaf_base_type(node, nodes_by_path);
    let wrapped = if node.config {
        quote! { super::types::LeafPresence<#base> }
    } else {
        quote! { Option<#base> }
    };
    if super::types::is_sensitive_node(node) {
        quote! { super::types::SecretLeaf<#wrapped> }
    } else {
        wrapped
    }
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

fn leaf_base_type(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String) => quote! { String },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Int64) => quote! { super::types::YangInt64 },
        Some(TypeRef::Decimal64) => quote! { super::types::YangDecimal64 },
        Some(TypeRef::Empty) => quote! { super::types::YangEmpty },
        Some(TypeRef::IdentityRef { .. }) | Some(TypeRef::LeafRef { .. }) => quote! { String },
        Some(TypeRef::Custom { name }) => {
            let custom_ident = format_ident!("{}", to_pascal_case(name));
            quote! { #custom_ident }
        }
        None => quote! { () },
    }
}

fn leaf_inner_expr(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    let value_expr = if super::types::is_sensitive_node(node) {
        quote! { value.get() }
    } else {
        quote! { value }
    };

    if node.config {
        let scalar = scalar_to_string_expr(node, nodes_by_path, quote! { v });
        quote! {
            match #value_expr {
                super::types::LeafPresence::Explicit(v) => Some((#scalar, false)),
                super::types::LeafPresence::Defaulted(v) => Some((#scalar, true)),
                super::types::LeafPresence::Absent => None,
            }
        }
    } else {
        let scalar = scalar_to_string_expr(node, nodes_by_path, quote! { v });
        quote! {
            #value_expr.as_ref().map(|v| (#scalar, false))
        }
    }
}

fn scalar_to_string_expr(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
    value_ident: TokenStream,
) -> TokenStream {
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean)
        | Some(TypeRef::String)
        | Some(TypeRef::Uint16)
        | Some(TypeRef::Uint32) => quote! { #value_ident.to_string() },
        Some(TypeRef::Int64) | Some(TypeRef::Decimal64) => quote! { #value_ident.0.to_string() },
        Some(TypeRef::Empty) => quote! { { let _ = #value_ident; String::new() } },
        Some(TypeRef::IdentityRef { .. }) | Some(TypeRef::LeafRef { .. }) => {
            quote! { #value_ident.clone() }
        }
        Some(TypeRef::Custom { .. }) | None => quote! { #value_ident.to_string() },
    }
}

fn sequence_field_type(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> TokenStream {
    match node.kind {
        SchemaNodeKind::List => {
            let local = clean_segment(last_segment(&node.path));
            let type_ident = format_ident!("{}", to_pascal_case(local));
            if node.key_leaves.is_empty() {
                quote! { Vec<super::types::#type_ident> }
            } else {
                let key_type = list_key_type(node, nodes_by_path);
                quote! { std::collections::BTreeMap<#key_type, super::types::#type_ident> }
            }
        }
        SchemaNodeKind::LeafList => {
            let elem_type = leaf_list_element_type(node, nodes_by_path);
            quote! { Vec<#elem_type> }
        }
        _ => unreachable!(),
    }
}

fn list_key_type(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    if node.key_leaves.len() == 1 {
        let key_name = &node.key_leaves[0];
        for child_path in &node.child_paths {
            if let Some(child) = nodes_by_path.get(child_path) {
                let child_name = clean_segment(last_segment(&child.path));
                if child_name == key_name {
                    return leaf_base_type(child, nodes_by_path);
                }
            }
        }
        quote! { String }
    } else {
        let local = clean_segment(last_segment(&node.path));
        let key_ident = format_ident!("{}Key", to_pascal_case(local));
        quote! { super::types::#key_ident }
    }
}

fn leaf_list_element_type(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> TokenStream {
    let mut ty = node.type_ref.as_ref();
    if let Some(TypeRef::LeafRef { target_path }) = ty {
        if let Some(target) = nodes_by_path.get(target_path) {
            ty = target.type_ref.as_ref();
        }
    }
    match ty {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String) => quote! { String },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Int64) => quote! { super::types::YangInt64 },
        Some(TypeRef::Decimal64) => quote! { super::types::YangDecimal64 },
        Some(TypeRef::Empty) => quote! { super::types::YangEmpty },
        Some(TypeRef::IdentityRef { .. }) | Some(TypeRef::LeafRef { .. }) => quote! { String },
        Some(TypeRef::Custom { name }) => {
            let custom_ident = format_ident!("{}", to_pascal_case(name));
            quote! { #custom_ident }
        }
        None => quote! { String },
    }
}
