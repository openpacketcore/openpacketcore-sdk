//! Generates a schema-backed gNMI JSON/RFC 7951 projection for read paths.
//!
//! The emitted module implements `opc_gnmi_server::GnmiJsonRenderer` for the
//! generated root config type. It renders deterministic gNMI updates for
//! authorized canonical paths, preserves YANG module prefixes in update paths,
//! redacts non-cleartext data classes at the JSON boundary, and fails closed for
//! shapes this slice cannot render correctly.

use super::NodeIndex;
use super::{clean_segment, last_segment, to_pascal_case, to_snake_case, RustGenerationError};
use crate::emit::CanonicalInput;
use crate::ir::{SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Emits the `gnmi_json` module for the generated crate.
pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let nodes_by_path = NodeIndex::new(&input.nodes);

    let mut sorted_nodes: Vec<&SchemaNode> = input.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| a.path.cmp(&b.path));

    let root = sorted_nodes
        .iter()
        .find(|n| is_root_path(&n.path))
        .ok_or_else(|| RustGenerationError::new("gnmi_json: no root container found"))?;

    let root_type = nodes_by_path.type_name(root);
    let root_type_ident = format_ident!("{}", root_type);

    let mut render_fns = Vec::new();
    let mut has_ordered_projection = false;
    for node in &sorted_nodes {
        match node.kind {
            SchemaNodeKind::Container => {
                render_fns.push(render_container_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::Leaf => {
                render_fns.push(render_leaf_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::List => {
                render_fns.push(render_list_fn(node, &nodes_by_path)?);
                has_ordered_projection |= super::is_user_ordered(node)
                    && !node.key_leaves.is_empty()
                    && !super::types::is_sensitive_node(node);
            }
            SchemaNodeKind::LeafList => {
                render_fns.push(render_leaf_list_fn(node, &nodes_by_path)?);
            }
            SchemaNodeKind::Choice | SchemaNodeKind::Case => {
                return Err(RustGenerationError::new(format!(
                    "gnmi_json: unsupported node kind {:?} at {}",
                    node.kind, node.path
                )));
            }
        }
    }

    let root_path = &root.path;
    let root_function = format_ident!("render_{}", nodes_by_path.helper_name(root_path));
    let ordered_projection = if has_ordered_projection {
        ordered_projection_helpers()
    } else {
        TokenStream::new()
    };
    let sort_updates = if has_ordered_projection {
        // Schema traversal is deterministic; sorting would lose configured row order.
        TokenStream::new()
    } else {
        quote! { updates.sort_by(|a, b| a.path().as_str().cmp(b.path().as_str())); }
    };

    let tokens = quote! {
        #[allow(unused_imports)]
        use super::types::*;
        use opc_config_model::YangPath;
        use opc_gnmi_server::{
            GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate, ReadSelection,
        };

        /// Generated gNMI JSON/RFC 7951 renderer for this schema.
        pub struct GeneratedGnmiJsonRenderer;

        impl GnmiJsonRenderer<super::types::#root_type_ident> for GeneratedGnmiJsonRenderer {
            fn render_running_json(
                &self,
                config: &super::types::#root_type_ident,
                selection: ReadSelection<'_>,
            ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
                let mut updates = Vec::new();
                #root_function(config, selection, #root_path, #root_path, &mut updates)?;
                #sort_updates
                Ok(updates)
            }
        }

        #(#render_fns)*
        #ordered_projection

        fn push_update(
            updates: &mut Vec<GnmiJsonUpdate>,
            canonical_path: &str,
            value_json: String,
        ) -> Result<(), GnmiJsonProjectionError> {
            let path = YangPath::new(canonical_path)
                .map_err(|_| GnmiJsonProjectionError::projection("invalid generated gNMI path"))?;
            updates.push(GnmiJsonUpdate::new(path, value_json)?);
            Ok(())
        }

        fn to_json<T: serde::Serialize>(
            path: &'static str,
            value: &T,
        ) -> Result<String, GnmiJsonProjectionError> {
            serde_json::to_string(value).map_err(|_| {
                GnmiJsonProjectionError::projection(format!("gNMI JSON projection failed at {path}"))
            })
        }

        #[allow(dead_code)]
        fn redacted_value(path: &'static str, raw: &str) -> String {
            let data_class = super::schema_registry::registry()
                .data_class(path)
                .unwrap_or(opc_mgmt_schema::DataClass::Public);
            if data_class.allows_cleartext() {
                raw.to_string()
            } else {
                opc_redaction::redact(
                    raw,
                    data_class,
                    opc_redaction::RedactionLevel::Mask,
                    None,
                    None,
                )
                .to_string()
            }
        }

        #[allow(dead_code)]
        fn redacted_json(
            path: &'static str,
            raw: &str,
        ) -> Result<String, GnmiJsonProjectionError> {
            to_json(path, &redacted_value(path, raw))
        }

        fn append_child_path(parent: &str, child_schema_path: &'static str) -> String {
            let local = child_schema_path
                .rsplit('/')
                .next()
                .unwrap_or(child_schema_path);
            format!("{parent}/{local}")
        }

        #[allow(dead_code)]
        fn append_key_predicate(path: &mut String, key_name: &'static str, raw_value: &str) {
            path.push('[');
            path.push_str(key_name);
            path.push_str("='");
            for ch in raw_value.chars() {
                if ch == '\\' || ch == '\'' {
                    path.push('\\');
                }
                path.push(ch);
            }
            path.push_str("']");
        }

        /// Returns the generated gNMI JSON/RFC 7951 renderer for this schema.
        pub fn renderer() -> GeneratedGnmiJsonRenderer {
            GeneratedGnmiJsonRenderer
        }
    };

    Ok(tokens.to_string())
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

fn ordered_child_paths(node: &SchemaNode) -> Vec<&String> {
    let mut sorted: Vec<&String> = node.child_paths.iter().collect();
    sorted.sort();

    if node.key_leaves.is_empty() {
        return sorted;
    }

    let mut key_paths = Vec::new();
    let mut other_paths = Vec::new();
    for cp in sorted {
        let child_name = clean_segment(last_segment(cp));
        if node
            .key_leaves
            .iter()
            .any(|k| clean_segment(k) == child_name)
        {
            key_paths.push(cp);
        } else {
            other_paths.push(cp);
        }
    }

    key_paths.sort_by(|a, b| {
        let name_a = clean_segment(last_segment(a));
        let name_b = clean_segment(last_segment(b));
        let idx_a = node
            .key_leaves
            .iter()
            .position(|k| clean_segment(k) == name_a)
            .unwrap_or(usize::MAX);
        let idx_b = node
            .key_leaves
            .iter()
            .position(|k| clean_segment(k) == name_b)
            .unwrap_or(usize::MAX);
        idx_a.cmp(&idx_b)
    });

    key_paths.into_iter().chain(other_paths).collect()
}

fn render_container_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", nodes_by_path.helper_name(&node.path));
    let type_ident = format_ident!("{}", nodes_by_path.type_name(node));
    let child_stmts = child_render_stmts(node, nodes_by_path)?;

    Ok(quote! {
        #[allow(dead_code)]
        fn #fn_ident(
            value: &super::types::#type_ident,
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
            updates: &mut Vec<GnmiJsonUpdate>,
        ) -> Result<(), GnmiJsonProjectionError> {
            if !selection.is_subtree_selected(schema_path) {
                return Ok(());
            }
            #(#child_stmts)*
            Ok(())
        }
    })
}

fn render_list_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", nodes_by_path.helper_name(&node.path));
    let entry_fn_ident = format_ident!("render_{}_entry", nodes_by_path.helper_name(&node.path));
    let entry_type_ident = format_ident!("{}", nodes_by_path.type_name(node));
    let field_type = if node.key_leaves.is_empty() && !super::types::is_sensitive_node(node) {
        quote! { [super::types::#entry_type_ident] }
    } else {
        sequence_field_type(node, nodes_by_path)
    };

    if super::types::is_sensitive_node(node) || node.key_leaves.is_empty() {
        return Ok(quote! {
            #[allow(dead_code)]
            fn #fn_ident(
                value: &#field_type,
                selection: ReadSelection<'_>,
                schema_path: &'static str,
                _canonical_path: &str,
                _updates: &mut Vec<GnmiJsonUpdate>,
            ) -> Result<(), GnmiJsonProjectionError> {
                if !selection.is_subtree_selected(schema_path) {
                    return Ok(());
                }
                if value.is_empty() {
                    return Ok(());
                }
                Err(GnmiJsonProjectionError::projection(format!(
                    "gNMI JSON projection does not support list at {schema_path}"
                )))
            }
        });
    }

    let entry_fn = render_list_entry_fn(node, nodes_by_path, &entry_fn_ident, &entry_type_ident)?;
    let key_paths = list_key_schema_paths(node, nodes_by_path)?;
    let iter_expr = quote! { value.values() };
    let render_entries = quote! {
        for entry in #iter_expr {
            #entry_fn_ident(entry, selection, schema_path, canonical_path, updates)?;
        }
    };

    Ok(quote! {
        #entry_fn

        #[allow(dead_code)]
        fn #fn_ident(
            value: &#field_type,
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
            updates: &mut Vec<GnmiJsonUpdate>,
        ) -> Result<(), GnmiJsonProjectionError> {
            if !selection.is_subtree_selected(schema_path) {
                return Ok(());
            }
            // The server has authorized all identifying keys. Data classes
            // still decide whether a key can be carried in a protocol path.
            // Refuse before extracting or formatting any stored key value.
            if ![#(#key_paths),*].iter().all(|path| {
                super::schema_registry::registry().data_class(path)
                    .is_some_and(|class| class.allows_cleartext())
            }) {
                if value.is_empty() {
                    return Ok(());
                }
                return Err(GnmiJsonProjectionError::projection(format!(
                    "gNMI JSON projection does not support list at {schema_path}"
                )));
            }
            #render_entries
            Ok(())
        }
    })
}

fn ordered_projection_helpers() -> TokenStream {
    quote! {
        // Preserve nested list row order without exposing predicates or fields
        // that were not returned by the existing authorized leaf renderers.
        enum OrderedProjection {
            Object(std::collections::BTreeMap<String, OrderedProjection>),
            List {
                rows: Vec<OrderedProjection>,
                positions: std::collections::HashMap<std::collections::BTreeMap<String, String>, usize>,
            },
            Value(serde_json::Value),
        }

        impl Default for OrderedProjection {
            fn default() -> Self { Self::Object(Default::default()) }
        }

        impl OrderedProjection {
            fn into_json(self) -> serde_json::Value {
                match self {
                    Self::Object(fields) => serde_json::Value::Object(fields.into_iter()
                        .map(|(name, value)| (name, value.into_json())).collect()),
                    Self::List { rows, .. } => serde_json::Value::Array(rows.into_iter()
                        .map(Self::into_json).collect()),
                    Self::Value(value) => value,
                }
            }

            fn insert(
                &mut self,
                segments: &[super::patch::PathSegment],
                parent: &opc_mgmt_schema::NodeMeta,
                value: serde_json::Value,
            ) -> Result<(), GnmiJsonProjectionError> {
                let Some((segment, rest)) = segments.split_first() else {
                    *self = Self::Value(value);
                    return Ok(());
                };
                let path = format!("{}/{}", parent.path, segment.name);
                let node = super::schema_registry::registry().node(&path)
                    .ok_or_else(|| GnmiJsonProjectionError::projection("invalid ordered-list child path"))?;
                let local = opc_mgmt_schema::bare_segment(&segment.name);
                let name = if node.module == parent.module {
                    local.to_string()
                } else {
                    format!("{}:{local}", node.module)
                };
                let Self::Object(fields) = self else {
                    return Err(GnmiJsonProjectionError::projection("conflicting ordered-list projections"));
                };
                let field = fields.entry(name).or_default();
                if segment.keys.is_empty() {
                    return field.insert(rest, node, value);
                }
                if matches!(field, Self::Object(fields) if fields.is_empty()) {
                    *field = Self::List { rows: Vec::new(), positions: Default::default() };
                }
                let Self::List { rows, positions } = field else {
                    return Err(GnmiJsonProjectionError::projection("conflicting ordered-list rows"));
                };
                let index = if let Some(&index) = positions.get(&segment.keys) {
                    index
                } else {
                    let index = rows.len();
                    positions.insert(segment.keys.clone(), index);
                    rows.push(Self::default());
                    index
                };
                rows[index].insert(rest, node, value)
            }
        }

        fn ordered_collection_selected(
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
        ) -> Result<bool, GnmiJsonProjectionError> {
            if selection.entries().is_empty() {
                return Ok(selection.contains(schema_path));
            }
            let path = YangPath::new(canonical_path)
                .map_err(|_| GnmiJsonProjectionError::projection("invalid ordered-list entry path"))?;
            for entry in selection.entries().iter().filter(|entry| entry.schema_path() == schema_path) {
                let segments = super::patch::parse_path(entry.canonical_path().as_str())
                    .map_err(|_| GnmiJsonProjectionError::projection("invalid ordered-list selection"))?;
                if segments.last().is_some_and(|segment| segment.keys.is_empty())
                    && ReadSelection::with_entries(&[schema_path], std::slice::from_ref(entry))
                        .contains_path(schema_path, &path)
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn ordered_projection_row(
            schema_path: &'static str,
            children: Vec<GnmiJsonUpdate>,
        ) -> Result<serde_json::Value, GnmiJsonProjectionError> {
            let parent = super::schema_registry::registry().node(schema_path)
                .ok_or_else(|| GnmiJsonProjectionError::projection("invalid ordered-list path"))?;
            let depth = schema_path.split('/').filter(|segment| !segment.is_empty()).count();
            let mut row = OrderedProjection::default();
            for child in children {
                let segments = super::patch::parse_path(child.path().as_str())
                    .map_err(|_| GnmiJsonProjectionError::projection("invalid ordered-list projection path"))?;
                let suffix = segments.get(depth..)
                    .ok_or_else(|| GnmiJsonProjectionError::projection("invalid ordered-list projection depth"))?;
                let value = serde_json::from_str(child.value_json())
                    .map_err(|_| GnmiJsonProjectionError::projection("invalid ordered-list JSON"))?;
                row.insert(suffix, parent, value)?;
            }
            Ok(row.into_json())
        }
    }
}

fn render_list_entry_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
    fn_ident: &proc_macro2::Ident,
    type_ident: &proc_macro2::Ident,
) -> Result<TokenStream, RustGenerationError> {
    let key_stmts = list_key_predicate_stmts(node, nodes_by_path)?;
    let child_stmts = child_render_stmts(node, nodes_by_path)?;
    let render_children = if super::is_user_ordered(node) {
        quote! {
            let mut children = Vec::new();
            {
                let updates = &mut children;
                #(#child_stmts)*
            }
            if !children.is_empty() && ordered_collection_selected(selection, schema_path, canonical_path)? {
                // One bounded value per row, containing only authorized, redacted children.
                let row = ordered_projection_row(schema_path, children)?;
                push_update(updates, canonical_path, to_json(schema_path, &row)?)?;
            } else {
                updates.extend(children);
            }
        }
    } else {
        quote! { #(#child_stmts)* }
    };

    Ok(quote! {
        #[allow(dead_code)]
        fn #fn_ident(
            value: &super::types::#type_ident,
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
            updates: &mut Vec<GnmiJsonUpdate>,
        ) -> Result<(), GnmiJsonProjectionError> {
            if !selection.is_subtree_selected(schema_path) {
                return Ok(());
            }
            let mut entry_canonical_path = canonical_path.to_string();
            #(#key_stmts)*
            let canonical_path = entry_canonical_path.as_str();
            #render_children
            Ok(())
        }
    })
}

fn render_leaf_list_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", nodes_by_path.helper_name(&node.path));
    let field_type = sequence_field_type(node, nodes_by_path);
    let value_expr = if super::types::is_sensitive_node(node) {
        quote! { value.get() }
    } else {
        quote! { value }
    };

    let is_custom =
        resolved_type(node, nodes_by_path).is_some_and(|t| matches!(t, TypeRef::Custom { .. }));

    if is_custom {
        return Ok(quote! {
            #[allow(dead_code)]
            fn #fn_ident(
                _value: &#field_type,
                selection: ReadSelection<'_>,
                schema_path: &'static str,
                canonical_path: &str,
                _updates: &mut Vec<GnmiJsonUpdate>,
            ) -> Result<(), GnmiJsonProjectionError> {
                let path = YangPath::new(canonical_path)
                    .map_err(|_| GnmiJsonProjectionError::projection("invalid generated gNMI path"))?;
                if !selection.contains_path(schema_path, &path) {
                    return Ok(());
                }
                Err(GnmiJsonProjectionError::projection(format!(
                    "gNMI JSON projection does not support leaf-list at {schema_path}"
                )))
            }
        });
    }

    let value_json = if super::types::is_sensitive_node(node) {
        let scalar = scalar_to_string_expr(node, nodes_by_path, quote! { v });
        quote! {
            {
                let mut redacted = Vec::<String>::new();
                for v in values {
                    let raw = #scalar;
                    redacted.push(redacted_value(schema_path, &raw));
                }
                to_json(schema_path, &redacted)?
            }
        }
    } else {
        quote! { to_json(schema_path, values)? }
    };

    Ok(quote! {
        #[allow(dead_code)]
        fn #fn_ident(
            value: &#field_type,
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
            updates: &mut Vec<GnmiJsonUpdate>,
        ) -> Result<(), GnmiJsonProjectionError> {
            let path = YangPath::new(canonical_path)
                .map_err(|_| GnmiJsonProjectionError::projection("invalid generated gNMI path"))?;
            if !selection.contains_path(schema_path, &path) {
                return Ok(());
            }
            let values = #value_expr;
            if values.is_empty() {
                return Ok(());
            }
            let value_json = #value_json;
            push_update(updates, canonical_path, value_json)
        }
    })
}

fn render_leaf_fn(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<TokenStream, RustGenerationError> {
    let fn_ident = format_ident!("render_{}", nodes_by_path.helper_name(&node.path));
    let field_type = leaf_field_type(node, nodes_by_path);

    let is_custom =
        resolved_type(node, nodes_by_path).is_some_and(|t| matches!(t, TypeRef::Custom { .. }));

    if is_custom {
        return Ok(quote! {
            #[allow(dead_code)]
            fn #fn_ident(
                _value: &#field_type,
                selection: ReadSelection<'_>,
                schema_path: &'static str,
                canonical_path: &str,
                _updates: &mut Vec<GnmiJsonUpdate>,
            ) -> Result<(), GnmiJsonProjectionError> {
                let path = YangPath::new(canonical_path)
                    .map_err(|_| GnmiJsonProjectionError::projection("invalid generated gNMI path"))?;
                if !selection.contains_path(schema_path, &path) {
                    return Ok(());
                }
                Err(GnmiJsonProjectionError::projection(format!(
                    "gNMI JSON projection does not support leaf at {schema_path}"
                )))
            }
        });
    }

    let value_expr = leaf_value_expr(node, nodes_by_path);
    let value_json = if super::types::is_sensitive_node(node) {
        let scalar = scalar_to_string_expr(node, nodes_by_path, quote! { v });
        quote! {
            {
                let raw = #scalar;
                redacted_json(schema_path, &raw)?
            }
        }
    } else {
        quote! { to_json(schema_path, v)? }
    };

    Ok(quote! {
        #[allow(dead_code)]
        fn #fn_ident(
            value: &#field_type,
            selection: ReadSelection<'_>,
            schema_path: &'static str,
            canonical_path: &str,
            updates: &mut Vec<GnmiJsonUpdate>,
        ) -> Result<(), GnmiJsonProjectionError> {
            let path = YangPath::new(canonical_path)
                .map_err(|_| GnmiJsonProjectionError::projection("invalid generated gNMI path"))?;
            if !selection.contains_path(schema_path, &path) {
                return Ok(());
            }
            let maybe_value = #value_expr;
            let Some(v) = maybe_value else {
                return Ok(());
            };
            let value_json = #value_json;
            push_update(updates, canonical_path, value_json)
        }
    })
}

fn child_render_stmts(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<Vec<TokenStream>, RustGenerationError> {
    let mut child_stmts = Vec::new();
    for child_path in ordered_child_paths(node) {
        let Some(child) = nodes_by_path.get(child_path) else {
            continue;
        };
        let child_fn = format_ident!("render_{}", nodes_by_path.helper_name(&child.path));
        let child_local = clean_segment(last_segment(&child.path));
        let field_ident = format_ident!("{}", to_snake_case(child_local));

        let access_expr = match child.kind {
            SchemaNodeKind::Container => {
                quote! {
                    if let Some(v) = value.#field_ident.as_ref() {
                        let child_canonical_path = append_child_path(canonical_path, #child_path);
                        #child_fn(v, selection, #child_path, &child_canonical_path, updates)?;
                    }
                }
            }
            SchemaNodeKind::Leaf | SchemaNodeKind::List | SchemaNodeKind::LeafList => {
                quote! {
                    let child_canonical_path = append_child_path(canonical_path, #child_path);
                    #child_fn(&value.#field_ident, selection, #child_path, &child_canonical_path, updates)?;
                }
            }
            _ => continue,
        };
        child_stmts.push(access_expr);
    }
    Ok(child_stmts)
}

fn list_key_predicate_stmts(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<Vec<TokenStream>, RustGenerationError> {
    let mut stmts = Vec::new();
    for key_name in &node.key_leaves {
        let Some(child) = node.child_paths.iter().find_map(|child_path| {
            let child = nodes_by_path.get(child_path)?;
            (clean_segment(last_segment(&child.path)) == clean_segment(key_name)).then_some(child)
        }) else {
            return Err(RustGenerationError::new(format!(
                "gnmi_json: list {} key leaf {} not found",
                node.path, key_name
            )));
        };
        let field_ident = format_ident!("{}", to_snake_case(clean_segment(key_name)));
        let key_schema_name = last_segment(&child.path);
        let key_value = leaf_value_expr_from(child, quote! { &value.#field_ident });
        let raw = scalar_to_string_expr(child, nodes_by_path, quote! { v });
        stmts.push(quote! {
            let maybe_key_value = #key_value;
            let Some(v) = maybe_key_value else {
                return Err(GnmiJsonProjectionError::projection(format!(
                    "gNMI JSON projection missing list key at {schema_path}"
                )));
            };
            let raw = #raw;
            append_key_predicate(&mut entry_canonical_path, #key_schema_name, &raw);
            let _ = &value.#field_ident;
        });
    }
    Ok(stmts)
}

fn list_key_schema_paths(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
) -> Result<Vec<String>, RustGenerationError> {
    let mut paths = Vec::new();
    for key_name in &node.key_leaves {
        let Some(child) = node.child_paths.iter().find_map(|child_path| {
            let child = nodes_by_path.get(child_path)?;
            (clean_segment(last_segment(&child.path)) == clean_segment(key_name)).then_some(child)
        }) else {
            return Err(RustGenerationError::new(format!(
                "gnmi_json: list {} key leaf {} not found",
                node.path, key_name
            )));
        };
        paths.push(child.path.clone());
    }
    Ok(paths)
}

fn leaf_field_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
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
    nodes_by_path: &'a NodeIndex<'a>,
) -> Option<&'a TypeRef> {
    nodes_by_path.legacy_or_resolved(node).type_ref.as_ref()
}

fn leaf_base_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
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
        Some(TypeRef::Uint64) => quote! { super::types::YangUint64 },
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

fn leaf_value_expr(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    let _ = nodes_by_path;
    leaf_value_expr_from(node, quote! { value })
}

fn leaf_value_expr_from(node: &SchemaNode, value_base: TokenStream) -> TokenStream {
    let value_expr = if super::types::is_sensitive_node(node) {
        quote! { #value_base.get() }
    } else {
        value_base
    };

    if node.config {
        quote! {
            match #value_expr {
                super::types::LeafPresence::Explicit(v)
                | super::types::LeafPresence::Defaulted(v) => Some(v),
                super::types::LeafPresence::Absent => None,
            }
        }
    } else {
        quote! {
            #value_expr.as_ref()
        }
    }
}

fn scalar_to_string_expr(
    node: &SchemaNode,
    nodes_by_path: &NodeIndex<'_>,
    value_ident: TokenStream,
) -> TokenStream {
    match resolved_type(node, nodes_by_path) {
        Some(TypeRef::Boolean)
        | Some(TypeRef::String | TypeRef::RestrictedString { .. })
        | Some(TypeRef::Enumeration { .. })
        | Some(TypeRef::Uint8)
        | Some(TypeRef::Int8)
        | Some(TypeRef::Int16)
        | Some(TypeRef::Int32)
        | Some(TypeRef::Uint16)
        | Some(TypeRef::Uint32) => quote! { #value_ident.to_string() },
        Some(TypeRef::Uint64) | Some(TypeRef::Int64) | Some(TypeRef::Decimal64) => {
            quote! { #value_ident.0.to_string() }
        }
        Some(TypeRef::Empty) => quote! { { let _ = #value_ident; String::new() } },
        Some(TypeRef::IdentityRef { .. }) | Some(TypeRef::LeafRef { .. }) => {
            quote! { #value_ident.clone() }
        }
        Some(TypeRef::Custom { .. }) | None => quote! { #value_ident.to_string() },
    }
}

fn sequence_field_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    let inner = match node.kind {
        SchemaNodeKind::List => {
            let type_ident = format_ident!("{}", nodes_by_path.type_name(node));
            if node.key_leaves.is_empty() {
                quote! { Vec<super::types::#type_ident> }
            } else {
                let key_type = list_key_type(node, nodes_by_path);
                if super::is_user_ordered(node) {
                    quote! { super::serde::UserOrderedMap<#key_type, super::types::#type_ident> }
                } else {
                    quote! { std::collections::BTreeMap<#key_type, super::types::#type_ident> }
                }
            }
        }
        SchemaNodeKind::LeafList => {
            let elem_type = leaf_list_element_type(node, nodes_by_path);
            quote! { Vec<#elem_type> }
        }
        _ => unreachable!(),
    };
    if super::types::is_sensitive_node(node) {
        quote! { super::types::SecretLeaf<#inner> }
    } else {
        inner
    }
}

fn list_key_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    if node.key_leaves.len() == 1 {
        let key_name = &node.key_leaves[0];
        for child_path in &node.child_paths {
            if let Some(child) = nodes_by_path.get(child_path) {
                let child_name = clean_segment(last_segment(&child.path));
                if child_name == key_name {
                    let raw = leaf_base_type(child, nodes_by_path);
                    return if super::types::is_sensitive_node(child) {
                        quote! { super::types::SensitiveKey<#raw> }
                    } else {
                        raw
                    };
                }
            }
        }
        quote! { String }
    } else {
        let key_ident = format_ident!("{}Key", nodes_by_path.type_name(node));
        quote! { super::types::#key_ident }
    }
}

fn leaf_list_element_type(node: &SchemaNode, nodes_by_path: &NodeIndex<'_>) -> TokenStream {
    let ty = nodes_by_path.legacy_or_resolved(node).type_ref.as_ref();
    match ty {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String | TypeRef::RestrictedString { .. })
        | Some(TypeRef::Enumeration { .. }) => quote! { String },
        Some(TypeRef::Uint8) => quote! { u8 },
        Some(TypeRef::Int8) => quote! { i8 },
        Some(TypeRef::Int16) => quote! { i16 },
        Some(TypeRef::Int32) => quote! { i32 },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Uint64) => quote! { super::types::YangUint64 },
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
