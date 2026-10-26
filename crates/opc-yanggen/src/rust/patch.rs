use super::NodeIndex;
use super::{clean_segment, is_sensitive_name, last_segment, to_snake_case, RustGenerationError};
use crate::emit::CanonicalInput;
use crate::ir::{AllocationStrategy, SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

fn is_sensitive_node(node: &SchemaNode) -> bool {
    if let Some(ref dc) = node.data_class {
        dc != "public" && dc != "operational"
    } else {
        is_sensitive_name(clean_segment(last_segment(&node.path)))
    }
}

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let has_state = input.nodes.iter().any(|node| !node.config);
    let root = input
        .nodes
        .iter()
        .find(|node| {
            let trimmed = node.path.trim_start_matches('/');
            !trimmed.is_empty() && !trimmed.contains('/')
        })
        .ok_or_else(|| {
            RustGenerationError::new("root node not found while generating patch module")
        })?;

    let root_path = &root.path;

    let nodes_by_path = NodeIndex::new(&input.nodes);
    let normalize_errors =
        super::has_extended_integers(input) || super::strings::has_constraints(input);
    let (json_error, json_error_helper) = if normalize_errors {
        (
            quote! { scalar_json_error },
            quote! {
                fn scalar_json_error(error: serde_json::Error) -> ConfigError {
                    config_error("invalid-value", super::types::json_error_reason(&error.to_string()))
                }
            },
        )
    } else {
        (
            quote! { |_| config_error("invalid-value", "invalid JSON value") },
            quote! {},
        )
    };
    let integer_error = if normalize_errors {
        quote! { |_| config_error("invalid-value", "invalid integer value") }
    } else {
        quote! { |_| config_error("invalid-value", "invalid numeric value") }
    };
    let validate_merge = if normalize_errors {
        quote! { let _: Self = serde_json::from_str(v).map_err(#json_error)?; }
    } else {
        quote! {}
    };

    let root_type = format_ident!("{}", nodes_by_path.type_name(root));
    let has_scalar_constraints =
        super::has_extended_integers(input) || super::strings::has_constraints(input);

    let ordered_lists: Vec<_> = input
        .nodes
        .iter()
        .filter(|node| {
            node.kind == SchemaNodeKind::List
                && super::is_user_ordered(node)
                && !node.key_leaves.is_empty()
        })
        .collect();
    let has_ordered_lists = !ordered_lists.is_empty();
    let apply_segments = if has_ordered_lists {
        format_ident!("apply_patch_segments_with_order")
    } else if has_scalar_constraints {
        format_ident!("apply_patch_segments_inner")
    } else {
        format_ident!("apply_patch_segments")
    };
    let apply_visibility = if has_ordered_lists || has_scalar_constraints {
        quote! {}
    } else {
        quote! { pub }
    };
    let inner_apply = if has_state && has_scalar_constraints && !has_ordered_lists {
        // The scalar wrapper already uses `apply_patch_segments_inner` for its
        // checked entry point. State recursion needs a distinct private method.
        format_ident!("apply_patch_segments_state_inner")
    } else if has_state {
        format_ident!("apply_patch_segments_inner")
    } else {
        apply_segments.clone()
    };
    let inner_visibility = if has_state {
        quote! {}
    } else {
        apply_visibility.clone()
    };
    let ordered_parameter = if has_ordered_lists {
        quote! { , ordered_list: Option<&OrderedListReplacement> }
    } else {
        quote! {}
    };
    let ordered_argument = if has_ordered_lists {
        quote! { , ordered_list }
    } else {
        quote! {}
    };
    let ordered_none = if has_ordered_lists {
        quote! { , None }
    } else {
        quote! {}
    };
    let reject_ordered_target = if has_ordered_lists {
        quote! {
            if ordered_list.is_some() {
                return Err(config_error("invalid-path", "ordered-list replacement requires its collection path"));
            }
        }
    } else {
        quote! {}
    };
    let ordered_definitions = if has_ordered_lists {
        let variants = ordered_lists.iter().map(|node| {
            let row_type = format_ident!("{}", nodes_by_path.type_name(node));
            let key_type = super::types::get_key_type(node, &nodes_by_path);
            quote! { #row_type(super::serde::UserOrderedMap<#key_type, #row_type>), }
        });
        quote! {
            /// Typed list snapshots used by diff to retain leaf presence during reordering.
            #[derive(Debug, Clone, PartialEq)]
            pub enum OrderedListReplacement { #(#variants)* }
        }
    } else {
        quote! {}
    };
    let ordered_delta = if has_ordered_lists {
        quote! {
            /// Replaces a user-ordered collection without a JSON round trip.
            ReplaceOrderedList(YangPath, OrderedListReplacement),
        }
    } else {
        quote! {}
    };
    let ordered_path_arm = if has_ordered_lists {
        quote! { ConfigDelta::ReplaceOrderedList(p, _) => p, }
    } else {
        quote! {}
    };
    let ordered_apply_arm = if has_ordered_lists {
        quote! {
            ConfigDelta::ReplaceOrderedList(p, rows) => (p, ConfigOp::Replace, None, Some(rows)),
        }
    } else {
        quote! {}
    };

    let mut impls = TokenStream::new();

    for node in &input.nodes {
        if node.kind == SchemaNodeKind::Container || node.kind == SchemaNodeKind::List {
            let struct_name = format_ident!("{}", nodes_by_path.type_name(node));
            let mut field_arms = TokenStream::new();
            let mut diff_fields = TokenStream::new();
            let all_fields_read_only = has_state
                && node
                    .child_paths
                    .iter()
                    .filter_map(|path| nodes_by_path.get(path))
                    .all(|child| !child.config);
            let dispatch_return = if all_fields_read_only {
                quote! {}
            } else {
                quote! { return }
            };
            let dispatch_semicolon = if all_fields_read_only {
                quote! {}
            } else {
                quote! { ; }
            };

            for child_path in &node.child_paths {
                if let Some(child) = nodes_by_path.get(child_path) {
                    let child_name = clean_segment(last_segment(&child.path));
                    let field_ident = format_ident!("{}", to_snake_case(child_name));
                    let child_name_str = child_name;
                    let is_sensitive = is_sensitive_node(child);

                    let scalar_path = &child.path;
                    let parse_and_assign = match &nodes_by_path.patch_scalar_node(child).type_ref {
                        Some(TypeRef::RestrictedString { .. }) => quote! {
                            if !super::strings::valid(#scalar_path, _v) { return Err(config_error("invalid-value", "string violates YANG constraints")); }
                            let parsed = _v.to_string();
                        },
                        Some(TypeRef::Boolean) => quote! {
                            let parsed = match _v {
                                "true" => true,
                                "false" => false,
                                _ => return Err(config_error("invalid-value", "invalid boolean value")),
                            };
                        },
                        Some(TypeRef::Uint8) => quote! {
                            let parsed = _v.parse::<u8>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Int8) => quote! {
                            let parsed = _v.parse::<i8>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Int16) => quote! {
                            let parsed = _v.parse::<i16>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Int32) => quote! {
                            let parsed = _v.parse::<i32>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Uint16) => quote! {
                            let parsed = _v.parse::<u16>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Uint32) => quote! {
                            let parsed = _v.parse::<u32>().map_err(#integer_error)?;
                        },
                        Some(TypeRef::Uint64) => quote! {
                            let parsed = YangUint64(_v.parse::<u64>().map_err(#integer_error)?);
                        },
                        Some(TypeRef::Int64) => quote! {
                            let parsed = YangInt64(_v.parse::<i64>().map_err(#integer_error)?);
                        },
                        Some(TypeRef::Decimal64 { fraction_digits }) => quote! {
                            let parsed = _v.parse::<YangDecimal64<#fraction_digits>>().map_err(|_| config_error("invalid-value", "invalid decimal64 value"))?;
                        },
                        Some(TypeRef::Empty) => quote! {
                            let parsed = YangEmpty;
                        },
                        Some(TypeRef::Enumeration { values }) => {
                            let allowed: Vec<&String> =
                                values.iter().map(|value| &value.name).collect();
                            quote! {
                                let parsed = _v.to_string();
                                if ![ #(#allowed),* ].contains(&parsed.as_str()) {
                                    return Err(config_error("invalid-value", "unsupported enumeration value"));
                                }
                            }
                        }
                        _ => quote! {
                            let parsed = _v.to_string();
                        },
                    };

                    let assign_stmt = if child.config {
                        if is_sensitive {
                            quote! { self.#field_ident = SecretLeaf::new(LeafPresence::Explicit(parsed)); }
                        } else {
                            quote! { self.#field_ident = LeafPresence::Explicit(parsed); }
                        }
                    } else if is_sensitive {
                        quote! { self.#field_ident = SecretLeaf::new(Some(parsed)); }
                    } else {
                        quote! { self.#field_ident = Some(parsed); }
                    };

                    let delete_stmt = if child.config {
                        if is_sensitive {
                            quote! { self.#field_ident = SecretLeaf::new(LeafPresence::Absent); }
                        } else {
                            quote! { self.#field_ident = LeafPresence::Absent; }
                        }
                    } else if is_sensitive {
                        quote! { self.#field_ident = SecretLeaf::new(None); }
                    } else {
                        quote! { self.#field_ident = None; }
                    };

                    let arm = match child.kind {
                        SchemaNodeKind::Leaf => {
                            quote! {
                                #child_name_str => {
                                    #reject_ordered_target
                                    if segments.len() > 1 {
                                        return Err(config_error("invalid-path", "path goes deeper than leaf"));
                                    }
                                    match op {
                                        ConfigOp::Delete | ConfigOp::Remove => {
                                            #delete_stmt
                                        }
                                        ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                            let _v = value.ok_or_else(|| config_error("missing-value", "Value is required for leaf"))?;
                                            #parse_and_assign
                                            #assign_stmt
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::Container => {
                            let mut is_boxed = false;
                            for shape in &input.stack_shapes {
                                if shape.yang_path == child.path
                                    && shape.allocation == AllocationStrategy::Boxed
                                {
                                    is_boxed = true;
                                }
                            }
                            let get_mut_container = if is_boxed {
                                quote! { self.#field_ident.get_or_insert_with(|| Box::new(Default::default())) }
                            } else {
                                quote! { self.#field_ident.get_or_insert_with(Default::default) }
                            };
                            quote! {
                                #child_name_str => {
                                    if (op == &ConfigOp::Delete || op == &ConfigOp::Remove) && segments.len() == 1 {
                                        self.#field_ident = None;
                                    } else {
                                        if op == &ConfigOp::Delete || op == &ConfigOp::Remove {
                                            if let Some(ref mut container) = self.#field_ident {
                                                container.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                            }
                                        } else {
                                            let container = #get_mut_container;
                                            container.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::List => {
                            let ty_name = format_ident!("{}", nodes_by_path.type_name(child));
                            // Collection merges are needed for RFC 7951 arrays inside
                            // user-ordered rows. Other system lists retain their API.
                            let below_ordered_list = ordered_lists.iter().any(|ancestor| {
                                child
                                    .path
                                    .strip_prefix(&ancestor.path)
                                    .is_some_and(|suffix| suffix.starts_with('/'))
                            });
                            let collection_patch = if !child.key_leaves.is_empty()
                                && (super::is_user_ordered(child) || below_ordered_list)
                            {
                                let key_type = super::types::get_key_type(child, &nodes_by_path);
                                let access = if is_sensitive {
                                    quote! { self.#field_ident.get_mut() }
                                } else {
                                    quote! { &mut self.#field_ident }
                                };
                                let user_ordered = super::is_user_ordered(child);
                                let collection_operations = if user_ordered {
                                    quote! {}
                                } else {
                                    // Nested RFC 7951 arrays can merge at a system-list path.
                                    quote! { && matches!(op, ConfigOp::Update | ConfigOp::Merge) }
                                };
                                let replace_rows = if user_ordered {
                                    quote! { *list = rows; }
                                } else {
                                    quote! { *list = rows.into_iter().collect(); }
                                };
                                let typed_replacement = if user_ordered {
                                    let mismatch = if ordered_lists.len() > 1 {
                                        quote! { _ => return Err(config_error("invalid-value", "ordered-list replacement type does not match its path")), }
                                    } else {
                                        quote! {}
                                    };
                                    quote! {
                                        if let Some(replacement) = ordered_list {
                                            match replacement {
                                                OrderedListReplacement::#ty_name(rows) => {
                                                    for (key, row) in rows {
                                                        let row_key: Option<#key_type> = super::serde::ExtractKey::extract_key(row);
                                                        if row_key.as_ref() != Some(key) {
                                                            return Err(config_error("invalid-value", "invalid user-ordered list"));
                                                        }
                                                    }
                                                    // Keep the JSON path's value checks without reloading
                                                    // defaulted leaves as explicit values.
                                                    serde_json::to_writer(std::io::sink(), rows)
                                                        .map_err(|_| config_error("invalid-value", "invalid user-ordered list"))?;
                                                    *list = rows.clone();
                                                }
                                                #mismatch
                                            }
                                            return Ok(());
                                        }
                                    }
                                } else {
                                    reject_ordered_target.clone()
                                };
                                let list_error = if user_ordered {
                                    "invalid user-ordered list"
                                } else {
                                    "invalid keyed list"
                                };
                                let parse_rows = if user_ordered {
                                    quote! {
                                        let rows: super::serde::UserOrderedMap<#key_type, #ty_name> = serde_json::from_str(value)
                                            .map_err(|_| config_error("invalid-value", #list_error))?;
                                    }
                                } else {
                                    // A single map key has the scalar's Copy semantics,
                                    // including SensitiveKey<T> when T is Copy. Composite
                                    // keys and owned scalar keys still need their clone.
                                    let cloned_map_key = match child.key_leaves.as_slice() {
                                        [key_leaf] => child
                                            .child_paths
                                            .iter()
                                            .filter_map(|path| nodes_by_path.get(path))
                                            .find(|node| {
                                                clean_segment(last_segment(&node.path)) == key_leaf
                                            })
                                            .map(|node| {
                                                super::types::cloned_key_value(
                                                    node,
                                                    &nodes_by_path,
                                                    quote! { key },
                                                )
                                            })
                                            .unwrap_or_else(|| quote! { key.clone() }),
                                        _ => quote! { key.clone() },
                                    };
                                    quote! {
                                        let parsed_rows: Vec<#ty_name> = serde_json::from_str(value)
                                            .map_err(|_| config_error("invalid-value", #list_error))?;
                                        let mut keys = std::collections::BTreeSet::new();
                                        let mut rows = Vec::with_capacity(parsed_rows.len());
                                        for row in parsed_rows {
                                            let key: #key_type = super::serde::ExtractKey::extract_key(&row)
                                                .ok_or_else(|| config_error("invalid-value", #list_error))?;
                                            if !keys.insert(#cloned_map_key) {
                                                return Err(config_error("invalid-value", #list_error));
                                            }
                                            rows.push((key, row));
                                        }
                                    }
                                };
                                quote! {
                                    if segments.len() == 1 && next_seg.keys.is_empty() #collection_operations {
                                        let list = #access;
                                        #typed_replacement
                                        match op {
                                            ConfigOp::Delete | ConfigOp::Remove => list.clear(),
                                            ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                let value = value.ok_or_else(|| config_error("missing-value", "Value is required for list"))?;
                                                #parse_rows
                                                if op == &ConfigOp::Replace {
                                                    #replace_rows
                                                } else {
                                                    // Keep the caller's field presence, including explicit empty lists.
                                                    let raw_rows: Vec<serde_json::Value> = serde_json::from_str(value)
                                                        .map_err(|_| config_error("invalid-value", #list_error))?;
                                                    for ((key, _), raw_row) in rows.into_iter().zip(raw_rows) {
                                                        let value = raw_row.to_string();
                                                        list.entry(key).or_default().#inner_apply(op, &[], Some(&value) #ordered_argument)?;
                                                    }
                                                }
                                            }
                                        }
                                        return Ok(());
                                    }
                                }
                            } else {
                                quote! {}
                            };
                            if child.key_leaves.is_empty() {
                                quote! {
                                    #child_name_str => {
                                        #reject_ordered_target
                                        if segments.len() == 1 {
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.clear();
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let v = value.ok_or_else(|| config_error("missing-value", "Value is required"))?;
                                                    self.#field_ident = serde_json::from_str(v).map_err(#json_error)?;
                                                }
                                            }
                                        } else {
                                            return Err(config_error("unsupported-operation", "index-based patch on unkeyed list is not supported"));
                                        }
                                    }
                                }
                            } else if child.key_leaves.len() == 1 {
                                let key_leaf = &child.key_leaves[0];
                                // Parse key
                                let mut find_key_leaf_node = None;
                                for key_child_path in &child.child_paths {
                                    if let Some(key_child) = nodes_by_path.get(key_child_path) {
                                        if clean_segment(last_segment(&key_child.path)) == key_leaf
                                        {
                                            find_key_leaf_node = Some(key_child);
                                            break;
                                        }
                                    }
                                }
                                let key_leaf_node = find_key_leaf_node.ok_or_else(|| {
                                    RustGenerationError::new(format!(
                                        "list '{}' key leaf '{}' is not a child node",
                                        child.path, key_leaf
                                    ))
                                })?;
                                let parse_key = match nodes_by_path
                                    .patch_scalar_node(key_leaf_node)
                                    .type_ref
                                    .as_ref()
                                {
                                    Some(TypeRef::Uint8) => quote! {
                                        let parsed_key = key_val.parse::<u8>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Int8) => quote! {
                                        let parsed_key = key_val.parse::<i8>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Int16) => quote! {
                                        let parsed_key = key_val.parse::<i16>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Int32) => quote! {
                                        let parsed_key = key_val.parse::<i32>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Uint16) => quote! {
                                        let parsed_key = key_val.parse::<u16>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Uint32) => quote! {
                                        let parsed_key = key_val.parse::<u32>().map_err(#integer_error)?;
                                    },
                                    Some(TypeRef::Uint64) => quote! {
                                        let parsed_key = YangUint64(key_val.parse::<u64>().map_err(#integer_error)?);
                                    },
                                    Some(TypeRef::Int64) => quote! {
                                        let parsed_key = YangInt64(key_val.parse::<i64>().map_err(#integer_error)?);
                                    },
                                    Some(TypeRef::Decimal64 { fraction_digits }) => quote! {
                                        let parsed_key = key_val.parse::<YangDecimal64<#fraction_digits>>().map_err(|_| config_error("invalid-value", "invalid decimal64 key"))?;
                                    },
                                    _ => quote! {
                                        let parsed_key = key_val.clone();
                                    },
                                };

                                let key_field_ident = format_ident!("{}", to_snake_case(key_leaf));
                                let key_is_sensitive = is_sensitive_node(key_leaf_node);
                                let cloned_key = super::types::cloned_key_value(
                                    key_leaf_node,
                                    &nodes_by_path,
                                    quote! { parsed_key },
                                );
                                let key_value = super::types::explicit_leaf_value(
                                    key_leaf_node,
                                    cloned_key.clone(),
                                );
                                let key_assign =
                                    quote! { parsed_item.#key_field_ident = #key_value; };
                                let entry_key_assign =
                                    quote! { entry.#key_field_ident = #key_value; };
                                let valueless_key_assign = if has_scalar_constraints {
                                    quote! { else { #entry_key_assign } }
                                } else {
                                    quote! {}
                                };
                                let map_key = if key_is_sensitive {
                                    quote! { SensitiveKey::from(#cloned_key) }
                                } else {
                                    cloned_key
                                };

                                quote! {
                                    #child_name_str => {
                                        #collection_patch
                                        let key_val = next_seg.keys.get(#key_leaf).ok_or_else(|| config_error("missing-key", format!("missing key: {}", #key_leaf)))?;
                                        #parse_key
                                        if segments.len() == 1 {
                                            #reject_ordered_target
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.remove(&parsed_key);
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let entry = self.#field_ident.entry(#map_key).or_default();
                                                    if let Some(v) = value {
                                                        let mut parsed_item: #ty_name = serde_json::from_str(v).map_err(#json_error)?;
                                                        #key_assign
                                                        *entry = parsed_item;
                                                    }
                                                    #valueless_key_assign
                                                }
                                            }
                                        } else {
                                            if op == &ConfigOp::Delete || op == &ConfigOp::Remove {
                                                if let Some(entry) = self.#field_ident.get_mut(&parsed_key) {
                                                    entry.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                                }
                                            } else {
                                                let entry = self.#field_ident.entry(#map_key).or_default();
                                                #entry_key_assign
                                                entry.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Multi-key list lookup
                                let key_struct_name =
                                    format_ident!("{}Key", nodes_by_path.type_name(child));
                                let mut parse_keys = Vec::new();
                                let mut key_idents = Vec::new();
                                let mut key_assigns = Vec::new();
                                let mut entry_key_assigns = Vec::new();
                                let mut key_fields = TokenStream::new();
                                for key_leaf in &child.key_leaves {
                                    let mut find_key_leaf_node = None;
                                    for key_child_path in &child.child_paths {
                                        if let Some(key_child) = nodes_by_path.get(key_child_path) {
                                            if clean_segment(last_segment(&key_child.path))
                                                == key_leaf
                                            {
                                                find_key_leaf_node = Some(key_child);
                                                break;
                                            }
                                        }
                                    }
                                    let key_ident = format_ident!("k_{}", to_snake_case(key_leaf));
                                    let key_leaf_node = find_key_leaf_node.ok_or_else(|| {
                                        RustGenerationError::new(format!(
                                            "list '{}' key leaf '{}' is not a child node",
                                            child.path, key_leaf
                                        ))
                                    })?;
                                    let parse_key = match nodes_by_path
                                        .patch_scalar_node(key_leaf_node)
                                        .type_ref
                                        .as_ref()
                                    {
                                        Some(TypeRef::Uint8) => quote! {
                                            let #key_ident = key_val.parse::<u8>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Int8) => quote! {
                                            let #key_ident = key_val.parse::<i8>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Int16) => quote! {
                                            let #key_ident = key_val.parse::<i16>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Int32) => quote! {
                                            let #key_ident = key_val.parse::<i32>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Uint16) => quote! {
                                            let #key_ident = key_val.parse::<u16>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Uint32) => quote! {
                                            let #key_ident = key_val.parse::<u32>().map_err(#integer_error)?;
                                        },
                                        Some(TypeRef::Uint64) => quote! {
                                            let #key_ident = YangUint64(key_val.parse::<u64>().map_err(#integer_error)?);
                                        },
                                        Some(TypeRef::Int64) => quote! {
                                            let #key_ident = YangInt64(key_val.parse::<i64>().map_err(#integer_error)?);
                                        },
                                        Some(TypeRef::Decimal64 { fraction_digits }) => quote! {
                                            let #key_ident = key_val.parse::<YangDecimal64<#fraction_digits>>().map_err(|_| config_error("invalid-value", "invalid decimal64 key"))?;
                                        },
                                        _ => quote! {
                                            let #key_ident = key_val.clone();
                                        },
                                    };
                                    parse_keys.push(quote! {
                                        let key_val = next_seg.keys.get(#key_leaf).ok_or_else(|| config_error("missing-key", format!("missing key: {}", #key_leaf)))?;
                                        #parse_key
                                    });
                                    key_idents.push(key_ident.clone());

                                    let key_field_ident =
                                        format_ident!("{}", to_snake_case(key_leaf));
                                    let cloned_key = super::types::cloned_key_value(
                                        key_leaf_node,
                                        &nodes_by_path,
                                        quote! { #key_ident },
                                    );
                                    key_fields.extend(quote! {
                                        #key_field_ident: #cloned_key,
                                    });
                                    let key_value = super::types::explicit_leaf_value(
                                        key_leaf_node,
                                        cloned_key,
                                    );
                                    key_assigns.push(
                                        quote! { parsed_item.#key_field_ident = #key_value; },
                                    );
                                    entry_key_assigns
                                        .push(quote! { entry.#key_field_ident = #key_value; });
                                }
                                let valueless_key_assign = if has_scalar_constraints {
                                    quote! { else { #(#entry_key_assigns)* } }
                                } else {
                                    quote! {}
                                };

                                quote! {
                                    #child_name_str => {
                                        #collection_patch
                                        #(#parse_keys)*
                                        let parsed_key = #key_struct_name {
                                            #key_fields
                                        };
                                        if segments.len() == 1 {
                                            #reject_ordered_target
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.remove(&parsed_key);
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                    if let Some(v) = value {
                                                        let mut parsed_item: #ty_name = serde_json::from_str(v).map_err(#json_error)?;
                                                        #(#key_assigns)*
                                                        *entry = parsed_item;
                                                    }
                                                    #valueless_key_assign
                                                }
                                            }
                                        } else {
                                            if op == &ConfigOp::Delete || op == &ConfigOp::Remove {
                                                if let Some(entry) = self.#field_ident.get_mut(&parsed_key) {
                                                    entry.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                                }
                                            } else {
                                                let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                #(#entry_key_assigns)*
                                                entry.#inner_apply(op, &segments[1..], value #ordered_argument)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::LeafList => {
                            let is_sensitive = is_sensitive_node(child);
                            let list_access = if is_sensitive {
                                quote! { self.#field_ident.get_mut() }
                            } else {
                                quote! { &mut self.#field_ident }
                            };
                            let check_duplicates = if super::is_user_ordered(child) {
                                quote! {
                                    if super::serde::has_duplicate_values(values) {
                                        return Err(config_error("invalid-value", super::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR));
                                    }
                                }
                            } else {
                                quote! {}
                            };
                            // Match the element type emitted by `types`: a
                            // leafref carries its target's scalar type, not
                            // necessarily a string.
                            let element_type =
                                nodes_by_path.legacy_or_resolved(child).type_ref.as_ref();
                            let scalar_path = &child.path;
                            let parse_elem = match element_type {
                                Some(TypeRef::RestrictedString { .. }) => quote! {
                                    if !super::strings::valid(#scalar_path, v) { return Err(config_error("invalid-value", "string violates YANG constraints")); }
                                    let parsed_elem = v.to_string();
                                },
                                Some(TypeRef::Boolean) => quote! {
                                    let parsed_elem = match v {
                                        "true" => true,
                                        "false" => false,
                                        _ => return Err(config_error("invalid-value", "invalid boolean value")),
                                    };
                                },
                                Some(TypeRef::Uint8) => quote! {
                                    let parsed_elem = v.parse::<u8>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Int8) => quote! {
                                    let parsed_elem = v.parse::<i8>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Int16) => quote! {
                                    let parsed_elem = v.parse::<i16>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Int32) => quote! {
                                    let parsed_elem = v.parse::<i32>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Uint16) => quote! {
                                    let parsed_elem = v.parse::<u16>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Uint32) => quote! {
                                    let parsed_elem = v.parse::<u32>().map_err(#integer_error)?;
                                },
                                Some(TypeRef::Uint64) => quote! {
                                    let parsed_elem = YangUint64(v.parse::<u64>().map_err(#integer_error)?);
                                },
                                Some(TypeRef::Int64) => quote! {
                                    let parsed_elem = YangInt64(v.parse::<i64>().map_err(#integer_error)?);
                                },
                                Some(TypeRef::Decimal64 { fraction_digits }) => quote! {
                                    let parsed_elem = v.parse::<YangDecimal64<#fraction_digits>>().map_err(|_| config_error("invalid-value", "invalid decimal64 value"))?;
                                },
                                Some(TypeRef::Empty) => quote! {
                                    let parsed_elem = YangEmpty;
                                },
                                Some(TypeRef::Enumeration { values }) => {
                                    let allowed: Vec<&String> =
                                        values.iter().map(|value| &value.name).collect();
                                    quote! {
                                        let parsed_elem = v.to_string();
                                        if ![ #(#allowed),* ].contains(&parsed_elem.as_str()) {
                                            return Err(config_error("invalid-value", "unsupported enumeration value"));
                                        }
                                    }
                                }
                                _ => quote! {
                                    let parsed_elem = v.to_string();
                                },
                            };
                            quote! {
                                #child_name_str => {
                                    #reject_ordered_target
                                    if segments.len() == 1 {
                                        match op {
                                            ConfigOp::Delete | ConfigOp::Remove => {
                                                let values = #list_access;
                                                if let Some(v) = value {
                                                    #parse_elem
                                                    values.retain(|x| x != &parsed_elem);
                                                } else {
                                                    values.clear();
                                                }
                                            }
                                            ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                let values = #list_access;
                                                let v = value.ok_or_else(|| config_error("missing-value", "Value is required"))?;
                                                if v.starts_with('[') {
                                                    *values = serde_json::from_str(v).map_err(#json_error)?;
                                                } else {
                                                    #parse_elem
                                                    values.push(parsed_elem);
                                                }
                                                #check_duplicates
                                            }
                                        }
                                    } else {
                                        return Err(config_error("invalid-path", "cannot index inside leaf-list"));
                                    }
                                }
                            }
                        }
                        _ => quote! {},
                    };

                    if child.config {
                        field_arms.extend(arm);
                    } else {
                        field_arms.extend(quote! {
                            #child_name_str => {
                                #dispatch_return Err(config_error("read-only", "cannot modify read-only path")) #dispatch_semicolon
                            }
                        });
                    }

                    // State data never belongs to a configuration diff, even
                    // when a collection or an optional container disappears.
                    if !child.config {
                        continue;
                    }

                    // Diff logic
                    let child_segment_str = last_segment(&child.path);
                    let diff_arm = match child.kind {
                        SchemaNodeKind::Leaf => {
                            if child.config {
                                if is_sensitive {
                                    quote! {
                                        if self.#field_ident.get().as_option() != previous.#field_ident.get().as_option() {
                                            let p = YangPath::new(format!("{}/{}", _path_prefix, #child_segment_str)).expect("valid path");
                                            if let Some(ref val) = self.#field_ident.get().as_option() {
                                                let v_str = serde_json::to_string(val).unwrap().trim_matches('"').to_string();
                                                deltas.push(ConfigDelta::Update(p, v_str));
                                            } else {
                                                deltas.push(ConfigDelta::Delete(p));
                                            }
                                        }
                                    }
                                } else {
                                    quote! {
                                        if self.#field_ident.as_option() != previous.#field_ident.as_option() {
                                            let p = YangPath::new(format!("{}/{}", _path_prefix, #child_segment_str)).expect("valid path");
                                            if let Some(ref val) = self.#field_ident.as_option() {
                                                let v_str = serde_json::to_string(val).unwrap().trim_matches('"').to_string();
                                                deltas.push(ConfigDelta::Update(p, v_str));
                                            } else {
                                                deltas.push(ConfigDelta::Delete(p));
                                            }
                                        }
                                    }
                                }
                            } else {
                                quote! {}
                            }
                        }
                        SchemaNodeKind::Container => {
                            quote! {
                                let child_path = format!("{}/{}", _path_prefix, #child_segment_str);
                                match (&self.#field_ident, &previous.#field_ident) {
                                    (Some(cur), Some(prev)) => {
                                        cur.diff_segments(prev, &child_path, deltas)?;
                                    }
                                    (Some(cur), None) => {
                                        cur.diff_segments(&Default::default(), &child_path, deltas)?;
                                    }
                                    (None, Some(_)) => {
                                        deltas.push(ConfigDelta::Delete(YangPath::new(child_path).expect("valid path")));
                                    }
                                    (None, None) => {}
                                }
                            }
                        }
                        SchemaNodeKind::List => {
                            if child.key_leaves.is_empty() {
                                quote! {
                                    if self.#field_ident != previous.#field_ident {
                                        let p = YangPath::new(format!("{}/{}", _path_prefix, #child_segment_str)).expect("valid path");
                                        let v_str = serde_json::to_string(&self.#field_ident).unwrap();
                                        deltas.push(ConfigDelta::Update(p, v_str));
                                    }
                                }
                            } else {
                                let key_bracket_construction = if child.key_leaves.len() == 1 {
                                    let key_leaf = &child.key_leaves[0];
                                    let key_node = child.child_paths.iter().find_map(|path| {
                                        nodes_by_path.get(path).copied().filter(|node| {
                                            clean_segment(last_segment(&node.path)) == key_leaf
                                        })
                                    });
                                    let key_value = if key_node.is_some_and(is_sensitive_node) {
                                        quote! { k.get().to_string() }
                                    } else {
                                        quote! { k.to_string() }
                                    };
                                    quote! {
                                        let key_bracket_str = format!("[{}='{}']", #key_leaf, escape_key_value(&#key_value));
                                    }
                                } else {
                                    let mut key_bracket_parts = TokenStream::new();
                                    for key_leaf in &child.key_leaves {
                                        let field_ident =
                                            format_ident!("{}", to_snake_case(key_leaf));
                                        key_bracket_parts.extend(quote! {
                                            key_bracket_str.push_str(&format!(
                                                "[{}='{}']",
                                                #key_leaf,
                                                escape_key_value(&k.#field_ident.to_string())
                                            ));
                                        });
                                    }
                                    quote! {
                                        let mut key_bracket_str = String::new();
                                        #key_bracket_parts
                                    }
                                };
                                let key_bracket_construction_prev =
                                    key_bracket_construction.clone();

                                let keyed_diff = quote! {
                                    let list_path = format!("{}/{}", _path_prefix, #child_segment_str);
                                    for (k, cur_val) in &self.#field_ident {
                                        #key_bracket_construction
                                        let entry_path = format!("{}{}", list_path, key_bracket_str);
                                        if let Some(prev_val) = previous.#field_ident.get(k) {
                                            cur_val.diff_segments(prev_val, &entry_path, deltas)?;
                                        } else {
                                            cur_val.diff_segments(&Default::default(), &entry_path, deltas)?;
                                        }
                                    }
                                    for k in previous.#field_ident.keys() {
                                        if !self.#field_ident.contains_key(k) {
                                            #key_bracket_construction_prev
                                            let entry_path = format!("{}{}", list_path, key_bracket_str);
                                            deltas.push(ConfigDelta::Delete(YangPath::new(&entry_path).expect("valid path")));
                                        }
                                    }
                                };
                                if super::is_user_ordered(child) {
                                    let ty_name =
                                        format_ident!("{}", nodes_by_path.type_name(child));
                                    let list_value = if is_sensitive {
                                        quote! { self.#field_ident.get().clone() }
                                    } else {
                                        quote! { self.#field_ident.clone() }
                                    };
                                    quote! {
                                        #keyed_diff
                                        // Keyed edits retain old positions and append new keys. Only
                                        // replace the collection when that cannot produce the new order.
                                        let edited_order = previous.#field_ident.keys()
                                            .filter(|key| self.#field_ident.contains_key(*key))
                                            .chain(self.#field_ident.keys()
                                                .filter(|key| !previous.#field_ident.contains_key(*key)));
                                        if !self.#field_ident.keys().eq(edited_order) {
                                            let path = YangPath::new(format!("{}/{}", _path_prefix, #child_segment_str))
                                                .map_err(|_| config_error("invalid-path", "invalid list path"))?;
                                            deltas.push(ConfigDelta::ReplaceOrderedList(
                                                path, OrderedListReplacement::#ty_name(#list_value),
                                            ));
                                        }
                                    }
                                } else {
                                    keyed_diff
                                }
                            }
                        }
                        SchemaNodeKind::LeafList => {
                            quote! {
                                if self.#field_ident != previous.#field_ident {
                                    let p = YangPath::new(format!("{}/{}", _path_prefix, #child_segment_str)).expect("valid path");
                                    let v_str = serde_json::to_string(&self.#field_ident).unwrap();
                                    deltas.push(ConfigDelta::Update(p, v_str));
                                }
                            }
                        }
                        _ => quote! {},
                    };

                    diff_fields.extend(diff_arm);
                }
            }

            // No-op configuration diffs need no inputs in any schema profile.
            let empty_state_diff = diff_fields.is_empty();
            let previous_param = format_ident!(
                "{}",
                if empty_state_diff {
                    "_previous"
                } else {
                    "previous"
                }
            );
            let deltas_param = format_ident!(
                "{}",
                if empty_state_diff {
                    "_deltas"
                } else {
                    "deltas"
                }
            );
            let public_apply_wrapper = if has_scalar_constraints {
                let checks = subtree_constraint_checks(node, &nodes_by_path);
                quote! {
                    pub fn apply_patch_segments(
                        &mut self,
                        op: &ConfigOp,
                        segments: &[PathSegment],
                        value: Option<&str>,
                    ) -> Result<(), ConfigError> {
                        let mut candidate = self.clone();
                        candidate.#apply_segments(op, segments, value #ordered_none)?;
                        candidate.validate_patch_constraints()?;
                        *self = candidate;
                        Ok(())
                    }

                    fn validate_patch_constraints(&self) -> Result<(), ConfigError> {
                        #checks
                        Ok(())
                    }
                }
            } else if has_ordered_lists {
                quote! {
                    pub fn apply_patch_segments(
                        &mut self,
                        op: &ConfigOp,
                        segments: &[PathSegment],
                        value: Option<&str>,
                    ) -> Result<(), ConfigError> {
                        self.#apply_segments(op, segments, value, None)
                    }
                }
            } else {
                quote! {}
            };
            let state_matcher = if has_state {
                state_matcher(node, &nodes_by_path)
            } else {
                quote! {}
            };
            let checked_apply = if has_state {
                let path = &node.path;
                quote! {
                    #apply_visibility fn #apply_segments(
                        &mut self,
                        op: &ConfigOp,
                        segments: &[PathSegment],
                        value: Option<&str> #ordered_parameter,
                    ) -> Result<(), ConfigError> {
                        validate_patch_input(#path, segments, value)?;
                        let mut candidate = self.clone();
                        candidate.#inner_apply(op, segments, value #ordered_argument)?;
                        if !candidate.state_matches(self) {
                            return Err(config_error("read-only", "cannot modify read-only path"));
                        }
                        *self = candidate;
                        Ok(())
                    }
                }
            } else {
                quote! {}
            };
            let validate_inner = if has_state {
                let path = &node.path;
                quote! { validate_patch_input(#path, segments, value)?; }
            } else {
                quote! {}
            };
            let dispatch_success = if all_fields_read_only {
                quote! {}
            } else {
                quote! { Ok(()) }
            };
            impls.extend(quote! {
                impl #struct_name {
                    #public_apply_wrapper
                    #state_matcher
                    #checked_apply
                    #inner_visibility fn #inner_apply(
                        &mut self,
                        op: &ConfigOp,
                        segments: &[PathSegment],
                        value: Option<&str> #ordered_parameter,
                    ) -> Result<(), ConfigError> {
                        #validate_inner
                        if segments.is_empty() {
                            #reject_ordered_target
                            match op {
                                ConfigOp::Delete | ConfigOp::Remove => {
                                    *self = Self::default();
                                    return Ok(());
                                }
                                ConfigOp::Replace => {
                                    if let Some(v) = value {
                                        *self = serde_json::from_str(v).map_err(#json_error)?;
                                        return Ok(());
                                    } else {
                                        return Err(config_error("missing-value", "Value is required for replace"));
                                    }
                                }
                                ConfigOp::Update | ConfigOp::Merge => {
                                    if let Some(v) = value {
                                        #validate_merge
                                        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(v) {
                                            for (k, val) in map {
                                                let val_str = if val.is_string() {
                                                    val.as_str().unwrap().to_string()
                                                } else {
                                                    val.to_string()
                                                };
                                                let segs = parse_path(&k).map_err(|_| config_error("invalid-path", "invalid path"))?;
                                                self.#inner_apply(op, &segs, Some(&val_str) #ordered_argument)?;
                                            }
                                            return Ok(());
                                        } else {
                                            *self = serde_json::from_str(v).map_err(#json_error)?;
                                            return Ok(());
                                        }
                                    } else {
                                        return Err(config_error("missing-value", "Value is required for update/merge"));
                                    }
                                }
                            }
                        }

                        let next_seg = &segments[0];
                        let cleaned_name = clean_segment(&next_seg.name);
                        match cleaned_name {
                            #field_arms
                            _ => {
                                #dispatch_return Err(config_error("unsupported-path", "unsupported field")) #dispatch_semicolon
                            }
                        }
                        #dispatch_success
                    }

                    pub fn diff_segments(
                        &self,
                        #previous_param: &Self,
                        _path_prefix: &str,
                        #deltas_param: &mut Vec<ConfigDelta>,
                    ) -> Result<(), ConfigError> {
                        #diff_fields
                        Ok(())
                    }
                }
            });
        }
    }

    let escape_key_value_fn =
        if input.nodes.iter().any(|node| {
            node.config && node.kind == SchemaNodeKind::List && !node.key_leaves.is_empty()
        }) {
            quote! {
                fn escape_key_value(value: &str) -> String {
                    value.replace('\\', "\\\\").replace('\'', "\\'")
                }
            }
        } else {
            quote! {}
        };

    let scalar_validation = if has_scalar_constraints {
        quote! { super::validate::validate_syntax(&temp).map_err(|error| config_error("invalid-value", error.message))?; }
    } else {
        quote! {}
    };
    let scalar_constraint_error_helper = if input
        .nodes
        .iter()
        .any(|node| super::types::has_scalar_constraints(node, &nodes_by_path))
    {
        quote! {
            fn scalar_constraint_error(reason: &'static str) -> ConfigError {
                config_error("invalid-value", reason)
            }
        }
    } else {
        quote! {}
    };
    let write_validation = if has_state {
        quote! {
            // Resolve relative helper paths and JSON member paths using the same
            // bare names as dispatch. Reject state before parsing its payload.
            fn write_target(
                mut node: &'static opc_mgmt_schema::NodeMeta,
                segments: &[PathSegment],
            ) -> Result<Option<&'static opc_mgmt_schema::NodeMeta>, ConfigError> {
                let registry = super::schema_registry::registry();
                for segment in segments {
                    if !node.config {
                        return Err(config_error("read-only", "cannot modify read-only path"));
                    }
                    let Some(child) = node.child_paths.iter().filter_map(|path| registry.node(path))
                        .find(|child| clean_segment(child.path.rsplit('/').next().unwrap_or("")) == clean_segment(&segment.name)) else {
                            // Existing dispatch/deserialization owns unknown fields.
                            return Ok(None);
                        };
                    node = child;
                }
                if !node.config {
                    return Err(config_error("read-only", "cannot modify read-only path"));
                }
                Ok(Some(node))
            }

            fn validate_state_members(
                node: &'static opc_mgmt_schema::NodeMeta,
                value: &serde_json::Value,
            ) -> Result<(), ConfigError> {
                use opc_mgmt_schema::NodeKind;
                if !matches!(node.kind, NodeKind::Container | NodeKind::List) {
                    return Ok(());
                }
                match value {
                    serde_json::Value::Object(members) => {
                        for (name, value) in members {
                            let segments = parse_path(name).map_err(|_| config_error("invalid-path", "invalid path"))?;
                            if let Some(child) = write_target(node, &segments)? {
                                validate_state_members(child, value)?;
                            }
                        }
                    }
                    serde_json::Value::Array(rows) if node.kind == NodeKind::List => {
                        for row in rows {
                            validate_state_members(node, row)?;
                        }
                    }
                    _ => {}
                }
                Ok(())
            }

            fn validate_patch_input(
                path: &'static str,
                segments: &[PathSegment],
                value: Option<&str>,
            ) -> Result<(), ConfigError> {
                let node = super::schema_registry::registry().node(path)
                    .ok_or_else(|| config_error("invalid-path", "invalid path"))?;
                if let Some(target) = write_target(node, segments)? {
                    if let Some(value) = value.and_then(|text| serde_json::from_str(text).ok()) {
                        validate_state_members(target, &value)?;
                    }
                }
                Ok(())
            }
        }
    } else {
        quote! {}
    };

    let tokens = quote! {
        use opc_config_model::{ConfigError, YangPath};
        use super::types::*;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ConfigOp {
            Replace,
            Update,
            Delete,
            Merge,
            Remove,
        }

        #[derive(Debug, Clone, PartialEq)]
        pub enum ConfigDelta {
            Replace(YangPath, String),
            Update(YangPath, String),
            Delete(YangPath),
            Merge(YangPath, String),
            Remove(YangPath),
            #ordered_delta
        }

        #ordered_definitions

        #write_validation

        fn config_error(kind: &'static str, message: impl Into<String>) -> ConfigError {
            ConfigError::new(kind, message)
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct PathSegment {
            pub name: String,
            pub keys: std::collections::BTreeMap<String, String>,
        }

        pub fn parse_path(path: &str) -> Result<Vec<PathSegment>, String> {
            let mut segments = Vec::new();
            let mut current_segment = String::new();
            let mut in_brackets = false;
            let mut quote_char = None;
            let mut chars = path.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    current_segment.push(c);
                    if let Some(next_c) = chars.next() {
                        current_segment.push(next_c);
                    }
                } else if let Some(q) = quote_char {
                    if c == q {
                        quote_char = None;
                    }
                    current_segment.push(c);
                } else {
                    if c == '\'' || c == '"' {
                        quote_char = Some(c);
                        current_segment.push(c);
                    } else if c == '/' && !in_brackets {
                        if !current_segment.is_empty() {
                            segments.push(parse_segment(&current_segment)?);
                            current_segment.clear();
                        }
                    } else {
                        if c == '[' {
                            in_brackets = true;
                        } else if c == ']' {
                            in_brackets = false;
                        }
                        current_segment.push(c);
                    }
                }
            }
            if !current_segment.is_empty() {
                segments.push(parse_segment(&current_segment)?);
            }
            Ok(segments)
        }

        fn parse_segment(seg: &str) -> Result<PathSegment, String> {
            let mut first_bracket_idx = None;
            let mut quote_char = None;
            let mut escaped = false;
            for (idx, c) in seg.char_indices() {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if let Some(q) = quote_char {
                    if c == q {
                        quote_char = None;
                    }
                } else if c == '\'' || c == '"' {
                    quote_char = Some(c);
                } else if c == '[' {
                    first_bracket_idx = Some(idx);
                    break;
                }
            }

            if let Some(idx) = first_bracket_idx {
                let name = seg[..idx].to_string();
                let bracket_part = &seg[idx..];
                let mut keys = std::collections::BTreeMap::new();
                let mut current_key = String::new();
                let mut in_key = false;
                let mut quote_char = None;
                let mut chars = bracket_part.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        current_key.push(c);
                        if let Some(next_c) = chars.next() {
                            current_key.push(next_c);
                        }
                    } else if let Some(q) = quote_char {
                        if c == q {
                            quote_char = None;
                        }
                        current_key.push(c);
                    } else if c == '\'' || c == '"' {
                        quote_char = Some(c);
                        current_key.push(c);
                    } else {
                        if c == '[' {
                            in_key = true;
                        } else if c == ']' {
                            in_key = false;
                            if let Some(eq_idx) = current_key.find('=') {
                                let k = current_key[..eq_idx].trim();
                                let clean_k = clean_segment(k).to_string();
                                let v = current_key[eq_idx + 1..].trim()
                                    .trim_matches('\'')
                                    .trim_matches('"')
                                    .to_string();
                                let v = unescape_quoted_value(&v);
                                keys.insert(clean_k, v);
                            }
                            current_key.clear();
                        } else if in_key {
                            current_key.push(c);
                        }
                    }
                }
                Ok(PathSegment { name, keys })
            } else {
                Ok(PathSegment {
                    name: seg.to_string(),
                    keys: std::collections::BTreeMap::new(),
                })
            }
        }

        fn clean_segment(seg: &str) -> &str {
            if let Some(idx) = seg.find(':') {
                &seg[idx + 1..]
            } else {
                seg
            }
        }

        fn unescape_quoted_value(value: &str) -> String {
            let mut out = String::with_capacity(value.len());
            let mut chars = value.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.peek().copied() {
                        Some('\\' | '\'' | '"') => {
                            out.push(chars.next().expect("peeked next character"));
                        }
                        Some(_) | None => out.push(c),
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }

        #escape_key_value_fn

        pub fn diff_root(current: &#root_type, previous: &#root_type) -> Result<Vec<ConfigDelta>, ConfigError> {
            let mut deltas = Vec::new();
            current.diff_segments(previous, #root_path, &mut deltas)?;
            Ok(deltas)
        }

        pub fn apply_patch(root: &mut #root_type, deltas: &[ConfigDelta]) -> Result<(), ConfigError> {
            // Validate all paths upfront to satisfy fail-closed semantics
            for delta in deltas {
                let path = match delta {
                    ConfigDelta::Update(p, _) => p,
                    ConfigDelta::Replace(p, _) => p,
                    ConfigDelta::Delete(p) => p,
                    ConfigDelta::Merge(p, _) => p,
                    ConfigDelta::Remove(p) => p,
                    #ordered_path_arm
                };
                if !super::paths::is_valid_path(path.as_str()) {
                    return Err(config_error("invalid-path", "invalid path"));
                }
                if !super::paths::is_config_path(path.as_str()) {
                    return Err(config_error("read-only", "cannot modify read-only path"));
                }
            }

            // Clone and apply to verify transactions succeed before modifying target root
            let mut temp = root.clone();
            for delta in deltas {
                let (path, op, value #ordered_argument) = match delta {
                    ConfigDelta::Update(p, v) => (p, ConfigOp::Update, Some(v.as_str()) #ordered_none),
                    ConfigDelta::Replace(p, v) => (p, ConfigOp::Replace, Some(v.as_str()) #ordered_none),
                    ConfigDelta::Delete(p) => (p, ConfigOp::Delete, None #ordered_none),
                    ConfigDelta::Merge(p, v) => (p, ConfigOp::Merge, Some(v.as_str()) #ordered_none),
                    ConfigDelta::Remove(p) => (p, ConfigOp::Remove, None #ordered_none),
                    #ordered_apply_arm
                };
                let segments = parse_path(path.as_str()).map_err(|_| config_error("invalid-path", "invalid path"))?;
                if segments.is_empty() {
                    return Err(config_error("invalid-path", "Path is empty"));
                }
                temp.#apply_segments(&op, &segments[1..], value #ordered_argument)?;
            }
            #scalar_validation
            *root = temp;
            Ok(())
        }

        pub fn root_path() -> YangPath {
            YangPath::new(#root_path).expect("opc-yanggen emitted an invalid root YANG path")
        }

        #json_error_helper
        #scalar_constraint_error_helper
        #impls
    };

    Ok(tokens.to_string())
}

// Public subtree methods need the same admission checks as the root transaction.
// Internal recursion stays in-place on the already-cloned transaction candidate.
fn subtree_constraint_checks(node: &SchemaNode, nodes: &NodeIndex<'_>) -> TokenStream {
    let mut checks = TokenStream::new();
    for child_path in &node.child_paths {
        let Some(child) = nodes.get(child_path) else {
            continue;
        };
        let field = format_ident!("{}", to_snake_case(clean_segment(last_segment(child_path))));
        checks.extend(super::types::scalar_constraint_check(
            child,
            nodes,
            quote! { self.#field },
            quote! { scalar_constraint_error },
        ));
        let access = if is_sensitive_node(child) {
            quote! { self.#field.get() }
        } else {
            quote! { &self.#field }
        };
        checks.extend(match child.kind {
            SchemaNodeKind::Container => quote! {
                if let Some(child) = #access { child.validate_patch_constraints()?; }
            },
            SchemaNodeKind::List if child.key_leaves.is_empty() => quote! {
                for child in #access { child.validate_patch_constraints()?; }
            },
            SchemaNodeKind::List => quote! {
                { let children = #access; for child in children.values() { child.validate_patch_constraints()?; } }
            },
            SchemaNodeKind::LeafList if super::is_user_ordered(child) => quote! {
                if super::serde::has_duplicate_values(#access) {
                    return Err(config_error("invalid-value", super::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR));
                }
            },
            _ => TokenStream::new(),
        });
    }
    checks
}

// Compare only operational fields so replacing/removing a configuration ancestor
// cannot erase retained observations. Configuration list order is independent of
// the state associated with each key.
fn state_matcher(node: &SchemaNode, nodes: &NodeIndex<'_>) -> TokenStream {
    if !node.config {
        return quote! {
            pub(crate) fn state_matches(&self, previous: &Self) -> bool {
                self == previous
            }
        };
    }
    let mut checks = Vec::new();
    for child in node.child_paths.iter().filter_map(|path| nodes.get(path)) {
        let field = format_ident!(
            "{}",
            to_snake_case(clean_segment(last_segment(&child.path)))
        );
        if !child.config {
            checks.push(quote! { self.#field == previous.#field });
            continue;
        }
        if !nodes.nodes.values().any(|descendant| {
            !descendant.config
                && descendant
                    .path
                    .strip_prefix(&child.path)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            continue;
        }
        let current = if is_sensitive_node(child) {
            quote! { self.#field.get() }
        } else {
            quote! { self.#field }
        };
        let previous = if is_sensitive_node(child) {
            quote! { previous.#field.get() }
        } else {
            quote! { previous.#field }
        };
        let (current_iter, previous_iter) = if super::is_user_ordered(child) {
            if is_sensitive_node(child) {
                (
                    quote! { (#current).into_iter() },
                    quote! { (#previous).into_iter() },
                )
            } else {
                (
                    quote! { (&self.#field).into_iter() },
                    quote! { (&previous.#field).into_iter() },
                )
            }
        } else {
            (quote! { (#current).iter() }, quote! { (#previous).iter() })
        };
        let check = match child.kind {
            SchemaNodeKind::Container => quote! {
                match ((#current).as_ref(), (#previous).as_ref()) {
                    (Some(current), Some(previous)) => current.state_matches(previous),
                    (Some(current), None) => current.state_matches(&Default::default()),
                    (None, Some(previous)) => previous.state_matches(&Default::default()),
                    (None, None) => true,
                }
            },
            SchemaNodeKind::List if child.key_leaves.is_empty() => quote! {
                (#current).iter().enumerate().all(|(index, row)| {
                    (#previous).get(index).map_or_else(
                        || row.state_matches(&Default::default()),
                        |old| row.state_matches(old),
                    )
                }) && (#previous).iter().skip((#current).len())
                    .all(|row| row.state_matches(&Default::default()))
            },
            SchemaNodeKind::List => quote! {
                #current_iter.all(|(key, row)| {
                    (#previous).get(key).map_or_else(
                        || row.state_matches(&Default::default()),
                        |old| row.state_matches(old),
                    )
                }) && #previous_iter.all(|(key, row)| {
                    (#current).contains_key(key) || row.state_matches(&Default::default())
                })
            },
            _ => continue,
        };
        checks.push(check);
    }
    if checks.is_empty() {
        quote! {
            pub(crate) fn state_matches(&self, _previous: &Self) -> bool { true }
        }
    } else if checks.len() == 1 {
        let check = &checks[0];
        quote! {
            pub(crate) fn state_matches(&self, previous: &Self) -> bool {
                #check
            }
        }
    } else {
        quote! {
            pub(crate) fn state_matches(&self, previous: &Self) -> bool {
                #((#checks))&&*
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::YangSourceLocation;
    use crate::emit::CanonicalProfile;
    use crate::ir::{SchemaModule, StackBudget};

    fn malformed_input_with_list(list: SchemaNode, extra_nodes: Vec<SchemaNode>) -> CanonicalInput {
        let source = YangSourceLocation::new("dangling-key.yang", 1, 1);
        let root = SchemaNode {
            path: "/test:system".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec![list.path.clone()],
            source: source.clone(),
            ..Default::default()
        };
        let mut nodes = vec![root, list];
        nodes.extend(extra_nodes);

        CanonicalInput {
            profile: CanonicalProfile {
                generation: "test".to_string(),
                lockfile_mismatch: None,
            },
            locked_modules: vec![],
            schema_modules: vec![SchemaModule {
                name: "test".to_string(),
                revision: "2026-07-07".to_string(),
                namespace: "urn:test".to_string(),
                prefix: "test".to_string(),
                source,
                ..Default::default()
            }],
            nodes,
            constraints: vec![],
            stack_shapes: vec![],
            stack_budget: StackBudget::default(),
            canonicalization_skipped: false,
            max_canonical_scan_stack_len: None,
        }
    }

    #[test]
    fn patch_generation_reports_missing_single_key_child_node() {
        let source = YangSourceLocation::new("dangling-key.yang", 2, 1);
        let list = SchemaNode {
            path: "/test:system/test:entry".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["id".to_string()],
            child_paths: vec![],
            source,
            ..Default::default()
        };
        let input = malformed_input_with_list(list, vec![]);

        let err = generate(&input).expect_err("missing key child should fail closed");

        assert!(err.message().contains("key leaf 'id' is not a child node"));
        assert!(err.message().contains("/test:system/test:entry"));
    }

    #[test]
    fn patch_generation_reports_missing_multi_key_child_node() {
        let source = YangSourceLocation::new("dangling-key.yang", 2, 1);
        let id = SchemaNode {
            path: "/test:system/test:entry/test:id".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        };
        let list = SchemaNode {
            path: "/test:system/test:entry".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["id".to_string(), "slot".to_string()],
            child_paths: vec![id.path.clone()],
            source,
            ..Default::default()
        };
        let input = malformed_input_with_list(list, vec![id]);

        let err = generate(&input).expect_err("missing key child should fail closed");

        assert!(err
            .message()
            .contains("key leaf 'slot' is not a child node"));
        assert!(err.message().contains("/test:system/test:entry"));
    }
}
