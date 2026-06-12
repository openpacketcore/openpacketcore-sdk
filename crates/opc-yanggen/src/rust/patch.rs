use super::{
    clean_segment, is_sensitive_name, last_segment, to_pascal_case, to_snake_case,
    RustGenerationError,
};
use crate::emit::CanonicalInput;
use crate::ir::{AllocationStrategy, SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

fn is_sensitive_node(node: &SchemaNode) -> bool {
    if let Some(ref dc) = node.data_class {
        dc != "public" && dc != "operational"
    } else {
        is_sensitive_name(clean_segment(last_segment(&node.path)))
    }
}

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let root = input
        .nodes
        .iter()
        .find(|node| {
            let trimmed = node.path.trim_start_matches('/');
            !trimmed.is_empty() && !trimmed.contains('/')
        })
        .expect("Rust generation validates one root node before emitting patches");
    let root_name = clean_segment(last_segment(&root.path));
    let root_type = format_ident!("{}", to_pascal_case(root_name));
    let root_path = &root.path;

    let mut nodes_by_path = HashMap::new();
    for node in &input.nodes {
        nodes_by_path.insert(node.path.clone(), node);
    }

    let mut impls = TokenStream::new();

    for node in &input.nodes {
        if node.kind == SchemaNodeKind::Container || node.kind == SchemaNodeKind::List {
            let struct_name = format_ident!(
                "{}",
                to_pascal_case(clean_segment(last_segment(&node.path)))
            );
            let mut field_arms = TokenStream::new();
            let mut diff_fields = TokenStream::new();

            for child_path in &node.child_paths {
                if let Some(child) = nodes_by_path.get(child_path) {
                    let child_name = clean_segment(last_segment(&child.path));
                    let field_ident = format_ident!("{}", to_snake_case(child_name));
                    let child_name_str = child_name;
                    let is_sensitive = is_sensitive_node(child);

                    let parse_and_assign = match &child.type_ref {
                        Some(TypeRef::Boolean) => quote! {
                            let parsed = match _v {
                                "true" => true,
                                "false" => false,
                                _ => return Err(config_error("invalid-value", "invalid boolean value")),
                            };
                        },
                        Some(TypeRef::Uint16) => quote! {
                            let parsed = _v.parse::<u16>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                        },
                        Some(TypeRef::Uint32) => quote! {
                            let parsed = _v.parse::<u32>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                        },
                        Some(TypeRef::Int64) => quote! {
                            let parsed = YangInt64(_v.parse::<i64>().map_err(|e| config_error("invalid-value", e.to_string()))?);
                        },
                        Some(TypeRef::Decimal64) => quote! {
                            let parsed = YangDecimal64(_v.parse::<f64>().map_err(|e| config_error("invalid-value", e.to_string()))?);
                        },
                        Some(TypeRef::Empty) => quote! {
                            let parsed = YangEmpty;
                        },
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
                                    if segments.len() > 1 {
                                        return Err(config_error("invalid-path", format!("path goes deeper than leaf: {}", cleaned_name)));
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
                                                container.apply_patch_segments(op, &segments[1..], value)?;
                                            }
                                        } else {
                                            let container = #get_mut_container;
                                            container.apply_patch_segments(op, &segments[1..], value)?;
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::List => {
                            let ty_name = format_ident!("{}", to_pascal_case(child_name));
                            if child.key_leaves.is_empty() {
                                quote! {
                                    #child_name_str => {
                                        if segments.len() == 1 {
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.clear();
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let v = value.ok_or_else(|| config_error("missing-value", "Value is required"))?;
                                                    self.#field_ident = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
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
                                let parse_key = match find_key_leaf_node
                                    .and_then(|n| n.type_ref.as_ref())
                                {
                                    Some(TypeRef::Uint16) => quote! {
                                        let parsed_key = key_val.parse::<u16>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                                    },
                                    Some(TypeRef::Uint32) => quote! {
                                        let parsed_key = key_val.parse::<u32>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                                    },
                                    _ => quote! {
                                        let parsed_key = key_val.clone();
                                    },
                                };

                                let key_field_ident = format_ident!("{}", to_snake_case(key_leaf));
                                let key_is_sensitive =
                                    is_sensitive_node(find_key_leaf_node.unwrap());
                                let key_assign = if key_is_sensitive {
                                    quote! { parsed_item.#key_field_ident = SecretLeaf::new(LeafPresence::Explicit(parsed_key.clone())); }
                                } else {
                                    quote! { parsed_item.#key_field_ident = LeafPresence::Explicit(parsed_key.clone()); }
                                };

                                quote! {
                                    #child_name_str => {
                                        let key_val = next_seg.keys.get(#key_leaf).ok_or_else(|| config_error("missing-key", format!("missing key: {}", #key_leaf)))?;
                                        #parse_key
                                        if segments.len() == 1 {
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.remove(&parsed_key);
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                    if let Some(v) = value {
                                                        let mut parsed_item: #ty_name = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
                                                        #key_assign
                                                        *entry = parsed_item;
                                                    }
                                                }
                                            }
                                        } else {
                                            if op == &ConfigOp::Delete || op == &ConfigOp::Remove {
                                                if let Some(entry) = self.#field_ident.get_mut(&parsed_key) {
                                                    entry.apply_patch_segments(op, &segments[1..], value)?;
                                                }
                                            } else {
                                                let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                entry.apply_patch_segments(op, &segments[1..], value)?;
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Multi-key list lookup
                                let key_struct_name =
                                    format_ident!("{}Key", to_pascal_case(child_name));
                                let mut parse_keys = Vec::new();
                                let mut key_idents = Vec::new();
                                let mut key_assigns = Vec::new();
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
                                    let parse_key = match find_key_leaf_node
                                        .and_then(|n| n.type_ref.as_ref())
                                    {
                                        Some(TypeRef::Uint16) => quote! {
                                            let #key_ident = key_val.parse::<u16>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                                        },
                                        Some(TypeRef::Uint32) => quote! {
                                            let #key_ident = key_val.parse::<u32>().map_err(|e| config_error("invalid-value", e.to_string()))?;
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
                                    key_fields.extend(quote! {
                                        #key_field_ident: #key_ident.clone(),
                                    });
                                    let is_sensitive =
                                        is_sensitive_node(find_key_leaf_node.unwrap());
                                    if is_sensitive {
                                        key_assigns.push(quote! { parsed_item.#key_field_ident = SecretLeaf::new(LeafPresence::Explicit(#key_ident.clone())); });
                                    } else {
                                        key_assigns.push(quote! { parsed_item.#key_field_ident = LeafPresence::Explicit(#key_ident.clone()); });
                                    }
                                }

                                quote! {
                                    #child_name_str => {
                                        #(#parse_keys)*
                                        let parsed_key = #key_struct_name {
                                            #key_fields
                                        };
                                        if segments.len() == 1 {
                                            match op {
                                                ConfigOp::Delete | ConfigOp::Remove => {
                                                    self.#field_ident.remove(&parsed_key);
                                                }
                                                ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                    let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                    if let Some(v) = value {
                                                        let mut parsed_item: #ty_name = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
                                                        #(#key_assigns)*
                                                        *entry = parsed_item;
                                                    }
                                                }
                                            }
                                        } else {
                                            if op == &ConfigOp::Delete || op == &ConfigOp::Remove {
                                                if let Some(entry) = self.#field_ident.get_mut(&parsed_key) {
                                                    entry.apply_patch_segments(op, &segments[1..], value)?;
                                                }
                                            } else {
                                                let entry = self.#field_ident.entry(parsed_key.clone()).or_default();
                                                entry.apply_patch_segments(op, &segments[1..], value)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::LeafList => {
                            let parse_elem = match &child.type_ref {
                                Some(TypeRef::Boolean) => quote! {
                                    let parsed_elem = match v {
                                        "true" => true,
                                        "false" => false,
                                        _ => return Err(config_error("invalid-value", "invalid boolean value")),
                                    };
                                },
                                Some(TypeRef::Uint16) => quote! {
                                    let parsed_elem = v.parse::<u16>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                                },
                                Some(TypeRef::Uint32) => quote! {
                                    let parsed_elem = v.parse::<u32>().map_err(|e| config_error("invalid-value", e.to_string()))?;
                                },
                                Some(TypeRef::Int64) => quote! {
                                    let parsed_elem = YangInt64(v.parse::<i64>().map_err(|e| config_error("invalid-value", e.to_string()))?);
                                },
                                Some(TypeRef::Decimal64) => quote! {
                                    let parsed_elem = YangDecimal64(v.parse::<f64>().map_err(|e| config_error("invalid-value", e.to_string()))?);
                                },
                                Some(TypeRef::Empty) => quote! {
                                    let parsed_elem = YangEmpty;
                                },
                                _ => quote! {
                                    let parsed_elem = v.to_string();
                                },
                            };
                            quote! {
                                #child_name_str => {
                                    if segments.len() == 1 {
                                        match op {
                                            ConfigOp::Delete | ConfigOp::Remove => {
                                                if let Some(v) = value {
                                                    #parse_elem
                                                    self.#field_ident.retain(|x| x != &parsed_elem);
                                                } else {
                                                    self.#field_ident.clear();
                                                }
                                            }
                                            ConfigOp::Replace | ConfigOp::Update | ConfigOp::Merge => {
                                                let v = value.ok_or_else(|| config_error("missing-value", "Value is required"))?;
                                                if v.starts_with('[') {
                                                    self.#field_ident = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
                                                } else {
                                                    #parse_elem
                                                    self.#field_ident.push(parsed_elem);
                                                }
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

                    field_arms.extend(arm);

                    // Diff logic
                    let child_path_str = &child.path;
                    let diff_arm = match child.kind {
                        SchemaNodeKind::Leaf => {
                            if child.config {
                                if is_sensitive {
                                    quote! {
                                        if self.#field_ident.get().as_option() != previous.#field_ident.get().as_option() {
                                            let p = YangPath::new(#child_path_str).expect("valid path");
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
                                            let p = YangPath::new(#child_path_str).expect("valid path");
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
                                match (&self.#field_ident, &previous.#field_ident) {
                                    (Some(cur), Some(prev)) => {
                                        cur.diff_segments(prev, #child_path_str, deltas)?;
                                    }
                                    (Some(cur), None) => {
                                        cur.diff_segments(&Default::default(), #child_path_str, deltas)?;
                                    }
                                    (None, Some(_)) => {
                                        deltas.push(ConfigDelta::Delete(YangPath::new(#child_path_str).expect("valid path")));
                                    }
                                    (None, None) => {}
                                }
                            }
                        }
                        SchemaNodeKind::List => {
                            if child.key_leaves.is_empty() {
                                quote! {
                                    if self.#field_ident != previous.#field_ident {
                                        let p = YangPath::new(#child_path_str).expect("valid path");
                                        let v_str = serde_json::to_string(&self.#field_ident).unwrap();
                                        deltas.push(ConfigDelta::Update(p, v_str));
                                    }
                                }
                            } else {
                                let key_bracket_construction = if child.key_leaves.len() == 1 {
                                    let key_leaf = &child.key_leaves[0];
                                    quote! {
                                        let key_bracket_str = format!("[{}='{}']", #key_leaf, k);
                                    }
                                } else {
                                    let mut format_str = String::new();
                                    let mut format_args = Vec::new();
                                    for key_leaf in &child.key_leaves {
                                        format_str.push_str(&format!("[{key_leaf}='{{}}']"));
                                        let field_ident =
                                            format_ident!("{}", to_snake_case(key_leaf));
                                        format_args.push(quote! { k.#field_ident });
                                    }
                                    quote! {
                                        let key_bracket_str = format!(#format_str, #(#format_args),*);
                                    }
                                };
                                let key_bracket_construction_prev =
                                    key_bracket_construction.clone();

                                quote! {
                                    for (k, cur_val) in &self.#field_ident {
                                        #key_bracket_construction
                                        let entry_path = format!("{}{}", #child_path_str, key_bracket_str);
                                        if let Some(prev_val) = previous.#field_ident.get(k) {
                                            cur_val.diff_segments(prev_val, &entry_path, deltas)?;
                                        } else {
                                            cur_val.diff_segments(&Default::default(), &entry_path, deltas)?;
                                        }
                                    }
                                    for (k, _) in &previous.#field_ident {
                                        if !self.#field_ident.contains_key(k) {
                                            #key_bracket_construction_prev
                                            let entry_path = format!("{}{}", #child_path_str, key_bracket_str);
                                            deltas.push(ConfigDelta::Delete(YangPath::new(&entry_path).expect("valid path")));
                                        }
                                    }
                                }
                            }
                        }
                        SchemaNodeKind::LeafList => {
                            quote! {
                                if self.#field_ident != previous.#field_ident {
                                    let p = YangPath::new(#child_path_str).expect("valid path");
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

            impls.extend(quote! {
                impl #struct_name {
                    pub fn apply_patch_segments(
                        &mut self,
                        op: &ConfigOp,
                        segments: &[PathSegment],
                        value: Option<&str>,
                    ) -> Result<(), ConfigError> {
                        if segments.is_empty() {
                            match op {
                                ConfigOp::Delete | ConfigOp::Remove => {
                                    *self = Self::default();
                                    return Ok(());
                                }
                                ConfigOp::Replace => {
                                    if let Some(v) = value {
                                        *self = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
                                        return Ok(());
                                    } else {
                                        return Err(config_error("missing-value", "Value is required for replace"));
                                    }
                                }
                                ConfigOp::Update | ConfigOp::Merge => {
                                    if let Some(v) = value {
                                        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(v) {
                                            for (k, val) in map {
                                                let val_str = if val.is_string() {
                                                    val.as_str().unwrap().to_string()
                                                } else {
                                                    val.to_string()
                                                };
                                                let segs = parse_path(&k).map_err(|e| config_error("invalid-path", e))?;
                                                self.apply_patch_segments(op, &segs, Some(&val_str))?;
                                            }
                                            return Ok(());
                                        } else {
                                            *self = serde_json::from_str(v).map_err(|e| config_error("invalid-value", e.to_string()))?;
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
                                return Err(config_error("unsupported-path", format!("unsupported field: {}", cleaned_name)));
                            }
                        }
                        Ok(())
                    }

                    pub fn diff_segments(
                        &self,
                        previous: &Self,
                        _path_prefix: &str,
                        deltas: &mut Vec<ConfigDelta>,
                    ) -> Result<(), ConfigError> {
                        #diff_fields
                        Ok(())
                    }
                }
            });
        }
    }

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
        }

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
                                let mut v = current_key[eq_idx + 1..].trim()
                                    .trim_matches('\'')
                                    .trim_matches('"')
                                    .to_string();
                                v = v.replace("\\'", "'").replace("\\\"", "\"");
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
                };
                if !super::paths::is_valid_path(path.as_str()) {
                    return Err(config_error("invalid-path", format!("invalid path: {}", path)));
                }
                if !super::paths::is_config_path(path.as_str()) {
                    return Err(config_error("read-only", format!("cannot modify read-only path: {}", path)));
                }
            }

            // Clone and apply to verify transactions succeed before modifying target root
            let mut temp = root.clone();
            for delta in deltas {
                let (path, op, value) = match delta {
                    ConfigDelta::Update(p, v) => (p, ConfigOp::Update, Some(v.as_str())),
                    ConfigDelta::Replace(p, v) => (p, ConfigOp::Replace, Some(v.as_str())),
                    ConfigDelta::Delete(p) => (p, ConfigOp::Delete, None),
                    ConfigDelta::Merge(p, v) => (p, ConfigOp::Merge, Some(v.as_str())),
                    ConfigDelta::Remove(p) => (p, ConfigOp::Remove, None),
                };
                let segments = parse_path(path.as_str()).map_err(|e| config_error("invalid-path", e))?;
                if segments.is_empty() {
                    return Err(config_error("invalid-path", "Path is empty"));
                }
                temp.apply_patch_segments(&op, &segments[1..], value)?;
            }
            *root = temp;
            Ok(())
        }

        pub fn root_path() -> YangPath {
            YangPath::new(#root_path).expect("opc-yanggen emitted an invalid root YANG path")
        }

        #impls
    };

    Ok(tokens.to_string())
}
