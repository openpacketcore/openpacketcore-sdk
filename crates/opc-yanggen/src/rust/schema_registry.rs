//! Generates the runtime `opc_mgmt_schema::SchemaRegistry` projection.
//!
//! This emits a `schema_registry` module into the generated crate containing a
//! zero-field `GeneratedSchemaRegistry` that implements
//! `opc_mgmt_schema::SchemaRegistry` over `&'static` tables built from the
//! canonical `CanonicalInput`. It is the single runtime view of the schema the
//! gNMI/NETCONF servers query — module identity, the path tree, config/state
//! classification, list key order, leaf types, redaction data classes, NACM
//! actions (derived in `opc-mgmt-schema`), gNMI origins, and defaults — derived
//! from the same canonical source as validation and serialization (no side
//! schema).
//!
//! Fail-closed at generation: `TypeRef` -> `LeafType` is an exhaustive match;
//! `Choice`/`Case` and an unknown `data_class` string are refused (the latter is
//! stricter than `metadata.rs`, which silently defaults to `Public` — the
//! registry must never under-redact a secret); and a list `key` that is not a
//! declared child leaf is refused so runtime keyed-path validation always has a
//! resolvable key. (`generate` runs after `validate_supported_input`, so root /
//! Choice/Case / untyped-leaf / dangling-child inputs are already rejected.)

use super::{clean_segment, last_segment, RustGenerationError};
use crate::emit::{schema_digest_from_canonical, CanonicalInput};
use crate::ir::{SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::quote;
use std::collections::HashMap;

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut nodes_by_path = HashMap::new();
    for node in &input.nodes {
        nodes_by_path.insert(node.path.clone(), node);
    }

    // Generation-time integrity gate: every list key must resolve to a declared
    // child leaf, so the runtime missing-key check always has a resolvable key.
    for node in &input.nodes {
        if node.kind == SchemaNodeKind::List {
            for key in &node.key_leaves {
                let key_bare = clean_segment(key);
                let is_child_leaf = node.child_paths.iter().any(|cp| {
                    nodes_by_path.get(cp).is_some_and(|c| {
                        c.kind == SchemaNodeKind::Leaf
                            && clean_segment(last_segment(&c.path)) == key_bare
                    })
                });
                if !is_child_leaf {
                    return Err(RustGenerationError::new(format!(
                        "schema_registry: list {} key '{}' is not a declared child leaf",
                        node.path, key
                    )));
                }
            }
        }
    }

    // One NodeMeta literal per node, sorted by path. `to_canonical` sorts nodes,
    // but `generate_rust` may be called with a `CanonicalInput` built directly
    // from `compile()` output (declaration order), so we sort here to make the
    // emitted NODES table deterministic and to uphold the registry's sortedness
    // invariant (`SchemaRegistry::self_check`) regardless of caller input order.
    let mut sorted_nodes: Vec<&SchemaNode> = input.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| a.path.cmp(&b.path));
    let mut node_inits = Vec::with_capacity(sorted_nodes.len());
    for node in sorted_nodes {
        node_inits.push(node_meta_tokens(node)?);
    }

    // Served models -> ModelData literals.
    let model_inits: Vec<TokenStream> = input
        .schema_modules
        .iter()
        .map(|m| {
            let (name, revision, namespace, prefix) =
                (&m.name, &m.revision, &m.namespace, &m.prefix);
            quote! {
                opc_mgmt_schema::ModelData {
                    name: #name,
                    revision: #revision,
                    namespace: #namespace,
                    prefix: #prefix,
                }
            }
        })
        .collect();

    // gNMI origins: each served module is its own origin; the default origin ""
    // spans every served module. Unknown origins resolve to None at runtime
    // (fail closed). This is a pure projection of schema_modules, so it cannot
    // drift from the served-model list.
    let mut module_names: Vec<&str> = input
        .schema_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    module_names.sort_unstable();
    module_names.dedup();
    let mut origin_inits: Vec<TokenStream> = Vec::with_capacity(module_names.len() + 1);
    origin_inits.push(quote! {
        opc_mgmt_schema::OriginEntry { origin: "", modules: &[ #(#module_names),* ] }
    });
    for name in &module_names {
        origin_inits.push(quote! {
            opc_mgmt_schema::OriginEntry { origin: #name, modules: &[ #name ] }
        });
    }

    let digest = schema_digest_from_canonical(input);

    let tokens = quote! {
        // `LeafType` is intentionally not imported: it is referenced fully
        // qualified in leaf-type tokens so a schema with no typed leaves does not
        // leave an unused import (the generated crate compiles with -Dwarnings).
        use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};

        static NODES: &[NodeMeta] = &[ #(#node_inits),* ];
        static MODELS: &[ModelData] = &[ #(#model_inits),* ];
        static ORIGINS: &[OriginEntry] = &[ #(#origin_inits),* ];
        const DIGEST: &str = #digest;

        /// The generated, const-constructible schema registry for this model.
        pub struct GeneratedSchemaRegistry;

        static REGISTRY: GeneratedSchemaRegistry = GeneratedSchemaRegistry;

        impl SchemaRegistry for GeneratedSchemaRegistry {
            fn schema_digest(&self) -> &'static str {
                DIGEST
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

        /// Returns the runtime schema registry for this generated model.
        pub fn registry() -> &'static dyn SchemaRegistry {
            &REGISTRY
        }
    };

    Ok(tokens.to_string())
}

fn node_meta_tokens(node: &SchemaNode) -> Result<TokenStream, RustGenerationError> {
    let path = &node.path;
    let module = &node.module;
    let config = node.config;
    let presence = node.presence.is_some();
    let has_default = node.default.is_some();

    let kind_tok = match node.kind {
        SchemaNodeKind::Container => quote! { NodeKind::Container },
        SchemaNodeKind::List => quote! { NodeKind::List },
        SchemaNodeKind::Leaf => quote! { NodeKind::Leaf },
        SchemaNodeKind::LeafList => quote! { NodeKind::LeafList },
        // Unreachable in practice (validate_supported_input rejects these first);
        // kept as defense-in-depth so the registry never labels an unsupported kind.
        SchemaNodeKind::Choice | SchemaNodeKind::Case => {
            return Err(RustGenerationError::new(format!(
                "schema_registry: unsupported node kind {:?} at {}",
                node.kind, node.path
            )));
        }
    };

    let leaf_type_tok = match &node.type_ref {
        Some(t) => {
            let lt = leaf_type_tokens(t);
            quote! { Some(#lt) }
        }
        None => quote! { None },
    };

    let data_class_tok = data_class_tokens(node)?;

    let default_tok = match &node.default {
        Some(d) => quote! { Some(#d) },
        None => quote! { None },
    };

    // Key order is load-bearing: emit verbatim, never sorted.
    let key_leaves: Vec<&String> = node.key_leaves.iter().collect();
    // Child paths are sorted for deterministic output (independent of whether the
    // caller's CanonicalInput came through to_canonical, which also sorts them).
    let mut child_paths: Vec<&String> = node.child_paths.iter().collect();
    child_paths.sort();

    Ok(quote! {
        NodeMeta {
            path: #path,
            module: #module,
            kind: #kind_tok,
            config: #config,
            leaf_type: #leaf_type_tok,
            key_leaves: &[ #(#key_leaves),* ],
            data_class: #data_class_tok,
            default: #default_tok,
            has_default: #has_default,
            presence: #presence,
            child_paths: &[ #(#child_paths),* ],
        }
    })
}

fn leaf_type_tokens(t: &TypeRef) -> TokenStream {
    match t {
        TypeRef::Boolean => quote! { opc_mgmt_schema::LeafType::Boolean },
        TypeRef::String => quote! { opc_mgmt_schema::LeafType::String },
        TypeRef::Uint16 => quote! { opc_mgmt_schema::LeafType::Uint16 },
        TypeRef::Uint32 => quote! { opc_mgmt_schema::LeafType::Uint32 },
        TypeRef::Int64 => quote! { opc_mgmt_schema::LeafType::Int64 },
        TypeRef::Decimal64 => quote! { opc_mgmt_schema::LeafType::Decimal64 },
        TypeRef::Empty => quote! { opc_mgmt_schema::LeafType::Empty },
        TypeRef::IdentityRef { base } => {
            quote! { opc_mgmt_schema::LeafType::IdentityRef { base: #base } }
        }
        TypeRef::LeafRef { target_path } => {
            quote! { opc_mgmt_schema::LeafType::LeafRef { target_path: #target_path } }
        }
        TypeRef::Custom { name } => quote! { opc_mgmt_schema::LeafType::Custom { name: #name } },
    }
}

/// Maps the node's data class to a `DataClass` token. Mirrors
/// `metadata.rs::map_data_class` for the known kebab-case classes and the
/// name-heuristic fallback, but is **fail-closed**: an unknown non-empty
/// `data_class` string is a generation error rather than a silent `Public`
/// (which would under-redact a sensitive node).
fn data_class_tokens(node: &SchemaNode) -> Result<TokenStream, RustGenerationError> {
    if let Some(dc) = &node.data_class {
        Ok(match dc.as_str() {
            "public" => quote! { DataClass::Public },
            "operational" => quote! { DataClass::Operational },
            "network-sensitive" => quote! { DataClass::NetworkSensitive },
            "subscriber-id" => quote! { DataClass::SubscriberId },
            "subscriber-session" => quote! { DataClass::SubscriberSession },
            "security-secret" => quote! { DataClass::SecuritySecret },
            "charging-record" => quote! { DataClass::ChargingRecord },
            "lawful-intercept" => quote! { DataClass::LawfulIntercept },
            "analytics-sensitive" => quote! { DataClass::AnalyticsSensitive },
            "audit-regulated" => quote! { DataClass::AuditRegulated },
            other => {
                return Err(RustGenerationError::new(format!(
                    "schema_registry: unknown data_class '{}' at {}",
                    other, node.path
                )));
            }
        })
    } else if super::is_sensitive_name(clean_segment(last_segment(&node.path))) {
        Ok(quote! { DataClass::SecuritySecret })
    } else {
        Ok(quote! { DataClass::Public })
    }
}
