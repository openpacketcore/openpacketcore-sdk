pub mod metadata;
pub mod netconf_xml;
pub mod patch;
pub mod paths;
pub mod redaction;
pub mod schema_registry;
pub mod serde;
pub mod types;
pub mod validate;

use crate::emit::{fnv1a64, schema_digest_from_canonical, CanonicalInput};
use crate::ir::{SchemaNode, SchemaNodeKind, TypeRef};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustGenerationError {
    message: String,
}

impl RustGenerationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RustGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RustGenerationError {}

pub fn generate_rust(
    input: &CanonicalInput,
) -> Result<HashMap<String, String>, RustGenerationError> {
    let root = validate_supported_input(input)?;
    let root_name = clean_segment(last_segment(&root.path));
    let root_type = to_pascal_case(root_name);
    let schema_digest = schema_digest_from_canonical(input);
    let opc_config_schema_digest = schema_digest_hex_for_opc_config(&schema_digest);
    let mut files = HashMap::new();

    let mod_rs_content = r#"
pub mod types;
pub mod serde;
pub mod paths;
pub mod patch;
pub mod validate;
pub mod metadata;
pub mod netconf_xml;
pub mod redaction;
pub mod schema_registry;

use opc_config_model::{OpcConfig, ConfigError, YangPath, ValidationError, ValidationContext};
use opc_types::SchemaDigest;
use std::str::FromStr;

impl OpcConfig for types::__ROOT_TYPE__ {
    type Delta = patch::ConfigDelta;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("__OPC_CONFIG_SCHEMA_DIGEST__")
            .expect("opc-yanggen emitted an invalid schema digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        patch::diff_root(self, previous)
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        let mut paths = Vec::new();
        for delta in deltas {
            match delta {
                patch::ConfigDelta::Replace(p, _) => paths.push(p.clone()),
                patch::ConfigDelta::Update(p, _) => paths.push(p.clone()),
                patch::ConfigDelta::Delete(p) => paths.push(p.clone()),
                patch::ConfigDelta::Merge(p, _) => paths.push(p.clone()),
                patch::ConfigDelta::Remove(p) => paths.push(p.clone()),
            }
        }
        paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        paths.dedup();
        Ok(paths)
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        patch::apply_patch(self, &[delta])
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        validate::validate_syntax(self)
    }

    fn validate_semantics(&self, ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        validate::validate_semantics(self, ctx)
    }
}
"#
    .replace("__ROOT_TYPE__", &root_type)
    .replace("__OPC_CONFIG_SCHEMA_DIGEST__", &opc_config_schema_digest);

    files.insert("mod.rs".to_string(), mod_rs_content);
    files.insert("types.rs".to_string(), types::generate(input)?);
    files.insert("serde.rs".to_string(), serde::generate(input)?);
    files.insert("paths.rs".to_string(), paths::generate(input)?);
    files.insert("patch.rs".to_string(), patch::generate(input)?);
    files.insert("validate.rs".to_string(), validate::generate(input)?);
    files.insert("metadata.rs".to_string(), metadata::generate(input)?);
    files.insert("netconf_xml.rs".to_string(), netconf_xml::generate(input)?);
    files.insert("redaction.rs".to_string(), redaction::generate(input)?);
    files.insert(
        "schema_registry.rs".to_string(),
        schema_registry::generate(input)?,
    );

    Ok(files)
}

fn schema_digest_hex_for_opc_config(registry_digest: &str) -> String {
    let mut out = String::with_capacity(64);
    for lane in 0..4 {
        let material = format!("opc-yanggen-opc-config-schema-digest-v1:{lane}:{registry_digest}");
        out.push_str(&format!("{:016x}", fnv1a64(material.as_bytes())));
    }
    out
}

fn validate_supported_input(input: &CanonicalInput) -> Result<&SchemaNode, RustGenerationError> {
    if input.nodes.is_empty() {
        return Err(RustGenerationError::new(
            "cannot generate Rust model for an empty YANG schema",
        ));
    }
    if input.canonicalization_skipped {
        return Err(RustGenerationError::new(
            "cannot generate Rust model when constraint canonicalization was skipped",
        ));
    }

    let root_nodes: Vec<&SchemaNode> = input
        .nodes
        .iter()
        .filter(|node| is_root_path(&node.path))
        .collect();
    if root_nodes.len() != 1 {
        return Err(RustGenerationError::new(format!(
            "expected exactly one root container, found {}",
            root_nodes.len()
        )));
    }
    let root = root_nodes[0];
    if root.kind != SchemaNodeKind::Container {
        return Err(RustGenerationError::new(format!(
            "root node {} must be a container",
            root.path
        )));
    }

    for node in &input.nodes {
        validate_supported_node(input, node)?;
    }

    Ok(root)
}

fn validate_supported_node(
    input: &CanonicalInput,
    node: &SchemaNode,
) -> Result<(), RustGenerationError> {
    if !node.path.starts_with('/') {
        return Err(RustGenerationError::new(format!(
            "node path {} is not absolute",
            node.path
        )));
    }

    match node.kind {
        SchemaNodeKind::Container => {
            if node.type_ref.is_some() {
                return Err(RustGenerationError::new(format!(
                    "container {} must not carry a type",
                    node.path
                )));
            }
        }
        SchemaNodeKind::Leaf => match &node.type_ref {
            Some(
                TypeRef::Boolean
                | TypeRef::String
                | TypeRef::Uint16
                | TypeRef::Uint32
                | TypeRef::Int64
                | TypeRef::Decimal64
                | TypeRef::Empty
                | TypeRef::IdentityRef { .. }
                | TypeRef::LeafRef { .. }
                | TypeRef::Custom { .. },
            ) => {}
            None => {
                return Err(RustGenerationError::new(format!(
                    "leaf {} has no type",
                    node.path
                )));
            }
        },
        SchemaNodeKind::List | SchemaNodeKind::LeafList => {}
        SchemaNodeKind::Choice | SchemaNodeKind::Case => {
            return Err(RustGenerationError::new(format!(
                "node {} has unsupported kind {:?}",
                node.path, node.kind
            )));
        }
    }

    for child_path in &node.child_paths {
        if !input.nodes.iter().any(|child| &child.path == child_path) {
            return Err(RustGenerationError::new(format!(
                "node {} references missing child {}",
                node.path, child_path
            )));
        }
    }

    Ok(())
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

pub fn to_pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for c in s.chars() {
        if c == '-' || c == '_' || c == ':' {
            capitalize = true;
        } else if capitalize {
            out.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(c);
        }
    }
    out
}

pub fn to_snake_case(s: &str) -> String {
    s.replace(['-', ':'], "_")
}

pub fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn clean_segment(seg: &str) -> &str {
    if let Some(idx) = seg.find(':') {
        &seg[idx + 1..]
    } else {
        seg
    }
}

pub fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("secret")
        || name.contains("password")
        || name.contains("token")
        || name.contains("credential")
        || name.contains("private-key")
}
