pub mod gnmi_json;
pub mod gnmi_set;
pub mod metadata;
pub mod netconf_xml;
pub mod netconf_xml_edit;
pub mod patch;
pub mod paths;
pub mod redaction;
pub mod schema_registry;
pub mod serde;
pub mod types;
pub mod validate;

use crate::emit::{fnv1a64, schema_digest_from_canonical, CanonicalInput};
use crate::ir::{ConstraintBinding, SchemaNode, SchemaNodeKind, TypeRef};
use std::collections::{HashMap, HashSet};
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
    let input = normalize_for_rust_generation(input)?;
    let root = validate_supported_input(&input)?;
    let root_name = clean_segment(last_segment(&root.path));
    let root_type = to_pascal_case(root_name);
    let schema_digest = schema_digest_from_canonical(&input);
    let opc_config_schema_digest = schema_digest_hex_for_opc_config(&schema_digest);
    let mut files = HashMap::new();

    let mod_rs_content = r#"
pub mod types;
pub mod serde;
pub mod paths;
pub mod patch;
pub mod validate;
pub mod metadata;
pub mod gnmi_json;
pub mod gnmi_set;
pub mod netconf_xml;
pub mod netconf_xml_edit;
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
    files.insert("types.rs".to_string(), types::generate(&input)?);
    files.insert("serde.rs".to_string(), serde::generate(&input)?);
    files.insert("paths.rs".to_string(), paths::generate(&input)?);
    files.insert("patch.rs".to_string(), patch::generate(&input)?);
    files.insert("validate.rs".to_string(), validate::generate(&input)?);
    files.insert("metadata.rs".to_string(), metadata::generate(&input)?);
    files.insert("gnmi_json.rs".to_string(), gnmi_json::generate(&input)?);
    files.insert("gnmi_set.rs".to_string(), gnmi_set::generate(&input)?);
    files.insert("netconf_xml.rs".to_string(), netconf_xml::generate(&input)?);
    files.insert(
        "netconf_xml_edit.rs".to_string(),
        netconf_xml_edit::generate(&input)?,
    );
    files.insert("redaction.rs".to_string(), redaction::generate(&input)?);
    files.insert(
        "schema_registry.rs".to_string(),
        schema_registry::generate(&input)?,
    );

    Ok(files)
}

/// Returns the canonical input shape used by Rust artifacts.
///
/// Source ingestion can produce same-module descendants without repeated module
/// prefixes. Generated Rust artifacts use fully prefix-qualified schema-node
/// paths so schema metadata, gNMI, NETCONF, NACM, and audit attribution all
/// report one canonical path form.
pub fn normalize_for_rust_generation(
    input: &CanonicalInput,
) -> Result<CanonicalInput, RustGenerationError> {
    prefix_qualify_generated_paths(input)
}

fn schema_digest_hex_for_opc_config(registry_digest: &str) -> String {
    let mut out = String::with_capacity(64);
    for lane in 0..4 {
        let material = format!("opc-yanggen-opc-config-schema-digest-v1:{lane}:{registry_digest}");
        out.push_str(&format!("{:016x}", fnv1a64(material.as_bytes())));
    }
    out
}

fn prefix_qualify_generated_paths(
    input: &CanonicalInput,
) -> Result<CanonicalInput, RustGenerationError> {
    let module_prefixes: HashMap<&str, &str> = input
        .schema_modules
        .iter()
        .map(|module| (module.name.as_str(), module.prefix.as_str()))
        .collect();
    let node_modules: HashMap<&str, &str> = input
        .nodes
        .iter()
        .map(|node| (node.path.as_str(), node.module.as_str()))
        .collect();
    let mut path_map = HashMap::with_capacity(input.nodes.len());
    let mut qualified_paths = HashSet::with_capacity(input.nodes.len());

    for node in &input.nodes {
        let qualified =
            qualify_schema_path(&node.path, &node.module, &node_modules, &module_prefixes)?;
        if !qualified_paths.insert(qualified.clone()) {
            return Err(RustGenerationError::new(format!(
                "normalized generated schema path collision at {qualified}"
            )));
        }
        path_map.insert(node.path.clone(), qualified);
    }

    let mut normalized = input.clone();
    for node in &mut normalized.nodes {
        let original_path = node.path.clone();
        node.path = path_map
            .get(&original_path)
            .cloned()
            .ok_or_else(|| RustGenerationError::new("missing normalized schema path"))?;
        node.child_paths = node
            .child_paths
            .iter()
            .map(|child_path| {
                path_map.get(child_path).cloned().ok_or_else(|| {
                    RustGenerationError::new(format!(
                        "node {} references missing child {}",
                        original_path, child_path
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        node.child_paths.sort();
        if let Some(TypeRef::LeafRef { target_path }) = &mut node.type_ref {
            *target_path = qualify_referenced_path(
                target_path,
                &node.module,
                &path_map,
                &node_modules,
                &module_prefixes,
            )?;
        }
    }
    normalized
        .nodes
        .sort_by(|left, right| left.path.cmp(&right.path));

    for constraint in &mut normalized.constraints {
        qualify_constraint_target(constraint, &path_map, &node_modules, &module_prefixes)?;
    }
    normalized.constraints.sort_by(|left, right| {
        (&left.target_path, &left.expr, &left.source).cmp(&(
            &right.target_path,
            &right.expr,
            &right.source,
        ))
    });

    Ok(normalized)
}

fn qualify_constraint_target(
    constraint: &mut ConstraintBinding,
    path_map: &HashMap<String, String>,
    node_modules: &HashMap<&str, &str>,
    module_prefixes: &HashMap<&str, &str>,
) -> Result<(), RustGenerationError> {
    let owner_module = node_modules
        .get(constraint.target_path.as_str())
        .copied()
        .unwrap_or_default();
    constraint.target_path = qualify_referenced_path(
        &constraint.target_path,
        owner_module,
        path_map,
        node_modules,
        module_prefixes,
    )?;
    Ok(())
}

fn qualify_referenced_path(
    path: &str,
    fallback_module: &str,
    path_map: &HashMap<String, String>,
    node_modules: &HashMap<&str, &str>,
    module_prefixes: &HashMap<&str, &str>,
) -> Result<String, RustGenerationError> {
    if let Some(qualified) = path_map.get(path) {
        return Ok(qualified.clone());
    }
    qualify_schema_path(path, fallback_module, node_modules, module_prefixes)
}

fn qualify_schema_path(
    path: &str,
    fallback_module: &str,
    node_modules: &HashMap<&str, &str>,
    module_prefixes: &HashMap<&str, &str>,
) -> Result<String, RustGenerationError> {
    if !path.starts_with('/') {
        return Err(RustGenerationError::new(format!(
            "schema path {path} is not absolute"
        )));
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(RustGenerationError::new(format!(
            "schema path {path} contains an empty segment"
        )));
    }

    let mut out = String::with_capacity(path.len() + segments.len() * 8);
    let mut original_prefix = String::new();
    for segment in segments {
        original_prefix.push('/');
        original_prefix.push_str(segment);
        out.push('/');
        out.push_str(&qualify_segment(
            segment,
            &original_prefix,
            fallback_module,
            node_modules,
            module_prefixes,
        ));
    }
    Ok(out)
}

fn qualify_segment(
    segment: &str,
    original_prefix: &str,
    fallback_module: &str,
    node_modules: &HashMap<&str, &str>,
    module_prefixes: &HashMap<&str, &str>,
) -> String {
    let (name, suffix) = segment
        .split_once('[')
        .map_or((segment, ""), |(name, rest)| (name, rest));
    if name.contains(':') {
        return segment.to_string();
    }

    let module = node_modules
        .get(original_prefix)
        .copied()
        .unwrap_or(fallback_module);
    let prefix = module_prefix(module, module_prefixes);
    if suffix.is_empty() {
        format!("{prefix}:{name}")
    } else {
        format!("{prefix}:{name}[{suffix}")
    }
}

fn module_prefix<'a>(module: &'a str, module_prefixes: &HashMap<&str, &'a str>) -> &'a str {
    module_prefixes
        .get(module)
        .copied()
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or(module)
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
            if types::is_sensitive_node(node) {
                return Err(RustGenerationError::new(format!(
                    "container {} must not be classified as sensitive; classify sensitive leaves instead",
                    node.path
                )));
            }
        }
        SchemaNodeKind::Leaf => match &node.type_ref {
            Some(
                TypeRef::Boolean
                | TypeRef::String
                | TypeRef::Enumeration { .. }
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
        SchemaNodeKind::List => {
            if types::is_sensitive_node(node) {
                return Err(RustGenerationError::new(format!(
                    "list {} must not be classified as sensitive; classify sensitive leaves instead",
                    node.path
                )));
            }
        }
        SchemaNodeKind::LeafList => {}
        SchemaNodeKind::Choice | SchemaNodeKind::Case => {
            return Err(RustGenerationError::new(format!(
                "node {} has unsupported kind {:?}",
                node.path, node.kind
            )));
        }
    }

    if !node.numeric_range.is_empty() {
        if !matches!(
            node.type_ref.as_ref(),
            Some(TypeRef::Uint16 | TypeRef::Uint32 | TypeRef::Int64)
        ) {
            return Err(RustGenerationError::new(format!(
                "numeric range metadata at {} requires an integer leaf type",
                node.path
            )));
        }
        for interval in &node.numeric_range {
            if interval.min > interval.max {
                return Err(RustGenerationError::new(format!(
                    "numeric range metadata at {} has a lower bound greater than upper bound",
                    node.path
                )));
            }
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
