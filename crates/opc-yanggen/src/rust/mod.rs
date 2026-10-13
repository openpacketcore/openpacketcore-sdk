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
mod strings;
pub mod types;
pub mod validate;

use crate::emit::{fnv1a64, schema_digest_from_canonical, CanonicalInput};
use crate::ir::{ConstraintBinding, SchemaNode, SchemaNodeKind, TypeRef};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Schema lookup and the shared Rust type namespace for one emission pass.
struct NodeIndex<'a> {
    nodes: HashMap<String, &'a SchemaNode>,
    names: HashMap<String, String>,
    helpers: HashMap<String, String>,
    extended_integers: bool,
    expanded_profile: bool,
}

impl<'a> NodeIndex<'a> {
    fn new(nodes: &'a [SchemaNode]) -> Self {
        let mut structural: Vec<_> = nodes
            .iter()
            .filter(|node| matches!(node.kind, SchemaNodeKind::Container | SchemaNodeKind::List))
            .collect();
        structural.sort_by(|a, b| a.path.cmp(&b.path));
        let mut counts = HashMap::<String, usize>::new();
        for node in &structural {
            *counts
                .entry(to_pascal_case(clean_segment(last_segment(&node.path))))
                .or_default() += 1;
        }
        let extended_integers = nodes.iter().any(|node| {
            matches!(
                node.type_ref,
                Some(
                    TypeRef::Uint8
                        | TypeRef::Uint64
                        | TypeRef::Int8
                        | TypeRef::Int16
                        | TypeRef::Int32
                )
            )
        });
        let reserved: Vec<_> = [
            "LeafPresence",
            "SecretLeaf",
            "SensitiveKey",
            "RedactedKeyFieldDebug",
            "YangInt64",
            "YangUint64",
            "YangDecimal64",
            "YangEmpty",
            "String",
            "Vec",
            "Option",
            "Result",
            "Serialize",
            "Deserialize",
            "Default",
            "Box",
            "From",
            "IntoIterator",
            "ConfigError",
            "YangPath",
            "ConfigOp",
            "ConfigDelta",
            "PathSegment",
            "ValidationError",
            "ValidationContext",
            "Redactable",
            "DeterministicHash",
            "EditConfigNode",
            "EditOperation",
            "NetconfEditError",
            "NetconfXmlEditApplicator",
            "NodeKind",
            "GeneratedNetconfXmlEditApplicator",
        ]
        .into_iter()
        .filter(|name| *name != "YangUint64" || extended_integers)
        .collect();
        // Keep natural names available even when another node's parent-qualified
        // name or composite-key companion would otherwise claim them.
        let mut used: HashSet<String> = counts.keys().cloned().collect();
        used.extend(reserved.iter().map(|name| (*name).to_string()));
        let mut names = HashMap::new();
        let has_key =
            |node: &SchemaNode| node.kind == SchemaNodeKind::List && node.key_leaves.len() > 1;
        for node in &structural {
            let name = to_pascal_case(clean_segment(last_segment(&node.path)));
            if counts[&name] == 1
                && !reserved.contains(&name.as_str())
                && (!has_key(node) || !used.contains(&format!("{name}Key")))
            {
                if has_key(node) {
                    used.insert(format!("{name}Key"));
                }
                names.insert(node.path.clone(), name);
            }
        }
        for node in structural {
            if names.contains_key(&node.path) {
                continue;
            }
            let parts: Vec<_> = node
                .path
                .split('/')
                .filter(|part| !part.is_empty())
                .map(clean_segment)
                .map(to_pascal_case)
                .collect();
            let available = |name: &str| {
                !used.contains(name) && (!has_key(node) || !used.contains(&format!("{name}Key")))
            };
            let mut name = (2..=parts.len())
                .map(|depth| parts[parts.len() - depth..].concat())
                .find(|name| available(name));
            if name.is_none() {
                let base = parts.concat();
                name = (2..)
                    .map(|suffix| format!("{base}{suffix}"))
                    .find(|name| available(name));
            }
            if let Some(name) = name {
                used.insert(name.clone());
                if has_key(node) {
                    used.insert(format!("{name}Key"));
                }
                names.insert(node.path.clone(), name);
            }
        }
        let expanded_profile = extended_integers
            || nodes
                .iter()
                .any(|node| matches!(node.type_ref, Some(TypeRef::RestrictedString { .. })))
            || names
                .iter()
                .any(|(path, name)| *name != to_pascal_case(clean_segment(last_segment(path))));
        let mut paths: Vec<_> = nodes.iter().map(|node| &node.path).collect();
        paths.sort();
        let natural: Vec<_> = paths
            .iter()
            .map(|path| {
                path.split('/')
                    .filter(|s| !s.is_empty())
                    .map(clean_segment)
                    .map(|s| {
                        let name = to_snake_case(s);
                        if expanded_profile {
                            name.split('_')
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                                .join("_")
                        } else {
                            name
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("_")
            })
            .collect();
        let mut helper_counts = HashMap::new();
        for name in &natural {
            *helper_counts.entry(name.clone()).or_insert(0) += 1;
        }
        let mut used_helpers: HashSet<_> = natural.iter().cloned().collect();
        let list_paths: HashSet<_> = nodes
            .iter()
            .filter(|node| node.kind == SchemaNodeKind::List)
            .map(|node| node.path.as_str())
            .collect();
        for (path, name) in paths.iter().zip(&natural) {
            if list_paths.contains(path.as_str()) {
                *helper_counts.entry(format!("{name}_entry")).or_insert(0) += 1;
                used_helpers.insert(format!("{name}_entry"));
            }
        }
        let helpers = paths
            .into_iter()
            .zip(natural)
            .map(|(path, mut name)| {
                if helper_counts[&name] > 1
                    || helper_counts
                        .get(&format!("{name}_entry"))
                        .is_some_and(|count| *count > 1)
                {
                    let base = name.clone();
                    for suffix in 2.. {
                        let candidate = format!("{base}_{suffix}");
                        if !used_helpers.contains(&candidate)
                            && !used_helpers.contains(&format!("{candidate}_entry"))
                        {
                            name = candidate;
                            break;
                        }
                    }
                    used_helpers.insert(name.clone());
                    used_helpers.insert(format!("{name}_entry"));
                }
                (path.clone(), name)
            })
            .collect();
        Self {
            expanded_profile,
            nodes: nodes.iter().map(|node| (node.path.clone(), node)).collect(),
            names,
            helpers,
            extended_integers,
        }
    }

    fn get(&self, path: &str) -> Option<&&'a SchemaNode> {
        self.nodes.get(path)
    }

    fn type_name(&self, node: &SchemaNode) -> &str {
        &self.names[&node.path]
    }

    fn helper_name(&self, path: &str) -> &str {
        &self.helpers[path]
    }

    fn legacy_or_resolved(&self, node: &'a SchemaNode) -> &'a SchemaNode {
        if self.expanded_profile {
            return self.scalar_node(node);
        }
        if let Some(TypeRef::LeafRef { target_path }) = &node.type_ref {
            if let Some(target) = self.get(target_path) {
                return target;
            }
        }
        node
    }

    fn patch_scalar_node(&self, node: &'a SchemaNode) -> &'a SchemaNode {
        if self.expanded_profile {
            self.scalar_node(node)
        } else {
            node
        }
    }

    fn scalar_node(&self, node: &'a SchemaNode) -> &'a SchemaNode {
        let mut current = node;
        let mut visited = HashSet::new();
        while let Some(TypeRef::LeafRef { target_path }) = &current.type_ref {
            if !visited.insert(current.path.as_str()) {
                break;
            }
            match self.get(target_path) {
                Some(target) => current = target,
                None => break,
            }
        }
        current
    }
}

fn has_extended_integers(input: &CanonicalInput) -> bool {
    input.nodes.iter().any(|node| {
        matches!(
            node.type_ref,
            Some(
                TypeRef::Uint8 | TypeRef::Uint64 | TypeRef::Int8 | TypeRef::Int16 | TypeRef::Int32
            )
        )
    })
}

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

/// RFC 7950 ignores `ordered-by` on state data.
fn is_user_ordered(node: &SchemaNode) -> bool {
    node.config && node.ordered_by.as_deref() == Some("user")
}

fn has_user_ordered_collections(input: &CanonicalInput) -> bool {
    input.nodes.iter().any(|node| {
        is_user_ordered(node)
            && (node.kind == SchemaNodeKind::LeafList
                || (node.kind == SchemaNodeKind::List && !node.key_leaves.is_empty()))
    })
}

pub fn generate_rust(
    input: &CanonicalInput,
) -> Result<HashMap<String, String>, RustGenerationError> {
    let input = normalize_for_rust_generation(input)?;
    let root = validate_supported_input(&input)?;
    strings::validate_schema(&input)?;
    let nodes_by_path = NodeIndex::new(&input.nodes);
    let root_type = nodes_by_path.type_name(root);
    let schema_digest = schema_digest_from_canonical(&input);
    let opc_config_schema_digest = schema_digest_hex_for_opc_config(&schema_digest);
    let mut files = HashMap::new();
    let ordered_replacement_changed_path = if input.nodes.iter().any(|node| {
        node.kind == SchemaNodeKind::List && is_user_ordered(node) && !node.key_leaves.is_empty()
    }) {
        "                patch::ConfigDelta::ReplaceOrderedList(p, _) => paths.push(p.clone()),\n"
    } else {
        ""
    };

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
__ORDERED_REPLACEMENT_CHANGED_PATH__            }
        }
        paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        paths.dedup();
        Ok(paths)
    }

    fn admission_payload_size_bytes(&self) -> Result<Option<usize>, ConfigError> {
        serde_json::to_vec(self)
            .map(|bytes| Some(bytes.len()))
            .map_err(|_| {
                ConfigError::new(
                    "admission-payload-size",
                    "failed to serialize config for admission payload size",
                )
            })
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
    .replace("__ROOT_TYPE__", root_type)
    .replace("__OPC_CONFIG_SCHEMA_DIGEST__", &opc_config_schema_digest)
    .replace(
        "__ORDERED_REPLACEMENT_CHANGED_PATH__",
        ordered_replacement_changed_path,
    );

    let mod_rs_content = if strings::has_constraints(&input) {
        files.insert("strings.rs".to_string(), strings::generate(&input)?);
        mod_rs_content.replacen("pub mod types;", "pub mod types;\npub mod strings;", 1)
    } else {
        mod_rs_content
    };
    let mod_rs_content = if nodes_by_path.expanded_profile
        && input.nodes.iter().any(|node| {
            clean_segment(last_segment(&node.path))
                .chars()
                .any(char::is_uppercase)
        }) {
        // Rust fields retain YANG's case-sensitive identifiers, including a/A.
        format!("// Preserve case-sensitive YANG field names.\n#![allow(non_snake_case)]\n{mod_rs_content}")
    } else {
        mod_rs_content
    };
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

    let nodes = NodeIndex::new(&input.nodes);
    for node in &input.nodes {
        validate_supported_node(input, node)?;
        validate_integer_default(node, &nodes)?;
    }
    validate_rust_identifier_collisions(input)?;

    Ok(root)
}

fn validate_integer_default(
    node: &SchemaNode,
    nodes: &NodeIndex<'_>,
) -> Result<(), RustGenerationError> {
    let Some(default) = &node.default else {
        return Ok(());
    };
    let scalar = nodes.scalar_node(node);
    let Some((min, max)) = scalar.type_ref.as_ref().and_then(TypeRef::integer_bounds) else {
        return Ok(());
    };
    if parse_integer_default(default).is_some_and(|value| {
        (min..=max).contains(&value)
            && (scalar.numeric_range.is_empty()
                || scalar
                    .numeric_range
                    .iter()
                    .any(|range| (range.min..=range.max).contains(&value)))
    }) {
        Ok(())
    } else {
        Err(RustGenerationError::new(format!(
            "integer default at {} is invalid or outside its type or declared range",
            node.path,
        )))
    }
}

// RFC 7950 section 9.2.1 permits decimal, octal, and hexadecimal defaults.
// This is schema syntax only; protocol values retain their decimal codecs.
fn parse_integer_default(text: &str) -> Option<i128> {
    let (negative, digits) = if let Some(digits) = text.strip_prefix('-') {
        (true, digits)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    let (digits, radix) = if let Some(digits) = digits.strip_prefix("0x") {
        (digits, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (&digits[1..], 8)
    } else {
        (digits, 10)
    };
    if digits.is_empty() || !digits.chars().all(|ch| ch.is_digit(radix)) {
        return None;
    }
    let value = i128::from_str_radix(digits, radix).ok()?;
    Some(if negative { -value } else { value })
}

fn validate_rust_identifier_collisions(input: &CanonicalInput) -> Result<(), RustGenerationError> {
    let nodes_by_path: HashMap<&str, &SchemaNode> = input
        .nodes
        .iter()
        .map(|node| (node.path.as_str(), node))
        .collect();

    for node in &input.nodes {
        if matches!(node.kind, SchemaNodeKind::Container | SchemaNodeKind::List) {
            let mut field_idents: HashMap<String, &str> = HashMap::new();
            for child_path in &node.child_paths {
                let Some(child) = nodes_by_path.get(child_path.as_str()) else {
                    continue;
                };
                let local = clean_segment(last_segment(&child.path));
                let ident = to_snake_case(local);
                if let Some(existing) = field_idents.insert(ident.clone(), child.path.as_str()) {
                    if existing != child.path {
                        return Err(RustGenerationError::new(format!(
                            "normalized generated Rust identifier collision under {}: {} and {} both map to {ident}",
                            node.path, existing, child.path
                        )));
                    }
                }
            }

            let mut key_idents: HashMap<String, &str> = HashMap::new();
            for key in &node.key_leaves {
                let ident = to_snake_case(key);
                if let Some(existing) = key_idents.insert(ident.clone(), key.as_str()) {
                    if existing != key {
                        return Err(RustGenerationError::new(format!(
                            "normalized generated Rust identifier collision in keys for {}: {} and {} both map to {ident}",
                            node.path, existing, key
                        )));
                    }
                }
            }
        }
    }

    Ok(())
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
                | TypeRef::RestrictedString { .. }
                | TypeRef::Enumeration { .. }
                | TypeRef::Uint8
                | TypeRef::Uint64
                | TypeRef::Int8
                | TypeRef::Int16
                | TypeRef::Int32
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
        let (base_min, base_max) = node
            .type_ref
            .as_ref()
            .and_then(TypeRef::integer_bounds)
            .ok_or_else(|| {
                RustGenerationError::new(format!(
                    "numeric range metadata at {} requires an integer leaf type",
                    node.path,
                ))
            })?;
        for interval in &node.numeric_range {
            if interval.min > interval.max {
                return Err(RustGenerationError::new(format!(
                    "numeric range metadata at {} has a lower bound greater than upper bound",
                    node.path
                )));
            }
            if interval.min < base_min || interval.max > base_max {
                return Err(RustGenerationError::new(format!(
                    "numeric range metadata at {} exceeds the base integer type bounds",
                    node.path,
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
    if is_rust_keyword(&out) {
        out.push('_');
    }
    out
}

pub fn to_snake_case(s: &str) -> String {
    let mut out = s.replace(['-', ':'], "_");
    if is_rust_keyword(&out) {
        out.push('_');
    }
    out
}

fn is_rust_keyword(ident: &str) -> bool {
    matches!(
        ident,
        "Self"
            | "abstract"
            | "as"
            | "async"
            | "await"
            | "become"
            | "box"
            | "break"
            | "const"
            | "continue"
            | "crate"
            | "do"
            | "dyn"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "final"
            | "fn"
            | "for"
            | "gen"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "macro"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "override"
            | "priv"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "try"
            | "type"
            | "typeof"
            | "union"
            | "unsafe"
            | "unsized"
            | "use"
            | "virtual"
            | "where"
            | "while"
            | "yield"
    )
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

#[cfg(test)]
mod scalar_resolution_tests {
    use super::*;

    #[test]
    fn cyclic_leafrefs_terminate_without_losing_the_declared_node() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for targets in [["/t:a", "/t:b"], ["/t:b", "/t:a"]] {
                let nodes = ["/t:a", "/t:b"]
                    .into_iter()
                    .zip(targets)
                    .map(|(path, target)| SchemaNode {
                        path: path.into(),
                        kind: SchemaNodeKind::Leaf,
                        type_ref: Some(TypeRef::LeafRef {
                            target_path: target.into(),
                        }),
                        ..Default::default()
                    })
                    .collect::<Vec<_>>();
                let index = NodeIndex::new(&nodes);
                for node in &nodes {
                    assert_eq!(index.scalar_node(node).path, node.path);
                }
            }
            sender.send(()).unwrap();
        });
        // A removed cycle guard must fail this test instead of hanging the
        // test process. The worker owns only these synthetic schema nodes.
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
    }
}
