//! Source YANG ingestion and source/IR consistency checks.
//!
//! This module intentionally validates the YANG subset represented by the
//! current `GenerationInput` IR. Constraint-bearing constructs that would be
//! lost by the current IR are rejected with
//! `DiagnosticCode::UnsupportedYangFeature` rather than silently ignored.

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::{Diagnostic, DiagnosticCode, YangSourceLocation};
use crate::emit::{fnv1a64, schema_digest, GenerationInput};
use crate::ir::{
    EnumValue, LockedModule, ModuleConformance, ModuleImport, ModuleLockfile, SchemaModule,
    SchemaNode, SchemaNodeKind, StackBudget, TypeRef,
};

/// In-memory YANG source module used by ingestion and consistency validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangSource {
    /// File name used in diagnostics and in emitted `YangSourceLocation`s.
    pub file_name: String,
    /// Raw source text. The text is preserved in generated `SchemaModule`
    /// values for NETCONF `<get-schema>` and discovery metadata.
    pub text: String,
}

impl YangSource {
    /// Creates a source module from a file name and raw YANG text.
    #[must_use]
    pub fn new(file_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            file_name: file_name.into(),
            text: text.into(),
        }
    }
}

/// Parses source YANG modules into a `GenerationInput` for the current
/// supported IR subset.
///
/// The resulting input includes all parsed source text on `SchemaModule` so
/// downstream NETCONF `<get-schema>` and discovery metadata can be served from
/// the same source artifact used for code generation.
///
/// # Errors
///
/// Returns a `Diagnostic` when the source is syntactically invalid, does not
/// contain exactly one module per source file, or uses a YANG construct not
/// represented by the current IR subset.
pub fn generation_input_from_yang_sources(
    profile: impl Into<String>,
    sources: &[YangSource],
) -> Result<GenerationInput, Diagnostic> {
    let parsed = parse_yang_sources(sources)?;
    Ok(parsed.into_generation_input(profile.into()))
}

/// Validates that `input` matches the supplied source YANG modules.
///
/// This checks module metadata, preserved source text, imports, node paths,
/// child relationships, list keys, config/state flags, type references,
/// defaults, presence markers, ordered-by, data classes, unique constraints,
/// and the schema digest implied by those source-derived fields.
///
/// # Errors
///
/// Returns a `Diagnostic` when the source cannot be parsed, contains an
/// unsupported construct, or does not match `input`.
pub fn validate_generation_input_yang_sources(
    input: &GenerationInput,
    sources: &[YangSource],
) -> Result<(), Diagnostic> {
    let parsed = parse_yang_sources(sources)?;
    validate_against_parsed_sources(input, &parsed)
}

/// Validates `input` against the `source_text` embedded in its schema modules.
///
/// # Errors
///
/// Returns a `Diagnostic` when any schema module is missing source text or
/// when the embedded sources do not match the rest of `input`.
pub fn validate_generation_input_embedded_yang_sources(
    input: &GenerationInput,
) -> Result<(), Diagnostic> {
    let mut sources = Vec::with_capacity(input.schema_modules.len());
    for module in &input.schema_modules {
        let Some(source_text) = module.source_text.clone() else {
            return Err(mismatch(
                &module.source,
                format!("schema module `{}` is missing source_text", module.name),
            ));
        };
        sources.push(YangSource::new(module.source.file.clone(), source_text));
    }
    validate_generation_input_yang_sources(input, &sources)
}

#[derive(Debug, Clone)]
struct ParsedYang {
    modules: Vec<SchemaModule>,
    nodes: Vec<SchemaNode>,
}

impl ParsedYang {
    fn into_generation_input(self, profile: String) -> GenerationInput {
        let modules = self
            .modules
            .iter()
            .map(|module| LockedModule {
                name: module.name.clone(),
                revision: module.revision.clone(),
                namespace: module.namespace.clone(),
                checksum: semantic_module_checksum(module, &self.nodes),
                imports: module.imports.clone(),
            })
            .collect();

        GenerationInput {
            profile: profile.clone(),
            lockfile: ModuleLockfile { profile, modules },
            schema_modules: self.modules,
            nodes: self.nodes,
            constraints: Vec::new(),
            stack_budget: StackBudget::default(),
            stack_shapes: Vec::new(),
            unsupported_features: Vec::new(),
        }
    }
}

fn validate_against_parsed_sources(
    input: &GenerationInput,
    parsed: &ParsedYang,
) -> Result<(), Diagnostic> {
    if !input.unsupported_features.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::UnsupportedYangFeature,
            "generation input already contains unsupported YANG features",
            input
                .unsupported_features
                .first()
                .map(|feature| feature.source.clone()),
            Some("remove the unsupported feature or add an explicit lowering strategy"),
        ));
    }

    if !input.constraints.is_empty() {
        return Err(mismatch(
            &input.constraints[0].source,
            "source YANG consistency gate does not yet lower constraints; input constraints must be empty",
        ));
    }

    let input_modules = input
        .schema_modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect::<BTreeMap<_, _>>();
    let parsed_modules = parsed
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect::<BTreeMap<_, _>>();

    for parsed_module in &parsed.modules {
        let Some(input_module) = input_modules.get(parsed_module.name.as_str()) else {
            return Err(mismatch(
                &parsed_module.source,
                format!(
                    "source module `{}` is missing from GenerationInput.schema_modules",
                    parsed_module.name
                ),
            ));
        };
        compare_module(input_module, parsed_module)?;
    }

    for input_module in &input.schema_modules {
        if !parsed_modules.contains_key(input_module.name.as_str()) {
            return Err(mismatch(
                &input_module.source,
                format!(
                    "GenerationInput.schema_modules contains `{}` but no matching source module was supplied",
                    input_module.name
                ),
            ));
        }
    }

    compare_lockfile(input, parsed)?;
    compare_nodes(input, parsed)?;
    compare_schema_digest(input, parsed)
}

fn compare_module(input: &SchemaModule, parsed: &SchemaModule) -> Result<(), Diagnostic> {
    compare_field(
        &input.source,
        "module revision",
        &input.revision,
        &parsed.revision,
    )?;
    compare_field(
        &input.source,
        "module namespace",
        &input.namespace,
        &parsed.namespace,
    )?;
    compare_field(
        &input.source,
        "module prefix",
        &input.prefix,
        &parsed.prefix,
    )?;
    compare_vec(
        &input.source,
        "module imports",
        &input.imports,
        &parsed.imports,
    )?;
    if input.source_text.as_deref() != parsed.source_text.as_deref() {
        return Err(mismatch(
            &input.source,
            format!(
                "schema module `{}` source_text does not match supplied YANG source",
                input.name
            ),
        ));
    }
    Ok(())
}

fn compare_lockfile(input: &GenerationInput, parsed: &ParsedYang) -> Result<(), Diagnostic> {
    if input.lockfile.modules.is_empty() {
        return Ok(());
    }

    let parsed_modules = parsed
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect::<BTreeMap<_, _>>();

    for locked in &input.lockfile.modules {
        let Some(parsed_module) = parsed_modules.get(locked.name.as_str()) else {
            return Err(mismatch(
                &YangSourceLocation::default(),
                format!(
                    "lockfile module `{}` has no matching supplied YANG source",
                    locked.name
                ),
            ));
        };
        compare_field(
            &parsed_module.source,
            "lockfile revision",
            &locked.revision,
            &parsed_module.revision,
        )?;
        compare_field(
            &parsed_module.source,
            "lockfile namespace",
            &locked.namespace,
            &parsed_module.namespace,
        )?;
        compare_vec(
            &parsed_module.source,
            "lockfile imports",
            &locked.imports,
            &parsed_module.imports,
        )?;
    }

    Ok(())
}

fn compare_nodes(input: &GenerationInput, parsed: &ParsedYang) -> Result<(), Diagnostic> {
    let input_nodes = input
        .nodes
        .iter()
        .map(|node| (node.path.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let parsed_nodes = parsed
        .nodes
        .iter()
        .map(|node| (node.path.as_str(), node))
        .collect::<BTreeMap<_, _>>();

    for parsed_node in &parsed.nodes {
        let Some(input_node) = input_nodes.get(parsed_node.path.as_str()) else {
            return Err(mismatch(
                &parsed_node.source,
                format!(
                    "source node `{}` is missing from GenerationInput.nodes",
                    parsed_node.path
                ),
            ));
        };
        compare_node(input_node, parsed_node)?;
    }

    let parsed_module_names = parsed
        .modules
        .iter()
        .map(|module| module.name.as_str())
        .collect::<BTreeSet<_>>();
    for input_node in &input.nodes {
        if parsed_module_names.contains(input_node.module.as_str())
            && !parsed_nodes.contains_key(input_node.path.as_str())
        {
            return Err(mismatch(
                &input_node.source,
                format!(
                    "GenerationInput node `{}` has no matching source node",
                    input_node.path
                ),
            ));
        }
    }

    Ok(())
}

fn compare_node(input: &SchemaNode, parsed: &SchemaNode) -> Result<(), Diagnostic> {
    compare_field(&input.source, "node module", &input.module, &parsed.module)?;
    compare_field(&input.source, "node kind", &input.kind, &parsed.kind)?;
    compare_field(
        &input.source,
        "node config flag",
        &input.config,
        &parsed.config,
    )?;
    compare_field(
        &input.source,
        "node type reference",
        &input.type_ref,
        &parsed.type_ref,
    )?;
    compare_vec(
        &input.source,
        "list key leaves",
        &input.key_leaves,
        &parsed.key_leaves,
    )?;
    compare_vec(
        &input.source,
        "child paths",
        &sorted_strings(&input.child_paths),
        &sorted_strings(&parsed.child_paths),
    )?;
    compare_field(
        &input.source,
        "default value",
        &input.default,
        &parsed.default,
    )?;
    compare_field(&input.source, "presence", &input.presence, &parsed.presence)?;
    compare_field(
        &input.source,
        "ordered-by",
        &input.ordered_by,
        &parsed.ordered_by,
    )?;
    compare_field(
        &input.source,
        "data class",
        &input.data_class,
        &parsed.data_class,
    )?;
    compare_vec(
        &input.source,
        "unique constraints",
        &input.unique_constraints,
        &parsed.unique_constraints,
    )
}

fn compare_schema_digest(input: &GenerationInput, parsed: &ParsedYang) -> Result<(), Diagnostic> {
    let source_input = GenerationInput {
        profile: input.profile.clone(),
        lockfile: input.lockfile.clone(),
        schema_modules: parsed.modules.clone(),
        nodes: parsed.nodes.clone(),
        constraints: Vec::new(),
        stack_budget: input.stack_budget,
        stack_shapes: input.stack_shapes.clone(),
        unsupported_features: Vec::new(),
    };
    let input_digest = schema_digest(input);
    let source_digest = schema_digest(&source_input);
    if input_digest != source_digest {
        return Err(mismatch(
            &YangSourceLocation::default(),
            format!(
                "GenerationInput schema digest `{input_digest}` does not match source-derived digest `{source_digest}`"
            ),
        ));
    }
    Ok(())
}

fn compare_field<T>(
    source: &YangSourceLocation,
    label: &str,
    actual: &T,
    expected: &T,
) -> Result<(), Diagnostic>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        return Ok(());
    }
    Err(mismatch(
        source,
        format!("{label} mismatch: input={actual:?} source={expected:?}"),
    ))
}

fn compare_vec<T>(
    source: &YangSourceLocation,
    label: &str,
    actual: &[T],
    expected: &[T],
) -> Result<(), Diagnostic>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        return Ok(());
    }
    Err(mismatch(
        source,
        format!("{label} mismatch: input={actual:?} source={expected:?}"),
    ))
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted
}

fn parse_yang_sources(sources: &[YangSource]) -> Result<ParsedYang, Diagnostic> {
    if sources.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            "at least one YANG source module is required",
            None,
            Some("pass one or more source modules to the consistency gate"),
        ));
    }

    let mut modules = Vec::with_capacity(sources.len());
    let mut nodes = Vec::new();
    for source in sources {
        let statements = Parser::new(source)?.parse_document()?;
        let module_statement = single_module_statement(&statements, source)?;
        let parsed_module = parse_module(module_statement, source)?;
        nodes.extend(parsed_module.nodes);
        modules.push(parsed_module.module);
    }

    modules.sort_by(|left, right| left.name.cmp(&right.name));
    nodes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ParsedYang { modules, nodes })
}

fn single_module_statement<'a>(
    statements: &'a [Statement],
    source: &YangSource,
) -> Result<&'a Statement, Diagnostic> {
    let modules = statements
        .iter()
        .filter(|statement| statement.keyword == "module")
        .collect::<Vec<_>>();
    match modules.as_slice() {
        [module] => Ok(module),
        [] => Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!(
                "YANG source `{}` does not contain a module statement",
                source.file_name
            ),
            Some(YangSourceLocation::new(&source.file_name, 1, 1)),
            Some("supply complete YANG module source files"),
        )),
        _ => Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!(
                "YANG source `{}` contains multiple module statements",
                source.file_name
            ),
            Some(YangSourceLocation::new(&source.file_name, 1, 1)),
            Some("split modules into separate source files"),
        )),
    }
}

struct ParsedModule {
    module: SchemaModule,
    nodes: Vec<SchemaNode>,
}

fn parse_module(statement: &Statement, source: &YangSource) -> Result<ParsedModule, Diagnostic> {
    let module_name = required_argument(statement, "module")?.to_string();
    let mut namespace = None;
    let mut prefix = None;
    let mut revision = None;
    let mut imports = Vec::new();
    let mut features = Vec::new();
    let mut nodes = Vec::new();

    for child in &statement.children {
        match child.keyword.as_str() {
            "yang-version" | "organization" | "contact" | "description" | "reference"
            | "status" => {}
            "namespace" => namespace = Some(required_argument(child, "namespace")?.to_string()),
            "prefix" => prefix = Some(required_argument(child, "prefix")?.to_string()),
            "revision" => {
                if revision.is_none() {
                    revision = Some(required_argument(child, "revision")?.to_string());
                }
                ensure_only_documentation_children(child)?;
            }
            "import" => imports.push(parse_import(child)?),
            "feature" => {
                features.push(required_argument(child, "feature")?.to_string());
                ensure_only_documentation_children(child)?;
            }
            "container" | "list" | "leaf" | "leaf-list" | "choice" | "case" => {
                let parsed = parse_data_node(
                    child,
                    &module_name,
                    prefix.as_deref().unwrap_or(""),
                    None,
                    true,
                )?;
                nodes.extend(parsed);
            }
            "extension" => return Err(unsupported(child, "extension")),
            "deviation" => return Err(unsupported(child, "deviation")),
            "if-feature" => return Err(unsupported(child, "if-feature")),
            "include" | "typedef" | "grouping" | "uses" | "augment" | "rpc" | "notification"
            | "identity" => return Err(unsupported(child, child.keyword.as_str())),
            other => return Err(unsupported(child, other)),
        }
    }

    let module_source = statement.source.clone();
    let namespace = namespace.ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!("module `{module_name}` is missing namespace"),
            Some(module_source.clone()),
            Some("add a namespace statement to the module"),
        )
    })?;
    let prefix = prefix.ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!("module `{module_name}` is missing prefix"),
            Some(module_source.clone()),
            Some("add a prefix statement to the module"),
        )
    })?;
    let revision = revision.unwrap_or_default();

    imports.sort();
    features.sort();

    Ok(ParsedModule {
        module: SchemaModule {
            name: module_name,
            revision,
            namespace,
            prefix,
            source: module_source,
            source_text: Some(source.text.clone()),
            imports,
            features,
            deviations: Vec::new(),
            conformance: ModuleConformance::Implement,
        },
        nodes,
    })
}

fn parse_import(statement: &Statement) -> Result<ModuleImport, Diagnostic> {
    let name = required_argument(statement, "import")?.to_string();
    let mut revision = String::new();
    for child in &statement.children {
        match child.keyword.as_str() {
            "prefix" | "description" | "reference" => {}
            "revision-date" => revision = required_argument(child, "revision-date")?.to_string(),
            "if-feature" => return Err(unsupported(child, "if-feature")),
            other => return Err(unsupported(child, other)),
        }
    }
    Ok(ModuleImport { name, revision })
}

fn parse_data_node(
    statement: &Statement,
    module_name: &str,
    module_prefix: &str,
    parent_path: Option<&str>,
    inherited_config: bool,
) -> Result<Vec<SchemaNode>, Diagnostic> {
    let name = required_argument(statement, statement.keyword.as_str())?;
    let path = match parent_path {
        Some(parent) => format!("{parent}/{name}"),
        None => format!("/{module_prefix}:{name}"),
    };
    let kind = match statement.keyword.as_str() {
        "container" => SchemaNodeKind::Container,
        "list" => SchemaNodeKind::List,
        "leaf" => SchemaNodeKind::Leaf,
        "leaf-list" => SchemaNodeKind::LeafList,
        "choice" => SchemaNodeKind::Choice,
        "case" => SchemaNodeKind::Case,
        other => return Err(unsupported(statement, other)),
    };

    let mut config = inherited_config;
    for child in &statement.children {
        if child.keyword == "config" {
            config = parse_bool_argument(child, "config")?;
        }
    }

    let mut node = SchemaNode {
        path: path.clone(),
        module: module_name.to_string(),
        kind,
        config,
        source: statement.source.clone(),
        ..Default::default()
    };
    let mut descendants = Vec::new();

    for child in &statement.children {
        match child.keyword.as_str() {
            "description" | "reference" | "status" | "mandatory" | "min-elements"
            | "max-elements" | "units" | "config" => {}
            "presence" => node.presence = Some(required_argument(child, "presence")?.to_string()),
            "ordered-by" => {
                node.ordered_by = Some(required_argument(child, "ordered-by")?.to_string());
            }
            "default" => node.default = Some(required_argument(child, "default")?.to_string()),
            "key" => {
                node.key_leaves = split_yang_words(required_argument(child, "key")?);
            }
            "unique" => {
                node.unique_constraints
                    .push(split_yang_words(required_argument(child, "unique")?));
            }
            "type" => node.type_ref = Some(parse_type_ref(child)?),
            "container" | "list" | "leaf" | "leaf-list" | "choice" | "case" => {
                let child_nodes =
                    parse_data_node(child, module_name, module_prefix, Some(&path), config)?;
                let child_path = child_nodes
                    .first()
                    .expect("parse_data_node always returns the node before descendants")
                    .path
                    .clone();
                node.child_paths.push(child_path);
                descendants.extend(child_nodes);
            }
            keyword if is_data_class_keyword(keyword) => {
                node.data_class = Some(required_argument(child, keyword)?.to_string());
            }
            "if-feature" => return Err(unsupported(child, "if-feature")),
            "must" | "when" | "uses" | "augment" | "anydata" | "anyxml" | "action"
            | "notification" => return Err(unsupported(child, child.keyword.as_str())),
            other => return Err(unsupported(child, other)),
        }
    }

    if matches!(node.kind, SchemaNodeKind::Leaf | SchemaNodeKind::LeafList)
        && node.type_ref.is_none()
    {
        return Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!(
                "{} `{}` is missing a type statement",
                statement.keyword, path
            ),
            Some(statement.source.clone()),
            Some("add a type statement or remove the node from the source module"),
        ));
    }

    let mut nodes = Vec::with_capacity(descendants.len() + 1);
    nodes.push(node);
    nodes.extend(descendants);
    Ok(nodes)
}

fn parse_type_ref(statement: &Statement) -> Result<TypeRef, Diagnostic> {
    let type_name = required_argument(statement, "type")?;
    match type_name {
        "boolean" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::Boolean),
        "string" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::String),
        "enumeration" => parse_enumeration_type(statement),
        "uint16" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::Uint16),
        "uint32" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::Uint32),
        "int64" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::Int64),
        "decimal64" => {
            ensure_type_children_supported(statement, &["fraction-digits"])?;
            Ok(TypeRef::Decimal64)
        }
        "empty" => ensure_type_children_supported(statement, &[]).map(|()| TypeRef::Empty),
        "identityref" => {
            let base = required_child_argument(statement, "base")?;
            ensure_type_children_supported(statement, &["base"])?;
            Ok(TypeRef::IdentityRef { base })
        }
        "leafref" => {
            let target_path = required_child_argument(statement, "path")?;
            ensure_type_children_supported(statement, &["path", "require-instance"])?;
            Ok(TypeRef::LeafRef { target_path })
        }
        other => ensure_type_children_supported(statement, &[])
            .map(|()| TypeRef::Custom { name: other.into() }),
    }
}

fn parse_enumeration_type(statement: &Statement) -> Result<TypeRef, Diagnostic> {
    let mut values = Vec::new();
    for child in &statement.children {
        match child.keyword.as_str() {
            "enum" => {
                let name = required_argument(child, "enum")?.to_string();
                let mut description = None;
                for enum_child in &child.children {
                    match enum_child.keyword.as_str() {
                        "description" => {
                            description =
                                Some(required_argument(enum_child, "description")?.to_string());
                        }
                        "reference" | "status" => {}
                        other => return Err(unsupported(enum_child, other)),
                    }
                }
                values.push(EnumValue { name, description });
            }
            "description" | "reference" | "status" | "units" => {}
            other => return Err(unsupported(child, other)),
        }
    }
    if values.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            "enumeration type requires at least one enum value",
            Some(statement.source.clone()),
            Some("add one or more enum statements"),
        ));
    }
    Ok(TypeRef::Enumeration { values })
}

fn ensure_type_children_supported(
    statement: &Statement,
    allowed: &[&str],
) -> Result<(), Diagnostic> {
    for child in &statement.children {
        if allowed.contains(&child.keyword.as_str()) {
            continue;
        }
        if matches!(
            child.keyword.as_str(),
            "description" | "reference" | "status" | "units"
        ) {
            continue;
        }
        return Err(unsupported(child, child.keyword.as_str()));
    }
    Ok(())
}

fn required_child_argument(statement: &Statement, keyword: &str) -> Result<String, Diagnostic> {
    statement
        .children
        .iter()
        .find(|child| child.keyword == keyword)
        .map(|child| required_argument(child, keyword).map(ToString::to_string))
        .transpose()?
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCode::YangSourceSyntaxError,
                format!(
                    "type `{}` is missing `{keyword}`",
                    statement.argument_text()
                ),
                Some(statement.source.clone()),
                Some("add the required child statement"),
            )
        })
}

fn ensure_only_documentation_children(statement: &Statement) -> Result<(), Diagnostic> {
    for child in &statement.children {
        match child.keyword.as_str() {
            "description" | "reference" | "status" => {}
            "if-feature" => return Err(unsupported(child, "if-feature")),
            other => return Err(unsupported(child, other)),
        }
    }
    Ok(())
}

fn parse_bool_argument(statement: &Statement, label: &str) -> Result<bool, Diagnostic> {
    match required_argument(statement, label)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!("{label} expects true or false, found `{other}`"),
            Some(statement.source.clone()),
            Some("use a boolean YANG argument"),
        )),
    }
}

fn required_argument<'a>(statement: &'a Statement, label: &str) -> Result<&'a str, Diagnostic> {
    statement.argument.as_deref().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!("{label} statement is missing an argument"),
            Some(statement.source.clone()),
            Some("add the required YANG statement argument"),
        )
    })
}

fn split_yang_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
}

fn is_data_class_keyword(keyword: &str) -> bool {
    keyword == "data-class" || keyword.ends_with(":data-class")
}

fn semantic_module_checksum(module: &SchemaModule, nodes: &[SchemaNode]) -> String {
    let module_nodes = nodes
        .iter()
        .filter(|node| node.module == module.name)
        .map(|node| {
            serde_json::json!({
                "path": node.path,
                "kind": node.kind,
                "config": node.config,
                "type_ref": node.type_ref,
                "key_leaves": node.key_leaves,
                "child_paths": sorted_strings(&node.child_paths),
                "default": node.default,
                "presence": node.presence,
                "ordered_by": node.ordered_by,
                "data_class": node.data_class,
                "unique_constraints": node.unique_constraints,
            })
        })
        .collect::<Vec<_>>();
    let material = serde_json::json!({
        "name": module.name,
        "revision": module.revision,
        "namespace": module.namespace,
        "prefix": module.prefix,
        "imports": module.imports,
        "features": module.features,
        "nodes": module_nodes,
    });
    let encoded = serde_json::to_string(&material)
        .expect("semantic module checksum material should serialize");
    format!("fnv1a64:{:016x}", fnv1a64(encoded.as_bytes()))
}

fn unsupported(statement: &Statement, construct: &str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::UnsupportedYangFeature,
        format!("unsupported YANG construct `{construct}` encountered during source ingestion"),
        Some(statement.source.clone()),
        Some("remove the construct or add an explicit lowering strategy before generation"),
    )
}

fn mismatch(source: &YangSourceLocation, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceMismatch,
        message,
        Some(source.clone()),
        Some("regenerate the GenerationInput from the source YANG or update the source module"),
    )
}

#[derive(Debug, Clone)]
struct Statement {
    keyword: String,
    argument: Option<String>,
    source: YangSourceLocation,
    children: Vec<Statement>,
}

impl Statement {
    fn argument_text(&self) -> &str {
        self.argument.as_deref().unwrap_or("")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    String(String),
    LBrace,
    RBrace,
    Semicolon,
    Plus,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    source: YangSourceLocation,
}

struct Parser<'a> {
    tokens: Vec<Token>,
    index: usize,
    file_name: &'a str,
}

impl<'a> Parser<'a> {
    fn new(source: &'a YangSource) -> Result<Self, Diagnostic> {
        Ok(Self {
            tokens: lex(source)?,
            index: 0,
            file_name: &source.file_name,
        })
    }

    fn parse_document(&mut self) -> Result<Vec<Statement>, Diagnostic> {
        let mut statements = Vec::new();
        while !self.is_eof() {
            statements.push(self.parse_statement()?);
        }
        Ok(statements)
    }

    fn parse_statement(&mut self) -> Result<Statement, Diagnostic> {
        let token = self.next().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCode::YangSourceSyntaxError,
                "unexpected end of YANG source",
                Some(YangSourceLocation::new(self.file_name, 1, 1)),
                Some("complete the current YANG statement"),
            )
        })?;
        let TokenKind::Ident(keyword) = token.kind else {
            return Err(Diagnostic::new(
                DiagnosticCode::YangSourceSyntaxError,
                "expected YANG statement keyword",
                Some(token.source),
                Some("start the statement with an identifier"),
            ));
        };

        let mut argument_parts = Vec::new();
        loop {
            let Some(peek) = self.peek() else {
                return Err(Diagnostic::new(
                    DiagnosticCode::YangSourceSyntaxError,
                    format!("statement `{keyword}` is missing `;` or `{{`"),
                    Some(token.source),
                    Some("terminate the statement or add a child block"),
                ));
            };
            match &peek.kind {
                TokenKind::Semicolon => {
                    self.index += 1;
                    return Ok(Statement {
                        keyword,
                        argument: joined_argument(argument_parts),
                        source: token.source,
                        children: Vec::new(),
                    });
                }
                TokenKind::LBrace => {
                    self.index += 1;
                    let children = self.parse_block()?;
                    return Ok(Statement {
                        keyword,
                        argument: joined_argument(argument_parts),
                        source: token.source,
                        children,
                    });
                }
                TokenKind::RBrace => {
                    return Err(Diagnostic::new(
                        DiagnosticCode::YangSourceSyntaxError,
                        format!("statement `{keyword}` ended before `;` or `{{`"),
                        Some(peek.source.clone()),
                        Some("terminate the statement before closing the parent block"),
                    ));
                }
                TokenKind::Plus => {
                    self.index += 1;
                }
                TokenKind::Ident(value) | TokenKind::String(value) => {
                    argument_parts.push(value.clone());
                    self.index += 1;
                }
            }
        }
    }

    fn parse_block(&mut self) -> Result<Vec<Statement>, Diagnostic> {
        let mut children = Vec::new();
        loop {
            let Some(peek) = self.peek() else {
                return Err(Diagnostic::new(
                    DiagnosticCode::YangSourceSyntaxError,
                    "unclosed YANG statement block",
                    Some(YangSourceLocation::new(self.file_name, 1, 1)),
                    Some("add a closing `}`"),
                ));
            };
            if peek.kind == TokenKind::RBrace {
                self.index += 1;
                return Ok(children);
            }
            children.push(self.parse_statement()?);
        }
    }

    fn is_eof(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned()?;
        self.index += 1;
        Some(token)
    }
}

fn joined_argument(parts: Vec<String>) -> Option<String> {
    match parts.len() {
        0 => None,
        1 => parts.into_iter().next(),
        _ => Some(parts.join("")),
    }
}

fn lex(source: &YangSource) -> Result<Vec<Token>, Diagnostic> {
    let mut tokens = Vec::new();
    let chars = source.text.chars().collect::<Vec<_>>();
    let mut index = 0;
    let mut line = 1;
    let mut column = 1;

    while index < chars.len() {
        let ch = chars[index];
        match ch {
            c if c.is_whitespace() => {
                advance_char(c, &mut line, &mut column);
                index += 1;
            }
            '/' if chars.get(index + 1) == Some(&'/') => {
                index += 2;
                column += 2;
                while let Some(&next) = chars.get(index) {
                    index += 1;
                    advance_char(next, &mut line, &mut column);
                    if next == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.get(index + 1) == Some(&'*') => {
                let start = YangSourceLocation::new(&source.file_name, line, column);
                index += 2;
                column += 2;
                let mut closed = false;
                while index < chars.len() {
                    if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                        index += 2;
                        column += 2;
                        closed = true;
                        break;
                    }
                    let current = chars[index];
                    index += 1;
                    advance_char(current, &mut line, &mut column);
                }
                if !closed {
                    return Err(Diagnostic::new(
                        DiagnosticCode::YangSourceSyntaxError,
                        "unterminated block comment",
                        Some(start),
                        Some("close the comment with `*/`"),
                    ));
                }
            }
            '{' => {
                tokens.push(symbol_token(
                    TokenKind::LBrace,
                    &source.file_name,
                    line,
                    column,
                ));
                index += 1;
                column += 1;
            }
            '}' => {
                tokens.push(symbol_token(
                    TokenKind::RBrace,
                    &source.file_name,
                    line,
                    column,
                ));
                index += 1;
                column += 1;
            }
            ';' => {
                tokens.push(symbol_token(
                    TokenKind::Semicolon,
                    &source.file_name,
                    line,
                    column,
                ));
                index += 1;
                column += 1;
            }
            '+' => {
                tokens.push(symbol_token(
                    TokenKind::Plus,
                    &source.file_name,
                    line,
                    column,
                ));
                index += 1;
                column += 1;
            }
            '"' | '\'' => {
                let quote = ch;
                let start = YangSourceLocation::new(&source.file_name, line, column);
                index += 1;
                column += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < chars.len() {
                    let current = chars[index];
                    index += 1;
                    advance_char(current, &mut line, &mut column);
                    if current == quote {
                        closed = true;
                        break;
                    }
                    if current == '\\' && quote == '"' {
                        let Some(&escaped) = chars.get(index) else {
                            value.push(current);
                            break;
                        };
                        index += 1;
                        advance_char(escaped, &mut line, &mut column);
                        value.push(match escaped {
                            'n' => '\n',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            other => other,
                        });
                    } else {
                        value.push(current);
                    }
                }
                if !closed {
                    return Err(Diagnostic::new(
                        DiagnosticCode::YangSourceSyntaxError,
                        "unterminated string literal",
                        Some(start),
                        Some("close the string before the end of the file"),
                    ));
                }
                tokens.push(Token {
                    kind: TokenKind::String(value),
                    source: start,
                });
            }
            _ => {
                let start_line = line;
                let start_column = column;
                let mut value = String::new();
                while let Some(&current) = chars.get(index) {
                    if current.is_whitespace() || matches!(current, '{' | '}' | ';' | '"' | '\'') {
                        break;
                    }
                    if current == '/' && matches!(chars.get(index + 1), Some('/') | Some('*')) {
                        break;
                    }
                    if current == '+' {
                        break;
                    }
                    value.push(current);
                    index += 1;
                    advance_char(current, &mut line, &mut column);
                }
                if value.is_empty() {
                    return Err(Diagnostic::new(
                        DiagnosticCode::YangSourceSyntaxError,
                        format!("unexpected character `{ch}`"),
                        Some(YangSourceLocation::new(&source.file_name, line, column)),
                        Some("remove the character or quote it as a YANG string"),
                    ));
                }
                tokens.push(Token {
                    kind: TokenKind::Ident(value),
                    source: YangSourceLocation::new(&source.file_name, start_line, start_column),
                });
            }
        }
    }

    Ok(tokens)
}

fn symbol_token(kind: TokenKind, file_name: &str, line: usize, column: usize) -> Token {
    Token {
        kind,
        source: YangSourceLocation::new(file_name, line, column),
    }
}

fn advance_char(ch: char, line: &mut usize, column: &mut usize) {
    if ch == '\n' {
        *line += 1;
        *column = 1;
    } else {
        *column += 1;
    }
}
