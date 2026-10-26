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
    EnumValue, LockedModule, ModuleConformance, ModuleImport, ModuleLockfile, NumericRangeInterval,
    SchemaModule, SchemaNode, SchemaNodeKind, StackBudget, TypeRef,
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
/// defaults, mandatory/cardinality, presence markers, ordered-by, data classes, unique constraints,
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
        "numeric range",
        &input.numeric_range,
        &parsed.numeric_range,
    )?;
    compare_field(
        &input.source,
        "mandatory",
        &input.mandatory,
        &parsed.mandatory,
    )?;
    compare_field(
        &input.source,
        "min-elements",
        &input.min_elements,
        &parsed.min_elements,
    )?;
    compare_field(
        &input.source,
        "max-elements",
        &input.max_elements,
        &parsed.max_elements,
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
    let qualified_name = format!("{module_prefix}:{name}");
    let path = match parent_path {
        Some(parent) => format!("{parent}/{qualified_name}"),
        None => format!("/{qualified_name}"),
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
    let mut seen_cardinality = BTreeSet::new();

    for child in &statement.children {
        if matches!(
            child.keyword.as_str(),
            "mandatory" | "min-elements" | "max-elements"
        ) && !seen_cardinality.insert(child.keyword.as_str())
        {
            return Err(invalid_cardinality(
                child,
                "duplicate cardinality statement",
            ));
        }
        if matches!(
            child.keyword.as_str(),
            "mandatory" | "min-elements" | "max-elements"
        ) {
            ensure_type_children_supported(child, &[])?;
        }
        match child.keyword.as_str() {
            "description" | "reference" | "status" | "units" | "config" => {}
            "mandatory" => node.mandatory = Some(parse_bool_argument(child, "mandatory")?),
            "min-elements" => node.min_elements = Some(parse_element_bound(child)?),
            "max-elements" => {
                if required_argument(child, "max-elements")? != "unbounded" {
                    node.max_elements = Some(parse_element_bound(child)?);
                }
                if !matches!(kind, SchemaNodeKind::List | SchemaNodeKind::LeafList) {
                    return Err(invalid_cardinality(
                        child,
                        "element bounds require a list or leaf-list",
                    ));
                }
            }
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
            "type" => {
                let parsed_type = parse_type_ref(child)?;
                node.type_ref = Some(parsed_type.type_ref);
                node.numeric_range = parsed_type.numeric_range;
            }
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

    node.validate_cardinality()
        .map_err(|message| invalid_cardinality(statement, message))?;
    let mut nodes = Vec::with_capacity(descendants.len() + 1);
    nodes.push(node);
    nodes.extend(descendants);
    Ok(nodes)
}

fn invalid_cardinality(statement: &Statement, message: &'static str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        message,
        Some(statement.source.clone()),
        Some("use valid mandatory and element bounds for this node"),
    )
}

fn parse_element_bound(statement: &Statement) -> Result<u32, Diagnostic> {
    let argument = required_argument(statement, &statement.keyword)?;
    if argument.is_empty() || !argument.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_cardinality(
            statement,
            "element bound must be an unsigned decimal integer",
        ));
    }
    argument
        .parse()
        .map_err(|_| invalid_cardinality(statement, "element bound exceeds the uint32 domain"))
}

struct ParsedTypeRef {
    type_ref: TypeRef,
    numeric_range: Vec<NumericRangeInterval>,
}

fn parse_type_ref(statement: &Statement) -> Result<ParsedTypeRef, Diagnostic> {
    let type_name = required_argument(statement, "type")?;
    match type_name {
        "boolean" => parse_plain_type(statement, TypeRef::Boolean),
        "string" => parse_string_type(statement),
        "enumeration" => parse_enumeration_type(statement).map(|type_ref| ParsedTypeRef {
            type_ref,
            numeric_range: Vec::new(),
        }),
        "uint8" => parse_integer_type(statement, TypeRef::Uint8, 0, i128::from(u8::MAX)),
        "uint64" => parse_integer_type(statement, TypeRef::Uint64, 0, i128::from(u64::MAX)),
        "int8" => parse_integer_type(
            statement,
            TypeRef::Int8,
            i128::from(i8::MIN),
            i128::from(i8::MAX),
        ),
        "int16" => parse_integer_type(
            statement,
            TypeRef::Int16,
            i128::from(i16::MIN),
            i128::from(i16::MAX),
        ),
        "int32" => parse_integer_type(
            statement,
            TypeRef::Int32,
            i128::from(i32::MIN),
            i128::from(i32::MAX),
        ),
        "uint16" => parse_integer_type(statement, TypeRef::Uint16, 0, i128::from(u16::MAX)),
        "uint32" => parse_integer_type(statement, TypeRef::Uint32, 0, i128::from(u32::MAX)),
        "int64" => parse_integer_type(
            statement,
            TypeRef::Int64,
            i128::from(i64::MIN),
            i128::from(i64::MAX),
        ),
        "decimal64" => {
            ensure_type_children_supported(statement, &["fraction-digits"])?;
            Ok(ParsedTypeRef {
                type_ref: TypeRef::Decimal64,
                numeric_range: Vec::new(),
            })
        }
        "empty" => parse_plain_type(statement, TypeRef::Empty),
        "identityref" => {
            let base = required_child_argument(statement, "base")?;
            ensure_type_children_supported(statement, &["base"])?;
            Ok(ParsedTypeRef {
                type_ref: TypeRef::IdentityRef { base },
                numeric_range: Vec::new(),
            })
        }
        "leafref" => {
            let target_path = required_child_argument(statement, "path")?;
            ensure_type_children_supported(statement, &["path", "require-instance"])?;
            Ok(ParsedTypeRef {
                type_ref: TypeRef::LeafRef { target_path },
                numeric_range: Vec::new(),
            })
        }
        other => ensure_type_children_supported(statement, &[]).map(|()| ParsedTypeRef {
            type_ref: TypeRef::Custom { name: other.into() },
            numeric_range: Vec::new(),
        }),
    }
}

fn parse_plain_type(statement: &Statement, type_ref: TypeRef) -> Result<ParsedTypeRef, Diagnostic> {
    ensure_type_children_supported(statement, &[])?;
    Ok(ParsedTypeRef {
        type_ref,
        numeric_range: Vec::new(),
    })
}

fn parse_string_type(statement: &Statement) -> Result<ParsedTypeRef, Diagnostic> {
    use crate::ir::{StringLengthInterval, StringPattern};
    use opc_mgmt_schema::string_constraints::{CompiledYangPattern, PatternError};
    ensure_type_children_supported(statement, &["length", "pattern"])?;
    let mut length = Vec::new();
    let mut patterns = Vec::new();
    let mut seen_length = false;
    for child in &statement.children {
        match child.keyword.as_str() {
            "length" => {
                if seen_length {
                    return Err(invalid_string_constraint(
                        child,
                        "duplicate string length statement",
                    ));
                }
                seen_length = true;
                // Length uses the same interval grammar, with an unsigned
                // character-count domain. Keep declaration order for validation.
                let mut range_statement = child.clone();
                range_statement.keyword = "range".into();
                for interval in parse_numeric_range(&range_statement, 0, i128::from(u64::MAX))? {
                    let interval = StringLengthInterval {
                        min: interval.min as u64,
                        max: interval.max as u64,
                    };
                    if length
                        .last()
                        .is_some_and(|prior: &StringLengthInterval| prior.max >= interval.min)
                    {
                        return Err(invalid_string_constraint(
                            child,
                            "string length intervals must be ascending and disjoint",
                        ));
                    }
                    length.push(interval);
                }
            }
            "pattern" => {
                if patterns.len() == 64 {
                    return Err(invalid_string_constraint(
                        child,
                        "string type exceeds the 64-pattern limit",
                    ));
                }
                let expression = required_argument(child, "pattern")?.to_string();
                CompiledYangPattern::compile(&expression).map_err(|error| {
                    Diagnostic::new(
                        if error == PatternError::UnsupportedEscape {
                            DiagnosticCode::UnsupportedYangFeature
                        } else {
                            DiagnosticCode::YangSourceSyntaxError
                        },
                        error.to_string(),
                        Some(child.source.clone()),
                        Some("use the documented bounded XSD pattern profile"),
                    )
                })?;
                let mut invert_match = false;
                let mut seen_modifier = false;
                for sub in &child.children {
                    match sub.keyword.as_str() {
                        "description" | "reference" | "error-message" | "error-app-tag" => {}
                        "modifier" => {
                            if seen_modifier
                                || required_argument(sub, "modifier")? != "invert-match"
                                || !sub.children.is_empty()
                            {
                                return Err(invalid_string_constraint(
                                    sub,
                                    "pattern modifier must be one invert-match statement",
                                ));
                            }
                            seen_modifier = true;
                            invert_match = true;
                        }
                        other => return Err(unsupported(sub, other)),
                    }
                }
                patterns.push(StringPattern {
                    expression,
                    invert_match,
                });
            }
            _ => {}
        }
    }
    Ok(ParsedTypeRef {
        type_ref: if seen_length || !patterns.is_empty() {
            TypeRef::RestrictedString { length, patterns }
        } else {
            TypeRef::String
        },
        numeric_range: Vec::new(),
    })
}

fn invalid_string_constraint(statement: &Statement, message: &'static str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        message,
        Some(statement.source.clone()),
        Some("use a valid YANG string length or pattern restriction"),
    )
}

fn parse_integer_type(
    statement: &Statement,
    type_ref: TypeRef,
    base_min: i128,
    base_max: i128,
) -> Result<ParsedTypeRef, Diagnostic> {
    ensure_type_children_supported(statement, &["range"])?;
    Ok(ParsedTypeRef {
        type_ref,
        numeric_range: parse_optional_numeric_range(statement, base_min, base_max)?,
    })
}

fn parse_optional_numeric_range(
    statement: &Statement,
    base_min: i128,
    base_max: i128,
) -> Result<Vec<NumericRangeInterval>, Diagnostic> {
    let mut parsed_range = None;
    for child in &statement.children {
        if child.keyword != "range" {
            continue;
        }
        if parsed_range.is_some() {
            return Err(Diagnostic::new(
                DiagnosticCode::YangSourceSyntaxError,
                "integer type declares more than one range statement",
                Some(child.source.clone()),
                Some("combine the intervals into one range statement separated by '|'"),
            ));
        }
        parsed_range = Some(parse_numeric_range(child, base_min, base_max)?);
    }
    Ok(parsed_range.unwrap_or_default())
}

fn parse_numeric_range(
    statement: &Statement,
    base_min: i128,
    base_max: i128,
) -> Result<Vec<NumericRangeInterval>, Diagnostic> {
    for child in &statement.children {
        match child.keyword.as_str() {
            "description" | "reference" | "error-message" | "error-app-tag" => {}
            other => return Err(unsupported(child, other)),
        }
    }

    let raw = required_argument(statement, "range")?;
    let mut intervals = Vec::new();
    for part in raw.split('|') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(invalid_range(statement, "range interval must not be empty"));
        }
        let (min_raw, max_raw) = trimmed
            .split_once("..")
            .map_or((trimmed, trimmed), |(min, max)| (min.trim(), max.trim()));
        let min = parse_numeric_range_bound(statement, min_raw, base_min, base_max)?;
        let max = parse_numeric_range_bound(statement, max_raw, base_min, base_max)?;
        if min > max {
            return Err(invalid_range(
                statement,
                "range lower bound must not exceed upper bound",
            ));
        }
        if min < base_min || max > base_max {
            return Err(invalid_range(
                statement,
                "range interval exceeds the base integer type bounds",
            ));
        }
        intervals.push(NumericRangeInterval { min, max });
    }
    if intervals.is_empty() {
        return Err(invalid_range(
            statement,
            "range must contain at least one interval",
        ));
    }
    Ok(intervals)
}

fn parse_numeric_range_bound(
    statement: &Statement,
    raw: &str,
    base_min: i128,
    base_max: i128,
) -> Result<i128, Diagnostic> {
    match raw {
        "min" => Ok(base_min),
        "max" => Ok(base_max),
        "" => Err(invalid_range(statement, "range bound must not be empty")),
        value => value.parse::<i128>().map_err(|_| {
            invalid_range(statement, "range bound must be an integer, 'min', or 'max'")
        }),
    }
}

fn invalid_range(statement: &Statement, message: &'static str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        message,
        Some(statement.source.clone()),
        Some("use YANG integer range syntax such as \"1..max\" or \"0..10 | 20\""),
    )
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
            let mut node_json = serde_json::json!({
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
            });
            if !node.numeric_range.is_empty() {
                node_json["numeric_range"] = serde_json::json!(node.numeric_range);
            }
            node_json
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

        let mut argument = None;
        if let Some(peek) = self.peek() {
            if let TokenKind::Ident(value) | TokenKind::String(value) = &peek.kind {
                let quoted = matches!(peek.kind, TokenKind::String(_));
                let mut value = value.clone();
                self.index += 1;
                if quoted {
                    while self
                        .peek()
                        .is_some_and(|token| token.kind == TokenKind::Plus)
                    {
                        self.index += 1;
                        let Some(Token {
                            kind: TokenKind::String(part),
                            ..
                        }) = self.next()
                        else {
                            return Err(self.invalid_argument());
                        };
                        value.push_str(&part);
                    }
                }
                argument = Some(value);
            }
        }
        let Some(terminator) = self.next() else {
            return Err(Diagnostic::new(
                DiagnosticCode::YangSourceSyntaxError,
                format!("statement `{keyword}` is missing `;` or `{{`"),
                Some(token.source),
                Some("terminate the statement or add a child block"),
            ));
        };
        let children = match terminator.kind {
            TokenKind::Semicolon => Vec::new(),
            TokenKind::LBrace => self.parse_block()?,
            TokenKind::RBrace => {
                return Err(Diagnostic::new(
                    DiagnosticCode::YangSourceSyntaxError,
                    format!("statement `{keyword}` ended before `;` or `{{`"),
                    Some(terminator.source),
                    Some("terminate the statement before closing the parent block"),
                ));
            }
            _ => return Err(self.invalid_argument()),
        };
        Ok(Statement {
            keyword,
            argument,
            source: token.source,
            children,
        })
    }

    fn invalid_argument(&self) -> Diagnostic {
        Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            "YANG arguments require one string or quoted strings joined by '+'",
            self.tokens
                .get(self.index.saturating_sub(1))
                .map(|token| token.source.clone()),
            Some("join quoted strings with '+' or use a single argument"),
        )
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

fn lex(source: &YangSource) -> Result<Vec<Token>, Diagnostic> {
    let mut tokens = Vec::new();
    let chars = source.text.chars().collect::<Vec<_>>();
    let mut index = 0;
    let mut line = 1;
    let mut column = 1;

    while index < chars.len() {
        let ch = chars[index];
        match ch {
            c if is_yang_whitespace(c) => {
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
            '*' if chars.get(index + 1) == Some(&'/') => {
                return Err(Diagnostic::new(
                    DiagnosticCode::YangSourceSyntaxError,
                    "unexpected block comment terminator",
                    Some(YangSourceLocation::new(&source.file_name, line, column)),
                    Some("remove the unmatched comment terminator or quote the string"),
                ));
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
            '+' if tokens
                .last()
                .is_some_and(|token| matches!(token.kind, TokenKind::String(_))) =>
            {
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
                        if !matches!(escaped, 'n' | 't' | '"' | '\\') {
                            return Err(Diagnostic::new(
                                DiagnosticCode::YangSourceSyntaxError,
                                "invalid escape in double-quoted YANG string",
                                Some(start),
                                Some("double-quoted YANG strings allow only n, t, double quote, or backslash after a backslash"),
                            ));
                        }
                        // Preserve escapes until indentation and trailing
                        // whitespace have been stripped (RFC 7950 section 6.1.3).
                        value.push(current);
                        value.push(escaped);
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
                if quote == '"' {
                    value = decode_double_quoted(&value, start.column);
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
                    if is_yang_whitespace(current)
                        || matches!(current, '{' | '}' | ';' | '"' | '\'')
                    {
                        break;
                    }
                    if current == '/' && matches!(chars.get(index + 1), Some('/') | Some('*')) {
                        break;
                    }
                    if current == '*' && chars.get(index + 1) == Some(&'/') {
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

fn is_yang_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

// Trim physical lines before interpreting escapes, and preserve CRLF/LF.
fn decode_double_quoted(raw: &str, quote_column: usize) -> String {
    let mut trimmed = String::new();
    for (index, line) in raw.split_inclusive('\n').enumerate() {
        let (line, ending) = if let Some(body) = line.strip_suffix("\r\n") {
            (body, "\r\n")
        } else if let Some(body) = line.strip_suffix('\n') {
            (body, "\n")
        } else {
            (line, "")
        };
        let mut chars = line.chars().peekable();
        let mut body = String::new();
        if index > 0 {
            let mut remaining = quote_column;
            while remaining > 0 {
                let width = match chars.peek() {
                    Some(' ') => 1,
                    Some('\t') => 8,
                    _ => break,
                };
                chars.next();
                if width > remaining {
                    body.extend(std::iter::repeat_n(' ', width - remaining));
                }
                remaining = remaining.saturating_sub(width);
            }
        }
        body.extend(chars);
        trimmed.push_str(if ending.is_empty() {
            &body
        } else {
            body.trim_end_matches([' ', '\t'])
        });
        trimmed.push_str(ending);
    }
    let mut decoded = String::new();
    let mut chars = trimmed.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            decoded.push(match chars.next() {
                Some('n') => '\n',
                Some('t') => '\t',
                Some('"') => '"',
                Some('\\') => '\\',
                _ => unreachable!("the lexer validated every double-quoted escape"),
            });
        } else {
            decoded.push(ch);
        }
    }
    decoded
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
    } else if ch == '\t' {
        *column += 8;
    } else {
        *column += 1;
    }
}
