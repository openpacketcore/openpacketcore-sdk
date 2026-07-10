use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ActionContract, CapabilityId, CatalogError, CatalogLimits, CommandId, CommandSchema,
    CommandToken, CommandVersion, CompletionSpec, DataNodeAccess, EffectClass, ExecutionLimits,
    GrammarNode, HelpText, OperationPlan, PresentationSpec, ReadPlan, ReadSource, SchemaPath,
    ValueSpec,
};

/// Bounded sequence forming one command grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandGrammar {
    nodes: Vec<GrammarNode>,
}

impl CommandGrammar {
    /// Constructs a grammar. Registry freeze performs bounded deep validation.
    #[must_use]
    pub fn new(nodes: impl IntoIterator<Item = GrammarNode>) -> Self {
        Self {
            nodes: nodes.into_iter().collect(),
        }
    }

    /// Root grammar nodes.
    pub fn nodes(&self) -> &[GrammarNode] {
        &self.nodes
    }
}

/// One declarative operational command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    id: CommandId,
    version: CommandVersion,
    grammar: CommandGrammar,
    summary: HelpText,
    description: Option<HelpText>,
    examples: Vec<HelpText>,
    effect: EffectClass,
    operation: OperationPlan,
    presentation: PresentationSpec,
    limits: ExecutionLimits,
    capabilities: Vec<CapabilityId>,
}

impl CommandSpec {
    /// Constructs a command with all required behavior.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: CommandId,
        version: CommandVersion,
        grammar: CommandGrammar,
        summary: HelpText,
        effect: EffectClass,
        operation: OperationPlan,
        presentation: PresentationSpec,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            id,
            version,
            grammar,
            summary,
            description: None,
            examples: Vec::new(),
            effect,
            operation,
            presentation,
            limits,
            capabilities: Vec::new(),
        }
    }

    /// Adds long help.
    #[must_use]
    pub fn with_description(mut self, description: HelpText) -> Self {
        self.description = Some(description);
        self
    }

    /// Adds command examples.
    #[must_use]
    pub fn with_examples(mut self, examples: impl IntoIterator<Item = HelpText>) -> Self {
        self.examples = examples.into_iter().collect();
        self
    }

    /// Adds required target capabilities/models.
    #[must_use]
    pub fn with_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = CapabilityId>,
    ) -> Self {
        self.capabilities = capabilities.into_iter().collect();
        self
    }

    /// Stable command identity.
    pub fn id(&self) -> &CommandId {
        &self.id
    }

    /// Command version.
    pub const fn version(&self) -> CommandVersion {
        self.version
    }

    /// Human grammar.
    pub fn grammar(&self) -> &CommandGrammar {
        &self.grammar
    }

    /// Short help.
    pub fn summary(&self) -> &HelpText {
        &self.summary
    }

    /// Long help.
    pub fn description(&self) -> Option<&HelpText> {
        self.description.as_ref()
    }

    /// Examples.
    pub fn examples(&self) -> &[HelpText] {
        &self.examples
    }

    /// Effect class.
    pub const fn effect(&self) -> EffectClass {
        self.effect
    }

    /// Typed operation plan.
    pub fn operation(&self) -> &OperationPlan {
        &self.operation
    }

    /// Result presentation.
    pub fn presentation(&self) -> &PresentationSpec {
        &self.presentation
    }

    /// Execution limits.
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Required capabilities.
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }
}

/// Mutable CNF command registry before schema validation/freeze.
#[derive(Debug, Default)]
pub struct CommandRegistry {
    commands: BTreeMap<CommandId, CommandSpec>,
}

impl CommandRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one stable command ID.
    pub fn register(&mut self, command: CommandSpec) -> Result<(), CatalogError> {
        if self.commands.contains_key(command.id()) {
            return Err(CatalogError::DuplicateCommand(command.id().clone()));
        }
        self.commands.insert(command.id().clone(), command);
        Ok(())
    }

    /// Validates and freezes the catalog in deterministic command-ID order.
    pub fn freeze(
        self,
        schema: &dyn CommandSchema,
        limits: CatalogLimits,
    ) -> Result<ValidatedCommandCatalog, CatalogError> {
        limits.validate()?;
        check_limit("commands", limits.max_commands, self.commands.len())?;

        let mut total_nodes = 0usize;
        let mut total_text = 0usize;
        let mut registered_syntaxes: Vec<(CommandId, ExpandedSyntax)> = Vec::new();

        for command in self.commands.values() {
            validate_command(command, schema, &limits, &mut total_nodes, &mut total_text)?;
            let syntaxes = expand_grammar(command, &limits)?;
            validate_internal_ambiguity(command.id(), &syntaxes)?;

            for syntax in syntaxes {
                if let Some((other, _)) = registered_syntaxes
                    .iter()
                    .find(|(_, candidate)| syntaxes_overlap(candidate, &syntax))
                {
                    return Err(CatalogError::AmbiguousSyntax {
                        first: other.clone(),
                        second: command.id().clone(),
                    });
                }
                registered_syntaxes.push((command.id().clone(), syntax));
            }
        }

        Ok(ValidatedCommandCatalog {
            commands: self.commands.into_values().collect(),
            limits,
        })
    }
}

/// Immutable validated command catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCommandCatalog {
    commands: Vec<CommandSpec>,
    limits: CatalogLimits,
}

impl ValidatedCommandCatalog {
    /// Commands sorted by stable ID.
    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }

    /// Validated limits used to freeze the catalog.
    pub const fn limits(&self) -> CatalogLimits {
        self.limits
    }

    /// Looks up a stable command ID.
    pub fn command(&self, id: &CommandId) -> Option<&CommandSpec> {
        self.commands
            .binary_search_by(|command| command.id().cmp(id))
            .ok()
            .map(|index| &self.commands[index])
    }
}

fn validate_command(
    command: &CommandSpec,
    schema: &dyn CommandSchema,
    limits: &CatalogLimits,
    total_nodes: &mut usize,
    total_text: &mut usize,
) -> Result<(), CatalogError> {
    check_limit(
        "examples_per_command",
        limits.max_examples_per_command,
        command.examples().len(),
    )?;
    check_limit(
        "capabilities_per_command",
        limits.max_capabilities_per_command,
        command.capabilities().len(),
    )?;
    check_limit(
        "execution_deadline_millis",
        usize::try_from(limits.max_execution_deadline.as_millis()).unwrap_or(usize::MAX),
        usize::try_from(command.limits().deadline().as_millis()).unwrap_or(usize::MAX),
    )?;
    check_limit(
        "execution_output_bytes",
        limits.max_execution_output_bytes,
        command.limits().max_output_bytes(),
    )?;
    check_limit(
        "execution_items",
        limits.max_execution_items,
        command.limits().max_items(),
    )?;
    ensure_unique(command.id(), "example", command.examples())?;
    ensure_unique(command.id(), "capability", command.capabilities())?;

    let mut command_text = command.id().as_str().len() + command.summary().as_str().len();
    command_text = checked_sum(
        command_text,
        command.description().map_or(0, |text| text.as_str().len()),
    );
    for example in command.examples() {
        command_text = checked_sum(command_text, example.as_str().len());
    }
    for capability in command.capabilities() {
        command_text = checked_sum(command_text, capability.as_str().len());
    }

    let grammar_stats = validate_grammar(command, limits)?;
    *total_nodes = checked_sum(*total_nodes, grammar_stats.nodes);
    check_limit(
        "total_grammar_nodes",
        limits.max_total_grammar_nodes,
        *total_nodes,
    )?;
    command_text = checked_sum(command_text, grammar_stats.text_bytes);

    validate_operation(command, schema, limits, &mut command_text)?;
    validate_presentation(command, schema, limits, &mut command_text)?;

    *total_text = checked_sum(*total_text, command_text);
    check_limit(
        "catalog_text_bytes",
        limits.max_catalog_text_bytes,
        *total_text,
    )
}

#[derive(Debug, Default)]
struct GrammarStats {
    nodes: usize,
    text_bytes: usize,
}

fn validate_grammar(
    command: &CommandSpec,
    limits: &CatalogLimits,
) -> Result<GrammarStats, CatalogError> {
    if command.grammar().nodes().is_empty() {
        return Err(CatalogError::InvalidGrammar {
            command: command.id().clone(),
            reason: "root sequence is empty",
        });
    }
    let mut stats = GrammarStats::default();
    validate_sequence(
        command.id(),
        command.grammar().nodes(),
        1,
        limits,
        &mut stats,
    )?;
    Ok(stats)
}

fn validate_sequence(
    command: &CommandId,
    nodes: &[GrammarNode],
    depth: usize,
    limits: &CatalogLimits,
    stats: &mut GrammarStats,
) -> Result<(), CatalogError> {
    if nodes.is_empty() {
        return Err(CatalogError::InvalidGrammar {
            command: command.clone(),
            reason: "nested sequence is empty",
        });
    }
    check_limit("grammar_depth", limits.max_grammar_depth, depth)?;
    check_limit("sequence_nodes", limits.max_sequence_nodes, nodes.len())?;

    for node in nodes {
        stats.nodes = checked_sum(stats.nodes, 1);
        match node {
            GrammarNode::Literal {
                token,
                aliases,
                help,
            } => {
                check_limit(
                    "aliases_per_literal",
                    limits.max_aliases_per_literal,
                    aliases.len(),
                )?;
                let mut seen = BTreeSet::new();
                seen.insert(token);
                if aliases.iter().any(|alias| !seen.insert(alias)) {
                    return Err(CatalogError::DuplicateValue {
                        command: command.clone(),
                        field: "literal alias",
                    });
                }
                stats.text_bytes = checked_sum(stats.text_bytes, token.as_str().len());
                stats.text_bytes = checked_sum(stats.text_bytes, help.as_str().len());
                for alias in aliases {
                    stats.text_bytes = checked_sum(stats.text_bytes, alias.as_str().len());
                }
            }
            GrammarNode::Argument {
                name,
                value,
                completion,
                ..
            } => {
                value.validate().map_err(|_| CatalogError::InvalidGrammar {
                    command: command.clone(),
                    reason: "argument value specification is invalid",
                })?;
                stats.text_bytes = checked_sum(stats.text_bytes, name.as_str().len());
                if let ValueSpec::Enumeration { values } = value {
                    check_limit(
                        "argument_enum_values",
                        limits.max_argument_enum_values,
                        values.len(),
                    )?;
                    ensure_unique(command, "enumeration value", values)?;
                    for value in values {
                        stats.text_bytes = checked_sum(stats.text_bytes, value.as_str().len());
                    }
                }
                if let CompletionSpec::Static(values) = completion {
                    check_limit(
                        "static_completion_values",
                        limits.max_static_completion_values,
                        values.len(),
                    )?;
                    ensure_unique(command, "completion value", values)?;
                    for value in values {
                        stats.text_bytes = checked_sum(stats.text_bytes, value.as_str().len());
                    }
                }
            }
            GrammarNode::Optional(sequence) => {
                validate_sequence(command, sequence, depth + 1, limits, stats)?;
            }
            GrammarNode::Choice(arms) => {
                check_limit("choice_arms", limits.max_choice_arms, arms.len())?;
                if arms.is_empty() {
                    return Err(CatalogError::InvalidGrammar {
                        command: command.clone(),
                        reason: "choice has no arms",
                    });
                }
                for arm in arms {
                    validate_sequence(command, arm, depth + 1, limits, stats)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_operation(
    command: &CommandSpec,
    schema: &dyn CommandSchema,
    limits: &CatalogLimits,
    text_bytes: &mut usize,
) -> Result<(), CatalogError> {
    match (command.effect(), command.operation()) {
        (EffectClass::Observe, OperationPlan::Get(read)) => {
            validate_read(command.id(), read, schema, limits, text_bytes)
        }
        (EffectClass::Observe, OperationPlan::Composite(composite)) => {
            if composite.reads().is_empty() {
                return Err(CatalogError::EmptyCollection {
                    command: command.id().clone(),
                    field: "composite read",
                });
            }
            check_limit(
                "composite_reads",
                limits.max_composite_reads,
                composite.reads().len(),
            )?;
            let total_paths = composite
                .reads()
                .iter()
                .fold(0usize, |sum, read| checked_sum(sum, read.paths().len()));
            check_limit(
                "paths_per_operation",
                limits.max_paths_per_operation,
                total_paths,
            )?;
            for read in composite.reads() {
                validate_read(command.id(), read, schema, limits, text_bytes)?;
            }
            Ok(())
        }
        (EffectClass::Monitor, OperationPlan::Subscribe(subscription)) => {
            validate_paths_nonempty(command.id(), subscription.paths())?;
            check_limit(
                "paths_per_operation",
                limits.max_paths_per_operation,
                subscription.paths().len(),
            )?;
            ensure_unique(command.id(), "subscription path", subscription.paths())?;
            for path in subscription.paths() {
                *text_bytes = checked_sum(*text_bytes, path.as_str().len());
                match schema.data_node_access(path) {
                    Some(DataNodeAccess::Operational) => {}
                    Some(DataNodeAccess::Configuration) => {
                        return Err(CatalogError::ReadSourceMismatch {
                            command: command.id().clone(),
                            path: path.clone(),
                        });
                    }
                    None => {
                        return Err(CatalogError::UnknownSchemaPath {
                            command: command.id().clone(),
                            path: path.clone(),
                        });
                    }
                }
            }
            Ok(())
        }
        (EffectClass::Probe | EffectClass::Operate, OperationPlan::Invoke(action)) => {
            *text_bytes = checked_sum(*text_bytes, action.path().as_str().len());
            let Some(contract) = schema.action_contract(action.path()) else {
                return Err(CatalogError::UnknownAction {
                    command: command.id().clone(),
                    path: action.path().clone(),
                });
            };
            validate_action_contract(command, action.path(), action.idempotency(), contract)
        }
        _ => Err(CatalogError::EffectOperationMismatch {
            command: command.id().clone(),
        }),
    }
}

fn validate_action_contract(
    command: &CommandSpec,
    path: &SchemaPath,
    idempotency: crate::ActionIdempotency,
    contract: ActionContract,
) -> Result<(), CatalogError> {
    if contract.effect() != command.effect() || contract.idempotency() != idempotency {
        return Err(CatalogError::ActionContractMismatch {
            command: command.id().clone(),
            path: path.clone(),
        });
    }
    Ok(())
}

fn validate_read(
    command: &CommandId,
    read: &ReadPlan,
    schema: &dyn CommandSchema,
    limits: &CatalogLimits,
    text_bytes: &mut usize,
) -> Result<(), CatalogError> {
    validate_paths_nonempty(command, read.paths())?;
    check_limit(
        "paths_per_operation",
        limits.max_paths_per_operation,
        read.paths().len(),
    )?;
    ensure_unique(command, "read path", read.paths())?;
    for path in read.paths() {
        *text_bytes = checked_sum(*text_bytes, path.as_str().len());
        let Some(access) = schema.data_node_access(path) else {
            return Err(CatalogError::UnknownSchemaPath {
                command: command.clone(),
                path: path.clone(),
            });
        };
        let matches = match read.source() {
            ReadSource::Operational => access == DataNodeAccess::Operational,
            ReadSource::RunningConfig => access == DataNodeAccess::Configuration,
            ReadSource::All => true,
        };
        if !matches {
            return Err(CatalogError::ReadSourceMismatch {
                command: command.clone(),
                path: path.clone(),
            });
        }
    }
    Ok(())
}

fn validate_presentation(
    command: &CommandSpec,
    schema: &dyn CommandSchema,
    limits: &CatalogLimits,
    text_bytes: &mut usize,
) -> Result<(), CatalogError> {
    let field_count = command.presentation().item_count();
    if field_count == 0 {
        return Err(CatalogError::EmptyCollection {
            command: command.id().clone(),
            field: "presentation field",
        });
    }
    check_limit(
        "presentation_fields",
        limits.max_presentation_fields,
        field_count,
    )?;
    let mut fields = BTreeSet::new();
    for field in command.presentation().fields() {
        if !fields.insert(field) {
            return Err(CatalogError::DuplicateValue {
                command: command.id().clone(),
                field: "presentation field",
            });
        }
        if !schema.result_field_exists(command.operation(), field) {
            return Err(CatalogError::UnknownResultField {
                command: command.id().clone(),
                field: field.clone(),
            });
        }
    }
    *text_bytes = checked_sum(*text_bytes, command.presentation().text_bytes());
    Ok(())
}

fn validate_paths_nonempty(command: &CommandId, paths: &[SchemaPath]) -> Result<(), CatalogError> {
    if paths.is_empty() {
        return Err(CatalogError::EmptyCollection {
            command: command.clone(),
            field: "operation path",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SyntaxAtom {
    Literal(BTreeSet<CommandToken>),
    Argument,
}

type ExpandedSyntax = Vec<SyntaxAtom>;

fn expand_grammar(
    command: &CommandSpec,
    limits: &CatalogLimits,
) -> Result<Vec<ExpandedSyntax>, CatalogError> {
    let expanded = expand_sequence(command.id(), command.grammar().nodes(), limits)?;
    check_limit(
        "expanded_syntaxes_per_command",
        limits.max_expanded_syntaxes_per_command,
        expanded.len(),
    )?;
    for syntax in &expanded {
        if syntax.is_empty() {
            return Err(CatalogError::InvalidGrammar {
                command: command.id().clone(),
                reason: "grammar expands to an empty command",
            });
        }
        if !matches!(syntax.first(), Some(SyntaxAtom::Literal(_))) {
            return Err(CatalogError::InvalidGrammar {
                command: command.id().clone(),
                reason: "command must begin with a literal",
            });
        }
    }
    Ok(expanded)
}

fn expand_sequence(
    command: &CommandId,
    nodes: &[GrammarNode],
    limits: &CatalogLimits,
) -> Result<Vec<ExpandedSyntax>, CatalogError> {
    let mut prefixes = vec![Vec::new()];
    for node in nodes {
        let suffixes = expand_node(command, node, limits)?;
        prefixes = product(command, prefixes, suffixes, limits)?;
    }
    Ok(prefixes)
}

fn expand_node(
    command: &CommandId,
    node: &GrammarNode,
    limits: &CatalogLimits,
) -> Result<Vec<ExpandedSyntax>, CatalogError> {
    match node {
        GrammarNode::Literal { token, aliases, .. } => {
            let mut values = BTreeSet::new();
            values.insert(token.clone());
            values.extend(aliases.iter().cloned());
            Ok(vec![vec![SyntaxAtom::Literal(values)]])
        }
        GrammarNode::Argument { .. } => Ok(vec![vec![SyntaxAtom::Argument]]),
        GrammarNode::Optional(nodes) => {
            let mut expanded = vec![Vec::new()];
            expanded.extend(expand_sequence(command, nodes, limits)?);
            check_limit(
                "expanded_syntaxes_per_command",
                limits.max_expanded_syntaxes_per_command,
                expanded.len(),
            )?;
            Ok(expanded)
        }
        GrammarNode::Choice(arms) => {
            let mut expanded = Vec::new();
            for arm in arms {
                expanded.extend(expand_sequence(command, arm, limits)?);
                check_limit(
                    "expanded_syntaxes_per_command",
                    limits.max_expanded_syntaxes_per_command,
                    expanded.len(),
                )?;
            }
            Ok(expanded)
        }
    }
}

fn product(
    command: &CommandId,
    prefixes: Vec<ExpandedSyntax>,
    suffixes: Vec<ExpandedSyntax>,
    limits: &CatalogLimits,
) -> Result<Vec<ExpandedSyntax>, CatalogError> {
    let count = prefixes.len().saturating_mul(suffixes.len());
    check_limit(
        "expanded_syntaxes_per_command",
        limits.max_expanded_syntaxes_per_command,
        count,
    )?;
    let mut out = Vec::with_capacity(count);
    for prefix in &prefixes {
        for suffix in &suffixes {
            let len = prefix.len().saturating_add(suffix.len());
            check_limit("sequence_nodes", limits.max_sequence_nodes, len)?;
            let mut syntax = prefix.clone();
            syntax.extend(suffix.iter().cloned());
            out.push(syntax);
        }
    }
    if out.is_empty() {
        return Err(CatalogError::InvalidGrammar {
            command: command.clone(),
            reason: "grammar expansion is empty",
        });
    }
    Ok(out)
}

fn validate_internal_ambiguity(
    command: &CommandId,
    syntaxes: &[ExpandedSyntax],
) -> Result<(), CatalogError> {
    for (index, syntax) in syntaxes.iter().enumerate() {
        if syntaxes[..index]
            .iter()
            .any(|candidate| syntaxes_overlap(candidate, syntax))
        {
            return Err(CatalogError::InvalidGrammar {
                command: command.clone(),
                reason: "alternatives overlap",
            });
        }
    }
    Ok(())
}

fn syntaxes_overlap(left: &ExpandedSyntax, right: &ExpandedSyntax) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| match (left, right) {
                (SyntaxAtom::Literal(left), SyntaxAtom::Literal(right)) => {
                    left.iter().any(|token| right.contains(token))
                }
                (SyntaxAtom::Argument, SyntaxAtom::Argument) => true,
                // Literal-first parsing makes a keyword more specific than an argument.
                (SyntaxAtom::Literal(_), SyntaxAtom::Argument)
                | (SyntaxAtom::Argument, SyntaxAtom::Literal(_)) => false,
            })
}

fn ensure_unique<T: Ord>(
    command: &CommandId,
    field: &'static str,
    values: &[T],
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(CatalogError::DuplicateValue {
            command: command.clone(),
            field,
        });
    }
    Ok(())
}

fn check_limit(limit: &'static str, max: usize, actual: usize) -> Result<(), CatalogError> {
    if actual > max {
        return Err(CatalogError::LimitExceeded { limit, max, actual });
    }
    Ok(())
}

fn checked_sum(left: usize, right: usize) -> usize {
    left.saturating_add(right)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use super::*;
    use crate::{
        ActionIdempotency, ActionPlan, ArgumentName, ColumnSpec, ModelError, SubscribePlan,
        TableSpec,
    };

    #[derive(Default)]
    struct FakeSchema {
        nodes: BTreeMap<SchemaPath, DataNodeAccess>,
        actions: BTreeMap<SchemaPath, ActionContract>,
        fields: BTreeSet<SchemaPath>,
    }

    impl CommandSchema for FakeSchema {
        fn data_node_access(&self, path: &SchemaPath) -> Option<DataNodeAccess> {
            self.nodes.get(path).copied()
        }

        fn action_contract(&self, path: &SchemaPath) -> Option<ActionContract> {
            self.actions.get(path).copied()
        }

        fn result_field_exists(&self, _operation: &OperationPlan, field: &SchemaPath) -> bool {
            self.fields.contains(field)
        }
    }

    fn path(value: &str) -> SchemaPath {
        SchemaPath::new(value).expect("test schema path")
    }

    fn token(value: &str) -> CommandToken {
        CommandToken::new(value).expect("test command token")
    }

    fn help(value: &str) -> HelpText {
        HelpText::new(value).expect("test help")
    }

    fn limits() -> ExecutionLimits {
        ExecutionLimits::new(Duration::from_secs(5), 1024 * 1024, 1024).expect("test limits")
    }

    fn grammar(second: GrammarNode) -> CommandGrammar {
        CommandGrammar::new([
            GrammarNode::literal(token("show"), help("Display state")),
            second,
        ])
    }

    fn read_command(id: &str, second: GrammarNode, read_path: SchemaPath) -> CommandSpec {
        CommandSpec::new(
            CommandId::new(id).expect("test command id"),
            CommandVersion::new(1).expect("test version"),
            grammar(second),
            help("Display state"),
            EffectClass::Observe,
            OperationPlan::Get(ReadPlan::new(ReadSource::Operational, [read_path.clone()])),
            PresentationSpec::Table(TableSpec::new([ColumnSpec::new(help("State"), read_path)])),
            limits(),
        )
    }

    #[test]
    fn freezes_valid_catalog_in_command_id_order() {
        let health = path("/sys:state/sys:health");
        let peers = path("/sys:state/sys:peers");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(health.clone(), DataNodeAccess::Operational);
        schema
            .nodes
            .insert(peers.clone(), DataNodeAccess::Operational);
        schema.fields.extend([health.clone(), peers.clone()]);

        let mut registry = CommandRegistry::new();
        registry
            .register(read_command(
                "opc.show-peers",
                GrammarNode::literal(token("peers"), help("Peers")),
                peers,
            ))
            .expect("register peers");
        registry
            .register(read_command(
                "opc.show-health",
                GrammarNode::literal(token("health"), help("Health")),
                health,
            ))
            .expect("register health");

        let catalog = registry
            .freeze(&schema, CatalogLimits::default())
            .expect("freeze catalog");
        let ids: Vec<&str> = catalog
            .commands()
            .iter()
            .map(|command| command.id().as_str())
            .collect();
        assert_eq!(ids, ["opc.show-health", "opc.show-peers"]);
    }

    #[test]
    fn duplicate_id_is_rejected_at_registration() {
        let health = path("/sys:state/sys:health");
        let command = read_command(
            "opc.show-health",
            GrammarNode::literal(token("health"), help("Health")),
            health,
        );
        let mut registry = CommandRegistry::new();
        registry
            .register(command.clone())
            .expect("first registration");
        assert!(matches!(
            registry.register(command),
            Err(CatalogError::DuplicateCommand(_))
        ));
    }

    #[test]
    fn ambiguous_argument_syntax_is_rejected() {
        let state = path("/sys:state/sys:peer");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(state.clone(), DataNodeAccess::Operational);
        schema.fields.insert(state.clone());

        let argument = || {
            GrammarNode::argument(
                ArgumentName::new("peer").expect("argument"),
                ValueSpec::Text { max_bytes: 64 },
            )
        };
        let mut registry = CommandRegistry::new();
        registry
            .register(read_command("opc.show-peer", argument(), state.clone()))
            .expect("first registration");
        registry
            .register(read_command("epdg.show-peer", argument(), state))
            .expect("second registration");

        assert!(matches!(
            registry.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::AmbiguousSyntax { .. })
        ));
    }

    #[test]
    fn aliases_participate_in_ambiguity_detection() {
        let health = path("/sys:state/sys:health");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(health.clone(), DataNodeAccess::Operational);
        schema.fields.insert(health.clone());

        let mut registry = CommandRegistry::new();
        registry
            .register(read_command(
                "opc.show-health",
                GrammarNode::literal_with_aliases(
                    token("health"),
                    [token("status")],
                    help("Health"),
                ),
                health.clone(),
            ))
            .expect("health registration");
        registry
            .register(read_command(
                "opc.show-status",
                GrammarNode::literal(token("status"), help("Status")),
                health,
            ))
            .expect("status registration");

        assert!(matches!(
            registry.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::AmbiguousSyntax { .. })
        ));
    }

    #[test]
    fn unknown_and_mismatched_read_paths_fail_closed() {
        let config = path("/sys:config/sys:name");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(config.clone(), DataNodeAccess::Configuration);
        schema.fields.insert(config.clone());

        let mut mismatch = CommandRegistry::new();
        mismatch
            .register(read_command(
                "opc.show-name",
                GrammarNode::literal(token("name"), help("Name")),
                config,
            ))
            .expect("registration");
        assert!(matches!(
            mismatch.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::ReadSourceMismatch { .. })
        ));

        let unknown = path("/sys:state/sys:missing");
        let mut absent = CommandRegistry::new();
        absent
            .register(read_command(
                "opc.show-missing",
                GrammarNode::literal(token("missing"), help("Missing")),
                unknown,
            ))
            .expect("registration");
        assert!(matches!(
            absent.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::UnknownSchemaPath { .. })
        ));
    }

    #[test]
    fn actions_require_matching_server_contract() {
        let action_path = path("/epdg:diagnostics/epdg:ping");
        let result = path("/epdg:diagnostics/epdg:ping/epdg:result");
        let command = CommandSpec::new(
            CommandId::new("epdg.diagnose-ping").expect("id"),
            CommandVersion::new(1).expect("version"),
            CommandGrammar::new([
                GrammarNode::literal(token("diagnose"), help("Diagnostics")),
                GrammarNode::literal(token("ping"), help("Ping")),
            ]),
            help("Run a bounded ping"),
            EffectClass::Probe,
            OperationPlan::Invoke(ActionPlan::new(
                action_path.clone(),
                ActionIdempotency::NonIdempotent,
            )),
            PresentationSpec::Table(TableSpec::new([ColumnSpec::new(
                help("Result"),
                result.clone(),
            )])),
            limits(),
        );

        let mut missing = CommandRegistry::new();
        missing.register(command.clone()).expect("registration");
        assert!(matches!(
            missing.freeze(&FakeSchema::default(), CatalogLimits::default()),
            Err(CatalogError::UnknownAction { .. })
        ));

        let mut schema = FakeSchema::default();
        schema.actions.insert(
            action_path,
            ActionContract::new(EffectClass::Operate, ActionIdempotency::NonIdempotent),
        );
        schema.fields.insert(result);
        let mut mismatch = CommandRegistry::new();
        mismatch.register(command).expect("registration");
        assert!(matches!(
            mismatch.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::ActionContractMismatch { .. })
        ));
    }

    #[test]
    fn subscription_rejects_config_nodes() {
        let config = path("/sys:config/sys:name");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(config.clone(), DataNodeAccess::Configuration);
        schema.fields.insert(config.clone());
        let command = CommandSpec::new(
            CommandId::new("opc.monitor-name").expect("id"),
            CommandVersion::new(1).expect("version"),
            CommandGrammar::new([
                GrammarNode::literal(token("monitor"), help("Monitor")),
                GrammarNode::literal(token("name"), help("Name")),
            ]),
            help("Monitor name"),
            EffectClass::Monitor,
            OperationPlan::Subscribe(SubscribePlan::new([config.clone()])),
            PresentationSpec::Table(TableSpec::new([ColumnSpec::new(help("Name"), config)])),
            limits(),
        );
        let mut registry = CommandRegistry::new();
        registry.register(command).expect("registration");
        assert!(matches!(
            registry.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::ReadSourceMismatch { .. })
        ));
    }

    #[test]
    fn grammar_expansion_is_bounded_before_allocation() {
        let health = path("/sys:state/sys:health");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(health.clone(), DataNodeAccess::Operational);
        schema.fields.insert(health.clone());
        let optional_nodes = (0..8).map(|_| {
            GrammarNode::optional([GrammarNode::literal(token("detail"), help("Detail"))])
        });
        let mut nodes = vec![GrammarNode::literal(token("show"), help("Show"))];
        nodes.extend(optional_nodes);
        let command = CommandSpec::new(
            CommandId::new("opc.show-health").expect("id"),
            CommandVersion::new(1).expect("version"),
            CommandGrammar::new(nodes),
            help("Health"),
            EffectClass::Observe,
            OperationPlan::Get(ReadPlan::new(ReadSource::Operational, [health.clone()])),
            PresentationSpec::Table(TableSpec::new([ColumnSpec::new(help("Health"), health)])),
            limits(),
        );
        let mut registry = CommandRegistry::new();
        registry.register(command).expect("registration");
        let catalog_limits = CatalogLimits {
            max_expanded_syntaxes_per_command: 64,
            ..CatalogLimits::default()
        };
        assert!(matches!(
            registry.freeze(&schema, catalog_limits),
            Err(CatalogError::LimitExceeded {
                limit: "expanded_syntaxes_per_command",
                ..
            })
        ));
    }

    #[test]
    fn zero_catalog_limit_is_rejected() {
        let catalog_limits = CatalogLimits {
            max_commands: 0,
            ..CatalogLimits::default()
        };
        assert!(matches!(
            CommandRegistry::new().freeze(&FakeSchema::default(), catalog_limits),
            Err(CatalogError::ZeroLimit { limit: "commands" })
        ));
    }

    #[test]
    fn catalog_caps_argument_enums_and_execution_output() {
        let state = path("/sys:state/sys:peer");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(state.clone(), DataNodeAccess::Operational);
        schema.fields.insert(state.clone());

        let enum_argument = GrammarNode::argument(
            ArgumentName::new("state").expect("argument"),
            ValueSpec::Enumeration {
                values: ["up", "down", "unknown"]
                    .into_iter()
                    .map(|value| crate::ArgumentValue::new(value).expect("enum value"))
                    .collect(),
            },
        );
        let mut enum_registry = CommandRegistry::new();
        enum_registry
            .register(read_command("opc.show-peer", enum_argument, state.clone()))
            .expect("registration");
        let catalog_limits = CatalogLimits {
            max_argument_enum_values: 2,
            ..CatalogLimits::default()
        };
        assert!(matches!(
            enum_registry.freeze(&schema, catalog_limits),
            Err(CatalogError::LimitExceeded {
                limit: "argument_enum_values",
                ..
            })
        ));

        let command = CommandSpec::new(
            CommandId::new("opc.show-state").expect("id"),
            CommandVersion::new(1).expect("version"),
            grammar(GrammarNode::literal(token("state"), help("State"))),
            help("Display state"),
            EffectClass::Observe,
            OperationPlan::Get(ReadPlan::new(ReadSource::Operational, [state.clone()])),
            PresentationSpec::Table(TableSpec::new([ColumnSpec::new(help("State"), state)])),
            ExecutionLimits::new(Duration::from_secs(5), 4096, 10).expect("execution limits"),
        );
        let mut output_registry = CommandRegistry::new();
        output_registry.register(command).expect("registration");
        let output_limits = CatalogLimits {
            max_execution_output_bytes: 1024,
            ..CatalogLimits::default()
        };
        assert!(matches!(
            output_registry.freeze(&schema, output_limits),
            Err(CatalogError::LimitExceeded {
                limit: "execution_output_bytes",
                ..
            })
        ));
    }

    #[test]
    fn presentation_fields_must_exist_in_result_schema() {
        let health = path("/sys:state/sys:health");
        let mut schema = FakeSchema::default();
        schema
            .nodes
            .insert(health.clone(), DataNodeAccess::Operational);
        let mut registry = CommandRegistry::new();
        registry
            .register(read_command(
                "opc.show-health",
                GrammarNode::literal(token("health"), help("Health")),
                health,
            ))
            .expect("registration");
        assert!(matches!(
            registry.freeze(&schema, CatalogLimits::default()),
            Err(CatalogError::UnknownResultField { .. })
        ));
    }

    #[test]
    fn execution_limits_reject_zero_values() {
        assert_eq!(
            ExecutionLimits::new(Duration::ZERO, 1, 1),
            Err(ModelError::Zero {
                field: "execution_deadline"
            })
        );
    }
}
