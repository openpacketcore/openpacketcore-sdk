use std::time::Duration;

use crate::CatalogError;

/// Hard bounds for command registration and grammar expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogLimits {
    /// Maximum commands in one principal-visible catalog.
    pub max_commands: usize,
    /// Maximum UTF-8 bytes across IDs, help, tokens, paths, and presentation.
    pub max_catalog_text_bytes: usize,
    /// Maximum total grammar nodes across the catalog.
    pub max_total_grammar_nodes: usize,
    /// Maximum nested optional/choice depth.
    pub max_grammar_depth: usize,
    /// Maximum nodes in one grammar sequence.
    pub max_sequence_nodes: usize,
    /// Maximum arms in one choice.
    pub max_choice_arms: usize,
    /// Maximum aliases for one literal.
    pub max_aliases_per_literal: usize,
    /// Maximum static completion values for one argument.
    pub max_static_completion_values: usize,
    /// Maximum enum values in one argument type.
    pub max_argument_enum_values: usize,
    /// Maximum examples on one command.
    pub max_examples_per_command: usize,
    /// Maximum required capability IDs on one command.
    pub max_capabilities_per_command: usize,
    /// Maximum paths across one operation plan.
    pub max_paths_per_operation: usize,
    /// Maximum read plans in one composite operation.
    pub max_composite_reads: usize,
    /// Maximum fields/columns in one presentation.
    pub max_presentation_fields: usize,
    /// Maximum expanded syntax alternatives per command.
    pub max_expanded_syntaxes_per_command: usize,
    /// Maximum declared command deadline accepted from a catalog.
    pub max_execution_deadline: Duration,
    /// Maximum declared encoded output bytes.
    pub max_execution_output_bytes: usize,
    /// Maximum declared result items.
    pub max_execution_items: usize,
}

impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_commands: 512,
            max_catalog_text_bytes: 1024 * 1024,
            max_total_grammar_nodes: 8192,
            max_grammar_depth: 16,
            max_sequence_nodes: 64,
            max_choice_arms: 32,
            max_aliases_per_literal: 8,
            max_static_completion_values: 128,
            max_argument_enum_values: 256,
            max_examples_per_command: 16,
            max_capabilities_per_command: 64,
            max_paths_per_operation: 64,
            max_composite_reads: 16,
            max_presentation_fields: 64,
            max_expanded_syntaxes_per_command: 128,
            max_execution_deadline: Duration::from_secs(5 * 60),
            max_execution_output_bytes: 16 * 1024 * 1024,
            max_execution_items: 100_000,
        }
    }
}

impl CatalogLimits {
    pub(crate) fn validate(&self) -> Result<(), CatalogError> {
        let limits = [
            ("commands", self.max_commands),
            ("catalog_text_bytes", self.max_catalog_text_bytes),
            ("total_grammar_nodes", self.max_total_grammar_nodes),
            ("grammar_depth", self.max_grammar_depth),
            ("sequence_nodes", self.max_sequence_nodes),
            ("choice_arms", self.max_choice_arms),
            ("aliases_per_literal", self.max_aliases_per_literal),
            (
                "static_completion_values",
                self.max_static_completion_values,
            ),
            ("argument_enum_values", self.max_argument_enum_values),
            ("examples_per_command", self.max_examples_per_command),
            (
                "capabilities_per_command",
                self.max_capabilities_per_command,
            ),
            ("paths_per_operation", self.max_paths_per_operation),
            ("composite_reads", self.max_composite_reads),
            ("presentation_fields", self.max_presentation_fields),
            (
                "expanded_syntaxes_per_command",
                self.max_expanded_syntaxes_per_command,
            ),
            (
                "execution_deadline_millis",
                usize::try_from(self.max_execution_deadline.as_millis()).unwrap_or(usize::MAX),
            ),
            ("execution_output_bytes", self.max_execution_output_bytes),
            ("execution_items", self.max_execution_items),
        ];
        for (limit, value) in limits {
            if value == 0 {
                return Err(CatalogError::ZeroLimit { limit });
            }
        }
        Ok(())
    }
}
