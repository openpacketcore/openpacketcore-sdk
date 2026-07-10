use thiserror::Error;

use crate::{CommandId, SchemaPath};

/// Failure constructing one lexical command-model value.
///
/// Errors describe only public catalog structure. They never include runtime
/// argument values or management payloads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ModelError {
    /// A required value was empty.
    #[error("command model value '{field}' must not be empty")]
    Empty {
        /// Stable field name.
        field: &'static str,
    },
    /// A value exceeded its hard lexical bound.
    #[error("command model value '{field}' exceeds {max} bytes")]
    TooLong {
        /// Stable field name.
        field: &'static str,
        /// Hard maximum.
        max: usize,
    },
    /// A value contained an invalid character or structure.
    #[error("command model value '{field}' is malformed")]
    Malformed {
        /// Stable field name.
        field: &'static str,
    },
    /// A version or configured execution limit was zero.
    #[error("command model value '{field}' must be greater than zero")]
    Zero {
        /// Stable field name.
        field: &'static str,
    },
    /// A closed range was inverted.
    #[error("command model range '{field}' is inverted")]
    InvertedRange {
        /// Stable field name.
        field: &'static str,
    },
}

/// Failure registering or freezing a command catalog.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CatalogError {
    /// The same stable command ID was registered twice.
    #[error("duplicate command id '{0}'")]
    DuplicateCommand(CommandId),
    /// Two commands expand to the same parse shape.
    #[error("commands '{first}' and '{second}' have ambiguous syntax")]
    AmbiguousSyntax {
        /// Earlier command.
        first: CommandId,
        /// Conflicting command.
        second: CommandId,
    },
    /// One command's grammar was invalid.
    #[error("command '{command}' has invalid grammar: {reason}")]
    InvalidGrammar {
        /// Stable command ID.
        command: CommandId,
        /// Payload-free structural reason.
        reason: &'static str,
    },
    /// A configurable catalog bound was zero.
    #[error("catalog limit '{limit}' must be greater than zero")]
    ZeroLimit {
        /// Stable limit name.
        limit: &'static str,
    },
    /// One catalog bound was exceeded.
    #[error("catalog limit '{limit}' exceeded: {actual} > {max}")]
    LimitExceeded {
        /// Stable limit name.
        limit: &'static str,
        /// Configured maximum.
        max: usize,
        /// Observed amount.
        actual: usize,
    },
    /// The effect class and operation primitive were inconsistent.
    #[error("command '{command}' effect does not match its operation")]
    EffectOperationMismatch {
        /// Stable command ID.
        command: CommandId,
    },
    /// A referenced data node was unknown.
    #[error("command '{command}' references an unknown schema path '{path}'")]
    UnknownSchemaPath {
        /// Stable command ID.
        command: CommandId,
        /// Predicate-free schema path, never an instance path.
        path: SchemaPath,
    },
    /// A read source did not match the schema node's config/state class.
    #[error("command '{command}' read source does not match schema path '{path}'")]
    ReadSourceMismatch {
        /// Stable command ID.
        command: CommandId,
        /// Predicate-free schema path.
        path: SchemaPath,
    },
    /// The server-side action allowlist did not contain the action.
    #[error("command '{command}' references an unregistered action '{path}'")]
    UnknownAction {
        /// Stable command ID.
        command: CommandId,
        /// Static action path.
        path: SchemaPath,
    },
    /// Catalog effect/idempotency metadata did not match the server allowlist.
    #[error("command '{command}' action contract mismatch for '{path}'")]
    ActionContractMismatch {
        /// Stable command ID.
        command: CommandId,
        /// Static action path.
        path: SchemaPath,
    },
    /// A presentation referenced a field absent from the operation result.
    #[error("command '{command}' references an unknown result field '{field}'")]
    UnknownResultField {
        /// Stable command ID.
        command: CommandId,
        /// Static result schema field.
        field: SchemaPath,
    },
    /// A list that must be non-empty was empty.
    #[error("command '{command}' requires at least one {field}")]
    EmptyCollection {
        /// Stable command ID.
        command: CommandId,
        /// Stable collection name.
        field: &'static str,
    },
    /// Two values that must be unique collided.
    #[error("command '{command}' contains duplicate {field}")]
    DuplicateValue {
        /// Stable command ID.
        command: CommandId,
        /// Stable collection name.
        field: &'static str,
    },
}
