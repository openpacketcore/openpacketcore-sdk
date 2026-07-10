//! Transport-neutral operational command catalog contracts.
//!
//! This crate owns the pure RFC 014 command domain. It deliberately has no
//! transport, terminal, OAuth, runtime, config-bus, or persistence dependency.
//! CNFs describe commands here; adapters later project a validated catalog to
//! gNMI/NETCONF and consume it in the interactive console.
//!
//! Configuration mutation is absent from [`OperationPlan`] by construction.
//! Typed actions must also exist in the server-side allowlist exposed through
//! [`CommandSchema::action_contract`] before a registry can freeze.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod grammar;
mod limits;
mod model;
mod operation;
mod presentation;
mod registry;
mod schema;

pub use error::{CatalogError, ModelError};
pub use grammar::{ArgumentSensitivity, CompletionSpec, GrammarNode, ValueSpec};
pub use limits::CatalogLimits;
pub use model::{
    ArgumentName, ArgumentValue, CapabilityId, CommandId, CommandToken, CommandVersion, HelpText,
    SchemaPath,
};
pub use operation::{
    ActionIdempotency, ActionPlan, CompositeReadPlan, EffectClass, ExecutionLimits, OperationPlan,
    ReadPlan, ReadSource, SubscribePlan,
};
pub use presentation::{
    ColumnSpec, DetailSpec, EventStreamSpec, PresentationSpec, ScalarSpec, TableSpec, TreeSpec,
};
pub use registry::{CommandGrammar, CommandRegistry, CommandSpec, ValidatedCommandCatalog};
pub use schema::{ActionContract, CommandSchema, DataNodeAccess};
