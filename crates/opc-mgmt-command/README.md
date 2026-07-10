# opc-mgmt-command

Transport-neutral operational command catalog contracts.

This crate is the pure domain foundation for RFC 014. CNFs register bounded,
declarative commands that map operator-friendly grammar onto state reads,
subscriptions, or allowlisted typed actions. A registry freezes only after its
grammar, resource limits, schema paths, action contracts, and presentation
fields validate.

## API Shape

Core exports:

- `CommandSpec`, `CommandId`, `CommandVersion`, `EffectClass`, and
  `CommandGrammar`.
- `GrammarNode`, `ValueSpec`, `CompletionSpec`, and argument sensitivity
  metadata.
- `OperationPlan`, `ReadPlan`, `SubscribePlan`, `ActionPlan`, and
  `ExecutionLimits`.
- `PresentationSpec`, `TableSpec`, `ColumnSpec`, and structured field
  projections.
- `CommandRegistry`, `CatalogLimits`, and `ValidatedCommandCatalog`.
- `CommandSchema`, the port used during freeze to validate data paths, result
  fields, and the server-side action allowlist.

Example:

```rust
use std::time::Duration;

use opc_mgmt_command::{
    CatalogLimits, ColumnSpec, CommandGrammar, CommandId, CommandRegistry,
    CommandSpec, CommandToken, CommandVersion, EffectClass, ExecutionLimits,
    GrammarNode, HelpText, OperationPlan, PresentationSpec, ReadPlan, ReadSource,
    SchemaPath, TableSpec,
};

# fn example(schema: &dyn opc_mgmt_command::CommandSchema) -> Result<(), Box<dyn std::error::Error>> {
let grammar = CommandGrammar::new([
    GrammarNode::literal(CommandToken::new("show")?, HelpText::new("Display state")?),
    GrammarNode::literal(CommandToken::new("health")?, HelpText::new("CNF health")?),
]);
let path = SchemaPath::new("/opc-runtime:runtime/opc-runtime:health")?;
let command = CommandSpec::new(
    CommandId::new("opc.show-health")?,
    CommandVersion::new(1)?,
    grammar,
    HelpText::new("Display CNF health")?,
    EffectClass::Observe,
    OperationPlan::Get(ReadPlan::new(ReadSource::Operational, [path.clone()])),
    PresentationSpec::Table(TableSpec::new([ColumnSpec::new(
        HelpText::new("Health")?,
        path,
    )])),
    ExecutionLimits::new(Duration::from_secs(5), 1024 * 1024, 1024)?,
);

let mut registry = CommandRegistry::new();
registry.register(command)?;
let catalog = registry.freeze(schema, CatalogLimits::default())?;
assert_eq!(catalog.commands().len(), 1);
# Ok(())
# }
```

## Relationships

- Implements the command/catalog domain described by RFC 014.
- Future gNMI and NETCONF catalog adapters consume
  `ValidatedCommandCatalog`.
- CNF schema adapters implement `CommandSchema`; this crate does not depend on
  protobuf, XML, terminal, OAuth, or async runtimes.

## Status And Limits

Current scope:

- Pure catalog domain types and lexical newtypes.
- Bounded grammar traversal and expansion.
- Duplicate/ambiguous syntax detection with literal-first parsing semantics.
- Read/subscription schema validation and server action-contract validation.
- Presentation field validation and immutable deterministic catalog freeze.

Not yet implemented:

- Catalog wire encoding or the well-known YANG projection.
- Argument-to-operation bindings.
- Interactive parsing, help, completion, or terminal rendering.
- gNMI/NETCONF client adapters.

## Verification

Run:

```sh
cargo test -p opc-mgmt-command
```
