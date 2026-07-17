# opc-config-model

Shared configuration model contracts for OpenPacketCore CNFs.

This crate contains pure data types and traits used by the config subsystem. It
does not provide a datastore, commit worker, management protocol server, or
generated CNF model.

## API Shape

Core exports:

- Identity and request context: `WorkloadIdentity`, `TrustedPrincipal`,
  `AuthStrength`, `TransportType`, and `RequestSource`.
- Request types: `ConfigOperation`, `CommitMode`, `RollbackTarget`,
  `RequestId`, `IdempotencyKey`, and `YangPath`.
- Commit results and failures: `CommitStatus`, `CommitErrorCode`,
  `CommitError`, and `ConfigError`.
- Validation contracts: `ValidationStage`, `ValidationError`, and
  `ValidationContext`.
- `OpcConfig`, the trait implemented by generated or hand-written CNF config
  models.
- `CommitRequest<C>` and `CommitResult`.
- Apply-plan support: `ApplyPlan`, `ApplyPlanChange`, `ApplyPlanWarning`,
  `ApplyPlanError`, `ChangeImpact`, `ChangeImpactClass`,
  `ConfigImpactClassifier`, `HotConfigImpactClassifier`, and
  `ConfigWorkflowRequirement`.

Example imports:

```rust
use opc_config_model::{CommitRequest, OpcConfig, RequestSource};
```

`OpcConfig` implementors provide schema identity, syntax and semantic
validation, diff/changed-path reporting, and candidate application. Optional
`admission_payload_size_bytes` support lets the config bus reject oversized
requests before expensive work.

## Relationships

- Implemented by generated CNF config types from `opc-yanggen` or by fixtures.
- Consumed by `opc-config-bus` for commit processing.
- Referenced by management protocol crates, authorization adapters, and
  operational-state projections.

## Status And Limits

Current scope:

- Stable contracts and shared enums for config operations.
- Redaction-friendly validation and commit errors.
- Apply-plan impact classification for hot, warm, drain-required,
  restart-required, and forbidden-live changes.

Important behavior:

- `ForbiddenLive` changes normalize to hard errors.
- `DrainRequired` and `RestartRequired` changes block traffic until an external
  workflow completes.
- `CommitResult::committed_revision` defaults to `None` when deserializing
  older payloads. Downstream Rust struct literals must add
  `committed_revision: None` (or preserve the returned revision) when upgrading.

## Roadmap

- Keep this crate free of storage and transport dependencies.
- Add new shared config concepts here only when multiple subsystems require the
  same contract.

## Verification

Run:

```sh
cargo test -p opc-config-model
```
