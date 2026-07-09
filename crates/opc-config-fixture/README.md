# opc-config-fixture

Toy `OpcConfig` implementation for tests and examples.

This crate provides a generated-like config model used by integration tests,
examples, and management-stack smoke tests. It is intentionally small and should
not be used as a production CNF schema.

## API Shape

Public API:

- `ToyConfig`, the fixture config model.
- `ToyDelta`, the applied-change metadata used for diffing and validation.
- `ToyFieldClassification`, the field-level impact classifier.

Example:

```rust
use opc_config_fixture::ToyConfig;
use opc_config_model::OpcConfig;

let config = ToyConfig::new("node-a");
config.validate_syntax()?;
```

`ToyConfig` fields are private. Build initial values through constructors and
derive candidates with `ToyConfig::from_previous(previous, deltas)` so diff and
validation metadata stays accurate.

Secrets such as admin password and TLS PSK use redacted types. Semantic
validation uses the recorded deltas to require `security-admin` authority for
secret changes, while startup recovery remains exempt.

## Relationships

- Implements `opc-config-model::OpcConfig`.
- Used by config-bus, gNMI, NETCONF, NACM, and SDK integration tests.
- Mirrors patterns generated CNF config crates are expected to follow.

## Status And Limits

Current scope:

- Fixture-only config model with deterministic schema digest.
- Diff, changed-path, validation, and impact-classification behavior useful for
  tests.

Limitations:

- Not generated from YANG.
- Not a complete CNF config model.
- Cloning clears applied-delta metadata by design.

## Roadmap

- Keep this crate focused on stable test coverage for config-management APIs.
- Do not add production behavior here.

## Verification

Run:

```sh
cargo test -p opc-config-fixture
```
