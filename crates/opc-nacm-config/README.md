# opc-nacm-config

Operator-facing NACM configuration model.

This crate models `/nacm:nacm`, validates rule lists and groups, compiles them
into `opc-nacm` policies, and maps matching groups into signed management
principal grants. It is also an `OpcConfig` model for standalone NACM config.

## API Shape

Public API:

- Config model:
  `NacmConfig`, `NacmConfigDelta`, `NacmGroup`,
  `SpiffeWorkloadSelector`, `NacmConfigRuleList`, and `NacmConfigRule`.
- Rule fields:
  `NacmAccessOperation` and `NacmConfigEffect`.
- Errors and schema:
  `NacmConfigError` and `schema_registry`.
- Trait implementations:
  `OpcConfig` and `SignedGrantSource`.

Example imports:

```rust
use opc_nacm_config::{schema_registry, NacmConfig};
use opc_mgmt_principal::SignedGrantSource;
```

`enabled = false` compiles to an empty deny-all policy. It is fail-closed and
does not bypass authorization.

## Relationships

- Compiles to `opc-nacm::NacmPolicy`.
- Implements `opc_config_model::OpcConfig`.
- Implements `opc_mgmt_principal::SignedGrantSource` for group grants.
- Used by management authorization layers through active policy sources.

## Status And Limits

Current scope:

- Full-replace config delta at `/nacm:nacm`.
- Group membership by exact user name and SPIFFE workload selectors.
- Rule-list validation with required groups, non-empty rules, unique names, and
  explicit allow/deny effects.
- Static schema registry for the standalone NACM model.

Important behavior:

- SPIFFE workload selectors require tenant consistency between the principal and
  identity path.
- Rule paths drive module registration for the compiled policy, along with
  built-in modules. Arbitrary external schema-registry integration is not
  provided here.

## Roadmap

- Keep NACM config fail-closed.
- Add external schema integration only through a clear registry contract.

## Verification

Run:

```sh
cargo test -p opc-nacm-config
```
