# opc-sdk

Feature-gated facade for common OpenPacketCore SDK crates.

This crate re-exports the high-level runtime, observability, config, session,
SBI, alarm, identity, key, crypto, TLS, NACM-config, and shared-type crates used
by CNFs. It is a convenience facade, not a replacement for depending directly on
specialized protocol or generated model crates.

## API Shape

Optional root re-exports are controlled by Cargo features:

- `runtime` -> `opc_runtime`
- `observability` -> `opc_observability`
- `config` -> `opc_config_model`, `opc_config_bus`, and `opc_nacm_config`
- `session` -> `opc_session_cache` and `opc_session_store`
- `sbi` -> `opc_sbi`
- `alarm` -> `opc_alarm`
- `identity` -> `opc_identity` and `opc_tls`
- `key` -> `opc_key` and `opc_crypto`
- `types` -> `opc_types`
- `testkit` -> `opc-sbi?/testkit`

The `prelude` module gathers commonly used types from the enabled features.
With `session`, this includes the validated `StableId` and `ReplicationTxId`
types and their exact 1..=64-byte and 1..=128-byte production limits; callers
cannot bypass the session-store admission contract through the facade. New
replication coordinator IDs use the canonical fixed 32-byte lowercase
hexadecimal representation while valid legacy IDs remain exact.

Example:

```rust
use opc_sdk::prelude::*;
```

Default features enable the common CNF runtime stack. Disable defaults when a
library needs a smaller dependency surface.

## Relationships

- Re-exports SDK building blocks from sibling crates. Enabling a feature does
  not attest to the production maturity of its transitive crates or adapters.
- Leaves protocol server crates such as `opc-gnmi-server` and
  `opc-netconf-server` as direct dependencies so applications opt in
  explicitly.
- Leaves generated CNF config crates outside the facade.

## Status And Limits

Current scope:

- Convenience imports for application code and examples.
- Feature-gated dependency surface for CNF services.
- Smoke examples for runtime, alarms, config, SBI, identity, and security
  prelude wiring.

The facade has no independent production maturity. Each enabled crate and
deployment profile retains its own status and limits, and the default feature
set is a composition convenience rather than an approved production profile.

Limitations:

- No management protocol codec/server facade.
- No generated schema or model exports.

## Roadmap

- Keep the facade narrow and feature-gated.
- Add re-exports only for broadly used SDK crates whose maturity and limits are
  documented.

## Verification

Run:

```sh
cargo test -p opc-sdk
cargo run -p opc-sdk --example minimal_cnf
```
