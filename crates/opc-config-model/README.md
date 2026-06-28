# Opc Config Model

Shared config-model request, result, identity, and error types for OpenPacketCore.

This crate also owns the generic config apply-plan contract. An apply plan is
the impact classification produced after diff/validation and before durable
commit. Validation answers "is this candidate syntactically and semantically
valid"; the apply plan answers "can this valid candidate be applied live, and
what operational workflow does it require?"

Impact classes are ordered by operational disruption:

- `hot`: accepted immediately for existing and new work.
- `warm`: accepted live, but only new work observes the change.
- `drain-required`: accepted, but traffic must drain before it is safe.
- `restart-required`: accepted, but the CNF must restart before it is safe.
- `forbidden-live`: rejected by default and returned on `CommitError.apply_plan`.

Products install a `ConfigImpactClassifier` in `opc-config-bus` when they need
domain-specific rules. Without one, the default classifier returns a hot plan
from the SDK-derived changed paths, preserving existing behavior.

## Status

**Production-ready**

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/001-management-substrate.md)

## Quick start

```rust,no_run
use opc_config_model::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
