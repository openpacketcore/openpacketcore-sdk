# opc-nacm

NACM policy engine for OpenPacketCore management authorization.

This crate evaluates normalized YANG paths and management actions against a
compiled NACM policy. It is the policy engine, not the operator-facing NACM
configuration model or a datastore.

## API Shape

Public API:

- Actions and decisions:
  `NacmAction`, `AuthorizationDecision`, `NacmEffect`, and `NacmError`.
- Policy model:
  `NacmPolicy`, `NacmPolicyBuilder`, `NacmRule`, `NacmRuleList`, and
  `PolicyVersion`.
- Path and module model:
  `ModuleRegistry`, `QualifiedNodeName`, `YangPath`, `YangPathPattern`, and
  `YangPathPatternSegment`.
- Runtime evaluator:
  `NacmEvaluator`.

Example:

```rust
use opc_nacm::{NacmEvaluator, NacmPolicy, PolicyVersion};

let policy = NacmPolicy::empty(PolicyVersion::default());
let mut evaluator = NacmEvaluator::default();
```

Policies default-deny. Rule evaluation is first-match by rule order, not
most-specific-match. A special `*` group can be used by policy builders for all
users.

## Relationships

- `opc-nacm-config` compiles operator-facing config into `NacmPolicy`.
- `opc-mgmt-authz` adapts the evaluator to read/write/exec management flows.
- `opc-mgmt-schema` supplies schema-node action metadata used by protocol
  authorization layers.

## Status And Limits

Current scope:

- Normalized YANG path parsing and pattern matching.
- Exact, wildcard, `module:*`, and trailing `/**` pattern support.
- Bounded evaluator cache with invalidation on policy identity, version, or
  group set changes.
- Metrics updates through `opc-redaction` metric helpers.

Limitations:

- No policy persistence.
- No principal grant resolution.
- Ambiguous module prefixes are rejected rather than guessed.

## Roadmap

- Keep this crate focused on deterministic policy evaluation.
- Put user-facing config and grant mapping in `opc-nacm-config`.

## Verification

Run:

```sh
cargo test -p opc-nacm
```
