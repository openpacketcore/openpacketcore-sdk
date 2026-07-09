# opc-mgmt-opstate

Operational-state contracts for management protocols.

This crate defines how CNFs expose operational values and operational event
streams to gNMI, NETCONF, and generated management bindings. It also contains a
projection for config-apply workflow state.

## API Shape

Core exports:

- `Origin`, `OperationalRequest`, `OperationalResponse`, and
  `OperationalValue`.
- `OperationalStateProvider` for on-demand operational reads.
- `OperationalSubscriptionRequest`, `OperationalEvent`,
  `OperationalEventSender`, `OperationalEventReceiver`, and
  `operational_event_channel` for bounded event streams.
- `OperationalError`, `OperationalValueError`, `OperationalResponseError`, and
  `OperationalStreamError`.

Config-apply projection exports:

- `ConfigApplyPlanState`.
- `ConfigCandidateState` and `ConfigCandidateStatus`.
- `ConfigWorkflowCompletion`.
- `ConfigWorkflowActionTarget`, `ConfigWorkflowActionStatus`,
  `ConfigWorkflowActionConflictReason`, and `ConfigWorkflowActionResult`.

Example:

```rust
use opc_mgmt_opstate::{OperationalRequest, OperationalStateProvider};

fn read_opstate(
    provider: &dyn OperationalStateProvider,
    request: OperationalRequest,
) -> Result<opc_mgmt_opstate::OperationalResponse, opc_mgmt_opstate::OperationalError> {
    provider.get(&request)
}
```

Operational values are RFC 7951 JSON strings checked at construction. Providers
must omit unknown paths instead of fabricating values. Origin may be included
only when requested and genuinely known.

## Relationships

- Consumed by `opc-gnmi-server` and `opc-netconf-server`.
- Uses `opc-config-model` paths and config workflow metadata.
- Uses `opc-mgmt-errors` to map commit failures in apply-plan state.

## Status And Limits

Current scope:

- Anti-fabrication read contract for operational state.
- Bounded operational event channels.
- Config-apply workflow state suitable for management-plane projection.

Limitations:

- This crate does not collect metrics, watch Kubernetes resources, or implement
  a CNF provider. CNFs must implement the provider traits.
- Event queue sizing is bounded; a zero queue request normalizes to one.

## Roadmap

- Keep protocol-facing operational contracts stable.
- Add reusable projections only when multiple protocol crates need them.

## Verification

Run:

```sh
cargo test -p opc-mgmt-opstate
```
