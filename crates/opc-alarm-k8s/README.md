# opc-alarm-k8s

Kubernetes-style alarm projections.

This crate maps `opc-alarm` values into serializable condition and event shapes
that can be consumed by Kubernetes operators or tests. It does not depend on
`kube`, `k8s-openapi`, or an API server client.

## API Shape

Public API:

- `K8sCondition`
- `K8sEvent`
- `alarm_to_condition`
- `alarm_to_condition_with_previous`
- `alarm_to_event`
- `alarm_to_event_with_count`

Example:

```rust
use opc_alarm_k8s::{alarm_to_condition, alarm_to_event};
```

`alarm_to_condition_with_previous` preserves the previous transition time when
condition status does not change. Condition types are sanitized from the alarm
type and include a stable hash suffix. Events map alarm severity to Kubernetes
`Normal` or `Warning` style event types and use redacted alarm text.

## Relationships

- Consumes `opc-alarm`.
- Intended for controllers, fixtures, or tests that already own Kubernetes API
  writing.
- Does not manage watches, reconciliation, or CRD status updates.

## Status And Limits

Current scope:

- Pure projection into serializable structs.
- Stable condition names and event counts.
- Redaction-preserving event messages.

Limitations:

- No Kubernetes client.
- No controller runtime.
- No API server side effects.

## Roadmap

- Keep this crate projection-only.
- Add controller behavior in a separate integration crate if needed.

## Verification

Run:

```sh
cargo test -p opc-alarm-k8s
```
