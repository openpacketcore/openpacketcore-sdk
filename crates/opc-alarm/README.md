# opc-alarm

Alarm model, manager, sinks, and optional authorization/persistence adapters for
OpenPacketCore CNFs.

This crate provides the shared alarm taxonomy and in-process alarm manager used
by runtime and management components. It keeps alarm text redaction, deduping,
admin actions, audit hooks, and sink behavior in one place.

## API Shape

Main exports:

- Model types:
  `Alarm`, `AlarmId`, `AlarmType`, `AlarmState`, `AlarmDetails`,
  `AffectedObject`, `DedupKey`, `Severity`, `ProbableCause`,
  `ReadinessImpact`, `RegionId`, `RedactedText`, and `TAXONOMY_VERSION`.
- Manager types:
  `AlarmManager`, `SharedAlarmManager`, `AlarmStore`, `InMemoryStore`,
  `AlarmAction`, `AlarmActionScope`, `AlarmActionContext`,
  `AlarmActionAuthorizer`, `SuppressionAuth`, `AlarmOpResult`,
  `AlarmAuditEvent`, `AlarmAuditSink`, and default active/history limits.
- Sink types:
  `AlarmSink`, `AlarmSinkError`, `BoundedAlarmSink`, `RecordingSink`,
  `SinkStatus`, and `TracingSink`.
- Optional adapters:
  `NacmAlarmAuthorizer` behind the `nacm` feature and
  `PersistAlarmAuditSink` behind the `persist` feature.
- `prelude`, collecting common alarm imports.

Example imports:

```rust
use opc_alarm::prelude::*;
```

The manager deduplicates active alarms by alarm type, probable cause, affected
object, tenant, slice, and region. Raising an existing dedup key updates the
active alarm. Clearing an alarm that is not active is a no-op.

## Features

- `default = []`
- `nacm`: enable NACM-backed authorization for administrative alarm actions.
- `persist`: enable persistence-backed audit sink support.
- `persist-test-hooks`: enable persistence test hooks; not for production.

## Relationships

- Used by runtime and SDK integration crates for alarm reporting.
- `opc-alarm-k8s` projects alarms into Kubernetes-style conditions/events.
- `opc-alarm-yang` projects alarms into YANG-style JSON and provides a schema
  string.
- `opc-alarm-testkit` provides test assertions around this crate.

## Status And Limits

Current scope:

- In-process alarm lifecycle management.
- Redaction-aware alarm text handling.
- Bounded in-memory store for active and historical alarms.
- Admin acknowledge/suppress actions with fail-closed authorization and audit.

Production notes:

- Callers must provide already-redacted alarm text and details.
- `InMemoryStore` is useful for local runtime state but is not a durable alarm
  archive.
- Optional persistence and NACM features must be wired explicitly.

## Roadmap

- Keep the taxonomy versioned and additive where possible.
- Add adapters outside the core model when they target a specific platform or
  persistence backend.

## Verification

Run:

```sh
cargo test -p opc-alarm
cargo test -p opc-alarm --features nacm,persist
```
