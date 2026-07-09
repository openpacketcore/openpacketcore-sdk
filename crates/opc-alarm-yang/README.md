# opc-alarm-yang

YANG-style alarm schema fixture and JSON projection.

This crate exposes a static alarm YANG module string and a helper that converts
`opc-alarm` values into YANG-shaped JSON. It does not serve NETCONF or gNMI by
itself.

## API Shape

Public API:

- `YANG_ALARM_SCHEMA`, the `openpacketcore-alarm` YANG module text.
- `alarm_to_yang_json`, converting an `opc_alarm::Alarm` into
  `serde_json::Value`.

Example:

```rust
use opc_alarm_yang::{alarm_to_yang_json, YANG_ALARM_SCHEMA};
```

The JSON projection includes alarm identity, type, severity, probable cause,
affected object, tenant/slice/region metadata, state, timestamps, details, and
redacted text.

## Relationships

- Consumes `opc-alarm`.
- Can be used by tests, examples, or management bindings that need a simple
  alarm projection.
- Independent of `opc-yanggen`; the schema is a static fixture.

## Status And Limits

Current scope:

- Static YANG module text for alarm projection tests.
- Pure JSON conversion helper.

Limitations:

- No NETCONF or gNMI server.
- No generated schema-registry implementation.
- No datastore or subscription support.

## Roadmap

- Keep this crate a lightweight projection fixture.
- Move generated registry/server behavior into generated model or protocol
  crates if production alarm management needs it.

## Verification

Run:

```sh
cargo test -p opc-alarm-yang
```
