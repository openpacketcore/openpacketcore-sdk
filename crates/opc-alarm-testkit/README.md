# opc-alarm-testkit

Test helpers for `opc-alarm`.

This crate provides polling assertions and inspection helpers for alarm manager
tests. It is intended for test code and integration fixtures, not production
runtime dependencies.

## API Shape

Public API:

- `AlarmAsserter`
- `AuditAsserter`
- `assert_eventually_raised`
- `assert_eventually_cleared`
- `assert_eventually_not_raised`
- `assert_eventually_deduplicated`
- `assert_redacted`

Example:

```rust
use opc_alarm_testkit::{assert_eventually_raised, AlarmAsserter};
```

The async helpers poll caller-supplied snapshots and use Tokio time utilities.
`AuditAsserter` verifies audit-event behavior, while redaction helpers check
that exported alarm text does not leak sensitive values.

## Relationships

- Depends on `opc-alarm`.
- Used by alarm, runtime, and SDK integration tests.
- Complements `RecordingSink` and in-memory stores from the core alarm crate.

## Status And Limits

Current scope:

- Test-only alarm lifecycle assertions.
- Audit assertions.
- Redaction checks.

Limitations:

- Not a production monitoring library.
- No persistent store or controller integration.

## Roadmap

- Add helpers only when they simplify repeated cross-crate alarm tests.

## Verification

Run:

```sh
cargo test -p opc-alarm-testkit
```
