# Reference SMF Consumer

This is a deliberately bounded **reference consumer** of the OpenPacketCore
SDK. It lives outside the SDK workspace (it has its own `Cargo.toml` and
lockfile) and consumes SDK crates via path dependencies, exactly as a
downstream team would consume published versions.

It is **not a product-grade SMF**: it has no N7/PCF integration, no charging,
no NAS signalling, no real UPF selection, and no persistence beyond the
session-store test backend. It exists to prove that the SDK composes from
outside its own workspace and to surface every API friction point.

## What it exercises

- `opc-runtime`: startup phases, graceful drain, and a runtime panic hook.
- `opc-sbi`: NRF registration heartbeat and deregister-on-drain, plus the
  SBI testkit's mock NRF in tests.
- `opc-proto-pfcp`: real PFCP/N4 bytes over UDP — association setup/release,
  session establishment/modification/deletion, and heartbeat keepalive.
- `opc-session-store`: session-record create/get with leases and fencing.
- `opc-alarm`: alarm manager wired into the runtime.
- `opc-config-bus`: loaded at runtime (the reference uses an in-memory/SQLite
  datastore).

## Run

All commands run from this directory so the standalone workspace is used:

```bash
cd examples/smf-reference
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Test coverage

- `tests/nrf.rs`: NRF registration, heartbeat, and deregistration using the
  SDK's `MockNrf`.
- `tests/e2e.rs`: a fake UPF peer exchanges real PFCP bytes with the SMF over
  loopback UDP — association setup, session establishment with typed
  Create PDR/FAR/QER IEs, session modification, session deletion, and
  heartbeat handling.

## Friction journal

API rough edges hit while building this consumer are recorded in
`.planning/v0.5-report.md` at the repository root.
