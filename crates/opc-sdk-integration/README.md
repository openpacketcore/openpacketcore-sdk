# opc-sdk-integration

Integration fixture crate for exercising the SDK as a small toy network
function.

This crate is not the SDK facade. It packages a toy runtime, toy config model,
alarm wiring, evidence artifacts, and scenario helpers used by integration and
conformance-style tests.

## API Shape

Public API:

- Evidence artifact names:
  `HEALTH_ARTIFACT`, `ALARMS_ARTIFACT`, and `SCENARIO_STATE_ARTIFACT`.
- Toy config:
  `ToyConfig` and `ToyObservedConfig`.
- Runtime state:
  `ToyHealthSnapshot`, `ToyNetworkFunction`, and `ScenarioRunOutput`.
- Error type:
  `ToyIntegrationError`.

Example imports:

```rust
use opc_sdk_integration::{ToyConfig, ToyNetworkFunction};
```

`ToyConfig` implements `OpcConfig` with a hostname and NRF peer endpoint. The
default endpoint is `nrf://bootstrap`, and validation requires the `nrf://`
scheme.

`ToyNetworkFunction` can start a supervised toy runtime, wait for readiness,
commit config, wait for config versions, raise and clear redacted alarms,
inspect alarm history, inject runtime task failure, run scenarios, and shut
down.

## Relationships

- Uses the SDK runtime, config, alarm, observability, session, SBI, identity,
  and persistence test surfaces.
- Uses dev-only config-bus wiring and mock/in-memory storage where appropriate
  for tests.
- Provides evidence fixtures for repository integration tests.

## Status And Limits

Current scope:

- Integration-test harness and toy NF.
- Privacy and redaction checks around alarms and evidence.
- Runtime readiness and failure-injection scenarios.

Limitations:

- Not a production runtime API.
- Not a production config schema.
- Dev-only authorization/storage choices are intentional and must not be copied
  into production wiring.

## Roadmap

- Keep this crate focused on end-to-end SDK confidence tests.
- Add scenarios only when they cover cross-crate behavior.

## Verification

Run:

```sh
cargo test -p opc-sdk-integration
```
