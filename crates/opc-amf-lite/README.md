# opc-amf-lite

Internal AMF-style vertical integration slice for proving SDK composition.

## Purpose

`opc-amf-lite` is not a production AMF. It is an unpublished integration crate
that wires a realistic AMF control-plane slice through the SDK runtime,
configuration, persistence, keying, session-store, NACM, alarms, privacy, and
testbed boundaries.

## API Shape

- `AmfConfig` is the typed AMF-lite configuration and implements
  `opc_config_model::OpcConfig`.
- `UeSessionContext` is the stored UE-context payload used by the slice.
- `PersistDatastore<C, S>` adapts `opc_persist::ConfigStore` to the
  `opc-config-bus` `ManagedDatastore` shape for sealed config.
- `NacmConfigAuthorizer` adapts `opc-nacm` policy evaluation to config-bus
  authorization.
- `AmfLite::start` and `start_with_clock` launch the slice with config store,
  session replicas, KMS endpoint, admin address, NACM policy/modules, and
  optional injected clock.
- Runtime methods include `register_ue`, `update_ue_session`,
  `session_key_for_subscriber`, `commit_config`, `commit_config_with_mode`,
  `health`, `phase`, `readiness`, `supervisor`, `config_bus`,
  `session_store`, `alarms`, and `shutdown`.
- `AMF_SCHEMA_DIGEST` and `add_duration` are exported helpers used by tests.

```rust
use opc_amf_lite::{AmfConfig, AMF_SCHEMA_DIGEST};

let config = AmfConfig::default();
assert!(config.nrf_endpoint.starts_with("http"));
assert_eq!(AMF_SCHEMA_DIGEST.len(), 64);
```

## Relationships

- Uses `opc-runtime` for lifecycle, readiness, shutdown, and supervision.
- Uses `opc-config-bus`, `opc-config-model`, and `opc-persist` for transactional
  encrypted config commits.
- Uses `opc-session-store` quorum/fencing plus `EncryptingSessionBackend` for
  UE session state.
- Uses `opc-key` and `opc-crypto` through a KMS provider boundary.
- Uses `opc-nacm` for config authorization, `opc-alarm` for alarm reporting,
  and `opc-redaction`/`opc-privacy` for subscriber-safe identifiers.
- Uses `opc-testbed` clocks and test helpers in integration tests.

## Status Notes

- `publish = false`.
- This crate is an integration proving ground, not a feature-complete AMF, NRF
  registration implementation, or carrier acceptance artifact.
- Subscriber session keys are derived from keyed privacy digests rather than
  raw IMSI values.
- The current KMS path uses `KmsKeyProvider`; test coverage injects fake KMS
  behavior through `opc-security-testkit`.
- Config consensus and session HA paths are exercised by tests, but their
  production readiness is bounded by the underlying SDK crates.

## Roadmap

- Keep the slice focused on end-to-end SDK composition.
- Add AMF behavior only when it proves a shared SDK boundary.
- Avoid adding product-specific protocol orchestration that belongs in a real
  NF crate.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and `tests/amf_lite_tests.rs`.
- Run with:

```bash
cargo test -p opc-amf-lite --all-features -- --test-threads=1
```

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
