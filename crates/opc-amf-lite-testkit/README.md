# opc-amf-lite-testkit

Reusable fixtures and builder patterns for AMF-lite tests.

## Purpose

`opc-amf-lite-testkit` provides the small set of test fixtures shared by
AMF-lite tests and by future CNF testkit patterns. It does not start AMF-lite
or provide production mocks.

## API Shape

- `AmfTestFixture::new()` builds a Lab-mode runtime profile, shared alarm
  manager, empty NACM policy, module registry, and virtual clock.
- `with_runtime_mode` overrides the runtime mode.
- `with_nacm_policy` installs a test NACM policy.
- `assert_alarms` returns an `opc-alarm-testkit` `AlarmAsserter`.
- `CnfTestkitPatternDoc::pattern_description()` documents the expected pattern
  for future CNF testkits.

```rust
use opc_amf_lite_testkit::AmfTestFixture;
use opc_runtime::RuntimeMode;

let fixture = AmfTestFixture::new().with_runtime_mode(RuntimeMode::Lab);
assert_eq!(fixture.runtime_profile.mode, RuntimeMode::Lab);
```

## Relationships

- Uses `opc-runtime` profiles and virtual-time-friendly settings.
- Uses `opc-alarm` plus `opc-alarm-testkit` for alarm assertions.
- Uses `opc-nacm` for policy fixtures.
- Uses `opc-testbed::VirtualClock` for deterministic time.

## Status Notes

- `publish = false`.
- Intended for tests only.
- Future SMF/UPF-style testkits should follow the same pattern rather than
  inventing standalone mock datastores.

## Roadmap

- Add fixtures only when AMF-lite tests need shared setup.
- Keep downstream CNF guidance in pattern documentation until those CNF crates
  exist.
- Keep this crate small and unpublished.

## Verification

- Source checked: `Cargo.toml` and `src/lib.rs`.
- Run with: `cargo test -p opc-amf-lite-testkit`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
