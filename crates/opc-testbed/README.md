# opc-testbed

Scenario DSL, virtual time, assertions, fixture provenance, runners, and
simulator building blocks for OpenPacketCore conformance tests.

## Purpose

`opc-testbed` is the shared test framework for SDK and NF-level scenarios. It
loads RFC 012 YAML/JSON scenarios, runs them against in-process or planned
environment runners, records evidence, and provides product-neutral simulators
for early scenario development.

## API Shape

- Scenario DSL: `Scenario`, `Topology`, `NfSpec`, `Step`,
  `ProtocolFixtureStep`, and `DSL_VERSION`.
- Assertions: `Assertion`, `AssertionOutcome`, and `evaluate` for the supported
  `path.to.key == value` form.
- Virtual time: `VirtualClock` and `Clock`.
- Fixture provenance: `FixtureProvenance` and `FixtureRegistry`.
- Evidence: `ScenarioEvidence` and `ScenarioOutcome`, with conversion to
  RFC 006 `EvidenceRecord`s.
- Runners: `LocalRunner`, `KindRunner`, `KindRunnerConfig`,
  `HardwareLabRunner`, and `HardwareLabRunnerConfig`.
- Simulators live under `opc_testbed::simulators` and include fake AMF/SMF/UPF
  mechanics plus experimental EPC/ePDG peer skeletons.

```rust,no_run
use opc_testbed::{LocalRunner, Scenario, VirtualClock};
use opc_types::Timestamp;

fn run_scenario(yaml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = Scenario::from_yaml(yaml)?;
    scenario.validate()?;

    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);
    let evidence = runner.run(&scenario)?;
    assert_eq!(evidence.scenario_id, scenario.id);
    Ok(())
}
```

## Simulator Status

- `simulators::fake`, `amf`, `smf`, and `upf` provide deterministic in-process
  state for scenario-runner tests.
- `UpfSimulator` accepts SDK-decoded user-plane metadata and tracks TEID/SPI,
  extension-header presence, continuity state, counters, and redaction-safe
  session keys.
- `PgwS2bSimulator` accepts SDK-decoded S2b message views. Fidelity is
  `stateful-mock` and experimental.
- `DiameterPeerSimulator` accepts decoded Diameter metadata. Fidelity is
  `stateful-mock` and experimental.
- EPC/ePDG skeletons do not parse bytes locally, are not procedure-faithful
  conformance simulators, and are not production PGW/ePDG/AAA/HSS/CDF peers.

## Relationships

- Uses `opc-evidence` for requirement IDs and evidence records.
- Uses `opc-schema-validate` for scenario schema validation.
- Uses `opc-redaction` to sanitize failure summaries and hardware plans.
- Uses protocol crates in tests, while the simulator APIs accept decoded views
  rather than owning protocol parsers.

## Status Notes

- Core scenario parsing, validation, local runner mechanics, fixture
  provenance, virtual time, and evidence conversion are ready for use in SDK
  tests. This is test-infrastructure scope, not a deployment maturity claim.
- Kind and hardware-lab runners currently produce validated plans or dry-run
  evidence; live environment execution remains downstream/operator-owned.
- Scenario `seed` is recorded for deterministic evidence but current SDK
  simulators do not consume it.
- Assertion evaluation is deliberately small and fails/skips unsupported
  expression forms rather than silently passing them.

## Roadmap

- Keep NF-specific testkits built on this crate instead of standalone mocks.
- Expand simulator fidelity only when protocol crates provide decoded models
  and tests require stronger behavior.
- Keep fixture provenance and scenario schema validation fail closed.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, scenario, runner, evidence,
  fixture, assertion, virtual-time, simulator modules, and tests.
- Run with: `cargo test -p opc-testbed`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
