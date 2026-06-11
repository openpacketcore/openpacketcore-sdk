# opc-amf-lite-testkit

This crate provides reusable test fixtures, builders, and boundaries for testing the `opc-amf-lite` network function.

## Usage

Use `AmfTestFixture` to set up a standardized environment for testing the AMF network function:

```rust
use opc_amf_lite_testkit::AmfTestFixture;
use opc_runtime::RuntimeMode;

let fixture = AmfTestFixture::new()
    .with_runtime_mode(RuntimeMode::Lab);
```

## Pattern for Downstream CNF Testkits

This crate serves as the reference pattern for future CNF testkits (e.g. `opc-smf-testkit`, `opc-upf-testkit`):
- **Runtime & Budget Builders**: Standardise profile and budget setup.
- **Alarm Asserters**: Leverage `opc-alarm-testkit` to assert alarm raising, clearing, and redaction compliance.
- **Shared peer simulators**: Rely on `opc-testbed` rather than internal stubs.
