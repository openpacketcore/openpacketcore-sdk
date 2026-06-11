# OpenPacketCore SDK Quickstart

This guide shows how to build a minimal 5G CNF using the `opc-sdk` facade crate in under 50 lines of Rust.

## Prerequisites

- Rust 1.88 or later
- `cargo` and `rustc` on your PATH
- (Optional) `tokio-console` for async task introspection

## Add the SDK to your project

```toml
[dependencies]
opc-sdk = { path = "../crates/opc-sdk", version = "0.1.0", features = ["runtime", "sbi", "alarm"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Minimal CNF

```rust,no_run
use std::time::Duration;
use opc_sdk::prelude::*;
use opc_sdk::opc_alarm::{
    AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = RuntimeProfile::dev("my-cnf");
    let alarms = SharedAlarmManager::default();

    let handle = Builder::new(profile.clone())
        .with_alarm_manager(alarms.clone())
        .build()
        .await?;

    tracing::info!("Runtime phase: {:?}", handle.phase().await);

    // Register with a mock NRF (testkit feature)
    let nrf = opc_sdk::opc_sbi::testkit::MockNrf::new();
    nrf.register(opc_sdk::opc_sbi::nrf::NfProfile {
        nf_instance_id: NfInstanceId::new("my-cnf-01")?,
        nf_type: NfType::new("amf")?,
        nf_status: opc_sdk::opc_sbi::nrf::NfStatus::Registered,
        ipv4_addresses: vec!["127.0.0.1".into()],
        fqdn: None,
        plmn_list: vec![],
        s_nssais: vec![],
        nf_services: vec![],
        priority: 10,
        capacity: 100,
    })?;

    // Raise and clear an alarm
    let affected = AffectedObject::NfInstance {
        kind: "my-cnf".into(),
        instance: "my-cnf-01".into(),
    };
    alarms.raise(
        AlarmType::new("my-cnf.test.alarm"),
        Severity::Warning,
        ProbableCause::Other("demo".into()),
        affected.clone(),
        None, None, None,
        RedactedText::new("demo alarm"),
        AlarmDetails::empty(),
    );
    alarms.clear(
        &AlarmType::new("my-cnf.test.alarm"),
        ProbableCause::Other("demo".into()),
        &affected,
        None, None, None,
    );

    // Graceful drain on SIGTERM
    tokio::time::sleep(Duration::from_secs(5)).await;
    handle.shutdown_token().request_shutdown();
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
```

## Run the example

The code in this guide is taken from the compiling, CI-tested example at
[`crates/opc-sdk/examples/minimal_cnf.rs`](../crates/opc-sdk/examples/minimal_cnf.rs);
if this page and the example ever disagree, the example is authoritative. The
same composition is exercised by the integration test
[`crates/opc-sdk/tests/example_smoke.rs`](../crates/opc-sdk/tests/example_smoke.rs),
which asserts readiness and a clean drain.

```bash
cargo run -p opc-sdk --example minimal_cnf --features testkit
```

## What the SDK provides

| Feature | Crates | Purpose |
| :--- | :--- | :--- |
| `runtime` | `opc-runtime` | Process lifecycle, health probes, graceful drain |
| `config` | `opc-config-bus`, `opc-config-model` | Transactional, encrypted config pipeline |
| `session` | `opc-session-store`, `opc-session-cache` | Quorum-replicated session database |
| `sbi` | `opc-sbi` | 5G SBI client/server, NRF discovery, retry |
| `alarm` | `opc-alarm` | Alarm raise/clear with severity and probable cause |
| `identity` | `opc-identity`, `opc-tls` | SPIFFE workload identity, mTLS rotation |
| `key` | `opc-key`, `opc-crypto` | Tenant-bound AEAD envelope encryption |
| `types` | `opc-types` | Shared primitives (`NfInstanceId`, `PlmnId`, etc.) |

## Next steps

- Read [RFC 008 — CNF Runtime Chassis](rfc/008-cnf-runtime-chassis.md) for the runtime model used above.
- Read [RFC 007 — SBI Service Framework](rfc/007-sbi-service-framework.md) before building real SBI services.
- Read the [Architecture Decision Records](adr/) for design rationale.
- Explore the [operators/](../operators/) directory for the reference Kubernetes operator.
- Run the full test suite with `cargo test --workspace`.
