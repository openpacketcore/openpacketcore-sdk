# opc-runtime

CNF runtime chassis for startup, supervision, health, shutdown, and resource
governance.

## Purpose

`opc-runtime` provides the process-level runtime frame for OpenPacketCore CNFs:
startup phases, supervised tasks, readiness gates, graceful drain, admin health,
resource budgets, source admission, and deterministic test clocks.

## API Shape

- `Builder::new(profile)` creates a runtime builder. It supports startup phase
  hooks, init callbacks, alarm manager injection, clock injection, drain hooks,
  and `build`.
- `RuntimeHandle` exposes phase, readiness, shutdown, supervisor, config
  version metadata, alarm manager, and shutdown token access.
- `RuntimeProfile`, `RuntimeMode`, `ResourceBudget`, and `SigintHandling`
  define mode-specific runtime behavior.
- `Supervisor` registers and spawns `TaskSpec` tasks with `Criticality`,
  `RestartPolicy`, `ShutdownPolicy`, task kind, heartbeat timeout, and memory
  pressure checks.
- Health APIs include `HealthModel`, `HealthGateSet`, `HealthGate`,
  `GateStatus`, `Readiness`, `StartupPhase`, and `known_gates`.
- Shutdown APIs include `ShutdownToken`, `ShutdownPhase`, and `DrainHook`.
- Admission APIs include per-source `SourceTokenBucketPolicy`,
  `SourceTokenBucket`, and `SourceAdmissionDecision`, plus the process-wide
  `AggregateAdmissionConfig`, `AggregateAdmissionBudget`, RAII
  `AggregateAdmissionPermit`, typed exhaustion errors, and fixed-cardinality
  metrics.
- UDP helpers receive the concrete local destination and can send a reply from
  that exact endpoint. Linux and Android use per-datagram packet-info ancillary
  data; platforms without it only allow the send when a concrete socket bind
  already guarantees the requested source. Typed socket options can opt a
  listener into Linux/Android `SO_BINDTODEVICE` scoping before address bind.
- Feature `observability` adds `init_observability_logging`.

```rust,no_run
use opc_runtime::{Builder, RuntimeProfile};

async fn start() -> Result<opc_runtime::RuntimeHandle, opc_runtime::RuntimeError> {
    let profile = RuntimeProfile::dev("nrf");
    let runtime = Builder::new(profile).build().await?;
    Ok(runtime)
}
```

Layer the aggregate gate after the source gate and hold its permit until the
expensive operation finishes:

```rust,no_run
use std::{net::IpAddr, num::NonZeroU32, time::Instant};

use opc_runtime::{
    AggregateAdmissionBudget, AggregateAdmissionConfig, AggregateAdmissionError,
    AggregateAdmissionPermit, SourceAdmissionDecision, SourceTokenBucket,
};

fn admit_expensive_work(
    sources: &SourceTokenBucket<IpAddr>,
    aggregate: &AggregateAdmissionBudget,
    source: IpAddr,
    now: Instant,
) -> Result<Option<AggregateAdmissionPermit>, AggregateAdmissionError> {
    if sources.admit(source, now) != SourceAdmissionDecision::Allowed {
        return Ok(None);
    }
    aggregate.try_acquire(now).map(Some)
}

let Some(rate) = NonZeroU32::new(200) else {
    return;
};
let Some(burst) = NonZeroU32::new(400) else {
    return;
};
let Some(in_flight) = NonZeroU32::new(16) else {
    return;
};
let aggregate = AggregateAdmissionBudget::new(AggregateAdmissionConfig::per_second(
    rate, burst, in_flight,
));
let _ = aggregate.metrics();
```

The aggregate budget stores no source identities and performs no eviction, so
source-address churn cannot restore its rate tokens. `try_acquire` never waits;
rate and in-flight exhaustion are distinct stable typed errors. Dropping the
non-cloneable permit, including through future cancellation, synchronously
returns its in-flight slot. Consumers still own cookie ordering, policy values,
and placement of synchronous cryptography on an appropriate blocking pool.

Pair the receive metadata with `send_to_from` for wildcard-bound VIP listeners:

```rust,no_run
use std::{io, net::SocketAddr};

use opc_runtime::bind_udp_socket_with_destination_metadata;

async fn receive_and_reply(bind: SocketAddr) -> io::Result<()> {
    let socket = bind_udp_socket_with_destination_metadata(bind)?;
    let mut payload = [0_u8; 2048];
    let received = socket.recv_from_with_destination(&mut payload).await?;
    let local_source = received
        .local_destination()
        .socket_addr_value()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "udp_destination_missing"))?;

    socket
        .send_to_from(
            &payload[..received.bytes()],
            received.source(),
            local_source,
        )
        .await?;
    Ok(())
}
```

`send_to_from` rejects source/peer family mismatches, a source port different
from the bound socket, unspecified/multicast/broadcast sources, non-local
addresses, and oversized datagrams before sending. It never silently falls
back to kernel source selection. Product code remains responsible for carrying
the observed destination through every normal, replay, retransmit, and error
reply path.

Linux and Android applications that place a UDP listener in a VRF or another
device-scoped L3 domain can opt in explicitly:

```rust,no_run
use std::{io, net::SocketAddr};

use opc_runtime::{
    bind_udp_socket_with_destination_metadata_and_options, UdpSocketOptions,
};

fn bind_in_vrf(bind: SocketAddr) -> io::Result<opc_runtime::UdpDestinationMetadataSocket> {
    let options = UdpSocketOptions::default().with_bind_device("vrf-public");
    bind_udp_socket_with_destination_metadata_and_options(bind, &options)
}
```

The device option is default-off. When configured, the runtime validates the
interface name, applies `SO_BINDTODEVICE` before `bind(2)`, and keeps the same
scope for source-locality probes used by `send_to_from`. Linux requires
`CAP_NET_RAW`; unsupported platforms return `io::ErrorKind::Unsupported`
instead of silently binding in the default routing domain. The original
`bind_udp_socket_with_destination_metadata` constructor remains unchanged in
behavior and does not select a device.

## Relationships

- Used by AMF-lite and CNF crates as the process lifecycle owner.
- Optional `observability` integration delegates logging setup to
  `opc-observability`.
- Alarm integration composes with `opc-alarm` through injected shared managers.

## Status Notes

- `RuntimeMode::Production` and `RuntimeMode::Conformance` fail closed when
  required bootstrap material is missing.
- Dev, Lab, and Conformance modes allow debug endpoints without production
  gating; Production and Perf require debug surfaces to be gated or disabled.
- Empty supervisors are not ready.
- Memory-limit pressure can force readiness to NotReady.
- AMF/SMF/UPF dev, conformance, and production profiles require an NRF drain
  hook.

## Roadmap

- Keep listener startup and shutdown semantics documented in the crate root.
- Add runtime surfaces only when they can be supervised, health-gated, and
  tested deterministically.
- Keep optional integrations feature-gated.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, builder, runtime, supervisor,
  health, profile, shutdown, admission, UDP, admin, and tests.
- Run with: `cargo test -p opc-runtime`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
