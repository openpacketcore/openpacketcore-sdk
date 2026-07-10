# opc-dataplane-testkit

## Purpose

`opc-dataplane-testkit` provides deterministic dataplane traffic generation,
GTP-U helpers, reflectors, and packet-continuity evidence for OpenPacketCore
tests. It is pure Rust: no sockets, clocks, random numbers, or kernel state are
used unless a caller builds those around it.

## API Shape

- `TrafficEngine`, `TrafficPlan`, and `GeneratedPacket`: deterministic
  measurement T-PDU generation.
- `InnerIpFlow`, `MeasurementHeader`, `DecodedTpdu`,
  `build_measurement_tpdu`, `decode_measurement_tpdu`, and `echo_tpdu`: inner
  IPv4/IPv6 UDP measurement packets.
- `decode_gtpu`, `encode_gpdu`, `encode_gpdu_with_extensions`,
  `encode_echo_request`, and `validate_error_indication_ies`: GTP-U test
  datagram helpers built on `opc-proto-gtpu`.
- `GtpuReflector`, `ReflectorConfig`, `MultiSessionReflectorConfig`,
  `ReflectorSession`, `ReflectorPolicy`, `ReflectorAction`, and
  `ReflectorStats`: bounded in-memory single- or multi-TEID echo, sink, and
  route behavior.
- `ContinuityObserver`, `GtpuReturnDatagramOutcome`,
  `PacketContinuityBudget`, `PacketContinuityReport`, and `LatencySummary`:
  redaction-safe forwarding and packet-continuity evidence.
- `PACKET_CONTINUITY_SCHEMA_VERSION` and
  `schemas/packet-continuity-report.schema.json`: stable report shape.

## Usage

```rust
use std::net::Ipv4Addr;

use opc_dataplane_testkit::{
    ContinuityObserver, InnerIpFlow, PacketContinuityBudget, TrafficEngine,
    TrafficPlan,
};

let flow = InnerIpFlow::Ipv4 {
    src: Ipv4Addr::new(10, 23, 0, 2),
    dst: Ipv4Addr::new(198, 51, 100, 7),
    src_port: 49152,
    dst_port: 9,
};

let mut engine = TrafficEngine::new();
let packets = engine
    .generate(
        flow,
        TrafficPlan {
            packet_count: 3,
            target_rate_pps: 1_000,
            first_send_timestamp_ns: 1_000_000,
        },
    )
    .unwrap();

let mut observer = ContinuityObserver::new();
for packet in &packets {
    observer.record_sent(packet);
    observer
        .record_received_tpdu(packet.send_timestamp_ns + 50_000, &packet.tpdu)
        .unwrap();
}

let report = observer.report(
    "flow-a",
    1_000_000,
    2_000_000,
    PacketContinuityBudget::zero_loss(),
);
assert!(report.packet_continuity_proven);
```

## Relationships

- Uses `opc-proto-gtpu` and `opc-protocol` for GTP-U encoding/decoding.
- Projects continuity evidence into `opc-evidence::DataplaneSnapshot`.
- Used by dataplane and gateway integration tests that need repeatable packet
  streams without relying on live networking in unit tests.

## Status And Limits

- Deterministic testkit, not a production packet generator.
- Report `Debug` output redacts flow labels; reports must still be populated
  with safe `flow_id` values and can be checked with `validate_redaction`.
- GTP-U helpers support the message shapes needed by the current continuity and
  reflector tests; they are not a full conformance test suite for TS 29.281.
- Multi-session reflection keys mappings by the inbound local TEID learned from
  control-plane F-TEIDs; inner-flow learning remains a product/lab concern.

## Roadmap

- Keep schema changes explicit and versioned.
- Add new reflector policies only with tests that cover emitted datagrams and
  evidence counters.
- Reuse protocol crates for wire encoding rather than hand-rolling complete
  protocol stacks here.

## Verification

```sh
cargo test -p opc-dataplane-testkit
```
