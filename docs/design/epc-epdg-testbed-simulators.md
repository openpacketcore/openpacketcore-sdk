# EPC/ePDG testbed simulator skeletons

## Status

Experimental design and first `opc-testbed` skeletons.

## Scope and boundary

This design adds product-neutral simulator mechanics for EPC and untrusted-access
testbeds. It follows ADR 0018: the SDK owns reusable peer mechanics, protocol
fixture provenance, and deterministic assertion state; downstream products own
ePDG attach orchestration, APN/realm/PLMN policy, AAA/HSS/CDF business policy,
charging behavior, lawful-intercept workflow, deployment defaults, and carrier
acceptance claims.

The first skeletons are:

- `PgwS2bSimulator`: a PGW S2b peer state skeleton. It accepts decoded S2b
  message views and tracks procedure, request/response direction, TEID,
  sequence number, raw-preservation support, rejection counters, and synthetic
  session count.
- `DiameterPeerSimulator`: a Diameter peer metadata skeleton. It accepts
  decoded command metadata and tracks Capabilities Exchange, Device Watchdog,
  Disconnect Peer, application-message, Session-Id-present, and rejection
  counters.

Neither simulator parses raw protocol bytes locally. Callers must decode
untrusted bytes through SDK protocol crates first, then pass decoded views into
the simulator interfaces.

## RFC 012 fidelity declaration

Per RFC 012 §6, these first EPC/ePDG simulators declare fidelity per interface:

| Simulator interface | RFC 012 fidelity level | Production/conformance status |
| --- | --- | --- |
| PGW S2b decoded-message interface | `stateful-mock` | Experimental skeleton only; not procedure-faithful, not a conformance simulator, and not a production PGW/ePDG control plane. |
| Diameter peer decoded-metadata interface | `stateful-mock` | Experimental skeleton only; not procedure-faithful, not a Diameter conformance simulator, and not a production AAA/HSS/CDF peer. |

The `stateful-mock` label means the simulators retain deterministic state and
fail-closed fault-injection state for tests, but they do not implement full
normative procedures, peer routing, business policy, retransmission behavior, or
carrier acceptance evidence.

## Protocol-crate ownership

| Simulator | Decode owner | Current interface |
| --- | --- | --- |
| PGW S2b | `opc-proto-gtpv2c` | `S2bMessageView` adapters over SDK-decoded S2b typed views. Tests decode spec-authored GTPv2-C S2b fixtures with `opc-proto-gtpv2c` before calling the simulator. |
| Diameter peer | future `opc-proto-diameter` | `DiameterMessageView` metadata trait. Until the SDK Diameter codec lands, the simulator records already-decoded command metadata only and carries no raw Diameter parser. |

Both simulators expose `SdkDecodeProfile` values built from `opc-protocol`
limits so test code can use consistent validation settings when invoking the
protocol crate.

## Fixture provenance

Simulator interface tests reuse the spec-authored S2b fixtures owned by
`opc-proto-gtpv2c`. The manifest at
`crates/opc-testbed/tests/fixtures/epc_epdg_simulator_manifest.json` records the
provenance class, owning protocol crate, and redaction status for each packet
used by the simulator tests.

Diameter has no packet fixture in this skeleton because there is no SDK
Diameter codec in this worktree. The manifest records the Diameter interface as
`no-packet-fixture-yet` and `sdk-protocol-crate-only`; adding raw Diameter bytes
must wait for `opc-proto-diameter` and ADR 0015 fixture provenance.

## Fail-closed behavior

- PGW S2b rejects unsupported message types and state-changing requests that
  require an active synthetic session.
- Diameter rejects decoded messages when the peer is fault-injected as
  unavailable.
- Both simulators expose `record_decode_failure(...)` so callers can propagate
  SDK protocol-crate decode errors into deterministic assertion state.
- Neither simulator stores subscriber identifiers, Diameter Session-Id values,
  key material, or lawful-intercept identifiers.

## Future work

- Add a production `opc-proto-diameter` adapter once the SDK Diameter crate and
  conformance fixtures exist.
- Add UE/IKE and charging CDF simulator skeletons only after their protocol
  crates or decoded-view boundaries exist.
- Extend RFC 012 scenarios with protocol-specific packet steps only after the
  DSL has schema support for fixture provenance and raw-byte ownership.
