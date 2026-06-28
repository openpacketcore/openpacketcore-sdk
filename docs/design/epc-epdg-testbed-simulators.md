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

- `PgwS2bSimulator`: a PGW S2b peer state skeleton with RFC 012
  `stateful-mock` fidelity (experimental). It accepts decoded S2b message views
  and tracks procedure, request/response direction, TEID, sequence number,
  raw-preservation support, rejection counters, and synthetic session count. It
  is not procedure-faithful, not a conformance simulator, and not a production
  PGW/ePDG control plane.
- `DiameterPeerSimulator`: a Diameter peer metadata skeleton with RFC 012
  `stateful-mock` fidelity (experimental). It accepts decoded command metadata
  and tracks Capabilities Exchange, Device Watchdog, Disconnect Peer,
  application-message, Session-Id-present, and rejection counters. It is not
  procedure-faithful, not a Diameter conformance simulator, and not a production
  AAA/HSS/CDF peer.

Neither simulator parses raw protocol bytes locally. Callers must decode
untrusted bytes through SDK protocol crates first, then pass decoded views into
the simulator interfaces.

## RFC 012 fidelity declaration

Per RFC 012 §6, these first EPC/ePDG simulators declare fidelity per interface:

| Simulator interface | RFC 012 fidelity level | Production/conformance status |
| --- | --- | --- |
| `PgwS2bSimulator` decoded-message interface | RFC 012 `stateful-mock` | Experimental skeleton only; not procedure-faithful, not a conformance simulator, and not a production PGW/ePDG control plane. |
| `DiameterPeerSimulator` decoded-metadata interface | RFC 012 `stateful-mock` | Experimental skeleton only; not procedure-faithful, not a Diameter conformance simulator, and not a production AAA/HSS/CDF peer. |

The `stateful-mock` label means the simulators retain deterministic state and
fail-closed fault-injection state for tests, but they do not implement full
normative procedures, peer routing, business policy, retransmission behavior, or
carrier acceptance evidence.

## Protocol-crate ownership

| Simulator | Decode owner | Current interface |
| --- | --- | --- |
| PGW S2b | `opc-proto-gtpv2c` | `S2bMessageView` adapters over SDK-decoded S2b typed views. Tests decode spec-authored GTPv2-C S2b fixtures with `opc-proto-gtpv2c` before calling the simulator. |
| Diameter peer | `opc-proto-diameter` | `DiameterMessageView` metadata trait. The simulator records SDK-decoded command metadata only and carries no raw Diameter parser. |

Both simulators expose `SdkDecodeProfile` values built from `opc-protocol`
limits so test code can use consistent validation settings when invoking the
protocol crate.

## Fixture provenance

Simulator interface tests reuse the spec-authored S2b fixtures owned by
`opc-proto-gtpv2c`. The manifest at
`crates/opc-testbed/tests/fixtures/epc_epdg_simulator_manifest.json` records the
provenance class, owning protocol crate, and redaction status for each packet
used by the simulator tests.

Diameter packet fixtures remain owned by `opc-proto-diameter`, not by this
testbed skeleton. The manifest records the Diameter interface as
`no-packet-fixture-yet` and `sdk-protocol-crate-only`; adding raw Diameter bytes
to `opc-testbed` must preserve ADR 0015 fixture provenance and keep the protocol
crate as conformance owner.

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

- Add a reusable `opc-proto-diameter` adapter if the metadata bridge needs more
  than local integration-test wrappers.
- Add UE/IKE and charging CDF simulator skeletons only after their protocol
  crates or decoded-view boundaries exist.
- Extend RFC 012 scenarios with protocol-specific packet steps only after the
  DSL has schema support for fixture provenance and raw-byte ownership.
