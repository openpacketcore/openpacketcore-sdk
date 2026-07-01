# opc-proto-gtpv2c

`opc-proto-gtpv2c` is the OpenPacketCore GTPv2-C crate for an S2b-focused typed
subset with **S2b Production Profile v1** available for the documented codec,
typed-view, validation, and transport-neutral helper boundary.

Current scope is intentionally narrow:

- common GTPv2-C header decode/encode integrated with `opc-protocol` traits;
- raw-preserving TLIV Information Element validation and iteration;
- owned and borrowed message shells for async handoff and forwarding paths;
- typed S2b IE examples for IMSI, Cause, Recovery, APN, AMBR, EBI, MEI,
  MSISDN, Indication, PCO, PAA, Bearer QoS, RAT Type, Serving Network,
  F-TEID, Bearer Context, Charging ID, PDN Type, APN Restriction, Selection
  Mode, and APCO;
- typed S2b message views for Echo plus Create/Modify/Delete/Update
  Session-oriented flows, with ProcedureAware mandatory-IE checks for the
  claimed examples;
- public profile constructors for Echo, Create Session, Modify Bearer, Delete
  Session, and Update Bearer profile-owned request/response shapes;
- a transport-neutral Echo peer helper that tracks liveness, Recovery restart
  counters, and restart-reconciliation fencing before new Echo exchanges;
- provenance-labeled fixture replay that separates spec-authored conformance
  bytes, independent-capture intake, parity-only ePDG regression seeds, and
  synthetic malformed inputs;
- a public `MessageType` enum with `Unknown(u8)` fallback plus raw fallback for
  unsupported/private IEs; and
- cargo-fuzz decode, typed S2b, and raw-preserving round-trip targets.

The Production Profile v1 boundary is a codec, typed-view, validation, and
transport-neutral helper profile for ePDG/PGW S2b integration. Public profile
constructors cover Echo, Create Session, Modify Bearer, Delete Session, and
Update Bearer profile-owned request/response shapes. It does **not** provide a
complete GTPv2-C implementation, full S2b semantic state-machine validation
beyond the documented Echo and client-transaction helpers, carrier acceptance
evidence, independent-peer interoperability evidence, or a production ePDG/PGW
control-plane stack. See
[CONFORMANCE.md](CONFORMANCE.md) for the precise production profile boundary.

## Minimal use

```rust
use opc_proto_gtpv2c::S2bMessage;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
let (_tail, message) = S2bMessage::decode(&packet, DecodeContext::default())?;
assert!(message.as_view().is_some());
# Ok::<(), opc_protocol::DecodeError>(())
```

## Verification

```bash
cargo check -p opc-proto-gtpv2c --all-targets --all-features
cargo test -p opc-proto-gtpv2c --all-features header
cargo test -p opc-proto-gtpv2c --all-features ie_raw
cargo test -p opc-proto-gtpv2c --all-features malformed
cargo test -p opc-proto-gtpv2c --all-features --test corpus_replay
cargo test -p opc-proto-gtpv2c --all-features --test s2b_typed
cargo run -p opc-proto-gtpv2c --example production_profile_v1
(cd crates/opc-proto-gtpv2c && cargo +nightly fuzz list)
```

For the Production Profile v1 constructor and ProcedureAware validation path,
see `examples/production_profile_v1.rs`. It constructs Echo, Create Session,
Modify Bearer, Delete Session, and Update Bearer S2b messages through typed
APIs, then encodes and decodes them without manual raw byte assembly.
