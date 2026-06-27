# opc-proto-gtpv2c

`opc-proto-gtpv2c` is the OpenPacketCore GTPv2-C crate for an experimental,
S2b-focused typed subset.

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
- a public `MessageType` enum with `Unknown(u8)` fallback plus raw fallback for
  unsupported/private IEs; and
- a cargo-fuzz manifest and decode target skeleton.

It does **not** provide a complete GTPv2-C implementation, full S2b semantic
state-machine validation, carrier acceptance evidence, or a production ePDG/PGW
control-plane stack. See [CONFORMANCE.md](CONFORMANCE.md) for the precise
evidence boundary.

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
cargo test -p opc-proto-gtpv2c --all-features s2b_typed
```
