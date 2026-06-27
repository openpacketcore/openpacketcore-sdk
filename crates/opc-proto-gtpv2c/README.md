# opc-proto-gtpv2c

`opc-proto-gtpv2c` is the OpenPacketCore GTPv2-C crate scaffold for a future
S2b-focused control-plane subset.

Current scope is intentionally narrow:

- common GTPv2-C header decode/encode integrated with `opc-protocol` traits;
- raw-preserving TLIV Information Element validation and iteration;
- owned and borrowed message shells for async handoff and forwarding paths;
- S2b procedure message-type constants for follow-on typed work;
- a cargo-fuzz manifest and decode target skeleton.

It does **not** yet provide typed S2b procedure validation, mandatory-IE
checking, carrier conformance for Create/Modify/Delete Session exchanges, or a
production ePDG/PGW control-plane stack. See [CONFORMANCE.md](CONFORMANCE.md)
for the precise evidence boundary.

## Minimal use

```rust
use opc_proto_gtpv2c::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
let (_tail, message) = Message::decode(&packet, DecodeContext::default())?;
assert_eq!(message.header.sequence_number, 1);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Verification

```bash
cargo check -p opc-proto-gtpv2c --all-targets --all-features
cargo test -p opc-proto-gtpv2c --all-features header
cargo test -p opc-proto-gtpv2c --all-features ie_raw
cargo test -p opc-proto-gtpv2c --all-features malformed
```
