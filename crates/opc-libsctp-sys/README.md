# opc-libsctp-sys

## Purpose

`opc-libsctp-sys` is the narrow unsafe SCTP socket boundary allowed for
OpenPacketCore transport work. It wraps Linux kernel SCTP socket UAPI calls
through `libc` and exposes typed helpers to the safe `opc-sctp` crate.

It does not implement SCTP in userspace and does not bind NGAP, Diameter, or
other protocol codecs.

## API Shape

- Types: `AssocId`, `AddressFamily`, `SocketStyle`, `ConnectStatus`, `InitMsg`,
  `RtoParameters`, `PeerAddressParameters`, `EventSubscriptions`, `SendInfo`,
  `RecvInfo`, `RecvFlags`, and `Received`.
- Functions: `open_socket`, single-address `bind`/`connect`, bounded atomic
  `bind_addresses`/`connect_addresses`, `local_addresses`, `peer_addresses`,
  `peer_primary_address`, `listen`, `accept`, `socket_error`, `set_initmsg`,
  `set_rto_parameters`, `set_peer_address_parameters`,
  `set_primary_peer_address`, `set_nodelay`, `set_recv_rcvinfo`, `set_events`,
  `send_msg`, and `recv_msg`.
- Constants: `SCTP_UNORDERED_FLAG`, `SCTP_NOTIFICATION_FLAG`,
  `SCTP_ASSOC_CHANGE_NOTIFICATION`, and `SCTP_SHUTDOWN_EVENT_NOTIFICATION`.

## Usage

Most callers should use `opc-sctp` instead. Direct use is for safe transport
wrapper code that needs file-descriptor-level control.

```rust,no_run
use opc_libsctp_sys::{open_socket, AddressFamily, SocketStyle};

let fd = open_socket(AddressFamily::Ipv4, SocketStyle::OneToOne)?;
# Ok::<(), std::io::Error>(())
```

## Relationships

- Used by `opc-sctp` for Tokio-integrated SCTP endpoints and associations.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Contains Linux SCTP syscall/ancillary-data `unsafe`.
- Non-Linux builds return explicit unsupported-platform errors.
- Bindx/connectx use the Linux packed-address socket UAPI directly, without a
  runtime `libsctp` dependency, and accept at most `MAX_SCTP_ADDRESSES` entries.
- Address-list inspection is bounded to the same maximum and rejects malformed
  kernel responses before exposing them to the safe crate.
- RTO, peer-path heartbeat/retransmission, and primary-address helpers bind the
  exact Linux packed/aligned UAPI layouts. Unit tests assert every field offset,
  total size, alignment, option-update encoding, wildcard behavior, and
  redaction-safe peer-parameter `Debug` output.

## Roadmap

- Add further SCTP options only when the safe crate can validate and expose
  them without guessing at UAPI layout.
- Keep unsupported-platform behavior explicit and tested.

## Verification

```sh
cargo test -p opc-libsctp-sys
cargo test -p opc-libsctp-sys linux::tests::loopback_bindx_connectx_reports_all_addresses -- --ignored --exact
cargo test -p opc-libsctp-sys linux::tests::loopback_path_tuning_and_primary_selection -- --ignored --exact
```
