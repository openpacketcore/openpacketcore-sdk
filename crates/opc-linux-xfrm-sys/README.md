# opc-linux-xfrm-sys

## Purpose

`opc-linux-xfrm-sys` is the narrow unsafe boundary for Linux `NETLINK_XFRM`.
It exposes the raw socket wrapper plus selected XFRM netlink constants and
`repr(C)` layouts needed by `opc-ipsec-xfrm`.

It does not implement IKE, ESP processing, SA/SPD policy, namespace management,
privilege selection, or deployment defaults.

## API Shape

- `NetlinkSocket`: close-on-exec, nonblocking XFRM netlink socket wrapper.
- Functions: `open_netlink_socket`, `send_message`, `receive_message`, and the
  typed `receive_message_outcome` boundary.
- `ReceiveMessageOutcome` distinguishes a complete bounded datagram from an
  oversized datagram that Linux has already consumed, retaining both sizes
  without parsing an error string.
- UAPI constants for netlink flags/control messages, XFRM SA/policy message
  types, policy directions/actions, modes, optional attributes, ESN flags, and
  algorithm name length.
- `repr(C)` layouts for XFRM addresses, IDs, selectors, lifetimes, stats, SA
  info, SA IDs, policy info, policy IDs, templates, SPI allocation, algorithm
  headers, marks, UDP encapsulation templates, netlink headers, and errors.
- `XfrmAddress::{from_words, from_ipv4_octets, from_ipv6_octets}` helpers.
- `align_to_netlink` for Linux 4-byte netlink attribute/message alignment.

## Usage

Most callers should use `opc-ipsec-xfrm` instead:

```rust,no_run
use opc_linux_xfrm_sys::{open_netlink_socket, receive_message, send_message};

let socket = open_netlink_socket()?;
let request = Vec::<u8>::new();
send_message(&socket, &request)?;

let mut response = vec![0u8; 16384];
let _len = receive_message(&socket, &mut response)?;
# Ok::<(), std::io::Error>(())
```

## Relationships

- Used by `opc-ipsec-xfrm` for safe SA/SPD operations.
- Kept separate from the GTP-U and route sys crates to limit unsafe ownership.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Contains the syscall `unsafe` allowed by its lint configuration.
- Non-Linux or `opc_linux_xfrm_sys_force_unsupported` builds compile to
  unsupported stubs.
- `receive_message_outcome` treats the caller buffer as a hard cap. It reports
  `ConsumedOversize` with the configured and actual sizes after Linux consumes
  an oversized datagram; callers must not try a second receive for that
  datagram.
- The source-compatible `receive_message` wrapper maps `ConsumedOversize` to
  `InvalidData`. Mutation-aware callers should use the typed API so they can
  preserve ownership ambiguity.

## Roadmap

- Add XFRM UAPI structs only when the safe wrapper encodes or decodes them.
- Keep layout and constant tests in lockstep with any expanded kernel surface.

## Verification

```sh
cargo test -p opc-linux-xfrm-sys
```
