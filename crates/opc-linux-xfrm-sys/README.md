# opc-linux-xfrm-sys

## Purpose

`opc-linux-xfrm-sys` is the narrow unsafe boundary for Linux `NETLINK_XFRM`.
It exposes the raw socket wrapper plus selected XFRM netlink constants and
`repr(C)` layouts needed by `opc-ipsec-xfrm`.

It does not implement IKE, ESP processing, SA/SPD policy, namespace management,
privilege selection, or deployment defaults.

## API Shape

- `NetlinkSocket`: close-on-exec, nonblocking XFRM netlink socket wrapper.
- Functions: `open_netlink_socket`, `send_message`, and `receive_message`.
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
- `receive_message` consumes oversized netlink datagrams and reports
  `InvalidData`; callers should size buffers for expected XFRM responses.

## Roadmap

- Add XFRM UAPI structs only when the safe wrapper encodes or decodes them.
- Keep layout and constant tests in lockstep with any expanded kernel surface.

## Verification

```sh
cargo test -p opc-linux-xfrm-sys
```
