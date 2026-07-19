# opc-linux-route-sys

## Purpose

`opc-linux-route-sys` is the narrow unsafe boundary for Linux rtnetlink route
and rule operations. It owns the raw socket wrapper and selected UAPI
constants/layouts used by the safe `opc-route-steering` crate for bounded
mutation and readback.

It does not implement route policy, table allocation, session steering,
namespace management, privilege selection, or product deployment defaults.

## API Shape

- `NetlinkSocket`: close-on-exec, nonblocking rtnetlink socket wrapper.
- Functions: `open_route_netlink_socket`, `send_message`, and
  `receive_message`; receive rejects truncated datagrams and non-kernel sender
  addresses before exposing bytes to the safe parser.
- UAPI constants for netlink flags/control messages, `RTM_NEWROUTE`,
  `RTM_DELROUTE`, `RTM_GETROUTE`, `RTM_NEWRULE`, `RTM_DELRULE`, `RTM_GETRULE`,
  multipart dump flags, address families, route tables, route attributes, and
  rule attributes, including `RTPROT_STATIC` and `FRA_PROTOCOL`.
- `repr(C)` layouts: `NetlinkMessageHeader`, `RouteAttributeHeader`,
  `RouteMessage`, `FibRuleHeader`, and `NetlinkErrorMessage`.
- `align_to_netlink` for Linux 4-byte netlink attribute/message alignment.

## Usage

Most callers should use `opc-route-steering` instead:

```rust,no_run
use opc_linux_route_sys::{
    open_route_netlink_socket, receive_message, send_message,
};

let socket = open_route_netlink_socket()?;
let request = Vec::<u8>::new();
send_message(&socket, &request)?;

let mut response = vec![0u8; 8192];
let _len = receive_message(&socket, &mut response)?;
# Ok::<(), std::io::Error>(())
```

## Relationships

- Used by `opc-route-steering` for route/rule netlink transactions.
- Separate from `opc-linux-gtpu-sys` and `opc-linux-xfrm-sys` so each safe
  wrapper depends only on the UAPI family it needs.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Contains the syscall `unsafe` allowed by its lint configuration.
- Non-Linux or `opc_linux_route_sys_force_unsupported` builds compile to
  unsupported stubs.
- The crate sends and receives opaque buffers; request encoding and policy live
  in `opc-route-steering`.
- Exporting the `FRA_PROTOCOL` constant does not assert runtime kernel support.
  The safe wrapper performs non-mutating version evidence, per-create readback,
  and leak-safe rollback; upstream Linux added the attribute in 4.17 and older
  vendor kernels may backport it.

## Roadmap

- Keep the public UAPI surface narrow and driven by safe-wrapper needs.
- Add layout tests for any new kernel structs before exposing them.

## Verification

```sh
cargo test -p opc-linux-route-sys
```
