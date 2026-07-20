# opc-linux-gtpu-sys

## Purpose

`opc-linux-gtpu-sys` is the narrow unsafe boundary for Linux GTP-U dataplane
syscalls and selected UAPI definitions. It opens route and generic netlink
sockets, opens bound GTP-U UDP sockets, resolves interface indexes, sends and
receives raw netlink datagrams, and exposes the constants/layouts needed by
`opc-gtpu-dataplane`.

It does not implement PDP lifecycle policy, GTP-U packet encoding, route
steering, XFRM policy, namespace management, privilege selection, or deployment
defaults.

## API Shape

- Socket wrappers: `NetlinkSocket`, including its kernel-assigned local port
  identifier for reply correlation, and `GtpuUdpSocket`.
- Bind model: `GtpuUdpBind` and `GtpuIpAddress`.
- Functions: `open_route_netlink_socket`, `open_generic_netlink_socket`,
  `open_gtpu_udp_socket`, `ifindex_by_name`, `send_message`, and
  `receive_message`.
- UAPI constants for netlink flags/control messages, rtnetlink link/tc
  messages, GTP link attributes, GTP generic-netlink commands, PDP attributes,
  and address families.
- `repr(C)` layouts: `NetlinkMessageHeader`, `RouteAttributeHeader`,
  `IfInfoMessage`, `GenericNetlinkHeader`, and `NetlinkErrorMessage`.
- `align_to_netlink` for Linux 4-byte netlink attribute/message alignment.

## Usage

Most callers should use `opc-gtpu-dataplane` instead. Direct use is intended
for safe wrapper code that needs raw UAPI buffers:

```rust,no_run
use opc_linux_gtpu_sys::{
    open_generic_netlink_socket, receive_message, send_message,
};

let socket = open_generic_netlink_socket()?;
let request = Vec::<u8>::new();
send_message(&socket, &request)?;

let mut response = vec![0u8; 8192];
let _len = receive_message(&socket, &mut response)?;
# Ok::<(), std::io::Error>(())
```

## Relationships

- Used by `opc-gtpu-dataplane` Linux netdevice backend.
- eBPF map/wire layouts are not here; they live in `opc-gtpu-ebpf-common`.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Contains the syscall `unsafe` allowed by its lint configuration.
- Non-Linux or `opc_linux_gtpu_sys_force_unsupported` builds compile to
  unsupported stubs.
- `receive_message` uses `MSG_TRUNC` handling and returns `InvalidData` rather
  than silently accepting truncated datagrams.

## Roadmap

- Add only the Linux UAPI constants/layouts required by safe wrappers.
- Keep platform stubs explicit so downstream crates can compile and report
  unsupported platforms honestly.

## Verification

```sh
cargo test -p opc-linux-gtpu-sys
```
