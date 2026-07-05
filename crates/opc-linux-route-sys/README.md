# opc-linux-route-sys

`opc-linux-route-sys` is a narrow Linux rtnetlink UAPI boundary for
OpenPacketCore dataplane route and rule steering work. It owns the small amount
of `unsafe` syscall code needed to open `NETLINK_ROUTE` sockets and exchange raw
route/rule messages with the kernel, plus `repr(C)` Rust definitions for the
selected route and rule structures used by the safe wrapper.

The crate does not implement route policy, table allocation, session steering
decisions, namespace management, privilege selection, or product deployment
defaults. Non-Linux platforms compile to explicit unsupported-platform stubs.
