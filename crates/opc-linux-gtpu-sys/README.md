# opc-linux-gtpu-sys

`opc-linux-gtpu-sys` is a narrow Linux rtnetlink, generic-netlink, and UDP
socket UAPI boundary for OpenPacketCore GTP-U dataplane readiness work. It owns
the small amount of `unsafe` syscall code needed to open route/generic netlink
sockets, exchange raw messages with the kernel, and bind the UDP GTP-U socket
passed to the kernel `gtp` netdevice.

The crate does not implement GTP-U packet encoding, PDP lifecycle policy,
routes, XFRM steering, namespace management, or product deployment defaults.
Non-Linux platforms compile to explicit unsupported-platform stubs.
