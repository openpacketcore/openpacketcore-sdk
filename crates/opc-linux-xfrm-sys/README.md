# opc-linux-xfrm-sys

`opc-linux-xfrm-sys` is a narrow Linux XFRM/netlink UAPI boundary for
OpenPacketCore IPsec readiness work. It owns the small amount of `unsafe`
syscall code needed to open and exchange raw messages on `NETLINK_XFRM`, plus
`repr(C)` Rust definitions for the XFRM structures used by the later safe
IPsec/XFRM wrapper.

The crate does not implement IKEv2, ESP, SA/SPD policy, namespace management,
privilege selection, or product deployment defaults. Non-Linux platforms compile
to explicit unsupported-platform stubs.
