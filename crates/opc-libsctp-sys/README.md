# opc-libsctp-sys

`opc-libsctp-sys` is the single OpenPacketCore crate permitted by ADR 0017 to
contain unsafe SCTP transport boundary code. It wraps Linux kernel SCTP socket
UAPI calls through `libc` and exposes only small, typed helpers to the safe
`opc-sctp` crate.

The crate does not implement SCTP in userspace and does not bind any foreign
protocol codec. Non-Linux platforms compile to explicit unsupported-platform
errors.
