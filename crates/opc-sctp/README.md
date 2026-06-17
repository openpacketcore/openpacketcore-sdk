# opc-sctp

`opc-sctp` is the safe SCTP transport foundation for OpenPacketCore CNFs that
terminate N2/NGAP or other SCTP interfaces.

Current support:

- Linux-only SCTP sockets through the `opc-libsctp-sys` ADR 0017 boundary.
- One-to-one and one-to-many socket modes.
- Tokio readiness integration through `AsyncFd`.
- Message-boundary preserving send/receive APIs.
- Stream ID, association ID, ordered/unordered delivery, and PPID metadata.
- NGAP PPID helper for PPID 60 with explicit host/network byte-order handling.
- Capability-honest unsupported-platform errors on non-Linux hosts.

Current explicit deferrals:

- Multi-address bind/connect fails closed until a layout-backed
  `sctp_bindx`/`sctp_connectx` helper boundary is added.
- Custom RTO and heartbeat options are represented in config but non-default
  values fail closed until their Linux UAPI layouts are bound and tested.
- Live loopback tests are ignored unless run on a host with kernel SCTP support.
