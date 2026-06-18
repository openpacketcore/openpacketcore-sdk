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

Current capability limits:

- Multi-address bind/connect fails closed in this profile; callers must use a
  single local and remote address per association.
- Custom RTO and heartbeat options are represented in config but non-default
  values fail closed unless the Linux UAPI layouts are explicitly supported.
- Live loopback tests are ignored unless run on a host with kernel SCTP support.
