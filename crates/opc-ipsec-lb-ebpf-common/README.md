# opc-ipsec-lb-ebpf-common

Shared, dependency-free map layouts for the SWu IPsec load-balancing XDP
datapath and its userspace loader.

This crate intentionally contains no IPsec key material, packet decryption, or
runtime I/O. It defines only stable byte encodings and the shared decision
logic used by both the eBPF program and the host:

- the versioned, pinned owner-map ABI: a fixed 64-byte key wrapping the
  canonical destination-scoped ownership key (`SessionOwnershipKey`'s
  `OPCO` encoding, owned here so kernel and userspace derive byte-identical
  keys), and a 16-byte value with owner identity and ownership generation;
  the kernel hash map publishes a replacement element old-or-new to
  concurrent readers, while strict flags/reserved-byte decoding makes schema
  skew fail closed;
- the versioned single-slot datapath configuration (self shard, routing
  domain, userspace-redirector hand-off ifindex) and the separate
  single-entry ownership fence generation in its own hash map, so replacement
  publishes the old or new `u64` element to concurrent readers;
- the per-verdict counter indices (local, redirect, miss, stale,
  unclassifiable, error, pass-through, NAT-T keepalive);
- the branch-bounded transport classification decision procedure
  (`classify_transport`), owner-map key derivation (`ownership_map_key`), and
  owner-verdict decision (`decide_owner_verdict`), shared verbatim by the
  eBPF program and host-side tests;
- the fail-closed split for IPv6 extensions: XDP slow-paths every current
  IANA-registered extension kind except direct native ESP, while userspace
  performs a complete semantic walk for its supported subset and rejects the
  rest;
- the documented Linux 5.18 kernel feature floor for `bpf_xdp_load_bytes` and
  XDP `bpf_link` attachment/replacement;
- the authenticated ingress-redirect frame header ABI used by the userspace
  redirect transport.
