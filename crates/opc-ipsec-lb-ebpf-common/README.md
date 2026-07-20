# opc-ipsec-lb-ebpf-common

Shared, dependency-free map layouts for the SWu IPsec load-balancing XDP
datapath and its userspace loader.

This crate intentionally contains no IPsec key material, packet decryption, or
runtime I/O. It defines only stable byte encodings and the shared decision
logic used by both the eBPF program and the host:

- the versioned, pinned owner-map ABI: a fixed 64-byte key wrapping the
  canonical destination-scoped ownership key (`SessionOwnershipKey`'s
  `OPCO` encoding, owned here so kernel and userspace derive byte-identical
  keys), and a 16-byte value with owner identity and ownership generation
  (whole-value atomic-per-key updates in practice, with a strict
  flags/reserved-byte decode that fails closed if a value is ever torn);
- the versioned single-slot datapath configuration (self shard, routing
  domain, userspace-redirector hand-off ifindex) and the separate
  single-slot ownership fence generation, an aligned `u64` in its own map
  so fence advances are tear-free single stores;
- the per-verdict counter indices (local, redirect, miss, stale,
  unclassifiable, error, pass-through, NAT-T keepalive);
- the branch-bounded transport classification decision procedure
  (`classify_transport`), owner-map key derivation (`ownership_map_key`), and
  owner-verdict decision (`decide_owner_verdict`), shared verbatim by the
  eBPF program and host-side tests;
- the documented kernel feature floor constants for load/attach (5.4) and
  atomic program replacement (5.7);
- the authenticated ingress-redirect frame header ABI used by the userspace
  redirect transport.
