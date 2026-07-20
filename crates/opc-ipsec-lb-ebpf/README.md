# opc-ipsec-lb-ebpf

Standalone XDP eBPF program for SWu IPsec load balancing.

This crate is excluded from the host workspace and built with
`scripts/build-ipsec-lb-ebpf.sh` for `bpfel-unknown-none`. The userspace loader
uses the committed object through `opc-ipsec-lb`.

## What the program does

The program executes the same branch-bounded keyless classification decision
procedure as the userspace classifier in `opc-ipsec-lb`:

- UDP/500 -> IKE;
- UDP/4500 with a zero RFC 3948 non-ESP marker -> IKE; a nonzero first word ->
  ESP-in-UDP (SPI extracted);
- IP protocol 50 -> native ESP (SPI extracted);
- anything else -> passed to the normal stack untouched.

Each classified packet is looked up in the pinned owner map
(`IPSEC_LB_OWNERS`), keyed by the canonical destination-scoped ownership key
(destination address + routing domain + encapsulation + SPI context) shared
with `SessionOwnershipKey::to_canonical_bytes`. The verdict is fail-closed and
the program never returns `XDP_DROP`:

- owner = self -> `XDP_PASS` (local counter);
- owner = remote -> `XDP_REDIRECT` into the configured userspace-redirector
  hand-off interface (redirect counter). The authenticated steering
  encapsulation is applied in userspace: AEAD crypto cannot run in the
  kernel, so the kernel/userspace split is this explicit, observable channel;
- map miss, stale ownership generation (entry older than the configured
  fence), unclassifiable SWu candidates, and internal errors -> `XDP_PASS` to
  the userspace slow path with a distinct counter each.

Per-verdict per-CPU counters are exported via `IPSEC_LB_COUNTERS` (local,
redirect, miss, stale, unclassifiable, error, plus pass-through and NAT-T
keepalive). No map or program section carries IPsec key material.

## Kernel feature floor

- Load/attach: Linux >= 5.4 with kernel BTF (`/sys/kernel/btf/vmlinux`),
  XDP, bpffs map pinning, per-CPU arrays, `bpf_redirect`, and
  `bpf_xdp_load_bytes` (since 4.18).
- Graceful program replacement: Linux >= 5.7 (netlink `XDP_FLAGS_REPLACE` +
  `IFLA_XDP_EXPECTED_FD`) or >= 5.9 (XDP `bpf_link` update). Replacement
  adopts the pinned maps and swaps the program atomically, so there is no
  window of dropped or mis-verdicted traffic.

The `opc-ipsec-lb` loader enforces both floors with the typed
`IpsecLbError::XdpKernelFloorNotMet` error.
