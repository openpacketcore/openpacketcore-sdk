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

Deliberate, fail-closed divergences from the userspace classifier: any IP
fragmentation (including initial fragments), every packet whose base IPv6
header names an IANA-registered extension kind except direct native ESP, and
ICMP error quotes are handed to the slow path rather than classified. This
includes extension kinds the userspace walker rejects, preventing an unwalked
extension from concealing SWu traffic. Userspace performs the complete IPv6
extension order, duplicate, AH-alignment, and fragment validation for its
supported subset. 802.1Q VLAN-tagged ingress bypasses
steering entirely (the ethertype is not IPv4/IPv6), passing untouched —
consistent with the userspace classifier and never a drop.

Each classified packet is looked up in the pinned owner map
(`IPSEC_LB_OWNERS`), keyed by the canonical destination-scoped ownership key
(destination address + routing domain + encapsulation + SPI context) shared
with `SessionOwnershipKey::to_canonical_bytes`. The verdict is fail-closed and
the program never returns `XDP_DROP`:

- owner = self -> `XDP_PASS` (local counter);
- owner = remote -> `XDP_REDIRECT` into the configured userspace-redirector
  hand-off interface (redirect counter, incremented only when the
  `bpf_redirect` helper confirms the redirect; a helper-level failure falls
  back to the slow path with the error counter). The authenticated steering
  encapsulation is applied in userspace: AEAD crypto cannot run in the
  kernel, so the kernel/userspace split is this explicit, observable channel.
  Some kernels defer transmit failures past the helper return, so the loader
  additionally validates the hand-off interface at attach time (it must
  exist, be up, and differ from the attached interface);
- map miss, absent destination-scoped fence, or stale ownership generation ->
  slow path. ABI v5 selects the fence domain through `IPSEC_LB_CONFIG`:
  legacy/global operation reads the single-entry `IPSEC_LB_FENCE` map, while
  production re-pin reads the same canonical key from
  `IPSEC_LB_KEY_FENCES`. An owner is live only when its generation exactly
  equals the selected nonzero fence; owner-first/fence-last publication and
  fence-first retirement therefore remain fail-closed at every crash cut;
  unclassifiable SWu candidates, and internal errors -> `XDP_PASS` to the
  userspace slow path with a distinct counter each.

Per-verdict per-CPU counters are exported via `IPSEC_LB_COUNTERS` (local,
redirect, miss, stale, unclassifiable, error, plus pass-through and NAT-T
keepalive). No map or program section carries IPsec key material.

## Kernel feature floor

- Load/attach: Linux >= 5.18 with kernel BTF (`/sys/kernel/btf/vmlinux`),
  XDP `bpf_link`, bpffs map pinning, per-CPU arrays, `bpf_redirect`, and
  `bpf_xdp_load_bytes`, plus effective `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`.
  `CAP_BPF` alone is insufficient for the loader's exact object-enumeration
  and ID-open checks. The loader probes the helper and confirms the attachment
  produced a BPF link; legacy netlink fallback is detached and rejected.
- Graceful cross-process handoff stages a fresh versioned map namespace and
  uses `bpf_link_update` with `BPF_F_REPLACE` and the exact expected old
  program, so there is no unattached or silently overwritten window.

The `opc-ipsec-lb` loader enforces both floors with the typed
`IpsecLbError::XdpKernelFloorNotMet` error.
