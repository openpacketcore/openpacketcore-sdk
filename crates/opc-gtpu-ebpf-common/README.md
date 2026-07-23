# opc-gtpu-ebpf-common

## Purpose

`opc-gtpu-ebpf-common` is the shared, dependency-free, no-std layout crate for
the GTP-U eBPF datapath and its userspace loader. It is the single source of
truth for BPF map values, program/map names, counter indexes, and byte-exact
GTP-U encapsulation/classification helpers.

## API Shape

- Constants for GTP-U, IPv4, IPv6, UDP, map names, program names, and counter
  slots.
- `UplinkFar`, `DownlinkPdr`, `DownlinkEndpointBinding`, and
  `MarkedBearerOwner` encode/decode fixed BPF map value layouts.
- `GtpuEndpointAddress` and `GtpuSourcePortPolicy` model canonical IPv4/IPv6
  endpoint identity plus explicit `Any`, exact, or inclusive-range UDP source
  authorization. `validate_ipv4_downlink_binding_wire` and the owner wire
  helpers provide allocation-free verifier-facing checks over map-owned bytes.
- `DownlinkBindingMismatch` defines the fixed invalid/family/peer/local/
  ingress/source-port counter cardinality; map names and indexes are shared by
  userspace and the tc object.
- `build_uplink_encap` builds the exact 36-byte outer IPv4/UDP/GTPv1-U header
  sequence for uplink encapsulation.
- `classify_gtpu` classifies a mandatory GTP-U header as `NotGtpV1`,
  `NotGpdu`, or `Gpdu { teid, length, has_opt, has_ext }`.
- `ipv4_header_checksum` computes an option-free IPv4 header checksum.
- `Ipv4EnvelopeBounds`, `UdpEnvelopeBounds`, and `GtpuEnvelopeBounds` validate
  the exact nested downlink boundary with checked arithmetic while retaining
  legal layer-2 padding outside the IPv4 packet.
- `Ipv6UdpEnvelopeBounds` validates the exact IPv6 payload, UDP, and GTP-U
  boundaries. The bounded extension walker accepts safe option headers and
  atomic fragments, rejects jumbograms and packets requiring reassembly, and
  lets a shared hook distinguish unrelated IPv6 traffic from a malformed
  UDP/2152 candidate.
- `classify_udp_checksum` uses typed `UdpChecksumEvidence` to distinguish legal
  IPv4 checksum omission, positive kernel verification, and exact software
  verification. `NoPendingOffload` is an explicit caller proof, not something
  inferred from a failed metadata query. Internet and IPv4 UDP checksum helpers
  cover variable and odd-length fixtures without kernel access.
- IPv6 UDP checksum helpers always require a non-zero, valid checksum and
  preserve an odd byte across segmented inputs.
- The `GtpuSession*` layouts define a separate family-tagged grouped-session
  schema: canonical inner IPv4 `/32` and TS 29.274 IPv6 `/64` PAAs, exact outer
  `/32` or `/128` endpoints, generation/slot index candidates, one normal HASH
  authority value, exact device configuration, and a bounded in-flight
  transaction journal.

All multi-byte wire and map fields are network byte order unless noted in the
Rust docs.

## Usage

```rust
use opc_gtpu_ebpf_common::{
    build_uplink_encap, DownlinkEndpointBinding, DownlinkPdr,
    GtpuEndpointAddress, GtpuSourcePortPolicy, UplinkFar, GTPU_ENCAP_LEN,
};

let far = UplinkFar {
    peer_ip: [192, 0, 2, 10],
    local_ip: [192, 0, 2, 20],
    o_teid: 0x2000_0001u32.to_be_bytes(),
};
let bytes = far.encode();
assert_eq!(UplinkFar::decode(&bytes), far);

let pdr = DownlinkPdr { ue_ip: [10, 23, 0, 2] };
assert_eq!(DownlinkPdr::decode(&pdr.encode()), pdr);

let binding = DownlinkEndpointBinding::new(
    GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
    GtpuEndpointAddress::Ipv4([192, 0, 2, 20]),
    7,
    GtpuSourcePortPolicy::Exact(2152),
)
.unwrap();
assert_eq!(DownlinkEndpointBinding::decode(&binding.encode()), binding);

let encap = build_uplink_encap(&far, 64).unwrap();
assert_eq!(encap.len(), GTPU_ENCAP_LEN);
```

## Relationships

- Used by `opc-gtpu-dataplane-ebpf` inside BPF code.
- Used by `opc-gtpu-dataplane` userspace code when writing pinned maps and
  validating datapath ownership.

## Status And Limits

- `#![no_std]`, `#![forbid(unsafe_code)]`, and dependency-free.
- Contains no map access, loader code, tc hooks, kernel syscalls, or product
  policy.
- The grouped-session constants are an additive ABI foundation. They do not
  change legacy key bytes or claim that a loader or tc program currently
  publishes the new maps. The independent `GTPU_SCHEMA6` marker prevents a v5
  graph from being mistaken for this schema.
- Group authority is designed for whole-value `BPF_MAP_UPDATE_ELEM` replacement
  in an ordinary non-per-CPU HASH map. A tc consumer retains an index value,
  performs one authority lookup, validates generation and slot, and does not
  re-read the index. An old RCU holder may therefore finish; immediate
  selector/TEID reuse still requires a caller-proven drain or grace period.
- Public construction creates only Active authority and Prepared journals.
  Pending/Removing authority comes only from the matching phase-gated journal
  helper, while later journal phases come only from canonical `advance` or
  validation of already-persisted bytes.
- Group IDs are caller-owned cryptographically unique values, never selector
  derivatives, and are permanently retired by the caller for the stable pin
  namespace lifetime. The bounded dataplane journal retains only in-flight
  work, not permanent tombstones.
- The 44-byte endpoint-binding layout is canonical and versioned. IPv4 values
  zero their unused twelve-byte tails; families must match; addresses and the
  ingress ifindex must be non-zero; exact/range policy encodings are bounded.
  Decode retains invalid-format evidence rather than normalizing corrupt map
  bytes into an authorized value.
- The shared envelope model validates declarations and checksum bytes but does
  not inspect kernel checksum metadata or access packet memory. A live skb
  caller must exclude pending offload before supplying `NoPendingOffload`; the
  eBPF program owns that evidence boundary and GTP-U extension walking.
- The shared IPv6 ingress triage is intentionally not an IPv6 firewall.
  Unrelated traffic, unsupported extension processing such as AH/ESP, and
  packets requiring reassembly pass to the host stack. Only a packet already
  proven to target UDP/2152 becomes a reject candidate for malformed envelope
  or checksum state.

## Roadmap

- Treat layout changes as compatibility-sensitive and cover them with tests.
- Add new map or counter fields only when both loader and BPF program consume
  the same versioned layout.

## Verification

```sh
cargo test -p opc-gtpu-ebpf-common
```
