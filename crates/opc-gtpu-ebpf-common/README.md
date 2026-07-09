# opc-gtpu-ebpf-common

## Purpose

`opc-gtpu-ebpf-common` is the shared, dependency-free, no-std layout crate for
the GTP-U eBPF datapath and its userspace loader. It is the single source of
truth for BPF map values, program/map names, counter indexes, and byte-exact
GTP-U encapsulation/classification helpers.

## API Shape

- Constants for GTP-U, IPv4, UDP, map names, program names, and counter slots.
- `UplinkFar` and `DownlinkPdr` encode/decode fixed BPF map value layouts.
- `build_uplink_encap` builds the exact 36-byte outer IPv4/UDP/GTPv1-U header
  sequence for uplink encapsulation.
- `classify_gtpu` classifies a mandatory GTP-U header as `NotGtpV1`,
  `NotGpdu`, or `Gpdu { teid, length, has_opt, has_ext }`.
- `ipv4_header_checksum` computes an option-free IPv4 header checksum.

All multi-byte wire and map fields are network byte order unless noted in the
Rust docs.

## Usage

```rust
use opc_gtpu_ebpf_common::{
    build_uplink_encap, DownlinkPdr, UplinkFar, GTPU_ENCAP_LEN,
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
- Downlink classification only inspects the mandatory GTP-U header; extension
  walking happens in the eBPF program.

## Roadmap

- Treat layout changes as compatibility-sensitive and cover them with tests.
- Add new map or counter fields only when both loader and BPF program consume
  the same versioned layout.

## Verification

```sh
cargo test -p opc-gtpu-ebpf-common
```
