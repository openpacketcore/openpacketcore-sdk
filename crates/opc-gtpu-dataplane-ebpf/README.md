# opc-gtpu-dataplane-ebpf

## Purpose

`opc-gtpu-dataplane-ebpf` contains the Rust/aya tc programs used by
`opc-gtpu-dataplane`'s `EbpfGtpuDataplaneBackend`.

It is not a normal workspace library. It targets `bpfel-unknown-none`, builds a
CO-RE object, and is intentionally excluded from the SDK workspace.

## API Shape

The crate exposes tc entry points, not a Rust library API:

- `opc_gtpu_uplink`: tc egress program. It resolves an IPv4 `/32` or canonical
  IPv6 `/64` UE source plus the complete packet mark through the grouped
  uplink index, retains that index value, and performs exactly one
  generation/slot-authority lookup. The selected entry may use an independent
  outer IPv4 or IPv6 endpoint family. It then prepends the corresponding
  `[outer IP][UDP][GTPv1-U]` header, consumes a nonzero mark, and redirects
  toward the peer. A present but malformed, transitional, stale, or
  mismatched grouped reference drops fail closed; only a true grouped-index
  miss may use the frozen v5 IPv4 maps. Outer IPv6 requires fully materialized,
  non-GSO bytes, gets a mandatory software-generated UDP checksum, and accounts
  56 bytes against the effective link MTU; outer IPv4 accounts 36 bytes and
  retains the strict DF behavior. The UDP destination port is always 2152.
  The host-only `RequireOuterFragmentation` policy remains non-executable
  because `bpf_redirect_neigh` bypasses the kernel fragmentation path.
- `opc_gtpu_downlink`: tc ingress program. It matches UDP/2152 GTPv1-U G-PDUs,
  proves the complete outer IPv4 or IPv6 envelope and checksum boundary,
  derives the independent inner family, and resolves `(outer family, inner
  family, local TEID)` through the retained grouped index and one authority
  lookup. Only an exact `Active` generation/slot, attachment configuration,
  outer peer/local endpoint, UDP source-port policy, and inner destination may
  decapsulate. The program strips the proven outer envelope, writes the
  dedicated-bearer mark (or zero), and continues through the ePDG's XFRM
  output policy. A true grouped-index miss alone may enter the legacy IPv4
  PDR/commit path. Legacy outer-IPv4 fragments retain the bounded
  kernel-reassembly handoff. Grouped outer-IPv4 and outer-IPv6 packets
  requiring reassembly pass to the host, but the backend reports both
  per-family grouped fragment capabilities as unsupported because the current
  consumer cannot authorize the grouped graph. A bounded IPv6 extension walk
  accepts canonical Hop-by-Hop, Destination Options,
  Routing-with-zero-Segments-Left, and atomic Fragment headers. AH, ESP, active
  routing, discard-required options, non-atomic fragments, or chains outside
  the bounded contract are left to the host before any grouped session is
  authorized. IPv6 UDP checksums are mandatory.

Map names, counter indexes, program names, and byte layouts are imported from
`opc-gtpu-ebpf-common`. `GTPU_DL_DROP` is a fixed six-slot per-CPU counter map
for invalid, family, peer, local, ingress, and source-port binding failures.
Its values are aggregate and contain no rejected endpoint or session fields.

## Relationships

- `opc-gtpu-ebpf-common`: shared no-std layout and classification crate.
- `opc-gtpu-dataplane`: userspace loader and safe backend that pins maps,
  attaches/detaches tc programs, and embeds the built object.
- `crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o`: committed artifact
  produced from this crate.

## Status And Limits

- Unpublished standalone crate (`publish = false`) with its own `Cargo.lock`.
- Build profile uses `panic = "abort"` and optimized BPF codegen.
- The grouped datapath supports all four independent outer/inner IPv4/IPv6
  combinations and simultaneous IPv4v6 session groups. The frozen v5 maps
  remain an IPv4-only compatibility fallback and are never consulted after a
  grouped selector has been observed.
- Missing, corrupt, transitional, or mismatched grouped authority, index,
  attachment configuration, legacy commit record, or endpoint binding fails
  closed before inner packet delivery.
- IPv6 extension and checksum processing use bounded `bpf_loop` callbacks.
  The committed classifiers are verifier-loaded on exact Linux 6.8 in CI so
  their complete call chains remain below that kernel's cumulative 512-byte
  BPF stack limit without reducing checksum coverage.
- Outer IPv6 is `MaterializedOnly`: GSO and pending
  `CHECKSUM_PARTIAL` state are rejected before encapsulation. Outer IPv6
  fragment reassembly is not claimed; only atomic Fragment headers are handled
  by the fast path. Grouped outer-IPv4 fragment reassembly is also unsupported;
  the qualified IPv4 reassembly consumer remains specific to the legacy maps.
- The S2b-U boundary owns the complete 32-bit packet mark; masked sharing is
  unsupported. The userspace crate remains safe Rust. Aya exposes a safe mark
  setter but no getter, so the verifier-bound program uses one isolated,
  aligned raw read of `__sk_buff::mark` in addition to its existing raw
  map/helper accesses.
- It does not load itself, manage bpffs pins, manage sessions, or implement
  product policy; those live in the userspace backend.

## Build

Do not build this crate with normal workspace commands. Use the pinned helper:

```sh
./scripts/build-gtpu-ebpf.sh
```

Prerequisites:

```sh
rustup toolchain install nightly-2026-06-22 --profile minimal --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
```

## Roadmap

- Keep the committed object reproducible from source and checked in CI.
- Extend map schemas only through `opc-gtpu-ebpf-common` so loader and program
  stay byte-for-byte compatible.
- Add protocol support only with matching unit tests and privileged datapath
  coverage.

## Verification

```sh
./scripts/build-gtpu-ebpf.sh
cargo test -p opc-gtpu-ebpf-common
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```
