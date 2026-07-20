# opc-gtpu-dataplane-ebpf

## Purpose

`opc-gtpu-dataplane-ebpf` contains the Rust/aya tc programs used by
`opc-gtpu-dataplane`'s `EbpfGtpuDataplaneBackend`.

It is not a normal workspace library. It targets `bpfel-unknown-none`, builds a
CO-RE object, and is intentionally excluded from the SDK workspace.

## API Shape

The crate exposes tc entry points, not a Rust library API:

- `opc_gtpu_uplink`: tc egress program. Mark zero looks up the default FAR by
  inner UE IPv4 source address. A non-zero complete packet mark selects an
  additive FAR by `(UE address, mark)` and must match an `Active` owner-journal
  entry before the program prepends `[outer IPv4][UDP][GTPv1-U]`, consumes the
  mark, and redirects toward the peer. The UDP destination port is always
  2152. The additive `GTPU_UL_SPORT`/`GTPU_ULM_SPORT` map value is a complete
  PDP-context commit record, including the explicit source port. The program
  accepts only an `Active` record whose FAR and DSCP match the selected live
  entries exactly; an absent, transitional, malformed, or mixed record drops
  fail closed. When the single-slot `GTPU_PMTU_CFG` policy map carries a
  configured effective link MTU, the program applies the shared
  `apply_uplink_mtu_policy` decision to every encapsulation: an over-MTU
  packet is emitted with DF clear only when the policy permits downstream
  outer fragmentation (the program transmits via `bpf_redirect_neigh`,
  bypassing the kernel's `ip_fragment`, so the oversized frame leaves whole
  and relies on a downstream fragmenting hop); otherwise it drops fail
  closed into the `GTPU_PMTU_DROP` per-CPU counter (slot 0 over-MTU rejects,
  slot 1 the corrupt-policy canary), never emitting the inner packet
  unencapsulated and never emitting ICMP itself. The strict policy stamps DF
  and refreshes the outer checksum on emitted
  packets; an all-zero slot is the explicit unset legacy behavior and
  corrupt policy bytes drop fail closed.
- `opc_gtpu_downlink`: tc ingress program. It matches UDP/2152 GTPv1-U G-PDUs,
  proves the existing outer envelope/checksum boundary, selects exactly one
  downlink PDR by TEID, and then requires a canonical `GTPU_DL_BIND` value that
  matches outer peer, local destination, IPv4 family, current tc attachment,
  and explicit UDP source-port policy. Before decapsulation, both default and
  marked paths require an `Active` commit record matching the complete selected
  FAR, DSCP, local TEID, endpoint binding, and source-port policy; marked PDRs
  additionally require the compatible owner journal. Only then does it validate
  the inner destination, strip outer headers, write zero for a default bearer
  or the exact dedicated mark, and continue to XFRM policy selection through
  the stack. Outer IPv4 fragments are passed to the kernel stack unchanged;
  the kernel reassembles under bounded `ipfrag` accounting and the SDK's
  userspace `GtpuReassemblyConsumer` re-applies this same PDR/binding/decap
  path to the reassembled datagram exactly once.

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
- The datapath is currently IPv4 GTP-U only.
- Missing, corrupt, transitional, or mismatched commit records and endpoint
  bindings fail closed before inner packet delivery. The userspace schema
  exposes IPv4/IPv6 semantics, but this object deliberately rejects a stored
  IPv6 binding as a family mismatch.
- The downlink envelope path uses a 256-byte bounded checksum callback. The
  endpoint/owner authorization and decapsulation phase is a separate BPF
  subprogram so the verified call chains remain below Linux's 512-byte stack
  limit without weakening either boundary.
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
