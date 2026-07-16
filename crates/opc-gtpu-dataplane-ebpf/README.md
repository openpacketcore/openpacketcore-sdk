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
  mark, and redirects toward the peer. Unknown or inactive marked state drops.
- `opc_gtpu_downlink`: tc ingress program. It matches UDP/2152 GTPv1-U G-PDUs,
  looks up downlink PDR state by TEID, validates the inner destination, strips
  outer headers, writes zero for a default bearer or the exact dedicated mark
  from an `Active` owner, and lets the inner packet continue to XFRM policy
  selection through the stack.

Map names, counter indexes, program names, and byte layouts are imported from
`opc-gtpu-ebpf-common`.

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
