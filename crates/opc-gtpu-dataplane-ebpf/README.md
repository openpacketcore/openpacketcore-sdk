# opc-gtpu-dataplane-ebpf

tc `clsact` eBPF GTP-U datapath programs for `opc-gtpu-dataplane`'s
`EbpfGtpuDataplaneBackend`:

- `opc_gtpu_uplink` (tc egress): GTP-U-encapsulates subscriber uplink by
  inner-source (UE PAA) FAR lookup — the direction the mainline `gtp`
  netdevice cannot serve.
- `opc_gtpu_downlink` (tc ingress): decapsulates GTPv1-U G-PDUs by TEID PDR
  lookup and hands the inner packet to the stack (and XFRM).

Byte layouts (map values, encapsulation, header classification) come from
`opc-gtpu-ebpf-common`, shared with the userspace loader and unit-tested in
ordinary CI.

## Building

This crate is excluded from the SDK workspace: it targets
`bpfel-unknown-none` with `-Z build-std=core` on a pinned nightly toolchain
and links with `bpf-linker`. Do not build it directly; use:

```sh
./scripts/build-gtpu-ebpf.sh
```

which refreshes the committed CO-RE artifact at
`crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o` (embedded into
`opc-gtpu-dataplane` at compile time). Re-run the script after any change
here or in `opc-gtpu-ebpf-common`; CI rebuilds the object and fails on
structural drift, and the privileged integration test exercises the committed
artifact end-to-end.

Prerequisites:

```sh
rustup toolchain install nightly-2026-06-22 --profile minimal --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
```
