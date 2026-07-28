# opc-egress-fence-ebpf

Standalone `bpfel-unknown-none` programs for the protocol-neutral lease-bound
egress fence.

The object contains:

- `opc_egress_gate`, attached directly to the unified default-hierarchy root's
  `BPF_CGROUP_INET_EGRESS` hook, which fails closed for the configured socket
  or packet domain unless the full socket cookie is currently authorized;
- `opc_fence_ctl`, an unattached sched-cls mutation program invoked only with
  `BPF_PROG_RUN`, which serializes token publication and per-cookie lifecycle
  transitions inside the kernel; and
- `opc_fence_view`, a distinct unattached, read-only sched-cls program invoked
  only with `BPF_PROG_RUN` for synchronized state inspection.

Build the committed object from the repository root:

```console
CARGO_HOME=/mnt/portable/opc-secondary/cargo-home \
OPC_EBPF_TARGET_DIR=/mnt/portable/opc-secondary/target-608-ebpf \
./scripts/build-egress-fence-ebpf.sh
```

The build remaps checkout, Cargo-home, toolchain, and user-home paths. Object
validation compares functional sections across two distinct absolute checkout
paths and separately checks the frozen program, map, and symbol inventory.
