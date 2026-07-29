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

The build copies the exact source state to a second, distinct absolute path and
builds both paths with distinct target directories. It always gates stable
program, map, BTF, relocation, symbol, and functional-section inventories. It
records whole-object byte identity when available and otherwise reports only
the stable-functional-inventory policy before replacing the committed object.
CI also supplies `OPC_EBPF_EXPECTED_ARTIFACT` so that the same stable inventory
must match the object already committed to the SDK.

The production cookie-map and configuration capacity is frozen at 4096.
Capacity pressure uses that production object rather than a reduced-capacity
object with a different identity.

## RED-only kernel-gate mutations

`mutation-bypass-gate` deliberately admits the configured protected socket or
packet domain without cookie authority. It is mutually exclusive with the
default `production` feature, and the build script refuses to write it to the
production object path. Build it only as a separate detector input:

```console
CARGO_HOME=/mnt/portable/opc-secondary/cargo-home \
OPC_EBPF_TARGET_DIR=/mnt/portable/opc-secondary/target-608-mutation-a \
OPC_EBPF_COMPARISON_TARGET_DIR=/mnt/portable/opc-secondary/target-608-mutation-b \
OPC_EBPF_FEATURES=mutation-bypass-gate \
OPC_EBPF_ARTIFACT=/mnt/portable/opc-secondary/target-608-mutation.bpf.o \
./scripts/build-egress-fence-ebpf.sh
```

An unchanged fencing detector must report RED against that object.

`mutation-bypass-deadline` retains the production cookie and lifecycle checks
but deliberately removes the live classifier's BOOTTIME deadline observation.
It is built with the default production feature plus the explicit mutation:

```console
CARGO_HOME=/mnt/portable/opc-secondary/cargo-home \
OPC_EBPF_TARGET_DIR=/mnt/portable/opc-secondary/target-608-deadline-a \
OPC_EBPF_COMPARISON_TARGET_DIR=/mnt/portable/opc-secondary/target-608-deadline-b \
OPC_EBPF_FEATURES=mutation-bypass-deadline \
OPC_EBPF_ARTIFACT=/mnt/portable/opc-secondary/target-608-deadline.bpf.o \
./scripts/build-egress-fence-ebpf.sh
```

The unchanged detector must report its exact expired-authority RED result
against this object. The `fault-inject-delete` feature is likewise test-only.
The build wrapper requires every fault-injection or mutation build to name a
separate explicit artifact path and rejects unknown or unsafe feature
combinations, so no test object can replace the committed production object.

## True-root privileged detector

The standalone oracle workspace also contains a multiprocess detector that
directly attaches the committed gate with revision-aware `BPF_PROG_ATTACH` at
the exact host cgroup-v2 root. A pristine revision of zero cannot enable the
kernel compare-and-swap guard, so the detector attaches a gate that is already
closed and requires an exact revision-one, single-program readback before any
activation. It creates and replaces isolated sender network namespaces and
holds the old sender in `SIGSTOP`. Before changing current ownership, it waits
past the active deadline, resumes the still-current old sender, and proves that
the kernel deadline alone drops every protected datagram. It stops that sender
again, transfers ownership, activates the successor, and proves that resumed
stale-cookie traffic remains absent while successor traffic passes. The same
run covers both address families, fragment policy, unregistered and unrelated
sentinels, loader-fd and pin loss, exact attachment readback, and
revision-exact detach cleanup.

Build both separate mutation objects first, then run the CI-facing production
and mutation set:

```console
CARGO_HOME=/mnt/portable/opc-secondary/cargo-home \
OPC_EGRESS_FENCE_DETECTOR_TARGET_DIR=/mnt/portable/opc-secondary/target-egress-fence-detector \
OPC_EGRESS_FENCE_DEADLINE_MUTATION_OBJECT=/mnt/portable/opc-secondary/egress-fence-deadline.bpf.o \
OPC_EGRESS_FENCE_GATE_MUTATION_OBJECT=/mnt/portable/opc-secondary/egress-fence-gate.bpf.o \
crates/opc-egress-fence-ebpf/oracle/scripts/run-privileged-detector.sh
```

The runner requires noninteractive root authority. It emits only stable,
value-free PASS, RED, or DEFECTIVE outcomes. Before the normal production and
mutation runs, it injects failures immediately after root-cgroup attachment and
immediately after host-veth creation while using the shipped production object.
It also fails immediately after a sender child is spawned and wrapped, proving
that the child is killed and reaped before the topology is removed. It requires
these exact cleanup proofs:

```text
egress-fence privileged cleanup detector: PASS (post-attach)
egress-fence privileged cleanup detector: PASS (post-veth)
egress-fence privileged cleanup detector: PASS (post-child)
```

The runner then requires the deadline mutation to produce the exact
expired-authority RED result and the whole-gate mutation to retain the exact
stale-authority RED result.
