# opc-egress-fence

`opc-egress-fence` is an opt-in, protocol-neutral, lease-bound Linux
root-cgroup-v2 egress gate for one exact local UDP endpoint.

Depending on this crate does not load or attach BPF, bind a socket, or change
ordinary `opc-runtime` UDP behavior. A caller opts in by constructing
`LinuxEgressFenceConfig` and calling
`install_or_adopt_linux_egress_fence`. Once an endpoint is enrolled, its safety
contract is intentionally not configurable: protected traffic remains closed
until durable authority is proven, and every uncertain lifecycle or integrity
result closes the socket.

## Exposed controls

The production composition is explicit:

1. Enter a Tokio runtime with its I/O driver enabled.
2. Supply one canonical, nonzero, unicast local UDP endpoint, an
   operator-mounted true host cgroup-v2 root, and a dedicated bpffs pin
   directory to `LinuxEgressFenceConfig::new`.
3. Call `install_or_adopt_linux_egress_fence`. The installer internally binds
   and immediately consumes the exclusive socket before its descriptor or
   64-bit cookie can escape.
4. Persist the returned opaque `FenceAttachmentIdentity` in the durable
   authority transaction.
5. Move the returned `FencedUdpSocket` into `run_fenced_udp_guardian`; product
   code sends only through `FencedUdpSender`.

The installer rejects wildcard, multicast, broadcast, zero-port, scoped
IPv6/link-local, IPv4-mapped IPv6, multiply assigned, reusable, connected,
freebind, transparent, device-bound, or dual-stack endpoint ambiguity.
For IPv4 prefixes shorter than `/31`, local-assignment proof rejects both host
extremes and requires canonical broadcast metadata on a broadcast-capable
interface; noncontiguous masks and noncanonical explicit broadcast values fail
closed. Both `/31` endpoint values and `/32` assignments remain eligible.
`FencedUdpSocket` is non-clone, not `Sync`, exposes no descriptor, and has no
public direct send method.

`EgressFenceLeaseAuthority` is the adapter boundary for a product's durable
store; this crate does not invent durable authority from an in-memory timer.
One acquisition transaction must mint the exact `LeaseGuard`, reserve the
nonwrapping socket/retirement token pair, bind the current attachment and gate
lifetime, and return prior-attachment evidence from the same durable record
generation. Terminal release must durably commit the supplied opaque terminal
evidence under the exact guard before releasing authority. Missing,
split-epoch, ambiguous, or independently read evidence is rejected.

## Kernel enforcement

The installer uses `BPF_PROG_ATTACH` directly at
`BPF_CGROUP_INET_EGRESS` on the true root of the unified cgroup-v2 default
hierarchy. It rejects delegated/private subtree roots and every pre-existing
attachment. The first pristine query can report revision zero, for which Linux
does not perform revision compare-and-swap. The staged classifier is therefore
closed before attachment, and no activation is possible until an exact
revision-one, single-program post-attach readback succeeds. Later operations
retain and reprove the exact root descriptor, revision, direct-attachment
provenance, program/map/config identity, committed generation, and endpoint
assignment.

The gate protects the configured source endpoint across the whole root
hierarchy, including descendant cgroups and network namespaces. A socket whose
full 64-bit cookie is not the one registered under the current durable
lifecycle token cannot emit protected traffic. An active entry is admitted
only while its absolute `bpf_ktime_get_boot_ns` deadline is strictly in the
future. Expiry is evaluated on every packet in the kernel and does not depend
on a userspace wakeup.

Deadlines are derived conservatively as:

```text
operation-start CLOCK_BOOTTIME + lease TTL - safety margin
```

The operation start is captured before acquisition or renewal. A delayed
completion that consumes the safe window cannot activate or refresh the gate.
Clock failure, regression, overflow, cancellation, lease discontinuity,
mutation failure, or readback failure terminal-closes the lifecycle.
The SDK also maps the reported acquisition interval to a conservative
BOOTTIME durable-expiry bound and advances it only by each exact positive
durable expiry extension. It refuses a requested kernel deadline beyond that
bound. Deterministic model coverage proves this SDK safety check; it is not a
durable-authority adapter conformance suite, and it does not relax the
adapter's obligation to grant the full requested TTL.

Traffic is classified at the L3 header supplied to `cgroup_skb/egress`.
Provably unrelated IPv4/IPv6 traffic passes. A protected socket or protected
source tuple requires exact cookie authority. An unregistered sentinel is
dropped. Malformed, truncated, unknown, or parser-over-budget L3 traffic that
cannot be proved unrelated is also dropped. Normal kernel fragmentation occurs
after this hook; already fragmented protected-source input whose UDP source
cannot be proved is fail-closed.

## Installation, restart, and upgrade

The durable installation manifest freezes the userspace/kernel ABI version,
object digest, program types/names/tags/map references, map IDs and schemas,
canonical configuration, root revision transition, and syscall-side map-freeze
policy. The cookie, configuration, counter, current-token,
mutation-authority, and manifest maps are frozen with `BPF_MAP_FREEZE`;
attached and control BPF programs can still perform their intended map
updates. Linux rejects freezing the separate BTF map containing
`bpf_spin_lock`, so the SDK does not claim it is frozen; admission instead
proves its exact schema, identity, program references, and canonical initial
state.

Publication uses staging, prepared, and committed generations with bounded
inventory. Restart may adopt one exact committed generation or resume one
prepared generation at either recognized crash point. Missing pins,
descriptor/path replacement, multiple generations, unknown objects, foreign
maps/programs/config, root drift, or ambiguous attachment state fail closed.
Stale cookie cleanup is bounded by the frozen production map capacity and can
remove only entries superseded by the exact current lifecycle token.

There is no in-place upgrade or uninstall call. A changed object or
configuration cannot adopt or replace a live generation, and the SDK never
silently detaches a current or foreign program. Upgrade requires exact
close/readback, durable terminal commit, and an explicit offline,
revision-checked operator procedure before installing the new identity. A
process restart with byte-for-byte compatible committed state uses exact
adoption instead.

## Deployment and threat boundary

Production requires a Linux kernel that exposes the revision-aware cgroup BPF
query/attach ABI used here (upstream mainline 6.17 or newer), the
suspend-aware BPF boot-time helper, a unified cgroup-v2 hierarchy, bpffs, and
the privileges needed to load and directly attach BPF. The supplied cgroup
path must resolve to the true default-hierarchy root with cgroup ID/inode 1.
The dedicated bpffs directory must already exist, be root-owned, and not be
writable by group or other users; generation directories are exact mode 0700.

The enforcement boundary is Linux IPv4/IPv6 output that traverses
`cgroup_skb/egress`. It does not mediate `AF_PACKET` or other link-layer
injection paths. Sender workloads must not have packet-socket capability or an
alternate kernel transmit path; deny `CAP_NET_RAW` where it would grant one.
The protected tuple is host-global across network namespaces, so the same
source tuple in another namespace is intentionally fenced too.

Host-root actors able to attach, detach, or replace BPF, change bpffs or its
mounts, or mutate kernel state outside the SDK are trusted and outside the
enforcement boundary. Runtime integrity checks detect drift before and after
control operations and before a protected send, but cannot make a malicious
privileged mutation atomic with the subsequent send syscall.

Forking after admission, descriptor duplication, `SCM_RIGHTS` passing, or any
alternate sender for the protected endpoint is forbidden. These actions can
retain the authorized socket cookie outside the single guardian, which the
Rust ownership surface alone cannot disprove.
