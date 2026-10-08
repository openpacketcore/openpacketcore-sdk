# Lease-timed namespace packet gate

Status: timing arithmetic only. `opc-egress-fence-common::scope_time` is an
opt-in, dependency-free foundation for a namespace-owned packet gate. It does
not provide a clock source, authenticate scope grants, attach a program, or
change any running workload. Existing cgroup-fence programs and map formats
are unchanged. No stored-format boundary is introduced.

## Clock contract

The scope-lease profile in [RFC 022](rfc/022-scope-leases.md#time-and-packet-use),
tracked by [#1134](https://github.com/openpacketcore/openpacketcore-sdk/issues/1134),
currently fixes the next renewal at issuance plus `h = 1 second`, the packet
stop at that renewal plus `G = 77 seconds`, and remote exclusion through the
stop plus a one-second guard. This arithmetic targets that profile; it does not
implement scope authority. Exact retries retain these absolute times. The gate
must not restart the permit's lifetime at receipt. A gate can close early if
the clock guarantee runs out; it cannot promise the entire forwarding grace
without a bound covering that entire interval.

[RFC 022](rfc/022-scope-leases.md#time-and-packet-use) derives the 77-second
permit grace and the resulting `h + G` stop (78 seconds) and
`h + G + 1 s` remote exclusion (79 seconds). Its sixty-second forwarding
contract includes issuance-interval excess, both clock-rate directions,
aggregate phase corrections and the first-send-to-stamp sampling budget, with
a clock horizon covering the deadline. These are provider and transport
qualification requirements. The gate still converts the immutable stop `S`;
this documentation update changes no arithmetic or gate constants.

`ScopeClockCorrelation::new` describes a trusted common-time interval `[L, U]`
sampled between kernel BOOTTIME observations `b0` and `b1`. Its width must be at
most one second, as required by RFC 022's profile. The same common-time domain
must be used by all voters and packet gates. Common time uses signed
nanoseconds, not the local boot origin.

The provider supplies a maximum forward rate error `d` in parts per billion,
total forward discontinuity/error allowance `J` in nanoseconds, and an absolute
BOOTTIME validity horizon `H`. With `Q = 1_000_000_000`, it promises:

```text
T(b) <= U + J + (b - b0) * (Q + d) / Q    for b1 <= b < H
```

Here `T` is actual common time; the ratio is real-valued. This promise includes
sampling uncertainty, relative drift, suspend accounting, synchronization loss
and any clock correction for the **whole** horizon. A provider cannot revoke
it early and rely on a userspace callback to close the gate. A wall-clock sample,
an assumed zero drift or a synchronization-status flag is insufficient. If no
such bound is available, no correlation may be supplied to an enforcing gate.
The promise begins at sample completion and ends before the horizon. The
constructor checks representation and interval shape, not provider truth.

BOOTTIME includes suspended time, and the kernel exposes it to BPF as
`bpf_ktime_get_boot_ns`. `CLOCK_MONOTONIC` stops during suspend and cannot replace
it. See the [kernel timekeeping contract](https://docs.kernel.org/core-api/timekeeping.html)
and [BPF helper contract](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
Userspace BOOTTIME can have a [time-namespace offset](https://man7.org/linux/man-pages/man7/time_namespaces.7.html).
The future Linux adapter must sample the kernel helper's domain directly or
prove the correlation to it; it must not mix these origins.

Guest suspend and a hypervisor stop are different cases: a hypervisor pause or
live migration can freeze guest BOOTTIME and later resume from its saved value.
For example, see [QEMU's KVM clock save/restore path](https://github.com/qemu/qemu/blob/a9431a03f70c8c711a870d4c1a0439bdbb4703cf/hw/i386/kvm/clock.c).
`J` must bound the total missing elapsed time through the horizon. Without such
a bound the platform is unsupported; closing in a userspace resume callback
cannot protect the first packet after resume.

The rate bound must also include time-daemon slew, not just oscillator drift,
unless `J` budgets its entire correction over the horizon. Linux permits clock
adjustments of about 10%, and chrony's default maximum slew is 83,333.333 ppm;
see the [chrony slew-rate contract](https://chrony-project.org/doc/4.6/chrony.conf.html#maxslewrate).
The envelope bounds common-time growth per boot tick: a boot clock slowed by
10% requires a rate factor of at least `1 / 0.9`, not `1.1`. A workload must not
assume a smaller host slew limit it can neither verify nor control. RFC 022
also accounts for frequency and adjtime rates, aggregate phase gain and
sampling delay in the full-grace availability bound; the ten-percent example
alone is insufficient to qualify that bound.

## Deadline and non-overlap proof

For the immutable permit stop `S`, `deadline_for(S, observed_boot_ns)` computes:

```text
remaining = S - U - J
D = min(H, b0 + floor(remaining * Q / (Q + d)))
```

It refuses nonpositive remaining time, arithmetic overflow, a regressing boot
observation, an expired bound, or an observation at/after `D`. No saturating or
wrapping conversion can create authority. The time predicate is `b1 <= b < D`;
equality at `D` is closed. The sampling delay is charged from `b0`, rather than
starting a new lifetime at sample completion or reply receipt.

If the common-time sample is carried in a store reply, it was taken after the
first send of that logical request. An exact retry returns the original stamp,
so `b0` remains the **first send**, not the retry's send; `b1` is receipt. Keep
that first-send reading across every retry. If it is lost, refuse the
correlation rather than reconstructing it from the delayed reply.

For every accepted `b`, `b - b0 < remaining * Q / (Q + d)`. The provider's
envelope therefore gives `T(b) < S`. Downward rounding and the horizon cap can
only close earlier. A remote successor is admitted only when its trusted
common-time lower bound is at least `S + guard`. Since that lower bound is no
greater than actual common time, packet authority and successor admission do
not overlap. Different boot origins and different leader uncertainty intervals
do not alter this argument. A new leader still must retain the committed stop
and exclusion and supply a valid interval; leadership alone grants nothing.

This proves a bound at the gate's decision, not at wire departure. Packets
already admitted can remain in qdiscs, TX rings and host queues. Reserve the
one-second exclusion margin for that post-gate delay; slice 4 must measure and
bound it for each supported network profile. Clock corrections and any
UTC leap behavior belong in the provider's clock envelope, not in a second
use of the queue budget.

Pauses need no renewal callback if the clock envelope remains valid: every
packet must read the kernel clock. Guest suspend normally advances BOOTTIME;
hypervisor pause and migration require the separate bound above. A clock source
whose suspend, pause or slew error violates the promised envelope invalidates
the proof and is not qualified by these unit tests. The tests exercise the
conditional theorem, including an exhaustive small-domain cross-multiplication
oracle, signed/overflow boundaries, delayed delivery/retry and simulated clock
advancement. They do not exercise leader changes or qualify hardware clocks,
real suspend, consensus behavior or an attached eBPF program.

A controller must derive/cache `D` once per **committed grant revision**.
Calling this arithmetic again with the same correlation cannot extend it;
re-correlating an old grant might change `D` and must not update that grant's
cached deadline. A `ScopePacketDeadline` carries no scope, execution, fence or
revision and is deliberately not a gate-update capability.

## Remaining implementation slices

Tracking issue: [#1143](https://github.com/openpacketcore/openpacketcore-sdk/issues/1143).
This timing slice is [#1144](https://github.com/openpacketcore/openpacketcore-sdk/issues/1144).
Each slice requires separate review and merge before the next is implemented.

2. Packet-domain ABI and parser in a dedicated `opc-scope-gate-common` crate:
   default-deny while closed, with exact store/API/management/DNS/clock-provider
   exemptions. Cover ESP, UDP-encapsulated ESP, plaintext GTP-U, userspace slow
   paths, IKE, GTP-C, Diameter, retransmissions and slot-address ARP/ND, including
   IPv4/IPv6 fragments and protected protocols using a non-scope source address.
   Refuse conflicting exemptions and malformed traffic. Move the timing model
   with its tests before extending the scope ABI, to separate future changes
   from the legacy cgroup fence's privileged CI trigger.
3. Kernel enforcement: sched-cls packet program and serialized control/readback
   programs, with immutable policy, bounded state, lock and counter maps. Bind
   execution, fence and committed grant revision; reject stale extensions and
   close on missing/damaged state. The gate runs first on each hook; allowed
   and exempt packets return `TC_ACT_UNSPEC` to continue classification, and
   denied packets return `TC_ACT_SHOT`. Reject an installed deadline beyond
   either its derived bound or a fixed ceiling of `h + G + 1 s` from its
   original sample (79 s under the RFC 022 profile); that ceiling grants no
   extra forwarding time. Test expiry, concurrency and mutation detectors
   against the real kernel.
4. Namespace loader and lease integration: legacy netlink tc attachment owned
   by the workload network namespace, surviving container/private-bpffs loss.
   Never use a process- or pin-owned BPF link, including TCX. Discover exact
   tc/program/map identities. Refuse to open with an earlier filter, any TCX
   program, or any unqualified tc bypass: XDP_TX/REDIRECT, AF_XDP,
   PACKET_QDISC_BYPASS, ingress/peer redirects, XFRM packet offload, or ungated
   devices. The gate precedes GTP-U priority 50 and DSCP priority 60, including
   their configurable variants. Preserve a first-running closed guard around
   replacement so existing XFRM traffic is never ungated. Depend on #1134's
   production bounded-clock provider, preferably using the committed
   permit's issue stamp bracketed by first send and receipt. Qualify slew,
   guest suspend, VM stop/continue, migration and post-gate queue delay; real
   VM tests run only in an isolated qualification environment.
5. Local same-workload handover proof: retain an exclusive lock on an unchanged
   inode in workload-lifetime storage, such as a Pod emptyDir. Prove predecessor
   exit and close/read back the local gate for #1134's store-side same-domain
   handover; this work does not implement that store operation. Before reopen,
   retire or block orphaned predecessor TCP/SCTP transmission and require proof
   that old XFRM/GTP-U forwarding state is retired or safely adopted through the
   separate kernel-state API. Another Pod still follows remote expiry. Graceful
   release first honors emergency-session holds, then terminally closes all
   gates before committing release. A lost reply cannot authorize reopening.
   Same-execution resume requires store proof of no intervening selection and
   retains local state.

No person, node cleanup, reboot or replacement Pod may be needed to recover
the workload's own leftovers. Kernel undo/reset is separate work. Expiry closes
all protected traffic, including emergency traffic; voluntary lifecycle actions
must not interrupt an emergency session. This arithmetic slice changes no
startup, shutdown, crash, rescheduling, session or packet behavior.
