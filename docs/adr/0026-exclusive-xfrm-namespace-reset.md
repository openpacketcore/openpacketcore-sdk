# ADR 0026: Startup reset of an exclusively owned XFRM namespace

## Status

Implementation contract. Privileged qualification remains a required CI gate.

## Decision

The caller must be the namespace's only XFRM writer, and nothing else may rely
on any SA or policy there. The caller retains no predecessor state and must
never combine reset with predecessor adoption, recovery or finalization in the
same process. The explicit acknowledgement constructor states those obligations;
the SDK cannot verify them. Every recovery-store family ever used in the
namespace must be bound. An unbound family is untouched.

A process that loses all object identities cannot invoke selective recovery:
durable records authenticate requests but deliberately do not retain their
identities. The namespace-bound actor therefore offers one optional startup
command that flushes all namespace policies, flushes all SAs, reads both tables
back to prove emptiness, and only then durably resets its bound stores. There is
no ownership inference from marks, request IDs or selectors.

The first ordinary mutation, durable preparation, recovery, relocation,
installed-authority validation/publication or companion activation closes the
reset window, even if that command fails. Passive SA and policy queries,
relocation-identity and counted SA-key queries, probes, relocation-capability
checks and read-only roster tickets do not close it. Counted SA-key queries mint
no authority. Once reset starts,
all commands except passive queries and a repeated reset are refused until the
complete reset succeeds and its caller acknowledges observing the reply. The
actor drains admitted work after cancellation. An unobserved or lost reply is
indeterminate and requires another reset before ordinary commands.

An existing store lease remains held throughout. The object and relocation
stores durably advance their authenticated epoch before unlinking records.
Roster stores also advance the epoch first, then atomically replace the journal
with an empty authenticated journal at that epoch, or unlink legacy records.
Every publication/removal uses the existing synchronization and crash-repair
rules. No format change, lease release, backward epoch, or new persistence path
is introduced. Epoch exhaustion fails closed. A partial store reset is safe to
repeat because the kernel was already proved empty before any record removal.
Old opaque handles remain absent or stale even if caller labels are reused.
The report contains only the number of bound stores reset.

Plaintext sources must stop before reset. Block policies are removed, and a
caller that needs protective policies reinstalls them before reopening sources.
Routes, devices, per-socket policies, default-policy settings, DSCP companion
state and other namespaces are outside the operation. Existing constructors and
recovery behavior are unchanged for consumers that never invoke reset.

## Linux boundary

The pinned [Linux v6.18 XFRM UAPI](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/xfrm.h)
defines `XFRM_MSG_FLUSHPOLICY`, `XFRM_MSG_FLUSHSA`, policy types MAIN/SUB and
`xfrm_usersa_flush`. The implementation issues policy flushes for MAIN and SUB;
SUB's `EINVAL` means a kernel without `CONFIG_XFRM_SUB_POLICY` for this fixed,
valid request. An all-type readback still must prove emptiness. The SA protocol
argument is zero, which matches all protocols; `IPSEC_PROTO_ANY` matches only
ESP, AH and IPComp.

In [xfrm_user.c](https://github.com/torvalds/linux/blob/v6.18/net/xfrm/xfrm_user.c),
both flush handlers turn empty-table `ESRCH` into success. GETPOLICY dumps walk
all types; an unfiltered GETSA dump walks all protocols. Reset uses a dedicated
multipart parser: an ACK, truncated datagram, wrong sequence, unexpected
message, dump interruption or failed DONE cannot prove emptiness. Kernel reply
buffers are bounded and zeroizing, and no key-bearing dump row is retained.

[xfrm_policy_flush](https://github.com/torvalds/linux/blob/v6.18/net/xfrm/xfrm_policy.c)
does not filter policy action, so block policies are removed; it excludes socket
directions 3 through 5, which readback likewise excludes. Default policies are
separate settings.
[xfrm_state_flush](https://github.com/torvalds/linux/blob/v6.18/net/xfrm/xfrm_state.c)
does not filter larval states. Kernel-owned tunnel helper states are released by
their owning transforms rather than directly flushed; any still visible SA
makes readback fail and keeps the stores and mutation gate closed for retry.

## Evidence

The deterministic tests cover predecessor roster residue, unresolved phases in
every store family and both roster formats, monotonic epochs and stale handles,
each ordered reset cut followed by a new actor, step failures, unbound stores,
lost or unobserved replies, idempotence and post-admission refusal. The mock
retains namespace state across an explicit test rebind and implements the same
startup gate and injected failure semantics.

The privileged detector SIGKILLs a predecessor holding all three stores and an
unresolved roster, with ESP, AH, IPComp, a larval SA and main block policies
present. It also adds a SUB block policy when the kernel supports it. Only exit
code 2 with the exact `Error: Invalid policy type.` response to that private
namespace's SUB add counts as unavailable support; any other fixture failure
fails the proof, without logging fixture values. With support, the proof covers
the SUB flush itself; without it, it covers the refused SUB flush followed by
the all-type empty readback. The hosted preflight on 2026-10-04 used kernel
`6.17.0-1022-azure` and iproute2 `6.1.0`, with `CONFIG_XFRM_SUB_POLICY` disabled;
its empty-namespace and socket-policy proofs passed. The local `7.1.8` host
supports sub-policies. A test-only forced refusal exercises the unsupported
fixture path locally and emits a distinct simulated marker, not real kernel
refusal evidence.

A successor resets, independent iproute2 dumps prove empty
tables, and installing the same roster succeeds. Device, route, default-policy
and separate-namespace sentinels survive. A separate socket-policy holder also
survives reset and remains visible to an independent dump. CI requires all proof
markers, an exact test count and exactly one real sub-policy case marker, which
is recorded in the workflow log and step summary. A skipped privileged detector
or a simulated case cannot count as hosted qualification.
