# Authenticated complete Child-SA relocation

The namespace-bound Linux XFRM actor can bind an installed Child-SA roster to
one established NWu MOBIKE responder, durably prepare an authenticated move,
and publish the complete relocated roster after fresh readback. It moves every
inbound and outbound incarnation, including receive-only rekey predecessors.
The caller continues to own IKE_AUTH trust, the IKE-to-children relationship,
traffic classification, namespace writer exclusion and application sends.

## Authority and admission

Bind `InstalledChildSaRoster` with `bind_child_sa_mobike` and the responder's
opaque `MigrationAssociation` before admitting an update. The independently
authenticated UPDATE_SA_ADDRESSES and COOKIE2 exchange produces `Migration`;
consuming it with `authorize` produces a non-cloneable `MigrationPermit` for
that exact responder, accepted-event generation, path and encapsulation mode.
Equal SPIs, keys or caller labels cannot recreate its private association.

Accepted fresh IKE events revoke older permits. Invalid authentication, replay
and caller-policy refusal do not advance this generation. Call
`invalidate_migration_authority` for other caller-owned IKE lifecycle events.
Responder drop, timeout, bad COOKIE2 and generation exhaustion close retained
authority. Serialize IKE events with final publication and traffic resumption.
ESP source observations grant no migration authority.

`prepare_child_sa_relocation` requires the actor's bound SA-relocation recovery
store, a current associated publication, a matching live permit and a complete
original `ChildSaRelocationIntent`. It verifies both directions, transient keys,
policies and target absence before one authenticated Prepared journal record.
The prepared authority is affine and bound to the actor, exact store instance,
operation, writer epoch and private admission seal. Preparation withdraws the
previous installed publication. Dropped or undelivered preparation requires
reconciliation of the known operation before later writers can proceed.

## Admitted profile

The existing installed-selection contract still admits 32 pairs and 256
classes. This relocation increment admits at most eight tunnel pairs and 256
classes, with a common original peer/local outer address pair. These are SDK
resource bounds. Every logical child has one concrete selected outbound policy
with a distinct full-mask mark. Receive-only predecessors must share that
selected child's selector, mark and interface scope. Identical inbound policies
are deduplicated by exact lookup identity and must agree byte for byte.

Every SA must change its outer identity or encapsulation. A no-op target,
fixed-DSCP declaration or incompatible block coverage is refused before durable
admission. Inner selectors, child IDs, incarnations, class/default choices,
keys, SPIs, request IDs, lifetime limits, marks and interface IDs remain intact.
Native ESP preserves absent encapsulation; NAT-T uses the verified directional
ports. The bounded codec also represents adding/removing UDP encapsulation.

`child_sa_relocation_capability` defaults to Missing on raw Linux, mock and
unsupported adapters. The namespace actor reports its kernel capability;
preparation additionally requires the bound recovery store and admitted profile.
There is no delete/reinstall fallback. Current stock kernels without the exact
`XFRM_MSG_MIGRATE_STATE` ABI or `CONFIG_XFRM_MIGRATE` return precise unsupported
results. A newer release number alone does not prove that capability.

## Ordered mutation contract

Before any effect, persist one Issuing record authenticating the entire original
roster, keys, class/default plan, incarnations and target. The live path checks
its opaque IKE authority before each effect and before publication.

1. Replace every selected outgoing allow policy with an exact Block policy.
2. Relocate both directional SAs of every pair in declared roster order,
   including receive-only predecessors. Preserve their sequence/replay state.
3. Replace each distinct inbound policy with its new outer template.
4. Restore every selected outgoing allow policy with its new outer template.

The Block replacement uses UPDPOLICY on the same selector, direction, mark,
interface and priority. Linux invalidates the replaced policy's cached routes;
there is no remove/install policy gap. All outgoing blocks precede every SA
move, and no outgoing allow returns until every SA and inbound policy is new.

Read every old/target SA identity, its complete immutable/key expectation and
every policy before choosing the next effect, and again after the last effect.
Only a state reachable by an ordered prefix of this exact program can resume.
Foreign, missing, duplicate, ambiguous or unreadable state permits no repair
mutation. Every successful effect must advance the observed prefix.

Kernel effects are individual. Only the complete SDK publication is atomic.
Any failed, stale or interrupted live operation publishes no usable roster.
Once admitted, the actor drains after caller cancellation; a lost reply never
transfers a receipt. Unresolved Issuing truth blocks later writers until
reconciliation. If the actor already persisted Relocated before noticing a lost
reply, that terminal record releases the writer gate but still transfers no
installed publication; the caller reconciles before resuming traffic.

## Durable recovery

The existing 208-byte authenticated record format is retained. A distinct
RosterWitnessed proof kind and separate whole-roster MAC domains prevent
single-SA recovery from interpreting a group record. No cleartext keys, packet
bodies or outer endpoints enter the SDK journal. The caller retains the full
original intent in protected storage; a caller-provided intent grants no trust.

`recover_child_sa_relocation` authenticates that exact intent, namespace, store,
operation, generation and writer epoch. Prepared recovery retires without any
kernel effect. Issuing recovery resumes only the previously admitted exact
target after complete prefix readback. Relocated recovery verifies the complete
target again. Foreign or indeterminate state stays gated for repair; recovery
never removes or reinstalls an SA. Another live admission cannot be recovered.

Recovery returns `NoMutation` or `Completed`, with no IKE or installed-roster
publication. Reestablish IKE ownership and perform fresh whole-roster publication
before resuming application traffic. Other SDK writer families use the same
namespace-wide gate and epoch. Noncooperating writers remain outside the lease.

`detector_cut_child_sa_relocation` is an isolated-test boundary on the production
path. It consumes ordinary authority, persists Issuing and returns
StateIndeterminate after a chosen fully read-back mutation prefix, including
zero or the final effect. It never returns a publication. It exists to qualify
actual process loss and recovery without changing kernel effects or journal
semantics; the retained operation must then be reconciled.

## Evidence and limits

The ordinary suite exercises complete read/mutation failure schedules, all
old/new member combinations, stale authority at every step, all encapsulation
transitions, full-handle tampering, member keys, ordering, incarnation and
class/default binding. Linux transport tests separately fail individual identity,
key and policy queries and reject wrong direction, key and duplicate target.

The native consumer independently seals synthetic AES-GCM IKE messages and
HMAC-SHA-256/null-cipher ESP. It qualifies signalling plus two user-plane children,
two flows per child, explicit default and a receive-only rekey predecessor.
The supported IPv4 kernel profile captures outgoing SPIs and sequences and
proves incoming delivery, replay and ICV rejection before/after native ESP and
NAT-T moves. Separate child processes crash at every whole-roster effect prefix,
then verify writer gating, wrong-intent refusal, complete recovery and fresh
publication. Live cases exercise cross-responder scope, stale permits, path/mode
mismatch, wrong actor, dropped preparation and caller cancellation.

`ci/qualify-n3-mobike-kernel.py` builds upstream Linux v7.3-rc3 at commit
`fd73f4a6659897191fa0d40695fe370925dd3780` with migration enabled, boots an
isolated VM on a digest-pinned Ubuntu image, requires positive completion markers
and exact executed-test counts, and removes its owned guest. It retains source,
image, configuration, executable and library digests. The minimal kernel
qualifies migration; the standard XFRM job separately qualifies BTF-backed
inbound provenance and precise unsupported-kernel outcomes.

These synthetic tests establish SDK/kernel behavior for the declared profile.
They are not external interoperability captures, IKE_AUTH authentication proof,
a complete 3GPP N3IWF implementation, a deployment-kernel certification, or an
extension of sealed ESP-in-UDP observations to arbitrary native-ESP packets.
IPv6/cross-family packet migration and simultaneous traffic during the move
have no native qualification in this increment.

Primary contracts: [RFC 4555](https://www.rfc-editor.org/rfc/rfc4555.html),
[upstream migration procedure](https://www.kernel.org/doc/html/next/networking/xfrm/xfrm_migrate_state.html),
and the [installed roster/provenance contract](n3-installed-child-sa-roster.md).
