# opc-ipsec-xfrm

## Purpose

`opc-ipsec-xfrm` is the safe Rust control surface for Linux XFRM IPsec state in
OpenPacketCore. It models Security Associations, Security Policies, replay
state, algorithms, key material, Linux backends, mocks, unsupported backends,
and rollback-aware composite operations.

The crate does not implement IKE negotiation, ESP packet processing, namespace
creation/switching, product SA/SPD policy, or deployment defaults. It can bind
backend execution to a calling thread's already-selected Linux network
namespace.

## Network-namespace binding

`LinuxXfrmBackend::bind_current_network_namespace` captures the calling
thread's current network namespace as an opaque device/inode identity and
starts a dedicated actor thread that inherits it. Invoke the binding method on
the thread that has already entered the intended namespace; the SDK does not
call `setns(2)` or select a namespace path.

```rust,no_run
use opc_ipsec_xfrm::{LinuxXfrmBackend, XfrmBackend};

# async fn example() -> Result<(), opc_ipsec_xfrm::XfrmError> {
let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
let capability = backend.probe().await?;
# let _ = capability;
# Ok(())
# }
```

All SA, policy, capability-probe, relocation, and fixed-DSCP work then runs on
that actor. The 64-entry queue applies bounded backpressure. Cancellation while
waiting for queue admission submits nothing; after admission, the actor drains
the operation even when the caller drops its future. Losing the reply to an
admitted mutation is reported as `StateIndeterminate` (`ALLOCSPI` included),
while a lost read/probe reply is `Unavailable`. Dropping the final backend clone
closes the queue and lets the detached actor drain without blocking `Drop`.

## API Shape

- `XfrmBackend`: async port for SPI allocation, SA
  install/query/rekey/relocation/removal, policy install/rekey/remove, and
  capability probing.
- `LinuxXfrmBackend`: safe adapter over `NETLINK_XFRM` through
  `opc-linux-xfrm-sys`.
- `NamespaceBoundLinuxXfrmBackend`: cloneable bounded actor that keeps every
  Linux XFRM operation in one captured network namespace.
- `MockXfrmBackend`: deterministic in-memory backend with operation capture,
  a source-compatible separate `MockSaRelocation` log, and failure injection.
- `UnsupportedXfrmBackend`: trait-compatible unsupported backend.
- Model exports include `IpAddress`, `XfrmSelector`, `XfrmId`, `SaParameters`,
  `PolicyParameters`, `XfrmTemplate`, `InstallSaRequest`,
  `InstallPolicyRequest`, `QuerySaRequest`, `SaState`, `SaReplayState`,
  `SaRelocationSelector`, `SaRelocationIdentity`, `SaRelocationEncap`,
  `SaRelocationDirection`, `RelocateSaRequest`,
  `XfrmRequestId`, `UdpEncap`, `UdpEncapError`, `XfrmMark`, `DscpCodepoint`,
  `LifetimeConfig`, and `XfrmProbe`.
- Algorithm/key exports include `Algorithm`, `AuthAlgorithm`, `AeadAlgorithm`,
  `KeyMaterial`, and Linux XFRM algorithm-name constants.
- Composite helpers include `install_sa_policy_with_rollback`,
  `install_bidirectional_sa_policy_with_rollback`, `rekey_sa_policy`, and
  `remove_policy_sa`.
- `XfrmStagedInstall` is the cancellation-safe counterpart of
  `install_sa_policy_with_rollback`. Its consuming `run(self, ...)` receiver
  makes one runner an affine, compiler-enforced invariant, while a
  caller-cloned `XfrmInstallJournal` survives cancellation. `run` accepts an
  `Arc` backend and, on first poll, moves the operation into an owned Tokio
  worker. Dropping the observing future therefore cannot detach a Linux
  `spawn_blocking` mutation and race cleanup; the journal remains live until
  the backend operation actually returns. An acknowledged install can be
  transferred to product teardown with `journal.commit()`. Otherwise the
  journal returns a generation-bound
  `XfrmInstallRecoveryPlan`; recovery requires an explicit `Owned`, `Absent`,
  `Foreign`, or `Indeterminate` classification for every exact SA/policy
  candidate and is serialized across journal clones. Recovery also runs in an
  owned worker, so dropping its observer cannot let a same-identity replacement
  overtake an issued removal. If either owned worker terminates abnormally, its
  guard records `SupervisionLost` and permanently rejects in-process recovery:
  a detached blocking syscall may still complete after the async worker is
  gone. A fresh process must re-establish namespace-wide XFRM writer exclusion
  and authoritative readback before deciding how to handle residue. Matching
  readback alone cannot distinguish an identical foreign replacement. Both
  supervised APIs require a live Tokio runtime and otherwise return a typed,
  redaction-safe runtime error.
- `XfrmStagedObjectInstall` is the single-object counterpart of
  `XfrmStagedInstall` for exact SA-only and policy-only installs: an SA that
  intentionally reuses an existing shared policy, or an additional policy
  direction for one SA. Its typed `XfrmObjectInstallRequest` supervises one
  operation without inventing a dummy companion mutation, under the same
  rules as the composite boundary: affine one-run execution, an owned Tokio
  worker after first poll, a caller-cloned `XfrmObjectInstallJournal`, an
  explicit `Acquired`/`Indeterminate`/`SupervisionLost` ownership state, and
  generation-bound classified recovery of the single exact
  `XfrmObjectRemovalRequest` candidate. An observed `AlreadyExists`
  rejection authorizes no removal of the pre-existing object; an unobserved
  result requires explicit `Owned`/`Absent`/`Foreign` classification under
  caller-held writer exclusion before any removal, and worker loss
  permanently disables in-process commit and recovery.
- `LinuxXfrmBackend::bind_current_network_namespace_with_object_recovery`
  exposes a durable single-object boundary for restart recovery. It opens and
  authenticates `XfrmObjectInstallRecoveryStore` on the namespace actor before
  returning any mutation-capable backend handle. The store keeps value-free
  operation records under a permanent filesystem lease, while
  `prepare_durable_object_install`, `run_durable_object_install`,
  `finalize_durable_object_install`, and `recover_durable_object_install`
  serialize preparation, effect admission, and recovery through the namespace
  actor. Running the effect requires consuming the opaque authority returned by
  preparation; there is no combined prepare-and-effect entrypoint.
  This boundary supplements rather than changes the process-local
  `XfrmStagedObjectInstall` cancellation and classification API.
- `InstalledOutboundSaBinding` is an opaque, unforgeable direction authority
  for one exact ESP SA and its sole outbound allow-policy. The only fresh mint
  is `XfrmStagedInstall::run_and_commit_outbound_sa_policy`, after both kernel
  acknowledgements and journal commit. After process loss,
  `NamespaceBoundLinuxXfrmBackend::recover_installed_outbound_sa_binding`
  performs actor-local `GETPOLICY` followed by `GETSA` before minting a new
  binding. Both paths reject inbound/block policies, mismatched selectors,
  marks or interface IDs, ambiguous templates, and unsupported kernel
  attributes. A wildcard template SPI is accepted only when the template and
  SA carry the same nonzero request ID.
- With feature `ikev2`, the crate also exports Child SA KEYMAT and negotiation
  mappers from `opc-proto-ikev2` into explicit XFRM install requests.
  `Ikev2ChildSaXfrmOptions` can carry one shared request ID and exact
  directional initial NAT-T templates without changing the established public
  request struct.

## Durable staged-object restart recovery

Use the durable namespace-bound API when the consumer can stop after an SA-only
or policy-only install completes but before it records the terminal result. The
consumer must durably retain the full install request, a generated
`XfrmObjectInstallOperationId`, a nonzero product generation, the store
location, and the stable proof-key reference before it submits the operation.
The store itself persists no address, selector, SPI, mark, interface ID, or key
material: it contains only authenticated opaque correlation, object kind,
phase, incarnation, epoch, and independent proof-keyed fingerprints of the
exact deletion identity and complete install request. Even SA algorithm/key
bytes are only streamed into the request HMAC and are never persisted.

On every initial start and restart, first call
`LinuxXfrmBackend::bind_current_network_namespace_with_object_recovery` after
selecting the target namespace. Store authentication, namespace binding, and
the permanent lease complete on the actor thread before the method returns the
backend/store pair. There is deliberately no later asynchronous attachment API:
it could not prove that this or a prior actor had not already mutated the
namespace outside the retained epoch.

The required ordering after that atomic bind is:

1. Call `prepare_durable_object_install` with the retained operation ID,
   generation, and complete request. It durably publishes authenticated
   `Prepared` truth and returns a non-cloneable
   `XfrmObjectInstallAdmissionAuthority`. No backend effect has been admitted
   when this call returns.
2. Durably commit the consumer's poll-admitted transition.
3. Pass the authority to `run_durable_object_install`. After the deferred-DSCP
   gate, the actor performs an exact readback of the deletion identity and
   embeds the witnessed presence (`Absent` or `Conflict`) as a durable
   pre-effect proof in the same authenticated record, then publishes
   `Issuing`. An `Absent` proof permits the actor-serialized backend effect;
   a `Conflict` proof admits no effect and proceeds directly to `NoMutation`,
   because an SA may expire autonomously after readback. The method durably
   publishes `Acquired`, `NoMutation`, or `Indeterminate` before returning its
   outcome. Two pre-consumption rejections return the same authenticated
   authority and retain `Prepared` for an exact retry: a deferred DSCP
   activation gate, and a pre-effect readback that could not be trusted
   (reported as `xfrm_object_install_pre_effect_readback_failed`).
4. Durably record the consumer decision. If an acquired object is adopted,
   call `finalize_durable_object_install` only after that adoption is durable.
   Finalization surrenders cleanup authority and leaves the object installed.
5. After restart, consult the consumer record. Finalize an adoption that was
   already committed; otherwise call `recover_durable_object_install` with the
   exact retained operation ID, generation, and request. Recovery retires a
   definitive no-mutation result without removal, removes only residue with
   authenticated, current `Acquired` authority, and additionally reconciles
   `Issuing` and `Indeterminate` records using their pre-effect proof.

A crash after preparation, whether before or after the consumer commits poll
admission, leaves authenticated `Prepared` truth. Restart recovery retires that
record as authoritative no-mutation and performs no `DELSA` or `DELPOLICY`.
Dropping an unsubmitted authority has the same recovery result. While
registered, a live authority intentionally blocks same-process retirement;
dropping it, losing the process, or losing a preparation reply leaves the
durable record recoverable. An independently admitted actor mutation
invalidates every prepared authority before its backend effect. Once the run
command is admitted to the actor, dropping the observing future does not cancel
its work.

The authority is process-local, non-serializable, and bound to the exact open
store, namespace actor, operation ID, generation, and complete request. A
duplicate preparation, replay, stale phase, wrong request, wrong store, or
presentation to another actor fails before the backend. Each new preparation
receives a fresh live actor seal, so retiring and recreating the same durable
correlation cannot revive an old admission authority. Missing, malformed,
duplicated, unauthenticated, wrong-namespace, or wrong-incarnation state
remains fail-closed. Callers reconcile a lost run result from the durable
record; they do not invent new correlation or bypass the authority boundary.

A crash after durable `Issuing` — before the syscall, after a kernel
acknowledgement but before terminal publication, or after an indeterminate
backend result — leaves an `Issuing` or `Indeterminate` record that carries
the pre-effect proof. `recover_durable_object_install` reconciles it by
combining that proof with a fresh exact readback of the deletion identity
(`GETSA` for an SA, exact `GETPOLICY` for a policy). Because the writer gate
excluded every other cooperating writer for the whole time the record stayed
unresolved, the proof plus the current presence is a complete classification:

| Readback | Pre-effect proof | Verdict | Deletion |
| --- | --- | --- | --- |
| absent | `Absent` | effect provably never happened | none; retired no-mutation |
| present | `Absent` | residue can only be this operation's | exact removal; `owned_residue_retired` |
| present | `Conflict` | witnessed foreign identity; no install was attempted | none; `foreign_untouched` |
| absent | `Conflict` | prior conflict is gone; no install was attempted | none; retired no-mutation |
| unreadable | either | retryable; record unchanged | none; `indeterminate` |
| stale epoch / missing proof | either | durable anomaly, product repair | none; `repair_required` |

Retained intent or a matching readback alone is never deletion authority: the
owned-residue verdict additionally requires the `Absent` proof, an
epoch-current record, and exact binding re-validation. An `AlreadyExists`
acknowledgement still becomes durable `NoMutation` and never authorizes
removal. Recovery is idempotent after a record retires, and a retryable
outcome leaves the record gating until it converges.

Linux has no owner- or generation-conditional `DELSA` or `DELPOLICY`. The
store therefore implements a cooperating-writer protocol: an unresolved
`Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted` record blocks
every later cooperating mutation admitted by that namespace actor — including
ordinary `XfrmBackend` operations, new preparation, and any other
`Prepared -> Issuing` transition — until it is finalized or recovered.
Entering `Issuing` and every independent actor mutation burns a durable global
writer epoch. Prepared authority remains actor-local and one-shot; the
current-epoch deletion check applies to `Acquired` and `RemovalAdmitted`, and
the same epoch-currency predicate guards `Issuing`/`Indeterminate`
reconciliation. `Acquired` already holds the writer gate, so publishing
`RemovalAdmitted` stays at that current epoch before deletion and has no
ambiguous half-advanced epoch crash cut. A scoped policy recovery additionally
proves the exact nonzero `XFRMA_IF_ID` with `GETPOLICY` before deletion. These
guarantees do not exclude another raw-netlink socket, another namespace actor
with a different store, or packet/product activity outside this protocol. A
deployment must use one store and one cooperating writer domain for all XFRM
identity mutations in the namespace; violating that exclusion can let an
unconditional delete race a same-identity replacement.

Durable records use format version 2, which carries the pre-effect proof in a
byte that version 1 reserved as zero. Version 1 records fail closed as
malformed; there is no compatibility path, migration bridge, or
unconditional-delete escape hatch. A store that still contains version 1
records must be repaired out-of-band before recovery is attempted.

As with the process-local staged-object boundary, a durable SA or policy
removal identity may be unmarked or use only a full-mask lookup mark. A narrow
mark is rejected before either store publication or backend mutation because
Linux mark selection is overlap- and insertion-order-sensitive.

The store root must be an absolute path under a trusted parent, owned by the
effective user, and exactly mode `0700`; record files are mode `0600`. The
256-bit proof key must come from durable secret configuration, remain stable
across restart, and never be reconstructed from operation data. Use a local
filesystem that provides reliable `flock`, `rename(..., RENAME_NOREPLACE)`, and
file/directory `fsync` semantics. The namespace seal covers nsfs device/inode,
Linux `SO_NETNS_COOKIE`, and kernel boot identity so a destroyed namespace or
reboot cannot adopt old authority through inode reuse. The actor holds the root
lease for its entire lifetime, and the atomic constructor attaches exactly one
store before exposing the actor. Public handles,
outcomes, errors, and diagnostics are value-free; a handle is correlation, not
standalone deletion authority.

The leased root is trusted authoritative, non-rollback storage for this runtime
crash contract. Do not restore, snapshot-rollback, or copy back an earlier
complete set of authenticated control, epoch, and operation files, and do not
allow the same UID or an administrator to rewrite that trusted root. An HMAC
and a monotonic epoch inside the same directory detect forgery and stale records
relative to the live inventory, but cannot detect a coherent rollback of the
directory itself. Deployments where such storage rollback is possible must add
an independent product monotonic witness outside that rollback domain and must
not recover until it matches; otherwise unconditional deletion is unsafe.

## Durable SA relocation restart recovery

`relocate_sa` is not blindly idempotent after process loss: a crash around the
single `XFRM_MSG_MIGRATE_STATE` effect can leave kernel state that readback
can observe but not own, while the outbound block policy (consumer-owned) and
the namespace-wide writer exclusion must stay fenced until reconciliation.
MOBIKE makes this a first-class restart case: UPDATE_SA_ADDRESSES changes only
the outer tunnel-header addresses and UDP-encapsulation port (RFC 4555 §1.1,
§3.3), one address pair exists per SA at a time so kernel migration is a move,
not a copy (RFC 4555 §1.2), NAT rebinding may change "IP address and/or port"
so encapsulation-only same-XfrmId relocation is expected (RFC 4555 §3.8),
and the initiator detects and recovers from failures, so fail-closed
cleanup of an unproven move is spec-consistent (RFC 4555 §3.11). Because the
Linux SAD identity is destination/SPI/protocol (RFC 4301 §4.1; plus lookup
mark on Linux), an address-changing relocation changes the XfrmId while an
encapsulation-only relocation does not; the durable boundary witnesses both
cases. NAT-T context follows RFC 3948.

`LinuxXfrmBackend::bind_current_network_namespace_with_sa_relocation_recovery`
(or the combined
`bind_current_network_namespace_with_object_and_sa_relocation_recovery` for
consumers that also run durable installs) authenticates and permanently leases
one `XfrmSaRelocationRecoveryStore` on the namespace actor before any
mutation-capable handle is returned. The store is a separate self-contained
record family (`OPCXRLC1`, format version 1 with the pre-effect proof byte
present from version 1); it shares no records or compatibility path with the
staged-object store.

The required ordering after that atomic bind is:

1. Call `prepare_sa_relocation` with the retained operation ID, generation,
   and complete `RelocateSaRequest`. It durably publishes authenticated
   `Prepared` truth and returns a non-cloneable
   `XfrmSaRelocationAdmissionAuthority`. No backend effect has been admitted
   when this call returns.
2. Durably commit the consumer's poll-admitted transition.
3. Pass the authority to `run_durable_sa_relocation`. After the deferred-DSCP
   gate, the actor performs exact `GETSA` readbacks of the old and target
   identities and embeds the witnessed target disposition as a durable
   pre-effect proof in the same authenticated record, publishes `Issuing`,
   and only then admits the single `relocate_sa` effect. The method durably
   publishes `Relocated`, `NoMutation`, or `Indeterminate` before returning
   its outcome. Pre-consumption rejections return the same authenticated
   authority and retain `Prepared` for an exact retry when they are proved
   and deterministic: a deferred DSCP activation gate, a present target
   identity (`xfrm_sa_relocation_target_conflict`), and an untrustworthy
   readback (`xfrm_sa_relocation_pre_effect_readback_failed`). A mismatching
   current state consumes the authority
   (`xfrm_sa_relocation_current_state_mismatch`); the retained `Prepared`
   record recovers as authoritative no-mutation.
4. Durably record the consumer decision. There is no finalize/adoption call:
   a terminal `Relocated` record is the durable proof that the consumer
   continues on the new addresses.
5. After restart, call `recover_durable_sa_relocation` with the exact
   retained operation ID, generation, and request.

The pre-effect proof is witnessed immediately before `Prepared -> Issuing`:

| Relocation shape | Proof | Meaning |
| --- | --- | --- |
| changed XfrmId (address change) | `TargetAbsent` | the distinct target identity was absent when the effect was admitted |
| unchanged XfrmId (encap/source only) | `SameIdentityWitnessed` | the shared identity matched the bound current identity when the effect was admitted |

Recovery of an unresolved `Issuing`/`Indeterminate` record revalidates the
binding, requires a current writer epoch and a proof consistent with the bound
request, and classifies fresh exact readbacks. With `OLD-INTACT` meaning the
old identity is present exactly matching the bound current identity, and
`TARGET-RELOCATED` meaning the target identity matches the bound current
identity with the relocated destination, new source, and resulting
encapsulation:

Different identities (`TargetAbsent`):

| Old readback | Target readback | Verdict | Recovery outcome | Deletion |
| --- | --- | --- | --- | --- |
| intact | absent | effect provably never happened | `no_mutation` (retired) | none |
| intact | present (any) | atomic move cannot duplicate | `foreign_untouched` | none |
| absent | TARGET-RELOCATED | move happened, never published | `owned_residue_retired` | exact `DELSA` of the target identity |
| absent | foreign/present-other | foreign | `foreign_untouched` | none |
| absent | absent | foreign removal/expiry; mutation history is unknown | `state_absent` | none |
| foreign | any | foreign | `foreign_untouched` | none |
| unreadable | any unreadable | retryable; record unchanged | `indeterminate` | none |
| stale epoch / missing or inconsistent proof | durable anomaly | `repair_required`, record keeps gating | none |

Same identity (`SameIdentityWitnessed`), one readback of the shared identity:

| Readback | Verdict | Recovery outcome | Deletion |
| --- | --- | --- | --- |
| matches bound current | never happened | `no_mutation` (retired) | none |
| matches relocation expectation | happened | `owned_residue_retired` | exact `DELSA` of the same identity |
| matches neither | foreign | `foreign_untouched` | none |
| absent | foreign removal/expiry; mutation history is unknown | `state_absent` | none |
| unreadable | retryable; record unchanged | `indeterminate` | none |

Recovery deletes only through the exact target deletion identity
(new destination, SPI, protocol, and lookup mark) after publishing
`RemovalAdmitted`; a failed removal stays `removal_pending` and retryable
across restart. Recovery is idempotent after a record retires, returns terminal
`Relocated` or `StateAbsent` proof without ever deleting after terminal
publication, and a retryable outcome leaves the record gating until it
converges. `StateAbsent` is intentionally distinct from `NoMutation`: absence
cannot prove whether the move happened before external removal or expiry.
Terminal idempotence holds only until the next cooperating write prunes the
terminal record; once pruned, restore fails `NotFound`.

Linux has no owner- or generation-conditional `DELSA`. The store therefore
implements a cooperating-writer protocol: every unresolved relocation phase —
`Prepared`, `Issuing`, `Indeterminate`, and `RemovalAdmitted` — blocks every
later cooperating mutation admitted by that namespace actor, including
ordinary `XfrmBackend` operations and new preparation, until recovery retires
the record. A prepared-but-unrecovered relocation reserves the namespace: the
relocation fencing holds while recovery authority and protocol egress remain
fenced. Entering `Issuing` and every independent actor mutation burns a
durable global writer epoch. Relocation `Prepared` and every effect-capable
record in either family gate the other family. Object `Prepared` is
metadata-only and may coexist with a prepared relocation; a relocation run
advances the object epoch and invalidates all older object admissions before
kernel access. Every object run is first gated by unresolved relocation
authority and advances the relocation epoch before kernel access. Each
admitted mutation advances both epochs.
Metadata-only recovery remains the escape from its own gate. A recovery phase
that may issue exact cleanup also respects the other durable family's gate and
advances that family's epoch before kernel access. These guarantees do not
exclude another raw-netlink socket, another namespace actor with a different
store, or packet/product activity outside this protocol; a deployment must use
one cooperating writer domain for all XFRM identity mutations in the namespace.

Relocation records carry only opaque operation correlation, phase, proof code,
incarnation, epoch, and independent proof-keyed fingerprints of the exact
deletion identity and complete relocation request. No address, selector, SPI,
mark, encap port, namespace identity, request body, or operation identity is
rendered; handles, outcomes, errors, and diagnostics are value-free. The
store root, proof-key, lease, and non-rollback obligations match the durable
staged-object boundary. Relocation records use format version 1 with the
pre-effect proof byte present from version 1; there is no compatibility path,
migration bridge, legacy fallback, or unconditional-delete escape hatch.

## Durable grouped object roster restart recovery

One protected flow usually needs several dependency-ordered XFRM objects at
once — an inbound SA, its inbound and forward policies, an outbound SA, and its
outbound policy. Driving those through the single-object boundary costs one
durable admission and one finalization per object, so the consumer waits on
five independent durable lifecycles before it can report success. The roster
boundary makes the whole ordered group one durable record, one namespace-actor
command, one queue permit, and one writer-epoch burn, with the same
crash-recovery contract.

`LinuxXfrmBackend::bind_current_network_namespace_with_object_roster_recovery`
is the recommended constructor: it authenticates and permanently leases one
`XfrmObjectRosterRecoveryStore` (`OPCXROS1` records under family-distinct
`OPCXRSC1`/`OPCXRSE1` control and epoch magics) on the namespace actor before
any mutation-capable handle is returned.
`bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery`
binds all three durable families for consumers that still run single-object
installs or SA relocations; it is the opt-in migration form, not the default,
because every ordinary mutation then scans and fsyncs three stores.

The required ordering after that atomic bind is:

1. Validate the group with `XfrmObjectRosterRequest::new`, passing up to
   `XFRM_OBJECT_ROSTER_MAX_MEMBERS` (8) `XfrmObjectRosterMemberRequest` values
   in the caller-declared apply order. Construction is the only place member
   admissibility is decided — exact removal identity, no shared deletion
   identity, no shared caller-supplied durable member identity, and no
   collision in the kernel's own coarse selection relation; it returns a
   value-free `XfrmObjectRosterRequestError` and contacts no backend.
2. Call `prepare_durable_object_roster` with the retained
   `XfrmObjectRosterGroupId`, a nonzero `XfrmObjectRosterOperationGeneration`,
   and that roster. It publishes one authenticated `Prepared` record binding
   the group identity, every member's durable identity and generation, and a
   keyed ordered digest over the whole member tuple, then returns a
   non-cloneable `XfrmObjectRosterAdmissionAuthority`. No backend effect has
   been admitted when this call returns, and a `Prepared` roster has no effects
   to recover, so it does not itself fence cooperating writers.
3. Durably commit the consumer's poll-admitted transition.
4. Pass the authority to `run_durable_object_roster`. One actor command runs
   the deferred-DSCP preflight for every SA member, sweeps every member's exact
   identity read-only, burns the roster's single writer epoch on
   `Prepared -> Issuing`, and then applies members in order, publishing each
   member's adjacent absence proof *before* that member's effect. Three proved
   pre-effect rejections return the exact authority through
   `XfrmObjectRosterRunError::into_retry_authority`: a closed
   cooperating-writer gate (`xfrm_object_roster_gated` — an unresolved
   single-object install, an unresolved SA relocation, or an unresolved sibling
   roster in the same store), a still-closed deferred DSCP gate
   (`xfrm_object_roster_dscp_activation_required`), and an untrusted sweep
   readback (`xfrm_object_roster_pre_effect_readback_failed`). The gated
   rejection is screened before anything at all is consumed, so it is a
   transient block that succeeds later with that very same authority.
5. Durably record the consumer decision, then call
   `finalize_durable_object_roster` only after adoption is durable. `Applied`
   becomes `Committed` with every member slot preserved as acquired. This leaves
   one terminal idempotence record, not unresolved cleanup authority; the next
   cooperating prepare or epoch advance deterministically prunes it.
6. After restart, call `adopt_durable_object_roster` or
   `recover_durable_object_roster` for every retained roster **before any other
   namespace mutation**. An intervening ordinary mutation burns the writer
   epoch that every adjacent absence proof depends on, and the roster then
   reports `repair_required` with the record retained and nothing deleted.

The SDK imposes no deadline. A roster collapses N consumer deadline scopes into
one, so a caller times the group rather than the members, and a caller-side
timeout does not stop the actor: once admitted, the command runs to a durable
terminal record even if the observing future is dropped. The correct action
after a caller-side timeout is adoption or recovery, never a replay.

Roster recovery's `Absent`-then-present cleanup rule requires the deployment to
exclude raw-netlink and independently stored XFRM writers for the namespace.
The SDK writer epoch orders cooperating actor writes only; it does not fence an
external writer. If that exclusion is violated, an identical object is
observationally ambiguous after a crash, and Linux's unconditional delete could
remove the external writer's object.

### Ordered apply and reverse compensation

Ordinal zero is applied first and compensated last. For a five-member roster:

| Ordinal | Member | Apply position | Compensation position |
| --- | --- | --- | --- |
| 0 | inbound SA | 1st | 5th |
| 1 | inbound policy | 2nd | 4th |
| 2 | inbound forward policy | 3rd | 3rd |
| 3 | outbound SA | 4th | 2nd |
| 4 | outbound policy | 5th | 1st |

Any member result other than a clean acquisition diverts the whole group. The
observed mutating call log is the applied prefix — up to and including the
install that diverted the group — followed by the exact reverse of whatever was
actually acquired. The read-only sweep and adjacent readbacks are omitted from
the table below; the sweep alone is one `query_*` per member.

| Divergence | Mutating backend calls | Terminal phase | Outcome |
| --- | --- | --- | --- |
| sweep proves a conflict at any ordinal | none | `NoMutation` | `no_mutation`, dispositions name the conflicting ordinals |
| ordinal 0 witnesses an adjacent conflict | none | `NoMutation` | `no_mutation` |
| ordinal 0 fails, or returns `AlreadyExists` | install 0 | `RolledBack` | `rolled_back`, `failed_member` 0, zero acquisitions and zero removals |
| ordinal 3 fails after 0-2 acquired | install 0, 1, 2, 3, then remove 2, 1, 0 | `RolledBack` | `rolled_back`, `failed_member` 3 |
| ordinal 4 returns `AlreadyExists` | install 0-4, then remove 3, 2, 1, 0 | `RolledBack` | `rolled_back`, `failed_member` 4 |
| a compensation removal fails | applied prefix, partial reverse | stays `Compensating` | `indeterminate`, record retained and gating |
| every member acknowledged | install 0-4 | `Applied` | `applied`, awaiting finalize |

The failing member's own install IS issued in the two failure rows: on a real
kernel that is a `XFRM_MSG_NEWSA`/`NEWPOLICY` message the kernel rejects, not a
call that never happened. `rolled_back` therefore does not imply that any
kernel object was created and then removed — at ordinal 0 the compensated
prefix is empty.

`AlreadyExists` from a member install under an `Absent` adjacent proof records
that member as no-mutation and **fails** the roster, deliberately diverging
from the single-object family's `AlreadyExists` success semantics. A
dependency-ordered roster must not report success when one leg is a foreign
object of unknown parameters: RFC 7296 §1.3/§2.8 give a partial Child SA
installation no wire representation, and RFC 4301 §4.4 treats the SPD and SAD
entries of one protected flow as a single consistent unit. The foreign object
is never deleted, at any phase, regardless of proof codes — deletion authority
for a member additionally requires its own `Absent` adjacent proof, an
epoch-current record, and exact binding re-validation.

Every outcome and every restart verdict carries
`XfrmObjectRosterMemberDispositions`: a value-free per-member ordinal plus the
member's durable state as closed enums — `XfrmObjectRosterMemberPhase`,
`XfrmObjectRosterSweepProof`, and `XfrmObjectRosterAdjacentProof` — so a
consumer branching on member state gets compiler-checked exhaustiveness. The
`&'static str` label accessors remain as logging conveniences over the same
values.
`XfrmObjectRosterRecoveryStore::inspect_dispositions` re-authenticates a
retained `XfrmObjectRosterRecoveryHandle` against this exact lease, group
identity, generation, and member set before yielding the same descriptor; it
publishes nothing and authorizes no deletion.

### Adopting against recovering after process loss

| Situation | Call |
| --- | --- |
| Record is `Applied` and the consumer's bookkeeping can still accept the group | `adopt_durable_object_roster` |
| Record is `Applied` but the consumer already gave up on the group | `recover_durable_object_roster` |
| Caller-side deadline expired while the actor converged | adopt first, recover if refused |
| Record is `Prepared`, `Issuing`, `Compensating`, `NoMutation`, or `RolledBack` | recover; adoption refuses |
| Record is `Committed` or `Retired` | either; both report it idempotently |

Adoption is additive and never deletes. It re-authenticates the binding,
incarnations, member digest, and epoch currency, reads every member back
exactly, and publishes `Applied -> Committed` only when every acquired member
is present. Otherwise it publishes nothing, leaves the record `Applied` with
the writer gate closed, and reports `adoption_refused` so the consumer can
still choose recovery. A refusal decided by an unresolved `Issuing` or
`Compensating` phase costs nothing across families: the namespace actor screens
those phases before it fences the other two durable stores, so using adoption
as a probe cannot burn their writer epochs or invalidate a prepared
single-object install or SA relocation authority. Only an `Applied` record,
which adoption can actually commit, carries recovery's full fencing cost. Recovery classifies each unresolved member from its own
adjacent proof plus a fresh exact readback — there is no conflict shortcut, a
member that never entered its effect window is never deleted, and a member that
witnessed a foreign object is left exactly as found (`foreign_untouched`) —
then reverse-compensates the acquired prefix. A prepared roster retires as
authoritative no-mutation without any backend call; an unfinalized `Applied`
roster is owned residue and is removed in reverse order
(`owned_residue_retired`). A failed removal stays `removal_pending`, an
untrustworthy readback stays `indeterminate`, and a stale writer epoch under an
unresolved roster reports `repair_required`; all three retain the record and
keep the writer gate closed until the product converges them.

### Migration and cross-family fencing

An unresolved roster fences single-object durable installs and durable SA
relocations, and an unresolved install or relocation fences rosters. That
coupling is deliberately fail-closed in both directions: a roster store that is
malformed, unreadable, or over full therefore fails single-object installs
closed too. A migrating consumer binds all three stores and uses either one
roster or the equivalent single-object operations for a given protected flow,
never both interleaved for the same flow. A half-migrated consumer is
serialized by the gates rather than corrupted, but each family then waits for
the other's resolution; consumers that have finished migrating should move back
to the roster-only constructor.

Because each family's recovery is itself gated on the other bound families, a
namespace that starts up already holding an unresolved record in *two* families
cannot recover either one while all three stores are bound. Running operations
never produce that state, but changing the bound store set across restarts can.
The escape is to bind only the family being recovered, run its recovery to a
terminal verdict, drop that backend, repeat for the next family, and only then
rebind the full set. That deletes, reorders, and replays nothing: it only lifts
the mutual gate while each recovery re-authenticates its own record and epoch.

### Kernel-proven notes

`XfrmObjectRosterRequest::new` rejects two members that share the kernel's
coarse selection key — the same destination, protocol, and SPI for SAs
regardless of mark, or the same selector, direction, and interface ID for
policies — with `AmbiguousKernelSelection`. That rule mirrors kernel truth
rather than guarding a durable invariant: on Linux 6.19.14, adding an unmarked
SA and then a full-mask marked SA at the same destination, protocol, and SPI is
refused outright by the kernel at insert with `EEXIST` ("File exists"), leaving
the first SA untouched. A roster that admitted such a pair would install one
member and then fail the other. Only a real kernel witnesses this: the mock
backend keys on the whole request and accepts both members happily.

When verifying roster state by hand, use the plain listings
(`ip xfrm state list`, `ip xfrm policy list`). Some supported iproute2 builds,
6.12 among them, ignore `-j` for `ip xfrm` and render numeric attributes as
hexadecimal text, so a JSON parser cannot be relied on for these objects.

Roster records are fixed size, carry `XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES`
of authenticated handle material, and retain only opaque group and member
correlation, group and member phases, sweep and adjacent proof codes,
incarnations, the publication sequence, the writer epoch, and independent
proof-keyed fingerprints of each member's exact deletion identity and complete
install request. No address, selector, SPI, mark, interface ID, request body,
or key material is persisted or rendered, so the consumer must durably retain
every complete member request, including key material, to adopt or recover.
`XFRM_OBJECT_ROSTER_MAX_MEMBERS` is a wire-format bound: raising it changes the
record size and is a format break with no compatibility path. The store root,
proof-key, lease, and non-rollback obligations match the durable staged-object
boundary, and handles, outcomes, errors, and diagnostics are value-free.

## Opaque outbound-SA binding

Use the binding-returning staged path when later work must prove that an SA is
the outbound member of an installed SA/policy pair:

```rust,no_run
use std::sync::Arc;

use opc_ipsec_xfrm::{
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend,
    OutboundSaBindingError, XfrmCompositeInstallRequest, XfrmStagedInstall,
};

async fn install_outbound(
    backend: Arc<NamespaceBoundLinuxXfrmBackend>,
    request: XfrmCompositeInstallRequest,
) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
    XfrmStagedInstall::new(request)
        .run_and_commit_outbound_sa_policy(backend)
        .await
}
```

Persist `binding.id().to_bytes()` only as a correlation value. An
`OutboundSaBindingId` is deliberately constructible from persisted bytes and
is never authority by itself; the live opaque binding and fresh actor-local
validation remain mandatory. Restart recovery uses retained install intent:

```rust,no_run
use opc_ipsec_xfrm::{
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend,
    OutboundSaBindingError, XfrmCompositeInstallRequest,
};

async fn recover_outbound(
    backend: &NamespaceBoundLinuxXfrmBackend,
    request: XfrmCompositeInstallRequest,
) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
    backend
        .recover_installed_outbound_sa_binding(request)
        .await
}
```

The binding and its stable ID are key-free: they retain algorithm identity and
key lengths, but never key bytes or key-derived hashes. This avoids creating a
second long-lived key-custody path alongside the product's HKMS integration.
At every recovery/use boundary, the supplied zeroizing `SaParameters` key
material is compared in constant time with key bytes from the zeroizing GETSA
response; those bytes are never copied into the binding, ID, logs, or errors.
The product remains responsible for key custody and for supplying the intended
SA parameters.

Linux lockdown can redact every GETSA key byte to zero without marking the
response. That wire shape is indistinguishable from intentionally configured
all-zero key material. The SDK therefore never falls back to algorithm shape:
either case fails closed with
`xfrm_outbound_sa_binding_key_readback_unavailable`. Fresh staged issuance
performs exact readback before journal commit or binding mint, so this failure
leaves a caller-held journal clone in the recoverable `Complete` state and
returns no authority. Recovery/use fails with the same code. Deployments whose
kernel lockdown policy redacts XFRM secrets cannot use this exact binding (and
the counter-repin operations gated by it) unless the platform provides readable
exact GETSA key material; product startup/readiness should surface this stable
capability failure.

Linux ESN SAs encode the fixed one-byte replay window as zero, as required by
the XFRM UAPI, and carry the complete window in `XFRMA_REPLAY_ESN_VAL` only.
Readback rejects mixed, duplicated, or flag-inconsistent replay
representations. Dynamic counters and last-used timestamps are permitted, but
unmodeled semantic SA or policy attributes fail closed.

## Sealed outbound ESP counter authority

Same-SPI failover must use
`NamespaceBoundLinuxXfrmBackend::apply_and_read_back_outbound_esp_counter`.
The production API accepts only the live `InstalledOutboundSaBinding`, its
exact `OutboundSaBindingId`, a durable `EspCounterResumeBinding`, and transient
exact SA parameters. It has no caller-selectable direction and is not exposed
through `XfrmBackend` or the mock backend. The durable ID intentionally remains
stable when identical state is recovered in another namespace. Before using a
receipt, the coordinator must therefore derive an `OutboundEspCounterTarget`
from its intended live binding and supply that opaque, process-local target to
proof validation. A receipt from another actor or network namespace is rejected
before the foreign backend is queried, even when every durable field is equal.

`EspCounterResumeBinding::new` takes the **next** ESP sequence number the
successor is allowed to emit. Linux GETSA replay state reports the last
assigned sequence, so the actor compares and, when necessary, writes
`requested_next - 1`. Legacy replay accepts the remaining 32-bit sequence
space; ESN uses the full 64-bit value. Exhausted or ambiguous state fails
closed. The actor uses the dedicated Linux `XFRM_MSG_NEWAE` replay-state UAPI,
not a generic SA replacement:

- an observed value above the requested floor returns typed `AlreadyAdvanced`
  without mutation;
- an equal value performs exact final readback and returns an idempotent
  receipt without mutation; and
- a lower value advances once, then requires exact policy, SA, transient-key,
  replay-mode, and counter readback before returning a receipt.

The namespace actor drains admitted work even if the observing future is
dropped. Exact retry after a lost reply therefore recovers the applied value
without issuing a second update. Receipts have no public constructor, expose
no topology or counter values, expire after 30 seconds, and are retained in a
bounded 1,024-entry actor-local registry. Generic SA or policy mutations
invalidate the registry before they execute, including when the mutation later
fails.

```rust,no_run
use opc_ipsec_xfrm::{
    EspCounterProofRequirement, EspCounterResumeApplyRequest,
    EspCounterResumeBinding, EspCounterResumeProofSet,
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend, SaParameters,
};

async fn apply_counter(
    backend: &NamespaceBoundLinuxXfrmBackend,
    authority: &InstalledOutboundSaBinding,
    operation_id: u128,
    fence_generation: u64,
    requested_next: u64,
    exact_sa: SaParameters,
) -> Result<(), opc_ipsec_xfrm::EspCounterResumeError> {
    let target = authority.outbound_esp_counter_target();
    let binding = EspCounterResumeBinding::new(
        operation_id,
        fence_generation,
        authority.id(),
        requested_next,
    )?;
    let receipt = backend
        .apply_and_read_back_outbound_esp_counter(
            authority,
            authority.id(),
            EspCounterResumeApplyRequest::new(binding, exact_sa),
        )
        .await?;
    EspCounterResumeProofSet::single(receipt)
        .validate_counter_proof(
            &target,
            binding,
            EspCounterProofRequirement::BeforeOwnershipCommit,
        )
        .await
}
```

The successor SA must remain quiescent and unpublished until the receipt is
validated immediately before its required ownership/publication boundary.
Products must preserve exclusive XFRM writer authority; packet emission or a
second raw-netlink writer between preflight and receipt validation violates
this contract.

After process loss and an already-committed ownership grant,
`recover_committed_outbound_esp_counter` performs read-only exact validation
and accepts a live counter at or above the durable floor. Its receipt is
structurally limited to `EspCounterProofRequirement::CommittedRecovery`; it
cannot authorize a new ownership fence. A product may use that proof while
resuming publication only after it independently proves that the exact
ownership fence was committed before process loss. This separation prevents an
advanced live SA from being reinterpreted as fresh pre-commit authority while
retaining crash recovery after fencing but before steering.

## Usage

```rust,no_run
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    SaParameters, XfrmBackend, XfrmId, XfrmMode, XfrmSelector,
    MockXfrmBackend,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MockXfrmBackend::new();
    let selector = XfrmSelector::new(
        IpAddress::Ipv4([10, 0, 0, 1]),
        IpAddress::Ipv4([10, 0, 0, 2]),
        50,
    );
    let sa = SaParameters {
        selector,
        id: XfrmId {
            destination: IpAddress::Ipv4([10, 0, 0, 2]),
            spi: 0x1234_5678,
            protocol: 50,
        },
        source_address: IpAddress::Ipv4([10, 0, 0, 1]),
        request_id: None,
        auth: Some((AuthAlgorithm::hmac_sha256(96), KeyMaterial::new(vec![0xab; 32]))),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    };

    backend.install_sa(InstallSaRequest { parameters: sa }).await?;
    Ok(())
}
```

## Authenticated-only ESP and ENCR_NULL

With the `ikev2` feature,
`Ikev2ChildSaCryptoProfile::new_authenticated_only` derives no encryption or
salt octets and the mapper emits separate Linux auth and NULL-crypt slots. The
Linux adapter uses the kernel's canonical `ecb(cipher_null)` transform with a
zero-bit key, exposed as `XFRM_ENCR_NULL` and `Algorithm::null()`. This is an
adapter representation required by the XFRM UAPI; it does not fabricate an
IKEv2 encryption key or alter the negotiated ENCR_NULL transform.

The encoder accepts an empty key only for this exact NULL algorithm. It rejects
a non-empty NULL key, NULL without separate authentication, empty key material
for every other cipher, AEAD in the crypt slot, and ESP auth without an
explicit NULL cipher before sending a netlink mutation. Linux itself rejects
the latter raw shape with `EINVAL`.
Generic models and mocks may still describe other protocol shapes, but Linux
authenticated-only ESP callers must use `Algorithm::null()` or the IKEv2
mapper.

`tests/xfrm_auth_only_privileged.rs` creates a fresh local/peer namespace pair,
installs bidirectional authenticated-only tunnel SAs through the SDK, captures
a real ESP packet, and proves both valid delivery and integrity-failure
rejection of a tampered packet. It contains synthetic documentation-address
and private-address fixtures only; keys are test-only and never logged.

## Initial IKEv2 Child SA NAT-T mapping

The established `Ikev2ChildSaXfrmRequest` shape and
`build_xfrm_requests_from_ikev2_child_sa` remain the source-compatible
native-ESP boundary. To map an already validated NAT-T decision, use the one
general options entry point:

```rust,no_run
use std::error::Error;

use opc_ipsec_xfrm::{
    build_xfrm_requests_from_ikev2_child_sa_with_options, Ikev2ChildSaXfrmOptions,
    Ikev2ChildSaXfrmRequest, Ikev2ChildSaXfrmRequests, UdpEncap,
};

fn map_natt_child_sa(
    request: &Ikev2ChildSaXfrmRequest,
) -> Result<Ikev2ChildSaXfrmRequests, Box<dyn Error>> {
    let options = Ikev2ChildSaXfrmOptions::new().with_udp_encapsulation(
        // Peer-to-local: translated peer source port to local NAT-T port.
        UdpEncap::esp_in_udp(62_000, 4500),
        // Local-to-peer: local NAT-T port to translated peer destination.
        UdpEncap::esp_in_udp(4500, 62_000),
    )?;
    Ok(build_xfrm_requests_from_ikev2_child_sa_with_options(
        request, options,
    )?)
}
```

The options constructor rejects every type other than RFC 3948 ESP-in-UDP and
rejects zero ports with stable, value-free errors. The mapper carries each
validated template unchanged into its matching `SaParameters::encap`; it never
reverses ports. Default options keep both directions at `None` and preserve the
original native-ESP mapping exactly.

NAT detection, deciding whether encapsulation is required, and selecting
original or translated directional ports remain product-owned. This initial
mapping does not observe post-establishment rebinding or relocate an installed
SA; use the separately fenced relocation boundary only after authenticated
control-plane authorization and exact state reconciliation.

## Exact SA relocation

`XfrmBackend::relocate_sa` moves one query-proven tunnel-mode ESP SA to
authenticated control-plane-signalled outer addresses and replacement
ESP-in-UDP ports. The Linux backend uses the current-upstream
`XFRM_MSG_MIGRATE_STATE` UAPI, which looks up the existing state by
destination, SPI, protocol, family, and input mark. It deliberately does not
use the older `XFRM_MSG_MIGRATE` operation: that operation cannot identify one
SA by SPI and mark and therefore cannot satisfy this API's exact-identity
contract.

Identity by mark is narrower than it looks, and the limit is a kernel
property rather than a choice this crate makes. See
[Lookup marks and what "exact" can mean](#lookup-marks-and-what-exact-can-mean).

Build the optimistic-concurrency identity from a fresh query instead of
reconstructing it from remembered configuration:

```rust,no_run
use opc_ipsec_xfrm::{
    IpAddress, QuerySaRequest, RelocateSaRequest, SaRelocationDirection,
    SaRelocationEncap, UdpEncap, XfrmBackend,
};

async fn move_authenticated_sa(
    backend: &impl XfrmBackend,
    query: QuerySaRequest,
) -> Result<(), opc_ipsec_xfrm::XfrmError> {
    let current = backend.query_sa_relocation_identity(query).await?;
    backend
        .relocate_sa(RelocateSaRequest {
            current,
            new_source_address: IpAddress::Ipv4([198, 51, 100, 10]),
            new_destination: IpAddress::Ipv4([198, 51, 100, 20]),
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::Inbound,
        })
        .await
}
```

This is an authenticated control-plane primitive, not packet inference. A
consumer may call it only after an authenticated/signalled procedure such as
MOBIKE or an equivalent product-owned rebind decision has authorized the new
endpoints. The SDK never learns or trusts a replacement endpoint merely
because a packet arrived from it.

The `direction` field makes the current-upstream Linux safety contract
explicit. `Inbound` needs no temporary policy: the kernel atomically transfers
sequence and replay state, and there is no cleartext egress fallback.
`OutboundBlockPolicyInstalled` is an assertion by the caller that the required
outbound block is already active. For every outgoing SA, follow this exact
order while holding the namespace-wide XFRM writer lock:

1. Install a higher-precedence block policy for the affected selector.
2. Remove the old allow policy.
3. Call `relocate_sa` with `OutboundBlockPolicyInstalled`.
4. Install the replacement allow policy/template for the relocated SA.
5. Remove the temporary block policy only after the replacement is proven.

Keep the block installed when relocation returns `StateIndeterminate`; resolve
the SA and policy state before allowing traffic. Omitting this sequence can
allow outbound cleartext during policy/SA transition. With AES-GCM it can also
allow a repeated `(key, IV)` pair, which destroys the algorithm's security.
That IV risk is outbound-only because the peer controls IV generation for an
incoming SA. This sequence follows the upstream Linux
[`XFRM_MSG_MIGRATE_STATE` documentation](https://docs.kernel.org/networking/xfrm/xfrm_migrate_state.html).

### Cancel safety

`relocate_sa` is not cancellation-safe once its future has been polled. The
blocking netlink worker can continue after the Rust future is dropped, so do
not put relocation behind an aborting timeout and do not assume that dropping
the future cancels the kernel operation. Supervise and poll it to completion.
Treat task cancellation, caller disconnection, or process uncertainty as
`StateIndeterminate` operationally. Keep the outbound block policy and the
namespace-wide XFRM writer exclusion in place until the worker completes and
exact GETSA queries reconcile both the old and new tuples. If the process exits,
keep traffic fenced and perform that reconciliation during recovery before
releasing the block. Retry only after exact readback; relocation is not blindly
idempotent after process loss.

`SaRelocationEncap::Preserve` omits the kernel attribute and exactly inherits
either native ESP or the installed NAT-T ports. `Set` adds or replaces an
ESP-in-UDP template; `Remove` uses the upstream type-zero sentinel to return to
native ESP. Invalid or no-op transitions fail before mutation.

The fresh identity also carries every selector field that the migration UAPI
installs: both ports and masks, prefix lengths, protocol, interface index, and
UID. Preflight and readback compare those fields exactly. When the destination
identity changes, success additionally requires an exact query proving that the
old tuple is absent; an old tuple that is still present or cannot be parsed or
queried unambiguously returns `StateIndeterminate`. Encapsulation-only changes
at the same destination use the single exact resulting-state readback because
the old and target lookup identities are identical. IPv4 union padding and
selector reserved bytes must be canonical. The narrow SDK NAT-T model has no
original-address (`xfrm_encap_tmpl.oa`) representation, so a queried SA with a
nonzero original address is rejected before mutation instead of silently
zeroing it.

The operation changes one SA only. It does not migrate XFRM policies or their
templates. Consumers must coordinate any policy changes, including policies
whose templates pin an outer address or SPI, and must serialize all XFRM
writers in the network namespace. The preflight and post-mutation GETSA proofs
cannot exclude a concurrent external writer. This primitive alone is not a
claim of seamless mobility: kernel support, authenticated IKE control-plane
handling, peer behavior, policy coordination, and traffic evidence remain
required.

Linux stores an internal `UnknownUntilUse` state until
`XfrmBackend::sa_relocation_capability` is called. That method sends the
upstream-documented non-mutating `XFRM_MSG_MIGRATE_STATE` missing-SA probe. Its
non-zero SPI is paired with protocol zero, which Linux does not permit on an
installed SA, so the probe tuple cannot collide even in a live namespace. An
`ESRCH` response proves `Available`; `EINVAL` proves that the kernel predates
the message; and `ENOPROTOOPT` proves that the message is known but
`CONFIG_XFRM_MIGRATE` is disabled. Both unsupported responses report
`Missing`. After support is established, `EINVAL` from a real relocation stays
a real operation failure and never masquerades as old-kernel evidence.
Successful exact relocation/readback also records `Available`, while a real
`ENOPROTOOPT` records `Missing`. The kernel must carry the upstream
`XFRM_MSG_MIGRATE_STATE` UAPI; version-string inference is intentionally not
used. The mock backend provides deterministic relocation semantics, while
unsupported backends reject the operation. The new trait methods have defaults
and the existing `XfrmProbe` and `SaState` shapes are unchanged, so existing
backend implementations and struct literals remain source compatible. No
Cargo feature is required.

## Authenticated ESP peer observations

`LinuxEspPeerObservationMonitor` is the production observation authority
needed before an RFC 7296 section 2.23 recovery updates an established
ESP-in-UDP path. It turns kernel-attributed ESP decap events into bounded,
typed observations keyed by exact SA identity and direction. When an admitted
inbound SA starts arriving from a new outer source, the consumer drains one
`EspPeerObservation` containing only the routing facts needed by product
policy: address family, kernel `skb_iif`, encapsulation source address and
port, monotonic per-SA generation, and explicit loss status. The monitor
never applies or infers a relocation.

An observation is only as strong as its trust anchor. The boundary accepts
solely `EspPeerEventProvenance::PostFinalReplayAccepted` events: the kernel
ESP decap path verified packet integrity (ICV or AEAD) and reached the
successful final anti-replay decision on the exact SA named by the event.
Stock Linux
`XFRM_MSG_MAPPING` does not meet that contract — it is emitted post-ICV but
before the final replay recheck (a concurrent duplicate can emit it and still
lose replay), its `GFP_ATOMIC` producer loss is invisible to receivers, and it
carries no ingress ifindex, ESP sequence, lookup mark, or XFRM `if_id`. The
crate therefore ships a committed CO-RE source that attaches to the final
replay-decision and XFRM lifecycle hooks. Construction loads and attaches that
source inside the namespace-bound XFRM actor, pins scope with
`SO_NETNS_COOKIE`, and keeps all provenance-bearing inputs private.

`register_sa` performs exact GETSA admission twice around an initially unarmed
map publication. It refuses crypt-only, replay-disabled, offloaded, outbound,
non-ESP-in-UDP, malformed, or changed SAs. Legacy states whose explicit
direction is absent are admitted only through the inbound ESP/replay path;
explicit outbound states are refused. Kernel lifecycle changes, tracing-link
loss, malformed records, torn state, or unaccounted producer loss terminate
the monitor fail-closed.

Polling is bounded by configuration and periodically revalidates every live SA
with exact GETSA. The boundary rejects foreign-scope, unknown-SA, cross-SA,
wrong-direction, family-mismatched, malformed, interface-scope-less,
stale-cursor, and post-teardown events with value-free labels. Memory and
kernel maps are bounded. A second distinct source while an observation remains
pending closes that SA slot; draining alone does not reopen it because the
kernel may already have suppressed the overflowed tuple.

After the product completes an authenticated relocation, call
`refresh_current_source` with the live handle. The monitor unpublishes the
registration, waits for admitted hooks to quiesce, reconciles exact
cursor/loss counts, proves the new source with two matching GETSA reads, and
only then arms the new baseline. The API never accepts an arbitrary
caller-supplied baseline. Cancellation leaves refresh or teardown unpublished
and resumable; ordinary polling returns an indeterminate-state error until the
interrupted transaction is resumed. Teardown uses the same quiescent protocol,
removes all per-SA state, and returns an exact termination record.

The host needs Linux BTF, tracing/eBPF privileges, and the kernel hooks named
by the committed CO-RE object. Failure to load, verify, attach, or retain every
required link is fail-closed. `Debug`/`Display` for observation types print
only labels and non-sensitive metadata—never addresses, ports, SPIs, marks,
or interface identities.

## Lookup marks and what "exact" can mean

An SA or policy lookup mark is [`XfrmLookupMark`], not a raw value/mask pair,
because Linux does not compare lookup marks as pairs. `xfrm_mark_get` returns
the incoming lookup value as `value & mask` while storing the raw pair on the
object, and `__xfrm_state_lookup` selects with

```text
(incoming_lookup_value & stored.mask) == stored.value
```

Two consequences drive the API.

**A value carrying bits outside its mask is unaddressable.** For a stored
`{ value: 0x11, mask: 0xf0 }`, every candidate left-hand side `(L & 0xf0)` has
its low nibble clear and can never equal `0x11`. `XfrmLookupMark::new` refuses
that shape, and the Linux parse boundaries refuse it on readback too: a state
another writer installed that way is reported as an error rather than adopted
as an identity this crate could later claim to remove. A zero mask is likewise
refused; `None` is the only unmarked form.

**Distinct canonical marks are not distinct identities.** Canonical
`{ 0x10, 0xf0 }` and `{ 0x11, 0xff }` overlap asymmetrically on one
destination/protocol/SPI tuple. Installing `{0x10,0xf0}` first makes
`{0x11,0xff}` collide, because `0x11 & 0xf0 == 0x10`; installing them in the
other order admits both, and a later lookup carrying `0x11` then matches both
stored states. Equal `Option<XfrmLookupMark>` values in Rust are therefore
**not** proof that a GETSA or DELSA can select only one object.

Because of that, an API that names one object and then mutates or deletes it
accepts only the **exact profile**: `None`, or a full-mask mark. Distinct
full-mask marks have disjoint lookup domains, so they cannot alias each other.
Anything narrower is rejected before a request is issued, by
`XfrmStagedInstall::run` (and therefore `run_and_commit_outbound_sa_policy`),
`XfrmStagedObjectInstall::run`, `install_sa_policy_with_rollback`,
`validate_outbound_request`, and `relocate_sa`. Read-only paths that verify identity by readback --
`query_sa` and ESP-peer-observation registration -- keep accepting any
canonical mark, because there a lookup that selected some other overlapping
state surfaces as a mismatch instead of a silent wrong answer.

Two limits remain, and they are preconditions on the deployment rather than
guarantees this crate can make:

- The exact profile makes marked-vs-marked aliasing impossible, not
  marked-vs-unmarked. An unmarked object stores `{ 0, 0 }`, and `(L & 0) == 0`
  holds for every `L`, so an unmarked SA is selected by *every* lookup value.
  Linux refuses to add a marked state when an unmarked one already occupies
  the tuple, but it will admit an unmarked state alongside marked ones. Do not
  mix unmarked and marked SAs on one destination/protocol/SPI.
- A foreign state installed by another writer with a narrower mask still
  widens the lookup domain. Proving otherwise would require dumping the tuple
  on every removal, which this crate does not do; it fails closed on the
  request instead.

## Per-SA output marks

`SaParameters::output_mark` emits the generic Linux
`XFRMA_SET_MARK`/`XFRMA_SET_MARK_MASK` pair. Linux applies that masked value to
`skb->mark` after the SA transforms a packet, including after an inbound SA
decrypts it. This lets a later routing or dataplane boundary distinguish which
SA accepted a packet even when several SAs carry the same inner address. The
Linux and mock backends both return the exact pair as `SaState::output_mark`.
The value and mask must not both be zero: Linux omits that pair from kernel
readback, so use `output_mark: None` when no post-transform mark mutation is
required.

The ignored privileged test installs matching peer and local XFRM paths, sends
real inbound ESP, receives the decrypted UDP payload, and observes the masked
output mark with an `iptables` INPUT counter. This distinguishes datapath
behavior from netlink state readback alone.

The output mark is independent of `SaParameters::mark`, and the two are
different Rust types for that reason: `mark` is an
[`XfrmLookupMark`](#lookup-marks-and-what-exact-can-mean), emits `XFRMA_MARK`
and participates in selecting the SA, while `output_mark` stays a plain
`XfrmMark` because it is an arbitrary post-transform value/mask pair -- a zero
mask is legal there -- and changes the packet only after that SA runs.

For example, a caller can annotate the inbound half of an IKEv2 Child SA
without changing SA lookup:

```rust,no_run
use opc_ipsec_xfrm::{InstallSaRequest, XfrmMark};

fn mark_inbound_bearer(mut request: InstallSaRequest) -> InstallSaRequest {
    request.parameters.output_mark = Some(XfrmMark {
        value: 0x0001_0000,
        mask: 0x00ff_0000,
    });
    request
}
```

Source migration: existing `SaParameters` struct literals must add
`output_mark: None` to preserve their previous wire behavior. Exhaustive
`SaState` destructuring must account for the new `output_mark` field (or use
`..`). No Cargo feature is required.

This generic path remains independent when the Linux backend also has the
fixed-DSCP companion configured: an SA with `egress_dscp: None` may use the
complete mark and mask, including `(value = 0, mask = u32::MAX)` to clear a
stale bearer selector. If `egress_dscp` is set on the same SA, the generic
output-mark value and mask must remain disjoint from the configured seven-bit
token window. The backend combines the disjoint generic value and DSCP token
into the kernel's single output-mark pair and rejects an overlap.

`SaState::output_mark` is always the exact kernel pair. A query cannot recover
whether an arbitrary overlapping generic mark was originally intended as a
DSCP token, so `SaState::egress_dscp` is decoded only when the output-mark pair
exclusively carries one complete token; broader, partial, or presence-free
overlaps remain generic. Callers own
namespace-wide `skb->mark` allocation and must coordinate every producer and
consumer of the selected bits. In particular, packets crossing the DSCP tc
companion must not carry an accidental token in its reserved window. A
successful Linux install or rekey includes an exact GETSA readback of the
output-mark pair; an ACK without that proof returns `StateIndeterminate` and is
never followed by an unsafe compensating delete.

## Fixed Outer DSCP

Linux XFRM exposes a masked output mark but no fixed outer-DSCP SA attribute.
The production backend therefore combines two kernel mechanisms:

1. `XFRMA_SET_MARK`/`XFRMA_SET_MARK_MASK` place a presence bit plus the
   validated six-bit `DscpCodepoint` into a deployment-reserved seven-bit
   `skb->mark` window after XFRM transformation.
2. A committed tc egress eBPF companion on every explicitly configured SWu
   egress interface consumes that token, stamps the outer IPv4 or IPv6 DSCP,
   preserves ECN and unrelated mark bits, updates the IPv4 checksum, and
   clears only the reserved token bits.

Configure the companion before installing any SA with `egress_dscp: Some(_)`:

```rust,no_run
use opc_ipsec_xfrm::{LinuxXfrmBackend, LinuxXfrmDscpMarkingConfig};

let mut marking = LinuxXfrmDscpMarkingConfig::new(
    [String::from("swu0")],
    25, // reserves skb mark bits 25..=31
)?;
marking.bpffs_pin_root = "/sys/fs/bpf/my-cnf/xfrm-dscp".into();
let backend = LinuxXfrmBackend::with_dscp_marking(marking)?;
# Ok::<(), opc_ipsec_xfrm::XfrmError>(())
```

When another external egress authority must become active before the
companion, retain the same validated configuration without effects and
activate it later on the namespace actor:

```rust,no_run
use opc_ipsec_xfrm::{LinuxXfrmBackend, LinuxXfrmDscpMarkingConfig};

# async fn example() -> Result<(), opc_ipsec_xfrm::XfrmError> {
let marking = LinuxXfrmDscpMarkingConfig::new([String::from("swu0")], 25)?;

// Validation and retention only: no eBPF load/pin, tc creation/attachment,
// or live companion adoption occurs here or during namespace binding.
let backend = LinuxXfrmBackend::with_deferred_dscp_marking(marking)?
    .bind_current_network_namespace()?;

// Establish the external egress authority here.
backend.activate_dscp_marking().await?;
# Ok(())
# }
```

`with_config_and_deferred_dscp_marking` provides the same boundary with a
custom `LinuxXfrmBackendConfig`. Binding through
`bind_current_network_namespace_with_object_recovery` likewise opens and
returns the authenticated durable store without loading, pinning, attaching,
adopting, or otherwise changing tc/eBPF DSCP state. That path must be ordered
as durable reconciliation, external egress-authority activation, and then
`activate_dscp_marking`. Before actor-local activation succeeds, every
DSCP-bearing SA mutation—including install, rekey, relocation, durable install
admission, and outbound replay-counter update—fails before XFRM mutation;
unmarked operations and durable preparation/finalization/recovery remain
available. A clean durable-admission rejection returns the original authority
through `XfrmObjectInstallRunError::into_retry_authority`, leaving its record
at `Prepared` for retry after activation.

Activation is serialized with those operations on the same namespace actor
and is idempotent after success. A failed attempt does not publish readiness
and may be retried after the caller establishes that the failure was clean. If
an activation observer is cancelled before success can be delivered, runtime
state from that attempt is not readiness authority: marked mutations remain
closed until a later activation revalidates or adopts it successfully.

The pin root must be a normalized child of `/sys/fs/bpf`. Interface names,
the tc priority/handle, and the exact seven-bit mask are validated. The CNF
must reserve the chosen mark window against every output-mark producer and
packet-mark consumer in its network namespace. An SA lookup mark may use the
same numeric bits because `XFRMA_MARK` is a separate kernel attribute; a
generic output mark on the same SA as fixed DSCP may compose only when its
value and mask are disjoint from the DSCP window. SAs without `egress_dscp`
remain independent of the backend-level companion configuration, while the
caller still prevents their packet values from accidentally encoding a token
on an interface where that companion runs. Fixed DSCP is accepted only for
tunnel-mode ESP SAs.

The existing `with_dscp_marking` constructors eagerly attach or adopt the exact
owned tc slot; the distinct deferred constructors do so only during explicit
actor-local activation. Every marked install/rekey revalidates the live map and
filter before sending netlink. The netlink filter is deliberately kernel-owned
rather than loader-owned, so an old process dropping its Aya handles cannot
remove a slot already adopted by its replacement. Adoption requires the live
tc program ID, pinned program ID, pinned config-map ID/profile, and the embedded
SDK artifact's kernel program tag/type/name to match exactly. A stale
pre-upgrade or foreign classifier fails closed without detaching or replacing
the live filter.

Classifier upgrades are intentionally drain-and-replace, not in-place: stop
all SDK writers for the namespace, drain/remove every marked SA and traffic
path, remove only the configured SDK tc priority/handle and its per-interface
pin directory, then start the new binary and require its probe/readback gates
again. Network-namespace teardown performs that cleanup naturally. Never
delete the pin or live filter while marked SAs can still emit traffic; this
implementation does not claim an atomic program-upgrade mechanism.

The deferred probe does not consult runtime capability before activation and
reports `egress_dscp_marking = Unknown`. After eager readiness or explicit
activation, it remains `Unknown` until exact marked GETSA readback proves the
stable redaction-safe SA fields and both `XFRMA_SET_MARK` attributes; a
NEWSA/UPDSA ACK alone is never attribute proof because an older kernel may
ignore unknown attributes. The ACK linearizes kernel acceptance of that
request, while the later GETSA observes current state. GETSA deliberately
excludes key material, so it cannot prove cryptographic ownership or exclude a
later same-identity UPDSA from another writer. The CNF must serialize
namespace-wide XFRM SA and policy identity mutations and rollback: Linux
DELSA/DELPOLICY has no owner- or generation-conditional delete. The probe
reports `Available` only while the exact companion remains live. Mock,
unsupported, and mainline Linux GTP-style paths reject `Some` instead of
silently ignoring it. `egress_dscp: None` does not require this configuration.
When `output_mark` is also `None`, the backend emits the exact pre-feature XFRM
netlink payload.

An SA or policy's optional lookup `XfrmLookupMark` is a separate identity
component from the companion's reserved output-mark window, and a different
type from it. Use the same mark on `SaParameters`, `PolicyParameters`,
`QuerySaRequest`, `RemoveSaRequest`, and `RemovePolicyRequest`.

Marked and unmarked SA identities are **not** unconditionally distinct, and a
mark does not by itself make a deletion exact: an unmarked object stores
`{ 0, 0 }`, which the kernel predicate matches for every lookup value. See
[Lookup marks and what "exact" can mean](#lookup-marks-and-what-exact-can-mean)
before relying on a mark to separate two objects on one
destination/protocol/SPI. The
request constructors target unmarked kernel objects, while `with_mark` selects
a marked object. Installs carrying any output mark are not reported successful
until an exact GETSA readback succeeds. If readback fails or any stable returned
field differs after the NEWSA ACK, the backend returns `StateIndeterminate` and
never sends a compensating DELSA: an external writer may already have updated
that identity, so deletion would be unsafe. An output-marked UPDSA readback
failure is likewise `StateIndeterminate` because safe query state deliberately
excludes the old key material needed for rollback.

## Relationships

- `opc-linux-xfrm-sys` owns raw XFRM netlink sockets and UAPI layouts.
- `opc-proto-ikev2` is optional and only used behind the `ikev2` feature.
- Route steering, GTP-U, and node-resource checks live in sibling crates and
  are intentionally not folded into this XFRM backend.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Safe Rust only (`#![forbid(unsafe_code)]`).
- `KeyMaterial` zeroizes on drop, redacts debug/display, and compares bytes
  with constant-time equality.
- Linux SA encoding validates and computes the complete UAPI body size before
  copying authentication, encryption, or AEAD keys. Algorithm temporaries, the
  fixed-capacity SA body, and the complete netlink request are zeroizing
  buffers; the destination allocation cannot grow after its first key copy.
  This covers the transient userspace UAPI copy only—kernel key custody remains
  platform-owned.
- The configured netlink receive size is a hard bound. A consumed oversized
  reply after a mutation returns `StateIndeterminate` with the original
  operation; an oversized read returns typed `ResponseTooLarge`. Neither path
  retries the already-consumed datagram.
- Linux mutation requires kernel XFRM support and effective `CAP_NET_ADMIN`.
- Exact SA relocation additionally requires the upstream
  `XFRM_MSG_MIGRATE_STATE` UAPI and product-owned authenticated endpoint and
  policy coordination.
- Fixed outer DSCP additionally requires bpffs, kernel BTF, `CAP_BPF` (or
  `CAP_SYS_ADMIN`), one configured tc egress attachment per SWu interface, and
  a globally reserved seven-bit skb-mark window.
- `query_sa` returns replay/lifetime/statistics and the exact generic/combined
  output mark, but never key material.
- The `ikev2` feature maps validated Child SA intent to XFRM requests; it does
  not run IKE, allocate SPIs, enable ENCR_NULL in an allowlist, or choose
  product policy. Caller-owned NAT detection and port selection may be passed
  as validated directional initial ESP-in-UDP options.
- The IKEv2 mapper keeps SPI-pinned policies as its compatibility default and
  also supports a shared non-zero request ID with wildcard policy-template SPI
  for simultaneous old/new Child-SA rekey overlap.

## Roadmap

- Keep additional XFRM algorithm support explicit and validated before encoding
  it to the kernel.
- Extend restore/query coverage where HA replay continuity requires more kernel
  state.
- Keep IKEv2 mapping exact: reject unrepresentable selector ranges or key shapes
  rather than approximating policy.

## Verification

```sh
cargo test -p opc-ipsec-xfrm
cargo test -p opc-ipsec-xfrm --features ikev2
./scripts/build-ipsec-xfrm-ebpf.sh
# Requires named-netns support, iproute2, ping, tcpdump with EN10MB capture,
# Linux XFRM, and effective CAP_NET_ADMIN/CAP_NET_RAW. The in-memory capture
# proves the first emitted ESP SPI/sequence and is neither logged nor saved.
sudo OPC_XFRM_RUN_NAMESPACE_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_namespace_bound_privileged -- --ignored --nocapture
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_dscp_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_RELOCATION_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_relocation_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_AUTH_ONLY_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --features ikev2 --test xfrm_auth_only_privileged -- --ignored --nocapture'
```
