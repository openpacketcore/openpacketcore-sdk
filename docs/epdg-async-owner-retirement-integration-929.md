# ePDG protected Async owner retirement: integration packet for SDK #929

Status: source-verified integration plan, 2026-09-20. No SDK production change,
new failing regression, ePDG implementation, or live qualification is claimed.

ePDG consumes the SDK capability for protected Async recovery after abrupt
majority/all-voter loss, but has not installed its complete external-owner
inventory or implemented the corresponding durable retirement adapters. The
unconfigured path correctly remains fenced. Updating the dependency pin or
removing that guard cannot supply the missing external authority.

The next implementation belongs in ePDG: establish actual owner coverage,
then implement a retained whole-range floor and effect exclusion before
enabling challenge signing. The SDK already supplies inventory verification,
challenge coordination, proof validation and the committed recovery boundary.
No reusable SDK defect was demonstrated in this assignment.

## Frozen sources and scope

| Input | Verified revision |
| --- | --- |
| SDK analysis/test base | `f7183b38ae51196f206b2add4f6246704adc0ba6` |
| SDK base tree | `bbd1990d7174bb2c1ef173e7357030080a30b901` |
| SDK #929 merge and ePDG consumed pin | `71c4409af43cebac45d96e6618c089f1c454e327` |
| ePDG baseline, including #272 | `34654a604425891b9069dc6a895978c6d457497f` |
| ePDG tree | `57b3a0611dec986630dc5b70f6181eb0854673ca` |
| Packet branch | `work/epdg-async-owner-retirement-20260920` |

The consumed pin is an ancestor of the SDK base. Comparing that pin with the
base found no changes in `crates/opc-session-store`, `crates/opc-session-net`,
`crates/opc-session-testkit`, or these four contract documents:

- [Protected Async recovery](async-protected-recovery-908.md).
- [Async majority recovery](async-majority-recovery-908.md).
- [Protected atomic roster](session-store-protected-atomic-roster.md).
- [ADR 0022: native session persistence](adr/0022-native-session-persistence-modes.md).

SDK source links below refer to that base; ePDG anchors refer exclusively to
the frozen ePDG revision. Read an ePDG anchor using
`git -C <epdg-checkout> show 34654a604425891b9069dc6a895978c6d457497f:<path>`.
This packet does not depend on private incident captures or credentials.

The following bounded search over the complete frozen ePDG `crates` tree
returned no matches (exit 1):

```sh
git -C <epdg-checkout> grep -n -E \
  'ProtectedAsyncRecovery|ProtectedRecoveryInventory|ProtectedAsyncRecoveryOwner|configure_protected_async_recovery' \
  34654a604425891b9069dc6a895978c6d457497f -- crates
```

This is source evidence of absent API composition, not an executed ePDG
recovery RED. E01 explicitly documents the same integration gap.

Orderly production shutdown already exists: E02 revokes consumer admission,
joins transports, then retains and rejoins the SDK store shutdown operation.
E04 contains Durable and Async protected-quorum reopen regressions. The
historical missing-shutdown finding is resolved at this baseline; orderly
shutdown is not abrupt recovery.

The handoff records successful full Linux ePDG `make ci` before #272 merged,
and distinct Durable/Async CRC startup and orderly recovery observations.
These were not rerun here. Its last common traffic-suite attempt stopped at
a then-failing CI prerequisite and was not rerun after final CI passed. That
is neither a traffic pass nor a newly observed forwarding failure.

## SDK authority and call path

| Stage | Exact SDK source | Required composition/meaning |
| --- | --- | --- |
| Describe each external signing owner | [ProtectedRecoveryOwner::new](../crates/opc-session-store/src/consensus/protected_recovery.rs#L175) | Nonzero 32-byte identity and valid compressed P-256 public key. This is an effect owner, not a roster-member ordinal. |
| Provision complete authority | [ProtectedRecoveryInventory::signing_digest](../crates/opc-session-store/src/consensus/protected_recovery.rs#L208), [from_signed_parts](../crates/opc-session-store/src/consensus/protected_recovery.rs#L230) | Root-signed exact configuration identity/epoch and fixed 3- or 5-voter set; 1–32 owners, strictly ordered unique identities. Canonical signatures and root binding are verified. Completeness is the root signer's responsibility. |
| Bind real adapters | [ProtectedAsyncRecovery::new](../crates/opc-session-store/src/consensus/protected_recovery.rs#L508) | Exact ordered inventory-to-adapter identity match; no missing or substitute owner. |
| Install on each concrete voter store | [configure_protected_async_recovery](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L130) | One-time installation. Checks Async mode, root, identity, bootstrap membership and retained inventory proof. Replacing authority in an open store is rejected. |
| Select retained history and elect | [recovery round/retained types](../crates/opc-session-store/src/consensus/recovery_types.rs#L39), [commit_recovery](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L665) | Existing unanimous retained-root protocol and real consensus election precede retirement; do not manufacture votes or choose history from session rows. |
| Issue exact owner challenge | [ProtectedRecoveryChallenge](../crates/opc-session-store/src/consensus/protected_recovery.rs#L302), [retire_before](../crates/opc-session-store/src/consensus/protected_recovery.rs#L536) | Binds complete inventory, configuration, recovery era, round and full selection: roots, boots, full votes/LogIds, completed generations/sequences and application digests. |
| Retire physical authority | [ProtectedAsyncRecoveryOwner](../crates/opc-session-store/src/consensus/protected_recovery.rs#L474) | `identity()` and async `retire(&ProtectedRecoveryChallenge)` implement the durable external-owner contract. SDK supervision cannot make a product journal or kernel operation crash-safe. |
| Confirm exact completion | [owner_signing_digest](../crates/opc-session-store/src/consensus/protected_recovery.rs#L335), [receipt](../crates/opc-session-store/src/consensus/protected_recovery.rs#L342), [ProtectedRecoveryProof](../crates/opc-session-store/src/consensus/protected_recovery.rs#L407) | Owner signs its owner-specific exact challenge digest, then the SDK verifies the receipt. Every owner must confirm; a floor number or unrelated receipt is insufficient. |
| Commit the internal boundary | [commit_recovery](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L665), [validate_protected_scope](../crates/opc-session-store/src/consensus/native/async_recovery.rs#L90), [apply_async_boundary](../crates/opc-session-store/src/consensus/native/async_recovery.rs#L269) | The real consensus log carries the complete proof. Native application/cold readers validate the actual root and scope. The boundary advances the reserved range without erasing retained protected admissions or immutable evidence. |
| Persist and activate all original voters | [ready_recovery](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L833), [activate_recovery](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L907) | Each original retained voter checks the exact selection and applied/persisted boundary. Full membership, boot, root, vote and persistence evidence remain necessary. |
| Obtain current serving authority | [fixed-quorum readiness](../crates/opc-session-store/src/consensus/store/quorum_readiness.rs#L11), E07, E16 | `Active` admits consensus participation. A fresh SDK traffic/placement proof and the product's current Recovery/serving authority still gate effects and publication. Async readiness does not promise Durable retention. |

The retirement floor is inclusive: `challenge.retire_through()` covers the
entire old reserved fence range, computed by the SDK from the recovery era.
An owner rejects any incoming old-range fence, including an unknown binding.
ePDG must consume this value, not reimplement its era arithmetic or compare
unrelated fence domains as bare integers.

The coordinator supervises accepted owner calls and joins all of them even
when a caller times out or one owner fails/panics. Same-challenge calls share
completion; `OwnerPending` permits another attempt. A different challenge
waits for earlier accepted responsibility. This supervisor survives caller
cancellation, not destruction of the owner process: durable restart
responsibility belongs in the adapter.

After a possible commit/lost reply,
[protected_commit_status](../crates/opc-session-store/src/consensus/store/async_persistence/majority.rs#L792)
authenticates progress for the exact selection, leader, full committed vote
and accepted proposal. It does not activate a voter. Preserve the accepted
cut/progress and original deadline; do not replace a committed cut to obtain
more time. Changed authority requires the SDK's fresh unanimous procedure.

## ePDG composition and source anchors

All paths in this table are relative to the frozen ePDG repository. Line
anchors identify entry points, not claims that a single line proves a whole
subsystem. The ownership table below specifies the missing proof at each one.

| ID | Path:line and symbol | Verified role |
| --- | --- | --- |
| E01 | `docs/upstream-dependencies.md:34` (#929 integration status) | Pin, completed orderly shutdown and explicitly missing external-owner composition. |
| E02 | `crates/epdg-app/src/state_quorum.rs:1204` `finish_state_quorum_store_shutdown` | Retains/rejoins shutdown after consumer revocation and transport joins. |
| E03 | `crates/epdg-app/src/state_quorum.rs:1639` `build_resources`; `:1599` `load_roster_consumer_authority` | Builds protected voter runtime; waits for convergence; activates fenced transition and V2 roster; authenticates ingress. Existing ingress signing authority is not a recovery-owner inventory. |
| E04 | `crates/epdg-app/src/state_quorum_bootstrap_tests.rs:424` `production_shutdown_reopens_protected_quorum` | Existing product orderly shutdown/reopen test helper. |
| E05 | `crates/epdg-app/src/serve/wiring.rs:3533` `build_cross_pod_quorum_runtime`; `:2532` `ProtectedRosterWorkerPool`; `:2577` `into_provider` | Concrete voter construction and independent consumer clients/pools. Pool members share supplied provider objects within this composition. |
| E06 | `crates/epdg-state/src/durable/quorum.rs:139` `build_cross_pod_quorum_session_store_backend`; `:186` `open_fixed_quorum_with_persistence` call | Anchored native database/snapshot roots and configured persistence; concrete SDK store available before RPC/init. |
| E07 | `crates/epdg-state/src/durable/evidence.rs:61` `FixedQuorumEvidence`; `:91` `probe_fixed_quorum_evidence` | Projects fresh SDK policy-aware readiness; preserves persistence distinction. |
| E08 | `crates/epdg-app/src/serve/mod.rs:25` `open_and_maintain_protected_roster_journal`; `:6558` `ProtectedRosterProductEffects::new` call | Opens retained worker journal; composes runtime, XFRM recovery store, member/publication effects and worker provider. |
| E09 | `crates/epdg-app/src/protected_roster_journal.rs:414` `provision_new`; `:510` `open`; `:3422` `open_connection` | Explicit initial provisioning versus existing-only reopen; SQLite WAL with FULL synchronous writes. |
| E10 | `crates/epdg-app/src/protected_roster_journal.rs:1553` `register_active_recovery`; `:1621` `mark_dispatch_possible`; `:1678` `active_recovery_rosters` | Sealed exact recovery index and durable possible-dispatch evidence, separate from recovered consensus rows. |
| E11 | `crates/epdg-app/src/protected_roster_journal.rs:1855` `prepare_member`; `:1987` `begin_member_execution`; `:2278` `member_applied_executed`; `:5954` `validate_member_binding_and_fence` | Per-binding fence and Prepared/EffectAmbiguous/completed transitions. No configuration-wide inclusive floor is established by these checks. |
| E12 | `crates/epdg-app/src/protected_roster_journal.rs:2612` `reserve_publication`; `:2735` `begin_publication_attempt`; `:2826` `publication_published_and_retire`; `:5967` `validate_publication_binding_and_fence` | Publication reservation, possible dispatch, immutable publication evidence and per-binding checks. Roster retirement/compaction is not whole-range authority retirement. |
| E13 | `crates/epdg-app/src/protected_roster.rs:953` `ProtectedRosterMemberEffectPort`; `:1035` `ProtectedRosterPublicationEffectPort`; `:1463` `ProtectedRosterProductEffects` | Product effect interfaces, runtime binding and in-memory handoff/cache state. |
| E14 | `crates/epdg-app/src/protected_roster.rs:1828` `execute_xfrm_roster`; `:2088` `execute_aggregate`; `:2415` member `execute` implementation | XFRM durable object-roster operations, dependent observations, grouped GTP-U and exact route readback/convergence. |
| E15 | `crates/epdg-app/src/protected_roster.rs:2972` member-provider `execute`; `:3072` `adopt`; `:3375` publication-provider `adopt`; `:3481` `ProtectedRosterWorkerProvider` | Journal-to-effect dispatch and ordinary provider receipts; prepared and recoverable worker handles. |
| E16 | `crates/epdg-app/src/runtime/dataplane_reconcile.rs:3931` `protocol_effect_permit`; `:3974` `settle_dispatched_terminal_cleanup`; `:4025` `begin_protected_roster_aggregate_effect` | Current Recovery authority, joining dispatched terminal SDK work and common local route/attach exclusion. |
| E17 | `crates/epdg-user-plane/src/route_steering.rs:552` `AuthorizedRouteSteeringBackend`; `:844` `publish_exact_cleanup`; `:913` `retire_current_group_for_exact_cleanup`; `:969` `publish_restart_or_terminal_cleanup_debt` | Exact route ownership/cleanup and process-local controller state. |
| E18 | `crates/epdg-user-plane/src/gtpu_dataplane/grouped.rs:293` `read_grouped_roster`; `:311` `converge_grouped_roster`; `:334` `remove_grouped_roster`; `:853` `converge_child` | SDK-backed grouped PDP/classifier/child ownership and retained possible effects. |
| E19 | `crates/epdg-app/src/runtime/swu_attach/finalize.rs:6864` `publish_protected_roster_startup_ike_auth_replay`; `:6951` `restore_protected_roster_startup_ike_auth_replay` | Recovery of sealed response bytes/deadlines and already-published replay state. |
| E20 | `crates/epdg-app/src/runtime/swu_attach/ike_auth.rs:9402` `begin_cached_swu_ike_auth_replay_publication`; `:9420` `poll_cached_swu_ike_auth_replay_first` | Cached response replay has a real wire publication boundary and current gates. |
| E21 | `crates/epdg-app/src/control_plane_ports.rs:965` `establish_bearer`; `:1310` `release_bearer`; `:821` `BearerReleaseOutcome` | Remote S2b accepted session and exact compensation; pending remote cleanup is distinct from local release. |
| E22 | `crates/epdg-app/src/control_plane_ports.rs:2425` `SubscriberAuthOwnerEffectFence`; `:2916` `DiameterSwmAuthAdapter` | SWm lifecycle owner authority and remote authentication/termination continuations. |
| E23 | `crates/epdg-app/src/session_checkpoint.rs:631` `SessionCheckpointRequest`; `:3837` `PreparedPredecessorTeardownCheckpoint`; `:3953` `PreparedSessionInitialCheckpoint` | Queued state transitions, replay/rebind work and retained prepared checkpoint continuations. |
| E24 | `crates/epdg-app/src/runtime/watchers.rs:4862` `flush_prepared_delete_session_cleanup`; `:4945` `finalize_completed_scheduled_delete_cleanups` | Scheduled/retried exact cleanup and terminal evidence after dispatch. |
| E25 | `crates/epdg-app/src/runtime/recovery_mutation.rs:294` `RecoveryExternalMutationDescriptor`; `:403` `matches_current_composition` | Exact serving/resource composition identity for recovery mutations, including XFRM install/relocation and dataplane session commit. |
| E26 | `crates/epdg-app/src/runtime/s2b_control_send.rs:487` `send_s2b_create_session_request`; `:518` `retransmit_s2b_create_session_request`; `:722` `send_s2b_delete_session_request`; `:748` `send_s2b_bearer_procedure_request` | Actual S2b wire sends, including delayed retransmission and Modify/Update bearer requests. |
| E27 | `crates/epdg-app/src/runtime/swu_attach/rekey.rs:250` `retire_swu_rekeyed_child_sa_pair`; `:1010` `replay_cached_swu_create_child_sa_response` | Rekey overlap cleanup and cached Child/IKE SA response replay through current Recovery authority. |
| E28 | `crates/epdg-app/src/runtime/swu_attach/informational.rs:3753` `spawn_subscriber_detach_bearer_release`; `:3797` `handle_swu_informational_delete` | Detached remote bearer release and authenticated informational teardown/response handling. |

Install the new authority in the concrete store construction path E06/E05
**before** `SessionConsensusServer::new` (E05, line 3685), its listener and the
background `initialize_cluster` driver (line 3716). Thread provisioned
inventory/adapter dependencies from E03. Configuring after convergence or
after V2 activation would miss the recovery that must establish convergence.
Every voter receives the same inventory; its adapters route to the actual
retained effect owners.

Worker-side retirement belongs beside the existing journal/product-effect
composition E08/E13/E15. Preserve pool shutdown ownership (E05,
`shutdown_source`, line 2573) and E02's completed shutdown behavior. An `Arc`
shared by clients in one process proves neither exclusion across independent
processes nor coverage of another worker replica.

## Candidate effect-owner inventory and proof obligations

“Verified” below means the effect family and composition are present in
source. **No row has a verified whole-range retirement implementation at this
baseline.** The table is a complete candidate checklist for the observed
effect paths, not a root-signable declaration of completeness. Before signing
an inventory, the product engineer must reconcile it against every configured
effect-capable process, replica, pool and alternate dispatch/cleanup path.

The six protected roster members are five XFRM observations plus one aggregate
member. The first XFRM member drives the durable group operation; dependent
members observe its result. The aggregate composes GTP-U and routes. These
ordinals, publications and protocol continuations do not establish an owner
count. One signing owner may cover several rows only if a single durable
authority actually controls all their effects across the deployment.

| Family | Verified source/authority today | Required retirement proof and owner scope |
| --- | --- | --- |
| Member provider journal and receipts | E09–E11, E13, E15: per-binding fences, durable ambiguity before dispatch, immutable completed observations. | Gate prepare/execute/status-with-mutation/adopt/reconcile/compensate before old effects, for known and unknown bindings. Include all journal openers, worker replicas and independent pools. Existing provider leaf receipt keys do not automatically authorize recovery signing. |
| Publication provider and handoff | E12/E13/E15: reservations, possible publication, completion and local handoffs. | Same inclusive floor for reserve/begin/adopt/reconcile/restore and final handoff. Account for accepted publications outside the journal transaction and handoffs already removed from an in-memory map. Preserve published evidence; cancellation is not “unpublished.” |
| SDK state transitions and queued checkpoint work | E03/E23: fenced-transition/V2 capabilities, prepared initial/predecessor checkpoints, replay refresh and rebind requests. | SDK consensus writes already have SDK authority checks. Prove which queued continuations can still perform external work and how their exact authority maps to the retired range. Do not count a pure CAS as a new external signer, or assume CAS rejection retracts earlier external effects. |
| Retained prepared handles and continuations | E10/E15/E23: prepared roster/recovery handles, sealed recovery index, checkpoint queues. | Track every accepted handle independently of returned Q1. Persist exact operation/capability identity before possible dispatch. Reject delayed old calls from a second client/pool even when no row exists; retain accepted work through timeout, drop and restart. |
| Protocol response, replay and control sends | E19/E20/E26–E28 and E13's publication port: sealed startup IKE_AUTH response, published replay restore, Child/IKE SA rekey replay, informational teardown and S2b sends/retransmission. | Gate the actual first wire poll/send and every later replay under exact current authority plus owner retirement. Cover response prepared before loss, pending handoff, actor mailbox and restored cache. Map each non-roster protocol authority to the protected scope or prove it cannot act for a retired owner. Local publication completion or absence of a recovered session does not prove the network saw nothing. |
| Remote accepted-session compensation | E21/E26/E28: PGW/S2b establishment, accepted outcome, exact release/cleanup pending states and detached release task. | Retain remote transaction/session debt before accepted work can outlive the task. Join/reconcile the exact remote outcome; preserve unknown outcomes. Bind cleanup to the original owner/generation even with reused identifiers. Remote completion/absence or permanent isolation is required; removing a local allocation is insufficient. |
| SWm/AAA owner lifecycle and continuations | E22, plus SWm pending-owner lifecycle used by these adapters. | Inventory outbound authentication/termination/retry effects and prepared callbacks that can survive admission loss. Prove how this owner authority relates to the SDK recovery configuration; a different lifecycle fence is not numerically interchangeable. If outside that scope, document the separate authority and prove it cannot mutate/publish for a retired protected owner. |
| XFRM objects and durable recovery state | E14/E16/E25: SDK durable object-roster prepare/run, retained XFRM recovery store, adopt/reconcile/compensate and SA relocation descriptors. | Include actual kernel backend executors and any detached/blocking SDK work, not just the product wrapper. Trace rekey, MOBIKE/NAT rebind and pair transactions as well as initial install. Persistent exclusion or exact reconciliation must cover SA/policy/selector generation and reused projections. Do not let delayed cleanup remove a successor object. Retain recovery keys and original object-roster evidence. |
| Routes/rules and shared resources | E14/E16/E17: exact route plans, common local locks, current controller/cleanup capabilities. | Durable scope must include route/rule writes and deletes, restart debt, same-subscriber replacement and shared NAT. Local controller epochs/locks alone do not fence another process or restart. Compare full ownership/composition; never sweep by address or subscriber alone. |
| GTP-U/PDP/classifiers and children | E14/E16/E18: grouped SDK ownership, child/default classifier provenance, converge/read/remove. | Bind exact PDP/group/child generations, TEID/address/selector reuse and shared default classifier ownership. Settle/fence old parent and child work in their actual dependency order before confirming. Preserve retained SDK group state. Ordinary grouped startup issue #273 remains separate. |
| Cleanup, watchers and scheduled retries | E16/E17/E21/E24/E25/E27/E28: predecessor teardown, delete-session, rekey overlap, detached remote debt and terminal finalization. | Treat compensation/deletion as effects, including work already dispatched to blocking code. Hold responsibility until exact settlement or permanent exclusion from successor resources. Cover queues, timers, callbacks and restart reconstruction; suppressing one watcher does not retire other cleanup owners. |

The root signer must produce a coverage manifest mapping these families to
stable owner IDs, signing public keys, physical roots, worker/process roles,
replica/pool coverage and exact exclusion mechanisms. Record excluded paths
with a source-backed reason they cannot affect the protected scope. Resolve
unmapped paths before inventory signing. Do not allocate one owner per
subscriber, discovered journal row, returned session or roster member.

All voters must verify identical immutable inventory bytes/commitment for the
same configuration. No smaller inventory may be substituted because an owner
is unavailable. Sharing a signing key does not merge owner identity: the SDK
owner-specific digest prevents relabelling a receipt between listed owners.
The inventory limit is 32; changing the ownership design or configuration
needs explicit authority, not silent truncation.

## Required durable owner state machine

This is a product design requirement, not an existing ePDG API/schema. Retain
an owner root outside the lossy Async session generations. Bind its header to
the configuration identity/epoch, inventory commitment and owner identity.
Keep a monotonic inclusive retired floor, exact challenge records, durable
accepted-operation/debt records, immutable outcomes and enough typed identity
to distinguish old resources from reused successor projections. Store
sensitive operation material sealed using the existing custody model.

| State/transition | Required durable action and effect rule |
| --- | --- |
| Provisioned / reopen | Admit only the configured root-signed inventory and real owner key. Initial creation is explicit; restart opens existing retained roots. Validate custody, schema and exact scope before serving effects. Missing/corrupt roots are not an empty owner. |
| Accept challenge | Authenticate the voter/adapter and exact scope; validate SDK-produced challenge binding. Persist the exact challenge/owner digest, requested inclusive floor and responsibility before acknowledging acceptance or dispatching retirement work. A digest alone is not authenticated authority. |
| Floor enforced / settling | Monotonically advance the scope-wide floor, serializing it with every admission and effect boundary. An incoming fence `<= floor` is refused even for unknown bindings. Persist floor enforcement before signing. Work already accepted below the floor remains owned and must be joined, exactly reconciled or permanently fenced. |
| Accepted effects resolved | Persist immutable outcome/debt for each possible effect. A completed old effect may remain for exact higher-fence adoption. Orphan cleanup must finish or be permanently unable to touch successor resources. Missing Q1, `NotFound`, lease expiry and dropped futures never convert ambiguity to `NotApplied`. |
| Ready to attest | Establish that every process/pool covered by this owner enforces the floor and no accepted lower-range effect can later violate it. Durably record exact completion before using the owner key. An unavailable/uncontrolled executor keeps the owner pending. |
| Signed / reply uncertain | Sign `owner_signing_digest(owner_id)` with the inventoried key and construct/verify the receipt through `challenge.receipt`. Retain the exact completed obligation and, if cached, exact receipt. A lost reply does not reopen effects or roll back the floor. |
| Duplicate / next challenge | A duplicate joins or reuses only its exact completed obligation. A new challenge waits for accepted responsibility, validates its own digest and receives its own receipt even when its scalar floor equals the previous floor. A delayed older request never lowers the floor or starts cleanup against newer resources. |
| Owner restart | Reopen the same authority and floor, recover accepted/debt records before admitting effects, and resume exact settlement. Reconstruct neither absence nor completion from the current session scan. A cached in-memory completion/lock is not restart evidence. |
| Successor operation | Admit a strictly higher fence only with ordinary current SDK/product authority and exact resource ownership. Retained Q1 can be recovered/reconciled through the protected API. Lost Q1 is not reconstructed from a subscriber key; surviving external debt is handled through its retained exact owner record. |

Implementation must close the check-to-effect race. Adding a SQLite floor
check to `begin_member_execution`, releasing its transaction, and allowing a
kernel future to run while another task signs retirement is insufficient.
Use an owned dispatch protocol: record possible work before dispatch, couple
admission with an exclusion mechanism covering all executors, and keep that
responsibility through actual effect completion. If an external backend
cannot fence a delayed operation itself, serialize its executor against
retirement and prove restart reconciliation before releasing successors.
Do not hold a database transaction across arbitrary network work as a
substitute for a recoverable ownership protocol.

E16 already demonstrates why this matters: terminal cleanup waits for
dispatched SDK work even after Recovery revocation because cancellation can
leave blocking work running. Extend that responsibility across the full
inventory and process crashes; a local mutex or cancelled future is not a
durable fence. Existing per-binding journal checks compare against that
binding's floor; adding the configuration floor must preserve those exact
binding/evidence checks as well.

At the four crash boundaries, retain these obligations:

1. **Floor persisted, settlement incomplete:** reopen the enforced floor and
   accepted-work ledger; return pending until all old effects are settled or
   permanently isolated. Do not sign merely because the floor exists.
2. **Settlement complete, no signature:** reuse exact durable completion and
   sign the requested owner-specific digest without redispatching effects.
3. **Signature produced, no durable consensus boundary yet:** the owner stays
   retired independently of the voter's outcome; duplicate exact receipt
   delivery is safe. A later challenge still needs its own receipt.
4. **Consensus commit possible, reply missing:** retain the owner result and
   let SDK authenticated progress rejoin the exact proposal/cut. Owner
   completion alone cannot declare a voter active or select another history.

Errors at the SDK adapter boundary remain the fixed
`ProtectedRecoveryError::{AuthorityRejected, OwnerPending, Deadline}`. Keep
physical debt/failure details in protected retained state. Use fixed product
reason enums and counts in diagnostics, without raw protocol values,
addresses, identifiers, signing material or arbitrary Debug/error output.

## Storage, signing authority and the voter/worker bridge

Preserve original voter database/snapshot roots and their retained
membership/incarnations. Preserve worker provider journals, exact recovery
indexes, XFRM object-roster recovery state, grouped resource state and their
existing recovery keys independently of returned Async generations. Existing
E09 provision-versus-open semantics are a useful foundation. Recovery must
not silently provision empty owner state on a missing path, restore an older
floor, clear a reservation or delete debt to make readiness pass.

Use the existing protected trust root to authorize the complete recovery
inventory. Provision dedicated owner retirement signing keys under that
authority and existing custody model. Separate root provisioning authority,
runtime owner signing authority and ordinary member/publication/ingress
receipt authority; a similarly named signer is not evidence of that binding.
Signatures must satisfy the SDK P-256 prehash/canonical low-S contract. Do not
install test keys, give arbitrary consumers a signing endpoint, or copy private owner
keys into every voter to simulate completion.

The voter and effect worker are separate composition points. Each SDK adapter
needs an authenticated, bounded route to the real owner, available while
normal consumer/traffic ingress is fenced. Starting that route only after
quorum readiness would create a circular dependency. The owner may settle
retained debt during recovery, but this channel cannot grant normal traffic
authority or create unrelated subscriber work.

`ProtectedRecoveryChallenge` is an opaque SDK object with public identity,
floor and digest/receipt methods; its internal wire representation is not a
public product serialization API. Keep that object in the voter adapter. If
the owner is remote, design a bounded authenticated request carrying the exact
SDK-derived owner digest, scope and floor, with the owner's provisioned
inventory binding and durable deduplication. The signer must trust and
authenticate the adapter's derivation, not sign arbitrary consumer bytes.
Return its signature to the adapter for SDK receipt verification. Prove
transport replay, timeout, process replacement and inventory mismatch behavior
before enabling it. This bridge is not implemented by the current product,
and no new generic SDK wire API is established as necessary by this packet.

E25 explicitly rejects retained descriptors from another pod incarnation,
boot/network namespace, backend selection or managed device incarnation.
Owner-process restart tests must state which of these identities survive.
Retaining journal bytes alone cannot authorize moving effects into a new
namespace. If the old executor or resources remain possible but inaccessible,
retain debt and stay pending until exact reconciliation or permanent fencing
is proved; do not weaken the composition check to obtain restart progress.

Retirement settlement may need to proceed while normal current traffic
authority is absent. Give it only exact retained-debt/exclusion capability;
do not bypass E16's serving gates wholesale. If current product handles cannot
settle debt in that state, leave `OwnerPending` and implement a constrained
recovery path. This is a concrete liveness question for the downstream design.

Provision inventory/owner custody through the existing deployment authority
model and retained paths. The assignment does not authorize a ConfigMap
application-configuration redesign, configuration-consensus service,
provisioner/KMS pods, new trust roots or platform privileges. Missing owners,
original roots, membership, custody or conflicting committed histories require
separate explicit repair authority; they are not automatic recovery cases.

## Ordered downstream implementation plan

1. **Close the coverage and fence-domain design.** At the frozen product base,
   map every candidate row to actual effect-capable processes/pools and exact
   retained roots. Trace alternate replay/cleanup/remote callbacks. Specify
   how SWm, protocol and prepared checkpoint authority maps to this scope, or
   prove separation. Assign owner IDs/keys only after this coverage proof.
2. **Build the smallest non-activating slice.** In the ePDG journal/effect
   composition (E09–E16), add retained configuration/owner floor state and a
   shared owned-dispatch guard for member and publication paths. First prove
   known/unknown old-binding rejection across two independently opened pools,
   accepted-effect draining, floor persistence and crash reopening. Include
   every mutation variant; a prepare-only guard is insufficient. Keep recovery
   signing/activation disabled while any effect family remains uncovered.
3. **Extend to actual physical owners and debt.** Cover XFRM, route/rule,
   grouped GTP-U/classifier, protocol replay, remote accepted-session and
   scheduled cleanup paths. Retain exact possible effects before dispatch;
   exercise resource reuse and higher-fence successors. Decide shared versus
   separate signers from demonstrated exclusion, not source-module count.
4. **Implement durable exact challenge handling and its bridge.** Add the
   state machine above, duplicate/join behavior and authenticated startup
   route; prove every crash boundary with real separate owner processes.
   Provision the immutable root-signed inventory through existing custody.
5. **Install before initialization.** Thread the complete inventory/adapters
   through E03/E06/E05 to every Async voter before listener/init. Retain the
   same authority across restart. Leave Durable construction and existing
   orderly shutdown behavior intact. Expose the passive SDK recovery state
   alongside independent current traffic/Recovery evidence.
6. **Run offline product regressions, then required gates.** Implement the
   matrix below through the repository's approved `epdg-dev`/`make ci` lanes;
   use its documented toolchain/profiles, native disk and existing deadlines.
   Capture a real baseline RED for any subsequently claimed defect and GREEN
   at the corrected source. No product-local SDK patch/path dependency.
7. **Request a separate live qualification after review/landing.** The CRC
   lane below is conditional on complete integration and offline gates, and
   has not been run by this assignment.

Reusable SDK gaps: **none demonstrated**. Existing APIs cover the required
contract and the focused controls below pass. A future inability to carry
the exact challenge safely across the real product process boundary, or a
missing backend exclusion capability, must be reduced to a minimal executed
regression before assigning SDK work. Product orchestration, key custody,
inventory completeness and adapter enforcement remain ePDG responsibilities.

## Executed focused SDK evidence

These are executions from this task at the frozen SDK base, retained during
interactive takeover and independently checked against their log hashes.
They are not historical #929 RED/GREEN logs. No passing command was rerun
without a code change. All 19 selected tests passed, with zero failed or
ignored tests; filtered tests were not executed.

Environment: `rustc 1.98.1 (48a229cea 2026-09-01)`,
`cargo 1.98.1 (797e8a9bc 2026-08-05)`, Linux private real-disk XFS TMPDIR
(`/dev/mapper/fedora-agents`, checked using `findmnt`), isolated target
directory. Settings were `RUSTUP_TOOLCHAIN=1.98.1`, `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_BUILD_JOBS=4`.
Inherited profile/OPC overrides and Rust flags were cleared by the runner;
debug assertions and overflow checks retained their normal enabled test
defaults. These are focused core settings with selected packages, not full
SDK CI feature unification or native-profile/full-workspace qualification.

The sibling evidence directory is named
`sdk-epdg-async-owner-retirement-20260920.packet`. It retains
`focused-results.json`, `run-focused.py`, `logs/<run>.log`, `tmp/` and
`target-core/`; these host artifacts are not committed. The commands, counts,
source revisions and hashes here make the result independently reviewable.

```sh
# protected-process
cargo test --locked -p opc-session-testkit --all-features \
  --test qualification_mtls_multiprocess \
  isolated_scale::majority_recovery::protected_ -- --test-threads=1 --nocapture

# provider-journal
cargo test --locked -p opc-session-net --all-features --lib \
  async_provider_authority_tests:: -- --test-threads=1

# protected-coordinator
cargo test --locked -p opc-session-store --all-features --lib \
  consensus::protected_recovery::tests:: -- --test-threads=1

# orderly-process
cargo test --locked -p opc-session-testkit --all-features \
  --test qualification_mtls_multiprocess \
  voters_preserve_public_receipts_and_joined_shutdown -- --test-threads=1
```

| Run | UTC start–end, 2026-09-20 | Exit | Passed / filtered | Log SHA-256 |
| --- | --- | --- | --- | --- |
| protected-process | 13:05:20.064885–13:07:27.274875 | 0 | 5 / 123 | `34bb4df3766faee918096cdbf839fb82c184a03f97d2d7a01c4fd9b6c2134b20` |
| provider-journal | 13:07:27.275256–13:08:30.068915 | 0 | 3 / 603 | `e0f072e95c4a7e44289303434ac562bcfff6aee72391affd90e31d838f1e2759` |
| protected-coordinator | 13:08:30.069278–13:09:38.443890 | 0 | 9 / 1764 | `3a7adbf49515ef7e29e80f8282e27defb6a1010b05a3f7ba296d6c2279fee5f4` |
| orderly-process | 13:09:38.444268–13:09:44.838565 | 0 | 2 / 126 | `b5134b7279ddc1e4bb56ad178e50628b67ffd359c977c77a4e55ea5259a1d579` |

The five [protected process controls](../crates/opc-session-testkit/tests/qualification_mtls_multiprocess/isolated_scale/majority_recovery.rs#L358)
are `protected_async_majority_return_recovers_successor_authority`,
`protected_async_all_cold_return_recovers_successor_authority`,
`protected_async_all_cold_loses_acknowledged_q1_but_retires_durable_effects`,
`protected_durable_majority_return_recovers_successor_authority` and
`protected_durable_all_cold_return_recovers_successor_authority`.
They use real original voter processes/native roots and production mTLS;
the majority case retains the survivor PID, and neither abrupt case supplies
a clean shutdown proof. They check successor authority/readback and stale
calls. The Durable controls explicitly release the old lease before loss and
require that acknowledged release and record to survive; they do not claim
that Durable recovery retires all old authority as Async does. The lost-Q1
case faults native generation publication after a completed
generation, executes an admitted effect, proves Q1 lies beyond every completed
frontier and then returns original roots. It does not delete state to simulate
loss. The [external-owner fixture](../crates/opc-session-testkit/src/qualification/protected_recovery.rs#L114)
is a synthetic SQLite resource/floor transaction using FULL sync, not ePDG
kernel or remote-protocol evidence.

The [provider controls](../crates/opc-session-net/src/fenced_mutation_roster/runtime/production_runtime_cut_matrix_tests/async_provider_authority_tests.rs#L203)
prove exact-binding reconciliation rejects delayed execute, a higher fence
on a different binding alone does not retire old provider authority, and
lease expiry does not reconstruct lost admission or undo a completed effect.
The latter two use synthetic missing-admission `CutBackend` fixtures. Their
passing results demonstrate why shortcuts are insufficient, not a newly
executed recovery failure or safe product activation.

The coordinator controls cover complete exact proofs, missing/duplicate/
foreign/oversized carriers, owner relabelling even with shared keys, signature
cache cold-decode boundaries, maximum inventory, expired deadlines, pending
retry, cancellation/replacement joins and an owner panic. The two orderly
controls preserve public receipts and joined shutdown in Durable and Async.
They do not exercise abrupt process loss.

Bounds were unchanged: the process fixture uses its existing
[CLUSTER_TRANSITION_TIMEOUT](../crates/opc-session-testkit/tests/qualification_mtls_multiprocess.rs#L171)
(`2 ×` the Durable profile's maximum election timeout plus operation timeout),
and its existing
[qualification operation/child limits](../crates/opc-session-testkit/src/qualification.rs#L1101)
(10,000 ms operation and 45,000 ms child reply). The source fixture's current
profile, not a historical prose timeout, is authoritative. No ignored-test
override, weakened assertion or extended deadline was used.

Packet checks also verify the frozen trees/ancestry, all 29 local SDK links
and 73 ePDG source anchors, byte equality of the 21 cited ePDG files against
the frozen revision, and the four retained log hashes/counts. The review
record is `packet-verification.json` in the sibling evidence directory.
Documentation whitespace checks pass. Full SDK CI, ePDG gates and live tests
were not run for this documentation change.

## Deterministic downstream regression matrix — proposed, not run

All T-cases below are **not-run ePDG proposals**. Existing SDK evidence is
identified separately; it does not satisfy the product assertion. Use
synthetic protocol/subscriber values and exact owned resource readback.
Inject at explicit dispatch/persistence barriers, not arbitrary sleeps.
Keep original roots, immutable inventory, membership and process identities
where the case requires them. A bounded safe refusal is an expected negative
result, not a positive recovery success.

For each `Txx/` artifact retain source/tree/pin, toolchain/profile, exact
command, unchanged deadlines, native mount type, UTC interval, exit code and
log hash in `result.json`. Retain sanitized event order, fixed typed statuses,
exact synthetic ownership assertions and successor result in `assertions.json`.
Identify RED/GREEN source separately. Never store private keys, raw subscriber
identifiers or production packet material in these artifacts.

| Case and setup | Actual boundary and required assertion | Expected frozen-baseline behavior / evidence to retain |
| --- | --- | --- |
| **T01 majority loss.** Three original protected Async voters plus retained worker; accepted/prepared old work; abruptly stop two voters, retain survivor and worker, return same roots/addresses/membership. | Real initialization through owner completion, committed/persisted boundary, all voters active; fresh traffic authority; strictly higher-fence successor and readback on every voter. Old still-unexpired authority must fail at the effect boundary. Preserve survivor/worker identity, not just voter count. | Product lacks configured retirement; positive recovery is not established and protected unconfigured refusal is expected, not an observed RED. SDK `protected-process` majority passes with synthetic owner. `T01/` records original identities, exact cut/state sequence, all-voter readback and old/successor effect assertions. |
| **T02 separate all-cold.** Stop all three voters abruptly without SDK shutdown; return original roots/inventory with retained effect owners. | Same proof/persistence/traffic/successor assertions as T01, with absence of orderly-close proof and continuity of original roots. Do not replace with fresh install or rollup of sequential orderly restarts. | Same missing product authority. SDK separate all-cold controls pass. `T02/` records original retained-root evidence, owner-floor continuity and exact recovery completion. |
| **T03 effect survives lost Q1.** Before loss, durably accept/execute an external effect while its acknowledged admission is newer than every selected completed Async generation. Include old known and previously unknown bindings. | Inject native generation-publication failure, establish completed frontiers versus Q1, then abrupt recovery. Before any stale write, reject both old bindings. Discover exact retained debt independently of sessions; settle or permanently fence it. Missing Q1 remains missing; no invented terminal/admission. Higher-fence successor succeeds without corruption. | No whole-range product proof; loss path not run here. SDK lost-Q1 process test passes; provider controls show the insufficiency of per-binding advancement/expiry. `T03/` retains frontier proof, durable dispatch/debt identity, zero stale effect assertions and successor readback. |
| **T04 delayed handles and independent pools.** Retain prepared handles from two separately opened clients/pools; pause execute/adopt/reconcile/compensate/publication after acceptance. Include response bytes and replay prepared before voter loss. | Resume each operation at its real kernel/remote/wire dispatch boundary after retirement. Every old operation is rejected before a new stale effect; already dispatched operations are joined/settled and cannot mutate successor resources. Check first send and subsequent replay, not just provider receipt rejection. | Existing per-binding/current-Recovery gates are partial controls; no product floor proof. `T04/<operation>/` retains controlled dispatch order, pool identities, immutable old outcomes and successor/exact resource assertions. |
| **T05a floor/settlement crash.** Persist floor while a real accepted effect is unresolved; cancel caller and separately kill/reopen owner. | Same root resumes retained responsibility and keeps every pool fenced. No receipt until settlement or permanent isolation; stale unknown binding cannot enter during reopen. | Product state machine absent. `T05a/` retains floor durability barrier, reopened accepted obligation and pending-to-complete order. |
| **T05b settlement/signature crash.** Stop owner after durable exact settlement before signing. | Reopen signs only the same completed challenge; immutable evidence remains; no repeated external dispatch. | Not implemented. `T05b/` retains settlement record, dispatch count plus exact outcome, and challenge-specific verification. |
| **T05c signature/commit crash.** Owner completes/signs; interrupt before durable quorum boundary. | Floor/evidence remain after restart; same challenge may reuse exact completion, new challenge receives a newly bound receipt; no premature traffic readiness. | SDK proof binding is tested; real product bridge not present. `T05c/` retains signature verification results and absence of boundary/serving authority before completion. |
| **T05d possible commit/lost reply.** Interrupt after accepted real proposal may commit but before response; retry within existing protocol deadlines. | SDK authenticated progress resumes exact selected cut; all original voters persist before activation. No replacement cut, forged vote, quarantine clear or timeout extension. Owner settlement remains idempotent. | SDK has the progress mechanism; downstream fault case not run. `T05d/` retains accepted/committed selection identity, voter application evidence and final current traffic proof. |
| **T06 duplicates and equal-floor new challenge.** Concurrent duplicate callers, one cancelled; then a different round/history with equal scalar floor while earlier work is accepted. | One exact completion is joined; new challenge waits for accepted work and cannot reuse the old receipt. Repeat across process restart and shared signing keys with different owner IDs. | SDK coordinator controls pass; product durable/remote join remains unproved. `T06/` retains accepted/completed sequence and typed verification failures for swapped receipts. |
| **T07 rejected authority.** Omit an owner; return partial/duplicate/malformed/mismatched receipts; use wrong root/configuration/epoch/voters/inventory, stale leader/boot or conflicting committed history. Also omit/corrupt original owner root. | Reject or remain pending with the precise fixed reason within existing caller bounds; never commit/activate from partial proof. Missing state never auto-provisions. Pending work survives caller expiry; no repair is inferred. Test each input independently. | SDK inventory/coordinator/cold-proof checks supply controls; product wiring/errors still need tests. `T07/<fault>/` retains expected versus observed enum, unchanged scope/floor and no-effect assertion. |
| **T08 exact ownership and reuse.** Two independently owned synthetic subscribers with A stale/B successor, then swap roles; same-subscriber replacement; shared NAT; forced address, selector, TEID and other identifier reuse. Include parent/default classifier and child cleanup. | Release delayed old publication/compensation/cleanup across recovery. Compare exact XFRM, routes/rules, PDP/group/classifier and remote owner state before/after, then perform a successor operation. Old cleanup never changes new or unrelated ownership. Counts alone cannot pass. | Product has exact ownership primitives but no integrated retirement qualification. `T08/<direction>/<reuse>/` retains exact synthetic ownership/generation comparisons and successor result; test actual backends in the later approved lane where offline doubles cannot prove exclusion. |
| **T09 persistence controls.** Durable majority and distinct all-cold; orderly Async shutdown/reopen; ordinary Async acknowledgements with generation writer blocked. | Durable preserves its promised acknowledged state; orderly Async joins/preserves receipts; normal Async ack can precede disk completion and retain documented loss semantics. Recovery synchronization must not become normal-ack synchronization. Keep Ephemeral behavior unchanged. | SDK Durable/process and orderly controls pass; this task did not separately run a new normal-ack timing/product control. `T09/<mode>/` records exact retained results and writer/ack ordering, not elapsed-time guesswork. |
| **T10 readiness/evidence.** Observe startup unconfigured, owner pending, rejected inventory, election/persistence in progress and active consensus while traffic/placement/Recovery proof is absent or expired. | Distinguish fixed states `ProtectedAuthorityRequired`, `AwaitingProtectedRetirement`, `ProtectedAuthorityRejected`, `ReformingQuorum`, `Active`; traffic readiness remains independently false until freshly proved. No subscriber data in diagnostics. | SDK passive states exist and E07 projects current readiness; complete product exposure/composition is unproved. `T10/` retains sanitized typed transitions and independently tested serving rejection/acceptance. |

Use the SDK native-disk/mTLS fixture when testing a reusable consensus
regression. Use ePDG's actual journal/effect adapters and separate processes
for product floor/bridge tests. A synthetic resource transaction cannot prove
XFRM/eBPF/route exclusion, remote PGW cleanup or wire replay safety. If an
owner cannot settle or permanently fence accepted work, a correct pending
result leaves positive recovery unqualified.

## Later CRC qualification — separate authorization required, not executed

Entry criteria: reviewed complete ePDG integration and immutable inventory,
all required offline RED/GREEN and full Linux `make ci` results, verified
retained owner custody, and a bounded fault/recovery procedure for the exact
landed SDK/product revisions. Issue #273's grouped startup behavior must have
its own disposition before claiming combined product recovery; this packet
does not repair it. The previous unrerun traffic suite is still a blocker to
a new traffic claim.

With explicit authorization for that later lane:

1. Preserve the CRC VM, existing application ConfigMap and original voter and
   worker roots. Never stop/delete/recreate/restart the VM. No reinstall,
   storage clearing, voter replacement or new inventory is a recovery test.
   Only the explicitly authorized `epdg-system` application lane is in scope;
   even there, these retained recovery roots and owners must survive.
2. Establish Durable and explicit Async startup/readiness controls and record
   fresh serving/placement authority. Use local/internal images at the
   reviewed revisions. No registry publication or configuration services.
3. Run T01 against two original voters while the original survivor and worker
   remain. Separately run T02 without a clean close. Exercise retained old
   handles/debt and exact higher-fence successors, current traffic authority
   and all-voter readback under unchanged deadlines.
4. Exercise T03/T04/T08 at the actual product effect boundaries with the
   approved synthetic workload, preserving exact resource ownership. Run the
   common traffic suite after its prerequisite gates. Report traffic/packet/
   audio results separately from consensus readiness and orderly recovery.
5. Use the existing operator `epdg-capture --mode restricted-full-fidelity`
   mechanism if capture is needed; no new capture plumbing. Keep sensitive
   captures out of ordinary reports. On a missing owner/root or conflicting
   history, preserve evidence and request separate repair authority.

No cluster/container commands, restarts, injection, traffic, captures or
handset operations were performed for this packet.

## Finding disposition and remaining blockers

| Finding | Disposition / evidence needed |
| --- | --- |
| Complete signed inventory, exact challenge/receipt verification, supervised joins, real committed proof and retained-voter activation | **Supplied by SDK #929**, unchanged in inspected paths at the SDK base; focused controls pass. |
| Orderly production transport/store shutdown and protected reopen composition | **Already present in ePDG #272**; E02/E04. Do not reopen the historical defect. |
| Complete physical-owner inventory and root-signing scope | **Missing in ePDG**. Need the coverage/process/fence-domain manifest and proof for every candidate family. |
| Durable global inclusive floor, all-pool effect exclusion and restart-owned accepted work | **Missing integration in ePDG**. Existing per-binding journals/local locks are foundations, not this proof. Need T03–T08 with actual adapters. |
| Authenticated exact voter-to-owner challenge bridge before readiness | **Missing in ePDG; design details unresolved**. Need durable duplicate/crash semantics and recovery-only debt authority without opening traffic ingress. |
| Reusable SDK defect | **None newly demonstrated**. No SDK patch or new bug RED is proposed. Reduce a concrete contract failure before changing SDK. |
| Bounded product majority/all-cold recovery with current traffic authority | **Unresolved/not run**. Need integrated T01/T02 and complete owner proofs; unconfigured refusal is not a successful recovery result. |
| Actual kernel/remote effects, exact resource reuse and common traffic qualification | **Unresolved/not run**. Need approved later product lane, full gates and independent #273 disposition. |

The smallest next implementation is the non-activating durable floor and
owned-dispatch slice at E09–E16, preceded by an explicit scope/owner mapping.
Its acceptance test is old known/unknown-binding refusal across independent
pools and owner restart, while accepted work is settled and immutable evidence
survives. Only complete coverage of the remaining families can authorize
inventory signing and protected Async activation.
