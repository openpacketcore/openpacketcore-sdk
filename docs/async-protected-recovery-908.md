# Protected-roster Async recovery: SDK #908 follow-up

This follow-up implements protected Async majority/all-cold recovery through
explicit external-owner retirement. PR #910 supplied the retained-owner
consensus recovery mechanism but could not retire protected provider effects.
The missing capability affected fresh roots too; deployment migration is
outside this work's scope. Normal Async acknowledgements remain independent
of disk. The new synchronization belongs to recovery.

Sequential cold rejoin must also preserve bounded progress after recovery.
Hosted native-profile validation exposed retries repeatedly obtaining a valid
committed barrier, exhausting their deadline during catch-up, then replacing
the cut with another later barrier. The same maximum-owner case failed on
unchanged source with the local test process limited to two CPUs. A separate
deterministic control blocks actual replication across two original deadlines
and proves that retry must retain its already certified attempt.

Retries now preserve that exact cut and matching-prefix progress. A newer
authenticated committed leader's append or snapshot request remains rejected
and requests fresh certification; it cannot activate the old attempt. A real
leader-change control, delayed lower-vote and uncommitted-vote controls, and
the existing membership/nonce/root validation controls preserve that boundary.
No deadline, voting rule or committed-application requirement changes.
The deterministic RED log SHA-256 is
`9b303149bfea690710a591e0e175c340411800b32ac851fbe9ddc16eace12cd2`.
Six native-profile controls passed with two CPUs and four test threads,
including maximum-owner rejoin and a subsequent operation; log SHA-256
`f0a2b4a3a8501012a71eb6664eb2b25c3e1c57b2f35684b1e1264b1dc8837e3b`.
These focused controls do not replace full integration validation.

## Executed baseline

Baseline source: `4356ef8595f0e010ea49ce01b5c225c4b9f06036`.
The new `ProtectedRecoveryControl` fixture constructs three independent voter
processes with the protected trust root, activates the exact V2 profile, and
uses production mutual-TLS replication and real native disk storage. It issues
a lease and commits a session record before abrupt process loss. The same
configured roots and addresses return; the majority case keeps the original
survivor process. No close proof, replacement roster or storage reset is used.

The positive acceptance assertion requires initialization, current traffic
authority, a higher-fence successor write, stale-lease rejection on the
unchanged survivor, and readback from every voter. Durable controls explicitly
release the old lease before loss because Durable must retain that release and
the acknowledged record. Async must retire its old range during recovery.

```sh
cargo test --locked -p opc-session-testkit --all-features \
  --test qualification_mtls_multiprocess \
  isolated_scale::majority_recovery::protected_ -- --test-threads=1 --nocapture
```

| Mode | Two voters return | All voters return |
| --- | --- | --- |
| Async | Fails to recover within the existing bound | Fails to recover within the existing bound |
| Durable | Passes through successor operation | Passes through successor operation |

The executed four-case baseline exits 101: two passed, two failed, none ignored.
The log SHA-256 is
`483021ee8b29e72fd8e1443d2b87de9d42dc68288eda2e71cb166775fe0a9271`.
It used Rust 1.98.1, the CI core profile and a private XFS `TMPDIR`, verified
with `findmnt` inside the test mount namespace. This is a recovery RED with
unchanged production code, not a successful fencing qualification. It does
not yet exercise a retained protected admission or prepared transition.

## Established authority boundary

The `ProtectedAuthorityRequired` guard remains for unconfigured owners. Removing it
alone would not define how a lost protected admission, its external effects,
or an old provider permit is reconciled with the successor. Ordinary Async
acknowledgements must remain independent of disk; Durable and Ephemeral
semantics are outside this correction.

Protected member calls use startup-owned local authority checks and provider
journals bound to an exact member operation. Publication additionally checks
current consensus authority. Recovery must account for both boundaries and
preserve retained immutable admissions, terminal evidence and reservations.
An external effect's absence from the selected Async generation is not proof
that it never occurred. See the
[protected-roster contract](session-store-protected-atomic-roster.md).

The baseline is historical RED evidence. The existing CRC failure evidence
remains unchanged; SDK recovery tests cannot establish product recovery.

### Independent provider controls

`opc-session-net` now exercises the production roster executor, real signed
provider receipts and a synthetic SQLite provider journal using `FULL` sync.
Each call reopens the same provider database. Fence advancement, immutable
outcome and the synthetic resource write commit atomically. Its fence key is
the SDK-issued `MemberCall::fence_binding_commitment`, exactly as required by
the current public `MemberProvider` contract.

| Control | Executed observation |
| --- | --- |
| Retain the exact admission; reconcile it under a higher fence | The old local permit reaches the provider, which rejects the delayed execute; no resource write occurs. The successor terminalizes Aborted. |
| Give another admission of the same resource a higher fence | The successor effect applies, then the old still-unexpired permit can apply its effect under its separate journal binding. Current backend authority rejects the old terminalization **after** the effect. |
| Expire the old lease after its effect committed; recover without its admission | The old permit is rejected, the provider effect persists, and an unexpired higher-fence lookup cannot recover the missing admitted bytes. |

The second and third controls use separate `CutBackend` fixtures to model the
missing admission; they do not reopen real Async roots or authorize such a
selection. The real quorum guard remains intact. These are independent
counterexamples to proposed shortcuts, not protected recovery GREENs or claims
that a presently permitted production recovery can perform those shortcuts.
All fixtures are synthetic. No product provider behavior is inferred from them.

The focused three controls passed (exit 0, no ignored tests), log SHA-256
`0aebd4da9c929124ae368e141a2000ae50756c389c75c9fbbb804627bc8baf52`.
After strengthening exact typed-error assertions and supplying a current
successor lease in the expiry control, all 104 `fenced_mutation_roster::` unit
tests passed (exit 0, no ignored tests), log SHA-256
`cd5bdaddb8a69c7592904600a74f55b71446d461729b2af63c54570be8fecc53`.
Both used the CI core profile and a private XFS `TMPDIR` verified by `findmnt`.

## Implemented recovery capability and ownership

`consensus::protected_recovery` supplies four composition steps:

1. The protected trust-root authority provisions one complete immutable
   `ProtectedRecoveryInventory` for the exact configuration identity, epoch
   and fixed voter set. It lists 1–32 external owner identities and P-256 keys
   in canonical order. The root signer establishes completeness from actual
   ownership, including every member and publication provider, replica and
   pool. It must never infer completeness from returned session state or sign
   a different inventory for the same configuration as a recovery shortcut.
2. Every voter installs that same inventory and its owner adapters once using
   `ProtectedAsyncRecovery::new` and
   `ConsensusSessionStore::configure_protected_async_recovery`. The store
   checks Async mode, exact configuration/root/membership and any retained
   prior proof. Replacing configured authority in an open store is rejected.
3. The existing unanimous protocol obtains durable promises and a real
   election. Its selected leader issues an SDK-only challenge binding the
   complete inventory, exact round and selected history: all retained
   roots/incarnations, full votes/LogIds, completed generations and application
   digests. Each owner durably retires the entire inclusive old reserved fence
   range, then signs its owner-specific challenge digest. An old reply cannot
   authorize another round or selection, even when the scalar floor matches.
4. The SDK requires every listed owner's verified receipt in its internal
   committed recovery boundary. Native application and cold/snapshot readers
   validate the proof against the actual root/configuration. Every retained
   voter must apply and persist the boundary and check its exact selection
   before activation. Normal current quorum/traffic checks still follow.

### Provider effect boundary

The owner must enforce a crash-durable global floor across **all** bindings in
its configuration. A per-admission fence cannot substitute for this floor.
Every prepare, execute, adopt, reconcile, compensate and publication effect
must respect it, across processes, replicas and independent connection pools.
An unknown binding also rejects an old fence. A delayed retirement request
cannot lower the floor or affect resources owned by a newer range.

Before signing, the owner must join accepted lower-range work, conclusively
reconcile it, or make it permanently unable to affect successor resources.
A dropped request/reply, cancellation or process replacement must not discard
that responsibility. Completed outcomes and their evidence remain immutable.
Completed effects may remain for exact higher-fence adoption; orphan cleanup
must complete or be permanently fenced from successor resources before the
receipt. Neither lost Q1 nor `NotFound` proves `NotApplied`. The root inventory
signer and the provider signing keys are privileged authorities, not arbitrary
consumer opt-ins.

Retained protected admissions, reservations, prepared bodies and terminal
receipts remain intact. A higher-fence successor uses the ordinary protected
API to recover the exact admission and reconcile its providers before Q2.
The boundary does not clear a reservation, invent a terminal or reconstruct a
lost admission from a subscriber key. A provider must return pending if its
physical effects cannot satisfy this contract; a signature without enforcement
is a broken provider implementation, not a valid recovery implementation.

### Deadlines and responsibility

The coordinator retains accepted calls under an owned supervisor. It joins
**all** owners even when one fails or the original caller stops waiting.
Duplicate calls share exact completion; a newer challenge waits for earlier
accepted responsibility. Provider adapters additionally retain responsibility
across provider-process loss. Caller deadlines remain unchanged and consume
lock, election, provider, commit and persistence waits together.

After a deadline or lost commit reply, an authenticated progress query checks
the exact selected leader, current full committed vote, local recovery binding
and accepted proposal status. An intact protected election resumes its owned
work on the next initialization call. This progress reply cannot activate a
voter or replace a commit/application certificate. A failed election/proposal,
replaced incarnation or rejected authority starts a fresh unanimous round.

| Passive typed state | Meaning |
| --- | --- |
| `ProtectedAuthorityRequired` | The protected configuration has no complete recovery capability installed. |
| `AwaitingProtectedRetirement` | A selected round is waiting for durable completion from its external owners. |
| `ProtectedAuthorityRejected` | Inventory, signature or exact authority binding was rejected. |
| `ReformingQuorum` | Real election, catch-up, committed boundary or persisted completion remains in progress. |
| `Active` | Consensus participation is admitted; current traffic authority still requires its own probe. |

Diagnostics expose fixed states only. No subscriber values, addresses,
credentials, arbitrary protocol/debug state or packet payloads are required.

## Validation and remaining integration

The initial implementation passed the four real process recovery cases
(two protected Async and two Durable controls), exit 0, log SHA-256
`cc1bc06c178ff157dc967251e52d9f21789e5ce5ce99ddbc68a1b1a6865c70fa`.
The external FULL-sync journal retained a prepared effect, a completed effect,
and the global floor; old known and unknown bindings could not mutate the
successor. This first GREEN preceded the stronger composed Q1 tests and is
not a full-gate qualification.

Further focused coverage includes retained protected Q1 and prepared member
work, differing generations and acknowledged volatile lease tails, all-cold
recovery, delayed/duplicate proofs, missing owners, sequential catch-up,
cancellation and replacement. Exact commands, source hashes, exit codes and
full-gate results belong in the PR's validation evidence; unfinished checks
must not be reported as passes.

The strengthened process suite passed five cases (exit 0), log SHA-256
`ee1f233867456be9427ae1fbbdcfb4ce662f0443ce6e11811faa3d59f8b19e01`:
the same two Durable controls, protected Async majority/all-cold return with
retained Q1 and successful reconciled Q2, and a separate all-cold case with an
acknowledged Q1 missing from every returned generation. The last case injects
ENOSPC only before real native generation publication; it verifies completed
frontiers stayed before Q1, kills all voter processes, removes only the I/O
fault and reopens unchanged roots. The durable provider effect survives;
missing Q1 returns exactly `RecoveryRequired`, old prepared handles cannot
write, and successor lease/CAS/provider operations succeed. `RecoveryRequired`
preserves the ambiguity of the missing admission; it cannot manufacture a
negative outcome for the provider's completed effect.

A slow-owner regression separately failed before progress resumption (exit
101, SHA-256 `bb8d127638926e8ebbf0254a956c710ee8859f60027cae5a5c9b0f0cbeda074c`)
and passed afterward (exit 0, SHA-256
`0e392f1c2e9c2258f8830d03b8326135bbca44c847279c96e31d65103b39be61`).
Its retirement takes 1,600 ms against unchanged 800 ms RPC deadlines; repeated
ordinary initialization joins exactly one owner call, then performs a valid
successor operation. Full repository qualification is reported separately in
[PR #929](https://github.com/openpacketcore/openpacketcore-sdk/pull/929);
focused tests alone do not qualify the full gates or separate CI profiles.

The separate egress CI profile exposed another admission race: an ordinary
cold initialization could await peer progress while an independently owned
recovery RPC activated the same incarnation, then overwrite that admission
with quarantine. The cold transition now checks its admissible source states
under the exclusive admission lock; it cannot replace Preparing, Reforming or
Active state. Two deterministic controls use real committed recovery and fail
before this check (exit 101, SHA-256
`c71acde1cac5b5d50cdb3ebea7c74b30ff8ae21fb60de6e0963c4e4b87974efd`).
They pass with the check, together with the maximum-owner recovery/reopen and
six authority-reservation controls (nine passed, exit 0, SHA-256
`4326dd2d9addd88fa2e958dd820b711010f70be7ab9acff7dfae9c7b33f879a2`).
The reservation fixtures now reopen their retained roots to obtain cold
admission rather than forcibly replacing an Active admission. No deadline,
cryptographic check or completed-application requirement changes.

A later two-CPU native replay failed the maximum-owner fixture after recovery
and lease acquisition: `delete_fenced` returned an unknown outcome within the
unchanged 800 ms bound (exit 101, SHA-256
`d28890591c6d5914084d2e5dffed7cb3b7d2f8ff5c2f6cb5c0248f0a174831e8`).
This is distinct from the cold-rejoin progress defect. Diagnostic counters and
stack samples identified repeated verification of the same 32-owner signatures
during ordinary frontier validation. A traced control run passed but spent
718 ms acquiring the lease and 742 ms deleting it. The fixture first observes
a fence and constructs a request; it does not create a session record there.

An in-memory signature now retains one positive result bound to its exact
public key, digest and both scalar byte arrays. All surrounding validation
still runs. The result cannot be supplied on the wire or recovered from disk;
deserialization starts empty. Changed keys, digests, signatures and authority
remain rejected. With this correction the same traced operations took 45 ms
and 34 ms; all fifteen selected recovery/crypto controls passed (exit 0,
SHA-256 `7c96f0c833c87f78cc1cb849cbb874f6de07c82f49b050f763142e04a8aa5617`).
These are diagnostic observations, not a latency qualification. Temporary
counters were removed; exact-revision native and full gates remain separately
reported in the PR. No production deadline or verification predicate changed.

This is a new explicit SDK capability, not an automatic claim about an
existing product provider. ePDG must provision the complete inventory, wire
actual member/publication owners to enforce retirement at their effect
boundaries, repin the reviewed SDK and qualify that composition. The separate
CRC exercise must retain the original worker, membership, roots and Recovery
authority, test Durable/Async majority recovery and a separate all-cold case,
then run the common service suite. No live CRC, storage reset, call continuity,
audio or production-HA result is claimed here.

Async can still lose acknowledged records, admissions and results absent from
all selected generations. Recovery requires all original retained owners on
this unanimous path; permanently missing/corrupt roots, missing persisted
membership and conflicting committed histories require separate repair
authority. These availability limits must remain explicit.
