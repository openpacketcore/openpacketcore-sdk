# Async majority-restart recovery: SDK #908

The [protected-roster follow-up](async-protected-recovery-908.md) reproduces the
remaining current-configuration failure after PR #910. It affects newly
created protected roots; deployment migration is outside that follow-up.

The implementation adds automatic majority/all-cold recovery for new-format
Async roots once every configured retained owner returns. Normal session
acknowledgements still do not wait for disk. Recovery durably prepares a new
reserved authority range, performs real Raft election/replication, and requires
every member's committed boundary to persist before activation. Lost volatile
lease authority is retired rather than reconstructed from an old snapshot.

Focused lost-tail, adversarial and abrupt mTLS process-loss tests pass. These
results are distinct from full SDK/platform qualification; the current gate
status is recorded in [draft PR #910](https://github.com/openpacketcore/openpacketcore-sdk/pull/910).
Legacy roots and
protected-roster retirement require authority absent from this protocol;
repinning the already-fenced legacy CRC installation is not a supported repair.
No live cluster action has been performed and no product recovery is claimed.

## Executed baseline

The baseline is `76597d3ccd9438d956cb6257733cc7a256c5cc4c`. Before production
changes, `opc-session-net`'s `consensus_transport/majority_recovery.rs` forms
three fixed voters using real native storage and the production mutual-TLS
peer/server adapters. It commits a sealed record under a lease, drains local
Async persistence, closes two voters, preserves the original leader, and
reopens the same databases and snapshot directories under unchanged membership.
The stopped owners and listeners are joined; no root or authority is replaced.

The test requires normal initialization, fresh mode-aware traffic authority,
then a higher-fence acquisition, a successful successor CAS, rejection of a
delayed mutation carrying the previous lease, and readback of the successor.
Each call retains the SDK's ten-second default. The outer recovery observation
uses the existing transport suite's cluster-transition bound. A one-second
synthetic lease expires during the absence; this is not the product's
65-second CRC experiment.

```sh
cargo test --locked -p opc-session-net --all-features \
  --test consensus_transport majority_recovery:: -- --test-threads=1
```

The first focused run executed two tests: Async failed at usable-authority
recovery, and Durable passed through the successor operation and old-lease
rejection. Exit status was 101. The raw log SHA-256 is
`cdcfcc1d0a031997386f07d960154ee8e6ea2bfe2c5c6d0d3d305bab90f9752c`.
Rust was 1.98.0, with CI core debug/incremental settings disabled and a private
XFS `TMPDIR`. Earlier fixture compilation/sealing mistakes are retained
separately and are not counted as recovery REDs.

The expanded fixture separately exercises sequential returns and all-cold
returns. Its Async majority/all-cold assertions remain positive availability
requirements; they are neither ignored nor inverted into quarantine passes.

| Policy and restart | Executed result |
| --- | --- |
| Async, sequential retained-root return | Pass, including successor operation |
| Async, two of three retained roots return | Fail at usable-authority recovery |
| Async, all three retained roots return | Fail at usable-authority recovery |
| Durable, two of three retained roots return | Pass, including successor operation |
| Durable, all three retained roots return | Pass, including successor operation |

That baseline five-test run exits 101; log SHA-256:
`9b0a54f69126d7c993a35f1d85abee638fd09fa98321bd9e3c6bce57e2973e97`.

## Completed-shutdown recovery

New-format Async roots can publish a one-use proof after the active consensus
engine, storage owners and final disk generation have all completed shutdown.
Reopen validates its exact authority and durably consumes it before starting
consensus. It grants no traffic authority; the ordinary fresh quorum and
application checks remain required. The format rejects older SDK readers that
cannot consume the proof. Legacy roots keep their existing quarantine contract.

With this implementation, the same five-case mTLS matrix passes, including
the successor operation and stale-lease rejection. The focused command above
exited 0; log SHA-256:
`cdc6192d125a87d8ccdebad9fb4e08e5e52df7073a175cb265f367ed710b5170`.
This test drains and joins real owners. It proves orderly restart, not power
loss, lost-tail recovery or migration of an already-fenced installation.

The subsequent transport fixture also checks majority and all-cold recovery
after explicitly revoking a still-unexpired credential. Its lease clock is a
scenario input: it advances only for the expiry cases. Raft, TLS, operation
deadlines and the real absence interval retain their original clocks and
bounds. This avoids making initial disk setup an accidental one-second lease
performance test, as exposed by the i686 CI run. Stale writes must return
exactly `LeaseExpired` or `StaleFence`, followed by unchanged successor readback.

The separate-process `isolated_scale` boundary controls use three actual voter
processes for each mode, join successful shutdown, and reopen the same storage
in three new processes. Both Async and Durable recover the exact prior receipt
and replay, then commit a new request and read its receipt within the original
800 ms client deadline. The focused two-test run passed; log SHA-256:
`ce7dbae64c6db67e93f41076d2e46dc20924b3e7094a77cd3520f8bcf241c3db`.
This is SDK process-boundary evidence, not product or unclean-loss qualification.

Disabling only the closed-proof admission path makes the same majority and
all-cold cases fail again, while sequential Async and both Durable controls
still pass. This fix-removal run exited 101; log SHA-256:
`ec29cd4388b646bfcb7fd99ee8236229aec5b34d085a3b3b09f218d1d9d0c8dd`.
The production source was restored byte-for-byte after this control.

Adversarial controls exercise proof publication and consumption failures,
one-use consumption, corrupt/foreign/stale proof rejection, file replacement,
shutdown cancellation and the retired writer's inability to mutate its
successor. Quarantined shutdown cannot manufacture a proof. The original cold
repair tests deliberately omit close certification while still joining their
actual owners, preserving their uncertified-incarnation scenarios.

Two additional positive tests require recovery after the acknowledged volatile
tail described below. Both were executed before production edits and failed at
usable-authority recovery; log SHA-256:
`3ba242d01464c56efb7562f53500d907605b735a7d7b26c32d5238a6fb25a0c4`.
The same two tests now pass through usable authority, rejection of both retained
and lost old credentials, and a valid successor operation. Command:

```sh
cargo test --locked -p opc-session-store --all-features --lib \
  volatile_tail_recovers_successor_authority -- --test-threads=1
```

GREEN log SHA-256:
`72402bb75b98d356da995ba5e354f0aac637582e98f8746b7552c52db428fc10`.
These use the real storage/engine and authenticated fixture boundary, not the
production mTLS adapter. The retained roots differ and the live survivor lacks
the later majority prefix. The tests keep the lost credentials unexpired;
local expiry is not the recovery authority.

## Missing authority, beyond the cold-barrier dependency

The store's `async_persistence/tests/majority_authority.rs` controls use real
three-voter Openraft operations and retained native roots. Their controllable
in-process authenticated-peer boundary is distinct from the mTLS reproduction.
Only generation I/O and network reachability are faulted; no admission gate,
vote, acknowledgement, selected generation, or membership is fabricated.

1. Commit a record and its lease and persist the initial generations.
2. Partition a follower, retaining its live process. Commit and persist a
   newer prefix on the other two voters so their retained state differs.
3. Fail the majority's subsequent generation writes with ENOSPC. The actual
   resident quorum still acknowledges a series of higher-fence leases. It
   rejects the initial credential, proving revocation before the restart.
4. Join those failed writers and reopen their original selected roots. A
   separate case closes and reopens the survivor as well.
5. Read the actual recovered native rows and allocator frontiers without
   invoking traffic admission. Every copy is below the issued fence and
   credential; the exact predecessor credential is present again. The newer
   external credential remains unexpired.

The checks of raw native fields are test-only observations. They do not apply
a mutation or relax quarantine. Passing these controls means missing evidence
was demonstrated; it never means service recovered. ENOSPC provides a
deterministic acknowledged volatile tail, not a power-loss simulation.
Both controls pass; log SHA-256:
`35c14c09df9c5834e73d81dc087385cab72e6f100574eec1650cdf4b4643045e`.

## Why local selection cannot safely fix it

`sqlite/consensus/wal/async_persistence.rs::admit` completes the storage
acknowledgement after resident projection. That includes the log adapter's
vote, append and commit operations. Generation selection happens later.
`consensus/native/ordinary.rs` advances `next_fence` and `next_credential` in
that same resident state when issuing leases. A legacy retained root identifies storage lineage and mode; it does not
reserve an upper bound for future volatile allocations. Legacy roots do not identify a durably closed consensus
incarnation either.

Without completed-shutdown evidence, the cold protocol cannot distinguish a fully persisted safe cut from
an otherwise identical retained cut followed by lost acknowledged effects.
Increasing a retained scalar once does not solve this: arbitrarily many
allocations may have occurred before the loss, up to the existing counter
limit. Choosing that limit leaves no usable successor allocation. A surviving
process can also be the lagging voter excluded from all of those commits.

This leaves two obligations, neither supplied by a newer local snapshot:

- Recover or supersede vote/log authority without violating previous quorum
  decisions, with full vote/LogId, membership, root, mode and attempt binding.
- Preserve monotonic externally issued fences, or revoke the old incarnation
at every effect boundary before issuing successor authority. Local lease
expiry and accepted data loss are insufficient revocation evidence.

The existing operator-recovery API does not supply this missing authority.
`ConsensusSessionStore::commit_operator_recovery` first requires fixed-quorum
admission, then submits `FinalizeOperatorRecoveryV2` through the ordinary
leader proposal path. It cannot finalize a new epoch without the quorum whose
recovery is in question. Neither a larger local epoch number nor possession of
the product's existing Recovery object changes that requirement.

Lease expiry rejects the expired credential at the store. It does not recover
the lost scalar high-water mark: external fencing consumers may retain a
higher issued fence after expiry. For example, the XDP owner-install path
adopts persisted fencing evidence and rejects an older generation. Waiting
longer therefore cannot establish the required successor ordering.

## Implemented contract and limits

[ADR 0022](adr/0022-native-session-persistence-modes.md#unanimous-retained-owner-recovery-sdk-908)
and the [public README](../crates/opc-session-store/README.md#fixed-quorum-asynchronous-persistence)
specify the protocol and data-loss boundary. New `OPCNA003` roots reserve a
finite ceiling before volatile issuance; recovery alone synchronizes successor
promises and complete generations. No per-operation durable journal is added.
Every retained participant must bind the same exact membership/root/boot/round,
finish its accepted effects, and prepare above all old ranges. The selected
candidate covers retained committed cuts; real election and committed
application install the retirement boundary. All members persist that boundary
before admission. Current application Recovery authority remains an independent
gate; the protocol never clears it or changes configuration epochs.

Old receipts cannot supply new lease authority, and old leases cannot mutate a
successor. V1/V2 history and watch retirement retain independently validated
accounting and immutable request bindings. Incoming/outgoing engine operations
and disk promises retain accepted responsibility after timeout/cancellation.
Replacement rejects stale completion sets. Retrying an interrupted election
prepares a newer durable range rather than forging or replaying a vote.

Executed adversarial REDs found and corrected a missing owner fence after
promise I/O failure, retired lease visibility in cached receipts, activation
retry after a real leader change, and an interrupted election with no retry
transition. Twelve reservation/protocol tests passed, log SHA-256:
`e51f98d39679503619862f39ecd917271d8601647c7ee8bc97080ad4d366e4fc`.
The expanded Async module suite passed 46 tests, including cancellation during
an accepted disk promise, repeated five-voter recovery and sequential rejoin
with another voter unavailable. Log SHA-256:
`2050bbcc5ebc5261ec3842444c14b854ef7e65aa6aced2f98fee8f7f7fa8dcee`.
Two additional tests passed for partial/complete snapshot installation followed
by actual matching append, and a protected trust root whose activation was not
retained. Log SHA-256:
`a29825724fbd192a8b7b772676784f78c93cabcf754abd824a92f9ce530872e5`.

The production-mTLS process fixture separately kills two of three actual
voters, retaining the original survivor, and kills all three. It reopens the
same roots and addresses without completed-shutdown evidence. Both cases
recovered traffic authority, acquired a higher fence, committed a successor
mutation and read it from every voter; the survivor's old lease was rejected.
The fixture selects ordinary fixed authority at initial creation; it does not
remove a protected trust root from existing storage. Command:

```sh
cargo test --locked -p opc-session-testkit --all-features \
  --test qualification_mtls_multiprocess isolated_scale::majority_recovery \
  -- --test-threads=1 --nocapture
```

Both tests passed; log SHA-256:
`920ea367e9b4bd47edc4d646101990372c7efc3aa55f4fc2e57bce0e8f940ff6`.
Disabling only the call to the unanimous recovery path caused the unchanged
two tests to fail at their original recovery deadline (exit 101), log SHA-256:
`83ce5fe33e2f56054e944d86b1997e2cb6a621817c28eafc632006c3e37d2686`.
The implementation was restored byte-for-byte afterward. These focused results
are not a final full-gate pass, disk hardware failure qualification or CRC proof.

The restored implementation also passed both process tests after adding an
explicit assertion that stale-lease rejection precedes expiry; log SHA-256:
`c52deb58fc834d5ad64a39f672ba3991564e6636b7cdcad0d8faf36c42bd250f`.
An additional diagnostic RED exposed an unsupported protected authority reason
being hidden by an unavailable peer. Its corrected test and 16 native log
admission controls passed; log SHA-256:
`0b716232aea6fb68503cec38cba7961ba82c91a2dfb3dbb189b04305d30e8a54`.
Package all-target/all-feature Clippy passed; log SHA-256:
`73c5f09b556223a452ee6181be6687423a35cbd675490e41b5327935801f75c8`.

Automatic recovery still requires every exact retained configured owner and
an applied fixed membership. Missing/corrupt roots, formation lost before the
first persisted membership, conflicting committed histories and exhausted
ranges are explicit repair boundaries. A protected-roster trust root disables
this retirement path, including when its activation was volatile and lost.
Async peers/consumers must understand `OPC-ASYNC-2`; mixed old/new Async peers
are rejected. Durable encoding and semantics are unchanged.

Already-fenced `OPCNA001`/`OPCNA002` roots cannot gain the missing ceiling
retroactively. Their existing live-quorum/closed-proof paths remain applicable,
but an unclean lost majority needs independent authority that can durably retire
the lost scope, finish or revoke accepted external effects, select an exact
successor and establish authority all affected consumers enforce. Neither a
local snapshot, data-loss acceptance, the existing product Recovery object,
nor an unchecked flag proves those obligations. This change does not provide
that separate migration/repair capability, and a permanent fence is not a fix
for those installations.

The downstream product must qualify its consumer retry/history behavior and
fence enforcement, then repin a reviewed SDK and repeat Durable/Async majority
return with the original worker, retained exact storage and Recovery authority.
The legacy CRC installation first needs a separately reviewed supported
migration/repair contract; it must not be reset to manufacture a recovery pass.
After an applicable integration, run the common service suite. SDK tests make
no CRC, call-continuity, audio or production-HA claim.
