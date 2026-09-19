# Protected-roster Async recovery: SDK #908 follow-up

PR #910 does not cover the protected-roster configuration used by ePDG. This
gap also affects roots created by the current SDK. It is independent of older
storage formats or deployment migration; adding a legacy upgrade workflow is
outside this follow-up's scope.

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

The current `ProtectedAuthorityRequired` guard remains in place. Removing it
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

No production correction, full-gate pass or new CRC result is claimed by this
baseline. The existing CRC failure evidence remains unchanged. Further SDK
work and downstream product qualification are required before #908 is closed.

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

## Required contract extension and ownership

The missing authority is permission to retire **every** old protected effect
in the exact configuration, including bindings absent from all returned
generations. The current provider API only prepares, executes, statuses,
adopts and reconciles an already known exact member. It has no complete
provider inventory, scope-retirement operation, or proof that unknown old
work is fenced. A trust root authenticates signatures; by itself it proves
none of those facts.

A safe recovery capability must provide all of the following:

1. Bind the configuration epoch, retained roots, fixed membership, persistence
   mode, old reserved range, proposed successor range and exact recovery round.
   Bind any authorization to the selected state/generation as well; a stale
   receipt cannot authorize another candidate, replacement owner or round.
2. Durably retire the old range at every affected member and publication
   provider, including absent journal bindings. Checks at effect boundaries
   must enforce that retirement across processes and different admissions.
   Already accepted work must finish under retained ownership, be conclusively
   reconciled, or be irrevocably fenced before successor effects are enabled.
   Caller cancellation or a dropped reply must not drop that responsibility.
3. Preserve exact retained admissions, reservations, prepared bodies and
   terminal evidence. Reconcile effects missing from the selected Async
   generation under explicit retirement authority; neither `NotFound` nor an
   expired timer permits inventing a replacement admission or claiming
   `NotApplied`.
4. Carry verified completion into the existing real election, committed
   application, complete persisted-generation and readiness checks. Missing
   participants or provider authority remain fixed typed pending/repair states
   within the original deadlines; partial or interrupted retirement must be
   resumable under the same exact binding.

This extends the SDK recovery/provider boundary and requires composition by
the actual provider owners. It does not require ordinary Async session
acknowledgements to wait for disk, or a redesign of Durable or Ephemeral.
Disk synchronization for the new retirement authority belongs in recovery.
The generic SDK cannot assert that arbitrary external effects have been
retired using the current opaque provider methods. A boolean opt-in, a signed
assertion without that provider contract, or removing the trust root would
only conceal the missing authority.

This follow-up establishes that technical blocker; it does not implement the
new capability. The required positive tests remain RED, and draft PR #929 must
not be presented or merged as a recovery fix. Retained prepared transitions,
lost volatile protected admissions, unavailable providers, interrupted
retirement, partial catch-up, cancellation and owner replacement still need
positive/negative composed coverage once the capability exists. Full SDK
gates and the separate CI profiles remain required for that implementation.

Downstream ePDG must then wire the provider retirement authority, repin the
validated SDK and repeat retained-root Durable/Async majority and all-cold
recovery with the original worker, followed by the common service suite. No
live CRC, storage reset, packet-continuity, audio or production-HA result is
claimed here. Older deployment migration is outside this work's scope.
