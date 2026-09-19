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

## Authority boundary under investigation

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
