# Atomic Fenced Transition Evidence

This file retains the reproducible store-side evidence for SDK issue #696.
Commands were run from the repository root through
`/srv/agents/agent-codex/.local/bin/opc-heavy`; no shared target directory or
build-environment override was used.

## Revision and scope

- Assigned branch: `feat/696-atomic-fenced-transition-wm-20260816`
- Original published #684 dependency head:
  `514f2a96d5bf36b8f3e40afccd03a5771655e218`
- Landed #684/main dependency head:
  `0ffb7faed75914d3e99f8f9f1a287fbb6cb14aa7`
- Landed #684/main dependency tree:
  `189d22525fe6feb3f895ca5e5c922d2a6319e0a6`
- Store-hardening preservation checkpoint:
  `fbf0f55429103efbbebad009db0231b57af754fd` (tree
  `8b1bad3dcd5088d9e097476adde988c454019d22`), followed by the
  formatting-only `bd8580c868610ea71eaf34ca1c582dc54b5d1458` (tree
  `147bcb134ae7df1bd348d33c777e56c8c65d1599`). Exact-head audit then
  found that the first removal mutation below had accidentally remained in
  both published commits; the current source restores the typed outcome and
  the restoration digest pinned below before any #695 integration.
- Pre-#695 feature head: `e2706a32a8d109cf3ad1a327f45ddcb562db6cd6`
  (tree `4c64318d5c2bb6747d24a951203af2de8b1d5329`).
- Landed #695/main dependency and reviewed feature tree:
  `b67143041c00b632fc5af634117b491839af68ff` (tree
  `d47deb6bcd6bac85497ea06ed540403ff3593ade`).
- Signed normal, non-rebased #695/main merge:
  `dbe54e362a8cc0ce2143fbb3c1e427565d568cdc` (tree
  `14b27eb4e760f7a3164aec4f67ea9a4300285c76`).
- Included after that merge: the generic `opc-session-store` model and all
  consensus/SQLite/recovery/snapshot boundaries, plus the revision-3 typed
  least-authority one-shot and bounded persistent consumer transports.
- Still excluded: every product/ePDG schema, Diameter/IKE/SWm/S2b/XFRM
  semantic, arbitrary multi-key transaction, or raw consensus authority.

## Retained RED: the old split boundary

`red_696_split_acquire_then_cas_leaves_a_committed_intermediate_boundary`
uses only the pre-existing lease-acquire, CAS, log, watch, and read-only SQLite
surfaces. It proves that the old composition commits two adjacent consensus
entries. After the first entry, the lease/fence is durable while the exact
record is still absent; only the second entry installs it. The journal and
watch likewise expose two separate effects. That observable state is the crash
and competing-owner race boundary removed by the one-entry primitive.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  red_696_split_acquire_then_cas_leaves_a_committed_intermediate_boundary \
  --all-features -- --exact
result: PASS (1 passed)
```

`red_696_split_renew_then_cas_leaves_a_committed_intermediate_boundary`
retains the corresponding existing-record proof. The legacy renewal durably
extends the exact lease while the record remains at its old generation and
payload; only a later CAS installs the successor. The two ordered application
and watch entries expose the crash/race boundary independently of any internal
logical-time entries that Raft may also commit.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  red_696_split_renew_then_cas_leaves_a_committed_intermediate_boundary \
  --all-features -- --exact
result: PASS (1 passed)
```

## Fix-removal mutation: OutcomeUnknown

Mutation: remove the fenced-transition disjunct that converts a forwarded
post-transmission failure into the typed unknown outcome. The exact regression
then failed at the assertion
`a possibly delivered transition returns typed ambiguity`. Restoring the
disjunct made the same command pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_does_not_auto_replay_after_forward_write_boundary \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: record owner and fence

Mutation: weaken the renew-side record authorization from rejecting either an
owner mismatch or a fence mismatch to rejecting only when both fields differ.
The regression failed because a still-valid lease mutated a record whose owner
alone differed. Restoring the disjunction made the exact test pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_renew_rejects_record_owner_or_fence_mismatch \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: expected generation

Mutation: accept every present expected generation against every present
record instead of requiring equality. The regression failed because the
unexpected generation renewed the lease and replaced the record. Restoring
exact equality made the same command pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_stale_fence_and_generation_rejections_leave_state_unchanged \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: durable complete-body binding

Mutation: bypass the persisted request-digest mismatch branch during apply
replay. The exact receipt regression failed closed while processing the
different-body request, instead of returning its committed `RequestConflict`.
Restoring the digest comparison returned the typed no-effect conflict and made
the test pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_receipt_replays_conflicts_and_expires_to_a_tombstone \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: follower request identity admission

Mutation: bypass the follower-log equality check between the outer consensus
request ID and the typed transition request ID. The regression failed because
the mismatched entry entered the follower log. Restoring the equality check
made follower and apply admission reject the entry again.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_outer_request_id_mismatch_fails_follower_and_apply_admission \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Canonical V1 request commitment

`fenced_transition_v1_request_digest_has_a_pinned_protocol_vector` fixes the
complete canonical request commitment at
`a66db3c2afb0c176d63d2f528f1466e33c7317c81b3a61efb1f3aed5bfe0ce08`.
The same test proves that leader time, outer consensus schema metadata,
forwarding origin, and changing authority identity do not change V1 caller
semantics, while changing one canonical request field does.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_v1_request_digest_has_a_pinned_protocol_vector \
  --all-features -- --exact
result: PASS (1 passed)
```

## Fresh pre-#695 mutation restoration boundary

All five mutations above were rerun on 2026-08-16 against this coherent
pre-#695 working tree. Each exact test failed at its intended invariant and
passed after the one-line mutation was restored. The restored source digests
were then checked against the values captured before the mutation sequence:

```text
9d06760723aa22bb064d383077b36c2ce062199c8073ccb2c289c1d0c239f519  crates/opc-session-store/src/sqlite/consensus.rs
26f4bc9d530f34573ecf3e6d0250131e41a9b660efde3e834e5105aadfc1f049  crates/opc-session-store/src/consensus/store.rs
```

They were rerun once more after #695 integration at the final candidate; this
pre-integration evidence is intentionally not the final merge gate.

## Final post-#695 mutation integrity

The historical mutation results above are retained evidence, not a substitute
for the final current-head qualification. Exact-head review of the preservation
checkpoint detected that the OutcomeUnknown mutation itself had been retained;
it was restored before continuing. On 2026-08-18, after the normal #695 merge,
durable activation, counter-exhaustion handling, recovery work, and the
revoked-envelope ordering correction, all five mutations were rerun again.
Each exact test failed at its intended invariant, the single mutation was
restored immediately, and the same test then passed. Both source digests were
verified before every next mutation and after the complete sequence:

```text
6131da4ba33366220c43c8c5872974df95d502407fc43fff17c7e69b651b8419  crates/opc-session-store/src/sqlite/consensus.rs
45f15c2e1f4c30c44a5122b1e590eb441576d6327b345d4f35b23dd8d490f9a4  crates/opc-session-store/src/consensus/store.rs
```

The five one-line removal mutations and their exact regression commands are:

1. In `consensus/store.rs`, map `FencedTransition` in
   `consensus_outcome_unavailable` to the generic backend-outcome error;
   `fenced_transition_does_not_auto_replay_after_forward_write_boundary` must
   fail, then pass after restoring `FencedTransitionOutcomeUnknown`.
2. In `sqlite/consensus.rs`, weaken the renew record identity check from
   `owner != ... || fence != ...` to `owner != ... && fence != ...`;
   `fenced_transition_renew_rejects_record_owner_or_fence_mismatch` must fail,
   then pass after restoring `||`.
3. In `sqlite/consensus.rs`, bypass the present-record equality guard in the
   expected-generation match;
   `fenced_transition_stale_fence_and_generation_rejections_leave_state_unchanged`
   must fail, then pass after restoring exact equality.
4. In `sqlite/consensus.rs`, bypass only the
   `replay_fenced_transition_receipt_sync` body-digest mismatch branch;
   `sqlite::consensus::tests::fenced_transition_receipt_replays_conflicts_and_expires_to_a_tombstone`
   must fail, then pass after restoring the digest comparison.
5. In `sqlite/consensus.rs`, bypass only the follower-log outer/inner request
   ID equality check in `validate_normal_command`;
   `sqlite::consensus::tests::fenced_transition_outer_request_id_mismatch_fails_follower_and_apply_admission`
   must fail, then pass after restoring that equality check.

Each command used the exact `opc-heavy cargo test --locked -p
opc-session-store --all-features` invocation already printed in its historical
mutation section above. The five RED assertions were, respectively: loss of
typed ambiguity after possible delivery; mutation of a record with a different
owner or fence; renewal/replacement at an unexpected generation; a receipt
body conflict no longer returning its committed no-effect result; and a
mismatched outer/nested ID entering a follower log. No mutation was retained
for a second command.

## Post-#695 integration checkpoint

These commands passed on 2026-08-17 after the normal #695 merge and initial
revision-3 transport integration. They remain an historical integration
checkpoint; the later durable activation and final mutation reruns are recorded
separately above and in the final candidate sections below.

```text
production_readiness_requires_fresh_authenticated_topology_and_accepts_refresh
result: PASS (1 passed, 4.81s)

lagging_replica_installs_compacted_snapshot_without_losing_committed_state
result: PASS (1 passed, 57.49s)

fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect
result: PASS (1 passed, 55.74s)

committed_write_with_a_late_forward_result_is_typed_ambiguous_and_applied_once
result: PASS (1 passed, 0.89s)

cargo fmt --all --check && git diff --check
result: PASS (wrapper exit 0)

cargo check --locked -p opc-session-store --all-targets --all-features
result: PASS

cargo check --locked -p opc-session-net --all-targets --all-features
result: PASS

cargo test --locked -p opc-session-store --lib fenced_transition --all-features
result: PASS (41 passed)

cargo test --locked -p opc-session-store --lib --all-features
result: PASS (383 passed)

cargo test --locked -p opc-session-net --lib consumer --no-fail-fast
result: PASS (59 passed)

cargo test --locked -p opc-session-net --lib --all-features
result: PASS (261 passed)
```

The revision-4 store consumer boundary derives one domain-separated internal
receipt ID from the authenticated consumer identity, stable cluster identity,
and public request ID, independent of body and changing configuration epoch.
The same internal ID occupies the outer and nested consensus request fields;
the durable receipt binds the complete canonical transition body. The adapter
does not emit the legacy `BindConsumerRequest` command, so one consumer
transition still has exactly one application log position. Both one-shot and
persistent clients preserve the public request ID across `NotTransmitted`,
`OutcomeUnknown`, and exact status recovery.

The snapshot tests previously exceeded their five-minute command-batch bound
because the durable append/apply path reconstructed two canonical in-memory
SQLite schemas for every activated-ledger validation. The expected immutable
normalized DDL forms are now initialized once with `OnceLock`; each durable
call still reads and exactly validates the actual marker, `sqlite_master`
definition, receipt table, and index.

The readiness test now acquires its capacity-one fixture permit before minting
its real monotonic-expiry evidence, so evidence cannot expire in the test
queue. Its 250 ms test-only timer-dispatch tolerance is not a production
timeout change: `timeout_at` selects the deadline event, but a host runtime
cannot promise that the task is scheduled at the identical wall-clock instant.
The test proves entry into the delayed peer path and sets 3 s/4 s injected
faults for 1 s/2 s attestation budgets, leaving at least 1.75 s between the
asserted upper bound and a completed peer response. Thus it still detects a
barrier that waits for the peer or the 5 s operation deadline instead of the
attestation deadline.

## Independent store hardening evidence

The current store-only hardening adds and exercises:

- permanent bounded request/body and response commitments, including exact V1
  request-digest parity and corruption/reopen rejection;
- the 4096-entry absorbing history cap and exact 24-hour retention horizon;
- an additive empty `Prepared` receipt ledger at the released schema version,
  followed only by a unanimously proved first transition that atomically raises
  the persistent downgrade fence, installs the exact current-scope activation
  certificate, and records the caller receipt/effect in the same command;
- exact markerless #684 migration, exact enumeration of all 12 released
  lease/operator-recovery/restore schema products, an attached-only exact
  pre-authority Dynamic snapshot exception, and rejection of activated
  missing/weak/partial ledger, identity-marker, certificate, or
  historical-hybrid state;
- monotonic snapshot-install floors for logical/application/watch/recovery
  state, including the application and recovery digest chains;
- exact replay after snapshot installation without a second effect;
- legacy postcard ordinal parity for every pre-#696 consensus intent, outcome,
  and `StoreError` variant;
- fixed non-identifying Debug output at command, response, store, transition,
  and replication boundaries; and
- inclusive 1 MiB record, 16 KiB public-outcome, and 2 MiB consensus-RPC
  boundaries with one-over rejection.

On 2026-08-16, before the subsequent activation/snapshot hardening and #695
integration, a coherent store-only checkpoint passed:

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --all-features
result: PASS (complete package: all unit, integration, and doc tests)

/srv/agents/agent-codex/.local/bin/opc-heavy cargo clippy --locked \
  -p opc-session-store --all-targets --all-features -- -D warnings
result: PASS

/srv/agents/agent-codex/.local/bin/opc-heavy cargo fmt --all --check
result: PASS

/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition --all-features
result: PASS (17 passed)
```

The 17-test three-voter filter includes deterministic before-proposal,
after-proposal/before-commit, after-commit/before-response, leader-transfer,
capability-downgrade, exact replay, no-auto-replay, expired-owner takeover,
and snapshot-install replay paths. It also proves that Acquire+Create and each
Renew+Update/RefreshTtl/Delete operation consume one consensus application
entry and expose one ordered two-operation application/watch batch. The absent
and exact-record-expiry matrix records `CasConflict` for
Update/RefreshTtl/Delete without renewing the lease or creating a record,
fence, application sequence, or watch effect.

These are retained historical store-side gates, not the final exact-head
verification. The hardened pre-#695 work was published early for durability;
at that checkpoint its exact heavy-gate rerun remained pending behind the
active #695/urgent shared build queue. The final sections below record the
completed post-merge reruns, including all five restored mutations, workspace
CI, and least-authority consumer transport evidence.

## Published-#684 recovery compatibility

The additive receipt commitments and persisted lease-acquisition timestamp
remain compatible with the exact published #684 database and snapshot shapes.
Read-only recovery projects the absent acquisition timestamp as an explicit
non-authoritative `NULL`. Only the exact markerless #684 manifest with neither
receipt nor activation-certificate table is accepted as an empty ledger.
Read-only inspection does not mutate that source; writable open or staged
recovery creates the exact empty `Prepared` ledger with marker `0` at the
released schema version. It does not activate V1. Activation happens only in a
unanimously proved caller transition and raises the persistent schema fence in
that same command. A present empty weak or unpublished table, as well as any
populated, partial, malformed, or activated missing-ledger layout, remains
fail-closed.

Snapshot installation has one narrower historical exception: the exact
pre-authority Dynamic-consensus manifest is accepted only while attached as an
incoming snapshot and only with every later artifact absent. The same file is
rejected as a writable or read-only main database. Focused classifier evidence
also retains the marker, receipt table/index, and `leases.acquired_at` one at a
time and proves that each impossible hybrid is rejected.

The pinpointed regression and the complete recovery matrix were rerun after
fixing the recovery-only log projection:

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  recovery::tests::current_recovery_inspection_accepts_pre_ledger_replica \
  --all-features -- --exact --nocapture
result: PASS (1 passed)

/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib recovery:: --all-features
result: PASS (42 passed)
```

The current 42-test recovery matrix (also covered by the final 389-test
store-library PASS below) includes exact pre-acquisition lease schema inspection,
conversion, recovery planning, and digest equivalence; exact absent-ledger
#684 acceptance; and rejection of present weak/empty, populated, partial,
oversized, prematurely compacted, malformed, or durable-floor-inconsistent
receipts. It also stages and applies an `Activated` majority checkpoint and
proves that the raised schema fence, exact certificate, and retained receipt
body/response commitments survive inspection, planning, and recovery.

## Independent canonical lanes after the #695 merge

The following source-independent lanes passed on 2026-08-17 and were retained
through the completed final Rust activation qualification:

```text
management-plane policy self-test/check: PASS
Diameter corpus helper self-test: PASS
CI shard manifest/partition verification: PASS (269 integration targets)
Go SDK reference operator gofmt/vet/race: PASS
Go operator SDK gofmt/vet/race/downstream import: PASS
Kustomize build plus Helm lint and both rendered YAML modes: PASS
vendored dimpl source-policy searches: PASS
```

The source-independent results are retained here; the final integrated
candidate results and current host-only limitations are recorded below.

## Final integrated candidate: authority, durability, and transport

The post-#695 candidate retains one generic mutation command. A consumer
request derives one domain-separated, nonzero internal ID from the
authenticated consumer identity, stable cluster identity, and public 16-byte
request ID. The operation body and rotating authority epoch are deliberately
excluded from that derivation. The same internal ID occupies the outer
consensus envelope and nested fenced request, while the durable receipt binds
the complete canonical transition body. Consequently, an exact replay returns
the recorded outcome, a changed body under the same public ID returns
`FencedTransitionRequestConflict`, and distinct authenticated identities use
distinct receipt namespaces. The adapter never emits the legacy consumer
binding command, so the lease decision and one bounded record mutation still
occupy one application-log position.

Mixed-version admission is durable rather than a perpetual all-voter liveness
dependency. An empty writable ledger is only `Prepared`. Before the first V1
transition for an exact authority scope, every configured voter must answer an
authenticated V1 capability probe. The first caller command then carries the
internal activation wrapper and atomically installs the raised schema-version
downgrade fence, exact scope/voter-set certificate, receipt, lease decision,
and record effect. Once that command commits, capability, observation,
execution, status, failover, and restart use ordinary current-scope quorum
authority. A topology cutover deletes the predecessor certificate but retains
the one-way schema fence and receipt history; the successor scope must prove
all of its exact voters on its first transition. Revoked predecessor envelopes
are deterministic no-effect entries: they neither install a certificate nor
execute the body, and an unactivated ledger does not bind them prematurely.

Follower projection validates the outer/nested ID, activation state, exact
projected scope and voter digest, including topology and activation commands in
the same batch. Snapshot installation copies the identity fence, optional
exact-current certificate, and receipt ledger atomically; it rejects activated
to prepared regression and same-scope certificate erasure/substitution while
permitting a legitimately unactivated successor scope. Recovery includes the
activation layout and optional certificate in its checkpoint digest and
preserves them through inspect/plan/stage/apply. A released #684 database
remains accepted only in its exact historical shape, and a pre-V1 binary is
fenced from opening the activated schema.

All SQLite-backed counters that must fit positive signed storage values are
admitted before effect persistence. Generation, fence, credential, restore,
application, and watch exhaustion produce the fixed retained
`FencedTransitionStorageExhausted` no-effect result instead of a committed
node-local state-machine fault. Exact replay, status, changed-body conflict,
snapshot/reopen, replica convergence, and a following log entry remain
deterministic at the boundary.

The general public `/1` consumer wire is revision `6` for both one-shot and
bounded persistent transports. The separate epoch-fenced `/2` wire remains
revision `5`; it is not substituted for, or counted as, the general `/1`
transport. Frozen v7/#695 qualification remains the historical revision-2
contract. The retained v8 exact-head schema is also immutable historical
evidence and pins the then-current `/1` revision-5 compiled handshake constant;
the current runner may record a separate v9 artifact for `/1` revision `6`
only through the external exact-head gate. V9 is `experimental:true` and is
`qualification_complete:true` only after that complete gate succeeds and its
strict artifacts validate; this committed document does not assert a result.
The immutable schema digests are:

```text
3ce5f0e622508ba89820742514eddfd2c0575265754c0bdd1a726e5b3335ecca  qualification/v7/session-ha-profile.schema.json
0b02633f0118283f425c4b60d8540de4503023d3759b7c6939ebaf2d16365772  qualification/v7/session-ha-evidence.schema.json
5e3becf5094f3e222b94799e0fb7b6b77c3398aeabae743fc65b409c4cd4adfd  qualification/v8/session-ha-persistent-consumer-head-evidence.schema.json
65d456edc15359e9cbac25a6771822219797c53f03aa6ca5d8837e43a6dbc018  qualification/v9/session-ha-persistent-consumer-head-evidence.schema.json
```

The closed V9 external-pair contract records canonical absolute raw paths for
the producer Cargo target, owner-private evidence root, owner-private fs-verity
snapshot base, and the pair directory derived from the evidence root; each path
has a separate domain-separated commitment. The snapshot base also records its
descriptor-captured device/inode, so a same-path replacement is rejected. It
separately binds the exact normalized absolute Cargo invocation
alias, its canonical backing executable path, a SHA-256 of the backing content,
and executable mode. The alias (including a rustup-managed `.../cargo`
spelling), not the backing path, is `argv[0]` followed by 14 canonical tail
arguments; its normalized recorded vector has 15 elements beginning `cargo`.
The POSIX-escaped environment-prefixed reproduction command executes that
alias. Bound paths reject control
characters and NUL; the standard POSIX single-quote rendering is covered only
by its exact regression and makes no broader shell-injection claim. The pair
still contains only the unchanged exact leaves
`batch-release-gate-v1.json` and `persistent-consumer-v9.json`; its symmetric
run-ID uses the v4 domain and binds canonical V1, existing provenance/invocation
fields, and the canonical full V9 claims preimage whose only replacement is
`run_id_sha256 = sha256:` plus 64 zeroes—not final self-containing V9 bytes.
The command digest orders backing path, alias, backing SHA-256, u16-BE
executable mode, then argv. Run-ID v4 binds 20 ordered provenance strings: the
prior 16 ending alias, backing path, backing SHA-256, `cargo_profile`, and
`opt_level`, plus the fs-verity snapshot path, commitment, device, and inode.
It then binds u16-BE mode before the existing
V1/V9/argv/recipe/canonical-V1/claims-preimage material. The pair cannot be
transplanted. The downstream wrapper consumes that pair
with a fresh target distinct from the producer target. Its Python parent retains the
nofollow private lease inode through `/proc/<wrapper-pid>/fd/<fd>` for the
direct child without inheriting the raw FD; Rust opens/locks that procfd inode
and revalidates procfd, parent, name, and path before mkdir, publication, and
completion, closing the A-to-B split-lock seam. This is a contract update, not
an assertion that qualification ran or completed.

The frozen consumer set is general `/1` revision 6, ordinary fenced `/2`
revision 5, and protected-roster `/3` revision 5. A roster-enabled listener
advertises all three ALPNs concurrently; voter consensus remains
`opc-session-consensus/2` revision 5. Stateless admission is family-specific:
`/1` and opted-in `/3` share the 16 `/1`-family cap, while `/2` has its own
16-cap. Ordinary persistent `/1` and `/2` share aggregate width and can reclaim
an idle opposite-protocol lane. A protected `/3` pool is an opted-in distinct
profile, not a relabelled ordinary lane. After every loss/restart it rebinds to
a readiness-proven live leader; its exact foreign-tenant bracket is three
per-voter typed `Unavailable` observations. Only `NotFound` and backend
`Unavailable` receipt status are retryable; typed and durable negative receipt
outcomes are terminal.

## D90 supersession record

Do not cherry-pick commit `d90def1f627705f837312076f02673bb48ab4693`
(patch-id `58cace4be390bfb8175ed39c7fbe0833bf41b81e`). The current
`consensus_openraft` harness and end-to-end test strictly supersede it: every
voter is probed; a mismatch fails before proposal with no receipt and
`NotFound` status; and exact replies are verified through durable activation.

Request admission separately requires byte-identical public outer/nested IDs
and derived internal consensus outer/nested IDs. Transport response validation
checks the complete typed outcome against the request body and recorded logical
time; wire correlation and the status/recovery envelopes validate the public
request ID where they carry it. Proven pre-transmission failures remain
`NotTransmitted`; any possibly transmitted missing, substituted, malformed,
body-inconsistent, or envelope-ID-inconsistent response becomes
`OutcomeUnknown` with the public request ID retained for exact status recovery.
Observation and status collapse local SQLite/schema/hydration
failures to fixed SDK-controlled diagnostics; keys, owners, request IDs,
timestamps, record values, state classes, paths, SQL, and table names are not
returned.

## Final integrated candidate: focused and canonical local gates

The following focused gates passed after the activation, counter-exhaustion,
revision-5 transport, receipt-status recovery, and revoked-envelope corrections
were combined:

```text
cargo test --locked -p opc-session-store --lib fenced_transition --all-features
result: PASS (46 passed)

cargo test --locked -p opc-session-store --lib --all-features
result: PASS (389 passed)

cargo test --locked -p opc-session-store --test consensus_openraft fenced_transition --all-features
result: PASS (17 passed)

cargo test --locked -p opc-session-store --test consensus_openraft red_696_split --all-features
result: PASS (2 passed)

cargo test --locked -p opc-session-store --lib recovery:: --all-features
result: PASS (42 passed)

cargo test --locked -p opc-session-net --lib consumer --all-features --no-fail-fast
result: PASS (60 passed)

cargo test --locked -p opc-session-testkit --test qualification_profile
result: PASS (19 passed)

cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
result: PASS

RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
result: PASS

cargo fmt --all --check && git diff --check
result: PASS

management-plane policy self-test/check: PASS
Diameter corpus helper self-test: PASS
publish-order graph check: PASS (33 publishable crates)
```

The typed least-authority mTLS transition path passed independently in every
topology/transport combination. Each run covers capability and fresh
observation, Acquire+Create, exact replay, changed-body conflict, exact status,
all-voter convergence, replacement-leader status/readback with the same
authenticated consumer identity, and a fresh transition after failover:

```text
three_process_projected_mtls_stateless_quorum_consumers: PASS (42.09s)
three_process_projected_mtls_persistent_quorum_consumers: PASS (33.57s)
five_process_projected_mtls_stateless_quorum_consumers: PASS (35.39s)
five_process_projected_mtls_persistent_quorum_consumers: PASS (33.99s)
```

The repository-authored shard plan verified 269 integration targets plus the
explicit mTLS heavy partition. All six unmodified shard plans passed using
their generated commands and repository-default test thread counts:

```text
ci/test-shards.py verify: PASS (6 shards; 269 integration targets)
misc: PASS (including 42 selected mTLS tests; 2 ignored by plan)
it-0: PASS (94 targets)
it-1: PASS (75 targets)
it-2: PASS (100 targets)
heavy-0: PASS (2 passed; 349.74s)
heavy-1: PASS (2 passed; 444.97s)
ci/test-shards.py verify-heavy: PASS (48 = 44 misc + 4 heavy)
```

## First hosted exact-head result and fixture correction

The first hosted run of signed feature head
`e926cbfc407307451846d2e1efdc21ad79b4b3a2` (tree
`78e7fe927152cfab5fc9ad44bf9d08f98f258433`) completed 36 of 38 check
runs successfully. Security (`32107520559`), IPsec load-balancing
(`32107520554`), privileged GTP-U (`32107520555`), and egress-fence
(`32107520558`) were terminal green. The only underlying failure in CI run
`32107520556` was `Rust tests (it-0)` job `95619867084`; the `Rust
workspace` failure was its aggregate result.

All four failing `consensus_openraft` cases were healthy semantic paths using
the fixture-local 750 ms operation deadline rather than the exported 10 s
production complete-operation budget. Under hosted scheduler contention, two
read/status barriers returned the fixed `BackendUnavailable` outcome, one
accepted write correctly returned `FencedTransitionOutcomeUnknown`, and an
expiry assertion compared the same deadline class to `LeaseExpired`. No
production transition, authority, receipt, or ambiguity behavior failed.

The correction changes only those four semantic fixtures to use
`DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT`. The deliberate
possibly-transmitted fault still delays AppendEntries by the selected operation
budget plus 250 ms, so it continues to require `OutcomeUnknown` followed by
exact-ID recovery. With repository-default parallelism, the focused transition
filter passed 17/17 and the repository-generated `it-0` command passed in full;
its `consensus_openraft` target passed 34/34. Formatting and diff checks also
passed. The failed first run is not treated as a pass; a new signed exact head
must be published and its hosted terminal state recorded in PR #698.

The isolated and platform-admission lanes also passed:

```text
opc-persist default/no-feature Clippy and no-run contract: PASS
opc-persist four security/break-glass suites, serial: PASS (38 passed)
opc-persist all-feature serial suite: PASS
forced unsupported GTP-U cfg suite: PASS
examples/smf-reference format, all-target/all-feature Clippy, tests: PASS
vendored dimpl external-consumer resolution and formatting: PASS
vendored dimpl RustCrypto production panic-path Clippy: PASS
vendored dimpl RFC 6083 source invariants: PASS
```

The installed i686 Rust target could not be compiled or linked locally, and
therefore could not execute, because this host lacks the 32-bit libc
development/startup objects (`gnu/stubs-32.h`,
`Scrt1.o`, `crti.o`, and 32-bit `libgcc_s`). The vendored all-target/test lanes
likewise stop before source compilation because the host lacks `autoreconf` for
the wolfSSL build. No system package, toolchain, Git identity, concurrency, or
build configuration was changed to bypass either environmental prerequisite;
the dedicated hosted lanes must supply the authoritative results. The host also
lacks the pinned actionlint/pyflakes, cargo-hack, rasn-compiler, Rust 1.88,
FreeBSD, and macOS
toolchains, so those remain explicit hosted gates rather than locally inferred
passes.
