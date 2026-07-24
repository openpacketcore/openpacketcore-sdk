# Session-Net TLS Rotation Qualification Plan (#164)

This plan fixes the topology, lifecycle values, traffic mix, failure budget,
readiness rule, metrics and alert contract, pass/fail SLOs, evidence format,
and acceptance mapping for qualifying seamless TLS rotation on the
session-store quorum fleet. It is the qualification companion to the operator
mechanics in
[the consensus operator runbook](consensus-operator-runbook.md#7-shared-mtls-certificate-rotation):
the runbook defines the rotation procedures and the deployed-campaign
script; this plan defines what evidence proves the procedures and where each
#164 acceptance bullet is discharged.

**Status.** The in-process deterministic campaigns listed in section 6 are
implemented and validated in `crates/opc-session-net/tests/`. They extend —
they do not replace — the multi-process projected-mTLS campaigns in
`opc-session-testkit` and the deployed/Kubernetes campaign contract. The
deployed 3/5-member campaign, the signed release bundle, live alert
fire-and-clear, remote-HKMS rotation, platform soak, the crash-point matrix,
and the version-migration campaign remain gated as listed in section 10; the
session-HA profile stays `experimental` with `qualification_complete = false`
until those pass.

## 1. Qualification topology

- Fleets of exactly three and exactly five voting members; the failure
  budget is `floor((N - 1) / 2)` unavailable voters (1 of 3, 2 of 5) with
  quorum preserved throughout.
- Every member runs the production `ConsensusSessionStore` (Openraft) over a
  file-backed SQLite backend, served by the production
  `SessionConsensusServer` mTLS listener and reached through production
  `RemoteSessionConsensusPeer` clients over real loopback TCP with real TLS
  handshakes. No transport or authentication code is stubbed; only name
  resolution is test-controlled (a per-directed-path resolver with an
  enable fence and an attempt counter).
- Identity: one SPIFFE ID per member, pinned by the manifest; per-member
  leaf/intermediate material issued by campaign-local roots, published
  through the production watch-channel reload path with
  `SessionReauthenticationControl` orchestration. Trust bundles are sets of
  campaign roots (`old`, `overlap = old + new`, `new-only`).
- In-process fault semantics: an isolated member keeps its store running
  while its listener is stopped, every directed resolver path touching it is
  fenced, and its cached outbound lanes are retired. This is the strongest
  partition/restart semantics expressible in-process; a real network
  partition and host restart remain deployed-campaign gates (section 10).

## 2. Fixed lifecycle values and timing profile

Every campaign and the evidence checker pin the same values. Changing any of
them is a requalification event.

| Value | Bound |
| --- | --- |
| Connection max age | 60 s |
| Drain window (old-epoch connection retirement) | 100 ms |
| Reconnect cooldown per directed peer | 1–20 ms |
| Cold connect timeout | 1500 ms |
| AppendEntries (heartbeat) timeout | 2000 ms |
| Vote timeout | 5000 ms |
| Election window | 5000–8000 ms |
| Operation timeout (any complete operation) | 10 000 ms |

Derived campaign SLOs (the same derivation as the runbook restart-stage
table):

| SLO | Value | Derivation |
| --- | --- | --- |
| Member transition envelope | 26 s | 2 × election-max + operation timeout |
| Member recovery envelope | 37 s | transition envelope + one backend operation (10 s) + one delivery second (1 s) |
| Traffic round envelope | (N + 1) × 10 s | one committed write plus one linearizable read per reachable voter, each within the operation timeout |
| Local fault/measurement action | 10 s | one operation timeout |

The deployed-campaign budgets (rollback budget 21240 s / 33560 s, hard span
22560 s / 34880 s, forward campaign 57600 s / 91880 s, certificate horizon
80160 s / 126760 s for 3/5 members) are fixed by runbook section 7.2 and are
not redefined here.

## 3. Traffic mix

The continuous workload through every campaign phase:

- **Acknowledged encrypted canary writes.** One lease-guarded
  compare-and-set per traffic round against the current leader, with the
  expected generation pinned, through the `EncryptingSessionBackend`
  composition (authenticated encryption at rest above consensus). A round
  succeeds only on the exact CAS-success acknowledgement.
- **Linearizable reads.** Each round reads the canary back from every
  reachable voter within the operation timeout and byte-compares the
  generation and payload.
- **Fresh bidirectional handshake probes.** After every member transition,
  an idempotent empty Vote RPC is driven on every enabled directed path
  touching the changed member, and must complete on a connection resolved
  after the probe began (a real new TLS handshake in both directions).
- **Durable readiness probes.** `probe_durable_readiness` on every required
  voter after every transition and continuously through fault windows.
- **Connection recycling measurement.** Per-directed-path resolver attempt
  counters bound the handshake rate of every transition (section 6).
- **Retained/rejected chain probes.** One-shot clients prove a member that
  rejected a malformed reload still serves its exact pinned identity under
  retained last-known-good material, and that a removed trust anchor can no
  longer complete a handshake in either direction.

Watches, restore scans, and mixed lease/CAS/batch workloads under rotation
are covered by the merged single-link and multi-process campaigns
(`authenticated_replica_identity.rs`, `three_node_quorum.rs`, and the
testkit's seeded mixed workload); the deployed mixed-traffic matrix under
real faults remains a section-10 gate. The canary is deliberately the
strictest possible traffic for the durability claim: it makes every
acknowledged committed write individually checkable.

## 4. Failure budget and readiness rule

- The campaign tolerates at most `floor((N - 1) / 2)` unavailable voters and
  requires `fresh_reachable_voters >= required_quorum` and
  `agreeing_voters >= required_quorum` at every measurement point — the same
  inequalities as the runbook stop/continue matrix.
- Readiness rule: a member is ready only when a fresh durable readiness
  probe succeeds after the transition that touched it; the fleet is ready
  only when every required voter is ready. Probes are never cached.
- A member that rejects a malformed reload retains last-known-good material
  and counts as healthy (it keeps serving its exact pinned identity); the
  campaign must still repair and prove a coherent reload before completing.
- One unavailable member plus one rejected malformed reload stays within
  budget: the campaign proves quorum traffic continues, no member ever
  publishes mixed/invalid material, and the rejected reload causes zero
  connection churn.

## 5. Metrics and alert contract

The fixed-cardinality metric and alert contract is defined by runbook
section 7.1 and is not repeated here: `opc_security_rotation_total{kind,
outcome}` (exactly 3 kinds × 4 outcomes) and its saturation gauge, the SVID
expiry gauge, and the fixed-label connection/drain/reconnect/readiness
families with alerts distinguishing reload rejection
(`retained_last_good`/`rejected`), expiry, trust failure, drain overrun,
reconnect failure, and durable quorum loss. The multi-process observability
evidence (testkit) exercises those counters end to end.

The in-process campaigns assert the equivalent typed distinctions directly:
material availability (`Ready` vs `RetainingLastGood`) with the exact reload
rejection reason (`LocalIdentityChanged`, `MaterialUnavailable`,
`MaterialLimitExceeded`), typed peer error classes (`Authentication`,
`Timeout`, `Unavailable`), and per-outcome transport tallies
(authentication-failure outcomes must be exactly zero). Any fixed-label
regression in the metric pipeline fails the multi-process campaigns; any
semantic confusion between the six failure classes fails the in-process
campaigns.

## 6. Campaigns and pass/fail SLOs

All campaigns run in CI in
`crates/opc-session-net/tests/rotation_fault_matrix.rs` (the fault matrix
added by this plan) and `consensus_transport.rs` (the merged forward/rollback
rotation evidence). The fault-matrix campaigns time every phase against its
SLO, emit the section-7 evidence document, and validate it with the
independent checker; the merged rotation tests assert their probes and
canary generations in-test. A campaign fails if any phase exceeds its SLO,
any count bound is exceeded, or the checker rejects the document.

| Campaign | Scenario | Key pass/fail bounds |
| --- | --- | --- |
| `three_member_openraft_fleet_rotates_and_rolls_back_real_mtls` / `five_member_...` (merged) | Full 13-phase leaf/intermediate/root rollover, add-anchor, removal, rollback before and after removal | Fresh handshakes + durable probes after every member transition; canary generation exactly 13; old-anchor chains rejected in both directions after removal |
| `three_member_fleet_rotation_continues_through_follower_partition_and_recovery` | Follower partition overlapping a survivor leaf rotation; continuous canary traffic; heal and catch-up | Survivors ready within 26 s; isolated member provably trails; rejoin + convergence within 37 s; no acknowledged write lost (exact +1 canary accounting) |
| `five_member_fleet_rotation_stays_within_failure_budget_with_one_unavailable_and_one_rejected_reload` | One member unavailable; a second member rejects identity-mismatched, empty, and over-limit reloads | Typed rejection reasons on both client and server material; zero resolver churn per rejection; retained-chain one-shot probe succeeds; quorum traffic within budget; coherent reload recovers; heal within 37 s |
| `three_member_fleet_repeated_rotation_stays_within_handshake_and_descriptor_bounds` | Three full cycles of one-member-at-a-time leaf rotation | Every directed path touching the rotated member performs ≥ 1 fresh handshake per transition; total per-transition resolver deltas ≤ 16 (measured 7); per-path campaign totals ≤ 18 (two cached lanes plus one bounded retry per endpoint rotation, over three cycles; measured 9-13), with late retirement redials accounted rather than denied; a final 500 ms settle dials nothing; Linux FD growth ≤ 8 (measured 0); authentication-failure outcomes exactly 0 |
| `three_member_fleet_member_restarts_mid_rotation_and_rejoins_under_overlap_trust` | Member restart while the fleet adds the new anchor and rotates leaves to the new root | Member rejoins under the overlap bundle with material advanced while down; catch-up within 37 s; fleet reaches new-only trust; old-chain client rejected at the restarted member |
| `rotation_fault_evidence_checker_binds_digests_bounds_and_provenance` | Contract test for the independent checker | A valid document passes; every structural, digest, freshness, SLO, accounting, or provenance violation fails closed |

Phase-kind SLOs enforced by the checker: `fault` ≤ 10 s, `rotation` ≤ 26 s,
`traffic` ≤ (members + 1) × 10 s, `recovery` ≤ 37 s, `bounds` ≤ 10 s.

## 7. Evidence format and provenance

Each campaign emits one `opc.session-net.rotation-fault-evidence.v1` JSON
document, validated by the independent stdlib-only checker
`scripts/check-session-rotation-fleet-evidence.py` (no repository imports).
The document records:

- **Topology and failure budget** (members, cluster, budget; budget must
  equal `floor((members - 1) / 2)`).
- **Configuration**: the exact section-2 lifecycle values and timing
  profile; the checker pins them byte-for-byte.
- **Phase plan digest**: SHA-256 over the campaign identity and the ordered
  `(name, kind, member)` phase sequence, recomputed by the checker.
- **Per-phase records**: kind, member, canary generation, fresh-handshake
  path count, ready members, duration, completion timestamp. The checker
  enforces the section-6 SLOs and the exact canary accounting: the first
  phase seeds generation 1, every `traffic` phase advances it by exactly
  one, and no other phase may change it — no acknowledged committed write
  is lost, rolled back, or double-counted.
- **Bounds**: FD growth vs allowance (nullable on non-Linux), maximum
  per-transition resolver deltas vs allowance, maximum per-path campaign
  resolver total vs the per-endpoint-rotation replacement allowance, final
  quiet-window deltas (must be 0: no lane may redial once the campaign has
  settled), authentication-failure outcomes (must be 0), rejected reload
  retentions.
- **Artifact digests**: SHA-256 of the test binary, SHA-256 of every
  campaign trust-anchor certificate (sorted, unique), and the checker
  provenance binding — the document carries the SHA-256 of the checker,
  which the running checker recomputes over its own bytes, so a modified
  checker rejects every document.
- **Timestamps**: campaign start/finish and per-phase completion in seconds
  since the UTC epoch, ordered, with the finish within a freshness window
  of −60 s/+5 s against validation time.
- **Outcome**: only `"pass"` is a valid document.

**Reproducibility.** Campaign PKI keys are drawn fresh from the OS CSPRNG on
each run, so evidence binds the run's anchors by digest rather than by seed;
the phase plan, fixed configuration, closed bounds, and exact accounting
keep the outcome reproducible run over run. The seeded counterpart is the
testkit's digest-bound workload schedule, and the deployed-campaign evidence
schema (`opc.security.rotation.evidence.v1`, runbook section 7.2) binds the
release digest, lease fence, and per-operation nonces. **Signing** is an
operator step over the archived documents (the `opc-evidence` bundle signing
primitives), and remains part of the section-10 signed-release gate.

**Archival.** Tests validate evidence in a temporary directory. Setting
`OPC_ROTATION_EVIDENCE_DIR` archives each document for inspection or
signing; the checker accepts a `--now-epoch` override so archived documents
re-validate deterministically.

## 8. Acceptance mapping

| #164 acceptance bullet | Evidence |
| --- | --- |
| 3- and 5-member leaf, intermediate, and root rollover without traffic/readiness interruption outside approved numeric SLOs | Merged `three_member_...` / `five_member_openraft_fleet_rotates_and_rolls_back_real_mtls`; fault-matrix campaigns here; per-phase SLOs in the evidence documents |
| One unavailable member plus one rejected malformed reload stays within the failure budget and never publishes mixed/invalid material | `five_member_fleet_rotation_stays_within_failure_budget_with_one_unavailable_and_one_rejected_reload`; testkit multi-process fault campaign |
| No acknowledged committed write is lost or rolled back (requires #127 commit authority) | Exact +1 canary generation accounting in every campaign, checker-enforced; #127 commit authority is merged |
| Watches gap-free/duplicate-free; every old-epoch connection drains by the hard deadline | `independent_client_and_server_leaf_rotation_preserves_active_requests_and_watch`; `consensus_server_only_material_rotation_replaces_both_cached_lanes`; drain-window lifecycle assertions; testkit drain discipline |
| Old-anchor connections cannot be established after removal; no connection survives either peer leaf expiry | Removed-root rejection probes in the merged rotation tests and in the restart campaign; `real_mtls_local_and_peer_leaf_expiry_force_exact_reauthentication`; paused-time lifecycle retirement tests |
| Rollback procedures executable and tested before and after old-anchor removal | The 13-phase merged rotation tests exercise both rollback paths; runbook section 7.4 procedures |
| Resource, task, file-descriptor, handshake-rate, and reconnect-backoff bounds under repeated rotations | `three_member_fleet_repeated_rotation_stays_within_handshake_and_descriptor_bounds` (FD ≤ 8, per-transition resolver deltas ≤ 16, per-path campaign totals ≤ 18, final settle quiet window = 0, zero authentication failures); testkit traffic/resource campaign (manual long-running gate) |
| Metrics/alerts expose only approved fixed labels and distinguish reload rejection, expiry, trust failure, drain overrun, reconnect failure, and durable quorum loss | Runbook section 7.1 contract; testkit observability campaigns; in-process typed distinctions asserted per campaign (section 5) |
| Evidence records exact artifact digests, configuration, seeds, timestamps, and independent checker provenance | Section 7 of this plan; the checker contract test; testkit digest-bound evidence; signing remains an operator step |

## 9. Reproduction

```console
cargo test -p opc-session-net --test rotation_fault_matrix
cargo test -p opc-session-net --test consensus_transport
python3 scripts/check-session-rotation-fleet-evidence.py \
  "$OPC_ROTATION_EVIDENCE_DIR/three-member-repeated-rotation-bounds-evidence.json"
```

The fault-matrix campaigns are deterministic in structure and must pass 10
consecutive runs in CI before a change claiming them lands. The fleet
campaigns serialize on a binary-local guard so concurrent fleet runtimes
cannot starve election timers on small runners.

## 10. Remaining gates (not discharged by this plan's in-process campaigns)

Tracked by the session-HA candidate profile's unproven acceptance gates and
the runbook's explicit non-claims:

- Deployed Kubernetes 3/5-member rotation under the documented fault and
  traffic matrix (the testkit renderer/campaign runners exist; a live
  cluster run with the pinned image, Secrets, and procfs checks has not been
  executed as evidence; no kind-based harness exists).
- Signed release bundle over the deployed evidence (operator signing step).
- Live alert fire-and-clear against a running monitoring stack.
- Remote-HKMS rotation qualification.
- Platform sizing and soak evidence, real network/storage fault injection,
  the crash-point matrix, and version-migration/rollback campaigns.
