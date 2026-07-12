# Session-Store Legacy Fork Recovery Runbook

This runbook covers the offline `opc-session-store::recovery` workflow for a
drained fleet whose persisted replicas cannot safely rejoin through ordinary
Openraft follower recovery. It is an emergency administrative boundary, not a
second consensus implementation. Openraft remains the only authority that can
commit the recovery epoch and return the fleet to service.

Use ordinary Openraft reconciliation for a current follower with an
uncommitted divergent tail. Use this workflow only when readiness reports
operator recovery required, or when a pre-Openraft fleet has no durable commit
proof. Completing this runbook does not by itself qualify a deployment for the
production HA profile; the distributed qualification and transport-rotation
gates still apply.

## Safety invariants

- The fleet is drained for the entire workflow. Session traffic, lease
  acquisition, ownership publication, VIP advertisement, and replacement pod
  startup remain disabled until the final state is `rejoined`.
- Production topology is one exact odd voter set of 3 through 31 members. A
  two-voter topology is never admitted as a production recovery contract.
- Planning is read-only, bounded, deterministic, and redaction-safe. The plan
  contains digests and bounded facts, never raw replica IDs, paths, session
  keys, payloads, key-provider handles, or recovery integrity-key material.
- Execution re-inspects the entire plan-bound replica set immediately before
  its first backup. A changed source, changed target, changed global
  fence/credential high-water, wrong cluster, pending workflow, or lost
  majority aborts before mutation.
- Every explicitly selected target is backed up and integrity-verified before
  any target is replaced. Legacy recovery explicitly selects every PVC,
  including the chosen source PVC.
- One immutable checkpoint is created from the selected source after all
  quarantine backups complete. Every selected legacy PVC is converted from
  that same checkpoint; the procedure never reselects a branch while resuming.
- Reset replicas remain readiness-fenced by the exact pending recovery epoch
  and plan digest. Only a normal command committed by the current local
  Openraft leader can finalize the recovery.
- Finalization invalidates pre-recovery leases and credentials, preserves or
  raises every observed fence and credential high-water, commits a monotonic
  recovery epoch, and requires a fresh durable-readiness barrier before
  service admission.

## Prerequisites

1. Stop all writers and verify that every member's process is stopped. Preserve
   each database, WAL/SHM/journal sidecar, snapshot directory, admitted cluster
   ID, configuration ID, configuration epoch, and logical `ReplicaId` mapping.
2. Supply the exact admitted voter set and all of its file-backed replicas. Do
   not substitute DNS names, FQDNs, pod hostnames, endpoints, or certificate
   identities for logical replica identity.
3. Mount a dedicated backup root owned by the recovery process. On Unix it must
   be a real directory with mode `0700`; artifacts are created as `0600` files
   beneath `0700` directories. Symlinks, permissive modes, unexpected files,
   and insecure pre-existing artifacts fail closed.
4. Provision a non-zero, purpose-separated `RecoveryIntegrityKey` through the
   approved secret boundary. It authenticates plans, workflow journals, and
   quarantine manifests. It is not an HKMS payload-encryption key and must not
   be logged, serialized into the plan, or stored beside the backups.
5. Construct `RecoveryContext` only after management authentication. Configure
   a default-deny `RecoveryAuthorizer`, a durable `AuditSink`, and a
   `RecoveryObserver`. There is no allow-all or best-effort-audit production
   constructor.
6. Select explicit non-zero `RecoveryLimits` for database size, snapshot size,
   rows, per-value bytes, cumulative value bytes, and inspection duration.
   Budget exhaustion is an abort, not permission to skip evidence.
7. Ensure every node runs the same recovery-capable SDK and schema before
   beginning. Do not mix old and new recovery implementations within one
   campaign.

## Choose the authority mode

### Verified current-format minority repair

Choose `RecoveryDecisionBasis::VerifiedCommittedMajority` only when a strict
majority independently proves the exact same current Openraft cluster,
configuration, committed index, fully applied checkpoint, membership, and
branch digest. The selected targets must be an explicit minority, must exclude
the source, and must differ from the proved branch. The workflow does not vote,
elect a leader, infer a majority-visible prefix, or commit a log entry.

If the strict-majority proof cannot be reproduced, stop. Do not downgrade a
current-format fork to legacy confirmation.

### Explicit legacy checkpoint campaign

Choose `RecoveryDecisionBasis::ExplicitLegacyCheckpoint` only when every
replica is legacy format and no durable commit proof exists. The operator must
select one exact source and explicitly enumerate every fleet member as a
target, including that source. Execution requires confirmation bound to the
sealed plan and source branch plus this exact acknowledgement:

```text
ACKNOWLEDGE-UNPROVEN-LEGACY-BRANCH-DISCARD
```

This acknowledgement means the selected checkpoint is an operator decision,
not an SDK inference. Every non-selected branch remains available in its
authenticated quarantine backup.

## Procedure

1. Call `LegacyForkRecovery::plan` with the exact identity, voter set, replica
   set, source, target set, decision basis, and limits. Review the returned
   evidence, source branch digest, target tokens, next recovery epoch, and
   global fence/credential high-waters. Repeated planning over unchanged files
   must produce the same plan digest and must not modify a replica.
2. Obtain the required confirmation for that exact plan. Never reuse a
   confirmation after replanning or after any replica file changes.
3. Call `LegacyForkRecovery::execute` with the same full replica set and private
   backup root. It performs, in order:

   - full-fleet re-inspection and authority/high-water revalidation;
   - an HMAC-authenticated quarantine backup for every selected target;
   - creation and verification of one immutable source checkpoint;
   - creation of one staged image bound to the pending epoch and plan digest;
   - atomic installation on each explicitly selected target; and
   - a sealed transition to `awaiting_epoch_commit`.

4. Keep the fleet drained. Start the recovered Openraft members under the exact
   admitted identity and membership. A pending member may exchange Raft traffic
   so the cluster can form, but ordinary session operations and readiness stay
   blocked.
5. Route `LegacyForkRecovery::finalize` to the current leader's local
   administrative boundary. The generic peer RPC surface cannot forward or
   authorize this command. Finalization commits the exact epoch/digest and
   preserved high-waters through Openraft, deactivates old leases, advances the
   allocation floors, and runs the ordinary durable-readiness barrier.
6. Resume traffic only after the returned and durably journaled state is
   `rejoined`, `opc_session_store_operator_recovery_required` is `0`, and the
   normal durable-readiness probe is ready on the expected members.
7. Retain quarantine artifacts according to the incident and data-retention
   policy. They contain encrypted session envelopes and host-visible metadata;
   treat them as sensitive production storage even though payload plaintext is
   not introduced by recovery.

## Crash-safe resume

Reuse the same sealed plan, integrity key, exact replica set, confirmation, and
backup root. Do not delete individual artifacts or create a new source choice.
The workflow authenticates its journal, every target manifest, the immutable
checkpoint, and the staged image before continuing.

| Durable state | Meaning | Safe next action |
| --- | --- | --- |
| `planned` | No target replacement is recorded. | Resume `execute`; it will re-prove the full fleet before backup. |
| `backup_verified` | All target quarantines and the immutable checkpoint are durable. | Resume `execute` with the exact same inputs. |
| `awaiting_epoch_commit` | Selected targets are installed and readiness-fenced. | Form the exact Openraft fleet, then call `finalize` on the local leader. |
| `epoch_committed` | Openraft committed fencing, but the rejoin barrier is incomplete. | Resume `finalize`; do not serve traffic. |
| `rejoined` | The epoch and fresh durable-readiness barrier completed. | Admit service after ordinary product readiness checks. |
| `audit_pending` | A side effect completed but its success audit was unavailable. | Restore the audit sink and resume the same operation; keep readiness blocked. |

## Abort matrix

| Signal | Interpretation | Required response |
| --- | --- | --- |
| `AuthorizationDenied` or audit intent failure | The privileged boundary did not authorize or durably record intent. | Stop; correct management authentication/authorization/audit. No recovery mutation is permitted. |
| `WrongCluster` | Persisted identity differs from the requested cluster/configuration. | Stop and correct inventory. Never rewrite identity to make it match. |
| `InsufficientAuthority` | A current-format source lacks strict committed-majority proof. | Restore members/connectivity or escalate; never guess a branch. |
| `RecoveryInProgress` | At least one replica carries a pending epoch/digest. | Resume the exact sealed workflow that owns it. Do not create a new plan. |
| `SourceChanged` or `StalePlan` | Source, target set, evidence, membership, or high-water changed. | Stop, preserve artifacts, and create a new read-only plan only after resolving the change. |
| `BackupCorrupt` | A journal, manifest, checkpoint, snapshot, or staged digest/MAC failed. | Stop and preserve the backup root for investigation. Never bypass verification. |
| `WorkLimitExceeded` | A size, row, value, cumulative-byte, or duration budget was reached. | Increase an approved bound or reduce the offline input; do not skip validation. |
| `ConsensusUnavailable` | No local leader commit or fresh durable-readiness barrier completed. | Keep traffic drained, restore exact peer connectivity, and resume `finalize`. |
| `RecoveryEpochRejected` | The state machine observed a stale/conflicting epoch, digest, or high-water. | Stop and reconcile the workflow/cluster identity. Never force the epoch locally. |

## Journal cursor and legacy-log handling

A legacy replication-log tail can be contiguous and structurally valid without
proving that it produced the selected checkpoint. Recovery therefore retains
that tail only in quarantine. The converted Openraft runtime clears the legacy
log, preserves its sequence as the application high-water, and records a
watch-cursor invalidation floor. Reads or watches starting at or below that
floor fail closed; new committed application entries continue above it.

## Encryption and HKMS boundary

Recovery copies and validates already-sealed `EncryptedSessionPayload`
envelopes. It does not decrypt records, call HKMS/KMS, persist provider handles,
or place payload keys in Openraft commands, snapshots, plans, audit events, or
metrics. Historical payload-key availability remains the responsibility of the
outer `EncryptingSessionBackend` or `RemoteSealingSessionBackend` and its key
provider. Recovery protects payload-envelope confidentiality; it is not
full-file encryption, so SQLite/Openraft metadata and envelope key IDs remain
visible to the host storage boundary.

## Observability

The observer emits the fixed states above and the low-cardinality alarms
`operator_recovery_required`, `operator_recovery_aborted`, and
`operator_recovery_audit_pending`. The metrics surface is identifier-free:

- `opc_session_store_operator_recovery_attempts_total`
- `opc_session_store_operator_recovery_failures_total`
- `opc_session_store_operator_recovery_required`
- `opc_session_store_operator_recovery_epoch`
- `opc_session_store_operator_recovery_rejoins_total`

Audit events use the fixed schema path
`/opc-session-store:legacy-recovery`, the authenticated principal and request
ID supplied by the management boundary, and the plan digest as transaction ID.
Plans, metrics, alarms, and error variants do not expose replica IDs, paths,
session identifiers, payloads, trust material, or raw provider errors.
