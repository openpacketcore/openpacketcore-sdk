# OPC-SDK-RFC-009: Operator Lifecycle, Upgrade, Migration, and Rollback

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: operator authors, NF owners, release engineers, SREs

## 1. Abstract

This RFC defines the lifecycle contract between the OpenPacketCore Kubernetes
operator, lifecycle CRDs, canonical YANG configuration, NF pods, persistent
state, and release artifacts. It specifies reconciliation phases, version skew,
CRD conversion, YANG schema migration, state migration, rollout strategies,
rollback, drain, status conditions, and release gates.

This RFC turns the thin-CRD/fat-YANG pattern into an upgrade-safe product
contract across all CNFs.

## 2. Scope

### 2.1 In Scope

- Lifecycle CRD reconciliation.
- Operator/NF version compatibility.
- CRD versioning and conversion webhooks.
- Canonical config revision and schema migration.
- NF image rollout strategies.
- Session-aware drain and handover coordination.
- Rollback and downgrade policy.
- Status, events, and GitOps health gates.
- Multi-cluster rollout topology.

### 2.2 Out of Scope

- Runtime process shutdown internals. See RFC 008.
- Session storage primitives. See RFC 004.
- Evidence bundle generation. See RFC 006.
- Node resource scheduling. See RFC 011.

## 3. Design Goals

### 3.1 Security

- Prevent unsigned, unverified, or policy-disallowed images from rolling out.
- Prevent config downgrades that bypass validation or reintroduce forbidden
  settings.
- Ensure rollback preserves audit and does not silently lose regulated data.
- Keep break-glass upgrade paths narrow, explicit, and auditable.

### 3.2 Performance

- Rollouts must avoid unnecessary full-cluster disruption.
- Stateful NFs must drain or transfer ownership before termination.
- Operator reconciliation must avoid hot loops and unbounded API traffic.
- Large config migrations must be staged and observable.

### 3.3 Maintainability

- Every lifecycle phase has stable names, conditions, and event reasons.
- Compatibility matrices are machine-readable.
- Migration functions are versioned, deterministic, and tested.
- Per-NF deviations are explicit.

### 3.4 Functionality

- Support install, update, scale, config change, restart, drain, rollback,
  restore, and delete.
- Support CRD conversion webhooks.
- Support canary and partitioned rollouts.
- Support GitOps promotion gates.

## 4. Version Model

### 4.1 Versions

The operator tracks:

- operator version,
- CRD API version,
- lifecycle contract version,
- NF image version and digest,
- NF binary SDK version,
- YANG schema digest,
- canonical config revision,
- session state schema version,
- evidence bundle digest.

### 4.2 Compatibility Matrix

Every release MUST publish:

```yaml
operator: 0.4.0
supports:
  crd_versions: ["v1alpha1", "v1alpha2"]
  lifecycle_contracts: ["v1alpha1"]
  nf_images:
    opc-amf: ">=0.3.0 <0.5.0"
    opc-smf: ">=0.3.0 <0.5.0"
  yang_schema_digests:
    opc-amf:
      - "sha256:..."
```

The operator MUST reject unsupported combinations unless an explicit waiver is
present and policy allows it.

## 5. Lifecycle State Machine

Every reconcile moves through:

| Phase | Purpose |
| :--- | :--- |
| `Admitted` | CR accepted by admission policy |
| `Resolved` | image, config, secrets, devices, and dependencies resolved |
| `Provisioning` | workload resources created/updated |
| `Bootstrapping` | pod reachable and management plane alive |
| `Configuring` | canonical config applied |
| `Verifying` | drift, health, and readiness checked |
| `Ready` | service is available |
| `Draining` | rollout/delete drain in progress |
| `Migrating` | schema/state migration in progress |
| `Degraded` | service impaired but not terminal |
| `Failed` | reconciliation cannot proceed without operator action |
| `Terminating` | deletion finalizers active |

Phase names are public API and MUST be stable.

## 6. Conditions and Events

Required conditions:

- `Admitted`
- `Resolved`
- `Provisioned`
- `Bootstrapped`
- `ConfigResolved`
- `AppConfigApplied`
- `Drift`
- `MigrationReady`
- `MigrationApplied`
- `DrainReady`
- `RollbackAvailable`
- `Ready`

Each condition MUST include:

- status,
- reason,
- message,
- observed generation,
- last transition time.

Event reasons MUST be stable and documented. Events MUST NOT contain secrets or
raw config payloads.

## 7. Admission and Policy

Admission MUST verify:

- image digest present,
- image signature valid,
- evidence bundle available where required,
- CRD field validation,
- canonical config reference exists,
- manual/break-glass authority policy,
- required secrets and service accounts,
- pod security exceptions,
- per-NF node resource references.

Admission should reject failures early rather than allowing a reconcile to fail
late in the workload.

## 8. Canonical Config Lifecycle

### 8.1 Revision

`canonicalConfigRevision` is opaque but immutable for a given config artifact.
Changing config content MUST change the revision or digest.

### 8.2 Apply

The operator applies config through RFC 001 management APIs. It MUST:

- verify schema digest,
- run validate-only before commit where supported,
- use idempotency keys for retries,
- record applied revision and tx ID,
- read back running config for drift detection.

### 8.3 Drift

Drift states:

- `InSync`
- `DriftDetected`
- `BreakGlassActive`
- `ResyncRequired`
- `Unknown`

Runtime state such as counters and sessions MUST be filtered out of drift
comparison.

## 9. CRD Versioning and Conversion

Public lifecycle CRDs MUST use hub-and-spoke conversion once a second served
version exists.

Rules:

- one storage version at a time,
- conversion webhooks are deterministic,
- lossy conversion is forbidden unless the target version has an explicit
  status condition and known gap,
- deprecated fields retain read compatibility for at least one minor release,
- removed fields require migration notes and evidence.

Conversion tests MUST include round trips for every CRD version pair.

## 10. YANG Schema Migration

YANG migration follows RFC 002. Operator responsibilities:

- detect persisted schema digest,
- select migration chain,
- run validate-only against target NF before commit,
- back up previous config envelope before migration,
- record migration tx ID,
- fail closed if migration chain is missing.

Per-NF migrations MUST be deterministic and golden-tested.

## 11. State Migration

Session and durable state migrations are separate from config migrations.

State migration plans MUST define:

- source version,
- target version,
- online/offline mode,
- rollback support,
- validation query,
- maximum expected duration,
- data-loss risk,
- RPO/RTO impact.

Authoritative session migrations MUST preserve RFC 004 generation and fencing
semantics.

## 12. Rollout Strategies

Supported strategies:

| Strategy | Use |
| :--- | :--- |
| `rolling` | stateless or safely drainable NFs |
| `partitioned` | stateful sets and ordered migrations |
| `canary` | high-risk release or config change |
| `blue-green` | major upgrades or incompatible config/state changes |
| `manual` | operator-approved special cases |

Each NF declares allowed strategies.

## 13. Drain and Handover

Before terminating or replacing a pod, the operator MUST invoke or observe NF
drain where the NF is stateful.

Drain contract:

```rust
pub enum DrainMode {
    RejectNewWork,
    TransferOwnership,
    FlushAndStop,
    ImmediateEmergency,
}
```

Drain MUST:

- mark readiness false before removing work,
- stop new session ownership,
- transfer or release leases where possible,
- flush audit and local state,
- respect timeout,
- expose progress in status.

UPF, AMF, SMF, ePDG, N3IWF, SMSC, and IMS NFs MUST define NF-specific drain
behavior.

## 14. Rollback and Downgrade

### 14.1 Rollback

Rollback is allowed when:

- previous image digest is still policy-allowed,
- previous config schema is compatible or migration back exists,
- state schema supports downgrade or state can be rebuilt,
- evidence permits rollback.

### 14.2 Downgrade

Downgrade is forbidden by default for stateful NFs unless explicitly supported.
If downgrade is unsupported, the operator MUST fail before changing workload
resources.

### 14.3 Failed Rollout

On failed rollout:

1. Stop further pod replacement.
2. Preserve logs/events/evidence references.
3. Mark `Degraded` or `Failed`.
4. Attempt rollback only if policy says automatic rollback is safe.
5. Require manual approval for destructive recovery.

## 15. Backup and Restore

Before high-risk migration, the operator MUST ensure backups exist for:

- canonical config,
- shadow-security material where policy allows,
- session state if durable and required,
- audit state,
- CR status needed for recovery.

Restore MUST be tested per NF and recorded in RFC 006 evidence.

## 16. Multi-Cluster Lifecycle

In multi-cluster deployments:

- management cluster owns desired lifecycle state,
- workload clusters own local pod status,
- status aggregation is explicit,
- cluster identity is part of every condition source,
- rollout waves are region-aware,
- rollback can be per-cluster or global.

The operator MUST avoid applying incompatible migrations to only part of a
fenced session ownership domain.

## 17. Observability

Required metrics:

- `opc_operator_reconcile_total{kind,outcome}`
- `opc_operator_reconcile_duration_seconds{kind,phase}`
- `opc_operator_rollout_total{kind,strategy,outcome}`
- `opc_operator_migration_total{kind,type,outcome}`
- `opc_operator_drain_total{kind,outcome}`
- `opc_operator_drift_observations_total{kind,state}`
- `opc_operator_rollback_total{kind,outcome}`
- `opc_operator_version_skew{kind}`

Required status fields:

- current image digest,
- desired image digest,
- applied config revision,
- applied config hash,
- running schema digest,
- last successful tx ID,
- evidence bundle digest,
- migration state.

## 18. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `operator-lifecycle` | shared phase/condition composition |
| `operator-compat` | compatibility matrix parser/evaluator |
| `operator-config-apply` | validate-only, commit, readback |
| `operator-conversion` | CRD conversion webhook helpers |
| `operator-migration` | config/state migration orchestration |
| `operator-rollout` | rolling/canary/blue-green strategies |
| `operator-drain` | NF drain API clients and progress |
| `operator-backup` | backup/restore orchestration |
| `operator-testkit` | fake NF, fake config bus, fake session store |

Agents must keep NF-specific reconcile logic behind interfaces and avoid
duplicating phase/condition code.

## 19. Testing Requirements

### 19.1 Unit Tests

- Compatibility matrix evaluation.
- Phase transition reducer.
- Condition reason stability.
- CRD conversion round trips.
- Migration chain selection.
- Rollback eligibility.

### 19.2 Integration Tests

- Install fresh NF.
- Config-only update.
- Image-only update.
- Image plus config update.
- Failed validate-only blocks rollout.
- Drift detection and resync.
- Canary success and failure.
- Rollback with compatible config.

### 19.3 Fault Injection

- Operator restart mid-rollout.
- NF pod deleted during migration.
- gNMI commit timeout.
- Conversion webhook unavailable.
- Backup failure.
- Session drain timeout.
- Partial multi-cluster rollout failure.

### 19.4 Performance Gates

- Reconcile avoids hot loops under persistent failure.
- 1,000 lifecycle CRs do not exceed configured API QPS.
- Drift compare for large config stays within budget.
- Status update rate is bounded.

## 20. Acceptance Criteria

This RFC is implemented when:

1. Operator/NF/version compatibility is machine-readable and enforced.
2. Lifecycle phases and conditions are stable across all CNFs.
3. Config apply uses RFC 001 validate/commit/readback behavior.
4. CRD conversions are deterministic and tested.
5. YANG and state migrations are explicit and evidence-linked.
6. Stateful rollouts drain or transfer ownership before termination.
7. Rollback eligibility is evaluated before workload mutation.
8. Multi-cluster rollout status is explicit and safe.
