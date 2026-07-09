# operator-lifecycle

## Purpose

`operator-lifecycle` is the pure Rust lifecycle contract shared by
OpenPacketCore operators. It defines admission, compatibility, config-apply,
drain/upgrade planning, Kubernetes-style lifecycle status, and reconcile/status
intent models.

The crate does not call Kubernetes, run webhooks, patch status, or execute
drains. Those responsibilities live in `operator-controller` or product
controllers.

## API Shape

- `CONTRACT_VERSION`: Rust-to-Go JSON boundary version used by
  `operator-lifecycle-cli`.
- Admission: `AdmissionRequest`, `AdmissionResponse`, `AdmissionStatus`,
  `AdminAuthSpec`, `IdentitySpec`, `ResourceProfileSpec`,
  `IpsecNetworkAttachmentSpec`, `evaluate_admission`,
  `ipsec_gateway_profile_from_spec`, and `sanitize_denial_message`.
- Compatibility: `CompatibilityMatrix`, `CompatibilityRule`,
  `CompatibilityDecision`, `CompatibilityBlockReason`,
  `CompatibilityEvidence`, release descriptors, supported ranges, and migration
  compatibility descriptors.
- Config apply: `evaluate_config_apply`, `evaluate_rollback_target`,
  `CandidateMetadata`, `StoredConfigMetadata`, `PendingConfirmationState`, and
  `ConfigApplyDecision`.
- Drain/upgrade planning: `generate_upgrade_plan`, `UpgradePlan`, and
  `UpgradeAction`.
- Lifecycle status: `LifecycleStatus`, `LifecycleCondition`, `LifecyclePhase`,
  `ConditionStatus`, and `ConditionSeverity`.
- Reconcile/status intent: `CnfWorkloadIntent`, image/replica/placement/network
  and management intent types, `StatusPatchIntent`, `TrafficStatusIntent`,
  `OwnedStatusProjection`, `ConflictRetryIntent`, `reject_app_config_fields`,
  and `lifecycle_condition_intent`.

## Usage

```rust,no_run
use operator_lifecycle::{LifecyclePhase, LifecycleStatus};

let mut status = LifecycleStatus::new(42);
status.set_phase(LifecyclePhase::Ready);
assert_eq!(status.phase, LifecyclePhase::Ready);
```

## Relationships

- Uses `opc-node-resources` for data-plane preflight checks.
- Used by `operator-controller` for executor-layer algorithms.
- Exposed to non-Rust controllers through `operator-lifecycle-cli`.

## Status And Limits

- Production-readiness rules are implemented for admission, compatibility,
  commit-confirmed config apply, preflight integration, drain/upgrade planning,
  and redaction-safe lifecycle status.
- Lifecycle conditions serialize with Kubernetes-style camelCase fields and
  RFC3339 `lastTransitionTime`; legacy tuple timestamps still deserialize.
- App config payloads are intentionally rejected at platform spec/status
  boundaries; only redaction-safe metadata belongs here.
- The crate is pure logic. Kubernetes API integration, watch loops, webhook
  servers, and external drain clients are outside this crate.

## Roadmap

- Increment `CONTRACT_VERSION` when the JSON envelope shape changes.
- Keep compatibility and migration policy explicit rather than inferred.
- Add new operator decisions as pure functions first, then wire them through
  controller or CLI adapters.

## Verification

```sh
cargo test -p operator-lifecycle
```
