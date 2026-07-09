# operator-controller

## Purpose

`operator-controller` is the execution-layer companion to
`operator-lifecycle`. It provides deterministic CRD conversion helpers,
migration orchestration, out-of-process drain execution contracts,
Kubernetes-style status patch contracts, and multi-cluster rollout aggregation.

It does not include a live Kubernetes webhook server, informer/reconcile loop,
or concrete Kubernetes API client. Those are supplied by product controllers.

## API Shape

- `conversion`: strict `v1alpha1`/`v1beta1` CRD models, defaulting helpers,
  `convert_v1alpha1_to_v1beta1`, `convert_v1beta1_to_v1alpha1`, and
  `ConversionError`.
- `migration`: `MigrationPlan`, `MigrationStep`, `SafetyClassification`,
  `MigrationBlockReason`, `MigrationDriver`, `validate_migration_plan`,
  `evaluate_migration_readiness`, and `execute_migration`.
- `drain`: injected async client traits (`NrfClient`, `SessionDrainClient`,
  `QuorumClient`, `WorkloadFenceClient`), `DrainExecutor`, and fake clients for
  deterministic tests.
- `status_patch`: `StatusPatchClient`, `StatusPatchResourceSnapshot`,
  `StatusPatchClientError`, `StatusPatchOutcome`, `StatusPatchOutcomeKind`,
  `StatusPatchError`, `execute_status_patch`,
  `execute_owned_status_patch`, `status_merge_patch`, and
  `owned_status_merge_patch`.
- `multicluster`: `ClusterRolloutStatus`, `MultiClusterRolloutStatus`, and
  `MultiClusterRolloutPhase`.

## Usage

```rust,no_run
use operator_controller::conversion::{apply_defaults_v1alpha1, v1alpha1};

let mut spec = v1alpha1::NetworkFunctionSpec {
    kind: "upf".to_string(),
    replicas: 1,
    profile: None,
    config_backend: None,
    session_backend: None,
    admin_token: None,
    token_enabled: None,
    resource_profile: None,
};
apply_defaults_v1alpha1(&mut spec);
assert_eq!(spec.config_backend.as_deref(), Some("sqlite"));
```

## Relationships

- Builds on `operator-lifecycle` for admission, phase/status, compatibility,
  config-apply, and drain planning primitives.
- Uses `opc-node-resources`, `opc-alarm`, `opc-runtime`, `opc-config-model`,
  and `opc-config-bus` types where controller decisions cross those contracts.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Safe Rust only (`#![forbid(unsafe_code)]`).
- Conversion helpers are core algorithms, not a TLS-enabled Kubernetes webhook
  server.
- Status patching is expressed through an injected `StatusPatchClient`; no
  concrete Kubernetes client is bundled.
- Drain execution is through injected clients and bounded timeouts; product
  controllers own real NRF/session/quorum/fence integrations.

## Roadmap

- Keep executor contracts injectable so product controllers can choose their
  Kubernetes client/runtime stack.
- Add new CRD versions through explicit conversion/defaulting tests.
- Expand status patch ownership by implementing `OwnedStatusProjection` rather
  than merging unrelated status fields.

## Verification

```sh
cargo test -p operator-controller
```
