# Operator Lifecycle Foundation (`operator-lifecycle`)

This crate provides the core lifecycle, preflight admission, config-apply evaluation, and drain/upgrade planning primitives for OpenPacketCore deployment readiness. It is designed to be deterministic and unit-testable without a live Kubernetes cluster or out-of-process dependencies.

> [!IMPORTANT]
> **Scope & Status:** This crate defines the stable lifecycle and admission *models* and *validation contracts*. It does not implement a live Kubernetes controller, controller manager, or Custom Resource Definition (CRD) webhook. Those components will consume this library when implemented in future workstreams.

## Core Components

### 1. Stable Lifecycle Phases & Conditions (`phase`)
Defines the `LifecyclePhase` state machine:
- `Pending`, `Installing`, `Starting`, `Ready`, `Degraded`, `Draining`, `Upgrading`, `RollingBack`, `Failed`, `RecoveryRequired`

And Kubernetes-style conditions (`LifecycleCondition`):
- `Ready`, `Progressing`, `Degraded`, `ConfigApplied`, `DrainComplete`, `RollbackAvailable`, `RecoveryRequired`

All condition updates enforce **monotonic transitions** in observed generation and timestamp. Transitions are only written if status or reason changes, preserving transition times for static states.

### 2. Config-Apply Evaluation (`config_apply`)
Implements `evaluate_config_apply` and rollback target resolution:
- Enforces **commit-confirmed semantics and rollback deadlines**. If a commit-confirmed config expires without confirmation, it triggers a rollback to the previous confirmed version.
- Unsafe upgrades are blocked while a configuration is pending confirmation.
- `RecoveryRequired` states block any new configuration apply.
- Active `Critical` alarms block rollout/upgrade.
- `Degraded` states allow only rollback or safe recovery operations.
- The rollback target evaluator always filters for confirmed configurations, never selecting a pending/unconfirmed version.

### 3. Preflight Admission check (`admission`)
Validates spec properties suitable for Kubernetes admission control:
- Rejects production specs claiming high-availability (HA) while using single-node SQLite/Fake config or session backends.
- Requires the consensus config backend and quorum session backend for production HA claims.
- Rejects missing or unsafe admin auth configurations (insecure/short tokens).
- Rejects missing KMS or SPIFFE identities in production mode.
- Rejects missing production resource profiles.
- Validates CPU pinning layouts, requiring isolated cores and exclusive scheduling for fast-path data-planes in production.
- **Redacts all client-visible error/denial messages** to ensure they do not leak paths, tokens, subscriber IDs (IMSI/SUPI), PEM blocks, SQL, or raw config blobs.

### 4. Drain & Upgrade Planning Primitives (`drain_upgrade`)
Given the current node state, alarms, config version, and session HA state, produces an action plan:
- Triggers NRF deregistration and session draining before configuration applications.
- Injects waits for session store quorum catch-up when replication is degraded.
- Blocks and records reasons if active `Critical` alarms or recovery fences are present.

## Testing & Conformance

Run crate-specific tests:
```bash
cargo test -p operator-lifecycle --all-features
```
All components are fully validated to fail-closed under production policy violations.
