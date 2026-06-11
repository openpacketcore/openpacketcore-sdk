# OpenPacketCore SDK Refactoring: Module Boundaries

This document details the refactoring of large production and test files in the OpenPacketCore SDK. The structural refactor breaks monolithic files down into coherent, domain-scoped modules without changing behavioral patterns or public contracts.

---

## Refactoring Overview

The primary objectives achieved during this refactoring are:
1. **Separation of Concerns**: Extracted domain responsibilities into clear modules.
2. **Maintained Public Facades**: Retained original `lib.rs` exports and API signatures to prevent downstream breaking changes.
3. **Improved Test Maintainability**: Segmented integration test suites by feature group and extracted shared fixtures to common test modules.
4. **No Codebase Fragmentation**: Avoided general `utils.rs` or arbitrary file splits. Every file corresponds to a specific responsibility.
5. **No Semantic Changes**: Verified all tests pass sequentially and that the behavior remains identical to the original implementation.

---

## Structural Module Layout

### 1. `opc-node-resources`
* **Facade**: [lib.rs](../../crates/opc-node-resources/src/lib.rs)
* **Domain Modules**:
  * [types.rs](../../crates/opc-node-resources/src/types.rs): Profiles, capabilities, and evidence structs.
  * [cpu.rs](../../crates/opc-node-resources/src/cpu.rs): CPU isolation, topology policy check, and core validation.
  * [numa.rs](../../crates/opc-node-resources/src/numa.rs): NUMA topology and affinity checking.
  * [hugepages.rs](../../crates/opc-node-resources/src/hugepages.rs): Hugepage pool validation and memory checking.
  * [network.rs](../../crates/opc-node-resources/src/network.rs): SR-IOV and AF_XDP NIC interface verification.
  * [bpf.rs](../../crates/opc-node-resources/src/bpf.rs): BPF digest, signature, and capabilities check.
  * [pod_security.rs](../../crates/opc-node-resources/src/pod_security.rs): hostPath / privilege escalation exception checking.
  * [validation.rs](../../crates/opc-node-resources/src/validation.rs): Entry point orchestration.
  * [tests.rs](../../crates/opc-node-resources/src/tests.rs): Unit and validation tests.

### 2. `opc-persist`
* **Facade**: [src/lib.rs](../../crates/opc-persist/src/lib.rs)
* **Backend Database Modules**:
  * [backend/mod.rs](../../crates/opc-persist/src/backend/mod.rs): Main SqliteBackend facade.
  * [backend/ops.rs](../../crates/opc-persist/src/backend/ops.rs): Local store CRUD and commit state checks.
  * [backend/replication.rs](../../crates/opc-persist/src/backend/replication.rs): Consensus WAL logs and snapshot saves.
* **Consensus Modules**:
  * [consensus/mod.rs](../../crates/opc-persist/src/consensus/mod.rs): Consensus facade & engine orchestration.
  * [consensus/types.rs](../../crates/opc-persist/src/consensus/types.rs): State definitions and client request frames.
  * [consensus/membership.rs](../../crates/opc-persist/src/consensus/membership.rs): Quorum voter promotion/removal.
  * [consensus/election.rs](../../crates/opc-persist/src/consensus/election.rs): Campaigns and candidate/leader role transitions.
  * [consensus/replication.rs](../../crates/opc-persist/src/consensus/replication.rs): AppendEntries logs replicate and index tracking.
  * [consensus/read_index.rs](../../crates/opc-persist/src/consensus/read_index.rs): Linearizable client queries validation.
  * [consensus/snapshot.rs](../../crates/opc-persist/src/consensus/snapshot.rs): Compact snapshots saving and verification.
  * [consensus/transport.rs](../../crates/opc-persist/src/consensus/transport.rs): TCP RPC network bounds framing.
  * [consensus/identity.rs](../../crates/opc-persist/src/consensus/identity.rs): SPIFFE cert credentials checker.
* **Security Policy Modules**:
  * [security_policy/mod.rs](../../crates/opc-persist/src/security_policy/mod.rs): Entry point.
  * [security_policy/service.rs](../../crates/opc-persist/src/security_policy/service.rs): Main security policy validator.
  * [security_policy/break_glass.rs](../../crates/opc-persist/src/security_policy/break_glass.rs): Break-glass session lifetime admin checker.
  * [security_policy/crypto.rs](../../crates/opc-persist/src/security_policy/crypto.rs): Low-level cryptographic validation helper routines.

### 3. `opc-config-bus`
* **Facade**: [lib.rs](../../crates/opc-config-bus/src/lib.rs)
* **Domain Modules**:
  * [types.rs](../../crates/opc-config-bus/src/types.rs): Shared error variants and event records.
  * [authorizer.rs](../../crates/opc-config-bus/src/authorizer.rs): Configuration access authority control guards.
  * [datastore.rs](../../crates/opc-config-bus/src/datastore.rs): Managed database access traits.
  * [commit.rs](../../crates/opc-config-bus/src/commit.rs): Config transaction validation and deadline commitments.
  * [rollback.rs](../../crates/opc-config-bus/src/rollback.rs): Transaction rollbacks and validation constraints.
  * [restore.rs](../../crates/opc-config-bus/src/restore.rs): Startup database repair and journal recovery checks.
  * [subscribers.rs](../../crates/opc-config-bus/src/subscribers.rs): Event message distribution queueing.
  * [alarms.rs](../../crates/opc-config-bus/src/alarms.rs): Active transaction error alerts raising handler.
  * [metrics.rs](../../crates/opc-config-bus/src/metrics.rs): Bus operations performance counters.

### 4. `opc-alarm`
* **Facade**: [src/lib.rs](../../crates/opc-alarm/src/lib.rs)
* **Manager Modules**:
  * [manager/mod.rs](../../crates/opc-alarm/src/manager/mod.rs): Main AlarmManager facade.
  * [manager/state.rs](../../crates/opc-alarm/src/manager/state.rs): Active alarms deduplication lookup table.
  * [manager/admin.rs](../../crates/opc-alarm/src/manager/admin.rs): Acknowledge and suppress administration operations.
  * [manager/audit.rs](../../crates/opc-alarm/src/manager/audit.rs): Redacted audit trail entries generator.
  * [manager/metrics.rs](../../crates/opc-alarm/src/manager/metrics.rs): Alert statistics update helpers.
  * [manager/security.rs](../../crates/opc-alarm/src/manager/security.rs): Safe suppress verification logic.
  * [manager/tests.rs](../../crates/opc-alarm/src/manager/tests.rs): Alert handling behavior validation test suite.

### 5. `opc-runtime`
* **Facade**: [lib.rs](../../crates/opc-runtime/src/lib.rs)
* **Supervisor Modules**:
  * [supervisor/mod.rs](../../crates/opc-runtime/src/supervisor/mod.rs): Main runtime worker supervisor facade.
  * [supervisor/task.rs](../../crates/opc-runtime/src/supervisor/task.rs): Running task profiles metadata model.
  * [supervisor/spawn.rs](../../crates/opc-runtime/src/supervisor/spawn.rs): Process admission limits and security isolation checker.
  * [supervisor/heartbeat.rs](../../crates/opc-runtime/src/supervisor/heartbeat.rs): Keepalive checking.
  * [supervisor/restart.rs](../../crates/opc-runtime/src/supervisor/restart.rs): Backoff timing when restart loops are detected.
  * [supervisor/shutdown.rs](../../crates/opc-runtime/src/supervisor/shutdown.rs): Draining state and SIGTERM/SIGKILL handlers.
  * [supervisor/metrics.rs](../../crates/opc-runtime/src/supervisor/metrics.rs): Process lifecycle statistics.
  * [supervisor/tests.rs](../../crates/opc-runtime/src/supervisor/tests.rs): Lifecycle test scenarios.

### 6. `opc-session-store`
* **Facade**: [src/lib.rs](../../crates/opc-session-store/src/lib.rs)
* **Fake Backend**:
  * [fake/mod.rs](../../crates/opc-session-store/src/fake/mod.rs): Thread-safe in-memory session database mock.
  * [fake/tests.rs](../../crates/opc-session-store/src/fake/tests.rs): Mock storage behavior validation.
* **SQLite Backend**:
  * [sqlite/mod.rs](../../crates/opc-session-store/src/sqlite/mod.rs): SQLite session db interface.
  * [sqlite/lease.rs](../../crates/opc-session-store/src/sqlite/lease.rs): Keep-alive sessions lease management.
  * [sqlite/ops.rs](../../crates/opc-session-store/src/sqlite/ops.rs): Session entries CRUD and compare-and-swap checks.
  * [sqlite/replication.rs](../../crates/opc-session-store/src/sqlite/replication.rs): Multi-node sqlite session sync operations.
  * [sqlite/watch.rs](../../crates/opc-session-store/src/sqlite/watch.rs): DB events change stream observer subscription hooks.

### 7. `opc-key`
* **Facade**: [lib.rs](../../crates/opc-key/src/lib.rs)
* **Domain Modules**:
  * [provider.rs](../../crates/opc-key/src/provider.rs): HSM / KMS access interfaces.
  * [memory.rs](../../crates/opc-key/src/memory.rs): Mock keys database.
  * [kms.rs](../../crates/opc-key/src/kms.rs): Remote secure vault connector.
  * [scope.rs](../../crates/opc-key/src/scope.rs): Multi-tenant secure scopes and usage policies.
  * [errors.rs](../../crates/opc-key/src/errors.rs): Secure error text scrubbers.
  * [tests.rs](../../crates/opc-key/src/tests.rs): Key management tests.

---

## Remaining Large Files

A few files remain above 1000 LOC after the first structural pass:
* **`crates/opc-alarm/src/manager/tests.rs` (~1935 LOC)**: Unit test module extracted from `manager.rs`; it should be split further by alarm lifecycle/admin/readiness groups in a follow-up test-only cleanup.
* **`crates/opc-node-resources/src/tests.rs` (~1836 LOC)**: Unit test module extracted from `lib.rs`; it should be split further by CPU/NUMA/network/BPF/pod-security validation groups.
* **`crates/opc-redaction/src/metrics.rs` (~1476 LOC)**: Static metrics scrubber and metric registry implementation, currently below the 1500 LOC hard limit but still a candidate for a future metrics-family split.
* **`crates/opc-sdk-integration/src/lib.rs` (~1328 LOC)**: SDK integration facade containing initialization routines and re-exports, currently below the 1500 LOC hard limit.

No integration test file introduced by this refactor remains above the 1500 LOC target. The confirmed-commit suite was split into admission, idempotency, persistence/error handling, and confirmed-deadline files after review.

---

## Top 20 Files Line Count Table

Here is the comparison of the largest files in the repository before and after the refactoring.

| Filename | Before LOC | After LOC | Status / Split Layout |
|---|---|---|---|
| `crates/opc-config-bus/tests/config_bus.rs` | 4,057 | - | Deleted (Split into 9 distinct files + `config_bus_common/`) |
| `crates/opc-node-resources/src/lib.rs` | 3,933 | 185 | Facade remains; implementation split across 8 domain modules. |
| `crates/opc-persist/src/consensus.rs` | 3,783 | - | Deleted (Split into 10 domain modules under `consensus/`) |
| `crates/opc-config-bus/src/lib.rs` | 2,985 | 120 | Facade remains; implementation split across 9 domain modules. |
| `crates/opc-alarm/src/manager.rs` | 2,902 | - | Deleted (Split into 6 domain modules under `manager/`) |
| `crates/opc-evidence/tests/evidence_pipeline.rs` | 2,409 | - | Deleted (Split into 12 integration files + `evidence_common/`) |
| `crates/opc-runtime/src/supervisor.rs` | 2,119 | - | Deleted (Split into 7 domain modules under `supervisor/`) |
| `crates/opc-session-store/src/fake.rs` | 2,041 | - | Deleted (Split into `fake/mod.rs` & `fake/tests.rs`) |
| `crates/opc-persist/src/backend.rs` | 1,958 | - | Deleted (Split into `backend/mod.rs` & submodules) |
| `crates/opc-alarm/src/manager/tests.rs` | - | 1,935 | New (Extracted test file from `manager.rs`) |
| `crates/opc-persist/src/security_policy.rs` | 1,900 | - | Deleted (Split into `security_policy/mod.rs` & submodules) |
| `crates/opc-node-resources/src/tests.rs` | - | 1,836 | New (Extracted test file from `lib.rs`) |
| `crates/opc-session-store/src/sqlite.rs` | 1,724 | - | Deleted (Split into `sqlite/mod.rs` & submodules) |
| `crates/opc-key/src/lib.rs` | 1,719 | 90 | Facade remains; split across 5 domain files + `tests.rs`. |
| `crates/opc-config-bus/tests/config_bus_confirmed_commit.rs` | - | 533 | New (Confirmed-deadline tests extracted from `config_bus.rs`) |
| `crates/opc-runtime/src/lib.rs` | 1,617 | 110 | Facade remains; split across 4 domain files + `tests.rs`. |
| `crates/opc-redaction/src/metrics.rs` | 1,476 | 1,476 | Unchanged (Static metrics scrubbers registry). |
| `crates/operator-lifecycle/tests/lifecycle_tests.rs` | 1,455 | - | Deleted (Split into 6 integration files + `lifecycle_common/`) |
| `crates/opc-runtime/tests/graceful_shutdown.rs` | 1,422 | 1,422 | Unchanged (Pre-existing integration test). |
| `crates/opc-sdk-integration/tests/fault_injection.rs` | 1,419 | 1,419 | Unchanged (Pre-existing integration test). |
| `crates/opc-sdk-integration/src/lib.rs` | 1,328 | 1,328 | Unchanged (SDK entry facade). |
