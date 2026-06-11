# opc-amf-lite

`opc-amf-lite` is the first real NF-style vertical integration slice designed to prove the OpenPacketCore SDK foundation seams end-to-end without toy bypasses. It models a realistic Access and Mobility Management Function (AMF) control-plane slice, verifying the composition of the SDK subsystems under real lifecycles, configuration commits, security keying, alarms, metrics, and HA/recovery paths.

## SDK Seams Proved
The vertical slice integrates and verifies the following core SDK seams:
1. **Runtime & Supervision**: Starts, runs, and shuts down under `opc-runtime` supervision, using readiness hooks and SIGTERM graceful drain.
2. **Transactional Config**: Commits configuration updates through the secure-by-default `ConfigBus`, utilizing standard validator and authorizer boundaries, persisted dynamically to a multi-node `ConsensusConfigStore`.
3. **Quorum Session Store**: Manages subscriber context and session states in a replicated `QuorumSessionStore` using monotonic fences, lease guards, and compare-and-set (CAS) operations.
4. **Identity & KMS Keying**: Workload transport verification integrates SPIFFE/mTLS certificates, and dynamic AEAD envelope encryption keys are retrieved from a secure production KMS provider boundary (unix-socket endpoint).
5. **NACM & Auditing**: Limits administrative actions via standard `NacmPolicy` rules, writing tamper-evident audit logs to a durable persistence backend.
6. **Alarms & Observability**: Emits alarms for lifecycle, config, and session storage failures to the runtime-owned `SharedAlarmManager`. System metrics are exposed via the HTTP admin router.

## Testing & HA Failover
The integration test suite under `tests/amf_lite_tests.rs` covers:
- **E2E Happy Path**: Complete lifecycle from startup, registration, config commit, session context creation/mutation, to graceful drain.
- **HA Failover & Recovery**: Config leader crash and failover (Raft consensus promotion) combined with session replica network drops, rejoin, catch-up, and read-repair.
- **Security & Redaction**: Default-deny NACM policy blocking unauthorized roles, KMS timeouts failing closed, and redaction verification of subscriber IDs (IMSI) in Prometheus metrics.

## Running Tests
Run the focused test suite directly:
```bash
cargo test -p opc-amf-lite --all-features -- --test-threads=1
```
