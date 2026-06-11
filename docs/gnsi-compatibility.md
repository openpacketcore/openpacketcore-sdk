# gNSI Compatibility Classification

This document classifies and describes the gNSI compatibility of the OpenPacketCore SDK security policy administration substrate.

## Classification: gNSI-Inspired SDK API

The implementation in the `opc-persist` crate (`SecurityPolicyService` and `SqliteSecurityPolicyService`) is a **gNSI-inspired SDK API**. It is designed to act as the backend domain engine that maps directly to gNSI gRPC service definitions, but is not itself an exact gNSI protobuf/gRPC server implementation.

### Rationale

1. **Abstractions and Scope**: The SDK exposes a programmatic Rust trait interface (`SecurityPolicyService`) rather than directly exposing gRPC network endpoints. This enables local library-level or actor-level wiring within cloud-native network functions (CNFs) without requiring an in-process gRPC server for local calls.
2. **Backend Engine**: The service manages the complete state machine required by gNSI: staging policies, executing lockout checks (validating candidate rules against `/security:policy` paths), performing atomic applies (swapping active policy, invalidating caches), tracking history, and running rollbacks (both explicit version targets and transaction-level rollbacks).
3. **gNSI Facade Ready**: A future gRPC facade crate (such as `opc-gnsi-server`) will map standard gNSI pathz and authz RPC requests (such as `Rotate`, `Install`, `Get`, `Rollback`) directly to the corresponding methods in `SecurityPolicyService`.

---

## Service Mapping Matrix

| gNSI RPC / Concept | `SecurityPolicyService` API | Behavior & Integrity |
|:---|:---|:---|
| **Staging Candidate** | `stage_policy(tenant, principal, policy)` | Serializes and encrypts the candidate policy using `KeyPurpose::ShadowSecurity` key lane, storing it in the `staged_security_policy` table. |
| **Lockout Verification** | `validate_policy(tenant, principal)` | Compiles the staged candidate and evaluates it against the administrative path `/security:policy` for `NacmAction::SecurityAdmin`. Fails if denied. |
| **Atomic Apply** | `apply_policy(tenant, principal)` | Performs lockout validation, verifies version is newer, swaps the active database row, updates the history ledger, clears the staged table, and invalidates the in-memory evaluator cache. |
| **Dry Run** | `dry_run_policy(tenant, principal, path, action)` | Simulates NACM rule evaluation on the staged candidate without modifying active state. |
| **Rollback** | `rollback_policy(tenant, principal, target)` | Validates the rollback target (lockout checks) and swaps it back to active status in the database. Supports target types: `Previous`, `ByVersion`, `ByTxId`, `ByLabel`. |
| **Telemetry / History** | `inspect_active_policy` & `list_policy_history` | Exposes policy metadata and historical transition records. |

---

## Security and Tenancy Controls

1. **SPIFFE Tenant Verification**: Tenant identifiers are cryptographically extracted from the principal's validated SPIFFE ID (e.g. `spiffe://<td>/tenant/<tenant-id>/...`) and checked against the target tenant parameter. Mismatches are rejected with `Unauthorized`.
2. **Access Control**: Mutations require the caller to possess the `"security-admin"` role and be authorized against the active NACM policy for `/security:policy` and `NacmAction::SecurityAdmin`.
3. **Audit Trails**: Every lifecycle transition (stage, validation success/failure, dry-run, apply, rollback) is logged in structured JSON formats and appended to the HMAC-chained `security_policy_audit` table.
4. **Encryption at Rest**: Staged, active, and historical policies are encrypted using `AES-256-GCM-SIV`. The AAD binds explicitly to the tenant name, version number, and `KeyPurpose::ShadowSecurity`.
5. **Error Redaction**: Internal database paths, SQL commands, and key lane details are caught, trace-logged internally, and returned to clients as sanitized `SecurityPolicyError` variants to prevent information leaks.
