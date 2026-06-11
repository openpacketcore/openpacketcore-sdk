# OPC-SDK-RFC-010: Data Governance, Privacy, and Regulated Records

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: security engineers, privacy reviewers, NF owners, LI/charging implementers, SREs

## 1. Abstract

This RFC defines the data governance substrate for OpenPacketCore CNFs. It
standardizes classification, handling, redaction, retention, encryption,
backup, export, audit, and evidence rules for subscriber identifiers, session
records, charging data, lawful-intercept material, analytics, security logs,
and management configuration.

The purpose is to ensure that every CNF treats sensitive telecom data
consistently and that privacy behavior is implemented as an auditable platform
contract, not as scattered per-NF convention.

## 2. Scope

### 2.1 In Scope

- Data classification taxonomy.
- SUPI/GPSI/MSISDN/IP address handling.
- Charging, audit, LI, analytics, and session state records.
- Redaction and pseudonymization.
- Retention and deletion.
- Backup and restore handling.
- Export and external sink policy.
- Tenant/slice/PLMN data boundaries.
- Evidence and test requirements.

### 2.2 Out of Scope

- Cryptographic key management internals. See RFC 003.
- Session store consistency. See RFC 004.
- Evidence bundle mechanics. See RFC 006.
- Jurisdiction-specific legal interpretation.

## 3. Design Goals

### 3.1 Security

- Minimize sensitive data exposure by default.
- Encrypt regulated data at rest and in transit.
- Prevent cross-tenant, cross-slice, and cross-PLMN data leakage.
- Make audit and regulated exports tamper-evident.
- Ensure backup and debug workflows preserve classification.

### 3.2 Performance

- Redaction and classification must be cheap enough for hot-path logging.
- High-volume telemetry must avoid high-cardinality raw identifiers.
- Bulk retention jobs must be bounded and schedulable.
- Analytics minimization must be profile-driven and measurable.

### 3.3 Maintainability

- One classification vocabulary across all CNFs.
- Generated redaction metadata from RFC 002 drives code behavior.
- Retention policies are declarative through YANG.
- Exceptions are structured known gaps or waivers.

### 3.4 Functionality

- Support operational debugging without leaking raw subscriber data.
- Support charging and audit records with correct retention.
- Support LI material with strict plane separation.
- Support analytics minimization and privacy-preserving export.

## 4. Data Classification

### 4.1 Classes

| Class | Examples | Default Handling |
| :--- | :--- | :--- |
| `public` | build version, static feature flags | log/export allowed |
| `operational` | readiness, queue depth, non-sensitive counters | log/export allowed with cardinality controls |
| `network-sensitive` | topology, NF instance IDs, peer FQDNs | restricted logs, auth-gated debug |
| `subscriber-id` | SUPI, IMSI, GPSI, MSISDN, PEI | redacted or keyed digest |
| `subscriber-session` | PDU session, TEID, SEID, IP address, QoS state | encrypted, access-controlled |
| `security-secret` | keys, tokens, credentials, OP/OPc/K | never logged, secret types |
| `charging-record` | CDR, usage, rating inputs | retained/exported by charging policy |
| `lawful-intercept` | warrant, target selectors, X2/X3 products | LI plane only |
| `analytics-sensitive` | NWDAF source events, location, behavior traces | minimized before export |
| `audit-regulated` | admin actions, break-glass, security events | tamper-evident retention |

Each data field in generated models and hand-written domain types MUST be
classified.

### 4.2 Classification Metadata

```rust
pub enum DataClass {
    Public,
    Operational,
    NetworkSensitive,
    SubscriberId,
    SubscriberSession,
    SecuritySecret,
    ChargingRecord,
    LawfulIntercept,
    AnalyticsSensitive,
    AuditRegulated,
}
```

Generated YANG metadata and Rust annotations MUST feed the same classification
registry.

## 5. Identity and Pseudonymization

Raw SUPI/GPSI/MSISDN/PEI MUST NOT appear in:

- metric labels,
- info/warn/error logs,
- ordinary traces,
- backend keys,
- Kubernetes Events,
- unauthenticated debug output.

The default correlation form is a tenant-scoped keyed digest:

```text
digest = HMAC(tenant_privacy_key, data_class || identifier_type || raw_value)
```

Digest keys MUST be purpose-separated from encryption keys. Rotating digest keys
changes correlation IDs; this must be documented in operational runbooks.

## 6. Redaction

Redaction levels:

| Level | Behavior |
| :--- | :--- |
| `drop` | omit the field entirely |
| `mask` | show fixed placeholder |
| `class` | show class and presence only |
| `length-class` | show approximate length bucket |
| `digest` | show keyed digest |
| `cleartext` | allowed only by explicit policy |

`cleartext` is forbidden for `security-secret` and restricted for
`lawful-intercept`.

Redaction MUST apply to:

- logs,
- traces,
- metrics,
- audit views,
- admin/debug endpoints,
- panic hooks,
- error messages,
- test snapshots committed to git.

## 7. Retention Policy

Each data class has a retention policy:

```rust
pub struct RetentionPolicy {
    pub class: DataClass,
    pub min_duration: Option<Duration>,
    pub max_duration: Option<Duration>,
    pub deletion_mode: DeletionMode,
    pub legal_hold_supported: bool,
    pub export_allowed: bool,
}
```

Retention MUST be configured through canonical YANG and surfaced in evidence.

Default posture:

- operational telemetry: short retention,
- audit-regulated: longer tamper-evident retention,
- charging-record: charging policy retention,
- lawful-intercept: legal/LI policy retention,
- security-secret: no export, rotate/delete per key policy.

## 8. Legal Hold and Deletion

Legal hold prevents deletion of matching regulated records. It MUST:

- be authenticated and authorized,
- be audited,
- include scope and expiry,
- be visible to retention jobs,
- not expose target selectors outside authorized LI/audit roles.

Deletion jobs MUST be idempotent and evidence-producing. They MUST avoid
deleting records under legal hold.

## 9. Data Boundaries

The platform enforces boundaries by:

- tenant,
- slice/S-NSSAI,
- PLMN,
- region,
- NF instance,
- data class.

Every storage key, audit query, export job, and backup manifest MUST include
boundary metadata. Cross-boundary export is denied by default.

## 10. Backups and Restore

Backups MUST preserve:

- classification metadata,
- encryption envelope metadata,
- tenant and slice boundary,
- retention policy,
- legal hold flags,
- manifest digests.

Restore MUST verify that destination tenant/slice/PLMN policy allows the data.
Restoring LI or security-secret material into a different environment is denied
unless an explicit recovery policy allows it.

## 11. Charging Records

Charging records are regulated operational records. CNFs that produce charging
data MUST:

- classify records as `charging-record`,
- avoid raw identifiers in logs,
- use durable, auditable write path,
- support duplicate detection/idempotency,
- expose export status,
- test retention and replay behavior.

Charging exports MUST be signed or transmitted over authenticated channels.

## 12. Lawful Intercept Data

LI data is a special class with strict separation:

- X1 management/control material,
- X2 intercept-related information,
- X3 content/user-plane products.

LI records MUST NOT share ordinary audit, telemetry, or debug paths unless the
path is explicitly LI-authorized. LI selectors and products MUST be encrypted,
audited, and retained according to LI policy.

CNFs that are not LI functions MUST NOT adopt LI vocabulary for ordinary
analytics or operational telemetry.

## 13. Analytics and Privacy

Analytics-producing CNFs, especially NWDAF, MUST implement minimization before
export.

Minimization methods:

- field drop,
- coarsening,
- keyed hash,
- aggregation threshold,
- k-anonymity threshold,
- differential privacy noise where policy requires it.

The active minimization policy version MUST be recorded with each analytics
export.

## 14. Debug and Support Bundles

Support bundles MUST:

- exclude secrets by default,
- redact subscriber identifiers,
- include manifest and classification summary,
- require authorization,
- be time-bounded,
- be audited,
- be signed or checksummed.

Debug packet captures are disabled by default and require explicit policy.

## 15. Configuration Model

Shared YANG groupings SHOULD include:

- `data-governance/classification-overrides`
- `data-governance/retention`
- `data-governance/export-policy`
- `data-governance/legal-hold`
- `data-governance/redaction`
- `data-governance/support-bundle`

NF-specific YANG can refine but not bypass the baseline.

## 16. Observability

Required metrics:

- `opc_data_records_total{class,operation,outcome}`
- `opc_data_redactions_total{class,level}`
- `opc_data_retention_deletions_total{class,outcome}`
- `opc_data_legal_holds{class,state}`
- `opc_data_exports_total{class,outcome}`
- `opc_data_policy_version_info{class,version}`
- `opc_data_privacy_minimization_total{method,outcome}`

Metrics MUST NOT use raw subscriber identifiers as labels.

## 17. Evidence Requirements

RFC 006 evidence MUST include:

- classification registry,
- retention policy report,
- redaction test report,
- export policy report,
- legal hold test report where supported,
- privacy minimization report for analytics NFs,
- known gaps for any class not fully handled.

## 18. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-data-classification` | class registry and annotations |
| `opc-redaction` | redaction renderers and generated metadata adapter |
| `opc-privacy` | digesting, minimization, support bundle policy |
| `opc-retention` | retention jobs and legal hold interface |
| `opc-export` | signed/exported data handling |
| `opc-li-governance` | LI class boundaries and policy helpers |
| `opc-data-testkit` | fake records, redaction assertions, retention tests |

Agents implementing NF features must classify new fields before exposing logs,
metrics, storage, or exports.

## 19. Testing Requirements

### 19.1 Unit Tests

- Classification coverage.
- Redaction levels.
- Keyed digest stability.
- Retention eligibility.
- Legal hold blocks deletion.
- Support bundle manifest redaction.

### 19.2 Integration Tests

- NF logs contain no raw SUPI/GPSI/MSISDN.
- Metrics reject high-cardinality raw labels.
- Backup/restore preserves classification.
- Export denied across tenant boundary.
- Analytics minimization records policy version.

### 19.3 Fault Injection

- Missing privacy digest key.
- Retention job interrupted.
- Export sink unavailable.
- Backup manifest tampered.
- Legal hold expiry during deletion.

### 19.4 Performance Gates

- Hot-path redaction p99 under 5 microseconds for scalar identifiers.
- Digest generation p99 under 25 microseconds.
- Retention jobs respect configured I/O budget.
- Metrics classification checks do not allocate on common paths.

## 20. Acceptance Criteria

This RFC is implemented when:

1. Every generated and hand-written sensitive field has a data class.
2. Raw subscriber identifiers do not appear in logs, metrics, traces, events,
   backend keys, or support bundles by default.
3. Retention and legal hold policies are declarative and tested.
4. Backups, restores, and exports preserve classification metadata.
5. LI data is separated from ordinary telemetry and analytics.
6. Analytics exports record minimization policy.
7. RFC 006 evidence reports classification, redaction, retention, and privacy
   behavior.
