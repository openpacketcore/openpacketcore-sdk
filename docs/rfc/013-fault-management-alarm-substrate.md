# OPC-SDK-RFC-013: Fault Management and Alarm Substrate

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: SREs, NF implementers, operator authors, observability engineers

## 1. Abstract

This RFC defines the OpenPacketCore fault management and alarm substrate. It
standardizes alarm identity, severity, probable cause, affected object,
raise/update/clear semantics, deduplication, suppression, correlation,
Kubernetes condition mapping, gNMI/NETCONF notification projection, external
fault-management sink integration, and evidence requirements.

Metrics, logs, and traces describe behavior. Alarms describe actionable service
faults. Carrier CNFs need both.

## 2. Scope

### 2.1 In Scope

- Alarm model and lifecycle.
- Severity and probable-cause taxonomy.
- Affected-object naming.
- Raise, update, clear, acknowledge, suppress.
- Alarm correlation and deduplication.
- Mapping to Kubernetes conditions and events.
- Mapping to gNMI/NETCONF notifications.
- External FM sink integration.
- Alarm metrics, audit, and tests.

### 2.2 Out of Scope

- Full OSS/BSS ticketing implementation.
- Vendor-specific FM protocols unless implemented as adapters.
- Raw log aggregation.
- Performance SLO alerting rules outside CNF-generated alarms.

## 3. Design Goals

### 3.1 Security

- Alarms must not leak secrets or raw subscriber identifiers.
- Alarm administration must be authorized.
- Suppression and acknowledgement are audited.
- LI/security alarms must preserve regulated handling boundaries.

### 3.2 Performance

- Raising an alarm must be cheap and non-blocking.
- Alarm storms must be deduplicated and rate-limited.
- External sink outages must not block packet or request handling.

### 3.3 Maintainability

- One alarm vocabulary across all CNFs.
- Stable alarm IDs and probable causes.
- Generated YANG notification projection.
- Shared testkit for alarm lifecycle.

### 3.4 Functionality

- Support active and historical alarms.
- Support severity changes.
- Support clear conditions.
- Support suppression windows.
- Support external sinks and local query.

## 4. Alarm Model

```rust
pub struct Alarm {
    pub alarm_id: AlarmId,
    pub alarm_type: AlarmType,
    pub severity: Severity,
    pub probable_cause: ProbableCause,
    pub affected_object: AffectedObject,
    pub tenant: Option<TenantId>,
    pub slice: Option<Snssai>,
    pub region: Option<RegionId>,
    pub text: RedactedText,
    pub details: AlarmDetails,
    pub raised_at: Timestamp,
    pub updated_at: Timestamp,
    pub cleared_at: Option<Timestamp>,
    pub correlation_id: Option<CorrelationId>,
}
```

`AlarmId` MUST be stable for the same active fault instance.

## 5. Severity

Severity levels:

| Severity | Meaning |
| :--- | :--- |
| `critical` | service outage, data loss, security boundary failure |
| `major` | serious degradation or redundancy loss |
| `minor` | limited impairment with workaround |
| `warning` | approaching fault or policy exception |
| `indeterminate` | fault detected but impact unknown |
| `cleared` | fault no longer active |

Severity mapping MUST be consistent across CNFs.

## 6. Probable Cause Taxonomy

The SDK maintains a versioned taxonomy:

- `config-apply-failed`
- `config-drift-detected`
- `certificate-expiring`
- `certificate-expired`
- `identity-unavailable`
- `authorization-policy-invalid`
- `session-store-unavailable`
- `lease-lost`
- `backend-timeout`
- `nrf-unreachable`
- `sbi-overload`
- `peer-unreachable`
- `packet-drop-threshold`
- `dataplane-preflight-failed`
- `storage-corruption`
- `audit-chain-invalid`
- `key-unavailable`
- `li-delivery-failed`
- `charging-export-failed`
- `privacy-policy-violation`

Per-NF causes may be added but MUST be namespaced.

## 7. Affected Object

Affected objects use structured names:

```rust
pub enum AffectedObject {
    NfInstance { kind: NfKind, instance: InstanceId },
    Interface { nf: InstanceId, name: String },
    Peer { nf: InstanceId, peer_id: String },
    SessionStore { nf: InstanceId, shard: Option<String> },
    Slice { snssai: Snssai },
    Tenant { tenant: TenantId },
    Certificate { key_id: KeyId },
    DataPlaneQueue { nf: InstanceId, interface: String, queue: u16 },
}
```

Raw subscriber identifiers MUST NOT be affected-object names.

## 8. Alarm Lifecycle

States:

- `raised`
- `updated`
- `acknowledged`
- `suppressed`
- `cleared`
- `expired`

Lifecycle rules:

- A repeated raise with same dedup key updates the active alarm.
- Clear requires a matching active alarm or creates a no-op metric.
- Acknowledgement does not clear.
- Suppression does not delete history.
- Severity downgrade is an update, not clear plus raise.

## 9. Deduplication and Correlation

Dedup key:

```text
alarm_type || probable_cause || affected_object || tenant || slice
```

Correlation groups related alarms, such as:

- NRF unavailable causing SBI discovery failures.
- certificate expiry causing mTLS failures.
- session store outage causing lease lost alarms.

Correlation MUST NOT hide critical alarms; it only helps presentation.

## 10. Suppression

Suppression may be:

- maintenance window,
- known outage,
- test mode,
- dependency alarm correlation.

Suppression requires authorization and audit. Security-critical alarms SHOULD
not be suppressible unless carrier policy explicitly allows it.

## 11. Storage

The alarm store MUST support:

- active alarm query,
- historical alarm query,
- append-only lifecycle events,
- bounded retention,
- tenant/slice filtering,
- tamper-evident audit for admin actions.

Local storage may use RFC 001 persistence for management alarms. High-volume
alarm history SHOULD be exported to an external FM system.

## 12. Projection to Kubernetes

Alarms map to Kubernetes Conditions and Events:

- critical/major active alarms can drive `Ready=False` or `Degraded=True`
  according to NF policy,
- warning alarms usually do not change readiness,
- clear events update conditions when no other active alarm holds the state.

Condition reason strings MUST be stable.

## 13. Projection to gNMI/NETCONF

The alarm subsystem MUST expose:

- active alarms operational tree,
- alarm history operational tree,
- notifications for raise/update/clear,
- authorized acknowledge/suppress operations.

YANG notification generation SHOULD use RFC 002 metadata and RFC 006 evidence
tags.

## 14. External FM Sinks

Sink adapters:

- webhook,
- Kafka/NATS,
- OpenTelemetry events,
- SNMP/NETCONF adapter where needed,
- carrier OSS adapter.

External sink failure MUST:

- raise a sink alarm,
- buffer within limits if policy allows,
- never block fast paths,
- expose drop counters.

## 15. Alarm Sources

Common sources:

- RFC 001 config commit failures,
- RFC 003 identity/key/cert failures,
- RFC 004 session store and lease failures,
- RFC 007 SBI overload/discovery failures,
- RFC 008 runtime task failures,
- RFC 009 lifecycle migration failures,
- RFC 011 data-plane preflight and drop thresholds,
- RFC 010 privacy/legal-hold/export failures.

## 16. Observability

Required metrics:

- `opc_alarm_active{severity,cause}`
- `opc_alarm_events_total{event,severity,cause}`
- `opc_alarm_suppressed_total{cause}`
- `opc_alarm_sink_delivery_total{sink,outcome}`
- `opc_alarm_sink_queue_depth{sink}`
- `opc_alarm_clear_without_active_total{cause}`

Alarm text MUST be redacted through RFC 010.

## 17. Configuration Model

Shared YANG groupings SHOULD include:

- `alarms/severity-policy`
- `alarms/suppression`
- `alarms/sinks`
- `alarms/retention`
- `alarms/readiness-impact`
- `alarms/correlation`

Per-NF YANG may add alarm thresholds, such as packet drop ratio or peer outage
duration.

## 18. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-alarm-model` | alarm structs, severity, causes |
| `opc-alarm-store` | active/history store |
| `opc-alarm-manager` | raise/update/clear/dedup |
| `opc-alarm-policy` | suppression and readiness impact |
| `opc-alarm-k8s` | condition/event mapping |
| `opc-alarm-yang` | gNMI/NETCONF operational projection |
| `opc-alarm-sink` | external sink adapters |
| `opc-alarm-testkit` | alarm lifecycle fixtures |

Agents adding new alarms must add taxonomy entries, tests, and evidence tags.

## 19. Testing Requirements

### 19.1 Unit Tests

- Dedup key stability.
- Severity transition.
- Clear behavior.
- Suppression authorization.
- Redaction.
- Readiness impact policy.

### 19.2 Integration Tests

- Runtime task failure raises alarm.
- Alarm maps to Kubernetes condition.
- Alarm notification appears on gNMI subscription.
- External sink receives raise/update/clear.
- Sink outage buffers or drops according to policy.

### 19.3 Fault Injection

- Alarm storm.
- Sink outage.
- Store unavailable.
- Unauthorized suppression attempt.
- Duplicate raise from many tasks.

### 19.4 Performance Gates

- Alarm raise common path does not block longer than 100 microseconds.
- Alarm storm of 10,000 duplicate events deduplicates without unbounded memory.
- External sink outage does not impact protocol request p99.

## 20. Acceptance Criteria

This RFC is implemented when:

1. Every CNF uses shared alarm model and manager.
2. Alarm severity and probable cause taxonomy are stable and versioned.
3. Raise/update/clear semantics are deterministic.
4. Kubernetes conditions and events are derived consistently.
5. gNMI/NETCONF alarm operational state and notifications are available.
6. Suppression and acknowledgement are authorized and audited.
7. External sink failures do not block service paths.
8. Alarm behavior is covered by shared testkit and evidence.
