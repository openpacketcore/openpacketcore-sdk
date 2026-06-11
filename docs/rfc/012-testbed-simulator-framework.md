# OPC-SDK-RFC-012: Common Testbed, Simulator, and Scenario Framework

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: test engineers, NF implementers, conformance owners, SREs

## 1. Abstract

This RFC defines the shared OpenPacketCore testbed and simulator framework. It
standardizes reusable peer simulators, virtual time, traffic scenarios, protocol
fixtures, conformance packs, chaos hooks, load profiles, and evidence output.

The purpose is to prevent every CNF from building isolated mocks that cannot
compose into end-to-end 5G scenarios. The framework lets multiple contributors
implement NFs independently while verifying them against the same scenario
language and peer behavior.

## 2. Scope

### 2.1 In Scope

- Peer simulators for UE, gNB, AMF, SMF, UPF, NRF, AUSF, UDM, PCF, NSSF, SCP,
  SEPP, SMSC, and other core peers.
- Protocol fixture management and PCAP replay.
- Virtual time and deterministic timers.
- Scenario DSL.
- Conformance scenario packs.
- Load and soak profiles.
- Chaos and fault injection hooks.
- Evidence output for RFC 006.

### 2.2 Out of Scope

- Production NF logic.
- Standards certification by external bodies.
- Full radio access network simulation beyond interfaces required for core
  testing.

## 3. Design Goals

### 3.1 Security

- Test secrets must be synthetic and clearly marked.
- Fixtures containing real subscriber data are forbidden.
- Negative tests must cover malformed and hostile peer behavior.
- Testbed artifacts must not weaken production code paths.

### 3.2 Performance

- Simulators must support both deterministic unit-scale tests and high-rate load
  tests.
- Virtual time should make timer-heavy procedures fast and deterministic.
- Load profiles must be reproducible.

### 3.3 Maintainability

- One scenario DSL across all CNFs.
- Reusable protocol fixtures and peer simulators.
- Test evidence links back to RFC 006 requirement IDs.
- Each simulator has a documented fidelity level.

### 3.4 Functionality

- Support component, integration, end-to-end, conformance, chaos, and
  performance testing.
- Support both in-process and Kubernetes-deployed test modes.
- Support golden traces and expected state assertions.

## 4. Crate and Tooling Layout

```text
crates/opc-testbed/
  src/
    lib.rs
    scenario.rs
    virtual_time.rs
    assertions.rs
    fixtures.rs
    pcap.rs
    load.rs
    evidence.rs
    chaos.rs
    simulators/
      nrf.rs
      amf.rs
      smf.rs
      upf.rs
      gnb.rs
      ue.rs
      ausf.rs
      udm.rs
      pcf.rs
      nssf.rs
      scp.rs
      sepp.rs
```

Each NF MAY also provide `opc-<nf>-testkit`, but NF testkits SHOULD build on
`opc-testbed`.

## 5. Scenario DSL

Scenarios are declarative:

```yaml
id: AMF-REG-001
title: UE registration success
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { image: opc-amf:test }
    nrf: { simulator: nrf-basic }
    ausf: { simulator: ausf-5g-aka }
    udm: { simulator: udm-auth-sdm }
steps:
  - send_ngap:
      from: gnb-1
      to: amf
      message: InitialUEMessage.registration_request
  - expect_sbi:
      from: amf
      to: ausf
      operation: Nausf_UEAuthentication.Authenticate
  - expect_ngap:
      from: amf
      to: gnb-1
      message: InitialContextSetupRequest
assertions:
  - amf.ue_context.state == REGISTERED
```

The DSL MUST be versioned and schema-validated.

## 6. Simulator Fidelity Levels

| Level | Meaning |
| :--- | :--- |
| `stub` | fixed responses only |
| `stateful-mock` | protocol-aware state machine, simplified |
| `procedure-faithful` | follows normative procedure enough for conformance |
| `load-model` | optimized for traffic generation |
| `adversarial` | emits malformed, delayed, duplicated, or hostile behavior |

Every simulator MUST declare its fidelity level per interface.

## 7. Virtual Time

The testbed MUST provide a virtual clock compatible with RFC 008 runtime clocks.

Use cases:

- NAS timers,
- PFCP heartbeat,
- NRF heartbeat,
- retry/backoff,
- session lease expiry,
- SMS retry/expiry,
- retention jobs.

Tests MUST NOT sleep real time for long protocol timers when virtual time can
advance deterministically.

## 8. Protocol Fixtures and PCAP

Fixtures MUST include:

- source standard reference,
- release/version,
- generation tool or capture provenance,
- whether synthetic or captured,
- sanitization status,
- expected decode result,
- linked requirement IDs.

Real customer/subscriber captures are forbidden in the public repository.

PCAP replay MUST support:

- timestamp-preserving mode,
- accelerated mode,
- deterministic mode,
- packet mutation for fuzz-style tests.

## 9. Peer Simulators

Minimum simulator set:

- UE/NAS procedure driver.
- gNB/NGAP over SCTP driver.
- NRF SBI simulator.
- AUSF/UDM auth and subscription simulators.
- SMF/UPF/PFCP simulator pair.
- PCF policy simulator.
- NSSF slice selection simulator.
- SCP routing simulator.
- SEPP partner simulator.
- SMSC/SMSF/SMPP simulators.

Simulators MUST expose deterministic state assertions.

## 10. Test Modes

| Mode | Purpose |
| :--- | :--- |
| `in-process` | fast component integration |
| `multi-process` | local network behavior |
| `kind` | Kubernetes operator/chart validation |
| `hardware-lab` | SR-IOV/AF_XDP/real NIC validation |
| `chaos` | failure injection |
| `soak` | long-running reliability |

The same scenario SHOULD run in multiple modes where practical.

## 11. Fault Injection

Faults:

- packet loss,
- reordering,
- duplication,
- malformed protocol messages,
- delayed responses,
- peer restart,
- NRF outage,
- token expiry,
- backend timeout,
- clock skew,
- node drain,
- network partition.

Faults MUST be declarative in scenarios and evidence-linked.

## 12. Load Profiles

Load profiles define:

- arrival distribution,
- subscriber population,
- slice distribution,
- DNN distribution,
- session duration,
- mobility/handover rate,
- message mix,
- target throughput,
- duration,
- pass/fail SLOs.

Profiles MUST be reproducible from seeds.

## 13. Assertions

Assertions may target:

- protocol messages,
- SBI calls,
- config state,
- session store records,
- metrics,
- logs,
- traces,
- alarms,
- Kubernetes status,
- evidence output.

Assertions MUST avoid depending on nondeterministic ordering unless explicitly
marked.

## 14. Evidence Output

Each scenario run emits:

```json
{
  "scenario_id": "AMF-REG-001",
  "requirements": ["REQ-..."],
  "mode": "kind",
  "seed": 1234,
  "artifacts": ["trace.json", "metrics.prom", "events.json"],
  "outcome": "pass"
}
```

RFC 006 consumes these records for conformance reports.

## 15. Security and Privacy Rules

The testbed MUST:

- generate synthetic subscriber identities,
- mark all test keys as non-production,
- reject fixture import without sanitization metadata,
- prevent real bearer tokens from being stored in artifacts,
- redact logs and traces through RFC 010 redaction.

## 16. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-testbed-scenario` | DSL schema, parser, executor |
| `opc-testbed-time` | virtual clock and timer control |
| `opc-testbed-fixtures` | fixture registry and provenance |
| `opc-testbed-pcap` | PCAP replay and mutation |
| `opc-testbed-sim-nrf` | NRF simulator |
| `opc-testbed-sim-ran` | UE/gNB/NAS/NGAP drivers |
| `opc-testbed-sim-sbi` | generic SBI producer/consumer mock |
| `opc-testbed-chaos` | failure injection |
| `opc-testbed-evidence` | RFC 006 result emission |

Agents implementing a new NF must add scenarios before declaring conformance.

## 17. Testing Requirements

### 17.1 Unit Tests

- DSL schema validation.
- Virtual time advancement.
- Fixture provenance validation.
- Deterministic seed behavior.
- Assertion engine.

### 17.2 Integration Tests

- Scenario runs against fake NF.
- Mock NRF discovery and token flow.
- PCAP replay into protocol parser.
- Kind-mode lifecycle install and readiness.
- Evidence JSON emitted and validated.

### 17.3 Fault Injection Tests

- Peer timeout.
- Malformed message.
- Duplicate message.
- Clock skew.
- Node drain in kind.
- Backend outage.

### 17.4 Performance Gates

- In-process scenarios start under 100 milliseconds.
- Virtual-time timer tests avoid long real sleeps.
- Load generator reports achieved TPS and latency.
- Scenario artifacts remain within configured size budgets.

## 18. Acceptance Criteria

This RFC is implemented when:

1. A versioned scenario DSL exists.
2. Shared peer simulators cover core 5G procedures.
3. Virtual time is integrated with runtime/test clocks.
4. Fixtures carry provenance and sanitization metadata.
5. Scenarios emit RFC 006 evidence records.
6. NF testkits build on the shared framework.
7. Conformance and chaos scenarios are reusable across local and Kubernetes
   modes.
