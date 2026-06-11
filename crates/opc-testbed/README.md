# opc-testbed

OpenPacketCore Testbed and Simulator Framework (RFC 012).

This crate provides:
1. **Scenario DSL**: Versioned scenario format supporting NGAP/SBI messages and chaos engineering controls.
2. **Procedure-Faithful Simulators**:
   - `AmfSimulator`: Models AMF registration, session creation, NRF connectivity, configuration apply, alarms, and recovery.
   - `SmfSimulator`: Models session establishment, modification, release, stale fence rejection, and timeout injection.
   - `UpfSimulator`: Models PFCP-like association setup, dataplane preflight status, flow threshold alarms, and peer unreachable/recovery states.
3. **Scenario Runners**:
   - `LocalRunner`: In-process runner executing steps against virtual clocks and simulators.
   - `KindRunner`: Generates Kubernetes manifests, plan dry-runs, and validates image pull policies, namespaces, and config maps.
   - `HardwareLabRunner`: Structured preflight resource checking and dry-run plan generation.
4. **Evidence Emission**: Generates `ScenarioEvidence` mapping to RFC 006 `EvidenceRecord`s.

## Boundaries
- The SDK provides simulators, testkits, dry-run runners, and evidence.
- The SDK does not become a production CNF or a production Kubernetes operator.
- Live hardware-lab execution depends on downstream environment wiring.
