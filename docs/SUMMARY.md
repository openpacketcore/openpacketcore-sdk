# Summary

[Introduction](introduction.md)
- [Architecture](architecture.md)

# Getting Started

[Quickstart](quickstart.md)
[Implementation Status](implementation-status.md)

# Architecture

- [RFCs](rfc/README.md)
  - [001 — Management Substrate](rfc/001-management-substrate.md)
  - [002 — YANG Projection](rfc/002-yang-projection.md)
  - [003 — Security Substrate](rfc/003-security-substrate.md)
  - [004 — Session Store](rfc/004-session-store.md)
  - [005 — Protocol Framework](rfc/005-protocol-framework.md)
  - [006 — Conformance Pipeline](rfc/006-conformance-pipeline.md)
  - [007 — SBI Service Framework](rfc/007-sbi-service-framework.md)
  - [008 — CNF Runtime Chassis](rfc/008-cnf-runtime-chassis.md)
  - [009 — Operator Lifecycle Upgrade](rfc/009-operator-lifecycle-upgrade.md)
  - [010 — Data Governance & Privacy](rfc/010-data-governance-privacy.md)
  - [011 — Node Dataplane Resource Contract](rfc/011-node-dataplane-resource-contract.md)
  - [012 — Testbed & Simulator Framework](rfc/012-testbed-simulator-framework.md)
  - [013 — Fault Management & Alarm Substrate](rfc/013-fault-management-alarm-substrate.md)
  - [014 — Interactive Operational Console](rfc/014-interactive-operational-console.md)
- [ADRs](adr/README.md)
  - [0001 — Secure Config Management](adr/0001-secure-config-management.md)
  - [0002 — Config Store Consensus HA](adr/0002-config-store-consensus-ha.md)
  - [0003 — Session Store Quorum Replication](adr/0003-session-store-quorum-replication.md)
  - [0004 — Security Identity Keying Audit](adr/0004-security-identity-keying-audit.md)
  - [0005 — Runtime Observability Admin Probes](adr/0005-runtime-observability-admin-probes.md)
  - [0006 — Fault Injection Fail-Closed Validation](adr/0006-fault-injection-fail-closed-validation.md)
  - [0007 — Operator Lifecycle Rust Policy Core](adr/0007-operator-lifecycle-rust-policy-core.md)
  - [0008 — Go Reference Operator Boundary](adr/0008-go-reference-operator-boundary.md)
  - [0009 — Platform Preflight Resource Contract](adr/0009-platform-preflight-resource-contract.md)
  - [0010 — Release Assurance Evidence Pipeline](adr/0010-release-assurance-evidence-pipeline.md)
  - [0011 — First NF Vertical Proof](adr/0011-first-nf-vertical-proof.md)
  - [0012 — Diagnostics Safety Privacy Governance](adr/0012-diagnostics-safety-privacy-governance.md)
  - [0013 — NGAP ASN.1 Strategy](adr/0013-ngap-asn1-strategy.md)
  - [0014 — Dependency & Toolchain Policy](adr/0014-dependency-toolchain-policy.md)
  - [0015 — Protocol Codec Conformance Policy](adr/0015-protocol-codec-conformance-policy.md)
  - [0016 — Northbound gRPC Stack Exception](adr/0016-northbound-grpc-stack-exception.md)
  - [0017 — SCTP Transport FFI Boundary](adr/0017-sctp-transport-ffi-boundary.md)
  - [0018 — EPC Untrusted-Access SDK Boundary](adr/0018-epc-untrusted-access-sdk-boundary.md)
  - [0019 — One Openraft Consensus Engine](adr/0019-one-openraft-consensus-engine.md)
- [OPC gNMI Server Spec](design/opc-gnmi-server-spec.md)

# Operator Guide

[Building a CNF Operator](building-a-cnf-operator.md)

# Runbooks

[Consensus Operator Runbook](consensus-operator-runbook.md)
[Session-Store Legacy Fork Recovery](session-store-legacy-recovery.md)
[HA Design](ha-design.md)
[Operator Readiness](operator-readiness.md)
[GNSI Compatibility](gnsi-compatibility.md)
