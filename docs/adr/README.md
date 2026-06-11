# Architecture Decision Records

This directory contains accepted architecture decisions for the OpenPacketCore
SDK hardening work completed through June 8, 2026.

ADRs are the durable record of architectural intent. The audit completion
reports and implementation status matrix record what was validated; these ADRs
record why the shape of the SDK is what it is.

## Index

| ADR | Decision |
|:---|:---|
| [0001](0001-secure-config-management.md) | Config management is secure by default, commit-confirmed, audited, and explicitly authorized. |
| [0002](0002-config-store-consensus-ha.md) | Config persistence HA uses `ConsensusConfigStore` with Raft-style quorum safety, authenticated transport, durable membership, and snapshot integrity. |
| [0003](0003-session-store-quorum-replication.md) | Authoritative session state uses quorum ordered-log replication with majority-supported repair, not standalone SQLite HA. |
| [0004](0004-security-identity-keying-audit.md) | Production identity, TLS, keys, and audit integrity are explicit SDK substrates with fail-closed adapters. |
| [0005](0005-runtime-observability-admin-probes.md) | Runtime health, admin/probe routes, metrics, and alarms are shared SDK surfaces with production authorization and redaction. |
| [0006](0006-fault-injection-fail-closed-validation.md) | Storage, security, runtime, HA, and release evidence are validated through fail-closed fault injection. |
| [0007](0007-operator-lifecycle-rust-policy-core.md) | Operator lifecycle policy logic lives in Rust SDK crates as reusable policy engines. |
| [0008](0008-go-reference-operator-boundary.md) | Kubernetes operator integration is demonstrated by a Go reference harness without becoming a product CNF operator. |
| [0009](0009-platform-preflight-resource-contract.md) | Production data-plane claims require explicit node-resource, BPF, pod-security, and fallback validation. |
| [0010](0010-release-assurance-evidence-pipeline.md) | RFC 006 evidence, SBOM/VEX, provenance, bundle verification, performance baselines, and gates are first-class release inputs. |
| [0011](0011-first-nf-vertical-proof.md) | `opc-amf-lite` is the SDK vertical integration proof, not a product NF. |
| [0012](0012-diagnostics-safety-privacy-governance.md) | Diagnostics safety and privacy governance boundaries are structured, fail-closed, and compile-gated. |
