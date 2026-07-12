# Architecture Decision Records

This directory contains accepted and proposed architecture decisions for the
OpenPacketCore SDK hardening and management-plane work.

ADRs are the durable record of architectural intent. The audit completion
reports and implementation status matrix record what was validated; these ADRs
record why the shape of the SDK is what it is. Proposed ADRs are included here
when they gate in-progress work, but they do not authorize implementation until
accepted.

## Index

| ADR | Decision |
|:---|:---|
| [0001](0001-secure-config-management.md) | Config management is secure by default, commit-confirmed, audited, and explicitly authorized. |
| [0002](0002-config-store-consensus-ha.md) | Config persistence HA uses `ConsensusConfigStore` on the shared Openraft engine, with sealed/redacted commands, atomic authority fencing, shared authenticated transport, and exact offline legacy recovery. |
| [0003](0003-session-store-quorum-replication.md) | Authoritative session HA uses one Openraft-backed store with validated identity, committed state-machine application, and envelope encryption above consensus; standalone SQLite is not HA. |
| [0004](0004-security-identity-keying-audit.md) | Production identity, TLS, keys, and audit integrity are explicit SDK substrates with fail-closed adapters. |
| [0005](0005-runtime-observability-admin-probes.md) | Runtime health, admin/probe routes, metrics, and alarms are shared SDK surfaces with production authorization and redaction. |
| [0006](0006-fault-injection-fail-closed-validation.md) | Storage, security, runtime, HA, and release evidence are validated through fail-closed fault injection. |
| [0007](0007-operator-lifecycle-rust-policy-core.md) | Operator lifecycle policy logic lives in Rust SDK crates as reusable policy engines. |
| [0008](0008-go-reference-operator-boundary.md) | Kubernetes operator integration is demonstrated by a Go reference harness without becoming a product CNF operator. |
| [0009](0009-platform-preflight-resource-contract.md) | Production data-plane claims require explicit node-resource, BPF, pod-security, and fallback validation. |
| [0010](0010-release-assurance-evidence-pipeline.md) | RFC 006 evidence, SBOM/VEX, provenance, bundle verification, performance baselines, and gates are first-class release inputs. |
| [0011](0011-first-nf-vertical-proof.md) | `opc-amf-lite` is the SDK vertical integration proof, not a product NF. |
| [0012](0012-diagnostics-safety-privacy-governance.md) | Diagnostics safety and privacy governance boundaries are structured, fail-closed, and compile-gated. |
| [0013](0013-ngap-asn1-strategy.md) | NGAP requires generated ASN.1 APER code; hand-written and FFI codecs are rejected. |
| [0014](0014-dependency-toolchain-policy.md) | rustls/tokio-only dependency policy, no gRPC stack in SDK crates, and a measured (not aspirational) MSRV. |
| [0015](0015-protocol-codec-conformance-policy.md) | Protocol codecs are proven against spec-authored byte fixtures, never only their own encoder output. |
| [0016](0016-northbound-grpc-stack-exception.md) | _(proposed)_ `tonic`/`prost` are permitted only for `opc-gnmi-server` as the ADR 0014 §3 exception; core SDK crates stay gRPC-free. |
| [0017](0017-sctp-transport-ffi-boundary.md) | Explicitly allowlisted Linux kernel UAPI sys crates, including `opc-libsctp-sys`, `opc-linux-xfrm-sys`, and `opc-linux-gtpu-sys`, hold all `unsafe` UAPI FFI; this OS-transport exception to ADR 0014 §8 does not reopen ADR 0013's rejection of foreign C codec FFI. |
| [0018](0018-epc-untrusted-access-sdk-boundary.md) | EPC and untrusted-access additions are limited to SDK-owned reusable mechanisms; product policy, deployment defaults, ePDG orchestration, and carrier-readiness claims remain product-owned. |
| [0019](0019-one-openraft-consensus-engine.md) | Openraft is the only distributed-persistence consensus authority; domain state machines remain SDK-owned and the `opc-persist` migration is required before the workspace can claim a unified profile. |
