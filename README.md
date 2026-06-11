# OpenPacketCore SDK

[![CI](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml)

A robust, polyglot software development kit for building resilient, cloud-native 5G packet core network functions (CNFs). This SDK provides the standardized runtime chassis, quorum-replicated session storage, encrypted config persistence, data-governance/redaction boundary enforcement, and release-assurance evidence pipelines for packet core software with high-assurance deployment requirements.

The GTP-U user-plane codec is also applicable to LTE/EPC user plane. No EPC control-plane protocols (GTP-C, Diameter, S1AP) are provided.

> [!IMPORTANT]
> **Production Readiness & Reference Boundaries**
> * **Rust SDK Core**: The core Rust libraries have passed the current P0 SDK release-readiness gates. Downstream CNFs still need product-specific integration, deployment, and carrier acceptance validation.
> * **Go Reference Operator**: The Go operator located under `operators/sdk-reference-operator/` is a **reference harness and development utility only**. It is explicitly not a production-grade controller. Downstream product teams are responsible for implementing product-specific Kubernetes operators.
> * **No Unconditional Claims**: Standard deployments require integration with your local platform security policies, hardware topologies, and external KMS/SPIFFE infrastructure.

## Getting started

See [`docs/quickstart.md`](docs/quickstart.md) for a guided first build and a minimal CNF example.

---

## Workspace Layout & SDK Boundaries

The SDK is organized into a clean multi-crate Rust workspace and a Go reference operator directory:

### Core Runtime & Platform (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-sdk`](crates/opc-sdk/) | Facade crate: feature-gated re-exports of the core composition surface, a `prelude`, and the `minimal_cnf` end-to-end example. | [Quickstart](docs/quickstart.md) |
| [`opc-runtime`](crates/opc-runtime/) | CNF runtime chassis: process startup phases, task supervision, health probes, and graceful SIGTERM drains. | [RFC 008](docs/rfc/008-cnf-runtime-chassis.md) |
| [`opc-protocol`](crates/opc-protocol/) | Zero-copy protocol codec framework: traits, context, errors, and fuzzing contracts. | [RFC 005](docs/rfc/005-protocol-framework.md) |
| [`opc-proto-gtpu`](crates/opc-proto-gtpu/) | GTP-U protocol codec for the user-plane data path. | — |
| [`opc-proto-pfcp`](crates/opc-proto-pfcp/) | PFCP protocol codec (TS 29.244) for the 5G control plane *(experimental v0)*. | — |
| [`opc-proto-nas`](crates/opc-proto-nas/) | NAS-5GS (TS 24.501) v0 codec: plain headers, security-envelope recognition, 5GS mobile identity *(experimental v0)*. | — |
| [`opc-node-resources`](crates/opc-node-resources/) | Validates `ResourceProfile` compatibility against observed `NodeCapabilityReport`. | [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |

### Config & Management (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-config-bus`](crates/opc-config-bus/) | Transactional config bus supporting schema validation, tenant segregation, AAD-bound envelope encryption, and admission control. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-config-model`](crates/opc-config-model/) | Shared config-model request, result, identity, and error types. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-persist`](crates/opc-persist/) | Tamper-evident SQLite datastores, consensus config store membership, and fail-closed storage fault injection hooks. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-nacm`](crates/opc-nacm/) | Normalized YANG path parsing and NACM authorization evaluation. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-yanggen`](crates/opc-yanggen/) | YANG-to-Rust type projection, RFC 7951 JSON serde, iterative semantic constraint validation, and patch applicator. | [RFC 002](docs/rfc/002-yang-projection.md) |

### Security & Identity (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-identity`](crates/opc-identity/) | SPIFFE Workload Identity and SVID reload support. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-key`](crates/opc-key/) | Key-provider traits, in-memory adapters, and tenant-bound AEAD payload helpers. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-crypto`](crates/opc-crypto/) | AEAD envelope encoding, decoding, and provider-driven encryption. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-tls`](crates/opc-tls/) | Reloadable SPIFFE-aware mTLS client and server support. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-key-vault`](crates/opc-key-vault/) | HashiCorp Vault Transit `KeyProvider` adapter using the wrapped-data-key envelope pattern *(experimental)*. | [RFC 003](docs/rfc/003-security-substrate.md) |

### Session & State (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-session-store`](crates/opc-session-store/) | Quorum-replicated session database supporting lease management, CAS operations, and change-stream watches. Quorum semantics (fencing, leases, CAS, read-repair) are production-grade within a process; networked replication is experimental and provided by `opc-session-net`. | [RFC 004](docs/rfc/004-session-store.md) |
| [`opc-session-cache`](crates/opc-session-cache/) | Production-grade session cache with key-scoped invalidation, sequence tracking, and resume recovery. | [RFC 004](docs/rfc/004-session-store.md) |
| [`opc-session-net`](crates/opc-session-net/) | Networked session replication transport: mTLS length-prefixed wire protocol, replication server, and remote backend client *(experimental)*. | [RFC 004](docs/rfc/004-session-store.md) |

### Alarms & Observability (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-alarm`](crates/opc-alarm/) | Alarm model, severity taxonomy, dedup/update/clear manager, and in-memory store. | [RFC 013](docs/rfc/013-fault-management-alarm-substrate.md) |
| [`opc-alarm-k8s`](crates/opc-alarm-k8s/) | Kubernetes condition and event mappings for OpenPacketCore alarms. | [RFC 013](docs/rfc/013-fault-management-alarm-substrate.md) |
| [`opc-alarm-yang`](crates/opc-alarm-yang/) | YANG schema and operational projections for OpenPacketCore alarms. | [RFC 013](docs/rfc/013-fault-management-alarm-substrate.md) |

### Data Governance & Privacy (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-redaction`](crates/opc-redaction/) | Support-bundle redactor scrubbing SUPIs, GPSIs, IPs, paths, and private keys. | [RFC 010](docs/rfc/010-data-governance-privacy.md) |
| [`opc-data-governance`](crates/opc-data-governance/) | Data classification, tenant boundary isolation, retention policies, and legal holds. | [RFC 010](docs/rfc/010-data-governance-privacy.md) |
| [`opc-privacy`](crates/opc-privacy/) | Client-side privacy: cohort binning and k-anonymity validation. | [RFC 010](docs/rfc/010-data-governance-privacy.md) |
| [`opc-export`](crates/opc-export/) | Metadata-preserving schema/payload export validation for backup and restore. | [RFC 010](docs/rfc/010-data-governance-privacy.md) |

### Service-Based Interface (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-sbi`](crates/opc-sbi/) | Shared SBI client/server, auth, NRF, retry, and testkit primitives. | [RFC 007](docs/rfc/007-sbi-service-framework.md) |
| [`opc-api-nnrf`](crates/opc-api-nnrf/) | Generated Rust types for 3GPP TS 29.510 NRF `NfProfile` / `NfService` *(experimental)*. | [Design note](docs/design/openapi-codegen-plan.md) |

### Release Assurance (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-evidence`](crates/opc-evidence/) | Release assurance pipeline: SBOM generation, VEX scanning, and gate policy enforcement. | [RFC 006](docs/rfc/006-conformance-pipeline.md) |

### Operator Lifecycle (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`operator-lifecycle`](crates/operator-lifecycle/) | Kubernetes production-readiness lifecycle foundation, config-apply, admission, and drain/upgrade planning. | [RFC 009](docs/rfc/009-operator-lifecycle-upgrade.md) |
| [`operator-controller`](crates/operator-controller/) | Kubernetes operator controller execution layer *(internal, not published)*. | — |
| [`operator-lifecycle-cli`](crates/operator-lifecycle-cli/) | CLI interface exposing Rust SDK lifecycle contracts to Go controller-runtime operators via JSON *(internal, not published)*. | — |

### Testing & Integration (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-testbed`](crates/opc-testbed/) | Scenario DSL, virtual time, assertions, fixture provenance, and simulator framework. | [RFC 012](docs/rfc/012-cnf-simulators-and-testbeds.md) |
| [`opc-sdk-integration`](crates/opc-sdk-integration/) | Integration crate wiring runtime, config bus, alarms, and testbed evidence *(internal, not published)*. | — |
| [`opc-config-fixture`](crates/opc-config-fixture/) | Generated-like config fixture for integration testing *(internal, not published)*. | — |
| [`opc-amf-lite`](crates/opc-amf-lite/) | Realistic AMF-lite control-plane vertical slice integration proving SDK seams *(internal, not published)*. | [ADR 0011](docs/adr/0011-first-nf-vertical-proof.md) |

### Internal Testkits (`crates/`)

| Crate | Purpose |
| :--- | :--- |
| [`opc-alarm-testkit`](crates/opc-alarm-testkit/) | Deterministic testing and assertions for alarms *(internal)*. |
| [`opc-security-testkit`](crates/opc-security-testkit/) | Fake fixtures and fault injection for security validation *(internal)*. |
| [`opc-session-testkit`](crates/opc-session-testkit/) | Chaos and failure testing for session replication *(internal)*. |
| [`opc-amf-lite-testkit`](crates/opc-amf-lite-testkit/) | Reusable test fixtures and builders for `opc-amf-lite` *(internal)*. |

### Shared Types (`crates/`)

| Crate | Purpose |
| :--- | :--- |
| [`opc-types`](crates/opc-types/) | Shared identifier, version, time, and redaction types. |
| [`opc-schema-validate`](crates/opc-schema-validate/) | Lightweight JSON Schema validation engine (subset used by testbed/evidence schemas). |

### Kubernetes Operators (`operators/`)

* [`sdk-reference-operator`](operators/sdk-reference-operator/): A minimal Kubernetes `controller-runtime` operator in Go that consumes Rust SDK policy decisions (admission validation, conversion, and migration planning) through a schema-driven CLI boundary.
* [`operator-sdk-go`](operators/operator-sdk-go/): Reusable Go packages (`conditions`, `bridge`, `drain`, `workload`, `opmetrics`, `testing`) for building CNF operators.

---

## Verification & Validation Gates

To ensure release stability, the repository enforces several validation gates. These must all pass before a release candidate is pushed.

### 1. Code Formatting
Ensure all workspace Rust code complies with formatting rules:
```bash
cargo fmt --all --check
```

### 2. Git Cleanliness Check
Ensure there are no whitespace errors or trailing diff anomalies:
```bash
git diff --check
```

### 3. Rust Clippy Linters
Ensure the workspace is warning-free across all compilation targets and feature sets:
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### 4. Workspace Test Suite
Run all unit, integration, and chaos test suites:
```bash
cargo test --workspace --all-features --quiet -- --test-threads=4
```

### 5. Go Operator Tests
Run reference operator unit and mock-client integration tests:
```bash
cd operators/sdk-reference-operator
go test ./...
```

### 6. Kubernetes Manifest Validation
Compile and validate Kustomize reference manifests:
```bash
kubectl kustomize operators/sdk-reference-operator/config/default
```

---

## Community

* [Contributing](CONTRIBUTING.md) — development setup, validation gates, and commit conventions.
* [Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1.
* [Security](SECURITY.md) — vulnerability reporting and disclosure policy.
* [Governance](GOVERNANCE.md) — decision process and maintainer criteria.

---

## License

This project is licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE).
