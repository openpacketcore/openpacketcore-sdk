# OpenPacketCore SDK

[![CI](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml)

OpenPacketCore SDK is a Rust workspace for building cloud-native packet-core
network functions. It provides reusable SDK primitives for runtime startup,
configuration, management protocols, session state, security, observability,
protocol codecs, dataplane integration, operator lifecycle contracts, and
release-assurance evidence.

The repository is intentionally modular. The root README describes the workspace
shape and cross-crate roadmap; each crate README is the source of truth for that
crate's API surface, status, limitations, verification command, and local
roadmap.

## Boundary

- The Rust SDK crates are reusable building blocks, not a complete AMF, SMF,
  UPF, ePDG, N3IWF, or operator product.
- Experimental protocol crates expose useful codec/mechanism APIs, but do not
  claim full 3GPP control-plane product behavior.
- Linux dataplane and kernel-facing crates require the privileges, kernel
  modules, network namespaces, eBPF support, and platform policy expected by
  their individual READMEs.
- The Go operator under `operators/sdk-reference-operator/` is a reference
  harness. Product teams are expected to build product-specific Kubernetes
  controllers and CRDs.
- The reference SMF under `examples/smf-reference/` is an API acid test, not a
  production SMF.

## Getting Started

Start with [`docs/quickstart.md`](docs/quickstart.md) for a first build and a
minimal CNF example.

For the facade API, see [`crates/opc-sdk/README.md`](crates/opc-sdk/README.md).
For crate-specific usage and status, open the README in the crate directory.

## API Shape

### Facade, Runtime, And Shared Types

| Crate | API shape |
| :--- | :--- |
| [`opc-sdk`](crates/opc-sdk/) | Feature-gated facade re-exporting the core SDK crates plus a prelude and minimal CNF example. |
| [`opc-runtime`](crates/opc-runtime/) | Startup phases, task supervision, shutdown/drain hooks, health checks, runtime modes, UDP helpers, and optional observability bootstrap. |
| [`opc-types`](crates/opc-types/) | Shared IDs, NF kinds, PLMN/S-NSSAI values, schema/config versions, timestamps, transaction IDs, and redaction wrappers. |
| [`opc-observability`](crates/opc-observability/) | Tracing subscriber setup, runtime filter reload, and redacting field formatting. |
| [`opc-schema-validate`](crates/opc-schema-validate/) | Lightweight JSON Schema subset validator used by SDK fixtures and evidence schemas. |

### Configuration And Management

| Crate | API shape |
| :--- | :--- |
| [`opc-config-model`](crates/opc-config-model/) | Commit requests/results, trusted principals, request identity, config operations, validation context, and config error taxonomy. |
| [`opc-config-bus`](crates/opc-config-bus/) | Atomic config snapshots, commit sequencing, authorizers, datastores, rollback, restore, metrics, and bounded subscriber fanout. |
| [`opc-config-fixture`](crates/opc-config-fixture/) | Generated-like toy config model and deltas for integration tests. |
| [`opc-persist`](crates/opc-persist/) | `ConfigStore` contract, SQLite backend, quorum/fenced replicas, break-glass controls, security policy, audit integration, and consensus-node binary. |
| [`opc-nacm`](crates/opc-nacm/) | Normalized YANG paths and NACM rule evaluation. |
| [`opc-nacm-config`](crates/opc-nacm-config/) | RFC 8341-style NACM datastore model, validation, SPIFFE workload selectors, and policy compiler. |
| [`opc-yanggen`](crates/opc-yanggen/) | YANG source ingest, constrained IR lowering, Rust/schema projection, generated registry support, and `opc-yanggen` CLI. |
| [`opc-mgmt-schema`](crates/opc-mgmt-schema/) | Runtime YANG schema registry, node metadata, NETCONF projection traits, XML render/edit traits, and registry validation. |
| [`opc-mgmt-path`](crates/opc-mgmt-path/) | Registry-validated canonical YANG path construction and resolution. |
| [`opc-mgmt-principal`](crates/opc-mgmt-principal/) | Mapping SPIFFE or SSH transport identities into config-bus trusted principals and signed grants. |
| [`opc-mgmt-authz`](crates/opc-mgmt-authz/) | NACM authorization facades for reads, writes, subscriptions, and exec/action paths. |
| [`opc-mgmt-audit`](crates/opc-mgmt-audit/) | Management audit event model, outcome/reason labels, and pluggable audit sink. |
| [`opc-mgmt-errors`](crates/opc-mgmt-errors/) | Transport-neutral management status taxonomy and gNMI/NETCONF error mappings. |
| [`opc-mgmt-limits`](crates/opc-mgmt-limits/) | Fail-closed parser/session/input bounds shared by management protocols. |
| [`opc-mgmt-opstate`](crates/opc-mgmt-opstate/) | Operational-state provider and event source contracts for northbound reads/subscriptions. |
| [`opc-mgmt-transport`](crates/opc-mgmt-transport/) | Management-plane TLS bootstrap, ALPN policy, and plaintext-mode guardrails. |
| [`opc-gnmi-server`](crates/opc-gnmi-server/) | Capability-honest gNMI foundation for Capabilities/Get/Set/Subscribe over SDK-managed transport. |
| [`opc-gnmi-server/proto`](crates/opc-gnmi-server/proto/) | Checked-in protobuf sources and generated-code notes for the gNMI server crate. |
| [`opc-netconf-server`](crates/opc-netconf-server/) | Capability-gated NETCONF server core, framing, transports, sessions, NACM/audit hooks, bounded XML, and testkit support. |

### Security, Identity, Privacy, And Evidence

| Crate | API shape |
| :--- | :--- |
| [`opc-identity`](crates/opc-identity/) | SPIFFE identity model, file SVID source, trust bundles, reload events, and SVID watcher. |
| [`opc-tls`](crates/opc-tls/) | Reloading rustls client/server configs and SPIFFE-aware certificate verifiers. |
| [`opc-key`](crates/opc-key/) | Key-provider traits, in-memory provider, key scopes, AEAD payload helpers, and KMS boundary traits. |
| [`opc-key-vault`](crates/opc-key-vault/) | HashiCorp Vault Transit adapter for `opc-key`, with optional Kubernetes auth. |
| [`opc-crypto`](crates/opc-crypto/) | AEAD envelope encode/decode and provider-driven encryption/decryption helpers. |
| [`opc-data-governance`](crates/opc-data-governance/) | Data classes, telco identifier classes, and retention policy types. |
| [`opc-redaction`](crates/opc-redaction/) | Redaction levels, safe rendering, keyed digests, telco identifiers, metrics labels, and support-bundle redaction. |
| [`opc-privacy`](crates/opc-privacy/) | Minimization policies, cohort aggregation, value binning, and identifier hashing. |
| [`opc-export`](crates/opc-export/) | Classified export metadata, payload state, and validation errors for signed/exported items. |
| [`opc-evidence`](crates/opc-evidence/) | Evidence bundles, manifests, requirements, gap gates, SBOM/VEX records, provenance, dataplane snapshots, and release policy evaluation. |

### Session State

| Crate | API shape |
| :--- | :--- |
| [`opc-session-store`](crates/opc-session-store/) | Session backend/store contracts, records, leases, CAS, quorum/fenced replicas, payload codecs, restore evidence, handover, fake backend, and SQLite backend. |
| [`opc-session-cache`](crates/opc-session-cache/) | Key-scoped invalidation, sequence tracking, and resume-aware session cache. |
| [`opc-session-net`](crates/opc-session-net/) | Experimental networked session replication protocol, remote backend client, and replication server. |

### Protocols, Transport, And SBI

| Crate | API shape |
| :--- | :--- |
| [`opc-protocol`](crates/opc-protocol/) | Shared codec traits, decode/encode contexts, structured errors, spec references, and fuzzing contracts. |
| [`opc-proto-gtpu`](crates/opc-proto-gtpu/) | GTP-U header/message codec, extension-header walking, PDU Session Container helpers, and chain validation. |
| [`opc-proto-pfcp`](crates/opc-proto-pfcp/) | PFCP message/header codec, raw IE preservation, typed N4 session-management IEs, and Production Profile v1 builders/validators. |
| [`opc-proto-gtpv2c`](crates/opc-proto-gtpv2c/) | Experimental GTPv2-C S2b subset: header, raw/typed IE layer, message shell, and S2b profile builders. |
| [`opc-proto-ngap`](crates/opc-proto-ngap/) | Experimental NGAP APER PDU framing, first AMF N2 typed dispatch, and raw-preserving re-encode path. |
| [`opc-proto-nas`](crates/opc-proto-nas/) | Experimental NAS-5GS framing, mobile identity views, BCD helpers, message dispatch, and NAS security hooks. |
| [`opc-proto-diameter`](crates/opc-proto-diameter/) | Experimental Diameter RFC 6733 header/AVP codec, dictionary scaffold, peer helpers, and selected app dictionaries. |
| [`opc-proto-ikev2`](crates/opc-proto-ikev2/) | Experimental IKEv2 mechanism crate for headers, payload chains, fragmentation, NAT detection, SA_INIT/AUTH helpers, and crypto provider traits. |
| [`opc-api-nnrf`](crates/opc-api-nnrf/) | Generated Rust payload types for 3GPP TS 29.510 NRF APIs; operation wiring lives elsewhere. |
| [`opc-sbi`](crates/opc-sbi/) | Shared SBI auth, client/server primitives, headers, problem details, retry policy, NRF helpers, runtime hooks, and testkit support. |
| [`opc-peer-discovery`](crates/opc-peer-discovery/) | Transport-neutral peer discovery inputs, resolver injection, cache keys, deterministic selection, and evidence output. |
| [`opc-sctp`](crates/opc-sctp/) | Safe SCTP endpoint/association model, PPIDs, connect projections, Diameter SCTP peer helpers, metrics, and health. |
| [`opc-libsctp-sys`](crates/opc-libsctp-sys/) | Narrow Linux SCTP socket UAPI wrapper used by `opc-sctp`. |

### Dataplane, Linux, And Node Resources

| Crate | API shape |
| :--- | :--- |
| [`opc-gtpu-dataplane`](crates/opc-gtpu-dataplane/) | Safe GTP-U dataplane backend trait, Linux backend, eBPF backend adapter, mock backend, probe model, PDP context model, and redaction-safe errors. |
| [`opc-gtpu-dataplane-ebpf`](crates/opc-gtpu-dataplane-ebpf/) | Standalone Rust eBPF tc datapath program for GTP-U uplink/downlink handling; built with the pinned script, not normal host Cargo. |
| [`opc-gtpu-ebpf-common`](crates/opc-gtpu-ebpf-common/) | Shared wire-format constants, map names, map value layouts, checksum helpers, and GTP-U classification for eBPF/userspace. |
| [`opc-dataplane-testkit`](crates/opc-dataplane-testkit/) | Deterministic traffic generation, GTP-U helpers, reflectors, continuity observer, and dataplane evidence reports. |
| [`opc-ipsec-xfrm`](crates/opc-ipsec-xfrm/) | Safe XFRM backend trait, Linux/mock/unsupported backends, IPsec model, composite reconciliation, and optional IKEv2 Child SA mapping. |
| [`opc-route-steering`](crates/opc-route-steering/) | Safe route/rule steering backend trait, Linux/mock/unsupported backends, route/rule model, and redaction-safe errors. |
| [`opc-linux-gtpu-sys`](crates/opc-linux-gtpu-sys/) | Narrow Linux GTP-U rtnetlink/generic-netlink UAPI wrapper. |
| [`opc-linux-route-sys`](crates/opc-linux-route-sys/) | Narrow Linux rtnetlink route/rule UAPI wrapper. |
| [`opc-linux-xfrm-sys`](crates/opc-linux-xfrm-sys/) | Narrow Linux XFRM netlink UAPI wrapper. |
| [`opc-node-resources`](crates/opc-node-resources/) | Node capability reports, resource profiles, CPU/NUMA/hugepage/network/BPF/pod-security checks, and dataplane preflight validation. |

### Alarms And Fault Management

| Crate | API shape |
| :--- | :--- |
| [`opc-alarm`](crates/opc-alarm/) | Alarm model, severity taxonomy, manager, sink traits, in-memory store, optional NACM adapter, and optional persistence adapter. |
| [`opc-alarm-k8s`](crates/opc-alarm-k8s/) | Projection from alarms to Kubernetes-like conditions and events. |
| [`opc-alarm-yang`](crates/opc-alarm-yang/) | Alarm YANG schema string and JSON operational projection. |
| [`opc-alarm-testkit`](crates/opc-alarm-testkit/) | Alarm and audit assertions plus redaction checks for tests. |

### Operator Lifecycle

| Crate | API shape |
| :--- | :--- |
| [`operator-lifecycle`](crates/operator-lifecycle/) | Admission, compatibility, config-apply, drain/upgrade planning, phase/status projection, and reconcile intent contracts. |
| [`operator-controller`](crates/operator-controller/) | Controller execution helpers for CRD conversion, state migration, drain execution, multi-cluster status, and status patches. |
| [`operator-lifecycle-cli`](crates/operator-lifecycle-cli/) | JSON CLI bridge exposing Rust lifecycle contracts to Go controller-runtime operators. |

### Integration Crates And Testkits

| Crate | API shape |
| :--- | :--- |
| [`opc-testbed`](crates/opc-testbed/) | Scenario DSL, virtual time, runner, assertions, fixture provenance, evidence, and simulator framework. |
| [`opc-sdk-integration`](crates/opc-sdk-integration/) | Toy network function wiring runtime, config bus, alarms, and testbed evidence. |
| [`opc-amf-lite`](crates/opc-amf-lite/) | Internal AMF-lite vertical slice for proving SDK seams; not a production AMF. |
| [`opc-amf-lite-testkit`](crates/opc-amf-lite-testkit/) | Fixture builders and pattern docs for `opc-amf-lite`. |
| [`opc-security-testkit`](crates/opc-security-testkit/) | Fake CA/SPIRE/KMS fixtures and fault injection for security tests. |
| [`opc-session-testkit`](crates/opc-session-testkit/) | Skewable clock, chaos testkit, and restore evidence assertions for session replication. |

## Non-Rust Reference Areas

| Path | Purpose |
| :--- | :--- |
| [`operators/sdk-reference-operator`](operators/sdk-reference-operator/) | Go controller-runtime reference harness that consumes Rust lifecycle decisions through the CLI boundary. |
| [`operators/operator-sdk-go`](operators/operator-sdk-go/) | Reusable Go operator helpers for conditions, bridges, drain handling, workload policy, CNI, gates, rollout, metrics, and tests. |
| [`examples/smf-reference`](examples/smf-reference/) | Bounded Rust reference SMF consumer with real PFCP/N4 bytes and SDK runtime integration; not a product SMF. |

## Roadmap

The crate READMEs contain the detailed roadmap for each local API. At the
workspace level, current work is organized around:

1. Keeping the facade and crate READMEs synchronized with public exports,
   feature flags, test commands, and explicit maturity boundaries.
2. Hardening management-plane integration across generated YANG models,
   schema registries, gNMI, NETCONF, NACM, audit, and config commit flows.
3. Expanding protocol conformance where it serves SDK consumers, while keeping
   product behavior such as AAA/HSS/CDF logic, IKE SA state machines, and
   carrier policy outside codec crates.
4. Continuing privileged Linux dataplane validation for GTP-U, XFRM, route
   steering, SCTP, and eBPF without hiding the platform prerequisites.
5. Strengthening session-state, persistence, evidence, and privacy/governance
   contracts before downstream CNFs rely on them as release gates.
6. Moving operator lifecycle contracts toward production operator integration
   while keeping the included Go operator as a reference harness.

## Verification Gates

Use these gates before publishing a release candidate or relying on a broad
workspace change.

### Rust Formatting

```bash
cargo fmt --all --check
```

### Diff Hygiene

```bash
git diff --check
```

### Rust Lints

```bash
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

### Management-Plane Policy

```bash
python3 scripts/check-management-plane-policy.py --self-test
python3 scripts/check-management-plane-policy.py --check
```

### Rust Tests

```bash
cargo test --locked --workspace --exclude opc-persist --all-features --quiet -- --test-threads=4
cargo test --locked -p opc-persist --all-features --quiet -- --test-threads=1
```

The standalone eBPF datapath crate is excluded from the host workspace build
graph. Build it with:

```bash
scripts/build-gtpu-ebpf.sh
```

### Rust Documentation

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

### Go Operator Tests

```bash
cd operators/sdk-reference-operator
go test ./...

cd ../operator-sdk-go
go test ./...
```

### Kubernetes Manifests

```bash
kubectl kustomize operators/sdk-reference-operator/config/default

helm lint operators/helm/sdk-reference-operator/
helm template sdk-ref operators/helm/sdk-reference-operator/ > /tmp/rendered-certmanager.yaml
helm template sdk-ref operators/helm/sdk-reference-operator/ --set webhook.certMode=manual --set webhook.secretName=my-secret > /tmp/rendered-manual.yaml
```

## Community

- [Contributing](CONTRIBUTING.md) - development setup, validation gates, and commit conventions.
- [Code of Conduct](CODE_OF_CONDUCT.md) - Contributor Covenant v2.1.
- [Security](SECURITY.md) - vulnerability reporting and disclosure policy.
- [Governance](GOVERNANCE.md) - decision process and maintainer criteria.

## License

This project is licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE).
