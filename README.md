# OpenPacketCore SDK

[![CI](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/openpacketcore/openpacketcore-sdk/actions/workflows/ci.yml)

A polyglot software development kit of reusable foundations for cloud-native 5G
packet core network functions (CNFs). It includes runtime-chassis APIs,
one shared Openraft engine for config and session consensus, encrypted
config-persistence primitives,
northbound gNMI/NETCONF foundations, data-governance/redaction mechanisms, and
release-assurance schemas and policy APIs. Each surface has its own documented
maturity and deployment boundary; this repository does not currently claim a
workspace-wide high-assurance production profile.

The GTP-U user-plane codec is also applicable to LTE/EPC user plane. The SDK
now includes three experimental, transport-neutral protocol crates: the
`opc-proto-gtpv2c` crate, limited to an S2b typed GTPv2-C subset; the
`opc-proto-diameter` crate for RFC 6733 framing, base peer procedures, and
initial 3GPP application dictionary work; and the `opc-proto-ikev2` crate for
IKEv2 framing, typed executable SA_INIT crypto profiles and key derivation,
proposal selection, and AES-GCM/AES-CBC protected payload mechanisms. They are
consumed as direct protocol dependencies, not through the `opc-sdk` default
feature set or prelude.
They do **not** provide a product-ready EPC or ePDG control-plane stack: full
GTP-C and S1AP stacks are not provided; Diameter realm routing, AAA/HSS/CDF
behavior, IKE SA state machines, EAP-AKA, Child SA lifecycle policy, transport
operations, deployment privileges, and carrier-readiness decisions remain
downstream product responsibilities.

> [!IMPORTANT]
> **Production Readiness & Reference Boundaries**
> * **Rust SDK Core**: Core Rust libraries are covered by the repository's kernel-independent CI gates for the tested feature profiles. This is scoped verification, not a signed release attestation or production-readiness claim; no workspace-wide production profile is currently approved. Candidate releases and downstream CNFs still require release-evidence, privileged/kernel, integration, deployment, and carrier-acceptance validation.
> * **Go Reference Operator**: The Go operator located under `operators/sdk-reference-operator/` is a **reference harness and development utility only**. It is explicitly not a production-grade controller. Downstream product teams are responsible for implementing product-specific Kubernetes operators.
> * **Rust Reference SMF**: The `examples/smf-reference/` workspace is a **reference consumer and API acid test**, not a product-grade SMF. It has no N7/PCF, charging, NAS, or real UPF selection.
> * **No Unconditional Claims**: Standard deployments require integration with your local platform security policies, hardware topologies, and external KMS/SPIFFE infrastructure.

## Getting started

See [`docs/quickstart.md`](docs/quickstart.md) for a guided first build and a minimal CNF example.

Each crate README now documents that crate's purpose, API shape, relationships,
status and limits, roadmap, and verification command. The table below keeps the
workspace-level RFC/ADR map intact so reviewers can trace each crate back to the
design record that owns its boundary.

---

## Workspace Layout & SDK Boundaries

The SDK is organized into a clean multi-crate Rust workspace and a Go reference operator directory:

### Core Runtime & Platform (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-sdk`](crates/opc-sdk/) | Facade crate: feature-gated re-exports of the core composition surface, a `prelude`, and the `minimal_cnf` end-to-end example. | [Quickstart](docs/quickstart.md) |
| [`opc-runtime`](crates/opc-runtime/) | CNF runtime chassis: process startup phases, task supervision, health probes, admin/probe routes, metrics, and graceful SIGTERM drains. | [RFC 008](docs/rfc/008-cnf-runtime-chassis.md), [ADR 0005](docs/adr/0005-runtime-observability-admin-probes.md) |
| [`opc-observability`](crates/opc-observability/) | Tracing subscriber setup with runtime filter reload and structural redaction. | [ADR 0005](docs/adr/0005-runtime-observability-admin-probes.md) |
| [`opc-protocol`](crates/opc-protocol/) | Zero-copy protocol codec framework: traits, context, errors, and fuzzing contracts. | [RFC 005](docs/rfc/005-protocol-framework.md) |
| [`opc-proto-gtpu`](crates/opc-proto-gtpu/) | GTP-U protocol codec for the user-plane data path. | [RFC 005](docs/rfc/005-protocol-framework.md) |
| [`opc-proto-diameter`](crates/opc-proto-diameter/) | Diameter base codec and dictionary scaffold: RFC 6733 header/AVP framing, base peer procedure helpers, bounded grouped AVP validation, fixture-provenance notes, fuzz targets, typed Rf/SWm helpers, and selected 3GPP application dictionary subsets *(experimental; no realm routing, transport operation, AAA/HSS/CDF behavior, or product readiness claim)*. | [RFC 005](docs/rfc/005-protocol-framework.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [Conformance](crates/opc-proto-diameter/CONFORMANCE.md) |
| [`opc-proto-pfcp`](crates/opc-proto-pfcp/) | PFCP codec (TS 29.244): message layer, raw TLV preservation, and typed session-management IEs. | [RFC 005](docs/rfc/005-protocol-framework.md) |
| [`opc-proto-nas`](crates/opc-proto-nas/) | NAS-5GS (TS 24.501) codec: headers, body dispatch, mobile identity, BCD unpacking, Registration/Security Mode IEs, and NAS security hooks *(experimental)*. | [RFC 005](docs/rfc/005-protocol-framework.md) |
| [`opc-proto-ngap`](crates/opc-proto-ngap/) | NGAP (TS 38.413) v0 decoder via `rasn` APER: PDU framing, fixture-proven NGSetupRequest, raw-preserving re-encode *(experimental v0)*. | [RFC 005](docs/rfc/005-protocol-framework.md), [ADR 0013](docs/adr/0013-ngap-asn1-strategy.md) |
| [`opc-proto-gtpv2c`](crates/opc-proto-gtpv2c/) | GTPv2-C (TS 29.274) experimental S2b subset: raw-preserving header/IE shell plus typed Echo/Create/Modify/Delete/Update views. | [RFC 005](docs/rfc/005-protocol-framework.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-proto-ikev2`](crates/opc-proto-ikev2/) | Experimental IKEv2 (RFC 7296/RFC 7383) mechanisms: framing and typed payloads, executable SA_INIT profiles and proposal selection, PRF-HMAC-SHA2 key derivation, AES-GCM/AES-CBC `SK`/`SKF` protection, and fragmentation structure/reassembly helpers *(no IKE SA state machine, EAP-AKA, retransmission cache, or Child SA lifecycle policy)*. | [RFC 005](docs/rfc/005-protocol-framework.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [Conformance](crates/opc-proto-ikev2/CONFORMANCE.md) |
| [`opc-sctp`](crates/opc-sctp/) | Safe Linux SCTP transport wrapper for CNFs that terminate N2/NGAP or other SCTP interfaces. | [ADR 0017](docs/adr/0017-sctp-transport-ffi-boundary.md) |
| [`opc-libsctp-sys`](crates/opc-libsctp-sys/) | Narrow unsafe Linux SCTP UAPI boundary used only by `opc-sctp`; unsupported platforms fail explicitly. | [ADR 0017](docs/adr/0017-sctp-transport-ffi-boundary.md) |
| [`opc-linux-xfrm-sys`](crates/opc-linux-xfrm-sys/) | Narrow unsafe Linux XFRM netlink UAPI boundary; unsupported platforms fail explicitly. | [ADR 0017](docs/adr/0017-sctp-transport-ffi-boundary.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-linux-gtpu-sys`](crates/opc-linux-gtpu-sys/) | Narrow unsafe Linux GTP-U rtnetlink/generic-netlink UAPI boundary used by the safe dataplane wrapper. | [ADR 0017](docs/adr/0017-sctp-transport-ffi-boundary.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-linux-route-sys`](crates/opc-linux-route-sys/) | Narrow unsafe Linux rtnetlink route/rule UAPI boundary used by route steering. | [ADR 0017](docs/adr/0017-sctp-transport-ffi-boundary.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-ipsec-xfrm`](crates/opc-ipsec-xfrm/) | Safe Linux XFRM IPsec backend model, fixed outer-DSCP tc companion loader, mock backend, redaction-safe errors, and opt-in IKEv2 Child SA to XFRM request mapping. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-ipsec-xfrm-ebpf`](crates/opc-ipsec-xfrm-ebpf/) | Standalone Rust tc eBPF companion that consumes reserved XFRM output-mark tokens and stamps outer IPv4/IPv6 DSCP. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-ipsec-xfrm-ebpf-common`](crates/opc-ipsec-xfrm-ebpf-common/) | Shared validated XFRM DSCP mark-token profile, packet rewrite logic, map/program names, and fail-closed carrier classification. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-ipsec-lb`](crates/opc-ipsec-lb/) | Pure SWu IKE/IPsec load-balancing primitives: tagged SPI policy, classifier, rendezvous selector, cookie helper, failover safety guards, audited ownership-fenced re-pin coordination, session-store ownership reads and quorum-backed promotion, Host-XDP steering backend, BGP route-export VIP advertiser, and backend ports. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-ipsec-lb-ebpf`](crates/opc-ipsec-lb-ebpf/) | Standalone Rust XDP eBPF datapath for SWu IKE/ESP steering by stateless SPI tag targets plus bounded override rules. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-ipsec-lb-ebpf-common`](crates/opc-ipsec-lb-ebpf-common/) | Shared SWu IPsec LB eBPF map constants, key/value layouts, counters, and program names for the XDP datapath and userspace loader. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-sa-mirror`](crates/opc-sa-mirror/) | Live IPsec SA keymat mirroring for near-hitless failover in which keys never persist: producer/sink/takeover ports, in-memory zeroizing standby custody, an mTLS-only keymat transport, and takeover output pre-validated for the fenced re-pin *(experimental)*. | [RFC 015](docs/rfc/015-live-sa-mirror.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-route-steering`](crates/opc-route-steering/) | Safe Linux route/rule steering backend model, mock backend, and redaction-safe errors for packet-core CNFs. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-gtpu-dataplane`](crates/opc-gtpu-dataplane/) | Safe Linux GTP-U dataplane backend model, Linux and eBPF backend adapters, per-PDP uplink DSCP, capability probes, and redaction-safe errors. | [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-gtpu-dataplane-ebpf`](crates/opc-gtpu-dataplane-ebpf/) | Standalone Rust eBPF tc datapath program for GTP-U uplink/downlink handling; built with the pinned script outside the host workspace. | [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-gtpu-ebpf-common`](crates/opc-gtpu-ebpf-common/) | Shared GTP-U wire-format constants, map names, and map value layouts for the eBPF datapath and userspace loader. | [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md), [ADR 0018](docs/adr/0018-epc-untrusted-access-sdk-boundary.md) |
| [`opc-node-resources`](crates/opc-node-resources/) | Validates `ResourceProfile` compatibility against observed `NodeCapabilityReport`. | [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |

### Config & Management (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-config-bus`](crates/opc-config-bus/) | Transactional config bus supporting schema validation, tenant segregation, AAD-bound envelope encryption, and admission control. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-config-bus-consensus`](crates/opc-config-bus-consensus/) | Source-build-only sealed-config adapter from the config bus to the existing `ConsensusConfigStore`; it delegates consensus wholesale to Openraft and keeps HKMS/plaintext outside the Raft boundary. Multi-group production qualification remains open. | [ADR 0002](docs/adr/0002-config-store-consensus-ha.md), [ADR 0019](docs/adr/0019-one-openraft-consensus-engine.md) |
| [`opc-config-model`](crates/opc-config-model/) | Shared config-model request, result, identity, and error types. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-persist`](crates/opc-persist/) | Tamper-evident SQLite datastores and a `ConsensusConfigStore` on the shared Openraft engine, with atomic authority fencing, sealed/redacted commands, and exact offline legacy recovery. Production HA qualification remains conditional. | [RFC 001](docs/rfc/001-management-substrate.md), [ADR 0002](docs/adr/0002-config-store-consensus-ha.md), [ADR 0019](docs/adr/0019-one-openraft-consensus-engine.md) |
| [`opc-nacm`](crates/opc-nacm/) | Normalized YANG path parsing and NACM authorization evaluation. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-nacm-config`](crates/opc-nacm-config/) | Typed `/nacm` datastore model with RFC 8341 group/rule-list validation, SPIFFE group selectors, signed-grant resolution, and policy compilation. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-yanggen`](crates/opc-yanggen/) | YANG-to-Rust type projection, RFC 7951 JSON serde, schema registry generation, NETCONF XML/gNMI JSON projections, and patch applicators. | [RFC 002](docs/rfc/002-yang-projection.md) |
| [`opc-mgmt-schema`](crates/opc-mgmt-schema/) | Runtime schema-registry contract consumed by generated CNF models and northbound servers. | [RFC 002](docs/rfc/002-yang-projection.md) |
| [`opc-mgmt-path`](crates/opc-mgmt-path/) | Registry-validated YANG path normalization shared by gNMI, NETCONF, NACM, config commits, and audit. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-principal`](crates/opc-mgmt-principal/) | Converts transport-authenticated SPIFFE or SSH identities into grant-free config principals. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-authz`](crates/opc-mgmt-authz/) | Shared NACM authorization facade for reads, subscriptions, config writes, and management RPC/action execution. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-audit`](crates/opc-mgmt-audit/) | Management operation audit event model and pluggable audit sink for allowed, failed, and denied requests. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-audit-store`](crates/opc-mgmt-audit-store/) | Production SQLite-backed management audit sink with authenticated hash chaining, bounded retention/pages, restart verification, and fail-closed bounded acknowledgement. | [RFC 001](docs/rfc/001-management-substrate.md), [ADR 0004](docs/adr/0004-security-identity-keying-audit.md) |
| [`opc-mgmt-errors`](crates/opc-mgmt-errors/) | Transport-neutral management status taxonomy and gNMI/NETCONF error mappings. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-limits`](crates/opc-mgmt-limits/) | Shared fail-closed input limits for management protocol parsers and sessions. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-command`](crates/opc-mgmt-command/) | Transport-neutral operational command catalog, bounded grammar, schema/action validation, and deterministic registry freeze. | [RFC 014](docs/rfc/014-interactive-operational-console.md) |
| [`opc-mgmt-opstate`](crates/opc-mgmt-opstate/) | CNF-supplied operational-state provider contract for gNMI `Get`/`Subscribe` and NETCONF `<get>`. | [RFC 001](docs/rfc/001-management-substrate.md) |
| [`opc-mgmt-transport`](crates/opc-mgmt-transport/) | Fail-closed mTLS and plaintext-policy bootstrap for management listeners. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-gnmi-server`](crates/opc-gnmi-server/) | Capability-honest gNMI server foundation with schema-backed Capabilities/Get/Set/Subscribe over SDK-managed mTLS. | [gNMI spec](docs/design/opc-gnmi-server-spec.md) |
| [`opc-netconf-server`](crates/opc-netconf-server/) | Capability-gated NETCONF server core with SSH/TLS transports, datastore operations, NACM, audit, and bounded XML handling. | [RFC 001](docs/rfc/001-management-substrate.md) |

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
| [`opc-consensus`](crates/opc-consensus/) | Exact-pinned shared Openraft boundary with bounded codecs, stable cluster/configuration/node identity, and transport contracts; domain crates do not implement competing consensus authority. | [ADR 0019](docs/adr/0019-one-openraft-consensus-engine.md) |
| [`opc-session-store`](crates/opc-session-store/) | Openraft-backed session authority with lease/fenced-CAS semantics, deterministic SQLite state-machine storage, committed journal/watch output, linearizable readiness, bounded snapshots, envelope encryption above consensus, bounded privacy-safe stable IDs, and audited offline migration/recovery campaigns. Networked production qualification remains conditional. | [RFC 004](docs/rfc/004-session-store.md), [ADR 0003](docs/adr/0003-session-store-quorum-replication.md), [Stable-ID runbook](docs/session-store-stable-id-migration.md), [Recovery runbook](docs/session-store-legacy-recovery.md) |
| [`opc-session-cache`](crates/opc-session-cache/) | Coherence-aware read-through session cache with key-scoped invalidation, sequence tracking, and resume recovery. It is not a durability layer and does not elevate the selected backend/profile's maturity. | [RFC 004](docs/rfc/004-session-store.md) |
| [`opc-session-net`](crates/opc-session-net/) | Dedicated mTLS `opc-session-consensus/2` Openraft transport plus a feature-gated legacy backend/restore compatibility protocol. Logical member identity is independent of DNS/FQDN routing. | [RFC 004](docs/rfc/004-session-store.md) |

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
| [`opc-peer-discovery`](crates/opc-peer-discovery/) | Transport-neutral peer discovery, resolver injection, deterministic selection, and peer-discovery evidence. | [RFC 007](docs/rfc/007-sbi-service-framework.md) |
| [`opc-api-nnrf`](crates/opc-api-nnrf/) | Generated Rust types for 3GPP TS 29.510 NRF `NfProfile` / `NfService` *(experimental)*. | [Design note](docs/design/openapi-codegen-plan.md) |

### Release Assurance (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-evidence`](crates/opc-evidence/) | Release-assurance schemas and library primitives for SBOM, VEX, provenance, gap, performance, bundle, and policy evaluation. Complete signed-bundle production and enforcement are not yet wired into repository release workflows. | [RFC 006](docs/rfc/006-conformance-pipeline.md) |

### Operator Lifecycle (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`operator-lifecycle`](crates/operator-lifecycle/) | Kubernetes lifecycle policy foundation for config-apply, admission, compatibility, and drain/upgrade planning. | [RFC 009](docs/rfc/009-operator-lifecycle-upgrade.md) |
| [`operator-controller`](crates/operator-controller/) | Kubernetes operator controller execution layer *(internal, not published)*. | [RFC 009](docs/rfc/009-operator-lifecycle-upgrade.md) |
| [`operator-lifecycle-cli`](crates/operator-lifecycle-cli/) | CLI interface exposing Rust SDK lifecycle contracts to Go controller-runtime operators via JSON *(internal, not published)*. | [RFC 009](docs/rfc/009-operator-lifecycle-upgrade.md) |

### Testing & Integration (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-testbed`](crates/opc-testbed/) | Scenario DSL, virtual time, assertions, fixture provenance, and simulator framework. | [RFC 012](docs/rfc/012-testbed-simulator-framework.md) |
| [`opc-dataplane-testkit`](crates/opc-dataplane-testkit/) | Deterministic dataplane traffic generation, GTP-U helpers, reflectors, continuity evidence, and packet-continuity reports. | [RFC 006](docs/rfc/006-conformance-pipeline.md), [RFC 011](docs/rfc/011-node-dataplane-resource-contract.md) |
| [`opc-sdk-integration`](crates/opc-sdk-integration/) | Integration crate wiring runtime, config bus, alarms, and testbed evidence *(internal, not published)*. | [RFC 012](docs/rfc/012-testbed-simulator-framework.md) |
| [`opc-config-fixture`](crates/opc-config-fixture/) | Generated-like config fixture for integration testing *(internal, not published)*. | [RFC 001](docs/rfc/001-management-substrate.md), [RFC 002](docs/rfc/002-yang-projection.md) |
| [`opc-amf-lite`](crates/opc-amf-lite/) | Realistic AMF-lite control-plane vertical slice integration proving SDK seams *(internal, not published)*. | [ADR 0011](docs/adr/0011-first-nf-vertical-proof.md) |

### Internal Testkits (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-alarm-testkit`](crates/opc-alarm-testkit/) | Deterministic testing and assertions for alarms *(internal)*. | [RFC 013](docs/rfc/013-fault-management-alarm-substrate.md) |
| [`opc-security-testkit`](crates/opc-security-testkit/) | Fake fixtures and fault injection for security validation *(internal)*. | [RFC 003](docs/rfc/003-security-substrate.md) |
| [`opc-session-testkit`](crates/opc-session-testkit/) | Chaos and failure testing for session replication *(internal)*. | [RFC 004](docs/rfc/004-session-store.md) |
| [`opc-amf-lite-testkit`](crates/opc-amf-lite-testkit/) | Reusable test fixtures and builders for `opc-amf-lite` *(internal)*. | [ADR 0011](docs/adr/0011-first-nf-vertical-proof.md) |

### Shared Types (`crates/`)

| Crate | Purpose | Reference |
| :--- | :--- | :--- |
| [`opc-types`](crates/opc-types/) | Shared identifier, version, time, and redaction types. | [RFC 003](docs/rfc/003-security-substrate.md), [RFC 010](docs/rfc/010-data-governance-privacy.md) |
| [`opc-schema-validate`](crates/opc-schema-validate/) | Lightweight JSON Schema validation engine (subset used by testbed/evidence schemas). | [RFC 006](docs/rfc/006-conformance-pipeline.md), [RFC 012](docs/rfc/012-testbed-simulator-framework.md) |

### Kubernetes Operators (`operators/`)

* [`sdk-reference-operator`](operators/sdk-reference-operator/): A minimal Kubernetes `controller-runtime` operator in Go that consumes Rust SDK policy decisions (admission validation, conversion, and migration planning) through a schema-driven CLI boundary.
* [`operator-sdk-go`](operators/operator-sdk-go/): Reusable Go packages (`conditions`, `bridge`, `drain`, `workload`, `cni`, `gates`, `rollout`, `opmetrics`, `testing`) for building CNF operators. Packet-core helper additions for runtime gates, UDP/SCTP ports, Multus/SR-IOV attachments, and drain integration are experimental mechanism helpers; product CRDs, Helm/RBAC, privileges, and readiness policy remain downstream.

### Reference Consumers (`examples/`)

* [`smf-reference`](examples/smf-reference/): A deliberately bounded reference SMF that consumes the Rust SDK from outside the workspace (its own `Cargo.toml` and lockfile). It proves runtime startup, NRF registration, real PFCP/N4 bytes over UDP, and session-state tracking. Not a product-grade SMF.

---

## Workspace Roadmap

Detailed crate roadmaps live in each crate README. At the workspace level, the
current roadmap is:

1. Keep the facade and crate READMEs synchronized with public exports, feature
   flags, verification commands, and maturity boundaries.
2. Harden management-plane integration across generated YANG models, schema
   registries, gNMI, NETCONF, NACM, audit, and config commit flows.
3. Expand protocol conformance where it serves SDK consumers while keeping
   product behavior such as AAA/HSS/CDF logic, IKE SA state machines, and
   carrier policy outside codec crates.
4. Continue privileged Linux dataplane validation for GTP-U, XFRM, route
   steering, SCTP, and eBPF with explicit platform prerequisites.
5. Strengthen session-state, persistence, evidence, and privacy/governance
   contracts before downstream CNFs rely on them as release gates.
6. Move operator lifecycle contracts toward production operator integration
   while keeping the included Go operator as a reference harness.

---

## Verification & Validation Gates

The commands below are repository CI/developer verification gates for their
stated source, feature, and platform scopes. They are necessary but not
sufficient for a production release. End-to-end RFC 006 signed-evidence
enforcement is not yet wired into the release workflow.

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
cargo clippy --locked -p opc-persist --all-targets --no-default-features -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

The isolated `opc-persist` command runs before workspace feature unification so
default-profile conditional imports remain warning-free.

### 4. Management-Plane Policy Gates
Ensure dependency-boundary, SCTP FFI, and generated-management policy checks pass:
```bash
python3 scripts/check-management-plane-policy.py --self-test
python3 scripts/check-management-plane-policy.py --check
```

### 5. Workspace Test Suite
Run all unit, integration, and chaos test suites:
```bash
cargo test --locked -p opc-persist --no-run
cargo test --locked -p opc-persist \
  --test break_glass_tests \
  --test security_policy_tests \
  --test security_policy_stress_tests \
  --test security_policy_empirical_tests \
  -- --test-threads=1
cargo test --locked --workspace --exclude opc-persist --all-features --quiet -- --test-threads=4
cargo test --locked -p opc-persist --all-features --quiet -- --test-threads=1
```

The first command compiles the standalone default-feature test contract, and
the second executes its security-policy and break-glass behavior without test
hooks. The serial all-feature command executes the fault-injection suites as
well as the ordinary persistence coverage.

The standalone eBPF datapath crate is excluded from the host workspace build
graph. Build it with:

```bash
scripts/build-gtpu-ebpf.sh
```

### 6. Rust Documentation
Build workspace documentation with warnings denied:
```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

### 7. Go Operator Tests
Run reference operator and reusable Go operator SDK tests:
```bash
cd operators/sdk-reference-operator
go test ./...

cd ../operator-sdk-go
go test ./...
```

### 8. Kubernetes Manifest Validation
Compile Kustomize reference manifests and render the Helm chart in both cert-manager and manual-certificate modes:
```bash
kubectl kustomize operators/sdk-reference-operator/config/default

helm lint operators/helm/sdk-reference-operator/
helm template sdk-ref operators/helm/sdk-reference-operator/ > /tmp/rendered-certmanager.yaml
helm template sdk-ref operators/helm/sdk-reference-operator/ --set webhook.certMode=manual --set webhook.secretName=my-secret > /tmp/rendered-manual.yaml
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
