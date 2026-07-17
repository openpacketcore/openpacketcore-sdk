# ADR 0018: EPC and Untrusted-Access SDK Boundary

## Status

Accepted

## Date

2026-06-26

## Context

The SDK is beginning a work stream that harvests reusable primitives from an
ePDG-derived source packet for EPC and untrusted-access CNF use cases. Task 0.1
produced the committed inventory in
[`docs/refactoring/epdg-sdk-harvest-inventory.md`](../refactoring/epdg-sdk-harvest-inventory.md)
and the fixture provenance map in
[`docs/refactoring/epdg-sdk-fixture-provenance.md`](../refactoring/epdg-sdk-fixture-provenance.md).
Those documents classify the source material as planning and provenance context,
not as SDK-ready implementation, conformance evidence, or product claims.

This boundary matters because ePDG and EPC systems mix reusable mechanisms with
deployment policy:

- reusable protocol framing, bounded parsing, evidence schemas, resource models,
  redaction classes, and narrow kernel UAPI adapters can belong in a neutral SDK;
- product-specific attach procedures, APN/realm/PLMN selection, retransmission
  policy, IKE/Child SA state machines, lawful-intercept workflow, charging
  policy, CRDs, Helm values, carrier acceptance, and deployment defaults must
  remain outside the SDK.

The current public SDK already states that GTP-U is applicable to LTE/EPC user
plane while EPC control-plane protocols such as GTP-C, Diameter, and S1AP are not
currently provided. This ADR authorizes future *mechanism* work for selected
EPC/untrusted-access primitives without converting the SDK into an ePDG product,
an EPC core, or a carrier-accepted deployment.

## Decision

Adopt the following boundary for ePDG-derived EPC and untrusted-access work.

### 1. Source-use and provenance rule

The task 0.1 inventory and fixture provenance map are the normative inputs for
the first harvest tranche. They are not copy-paste authorization. Each SDK change
MUST re-author reusable behavior in SDK style and MUST keep product bytes,
product tests, and product claims out of conformance evidence unless they later
satisfy ADR 0015 provenance requirements.

If a source crate or directory lacks an explicit compatible license marker, code
copying is blocked until source ownership is confirmed. Concepts may still be
used to design independently authored SDK APIs when that does not import source
implementation.

### 2. Mechanism is SDK-owned; policy is product-owned

The SDK MAY own product-neutral mechanisms that are reusable by multiple packet
core CNFs:

- pure Rust wire codecs and typed views that preserve unknown/raw fields;
- bounded parser limits, hostile-input behavior, fuzz targets, and
  `CONFORMANCE.md` records required by ADR 0015;
- transport-neutral protocol metadata, dictionaries, and peer-test utilities;
- narrow Linux UAPI/sys boundaries plus safe wrappers, where an ADR authorizes
  the unsafe exception and mechanical gates enforce it;
- redaction and regulated-data classification primitives;
- resource/capability models and preflight validators;
- runtime health-gate aggregation primitives;
- simulator scaffolding and release-evidence schemas.

The product that embeds the SDK MUST own deployment and business policy:

- ePDG attach orchestration and subscriber/session lifecycle decisions;
- APN, DNN, realm, PLMN, PGW, AAA/HSS/CDF, and charging policy;
- IKE SA and Child SA state machines, EAP-AKA procedure, cookie/retransmit
  policy, key derivation choices, and 3GPP profile enforcement;
- XFRM SA/SPD policy, namespaces, privileges, kernel module loading, and rollout
  defaults;
- readiness thresholds, drain routing, peer-selection policy, CRD/YANG/Helm
  shapes, lawful-intercept workflow, and carrier acceptance claims.

SDK APIs for these primitives MUST be named and documented as mechanism surfaces,
not as an `epdg` product facade or production-ready EPC control plane.

### 3. Surface-specific boundary

| Surface from task 0.1 inventory | SDK-owned mechanism | Product-owned policy |
| --- | --- | --- |
| GTPv2-C S2b control plane | Experimental `opc-proto-gtpv2c` codec subset, IE framing, typed S2b views, raw/unknown IE preservation, hostile-input limits, fuzz, and conformance scaffolding. | UDP peer lifecycle, PGW selection, APN/realm/PLMN policy, attach/session orchestration, retries, timers, and deployment readiness. |
| Diameter base and 3GPP dictionaries | Future `opc-proto-diameter` header/AVP codec, bounded grouped AVPs, dictionary metadata, base-message helpers, and transport-neutral test helpers. | Realm routing, AAA/HSS/CDF business behavior, peer topology, transport operations, watchdog thresholds, and readiness policy. |
| Linux XFRM / IPsec installer | Narrow sys crate and safe wrapper for Linux XFRM UAPI, mock/dry-run backend, capability probes, redaction-safe error/report types, and exact IKEv2 Child SA intent to XFRM request mapping. | SA/SPD policy, IKE state, namespaces, privileges, key lifetime policy, kernel-module management, traffic readiness, and product rollout defaults. |
| Runtime health gates | Generic gate model, status/impact aggregation, stable JSON projection, and tests for blocking/degraded/unknown/informational gates. | Which gates are required, how peer health affects traffic, LI/charging/readiness thresholds, and drain/routing decisions. |
| Telco redaction and regulated data | Identifier classes and redaction primitives for IMSI/SUPI, MSISDN/GPSI, IMEI/MEI, NAI, SIP URI, APN/DNN, TEID, SPI, Diameter Session-Id, LI identifiers, and delivery addresses. | Lawful-intercept reveal workflow, warrant/correlation policy, retention choices, and deployment-specific support-bundle release decisions. |
| IPsec gateway node resources | Pure `ResourceProfile` and `NodeCapabilityReport` extensions for XFRM, UDP 500/4500, SCTP, Multus/network attachment, Linux capability, and lab-fallback validation. | CRD fields, Helm values, Multus network names, privilege rendering, canonical config projection, and product admission policy. |
| IKEv2 codec | Experimental `opc-proto-ikev2` framing and typed payloads, executable typed IKE-SA profiles, product-neutral SA_INIT proposal selection, PRF-HMAC-SHA2 key derivation, AES-GCM and AES-CBC/HMAC `SK`/`SKF` protection, IKE_AUTH cleartext helpers, Child SA negotiation intent, and RFC 7383 fragment framing/reassembly mechanisms. | IKE SA and EAP-AKA state machines, cookie and retransmit policy, response caching, deployment profile policy, Child SA lifecycle management, fragment queues, key custody, and carrier qualification. |
| EPC/ePDG testbed simulators | Simulator mechanics for AAA/HSS, Diameter peer, PGW S2b, UE/IKE, LI MDF, and charging CDF behaviors built on SDK protocol crates with fixture provenance. | ePDG smoke scenarios, deployment assertions, carrier acceptance, traffic-mix claims, and product soak policy. |
| Packet-core evidence packs | Reusable evidence schemas for protocol coverage, fixture provenance, fuzz corpus digests, redaction validation, kernel dataplane evidence, and explicit gap rows. | Product conformance claims, LI/charging sign-off, carrier acceptance, and readiness release decisions. |
| Generic operator helpers | Reusable Go helper APIs for conditions, observed generation, rollout gates, workload ports, network attachments, drain coordination, metrics, and fake-client tests. | Product CRDs, RBAC, cert-manager choices, LI mounts, XFRM privilege rendering, gNMI push sequence, and Helm defaults. |

### 4. Dependency, safety, and implementation guardrails

All future work under this boundary inherits existing SDK policy:

1. ADR 0014 remains in force: rustls only, tokio only, workspace MSRV 1.88,
   compatible licenses, justified dependencies, and no unauthorized gRPC stack.
2. ADR 0015 remains in force for every `opc-proto-*` codec: spec-authored or
   independent fixtures, byte-exact decode/encode where claimed, raw preservation,
   hostile-input tests, fuzz targets, and honest `CONFORMANCE.md` coverage.
3. ADR 0017 is the pattern for kernel UAPI exceptions. Any XFRM/IPsec sys crate
   MUST be narrow, mechanically checked, locally documented with adjacent
   `SAFETY:` comments, and kept below a safe public wrapper. This does not
   authorize FFI protocol parsers.
4. ePDG-derived fixture bytes are parity evidence until the provenance map's
   intake checklist is satisfied. They may test migration compatibility, but
   they MUST NOT be counted as SDK conformance proof by themselves.
5. Public APIs that can expose subscriber identifiers, key material, TEIDs, SPIs,
   Diameter Session-Id values, or lawful-intercept identifiers MUST include
   redaction-safe `Debug`, `Display`, error, metric, and evidence behavior.

### 5. Maturity and claim language

New crates and APIs created from this work stream start as experimental unless a
separate RFC/ADR, conformance record, and product-neutral test suite justify a
stronger status. Documentation MUST distinguish:

- "SDK provides a reusable primitive/mechanism";
- "a downstream product may compose the primitive into an ePDG/EPC function"; and
- "a downstream product has completed carrier acceptance."

Only the first claim is an SDK claim. The other two remain product claims.

## Consequences

- The SDK can grow reusable EPC and untrusted-access mechanisms without importing
  ePDG product policy, product defaults, or carrier-readiness claims.
- Future implementation tasks have a durable boundary to cite when deciding what
  belongs in `crates/*`, `operators/operator-sdk-go`, and test/evidence crates.
- Reviews can reject changes that make an SDK crate choose APN/realm policy,
  lawful-intercept workflow, charging behavior, production privileges, or attach
  orchestration, even if the source product contained that logic next to reusable
  mechanisms.
- The task 0.1 inventory remains the source map for this harvest tranche, while
  ADR 0014, ADR 0015, and ADR 0017 remain the dependency, conformance, and unsafe
  boundary gates.
