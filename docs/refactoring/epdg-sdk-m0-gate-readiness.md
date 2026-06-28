# ePDG SDK M0 Gate Readiness Check

This document records the Phase 0 design-gate review for the EPC and
untrusted-access SDK work stream. It is a readiness checkpoint for later SDK
implementation tasks; it does not import ePDG product policy, deployment
configuration, carrier-readiness claims, or source implementation into this
repository.

## Reviewed repo-local inputs

| Gate input | Repo-local source | Review result |
| --- | --- | --- |
| Harvest inventory | [ePDG SDK harvest inventory](epdg-sdk-harvest-inventory.md) | The inventory maps each reviewed ePDG source surface to a proposed SDK target, priority, ownership/licensing status, fixture status, first source task ID, and product-vs-SDK boundary note. |
| Fixture provenance map | [ePDG SDK fixture provenance map](epdg-sdk-fixture-provenance.md) | The map classifies observed test bytes as conformance, parity, not-applicable, or blocked/unknown evidence and provides a fixture intake checklist for follow-up protocol tasks. |
| Boundary ADR | [ADR 0018](../adr/0018-epc-untrusted-access-sdk-boundary.md) | Accepted. The ADR defines reusable SDK mechanisms versus product-owned policy for every harvested surface and references both Phase 0 provenance documents. |
| Dependency/toolchain guardrails | [ADR 0014](../adr/0014-dependency-toolchain-policy.md) | Future tasks inherit rustls-only, tokio-only, MSRV, licensing, unsafe, and dependency-justification policy. |
| Protocol conformance guardrails | [ADR 0015](../adr/0015-protocol-codec-conformance-policy.md) | Future `opc-proto-*` tasks must use spec-authored or independent fixtures, raw preservation, hostile-input tests, fuzz targets, and honest `CONFORMANCE.md` claims. |
| Unsafe transport-boundary guardrails | [ADR 0017](../adr/0017-sctp-transport-ffi-boundary.md) | Future Linux XFRM/IPsec sys work must follow the single-narrow-sys-crate pattern and must not reopen foreign C protocol codec FFI. |

## Later-task source-reference readiness

Later work should start from the repo-local documents above and the source paths
summarized below. The source paths are documentary references from the import
packet, not committed repository paths and not copy-paste authorization.

| Later source task area | Start from these Phase 0 references | Readiness conclusion |
| --- | --- | --- |
| 1.1-1.5 GTPv2-C S2b codec work | Harvest row for `common/crates/protocol/eg-gtpv2c-parser`, the fixture-provenance GTPv2-C row, ADR 0018 surface boundary, and ADR 0015. | Ready to start without direct `_scratch` discovery. Required first action is to create SDK-authored fixtures and keep ePDG bytes as parity until independently proven. |
| 2.1-2.5 Diameter base and app dictionaries | Harvest row for `common/crates/protocol/eg-diameter-parser`, the fixture-provenance Diameter row, ADR 0018 surface boundary, ADR 0014, and ADR 0015. | Ready to start without direct `_scratch` discovery. Local builder cases are parity/schema seeds, not conformance fixtures. |
| 3.1-3.2 Linux XFRM and safe IPsec backend | Harvest rows for `nfs/epdg/crates/eg-epdg/src/ipsec.rs` and related tests, the fixture-provenance XFRM/IPsec row, ADR 0018, ADR 0014, and ADR 0017. | Ready to start. License gaps and unsafe-boundary requirements are explicitly recorded before implementation begins. |
| 3.3 Runtime health gates | Harvest row for `admin.rs` and readiness tests, fixture-provenance runtime-health row, and ADR 0018. | Ready to start. Product readiness policy remains out of scope; SDK work should focus on generic gate aggregation and JSON projection. |
| 3.4 Telco redaction and regulated-data classes | Harvest row for `regulated_data.rs` and LI/telemetry uses, fixture-provenance telco-redaction row, ADR 0018, and ADR 0014. | Ready to start. Synthetic SDK-owned examples and redaction-safe public surfaces are required before claims expand. |
| 3.5 IPsec gateway node resources | Harvest row for operator/resource preflight material, fixture-provenance node-resource row, and ADR 0018. | Ready to start. SDK work is a pure resource/profile model; CRDs, Helm values, privilege choices, and deployment defaults stay product-owned. |
| 4.1 IKEv2 codec | Harvest row for `common/crates/protocol/eg-ikev2-parser`, fixture-provenance IKEv2 row, ADR 0018, and ADR 0015. | Ready to start with a known evidence gap: the referenced StrongSwan fixture was missing from the packet mirror and must be restored or replaced before independent-fixture claims. |
| 4.2 EPC/ePDG testbed simulators | Harvest row for `eg-epdg-testkit`, fixture-provenance simulator row, and ADR 0018. | Ready to start. Future simulators must use SDK protocol crates and carry per-fixture provenance. |
| 4.3 Packet-core evidence packs | Harvest row for product conformance/evidence pages, fixture-provenance evidence-pack row, and ADR 0018. | Ready to start. Product conformance pages are input shape examples only; SDK evidence schemas must include explicit gap and provenance fields. |
| 4.4 Generic operator helpers | Harvest row for operator helper patterns, fixture-provenance operator row, ADR 0018, and existing operator boundary ADRs. | Ready to start. Helper APIs must stay product-neutral and avoid ePDG-specific CRDs, LI mounts, and deployment defaults. |

## Gate checklist

- [x] Phase 0 inventory exists in a committed repo-local document.
- [x] Fixture provenance is separated from the inventory and prevents parity
      bytes from being counted as SDK conformance evidence.
- [x] Boundary ADR is accepted and links back to the inventory and provenance
      map.
- [x] Repo-local Phase 0 docs avoid absolute packet paths and `_scratch` paths;
      later tasks can use the committed inventory/provenance/ADR references as
      their starting point.
- [x] Known gaps are explicit and assigned to later task areas rather than hidden
      in the Phase 0 source packet.
- [x] The review preserves existing SDK product-claim boundaries: these
      documents authorize reusable mechanisms only, not an ePDG product, EPC
      control-plane implementation, deployment default, or carrier acceptance
      claim.

## M0 exit decision

M0 exit criteria are satisfied: the harvest inventory, fixture provenance map,
and EPC/untrusted-access boundary ADR provide sufficient repo-local source
references for later imported tasks to start without reading ignored `_scratch`
paths directly.
