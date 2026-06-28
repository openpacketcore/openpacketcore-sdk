# ePDG SDK Harvest Inventory

This inventory records the ePDG source surfaces reviewed for the EPC and
untrusted-access SDK work stream. It is a planning and provenance aid only: no
ePDG product policy, deployment default, attach orchestration, lawful-intercept
business rule, charging policy, YANG model, CRD, or production-readiness claim is
moved into the SDK by this document. The Phase 0 exit review is
recorded in the [M0 gate readiness check](epdg-sdk-m0-gate-readiness.md). The
Phase 4 P2/P3 integration closeout and downstream adapter boundary are recorded
in the [M4 follow-up closeout](epdg-sdk-m4-closeout.md).

## Import roots and source-use rule

| Role | Import path | Use in SDK work |
| --- | --- | --- |
| Task packet root | the ePDG import packet provided to Phase 0 | Documentary context for imported task packets and shared context. |
| Mirrored source root | the `epdg-source` subtree of the ePDG import packet provided to Phase 0 | Read-only harvest seed and comparison oracle. |

The mirrored ePDG workspace is not a copy-paste target. Each SDK task must
re-author reusable mechanisms in SDK style, keep protocol codecs pure Rust,
record fixture provenance, preserve raw/unknown protocol fields where required,
and satisfy the policy constraints in [ADR 0014](../adr/0014-dependency-toolchain-policy.md),
[ADR 0015](../adr/0015-protocol-codec-conformance-policy.md), and
[ADR 0017](../adr/0017-sctp-transport-ffi-boundary.md). Source paths below are
from the import packet and are not committed repo paths.

## Harvest inventory

| Design surface | ePDG harvest source | SDK target | Priority | License / ownership status | Fixture status | First task ID | Boundary notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GTPv2-C S2b control plane | `common/crates/protocol/eg-gtpv2c-parser`; product use in `nfs/epdg/crates/eg-epdg/src/gtpv2c/session.rs`; important files include `src/gtpv2c/parser.rs`, `serializer.rs`, `model.rs`, `messages.rs`, and `src/tests` | `crates/opc-proto-gtpv2c` | P0 | Crate manifest declares `license = "Apache-2.0"`; still re-author into `opc-protocol` trait style and keep source as comparison material. | Inline Rust tests build packets with local helpers and model builders; one block is labelled realistic S5/S8 capture. Treat as parity/negative seeds until independently annotated. | 1.1, then 1.2-1.5 | SDK owns codec, IE framing, typed S2b views, raw preservation, hostile-input limits, fuzz/conformance shell. Product keeps UDP transport, PGW selection, retransmission, APN policy, and attach state. |
| Diameter base and 3GPP dictionaries | `common/crates/protocol/eg-diameter-parser`; product use in `nfs/epdg/crates/eg-epdg/src/diameter` and `common/crates/platform/eg-aaa` | `crates/opc-proto-diameter` | P0 | Crate manifest declares `license = "Apache-2.0"`; re-author into SDK error, redaction, and feature-flag conventions. | Integration tests construct Diameter messages with local builders and cite RFC 6733 at a suite level; no independent binary fixture corpus was found. Treat as parity/schema seeds, not ADR 0015 conformance. | 2.1, then 2.2-2.5 | SDK owns header/AVP codec, base procedures, bounded grouped AVPs, dictionary metadata, and transport-neutral peer helpers. Product keeps TCP/SCTP connection management, realm routing, AAA/HSS/CDF business policy, and readiness decisions. |
| Linux XFRM / IPsec installer | `nfs/epdg/crates/eg-epdg/src/ipsec.rs`; tests in `nfs/epdg/crates/eg-epdg/tests/ipsec_xfrm_integration.rs` | `crates/opc-linux-xfrm-sys`, `crates/opc-ipsec-xfrm` | P1 | `eg-epdg/Cargo.toml` has no explicit `license` field in the packet; use as design reference unless source ownership confirms copying is allowed. The SDK sys crate must follow the `opc-libsctp-sys` unsafe-boundary pattern. | Kernel integration test is ignored unless Linux plus `CAP_NET_ADMIN` is available; in-memory installer tests are behavioral parity only. No protocol conformance fixture applies. | 3.1, 3.2 | SDK owns narrow Linux UAPI/sys boundary, safe wrapper, capability probe model, mock/dry-run backend, and redaction-safe errors. Product keeps SA policy, IKE negotiation, deployment privileges, and namespace choice. |
| Runtime health gates | `nfs/epdg/crates/eg-epdg/src/admin.rs`; readiness coverage in `nfs/epdg/crates/eg-epdg/tests/daemon_bootstrap.rs` and related daemon/operator tests | `crates/opc-runtime` | P1 | Source crate lacks explicit license in packet; treat field names and tests as product examples to generalize. | Tests are product readiness behavior and marker-file simulations. They can seed SDK gate-set cases but do not prove generic readiness semantics. | 3.3 | SDK owns named gate model, gate impact/status aggregation, and stable readiness JSON shape. Product keeps which gates are critical, peer thresholds, LI/charging policy, and route/drain decisions. |
| Telco redaction and regulated-data classes | `common/crates/platform/eg-nf-types/src/regulated_data.rs`, plus redaction uses in `nfs/epdg/crates/eg-epdg/src/x1.rs`, `x2.rs`, telemetry, and tests under `eg-nf-types/src/regulated_data/tests.rs` | `crates/opc-redaction`, `crates/opc-data-governance` | P1 | `eg-nf-types/Cargo.toml` has no explicit `license` field in the packet; concepts are first-party source context but implementation should be re-authored. | Unit fixtures prove local placeholder behavior for CPNI, precise location, auth material, and LI-sensitive data. Treat as expected-output parity and add SDK-owned telco identifier cases. | 3.4 | SDK owns reusable identifier classes, support-bundle/metrics sanitization, and data-governance classifications. Product keeps lawful-intercept warrant workflow and deployment-specific reveal policy. |
| IPsec gateway node resources | ePDG operator controller context under `operator/controllers`; runtime XFRM probes in `eg-epdg` tests | `crates/opc-node-resources` | P2 | Selected Go controller files carry Apache-2.0 headers, but the whole controller tree is product code; harvest generic condition/resource ideas only. | Operator fake-client tests and runtime marker tests are product preflight parity, not SDK model conformance. | 3.5 | SDK owns pure resource/profile model for XFRM, UDP 500/4500, SCTP, Multus/network attachment, Linux capability, and lab fallback validation. Product keeps CRD rendering, privilege choices, Multus names, and canonical config projection. |
| IKEv2 codec | `common/crates/protocol/eg-ikev2-parser`; product use in `nfs/epdg/crates/eg-epdg/src/ikev2` and `eg-epdg-testkit` | `crates/opc-proto-ikev2` | P2 | Crate manifest declares `license = "Apache-2.0"`; split codec from crypto/profile behavior before any SDK port. | Tests mostly synthesize byte payloads and round-trip the local encoder/decoder. They also reference `tests/fixtures/strongswan_ike_sa_init.bin`, but that file was missing from the packet mirror during this inventory. | 4.1 | SDK owns header/payload codec, unknown payload preservation, fragmentation framing checks, and optional crypto-provider traits. Product keeps IKE SA state machine, EAP-AKA procedure, cookie/retransmit policy, 3GPP profile enforcement, and Child SA installation. |
| EPC/ePDG testbed simulators | `nfs/epdg/crates/eg-epdg-testkit` (`aaa_hss.rs`, `pgw.rs`, `ikev2.rs`, lab/soak binaries) and `common/crates/testkit/eg-testkit` | `crates/opc-testbed` or future `crates/opc-testbed-epc` | P2 | `eg-epdg-testkit/Cargo.toml` has no explicit `license` field in the packet; use behavior as a simulator requirements source. | Smoke and mock-peer tests produce parity evidence for ePDG flows. Future SDK simulators must use SDK protocol crates and carry per-fixture provenance. | 4.2 | SDK owns reusable AAA/HSS, Diameter peer, PGW S2b, UE/IKE, LI MDF, and charging CDF simulator mechanics. Product keeps ePDG-specific smoke scenarios and deployment assertions. |
| Packet-core evidence packs | `docs/conformance`, `docs/conformance/evidence/archive`, smoke artifacts described by `eg-epdg-testkit` docs | `crates/opc-evidence` | P3 | ePDG conformance docs are product claims. Do not import claims as SDK guarantees; design schemas from the evidence shape. | Existing product conformance pages are claim context backed by local tests/CI, not SDK evidence packs. Future evidence must validate redaction and fixture provenance. | 4.3 | SDK owns reusable evidence schemas for protocol coverage, attach procedure summaries, and kernel dataplane evidence. Product keeps carrier acceptance, LI/charging claims, and readiness sign-off. |
| Generic operator helpers | ePDG `operator/controllers` condition, workload, rollout, drain, telemetry, and test-helper patterns | `operators/operator-sdk-go` | P3 | Some controller files include Apache-2.0 headers; nevertheless this is product operator code and should only inform generic helper APIs. | Go fake-client/render tests are parity examples for operator behavior, not reusable SDK fixtures. | 4.4 | SDK owns generic condition reasons, observed-generation helpers, runtime-gate rollout helpers, workload port/Multus helpers, and tests. Product keeps CRDs, Helm values, LI mounts, XFRM privilege rendering, and gNMI push sequence. |

## Surfaces deliberately out of first harvest scope

- Full ePDG attach, APN, realm, PLMN, charging, lawful-intercept, YANG, CRD,
  and deployment policy stay product-owned.
- `common/crates/platform/eg-session-store` can inform future session adapter
  work, but it is not part of the first EPC/untrusted-access SDK addition set.
- `common/crates/platform/eg-ike-crypto` can inform a future crypto-provider
  boundary, but no IKE crypto policy moves into `opc-proto-ikev2`.
- Existing SDK crates must not gain OpenSSL/native-tls, a second async runtime,
  unauthorized `tonic`/`prost`, or broad FFI protocol parser dependencies.

## Required follow-up provenance actions

1. Re-confirm license/ownership before copying from any packet source whose
   crate or directory lacks an explicit Apache-2.0 license marker.
2. Re-author protocol conformance fixtures from the relevant specifications or
   from independently captured implementations with capture metadata.
3. Label ePDG-derived bytes as parity evidence unless they are independently
   sourced and reviewed under ADR 0015.
4. Add redaction tests for every public `Debug`, `Display`, error, metrics, and
   evidence surface that can contain subscriber identifiers, key material,
   Diameter Session-Id values, TEIDs, SPIs, or LI identifiers.
5. Keep new APIs experimental until SDK-owned tests and at least one product or
   simulator validate that the surface is product-neutral.
