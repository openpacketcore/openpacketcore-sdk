# ePDG SDK Final Hardening Triage

This triage records the final-hardening review for the EPC/untrusted-access SDK
work stream. It is a cleanup ledger only: it does not expand SDK protocol
coverage, production-readiness claims, or downstream ePDG product scope beyond
the evidence already recorded in ADR 0018, the per-crate `CONFORMANCE.md` files,
and the phase gate notes.

## Evidence sources reviewed

| Source | Evidence used | Triage outcome |
| --- | --- | --- |
| Phase 0 gate and seam steward (`T-1b4196a6`, `T-acc98133`, `T-d42e0d6c`) | M0 inventory/provenance docs, `.brehon` artifact check, deep-`TMPDIR` Unix-socket seam | Converted before final hardening: `.brehon/` is ignored and the Unix-socket test helper cleanup was promoted and closed. No remaining final-hardening candidate. |
| Phase 1 GTPv2-C (`T-980a0abd`) | GTPv2-C crate, fuzz/corpus/conformance work, Phase 1 gate | No open cleanup candidate found. Remaining expanded procedure/IE coverage and independent fixture provenance are documented experimental-surface gaps, not before-main cleanup. |
| Phase 2 Diameter (`T-e29a136b`) | Diameter crate, CI/fuzz self-test, README/CHANGELOG/CONTRIBUTING updates, Phase 2 seam notes | One concrete docs-sync candidate found: `docs/implementation-status.md` and the `opc-sdk` facade docs still omit `opc-proto-diameter` from some protocol-status/direct-dependency summaries. |
| Phase 3 XFRM/readiness/redaction/node resources (`T-81ece0ab`, `T-c418ba27`) | Phase 3 seam steward and promoted follow-ups (`T-2150ee6a`, `T-c75cd782`, `T-6df97afd`, `T-2bc136a7`) | Converted or waived before final hardening. README ADR reference, node-resource type-hygiene, and telco-redaction review chains are terminal; residual product policy remains downstream by ADR 0018. |
| Phase 4 IKEv2/testbed/evidence/operator helpers (`T-8468bea7`, `T-7f59a2fe`) | M4 closeout, IKEv2/testbed/operator/evidence follow-ups (`T-3fc6bb76`, `T-8eeb94b6`, `T-c5834e24`, `T-d4e8b118`, `T-97b5e5c1`) | Most review follow-ups are converted/closed or explicitly waived. The actionable packet-core/gates residuals were deduplicated into final-hardening task `T-0e9cac9a`, approved and merged into the final-hardening branch. |
| M4 downstream adapter closeout (`T-f66d1016`) | `docs/refactoring/epdg-sdk-m4-closeout.md` downstream adapter list | Explicitly outside this SDK plan: product IKE SA/EAP-AKA/Child SA policy, ePDG attach orchestration, carrier-readiness evidence mapping, CRD/Helm/privilege wiring, and downstream fixture intake. No final-hardening task should absorb these. |

## Deduplicated cleanup ledger

| Candidate | Evidence | Decision |
| --- | --- | --- |
| Packet-core redaction false-negatives, schema-version drift guard, inline wrong-version schema tests, and duplicate rollout-gate test case | Approved-review follow-ups consolidated in `T-0e9cac9a` from `T-97b5e5c1` and `T-7f59a2fe` | Converted to concrete final-hardening task `T-0e9cac9a`; no duplicate task needed. |
| Operator helper API nits after duplicate-port and degraded-gate fixes | `T-d4e8b118` review follow-ups | Waived with rationale in Brehon as doc/test-symmetry nitpicks after functional fixes and tests. No before-main cleanup. |
| Node-resource `CniType` residual type hygiene | `T-c75cd782`, `T-6df97afd` | Converted and closed. No final-hardening task needed. |
| IKEv2 scaffold conformance defaults and fuzz workflow coverage | `T-3fc6bb76`; `.github/workflows/fuzz.yml` includes `opc-proto-ikev2` and `opc-proto-gtpv2c` | Converted and closed. Remaining typed-payload/fragmentation/fixture-provenance work is documented as experimental future scope. |
| EPC/ePDG simulator malformed-response runner path | `T-8eeb94b6` | Converted and closed. No final-hardening task needed. |
| Deep worktree Unix-socket path failures in tests | Phase 0 seam steward notes and `T-d42e0d6c` | Converted and closed. No final-hardening task needed. |
| Downstream ePDG adapter/product work | `docs/refactoring/epdg-sdk-m4-closeout.md` | Explicitly deferred outside this SDK plan by ADR 0018 boundary. Do not convert into final-hardening scope. |
| Protocol-status documentation drift for Diameter and IKEv2 | Current repo: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.github/workflows/fuzz.yml`, and `.github/workflows/ci.yml` include `opc-proto-diameter`, but `docs/implementation-status.md` RFC 005 rows 005-6/005-8 and the `opc-sdk` facade docs (`crates/opc-sdk/src/lib.rs`, `crates/opc-sdk/README.md`) summarize the new direct-dependency protocol set without `opc-proto-diameter` and the experimental `opc-proto-ikev2` | Owned by concrete final-hardening task `T-0cc9d976` ("Docs sync: reflect opc-proto-diameter and opc-proto-ikev2 in implementation-status and opc-sdk facade docs"), approved 3/3 and merged into the final-hardening branch. Actioned/closed; not at supervisor discretion. The IKEv2 facade-doc omission was covered by the same task. |

## Current final-hardening state

- `T-0e9cac9a` (packet-core redaction false-negatives and schema-version drift
  guard) is a concrete final-hardening task, approved and merged into the
  final-hardening branch.
- `T-0cc9d976` ("Docs sync: reflect opc-proto-diameter and opc-proto-ikev2 in
  implementation-status and opc-sdk facade docs") is a concrete final-hardening
  task, approved 3/3 and merged into the final-hardening branch.
- `T-0a1f3cdd` — "Resolve deferred cross-epic seams" (seeded final-hardening
  task; sequenced after triage).
- `T-8c57ecee` — "Final validation and operator readiness pass" (seeded
  final-hardening gate; runs last).
- These two seeded tasks are remaining sequencing work, not un-triaged deferred
  candidates. No broad rewrite candidate was identified. Downstream
  adapter/product work is intentionally outside the SDK final-hardening epic.

## Acceptance conclusion

Every deferred cross-epic cleanup candidate identified in this triage is either
a concrete final-hardening task (`T-0cc9d976` and `T-0e9cac9a`, both approved
and merged into the final-hardening branch) or explicitly waived with rationale
in the ledger above. No candidate is left open.
