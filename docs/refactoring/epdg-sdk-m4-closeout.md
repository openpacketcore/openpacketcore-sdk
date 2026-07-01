# M4 ePDG SDK follow-up closeout

This closeout records the Phase 4 gate for the EPC/untrusted-access harvest
stream. It is a repository-local roadmap note, not product certification or
carrier-acceptance evidence.

## Gate summary

The Phase 4 P2/P3 additions are accepted only as SDK mechanisms:

| Surface | SDK artifact | Experimental boundary |
| --- | --- | --- |
| IKEv2 codec scaffold | `crates/opc-proto-ikev2` | `README.md` and `CONFORMANCE.md` describe header, payload-chain, IKE_AUTH helper, Child SA intent, and RFC 7383 SKF structural coverage; IKE SA state machines, EAP-AKA, Child SA lifecycle policy, and profile policy remain downstream product work. |
| XFRM/IPsec request bridge | `crates/opc-ipsec-xfrm` | The optional `ikev2` feature maps validated ESP Child SA negotiation intent into bidirectional XFRM SA/policy install requests. It does not derive keys, allocate product policy, choose namespaces/privileges, or claim traffic readiness. |
| EPC/ePDG simulator skeletons | `crates/opc-testbed` plus `docs/design/epc-epdg-testbed-simulators.md` | The PGW S2b and Diameter peer simulator interfaces are RFC 012 `stateful-mock` skeletons; raw protocol bytes must be decoded by SDK protocol crates first. The SDK composition harness is a regression guard, not attach orchestration. |
| Packet-core evidence packs | `crates/opc-evidence` and RFC 006 §10.3 | Packet-core pack schemas are marked experimental and require `experimental: true`; downstream smoke artifacts mapped into the format are not SDK certification claims. |
| Generic operator helpers | `operators/operator-sdk-go` | Runtime-gate names, Multus/SR-IOV helpers, UDP/SCTP port helpers, rollout/drain helpers, and fake-client utilities are product-neutral helpers. Product CRDs, Helm values, privileges, and readiness policy stay outside the helper package. |

## Validation scope for this gate

Run targeted gates for the touched surfaces before moving the phase gate to
review:

```bash
cargo fmt --all --check
git diff --check
cargo test --locked -p opc-proto-ikev2 --all-features
cargo test --locked -p opc-testbed --all-features epc_epdg
cargo test --locked -p opc-evidence --all-features packet_core
(cd operators/operator-sdk-go && test -z "$(gofmt -l .)")
(cd operators/operator-sdk-go && go vet ./... && go test ./...)
```

The broader workspace and security gates from the root `README.md` and
`CONTRIBUTING.md` remain the release-candidate gates.

## Downstream adapter tasks outside this SDK plan

These are unresolved ePDG migration items that must be tracked by downstream
product adapter work, not by expanding the SDK roadmap or claiming product
readiness here:

1. Compose `opc-proto-ikev2` with a product IKE SA state machine, EAP-AKA,
   cookie/retransmit policy, Child SA lifecycle controller, key-derivation
   choices, the `opc-ipsec-xfrm` request bridge, and 3GPP ePDG profile
   validation.
2. Adapt ePDG attach orchestration to the SDK-owned GTPv2-C, Diameter metadata,
   IKEv2, testbed, and evidence mechanisms without moving APN, PLMN, realm,
   AAA/HSS/CDF, charging, or subscriber-session policy into the SDK.
3. Map product smoke and soak artifacts into packet-core evidence packs with
   product-owned carrier-readiness, lawful-intercept, charging, and release
   sign-off outside the SDK evidence schema.
4. Wire product CRDs, Helm values, Multus network attachment definitions,
   XFRM/IPsec privilege rendering, gNMI/config-push sequencing, and readiness
   thresholds onto `operator-sdk-go` helpers in the downstream operator.
5. Capture any independent peer fixtures used for downstream parity with the
   ADR 0015 provenance metadata, redaction record, and license/permission notes
   before treating them as more than product regression evidence.

These adapter tasks preserve ADR 0018's mechanism/policy split: the SDK owns
reusable primitives; downstream products own ePDG deployment policy and carrier
acceptance.
