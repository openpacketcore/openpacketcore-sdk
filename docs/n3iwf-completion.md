# N3IWF SDK completion map

Tracker [#795](https://github.com/openpacketcore/openpacketcore-sdk/issues/795)
covers ten reusable SDK lanes and their fixture prerequisite, #784. This map
links each declared inventory to its separately qualified runtime contract.
It does not establish an assembled N3IWF, subscriber authentication policy,
AMF selection, deployment readiness or external interoperability.

| Lane | Fixture completion | Runtime contract |
| --- | --- | --- |
| #785 EAP-5G | [eap5g](../crates/opc-n3iwf-fixtures/fixtures/eap5g/COMPLETION.json) | [EAP](../crates/opc-proto-eap/CONFORMANCE.md) |
| #786 NWu IKE | [nwu-ike](../crates/opc-n3iwf-fixtures/fixtures/nwu-ike/COMPLETION.json) | [IKE](../crates/opc-proto-ikev2/CONFORMANCE.md) |
| #787 NGAP | [ngap](../crates/opc-n3iwf-fixtures/fixtures/ngap/COMPLETION.json) | [23 qualified outcomes and handler boundaries](../crates/opc-proto-ngap/N3IWF-ACCEPTANCE.md) |
| #788 N2 SCTP | [n2-sctp](../crates/opc-n3iwf-fixtures/fixtures/n2-sctp/COMPLETION.json) | [SCTP](../crates/opc-sctp/CONFORMANCE.md) |
| #789 GRE/QFI | [gre-qfi](../crates/opc-n3iwf-fixtures/fixtures/gre-qfi/COMPLETION.json) | [GRE](../crates/opc-proto-gre/CONFORMANCE.md) |
| #790 N3 forwarding | [n3-gtpu](../crates/opc-n3iwf-fixtures/fixtures/n3-gtpu/COMPLETION.json) | [Fixed-flow forwarding](n3-fixed-flow-forwarding.md), [End Marker retirement](n3-end-marker-retirement.md) |
| #791 protocol-key custody | [protocol-key](../crates/opc-n3iwf-fixtures/fixtures/protocol-key/COMPLETION.json) | [IKE custody and key boundary](../crates/opc-proto-ikev2/CONFORMANCE.md) |
| #792 NAS/TCP | [nas-tcp](../crates/opc-n3iwf-fixtures/fixtures/nas-tcp/COMPLETION.json) | [NAS](../crates/opc-proto-nas/CONFORMANCE.md) |
| #793 installed Child-SA roster | [xfrm-roster](../crates/opc-n3iwf-fixtures/fixtures/xfrm-roster/COMPLETION.json) | [Selection/provenance](n3-installed-child-sa-roster.md), [MOBIKE/recovery](n3-child-sa-mobike.md) |
| #794 protected NGAP transport | [n2-dtls](../crates/opc-n3iwf-fixtures/fixtures/n2-dtls/COMPLETION.json) | [Generic RFC 6083 transport](rfc6083-generic-transport.md), [profile map](n3iwf-dtls-fixture-profiles.md) |

Each completion record lists constructed, received and unsupported outcomes
at the manifest's `validation_scope`. All ten inventories include positive,
malformed, duplicate, unknown-critical, ordering, truncation and bounded-overflow
classes where applicable. For scenario inputs those classes describe local
obligations, not invented network encodings. EAP's permitted unknown parameters
remain distinct from caller duplicate policy; an incomplete NAS frame remains
pending until more input or explicit finalization.

NGAP binds all 23 admitted outcomes to independent Release 18 message/IE
matrices. The other 17 applicable outcomes require external handlers and retain
disabled triggers. GRE includes received nonzero Protocol Type. N3 includes
directional PSC and zero/ignored Recovery; installed forwarding and local End
Marker submission have their own backend and ordering evidence.

Protocol-key records distinguish public synthetic AUTH known answers, custody
schedules and private memory-clearing audit. DTLS's 634 additional profile
references distinguish vectors and authored obligations from actual transport
execution. The [3,453 Child-SA references](n3iwf-child-sa-fixture-profiles.md)
similarly preserve the distinction between wire IKE, durable object recovery,
installed packet selection, source observations and authenticated relocation.
Earlier fixture labels are not promoted by these additive records.

The catalog gate checks immutable source digests, independent reference results,
exact inventories, redacted errors/Debug and publication ancestry. Each subset
can be loaded alone. Native kernel evidence requires the separately specified
profile, exact executed counts, positive markers and no ignored/skipped cases;
loading a reference or receiving Unsupported cannot replace that evidence.

Issue acceptance records and linked PRs retain failing original detectors,
removed-guard failures, adverse mutations, affected-crate results, repository
gates and exact public base/head/tree. `fixtures/PUBLIC_SDK.json` records the
catalog content revision and fixture tree without a self-referential hash.
See [maintenance](n3iwf-fixture-contracts.md) and
[conformance](../crates/opc-n3iwf-fixtures/CONFORMANCE.md) for reproduction and
remaining profile limits. Closing a lane accepts that documented SDK contract;
it adds no wider conformance or product claim.
