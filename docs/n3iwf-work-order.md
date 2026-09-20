# N3IWF SDK work order

The original planning snapshot below is retained as history. The resulting
[completion map](n3iwf-completion.md) links all ten fixture inventories and
their qualified SDK contracts, including the later installed forwarding,
Child-SA and protected-transport profiles. Use the tracker and that map when
assessing remaining work; the dated queue below is not current issue status.

This queue follows [tracker #795](https://github.com/openpacketcore/openpacketcore-sdk/issues/795).
Checked against SDK `main` at `1416b647aabcc57bf983ed2443897f8c7743d590`
on 2026-09-16. Issue state alone is not implementation evidence.

## Prerequisites already on main

[PR #830](https://github.com/openpacketcore/openpacketcore-sdk/pull/830)
merged the ten fixture inventories and their scoped completion records.
[PR #839](https://github.com/openpacketcore/openpacketcore-sdk/pull/839)
added independently encoded Release 18 NGAP messages;
[PR #840](https://github.com/openpacketcore/openpacketcore-sdk/pull/840)
added independent IKE AUTH known answers and the synthetic NGAP-key handoff.

The completion records permit consumers to depend on each declared inventory.
They do not prove live transport, key custody, kernel behavior or all of #784.
At this planning snapshot, [#784](https://github.com/openpacketcore/openpacketcore-sdk/issues/784)
remained open for evidence described in
[the fixture conformance document](../crates/opc-n3iwf-fixtures/CONFORMANCE.md).

## Implementation queue

The default serial queue retains the tracker's order. These are independent
lanes after their named fixture prerequisites, not a fabricated dependency
chain between consecutive issue numbers. An unrelated unfinished fixture lane
must not block a lane whose reviewed subset is available.

| Queue | SDK issue | Required fixture subset | Existing public work to audit before adding code |
| --- | --- | --- | --- |
| 1 | [#785 EAP-5G](https://github.com/openpacketcore/openpacketcore-sdk/issues/785) | `eap5g` | Existing `opc-proto-eap` projection boundary |
| 2 | [#786 NWu IKE](https://github.com/openpacketcore/openpacketcore-sdk/issues/786) | `nwu-ike` | Generic IKE payloads, actor and crypto policy; keep key custody in #791 |
| 3 | [#787 NGAP](https://github.com/openpacketcore/openpacketcore-sdk/issues/787) | `ngap` | #493; distinguish constructed encoding from raw-preserving receive |
| 4 | [#788 N2 SCTP](https://github.com/openpacketcore/openpacketcore-sdk/issues/788) | `n2-sctp` | #184, #192, #290, #347 |
| 5 | [#789 GRE/QFI](https://github.com/openpacketcore/openpacketcore-sdk/issues/789) | `gre-qfi` | Existing protocol and QoS types |
| 6 | [#790 N3 forwarding](https://github.com/openpacketcore/openpacketcore-sdk/issues/790) | `n3-gtpu` | #341, #644, #663, #671 |
| 7 | [#791 protocol-key custody](https://github.com/openpacketcore/openpacketcore-sdk/issues/791) | `protocol-key`, with `eap5g` and `ngap` handoff vectors | #334; integrate with #786 without adding byte export |
| 8 | [#792 NAS/TCP](https://github.com/openpacketcore/openpacketcore-sdk/issues/792) | `nas-tcp` | Existing NAS framing types; no listener or UE lifecycle |
| 9 | [#793 Child-SA roster](https://github.com/openpacketcore/openpacketcore-sdk/issues/793) | `xfrm-roster` and `nwu-ike` mobility | #315 single-SA migration and existing durable roster primitives |
| 10 | [#794 NGAP DTLS](https://github.com/openpacketcore/openpacketcore-sdk/issues/794) | `n2-dtls` | #348 protected transport and #347; no new DTLS engine |

EAP-5G is the first implementation in this queue. Review each later lane's
actual merged symbols and remaining delta before implementation; an open
umbrella issue is not evidence that its generic primitive is missing.
Standalone NAS/TCP or other independent lanes can move earlier without
violating the fixture prerequisites. Final IKE integration must exercise the
protocol-key handoff, and protected N2 must exercise the actual DTLS transport.

## Completion

For each lane retain the pre-change detector, fix-removal result, independent
adverse inputs, affected tests and repository gates. Record exact public SDK
base/head/tree and fixture provenance. Document constructed send, receive and
unsupported outcomes separately. Partial contributions use `Refs` and do not
close the issue. Close #795 only after every child has accepted evidence and
merged implementation. None of these SDK issues grants a product or deployment
claim.
