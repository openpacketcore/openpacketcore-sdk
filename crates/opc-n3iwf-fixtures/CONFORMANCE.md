# opc-n3iwf-fixtures conformance

3GPP / IETF baseline for synthetic N3IWF fixture contracts. This crate does
not claim codec, adapter, or interoperability behavior.

## Claim

The catalog publishes spec-authored or referenced-public-vector bytes, SHA-256
digests, sanitized-field inventories, and independently mergeable subset
completion records. Round trips of these bytes do not prove external
interoperability.

`runtime_claim=false` on every manifest and completion record.

## Scope

Reusable SDK fixture contracts only. This crate does not encode application
policy, subscriber authentication decisions, AMF selection, deployment
topology, readiness, or product claims. Tracking issue 795 is tracking-only
and is not implemented here.

## Specification baseline

| Document | Release | Clauses | Subsets |
| --- | --- | --- | --- |
| 3GPP TS 24.502 | V18.8.0 | 7.3–7.7, 8.2–8.3, 9.3–9.4 | eap5g, nwu-ike, gre-qfi, nas-tcp |
| 3GPP TS 29.413 | V18.5.0 | 5.2–5.4 | ngap N3IWF application |
| 3GPP TS 38.413 | V18.10.0 | message/IE definitions | ngap |
| 3GPP TS 38.412 | V18.1.0 | 7 | n2-sctp |
| 3GPP TS 29.281 | V18.4.0 | 4.4, 5.2.2.7, 7.2–7.3, 8.2 | n3-gtpu |
| 3GPP TS 38.415 | V18.2.0 | 5.5.3 | n3-gtpu uplink PSC |
| 3GPP TS 33.501 | V18.12.0 | 7.2.1 | protocol-key |
| IETF RFC 7296 | RFC 7296 | IKEv2 notify/create/modify/delete | nwu-ike |
| IETF RFC 4555 | RFC 4555 | MOBIKE additional-address | nwu-ike |
| IETF RFC 4960 | RFC 4960 | DATA chunk; path failure | n2-sctp, n2-dtls |
| IETF RFC 6083 | RFC 6083 | DTLS/SCTP PPID 66, AUTH, reliable delivery | n2-dtls |
| IETF RFC 6347 | RFC 6347 | DTLS 1.2 record labels | n2-dtls |

## Coverage

✅ = subset completion record is `complete` and consumers may depend on that
subset alone. 🚫 = explicitly unsupported in this crate.

| Subset | Status | Constructed | Receive | Unsupported |
| --- | --- | --- | --- | --- |
| eap5g | ✅ | Start; Notification (Message-Id 3) | NAS; Stop (Message-Id 4); spare ignore; permitted reorder | subscriber authentication, SUCI, EAP key derivation |
| nwu-ike | ✅ | notifies; CREATE_CHILD_SA 7.5; MODIFY_CHILD_SA 7.6; Delete ESP | MOBIKE ADDITIONAL_IP4_ADDRESS | XFRM install, SPI allocation, authentication |
| ngap | ✅ | none (typed encode unsupported) | Rel-18 NGSetupRequest; first-CNF 5.2 empty wrappers + IE matrices | constructed send; 5.2 messages outside first-CNF; Paging (29.413 5.4); AMF selection |
| n2-sctp | ✅ | PPID 60 / port 38412 | metadata order variants | PPID 66 on this profile; DTLS |
| gre-qfi | ✅ | downlink QFI+RQI | uplink QFI; nonzero Protocol Type ignore | XFRM install; QFI allocation |
| n3-gtpu | ✅ | Echo Request/Response Recovery 0; uplink PSC | downlink PSC; ignored Recovery; End Marker order | backend control port; eBPF offload (issue 644) |
| protocol-key | ✅ | generation-1 consume-once label | drop zeroize | byte export; hierarchy derivation; key material |
| nas-tcp | ✅ | complete two-octet envelope | two-frame stream; unknown inner EPD left opaque | TCP listen; reconnect; security termination |
| xfrm-roster | ✅ | inbound/outbound SPI pair label | overlap/rekey/relocate labels | IKE notify parsing |
| n2-dtls | ✅ | PPID 66; handshake/identity; SCTP-AUTH; DATA B/E | rekey; rotation; path failure | PPID 60 as protection; certificates |

Every subset includes the required case classes: positive, malformed,
duplicate, unknown-critical, ordering, truncation, and bounded-overflow.

## Reuse

| Issue | Status used here | Reuse |
| --- | --- | --- |
| 493 | closed DecodeContext / IE cardinality | NGAP 78-byte NGSetupRequest and policy paths by digest/path |
| 341 | GTP-U control codec already on main | Echo Request/Response and downlink PSC by digest |
| 644 | closed eBPF checksum | not duplicated; dataplane runtime remains out of scope |

`tests/contracts.rs` locks the reused octets to the merged `opc-proto-ngap`
and `opc-proto-gtpu` source files so a later edit of those proven vectors
fails this crate.

## Provenance

Allowed classes: `spec-authored`, `referenced-public-vector`,
`synthetic-negative`, `synthetic-kat`. Captures, customer topology, and key
material are rejected. Identifiers are documentation-range or reserved-test
values only.

## Publication

`fixtures/PUBLIC_SDK.json` records the public repository URL, base commit,
landing head, fixtures tree path, and tree object when stamped. The
interoperability note states that these contracts do not prove external
interoperability.

## Detectors

`FixtureCatalog::detect` and `scripts/check-n3iwf-fixture-contracts.py` fail
closed on missing case classes, digest mutation, `runtime_claim=true`,
forbidden provenance, and forbidden content. Errors expose stable codes only.
