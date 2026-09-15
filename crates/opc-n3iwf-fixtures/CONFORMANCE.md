# opc-n3iwf-fixtures conformance

3GPP / IETF baseline for synthetic N3IWF fixture contracts. This crate does
not claim codec, adapter, or interoperability behavior.

## Claim

The catalog publishes spec-authored or referenced-public-vector bytes, SHA-256
digests, sanitized-field inventories, and independently mergeable subset
completion records. Round trips of these bytes do not prove external
interoperability.

`runtime_claim=false` on every manifest and completion record.

## Specification baseline

| Document | Release | Subsets |
| --- | --- | --- |
| 3GPP TS 24.502 | V18.8.0 | eap5g, nwu-ike, gre-qfi, nas-tcp |
| 3GPP TS 38.413 | R18 | ngap |
| 3GPP TS 38.412 | V18.1.0 | n2-sctp |
| 3GPP TS 29.281 | V18.4.0 | n3-gtpu |
| 3GPP TS 38.415 | V18.2.0 | n3-gtpu uplink PSC |
| 3GPP TS 33.501 | V18.12.0 | protocol-key |
| IETF RFC 7296 | RFC 7296 | nwu-ike |
| IETF RFC 4555 | RFC 4555 | nwu-ike mobility notify |
| IETF RFC 4960 | RFC 4960 | n2-sctp DATA chunk |
| IETF RFC 6083 | RFC 6083 | n2-dtls PPID 66 |
| IETF RFC 6347 | RFC 6347 | n2-dtls record labels |

## Coverage

✅ = subset completion record is `complete` and consumers may depend on that
subset alone. 🚫 = explicitly unsupported in this crate.

| Subset | Status | Constructed | Receive | Unsupported |
| --- | --- | --- | --- | --- |
| eap5g | ✅ | EAP-Request/5G-Start | EAP-Response/5G-NAS; spare AN-parameter ignore | subscriber authentication, SUCI, EAP key derivation |
| nwu-ike | ✅ | NAS_IP4_ADDRESS, NAS_TCP_PORT, 5G_QOS_INFO, UP_IP4_ADDRESS, Delete ESP | MOBIKE ADDITIONAL_IP4_ADDRESS | XFRM install, SPI allocation, authentication |
| ngap | ✅ | none (typed encode unsupported) | 78-byte NGSetupRequest; empty wrapper | canonical typed encode; constructed N3IWF send |
| n2-sctp | ✅ | PPID 60 / port 38412 | metadata order variants | PPID 66 on this profile; DTLS |
| gre-qfi | ✅ | downlink QFI+RQI | uplink QFI; nonzero Protocol Type ignore | XFRM install; QFI allocation |
| n3-gtpu | ✅ | Echo Request/Response Recovery 0; uplink PSC | downlink PSC; ignored Recovery; End Marker order | backend control port; eBPF offload (issue 644) |
| protocol-key | ✅ | generation-1 consume-once label | drop zeroize | byte export; hierarchy derivation |
| nas-tcp | ✅ | complete two-octet envelope | two-frame stream; unknown inner EPD left opaque | TCP listen; reconnect; security termination |
| xfrm-roster | ✅ | inbound/outbound SPI pair label | overlap/rekey/relocate labels | IKE notify parsing |
| n2-dtls | ✅ | PPID 66; handshake header; expected-peer identity label; SCTP-AUTH length | rekey; path failure | PPID 60 as protection; certificates |

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
