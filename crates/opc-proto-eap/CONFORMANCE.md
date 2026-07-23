# EAP-AKA packet-projection conformance

This document defines the exact conformance boundary for `opc-proto-eap`. The
claim is a strict, redaction-safe structural projection of complete EAP-AKA
method packets, not an EAP method implementation or authentication claim.

## Specification baseline

| Specification | Claimed scope |
|:--|:--|
| IETF RFC 3748 | Section 4.1 complete Request/Response header framing |
| IETF RFC 4187 | Sections 6 through 10 EAP-AKA messages, attributes, Notification S/P semantics, and extensibility |
| IETF RFC 9048 | Current backwards-compatible EAP-AKA-prime specification, Sections 3 through 6; Type 50, KDF/KDF-Input, and AT_BIDDING updates |
| IETF RFC 5998 | Structural evidence consumed by an IKEv2 EAP-only product; no EAP-only safety decision |

RFC 9048 is the current EAP-AKA-prime baseline and updates the older RFC 5448
definition. RFC 3748 has no section 4.4; no conformance claim is made against
that erroneous reference.

## Validation contract

`EapAkaPacket::parse` accepts exactly one complete Code 1 Request or Code 2
Response with Type 23 or Type 50. It rejects:

- packets shorter than the eight-octet method header, a mismatched EAP length,
  unsupported Code/Type/Subtype, a nonzero AKA method-header reserved field,
  or a subtype illegal for the packet direction;
- truncated attribute headers/bodies, zero attribute length, more than 256
  top-level attributes, and more than 16 AT_KDF values;
- unknown non-skippable attributes, known attributes in the wrong packet,
  duplicate singleton attributes, invalid standardized lengths, malformed
  actual-length text, embedded or terminating NUL octets, nonzero alignment
  padding, invalid UTF-8, and unpaired AT_IV/AT_ENCR_DATA;
- AT_RES outside 32 through 128 bits or with nonzero unused bits/padding;
- missing mandatory attributes, mixed AKA-prime KDF-negotiation/authentication
  responses, reserved KDF zero, illegal KDF duplicates, or a Challenge Request
  without KDF-Input; and
- impossible Notification S/P bits or AT_MAC on a pre-authentication
  Notification.

Unknown attributes 128 through 255 are skipped and counted without retaining
their values. A known skippable attribute in a prohibited packet remains a
protocol error. Attribute order is insignificant except for the ordered KDF
preference list. The sole locally accepted duplicate-KDF shape is a selected
alternative prepended to a prior list, with the same value appearing once
later; a stateless parser reports that shape but cannot prove prior peer
correlation.

Sender-zero reserved fields inside RFC 4187 attributes are ignored on receive.
The AKA method-header reserved field is intentionally strict because this
projection's API contract explicitly requires it. AT_BIDDING exposes only its
D bit and ignores its receive-side reserved bits.

## Evidence surface and privacy

The source slice is a private borrow with no raw accessor. The projection
exposes direction, identifier, method, subtype, total/unknown counts, and a
typed packet-kind value. Packet-specific evidence reports only safe numeric or
boolean facts such as KDF number/count, result-indication presence,
Notification code/phase, ordered bounded KDF identifiers, or paired encryption
presence. The packet projection intentionally implements no equality trait, so
it cannot be mistaken for wire identity or replay evidence.

Custom packet `Debug` omits source bytes. Errors retain only numeric lengths,
offsets, codes, counts, and stable reason enums. No public result or diagnostic
contains raw Type-Data, raw attribute values, identities, RAND, AUTN, AUTS,
RES, MAC, IV, ciphertext, keys, nonces, addresses, realms, or packet-derived
hashes.

The following remain explicitly outside this crate:

- AT_MAC and AKA algorithm verification;
- AUTN freshness/authenticity, RES comparison, or AUTS resynchronization;
- encrypted nested-attribute parsing;
- stateful KDF-offer and result-indication correlation;
- key derivation and key availability;
- EAP retransmission/session state; and
- RFC 5998 mutual-authentication, key-generation, dictionary-resistance, or
  IKE_AUTH completion decisions.

## Test evidence

- `tests/projection.rs` covers both methods; every supported subtype; full
  Challenge request/response; KDF negotiation and legal/illegal duplicate
  shapes; synchronization; Identity; protected success Notification and
  acknowledgement; fast Reauthentication outer envelopes; malformed framing,
  lengths, padding, cardinality, directions, combinations, unknown attributes,
  resource bounds and diagnostic redaction.
- `opc-testbed/tests/eap_aka_transport_projection.rs` proves IKEv2 EAP and SWm
  DER/DEA accessors produce the same canonical projection and stable error.
- `fuzz/fuzz_targets/project_packet.rs` exercises the strict parser with
  arbitrary complete slices in repository PR-smoke and scheduled fuzz jobs.

## Known missing items within this structural scope

None. Cryptographic and stateful work listed above is a separate boundary, not
an incomplete structural-parser claim.
