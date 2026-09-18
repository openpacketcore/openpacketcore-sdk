# EAP packet conformance

This document defines the exact conformance boundaries for `opc-proto-eap`:
the EAP-AKA structural projection described first, and the separate
[EAP-5G bootstrap codec](#eap-5g-bootstrap-envelopes). Neither is an
authentication implementation or an authentication claim.

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
exposes direction, identifier, method, subtype, total/unknown counts, a typed
packet-kind value, and -- as the single deliberate exception -- the identity a
peer asserted in `AT_IDENTITY` (RFC 4187 clause 10.1), through
`EapAkaPacket::asserted_identity` and the non-extracting comparison
`asserted_identity_is`. That exception exists because presence alone cannot
distinguish an identity a relaying node already knows from a different one, so
such a node could not fail closed on a change. Both accessors use the Actual
Identity Length and exclude clause 10.1 padding. The returned value is
subscriber-correlatable and its handling is the caller's responsibility. Packet-specific evidence reports only safe numeric or
boolean facts such as KDF number/count, result-indication presence,
Notification code/phase, ordered bounded KDF identifiers, or paired encryption
presence. The packet projection intentionally implements no equality trait, so
it cannot be mistaken for wire identity or replay evidence.

Custom packet `Debug` omits source bytes and projects the asserted identity as
a length only. Errors retain only numeric lengths, offsets, codes, counts, and
stable reason enums. No **diagnostic** output contains raw Type-Data, raw
attribute values, identities, RAND, AUTN, AUTS, RES, MAC, IV, ciphertext, keys,
nonces, addresses, realms, or packet-derived hashes. No public **result**
contains any of those either, except the asserted `AT_IDENTITY` value described
above.

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

## EAP-5G bootstrap envelopes

`eap5g` is a separate structural codec. Its baseline is
[TS 24.502 V18.8.0](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.08.00_60/ts_124502v180800p.pdf)
clauses 7.3.3.1A, 9.2.1–9.2.3, 9.2.7 and 9.3.2, plus
[RFC 3748 sections 4.1 and 5.7](https://www.rfc-editor.org/rfc/rfc3748.html).
Requested NSSAI length/value framing follows
[TS 24.501 V18.11.1](https://www.etsi.org/deliver/etsi_ts/124500_124599/124501/18.11.01_60/ts_124501v181101p.pdf)
clauses 9.11.2.8 and 9.11.3.37: one to eight entries, with content lengths
1, 2, 4, 5 or 8. It does not perform slice selection.

| Envelope | Constructed send | Receive |
| --- | --- | --- |
| Request/5G-Start | Canonical 14-octet envelope | Spare bits/extensions ignored |
| Request/5G-NAS | Nonempty opaque NAS, exact two-octet length | Exact NAS borrow; trailing spare extensions ignored |
| Response/5G-NAS | Typed AN parameters plus nonempty opaque NAS | Bounded TLVs in any order; optional extended AN framing |
| Response/5G-Stop | Canonical 14-octet envelope | Spare bits/extensions ignored |
| Request/5G-Notification | Empty AN block | Spare types ignored; known TNGF contact fields unsupported |
| Response/5G-Notification | Canonical acknowledgement | Spare bits/extensions ignored |

The method header accepts only Expanded Type 254, Vendor-Id 10415 and
Vendor-Type 3. Code/Message-Id combinations are checked. Packet framing is
exact: trailing transport data outside the declared EAP Length is rejected.
Extensions inside that length obey the spare-field receive rules.

AN types 1–5, 7 and 8 have typed values. PLMN/GUAMI validate BCD digits;
NID ignores the spare nibble; cause ignores spare bits and maps spare cause
values to `MoData`. Spare GUAMI origin values are ignored; a recognized
GUAMI origin requires a GUAMI in the supported profile. UE identity (type 6,
ordinary or extended) returns a stable unsupported error, without retaining
or formatting its value. Other extended types are skipped after bounded,
nonzero length validation. No subscriber identity extraction is added.

Initial-response presence is checked explicitly by `validate_bootstrap`.
Selected PLMN and cause are required by this supported bootstrap profile;
the caller supplies the conditional facts for GUAMI, requested NSSAI,
selected NID and onboarding. The codec does not discover these facts by
decoding NAS. Default `Optional` requirements are not evidence that external
inclusion conditions were verified. Subsequent responses may have empty AN.

`Limits` are inclusive caller policy: defaults are 65,535 packet octets,
256 combined ordinary/extended AN octets and 64 AN entries. All entries,
including spare and duplicate types, count. `DuplicatePolicy::Reject` is a
local singleton policy; `FirstWins` validates every occurrence before keeping
the first and reporting the duplicate count. Neither parameter sorting nor
spare-type rejection is a receiver rule.

The wire maximum comes from EAP's 16-bit Length. Maximum NAS is 65,519 octets
in a request and 65,517 minus encoded AN octets in a response. Encoding checks
these totals before allocation or output writes; errors leave caller output
unchanged. Canonical encoding drops ignored fields and emits sender-zero
spares; it preserves opaque NAS exactly, without promising raw replay of the
entire received envelope. Parsing is allocation-free.

### Evidence and limitations

`tests/eap5g.rs` consumes all eleven independently spec-authored, merged
[`eap5g` fixture cases](../opc-n3iwf-fixtures/fixtures/eap5g/COMPLETION.json)
from #784. Their manifests retain source clauses, provenance and SHA-256
digests. Additional test-authored field layouts use reserved test PLMN 001/01
and synthetic identifiers; expected bytes do not come from the SDK encoder.
Tests cover all seven-field permutations, each length octet mutation,
truncation with both original and repaired outer length, malformed nested
S-NSSAI, conditional presence, inclusive limits, maximum EAP lengths,
canonical construction, private-byte diagnostics and unchanged output on error.

`fuzz/fuzz_targets/eap5g_packet.rs` runs in the existing PR/scheduled fuzz
matrix. It exercises raw input, repaired outer headers, caller limits,
duplicates, nested AN lengths, canonical stability, opaque NAS preservation
and failed-output atomicity. Corpus seeds derive from the published synthetic
fixtures. The existing AKA projection remains a separate test/fuzz target.

Not implemented: authentication, AKA/SWm decisions, UE identity parsing,
trusted-access contact information, NAS procedures, IKE transport or session
state, and EAP success/failure decisions. These tests establish the declared
constructed/receive subset, not external-peer interoperability or a complete
N3IWF. Refs #785; full acceptance and independent review remain required
before closing the issue.
