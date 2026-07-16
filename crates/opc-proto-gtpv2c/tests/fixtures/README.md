# GTPv2-C fixture corpus

This corpus follows ADR 0015 and the ePDG fixture-provenance intake checklist.
Only files in `spec/` are conformance evidence. Files in `epdg-parity/` are
SDK-authored parity/regression seeds for raw/private IE behavior and are **not**
counted as wire-format conformance proof. `independent/` has an enforced intake
harness but remains empty until an independently captured GTPv2-C packet includes
source, license/permission, redaction, and capture metadata. `malformed/`
contains hostile synthetic inputs that must never panic a decode path.

All subscriber identifiers are synthetic examples from documentation ranges or
non-real test digits. No key material, deployment secrets, LI identifiers, or
real subscriber data are included.

## `spec/` fixtures

The spec-authored fixtures are hand-authored from 3GPP TS 29.274 Release 18
common-header and TLIV IE layouts. They target the experimental S2b subset
implemented by `opc-proto-gtpv2c`; they are not a full GTPv2-C conformance
matrix.

The tables below cite the TS 29.274 R18 clauses used to hand-author
counted conformance bytes. Common-header rows cite clause 5.1; generic TLIV IE
header rows cite clause 8.2 plus the relevant IE-specific clause. IE type values
come from the TS 29.274 IE type registry (Table 8.1-1). The S2b procedure names
are used only to select the message type and mandatory-IE examples claimed by
this crate; the fixtures are not a complete procedure matrix.

Clause abbreviations used in the tables: IMSI §8.3.2, Cause §8.4, Recovery
§8.5, APN §8.6, APN-AMBR §8.7, EBI §8.8, Indication §8.12, PCO §8.13, PAA §8.14, Bearer QoS
§8.15, RAT Type §8.17, Serving Network/PLMN §8.18, F-TEID §8.22, Bearer Context
§8.28, Charging ID §8.29, PDN Type §8.34, Selection Mode §8.58, Bearer TFT
§8.28 plus TS 24.008 §10.5.6.12, and APCO §8.104.

The two header-only `.hex` fixtures below are decoded directly by
`tests/header.rs`; each whitespace-separated octet is a counted conformance
byte. They are kept textual so their complete normative construction remains
reviewable without a binary viewer.

### `message_priority_highest_header.hex`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `4c` | Version 2, T=1, MP=1, two spare bits zero (§5.4, §5.5.1). |
| 1 | `20` | Message Type 32 used as an EPC-header example (§5.5.1). |
| 2..3 | `00 08` | Length of the TEID, sequence, and priority fields, excluding the first four octets (§5.5.1). |
| 4..7 | `01 02 03 04` | Synthetic TEID used only to demonstrate the TEID-present EPC header (§5.5.1). |
| 8..10 | `00 ab cd` | 24-bit sequence number (§5.5.1). |
| 11 | `00` | Message Priority 0 (highest); low spare nibble zero (§5.5.1). |

### `message_priority_lowest_header.hex`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0..10 | `4c 20 00 08 01 02 03 04 00 ab cd` | Same TEID-present MP header and synthetic identifiers as the highest-priority fixture (§5.4, §5.5.1). |
| 11 | `f0` | Message Priority 15 (lowest); low spare nibble zero (§5.5.1). |

### `echo_request_recovery.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `40` | Common header flags: version 2, piggybacking 0, TEID flag 0, spare 0 (§5.1). |
| 1 | `01` | Message Type: Echo Request in the common-header message-type field (§5.1). |
| 2..3 | `00 09` | Length: sequence/spare (4) + Recovery IE (5), excluding first four octets (§5.1). |
| 4..6 | `00 00 01` | Sequence number 1 (§5.1). |
| 7 | `00` | Sequence spare octet (§5.1). |
| 8 | `03` | IE Type: Recovery (IE type registry Table 8.1-1; Recovery §8.5). |
| 9..10 | `00 01` | Recovery IE value length 1 in TLIV header (§8.2, §8.5). |
| 11 | `00` | IE spare 0 and instance 0 in TLIV header (§8.2). |
| 12 | `2a` | Recovery restart counter 42 (§8.5). |

### `echo_response_recovery.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `40` | Common header flags: version 2, piggybacking 0, TEID flag 0, spare 0 (§5.1). |
| 1 | `02` | Message Type: Echo Response in the common-header message-type field (§5.1). |
| 2..3 | `00 09` | Length: sequence/spare (4) + Recovery IE (5), excluding first four octets (§5.1). |
| 4..6 | `00 00 01` | Sequence number 1 (§5.1). |
| 7 | `00` | Sequence spare octet (§5.1). |
| 8 | `03` | IE Type: Recovery (IE type registry Table 8.1-1; Recovery §8.5). |
| 9..10 | `00 01` | Recovery IE value length 1 in TLIV header (§8.2, §8.5). |
| 11 | `00` | IE spare 0 and instance 0 in TLIV header (§8.2). |
| 12 | `2a` | Recovery restart counter 42 (§8.5). |

### `create_session_request_s2b_subset.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `40` | Common header flags: version 2, no TEID (§5.1). |
| 1 | `20` | Message Type: Create Session Request in the common-header message-type field (§5.1). |
| 2..3 | `00 9d` | Length: sequence/spare (4) + 153 octets of IEs, excluding first four octets (§5.1). |
| 4..7 | `00 10 01 00` | Sequence number `0x001001`, spare 0 (§5.1). |
| 8..11 | `01 00 08 00` | IMSI IE TLIV header: type 1, length 8, instance 0 (§8.2, §8.3.2). |
| 12..19 | `00 01 01 21 43 65 87 f9` | IMSI `001010123456789` in TBCD with filler nibble (§8.3.2). |
| 20..23 | `52 00 01 00` | RAT Type IE TLIV header (§8.2, §8.17). |
| 24 | `03` | RAT Type: WLAN (§8.17). |
| 25..28 | `53 00 03 00` | Serving Network IE TLIV header (§8.2, §8.18). |
| 29..31 | `00 f1 10` | PLMN `001/01` in TBCD MCC/MNC order (§8.18). |
| 32..35 | `57 00 19 00` | Sender F-TEID IE TLIV header (§8.2, §8.22). |
| 36 | `ca` | F-TEID V4 + V6 flags set, interface type 10 (§8.22). |
| 37..40 | `11 22 33 44` | F-TEID TEID/GRE key (§8.22). |
| 41..44 | `c0 00 02 0a` | F-TEID IPv4 `192.0.2.10` (documentation prefix; §8.22). |
| 45..60 | `20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01` | F-TEID IPv6 `2001:db8::1` (documentation prefix; §8.22). |
| 61..64 | `47 00 09 00` | APN IE TLIV header (§8.2, §8.6). |
| 65..73 | `08 69 6e 74 65 72 6e 65 74` | Single APN label `internet` with one-octet label length (§8.6). |
| 74..77 | `80 00 01 00` | Selection Mode IE TLIV header (§8.2, §8.58). |
| 78 | `00` | MS or network provided APN, subscription verified (§8.58). |
| 79..82 | `63 00 01 00` | PDN Type IE TLIV header (§8.2, §8.34). |
| 83 | `01` | PDN Type: IPv4 (§8.34). |
| 84..87 | `4f 00 05 00` | PAA IE TLIV header (§8.2, §8.14). |
| 88..92 | `01 c6 33 64 07` | IPv4 PAA `198.51.100.7` (documentation prefix; §8.14). |
| 93..96 | `5d 00 27 00` | Bearer Context grouped IE TLIV header (§8.2, §8.28). |
| 97..101 | `49 00 01 00 05` | Nested EBI TLIV/value: EPS Bearer ID 5 (§8.2, §8.8, §8.28). |
| 102..105 | `50 00 16 00` | Nested Bearer QoS IE TLIV header (§8.2, §8.15, §8.28). |
| 106..107 | `49 01` | Bearer QoS ARP octet (PCI=1, PL=2, PVI=1, spare bits zero) and GBR QCI 1 (§8.15). |
| 108..112 | `00 00 00 10 00` | Bearer QoS MBR uplink 4096 (§8.15). |
| 113..117 | `00 00 00 20 00` | Bearer QoS MBR downlink 8192 (§8.15). |
| 118..122 | `00 00 00 04 00` | Bearer QoS GBR uplink 1024 (§8.15). |
| 123..127 | `00 00 00 08 00` | Bearer QoS GBR downlink 2048 (§8.15). |
| 128..131 | `5e 00 04 00` | Nested Charging ID IE TLIV header (§8.2, §8.29, §8.28). |
| 132..135 | `12 34 56 78` | Charging ID example value (§8.29). |
| 136..139 | `4e 00 03 02` | PCO IE TLIV header, instance 2 (§8.2, §8.13). |
| 140..142 | `80 21 00` | Opaque PCO bytes preserved by typed value (§8.13). |
| 143..146 | `4d 00 02 00` | Indication IE TLIV header (§8.2, §8.12). |
| 147..148 | `40 01` | Opaque Indication flags preserved by typed value (§8.12). |
| 149..152 | `a3 00 03 01` | APCO IE TLIV header, instance 1 (§8.2, §8.104). |
| 153..155 | `80 21 01` | Opaque APCO bytes preserved by typed value (§8.104). |
| 156..159 | `fe 00 01 00` | Unsupported/private IE TLIV header retained by raw fallback (§8.2). |
| 160 | `aa` | Unsupported/private IE value preserved byte-exact by raw fallback (§8.2). |

### `create_session_response_s2b_subset.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `21` | Message Type: Create Session Response in the common-header message-type field (§5.1). |
| 2..3 | `00 2d` | Length: TEID/sequence/spare (8) + 37 octets of IEs, excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 02 00` | Sequence number `0x001002`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Cause IE TLIV/value: Request accepted, flags 0 (§8.2, §8.4). |
| 18..21 | `57 00 09 00` | Sender F-TEID IE TLIV header (§8.2, §8.22). |
| 22 | `8b` | F-TEID V4 flag set, interface type 11 (§8.22). |
| 23..26 | `55 66 77 88` | Sender F-TEID TEID/GRE key (§8.22). |
| 27..30 | `c0 00 02 01` | Sender F-TEID IPv4 `192.0.2.1` (documentation prefix; §8.22). |
| 31..39 | `4f 00 05 00 01 c6 33 64 07` | PAA IE TLIV/value: IPv4 `198.51.100.7` (§8.2, §8.14). |
| 40..48 | `5d 00 05 00 49 00 01 00 05` | Bearer Context grouped IE containing nested EBI 5 (§8.2, §8.28, §8.8). |

### `create_bearer_request_s2b.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `5f` | Message Type 95: Create Bearer Request (Table 7.2.3-1). |
| 2..3 | `00 52` | Length 82, excluding the first four octets (§5.1). |
| 4..7 | `10 20 30 40` | Receiver control-plane TEID (§5.1). |
| 8..11 | `01 02 03 00` | Sequence `0x010203`, spare 0 (§5.1). |
| 12..16 | `49 00 01 00 05` | Linked EBI 5, instance 0 (Table 7.2.3-2, §8.8). |
| 17..20 | `5d 00 41 00` | Bearer Context instance 0, value length 65 (Table 7.2.3-2, §8.28). |
| 21..25 | `49 00 01 00 00` | Nested request EBI has the required value 0 (Table 7.2.3-2). |
| 26..29 | `54 00 09 00` | Bearer TFT instance 0, value length 9 (§8.28). |
| 30..38 | `21 31 0a 05 30 11 50 11 94` | TS 24.008 Create-new TFT: one bidirectional filter, precedence 10, UDP next-header 17, remote port 4500 (§10.5.6.12). |
| 39..64 | `50 00 16 00 4d 01 00 00 0f 42 40 00 00 1e 84 80 00 00 07 d0 00 00 00 0b b8` | Bearer QoS instance 0: ARP PCI=1/PL=3/PVI=1 with spare bits zero, QCI 1, and bounded 40-bit integer-kbps MBR/GBR values (§8.15). |
| 65..77 | `57 00 09 04 a1 10 00 00 01 c0 00 02 0b` | S2b-U PGW F-TEID instance 4, interface type 33, TEID `0x10000001`, IPv4 `192.0.2.11` (Table 7.2.3-2, §8.22). |
| 78..85 | `5e 00 04 00 20 00 00 01` | Charging ID instance 0, required for S2b (Table 7.2.3-2, §8.29). |

### `create_bearer_response_s2b.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0..3 | `48 60 00 37` | Version 2/TEID header, Message Type 96, Length 55 (§5.1, Table 7.2.4-1). |
| 4..11 | `50 60 70 80 01 02 03 00` | Receiver TEID, correlated sequence `0x010203`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Message Cause: Request accepted (Table 7.2.4-2, §8.4). |
| 18..21 | `5d 00 25 00` | Response Bearer Context instance 0, value length 37 (Table 7.2.4-2). |
| 22..32 | `49 00 01 00 06 02 00 02 00 10 00` | Allocated EBI 6 and bearer Cause: Request accepted (§8.8, §8.4). |
| 33..45 | `57 00 09 08 9f 30 00 00 01 c0 00 02 15` | S2b-U ePDG F-TEID instance 8, interface type 31, TEID `0x30000001`, IPv4 `192.0.2.21` (Table 7.2.4-2, §8.22). |
| 46..58 | `57 00 09 09 a1 10 00 00 01 c0 00 02 0b` | Request PGW F-TEID copied at instance 9 for bearer correlation (Table 7.2.4-2, §8.22). |

### `delete_bearer_request_dedicated.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0..3 | `48 63 00 12` | Version 2/TEID header, Message Type 99, Length 18 (§5.1, Table 7.2.9.2-1). |
| 4..11 | `10 20 30 40 01 02 03 00` | Receiver TEID, sequence `0x010203`, spare 0 (§5.1). |
| 12..16 | `49 00 01 01 06` | Dedicated EBI 6, instance 1 (Table 7.2.9.2-1, §8.8). |
| 17..21 | `49 00 01 01 07` | Repeated dedicated EBI 7, instance 1; no mutually exclusive linked EBI is present. |

### `delete_bearer_response_partial.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0..3 | `48 64 00 2c` | Version 2/TEID header, Message Type 100, Length 44 (§5.1, Table 7.2.10.2-1). |
| 4..11 | `50 60 70 80 01 02 03 00` | Receiver TEID, correlated sequence `0x010203`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 11 00` | Message Cause: Request accepted partially (§8.4). |
| 18..32 | `5d 00 0b 00 49 00 01 00 06 02 00 02 00 10 00` | Bearer Context result for EBI 6: Request accepted (Table 7.2.10.2-1). |
| 33..47 | `5d 00 0b 00 49 00 01 00 07 02 00 02 00 40 00` | Bearer Context result for EBI 7: Context not found (Cause 64). |

### `modify_bearer_request_bearer_context.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `22` | Message Type: Modify Bearer Request in the common-header message-type field (§5.1). |
| 2..3 | `00 11` | Length: TEID/sequence/spare (8) + Bearer Context IE (9), excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 03 00` | Sequence number `0x001003`, spare 0 (§5.1). |
| 12..15 | `5d 00 05 00` | Bearer Context grouped IE TLIV header (§8.2, §8.28). |
| 16..20 | `49 00 01 00 05` | Nested EBI TLIV/value: EPS Bearer ID 5 (§8.2, §8.8, §8.28). |

### `modify_bearer_response_cause.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `23` | Message Type: Modify Bearer Response in the common-header message-type field (§5.1). |
| 2..3 | `00 0e` | Length: TEID/sequence/spare (8) + Cause IE (6), excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 04 00` | Sequence number `0x001004`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Cause IE TLIV/value: Request accepted, flags 0 (§8.2, §8.4). |

### `delete_session_request_linked_ebi.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `24` | Message Type: Delete Session Request in the common-header message-type field (§5.1). |
| 2..3 | `00 0d` | Length: TEID/sequence/spare (8) + EBI IE (5), excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 05 00` | Sequence number `0x001005`, spare 0 (§5.1). |
| 12..16 | `49 00 01 00 05` | Linked EPS Bearer ID IE TLIV/value: EBI 5 (§8.2, §8.8). |

### `delete_session_response_cause.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `25` | Message Type: Delete Session Response in the common-header message-type field (§5.1). |
| 2..3 | `00 0e` | Length: TEID/sequence/spare (8) + Cause IE (6), excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 06 00` | Sequence number `0x001006`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Cause IE TLIV/value: Request accepted, flags 0 (§8.2, §8.4). |

### `update_bearer_request_bearer_context.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `61` | Message Type: Update Bearer Request in the common-header message-type field (§5.1). |
| 2..3 | `00 1d` | Length: TEID/sequence/spare (8) + APN-AMBR IE (12) + Bearer Context IE (9), excluding first four octets (§5.1, Table 7.2.15-1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 07 00` | Sequence number `0x001007`, spare 0 (§5.1). |
| 12..23 | `48 00 08 00 00 00 fa 00 00 01 f4 00` | Mandatory APN-AMBR instance 0: uplink 64,000 kbps and downlink 128,000 kbps (§8.7, Table 7.2.15-1). |
| 24..27 | `5d 00 05 00` | Bearer Context instance 0, value length 5 (Tables 7.2.15-1 and 7.2.15-2). |
| 28..32 | `49 00 01 00 05` | Mandatory nested EBI instance 0: EPS Bearer ID 5 (§8.8, Table 7.2.15-2). |

### `update_bearer_response_cause.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `62` | Message Type: Update Bearer Response in the common-header message-type field (§5.1). |
| 2..3 | `00 1d` | Length: TEID/sequence/spare (8) + Cause IE (6) + Bearer Context IE (15), excluding first four octets (§5.1, Table 7.2.16-1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 08 00` | Sequence number `0x001008`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Cause IE TLIV/value: Request accepted, flags 0 (§8.2, §8.4). |
| 18..21 | `5d 00 0b 00` | Mandatory response Bearer Context instance 0, value length 11 (Tables 7.2.16-1 and 7.2.16-2). |
| 22..26 | `49 00 01 00 05` | Mandatory nested EBI instance 0: EPS Bearer ID 5 (§8.8, Table 7.2.16-2). |
| 27..32 | `02 00 02 00 10 00` | Mandatory nested Cause instance 0: Request accepted (§8.4, Table 7.2.16-2). |

## `epdg-parity/` fixtures

These files are parity/regression seeds only. They model raw/private IE handling
called out by the ePDG fixture-provenance map, but they were not independently
captured and are not counted as ADR 0015 conformance evidence.

- `create_session_unknown_private_ie.bin` — Create Session shell carrying an
  unsupported private IE value `aa`.
- `raw_unknown_ie_region_roundtrip.bin` — two unknown/private IEs, including
  non-zero IE spare bits, used to prove raw-preserving TLIV forwarding.
- `piggybacking_header_unknown_ie.bin` — piggybacking flag preservation with an
  unknown/private IE.

## `independent/` fixtures

Independent captures are public, sanitized, one-datagram S2b captures from an
implementation not authored by this repository. The corpus replay harness accepts
future `.bin` captures only when each has a sibling `.metadata` file documenting
capture kind, independent implementation/version, commit permission, redaction
review, redacted fields, synthetic replacements, expected S2b message,
byte-exact raw-preserving re-encode behavior, fuzz-seed policy, and reviewer.
The harness currently keeps the no-capture gap explicit instead of pretending
interoperability evidence exists.

## `malformed/` fixtures

The malformed corpus contains synthetic hostile inputs for truncation, declared
length overrun, strict spare-bit rejection, low-limit IE count-limit paths,
grouped IE recursion-depth limits, and S2b profile-critical negative cases.
`too_many_small_ies.bin` intentionally contains two small IEs and is replayed
with `DecodeContext::max_ies = 1` so both whole-message and decoded raw-IE
region validation reject on `IeCountExceeded`.
`nested_bearer_context_depth_limit.bin` is a valid Modify Bearer Request shell
whose top-level Bearer Context contains another Bearer Context; replay with
`DecodeContext::max_depth = 1` must reject on `DepthExceeded`.
`profile_*.bin` fixtures are syntactically bounded S2b messages that fail
ProcedureAware profile checks for missing Recovery, PAA, Bearer Context/EBI,
Sender F-TEID, Cause, Bearer TFT, mutually exclusive Delete Bearer target
forms, or malformed F-TEID/PAA values. Decode may return any structured
`DecodeError` outside those per-fixture assertions, but must never panic.
