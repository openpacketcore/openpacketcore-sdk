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
| 0 | `48` | Common header flags: version 2, TEID flag set (§5.1, Table 7.2.1-1). |
| 1 | `20` | Message Type: Create Session Request in the common-header message-type field (§5.1). |
| 2..3 | `00 9b` | Length: TEID/sequence/spare (8) + 147 octets of IEs, excluding first four octets (§5.1). |
| 4..7 | `00 00 00 00` | Create Session Request header TEID 0 (§5.1, Table 7.2.1-1). |
| 8..11 | `00 10 01 00` | Sequence number `0x001001`, spare 0 (§5.1). |
| 12..15 | `01 00 08 00` | IMSI IE TLIV header: type 1, length 8, instance 0 (§8.2, §8.3.2). |
| 16..23 | `00 01 01 21 43 65 87 f9` | IMSI `001010123456789` in TBCD with filler nibble (§8.3.2). |
| 24..27 | `52 00 01 00` | RAT Type IE TLIV header (§8.2, §8.17). |
| 28 | `03` | RAT Type: WLAN (§8.17). |
| 29..32 | `53 00 03 00` | Serving Network IE TLIV header (§8.2, §8.18). |
| 33..35 | `00 f1 10` | PLMN `001/01` in TBCD MCC/MNC order (§8.18). |
| 36..39 | `57 00 19 00` | Sender F-TEID IE TLIV header, instance 0 (Table 7.2.1-1, §8.22). |
| 40 | `de` | F-TEID V4 + V6 flags set, S2b ePDG GTP-C interface type 30 (§8.22, Table 8.22-1). |
| 41..44 | `11 22 33 44` | F-TEID TEID/GRE key (§8.22). |
| 45..48 | `c0 00 02 0a` | F-TEID IPv4 `192.0.2.10` (documentation prefix; §8.22). |
| 49..64 | `20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01` | F-TEID IPv6 `2001:db8::1` (documentation prefix; §8.22). |
| 65..68 | `47 00 09 00` | APN IE TLIV header (§8.2, §8.6). |
| 69..77 | `08 69 6e 74 65 72 6e 65 74` | Single APN label `internet` with one-octet label length (§8.6). |
| 78..81 | `80 00 01 00` | Selection Mode IE TLIV header (§8.2, §8.58). |
| 82 | `00` | MS or network provided APN, subscription verified (§8.58). |
| 83..86 | `4f 00 05 00` | PAA IE TLIV header (§8.2, §8.14). TS 29.274 Table 7.2.1-1 Note 1 prohibits a separate PDN Type IE on S2b. |
| 87..91 | `01 c6 33 64 07` | Static IPv4 PAA `198.51.100.7` (documentation prefix; §8.14). |
| 92..95 | `5d 00 2c 00` | Bearer Context-to-be-created grouped IE TLIV header, instance 0 (Table 7.2.1-1/-2, §8.28). |
| 96..100 | `49 00 01 00 05` | Nested EBI TLIV/value: EPS Bearer ID 5 (Table 7.2.1-2, §8.8). |
| 101..104 | `57 00 09 05` | Nested S2b-U ePDG F-TEID TLIV header, instance 5 (Table 7.2.1-2, §8.22). |
| 105 | `9f` | V4 flag set, S2b-U ePDG GTP-U interface type 31 (§8.22, Table 8.22-1). |
| 106..109 | `11 22 33 45` | User-plane TEID (§8.22). |
| 110..113 | `c0 00 02 14` | User-plane IPv4 `192.0.2.20` (documentation prefix; §8.22). |
| 114..117 | `50 00 16 00` | Nested Bearer QoS IE TLIV header (Table 7.2.1-2, §8.15). |
| 118..119 | `49 01` | Bearer QoS ARP octet (PCI=1, PL=2, PVI=1, spare bits zero) and GBR QCI 1 (§8.15). |
| 120..124 | `00 00 00 10 00` | Bearer QoS MBR uplink 4096 (§8.15). |
| 125..129 | `00 00 00 20 00` | Bearer QoS MBR downlink 8192 (§8.15). |
| 130..134 | `00 00 00 04 00` | Bearer QoS GBR uplink 1024 (§8.15). |
| 135..139 | `00 00 00 08 00` | Bearer QoS GBR downlink 2048 (§8.15). |
| 140..143 | `4d 00 02 00` | Indication IE TLIV header (§8.2, §8.12). |
| 144..145 | `40 01` | Opaque Indication flags preserved by typed value (§8.12). |
| 146..149 | `a3 00 03 00` | APCO IE TLIV header, Create Session Request instance 0 (Table 7.2.1-1, §8.104). |
| 150..152 | `80 21 01` | Opaque APCO bytes preserved by typed value (§8.104). |
| 153..156 | `fe 00 02 00` | IE Type Extension TLIV header: type 254, two-octet value, instance 0 (§8.2.1A). |
| 157..158 | `01 00` | Extended IE type 256, raw-preserved because this typed subset does not interpret it (§8.2.1A). |

### S2b Create Session PAA family fixtures

The following five compact Create Session Requests independently exercise the
complete PAA family registry. They share the same hand-authored required S2b
fields at offsets 0 through 66: TEID-present Create Session Request header with
TEID zero, synthetic IMSI, WLAN RAT, serving PLMN `001/01`, S2b ePDG control
F-TEID, `internet` APN, and Selection Mode. Each ends with the same instance-0
Bearer Context containing EBI 5. None contains IE type 99: Table 7.2.1-1 Note 1
says PDN Type is never sent on S2a/S2b, while PAA carries the requested family.

| Fixture | Header Length | PAA offsets and octets | Bearer Context | Spec basis |
| --- | --- | --- | --- | --- |
| `create_session_request_s2b_ipv4_dynamic.bin` | `00 51` | 67..75: `4f 00 05 00 01 00 00 00 00` | 76..84 | IPv4 type 1 with dynamic address `0.0.0.0` (Table 7.2.1-1, §8.14). |
| `create_session_request_s2b_ipv6_dynamic.bin` | `00 5e` | 67..88: `4f 00 12 00 02 00` followed by 16 zero octets | 89..97 | IPv6 type 2 with dynamic prefix length/address all zero (Table 7.2.1-1, §8.14). |
| `create_session_request_s2b_ipv4v6_dynamic.bin` | `00 62` | 67..92: `4f 00 16 00 03 00` followed by 20 zero octets | 93..101 | IPv4v6 type 3 with both dynamic family values all zero (Table 7.2.1-1, §8.14). |
| `create_session_request_s2b_non_ip.bin` | `00 4d` | 67..71: `4f 00 01 00 04` | 72..80 | Non-IP type 4 with no PDN Address and Prefix octets (§8.14). |
| `create_session_request_s2b_ethernet.bin` | `00 4d` | 67..71: `4f 00 01 00 05` | 72..80 | Ethernet type 5 with no PDN Address and Prefix octets (§8.14). |

### GTPv2-C protocol-error response plans

`spec/error_response_plans/*.hex` are text-encoded, hand-authored octets kept
independent of the production encoder. Tests parse each whitespace-separated
hex octet and compare planned output byte-for-byte. Addresses, TEIDs, sequence
numbers, and payload values use documentation-only synthetic values. These are
spec-authored conformance fixtures, not captures from an independent peer.

| Fixture | Exact wire intent and TS 29.274 Release 18 basis |
| --- | --- |
| `unsupported_version_request.hex` | Complete twelve-octet version-3/T=1 input with received sequence `aa bb cc`; §7.7.2 makes it answerable with message 3. |
| `version_not_supported_response.hex` | `40 03 00 04 01 02 03 00`: header-only type 3, T=0, local sequence `01 02 03`, Length 4 (§5.3, §7.1.3). |
| `too_short_common_header.hex` | Seven octets for a T=1 request; insufficient for the required twelve-octet header and silently discarded (§7.7.3). |
| `length_mismatch_create_session_request.hex` | Complete Create Session Request header declares 12 total octets but the datagram has a thirteenth octet (§7.7.3). |
| `invalid_length_create_session_response_remote.hex` | Type 33, copied request sequence, caller-supplied remote TEID `11223344`, and six-octet Cause IE value 67. |
| `invalid_length_create_session_response_no_lookup.hex` | Same protocol error with clause 5.5.2 optional no-lookup TEID zero; Cause remains 67, never Context Not Found. |
| `unknown_teid_delete_session_request.hex` | Length-consistent type 36 request with synthetic non-zero received TEID and linked EBI. |
| `context_not_found_delete_session_response.hex` | Type 37, copied request sequence, header TEID zero, and Cause 64 for an unknown received session TEID (§5.5.2, §8.4). |
| `missing_mandatory_create_session_request.hex` | Length-consistent type 32 envelope used with caller evidence that APN type 71/instance 0 is missing (§7.7.6). |
| `missing_mandatory_create_session_response.hex` | Type 33 with Cause 70 and offending field `47 00 00 00` (type 71, zero Length, instance 0; §8.4). |
| `missing_conditional_create_session_response.hex` | Type 33 with Cause 103 and offending field `4d 00 00 00` (Indication type 77/instance 0; §7.7.6, §8.4). |
| `invalid_ie_length_modify_bearer_request.hex` | Type 34 with a malformed Bearer Context used as caller-confirmed invalid mandatory IE length (§7.7.7). |
| `invalid_ie_length_modify_bearer_response.hex` | Type 35 with Cause 67 and offending field `5d 00 00 00` for Bearer Context type 93/instance 0. |
| `incorrect_ie_delete_session_request.hex` | Type 36 carrying reserved EBI value zero, used as caller-confirmed semantic failure (§7.7.8). |
| `incorrect_ie_delete_session_response.hex` | Type 37 with Cause 69 and offending field `49 00 00 00` for EBI type 73/instance 0. |
| `malformed_echo_request.hex` | Echo Request with a two-octet Recovery value; §7.1.2 requires ignoring the erroneous IE and sending Echo Response. |
| `echo_response.hex` | T=0 type 2 with copied request sequence and local one-octet Recovery IE; no Cause is present. |
| `length_mismatch_response.hex` | Type 35 response with inconsistent datagram/header length; silently discarded under §7.7.3. |
| `unknown_message.hex` | Complete version-2/T=1 header with unknown type 254; silently discarded under §7.7.4. |

### `create_session_response_s2b_subset.bin`

| Offset | Octets | Field and spec basis |
| --- | --- | --- |
| 0 | `48` | Common header flags: version 2, TEID present (§5.1). |
| 1 | `21` | Message Type: Create Session Response in the common-header message-type field (§5.1). |
| 2..3 | `00 2d` | Length: TEID/sequence/spare (8) + 37 octets of IEs, excluding first four octets (§5.1). |
| 4..7 | `01 02 03 04` | Header TEID (§5.1). |
| 8..11 | `00 10 02 00` | Sequence number `0x001002`, spare 0 (§5.1). |
| 12..17 | `02 00 02 00 10 00` | Cause IE TLIV/value: Request accepted, flags 0 (§8.2, §8.4). |
| 18..21 | `57 00 09 01` | PGW S2b control-plane F-TEID IE TLIV header, instance 1 (Table 7.2.2-1, §8.2, §8.22). |
| 22 | `a0` | F-TEID V4 flag set, S2b PGW GTP-C interface type 32 (§8.22). |
| 23..26 | `55 66 77 88` | PGW control-plane TEID (§8.22). |
| 27..30 | `c0 00 02 01` | PGW control-plane IPv4 `192.0.2.1` (documentation prefix; §8.22). |
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
