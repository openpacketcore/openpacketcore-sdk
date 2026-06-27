# GTPv2-C fixture corpus

This corpus follows ADR 0015 and the ePDG fixture-provenance intake checklist.
Only files in `spec/` are conformance evidence. Files in `epdg-parity/` are
SDK-authored parity/regression seeds for raw/private IE behavior and are **not**
counted as wire-format conformance proof. `independent/` is intentionally empty
until an independently captured GTPv2-C packet includes source, license,
redaction, and capture metadata. `malformed/` contains hostile synthetic inputs
that must never panic a decode path.

All subscriber identifiers are synthetic examples from documentation ranges or
non-real test digits. No key material, deployment secrets, LI identifiers, or
real subscriber data are included.

## `spec/` fixtures

The spec-authored fixtures are hand-authored from 3GPP TS 29.274 Release 18
common-header and TLIV IE layouts. They target the experimental S2b subset
implemented by `opc-proto-gtpv2c`; they are not a full GTPv2-C conformance
matrix.

### `echo_request_recovery.bin`

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `40` | Flags: version 2, piggybacking 0, TEID flag 0, spare 0. |
| 1 | `01` | Message Type: Echo Request. |
| 2..3 | `00 09` | Length: sequence/spare (4) + Recovery IE (5). |
| 4..6 | `00 00 01` | Sequence number 1. |
| 7 | `00` | Sequence spare octet. |
| 8 | `03` | IE Type: Recovery. |
| 9..10 | `00 01` | IE value length 1. |
| 11 | `00` | IE spare 0, instance 0. |
| 12 | `2a` | Restart counter 42. |

### `echo_response_recovery.bin`

Same TLIV layout as `echo_request_recovery.bin`, with message type `02`
(Echo Response) at offset 1.

### `create_session_request_s2b_subset.bin`

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `40` | Flags: version 2, no TEID. |
| 1 | `20` | Message Type: Create Session Request. |
| 2..3 | `00 9d` | Length: sequence/spare (4) + 153 octets of IEs. |
| 4..7 | `00 10 01 00` | Sequence number `0x001001`, spare 0. |
| 8..11 | `01 00 08 00` | IMSI IE header, value length 8, instance 0. |
| 12..19 | `00 01 01 21 43 65 87 f9` | IMSI `001010123456789` in TBCD with filler nibble. |
| 20..23 | `52 00 01 00` | RAT Type IE header. |
| 24 | `03` | RAT Type: WLAN. |
| 25..28 | `53 00 03 00` | Serving Network IE header. |
| 29..31 | `00 f1 10` | PLMN `001/01` in TBCD MCC/MNC order. |
| 32..35 | `57 00 19 00` | Sender F-TEID IE header. |
| 36 | `ca` | V4 + V6 flags set, interface type 10. |
| 37..40 | `11 22 33 44` | TEID/GRE key. |
| 41..44 | `c0 00 02 0a` | IPv4 `192.0.2.10` (documentation prefix). |
| 45..60 | `20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01` | IPv6 `2001:db8::1` (documentation prefix). |
| 61..64 | `47 00 09 00` | APN IE header. |
| 65..73 | `08 69 6e 74 65 72 6e 65 74` | Single APN label `internet`. |
| 74..77 | `80 00 01 00` | Selection Mode IE header. |
| 78 | `00` | MS or network provided APN, subscription verified. |
| 79..82 | `63 00 01 00` | PDN Type IE header. |
| 83 | `01` | PDN Type: IPv4. |
| 84..87 | `4f 00 05 00` | PAA IE header. |
| 88..92 | `01 c6 33 64 07` | IPv4 PAA `198.51.100.7` (documentation prefix). |
| 93..96 | `5d 00 27 00` | Bearer Context grouped IE header. |
| 97..101 | `49 00 01 00 05` | Nested EPS Bearer ID value 5. |
| 102..105 | `50 00 16 00` | Nested Bearer QoS IE header. |
| 106..107 | `49 09` | Bearer QoS priority/flags and QCI 9. |
| 108..112 | `00 00 00 10 00` | MBR uplink 4096. |
| 113..117 | `00 00 00 20 00` | MBR downlink 8192. |
| 118..122 | `00 00 00 04 00` | GBR uplink 1024. |
| 123..127 | `00 00 00 08 00` | GBR downlink 2048. |
| 128..131 | `5e 00 04 00` | Nested Charging ID IE header. |
| 132..135 | `12 34 56 78` | Charging ID example value. |
| 136..139 | `4e 00 03 02` | PCO IE header, instance 2. |
| 140..142 | `80 21 00` | Opaque PCO bytes preserved by typed value. |
| 143..146 | `4d 00 02 00` | Indication IE header. |
| 147..148 | `40 01` | Opaque Indication flags. |
| 149..152 | `a3 00 03 01` | APCO IE header, instance 1. |
| 153..155 | `80 21 01` | Opaque APCO bytes preserved by typed value. |
| 156..159 | `fe 00 01 00` | Unsupported/private IE header. |
| 160 | `aa` | Unsupported/private IE value preserved raw. |

### `create_session_response_s2b_subset.bin`

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `48` | Flags: version 2, TEID present. |
| 1 | `21` | Message Type: Create Session Response. |
| 2..3 | `00 2d` | Length: TEID/sequence/spare (8) + 37 octets of IEs. |
| 4..7 | `01 02 03 04` | Header TEID. |
| 8..11 | `00 10 02 00` | Sequence number `0x001002`, spare 0. |
| 12..17 | `02 00 02 00 10 00` | Cause IE: Request accepted, flags 0. |
| 18..21 | `57 00 09 00` | Sender F-TEID IE header. |
| 22 | `8b` | V4 flag set, interface type 11. |
| 23..26 | `55 66 77 88` | Sender TEID. |
| 27..30 | `c0 00 02 01` | IPv4 `192.0.2.1` (documentation prefix). |
| 31..39 | `4f 00 05 00 01 c6 33 64 07` | PAA IE, IPv4 `198.51.100.7`. |
| 40..48 | `5d 00 05 00 49 00 01 00 05` | Bearer Context containing nested EBI 5. |

### Modify/Delete/Update message fixtures

These fixtures validate the common header, mandatory IE shell, and S2b typed
view dispatch for the experimental subset:

| File | Message type | Payload after common header |
| --- | --- | --- |
| `modify_bearer_request_bearer_context.bin` | `22` Modify Bearer Request | `5d 00 05 00 49 00 01 00 05` Bearer Context with EBI 5. |
| `modify_bearer_response_cause.bin` | `23` Modify Bearer Response | `02 00 02 00 10 00` Cause Request accepted. |
| `delete_session_request_linked_ebi.bin` | `24` Delete Session Request | `49 00 01 00 05` linked EBI 5. |
| `delete_session_response_cause.bin` | `25` Delete Session Response | `02 00 02 00 10 00` Cause Request accepted. |
| `update_bearer_request_bearer_context.bin` | `61` Update Bearer Request | `5d 00 05 00 49 00 01 00 05` Bearer Context with EBI 5. |
| `update_bearer_response_cause.bin` | `62` Update Bearer Response | `02 00 02 00 10 00` Cause Request accepted. |

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

## `malformed/` fixtures

The malformed corpus contains synthetic hostile inputs for truncation, declared
length overrun, strict spare-bit rejection, low-limit IE count-limit paths, and
grouped IE recursion-depth limits. `too_many_small_ies.bin` intentionally
contains two small IEs and is replayed with `DecodeContext::max_ies = 1` so
both whole-message and decoded raw-IE region validation reject on
`IeCountExceeded`. `nested_bearer_context_depth_limit.bin` is a valid
Modify Bearer Request shell whose top-level Bearer Context contains another
Bearer Context; replay with `DecodeContext::max_depth = 1` must reject on
`DepthExceeded`. Decode may return any structured `DecodeError` outside those
per-fixture assertions, but must never panic.
