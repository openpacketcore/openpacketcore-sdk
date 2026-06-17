# NAS-5GS Protocol Conformance

This document defines the conformance of the `opc-proto-nas` crate against
3GPP TS 24.501.

## Specification Baseline

- **Document**: 3GPP TS 24.501 (with header formats per TS 24.007)
- **Release**: Release 18 (R18)
- **Status**: v2 — experimental; message framing, mobile identity, BCD,
  first-CNF body dispatch, selected 5GMM message bodies, and NAS security
  helper hooks are structured. Procedure state machines remain out of scope.

## Supported Features

### 1. Message Framing (§9.1.1)
- EPD dispatch: `0x7E` (5GMM) and `0x2E` (5GSM); all other EPDs rejected.
- Plain 5GMM header (3 octets): security header type nibble (spare nibble
  preserved; rejected non-zero in strict mode), message type, raw body.
- 5GSM header (4 octets): PDU session identity, PTI, message type, raw body.
- Security-protected envelope (security header types 1–4, §9.3.1): MAC
  (4 octets), NAS sequence number, and protected payload framed.
- `NasSecurityContext` verifies/generates MACs and applies ciphering through
  caller-provided `NasSecurityAlgorithms`; `NullNasSecurityAlgorithms`
  implements only NIA0/NEA0. NIA1/2/3 and NEA1/2/3 fail closed unless the
  caller supplies a concrete provider.
- NAS COUNT helpers model the 16-bit overflow plus 8-bit sequence number, and
  `NasReplayWindow` rejects stale or repeated COUNT values for one direction.
- Reserved security header types (5–15) rejected.
- NAS PDUs carry no internal length framing; decode consumes the entire
  input (the transport delimits PDUs).
- All round-trips are byte-exact: spare bits and unparsed regions are
  preserved verbatim. Conformance tests include hand-authored spec-byte
  fixtures, not only this codec's own output.

### 2. 5GS Mobile Identity (§9.11.3.4)
Decodes IE *content* (caller strips IEI/length framing):
- **SUCI** (type 1): SUPI format 0 (IMSI) parsed into PLMN, routing
  indicator, protection scheme id, home network public key id, and scheme
  output; SUPI format 1 (NAI) kept raw; other formats preserved raw.
  **SUCI de-concealment is explicitly out of scope.**
- **5G-GUTI** (type 2): PLMN, AMF Region ID, AMF Set ID (10 bits),
  AMF Pointer (6 bits), 5G-TMSI; exact 11-octet length enforced.
- **IMEI (3) / IMEISV (5)**: length-checked, odd/even digit indicator
  exposed, raw content preserved; BCD unpacking available via
  ``unpack_imei``.
- **5G-S-TMSI (4) / MAC (6) / EUI-64 (7) / no identity (0)**:
  length-validated, raw preservation only.

### 3. Message-Type Registries (Tables 9.7.1 / 9.7.2)
- 5GMM: 29 message types, Registration Request (0x41) through DL NAS
  Transport (0x68), with typed-or-raw body dispatch through
  `decode_mm_message_body` / `PlainMm::decode_body`.
- 5GSM: 16 message types, PDU Session Establishment Request (0xC1) through
  5GSM Status (0xD6), with raw-preserving first-CNF body dispatch through
  `decode_sm_message_body` / `Sm::decode_body`.
- Unknown code points do not fail decoding; `from_u8` returns `None` and
  the raw code remains available on the header.

### 4. BCD Digit Unpacking (TS 24.008 / 24.501 digit packing)
- ``unpack_plmn``: three BCD octets into MCC and
  MNC, including the 2-digit MNC case (`0xF` in octet 2 high nibble).
- ``unpack_routing_indicator``: two
  BCD octets, stopping at the first `0xF` filler nibble.
- ``unpack_imei``: IMEI or IMEISV content including
  the type octet, honoring the odd/even indicator and stopping at `0xF`.
- Filler-nibble, odd-count, and MNC-padding cases are covered by hand-
  authored spec-byte fixtures.

### 5. IE-Level Message Bodies And Dispatch (v2)

#### 5.1 Registration Request (§8.2.6)
- Mandatory IEs decoded: 5GS registration type, follow-on-request pending
  bit, ngKSI, and 5GS mobile identity (via the existing identity decoder).
- All remaining bytes are parsed as optional IEs and preserved raw so that
  unknown or future IEs round-trip byte-exactly.
- Known optional IE formats registered for TLV, TLV-E, type-1 half-octet,
  and fixed-length type-3 TV IEs used by Registration Request/Accept.
  Unknown IEIs outside the registry fall back to TLV; this is honest in the
  test corpus and noted below as a gap.

#### 5.2 Registration Accept (§8.2.7)
- Mandatory 5GS registration result decoded (LV, length must be 1).
- Optional IEs iterated and raw-preserved with the same registry as
  Registration Request.

#### 5.3 Security Mode Command (§8.2.20)
- Mandatory selected NAS security algorithms decoded into NIA/NEA enums.
- Mandatory ngKSI decoded and raw-preserved.
- Mandatory replayed UE security capability LV decoded and raw-preserved;
  zero-length capabilities and truncated LV values are rejected.
- Optional IEs are iterated and raw-preserved.

#### 5.4 Security Mode Complete (§8.2.21)
- Optional IEs are iterated and raw-preserved.

#### 5.5 First-CNF Raw Body Dispatch
- 5GMM first-CNF messages without field-level parsing are exposed through
  named `MmMessageBody` raw-preserving variants, including Registration
  Complete, Authentication Response, UL NAS Transport, and DL NAS Transport.
- 5GSM first-CNF messages are exposed through named `SmMessageBody`
  raw-preserving variants, including PDU Session Establishment and Release
  request/accept/command/complete/status messages.
- Unknown message type code points decode into `Unknown` raw-preserving body
  variants.

## Out of Scope

- NAS key derivation, key lifecycle, and concrete NIA1/2/3 or NEA1/2/3
  implementations. This crate validates `opc-key` session key handles and
  provides algorithm hooks; it does not own security context selection.
- SUCI de-concealment (home-network private key operations).
- NAS procedure state machines and policy validation.
- Field-level parsing of 5GSM message bodies and 5GMM messages other than
  Registration Request/Accept/Security Mode Command/Security Mode Complete.
- Semantic validation of optional IE contents beyond length/format framing.
- EPS (4G) NAS interworking formats.

## Known Limitations

- Optional IE format detection for unknown IEIs uses a conservative
  heuristic: IEIs `0x70–0x7F` are treated as TLV-E, IEIs with high nibble
  `0xA–0xF` as type-1 half-octet, and all others as TLV. Adding a new
  fixed-length type-3 IE to the registry is required for that IE to round
  trip correctly.
- The Registration Result `SMS over NAS` flag (bit 4 of the result value)
  is not surfaced separately; the raw value is preserved for byte-exact
  re-encode.
- The in-tree null security provider is useful only for explicit NIA0/NEA0
  profiles and tests. Production deployments using non-null NAS algorithms
  must supply an external `NasSecurityAlgorithms` implementation.

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through the
  decode entry points (`NasMessage::decode`/`decode_owned`, the v2 message bodies,
  `MobileIdentity::decode`, and the BCD digit helpers), under `catch_unwind`. Runs
  in ordinary `cargo test`; no nightly toolchain or libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode_nas.rs` with a seeded corpus,
  registered in `.github/workflows/fuzz.yml` and run weekly.
- **Verification** — a deep `cargo-fuzz` pass over the decoder completed ~32M
  executions with no crash, leak, or OOM.
