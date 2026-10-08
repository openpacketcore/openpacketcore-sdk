# NAS-5GS Protocol Conformance

This document defines the conformance of the `opc-proto-nas` crate against
3GPP TS 24.501, with a separate bounded NAS-over-TCP envelope subset of
TS 24.502 V18.8.0 clause 9.4.

## Specification Baseline

- **Document**: 3GPP TS 24.501 (with header formats per TS 24.007)
- **Release**: Release 18 framing baseline; the authentication subset below is
  verified against TS 24.501 V17.15.0 (Release 17).
- **Status**: v2 — experimental; message framing, mobile identity, BCD,
  first-CNF body dispatch, selected 5GMM message bodies, and NAS security
  helper hooks are structured. Procedure state machines are owned by consuming
  NF crates.

## Supported Features

### NAS-over-TCP Envelopes (TS 24.502 §9.4)

The `tcp` module reads/writes a two-octet big-endian length that counts NAS
payload octets only. Borrowed receive and incremental stream receive preserve
every payload octet, including protected or unrecognized NAS. They do not call
the TS 24.501 content or security decoder described below.

| Operation | Implemented contract |
| --- | --- |
| Construct | Exact envelope for 1–65,535 payload octets within the caller's bound; output untouched on refusal |
| Borrowed receive | First complete frame and unread tail; partial prefix/body needs more input |
| Incremental receive | Arbitrary segmentation; at most one frame per call; coalesced tail remains caller-owned |
| Finalize | Clean boundary succeeds permanently; partial prefix/body becomes sticky truncation |
| Refuse | Invalid caller bound, empty/above-bound length, insufficient output, bounded allocation failure, or input after termination |

Zero-length refusal, the inclusive caller bound, sticky terminal states and
single-frame buffering are SDK policy. Length validation precedes allocation;
the decoder requests only the declared payload size. TCP lifecycle, reconnect
selection, security termination, SA provenance and UE lifecycle are outside
this module. No live TCP/N3IWF/AMF interoperability is claimed.

The nine reviewed `nas-tcp` fixtures and 174 independent streams exercise both
receive APIs and exact construction. [TCP.md](TCP.md) records source revisions,
digests, allocation measurements, fuzz scope and reproduction commands.

### 1. Message Framing (§9.1.1)
- EPD dispatch: `0x7E` (5GMM) and `0x2E` (5GSM); all other EPDs rejected.
- Plain 5GMM header (3 octets): security header type nibble (spare nibble
  preserved; rejected non-zero in strict mode), message type, raw body.
- 5GSM header (4 octets): PDU session identity, PTI, message type, raw body.
- Security-protected envelope (security header types 1–4, §9.3.1): MAC
  (4 octets), NAS sequence number, and protected payload framed.
- `NasSecurityContext` verifies/generates MACs and applies ciphering through
  caller-provided `NasSecurityAlgorithms`; `NullNasSecurityAlgorithms`
  implements only NIA0/NEA0. `AesNasSecurityAlgorithms` implements NIA2 with
  NEA2 or NEA0 and a caller-owned key resolver. The connection context supplies
  BEARER and owns transmit COUNT allocation.
  NIA1/NEA1 and NIA3/NEA3 remain out of scope.
- NAS COUNT helpers model the 16-bit overflow plus 8-bit sequence number.
  `NasSecurityContext` estimates receive COUNT from full state and verifies the
  MAC with that estimate. `NasReplayWindow` is a standalone helper that rejects
  stale or repeated COUNT values for one direction; the context does not use it.
- Reserved security header types (5–15) rejected.
- NAS PDUs carry no internal length framing; decode consumes the entire
  input (the transport delimits PDUs).
- Framing and raw-preserved bodies round-trip byte-exactly. Authentication
  bodies use the canonical encoding described below. Conformance tests include hand-authored spec-byte
  fixtures, not only this codec's own output.

### 2. 5GS Mobile Identity (§9.11.3.4)
Decodes IE *content* (caller strips IEI/length framing):
- **SUCI** (type 1): SUPI format 0 (IMSI) parsed into PLMN, routing
  indicator, protection scheme id, home network public key id, and scheme
  output; SUPI format 1 (NAI) kept raw; other formats preserved raw.
  **SUCI de-concealment is a home-network key-management function, not a NAS
  codec function.**
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
  Complete, UL NAS Transport, and DL NAS Transport.
- 5GSM first-CNF messages are exposed through named `SmMessageBody`
  raw-preserving variants, including PDU Session Establishment and Release
  request/accept/command/complete/status messages.
- Unknown message type code points decode into `Unknown` raw-preserving body
  variants.

## Codec Boundary

- NAS key derivation, key lifecycle, NIA1/NEA1 (SNOW 3G), and NIA3/NEA3
  (ZUC). This crate validates `opc-key` session key handles and supplies AES
  algorithms and hooks; callers own resolver authorization, key derivation,
  security-context selection, durable COUNT preservation and exclusive restore.
- SUCI de-concealment (home-network private key operations).
- NAS procedure state machines and policy validation.
- Field-level parsing of 5GSM message bodies and 5GMM messages other than
  Registration Request/Accept, Security Mode Command/Complete, and the five
  Authentication messages.
- Semantic validation of optional IE contents beyond length/format framing.
- EPS (4G) NAS interworking formats.

## Known Limitations

- Outside the authentication bodies, optional IE format detection for unknown
  IEIs uses a conservative heuristic: IEIs `0x70–0x7F` are treated as TLV-E, IEIs with high nibble
  `0xA–0xF` as type-1 half-octet, and all others as TLV. Adding a new
  fixed-length type-3 IE to the registry is required for that IE to round
  trip correctly.
- The Registration Result `SMS over NAS` flag (bit 4 of the result value)
  is not surfaced separately; the raw value is preserved for byte-exact
  re-encode.
- The in-tree null security provider is useful only for explicit NIA0/NEA0
  profiles and tests. The AES provider does not negotiate algorithms or manage
  durable key/COUNT lifetimes, and has no live AMF interoperability qualification.

## Robustness & Fuzzing

Decode paths carry no `unsafe` and use bounded length arithmetic. The inner NAS
decoders do not preallocate from a wire-declared length; the separate incremental
TCP decoder allocates only after validating its prefix against the caller's
bound. Three layers guard the inner decoders:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through the
  decode entry points (`NasMessage::decode`/`decode_owned`, the v2 message bodies,
  `MobileIdentity::decode`, and the BCD digit helpers), under `catch_unwind`. Runs
  in ordinary `cargo test`; no nightly toolchain or libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode_nas.rs` with a seeded corpus,
  registered in `.github/workflows/fuzz.yml` and run weekly.
- **Verification** — a deep `cargo-fuzz` pass over the decoder completed ~32M
  executions with no crash, leak, or OOM.

The separate `nas_tcp` fuzz target compares segmented input with an independent
length/cursor model, checks exact payloads, caller-owned tails, terminal states,
encoding and redaction. A 61-second run completed 8,110,190 executions with no
failure, using a 4,096-byte input cap. Ordinary tests cover the 65,535-byte wire
maximum. The existing NAS fuzz workflow discovers both targets automatically.

## Authentication bodies and AES security

The body fixtures in `tests/nas_authentication.rs` are synthetic wire examples
written from the tables in [TS 24.501 V17.15.0](https://www.etsi.org/deliver/etsi_ts/124500_124599/124501/17.15.00_60/ts_124501v171500p.pdf),
§8.2.1–8.2.5. They cover AKA and EAP alternatives, all five message types,
conditional presence, truncation, malformed lengths, duplicate/unknown IEs,
redaction and encoding. These are codec fixtures, not captured peer exchanges.

| IE | Specification clause | Value and framing |
| --- | --- | --- |
| ngKSI | TS 24.501 §9.11.3.32 | Four bits: identifier 0–7 plus native/mapped flag; value 7 refused in network-originated authentication |
| ABBA | TS 24.501 §9.11.3.10 | 2–255 value octets; Request LV; Result optional TLV (0x38) |
| RAND | TS 24.501 §9.11.3.16 → TS 24.008 §10.5.3.1 | 16 value octets, TV (0x21) |
| AUTN | TS 24.501 §9.11.3.15 → TS 24.008 §10.5.3.1.1 | 16 value octets, TLV (0x20) |
| EAP message | TS 24.501 §9.11.2.2; RFC 3748 §4 | 4–1500 value octets, matching embedded EAP length; TLV-E (0x78) or mandatory Result LV-E |
| RES* | TS 24.501 §9.11.3.17 → TS 24.301 §9.9.3.4; Table 8.2.2.1.1 fixes the 16-octet size | 16 value octets, TLV (0x2d) |
| AUTS | TS 24.501 §9.11.3.14 → TS 24.008 §10.5.3.2.2 | 14 value octets, TLV (0x30) |
| 5GMM cause | TS 24.501 §9.11.3.2 | One octet; unknown values retained |

RAND/AUTN/AUTS encodings were checked against
[TS 24.008 V17.9.0](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/17.09.00_60/ts_124008v170900p.pdf).
Sender validation requires RAND and AUTN together, or EAP exclusively, in a
Request. Response requires
exactly one of RES* and EAP. Result requires ABBA for EAP-Success. Failure
requires AUTS if and only if the cause is synchronization failure (21). Reject
can be empty or carry EAP-Failure. EAP method bodies and procedure state remain
caller-owned; recognized EAP codes obey the header sizes in
[RFC 3748 §4.1–4.2](https://www.rfc-editor.org/rfc/rfc3748#section-4.1).

Encoding and Strict/ProcedureAware decoding enforce those sender rules. Default
Structural (and HeaderOnly body) decoding follows TS 24.007 §11.2.5/§11.4.1:
optional IEs do not cause missing/unexpected-presence errors. A Failure ignores
AUTS unless cause=21; Result accepts EAP-Success without ABBA (TS 24.501
§5.4.1.2.5.2), and Reject accepts a syntactically valid optional EAP packet.
Per TS 24.007 §11.4.2, excess AUTN/RES*/AUTS octets are discarded; RFC 3748
§4.1 EAP padding beyond its embedded Length is also discarded. Strict levels
require exact lengths. The EAP packet itself must remain 4–1500 octets, fit
inside its IE and obey its code's header size. Mandatory ngKSI, ABBA and EAP
remain checked at all levels.

Authentication-specific optional IE parsing follows
[TS 24.007 V17.5.0 §11.2.4–11.2.5](https://www.etsi.org/deliver/etsi_ts/124000_124099/124007/17.05.00_60/ts_124007v170500p.pdf)
and TS 24.501 §7.5–7.7. An unknown IE with bit 8 set occupies one octet;
0x70–0x7f use two length octets; other unknown IEs use one. Unknown
comprehension-required IEIs 0x00–0x0f and 0x7e–0x7f always fail. Other unknown
IEs are preserved, dropped or rejected according to `UnknownIePolicy` (strict
validation alone does not reject them). Repetitions use the first occurrence
as §7.6.3 requires, including when the shared context defaults to `Last`;
explicit `DuplicateIePolicy::Reject` refuses duplicates. A known IE appearing
before an already accepted later table entry is out of order: default levels
ignore it (§7.6.2), while Strict and ProcedureAware refuse it. At default levels,
malformed optional values are treated as absent (§7.7.1); parsing continues at
the next framed IE. If optional framing is
truncated, no trustworthy next boundary exists, so the remaining optional bytes
are ignored without attempting resynchronization. Strict levels refuse malformed
optional IEs. All optional IEs,
including ignored repetitions and dropped unknowns, count toward `max_ies`.
Known lengths are checked before copying values, and `max_message_len` is
checked before parsing. Syntactic failures are returned as redacted errors to
the procedure layer, which owns the §7 status-message/recovery behavior.

Authentication encoding validates mutable fields and raw extensions before
writing, and uses canonical table order followed by retained unknown IEs.
Duplicates, ignored values and spare bits are not retained. The typed bodies
have no original wire image, so `EncodeContext::raw_preserving` still produces
canonical output; use `PlainMm.body` for opaque forwarding. Default-decoded
values that violate sender presence rules must be resolved by the procedure
before encoding. The five `MmMessageBody` variants
now contain typed bodies; use their fields and `Encode`/`BorrowDecode`/
`OwnedDecode`, or retain `PlainMm.body` for opaque forwarding. The older
`NasKeySetIdentifier` API remains separate; the authentication `NgKsi` type
correctly distinguishes the context-type flag from the no-key identifier.

### Algorithm implementation and vector sources

[TS 33.501 V18.6.0 §D.2.1.3, §D.3.1.3, §D.4.4 and §D.4.5](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/18.06.00_60/ts_133501v180600p.pdf)
map NEA2/NIA2 directly to EEA2/EIA2 and their test sets. The committed
`tests/fixtures/nas_aes_33401.txt` records **all six** C.1 sets and **all eight**
C.2 sets from [TS 33.401 V18.0.0 Annex C](https://www.etsi.org/deliver/etsi_ts/133400_133499/133401/18.00.00_60/ts_133401v180000p.pdf).
Each row names its source clause and retains its key, COUNT, BEARER, DIRECTION,
bit LENGTH, message and expected result. Printed zero padding beyond the last
message octet is omitted. C.1 ciphertext is checked both ways; C.2 MACs are
checked against the published 32-bit values.

The provider uses RustCrypto `aes` 0.9.3, `cmac` 0.8 and `ctr` 0.10, all with
zeroization enabled. AES 0.9.3 declares Rust 1.89; CMAC 0.8, CTR 0.10 and
the CMAC `dbl` dependency declare Rust 1.85. Their MIT/Apache-2.0 licenses
are compatible with `deny.toml`.
`NasAesKey` owns a zeroizing 128-bit value and redacts `Debug`; the provider
never formats the resolver. Key resolution receives the opaque SDK handle and
an explicit integrity/ciphering usage and algorithm identity via
`NasKeyUsage::Integrity(Nia2)` or `NasKeyUsage::Ciphering(Nea2)` (TS 33.501
Annex A.8). The resolver must authorize that handle
and return an already-derived KNASint/KNASenc; no SDK storage key is extracted
or truncated. NIA1/NEA1 (SNOW 3G), NIA3/NEA3 (ZUC), KDFs and negotiation are
out of scope. NEA0 is pass-through without cipher-key resolution and works
with NIA2 under the ciphered header types (TS 24.501 §4.4.5). NIA0 remains
refused by the AES provider and requires the separate null provider.

NIA2 computes CMAC over the 64-bit COUNT/BEARER/DIRECTION/zero prefix followed
by the specified message bits and returns the leftmost 32 tag bits. The
partial-octet adapter uses the bit padding of NIST SP 800-38B §6.2 and adjusts
the last complete block by K1 XOR K2 before RustCrypto CMAC finalization;
RustCrypto supplies AES, subkey doubling, CBC chaining and finalization. Keys
and adapter scratch are zeroized. Ordinary NAS messages use the direct
byte-aligned CMAC path. NEA2 uses a big-endian 64-bit counter in the low half
of the AES input. Non-byte-aligned cipher output zeros unused low bits.

The context supplies `SQN || transmitted payload` to integrity and only the
payload to ciphering (TS 24.501 §4.4.3.3 and §4.4.4.1). Existing custom
providers must remove any SQN-prepending workaround and accept the new
`NasConnectionId` argument in both algorithm hooks. NAS COUNT is zero-extended
to 32 bits. BEARER is the immutable per-context connection identifier, 1 for
3GPP or 2 for non-3GPP access (TS 33.501 §6.4.2); the provider owns no BEARER.

`protect_payload` no longer takes an explicit COUNT. It reserves the next COUNT
from the context atomically before calling providers. Clones share counters,
provider errors burn the reservation, and 24-bit exhaustion never wraps.
`NasCountState` distinguishes the next unused transmit COUNT (`None` when
exhausted) from the highest authenticated receive COUNT. The receive estimate
is strictly higher than the stored value, including across lost messages and
restored sequence numbers (TS 24.501 §4.4.3.1). Authentication and deciphering
must both succeed before `verify_and_decipher` advances receive state. Replays
normally fail integrity against the newer estimate; concurrent stale acceptance
returns `ReplayRejected`. NIA0 cannot reliably detect replay because its MAC
does not authenticate COUNT.

Callers own key derivation/replacement and exclusive, current per-connection
state restoration. Snapshots do not supply durable reservations: persist and
fence state before reusing keys across restarts, or establish fresh keys. These
codec/provider changes do not implement Pod lifecycle, durable formats or
session draining.

The synthetic protected-envelope fixture was independently generated using
OpenSSL 3.5.7. For uplink COUNT=1, BEARER=2, payload `7e0043`, KNASenc=`22`
repeated 16 times and KNASint=`11` repeated 16 times:

```sh
printf '\x7e\x00\x43' | openssl enc -aes-128-ctr \
  -K 22222222222222222222222222222222 \
  -iv 00000001100000000000000000000000 | od -An -tx1
# 89 1b 5d
printf '\x00\x00\x00\x01\x10\x00\x00\x00\x01\x89\x1b\x5d' | \
  openssl mac -macopt cipher:AES-128-CBC \
  -macopt hexkey:11111111111111111111111111111111 CMAC
# NAS MAC is the first four octets: 55 ea 2a 24
```

The corresponding downlink prefix ends in `14000000`, giving ciphertext
`d6ca5a` and NAS MAC `f1ca634d`. Tests also cover tampering, replay, key-resolution
failures, invalid bearer/length, all final-bit positions, and Debug redaction.
The authentication QuickCheck test runs 2,000 generated bodies through all five
dispatch paths with default, conservative and small decoding limits. Values
that satisfy sender rules are encoded and decoded again; receiver-only values
must fail encoding without writing output. Ten canonical authentication frames
seed the fuzz corpus; both the fuzzer and corpus replay dispatch plain frame
bodies at default and Strict levels. Tests cover both accesses, NEA0, lost and
restored COUNTs, cloned/concurrent transmit allocation, exhaustion and redaction
of PlainMm, SecurityProtected and VerifiedNasPayload. Independent cryptographic/codec review and live peer interoperability
are separate qualification steps.
