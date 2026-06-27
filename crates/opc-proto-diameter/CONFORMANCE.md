# opc-proto-diameter Conformance

This document defines the conformance status of the `opc-proto-diameter` crate.

## Specification Baseline

- **Document**: IETF RFC 6733 — *Diameter Base Protocol*
- **3GPP references**: 3GPP TS 32.299 (Rf offline charging), 3GPP TS 29.273
  (SWm Diameter-EAP), 3GPP TS 29.212 (Gx), 3GPP TS 29.272 (S6a/S6d),
  3GPP TS 29.273 (S6b/SWx).
- **Status**: experimental scaffold with ADR 0015 evidence in progress

## Implemented scaffold

### 1. Message Header (RFC 6733 §3)

- Version 1 parsing and validation.
- 24-bit message length field honored: shorter input rejected as truncated,
  length smaller than the 20-octet header rejected as structural, length
  exceeding `DecodeContext::max_message_len` rejected as too large.
- Command flags: Request (`R`), Proxiable (`P`), Error (`E`), Potentially
  Retransmitted (`T`); reserved bits rejected in strict mode.
- 24-bit command code parsing; `CommandCode::fits_wire` rejects overflow at
  encode time.
- 32-bit application identifier, hop-by-hop identifier, and end-to-end
  identifier parsing and preservation.
- `Message::tail` returns unconsumed bytes after the header-declared boundary.

### 2. Generic AVP TLV Layer (RFC 6733 §4)

- Non-vendor AVP header (8 octets) and vendor-specific AVP header
  (12 octets, V bit + Vendor-Id) parsing.
- 24-bit AVP length field honored; length shorter than the header rejected,
  length beyond input rejected as truncated.
- Four-octet padding to boundary; strict mode rejects non-zero padding bytes.
- Reserved AVP flag bits rejected in strict mode.
- Vendor-specific AVPs with `Vendor-Id = 10415` (3GPP) recognized in
  dictionary lookups.

### 3. AVP-region validation

- Per-region AVP count limit via `DecodeContext::max_ies`.
- Duplicate AVP-key policy: `Reject`, `First`, `Last`.
- Dictionary-defined grouped AVP recursion bounded by
  `DecodeContext::max_depth`.
- Raw AVP-region validation checks lengths, counts, duplicates, padding, and
  dictionary-defined grouped-AVP recursion; it preserves unknown AVPs as opaque
  bytes. Unknown-mandatory rejection is a typed-layer policy enforced by the
  `peer` and application parsers (see below), not by the raw validator.

### 4. Base peer procedures (RFC 6733 §5.3–5.5)

Feature-gated under the `peer` feature.

| Procedure | Request | Answer | Notes |
|:----------|:--------|:-------|:------|
| Capabilities-Exchange | CER | CEA | Full capability AVPs, plus minimal protocol-error answer helper. |
| Device-Watchdog | DWR | DWA | Optional `Origin-State-Id`. |
| Disconnect-Peer | DPR | DPA | `Disconnect-Cause` enumeration. |

Peer helpers include:
- Capability intersection (`CapabilityNegotiation`) with Relay Application Id
  awareness.
- Result-code family classification and E-bit derivation per RFC 6733 §7.2.
- Optional answer diagnostics (`Error-Message`, raw `Failed-AVP` values).
- Unknown AVP handling: mandatory unknown AVPs are rejected; non-mandatory
  unknown AVPs are handled per `UnknownIePolicy` (`Drop`, `Preserve`, `Reject`).

### 5. Application dictionaries

Feature-gated per application. Dictionary metadata (applications, commands,
AVPs, data types, flag rules) is present; typed builders/parsers are limited to
`app-rf` and `app-swm`.

| Feature | Application | Command | Typed helpers |
|:--------|:------------|:--------|:--------------|
| `app-rf` | 3GPP Rf accounting (id 3) | Accounting-Request / Accounting-Answer (271) | `RfAccountingRequest`, `RfAccountingAnswer` |
| `app-swm` | 3GPP SWm (id 16_777_264) | Diameter-EAP-Request / Diameter-EAP-Answer (268) | `SwmDiameterEapRequest`, `SwmDiameterEapAnswer` |
| `app-gx` | 3GPP Gx (id 16_777_238) | — | dictionary only |
| `app-s6a` | 3GPP S6a/S6d (id 16_777_251) | — | dictionary only |
| `app-s6b` | 3GPP S6b (id 16_777_272) | — | dictionary only |
| `app-swx` | 3GPP SWx (id 16_777_265) | — | dictionary only |

### 6. Redaction

Sensitive typed fields are wrapped in `Redacted<T>`. `Debug` and `Display`
output the literal `REDACTED`; equality, cloning, and hashing delegate to the
inner value so business logic can still operate on the real data.

Covered redacted fields:
- `RfAccountingRequest` / `RfAccountingAnswer`: `Session-Id`, `Origin-Host`,
  `Origin-Realm`, `Destination-Realm`, `Destination-Host`, `User-Name`,
  `SubscriptionId::subscription_id_data`, IP addresses inside `PsInformation`.
- `SwmDiameterEapRequest` / `SwmDiameterEapAnswer`: `Session-Id`, `Origin-Host`,
  `Origin-Realm`, `Destination-Realm`, `Destination-Host`, `User-Name`,
  `EAP-Payload`, `EAP-Reissued-Payload`, `EAP-Master-Session-Key`.

Raw AVP bytes are **not** redacted: the raw layer is intentionally a
byte-preserving forwarding surface, and redaction is a typed-layer policy.

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  fuzz corpus entry, byte-truncations of each entry, and hostile constant
  inputs through the message and AVP decode entry points under `catch_unwind`.
  Runs in ordinary `cargo test`; no nightly toolchain or libFuzzer required.
- **Fuzz target registration and scheduled coverage** — `fuzz/Cargo.toml`
  registers `fuzz/fuzz_targets/decode_message.rs` and
  `fuzz/fuzz_targets/decode_avp.rs`. The repository-level
  `.github/workflows/fuzz.yml` matrix is the source of truth for weekly/manual
  fuzz-smoke scheduling; keep that matrix aligned with this document before
  citing scheduled CI coverage. When the workflow includes `opc-proto-diameter`,
  it runs `cargo +nightly fuzz list` and then executes the registered targets
  for a bounded smoke interval. Each target seeds *only* from its own directory
  under `fuzz/corpus/<target>/`; no committed seed file lives solely in a
  provenance or documentation directory.
- **Fuzz target compilation** — the per-PR `.github/workflows/ci.yml` gate does
  not currently run `cargo +nightly fuzz list`; local fuzz-target registration
  is checked with `cargo +nightly fuzz list` (and, when needed,
  `cargo +nightly fuzz build`) from `crates/opc-proto-diameter`.

### On-disk corpus layout

```text
fuzz/corpus/
├── decode_message/           # seeds for the decode_message fuzz target
│   ├── header_only_cer-*
│   ├── cer_request-*
│   ├── cea_success-*
│   ├── dwr_request-*
│   ├── dpr_request-*
│   ├── rf_acr_start-*
│   ├── swm_der-*
│   └── malformed_*-*         # hostile seeds: truncation, duplicate, depth, flags
└── decode_avp/               # seeds for the decode_avp fuzz target
    ├── ietf_origin_host-*
    ├── vendor_ps_info-*
    ├── grouped_failed_avp-*
    ├── padded_single_octet-*
    ├── arbitrary_avp_tree-*
    └── malformed_*-*         # hostile seeds: length, padding, duplicate, depth
```

The `fuzz/generate_corpus.py` script is the source of truth for the named
spec-valid and malformed seeds; running it regenerates the files above. Any
additional hash-only files in these directories are libFuzzer-discovered
regression seeds from prior runs.

## Fixture provenance

Test bytes are divided into four categories. Only categories 1 and 2 count as
ADR 0015 conformance evidence; categories 3 and 4 are parity or regression
evidence only.

1. **RFC-authored fixtures** (`tests/fixture_provenance.rs` and the spec-valid
   seeds in `fuzz/corpus/*/`) — hand-built from RFC 6733 §3 (header), §4 (AVP
   framing), and the cited AVP sections. These are the only fixtures counted as
   ADR 0015 conformance evidence for the base header and AVP layer.
2. **3GPP-authored fixtures** (`tests/fixture_provenance.rs` and the spec-valid
   seeds in `fuzz/corpus/*/`) — hand-built from RFC 6733 wire framing plus
   3GPP TS 32.299 §5.1/§7.1 (Rf) and 3GPP TS 29.273 §6.1 (SWm) command/AVP
   codes. They are application-dictionary evidence, not full
   application-conformance evidence.
3. **ePDG parity bytes** — *not imported*. The source plan references ePDG
   local-builder cases; those remain external **parity-only** seeds until a
   later fixture-intake task records provenance, license, and capture metadata.
   They are deliberately **not** treated as conformance evidence.
4. **Generated codec round trips** (`tests/fixture_provenance.rs` and existing
   `tests/app_dictionaries.rs`) — built with this crate's own encoder. Useful
   regression tests, but they do not prove wire conformance by themselves.

## Codec Boundary

The following are outside the current crate scope:

- Full RFC 6733 typed AVP value decoding for every base AVP.
- Typed helpers for `app-gx`, `app-s6a`, `app-s6b`, `app-swx`.
- Full message-specific semantic validation (e.g., mandatory-AVP presence for
  every command) beyond what the Rf/SWm typed helpers enforce.
- Complete 3GPP Rf/SWm/Gx/S6a/S6b/SWx application coverage.
- Transport operations, TCP/SCTP transport, TLS/TLS-PSK handling, realm routing,
  peer topology, watchdog thresholds, failover state machines, AAA/HSS/CDF
  behavior, charging decisions, and deployment readiness policy.
