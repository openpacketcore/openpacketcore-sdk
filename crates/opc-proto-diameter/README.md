# opc-proto-diameter

Experimental Diameter mechanism scaffold for OpenPacketCore.

## Purpose

`opc-proto-diameter` starts the SDK-owned Diameter surface described by ADR
0018. It provides RFC 6733 header and raw AVP framing, dictionary metadata,
feature-gated base peer procedure helpers, and early 3GPP application
dictionaries and typed helpers.

It does not provide peer transport, realm routing, AAA/HSS/CDF behavior,
charging decisions, watchdog policy, or a carrier-ready EPC/ePDG product claim.

## API Shape

- Root types include `Header`, `Message<'a>`, `OwnedMessage`, `AvpHeader`,
  `RawAvp<'a>`, `RawAvpIterator`, `ApplicationId`, `CommandCode`, `AvpCode`,
  `VendorId`, `CommandFlags`, and `AvpFlags`.
- `validate_avp_region` and `validate_avp_region_with_dictionary` enforce
  length, padding, count, duplicate-key, and dictionary-marked grouped-AVP
  recursion rules.
- `Message::decode_with_dictionary` and
  `OwnedMessage::decode_owned_with_dictionary` resolve exactly one command by
  application id, command code, and request/answer role before applying its
  top-level AVP cardinality. Missing or overlapping command profiles fail
  closed; raw `Message::decode` retains reject-all duplicate behavior.
- `dictionary` exposes `Dictionary`, `DictionarySet`, `ApplicationDefinition`,
  `CommandDefinition`, `CommandAvpRule`, `AvpCardinality`, `AvpDefinition`,
  `AvpDataType`, `AvpFlagRules`, and related metadata types.
- The `peer` feature adds transport-neutral CER/CEA, DWR/DWA, DPR/DPA
  builders/parsers, capability negotiation helpers, result-code helpers, and
  `PeerSession` projection state.
- The `app-rf` feature adds typed Rf accounting helpers.
- The `app-swm` feature adds typed SWm Diameter-EAP DER/DEA helpers, including
  exact, fail-closed resolution of an opt-in top-level default
  `Context-Identifier` extension to one of its repeated APN configurations.
  The top-level `Service-Selection` remains a distinct AVP and is not treated
  as that default pointer.
- `app-gx`, `app-s6a`, `app-s6b`, and `app-swx` currently provide dictionary
  slots rather than full typed application APIs.

## Example

```rust
use opc_proto_diameter::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x01, 0x00, 0x00, 0x14, // version, 24-bit length = 20
    0x80, 0x00, 0x01, 0x01, // request flag, command code 0x000101
    0x00, 0x00, 0x00, 0x00, // application id
    0x00, 0x00, 0x00, 0x01, // hop-by-hop id
    0x00, 0x00, 0x00, 0x02, // end-to-end id
];

let (tail, msg) = Message::decode(&packet, DecodeContext::default())?;
assert!(tail.is_empty());
assert_eq!(msg.header.length, 20);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Features

| Feature | Default | Scope |
| --- | --- | --- |
| `base` | yes | RFC 6733 common application and raw base metadata. |
| `peer` | no | CER/CEA, DWR/DWA, DPR/DPA helpers and peer-session projections. |
| `app-rf` | no | Rf accounting dictionary plus typed ACR/ACA helpers. |
| `app-swm` | no | SWm dictionary plus typed Diameter-EAP DER/DEA helpers. |
| `app-gx` | no | Gx dictionary slot only. |
| `app-s6a` | no | S6a/S6d dictionary slot only. |
| `app-s6b` | no | S6b dictionary slot only. |
| `app-swx` | no | SWx dictionary slot only. |
| `all-apps` | no | Enables every `app-*` feature. |

## Status And Limits

The crate is experimental and `publish = false`. It has ADR 0015 evidence in
progress for the base header and AVP layer, but it is not a production Diameter
stack. Raw AVP bytes are not redacted; typed helper layers own their own
redaction policies.

Use `CONFORMANCE.md` for the precise fixture provenance, fuzz target status,
application dictionary status, and typed helper gaps.

`SwmDiameterEapAnswer` struct literals must initialize
`default_context_identifier`; use `None` to preserve the prior wire shape or
`Some(id)` only when the deployment's AAA profile projects the TS 29.272
APN-Configuration-Profile default pointer into the SWm DEA extension surface.
The baseline SWm DEA command ABNF does not enumerate that top-level AVP. SDK
receivers predating this field reject the extension emitted with its required
M-bit as unknown, so upgrade decoders before enabling its emission from
encoders. Peers using the projected APN profile should decode with
`Message::decode_with_dictionary(..., DecodeContext::conservative(),
apps::SWM_PROJECTED_PROFILE_DICTIONARIES)`. That explicit profile permits
repeated `APN-Configuration` and `State` while retaining `DuplicateIe` for
every singleton and duplicate unknown key. Baseline callers use
`apps::APP_DICTIONARIES`, where APN-Configuration remains singleton. Never
combine the baseline and projected SWm dictionaries: overlapping command
grammars are rejected as ambiguous. Typed `set_once` checks remain defense in
depth.

`Dictionary::find_command` and `DictionarySet::find_command` now require an
`ApplicationId` before command code and role. Update callers that previously
looked up commands by code and role alone; wire encodings are unchanged.

## Roadmap

- Broaden typed application helpers beyond the current Rf and SWm subsets.
- Add independently sourced fixtures before raising interoperability claims.
- Keep transport, realm policy, watchdog thresholds, AAA/HSS/CDF behavior, and
  charging decisions in consuming products.

## Verification

```bash
cargo check -p opc-proto-diameter --all-targets --all-features
cargo test -p opc-proto-diameter --all-features
python3 crates/opc-proto-diameter/fuzz/generate_corpus.py self-test
(cd crates/opc-proto-diameter && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
