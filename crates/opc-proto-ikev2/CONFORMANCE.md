# opc-proto-ikev2 conformance scaffold

This document defines the current conformance boundary for the experimental
`opc-proto-ikev2` crate. It is a scaffold for RFC 7296 IKEv2 header and generic
payload-chain work, not a complete IKEv2 implementation and not an ePDG product
claim.

## Claimed coverage

| Area | Status | Evidence |
| --- | --- | --- |
| Fixed IKE header (`RFC 7296` §3.1) | Experimental structural coverage | `src/header.rs`; `tests/header.rs` decodes and raw-preserving re-encodes a hand-authored IKEv2 header, rejects bad major versions, short lengths, truncation, and strict reserved flag bits. |
| Generic payload header and chain (`RFC 7296` §3.2) | Experimental structural coverage for unencrypted payloads | `src/payload.rs`; `tests/payload_chain.rs` walks a hand-authored SA -> Nonce chain, validates length fields, count limits, truncation, strict reserved bits, and byte-exact raw re-encode through `Message`. |
| Unknown payload preservation | Experimental structural coverage | Unknown non-critical payloads remain raw-preserved; unknown critical payloads fail closed by default as required by RFC 7296 §2.2. |
| Protected payload boundary (`SK`, `SKF`) | Boundary only | `src/crypto.rs` and `tests/payload_chain.rs` expose `ProtectedPayloadContext` and `CryptoProvider`; the codec classifies both `SK` and `SKF`, treats protected bodies as opaque, and does not decrypt, authenticate, or parse inner payloads. |
| Hostile input safety | Initial regression coverage | `tests/malformed.rs` replays prefixes and malformed shapes through borrowed, owned, and iterator paths to assert structured errors without panic. |
| Fuzz target registration | Scheduled smoke coverage | `fuzz/fuzz_targets/decode_message.rs` and `roundtrip.rs` are registered in `.github/workflows/fuzz.yml` so the crate receives the same scheduled fuzz-list and smoke-run coverage as the other protocol crates. |
| `opc-protocol` integration | Implemented for scaffold | `Message` and `OwnedMessage` implement `BorrowDecode`, `OwnedDecode`, `Encode`, and `ToOwnedPdu`; errors use structured `opc-protocol` types and `SpecRef` references. |

## Payload-chain parser plan

The parser is intentionally staged so future work can add coverage without
changing the product boundary:

1. **Current scaffold:** parse the fixed header and generic payload chain, keep
   payload bodies raw, preserve unknown payload bytes, validate declared lengths,
   and stop at protected payload boundaries.
2. **Typed cleartext payload bodies:** add spec-authored fixtures and typed views
   for SA, KE, Nonce, Notify, Delete, Vendor ID, IDi/IDr, CERT/CERTREQ, AUTH,
   CP, EAP, and traffic selectors as each body is claimed. Each addition must
   include octet-level fixture comments and byte-exact decode -> encode tests.
3. **Protected payload opening boundary:** use caller-supplied `CryptoProvider`
   implementations to authenticate/decrypt `SK`/`SKF`, strip padding, and then
   feed the returned cleartext bytes back into the generic payload-chain parser.
   The SDK crate must not choose algorithms, keys, retransmission behavior,
   EAP-AKA procedure, Child SA installation, or 3GPP profile policy.
4. **Fragmentation framing:** add RFC 7383 `SKF` fragment-number/total-fragments
   structural checks and fixtures before claiming fragmentation conformance.
5. **Fuzz/corpus expansion:** promote the current fuzz target and malformed
   regression seeds into a provenance-labeled corpus once cleartext body typed
   views are added.

## Explicitly out of scope

- IKE SA state machines, retransmission timers, cookies, peer policy, NAT-T, or
  message correlation beyond structural Message ID parsing.
- EAP-AKA, 3GPP ePDG profile enforcement, subscriber/session lifecycle, Child SA
  installation, XFRM/IPsec programming, or key-management policy.
- Concrete cryptographic algorithms, key derivation, padding policy, integrity
  verification, or null-crypto defaults.
- Claims of interoperability with strongSwan, libreswan, carrier ePDG systems,
  or any production deployment.

## Canonicalization policy

Raw-preserving encode keeps the decoded fixed-header minor version, flags, and
payload-chain bytes. Canonical encode recomputes the fixed-header Length field,
emits IKE version 2.0, and clears the fixed-header Version flag and reserved
flag bits, but still carries payload-chain bytes exactly as provided. Future
typed payload-body work must document any body-level canonicalization here
before claiming it.

## Fixture provenance

The current tests use hand-authored structural byte arrays based on RFC 7296
§3.1 fixed-header and §3.2 generic payload layouts, with octet-level comments
on the conformance fixtures in `tests/header.rs` and `tests/payload_chain.rs`.
They are suitable for this scaffold's structural coverage only. They are not
independent-peer interoperability fixtures, and no source-product bytes are
counted as conformance evidence.

Future fixtures must follow ADR 0015: spec-authored or independently captured
bytes, octet-level comments, raw preservation for unknown payloads, negative
malformed cases, and clear separation between conformance, parity, and fuzz
corpus provenance.
