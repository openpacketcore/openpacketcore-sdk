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
| Protected payload boundary (`SK`, `SKF`) | Boundary plus AES-GCM `SK` opener/sealer | `src/crypto.rs` and `tests/payload_chain.rs` expose `ProtectedPayloadContext` and `CryptoProvider`; the codec classifies both `SK` and `SKF`, treats protected bodies as opaque, and never parses ciphertext as cleartext. `src/protected_payload_crypto.rs` and `tests/protected_payload_crypto.rs` provide caller-keyed RFC 5282 AES-GCM-16 `SK` open and seal helpers for already-derived SA_INIT key material. |
| IKE_AUTH cleartext payload helpers | Experimental typed coverage for opened payload chains | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` decode/build IDi/IDr, AUTH, EAP, CP, SA, TSi/TSr, Notify, and Delete payloads from cleartext chains with redaction-safe debug output and malformed-input checks. |
| IKE_AUTH shared-key AUTH MIC | Experimental transcript-bound helper coverage | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` compute and verify RFC 7296 shared-key AUTH MICs from explicit SA_INIT transcript bytes, peer nonce, ID payload body, negotiated PRF, `SK_pi`/`SK_pr`, and caller-supplied EAP/AAA keying material. The helper does not run EAP-AKA or choose AAA policy. |
| Child SA negotiation helpers | Product-neutral selection intent only | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` select a proposal and traffic selectors against caller-supplied protocol/transform/selector policy and build response SA/TS payload entries once the product supplies a responder SPI. The helper does not allocate SPIs, own Child SA lifecycle, install XFRM state, or decide product traffic readiness. |
| NAT detection Notify semantics (`RFC 7296` §2.23) | Boundary semantic coverage | `src/nat_detection.rs` and `tests/nat_detection.rs` compute NAT-D SHA-1 hashes, collect multiple source hashes plus one destination hash from typed Notify payloads, and evaluate no-NAT/source-NAT/destination-NAT/both/unknown outcomes from caller-supplied observed UDP endpoints. |
| Hostile input safety | Initial regression coverage | `tests/malformed.rs` replays prefixes and malformed shapes through borrowed, owned, and iterator paths to assert structured errors without panic. |
| Fuzz target registration | Scheduled smoke coverage | `fuzz/fuzz_targets/decode_message.rs` and `roundtrip.rs` are registered in `.github/workflows/fuzz.yml` so the crate receives the same scheduled fuzz-list and smoke-run coverage as the other protocol crates. |
| `opc-protocol` integration | Implemented for scaffold | `Message` and `OwnedMessage` implement `BorrowDecode`, `OwnedDecode`, `Encode`, and `ToOwnedPdu`; errors use structured `opc-protocol` types and `SpecRef` references. |

## Payload-chain parser plan

The parser is intentionally staged so future work can add coverage without
changing the product boundary:

1. **Current scaffold:** parse the fixed header and generic payload chain, keep
   payload bodies raw, preserve unknown payload bytes, validate declared lengths,
   and stop at protected payload boundaries.
2. **Typed cleartext payload bodies:** continue adding spec-authored fixtures
   and typed views for remaining bodies such as KE, Nonce, Vendor ID,
   CERT/CERTREQ, and fragmentation-related payload shapes as each body is
   claimed. Each addition must include octet-level fixture comments and
   byte-exact decode -> encode tests.
3. **Protected payload opening/sealing boundary:** use caller-supplied
   `CryptoProvider` implementations or the SDK's SA_INIT AES-GCM `SK`
   open/seal helpers to authenticate/decrypt or encrypt/authenticate protected
   payloads, strip/add padding, and then feed cleartext bytes back into the
   generic payload-chain parser. The SDK crate must not own IKE SA state, choose
   peer policy, choose retransmission behavior, run EAP-AKA, install Child SAs,
   or enforce 3GPP profile policy.
4. **Fragmentation framing:** add RFC 7383 `SKF` fragment-number/total-fragments
   structural checks and fixtures before claiming fragmentation conformance.
5. **Fuzz/corpus expansion:** promote the current fuzz target and malformed
   regression seeds into a provenance-labeled corpus once cleartext body typed
   views are added.

## Explicitly out of scope

- IKE SA state machines, retransmission timers, cookie policy, peer policy,
  NAT traversal policy beyond NAT-T datagram classification and NAT-D semantic
  evaluation, or message correlation beyond structural Message ID parsing.
- EAP-AKA, 3GPP ePDG profile enforcement, subscriber/session lifecycle, Child SA
  installation, XFRM/IPsec programming, or key-management policy.
- Cryptographic algorithms beyond the supported SA_INIT AES-GCM-16 `SK`
  opener, `SKF` decryption/reassembly, null-crypto defaults, or caller key
  lifecycle policy.
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
