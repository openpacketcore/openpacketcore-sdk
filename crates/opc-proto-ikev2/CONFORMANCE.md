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
| IKE_SA_INIT error Notify responses (`RFC 7296` §1.2, §2.6, §2.7, §2.21.1, §3.10.1) | Bounded wire-mechanism coverage | `src/sa_init.rs` and `tests/sa_init_error_notify.rs` build a single notify-only response with the non-zero request initiator SPI, zero responder SPI, Message ID zero, and canonical responder flags. The allowlist contains only IKE-SA-shaped `NO_PROPOSAL_CHOSEN` with empty data and `INVALID_KE_PAYLOAD` with an exact non-zero two-octet big-endian accepted group. Byte-exact and decode-roundtrip evidence covers both forms; malformed exchange/flag/SPI/Message ID, count, Notify Protocol ID/SPI, type, and data-length cases fail closed. `INVALID_SYNTAX` is rejected because RFC 7296 permits it only in a cryptographically validated encrypted packet. The caller retains source validation, rate limiting, retransmission behavior, and all anti-amplification policy. |
| IKE-SA crypto profile and KDF (`RFC 7296` §2.13, §2.14, §2.17, §2.18; `RFC 4868`) | Typed algorithm and derivation coverage | `src/sa_init_crypto.rs` preserves PRF, DH, encryption/key size, and optional typed integrity in an immutable validated profile. It supports PRF-HMAC-SHA2-256/384/512, AES-GCM-16 profile key material, and AES-CBC-128/192/256 with AUTH-HMAC-SHA2-256-128/384-192/512-256 key material. Transform selection is by type rather than wire order; duplicate, missing, unknown, and AEAD/integrity-contradictory sets fail closed. Initial IKE-SA, Child-SA, restore, PPK post-processing, and IKE-SA rekey derivation are covered; rekey uses the old PRF for `SKEYSEED` and the new PRF for the new seven-key expansion. RFC 4231/RFC 4868 HMAC-SHA2-512 vectors plus independently generated OpenSSL-based initial/rekey/Child KDF vectors provide non-round-trip evidence. Protected-payload algorithm coverage is claimed separately below. |
| IKE_SA_INIT proposal selection (`RFC 7296` §2.7, §3.3.2, §3.3.5, §3.3.6; `RFC 5282` §8) | Product-neutral executable-suite selection | `src/sa_init_negotiation.rs` selects against an ordered set of already-executable typed profiles. Same-type transforms are OR alternatives, different types are AND requirements, and wire order is irrelevant. The selected transform and every attribute are copied exactly into a single response-ready proposal. Unknown transform types make only their proposal unacceptable; unknown attributes make only their transform unusable. Exact duplicate transforms, duplicate attributes, invalid IKE proposal SPIs/numbers, missing types, KE/DH mismatch, and invalid KE public-value length fail closed with stable typed codes. `NoAcceptableProposal` maps cleanly to `NO_PROPOSAL_CHOSEN`; a supported offered group with a different KE has a distinct mismatch result for `INVALID_KE_PAYLOAD`. `tests/sa_init_negotiation.rs` independently audits a literal synthetic ENCR→INTEG→PRF→DH fixture and proves alternate order/alternatives, unsupported DH1, and duplicate rejection. |
| Unknown payload preservation | Experimental structural coverage | Unknown non-critical payloads remain raw-preserved; unknown critical payloads fail closed by default as required by RFC 7296 §2.2. |
| Protected payload boundary (`SK`, `SKF`) | Boundary plus AES-GCM and AES-CBC/SHA-2 open/seal | `src/crypto.rs` and `tests/payload_chain.rs` expose `ProtectedPayloadContext` and `CryptoProvider`; the codec classifies both `SK` and `SKF`, treats protected bodies as opaque, and never parses ciphertext as cleartext. `src/protected_payload_crypto.rs` and `tests/protected_payload_crypto.rs`/`tests/protected_payload_encrypt_then_mac.rs` provide caller-keyed RFC 5282 AES-GCM-16 and RFC 7296 AES-CBC with AUTH-HMAC-SHA2-256-128/384-192/512-256. CBC verifies the truncated ICV in constant time before decrypting, validates authenticated padding, and uses a fresh CSPRNG IV at the production sealing boundary. `tests/sa_init_negotiation.rs` decodes a literal capture-shaped SA_INIT, selects AES-CBC-256/PRF-SHA2-512/INTEG-SHA2-512-256/DH14, generates responder DH material, derives all seven keys, builds and independently decodes the SA_INIT response, then opens/seals bidirectional protected IKE_AUTH. Header/IV/ciphertext/ICV corruption, wrong-direction keys, malformed ciphertext, and authenticated invalid padding are rejected; cached response bytes replay unchanged. |
| IKEv2 encrypted fragmentation (`RFC 7383` `SKF`) | Experimental structural coverage | `src/fragmentation.rs` decodes/builds SKF fixed fields, enforces nonzero Fragment Number/Total Fragments, rejects number > total, enforces `Next Payload = 0` for non-first fragments, exposes the `IKEV2_FRAGMENTATION_SUPPORTED` notify type, and reassembles already-decrypted fragment cleartext with duplicate/missing/total/size checks. It does not decrypt SKF ciphertext or own retransmission/reassembly queues. |
| IKE_AUTH cleartext payload helpers | Experimental typed coverage for opened payload chains | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` decode/build IDi/IDr, AUTH, EAP, CP, SA, TSi/TSr, Notify, and Delete payloads from cleartext chains with redaction-safe debug output and malformed-input checks. |
| IKE_AUTH shared-key AUTH MIC | Experimental transcript-bound helper coverage | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` compute and verify RFC 7296 shared-key AUTH MICs from explicit SA_INIT transcript bytes, peer nonce, ID payload body, negotiated PRF, `SK_pi`/`SK_pr`, and caller-supplied EAP/AAA keying material. The helper does not run EAP-AKA or choose AAA policy. |
| 3GPP DEVICE_IDENTITY Notify (`TS 24.302` §8.2.9.2) | Experimental typed mechanism coverage | `src/device_identity.rs` and `tests/device_identity.rs` distinguish empty-value IMEI/IMEISV requests from responses; require Notify type 41101, Protocol ID 0, empty SPI, and an exact two-octet combined length; validate fixed-size TBCD digits and the IMEI terminal `0xF` end mark; preserve every received digit in redaction-safe `Imei15`/`Imeisv` values; and accept the TS 23.003 spare-zero form without treating Luhn as a wire rule. It does not select when to request identity, correlate an exchange, authorize emergency service, or replace RFC 7296 method-2 AUTH. |
| IKE_AUTH CERT/CERTREQ payloads (`RFC 7296` §3.6, §3.7) | Experimental typed coverage | `src/ike_auth.rs` and `tests/ike_auth_certificate.rs` decode/build CERT and CERTREQ payload bodies with opaque certificate bytes, fail closed on truncated bodies and zero encodings, and keep certificate bytes out of debug output. Certificate content is not interpreted by the payload codec. |
| IKE_AUTH signature AUTH (`RFC 7296` §2.15 method 1; `RFC 7427` method 14) | Experimental transcript-bound helper coverage | `src/ike_auth_signature.rs` and `tests/ike_auth_signature.rs` sign and verify the RFC 7296 signed octets with RSASSA-PKCS1-v1_5 SHA-256 (methods 1 and 14) and DER-encoded ECDSA P-256/P-384 (method 14), including RFC 7427 AlgorithmIdentifier framing, against a caller-supplied pinned SPKI or a caller-trusted certificate's SubjectPublicKeyInfo. No certificate-chain, validity-period, name, or key-usage validation is performed; the product layer owns certificate trust. RSA signing is compiled only with the opt-in `rsa-signing` feature, so default builds perform no RSA private-key operations and ECDSA responder certificates are the recommended deployment; RSA verification is always available. |
| EAP_ONLY_AUTHENTICATION notify (`RFC 5998`) | Experimental structural coverage | `src/notify.rs`, `src/ike_auth.rs`, and `tests/ike_auth_certificate.rs` decode the status notify from IKE_AUTH cleartext chains, expose a request accessor, and build the notify body. EAP-only policy decisions stay with the caller. |
| Child SA negotiation helpers | Product-neutral selection intent only | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` select a proposal and traffic selectors against caller-supplied protocol/transform/selector policy and build response SA/TS payload entries once the product supplies a responder SPI. The helper does not allocate SPIs, own Child SA lifecycle, install XFRM state, or decide product traffic readiness. |
| 3GPP multiple-bearer Notify values (`TS 24.302` R17 §8.1.2.2, §8.2.9.9-§8.2.9.14) | Typed wire-mechanism coverage | `src/dedicated_bearer.rs` decodes/builds `IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY` (42011), `EPS_QOS` (42014), `EXTENDED_EPS_QOS` (42015), `TFT` (42017), `MODIFIED_BEARER` (42020), `APN_AMBR` (42094), `EXTENDED_APN_AMBR` (42095), and private TFT/packet-filter errors 8241/8242/8244/8245. `src/dedicated_bearer/qos.rs` maps neutral integer-kbps GBR/non-GBR and APN-AMBR inputs onto the TS 24.301 normal/extended grids with explicit `Exact` or documented ceiling quantization, returns represented rates, checks standardized versus operator-specific QCI resource types and GBR relationships, shares the required Extended EPS QoS unit across each pair, and emits zero companion multipliers at the 10 Gbps and 65,280 Mbps extension thresholds. Strict receive decode normalizes the TS 24.301 APN-AMBR compact aliases (extended 251-255 to 250; extended-2 255 to zero), Extended EPS QoS unit aliases (zero to one; values above 21 to 21), and Extended APN-AMBR unit aliases (zero through two to three; values above 21 to 21). Typed Notify/exchange builders emit only canonical values and reject aliases supplied through raw constructors. Network-reserved base code 0, QCI resource shape, lower-tier saturation, GBR ordering, threshold use, and compact sentinels still fail closed. Boundary, alias-normalization, grid-gap, shared-unit, forged-value, and `u16` rollover tests define the evidence. TFT delegates to the shared `opc-proto-tft` TS 24.008 value codec. Debug output omits SPI and unrecognized bytes. |
| New dedicated-bearer Child SA (`TS 24.302` R17 §7.2.7, §7.4.6.3; `RFC 7296` §1.3, §2.8, §3.3) | Strict opened-payload boundary | `src/dedicated_bearer/exchange.rs` builds/decodes a non-rekey `CREATE_CHILD_SA` payload chain with SA, Nonce, optional KE, TSi, TSr, EPS QoS, TFT, and optional extended QoS/AMBR. It rejects `REKEY_SA`, duplicate or missing payloads, non-ESP/zero-or-wrong-sized SPIs, PRF/unknown ESP transform types, exact duplicate transforms/attributes, unsupported algorithms, mixed AEAD/non-AEAD offers, inconsistent DH/KE, and create TFTs without an uplink-applicable filter. Same-type request alternatives remain valid. Selected responses contain exactly one ENCR, optional single DH/ESN, and INTEG exactly when the selected supported encryption is non-AEAD; omitted ESN means `NO_ESN`. Response correlation verifies the selected algorithms/attributes, optional `NONE` semantics, KE group, IKE header, and selector narrowing. Existing Child-SA key derivation consumes the decoded nonces. |
| Dedicated-bearer modification/deletion (`TS 24.302` R17 §7.4.6.3; `RFC 7296` §1.4.1) | Strict opened-payload boundary | `src/dedicated_bearer/exchange.rs` builds/decodes `INFORMATIONAL` modification requests containing a typed four-octet ESP `MODIFIED_BEARER` SPI and optional QoS/TFT/AMBR updates. A normal deletion request names the local/ePDG inbound ESP SPI and its typed response must name exactly one paired peer/UE inbound ESP SPI; correlation checks both against application-supplied SA-pair state. An empty Delete response is accepted only through the explicit simultaneous-delete expectation required when crossed Delete requests already removed the paired SAs. Wrong protocol, SPI size/count, duplicate Delete payloads, and mismatched expected SPIs fail closed. |
| NAT detection Notify semantics (`RFC 7296` §2.23) | Boundary semantic coverage | `src/nat_detection.rs` and `tests/nat_detection.rs` compute NAT-D SHA-1 hashes, collect multiple source hashes plus one destination hash from typed Notify payloads, and evaluate no-NAT/source-NAT/destination-NAT/both/unknown outcomes from caller-supplied observed UDP endpoints. |
| Hostile input safety | Initial regression coverage | `tests/malformed.rs` replays prefixes and malformed shapes through borrowed, owned, and iterator paths to assert structured errors without panic. |
| Fuzz target registration | Scheduled smoke coverage | `fuzz/fuzz_targets/decode_message.rs`, `roundtrip.rs`, and `dedicated_bearer.rs` cover the message codec, raw-preserving encode, typed 3GPP Notify decoder, and every dedicated-bearer opened-payload decoder. The crate is registered in `.github/workflows/fuzz.yml` for scheduled fuzz-list and smoke-run coverage. |
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
   `CryptoProvider` implementations or the SDK's SA_INIT AES-GCM and
   AES-CBC/SHA-2 `SK`/`SKF` open/seal helpers to authenticate/decrypt or
   encrypt/authenticate protected payloads, strip/add padding, and then feed
   cleartext bytes back into the generic payload-chain parser. The SDK crate must not own IKE SA state, choose
   peer policy, choose retransmission behavior, run EAP-AKA, install Child SAs,
   or enforce 3GPP profile policy.
4. **Fragmentation framing:** RFC 7383 `SKF` structural checks now exist for
   fragment headers and already-decrypted cleartext reassembly. The concrete
   SA_INIT-key provider applies the selected AES-GCM or AES-CBC/SHA-2 profile
   to `SKF`; product-owned retransmission/reassembly queue policy remains out
   of scope.
5. **Fuzz/corpus expansion:** promote the current fuzz target and malformed
   regression seeds into a provenance-labeled corpus once cleartext body typed
   views are added.

## Explicitly out of scope

- IKE SA state machines, retransmission timers, exact-response caches, cookie policy, peer policy,
  NAT traversal policy beyond NAT-T datagram classification and NAT-D semantic
  evaluation, or message correlation outside the dedicated-bearer response
  validators.
- EAP-AKA, 3GPP ePDG profile enforcement, emergency authorization policy,
  subscriber/session lifecycle, Child SA lifecycle management, XFRM/IPsec
  programming, or key-management policy.
- Cryptographic algorithms beyond the supported SA_INIT AES-GCM-16 and
  AES-CBC/SHA-2 `SK`/`SKF` profiles, null-crypto defaults, retransmission
  queues, or caller key lifecycle policy.
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

`tests/sa_init_error_notify.rs` separately hand-authors complete 36-octet
`NO_PROPOSAL_CHOSEN` and 38-octet `INVALID_KE_PAYLOAD` response vectors. Both
use RFC 7296 §2.6 for a zero responder SPI, §3.1 for the IKE header, §3.2 for
generic-payload chaining, and §3.10 for the Notify body. The former uses §2.7
and §3.10.1 for error type 14 with no notification data; the latter uses
§1.2, §1.3, and §3.10.1 for error type 17 and the accepted Diffie-Hellman
group as exactly two big-endian octets. These are specification-derived wire
vectors, not independent-peer captures.

Future fixtures must follow ADR 0015: spec-authored or independently captured
bytes, octet-level comments, raw preservation for unknown payloads, negative
malformed cases, and clear separation between conformance, parity, and fuzz
corpus provenance.

`tests/dedicated_bearer.rs` contains specification-authored payload values from
TS 24.302 R17 §8.2.9.9-§8.2.9.14 and composes generic RFC 7296 payload builders
for complete opened `CREATE_CHILD_SA` and `INFORMATIONAL` chains. It proves the
exact Notify numbers and inner lengths, every typed Notify round trip, strict
negative cardinality/shape/correlation cases, supported ESP algorithm and
AEAD/INTEG relationship validation, exact duplicate rejection, ESN omission,
same-type offer alternatives, positive PFS and DH-NONE request/response
correlation, typed paired-SPI and crossed-request Delete responses, rejection of mixed success/error
response payloads, response selector narrowing, Child-SA key-derivation
compatibility, and byte identity between a canonical TS 24.008 TFT value
embedded in IKEv2 and the shared codec.
`tests/dedicated_bearer_cross_protocol.rs` additionally builds and
procedure-aware decodes a typed GTPv2-C Create Bearer Request, extracts the raw
nested Bearer TFT IE value, extracts the inner value from the typed IKEv2 TFT
Notify, and asserts literal byte identity. These vectors are
specification-derived rather than independent-peer captures.

`examples/dedicated_bearer_sdk_flow.rs` is the executable product-boundary
composition. It processes a triggered Create Bearer request exactly once,
passes the decoded canonical TFT and QoS into a non-rekey IKEv2 Child-SA
exchange, correlates both protocol responses, commits the GTP response for
exact replay, and then performs the corresponding Delete Bearer and IKEv2
Child-SA deletion flow. Admission, identifier allocation, key installation,
and dataplane programming remain explicit application responsibilities.
