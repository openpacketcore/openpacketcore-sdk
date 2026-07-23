# opc-proto-ikev2 conformance boundary

This document defines the current conformance boundary for the experimental
`opc-proto-ikev2` crate. Its typed IKE-SA profile, KDF, proposal-selection, and
protected-payload rows are executable mechanisms rather than structural codec
claims. The crate is not a complete IKEv2 state machine and does not make an
ePDG product-readiness claim.

## Claimed coverage

| Area | Status | Evidence |
| --- | --- | --- |
| Fixed IKE header (`RFC 7296` §3.1) | Experimental structural and receiver-profile coverage | `src/header.rs`; `tests/header.rs` decodes and raw-preserving re-encodes hand-authored IKEv2 headers, rejects bad major versions, short lengths, and truncation, accepts higher minor versions and receiver-ignored reserved flags, and diagnoses both through the opt-in sender-canonical profile. |
| Generic payload header and chain (`RFC 7296` §2.5, §3.2) | Experimental structural and receiver-profile coverage for unencrypted payloads | `src/payload.rs`; `tests/payload_chain.rs` walks a hand-authored SA -> Nonce chain, validates length fields, count limits, truncation, and byte-exact raw re-encode through `Message`. Network receive accepts and raw-preserves receiver-ignored reserved bits and the Critical bit on understood payloads; the sender-canonical profile diagnoses both. `tests/unknown_critical_rejection.rs` proves that a fully framed unknown critical payload fails closed while retaining only its exact type and bounded payload-region offset through the same iterator, including first/middle/final and maximum-count positions. Invalid or truncated framing and bounds failures never become typed unknown-critical outcomes. |
| IKE_SA_INIT error Notify responses (`RFC 7296` §1.2, §2.5, §2.6, §2.7, §2.21.1, §3.10.1) | Bounded request/reply wire-mechanism coverage | `src/sa_init.rs` and `tests/sa_init_error_notify.rs` build a single notify-only response with the non-zero request initiator SPI, zero responder SPI, Message ID zero, and canonical responder flags. The allowlist contains only IKE-SA-shaped `UNSUPPORTED_CRITICAL_PAYLOAD` with an exact one-octet offending payload type, `NO_PROPOSAL_CHOSEN` with empty data, and `INVALID_KE_PAYLOAD` with an exact non-zero two-octet big-endian accepted group. Dedicated helpers make the unsupported-payload and invalid-KE notification-data lengths unrepresentable by callers. `Message::decode_with_rejection` and the additive UDP/500/UDP/4500 inspection sidecar retain a redacted unknown-critical message fact while the original classifier preserves its public enum shape, but only an exact no-tail initial request can produce the private-header reply wrapper. Mixed-invalid rejection precedence is explicit: malformed offender framing remains malformed and bytes beyond the declared IKE boundary win as trailing, so neither yields the sidecar. Responses, malformed/truncated chains, trailing bytes, and exceeded bounds remain non-reply-capable. Independent first/middle/final fixtures compose into exact Notify type 1 bytes; response-loop and diagnostic-redaction negatives are covered by `tests/unknown_critical_rejection.rs`. `INVALID_SYNTAX` is rejected because RFC 7296 permits it only in a cryptographically validated encrypted packet. The caller retains source validation, rate limiting, retransmission behavior, and all anti-amplification policy. |
| IKE_SA_INIT KE receive fields (`RFC 7296` §3.4) | Experimental typed receiver-profile coverage | `src/sa_init.rs` and `tests/receiver_ignored_fields.rs` retain DH-group and key-data structural validation while accepting the two receiver-ignored KE reserved octets. The opt-in sender-canonical profile diagnoses non-zero values, and typed response builders emit zero. |
| IKE-SA crypto profile and KDF (`RFC 7296` §2.13, §2.14, §2.17, §2.18; `RFC 2404`; `RFC 4868`; `RFC 6989`) | Typed algorithm and derivation coverage | `src/sa_init_crypto.rs` preserves PRF, DH, encryption/key size, and optional typed integrity in an immutable validated profile. It supports PRF-HMAC-SHA1/SHA2-256/384/512, AES-GCM-16 profile key material, and AES-CBC-128/192/256 with AUTH-HMAC-SHA1-96 or AUTH-HMAC-SHA2-256-128/384-192/512-256 key material. MODP-768/1024/2048 public values and shared secrets use exact 96/128/256-octet widths; peer public values must satisfy `1 < r < p-1`, with malformed width and invalid value reported distinctly. ECP-256/384/521 behavior remains unchanged. Transform selection is by type rather than wire order; duplicate, missing, unknown, and AEAD/integrity-contradictory sets fail closed. Initial IKE-SA, Child-SA PFS, restore, PPK post-processing, and IKE-SA rekey derivation are covered; rekey uses the old PRF for `SKEYSEED`, the new PRF for the new seven-key expansion, and accepts only the selected group's fixed-width DH shared secret (DH1/2/14 96/128/256 octets; DH19/20/21 32/48/66 octets), reporting mismatches through the pre-existing redaction-safe invalid-key-length contract. RFC 2202/RFC 2404 SHA1 vectors, RFC 4231/RFC 4868 SHA2 vectors, independently reproduced MODP vectors, and synthetic initial/rekey/restore/Child round trips provide evidence. The SHA1 and MODP 1/2 algorithms are explicit compatibility only and are never inserted into caller policy. Protected-payload algorithm coverage is claimed separately below. |
| Process-wide IKEv2 module admission and routing (#334 slice 3) | Fail-closed executable-provider boundary | `src/crypto_module.rs` admits exactly one `Arc<dyn IkeCryptoModule>` only after a current capability report satisfies explicit policy and every configured profile, NAT hash, CERTREQ authority hash, and directional signature requirement passes algorithm preflight. NAT-D and CERTREQ are distinct requirements even though both use admitted SHA-1. The immutable slot has no production or `testkit` fallback. Every operation rechecks the same object's identity, validation declaration, the full policy-granted capability set (including non-IKE supporting requirements), live advertisement/readiness, and directional algorithm support; module-owned entropy supplies production CBC IVs, and opaque DH/signing handles are gated again at use. Successful hash, PRF/PRF+, integrity, AEAD/CBC, and DH outputs are rejected with the stable `InvalidOutput` classification unless their algorithm-derived widths match exactly; DH handles are also checked for selected group and public-value shape at creation and reuse. `tests/crypto_module_admission.rs` uses one process-isolated counting module to prove missing policy, unsupported algorithms, and changing evidence do not poison the unset slot; all hash/PRF/integrity/encryption/entropy/DH/signature paths reach the admitted object; deliberately malformed successful outputs never reach protocol consumers; withdrawal of both IKE and policy-only capabilities prevents provider invocation; and previously created handles cannot execute after withdrawal. The process-isolated CERTREQ admission tests prove NAT-D-only and CERTREQ-only requirements cannot authorize each other. `tests/rsa_verification_admission.rs` proves a default-feature build admits successful RSA peer verification while rejecting RSA private signing. The bundled software module declares `NotValidated` and makes no certification claim. TLS and `opc-key` custody remain later #334 slices. |
| Authenticated-only ESP Child-SA profile and KEYMAT (`RFC 7296` §2.17, §3.3.2; `RFC 8221` §5-§6) | Typed algorithm, negotiation, restore, and Linux datapath coverage | `Ikev2EncryptionAlgorithm::Null` preserves ENCR_NULL transform 11 with no Key Length attribute and zero encryption/salt KEYMAT. `Ikev2ChildSaCryptoProfile::new_authenticated_only` and `from_transform_ids` require a supported separate integrity transform; NULL+AUTH_NONE, NULL with Key Length, AEAD+INTEG, and ENCR_NULL as an IKE-SA protected-payload algorithm fail closed. `tests/encr_null_child_sa.rs` decodes a hand-authored ESP proposal, retains the exact transform through selection/response construction, and covers malformed combinations. `src/sa_init_crypto.rs` checks an independently generated RFC 7296/OpenSSL PRF+ vector and exact transform-ID restore. The optional `opc-ipsec-xfrm` mapper keeps protocol encryption KEYMAT empty while emitting Linux's required zero-key `ecb(cipher_null)` adapter attribute plus HMAC auth; encoder tests reject fabricated NULL key bytes and raw ESP auth without that canonical attribute. Its privileged namespace test proves bidirectional packet delivery and tamper rejection on the real kernel. No SDK policy enables or prefers ENCR_NULL. |
| IKE_SA_INIT proposal selection (`RFC 7296` §2.7, §3.3.2, §3.3.5, §3.3.6; `RFC 5282` §8) | Product-neutral executable-suite selection | `src/sa_init_negotiation.rs` selects against an ordered set of already-executable typed profiles. Same-type transforms are OR alternatives, different types are AND requirements, and wire order is irrelevant. The selected transform and every attribute are copied exactly into a single response-ready proposal. Unknown transform types make only their proposal unacceptable; unknown attributes make only their transform unusable. Exact duplicate transforms, duplicate attributes, invalid IKE proposal SPIs/numbers, missing types, KE/DH mismatch, and invalid KE public-value length fail closed with stable typed codes. `NoAcceptableProposal` maps cleanly to `NO_PROPOSAL_CHOSEN`; a supported offered group with a different KE has a distinct mismatch result for `INVALID_KE_PAYLOAD`. `tests/sa_init_negotiation.rs` independently audits a literal synthetic ENCR→INTEG→PRF→DH fixture and proves alternate order/alternatives, duplicate rejection, and that SHA1/MODP compatibility suites remain unacceptable until the caller explicitly places them in policy. |
| IKE-SA rekey `CREATE_CHILD_SA` (`RFC 7296` §1.3.2, §2.5, §2.18, §3.3, §3.10.1, §3.12) | Strict responder opened-payload boundary | `src/ike_sa_rekey.rs` classifies an authenticated/opened request with exact `SA, Ni, KEi` cardinality in any wire order. Proposal numbering, Protocol ID IKE, and non-zero eight-octet initiator SPIs are validated; every offered `DH=NONE` is prohibited, the request KE group must occur in at least one proposal, and executable selection enforces the selected proposal's exact KE group/length. Vendor IDs are retained. The explicit-context decoder drops unrecognized Notify and unknown non-critical payloads only under `Drop`; `Preserve` and `Reject` both retain them because RFC 7296 mandates ignoring these classes. Unknown critical payloads fail closed. ESP/AH, malformed/zero SPIs, `REKEY_SA`, TSi/TSr, other semantically invalid known payloads, and missing/duplicate required payloads fail closed with redaction-safe stable codes. `negotiate_ike_sa_rekey` reuses the executable SA_INIT policy while preserving the selected initiator SPI and produces a profile accepted directly by the existing rekey KDF. The response builder checks its caller-allocated responder SPI plus exact KEr group/length and emits immutable bytes in only `SA, Nr, KEr` order. `tests/ike_sa_rekey.rs` supplies byte-exact specification-authored AEAD and AES-CBC/HMAC request/response vectors independent of the production encoders, plus the complete negative shape and forward-compatibility matrices, including mandatory-ignore behavior under every unknown-IE policy. SPI allocation, collision/simultaneous-rekey policy, DH generation, `SK` open/seal, retransmission caching, installation, and old-SA deletion remain product-owned. |
| Unknown payload preservation | Experimental structural coverage | Unknown non-critical payloads remain raw-preserved; unknown critical payloads fail closed by default as required by RFC 7296 §2.2. |
| Protected payload boundary (`SK`, `SKF`) | Boundary plus AES-GCM and AES-CBC/HMAC open/seal | `src/crypto.rs` and `tests/payload_chain.rs` expose `ProtectedPayloadContext` and the caller-owned `CryptoProvider`; the generic trait is not process-module admission evidence because it cannot bind an arbitrary implementation's identity. Validated deployments delegate to the module-routed `Ikev2SaInitProtectedPayloadProvider` or an identity-bound admitted adapter; direct caller crypto is outside the SDK admission claim. The codec classifies both `SK` and `SKF`, treats protected bodies as opaque, and never parses ciphertext as cleartext. Provider errors pass through by value for local typed diagnostics while the outer provider-rejection classification stays uniform for peer-visible policy. `src/protected_payload_crypto.rs` and `tests/protected_payload_crypto.rs`/`tests/protected_payload_encrypt_then_mac.rs` provide RFC 5282 AES-GCM-16 and RFC 7296 AES-CBC with AUTH-HMAC-SHA1-96 or AUTH-HMAC-SHA2-256-128/384-192/512-256 through the admitted concrete provider. CBC verifies the truncated ICV in constant time before decrypting, validates authenticated padding, and obtains fresh production IV entropy from the admitted module. The SHA1 compatibility test covers round trip and uniform tamper rejection. `tests/sa_init_negotiation.rs` decodes a literal capture-shaped SA_INIT, selects AES-CBC-256/PRF-SHA2-512/INTEG-SHA2-512-256/DH14, generates responder DH material, derives all seven keys, builds and independently decodes the SA_INIT response, then opens/seals bidirectional protected IKE_AUTH. Header/IV/ciphertext/ICV corruption, wrong-direction keys, malformed ciphertext, and authenticated invalid padding are rejected; cached response bytes replay unchanged. |
| IKEv2 encrypted fragmentation (`RFC 7383` `SKF`) | Experimental structural coverage | `src/fragmentation.rs` decodes/builds SKF fixed fields, enforces nonzero Fragment Number/Total Fragments, rejects number > total, enforces `Next Payload = 0` for non-first fragments, exposes the `IKEV2_FRAGMENTATION_SUPPORTED` notify type, and reassembles already-decrypted fragment cleartext with duplicate/missing/total/size checks. That module owns framing/reassembly only; `protected_payload_crypto` authenticates, opens, and seals the supported `SKF` profiles. The crate does not own retransmission or reassembly queues. |
| IKE_AUTH cleartext payload helpers | Experimental typed receiver-profile coverage for opened payload chains | `src/ike_auth.rs`, `src/sa_init.rs`, `tests/ike_auth_payloads.rs`, and `tests/receiver_ignored_fields.rs` decode/build IDi/IDr, AUTH, EAP, CP, SA, TSi/TSr, Notify, and Delete payloads with redaction-safe debug output and malformed-input checks. RFC-defined SA Proposal/Transform, ID/AUTH/TS/CP, and CP-attribute reserved fields are ignored on network receive; CP attribute types are exposed without the ignored high bit, sender-canonical typed decoders diagnose each field, and builders emit zero. |
| IKE_AUTH shared-key AUTH MIC | Experimental transcript-bound helper coverage | `src/ike_auth.rs`, `tests/ike_auth_payloads.rs`, and `tests/receiver_ignored_fields.rs` compute and verify RFC 7296 shared-key AUTH MICs from explicit SA_INIT transcript bytes, peer nonce, the exact received ID payload body (including receiver-ignored reserved octets), negotiated PRF, `SK_pi`/`SK_pr`, and caller-supplied EAP/AAA keying material. Every synthetic transcript octet is mutation-tested; no received ID canonicalization occurs before AUTH. The helper does not run EAP-AKA or choose AAA policy. |
| 3GPP DEVICE_IDENTITY Notify (`TS 24.302` §8.2.9.2) | Experimental typed mechanism coverage | `src/device_identity.rs` and `tests/device_identity.rs` distinguish empty-value IMEI/IMEISV requests from responses; require Notify type 41101, Protocol ID 0, empty SPI, and an exact two-octet combined length; validate fixed-size TBCD digits and the IMEI terminal `0xF` end mark; preserve every received digit in redaction-safe `Imei15`/`Imeisv` values; and accept the TS 23.003 spare-zero form without treating Luhn as a wire rule. It does not select when to request identity, correlate an exchange, authorize emergency service, or replace RFC 7296 method-2 AUTH. |
| 3GPP AUTHORIZATION_REJECTED Notify (`TS 24.302` §7.4.1.2, §8.1.2.2; `RFC 7296` §3.10) | Typed private-error wire mechanism | `src/notify.rs`, `src/sa_init.rs`, and `tests/authorization_rejected_notify.rs` expose private error 9003 and construct its exact Protocol-ID-zero/empty-SPI/empty-data sender body. Receive recognition requires type 9003, empty SPI, and empty data while ignoring Protocol ID when SPI Size is zero as RFC 7296 mandates. Literal canonical `[00 00 23 2b]`, tolerated `[03 00 23 2b]`, and negative type/SPI/data evidence are covered without exposing notification bytes in diagnostics. AAA-result interpretation, IKE_AUTH exchange assembly/protection, ePDG authentication, provisioning UI, and authorization policy remain product-owned. |
| IKE_AUTH CERT/CERTREQ payloads (`RFC 7296` §3.6, §3.7) | Experimental typed coverage | `src/ike_auth.rs` and `tests/ike_auth_certificate.rs` decode/build CERT and CERTREQ payload bodies with opaque certificate bytes, fail closed on truncated bodies and zero encodings, and keep certificate bytes out of debug output. `src/certreq.rs` additionally validates one exact bounded DER `SubjectPublicKeyInfo` with no trailing bytes and hashes it through the separately required admitted IKE SHA-1 operation into a redaction-safe 20-octet authority identifier. KAT-shaped and adversarial tests cover missing installation, requirement separation, evidence/support withdrawal, provider failure, malformed output, and redaction. Certificate parsing, trust-anchor selection, and chain policy remain product-owned. |
| RFC 7427 signature-hash negotiation and IKE_AUTH signature AUTH (`RFC 7296` §2.15 method 1; `RFC 7427` §3-§4 method 14) | Bounded fail-closed typed mechanism coverage | `src/signature_hash.rs`, `src/ike_auth_signature.rs`, `tests/signature_hash_algorithms.rs`, `tests/signature_hash_admission.rs`, and `tests/ike_auth_signature.rs` encode/decode `SIGNATURE_HASH_ALGORITHMS` (16431), retain exact ordered standardized/unassigned/private-use identifiers, enforce a 64-identifier resource bound, and reject reserved zero, malformed length/shape, empty, duplicate, omitted, unsupported-only, uncorrelated, and trailing states. The boundary decodes both complete correlated SA_INIT messages and produces two independent sets as RFC 7427 requires: peer-offer ∩ admitted local signing support, and exact local offer ∩ admitted local verification support. No common hash between directions is required. Distinct non-copyable signing and verification authorities bind the applicable set to both exact SA_INIT messages and the expected AUTH peer. Every method-14 operation consumes a one-operation authorization minted only after the caller presents that same request/response pair; a presented stale pair, opposite-message substitution, and wrong-direction use fail before transcript PRF or signature execution. Local offer construction and exact-wire negotiation both preflight the installed crypto module's immutable algorithm admission. The helpers sign and verify RFC 7296 signed octets with RSASSA-PKCS1-v1_5 SHA-256 (methods 1 and 14) and DER-encoded ECDSA P-256/P-384 (method 14) against a caller-supplied pinned SPKI or caller-trusted certificate SubjectPublicKeyInfo. SPKI and certificate constructors require one exact DER value and reject trailing bytes with stable redaction-safe errors. The product must retain each authority, exact exchange, and key material as one IKE-SA state because the SDK cannot infer an external application-session association from separately supplied byte slices and key material. No certificate-chain, validity-period, name, or key-usage validation is performed; the product owns certificate trust and transport/retransmission of the exact SA_INIT bytes. RSA signing is compiled only with the opt-in `rsa-signing` feature; RSA verification is always available. |
| EAP_ONLY_AUTHENTICATION notify (`RFC 5998` §3) | Fail-closed typed structural coverage | `src/notify.rs`, `src/ike_auth.rs`, `tests/eap_only_authentication.rs`, and `tests/ike_auth_certificate.rs` require type 16417, Protocol ID zero, SPI Size zero, empty SPI bytes, and empty notification data. A public per-occurrence classifier distinguishes unrelated, canonical, and typed malformed values while preserving the original lossless Notify view. The IKE_AUTH aggregate distinguishes absence from exactly one valid signal and rejects one malformed or every duplicate combination; duplicate evidence retains canonical/malformed counts and the first structural reason without packet data. Both valid/malformed wire orders, inconsistent public views, stable redacted diagnostics, and the exact four-octet canonical builder are covered. Choosing EAP-only authentication and verifying that the negotiated EAP method is mutually authenticating, key-generating, and resistant to dictionary attacks remain caller policy. |
| P_CSCF_RESELECTION_SUPPORT notify (`TS 24.302` §7.2.1, §7.4.1.1, §8.2.9.4) | Fail-closed typed structural coverage | `src/notify.rs`, `src/sa_init.rs`, and `tests/pcscf_reselection_support.rs` expose private status type 41304, construct its exact `[00 00 a1 58]` body, and classify one decoded Notify without consuming its lossless raw view. The typed boundary requires Protocol ID zero, SPI Size zero, empty SPI bytes, and empty notification data. Wrong protocol, decoded nonzero SPI size, inconsistent public SPI views, and nonempty data fail with stable payload-free errors; unrelated Notify values remain distinct. Relaying the authenticated UE capability into a PCO or APCO Create Session request remains caller policy. |
| Child SA negotiation helpers | Product-neutral selection intent only | `src/ike_auth.rs` and `tests/ike_auth_payloads.rs` select a proposal and traffic selectors against caller-supplied protocol/transform/selector policy and build response SA/TS payload entries once the product supplies a responder SPI. The helper does not allocate SPIs, own Child SA lifecycle, install XFRM state, or decide product traffic readiness. |
| 3GPP multiple-bearer Notify values (`TS 24.302` R17 §8.1.2.2, §8.2.9.9-§8.2.9.14) | Typed wire-mechanism coverage | `src/dedicated_bearer.rs` decodes/builds `IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY` (42011), `EPS_QOS` (42014), `EXTENDED_EPS_QOS` (42015), `TFT` (42017), `MODIFIED_BEARER` (42020), `APN_AMBR` (42094), `EXTENDED_APN_AMBR` (42095), and private TFT/packet-filter errors 8241/8242/8244/8245. `src/dedicated_bearer/qos.rs` maps neutral integer-kbps GBR/non-GBR and APN-AMBR inputs onto the TS 24.301 normal/extended grids with explicit `Exact` or documented ceiling quantization, returns represented rates, checks standardized versus operator-specific QCI resource types and GBR relationships, shares the required Extended EPS QoS unit across each pair, and emits zero companion multipliers at the 10 Gbps and 65,280 Mbps extension thresholds. Strict receive decode normalizes the TS 24.301 APN-AMBR compact aliases (extended 251-255 to 250; extended-2 255 to zero), Extended EPS QoS unit aliases (zero to one; values above 21 to 21), and Extended APN-AMBR unit aliases (zero through two to three; values above 21 to 21). Typed Notify/exchange builders emit only canonical values and reject aliases supplied through raw constructors. Network-reserved base code 0, QCI resource shape, lower-tier saturation, GBR ordering, threshold use, and compact sentinels still fail closed. Boundary, alias-normalization, grid-gap, shared-unit, forged-value, and `u16` rollover tests define the evidence. TFT delegates to the shared `opc-proto-tft` TS 24.008 value codec. Debug output omits SPI and unrecognized bytes. |
| New dedicated-bearer Child SA (`TS 24.302` R17 §7.2.7, §7.4.6.3; `RFC 7296` §1.3, §2.8, §3.3) | Strict opened-payload boundary | `src/dedicated_bearer/exchange.rs` builds/decodes a non-rekey `CREATE_CHILD_SA` payload chain with SA, Nonce, optional KE, TSi, TSr, EPS QoS, TFT, and optional extended QoS/AMBR. It rejects `REKEY_SA`, duplicate or missing payloads, non-ESP/zero-or-wrong-sized SPIs, PRF/unknown ESP transform types, exact duplicate transforms/attributes, unsupported algorithms, mixed AEAD/non-AEAD offers, inconsistent DH/KE, and create TFTs without an uplink-applicable filter. Same-type request alternatives remain valid. Selected responses contain exactly one ENCR, optional single DH/ESN, and INTEG exactly when the selected supported encryption is non-AEAD; omitted ESN means `NO_ESN`. Response correlation verifies the selected algorithms/attributes, optional `NONE` semantics, KE group, IKE header, and selector narrowing. Existing Child-SA key derivation consumes the decoded nonces. |
| Dedicated-bearer modification/deletion (`TS 24.302` R17 §7.4.6.3; `RFC 7296` §1.4.1) | Strict opened-payload boundary | `src/dedicated_bearer/exchange.rs` builds/decodes `INFORMATIONAL` modification requests containing a typed four-octet ESP `MODIFIED_BEARER` SPI and optional QoS/TFT/AMBR updates. A normal deletion request names the local/ePDG inbound ESP SPI and its typed response must name exactly one paired peer/UE inbound ESP SPI; correlation checks both against application-supplied SA-pair state. An empty Delete response is accepted only through the explicit simultaneous-delete expectation required when crossed Delete requests already removed the paired SAs. Wrong protocol, SPI size/count, duplicate Delete payloads, and mismatched expected SPIs fail closed. |
| P-CSCF restoration `INFORMATIONAL` (`TS 23.380` §5.6.5.2; `TS 24.302` §7.2.3.2, §7.4.2.1; `RFC 7296` §3.2, §3.10.1, §3.15; `RFC 7651` §3-§4) | Strict opened-payload boundary | `src/pcscf_restoration.rs` owns configuration types 1/2 and P-CSCF attribute types 20/21 behind a typed, redaction-safe IPv4/IPv6 address API. A non-empty request accepts at most 128 entries, preserves every PGW-provided address and its exact order (including repeats), and emits each exact four- or sixteen-octet value in `CFG_REQUEST`; the bound is SDK resource policy, not a 3GPP cardinality claim. A single `CFG_REPLY` is accepted only when it carries one empty, unique, recognized attribute for every requested family, matching TS 24.302's distinct acknowledgement shape. Unsupported Configuration attributes, Vendor IDs, unfamiliar status Notify payloads, and unknown non-critical payloads are retained; unknown critical payloads, error-range Notify payloads, semantically invalid known payloads, and malformed extensions fail closed. Correlation requires that family set plus matching non-zero IKE SPIs, `INFORMATIONAL` exchange type, Message ID, response direction, and opposite Initiator flag. `tests/pcscf_restoration.rs` supplies literal valued same-family and dual-stack request bytes, repeat/order preservation, network-receiver reserved-field evidence, forward-compatible interleaved extensions, all family combinations, bounds/redaction checks, and negative absent/duplicate/valued-reply/wrong-type/truncated/critical/error/correlation cases. IKE SA protection, APCO interpretation, address selection, retransmission, and product session policy remain caller-owned. |
| NAT detection Notify semantics (`RFC 7296` §2.23) | Boundary semantic coverage | `src/nat_detection.rs` and `tests/nat_detection.rs` compute NAT-D SHA-1 hashes, collect multiple source hashes plus one destination hash from typed Notify payloads, and evaluate no-NAT/source-NAT/destination-NAT/both/unknown outcomes from caller-supplied observed UDP endpoints. |
| Hostile input safety | Initial regression coverage | `tests/malformed.rs` replays prefixes and malformed shapes through borrowed, owned, and iterator paths to assert structured errors without panic. |
| Fuzz target registration | Scheduled smoke coverage | `fuzz/fuzz_targets/decode_message.rs`, `roundtrip.rs`, and `dedicated_bearer.rs` cover the message codec, raw-preserving encode, bounded RFC 7427 signature-hash Notify decoder, typed 3GPP Notify decoder, and every dedicated-bearer opened-payload decoder. The crate is registered in `.github/workflows/fuzz.yml` for scheduled fuzz-list and smoke-run coverage. |
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
3. **Protected payload opening/sealing boundary:** use an identity-bound
   caller-supplied `CryptoProvider` adapter or the SDK's admitted SA_INIT AES-GCM and
   AES-CBC/HMAC `SK`/`SKF` open/seal helpers to authenticate/decrypt or
   encrypt/authenticate protected payloads, strip/add padding, and then feed
   cleartext bytes back into the generic payload-chain parser. Arbitrary direct
   caller crypto is outside the SDK process-module admission evidence. The SDK crate must not own IKE SA state, choose
   peer policy, choose retransmission behavior, run EAP-AKA, install Child SAs,
   or enforce 3GPP profile policy.
4. **Fragmentation framing:** RFC 7383 `SKF` structural checks now exist for
   fragment headers and already-decrypted cleartext reassembly. The concrete
   SA_INIT-key provider applies the selected AES-GCM or AES-CBC/HMAC profile
   to `SKF`; product-owned retransmission/reassembly queue policy remains out
   of scope.
5. **Fuzz/corpus expansion:** promote the current fuzz target and malformed
   regression seeds into a provenance-labeled corpus once cleartext body typed
   views are added.

## Explicitly out of scope

- IKE SA state machines, retransmission timers, exact-response caches, cookie policy, peer policy,
  NAT traversal policy beyond NAT-T datagram classification and NAT-D semantic
  evaluation, or message correlation outside the dedicated-bearer and P-CSCF
  restoration response validators.
- EAP-AKA, 3GPP ePDG profile enforcement, emergency authorization policy,
  subscriber/session lifecycle, Child SA lifecycle management, XFRM/IPsec
  programming, or key-management policy.
- Cryptographic algorithms beyond the supported SA_INIT AES-GCM-16 and
  AES-CBC/HMAC `SK`/`SKF` profiles, deployment defaults (including default
  enablement or preference of Child-SA ENCR_NULL), retransmission queues, or
  caller key lifecycle policy.
- Claims of interoperability with strongSwan, libreswan, carrier ePDG systems,
  or any production deployment.

## Canonicalization policy

`Ikev2ValidationProfile::NetworkReceive` is the standards-conforming default.
It ignores higher IKEv2 minor versions, the Version/Critical bits where RFC
7296 requires receiver ignore behavior, and reserved fields in the fixed and
generic headers, SA Proposal/Transform structures, ID, AUTH, KE, TS, CP, and
CP-attribute bodies. This is separate from `DecodeContext::validation_level`:
strict network input retains
all length, count, chaining, major-version, typed-field, unknown-critical,
integrity, and authentication checks. Received fixed/generic headers retain
raw values, and the typed ID view retains its three reserved octets for exact
AUTH transcript construction.

`Ikev2ValidationProfile::SenderCanonical` is an opt-in outbound-fixture test
profile. It diagnoses each of those non-canonical fields. Typed encoders emit
zero in every covered reserved field. Raw-preserving encode keeps the decoded
fixed-header minor version, flags, and payload-chain bytes. Canonical `Message`
encode recomputes the fixed-header Length field, emits IKE version 2.0, and
clears the fixed-header Version flag and reserved flag bits, but deliberately
carries caller-supplied raw payload-chain bytes exactly; callers constructing
raw outbound fixtures validate those bytes with the sender-canonical profile.

## Fixture provenance

The current tests use hand-authored structural byte arrays based on RFC 7296
§3.1 fixed-header and §3.2 generic payload layouts, with octet-level comments
on the conformance fixtures in `tests/header.rs` and `tests/payload_chain.rs`.
They are suitable for this scaffold's structural coverage only. They are not
independent-peer interoperability fixtures, and no source-product bytes are
counted as conformance evidence.

`tests/receiver_ignored_fields.rs` adds a fully synthetic combined IKE_AUTH
shape and individual header/generic/SA/ID/AUTH/KE/TS/CP vectors derived from
RFC 7296 §§2.5, 3.1-3.5, 3.8, 3.13, and 3.15. It contains no live peer
addresses, identities, SPIs, nonces, or key material. The negative matrix
retains major-version, hostile-length, malformed-chain, unknown-critical, and
AUTH-integrity failures and proves every authenticated transcript-octet
mutation fails verification.

`tests/sa_init_error_notify.rs` separately hand-authors complete 37-octet
`UNSUPPORTED_CRITICAL_PAYLOAD`, 36-octet `NO_PROPOSAL_CHOSEN`, and 38-octet
`INVALID_KE_PAYLOAD` response vectors. All use RFC 7296 §2.6 for a zero
responder SPI, §3.1 for the IKE header, §3.2 for generic-payload chaining, and
§3.10 for the Notify body. The first uses §2.5 and §3.10.1 for error type 1 and
one synthetic private-use offending payload-type octet; the second uses §2.7
and §3.10.1 for error type 14 with no notification data; the third uses §1.2,
§1.3, and §3.10.1 for error type 17 and the accepted Diffie-Hellman group as
exactly two big-endian octets. These are specification-derived wire vectors,
not independent-peer captures.

The SHA-1 primitive tests copy HMAC and 96-bit truncation values from RFC 2202
and RFC 2404, while the SHA-2 tests copy the published PRF and authenticator values from
[RFC 4868 §2.7](https://www.rfc-editor.org/rfc/rfc4868.html#section-2.7), which
in turn identifies the PRF cases sourced from RFC 4231. They cover SHA-256,
SHA-384, and SHA-512, including a SHA-512 key longer than its compression-block
size and the 256-bit integrity truncation. The RFC 7296 SHA1 PRF+ fixture and
the MODP group 1/2/14 fixed-exponent vectors were reproduced independently of
the SDK implementation. Fixed synthetic initial-IKE-SA,
mixed-PRF rekey, and Child-SA KEYMAT values were generated independently with
OpenSSL 3 HMAC operations and the RFC 7296 PRF+ equations. The complete
AES-CBC-256/HMAC-SHA2-512-256 message in
`tests/protected_payload_encrypt_then_mac.rs` was independently generated with
OpenSSL 3 AES-256-CBC and HMAC-SHA512; its literal final IKE and `SK` lengths
make incorrect MAC coverage fail. None of these values came from the handset
capture or from a second call into the SDK implementation.

`tests/sa_init_negotiation.rs` contains a literal, synthetic, redaction-safe
SA_INIT message with the observed protocol shape. Its addresses, SPIs, nonce,
DH public value, and notifications are authored test values. The test never
embeds or derives live subscriber or peer material.

`tests/ike_sa_rekey.rs` hand-authors complete opened `SA, Ni, KEi` and
`SA, Nr, KEr` chains for AES-GCM-16/PRF-SHA2-256/DH19 and
AES-CBC-256/HMAC-SHA2-512-256/PRF-SHA2-512/DH14. Their generic, Proposal,
Transform, Nonce, and KE lengths are literal specification-derived values and
the production response encoder is checked byte-for-byte against them. These
are redaction-safe synthetic vectors, not packet captures or independent-peer
interoperability evidence.

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

`tests/pcscf_restoration.rs` hand-authors the complete generic CP-header,
`CFG_REQUEST`, and valued RFC 7651 type-20/type-21 bytes for IPv4-only,
IPv6-only, and dual-stack request lists, including same-family reversal and
exact repeated entries. Synthetic `CFG_REPLY` fixtures cover the required empty
per-family acknowledgement, reversed valid attribute order, receiver-ignored
reserved fields, and interleaved unsupported Configuration attributes, Vendor
IDs, status Notify payloads, and unknown non-critical payloads. Missing,
duplicate, non-empty, wrong-type, malformed, truncated, oversized, unknown
critical, error-range Notify, and uncorrelated responses fail closed. All
addresses are documentation ranges or loopback values; no live address, SPI,
peer, subscriber, or capture material is present.

`tests/encr_null_child_sa.rs` hand-authors the RFC 7296 SA Proposal/Transform
bytes for ESP ENCR_NULL (11) plus AUTH-HMAC-SHA2-256-128 (12), including
negative NULL-only and prohibited Key Length forms. It also decodes the
dedicated-bearer fuzz seed as a complete synthetic `CREATE_CHILD_SA` request.
The directional integrity values are generated independently with OpenSSL 3
from the RFC 7296 PRF+ equations; no live SPI, nonce, key, address, or peer
capture is included.

`examples/dedicated_bearer_sdk_flow.rs` is the executable product-boundary
composition. It processes a triggered Create Bearer request exactly once,
passes the decoded canonical TFT and QoS into a non-rekey IKEv2 Child-SA
exchange, correlates both protocol responses, commits the GTP response for
exact replay, and then performs the corresponding Delete Bearer and IKEv2
Child-SA deletion flow. Admission, identifier allocation, key installation,
and dataplane programming remain explicit application responsibilities.
