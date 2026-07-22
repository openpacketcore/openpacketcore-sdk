# opc-proto-ikev2

Transport-neutral IKEv2 mechanisms for OpenPacketCore untrusted-access work.

## Purpose

`opc-proto-ikev2` covers transport-neutral IKEv2 wire mechanisms that are safe
to expose as SDK primitives today: header decode/encode, unencrypted payload
walking, protected-payload boundaries, selected SA_INIT and IKE_AUTH helpers,
NAT detection, NAT-T datagram classification, and product-neutral Child SA
negotiation intent. It includes a strict responder boundary for opened IKE-SA
rekey `CREATE_CHILD_SA` requests and exact successful responses. It also
provides strict opened-payload primitives for the TS 24.302 multiple-bearer
profile: typed QoS/TFT/AMBR notifications, new non-rekey dedicated-bearer
Child SA establishment, bearer modification, and bearer deletion. It also
provides a typed TS 24.302 P-CSCF restoration `INFORMATIONAL` boundary for
forwarding a bounded valued IPv4/IPv6 address list and accepting only the
required empty per-family `CFG_REPLY` echoes.

It does not implement an IKE SA state machine, EAP-AKA, retransmission policy,
cookie policy, Child SA lifecycle, XFRM/IPsec programming, bearer admission or
allocation policy, carrier acceptance evidence, or a production ePDG
control-plane stack.

## API Shape

- `Message<'a>` and `OwnedMessage` provide borrowed and owned IKEv2 messages.
- `header` exposes `Header`, `HeaderFlags`, `decode_header`, and
  `encode_header`.
- `payload` exposes `PayloadChain`, `RawPayload`, `RawPayloadIterator`,
  `PayloadType`, and ordinary or detailed payload-chain validation. The
  detailed boundary retains only an unknown critical payload's exact type and
  bounded chain offset; it never retains the payload body.
- `validation` exposes `Ikev2ValidationProfile`, separating conformant network
  receive behavior from opt-in sender-canonical fixture validation.
- `crypto` defines the caller-supplied `CryptoProvider` boundary and protected
  payload open result types. An arbitrary implementation is not covered by
  process-module admission; validated deployments use the module-routed
  `Ikev2SaInitProtectedPayloadProvider` or an adapter whose identity is bound
  to their admitted module. Direct caller crypto invalidates SDK admission
  claims rather than gaining them from a slot-presence check.
- `certreq` validates one bounded, exact DER X.509 `SubjectPublicKeyInfo` and
  computes its RFC 7296 section 3.7 Certification Authority identifier through
  the admitted IKE hash operation. The result has redaction-safe `Debug`.
- `sa_init`, `sa_init_crypto`, and `sa_init_negotiation` provide typed
  SA/KE/Nonce/Notify helpers, SA_INIT response builders, product-neutral
  responder proposal selection, Diffie-Hellman group/profile types, and
  IKE/Child SA key-material derivation. IKE-SA profiles preserve the complete negotiated
  PRF, DH, encryption/key-size, and optional integrity suite; invalid AEAD plus
  integrity or CBC without integrity combinations cannot be constructed.
  PRF-HMAC-SHA2-256/384/512 are supported for initial IKE-SA derivation,
  IKE-SA rekey (including distinct old/new PRFs), Child-SA KEYMAT, restore, and
  AUTH calculations. Child-SA profiles additionally support ENCR_NULL (11)
  with a mandatory separate SHA-2 integrity transform and exactly zero
  encryption/salt KEYMAT octets. The notify-only error builder is deliberately bounded to
  one IKE-SA-shaped `UNSUPPORTED_CRITICAL_PAYLOAD`, `NO_PROPOSAL_CHOSEN`, or
  `INVALID_KE_PAYLOAD`. Typed convenience builders write the offending payload
  type as exactly one octet or the accepted non-zero group as exactly two
  big-endian octets. These failures are mutually exclusive, so the builder
  rejects a multi-Notify response rather than emitting ambiguity.
- `protected_payload_crypto` provides caller-keyed AES-GCM-16 and
  AES-CBC/SHA-2 encrypt-then-MAC `SK`/`SKF` open/seal helpers for
  already-derived SA_INIT key material. Production CBC sealing obtains a fresh
  16-octet IV from the admitted module's `ApprovedEntropy` operation; callers
  cache the complete already-sealed response for retransmission.
- `ike_auth` and `ike_auth_signature` provide cleartext IKE_AUTH payload
  helpers, shared-key AUTH MIC helpers, signature AUTH helpers, and Child SA
  selector/proposal helpers.
- `ike_sa_rekey` strictly decodes authenticated/opened `SA, Ni, KEi`
  `CREATE_CHILD_SA` requests, selects an existing executable IKE-SA profile,
  and builds an immutable exact `SA, Nr, KEr` response chain. It rejects
  Child-SA protocol/SPI shapes, `REKEY_SA`, traffic selectors, `DH=NONE`, and
  KE/group mismatches without owning SPI allocation or IKE-SA lifecycle state.
- `device_identity` validates and builds TS 24.302 DEVICE_IDENTITY requests and
  responses using the redaction-safe exact-15-digit `Imei15` and `Imeisv`
  types. TBCD decoding preserves the received fifteenth IMEI digit (including
  a spare zero or non-Luhn digit) and enforces the terminal filler nibble.
- `notify` exposes the TS 24.302 private error value
  `IKEV2_NOTIFY_AUTHORIZATION_REJECTED` (9003). Construct its canonical
  Protocol-ID-zero, empty-SPI, empty-data body with
  `Ikev2NotifyPayloadBuild::authorization_rejected()`, encode it through
  `build_ike_auth_notify_payload`, and recognize its empty-SPI/empty-data
  receive shape with `Ikev2NotifyPayload::is_authorization_rejected()`.
  Consistent with RFC 7296 section 3.10, receive recognition ignores Protocol
  ID when SPI Size is zero. Choosing this outcome from Diameter or local
  authorization state remains product-owned.
- `dedicated_bearer` implements the TS 24.302 multiple-bearer Notify values and
  strict opened-payload views/builders for dedicated-bearer `CREATE_CHILD_SA`
  and `INFORMATIONAL` modification/deletion exchanges. TFT values use the
  canonical `opc-proto-tft` TS 24.008 codec shared with GTPv2-C. Response
  correlation checks the IKE SPIs, Message ID, exchange/flags, selected offered
  proposal/transforms, optional KE group, and traffic-selector narrowing.
- `pcscf_restoration` builds a canonical single-CP `INFORMATIONAL`
  `CFG_REQUEST` that preserves every PGW-provided typed IPv4 and IPv6 P-CSCF
  address in exact order, including repeated entries, and encodes its exact RFC
  7651 value. Its strict opened-reply decoder rejects absent, repeated, or
  valued known P-CSCF attributes while retaining unsupported Configuration
  attributes, Vendor IDs, unfamiliar status Notify payloads, and unknown
  non-critical payloads. Error-range Notify and unknown critical payloads fail
  closed. Correlation requires one empty acknowledgement per requested family
  plus matching IKE SPIs, exchange type, Message ID, and direction. Address and
  request `Debug` output is redacted.
- `fragmentation`, `notify`, `nat_detection`, `nat_traversal`, and `exchange`
  expose RFC-specific mechanism helpers without owning product state.

## Unknown critical payload rejection

`Message::decode_with_rejection` and NAT-T inspection preserve the exact
one-octet payload type required by RFC 7296 section 2.5. A generic message fact
is not reply authority. Only an exact initial IKE_SA_INIT request can be
converted into `Ikev2SaInitUnknownCriticalPayloadRequest`; responses, trailing
datagrams, malformed framing, truncation, and exceeded decode bounds cannot
produce that wrapper. Its header remains private and `build_response()` routes
through the existing bounded Notify type 1 builder:

```rust
use opc_proto_ikev2::{
    inspect_ike_nat_traversal_datagram, IKE_UDP_PORT,
};

# let datagram = [0u8; 0];
let inspection = inspect_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);
if let Some(rejection) = inspection.unknown_critical_payload() {
    if let Ok(request) = rejection.rejection().try_into_ike_sa_init_request() {
        let response = request.build_response()?;
        // Apply product-owned source admission, rate limiting, and
        // retransmission caching before sending `response`.
        let _ = response;
    }
}
# Ok::<(), opc_proto_ikev2::Ikev2SaInitNotifyBuildError>(())
```

Authenticated code that has already opened `SK`/`SKF` uses
`PayloadChain::validate_with_rejection` or
`RawPayloadIterator::unknown_critical_rejection` for the same protocol fact;
exchange correlation and protected error transmission remain caller-owned.
The original `classify_ike_nat_traversal_datagram` API keeps its public enum
shape and continues returning the coarse
`MalformedIke { decode_code: UnknownCriticalPayload }` outcome for existing
metrics and exhaustive matches on a fully framed, exact-length offender.
Rejection precedence is deliberately corrected for mixed-invalid input:
malformed offender framing stays malformed, and bytes beyond the declared IKE
length win as `TrailingIkeBytes`; neither produces a typed reply sidecar.

## Process-wide cryptographic module admission

IKEv2 cryptographic operations have no implicit software or `testkit`
fallback. Before accepting IKE traffic, a process must build
`Ikev2CryptoRequirements` from every configured IKE-SA profile, NAT-detection
use, CERTREQ authority hashing use, and signature direction, then admit one
exact `Arc<dyn IkeCryptoModule>`.
Admission probes the module, applies `ProviderPolicy`, preflights every named
algorithm, and sets an immutable process slot only after all checks succeed.
A failed preflight leaves the slot unset; a successful slot cannot be reset or
replaced. The module object may rotate its own keys, trust, sessions, or
material epochs internally without changing its admitted identity.

The runtime integration point is the async `StartupPhases::init_security`
hook. This complete composition aborts startup before any runtime-mediated
service listener binds:

```rust
use std::sync::Arc;

use opc_crypto_provider::{
    IkeCryptoModule, IkeSignatureAlgorithm, ProviderPolicy,
};
use opc_proto_ikev2::{
    install_ikev2_crypto_module, Ikev2CryptoRequirements,
    Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile,
};
use opc_runtime::{BootstrapError, StartupPhases};

fn security_phases(
    module: Arc<dyn IkeCryptoModule>,
    configured_profiles: &[Ikev2SaInitCryptoProfile],
) -> Result<StartupPhases, Ikev2SaInitCryptoError> {
    let mut requirements = Ikev2CryptoRequirements::new();
    for profile in configured_profiles.iter().copied() {
        requirements.require_ike_sa_profile(profile)?;
    }
    requirements.require_nat_detection();
    requirements.require_certreq_authority_hash();
    requirements.require_signature_generation(
        IkeSignatureAlgorithm::EcdsaP256Sha2_256,
    );
    requirements.require_signature_verification(
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
    );
    let policy = ProviderPolicy::new()
        .require_all(requirements.required_capabilities());

    Ok(StartupPhases {
        init_security: Some(Box::new(move |_runtime_profile| {
            let module = Arc::clone(&module);
            let requirements = requirements.clone();
            Box::pin(async move {
                install_ikev2_crypto_module(module, policy, requirements)
                    .await
                    .map(|_report| ())
                    .map_err(|error| BootstrapError::SecurityInit(Box::new(error)))
            })
        })),
        ..StartupPhases::default()
    })
}
```

`require_signature_generation` and `require_signature_verification` are
deliberately separate. Default builds can verify RSA peer AUTH but reject RSA
private-key signing unless the `rsa-signing` feature is compiled. The bundled
`Ikev2SoftwareCryptoModule` is an explicit RustCrypto-backed choice and reports
`ValidationState::NotValidated`; selecting it makes no certification claim.

`require_nat_detection` and `require_certreq_authority_hash` are also
deliberately separate. Both require `IkeHash` and SHA-1, but a configuration
that admits one protocol use does not authorize the other. To build one X.509
CERTREQ authority value, pass the complete DER `SubjectPublicKeyInfo` element
from the configured CA trust anchor—not a whole certificate, PEM, or the bare
public-key BIT STRING:

```rust
use opc_proto_ikev2::{
    ikev2_certreq_authority_key_hash, Ikev2CertReqSubjectPublicKeyInfo,
};

let spki = Ikev2CertReqSubjectPublicKeyInfo::from_der(configured_ca_spki_der)?;
let authority = ikev2_certreq_authority_key_hash(spki)?;
certreq_ca_data.extend_from_slice(authority.as_bytes());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The constructor accepts exactly one DER SPKI with no trailing bytes and rejects
empty, malformed, or over-bounded input before provider selection. Every hash
call then rechecks module identity, validation declaration, capability
admission, advertisement/readiness, SHA-1 operation support, provider success,
and an exact 20-octet output. Neither path has an implicit software/test
fallback.

Every operation rechecks the complete admitted capability set, current module
identity and validation declaration, readiness, advertisement, and the exact
algorithm requirement. Capability withdrawal fails before the provider
operation executes, including reuse of already-created opaque DH or signing
handles. Successful hash, PRF/PRF+, integrity, AEAD/CBC, and DH results are
checked immediately against their algorithm-derived widths. AEAD output must
retain the requested explicit IV; ECDSA output must be valid DER with scalars
in range for the selected curve; and RSA output must match the opaque handle's
public modulus width. DH public values are semantically validated and
snapshotted, and opaque DH/signing handles are rechecked when used. A module
contract violation fails with
`ike_crypto_module_invalid_output` before malformed bytes reach protocol
consumers. Production CBC IVs come from the admitted module's
`ApprovedEntropy` operation. Caller-supplied RNG and explicit-IV APIs remain
caller-owned compatibility/vector boundaries: encryption and integrity still
route through the module, but their supplied IV entropy is outside admission
evidence.

`require_child_sa_profile` admits the PRF used for Child-SA KEYMAT. A
CREATE_CHILD_SA configuration that offers PFS must additionally call
`require_child_sa_pfs_group` for every offered Child-SA DH group; the ESP
profile intentionally does not conflate its transforms with the separately
negotiated PFS transform.

The generic `CryptoProvider::open_payload` SPI/SA-lookup boundary remains
caller-owned. It cannot prove the identity of arbitrary external crypto and is
therefore not itself admitted or validated. The SDK-owned concrete
`Ikev2SaInitProtectedPayloadProvider` routes through this admitted slot. A
deployment using another adapter must bind that adapter to its admitted module;
performing crypto directly outside it is outside the SDK's admission evidence.

### Migration to admitted IKEv2 cryptography

Install the module during `StartupPhases::init_security` before invoking any
IKEv2 cryptographic operation. `ikev2_nat_detection_hash` and
`evaluate_ikev2_nat_detection` are now fallible and return
`Ikev2CryptoModuleError`; callers must propagate or map that error rather than
assuming NAT-D hashing cannot fail.

Applications that construct X.509 CERTREQ authority values must also call
`Ikev2CryptoRequirements::require_certreq_authority_hash` during startup,
validate the configured CA SPKI with
`Ikev2CertReqSubjectPublicKeyInfo::from_der`, and propagate
`ikev2_certreq_authority_key_hash` failures. Enabling NAT-D alone is
intentionally insufficient.

This additive API is source-breaking for downstream exhaustive matches. Add a
`CryptoModuleFailure { error }` arm to matches over:

- `Ikev2SaInitCryptoError`;
- `Ikev2ProtectedPayloadCryptoError`;
- `Ikev2IkeAuthVerificationError`; and
- `Ikev2SignatureKeyError`.

Code-enum matches must also accept
`Ikev2SaInitCryptoErrorCode::CryptoModuleFailure` and
`Ikev2ProtectedPayloadCryptoErrorCode::CryptoModuleFailure`. Existing semantic
error variants and their stable strings are unchanged; the new module-failure
strings are `ike_sa_init_crypto_module_failure`,
`ike_protected_payload_crypto_module_failure`,
`ike_auth_verify_crypto_module_failure`, and
`ike_auth_signature_crypto_module_failure`.

TLS and `opc-key` custody do not use this IKEv2 slot yet; those remain later
#334 slices.

## Network receive and sender-canonical validation

RFC 7296 requires senders to clear several reserved fields but explicitly
requires receivers to ignore them. `Message::decode`, `decode_header`, payload
iteration, and the typed ID/AUTH/KE/TS/CP decoders therefore use
`Ikev2ValidationProfile::NetworkReceive` by default. This remains the correct
profile even with `DecodeContext::conservative()` or `ValidationLevel::Strict`:
those context settings continue to enforce hostile lengths, bounded payload
counts, payload chaining, valid major version, typed cardinality, unknown
critical payloads, integrity, and authentication.

Generated outbound fixtures can opt into the separate canonical checks:

```rust
use opc_proto_ikev2::{Ikev2ValidationProfile, Message};
use opc_protocol::DecodeContext;

# let generated_message = [0u8; 0];
let result = Message::decode_with_profile(
    &generated_message,
    DecodeContext::conservative(),
    Ikev2ValidationProfile::SenderCanonical,
);
# let _ = result;
```

The corresponding `*_with_profile` typed body decoders and
`decode_ike_auth_cleartext_payloads_with_profile` diagnose a non-zero Version
bit, Critical bit on understood payloads, and non-zero SA Proposal/Transform,
ID, AUTH, KE, TS, CP, and CP-attribute reserved fields. Production typed
builders continue to emit zero. The raw `Message` shell deliberately preserves
supplied payload-chain bytes; callers generating outbound raw fixtures should
run sender-canonical validation before sending them.

`Ikev2IdentificationPayload::reserved` retains the exact three received ID
octets. `to_payload_body()` reconstructs the exact received ID body, including
those ignored octets, because RFC 7296 AUTH authenticates that body byte for
byte. It must not be replaced with a zero-canonicalized ID body during AUTH
verification.

## IKE-SA profile configuration

Profile construction is the startup capability-validation boundary. The old
infallible `Ikev2SaInitCryptoProfile::new(prf, dh, encryption)` API was removed
because it could construct AES-CBC without its negotiated integrity algorithm.
AEAD and encrypt-then-MAC suites now use separate validating constructors:

```rust
use opc_proto_ikev2::{
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile,
};

fn handset_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    )
}

fn existing_gcm_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
}
```

Configuration expressed as wire identifiers should use `from_transform_ids`;
its final argument is now `Option<u16>` containing the integrity Transform ID,
not an anonymous key length. `Some(14)` selects
AUTH-HMAC-SHA2-512-256; AEAD profiles pass `None`.

The executable IKE-SA matrix is:

| Mechanism | Transform IDs and sizes | Key/material contract |
| --- | --- | --- |
| PRF | HMAC-SHA2-256 (5), HMAC-SHA2-384 (6), HMAC-SHA2-512 (7) | 32, 48, or 64 octets for each of `SK_d`, `SK_pi`, and `SK_pr` |
| DH | MODP-2048 (14), ECP-256 (19), ECP-384 (20), ECP-521 (21) | Exact public-value lengths 256, 64, 96, and 132 octets |
| AES-GCM-16 | ENCR 20 with 128, 192, or 256-bit key; no INTEG | AES key plus four-octet salt; eight-octet explicit IV and 16-octet tag on the wire |
| AES-CBC | ENCR 12 with 128, 192, or 256-bit key | Raw 16, 24, or 32-octet `SK_e*`; fresh 16-octet IV per newly sealed message |
| SHA-2 integrity | AUTH-HMAC-SHA2-256-128 (12), 384-192 (13), or 512-256 (14) | 32/48/64-octet `SK_a*`; 16/24/32-octet ICV |

Every CBC key size may be paired with each supported SHA-2 integrity
algorithm. `validate_executable()` is the explicit startup check, although all
public profile constructors already enforce the same contract.

## Authenticated-only ESP Child SAs

ENCR_NULL is an explicit Child-SA capability, not a deployment default or a
policy preference. It is never accepted for an IKE SA and it is not added to
any allowlist automatically. A product that deliberately permits
authenticated-only ESP constructs or restores the exact typed profile:

```rust
use opc_proto_ikev2::{
    Ikev2ChildSaCryptoProfile, Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoError,
};

fn authenticated_only_child() -> Ikev2ChildSaCryptoProfile {
    Ikev2ChildSaCryptoProfile::new_authenticated_only(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
    )
}

fn restore_authenticated_only_child(
) -> Result<Ikev2ChildSaCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2ChildSaCryptoProfile::from_transform_ids(
        5,        // PRF_HMAC_SHA2_256
        11,       // ENCR_NULL
        None,     // Key Length is prohibited for ENCR_NULL
        Some(12), // AUTH_HMAC_SHA2_256_128
    )
}
```

RFC 7296 Child-SA KEYMAT contains `initiator A | responder A` for this
profile: each directional encryption and salt slice is empty, while the
selected integrity key is derived normally. Negotiation rejects ENCR_NULL
without INTEG, ENCR_NULL carrying any Key Length attribute, and AEAD carrying
a separate INTEG. Response construction copies transform 11 without adding an
attribute. Profile and key-material debug output remains redaction-safe.

The optional `opc-ipsec-xfrm` IKEv2 mapper installs this as Linux's canonical
zero-key `ecb(cipher_null)` crypt attribute plus the selected auth attribute.
That Linux-only adapter representation does not add protocol KEYMAT. Current
Linux kernels reject an ESP `NEWSA` containing auth but no crypt/aead
attribute, so consumers must use the mapper or `Algorithm::null()` rather than
constructing a raw auth-only `SaParameters` value.

### Migration from the anonymous integrity length

The old constructor could represent AES-CBC without its algorithm, and the old
wire-ID constructor accepted an arbitrary `usize` integrity-key length:

```text
Ikev2SaInitCryptoProfile::new(prf, dh, encryption)
Ikev2SaInitCryptoProfile::from_transform_ids(7, 14, 12, Some(256), 64)
```

Replace those calls with a fallible typed constructor or a typed integrity
Transform ID, and reject errors during configuration loading:

```rust
use opc_proto_ikev2::{Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile};

fn configured_handset_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    let profile = Ikev2SaInitCryptoProfile::from_transform_ids(
        7,         // PRF_HMAC_SHA2_512
        14,        // 2048-bit MODP
        12,        // ENCR_AES_CBC
        Some(256),
        Some(14),  // AUTH_HMAC_SHA2_512_256
    )?;
    profile.validate_executable()?;
    Ok(profile)
}
```

Downstream exhaustive matches must add these exact arms:

- `Ikev2EncryptionAlgorithm::Null` (Child-SA only; reject it in IKE-SA
  protected-payload paths);
- `Ikev2PrfAlgorithm::HmacSha2_512`;
- `Ikev2SaInitCryptoError::{MissingIntegrityTransform,
  UnexpectedIntegrityTransform}` and the corresponding
  `Ikev2SaInitCryptoErrorCode` variants;
- `Ikev2ProtectedPayloadCryptoError::{InvalidIvLength,
  InvalidCiphertextLength, RandomIvGenerationFailed}` and the corresponding
  `Ikev2ProtectedPayloadCryptoErrorCode` variants.

The existing `UnsupportedEncryptionProfile` error also changes field shape
from `integrity_key_len: usize` to
`integrity: Option<Ikev2IntegrityAlgorithm>`. Existing authentication,
authenticated-padding, unsupported-integrity, and key-material errors retain
their variants and stable codes.

Consumers must remove any blanket `integrity.is_some()` rejection. Preserve
the selected typed INTEG transform in the profile, pass that profile through
derivation/restore and protected-payload construction, and select the CBC
open/seal path when `encryption().is_aead()` is false. Restored CBC SAs pass the
same typed profile to `Ikev2SaInitKeyMaterial::from_established_keys`; integrity
ID 14 requires 64-octet `SK_ai`/`SK_ar`, while AES-CBC-256 requires 32-octet
`SK_ei`/`SK_er`. Existing AES-GCM callers use `new_aead`, retain empty `SK_a*`,
and keep their monotonic explicit-IV state.

## IKE_SA_INIT proposal selection

`Ikev2SaInitNegotiationPolicy` is the startup capability and responder
preference boundary. It accepts only complete executable profiles. The selector
combines transforms by type, so wire order never affects selection and
same-type alternatives remain valid. It returns one exact response proposal,
including the initiator's selected Key Length attribute unchanged:

```rust
use opc_proto_ikev2::{
    negotiate_ike_sa_init, Ikev2SaInitNegotiationError,
    Ikev2SaInitNegotiationPolicy, Ikev2SaInitPayloads,
};

fn select_handset_suite(
    payloads: &Ikev2SaInitPayloads<'_>,
) -> Result<opc_proto_ikev2::Ikev2SaInitNegotiation, Ikev2SaInitNegotiationError> {
    let profile = handset_profile()
        .map_err(Ikev2SaInitNegotiationError::UnsupportedConfiguredProfile)?;
    let policy = Ikev2SaInitNegotiationPolicy::new(vec![profile])?;
    negotiate_ike_sa_init(payloads, &policy)
}
# fn handset_profile() -> Result<opc_proto_ikev2::Ikev2SaInitCryptoProfile,
#     opc_proto_ikev2::Ikev2SaInitCryptoError> {
#     opc_proto_ikev2::Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
#         opc_proto_ikev2::Ikev2PrfAlgorithm::HmacSha2_512,
#         opc_proto_ikev2::Ikev2DhGroup::Modp2048,
#         opc_proto_ikev2::Ikev2EncryptionAlgorithm::AesCbc256,
#         opc_proto_ikev2::Ikev2IntegrityAlgorithm::HmacSha2_512_256,
#     )
# }
```

`NoAcceptableProposal` is a stable typed outcome suitable for
`NO_PROPOSAL_CHOSEN`. A supported offered suite whose DH transform does not
match the KE payload returns `KeyExchangeDhGroupMismatch`, allowing the product
to decide whether to send the bounded `INVALID_KE_PAYLOAD` response. Duplicate
transforms or attributes fail closed. NAT detection, fragmentation,
signature-hash, redirect, and unknown non-critical/private-use notifications do not
participate in algorithm selection. The product still owns responder SPI and
nonce allocation, anti-amplification policy, transaction caching, and the IKE
SA state machine.

## IKE-SA rekey responder boundary

`decode_ike_sa_rekey_request` accepts an already-authenticated and opened RFC
7296 IKE-SA rekey request. The outer header must identify a non-response
`CREATE_CHILD_SA` protected by `SK` on an established IKE SA. The inner chain
must contain exactly one SA payload, one Nonce, and one KE payload. Every
proposal uses Protocol ID IKE, a consecutive Proposal Number, and a non-zero
eight-octet new initiator SPI. The default decoder preserves Vendor IDs,
unrecognized Notify payloads, and unknown non-critical payloads as
redaction-safe borrowed views. The explicit-context decoder honors `Drop` for
the latter two classes and preserves them under both `Preserve` and `Reject`:
RFC 7296 requires these extensions to be ignored, so a generic reject policy
cannot reject this request. Unknown critical payloads always fail closed.
`REKEY_SA`, TSi/TSr, `DH=NONE`, other semantically invalid known payloads, and
a KE group absent from the proposals also fail closed with stable structural
codes.

Pass the decoded request to `negotiate_ike_sa_rekey` with the same
`Ikev2SaInitNegotiationPolicy` used for initial IKE-SA selection. The result
contains the selected transforms, the selected proposal's new initiator SPI,
and an `Ikev2SaInitCryptoProfile` that can be passed directly to
`derive_ike_sa_rekey_key_material` without re-decoding generated wire bytes.
That KDF accepts only the selected group's fixed-width shared secret: 256
octets for DH14 and 32, 48, or 66 octets for DH19, DH20, or DH21. A mismatch
returns the pre-existing stable `ike_sa_init_crypto_invalid_key_length` error
with only a redaction-safe input label and actual length; callers can obtain the
required width from `Ikev2DhGroup::shared_secret_len()`.

`build_ike_sa_rekey_response` requires a selected negotiation, a caller-owned
non-zero new responder SPI, Nr, and a KEr whose group and fixed public-value
length match the selected profile. It emits immutable generic-payload bytes in
exactly `SA, Nr, KEr` order. The caller remains responsible for generating DH
and nonce material, allocating collision-resistant SPIs, sealing and caching
the complete `SK` response, handling simultaneous rekeys, installing the new
SA, and deleting the old SA.

## Protected IKE_AUTH integration

For AES-CBC, use `ikev2_aes_cbc_protected_body_len` or
`ikev2_aes_cbc_protected_payload_len` to calculate the final outer IKE Length
and `SK`/`SKF` payload Length before sealing. Then pass the exact bytes through
the protected generic header as `message_prefix`. This is the production
sealing call for a responder IKE_AUTH:

```rust
use bytes::Bytes;
use opc_proto_ikev2::{
    seal_ikev2_sa_init_aes_cbc_protected_payload,
    Ikev2ProtectedPayloadCryptoError, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, ProtectedPayloadKind,
    ProtectedPayloadSealContext,
};

fn seal_responder_ike_auth(
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    final_message_prefix: &[u8],
    cleartext_payload_chain: &[u8],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        keys,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: final_message_prefix,
        },
        cleartext_payload_chain,
    )
}
```

The returned body is `IV || ciphertext || ICV`; for the observed profile the
lengths are 16, a non-empty multiple of 16, and 32 octets respectively. Use
`Ikev2SaInitProtectedPayloadProvider` with `InitiatorToResponder` to open the
handset's request. The provider authenticates the complete message before
decrypting. Well-formed, same-length corruption of authenticated header bytes,
IV, ciphertext, or ICV that reaches cryptographic verification returns the
same `AuthenticationFailed` outcome before decryption. Malformed framing and
lengths return their stable structural errors without decryption;
`InvalidPadding` is reachable only after successful authentication. Use the
same APIs for `SKF`; its four-octet Fragment Number/Total Fragments prefix is
included in the final authenticated prefix. Cache and replay the complete
already-built wire message for retransmissions—calling the production CBC
sealer again deliberately generates a different IV. The explicit-IV sealer is
a low-level test/vector boundary and must not be used by production callers.

`open_protected_payloads` preserves the provider error by value. With the
concrete SA_INIT-key provider its error type is
`Ikev2ProtectedPayloadOpenError`, and
`ProtectedPayloadOpenError::ProviderRejected(failure)` exposes
`failure.provider_error.code()` as an
`Ikev2ProtectedPayloadCryptoErrorCode`. This typed value is local diagnostic
evidence only. The outer error redacts it from both `Debug` and `Display`; a
caller that explicitly inspects a custom provider error remains responsible
for redaction. Do not send the inner variant or code to the peer: every
provider rejection retains the uniform outer
`ike_protected_payload_provider_rejected` classification, and products must
apply one peer-visible rejection/drop policy to authentication, malformed
length, and authenticated-padding failures. The outer error's `Display` text
is deliberately uniform as an additional defense against accidental detail
leakage; inspect the typed field locally instead.

## Dedicated-bearer integration

The dedicated-bearer API consumes and emits the cleartext payload chain inside
an authenticated `SK` payload. The application remains responsible for IKE SA
state, message-ID allocation, encryption/authentication, timer policy, and
installing or deleting the resulting Child SA.

```rust
use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    Header, Ikev2DedicatedBearerCreateChildSaRequest,
    Ikev2DedicatedBearerCreateChildSaRequestBuild,
    Ikev2DedicatedBearerCreateChildSaResponse, PayloadType,
};

fn encode_new_bearer(
    input: &Ikev2DedicatedBearerCreateChildSaRequestBuild,
) -> Result<(PayloadType, bytes::Bytes), Box<dyn std::error::Error>> {
    let cleartext = build_ikev2_dedicated_bearer_create_child_sa_request(input)?;
    // Seal these exact bytes once, then cache the complete encrypted request
    // for retransmission; do not reseal retransmissions with a new IV.
    Ok(cleartext.into_parts())
}

fn accept_new_bearer_response<'a>(
    request_header: &Header,
    request: &Ikev2DedicatedBearerCreateChildSaRequest<'_>,
    response_header: &Header,
    first_payload: PayloadType,
    opened_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerCreateChildSaResponse<'a>, Box<dyn std::error::Error>> {
    let response = decode_ikev2_dedicated_bearer_create_child_sa_response(
        response_header,
        first_payload,
        opened_payloads,
    )?;
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
        request_header,
        response_header,
        request,
        &response,
    )?;
    Ok(response)
}
```

Modification uses
`build_ikev2_dedicated_bearer_modification_request`; deletion uses
`build_ikev2_dedicated_bearer_delete_request`. A normal Delete response is
built/decoded with `build_ikev2_dedicated_bearer_delete_response` and
`decode_ikev2_dedicated_bearer_delete_response`: the ePDG request names its
inbound ESP SPI, while the UE response names the paired UE inbound ESP SPI.
Pass both values through `Ikev2DedicatedBearerDeleteResponseExpectation::PairedSa`
to `validate_ikev2_dedicated_bearer_delete_response_correlation` before changing
application state. An empty response is accepted only with the explicit
`SimultaneousDelete` expectation when RFC 7296 crossed Delete requests apply.
Modification responses remain empty or typed-error INFORMATIONAL responses and
use their corresponding decoder/correlation helper.

P-CSCF restoration keeps the selected family set with the immutable opened
request so a decoded reply can be correlated without downstream wire
constants. The application seals and caches the request, opens the
authenticated response, and owns retransmission and Update Bearer policy:

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

use opc_proto_ikev2::{
    build_ikev2_pcscf_restoration_request,
    decode_ikev2_pcscf_restoration_response,
    validate_ikev2_pcscf_restoration_response_correlation, Header,
    Ikev2PcscfRestorationAddress, Ikev2PcscfRestorationRequest, PayloadType,
};

fn begin_pcscf_restoration(
) -> Result<Ikev2PcscfRestorationRequest, Box<dyn std::error::Error>> {
    let request = build_ikev2_pcscf_restoration_request(
        &[
            Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 10,
            )),
        ],
    )?;
    // Seal request.first_payload()/request.bytes() once and cache both the
    // complete protected message and this immutable request for correlation.
    Ok(request)
}

fn accept_pcscf_restoration_reply(
    request_header: &Header,
    request: &Ikev2PcscfRestorationRequest,
    response_header: &Header,
    first_payload: PayloadType,
    opened_response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let response = decode_ikev2_pcscf_restoration_response(
        response_header,
        first_payload,
        opened_response,
    )?;
    validate_ikev2_pcscf_restoration_response_correlation(
        request_header,
        response_header,
        request,
        &response,
    )?;
    Ok(())
}
```

TS 23.380 section 5.6.5.2 requires the ePDG to forward the available P-CSCF
address list received from the PGW, so request attributes carry exact four- or
sixteen-octet values. TS 24.302 section 7.2.3.2 separately requires the UE's
reply attributes to be empty acknowledgements; the decoder rejects valued
known P-CSCF reply attributes. It retains unsupported Configuration
attributes, Vendor IDs, unfamiliar status Notify payloads, and unknown
non-critical payloads through redaction-safe borrowed accessors. Unknown
critical payloads, error-range Notify payloads, and known payloads invalid for
this procedure fail closed. The explicit-context decoder honors `Drop` for
unsupported material and normalizes `Reject` to preservation because RFC 7296
requires those extensions to be ignored rather than rejected; Vendor IDs are
always retained. IKE SA opening/sealing, APCO interpretation, P-CSCF address
selection, retransmission, and session policy remain outside this boundary.

The IKE-only establishment-and-deletion flow is in
[`examples/dedicated_bearer_ikev2.rs`](examples/dedicated_bearer_ikev2.rs).
The complete SDK composition from a triggered GTPv2-C Create Bearer request,
through a correlated IKEv2 Child-SA exchange and GTP response commit, followed
by Delete Bearer and Child-SA deletion, is executable as
[`examples/dedicated_bearer_sdk_flow.rs`](examples/dedicated_bearer_sdk_flow.rs).
That example makes the application-owned admission, allocation, and dataplane
boundaries explicit and proves exact GTP retransmission replay.

Integer-kbps bearer QoS must be mapped onto the discrete TS 24.301 NAS grid
before building `EPS_QOS`/`EXTENDED_EPS_QOS`. The checked mapping API makes the
operator-QCI GBR classification and quantization policy explicit and returns
the rate actually represented on the wire:

```rust
use opc_proto_ikev2::{
    Ikev2EpsBearerBitRatesKbps, Ikev2EpsQosKbps, Ikev2EpsQosMapping,
    Ikev2QosQuantization,
};

let mapped = Ikev2EpsQosMapping::from_kbps(
    Ikev2EpsQosKbps::Gbr {
        qci: 200, // Operator-specific: the variant supplies its GBR type.
        rates: Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: 10_000_001,
            maximum_downlink: 9_900_000,
            guaranteed_uplink: 9_000_000,
            guaranteed_downlink: 9_000_000,
        },
    },
    Ikev2QosQuantization::Ceiling,
)?;

assert_eq!(
    mapped.represented_rates().map(|rates| rates.maximum_uplink),
    Some(10_000_200),
);
# Ok::<(), opc_proto_ikev2::Ikev2QosMappingError>(())
```

`Exact` rejects rates between grid points. `Ceiling` is a documented SDK
policy that selects the smallest representation not below the requested rate;
TS 24.301 requires mapping to an explicit value but does not mandate that
rounding direction. `Ikev2ApnAmbrMapping` provides the same checked boundary
for APN-AMBR, including Extended APN-AMBR above 65,280 Mbps. See
[`examples/dedicated_bearer_qos_mapping.rs`](examples/dedicated_bearer_qos_mapping.rs).

The compact-code constructors remain available for lossless compatibility, but
they are not a way around the production profile. Strict decoders apply the TS
24.301 receiver interpretation for APN-AMBR compact aliases and extended-unit
aliases, then expose and re-encode their canonical equivalents. Reserved base
code 0 and inconsistent profiles still fail closed. Typed Notify builders and
`CREATE_CHILD_SA`/`INFORMATIONAL` builders accept manually supplied canonical
values but reject raw aliases, QCI resource mismatches, lower-tier saturation
errors, invalid maximum/guaranteed relationships, non-canonical units,
extension-threshold misuse, and inconsistent compact sentinels before any
payload bytes are returned.

## Example

```rust
use opc_proto_ikev2::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0, 0, 0, 0, 0, 0, 0, 0,
    40, 0x20, 34, 0x08,
    0, 0, 0, 0,
    0, 0, 0, 36,
    0, 0, 0, 8, 0x11, 0x22, 0x33, 0x44,
];

let (_tail, message) = Message::decode(&packet, DecodeContext::default())?;
assert_eq!(message.payloads().count(), 1);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Features

- `rsa-signing` enables RSA private-key signing for IKE_AUTH methods 1 and 14.
  It is off by default; RSA verification is still available in default builds.
- `testkit` exposes deterministic fixture builders for tests and downstream
  harnesses.

## Status And Limits

The crate is experimental and `publish = false`. The dedicated-bearer wire
boundary has typed, fail-closed validation and specification-authored tests,
but this crate is not a full IKEv2 implementation. Certificate-chain,
validity-period, name, and key-usage validation are caller responsibilities
when using signature AUTH helpers.

IKE_SA_INIT error responses are unauthenticated. The product owns source
validation, response rate limiting, retransmission behavior, and other
anti-amplification policy. The cleartext builder intentionally rejects
`INVALID_SYNTAX`: RFC 7296 §3.10.1 only permits that error in an encrypted
packet after Message ID and cryptographic checksum validation.

DEVICE_IDENTITY carries equipment identity only; it does not define or weaken
IKE authentication. Emergency procedures continue to use the ordinary RFC 7296
method-2 shared-key AUTH helper with caller-supplied, procedure-derived keying
material. The product layer owns exchange correlation and authorization policy.

The AUTHORIZATION_REJECTED helper only builds the TS 24.302 Notify body. A
product that selects it must still follow TS 24.302 section 7.4.1.2, including
providing the UE the information needed to authenticate the ePDG. The SDK does
not infer that selection from a Diameter result and does not implement captive
portal or provisioning policy.

See [CONFORMANCE.md](CONFORMANCE.md) for the exact evidence boundary and
explicit non-goals.

## Roadmap

- Add independent-peer fixtures before claiming interoperability.
- Continue adding typed cleartext payload bodies with octet-level fixture
  evidence.
- Keep SA state machines, retransmission queues, cookie policy, EAP-AKA, SPI
  allocation, Child SA installation, and ePDG product decisions outside this
  crate.

## Verification

```bash
cargo check -p opc-proto-ikev2 --all-targets --all-features
cargo test -p opc-proto-ikev2 --all-features
cargo clippy -p opc-proto-ikev2 --all-targets -- -D warnings
cargo run -p opc-proto-ikev2 --example dedicated_bearer_sdk_flow
cargo run -p opc-proto-ikev2 --example dedicated_bearer_qos_mapping
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz run dedicated_bearer -- -runs=1000)
```
