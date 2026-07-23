//! RFC 7427 signature-hash offer and negotiation boundary.
//!
//! The `SIGNATURE_HASH_ALGORITHMS` Notify is exchanged in `IKE_SA_INIT`.
//! This module preserves each peer's ordered offer, bounds untrusted input,
//! and produces distinct signing and verification authorities bound to the
//! exact request/response transcript. RFC 7427 does not require both
//! directions to use the same hash: each signer chooses from the offer sent by
//! the other peer.
//!
//! @spec IETF RFC7427 3, 4
//! @req REQ-IETF-RFC7427-SIGNATURE-HASH-001

use std::{error::Error, fmt, sync::Arc};

use opc_crypto_provider::IkeSignatureAlgorithm;
use opc_protocol::{BorrowDecode, DecodeContext};

use crate::{
    crypto_module::{
        signature_generation_algorithm_admitted, signature_verification_algorithm_admitted,
        Ikev2CryptoModuleError,
    },
    header::EXCHANGE_TYPE_IKE_SA_INIT,
    ike_auth::{Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets},
    message::Message,
    notify::{
        Ikev2NotifyPayload, IKEV2_NOTIFY_PROTOCOL_ID_NONE, IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS,
    },
    payload::PayloadType,
    sa_init::{
        decode_ike_sa_init_request_payloads, Ikev2KeyExchangePayload, Ikev2NoncePayload,
        Ikev2NotifyPayloadBuild, Ikev2SaPayload,
    },
};

/// Maximum number of 16-bit hash identifiers accepted in one RFC 7427 Notify.
///
/// RFC 7427 does not assign a protocol cardinality limit. This SDK resource
/// bound prevents an attacker-controlled `IKE_SA_INIT` from causing an
/// unbounded allocation while leaving ample room for registry growth.
pub const IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT: usize = 64;

/// An IANA IKEv2 signature-hash algorithm identifier.
///
/// Every currently assigned IANA identifier is named explicitly. Unassigned
/// and private-use identifiers are retained so the peer's exact ordered offer
/// is observable and forward compatible. Identifier zero is reserved and is
/// rejected by the decoder.
///
/// @spec IETF RFC7427 4, 7
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2SignatureHashAlgorithm {
    /// SHA-1 (identifier 1).
    Sha1,
    /// SHA2-256 (identifier 2).
    Sha2_256,
    /// SHA2-384 (identifier 3).
    Sha2_384,
    /// SHA2-512 (identifier 4).
    Sha2_512,
    /// Identity hash (identifier 5, RFC 8420).
    Identity,
    /// GOST R 34.11-2012 256-bit hash (identifier 6, RFC 9385).
    Streebog256,
    /// GOST R 34.11-2012 512-bit hash (identifier 7, RFC 9385).
    Streebog512,
    /// Currently unassigned IANA identifier in the range 8..=1023.
    Unassigned(u16),
    /// Private-use identifier in the range 1024..=65535.
    PrivateUse(u16),
}

impl Ikev2SignatureHashAlgorithm {
    /// Return the IANA wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Sha1 => 1,
            Self::Sha2_256 => 2,
            Self::Sha2_384 => 3,
            Self::Sha2_512 => 4,
            Self::Identity => 5,
            Self::Streebog256 => 6,
            Self::Streebog512 => 7,
            Self::Unassigned(value) | Self::PrivateUse(value) => value,
        }
    }

    /// Return whether this SDK has a method-14 signature primitive for the hash.
    ///
    /// Runtime use additionally requires the corresponding operation and
    /// algorithm to be admitted by the installed process crypto module.
    #[must_use]
    pub const fn is_sdk_supported(self) -> bool {
        matches!(self, Self::Sha2_256 | Self::Sha2_384)
    }

    fn from_wire(value: u16) -> Result<Self, Ikev2SignatureHashNegotiationError> {
        match value {
            0 => Err(Ikev2SignatureHashNegotiationError::ReservedAlgorithm),
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Sha2_256),
            3 => Ok(Self::Sha2_384),
            4 => Ok(Self::Sha2_512),
            5 => Ok(Self::Identity),
            6 => Ok(Self::Streebog256),
            7 => Ok(Self::Streebog512),
            8..=1023 => Ok(Self::Unassigned(value)),
            1024..=u16::MAX => Ok(Self::PrivateUse(value)),
        }
    }
}

/// Exact ordered signature-hash offer to encode into local `IKE_SA_INIT`.
///
/// Construction proves that every advertised hash has at least one
/// verification algorithm in the installed module's immutable startup
/// admission. This prevents configuration from advertising a hash that the
/// process cannot execute. Negotiation does not trust this builder as proof
/// that an offer was sent; it independently decodes the exact request and
/// response bytes.
#[derive(PartialEq, Eq)]
pub struct Ikev2SignatureHashLocalOffer {
    algorithms: Vec<Ikev2SignatureHashAlgorithm>,
}

impl Ikev2SignatureHashLocalOffer {
    /// Validate an ordered local offer against current crypto admission.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureHashNegotiationError`] when the offer is empty,
    /// exceeds the SDK bound, repeats an identifier, contains a hash without
    /// an admitted verification algorithm, or the installed crypto module is
    /// unavailable.
    pub fn new(
        algorithms: &[Ikev2SignatureHashAlgorithm],
    ) -> Result<Self, Ikev2SignatureHashNegotiationError> {
        validate_offer_shape(algorithms)?;
        for algorithm in algorithms {
            if !hash_verification_admitted(*algorithm)? {
                return Err(Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm);
            }
        }
        Ok(Self {
            algorithms: algorithms.to_vec(),
        })
    }

    /// Return the exact local preference order.
    #[must_use]
    pub fn algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.algorithms
    }

    /// Build the canonical RFC 7427 Notify value for this exact offer.
    ///
    /// The result has Protocol ID zero, an empty SPI, Notify type 16431, and
    /// consecutive big-endian 16-bit hash identifiers.
    #[must_use]
    pub fn to_notify_payload(&self) -> Ikev2NotifyPayloadBuild {
        let mut notification_data = Vec::with_capacity(self.algorithms.len() * 2);
        for algorithm in &self.algorithms {
            notification_data.extend_from_slice(&algorithm.as_u16().to_be_bytes());
        }
        Ikev2NotifyPayloadBuild {
            protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            spi: Vec::new(),
            notify_message_type: IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS,
            notification_data,
        }
    }
}

impl fmt::Debug for Ikev2SignatureHashLocalOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashLocalOffer")
            .field("algorithm_count", &self.algorithms.len())
            .finish()
    }
}

/// Validated exact ordered `SIGNATURE_HASH_ALGORITHMS` offer.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SignatureHashPeerOffer {
    algorithms: Vec<Ikev2SignatureHashAlgorithm>,
}

impl Ikev2SignatureHashPeerOffer {
    /// Return every identifier in its received wire order.
    ///
    /// Unsupported unassigned and private-use identifiers are retained.
    #[must_use]
    pub fn algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.algorithms
    }
}

impl fmt::Debug for Ikev2SignatureHashPeerOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sdk_supported_count = self
            .algorithms
            .iter()
            .filter(|algorithm| algorithm.is_sdk_supported())
            .count();
        f.debug_struct("Ikev2SignatureHashPeerOffer")
            .field("algorithm_count", &self.algorithms.len())
            .field("sdk_supported_count", &sdk_supported_count)
            .finish()
    }
}

/// Decode one RFC 7427 `SIGNATURE_HASH_ALGORITHMS` Notify occurrence.
///
/// An unrelated Notify returns `Ok(None)`. A matching Notify is strictly
/// checked for the canonical no-SPI shape, a non-empty even data length, the
/// SDK cardinality bound, reserved identifier zero, and duplicates.
///
/// # Errors
///
/// Returns [`Ikev2SignatureHashNegotiationError`] for a malformed matching
/// Notify. Unsupported identifiers are preserved for diagnostics and
/// forward-compatible policy.
///
/// @spec IETF RFC7427 4
pub fn decode_ikev2_signature_hash_algorithms_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2SignatureHashPeerOffer>, Ikev2SignatureHashNegotiationError> {
    if notify.notify_message_type != IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS {
        return Ok(None);
    }
    if notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE {
        return Err(Ikev2SignatureHashNegotiationError::ProtocolIdNonzero);
    }
    if notify.spi_size != 0 {
        return Err(Ikev2SignatureHashNegotiationError::SpiSizeNonzero);
    }
    if !notify.spi.is_empty() {
        return Err(Ikev2SignatureHashNegotiationError::SpiNonempty);
    }
    if notify.notification_data.is_empty() {
        return Err(Ikev2SignatureHashNegotiationError::EmptyOffer);
    }
    if !notify.notification_data.len().is_multiple_of(2) {
        return Err(Ikev2SignatureHashNegotiationError::MalformedDataLength);
    }
    let count = notify.notification_data.len() / 2;
    if count > IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT {
        return Err(Ikev2SignatureHashNegotiationError::TooManyAlgorithms);
    }

    let mut algorithms = Vec::with_capacity(count);
    for encoded in notify.notification_data.chunks_exact(2) {
        let value = u16::from_be_bytes([encoded[0], encoded[1]]);
        let algorithm = Ikev2SignatureHashAlgorithm::from_wire(value)?;
        if algorithms.contains(&algorithm) {
            return Err(Ikev2SignatureHashNegotiationError::DuplicateAlgorithm);
        }
        algorithms.push(algorithm);
    }
    Ok(Some(Ikev2SignatureHashPeerOffer { algorithms }))
}

/// Role of this process in the exact `IKE_SA_INIT` exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureHashLocalRole {
    /// The local process sent the request and received the response.
    Initiator,
    /// The local process received the request and sent the response.
    Responder,
}

/// Successful RFC 7427 offer exchange with directional executable sets.
///
/// `signing_algorithms` is the peer's offer intersected with locally admitted
/// signature-generation support, in peer wire order.
/// `verification_algorithms` is the exact local offer, after every element was
/// checked against locally admitted signature-verification support. The sets
/// intentionally need not intersect each other.
#[derive(PartialEq, Eq)]
pub struct Ikev2SignatureHashNegotiation {
    local_offer: Ikev2SignatureHashPeerOffer,
    peer_offer: Ikev2SignatureHashPeerOffer,
    signing_algorithms: Vec<Ikev2SignatureHashAlgorithm>,
    verification_algorithms: Vec<Ikev2SignatureHashAlgorithm>,
    local_binding: TranscriptBinding,
    peer_binding: TranscriptBinding,
}

impl Ikev2SignatureHashNegotiation {
    /// Return the exact locally sent offer recovered from the wire transcript.
    #[must_use]
    pub const fn local_offer(&self) -> &Ikev2SignatureHashPeerOffer {
        &self.local_offer
    }

    /// Return the exact received peer offer in peer wire order.
    #[must_use]
    pub const fn peer_offer(&self) -> &Ikev2SignatureHashPeerOffer {
        &self.peer_offer
    }

    /// Return hashes this local peer can use to sign, in peer preference order.
    #[must_use]
    pub fn signing_algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.signing_algorithms
    }

    /// Return hashes accepted when verifying the peer, in local offer order.
    #[must_use]
    pub fn verification_algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.verification_algorithms
    }

    /// Consume the negotiation and mint non-copyable directional authorities.
    #[must_use]
    pub fn into_authorities(self) -> Ikev2SignatureHashAuthorities {
        Ikev2SignatureHashAuthorities {
            signing: Ikev2SignatureHashSigningAuthority {
                algorithms: self.signing_algorithms,
                binding: self.local_binding,
            },
            verification: Ikev2SignatureHashVerificationAuthority {
                algorithms: self.verification_algorithms,
                binding: self.peer_binding,
            },
        }
    }
}

impl fmt::Debug for Ikev2SignatureHashNegotiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashNegotiation")
            .field("local_offer", &self.local_offer)
            .field("peer_offer", &self.peer_offer)
            .field("signing_algorithm_count", &self.signing_algorithms.len())
            .field(
                "verification_algorithm_count",
                &self.verification_algorithms.len(),
            )
            .finish()
    }
}

/// Non-copyable directional authorities for one exact SA_INIT exchange.
pub struct Ikev2SignatureHashAuthorities {
    signing: Ikev2SignatureHashSigningAuthority,
    verification: Ikev2SignatureHashVerificationAuthority,
}

impl Ikev2SignatureHashAuthorities {
    /// Authority for signatures produced by the local peer.
    #[must_use]
    pub const fn signing(&self) -> &Ikev2SignatureHashSigningAuthority {
        &self.signing
    }

    /// Authority for signatures checked from the remote peer.
    #[must_use]
    pub const fn verification(&self) -> &Ikev2SignatureHashVerificationAuthority {
        &self.verification
    }

    /// Consume the pair and return `(signing, verification)` authorities.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Ikev2SignatureHashSigningAuthority,
        Ikev2SignatureHashVerificationAuthority,
    ) {
        (self.signing, self.verification)
    }
}

impl fmt::Debug for Ikev2SignatureHashAuthorities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashAuthorities")
            .field("signing", &self.signing)
            .field("verification", &self.verification)
            .finish()
    }
}

/// Authority for method-14 signatures produced by the local peer.
///
/// It is bound to both exact `IKE_SA_INIT` messages and the expected AUTH peer
/// role. It cannot be copied or constructed outside this module.
pub struct Ikev2SignatureHashSigningAuthority {
    algorithms: Vec<Ikev2SignatureHashAlgorithm>,
    binding: TranscriptBinding,
}

impl Ikev2SignatureHashSigningAuthority {
    /// Return locally executable hashes offered by the peer.
    #[must_use]
    pub fn algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.algorithms
    }

    /// Bind one signing operation to the complete SA_INIT exchange.
    ///
    /// The returned authorization is deliberately non-copyable and is
    /// consumed by [`crate::compute_ike_auth_signature`]. Callers must present
    /// both exact messages for every operation. This prevents an authority
    /// from a different exchange from being used when the caller presents the
    /// current pair but only the signer-side message happens to be identical.
    /// The caller remains responsible for retaining the resulting authority,
    /// SA_INIT messages, and key material as one IKE-SA state; byte slices
    /// cannot prove that separately supplied key material came from the same
    /// product state.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureHashBindingError::ExchangeMismatch`] unless
    /// both messages exactly match the exchange that minted this authority.
    pub fn for_exchange<'a>(
        &'a self,
        request: &'a [u8],
        response: &'a [u8],
    ) -> Result<Ikev2SignatureHashSigningAuthorization<'a>, Ikev2SignatureHashBindingError> {
        self.binding.validate_exchange(request, response)?;
        Ok(Ikev2SignatureHashSigningAuthorization {
            authority: self,
            request,
            response,
        })
    }

    pub(crate) fn validate(
        &self,
        required: Ikev2SignatureHashAlgorithm,
        signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    ) -> Result<(), Ikev2SignatureHashAuthorityError> {
        validate_authority(&self.algorithms, &self.binding, required, signed_octets)
    }
}

impl fmt::Debug for Ikev2SignatureHashSigningAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashSigningAuthority")
            .field("algorithm_count", &self.algorithms.len())
            .field("expected_peer", &self.binding.expected_peer)
            .finish()
    }
}

/// Authority for method-14 signatures received from the remote peer.
///
/// It is bound to both exact `IKE_SA_INIT` messages and the expected AUTH peer
/// role. It cannot be copied or constructed outside this module.
pub struct Ikev2SignatureHashVerificationAuthority {
    algorithms: Vec<Ikev2SignatureHashAlgorithm>,
    binding: TranscriptBinding,
}

impl Ikev2SignatureHashVerificationAuthority {
    /// Return locally advertised and executable verification hashes.
    #[must_use]
    pub fn algorithms(&self) -> &[Ikev2SignatureHashAlgorithm] {
        &self.algorithms
    }

    /// Bind one verification operation to the complete SA_INIT exchange.
    ///
    /// The returned authorization is deliberately non-copyable and is
    /// consumed by [`crate::verify_ike_auth_signature`]. Callers must present
    /// both exact messages for every operation. The caller remains responsible
    /// for retaining the authority, messages, and key material as one IKE-SA
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureHashBindingError::ExchangeMismatch`] unless
    /// both messages exactly match the exchange that minted this authority.
    pub fn for_exchange<'a>(
        &'a self,
        request: &'a [u8],
        response: &'a [u8],
    ) -> Result<Ikev2SignatureHashVerificationAuthorization<'a>, Ikev2SignatureHashBindingError>
    {
        self.binding.validate_exchange(request, response)?;
        Ok(Ikev2SignatureHashVerificationAuthorization {
            authority: self,
            request,
            response,
        })
    }

    pub(crate) fn validate(
        &self,
        required: Ikev2SignatureHashAlgorithm,
        signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    ) -> Result<(), Ikev2SignatureHashAuthorityError> {
        validate_authority(&self.algorithms, &self.binding, required, signed_octets)
    }
}

impl fmt::Debug for Ikev2SignatureHashVerificationAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashVerificationAuthority")
            .field("algorithm_count", &self.algorithms.len())
            .field("expected_peer", &self.binding.expected_peer)
            .finish()
    }
}

/// One non-copyable method-14 signing authorization for an exact exchange.
///
/// Obtain this value from
/// [`Ikev2SignatureHashSigningAuthority::for_exchange`]. It contains no
/// caller-inspectable packet data and is consumed by the signing operation.
pub struct Ikev2SignatureHashSigningAuthorization<'a> {
    authority: &'a Ikev2SignatureHashSigningAuthority,
    request: &'a [u8],
    response: &'a [u8],
}

impl Ikev2SignatureHashSigningAuthorization<'_> {
    pub(crate) fn validate(
        &self,
        required: Ikev2SignatureHashAlgorithm,
        signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    ) -> Result<(), Ikev2SignatureHashAuthorityError> {
        self.authority
            .binding
            .validate_exchange(self.request, self.response)
            .map_err(|_| Ikev2SignatureHashAuthorityError::ExchangeMismatch)?;
        self.authority.validate(required, signed_octets)
    }
}

impl fmt::Debug for Ikev2SignatureHashSigningAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashSigningAuthorization")
            .field("algorithm_count", &self.authority.algorithms.len())
            .field("expected_peer", &self.authority.binding.expected_peer)
            .finish()
    }
}

/// One non-copyable method-14 verification authorization for an exact exchange.
///
/// Obtain this value from
/// [`Ikev2SignatureHashVerificationAuthority::for_exchange`]. It contains no
/// caller-inspectable packet data and is consumed by the verification
/// operation.
pub struct Ikev2SignatureHashVerificationAuthorization<'a> {
    authority: &'a Ikev2SignatureHashVerificationAuthority,
    request: &'a [u8],
    response: &'a [u8],
}

impl Ikev2SignatureHashVerificationAuthorization<'_> {
    pub(crate) fn validate(
        &self,
        required: Ikev2SignatureHashAlgorithm,
        signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    ) -> Result<(), Ikev2SignatureHashAuthorityError> {
        self.authority
            .binding
            .validate_exchange(self.request, self.response)
            .map_err(|_| Ikev2SignatureHashAuthorityError::ExchangeMismatch)?;
        self.authority.validate(required, signed_octets)
    }
}

impl fmt::Debug for Ikev2SignatureHashVerificationAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureHashVerificationAuthorization")
            .field("algorithm_count", &self.authority.algorithms.len())
            .field("expected_peer", &self.authority.binding.expected_peer)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
struct TranscriptBinding {
    expected_peer: Ikev2IkeAuthPeer,
    exchange: Arc<ExchangeBinding>,
}

impl TranscriptBinding {
    fn validate_exchange(
        &self,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), Ikev2SignatureHashBindingError> {
        if request != self.exchange.request || response != self.exchange.response {
            return Err(Ikev2SignatureHashBindingError::ExchangeMismatch);
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct ExchangeBinding {
    request: Vec<u8>,
    response: Vec<u8>,
}

/// Failure to bind a directional authority to an exact SA_INIT exchange.
///
/// This error deliberately carries no packet bytes, SPIs, identities, or
/// other transcript material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureHashBindingError {
    /// The presented request or response differs from the negotiated exchange.
    ExchangeMismatch,
}

impl Ikev2SignatureHashBindingError {
    /// Return a stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExchangeMismatch => "ike_signature_hash_authority_exchange_mismatch",
        }
    }
}

impl fmt::Display for Ikev2SignatureHashBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SignatureHashBindingError {}

/// Why a direction-specific authority rejected an AUTH operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ikev2SignatureHashAuthorityError {
    AlgorithmNotAuthorized,
    ExchangeMismatch,
}

/// Validate the exact request/response exchange and negotiate RFC 7427 hashes.
///
/// Both complete messages are decoded under `ctx`, must have no trailing
/// bytes, must form one correlated initial exchange, and must each contain
/// exactly one well-formed `SIGNATURE_HASH_ALGORITHMS` Notify. The locally
/// sent offer is checked against the installed module's admitted verification
/// algorithms; the peer offer is intersected independently with admitted
/// signature-generation algorithms.
///
/// # Errors
///
/// Returns [`Ikev2SignatureHashNegotiationError`] for invalid message shape or
/// correlation, missing/duplicate/malformed offers, an unsafe local offer,
/// no executable signing hash, or unavailable crypto admission.
///
/// @spec IETF RFC7427 3, 4
pub fn negotiate_ikev2_signature_hash_algorithms(
    local_role: Ikev2SignatureHashLocalRole,
    request_bytes: &[u8],
    response_bytes: &[u8],
    ctx: DecodeContext,
) -> Result<Ikev2SignatureHashNegotiation, Ikev2SignatureHashNegotiationError> {
    let request = decode_exact_message(request_bytes, ctx, true)?;
    let response = decode_exact_message(response_bytes, ctx, false)?;
    validate_exchange_headers(&request, &response)?;

    let request_payloads = decode_ike_sa_init_request_payloads(&request, ctx)
        .map_err(|_| Ikev2SignatureHashNegotiationError::InvalidRequestMessage)?;
    let request_missing = match local_role {
        Ikev2SignatureHashLocalRole::Initiator => {
            Ikev2SignatureHashNegotiationError::LocalOfferMissing
        }
        Ikev2SignatureHashLocalRole::Responder => {
            Ikev2SignatureHashNegotiationError::PeerOfferMissing
        }
    };
    let request_offer = extract_offer(&request_payloads.notifies, request_missing)?;
    let response_notifies = decode_response_notifies(&response, ctx)?;
    let response_missing = match local_role {
        Ikev2SignatureHashLocalRole::Initiator => {
            Ikev2SignatureHashNegotiationError::PeerOfferMissing
        }
        Ikev2SignatureHashLocalRole::Responder => {
            Ikev2SignatureHashNegotiationError::LocalOfferMissing
        }
    };
    let response_offer = extract_offer(&response_notifies, response_missing)?;

    let (local_offer, peer_offer, local_peer, peer_peer) = match local_role {
        Ikev2SignatureHashLocalRole::Initiator => (
            request_offer,
            response_offer,
            Ikev2IkeAuthPeer::Initiator,
            Ikev2IkeAuthPeer::Responder,
        ),
        Ikev2SignatureHashLocalRole::Responder => (
            response_offer,
            request_offer,
            Ikev2IkeAuthPeer::Responder,
            Ikev2IkeAuthPeer::Initiator,
        ),
    };

    for algorithm in local_offer.algorithms() {
        if !hash_verification_admitted(*algorithm)? {
            return Err(Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm);
        }
    }
    let verification_algorithms = local_offer.algorithms.clone();

    let mut signing_algorithms = Vec::new();
    for algorithm in peer_offer.algorithms() {
        if hash_generation_admitted(*algorithm)? {
            signing_algorithms.push(*algorithm);
        }
    }
    if signing_algorithms.is_empty() {
        return Err(Ikev2SignatureHashNegotiationError::UnsupportedOnly);
    }

    let exchange = Arc::new(ExchangeBinding {
        request: request_bytes.to_vec(),
        response: response_bytes.to_vec(),
    });
    Ok(Ikev2SignatureHashNegotiation {
        local_offer,
        peer_offer,
        signing_algorithms,
        verification_algorithms,
        local_binding: TranscriptBinding {
            expected_peer: local_peer,
            exchange: Arc::clone(&exchange),
        },
        peer_binding: TranscriptBinding {
            expected_peer: peer_peer,
            exchange,
        },
    })
}

fn validate_offer_shape(
    algorithms: &[Ikev2SignatureHashAlgorithm],
) -> Result<(), Ikev2SignatureHashNegotiationError> {
    if algorithms.is_empty() {
        return Err(Ikev2SignatureHashNegotiationError::EmptyOffer);
    }
    if algorithms.len() > IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT {
        return Err(Ikev2SignatureHashNegotiationError::TooManyAlgorithms);
    }
    let mut validated = Vec::with_capacity(algorithms.len());
    for algorithm in algorithms {
        if validated.contains(algorithm) {
            return Err(Ikev2SignatureHashNegotiationError::DuplicateAlgorithm);
        }
        validated.push(*algorithm);
    }
    Ok(())
}

fn signature_algorithms_for_hash(
    hash: Ikev2SignatureHashAlgorithm,
) -> &'static [IkeSignatureAlgorithm] {
    const SHA2_256: &[IkeSignatureAlgorithm] = &[
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
        IkeSignatureAlgorithm::EcdsaP256Sha2_256,
        IkeSignatureAlgorithm::EcdsaP384Sha2_256,
    ];
    const SHA2_384: &[IkeSignatureAlgorithm] = &[IkeSignatureAlgorithm::EcdsaP384Sha2_384];
    match hash {
        Ikev2SignatureHashAlgorithm::Sha2_256 => SHA2_256,
        Ikev2SignatureHashAlgorithm::Sha2_384 => SHA2_384,
        _ => &[],
    }
}

fn hash_verification_admitted(
    hash: Ikev2SignatureHashAlgorithm,
) -> Result<bool, Ikev2SignatureHashNegotiationError> {
    for algorithm in signature_algorithms_for_hash(hash) {
        if signature_verification_algorithm_admitted(*algorithm)
            .map_err(Ikev2SignatureHashNegotiationError::CryptoModuleFailure)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hash_generation_admitted(
    hash: Ikev2SignatureHashAlgorithm,
) -> Result<bool, Ikev2SignatureHashNegotiationError> {
    for algorithm in signature_algorithms_for_hash(hash) {
        if signature_generation_algorithm_admitted(*algorithm)
            .map_err(Ikev2SignatureHashNegotiationError::CryptoModuleFailure)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decode_exact_message<'a>(
    bytes: &'a [u8],
    ctx: DecodeContext,
    request: bool,
) -> Result<Message<'a>, Ikev2SignatureHashNegotiationError> {
    let (tail, message) = Message::decode(bytes, ctx).map_err(|_| {
        if request {
            Ikev2SignatureHashNegotiationError::InvalidRequestMessage
        } else {
            Ikev2SignatureHashNegotiationError::InvalidResponseMessage
        }
    })?;
    if !tail.is_empty() {
        return Err(if request {
            Ikev2SignatureHashNegotiationError::RequestTrailingBytes
        } else {
            Ikev2SignatureHashNegotiationError::ResponseTrailingBytes
        });
    }
    Ok(message)
}

fn validate_exchange_headers(
    request: &Message<'_>,
    response: &Message<'_>,
) -> Result<(), Ikev2SignatureHashNegotiationError> {
    if request.header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT
        || request.header.flags.response()
        || !request.header.flags.initiator()
        || request.header.initiator_spi == 0
        || request.header.responder_spi != 0
        || request.header.message_id != 0
    {
        return Err(Ikev2SignatureHashNegotiationError::InvalidRequestMessage);
    }
    if response.header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT
        || !response.header.flags.response()
        || response.header.flags.initiator()
        || response.header.initiator_spi != request.header.initiator_spi
        || response.header.responder_spi == 0
        || response.header.message_id != request.header.message_id
    {
        return Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage);
    }
    Ok(())
}

fn decode_response_notifies<'a>(
    response: &Message<'a>,
    ctx: DecodeContext,
) -> Result<Vec<Ikev2NotifyPayload<'a>>, Ikev2SignatureHashNegotiationError> {
    let mut security_association = false;
    let mut key_exchange = false;
    let mut nonce = false;
    let mut notifies = Vec::new();

    for raw in response.payloads_with_context(ctx) {
        let raw = raw.map_err(|_| Ikev2SignatureHashNegotiationError::InvalidResponseMessage)?;
        match raw.payload_type {
            PayloadType::SecurityAssociation => {
                if security_association || Ikev2SaPayload::decode(raw).is_err() {
                    return Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage);
                }
                security_association = true;
            }
            PayloadType::KeyExchange => {
                if key_exchange || Ikev2KeyExchangePayload::decode(raw).is_err() {
                    return Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage);
                }
                key_exchange = true;
            }
            PayloadType::Nonce => {
                if nonce || Ikev2NoncePayload::decode(raw).is_err() {
                    return Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage);
                }
                nonce = true;
            }
            PayloadType::Notify => {
                notifies.push(
                    Ikev2NotifyPayload::decode(raw)
                        .map_err(|_| Ikev2SignatureHashNegotiationError::InvalidResponseMessage)?,
                );
            }
            _ => {}
        }
    }

    if !security_association || !key_exchange || !nonce {
        return Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage);
    }
    Ok(notifies)
}

fn extract_offer(
    notifies: &[Ikev2NotifyPayload<'_>],
    missing: Ikev2SignatureHashNegotiationError,
) -> Result<Ikev2SignatureHashPeerOffer, Ikev2SignatureHashNegotiationError> {
    let mut offer = None;
    for notify in notifies {
        if let Some(decoded) = decode_ikev2_signature_hash_algorithms_notify(*notify)? {
            if offer.is_some() {
                return Err(Ikev2SignatureHashNegotiationError::DuplicateNotify);
            }
            offer = Some(decoded);
        }
    }
    offer.ok_or(missing)
}

fn validate_authority(
    algorithms: &[Ikev2SignatureHashAlgorithm],
    binding: &TranscriptBinding,
    required: Ikev2SignatureHashAlgorithm,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
) -> Result<(), Ikev2SignatureHashAuthorityError> {
    if !algorithms.contains(&required) {
        return Err(Ikev2SignatureHashAuthorityError::AlgorithmNotAuthorized);
    }
    let expected_message = match binding.expected_peer {
        Ikev2IkeAuthPeer::Initiator => binding.exchange.request.as_slice(),
        Ikev2IkeAuthPeer::Responder => binding.exchange.response.as_slice(),
    };
    if signed_octets.peer != binding.expected_peer
        || signed_octets.ike_sa_init_message != expected_message
    {
        return Err(Ikev2SignatureHashAuthorityError::ExchangeMismatch);
    }
    Ok(())
}

/// RFC 7427 Notify, exchange, admission, or selection failure.
///
/// Variants contain no packet bytes, signature bytes, certificate material,
/// peer addresses, identities, SPIs, or transcript bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureHashNegotiationError {
    /// Protocol ID was not zero.
    ProtocolIdNonzero,
    /// The declared SPI Size was not zero.
    SpiSizeNonzero,
    /// SPI bytes were present.
    SpiNonempty,
    /// Notification data or a local offer was empty.
    EmptyOffer,
    /// Notification data had an odd number of octets.
    MalformedDataLength,
    /// The configured SDK resource bound was exceeded.
    TooManyAlgorithms,
    /// Reserved identifier zero was offered.
    ReservedAlgorithm,
    /// One hash identifier occurred more than once.
    DuplicateAlgorithm,
    /// More than one `SIGNATURE_HASH_ALGORITHMS` Notify occurred in a message.
    DuplicateNotify,
    /// The local peer omitted its `SIGNATURE_HASH_ALGORITHMS` Notify.
    LocalOfferMissing,
    /// The remote peer omitted its `SIGNATURE_HASH_ALGORITHMS` Notify.
    PeerOfferMissing,
    /// The complete request was malformed or not an initial SA_INIT request.
    InvalidRequestMessage,
    /// The complete response was malformed or did not correlate to the request.
    InvalidResponseMessage,
    /// Bytes followed the request's declared IKE message boundary.
    RequestTrailingBytes,
    /// Bytes followed the response's declared IKE message boundary.
    ResponseTrailingBytes,
    /// The local offer named a hash without admitted verification support.
    UnsupportedLocalAlgorithm,
    /// The peer offered no hash with admitted local signing support.
    UnsupportedOnly,
    /// The installed process crypto module was unavailable or withdrawn.
    CryptoModuleFailure(Ikev2CryptoModuleError),
}

impl Ikev2SignatureHashNegotiationError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIdNonzero => "ike_signature_hash_protocol_id_nonzero",
            Self::SpiSizeNonzero => "ike_signature_hash_spi_size_nonzero",
            Self::SpiNonempty => "ike_signature_hash_spi_nonempty",
            Self::EmptyOffer => "ike_signature_hash_empty_offer",
            Self::MalformedDataLength => "ike_signature_hash_malformed_data_length",
            Self::TooManyAlgorithms => "ike_signature_hash_too_many_algorithms",
            Self::ReservedAlgorithm => "ike_signature_hash_reserved_algorithm",
            Self::DuplicateAlgorithm => "ike_signature_hash_duplicate_algorithm",
            Self::DuplicateNotify => "ike_signature_hash_duplicate_notify",
            Self::LocalOfferMissing => "ike_signature_hash_local_offer_missing",
            Self::PeerOfferMissing => "ike_signature_hash_peer_offer_missing",
            Self::InvalidRequestMessage => "ike_signature_hash_invalid_request_message",
            Self::InvalidResponseMessage => "ike_signature_hash_invalid_response_message",
            Self::RequestTrailingBytes => "ike_signature_hash_request_trailing_bytes",
            Self::ResponseTrailingBytes => "ike_signature_hash_response_trailing_bytes",
            Self::UnsupportedLocalAlgorithm => "ike_signature_hash_unsupported_local_algorithm",
            Self::UnsupportedOnly => "ike_signature_hash_unsupported_only",
            Self::CryptoModuleFailure(_) => "ike_signature_hash_crypto_module_failure",
        }
    }
}

impl fmt::Display for Ikev2SignatureHashNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SignatureHashNegotiationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CryptoModuleFailure(error) => Some(error),
            _ => None,
        }
    }
}
