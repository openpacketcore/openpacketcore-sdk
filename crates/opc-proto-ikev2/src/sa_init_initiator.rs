//! Caller-owned IKE_SA_INIT initiation and response admission.
//!
//! The caller chooses proposal preference, retains the live private DH key,
//! supplies fresh unpredictable nonces, and owns transport, retransmission and
//! retry limits. These helpers neither choose a default suite nor authenticate
//! the responder: IKE_AUTH must authenticate the admitted transcript before
//! the caller trusts the peer. COOKIE and INVALID_KE_PAYLOAD are unauthenticated
//! hints; a caller must bound retries and keep its original proposal policy.
//!
//! @spec IETF RFC7296 1.2, 2.6, 2.7, 2.10, 2.14, 2.15, 2.16, 3.1, 3.3, 3.4, 3.9, 3.10.1
//! @req REQ-IETF-RFC7296-SA-INIT-INITIATOR-001

use std::{error::Error, fmt};

use bytes::Bytes;
use opc_protocol::DecodeContext;

use crate::{
    sa_init::{encode_ke_payload_build, encode_notify_payload_build, encode_sa_payload_build},
    sa_init_crypto::validate_dh_public_value,
    Header, HeaderFlags, Ikev2CookieNotify, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2EphemeralDhKey, Ikev2IntegrityAlgorithm, Ikev2KeyExchangePayload,
    Ikev2KeyExchangePayloadBuild, Ikev2NoncePayload, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaPayload, Ikev2SaPayloadBuild,
    Ikev2SaProposal, Ikev2SaProposalBuild, Ikev2SaTransform, Ikev2SaTransformBuild,
    Ikev2TransformAttributeBuildValue, Ikev2TransformAttributeValue, Message, OwnedMessage,
    PayloadType, EXCHANGE_TYPE_IKE_SA_INIT, HEADER_LEN, IKEV2_NOTIFY_COOKIE,
    IKEV2_NOTIFY_INVALID_KE_PAYLOAD, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
};

/// Value-free failures from initiator construction or response admission.
///
/// No variant retains a nested decoder error, peer bytes, cryptographic input,
/// SPI or algorithm identifier. `Display` is a stable machine-readable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SaInitInitiatorError {
    /// The caller supplied the reserved zero initiator SPI.
    InvalidInitiatorSpi,
    /// The proposal list is malformed, incomplete, duplicated or unsupported.
    InvalidOffer,
    /// No offered DH transform names the caller-held key's group.
    KeyExchangeNotOffered,
    /// Ni is outside 16..=256 octets or too short for an offered PRF.
    InvalidInitiatorNonce,
    /// A supplied COOKIE Notify has invalid shape, length or multiplicity.
    InvalidNotify,
    /// An outbound payload or message exceeds its wire length field.
    Encoding,
    /// The response header does not identify this initial responder exchange.
    InvalidResponseHeader,
    /// A successful response has the reserved zero responder SPI.
    InvalidResponderSpi,
    /// A payload chain or typed payload is malformed or exceeds decode limits.
    InvalidResponsePayload,
    /// A payload is not valid in this cleartext initial exchange.
    UnexpectedPayload,
    /// A successful response lacks SA, KE or Nonce.
    MissingPayload,
    /// A response repeats SA, KE or Nonce.
    DuplicatePayload,
    /// The response did not select exactly one complete offered suite.
    InvalidSelection,
    /// The selected group, response KE and caller-held key do not agree.
    KeyExchangeMismatch,
    /// The responder's public value is invalid for the selected group.
    InvalidKeyExchange,
    /// Nr violates the RFC length constraints for the selected PRF.
    InvalidResponderNonce,
    /// A retry Notify is malformed, repeated or mixed with success payloads.
    InvalidRetry,
    /// The peer sent an error notification outside the supported retry types.
    UnsupportedNotification,
}

impl Ikev2SaInitInitiatorError {
    /// Stable diagnostic code containing no caller or peer values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInitiatorSpi => "ike_initiator_invalid_spi",
            Self::InvalidOffer => "ike_initiator_invalid_offer",
            Self::KeyExchangeNotOffered => "ike_initiator_ke_not_offered",
            Self::InvalidInitiatorNonce => "ike_initiator_invalid_nonce",
            Self::InvalidNotify => "ike_initiator_invalid_notify",
            Self::Encoding => "ike_initiator_encoding",
            Self::InvalidResponseHeader => "ike_initiator_response_header",
            Self::InvalidResponderSpi => "ike_initiator_response_spi",
            Self::InvalidResponsePayload => "ike_initiator_response_payload",
            Self::UnexpectedPayload => "ike_initiator_unexpected_payload",
            Self::MissingPayload => "ike_initiator_missing_payload",
            Self::DuplicatePayload => "ike_initiator_duplicate_payload",
            Self::InvalidSelection => "ike_initiator_invalid_selection",
            Self::KeyExchangeMismatch => "ike_initiator_ke_mismatch",
            Self::InvalidKeyExchange => "ike_initiator_invalid_ke",
            Self::InvalidResponderNonce => "ike_initiator_invalid_peer_nonce",
            Self::InvalidRetry => "ike_initiator_invalid_retry",
            Self::UnsupportedNotification => "ike_initiator_unsupported_notification",
        }
    }
}

impl fmt::Display for Ikev2SaInitInitiatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SaInitInitiatorError {}

/// An immutable request and the exact offer against which to admit its reply.
///
/// This object retains public wire material only, never the private DH handle.
/// Its `Debug` implementation hides payloads, nonces, SPIs and attributes.
#[derive(Clone)]
pub struct Ikev2SaInitRequest {
    message: OwnedMessage,
    offer: Ikev2SaPayloadBuild,
    dh_group: Ikev2DhGroup,
    cookie_length: usize,
}

impl Ikev2SaInitRequest {
    /// The exact request for transmission, retransmission and initiator AUTH.
    ///
    /// This explicit wire accessor exposes raw bytes; do not log its result.
    /// Encode it with [`opc_protocol::Encode`] and retain the latest successfully
    /// negotiated request as the initiator's IKE_AUTH transcript.
    pub const fn message(&self) -> &OwnedMessage {
        &self.message
    }

    /// Prepend or replace COOKIE while preserving every other payload byte.
    ///
    /// The SPI, Message ID, proposal order, KE and Ni remain unchanged. The
    /// caller owns retry limits and decides whether to retain a cookie across
    /// an INVALID_KE_PAYLOAD retry. For a new group, rebuild with a new caller-
    /// held key and the original offer; do not accept an unoffered group.
    ///
    /// # Errors
    /// Returns [`Ikev2SaInitInitiatorError::InvalidNotify`] unless `cookie` is
    /// 1..=64 octets, or [`Ikev2SaInitInitiatorError::Encoding`] on overflow.
    pub fn with_cookie(&self, cookie: &[u8]) -> Result<Self, Ikev2SaInitInitiatorError> {
        if !(1..=64).contains(&cookie.len()) {
            return Err(Ikev2SaInitInitiatorError::InvalidNotify);
        }
        let cookie_length = 8 + cookie.len();
        let mut raw = Vec::with_capacity(cookie_length + self.message.raw_payloads.len());
        raw.extend_from_slice(&[PayloadType::SecurityAssociation.as_u8(), 0]);
        let length =
            u16::try_from(cookie_length).map_err(|_| Ikev2SaInitInitiatorError::Encoding)?;
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(&[0, 0]);
        raw.extend_from_slice(&IKEV2_NOTIFY_COOKIE.to_be_bytes());
        raw.extend_from_slice(cookie);
        raw.extend_from_slice(&self.message.raw_payloads[self.cookie_length..]);
        let mut header = self.message.header.clone();
        header.next_payload = PayloadType::Notify.as_u8();
        header.length = message_length(raw.len())?;
        Ok(Self {
            message: OwnedMessage {
                header,
                raw_payloads: Bytes::from(raw),
            },
            offer: self.offer.clone(),
            dh_group: self.dh_group,
            cookie_length,
        })
    }
}

impl fmt::Debug for Ikev2SaInitRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaInitRequest")
            .field("proposal_count", &self.offer.proposals.len())
            .field("wire_length", &self.message.header.length)
            .finish_non_exhaustive()
    }
}

/// A structurally admitted, still unauthenticated IKE_SA_INIT response.
///
/// Use the caller-held key's `agree`, then `derive_ike_sa_init_key_material`.
/// Bind IKE_AUTH to the exact transmitted request and received response.
#[derive(Clone)]
pub struct Ikev2SaInitAccepted<'a> {
    profile: Ikev2SaInitCryptoProfile,
    responder_spi: u64,
    key_exchange: &'a [u8],
    nonce: &'a [u8],
    notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl<'a> Ikev2SaInitAccepted<'a> {
    /// The single complete executable suite selected from the sent offer.
    pub const fn profile(&self) -> Ikev2SaInitCryptoProfile {
        self.profile
    }
    /// The non-zero responder SPI for key derivation and subsequent messages.
    pub const fn responder_spi(&self) -> u64 {
        self.responder_spi
    }
    /// Validated KEr public bytes to pass to the retained DH handle's `agree`.
    pub const fn key_exchange(&self) -> &'a [u8] {
        self.key_exchange
    }
    /// Validated Nr value, excluding the generic Nonce payload header.
    pub const fn nonce(&self) -> &'a [u8] {
        self.nonce
    }
    /// Status notifications for caller-owned extension policy.
    pub fn notifies(&self) -> &[Ikev2NotifyPayload<'a>] {
        &self.notifies
    }
}

impl fmt::Debug for Ikev2SaInitAccepted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaInitAccepted")
            .field("profile", &self.profile)
            .field("key_exchange_length", &self.key_exchange.len())
            .field("nonce_length", &self.nonce.len())
            .field("notify_count", &self.notifies.len())
            .finish_non_exhaustive()
    }
}

/// Success or one of the three RFC-defined unauthenticated retry outcomes.
///
/// Retry diagnostics expose no cookie or peer-selected values. Error replies
/// accept either zero or non-zero SPIr, as required by RFC 7296 §2.6. A retry
/// does not establish an SA, authenticate the peer or authorize a downgrade.
#[derive(Clone)]
pub enum Ikev2SaInitResponse<'a> {
    /// One complete offered suite, KEr and Nr ready for key derivation.
    Accepted(Ikev2SaInitAccepted<'a>),
    /// A bounded cookie to echo using [`Ikev2SaInitRequest::with_cookie`].
    Cookie(Ikev2CookieNotify<'a>),
    /// An unauthenticated group hint. Retry only if caller policy offered it.
    InvalidKePayload {
        /// The peer's non-zero two-octet group identifier, possibly unsupported.
        requested_group: u16,
    },
    /// The responder rejected every proposal; no suite was negotiated.
    NoProposalChosen,
}

impl fmt::Debug for Ikev2SaInitResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(accepted) => f.debug_tuple("Accepted").field(accepted).finish(),
            Self::Cookie(_) => f.write_str("Cookie"),
            Self::InvalidKePayload { .. } => f.write_str("InvalidKePayload"),
            Self::NoProposalChosen => f.write_str("NoProposalChosen"),
        }
    }
}

/// Build a non-testkit IKE_SA_INIT request using a caller-held live DH key.
///
/// Proposal and transform order are preserved. Proposals must be numbered
/// consecutively from one and contain complete SDK-supported IKE suites with
/// no proposal SPI. Alternatives of the same transform type are permitted;
/// AEAD and separate-integrity ciphers need separate proposals. Ni must be
/// 16..=256 octets and at least half the preferred key length of every offered
/// PRF (RFC 7296 §2.10). The caller supplies unpredictable fresh Ni and SPIi.
///
/// Notifications follow Ni in caller order, except one valid COOKIE is moved
/// to the first payload as required by §2.6. Only the key's public value is
/// read; the key remains usable by the caller and no private state is exported.
///
/// # Errors
/// Returns a value-free [`Ikev2SaInitInitiatorError`] for an invalid offer,
/// zero SPIi, unoffered KE group, invalid nonce/COOKIE or wire-length overflow.
pub fn build_ike_sa_init_request(
    initiator_spi: u64,
    offer: &Ikev2SaPayloadBuild,
    key: &Ikev2EphemeralDhKey,
    nonce: &[u8],
    notifies: &[Ikev2NotifyPayloadBuild],
) -> Result<Ikev2SaInitRequest, Ikev2SaInitInitiatorError> {
    if initiator_spi == 0 {
        return Err(Ikev2SaInitInitiatorError::InvalidInitiatorSpi);
    }
    let nonce_minimum = validate_offer(offer)?;
    if !offer
        .proposals
        .iter()
        .flat_map(|p| &p.transforms)
        .any(|t| t.transform_type == 4 && t.transform_id == key.group().transform_id())
    {
        return Err(Ikev2SaInitInitiatorError::KeyExchangeNotOffered);
    }
    if !(nonce_minimum..=256).contains(&nonce.len()) {
        return Err(Ikev2SaInitInitiatorError::InvalidInitiatorNonce);
    }
    let mut entries = vec![
        (
            PayloadType::SecurityAssociation,
            encode_sa_payload_build(offer).map_err(|_| Ikev2SaInitInitiatorError::Encoding)?,
        ),
        (
            PayloadType::KeyExchange,
            encode_ke_payload_build(&Ikev2KeyExchangePayloadBuild {
                dh_group: key.group().transform_id(),
                key_exchange_data: key.public_value().to_vec(),
            })
            .map_err(|_| Ikev2SaInitInitiatorError::Encoding)?,
        ),
        (PayloadType::Nonce, nonce.to_vec()),
    ];
    let mut cookie = None;
    for notify in notifies {
        if notify.notify_message_type == IKEV2_NOTIFY_COOKIE {
            if cookie.is_some()
                || notify.protocol_id != 0
                || !notify.spi.is_empty()
                || !(1..=64).contains(&notify.notification_data.len())
            {
                return Err(Ikev2SaInitInitiatorError::InvalidNotify);
            }
            cookie = Some(notify.notification_data.as_slice());
        } else {
            entries.push((
                PayloadType::Notify,
                encode_notify_payload_build(notify)
                    .map_err(|_| Ikev2SaInitInitiatorError::Encoding)?,
            ));
        }
    }
    let raw = encode_chain(&entries)?;
    let mut header = Header::new(
        initiator_spi,
        0,
        PayloadType::SecurityAssociation,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    header.length = message_length(raw.len())?;
    let request = Ikev2SaInitRequest {
        message: OwnedMessage {
            header,
            raw_payloads: Bytes::from(raw),
        },
        offer: offer.clone(),
        dh_group: key.group(),
        cookie_length: 0,
    };
    match cookie {
        Some(cookie) => request.with_cookie(cookie),
        None => Ok(request),
    }
}

/// Admit a responder's initial exchange against the immutable sent offer.
///
/// Checks SPIi, SPIr on success, version, exchange, Message ID, R/I flags,
/// exactly one offered proposal with one unchanged transform per offered type,
/// the caller's and responder's KE group, KEr and Nr. RFC receiver-ignored
/// flags and minor versions remain ignored. Unknown non-critical payloads and
/// status notifications do not change suite selection. Retry payloads are
/// parsed before requiring success payloads; malformed or ambiguous replies
/// cannot be mistaken for successful negotiation.
///
/// # Errors
/// Returns a value-free [`Ikev2SaInitInitiatorError`] on invalid or unsupported
/// input. COOKIE, INVALID_KE_PAYLOAD and NO_PROPOSAL_CHOSEN are successful typed
/// outcomes, never generic decoder failures. Apply caller retry policy and
/// authenticate the resulting IKE_AUTH exchange before trusting the peer.
pub fn admit_ike_sa_init_response<'a>(
    request: &Ikev2SaInitRequest,
    response: &Message<'a>,
    ctx: DecodeContext,
) -> Result<Ikev2SaInitResponse<'a>, Ikev2SaInitInitiatorError> {
    let header = &response.header;
    if header.initiator_spi != request.message.header.initiator_spi
        || header.major_version != 2
        || header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT
        || header.message_id != 0
        || !header.flags.response()
        || header.flags.initiator()
        || header.next_payload != response.payloads.first_payload().as_u8()
        || usize::try_from(header.length).ok()
            != HEADER_LEN.checked_add(response.payloads.bytes().len())
    {
        return Err(Ikev2SaInitInitiatorError::InvalidResponseHeader);
    }
    let mut sa = None;
    let mut ke = None;
    let mut nonce = None;
    let mut notifies = Vec::new();
    let mut retry = None;
    for raw in response.payloads_with_context(ctx) {
        let raw = raw.map_err(|_| Ikev2SaInitInitiatorError::InvalidResponsePayload)?;
        match raw.payload_type {
            PayloadType::SecurityAssociation => {
                if sa.is_some() {
                    return Err(Ikev2SaInitInitiatorError::DuplicatePayload);
                }
                sa = Some(
                    Ikev2SaPayload::decode(raw)
                        .map_err(|_| Ikev2SaInitInitiatorError::InvalidResponsePayload)?,
                );
            }
            PayloadType::KeyExchange => {
                if ke.is_some() {
                    return Err(Ikev2SaInitInitiatorError::DuplicatePayload);
                }
                ke = Some(
                    Ikev2KeyExchangePayload::decode(raw)
                        .map_err(|_| Ikev2SaInitInitiatorError::InvalidResponsePayload)?,
                );
            }
            PayloadType::Nonce => {
                if nonce.is_some() {
                    return Err(Ikev2SaInitInitiatorError::DuplicatePayload);
                }
                nonce = Some(
                    Ikev2NoncePayload::decode(raw)
                        .map_err(|_| Ikev2SaInitInitiatorError::InvalidResponderNonce)?,
                );
            }
            PayloadType::Notify => {
                let notify = Ikev2NotifyPayload::decode(raw)
                    .map_err(|_| Ikev2SaInitInitiatorError::InvalidResponsePayload)?;
                if let Some(outcome) = retry_outcome(notify, raw.offset)? {
                    if retry.replace(outcome).is_some() {
                        return Err(Ikev2SaInitInitiatorError::InvalidRetry);
                    }
                } else {
                    notifies.push(notify);
                }
            }
            PayloadType::CertificateRequest | PayloadType::VendorId | PayloadType::Unknown(_) => {}
            _ => return Err(Ikev2SaInitInitiatorError::UnexpectedPayload),
        }
    }
    if let Some(retry) = retry {
        if sa.is_some() || ke.is_some() || nonce.is_some() {
            return Err(Ikev2SaInitInitiatorError::InvalidRetry);
        }
        return Ok(retry);
    }
    if header.responder_spi == 0 {
        return Err(Ikev2SaInitInitiatorError::InvalidResponderSpi);
    }
    let sa = sa.ok_or(Ikev2SaInitInitiatorError::MissingPayload)?;
    let [proposal] = sa.proposals.as_slice() else {
        return Err(Ikev2SaInitInitiatorError::InvalidSelection);
    };
    let offered = request
        .offer
        .proposals
        .iter()
        .find(|p| p.proposal_number == proposal.proposal_number)
        .ok_or(Ikev2SaInitInitiatorError::InvalidSelection)?;
    validate_selection(offered, proposal)?;
    let profile = Ikev2SaInitCryptoProfile::from_proposal(proposal)
        .map_err(|_| Ikev2SaInitInitiatorError::InvalidSelection)?;
    let ke = ke.ok_or(Ikev2SaInitInitiatorError::MissingPayload)?;
    if ke.dh_group != profile.dh_group().transform_id() || profile.dh_group() != request.dh_group {
        return Err(Ikev2SaInitInitiatorError::KeyExchangeMismatch);
    }
    validate_dh_public_value(profile.dh_group(), ke.key_exchange_data)
        .map_err(|_| Ikev2SaInitInitiatorError::InvalidKeyExchange)?;
    let nonce = nonce.ok_or(Ikev2SaInitInitiatorError::MissingPayload)?;
    if nonce.nonce.len() < profile.prf().output_len().div_ceil(2) {
        return Err(Ikev2SaInitInitiatorError::InvalidResponderNonce);
    }
    Ok(Ikev2SaInitResponse::Accepted(Ikev2SaInitAccepted {
        profile,
        responder_spi: header.responder_spi,
        key_exchange: ke.key_exchange_data,
        nonce: nonce.nonce,
        notifies,
    }))
}

fn retry_outcome(
    notify: Ikev2NotifyPayload<'_>,
    offset: usize,
) -> Result<Option<Ikev2SaInitResponse<'_>>, Ikev2SaInitInitiatorError> {
    if !matches!(
        notify.notify_message_type,
        IKEV2_NOTIFY_COOKIE | IKEV2_NOTIFY_INVALID_KE_PAYLOAD | IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN
    ) {
        return if notify.notify_message_type < 16384 {
            Err(Ikev2SaInitInitiatorError::UnsupportedNotification)
        } else {
            Ok(None)
        };
    }
    if notify.spi_size != 0 || !notify.spi.is_empty() {
        return Err(Ikev2SaInitInitiatorError::InvalidRetry);
    }
    match notify.notify_message_type {
        IKEV2_NOTIFY_COOKIE if (1..=64).contains(&notify.notification_data.len()) => {
            Ok(Some(Ikev2SaInitResponse::Cookie(Ikev2CookieNotify {
                offset,
                notify,
            })))
        }
        IKEV2_NOTIFY_INVALID_KE_PAYLOAD => {
            let [high, low] = notify.notification_data else {
                return Err(Ikev2SaInitInitiatorError::InvalidRetry);
            };
            let requested_group = u16::from_be_bytes([*high, *low]);
            if requested_group == 0 {
                return Err(Ikev2SaInitInitiatorError::InvalidRetry);
            }
            Ok(Some(Ikev2SaInitResponse::InvalidKePayload {
                requested_group,
            }))
        }
        IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN if notify.notification_data.is_empty() => {
            Ok(Some(Ikev2SaInitResponse::NoProposalChosen))
        }
        _ => Err(Ikev2SaInitInitiatorError::InvalidRetry),
    }
}

fn validate_offer(offer: &Ikev2SaPayloadBuild) -> Result<usize, Ikev2SaInitInitiatorError> {
    if offer.proposals.is_empty() || offer.proposals.len() > 255 {
        return Err(Ikev2SaInitInitiatorError::InvalidOffer);
    }
    let mut nonce_minimum = 16;
    for (index, proposal) in offer.proposals.iter().enumerate() {
        if usize::from(proposal.proposal_number) != index + 1
            || proposal.protocol_id != 1
            || !proposal.spi.is_empty()
            || proposal.transforms.len() > 255
        {
            return Err(Ikev2SaInitInitiatorError::InvalidOffer);
        }
        let mut kinds = [false; 5];
        let mut aead = None;
        for (index, transform) in proposal.transforms.iter().enumerate() {
            if proposal.transforms[..index].contains(transform) {
                return Err(Ikev2SaInitInitiatorError::InvalidOffer);
            }
            let invalid = |_| Ikev2SaInitInitiatorError::InvalidOffer;
            match transform.transform_type {
                1 => {
                    let bits = match transform.attributes.as_slice() {
                        [attribute] if attribute.attribute_type == 14 => match attribute.value {
                            Ikev2TransformAttributeBuildValue::Tv(bits) => Some(bits),
                            _ => return Err(Ikev2SaInitInitiatorError::InvalidOffer),
                        },
                        [] => None,
                        _ => return Err(Ikev2SaInitInitiatorError::InvalidOffer),
                    };
                    let algorithm =
                        Ikev2EncryptionAlgorithm::from_transform_id(transform.transform_id, bits)
                            .map_err(invalid)?;
                    if algorithm.is_null()
                        || aead.is_some_and(|previous| previous != algorithm.is_aead())
                    {
                        return Err(Ikev2SaInitInitiatorError::InvalidOffer);
                    }
                    aead = Some(algorithm.is_aead());
                }
                2 => {
                    let prf = Ikev2PrfAlgorithm::from_transform_id(transform.transform_id)
                        .map_err(invalid)?;
                    nonce_minimum = nonce_minimum.max(prf.output_len().div_ceil(2));
                }
                3 => {
                    Ikev2IntegrityAlgorithm::from_transform_id(transform.transform_id)
                        .map_err(invalid)?;
                }
                4 => {
                    Ikev2DhGroup::from_transform_id(transform.transform_id).map_err(invalid)?;
                }
                _ => return Err(Ikev2SaInitInitiatorError::InvalidOffer),
            }
            if transform.transform_type != 1 && !transform.attributes.is_empty() {
                return Err(Ikev2SaInitInitiatorError::InvalidOffer);
            }
            kinds[usize::from(transform.transform_type)] = true;
        }
        if !kinds[1] || !kinds[2] || !kinds[4] || aead == Some(kinds[3]) {
            return Err(Ikev2SaInitInitiatorError::InvalidOffer);
        }
    }
    Ok(nonce_minimum)
}

fn validate_selection(
    offered: &Ikev2SaProposalBuild,
    selected: &Ikev2SaProposal<'_>,
) -> Result<(), Ikev2SaInitInitiatorError> {
    if selected.protocol_id != offered.protocol_id
        || selected.spi_size != 0
        || !selected.spi.is_empty()
    {
        return Err(Ikev2SaInitInitiatorError::InvalidSelection);
    }
    let mut selected_kinds = [false; 5];
    for transform in &selected.transforms {
        let kind = usize::from(transform.transform_type);
        if kind == 0
            || kind >= selected_kinds.len()
            || selected_kinds[kind]
            || !offered
                .transforms
                .iter()
                .any(|candidate| same_transform(candidate, transform))
        {
            return Err(Ikev2SaInitInitiatorError::InvalidSelection);
        }
        selected_kinds[kind] = true;
    }
    if offered
        .transforms
        .iter()
        .any(|t| !selected_kinds[usize::from(t.transform_type)])
    {
        return Err(Ikev2SaInitInitiatorError::InvalidSelection);
    }
    Ok(())
}

fn same_transform(offered: &Ikev2SaTransformBuild, selected: &Ikev2SaTransform<'_>) -> bool {
    offered.transform_type == selected.transform_type
        && offered.transform_id == selected.transform_id
        && offered.attributes.len() == selected.attributes.len()
        && offered.attributes.iter().all(|a| {
            selected.attributes.iter().any(|b| {
                a.attribute_type == b.attribute_type
                    && match (&a.value, b.value) {
                        (
                            Ikev2TransformAttributeBuildValue::Tv(a),
                            Ikev2TransformAttributeValue::Tv(b),
                        ) => *a == b,
                        (
                            Ikev2TransformAttributeBuildValue::Tlv(a),
                            Ikev2TransformAttributeValue::Tlv(b),
                        ) => a == b,
                        _ => false,
                    }
            })
        })
}

fn encode_chain(entries: &[(PayloadType, Vec<u8>)]) -> Result<Vec<u8>, Ikev2SaInitInitiatorError> {
    let mut raw = Vec::new();
    for (index, (_, body)) in entries.iter().enumerate() {
        let length = body
            .len()
            .checked_add(4)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(Ikev2SaInitInitiatorError::Encoding)?;
        raw.push(entries.get(index + 1).map_or(0, |(kind, _)| kind.as_u8()));
        raw.push(0);
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(body);
    }
    Ok(raw)
}

fn message_length(payload_length: usize) -> Result<u32, Ikev2SaInitInitiatorError> {
    HEADER_LEN
        .checked_add(payload_length)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Ikev2SaInitInitiatorError::Encoding)
}
