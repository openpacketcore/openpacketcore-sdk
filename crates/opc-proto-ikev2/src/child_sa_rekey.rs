//! Strict initiator boundary for Child-SA rekey responses.
//!
//! The boundary consumes the existing
//! [`Ikev2CreateChildSaRekeyRequestBuild`] representation, retains its exact
//! canonical offer, current Child-SA selector floor, and request correlation
//! facts, and validates one authenticated, opened `CREATE_CHILD_SA` response.
//! A valid success or a valid error-range Notify commits the terminal response
//! exactly once.
//! Retransmission timing, exchange collision policy, SPI allocation, Child-SA
//! installation, and old-SA retirement remain product-owned.
//!
//! @spec IETF RFC7296 1.3.3, 2.7, 2.8, 2.9.2, 2.10, 2.25, 3.3, 3.4,
//! 3.9, 3.10
//! @req REQ-IETF-RFC7296-CHILD-SA-REKEY-RESPONSE-001

use core::fmt;
use std::error::Error;

use opc_protocol::{DecodeContext, DecodeErrorCode, UnknownIePolicy, ValidationLevel};

use crate::{
    dedicated_bearer::{
        traffic_selector_payload_is_narrowed, validate_sa_build, validate_sa_view,
        validate_selected_key_exchange, validate_selected_proposal, Ikev2SelectedKeyExchangeError,
        Ikev2UnknownNonCriticalPayload,
    },
    header::{Header, EXCHANGE_TYPE_CREATE_CHILD_SA},
    ike_auth::{
        build_create_child_sa_rekey_request_payloads, build_ike_auth_traffic_selector_payload,
        Ikev2CreateChildSaRekeyRequestBuild, Ikev2IkeAuthBuildError, Ikev2IkeAuthPayloadError,
        Ikev2TrafficSelectorPayload, Ikev2TrafficSelectorPayloadBuild,
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
    },
    notify::{
        Ikev2NotifyPayload, Ikev2NotifyPayloadError, IKEV2_NOTIFY_AUTHENTICATION_FAILED,
        IKEV2_NOTIFY_AUTHORIZATION_REJECTED, IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
        IKEV2_NOTIFY_FAILED_CP_REQUIRED, IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE,
        IKEV2_NOTIFY_INVALID_IKE_SPI, IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
        IKEV2_NOTIFY_INVALID_MAJOR_VERSION, IKEV2_NOTIFY_INVALID_MESSAGE_ID,
        IKEV2_NOTIFY_INVALID_SELECTORS, IKEV2_NOTIFY_INVALID_SPI, IKEV2_NOTIFY_INVALID_SYNTAX,
        IKEV2_NOTIFY_NO_ADDITIONAL_SAS, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, IKEV2_NOTIFY_REKEY_SA,
        IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED, IKEV2_NOTIFY_TEMPORARY_FAILURE,
        IKEV2_NOTIFY_TS_UNACCEPTABLE, IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
    },
    payload::{PayloadChain, PayloadType},
    sa_init::{
        Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadError, Ikev2NoncePayload,
        Ikev2NoncePayloadError, Ikev2SaPayload, Ikev2SaPayloadError, Ikev2VendorIdPayload,
    },
    sa_init_crypto::{
        validate_dh_public_value, Ikev2ChildSaCryptoProfile, Ikev2DhGroup,
        Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm,
        Ikev2SaInitCryptoError,
    },
};

const IKEV2_ERROR_NOTIFY_MAX_EXCLUSIVE: u16 = 16_384;
const IKEV2_ESP_SPI_LEN: usize = 4;
const IKEV2_TRANSFORM_TYPE_ENCR: u8 = 1;
const IKEV2_TRANSFORM_TYPE_INTEG: u8 = 3;
const IKEV2_TRANSFORM_TYPE_DH: u8 = 4;
const IKEV2_TRANSFORM_TYPE_ESN: u8 = 5;
const IKEV2_TRANSFORM_ID_NONE: u16 = 0;
const IKEV2_TRANSFORM_ID_ESN: u16 = 1;

/// Current traffic-selector floor of the Child SA being rekeyed.
///
/// RFC 7296 section 2.9.2 prohibits a replacement Child SA from becoming
/// narrower than the Child SA it replaces. The request may legitimately offer
/// a superset, so this value is intentionally separate from the request's TSi
/// and TSr offer.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaRekeyCurrentTrafficSelectors {
    traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
}

impl Ikev2ChildSaRekeyCurrentTrafficSelectors {
    /// Retain the current Child SA's TSi and TSr values.
    #[must_use]
    pub const fn new(
        traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
        traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
    ) -> Self {
        Self {
            traffic_selectors_initiator,
            traffic_selectors_responder,
        }
    }

    /// Current initiator-side selector floor.
    #[must_use]
    pub const fn traffic_selectors_initiator(&self) -> &Ikev2TrafficSelectorPayloadBuild {
        &self.traffic_selectors_initiator
    }

    /// Current responder-side selector floor.
    #[must_use]
    pub const fn traffic_selectors_responder(&self) -> &Ikev2TrafficSelectorPayloadBuild {
        &self.traffic_selectors_responder
    }
}

impl fmt::Debug for Ikev2ChildSaRekeyCurrentTrafficSelectors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaRekeyCurrentTrafficSelectors")
            .field(
                "initiator_selector_count",
                &self.traffic_selectors_initiator.selectors.len(),
            )
            .field(
                "responder_selector_count",
                &self.traffic_selectors_responder.selectors.len(),
            )
            .finish()
    }
}

/// Stable payload role used by missing and duplicate response diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2ChildSaRekeyResponsePayloadRole {
    /// Security Association payload.
    SecurityAssociation,
    /// Responder Nonce payload.
    Nonce,
    /// Responder Key Exchange payload.
    KeyExchange,
    /// Initiator Traffic Selectors payload.
    TrafficSelectorsInitiator,
    /// Responder Traffic Selectors payload.
    TrafficSelectorsResponder,
    /// Error-range Notify payload.
    ErrorNotify,
}

impl Ikev2ChildSaRekeyResponsePayloadRole {
    /// Stable machine-readable payload role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityAssociation => "security_association",
            Self::Nonce => "nonce",
            Self::KeyExchange => "key_exchange",
            Self::TrafficSelectorsInitiator => "traffic_selectors_initiator",
            Self::TrafficSelectorsResponder => "traffic_selectors_responder",
            Self::ErrorNotify => "error_notify",
        }
    }
}

/// Classification of a valid terminal Child-SA rekey error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2ChildSaRekeyPeerErrorKind {
    /// `INVALID_SYNTAX`.
    InvalidSyntax,
    /// `NO_PROPOSAL_CHOSEN`.
    NoProposalChosen,
    /// `INVALID_KE_PAYLOAD`.
    InvalidKePayload,
    /// `SINGLE_PAIR_REQUIRED`.
    SinglePairRequired,
    /// `NO_ADDITIONAL_SAS`.
    NoAdditionalSas,
    /// `TS_UNACCEPTABLE`.
    TrafficSelectorsUnacceptable,
    /// `TEMPORARY_FAILURE`.
    TemporaryFailure,
    /// `CHILD_SA_NOT_FOUND`.
    ChildSaNotFound,
    /// An unrecognized error-range type that RFC 7296 section 3.10.1 requires
    /// the recipient to treat as terminal request failure.
    Unknown,
}

/// Redaction-safe peer error that terminally rejected the rekey request.
///
/// Raw SPI and Notification Data are retained for extension-aware callers,
/// but `Debug` reports only their lengths.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaRekeyPeerError {
    kind: Ikev2ChildSaRekeyPeerErrorKind,
    notify_message_type: u16,
    protocol_id: u8,
    spi: Vec<u8>,
    notification_data: Vec<u8>,
    suggested_dh_group: Option<u16>,
}

impl Ikev2ChildSaRekeyPeerError {
    /// Typed error classification.
    #[must_use]
    pub const fn kind(&self) -> Ikev2ChildSaRekeyPeerErrorKind {
        self.kind
    }

    /// IKEv2 error-range Notify Message Type.
    #[must_use]
    pub const fn notify_message_type(&self) -> u16 {
        self.notify_message_type
    }

    /// Security Protocol ID carried by the Notify.
    #[must_use]
    pub const fn protocol_id(&self) -> u8 {
        self.protocol_id
    }

    /// Raw SPI bytes retained from the authenticated response.
    #[must_use]
    pub fn spi(&self) -> &[u8] {
        &self.spi
    }

    /// Raw Notification Data retained from the authenticated response.
    #[must_use]
    pub fn notification_data(&self) -> &[u8] {
        &self.notification_data
    }

    /// Responder-suggested DH group from `INVALID_KE_PAYLOAD`, when present.
    #[must_use]
    pub const fn suggested_dh_group(&self) -> Option<u16> {
        self.suggested_dh_group
    }
}

impl fmt::Debug for Ikev2ChildSaRekeyPeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaRekeyPeerError")
            .field("kind", &self.kind)
            .field("notify_message_type", &self.notify_message_type)
            .field("protocol_id", &self.protocol_id)
            .field("spi_len", &self.spi.len())
            .field("notification_data_len", &self.notification_data.len())
            .field("suggested_dh_group", &self.suggested_dh_group)
            .finish_non_exhaustive()
    }
}

/// Why a recognized error Notify was invalid for this exact rekey response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2ChildSaRekeyPeerErrorInvalidReason {
    /// This recognized Notify type is prohibited or belongs to another
    /// exchange/context.
    TypeNotAllowed,
    /// Security Protocol ID did not match the Notify's required context.
    ProtocolId,
    /// SPI length or presence did not match the Notify's required shape.
    SpiShape,
    /// SPI did not identify the exact Child SA named by the retained
    /// `REKEY_SA` request Notify.
    SpiMismatch,
    /// Notification Data length or presence was invalid for this type.
    NotificationDataShape,
    /// Notification Data carried a reserved or otherwise invalid value.
    NotificationDataValue,
    /// The Notify requires request state that was absent, such as
    /// `INVALID_KE_PAYLOAD` without a KE offer.
    RequestContext,
}

/// Strict successful Child-SA rekey response.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaRekeyResponse<'a> {
    replacement_initiator_spi: [u8; IKEV2_ESP_SPI_LEN],
    replacement_responder_spi: [u8; IKEV2_ESP_SPI_LEN],
    profile: Ikev2ChildSaCryptoProfile,
    pfs_group: Option<Ikev2DhGroup>,
    extended_sequence_numbers: bool,
    nonce: Ikev2NoncePayload<'a>,
    key_exchange: Option<Ikev2KeyExchangePayload<'a>>,
    traffic_selectors_initiator: Ikev2TrafficSelectorPayload<'a>,
    traffic_selectors_responder: Ikev2TrafficSelectorPayload<'a>,
    vendor_ids: Vec<Ikev2VendorIdPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
}

impl<'a> Ikev2ChildSaRekeyResponse<'a> {
    /// Initiator inbound ESP SPI from the selected retained proposal.
    #[must_use]
    pub const fn replacement_initiator_spi(&self) -> [u8; IKEV2_ESP_SPI_LEN] {
        self.replacement_initiator_spi
    }

    /// Non-zero responder inbound ESP SPI selected for the replacement SA.
    #[must_use]
    pub const fn replacement_responder_spi(&self) -> [u8; IKEV2_ESP_SPI_LEN] {
        self.replacement_responder_spi
    }

    /// Executable selected ESP encryption/integrity profile using the current
    /// IKE SA's PRF for Child-SA KEYMAT derivation.
    #[must_use]
    pub const fn profile(&self) -> Ikev2ChildSaCryptoProfile {
        self.profile
    }

    /// Selected PFS group, or `None` when the responder selected no PFS.
    #[must_use]
    pub const fn pfs_group(&self) -> Option<Ikev2DhGroup> {
        self.pfs_group
    }

    /// Whether the selected ESP proposal enables Extended Sequence Numbers.
    #[must_use]
    pub const fn extended_sequence_numbers(&self) -> bool {
        self.extended_sequence_numbers
    }

    /// Responder nonce used for replacement Child-SA KEYMAT derivation.
    #[must_use]
    pub const fn nonce(&self) -> &Ikev2NoncePayload<'a> {
        &self.nonce
    }

    /// Responder KE value when PFS was selected.
    #[must_use]
    pub const fn key_exchange(&self) -> Option<&Ikev2KeyExchangePayload<'a>> {
        self.key_exchange.as_ref()
    }

    /// Accepted initiator traffic selectors.
    #[must_use]
    pub const fn traffic_selectors_initiator(&self) -> &Ikev2TrafficSelectorPayload<'a> {
        &self.traffic_selectors_initiator
    }

    /// Accepted responder traffic selectors.
    #[must_use]
    pub const fn traffic_selectors_responder(&self) -> &Ikev2TrafficSelectorPayload<'a> {
        &self.traffic_selectors_responder
    }

    /// Vendor IDs retained from the successful response.
    #[must_use]
    pub fn vendor_ids(&self) -> &[Ikev2VendorIdPayload<'a>] {
        &self.vendor_ids
    }

    /// Unrecognized status-range Notifies retained under preserve policy.
    #[must_use]
    pub fn unrecognized_notifies(&self) -> &[Ikev2NotifyPayload<'a>] {
        &self.unrecognized_notifies
    }

    /// Unknown non-critical payloads retained under preserve policy.
    #[must_use]
    pub fn unknown_noncritical_payloads(&self) -> &[Ikev2UnknownNonCriticalPayload<'a>] {
        &self.unknown_noncritical_payloads
    }
}

impl fmt::Debug for Ikev2ChildSaRekeyResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaRekeyResponse")
            .field(
                "replacement_initiator_spi_len",
                &self.replacement_initiator_spi.len(),
            )
            .field(
                "replacement_responder_spi_len",
                &self.replacement_responder_spi.len(),
            )
            .field("profile", &self.profile)
            .field("pfs_group", &self.pfs_group)
            .field("extended_sequence_numbers", &self.extended_sequence_numbers)
            .field("nonce_len", &self.nonce.nonce.len())
            .field(
                "key_exchange_data_len",
                &self
                    .key_exchange
                    .as_ref()
                    .map(|key_exchange| key_exchange.key_exchange_data.len()),
            )
            .field(
                "initiator_selector_count",
                &self.traffic_selectors_initiator.selectors.len(),
            )
            .field(
                "responder_selector_count",
                &self.traffic_selectors_responder.selectors.len(),
            )
            .field("vendor_id_count", &self.vendor_ids.len())
            .field(
                "unrecognized_notify_count",
                &self.unrecognized_notifies.len(),
            )
            .field(
                "unknown_noncritical_payload_count",
                &self.unknown_noncritical_payloads.len(),
            )
            .finish()
    }
}

/// Stable failure while retaining or committing a Child-SA rekey response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2ChildSaRekeyResponseError {
    /// The supplied request header was not an encrypted Child-SA rekey request
    /// on an established IKE SA.
    RequestHeaderInvalid,
    /// The retained request builder could not produce its canonical payloads.
    RequestBuild(Ikev2IkeAuthBuildError),
    /// The current Child-SA selector floor could not be encoded.
    CurrentTrafficSelectorsBuild(Ikev2IkeAuthBuildError),
    /// The retained request offer was not a strict executable ESP offer.
    RequestOfferInvalid,
    /// The request TSi offer did not cover the current Child-SA TSi floor.
    InitiatorTrafficSelectorOfferNarrowerThanCurrent,
    /// The request TSr offer did not cover the current Child-SA TSr floor.
    ResponderTrafficSelectorOfferNarrowerThanCurrent,
    /// Initiator nonce was shorter than half the negotiated PRF preferred key
    /// length.
    InitiatorNonceTooShortForPrf {
        /// Received nonce length.
        actual: usize,
        /// Minimum length for the retained IKE-SA PRF.
        minimum: usize,
    },
    /// The retained request KE public value was invalid for its group.
    RequestKeyExchangeInvalid(Ikev2SaInitCryptoError),
    /// A successful or peer-error terminal response was already committed.
    TerminalResponseAlreadyCommitted,
    /// Response exchange type was not `CREATE_CHILD_SA`.
    WrongExchangeType {
        /// Received exchange type.
        actual: u8,
    },
    /// Response flag was absent.
    ResponseFlagMissing,
    /// Outer header did not name an encrypted `SK` or `SKF` payload.
    OuterPayloadNotEncrypted {
        /// Received outer payload type.
        actual: u8,
    },
    /// Established IKE SPI pair did not exactly match the retained request.
    IkeSpiMismatch,
    /// Message ID did not exactly match the retained request.
    MessageIdMismatch,
    /// Original-initiator flag did not identify the opposite response sender.
    InitiatorFlagMismatch,
    /// Opened response exceeded the configured parser bound.
    MessageTooLarge {
        /// Opened response length.
        actual: usize,
        /// Configured maximum length.
        maximum: usize,
    },
    /// Generic payload-chain framing was malformed.
    PayloadChain,
    /// Unknown critical payload failed closed.
    UnknownCriticalPayload,
    /// Required payload was absent.
    MissingPayload {
        /// Missing role.
        role: Ikev2ChildSaRekeyResponsePayloadRole,
    },
    /// Singleton payload was duplicated.
    DuplicatePayload {
        /// Duplicated role.
        role: Ikev2ChildSaRekeyResponsePayloadRole,
    },
    /// Known payload is prohibited in this response shape.
    UnexpectedPayloadType {
        /// Received payload type.
        payload_type: u8,
    },
    /// `REKEY_SA` is request-only and prohibited in this response.
    RekeySaNotifyProhibited,
    /// Error Notify was mixed with actual success payloads.
    ErrorResponseMixedWithPayloads,
    /// A recognized error Notify was prohibited or malformed for this exact
    /// Child-SA rekey response.
    InvalidPeerErrorNotify {
        /// Notify Message Type.
        notify_message_type: u16,
        /// Stable reason the Notify could not be accepted.
        reason: Ikev2ChildSaRekeyPeerErrorInvalidReason,
    },
    /// Peer returned one valid terminal error-range Notify.
    PeerErrorNotify(Ikev2ChildSaRekeyPeerError),
    /// Response SA did not contain exactly one proposal.
    ProposalCountInvalid {
        /// Received proposal count.
        actual: usize,
    },
    /// Selected proposal number/protocol was not in the retained offer.
    ProposalNotOffered,
    /// Selected proposal protocol was not ESP.
    ProposalProtocolNotEsp {
        /// Received Security Protocol ID.
        actual: u8,
    },
    /// Selected ESP proposal was structurally invalid or not executable.
    SelectedProposalInvalid,
    /// Replacement responder SPI was not four octets.
    ReplacementSpiLengthInvalid {
        /// Received SPI length.
        actual: usize,
    },
    /// Replacement responder SPI was all zero.
    ReplacementSpiZero,
    /// Selected ESP profile was unsupported or internally inconsistent.
    Profile(Ikev2SaInitCryptoError),
    /// KEr was present although the selected suite has no PFS group.
    KeyExchangeUnexpected,
    /// KEr was absent although the selected suite requires PFS.
    KeyExchangeRequired,
    /// KEr or retained KEi used a group other than the selected group.
    KeyExchangeGroupMismatch,
    /// KEr public value was invalid for the selected group.
    KeyExchangeValueInvalid(Ikev2SaInitCryptoError),
    /// Responder nonce was shorter than half the negotiated PRF preferred key
    /// length.
    ResponderNonceTooShortForPrf {
        /// Received nonce length.
        actual: usize,
        /// Minimum length for the retained IKE-SA PRF.
        minimum: usize,
    },
    /// Accepted initiator selectors were not a non-empty subset of the offer.
    InitiatorTrafficSelectorsNotOffered,
    /// Accepted responder selectors were not a non-empty subset of the offer.
    ResponderTrafficSelectorsNotOffered,
    /// Accepted initiator selectors did not cover the current Child-SA scope.
    InitiatorTrafficSelectorsNarrowerThanCurrent,
    /// Accepted responder selectors did not cover the current Child-SA scope.
    ResponderTrafficSelectorsNarrowerThanCurrent,
    /// Typed SA decoding failed.
    SecurityAssociation(Ikev2SaPayloadError),
    /// Typed Nonce decoding failed.
    Nonce(Ikev2NoncePayloadError),
    /// Typed KE decoding failed.
    KeyExchange(Ikev2KeyExchangePayloadError),
    /// Typed TS decoding failed.
    TrafficSelectors(Ikev2IkeAuthPayloadError),
    /// Typed Notify decoding failed.
    Notify(Ikev2NotifyPayloadError),
}

impl Ikev2ChildSaRekeyResponseError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RequestHeaderInvalid => "child_sa_rekey_response_request_header_invalid",
            Self::RequestBuild(_) => "child_sa_rekey_response_request_build_invalid",
            Self::CurrentTrafficSelectorsBuild(_) => {
                "child_sa_rekey_response_current_selectors_build_invalid"
            }
            Self::RequestOfferInvalid => "child_sa_rekey_response_request_offer_invalid",
            Self::InitiatorTrafficSelectorOfferNarrowerThanCurrent => {
                "child_sa_rekey_response_request_tsi_narrower_than_current"
            }
            Self::ResponderTrafficSelectorOfferNarrowerThanCurrent => {
                "child_sa_rekey_response_request_tsr_narrower_than_current"
            }
            Self::InitiatorNonceTooShortForPrf { .. } => {
                "child_sa_rekey_response_initiator_nonce_too_short_for_prf"
            }
            Self::RequestKeyExchangeInvalid(_) => {
                "child_sa_rekey_response_request_ke_value_invalid"
            }
            Self::TerminalResponseAlreadyCommitted => {
                "child_sa_rekey_response_terminal_already_committed"
            }
            Self::WrongExchangeType { .. } => "child_sa_rekey_response_exchange_type_wrong",
            Self::ResponseFlagMissing => "child_sa_rekey_response_flag_missing",
            Self::OuterPayloadNotEncrypted { .. } => {
                "child_sa_rekey_response_outer_payload_not_sk_or_skf"
            }
            Self::IkeSpiMismatch => "child_sa_rekey_response_ike_spi_mismatch",
            Self::MessageIdMismatch => "child_sa_rekey_response_message_id_mismatch",
            Self::InitiatorFlagMismatch => "child_sa_rekey_response_initiator_flag_mismatch",
            Self::MessageTooLarge { .. } => "child_sa_rekey_response_message_too_large",
            Self::PayloadChain => "child_sa_rekey_response_payload_chain_invalid",
            Self::UnknownCriticalPayload => "child_sa_rekey_response_unknown_critical_payload",
            Self::MissingPayload { .. } => "child_sa_rekey_response_payload_missing",
            Self::DuplicatePayload { .. } => "child_sa_rekey_response_payload_duplicate",
            Self::UnexpectedPayloadType { .. } => "child_sa_rekey_response_payload_unexpected",
            Self::RekeySaNotifyProhibited => "child_sa_rekey_response_rekey_sa_notify_prohibited",
            Self::ErrorResponseMixedWithPayloads => {
                "child_sa_rekey_response_error_mixed_with_payloads"
            }
            Self::InvalidPeerErrorNotify { .. } => {
                "child_sa_rekey_response_peer_error_notify_invalid"
            }
            Self::PeerErrorNotify(_) => "child_sa_rekey_response_peer_error_notify",
            Self::ProposalCountInvalid { .. } => "child_sa_rekey_response_proposal_count_invalid",
            Self::ProposalNotOffered => "child_sa_rekey_response_proposal_not_offered",
            Self::ProposalProtocolNotEsp { .. } => {
                "child_sa_rekey_response_proposal_protocol_not_esp"
            }
            Self::SelectedProposalInvalid => "child_sa_rekey_response_proposal_invalid",
            Self::ReplacementSpiLengthInvalid { .. } => {
                "child_sa_rekey_response_spi_length_invalid"
            }
            Self::ReplacementSpiZero => "child_sa_rekey_response_spi_zero",
            Self::Profile(_) => "child_sa_rekey_response_profile_invalid",
            Self::KeyExchangeUnexpected => "child_sa_rekey_response_ke_unexpected",
            Self::KeyExchangeRequired => "child_sa_rekey_response_ke_required",
            Self::KeyExchangeGroupMismatch => "child_sa_rekey_response_ke_group_mismatch",
            Self::KeyExchangeValueInvalid(_) => "child_sa_rekey_response_ke_value_invalid",
            Self::ResponderNonceTooShortForPrf { .. } => {
                "child_sa_rekey_response_responder_nonce_too_short_for_prf"
            }
            Self::InitiatorTrafficSelectorsNotOffered => "child_sa_rekey_response_tsi_not_offered",
            Self::ResponderTrafficSelectorsNotOffered => "child_sa_rekey_response_tsr_not_offered",
            Self::InitiatorTrafficSelectorsNarrowerThanCurrent => {
                "child_sa_rekey_response_tsi_narrower_than_current"
            }
            Self::ResponderTrafficSelectorsNarrowerThanCurrent => {
                "child_sa_rekey_response_tsr_narrower_than_current"
            }
            Self::SecurityAssociation(_) => "child_sa_rekey_response_sa_invalid",
            Self::Nonce(_) => "child_sa_rekey_response_nonce_invalid",
            Self::KeyExchange(_) => "child_sa_rekey_response_ke_invalid",
            Self::TrafficSelectors(_) => "child_sa_rekey_response_ts_invalid",
            Self::Notify(_) => "child_sa_rekey_response_notify_invalid",
        }
    }
}

impl fmt::Display for Ikev2ChildSaRekeyResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2ChildSaRekeyResponseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestBuild(error) | Self::CurrentTrafficSelectorsBuild(error) => Some(error),
            Self::RequestKeyExchangeInvalid(error)
            | Self::Profile(error)
            | Self::KeyExchangeValueInvalid(error) => Some(error),
            Self::SecurityAssociation(error) => Some(error),
            Self::Nonce(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            Self::TrafficSelectors(error) => Some(error),
            Self::Notify(error) => Some(error),
            _ => None,
        }
    }
}

/// Once-only initiator-side Child-SA rekey response boundary.
///
/// Construction consumes the existing request builder and retains canonical
/// SA/TS bodies plus the exact old-IKE-SA header correlation facts. The type
/// is deliberately not `Clone`: one boundary authorizes at most one terminal
/// response commit.
pub struct Ikev2ChildSaRekeyResponseBoundary {
    old_initiator_spi: u64,
    old_responder_spi: u64,
    request_message_id: u32,
    request_initiator_flag: bool,
    ike_sa_prf: Ikev2PrfAlgorithm,
    rekeyed_protocol_id: u8,
    rekeyed_spi: [u8; IKEV2_ESP_SPI_LEN],
    request_sa_body: Vec<u8>,
    request_tsi_body: Vec<u8>,
    request_tsr_body: Vec<u8>,
    current_tsi_body: Vec<u8>,
    current_tsr_body: Vec<u8>,
    initiator_nonce: Vec<u8>,
    request_key_exchange_group: Option<u16>,
    terminal_committed: bool,
}

impl Ikev2ChildSaRekeyResponseBoundary {
    /// Retain one exact Child-SA rekey request for response validation.
    ///
    /// `request_header` must be the encrypted outer header paired with
    /// `request`. The supplied PRF is the established IKE SA PRF used by RFC
    /// 7296 Child-SA KEYMAT derivation.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2ChildSaRekeyResponseError`] when the request header,
    /// builder encoding, ESP proposal, current/request selector relationship,
    /// nonce floor, or optional KE is invalid.
    pub fn new(
        request_header: &Header,
        request: Ikev2CreateChildSaRekeyRequestBuild,
        current_traffic_selectors: Ikev2ChildSaRekeyCurrentTrafficSelectors,
        ike_sa_prf: Ikev2PrfAlgorithm,
    ) -> Result<Self, Ikev2ChildSaRekeyResponseError> {
        validate_request_header(request_header)?;
        validate_sa_build(&request.security_association, false)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        let built = build_create_child_sa_rekey_request_payloads(&request)
            .map_err(Ikev2ChildSaRekeyResponseError::RequestBuild)?;
        let request_sa_body = built.security_association.body;
        let request_tsi_body = built.traffic_selectors_initiator.body;
        let request_tsr_body = built.traffic_selectors_responder.body;

        let request_sa = Ikev2SaPayload::decode_body(&request_sa_body)
            .map_err(Ikev2ChildSaRekeyResponseError::SecurityAssociation)?;
        let request_tsi = Ikev2TrafficSelectorPayload::decode_body(&request_tsi_body)
            .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?;
        let request_tsr = Ikev2TrafficSelectorPayload::decode_body(&request_tsr_body)
            .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?;
        validate_request_offer(&request, &request_sa, &request_tsi, &request_tsr)?;
        let current_tsi_body = build_ike_auth_traffic_selector_payload(
            &current_traffic_selectors.traffic_selectors_initiator,
        )
        .map_err(Ikev2ChildSaRekeyResponseError::CurrentTrafficSelectorsBuild)?;
        let current_tsr_body = build_ike_auth_traffic_selector_payload(
            &current_traffic_selectors.traffic_selectors_responder,
        )
        .map_err(Ikev2ChildSaRekeyResponseError::CurrentTrafficSelectorsBuild)?;
        let current_tsi = Ikev2TrafficSelectorPayload::decode_body(&current_tsi_body)
            .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?;
        let current_tsr = Ikev2TrafficSelectorPayload::decode_body(&current_tsr_body)
            .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?;
        if !traffic_selector_payload_is_narrowed(&request_tsi, &current_tsi) {
            return Err(
                Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorOfferNarrowerThanCurrent,
            );
        }
        if !traffic_selector_payload_is_narrowed(&request_tsr, &current_tsr) {
            return Err(
                Ikev2ChildSaRekeyResponseError::ResponderTrafficSelectorOfferNarrowerThanCurrent,
            );
        }
        let minimum_nonce_len = prf_nonce_minimum(ike_sa_prf);
        if request.nonce.nonce.len() < minimum_nonce_len {
            return Err(
                Ikev2ChildSaRekeyResponseError::InitiatorNonceTooShortForPrf {
                    actual: request.nonce.nonce.len(),
                    minimum: minimum_nonce_len,
                },
            );
        }
        let request_key_exchange_group = request
            .key_exchange
            .as_ref()
            .map(|key_exchange| key_exchange.dh_group);
        let initiator_nonce = request.nonce.nonce;
        let rekeyed_spi = <[u8; IKEV2_ESP_SPI_LEN]>::try_from(request.rekeyed_spi.as_slice())
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;

        Ok(Self {
            old_initiator_spi: request_header.initiator_spi,
            old_responder_spi: request_header.responder_spi,
            request_message_id: request_header.message_id,
            request_initiator_flag: request_header.flags.initiator(),
            ike_sa_prf,
            rekeyed_protocol_id: request.rekeyed_protocol_id,
            rekeyed_spi,
            request_sa_body,
            request_tsi_body,
            request_tsr_body,
            current_tsi_body,
            current_tsr_body,
            initiator_nonce,
            request_key_exchange_group,
            terminal_committed: false,
        })
    }

    /// Initiator nonce retained from the exact request for Child-SA KEYMAT.
    #[must_use]
    pub fn initiator_nonce(&self) -> &[u8] {
        &self.initiator_nonce
    }

    /// Return whether a valid success or valid peer-error response committed.
    #[must_use]
    pub const fn terminal_committed(&self) -> bool {
        self.terminal_committed
    }

    /// Validate and commit one authenticated, opened rekey response.
    ///
    /// Conservative parser bounds and unknown-payload preservation are used.
    /// A valid error-range Notify is returned as
    /// [`Ikev2ChildSaRekeyResponseError::PeerErrorNotify`] and still commits
    /// the terminal response. Malformed or uncorrelated input does not commit.
    ///
    /// # Errors
    ///
    /// Returns a stable error for correlation, framing, cardinality, proposal,
    /// PFS, selector, peer-error, or duplicate-terminal failures.
    pub fn commit_response<'a>(
        &mut self,
        response_header: &Header,
        first_payload: PayloadType,
        cleartext_payloads: &'a [u8],
    ) -> Result<Ikev2ChildSaRekeyResponse<'a>, Ikev2ChildSaRekeyResponseError> {
        let mut context = DecodeContext::conservative();
        context.unknown_ie_policy = UnknownIePolicy::Preserve;
        self.commit_response_with_context(
            response_header,
            first_payload,
            cleartext_payloads,
            context,
        )
    }

    /// Validate and commit with caller-supplied parser limits and unknown-item
    /// policy.
    ///
    /// Structural validation is always strict. Preserve retains unknown
    /// non-critical payloads and unrecognized status Notifies, Drop discards
    /// them, and Reject is normalized to Preserve because RFC 7296 requires
    /// both classes to be ignored.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::commit_response`].
    pub fn commit_response_with_context<'a>(
        &mut self,
        response_header: &Header,
        first_payload: PayloadType,
        cleartext_payloads: &'a [u8],
        mut context: DecodeContext,
    ) -> Result<Ikev2ChildSaRekeyResponse<'a>, Ikev2ChildSaRekeyResponseError> {
        if self.terminal_committed {
            return Err(Ikev2ChildSaRekeyResponseError::TerminalResponseAlreadyCommitted);
        }
        validate_response_header(response_header, self)?;
        if cleartext_payloads.len() > context.max_message_len {
            return Err(Ikev2ChildSaRekeyResponseError::MessageTooLarge {
                actual: cleartext_payloads.len(),
                maximum: context.max_message_len,
            });
        }
        context.validation_level = ValidationLevel::Strict;
        if context.unknown_ie_policy == UnknownIePolicy::Reject {
            context.unknown_ie_policy = UnknownIePolicy::Preserve;
        }

        let terminal = self.decode_terminal(first_payload, cleartext_payloads, context)?;
        self.terminal_committed = true;
        match terminal {
            DecodedTerminal::Success(response) => Ok(response),
            DecodedTerminal::PeerError(error) => {
                Err(Ikev2ChildSaRekeyResponseError::PeerErrorNotify(error))
            }
        }
    }

    fn decode_terminal<'a>(
        &self,
        first_payload: PayloadType,
        cleartext_payloads: &'a [u8],
        context: DecodeContext,
    ) -> Result<DecodedTerminal<'a>, Ikev2ChildSaRekeyResponseError> {
        let mut parts = ResponseParts::default();
        for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
            let raw = raw.map_err(|error| match error.code() {
                DecodeErrorCode::UnknownCriticalIe => {
                    Ikev2ChildSaRekeyResponseError::UnknownCriticalPayload
                }
                _ => Ikev2ChildSaRekeyResponseError::PayloadChain,
            })?;
            match raw.payload_type {
                PayloadType::SecurityAssociation => set_once(
                    &mut parts.security_association,
                    Ikev2SaPayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::SecurityAssociation)?,
                    Ikev2ChildSaRekeyResponsePayloadRole::SecurityAssociation,
                )?,
                PayloadType::Nonce => set_once(
                    &mut parts.nonce,
                    Ikev2NoncePayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::Nonce)?,
                    Ikev2ChildSaRekeyResponsePayloadRole::Nonce,
                )?,
                PayloadType::KeyExchange => set_once(
                    &mut parts.key_exchange,
                    Ikev2KeyExchangePayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::KeyExchange)?,
                    Ikev2ChildSaRekeyResponsePayloadRole::KeyExchange,
                )?,
                PayloadType::TrafficSelectorInitiator => set_once(
                    &mut parts.traffic_selectors_initiator,
                    Ikev2TrafficSelectorPayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?,
                    Ikev2ChildSaRekeyResponsePayloadRole::TrafficSelectorsInitiator,
                )?,
                PayloadType::TrafficSelectorResponder => set_once(
                    &mut parts.traffic_selectors_responder,
                    Ikev2TrafficSelectorPayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::TrafficSelectors)?,
                    Ikev2ChildSaRekeyResponsePayloadRole::TrafficSelectorsResponder,
                )?,
                PayloadType::Notify => {
                    let notify = Ikev2NotifyPayload::decode(raw)
                        .map_err(Ikev2ChildSaRekeyResponseError::Notify)?;
                    if notify.notify_message_type == IKEV2_NOTIFY_REKEY_SA {
                        return Err(Ikev2ChildSaRekeyResponseError::RekeySaNotifyProhibited);
                    }
                    if notify.notify_message_type < IKEV2_ERROR_NOTIFY_MAX_EXCLUSIVE {
                        set_once(
                            &mut parts.peer_error,
                            notify,
                            Ikev2ChildSaRekeyResponsePayloadRole::ErrorNotify,
                        )?;
                    } else {
                        preserve_notify(
                            &mut parts.unrecognized_notifies,
                            notify,
                            context.unknown_ie_policy,
                        );
                    }
                }
                PayloadType::VendorId => parts.vendor_ids.push(Ikev2VendorIdPayload {
                    vendor_id: raw.body,
                }),
                PayloadType::Unknown(payload_type) => preserve_unknown(
                    &mut parts.unknown_noncritical_payloads,
                    payload_type,
                    raw.body,
                    context.unknown_ie_policy,
                ),
                payload_type => {
                    return Err(Ikev2ChildSaRekeyResponseError::UnexpectedPayloadType {
                        payload_type: payload_type.as_u8(),
                    });
                }
            }
        }

        if let Some(peer_error) = parts.peer_error.as_ref() {
            if parts.has_any_success_payload() {
                return Err(Ikev2ChildSaRekeyResponseError::ErrorResponseMixedWithPayloads);
            }
            return Ok(DecodedTerminal::PeerError(validate_peer_error_notify(
                peer_error, self,
            )?));
        }

        let security_association = required(
            parts.security_association,
            Ikev2ChildSaRekeyResponsePayloadRole::SecurityAssociation,
        )?;
        let nonce = required(parts.nonce, Ikev2ChildSaRekeyResponsePayloadRole::Nonce)?;
        let traffic_selectors_initiator = required(
            parts.traffic_selectors_initiator,
            Ikev2ChildSaRekeyResponsePayloadRole::TrafficSelectorsInitiator,
        )?;
        let traffic_selectors_responder = required(
            parts.traffic_selectors_responder,
            Ikev2ChildSaRekeyResponsePayloadRole::TrafficSelectorsResponder,
        )?;

        let request_sa = Ikev2SaPayload::decode_body(&self.request_sa_body)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        let request_tsi = Ikev2TrafficSelectorPayload::decode_body(&self.request_tsi_body)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        let request_tsr = Ikev2TrafficSelectorPayload::decode_body(&self.request_tsr_body)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        let current_tsi = Ikev2TrafficSelectorPayload::decode_body(&self.current_tsi_body)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        let current_tsr = Ikev2TrafficSelectorPayload::decode_body(&self.current_tsr_body)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;

        let selection =
            validate_response_proposal(&request_sa, &security_association, self.ike_sa_prf)?;
        validate_key_exchange(
            self.request_key_exchange_group,
            parts.key_exchange.as_ref(),
            selection.pfs_group,
        )?;
        let minimum_nonce_len = prf_nonce_minimum(self.ike_sa_prf);
        if nonce.nonce.len() < minimum_nonce_len {
            return Err(
                Ikev2ChildSaRekeyResponseError::ResponderNonceTooShortForPrf {
                    actual: nonce.nonce.len(),
                    minimum: minimum_nonce_len,
                },
            );
        }
        if traffic_selectors_initiator.selectors.is_empty()
            || !traffic_selector_payload_is_narrowed(&request_tsi, &traffic_selectors_initiator)
        {
            return Err(Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorsNotOffered);
        }
        if traffic_selectors_responder.selectors.is_empty()
            || !traffic_selector_payload_is_narrowed(&request_tsr, &traffic_selectors_responder)
        {
            return Err(Ikev2ChildSaRekeyResponseError::ResponderTrafficSelectorsNotOffered);
        }
        if !traffic_selector_payload_is_narrowed(&traffic_selectors_initiator, &current_tsi) {
            return Err(
                Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorsNarrowerThanCurrent,
            );
        }
        if !traffic_selector_payload_is_narrowed(&traffic_selectors_responder, &current_tsr) {
            return Err(
                Ikev2ChildSaRekeyResponseError::ResponderTrafficSelectorsNarrowerThanCurrent,
            );
        }

        Ok(DecodedTerminal::Success(Ikev2ChildSaRekeyResponse {
            replacement_initiator_spi: selection.replacement_initiator_spi,
            replacement_responder_spi: selection.replacement_responder_spi,
            profile: selection.profile,
            pfs_group: selection.pfs_group,
            extended_sequence_numbers: selection.extended_sequence_numbers,
            nonce,
            key_exchange: parts.key_exchange,
            traffic_selectors_initiator,
            traffic_selectors_responder,
            vendor_ids: parts.vendor_ids,
            unrecognized_notifies: parts.unrecognized_notifies,
            unknown_noncritical_payloads: parts.unknown_noncritical_payloads,
        }))
    }
}

impl fmt::Debug for Ikev2ChildSaRekeyResponseBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaRekeyResponseBoundary")
            .field("request_message_id", &self.request_message_id)
            .field("ike_sa_prf", &self.ike_sa_prf)
            .field("initiator_nonce_len", &self.initiator_nonce.len())
            .field(
                "request_key_exchange_present",
                &self.request_key_exchange_group.is_some(),
            )
            .field("terminal_committed", &self.terminal_committed)
            .finish_non_exhaustive()
    }
}

enum DecodedTerminal<'a> {
    Success(Ikev2ChildSaRekeyResponse<'a>),
    PeerError(Ikev2ChildSaRekeyPeerError),
}

#[derive(Default)]
struct ResponseParts<'a> {
    security_association: Option<Ikev2SaPayload<'a>>,
    nonce: Option<Ikev2NoncePayload<'a>>,
    key_exchange: Option<Ikev2KeyExchangePayload<'a>>,
    traffic_selectors_initiator: Option<Ikev2TrafficSelectorPayload<'a>>,
    traffic_selectors_responder: Option<Ikev2TrafficSelectorPayload<'a>>,
    peer_error: Option<Ikev2NotifyPayload<'a>>,
    vendor_ids: Vec<Ikev2VendorIdPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
}

impl ResponseParts<'_> {
    fn has_any_success_payload(&self) -> bool {
        self.security_association.is_some()
            || self.nonce.is_some()
            || self.key_exchange.is_some()
            || self.traffic_selectors_initiator.is_some()
            || self.traffic_selectors_responder.is_some()
    }
}

fn validate_request_header(request_header: &Header) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if request_header.exchange_type != EXCHANGE_TYPE_CREATE_CHILD_SA
        || request_header.flags.response()
        || !outer_payload_is_encrypted(request_header.next_payload)
        || request_header.initiator_spi == 0
        || request_header.responder_spi == 0
    {
        return Err(Ikev2ChildSaRekeyResponseError::RequestHeaderInvalid);
    }
    Ok(())
}

fn validate_response_header(
    response_header: &Header,
    boundary: &Ikev2ChildSaRekeyResponseBoundary,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if response_header.exchange_type != EXCHANGE_TYPE_CREATE_CHILD_SA {
        return Err(Ikev2ChildSaRekeyResponseError::WrongExchangeType {
            actual: response_header.exchange_type,
        });
    }
    if !response_header.flags.response() {
        return Err(Ikev2ChildSaRekeyResponseError::ResponseFlagMissing);
    }
    if !outer_payload_is_encrypted(response_header.next_payload) {
        return Err(Ikev2ChildSaRekeyResponseError::OuterPayloadNotEncrypted {
            actual: response_header.next_payload,
        });
    }
    if response_header.initiator_spi != boundary.old_initiator_spi
        || response_header.responder_spi != boundary.old_responder_spi
    {
        return Err(Ikev2ChildSaRekeyResponseError::IkeSpiMismatch);
    }
    if response_header.message_id != boundary.request_message_id {
        return Err(Ikev2ChildSaRekeyResponseError::MessageIdMismatch);
    }
    if response_header.flags.initiator() == boundary.request_initiator_flag {
        return Err(Ikev2ChildSaRekeyResponseError::InitiatorFlagMismatch);
    }
    Ok(())
}

fn outer_payload_is_encrypted(next_payload: u8) -> bool {
    matches!(
        PayloadType::from_u8(next_payload),
        PayloadType::Encrypted | PayloadType::EncryptedFragment
    )
}

fn validate_request_offer(
    request: &Ikev2CreateChildSaRekeyRequestBuild,
    request_sa: &Ikev2SaPayload<'_>,
    request_tsi: &Ikev2TrafficSelectorPayload<'_>,
    request_tsr: &Ikev2TrafficSelectorPayload<'_>,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if request.rekeyed_protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP
        || request.rekeyed_spi.len() != IKEV2_ESP_SPI_LEN
        || request.rekeyed_spi.iter().all(|octet| *octet == 0)
        || request_tsi.selectors.is_empty()
        || request_tsr.selectors.is_empty()
        || request_sa.proposals.len() != request.security_association.proposals.len()
    {
        return Err(Ikev2ChildSaRekeyResponseError::RequestOfferInvalid);
    }

    for (index, (build, proposal)) in request
        .security_association
        .proposals
        .iter()
        .zip(&request_sa.proposals)
        .enumerate()
    {
        let expected_number = u8::try_from(index + 1)
            .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
        if build.proposal_number != expected_number
            || proposal.proposal_number != expected_number
            || build.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP
            || proposal.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP
            || build.spi.len() != IKEV2_ESP_SPI_LEN
            || build.spi.iter().all(|octet| *octet == 0)
        {
            return Err(Ikev2ChildSaRekeyResponseError::RequestOfferInvalid);
        }
    }

    if let Some(key_exchange) = &request.key_exchange {
        let group = Ikev2DhGroup::from_transform_id(key_exchange.dh_group)
            .map_err(Ikev2ChildSaRekeyResponseError::RequestKeyExchangeInvalid)?;
        validate_dh_public_value(group, &key_exchange.key_exchange_data)
            .map_err(Ikev2ChildSaRekeyResponseError::RequestKeyExchangeInvalid)?;
    }
    Ok(())
}

struct ValidatedChildSaSelection {
    replacement_initiator_spi: [u8; IKEV2_ESP_SPI_LEN],
    replacement_responder_spi: [u8; IKEV2_ESP_SPI_LEN],
    profile: Ikev2ChildSaCryptoProfile,
    pfs_group: Option<Ikev2DhGroup>,
    extended_sequence_numbers: bool,
}

fn validate_response_proposal(
    request_sa: &Ikev2SaPayload<'_>,
    response_sa: &Ikev2SaPayload<'_>,
    ike_sa_prf: Ikev2PrfAlgorithm,
) -> Result<ValidatedChildSaSelection, Ikev2ChildSaRekeyResponseError> {
    let selected = match response_sa.proposals.as_slice() {
        [proposal] => proposal,
        proposals => {
            return Err(Ikev2ChildSaRekeyResponseError::ProposalCountInvalid {
                actual: proposals.len(),
            });
        }
    };
    if selected.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP {
        return Err(Ikev2ChildSaRekeyResponseError::ProposalProtocolNotEsp {
            actual: selected.protocol_id,
        });
    }
    let offered = request_sa
        .proposals
        .iter()
        .find(|proposal| {
            proposal.proposal_number == selected.proposal_number
                && proposal.protocol_id == selected.protocol_id
        })
        .ok_or(Ikev2ChildSaRekeyResponseError::ProposalNotOffered)?;

    if usize::from(selected.spi_size) != IKEV2_ESP_SPI_LEN
        || selected.spi.len() != IKEV2_ESP_SPI_LEN
    {
        return Err(
            Ikev2ChildSaRekeyResponseError::ReplacementSpiLengthInvalid {
                actual: selected.spi.len(),
            },
        );
    }
    if selected.spi.iter().all(|octet| *octet == 0) {
        return Err(Ikev2ChildSaRekeyResponseError::ReplacementSpiZero);
    }
    validate_sa_view(response_sa, true)
        .map_err(|_| Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid)?;
    validate_selected_proposal(offered, selected)
        .map_err(|_| Ikev2ChildSaRekeyResponseError::ProposalNotOffered)?;

    let replacement_initiator_spi = <[u8; IKEV2_ESP_SPI_LEN]>::try_from(offered.spi)
        .map_err(|_| Ikev2ChildSaRekeyResponseError::RequestOfferInvalid)?;
    let replacement_spi = <[u8; IKEV2_ESP_SPI_LEN]>::try_from(selected.spi).map_err(|_| {
        Ikev2ChildSaRekeyResponseError::ReplacementSpiLengthInvalid {
            actual: selected.spi.len(),
        }
    })?;

    let encryption_transform = selected
        .transforms
        .iter()
        .find(|transform| transform.transform_type == IKEV2_TRANSFORM_TYPE_ENCR)
        .ok_or(Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid)?;
    let encryption = Ikev2EncryptionAlgorithm::from_sa_transform(encryption_transform)
        .map_err(Ikev2ChildSaRekeyResponseError::Profile)?;
    let integrity = selected
        .transforms
        .iter()
        .find(|transform| transform.transform_type == IKEV2_TRANSFORM_TYPE_INTEG)
        .map(|transform| Ikev2IntegrityAlgorithm::from_transform_id(transform.transform_id))
        .transpose()
        .map_err(Ikev2ChildSaRekeyResponseError::Profile)?;
    let profile = match integrity {
        Some(integrity) => {
            Ikev2ChildSaCryptoProfile::new_encrypt_then_mac(ike_sa_prf, encryption, integrity)
        }
        None => Ikev2ChildSaCryptoProfile::new_aead(ike_sa_prf, encryption),
    };
    profile
        .validate_executable()
        .map_err(Ikev2ChildSaRekeyResponseError::Profile)?;

    let pfs_group = selected
        .transforms
        .iter()
        .find(|transform| transform.transform_type == IKEV2_TRANSFORM_TYPE_DH)
        .and_then(|transform| {
            (transform.transform_id != IKEV2_TRANSFORM_ID_NONE).then_some(transform.transform_id)
        })
        .map(Ikev2DhGroup::from_transform_id)
        .transpose()
        .map_err(Ikev2ChildSaRekeyResponseError::Profile)?;

    let extended_sequence_numbers = selected.transforms.iter().any(|transform| {
        transform.transform_type == IKEV2_TRANSFORM_TYPE_ESN
            && transform.transform_id == IKEV2_TRANSFORM_ID_ESN
    });

    Ok(ValidatedChildSaSelection {
        replacement_initiator_spi,
        replacement_responder_spi: replacement_spi,
        profile,
        pfs_group,
        extended_sequence_numbers,
    })
}

fn validate_key_exchange(
    request_group: Option<u16>,
    response: Option<&Ikev2KeyExchangePayload<'_>>,
    selected_group: Option<Ikev2DhGroup>,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    validate_selected_key_exchange(
        request_group,
        response,
        selected_group.map(Ikev2DhGroup::transform_id),
    )
    .map_err(|error| match error {
        Ikev2SelectedKeyExchangeError::Unexpected => {
            Ikev2ChildSaRekeyResponseError::KeyExchangeUnexpected
        }
        Ikev2SelectedKeyExchangeError::Required => {
            Ikev2ChildSaRekeyResponseError::KeyExchangeRequired
        }
        Ikev2SelectedKeyExchangeError::GroupMismatch => {
            Ikev2ChildSaRekeyResponseError::KeyExchangeGroupMismatch
        }
    })?;
    match (selected_group, response) {
        (Some(group), Some(response)) => {
            validate_dh_public_value(group, response.key_exchange_data)
                .map_err(Ikev2ChildSaRekeyResponseError::KeyExchangeValueInvalid)
        }
        _ => Ok(()),
    }
}

fn validate_peer_error_notify(
    notify: &Ikev2NotifyPayload<'_>,
    boundary: &Ikev2ChildSaRekeyResponseBoundary,
) -> Result<Ikev2ChildSaRekeyPeerError, Ikev2ChildSaRekeyResponseError> {
    use Ikev2ChildSaRekeyPeerErrorInvalidReason as InvalidReason;

    let mut suggested_dh_group = None;
    let kind = match notify.notify_message_type {
        IKEV2_NOTIFY_INVALID_SYNTAX => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::InvalidSyntax
        }
        IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::NoProposalChosen
        }
        IKEV2_NOTIFY_INVALID_KE_PAYLOAD => {
            if boundary.request_key_exchange_group.is_none() {
                return Err(invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::RequestContext,
                ));
            }
            validate_empty_spi(notify)?;
            let group_bytes: [u8; 2] = notify.notification_data.try_into().map_err(|_| {
                invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::NotificationDataShape,
                )
            })?;
            let group = u16::from_be_bytes(group_bytes);
            if group == 0 {
                return Err(invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::NotificationDataValue,
                ));
            }
            suggested_dh_group = Some(group);
            Ikev2ChildSaRekeyPeerErrorKind::InvalidKePayload
        }
        IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::SinglePairRequired
        }
        IKEV2_NOTIFY_NO_ADDITIONAL_SAS => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::NoAdditionalSas
        }
        IKEV2_NOTIFY_TS_UNACCEPTABLE => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::TrafficSelectorsUnacceptable
        }
        IKEV2_NOTIFY_TEMPORARY_FAILURE => {
            validate_empty_spi(notify)?;
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::TemporaryFailure
        }
        IKEV2_NOTIFY_CHILD_SA_NOT_FOUND => {
            if notify.protocol_id != boundary.rekeyed_protocol_id {
                return Err(invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::ProtocolId,
                ));
            }
            if notify.spi.len() != IKEV2_ESP_SPI_LEN {
                return Err(invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::SpiShape,
                ));
            }
            if notify.spi != boundary.rekeyed_spi {
                return Err(invalid_peer_error_notify(
                    notify.notify_message_type,
                    InvalidReason::SpiMismatch,
                ));
            }
            validate_empty_notification_data(notify)?;
            Ikev2ChildSaRekeyPeerErrorKind::ChildSaNotFound
        }
        IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD
        | IKEV2_NOTIFY_INVALID_IKE_SPI
        | IKEV2_NOTIFY_INVALID_MAJOR_VERSION
        | IKEV2_NOTIFY_INVALID_MESSAGE_ID
        | IKEV2_NOTIFY_INVALID_SPI
        | IKEV2_NOTIFY_AUTHENTICATION_FAILED
        | IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE
        | IKEV2_NOTIFY_FAILED_CP_REQUIRED
        | IKEV2_NOTIFY_INVALID_SELECTORS
        | IKEV2_NOTIFY_AUTHORIZATION_REJECTED => {
            return Err(invalid_peer_error_notify(
                notify.notify_message_type,
                InvalidReason::TypeNotAllowed,
            ));
        }
        _ => Ikev2ChildSaRekeyPeerErrorKind::Unknown,
    };
    Ok(Ikev2ChildSaRekeyPeerError {
        kind,
        notify_message_type: notify.notify_message_type,
        protocol_id: notify.protocol_id,
        spi: notify.spi.to_vec(),
        notification_data: notify.notification_data.to_vec(),
        suggested_dh_group,
    })
}

fn validate_empty_spi(
    notify: &Ikev2NotifyPayload<'_>,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if notify.spi.is_empty() {
        Ok(())
    } else {
        Err(invalid_peer_error_notify(
            notify.notify_message_type,
            Ikev2ChildSaRekeyPeerErrorInvalidReason::SpiShape,
        ))
    }
}

fn validate_empty_notification_data(
    notify: &Ikev2NotifyPayload<'_>,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if notify.notification_data.is_empty() {
        Ok(())
    } else {
        Err(invalid_peer_error_notify(
            notify.notify_message_type,
            Ikev2ChildSaRekeyPeerErrorInvalidReason::NotificationDataShape,
        ))
    }
}

fn invalid_peer_error_notify(
    notify_message_type: u16,
    reason: Ikev2ChildSaRekeyPeerErrorInvalidReason,
) -> Ikev2ChildSaRekeyResponseError {
    Ikev2ChildSaRekeyResponseError::InvalidPeerErrorNotify {
        notify_message_type,
        reason,
    }
}

fn prf_nonce_minimum(ike_sa_prf: Ikev2PrfAlgorithm) -> usize {
    ike_sa_prf.output_len().div_ceil(2)
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    role: Ikev2ChildSaRekeyResponsePayloadRole,
) -> Result<(), Ikev2ChildSaRekeyResponseError> {
    if slot.is_some() {
        return Err(Ikev2ChildSaRekeyResponseError::DuplicatePayload { role });
    }
    *slot = Some(value);
    Ok(())
}

fn required<T>(
    value: Option<T>,
    role: Ikev2ChildSaRekeyResponsePayloadRole,
) -> Result<T, Ikev2ChildSaRekeyResponseError> {
    value.ok_or(Ikev2ChildSaRekeyResponseError::MissingPayload { role })
}

fn preserve_unknown<'a>(
    output: &mut Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    payload_type: u8,
    body: &'a [u8],
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => {
            output.push(Ikev2UnknownNonCriticalPayload { payload_type, body });
        }
        UnknownIePolicy::Drop => {}
    }
}

fn preserve_notify<'a>(
    output: &mut Vec<Ikev2NotifyPayload<'a>>,
    notify: Ikev2NotifyPayload<'a>,
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => {
            output.push(notify);
        }
        UnknownIePolicy::Drop => {}
    }
}
