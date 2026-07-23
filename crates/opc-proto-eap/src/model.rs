use std::fmt;

use crate::EapAkaError;

/// EAP-AKA method packet header length in octets.
pub const EAP_AKA_HEADER_LEN: usize = 8;
/// Maximum number of top-level attributes accepted by the projection parser.
pub const EAP_AKA_MAX_ATTRIBUTES: usize = 256;
/// Maximum number of AT_KDF attributes retained as bounded numeric evidence.
pub const EAP_AKA_MAX_KDF_ATTRIBUTES: usize = 16;

/// EAP Request/Response direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapCode {
    /// EAP Request (Code 1).
    Request,
    /// EAP Response (Code 2).
    Response,
}

impl EapCode {
    /// Return the EAP wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
        }
    }
}

/// Supported AKA-family EAP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapAkaMethod {
    /// EAP-AKA, Type 23.
    Aka,
    /// EAP-AKA-prime, Type 50.
    AkaPrime,
}

impl EapAkaMethod {
    /// Return the EAP method Type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Aka => 23,
            Self::AkaPrime => 50,
        }
    }
}

/// AKA-family method subtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapAkaSubtype {
    /// AKA Challenge, subtype 1.
    Challenge,
    /// AKA Authentication-Reject, subtype 2.
    AuthenticationReject,
    /// AKA Synchronization-Failure, subtype 4.
    SynchronizationFailure,
    /// AKA Identity, subtype 5.
    Identity,
    /// AKA Notification, subtype 12.
    Notification,
    /// AKA Reauthentication, subtype 13.
    Reauthentication,
    /// AKA Client-Error, subtype 14.
    ClientError,
}

impl EapAkaSubtype {
    /// Return the AKA subtype wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Challenge => 1,
            Self::AuthenticationReject => 2,
            Self::SynchronizationFailure => 4,
            Self::Identity => 5,
            Self::Notification => 12,
            Self::Reauthentication => 13,
            Self::ClientError => 14,
        }
    }
}

/// Identity class requested by an AKA Identity Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapAkaIdentityRequest {
    /// Permanent identity only.
    Permanent,
    /// Any suitable identity.
    Any,
    /// Permanent or pseudonym full-authentication identity.
    FullAuthentication,
}

/// Notification phase encoded by the RFC 4187 P bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapAkaNotificationPhase {
    /// After successful Challenge or Reauthentication; P=0.
    AfterAuthentication,
    /// Before Challenge or Reauthentication; P=1 and failure-only.
    BeforeAuthentication,
}

/// Bounded ordered EAP-AKA-prime AT_KDF values.
///
/// KDF identifiers are numeric protocol metadata, not key material. Retaining
/// this list lets a stateful caller verify re-offers and synchronization
/// copies without reparsing private Type-Data.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaKdfList {
    pub(crate) values: [u16; EAP_AKA_MAX_KDF_ATTRIBUTES],
    pub(crate) len: u8,
}

impl EapAkaKdfList {
    /// Return the number of ordered KDF identifiers.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Return whether the list is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Return the leading preferred/candidate KDF identifier.
    ///
    /// This is not a selection verdict until the exchange is correlated.
    #[must_use]
    pub const fn preferred(self) -> Option<u16> {
        if self.len == 0 {
            None
        } else {
            Some(self.values[0])
        }
    }

    /// Borrow all ordered KDF identifiers.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.values[..usize::from(self.len)]
    }
}

impl fmt::Debug for EapAkaKdfList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EapAkaKdfList")
            .field(&self.as_slice())
            .finish()
    }
}

/// Redaction-safe structural evidence for an AKA Challenge Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaChallengeRequestEvidence {
    pub(crate) kdfs: EapAkaKdfList,
    pub(crate) kdf_reoffer_shape: bool,
    pub(crate) kdf_input_present: bool,
    pub(crate) result_indication_present: bool,
    pub(crate) encrypted_data_present: bool,
    pub(crate) bidding_supports_aka_prime: Option<bool>,
}

impl EapAkaChallengeRequestEvidence {
    /// Return the number of ordered AT_KDF offers.
    #[must_use]
    pub const fn kdf_count(self) -> u8 {
        self.kdfs.len
    }

    /// Return the ordered bounded KDF list.
    #[must_use]
    pub const fn kdfs(self) -> EapAkaKdfList {
        self.kdfs
    }

    /// Return the leading preferred/candidate KDF number, if present.
    ///
    /// An initial offer is not selected, and even a server re-offer remains a
    /// stateless candidate until correlated with the peer response.
    #[must_use]
    pub const fn preferred_kdf(self) -> Option<u16> {
        self.kdfs.preferred()
    }

    /// Return whether the KDF list has the only locally recognizable legal
    /// duplicate shape for a server re-offer.
    ///
    /// A stateless parser cannot prove that a peer requested this re-offer.
    #[must_use]
    pub const fn has_kdf_reoffer_shape(self) -> bool {
        self.kdf_reoffer_shape
    }

    /// Return whether AT_KDF_INPUT is present.
    ///
    /// The network-name value is deliberately not exposed.
    #[must_use]
    pub const fn has_kdf_input(self) -> bool {
        self.kdf_input_present
    }

    /// Return whether protected-result negotiation was requested.
    #[must_use]
    pub const fn has_result_indication(self) -> bool {
        self.result_indication_present
    }

    /// Return whether paired AT_IV and AT_ENCR_DATA are present.
    #[must_use]
    pub const fn has_encrypted_data(self) -> bool {
        self.encrypted_data_present
    }

    /// Return the EAP-AKA AT_BIDDING D bit, if AT_BIDDING is present.
    ///
    /// Presence is structural evidence only and is not a downgrade-protection
    /// verdict because the AT_MAC has not been verified here.
    #[must_use]
    pub const fn bidding_supports_aka_prime(self) -> Option<bool> {
        self.bidding_supports_aka_prime
    }
}

/// Redaction-safe structural evidence for a complete Challenge Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaFullChallengeResponseEvidence {
    pub(crate) result_indication_present: bool,
    pub(crate) encrypted_data_present: bool,
}

impl EapAkaFullChallengeResponseEvidence {
    /// Return whether this response carries AT_RESULT_IND.
    ///
    /// The preceding request must be correlated before interpreting this as
    /// accepted protected-result negotiation.
    #[must_use]
    pub const fn has_result_indication(self) -> bool {
        self.result_indication_present
    }

    /// Return whether paired AT_IV and AT_ENCR_DATA are present.
    #[must_use]
    pub const fn has_encrypted_data(self) -> bool {
        self.encrypted_data_present
    }
}

/// Redaction-safe structural evidence for an AKA-prime KDF negotiation reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaKdfNegotiationEvidence {
    pub(crate) claimed_kdf: u16,
}

impl EapAkaKdfNegotiationEvidence {
    /// Return the peer's claimed alternative KDF number.
    ///
    /// The preceding KDF offer must be correlated before interpreting this
    /// structural value as a valid selection.
    #[must_use]
    pub const fn claimed_kdf(self) -> u16 {
        self.claimed_kdf
    }
}

/// Redaction-safe structural evidence for an AKA Notification Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaNotificationEvidence {
    pub(crate) code: u16,
    pub(crate) phase: EapAkaNotificationPhase,
    pub(crate) failure: bool,
    pub(crate) encrypted_data_present: bool,
}

impl EapAkaNotificationEvidence {
    /// Return the numeric notification code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.code
    }

    /// Return the phase encoded by the P bit.
    #[must_use]
    pub const fn phase(self) -> EapAkaNotificationPhase {
        self.phase
    }

    /// Return whether the S bit marks the notification as failure.
    #[must_use]
    pub const fn indicates_failure(self) -> bool {
        self.failure
    }

    /// Return whether paired AT_IV and AT_ENCR_DATA are present.
    ///
    /// Interpreting the encrypted contents requires method keys and exchange
    /// state.
    #[must_use]
    pub const fn has_encrypted_data(self) -> bool {
        self.encrypted_data_present
    }

    /// Return whether this is the structurally protected Success code.
    ///
    /// This does not prove MAC validity or the prior two-sided
    /// AT_RESULT_IND negotiation required to use code 32768.
    #[must_use]
    pub fn is_protected_success_candidate(self) -> bool {
        self.code == 32_768 && self.phase == EapAkaNotificationPhase::AfterAuthentication
    }
}

/// Redaction-safe structural evidence for a Notification acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EapAkaNotificationAckEvidence {
    pub(crate) mac_present: bool,
    pub(crate) encrypted_data_present: bool,
}

impl EapAkaNotificationAckEvidence {
    /// Return whether AT_MAC is present.
    ///
    /// Correlation with the preceding Notification Request is required to
    /// decide whether its phase required or prohibited a MAC.
    #[must_use]
    pub const fn has_mac(self) -> bool {
        self.mac_present
    }

    /// Return whether paired AT_IV and AT_ENCR_DATA are present.
    ///
    /// A stateless response cannot infer the preceding request's P bit.
    #[must_use]
    pub const fn has_encrypted_data(self) -> bool {
        self.encrypted_data_present
    }
}

/// Redaction-safe packet-specific structural evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapAkaPacketKind {
    /// Full-authentication Challenge Request shape.
    ChallengeRequest(EapAkaChallengeRequestEvidence),
    /// Challenge Response with the required AT_RES and AT_MAC shape.
    FullChallengeResponse(EapAkaFullChallengeResponseEvidence),
    /// AKA-prime Challenge Response containing one claimed alternative AT_KDF.
    AkaPrimeKdfNegotiationResponse(EapAkaKdfNegotiationEvidence),
    /// Authentication-Reject Response.
    AuthenticationReject,
    /// Synchronization-Failure Response and its carried AKA-prime KDF list.
    SynchronizationFailure {
        /// Ordered carried AT_KDF list; empty for EAP-AKA.
        kdfs: EapAkaKdfList,
        /// Whether the carried list has a locally legal server-reoffer shape.
        kdf_reoffer_shape: bool,
    },
    /// Identity Request.
    IdentityRequest {
        /// Mutually exclusive requested identity class.
        requested: EapAkaIdentityRequest,
    },
    /// Identity Response containing one AT_IDENTITY.
    IdentityResponse,
    /// Notification Request.
    NotificationRequest(EapAkaNotificationEvidence),
    /// Notification Response/acknowledgement.
    NotificationResponse(EapAkaNotificationAckEvidence),
    /// Fast Reauthentication Request outer protected envelope.
    ReauthenticationRequest {
        /// Whether protected-result negotiation was requested.
        result_indication_present: bool,
    },
    /// Fast Reauthentication Response outer protected envelope.
    ReauthenticationResponse {
        /// Whether this response carries AT_RESULT_IND.
        ///
        /// Correlation with the preceding request is required before treating
        /// this as accepted protected-result negotiation.
        result_indication_present: bool,
    },
    /// Client-Error Response.
    ClientError {
        /// Numeric client error code.
        code: u16,
    },
}

/// Strict borrowed projection of a complete EAP-AKA method packet.
///
/// The source packet is borrowed privately so parsing is allocation-free. No
/// raw-packet or attribute-value accessor exists. [`Debug`](fmt::Debug)
/// reports only bounded structural metadata.
#[derive(Clone, Copy)]
pub struct EapAkaPacket<'a> {
    pub(crate) packet: &'a [u8],
    pub(crate) code: EapCode,
    pub(crate) identifier: u8,
    pub(crate) method: EapAkaMethod,
    pub(crate) subtype: EapAkaSubtype,
    pub(crate) attribute_count: u16,
    pub(crate) unknown_skippable_count: u16,
    pub(crate) kind: EapAkaPacketKind,
}

impl<'a> EapAkaPacket<'a> {
    /// Parse and strictly validate a complete EAP-AKA or EAP-AKA-prime packet.
    pub fn parse(packet: &'a [u8]) -> Result<Self, EapAkaError> {
        crate::parser::parse(packet)
    }

    /// Return the Request/Response direction.
    #[must_use]
    pub const fn code(&self) -> EapCode {
        self.code
    }

    /// Return the EAP Identifier.
    #[must_use]
    pub const fn identifier(&self) -> u8 {
        self.identifier
    }

    /// Return the AKA-family method.
    #[must_use]
    pub const fn method(&self) -> EapAkaMethod {
        self.method
    }

    /// Return the method subtype.
    #[must_use]
    pub const fn subtype(&self) -> EapAkaSubtype {
        self.subtype
    }

    /// Return the number of top-level attributes.
    #[must_use]
    pub const fn attribute_count(&self) -> u16 {
        self.attribute_count
    }

    /// Return the number of unrecognized skippable attributes.
    #[must_use]
    pub const fn unknown_skippable_count(&self) -> u16 {
        self.unknown_skippable_count
    }

    /// Return packet-specific redaction-safe structural evidence.
    #[must_use]
    pub const fn kind(&self) -> EapAkaPacketKind {
        self.kind
    }
}

impl fmt::Debug for EapAkaPacket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EapAkaPacket")
            .field("code", &self.code)
            .field("identifier", &self.identifier)
            .field("method", &self.method)
            .field("subtype", &self.subtype)
            .field("packet_len", &self.packet.len())
            .field("attribute_count", &self.attribute_count)
            .field("unknown_skippable_count", &self.unknown_skippable_count)
            .field("kind", &self.kind)
            .finish()
    }
}
