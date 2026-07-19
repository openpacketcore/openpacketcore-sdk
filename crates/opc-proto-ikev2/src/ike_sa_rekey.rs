//! Strict responder boundary for IKE-SA rekey `CREATE_CHILD_SA` exchanges.
//!
//! The decoder operates only on an already-authenticated and opened `SK`
//! payload. It classifies the required RFC 7296 IKE-SA rekey request shape
//! (`SA, Ni, KEi`), preserves forward-compatible Vendor ID, unrecognized
//! Notify, and unknown non-critical payloads, selects an executable IKE-SA
//! profile through the existing product-neutral policy, and builds the exact
//! successful response shape (`SA, Nr, KEr`). It does not open or seal `SK`,
//! allocate SPIs, own IKE-SA lifecycle state, or decide retransmission and
//! collision policy.
//!
//! @spec IETF RFC7296 1.3.2, 2.18, 3.3, 3.4, 3.9
//! @req REQ-IETF-RFC7296-IKE-SA-REKEY-001

use core::fmt;
use std::error::Error;

use bytes::Bytes;
use opc_protocol::{DecodeContext, UnknownIePolicy, ValidationLevel};

use crate::{
    dedicated_bearer::Ikev2UnknownNonCriticalPayload,
    header::{Header, EXCHANGE_TYPE_CREATE_CHILD_SA},
    ike_auth::{
        build_ike_auth_cleartext_payload_chain, build_ike_auth_sa_payload, Ikev2IkeAuthBuildError,
        Ikev2IkeAuthPayloadBuild, IKEV2_SECURITY_PROTOCOL_ID_IKE,
    },
    notify::{Ikev2NotifyPayload, Ikev2NotifyPayloadError, IKEV2_NOTIFY_REKEY_SA},
    payload::{PayloadChain, PayloadType},
    sa_init::{
        encode_ke_payload_build, encode_nonce_payload_build, Ikev2KeyExchangePayload,
        Ikev2KeyExchangePayloadBuild, Ikev2KeyExchangePayloadError, Ikev2NoncePayload,
        Ikev2NoncePayloadBuild, Ikev2NoncePayloadError, Ikev2SaInitBuildError, Ikev2SaInitPayloads,
        Ikev2SaPayload, Ikev2SaPayloadBuild, Ikev2SaPayloadError, Ikev2SaProposal,
        Ikev2SaProposalBuild, Ikev2VendorIdPayload,
    },
    sa_init_crypto::Ikev2SaInitCryptoProfile,
    sa_init_negotiation::{
        negotiate_ike_sa_init, Ikev2SaInitNegotiationError, Ikev2SaInitNegotiationPolicy,
    },
};

const IKEV2_TRANSFORM_TYPE_DH: u8 = 4;
const IKEV2_TRANSFORM_ID_NONE: u16 = 0;

/// IKE SPI size in an IKE-SA rekey Proposal substructure.
pub const IKEV2_REKEY_IKE_SPI_LEN: usize = 8;

/// Stable payload role used by missing and duplicate request diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2IkeSaRekeyPayloadRole {
    /// Security Association payload.
    SecurityAssociation,
    /// Nonce payload.
    Nonce,
    /// Key Exchange payload.
    KeyExchange,
}

impl Ikev2IkeSaRekeyPayloadRole {
    /// Stable machine-readable role name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityAssociation => "security_association",
            Self::Nonce => "nonce",
            Self::KeyExchange => "key_exchange",
        }
    }
}

/// Strict borrowed view of an IKE-SA rekey `CREATE_CHILD_SA` request.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IkeSaRekeyRequest<'a> {
    security_association: Ikev2SaPayload<'a>,
    nonce: Ikev2NoncePayload<'a>,
    key_exchange: Ikev2KeyExchangePayload<'a>,
    vendor_ids: Vec<Ikev2VendorIdPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
}

impl<'a> Ikev2IkeSaRekeyRequest<'a> {
    /// IKE proposals offered by the new IKE-SA initiator.
    pub const fn security_association(&self) -> &Ikev2SaPayload<'a> {
        &self.security_association
    }

    /// New IKE-SA initiator nonce.
    pub const fn nonce(&self) -> &Ikev2NoncePayload<'a> {
        &self.nonce
    }

    /// Mandatory new IKE-SA initiator Diffie-Hellman value.
    pub const fn key_exchange(&self) -> &Ikev2KeyExchangePayload<'a> {
        &self.key_exchange
    }

    /// RFC 7296 Vendor ID payloads retained for extension-aware callers.
    pub fn vendor_ids(&self) -> &[Ikev2VendorIdPayload<'a>] {
        &self.vendor_ids
    }

    /// Notify payloads that are not part of the core IKE-SA rekey shape.
    ///
    /// The default decoder preserves these because RFC 7296 requires
    /// unrecognized request errors and status notifications to be ignored.
    /// Explicit-context callers may select drop behavior. At this protocol
    /// boundary, [`UnknownIePolicy::Reject`] is normalized to preservation so
    /// an RFC-mandated ignored Notify can never reject the request.
    pub fn unrecognized_notifies(&self) -> &[Ikev2NotifyPayload<'a>] {
        &self.unrecognized_notifies
    }

    /// Unknown non-critical payloads retained under preserve policy.
    ///
    /// RFC-mandated ignore semantics normalize
    /// [`UnknownIePolicy::Reject`] to preservation at this boundary. Explicit
    /// [`UnknownIePolicy::Drop`] leaves this collection empty.
    pub fn unknown_noncritical_payloads(&self) -> &[Ikev2UnknownNonCriticalPayload<'a>] {
        &self.unknown_noncritical_payloads
    }
}

impl fmt::Debug for Ikev2IkeSaRekeyRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeSaRekeyRequest")
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("dh_group", &self.key_exchange.dh_group)
            .field(
                "key_exchange_data_len",
                &self.key_exchange.key_exchange_data.len(),
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

/// Stable failure while decoding an opened IKE-SA rekey request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2IkeSaRekeyRequestError {
    /// IKE header exchange type was not `CREATE_CHILD_SA`.
    WrongExchangeType {
        /// Received exchange type.
        actual: u8,
    },
    /// IKE header marked the message as a response.
    ResponseFlagUnexpected,
    /// The outer IKE message did not name an `SK` payload.
    OuterPayloadNotEncrypted {
        /// Received outer payload type value.
        actual: u8,
    },
    /// The established IKE-SA header carried a zero IKE SPI.
    IkeSpiZero,
    /// Opened payload bytes exceeded the configured parser bound.
    MessageTooLarge {
        /// Received opened length.
        actual: usize,
        /// Configured maximum length.
        maximum: usize,
    },
    /// Generic payload-chain decoding failed.
    PayloadChain,
    /// A required payload was missing.
    MissingPayload {
        /// Missing payload role.
        role: Ikev2IkeSaRekeyPayloadRole,
    },
    /// A singleton payload was duplicated.
    DuplicatePayload {
        /// Duplicated payload role.
        role: Ikev2IkeSaRekeyPayloadRole,
    },
    /// A known payload is not valid in the rekey shape.
    UnexpectedPayloadType {
        /// Received payload type value.
        payload_type: u8,
    },
    /// `REKEY_SA` is Child-SA-specific and is prohibited for IKE-SA rekey.
    RekeySaNotifyProhibited,
    /// Proposal numbers were not consecutive from one.
    InvalidProposalNumber {
        /// Received Proposal Number.
        actual: u8,
        /// Required Proposal Number at this position.
        expected: usize,
    },
    /// A proposal selected ESP, AH, or another non-IKE protocol.
    ProposalProtocolNotIke {
        /// Proposal Number containing the invalid Protocol ID.
        proposal_number: u8,
        /// Received Protocol ID.
        actual: u8,
    },
    /// A proposal did not carry an eight-octet IKE SPI.
    ProposalSpiLengthInvalid {
        /// Proposal Number containing the invalid SPI.
        proposal_number: u8,
        /// Redaction-safe received SPI length.
        actual: usize,
    },
    /// A proposal carried the reserved all-zero new IKE SPI.
    ProposalSpiZero {
        /// Proposal Number containing the zero SPI.
        proposal_number: u8,
    },
    /// A proposal used the prohibited `DH=NONE` transform.
    DhNoneProhibited {
        /// Proposal Number containing `DH=NONE`.
        proposal_number: u8,
    },
    /// The KE group was not offered as a non-zero DH transform.
    KeyExchangeDhGroupMismatch {
        /// DH group received in the KE payload.
        received: u16,
    },
    /// Typed SA payload decoding failed.
    SecurityAssociation(Ikev2SaPayloadError),
    /// Typed Nonce payload decoding failed.
    Nonce(Ikev2NoncePayloadError),
    /// Typed KE payload decoding failed.
    KeyExchange(Ikev2KeyExchangePayloadError),
    /// Typed Notify payload decoding failed.
    Notify(Ikev2NotifyPayloadError),
}

impl Ikev2IkeSaRekeyRequestError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WrongExchangeType { .. } => "ike_sa_rekey_exchange_type_wrong",
            Self::ResponseFlagUnexpected => "ike_sa_rekey_response_flag_unexpected",
            Self::OuterPayloadNotEncrypted { .. } => "ike_sa_rekey_outer_payload_not_sk",
            Self::IkeSpiZero => "ike_sa_rekey_ike_spi_zero",
            Self::MessageTooLarge { .. } => "ike_sa_rekey_message_too_large",
            Self::PayloadChain => "ike_sa_rekey_payload_chain_invalid",
            Self::MissingPayload { .. } => "ike_sa_rekey_payload_missing",
            Self::DuplicatePayload { .. } => "ike_sa_rekey_payload_duplicate",
            Self::UnexpectedPayloadType { .. } => "ike_sa_rekey_payload_unexpected",
            Self::RekeySaNotifyProhibited => "ike_sa_rekey_rekey_sa_notify_prohibited",
            Self::InvalidProposalNumber { .. } => "ike_sa_rekey_proposal_number_invalid",
            Self::ProposalProtocolNotIke { .. } => "ike_sa_rekey_proposal_protocol_not_ike",
            Self::ProposalSpiLengthInvalid { .. } => "ike_sa_rekey_proposal_spi_length_invalid",
            Self::ProposalSpiZero { .. } => "ike_sa_rekey_proposal_spi_zero",
            Self::DhNoneProhibited { .. } => "ike_sa_rekey_dh_none_prohibited",
            Self::KeyExchangeDhGroupMismatch { .. } => "ike_sa_rekey_ke_group_mismatch",
            Self::SecurityAssociation(_) => "ike_sa_rekey_sa_invalid",
            Self::Nonce(_) => "ike_sa_rekey_nonce_invalid",
            Self::KeyExchange(_) => "ike_sa_rekey_ke_invalid",
            Self::Notify(_) => "ike_sa_rekey_notify_invalid",
        }
    }
}

impl fmt::Display for Ikev2IkeSaRekeyRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2IkeSaRekeyRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SecurityAssociation(error) => Some(error),
            Self::Nonce(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            Self::Notify(error) => Some(error),
            _ => None,
        }
    }
}

/// Decode a responder-side IKE-SA rekey `CREATE_CHILD_SA` request.
///
/// `cleartext_payloads` must come from a successfully authenticated and opened
/// `SK` payload, and `first_payload` must be the inner payload type carried by
/// that `SK` generic header. This function checks the outer header shape but
/// cannot itself prove that the supplied cleartext was authenticated.
///
/// Conservative parser limits are applied. The required inner chain contains
/// one SA, one Nonce, and one KE payload in any order. The default preserves
/// Vendor IDs, unrecognized Notify payloads, and unknown non-critical payloads
/// for RFC 7296 forward compatibility. `REKEY_SA`, traffic selectors, other
/// semantically invalid known payloads, and unknown critical payloads fail
/// closed.
///
/// # Errors
///
/// Returns [`Ikev2IkeSaRekeyRequestError`] for an invalid header, payload
/// chain, payload cardinality, proposal protocol/SPI, prohibited `DH=NONE`, or
/// KE/DH-group mismatch.
pub fn decode_ike_sa_rekey_request<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2IkeSaRekeyRequest<'a>, Ikev2IkeSaRekeyRequestError> {
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    decode_ike_sa_rekey_request_with_context(header, first_payload, cleartext_payloads, context)
}

/// Decode an IKE-SA rekey request with explicit parser limits.
///
/// Structural validation is always upgraded to strict. The caller-supplied
/// message and IE-count limits remain authoritative. The caller's unknown-IE
/// policy controls preservation or dropping of unknown non-critical payloads
/// and unrecognized Notify types. RFC 7296 requires both classes to be ignored,
/// so [`UnknownIePolicy::Reject`] is deterministically treated as
/// [`UnknownIePolicy::Preserve`] here. Vendor IDs are known standard payloads
/// and are always retained; unknown critical payloads always fail closed.
///
/// # Errors
///
/// Returns the same failures as [`decode_ike_sa_rekey_request`].
pub fn decode_ike_sa_rekey_request_with_context<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
    mut context: DecodeContext,
) -> Result<Ikev2IkeSaRekeyRequest<'a>, Ikev2IkeSaRekeyRequestError> {
    validate_request_header(header)?;
    if cleartext_payloads.len() > context.max_message_len {
        return Err(Ikev2IkeSaRekeyRequestError::MessageTooLarge {
            actual: cleartext_payloads.len(),
            maximum: context.max_message_len,
        });
    }
    context.validation_level = ValidationLevel::Strict;

    let mut security_association = None;
    let mut nonce = None;
    let mut key_exchange = None;
    let mut vendor_ids = Vec::new();
    let mut unrecognized_notifies = Vec::new();
    let mut unknown_noncritical_payloads = Vec::new();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2IkeSaRekeyRequestError::PayloadChain)?;
        match raw.payload_type {
            PayloadType::SecurityAssociation => {
                if security_association.is_some() {
                    return Err(Ikev2IkeSaRekeyRequestError::DuplicatePayload {
                        role: Ikev2IkeSaRekeyPayloadRole::SecurityAssociation,
                    });
                }
                security_association = Some(
                    Ikev2SaPayload::decode(raw)
                        .map_err(Ikev2IkeSaRekeyRequestError::SecurityAssociation)?,
                );
            }
            PayloadType::Nonce => {
                if nonce.is_some() {
                    return Err(Ikev2IkeSaRekeyRequestError::DuplicatePayload {
                        role: Ikev2IkeSaRekeyPayloadRole::Nonce,
                    });
                }
                nonce = Some(
                    Ikev2NoncePayload::decode(raw).map_err(Ikev2IkeSaRekeyRequestError::Nonce)?,
                );
            }
            PayloadType::KeyExchange => {
                if key_exchange.is_some() {
                    return Err(Ikev2IkeSaRekeyRequestError::DuplicatePayload {
                        role: Ikev2IkeSaRekeyPayloadRole::KeyExchange,
                    });
                }
                key_exchange = Some(
                    Ikev2KeyExchangePayload::decode(raw)
                        .map_err(Ikev2IkeSaRekeyRequestError::KeyExchange)?,
                );
            }
            PayloadType::Notify => {
                let notify =
                    Ikev2NotifyPayload::decode(raw).map_err(Ikev2IkeSaRekeyRequestError::Notify)?;
                if notify.notify_message_type == IKEV2_NOTIFY_REKEY_SA {
                    return Err(Ikev2IkeSaRekeyRequestError::RekeySaNotifyProhibited);
                }
                preserve_unrecognized_notify(
                    &mut unrecognized_notifies,
                    notify,
                    context.unknown_ie_policy,
                );
            }
            PayloadType::VendorId => vendor_ids.push(Ikev2VendorIdPayload {
                vendor_id: raw.body,
            }),
            PayloadType::Unknown(payload_type) => preserve_unknown_noncritical(
                &mut unknown_noncritical_payloads,
                payload_type,
                raw.body,
                context.unknown_ie_policy,
            ),
            payload_type => {
                return Err(Ikev2IkeSaRekeyRequestError::UnexpectedPayloadType {
                    payload_type: payload_type.as_u8(),
                });
            }
        }
    }

    let security_association =
        security_association.ok_or(Ikev2IkeSaRekeyRequestError::MissingPayload {
            role: Ikev2IkeSaRekeyPayloadRole::SecurityAssociation,
        })?;
    let nonce = nonce.ok_or(Ikev2IkeSaRekeyRequestError::MissingPayload {
        role: Ikev2IkeSaRekeyPayloadRole::Nonce,
    })?;
    let key_exchange = key_exchange.ok_or(Ikev2IkeSaRekeyRequestError::MissingPayload {
        role: Ikev2IkeSaRekeyPayloadRole::KeyExchange,
    })?;
    validate_request_sa(&security_association, &key_exchange)?;

    Ok(Ikev2IkeSaRekeyRequest {
        security_association,
        nonce,
        key_exchange,
        vendor_ids,
        unrecognized_notifies,
        unknown_noncritical_payloads,
    })
}

fn preserve_unknown_noncritical<'a>(
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

fn preserve_unrecognized_notify<'a>(
    output: &mut Vec<Ikev2NotifyPayload<'a>>,
    notify: Ikev2NotifyPayload<'a>,
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => output.push(notify),
        UnknownIePolicy::Drop => {}
    }
}

fn validate_request_header(header: &Header) -> Result<(), Ikev2IkeSaRekeyRequestError> {
    if header.exchange_type != EXCHANGE_TYPE_CREATE_CHILD_SA {
        return Err(Ikev2IkeSaRekeyRequestError::WrongExchangeType {
            actual: header.exchange_type,
        });
    }
    if header.flags.response() {
        return Err(Ikev2IkeSaRekeyRequestError::ResponseFlagUnexpected);
    }
    if PayloadType::from_u8(header.next_payload) != PayloadType::Encrypted {
        return Err(Ikev2IkeSaRekeyRequestError::OuterPayloadNotEncrypted {
            actual: header.next_payload,
        });
    }
    if header.initiator_spi == 0 || header.responder_spi == 0 {
        return Err(Ikev2IkeSaRekeyRequestError::IkeSpiZero);
    }
    Ok(())
}

fn validate_request_sa(
    security_association: &Ikev2SaPayload<'_>,
    key_exchange: &Ikev2KeyExchangePayload<'_>,
) -> Result<(), Ikev2IkeSaRekeyRequestError> {
    let mut key_exchange_group_offered = false;
    for (index, proposal) in security_association.proposals.iter().enumerate() {
        let expected = index + 1;
        if usize::from(proposal.proposal_number) != expected {
            return Err(Ikev2IkeSaRekeyRequestError::InvalidProposalNumber {
                actual: proposal.proposal_number,
                expected,
            });
        }
        if proposal.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_IKE {
            return Err(Ikev2IkeSaRekeyRequestError::ProposalProtocolNotIke {
                proposal_number: proposal.proposal_number,
                actual: proposal.protocol_id,
            });
        }
        if usize::from(proposal.spi_size) != IKEV2_REKEY_IKE_SPI_LEN
            || proposal.spi.len() != IKEV2_REKEY_IKE_SPI_LEN
        {
            return Err(Ikev2IkeSaRekeyRequestError::ProposalSpiLengthInvalid {
                proposal_number: proposal.proposal_number,
                actual: proposal.spi.len(),
            });
        }
        if proposal.spi.iter().all(|octet| *octet == 0) {
            return Err(Ikev2IkeSaRekeyRequestError::ProposalSpiZero {
                proposal_number: proposal.proposal_number,
            });
        }
        for transform in &proposal.transforms {
            if transform.transform_type == IKEV2_TRANSFORM_TYPE_DH {
                if transform.transform_id == IKEV2_TRANSFORM_ID_NONE {
                    return Err(Ikev2IkeSaRekeyRequestError::DhNoneProhibited {
                        proposal_number: proposal.proposal_number,
                    });
                }
                if transform.transform_id == key_exchange.dh_group {
                    key_exchange_group_offered = true;
                }
            }
        }
    }
    if !key_exchange_group_offered {
        return Err(Ikev2IkeSaRekeyRequestError::KeyExchangeDhGroupMismatch {
            received: key_exchange.dh_group,
        });
    }
    Ok(())
}

/// Selected IKE-SA rekey offer ready for KDF and response construction.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IkeSaRekeyNegotiation {
    profile: Ikev2SaInitCryptoProfile,
    selected_proposal: Ikev2SaProposalBuild,
    new_initiator_spi: [u8; IKEV2_REKEY_IKE_SPI_LEN],
}

impl Ikev2IkeSaRekeyNegotiation {
    /// Executable new IKE-SA profile for `derive_ike_sa_rekey_key_material`.
    pub const fn profile(&self) -> Ikev2SaInitCryptoProfile {
        self.profile
    }

    /// Selected request proposal with the new initiator SPI and exact selected transforms.
    pub const fn selected_proposal(&self) -> &Ikev2SaProposalBuild {
        &self.selected_proposal
    }

    /// New initiator SPI selected from the accepted request proposal.
    pub const fn new_initiator_spi(&self) -> [u8; IKEV2_REKEY_IKE_SPI_LEN] {
        self.new_initiator_spi
    }
}

impl fmt::Debug for Ikev2IkeSaRekeyNegotiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeSaRekeyNegotiation")
            .field("profile", &self.profile)
            .field("selected_proposal", &self.selected_proposal)
            .field("new_initiator_spi_len", &self.new_initiator_spi.len())
            .finish()
    }
}

/// Select one executable IKE-SA rekey proposal through the existing policy.
///
/// The request decoder has already validated the rekey-only SPI and DH shape.
/// This helper applies the same transform-alternative, duplicate, attribute,
/// KE/group, and KE-length checks as IKE_SA_INIT while preserving the selected
/// rekey proposal's new initiator SPI.
///
/// # Errors
///
/// Returns [`Ikev2SaInitNegotiationError`] when policy is invalid, proposals
/// are ambiguous, KE length does not match the selected group, or no complete
/// executable suite is acceptable.
pub fn negotiate_ike_sa_rekey(
    request: &Ikev2IkeSaRekeyRequest<'_>,
    policy: &Ikev2SaInitNegotiationPolicy,
) -> Result<Ikev2IkeSaRekeyNegotiation, Ikev2SaInitNegotiationError> {
    let security_association = Ikev2SaPayload {
        proposals: request
            .security_association
            .proposals
            .iter()
            .map(|proposal| Ikev2SaProposal {
                proposal_number: proposal.proposal_number,
                protocol_id: proposal.protocol_id,
                spi_size: 0,
                spi: &[],
                transforms: proposal.transforms.clone(),
            })
            .collect(),
    };
    let selection_payloads = Ikev2SaInitPayloads {
        security_association,
        key_exchange: request.key_exchange,
        nonce: request.nonce,
        notifies: Vec::new(),
        vendor_ids: Vec::new(),
        other_payload_count: 0,
    };
    let selection = negotiate_ike_sa_init(&selection_payloads, policy)?;
    let selected_number = selection.selected_proposal().proposal_number;
    let selected_offer = request
        .security_association
        .proposals
        .iter()
        .find(|proposal| proposal.proposal_number == selected_number)
        .ok_or(Ikev2SaInitNegotiationError::NoAcceptableProposal)?;

    let mut new_initiator_spi = [0_u8; IKEV2_REKEY_IKE_SPI_LEN];
    if selected_offer.spi.len() != new_initiator_spi.len() {
        return Err(Ikev2SaInitNegotiationError::NoAcceptableProposal);
    }
    new_initiator_spi.copy_from_slice(selected_offer.spi);
    let mut selected_proposal = selection.selected_proposal().clone();
    selected_proposal.spi = new_initiator_spi.to_vec();

    Ok(Ikev2IkeSaRekeyNegotiation {
        profile: selection.profile(),
        selected_proposal,
        new_initiator_spi,
    })
}

/// Builder input for an exact successful IKE-SA rekey response.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IkeSaRekeyResponseBuild {
    /// Previously selected request offer and executable profile.
    pub negotiation: Ikev2IkeSaRekeyNegotiation,
    /// Newly allocated non-zero responder SPI.
    pub new_responder_spi: [u8; IKEV2_REKEY_IKE_SPI_LEN],
    /// New responder nonce.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Mandatory responder Diffie-Hellman value.
    pub key_exchange: Ikev2KeyExchangePayloadBuild,
}

impl fmt::Debug for Ikev2IkeSaRekeyResponseBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeSaRekeyResponseBuild")
            .field("negotiation", &self.negotiation)
            .field("new_responder_spi_len", &self.new_responder_spi.len())
            .field("nonce_len", &self.nonce.nonce.len())
            .field("dh_group", &self.key_exchange.dh_group)
            .field(
                "key_exchange_data_len",
                &self.key_exchange.key_exchange_data.len(),
            )
            .finish()
    }
}

/// Immutable exact `SA, Nr, KEr` opened response payload chain.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IkeSaRekeyResponsePayloads {
    first_payload: PayloadType,
    bytes: Bytes,
}

impl Ikev2IkeSaRekeyResponsePayloads {
    /// First inner payload type to place in the outer `SK` generic header.
    pub const fn first_payload(&self) -> PayloadType {
        self.first_payload
    }

    /// Exact generic-payload-chain bytes in `SA, Nr, KEr` order.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consume the immutable representation into its wire components.
    pub fn into_parts(self) -> (PayloadType, Bytes) {
        (self.first_payload, self.bytes)
    }
}

impl fmt::Debug for Ikev2IkeSaRekeyResponsePayloads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeSaRekeyResponsePayloads")
            .field("first_payload", &self.first_payload)
            .field("encoded_len", &self.bytes.len())
            .finish()
    }
}

/// Stable failure while building an IKE-SA rekey response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2IkeSaRekeyBuildError {
    /// The newly allocated responder SPI was all zero.
    ResponderSpiZero,
    /// KEr used a group other than the selected proposal's DH group.
    KeyExchangeDhGroupMismatch {
        /// Selected DH transform ID.
        expected: u16,
        /// Supplied KEr group.
        actual: u16,
    },
    /// KEr public-value length did not match the selected DH group.
    InvalidKeyExchangeLength {
        /// Selected DH transform ID.
        dh_group: u16,
        /// Required public-value length.
        expected: usize,
        /// Supplied public-value length.
        actual: usize,
    },
    /// Selected SA proposal encoding failed.
    SecurityAssociation(Ikev2IkeAuthBuildError),
    /// Nonce payload encoding failed.
    Nonce(Ikev2SaInitBuildError),
    /// KE payload encoding failed.
    KeyExchange(Ikev2SaInitBuildError),
    /// Generic response payload-chain encoding failed.
    PayloadChain(Ikev2IkeAuthBuildError),
}

impl Ikev2IkeSaRekeyBuildError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ResponderSpiZero => "ike_sa_rekey_build_responder_spi_zero",
            Self::KeyExchangeDhGroupMismatch { .. } => "ike_sa_rekey_build_ke_group_mismatch",
            Self::InvalidKeyExchangeLength { .. } => "ike_sa_rekey_build_ke_length_invalid",
            Self::SecurityAssociation(_) => "ike_sa_rekey_build_sa_invalid",
            Self::Nonce(_) => "ike_sa_rekey_build_nonce_invalid",
            Self::KeyExchange(_) => "ike_sa_rekey_build_ke_invalid",
            Self::PayloadChain(_) => "ike_sa_rekey_build_payload_chain_invalid",
        }
    }
}

impl fmt::Display for Ikev2IkeSaRekeyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2IkeSaRekeyBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SecurityAssociation(error) | Self::PayloadChain(error) => Some(error),
            Self::Nonce(error) | Self::KeyExchange(error) => Some(error),
            _ => None,
        }
    }
}

/// Build the exact successful IKE-SA rekey response `SA, Nr, KEr`.
///
/// The selected proposal number and transforms are copied from the negotiated
/// request offer, while the Proposal SPI is replaced with the caller-allocated
/// responder SPI. The KEr group and public-value length must exactly match the
/// selected executable profile.
///
/// # Errors
///
/// Returns [`Ikev2IkeSaRekeyBuildError`] for a zero responder SPI, KE mismatch,
/// invalid nonce/KE/SA input, or IKEv2 length overflow.
pub fn build_ike_sa_rekey_response(
    input: &Ikev2IkeSaRekeyResponseBuild,
) -> Result<Ikev2IkeSaRekeyResponsePayloads, Ikev2IkeSaRekeyBuildError> {
    if input.new_responder_spi.iter().all(|octet| *octet == 0) {
        return Err(Ikev2IkeSaRekeyBuildError::ResponderSpiZero);
    }

    let selected_group = input.negotiation.profile.dh_group();
    let expected_group = selected_group.transform_id();
    if input.key_exchange.dh_group != expected_group {
        return Err(Ikev2IkeSaRekeyBuildError::KeyExchangeDhGroupMismatch {
            expected: expected_group,
            actual: input.key_exchange.dh_group,
        });
    }
    let expected_len = selected_group.public_value_len();
    let actual_len = input.key_exchange.key_exchange_data.len();
    if actual_len != expected_len {
        return Err(Ikev2IkeSaRekeyBuildError::InvalidKeyExchangeLength {
            dh_group: expected_group,
            expected: expected_len,
            actual: actual_len,
        });
    }

    let mut selected_proposal = input.negotiation.selected_proposal.clone();
    selected_proposal.spi = input.new_responder_spi.to_vec();
    let security_association = Ikev2SaPayloadBuild {
        proposals: vec![selected_proposal],
    };
    let sa_body = build_ike_auth_sa_payload(&security_association)
        .map_err(Ikev2IkeSaRekeyBuildError::SecurityAssociation)?;
    let nonce_body =
        encode_nonce_payload_build(&input.nonce).map_err(Ikev2IkeSaRekeyBuildError::Nonce)?;
    let key_exchange_body = encode_ke_payload_build(&input.key_exchange)
        .map_err(Ikev2IkeSaRekeyBuildError::KeyExchange)?;
    let entries = [
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Nonce,
            body: nonce_body,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::KeyExchange,
            body: key_exchange_body,
        },
    ];
    let (first_payload, bytes) = build_ike_auth_cleartext_payload_chain(&entries)
        .map_err(Ikev2IkeSaRekeyBuildError::PayloadChain)?;
    Ok(Ikev2IkeSaRekeyResponsePayloads {
        first_payload,
        bytes,
    })
}
