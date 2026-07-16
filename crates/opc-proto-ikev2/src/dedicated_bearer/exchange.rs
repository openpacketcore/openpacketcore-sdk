//! Strict opened-payload views and builders for TS 24.302 bearer exchanges.

use core::fmt;
use std::{collections::BTreeSet, error::Error};

use bytes::Bytes;
use opc_protocol::{DecodeContext, UnknownIePolicy, ValidationLevel};

use crate::{
    build_create_child_sa_rekey_response_payloads, build_delete_payload_body,
    build_ike_auth_cleartext_payload_chain,
    header::{Header, EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_INFORMATIONAL},
    ike_auth::{
        Ikev2CreateChildSaRekeyResponseBuild, Ikev2DeletePayload, Ikev2IkeAuthBuildError,
        Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2TrafficSelectorPayload,
        Ikev2TrafficSelectorPayloadBuild, IKEV2_IPSEC_SPI_SIZE, IKEV2_SECURITY_PROTOCOL_ID_ESP,
    },
    notify::{Ikev2NotifyPayload, Ikev2NotifyPayloadError, IKEV2_NOTIFY_REKEY_SA},
    payload::{PayloadChain, PayloadType, RawPayload},
    sa_init::{
        Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadBuild, Ikev2KeyExchangePayloadError,
        Ikev2NoncePayload, Ikev2NoncePayloadBuild, Ikev2NoncePayloadError, Ikev2SaPayload,
        Ikev2SaPayloadBuild, Ikev2SaPayloadError,
    },
};

use super::{
    build_ikev2_dedicated_bearer_notify, decode_ikev2_dedicated_bearer_notify, Ikev2ApnAmbr,
    Ikev2DedicatedBearerError, Ikev2DedicatedBearerEspSpi, Ikev2DedicatedBearerNotify,
    Ikev2DedicatedBearerProtocolError, Ikev2EpsQos, Ikev2ExtendedApnAmbr, Ikev2ExtendedEpsQos,
};

const IKEV2_TRANSFORM_TYPE_DH: u8 = 4;

/// Stable payload role used in missing/duplicate diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2DedicatedBearerPayloadRole {
    /// Security Association payload.
    SecurityAssociation,
    /// Nonce payload.
    Nonce,
    /// Key Exchange payload.
    KeyExchange,
    /// Initiator Traffic Selectors payload.
    TrafficSelectorsInitiator,
    /// Responder Traffic Selectors payload.
    TrafficSelectorsResponder,
    /// EPS_QOS Notify.
    EpsQos,
    /// EXTENDED_EPS_QOS Notify.
    ExtendedEpsQos,
    /// TFT Notify.
    Tft,
    /// MODIFIED_BEARER Notify.
    ModifiedBearer,
    /// APN_AMBR Notify.
    ApnAmbr,
    /// EXTENDED_APN_AMBR Notify.
    ExtendedApnAmbr,
    /// Delete payload.
    Delete,
    /// Error Notify.
    ErrorNotify,
}

impl Ikev2DedicatedBearerPayloadRole {
    /// Stable machine-readable role name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityAssociation => "security_association",
            Self::Nonce => "nonce",
            Self::KeyExchange => "key_exchange",
            Self::TrafficSelectorsInitiator => "traffic_selectors_initiator",
            Self::TrafficSelectorsResponder => "traffic_selectors_responder",
            Self::EpsQos => "eps_qos",
            Self::ExtendedEpsQos => "extended_eps_qos",
            Self::Tft => "tft",
            Self::ModifiedBearer => "modified_bearer",
            Self::ApnAmbr => "apn_ambr",
            Self::ExtendedApnAmbr => "extended_apn_ambr",
            Self::Delete => "delete",
            Self::ErrorNotify => "error_notify",
        }
    }
}

/// Borrowed unknown non-critical payload retained for extension-aware callers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2UnknownNonCriticalPayload<'a> {
    /// Unknown payload type value.
    pub payload_type: u8,
    /// Raw payload body, excluding the generic payload header.
    pub body: &'a [u8],
}

impl fmt::Debug for Ikev2UnknownNonCriticalPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2UnknownNonCriticalPayload")
            .field("payload_type", &self.payload_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Immutable encoded opened-payload chain suitable for exact retransmission.
///
/// The caller should seal this chain once and cache the complete encrypted IKE
/// request for retransmission. Re-encoding or resealing a retransmission would
/// change authenticated bytes and is intentionally outside this type.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerCleartextPayloads {
    first_payload: PayloadType,
    bytes: Bytes,
}

impl Ikev2DedicatedBearerCleartextPayloads {
    fn encode(
        payloads: Vec<Ikev2IkeAuthPayloadBuild>,
    ) -> Result<Self, Ikev2DedicatedBearerExchangeError> {
        let (first_payload, bytes) = build_ike_auth_cleartext_payload_chain(&payloads)
            .map_err(Ikev2DedicatedBearerExchangeError::Build)?;
        Ok(Self {
            first_payload,
            bytes,
        })
    }

    fn empty() -> Self {
        Self {
            first_payload: PayloadType::NoNext,
            bytes: Bytes::new(),
        }
    }

    /// First inner payload type to place in the outer SK payload header.
    pub const fn first_payload(&self) -> PayloadType {
        self.first_payload
    }

    /// Exact generic-payload-chain bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consume the immutable representation into its wire components.
    pub fn into_parts(self) -> (PayloadType, Bytes) {
        (self.first_payload, self.bytes)
    }
}

impl fmt::Debug for Ikev2DedicatedBearerCleartextPayloads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerCleartextPayloads")
            .field("first_payload", &self.first_payload)
            .field("encoded_len", &self.bytes.len())
            .finish()
    }
}

/// Builder for a new, non-rekey dedicated-bearer CREATE_CHILD_SA request.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerCreateChildSaRequestBuild {
    /// ESP Child-SA proposal or proposals.
    pub security_association: Ikev2SaPayloadBuild,
    /// Initiator nonce.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional KE payload when a proposal requests PFS.
    pub key_exchange: Option<Ikev2KeyExchangePayloadBuild>,
    /// Initiator traffic selectors.
    pub traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    /// Responder traffic selectors.
    pub traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
    /// Required EPS QoS.
    pub eps_qos: Ikev2EpsQos,
    /// Optional Extended EPS QoS.
    pub extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    /// Required canonical create-new TFT.
    pub tft: opc_proto_tft::TrafficFlowTemplate,
    /// Optional APN-AMBR for procedures where TS 24.302 permits it.
    pub apn_ambr: Option<Ikev2ApnAmbr>,
    /// Optional Extended APN-AMBR, valid only with APN-AMBR.
    pub extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
}

impl fmt::Debug for Ikev2DedicatedBearerCreateChildSaRequestBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerCreateChildSaRequestBuild")
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field("eps_qos", &self.eps_qos)
            .field("extended_eps_qos_present", &self.extended_eps_qos.is_some())
            .field("tft_operation", &self.tft.operation())
            .field("apn_ambr_present", &self.apn_ambr.is_some())
            .field(
                "extended_apn_ambr_present",
                &self.extended_apn_ambr.is_some(),
            )
            .finish()
    }
}

/// Borrowed strict view of a new, non-rekey CREATE_CHILD_SA request.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerCreateChildSaRequest<'a> {
    /// ESP Child-SA proposal or proposals.
    pub security_association: Ikev2SaPayload<'a>,
    /// Initiator nonce.
    pub nonce: Ikev2NoncePayload<'a>,
    /// Optional KE payload for PFS.
    pub key_exchange: Option<Ikev2KeyExchangePayload<'a>>,
    /// Initiator traffic selectors.
    pub traffic_selectors_initiator: Ikev2TrafficSelectorPayload<'a>,
    /// Responder traffic selectors.
    pub traffic_selectors_responder: Ikev2TrafficSelectorPayload<'a>,
    /// Required EPS QoS.
    pub eps_qos: Ikev2EpsQos,
    /// Optional Extended EPS QoS.
    pub extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    /// Required canonical TFT.
    pub tft: opc_proto_tft::TrafficFlowTemplate,
    /// Optional APN-AMBR.
    pub apn_ambr: Option<Ikev2ApnAmbr>,
    /// Optional Extended APN-AMBR.
    pub extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
    /// Unknown non-critical payloads retained in wire order.
    pub unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    /// Unrecognized Notify payloads retained in wire order.
    pub unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl fmt::Debug for Ikev2DedicatedBearerCreateChildSaRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerCreateChildSaRequest")
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field("eps_qos", &self.eps_qos)
            .field("extended_eps_qos_present", &self.extended_eps_qos.is_some())
            .field("tft_operation", &self.tft.operation())
            .field("apn_ambr_present", &self.apn_ambr.is_some())
            .field(
                "extended_apn_ambr_present",
                &self.extended_apn_ambr.is_some(),
            )
            .field(
                "unknown_noncritical_payload_count",
                &self.unknown_noncritical_payloads.len(),
            )
            .field(
                "unrecognized_notify_count",
                &self.unrecognized_notifies.len(),
            )
            .finish()
    }
}

/// Builder for a successful dedicated-bearer CREATE_CHILD_SA response.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerCreateChildSaResponseBuild {
    /// Selected ESP Child-SA proposal containing the responder SPI.
    pub security_association: Ikev2SaPayloadBuild,
    /// Responder nonce.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional responder KE payload when PFS was negotiated.
    pub key_exchange: Option<Ikev2KeyExchangePayloadBuild>,
    /// Accepted initiator traffic selectors.
    pub traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    /// Accepted responder traffic selectors.
    pub traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
}

impl fmt::Debug for Ikev2DedicatedBearerCreateChildSaResponseBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerCreateChildSaResponseBuild")
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("key_exchange_present", &self.key_exchange.is_some())
            .finish()
    }
}

/// Borrowed error Notify not specifically assigned by TS 24.302.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerPeerErrorNotify<'a> {
    /// IKEv2 error Notify Message Type (`< 16384`).
    pub notify_message_type: u16,
    /// Security Protocol ID.
    pub protocol_id: u8,
    /// Optional protocol-specific SPI.
    pub spi: &'a [u8],
    /// Error notification data.
    pub notification_data: &'a [u8],
}

impl fmt::Debug for Ikev2DedicatedBearerPeerErrorNotify<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerPeerErrorNotify")
            .field("notify_message_type", &self.notify_message_type)
            .field("protocol_id", &self.protocol_id)
            .field("spi_len", &self.spi.len())
            .field("notification_data_len", &self.notification_data.len())
            .finish()
    }
}

/// Typed peer rejection of a dedicated-bearer exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2DedicatedBearerResponseError<'a> {
    /// TS 24.302 TFT/packet-filter error.
    DedicatedBearer(Ikev2DedicatedBearerProtocolError),
    /// Other IKEv2 error Notify retained without logging its data.
    Peer(Ikev2DedicatedBearerPeerErrorNotify<'a>),
}

/// Strict CREATE_CHILD_SA response view.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2DedicatedBearerCreateChildSaResponse<'a> {
    /// Successful Child-SA negotiation.
    Success {
        /// Selected ESP proposal.
        security_association: Ikev2SaPayload<'a>,
        /// Responder nonce.
        nonce: Ikev2NoncePayload<'a>,
        /// Optional responder KE payload.
        key_exchange: Option<Ikev2KeyExchangePayload<'a>>,
        /// Accepted initiator traffic selectors.
        traffic_selectors_initiator: Ikev2TrafficSelectorPayload<'a>,
        /// Accepted responder traffic selectors.
        traffic_selectors_responder: Ikev2TrafficSelectorPayload<'a>,
        /// Unknown non-critical payloads retained in wire order.
        unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
        /// Unrecognized status Notifies retained in wire order.
        unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    },
    /// Peer rejected the exchange with an error Notify.
    Error(Ikev2DedicatedBearerResponseError<'a>),
}

impl fmt::Debug for Ikev2DedicatedBearerCreateChildSaResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success {
                security_association,
                nonce,
                key_exchange,
                unknown_noncritical_payloads,
                unrecognized_notifies,
                ..
            } => f
                .debug_struct("Ikev2DedicatedBearerCreateChildSaResponse::Success")
                .field("security_association", security_association)
                .field("nonce_len", &nonce.nonce.len())
                .field("key_exchange_present", &key_exchange.is_some())
                .field(
                    "unknown_noncritical_payload_count",
                    &unknown_noncritical_payloads.len(),
                )
                .field("unrecognized_notify_count", &unrecognized_notifies.len())
                .finish(),
            Self::Error(error) => f
                .debug_tuple("Ikev2DedicatedBearerCreateChildSaResponse::Error")
                .field(error)
                .finish(),
        }
    }
}

/// Build and encode a new non-rekey CREATE_CHILD_SA request payload chain.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] for an invalid Child-SA
/// proposal, KE relationship, TFT operation, AMBR dependency, or payload size.
pub fn build_ikev2_dedicated_bearer_create_child_sa_request(
    input: &Ikev2DedicatedBearerCreateChildSaRequestBuild,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    validate_sa_build(&input.security_association, false)?;
    validate_create_tft(&input.tft)?;
    validate_extended_ambr_dependency(input.apn_ambr, input.extended_apn_ambr)?;

    let common =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: input.security_association.clone(),
            nonce: input.nonce.clone(),
            key_exchange: input.key_exchange.clone(),
            traffic_selectors_initiator: input.traffic_selectors_initiator.clone(),
            traffic_selectors_responder: input.traffic_selectors_responder.clone(),
        })
        .map_err(Ikev2DedicatedBearerExchangeError::Build)?;
    let mut payloads = common.into_payloads();
    payloads.push(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::EpsQos(input.eps_qos.clone()),
    )?);
    if let Some(value) = input.extended_eps_qos {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ExtendedEpsQos(value),
        )?);
    }
    payloads.push(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::Tft(input.tft.clone()),
    )?);
    if let Some(value) = input.apn_ambr {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ApnAmbr(value),
        )?);
    }
    if let Some(value) = input.extended_apn_ambr {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ExtendedApnAmbr(value),
        )?);
    }
    Ikev2DedicatedBearerCleartextPayloads::encode(payloads)
}

/// Decode a strict new non-rekey CREATE_CHILD_SA request.
///
/// The default uses conservative limits while preserving unknown non-critical
/// extensions. It always rejects duplicate required/optional payloads.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] for a malformed header,
/// payload chain, required payload, proposal/SPI/KE relationship, or 3GPP
/// Notify.
pub fn decode_ikev2_dedicated_bearer_create_child_sa_request<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerCreateChildSaRequest<'a>, Ikev2DedicatedBearerExchangeError> {
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    decode_ikev2_dedicated_bearer_create_child_sa_request_with_context(
        header,
        first_payload,
        cleartext_payloads,
        context,
    )
}

/// Decode a new non-rekey CREATE_CHILD_SA request with explicit limits.
///
/// Structural validation is always upgraded to strict. The caller's unknown-IE
/// policy controls preservation/rejection of unknown non-critical payloads and
/// unrecognized Notify types.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] on any header, payload,
/// cardinality, proposal, or notification violation.
pub fn decode_ikev2_dedicated_bearer_create_child_sa_request_with_context<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
    mut context: DecodeContext,
) -> Result<Ikev2DedicatedBearerCreateChildSaRequest<'a>, Ikev2DedicatedBearerExchangeError> {
    validate_exchange_header(header, EXCHANGE_TYPE_CREATE_CHILD_SA, false)?;
    validate_cleartext_len(cleartext_payloads, context.max_message_len)?;
    context.validation_level = ValidationLevel::Strict;
    let mut parts = CreateChildSaParts::default();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2DedicatedBearerExchangeError::PayloadChain)?;
        parts.decode_request_payload(raw, context.unknown_ie_policy)?;
    }
    parts.finish_request()
}

/// Build and encode a successful CREATE_CHILD_SA response payload chain.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] unless exactly one selected
/// ESP proposal with a non-zero four-octet responder SPI is supplied and the
/// KE/proposal relationship is valid.
pub fn build_ikev2_dedicated_bearer_create_child_sa_response(
    input: &Ikev2DedicatedBearerCreateChildSaResponseBuild,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    validate_sa_build(&input.security_association, true)?;
    let common =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: input.security_association.clone(),
            nonce: input.nonce.clone(),
            key_exchange: input.key_exchange.clone(),
            traffic_selectors_initiator: input.traffic_selectors_initiator.clone(),
            traffic_selectors_responder: input.traffic_selectors_responder.clone(),
        })
        .map_err(Ikev2DedicatedBearerExchangeError::Build)?;
    Ikev2DedicatedBearerCleartextPayloads::encode(common.into_payloads())
}

/// Build and encode a TS 24.302 private-error CREATE_CHILD_SA response.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] only if the Notify payload
/// cannot fit IKEv2 length fields.
pub fn build_ikev2_dedicated_bearer_create_child_sa_error_response(
    error: Ikev2DedicatedBearerProtocolError,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    Ikev2DedicatedBearerCleartextPayloads::encode(vec![build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::ProtocolError(error),
    )?])
}

/// Decode a strict dedicated-bearer CREATE_CHILD_SA response.
///
/// A successful response requires exactly one SA, Nonce, TSi, and TSr and
/// validates the optional KE relationship. An error response must contain one
/// error Notify and no success payloads.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] on malformed or ambiguous
/// success/error payload sets.
pub fn decode_ikev2_dedicated_bearer_create_child_sa_response<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerCreateChildSaResponse<'a>, Ikev2DedicatedBearerExchangeError> {
    validate_exchange_header(header, EXCHANGE_TYPE_CREATE_CHILD_SA, true)?;
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    validate_cleartext_len(cleartext_payloads, context.max_message_len)?;
    let mut parts = CreateChildSaParts::default();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2DedicatedBearerExchangeError::PayloadChain)?;
        parts.decode_response_payload(raw, context.unknown_ie_policy)?;
    }
    parts.finish_response()
}

#[derive(Default)]
struct CreateChildSaParts<'a> {
    security_association: Option<Ikev2SaPayload<'a>>,
    nonce: Option<Ikev2NoncePayload<'a>>,
    key_exchange: Option<Ikev2KeyExchangePayload<'a>>,
    traffic_selectors_initiator: Option<Ikev2TrafficSelectorPayload<'a>>,
    traffic_selectors_responder: Option<Ikev2TrafficSelectorPayload<'a>>,
    eps_qos: Option<Ikev2EpsQos>,
    extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    tft: Option<opc_proto_tft::TrafficFlowTemplate>,
    apn_ambr: Option<Ikev2ApnAmbr>,
    extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
    error: Option<Ikev2DedicatedBearerResponseError<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl<'a> CreateChildSaParts<'a> {
    fn decode_request_payload(
        &mut self,
        raw: RawPayload<'a>,
        unknown_policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        match raw.payload_type {
            PayloadType::SecurityAssociation => set_once(
                &mut self.security_association,
                Ikev2SaPayload::decode(raw).map_err(Ikev2DedicatedBearerExchangeError::Sa)?,
                Ikev2DedicatedBearerPayloadRole::SecurityAssociation,
            ),
            PayloadType::Nonce => set_once(
                &mut self.nonce,
                Ikev2NoncePayload::decode(raw).map_err(Ikev2DedicatedBearerExchangeError::Nonce)?,
                Ikev2DedicatedBearerPayloadRole::Nonce,
            ),
            PayloadType::KeyExchange => set_once(
                &mut self.key_exchange,
                Ikev2KeyExchangePayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::KeyExchange)?,
                Ikev2DedicatedBearerPayloadRole::KeyExchange,
            ),
            PayloadType::TrafficSelectorInitiator => set_once(
                &mut self.traffic_selectors_initiator,
                Ikev2TrafficSelectorPayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::Payload)?,
                Ikev2DedicatedBearerPayloadRole::TrafficSelectorsInitiator,
            ),
            PayloadType::TrafficSelectorResponder => set_once(
                &mut self.traffic_selectors_responder,
                Ikev2TrafficSelectorPayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::Payload)?,
                Ikev2DedicatedBearerPayloadRole::TrafficSelectorsResponder,
            ),
            PayloadType::Notify => self.decode_request_notify(raw, unknown_policy),
            PayloadType::Unknown(value) => preserve_unknown(
                &mut self.unknown_noncritical_payloads,
                value,
                raw.body,
                unknown_policy,
            ),
            _ => Err(Ikev2DedicatedBearerExchangeError::UnexpectedPayloadType {
                payload_type: raw.payload_type.as_u8(),
            }),
        }
    }

    fn decode_request_notify(
        &mut self,
        raw: RawPayload<'a>,
        unknown_policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        let notify =
            Ikev2NotifyPayload::decode(raw).map_err(Ikev2DedicatedBearerExchangeError::Notify)?;
        if notify.notify_message_type == IKEV2_NOTIFY_REKEY_SA {
            return Err(Ikev2DedicatedBearerExchangeError::RekeyNotifyProhibited);
        }
        match decode_ikev2_dedicated_bearer_notify(notify)? {
            Some(Ikev2DedicatedBearerNotify::EpsQos(value)) => set_once(
                &mut self.eps_qos,
                value,
                Ikev2DedicatedBearerPayloadRole::EpsQos,
            ),
            Some(Ikev2DedicatedBearerNotify::ExtendedEpsQos(value)) => set_once(
                &mut self.extended_eps_qos,
                value,
                Ikev2DedicatedBearerPayloadRole::ExtendedEpsQos,
            ),
            Some(Ikev2DedicatedBearerNotify::Tft(value)) => {
                set_once(&mut self.tft, value, Ikev2DedicatedBearerPayloadRole::Tft)
            }
            Some(Ikev2DedicatedBearerNotify::ApnAmbr(value)) => set_once(
                &mut self.apn_ambr,
                value,
                Ikev2DedicatedBearerPayloadRole::ApnAmbr,
            ),
            Some(Ikev2DedicatedBearerNotify::ExtendedApnAmbr(value)) => set_once(
                &mut self.extended_apn_ambr,
                value,
                Ikev2DedicatedBearerPayloadRole::ExtendedApnAmbr,
            ),
            Some(
                Ikev2DedicatedBearerNotify::ProtocolError(_)
                | Ikev2DedicatedBearerNotify::ModifiedBearer(_)
                | Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity,
            ) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                notify_message_type: notify.notify_message_type,
            }),
            None => preserve_notify(&mut self.unrecognized_notifies, notify, unknown_policy),
        }
    }

    fn decode_response_payload(
        &mut self,
        raw: RawPayload<'a>,
        unknown_policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        if raw.payload_type != PayloadType::Notify {
            return self.decode_request_payload(raw, unknown_policy);
        }
        let notify =
            Ikev2NotifyPayload::decode(raw).map_err(Ikev2DedicatedBearerExchangeError::Notify)?;
        if notify.notify_message_type < 16_384 {
            let error = match decode_ikev2_dedicated_bearer_notify(notify)? {
                Some(Ikev2DedicatedBearerNotify::ProtocolError(error)) => {
                    Ikev2DedicatedBearerResponseError::DedicatedBearer(error)
                }
                Some(_) => {
                    return Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                        notify_message_type: notify.notify_message_type,
                    })
                }
                None => {
                    Ikev2DedicatedBearerResponseError::Peer(Ikev2DedicatedBearerPeerErrorNotify {
                        notify_message_type: notify.notify_message_type,
                        protocol_id: notify.protocol_id,
                        spi: notify.spi,
                        notification_data: notify.notification_data,
                    })
                }
            };
            set_once(
                &mut self.error,
                error,
                Ikev2DedicatedBearerPayloadRole::ErrorNotify,
            )
        } else {
            match decode_ikev2_dedicated_bearer_notify(notify)? {
                Some(_) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedSuccessNotify),
                None => preserve_notify(&mut self.unrecognized_notifies, notify, unknown_policy),
            }
        }
    }

    fn finish_request(
        self,
    ) -> Result<Ikev2DedicatedBearerCreateChildSaRequest<'a>, Ikev2DedicatedBearerExchangeError>
    {
        let security_association = required(
            self.security_association,
            Ikev2DedicatedBearerPayloadRole::SecurityAssociation,
        )?;
        let nonce = required(self.nonce, Ikev2DedicatedBearerPayloadRole::Nonce)?;
        let traffic_selectors_initiator = required(
            self.traffic_selectors_initiator,
            Ikev2DedicatedBearerPayloadRole::TrafficSelectorsInitiator,
        )?;
        let traffic_selectors_responder = required(
            self.traffic_selectors_responder,
            Ikev2DedicatedBearerPayloadRole::TrafficSelectorsResponder,
        )?;
        let eps_qos = required(self.eps_qos, Ikev2DedicatedBearerPayloadRole::EpsQos)?;
        let tft = required(self.tft, Ikev2DedicatedBearerPayloadRole::Tft)?;
        validate_sa_view(&security_association, false)?;
        validate_ke_view(&security_association, self.key_exchange.as_ref())?;
        validate_create_tft(&tft)?;
        validate_extended_ambr_dependency(self.apn_ambr, self.extended_apn_ambr)?;
        Ok(Ikev2DedicatedBearerCreateChildSaRequest {
            security_association,
            nonce,
            key_exchange: self.key_exchange,
            traffic_selectors_initiator,
            traffic_selectors_responder,
            eps_qos,
            extended_eps_qos: self.extended_eps_qos,
            tft,
            apn_ambr: self.apn_ambr,
            extended_apn_ambr: self.extended_apn_ambr,
            unknown_noncritical_payloads: self.unknown_noncritical_payloads,
            unrecognized_notifies: self.unrecognized_notifies,
        })
    }

    fn finish_response(
        self,
    ) -> Result<Ikev2DedicatedBearerCreateChildSaResponse<'a>, Ikev2DedicatedBearerExchangeError>
    {
        if let Some(error) = self.error {
            let has_success_payload = self.security_association.is_some()
                || self.nonce.is_some()
                || self.key_exchange.is_some()
                || self.traffic_selectors_initiator.is_some()
                || self.traffic_selectors_responder.is_some()
                || self.eps_qos.is_some()
                || self.extended_eps_qos.is_some()
                || self.tft.is_some()
                || self.apn_ambr.is_some()
                || self.extended_apn_ambr.is_some()
                || !self.unknown_noncritical_payloads.is_empty()
                || !self.unrecognized_notifies.is_empty();
            if has_success_payload {
                return Err(Ikev2DedicatedBearerExchangeError::ErrorResponseMixedWithPayloads);
            }
            return Ok(Ikev2DedicatedBearerCreateChildSaResponse::Error(error));
        }
        if self.eps_qos.is_some()
            || self.extended_eps_qos.is_some()
            || self.tft.is_some()
            || self.apn_ambr.is_some()
            || self.extended_apn_ambr.is_some()
        {
            return Err(Ikev2DedicatedBearerExchangeError::UnexpectedSuccessNotify);
        }
        let security_association = required(
            self.security_association,
            Ikev2DedicatedBearerPayloadRole::SecurityAssociation,
        )?;
        let nonce = required(self.nonce, Ikev2DedicatedBearerPayloadRole::Nonce)?;
        let traffic_selectors_initiator = required(
            self.traffic_selectors_initiator,
            Ikev2DedicatedBearerPayloadRole::TrafficSelectorsInitiator,
        )?;
        let traffic_selectors_responder = required(
            self.traffic_selectors_responder,
            Ikev2DedicatedBearerPayloadRole::TrafficSelectorsResponder,
        )?;
        validate_sa_view(&security_association, true)?;
        validate_ke_view(&security_association, self.key_exchange.as_ref())?;
        Ok(Ikev2DedicatedBearerCreateChildSaResponse::Success {
            security_association,
            nonce,
            key_exchange: self.key_exchange,
            traffic_selectors_initiator,
            traffic_selectors_responder,
            unknown_noncritical_payloads: self.unknown_noncritical_payloads,
            unrecognized_notifies: self.unrecognized_notifies,
        })
    }
}

fn validate_exchange_header(
    header: &Header,
    exchange_type: u8,
    response: bool,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if header.exchange_type != exchange_type {
        return Err(Ikev2DedicatedBearerExchangeError::WrongExchangeType {
            expected: exchange_type,
            actual: header.exchange_type,
        });
    }
    if header.flags.response() != response {
        return Err(if response {
            Ikev2DedicatedBearerExchangeError::ResponseFlagMissing
        } else {
            Ikev2DedicatedBearerExchangeError::ResponseFlagUnexpected
        });
    }
    if header.initiator_spi == 0 || header.responder_spi == 0 {
        return Err(Ikev2DedicatedBearerExchangeError::IkeSpiZero);
    }
    Ok(())
}

fn validate_cleartext_len(
    bytes: &[u8],
    maximum: usize,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if bytes.len() > maximum {
        Err(Ikev2DedicatedBearerExchangeError::MessageTooLarge {
            actual: bytes.len(),
            maximum,
        })
    } else {
        Ok(())
    }
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    role: Ikev2DedicatedBearerPayloadRole,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if slot.is_some() {
        return Err(Ikev2DedicatedBearerExchangeError::DuplicatePayload { role });
    }
    *slot = Some(value);
    Ok(())
}

fn required<T>(
    value: Option<T>,
    role: Ikev2DedicatedBearerPayloadRole,
) -> Result<T, Ikev2DedicatedBearerExchangeError> {
    value.ok_or(Ikev2DedicatedBearerExchangeError::MissingPayload { role })
}

fn preserve_unknown<'a>(
    output: &mut Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    payload_type: u8,
    body: &'a [u8],
    policy: UnknownIePolicy,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    match policy {
        UnknownIePolicy::Preserve => {
            output.push(Ikev2UnknownNonCriticalPayload { payload_type, body });
            Ok(())
        }
        UnknownIePolicy::Drop => Ok(()),
        UnknownIePolicy::Reject => {
            Err(Ikev2DedicatedBearerExchangeError::UnknownPayloadRejected { payload_type })
        }
    }
}

fn preserve_notify<'a>(
    output: &mut Vec<Ikev2NotifyPayload<'a>>,
    notify: Ikev2NotifyPayload<'a>,
    policy: UnknownIePolicy,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    match policy {
        UnknownIePolicy::Preserve => {
            output.push(notify);
            Ok(())
        }
        UnknownIePolicy::Drop => Ok(()),
        UnknownIePolicy::Reject => Err(Ikev2DedicatedBearerExchangeError::UnknownNotifyRejected {
            notify_message_type: notify.notify_message_type,
        }),
    }
}

fn validate_sa_build(
    sa: &Ikev2SaPayloadBuild,
    response: bool,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if sa.proposals.is_empty() {
        return Err(Ikev2DedicatedBearerExchangeError::MissingPayload {
            role: Ikev2DedicatedBearerPayloadRole::SecurityAssociation,
        });
    }
    if response && sa.proposals.len() != 1 {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseProposalCount {
            actual: sa.proposals.len(),
        });
    }
    let mut proposal_numbers = BTreeSet::new();
    for proposal in &sa.proposals {
        if proposal.proposal_number == 0 || !proposal_numbers.insert(proposal.proposal_number) {
            return Err(Ikev2DedicatedBearerExchangeError::InvalidProposalNumber {
                value: proposal.proposal_number,
            });
        }
        validate_proposal_spi(proposal.protocol_id, &proposal.spi)?;
    }
    Ok(())
}

fn validate_sa_view(
    sa: &Ikev2SaPayload<'_>,
    response: bool,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if response && sa.proposals.len() != 1 {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseProposalCount {
            actual: sa.proposals.len(),
        });
    }
    let mut proposal_numbers = BTreeSet::new();
    for proposal in &sa.proposals {
        if proposal.proposal_number == 0 || !proposal_numbers.insert(proposal.proposal_number) {
            return Err(Ikev2DedicatedBearerExchangeError::InvalidProposalNumber {
                value: proposal.proposal_number,
            });
        }
        if usize::from(proposal.spi_size) != proposal.spi.len() {
            return Err(Ikev2DedicatedBearerExchangeError::InvalidChildSaSpiLength {
                actual: proposal.spi.len(),
            });
        }
        validate_proposal_spi(proposal.protocol_id, proposal.spi)?;
    }
    Ok(())
}

fn validate_proposal_spi(
    protocol_id: u8,
    spi: &[u8],
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP {
        return Err(Ikev2DedicatedBearerExchangeError::ChildSaProtocolNotEsp {
            actual: protocol_id,
        });
    }
    Ikev2DedicatedBearerEspSpi::decode(spi)
        .map(|_| ())
        .map_err(|error| match error {
            Ikev2DedicatedBearerError::InvalidEspSpiLength { actual } => {
                Ikev2DedicatedBearerExchangeError::InvalidChildSaSpiLength { actual }
            }
            Ikev2DedicatedBearerError::ZeroEspSpi => {
                Ikev2DedicatedBearerExchangeError::ChildSaSpiZero
            }
            other => Ikev2DedicatedBearerExchangeError::ThreeGpp(other),
        })
}

fn validate_ke_view(
    sa: &Ikev2SaPayload<'_>,
    key_exchange: Option<&Ikev2KeyExchangePayload<'_>>,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    let mut dh_offered = false;
    let mut group_matches = false;
    for transform in sa
        .proposals
        .iter()
        .flat_map(|proposal| &proposal.transforms)
        .filter(|transform| transform.transform_type == IKEV2_TRANSFORM_TYPE_DH)
    {
        dh_offered = true;
        if key_exchange.is_some_and(|key_exchange| key_exchange.dh_group == transform.transform_id)
        {
            group_matches = true;
        }
    }
    match (dh_offered, key_exchange, group_matches) {
        (true, None, _) => Err(Ikev2DedicatedBearerExchangeError::KeyExchangeRequired),
        (false, Some(_), _) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedKeyExchange),
        (true, Some(_), false) => {
            Err(Ikev2DedicatedBearerExchangeError::KeyExchangeDhGroupMismatch)
        }
        _ => Ok(()),
    }
}

fn validate_create_tft(
    tft: &opc_proto_tft::TrafficFlowTemplate,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if tft.operation() != opc_proto_tft::TftOperation::CreateNew {
        return Err(Ikev2DedicatedBearerExchangeError::CreateTftOperationRequired);
    }
    if tft.packet_filters().is_empty() {
        return Err(Ikev2DedicatedBearerExchangeError::CreateTftEmpty);
    }
    Ok(())
}

fn validate_extended_ambr_dependency(
    apn_ambr: Option<Ikev2ApnAmbr>,
    extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if extended_apn_ambr.is_some() && apn_ambr.is_none() {
        Err(Ikev2DedicatedBearerExchangeError::ExtendedApnAmbrWithoutApnAmbr)
    } else {
        Ok(())
    }
}

/// Structured, redaction-safe exchange validation/build error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2DedicatedBearerExchangeError {
    /// Header exchange type was not the requested procedure.
    WrongExchangeType {
        /// Expected exchange type.
        expected: u8,
        /// Actual exchange type.
        actual: u8,
    },
    /// A response decoder received a header without the response flag.
    ResponseFlagMissing,
    /// A request decoder received a response header.
    ResponseFlagUnexpected,
    /// An established-SA exchange carried a zero IKE SPI.
    IkeSpiZero,
    /// Opened payload bytes exceeded the configured maximum.
    MessageTooLarge {
        /// Actual opened length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Generic payload-chain decode failed.
    PayloadChain,
    /// A required payload was missing.
    MissingPayload {
        /// Missing role.
        role: Ikev2DedicatedBearerPayloadRole,
    },
    /// A singleton payload was duplicated.
    DuplicatePayload {
        /// Duplicated role.
        role: Ikev2DedicatedBearerPayloadRole,
    },
    /// A known payload type is prohibited in this exchange.
    UnexpectedPayloadType {
        /// IKEv2 payload type value.
        payload_type: u8,
    },
    /// An unknown non-critical payload was rejected by policy.
    UnknownPayloadRejected {
        /// Unknown payload type.
        payload_type: u8,
    },
    /// An unrecognized Notify was rejected by policy.
    UnknownNotifyRejected {
        /// Notify Message Type.
        notify_message_type: u16,
    },
    /// A known 3GPP Notify is prohibited in this exchange.
    UnexpectedNotifyType {
        /// Notify Message Type.
        notify_message_type: u16,
    },
    /// REKEY_SA appeared in a new dedicated-bearer request.
    RekeyNotifyProhibited,
    /// A successful response carried request-only 3GPP status notifications.
    UnexpectedSuccessNotify,
    /// An error response also carried success or extension payloads.
    ErrorResponseMixedWithPayloads,
    /// Child-SA proposal Protocol ID was not ESP.
    ChildSaProtocolNotEsp {
        /// Received Protocol ID.
        actual: u8,
    },
    /// Child-SA proposal SPI was not four octets.
    InvalidChildSaSpiLength {
        /// Received SPI length.
        actual: usize,
    },
    /// Child-SA proposal SPI was zero.
    ChildSaSpiZero,
    /// Proposal number was zero or duplicated.
    InvalidProposalNumber {
        /// Proposal number.
        value: u8,
    },
    /// A response did not contain exactly one selected proposal.
    ResponseProposalCount {
        /// Proposal count.
        actual: usize,
    },
    /// A proposal used a DH transform but KE was absent.
    KeyExchangeRequired,
    /// KE was present without a DH transform.
    UnexpectedKeyExchange,
    /// KE group was not offered in the SA payload.
    KeyExchangeDhGroupMismatch,
    /// Dedicated-bearer creation TFT was not Create New TFT.
    CreateTftOperationRequired,
    /// Dedicated-bearer creation TFT had no packet filters.
    CreateTftEmpty,
    /// Extended APN-AMBR appeared without APN-AMBR.
    ExtendedApnAmbrWithoutApnAmbr,
    /// Extended EPS QoS appeared without EPS QoS.
    ExtendedEpsQosWithoutEpsQos,
    /// A modification request did not change QoS, TFT, or APN-AMBR.
    ModificationHasNoUpdates,
    /// Delete payload did not name exactly one ESP SPI.
    DeleteSpiCount {
        /// Received SPI count.
        actual: usize,
    },
    /// Response did not correlate with the request header.
    ResponseCorrelationMismatch,
    /// Successful response selected a proposal number/protocol not offered.
    ResponseProposalNotOffered,
    /// Successful response selected a transform not offered in that proposal.
    ResponseTransformNotOffered,
    /// Successful response KE presence or group did not match the request.
    ResponseKeyExchangeMismatch,
    /// Successful response expanded TSi or TSr beyond the request.
    ResponseTrafficSelectorsExpanded,
    /// Typed SA payload decode failed.
    Sa(Ikev2SaPayloadError),
    /// Typed Nonce payload decode failed.
    Nonce(Ikev2NoncePayloadError),
    /// Typed KE payload decode failed.
    KeyExchange(Ikev2KeyExchangePayloadError),
    /// Typed IKE payload decode failed.
    Payload(Ikev2IkeAuthPayloadError),
    /// Typed Notify decode failed.
    Notify(Ikev2NotifyPayloadError),
    /// TS 24.302 typed Notify validation failed.
    ThreeGpp(Ikev2DedicatedBearerError),
    /// Existing payload builder rejected the input.
    Build(Ikev2IkeAuthBuildError),
}

impl Ikev2DedicatedBearerExchangeError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WrongExchangeType { .. } => "ikev2_bearer_exchange_type_wrong",
            Self::ResponseFlagMissing => "ikev2_bearer_response_flag_missing",
            Self::ResponseFlagUnexpected => "ikev2_bearer_response_flag_unexpected",
            Self::IkeSpiZero => "ikev2_bearer_ike_spi_zero",
            Self::MessageTooLarge { .. } => "ikev2_bearer_message_too_large",
            Self::PayloadChain => "ikev2_bearer_payload_chain_invalid",
            Self::MissingPayload { .. } => "ikev2_bearer_payload_missing",
            Self::DuplicatePayload { .. } => "ikev2_bearer_payload_duplicate",
            Self::UnexpectedPayloadType { .. } => "ikev2_bearer_payload_unexpected",
            Self::UnknownPayloadRejected { .. } => "ikev2_bearer_unknown_payload_rejected",
            Self::UnknownNotifyRejected { .. } => "ikev2_bearer_unknown_notify_rejected",
            Self::UnexpectedNotifyType { .. } => "ikev2_bearer_notify_unexpected",
            Self::RekeyNotifyProhibited => "ikev2_bearer_rekey_notify_prohibited",
            Self::UnexpectedSuccessNotify => "ikev2_bearer_success_notify_unexpected",
            Self::ErrorResponseMixedWithPayloads => "ikev2_bearer_error_response_mixed",
            Self::ChildSaProtocolNotEsp { .. } => "ikev2_bearer_child_protocol_not_esp",
            Self::InvalidChildSaSpiLength { .. } => "ikev2_bearer_child_spi_length_invalid",
            Self::ChildSaSpiZero => "ikev2_bearer_child_spi_zero",
            Self::InvalidProposalNumber { .. } => "ikev2_bearer_proposal_number_invalid",
            Self::ResponseProposalCount { .. } => "ikev2_bearer_response_proposal_count",
            Self::KeyExchangeRequired => "ikev2_bearer_ke_required",
            Self::UnexpectedKeyExchange => "ikev2_bearer_ke_unexpected",
            Self::KeyExchangeDhGroupMismatch => "ikev2_bearer_ke_group_mismatch",
            Self::CreateTftOperationRequired => "ikev2_bearer_tft_create_required",
            Self::CreateTftEmpty => "ikev2_bearer_tft_create_empty",
            Self::ExtendedApnAmbrWithoutApnAmbr => "ikev2_bearer_extended_apn_ambr_without_base",
            Self::ExtendedEpsQosWithoutEpsQos => "ikev2_bearer_extended_eps_qos_without_base",
            Self::ModificationHasNoUpdates => "ikev2_bearer_modification_no_updates",
            Self::DeleteSpiCount { .. } => "ikev2_bearer_delete_spi_count",
            Self::ResponseCorrelationMismatch => "ikev2_bearer_response_correlation_mismatch",
            Self::ResponseProposalNotOffered => "ikev2_bearer_response_proposal_not_offered",
            Self::ResponseTransformNotOffered => "ikev2_bearer_response_transform_not_offered",
            Self::ResponseKeyExchangeMismatch => "ikev2_bearer_response_ke_mismatch",
            Self::ResponseTrafficSelectorsExpanded => "ikev2_bearer_response_ts_expanded",
            Self::Sa(_) => "ikev2_bearer_sa_invalid",
            Self::Nonce(_) => "ikev2_bearer_nonce_invalid",
            Self::KeyExchange(_) => "ikev2_bearer_ke_invalid",
            Self::Payload(_) => "ikev2_bearer_payload_invalid",
            Self::Notify(_) => "ikev2_bearer_notify_invalid",
            Self::ThreeGpp(_) => "ikev2_bearer_3gpp_notify_invalid",
            Self::Build(_) => "ikev2_bearer_build_invalid",
        }
    }
}

impl fmt::Display for Ikev2DedicatedBearerExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2DedicatedBearerExchangeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sa(error) => Some(error),
            Self::Nonce(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            Self::Payload(error) => Some(error),
            Self::Notify(error) => Some(error),
            Self::ThreeGpp(error) => Some(error),
            Self::Build(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Ikev2DedicatedBearerError> for Ikev2DedicatedBearerExchangeError {
    fn from(value: Ikev2DedicatedBearerError) -> Self {
        Self::ThreeGpp(value)
    }
}

/// Builder for a bearer modification INFORMATIONAL request.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerModificationRequestBuild {
    /// ePDG-owned ESP SPI identifying the bearer to modify.
    pub modified_bearer: Ikev2DedicatedBearerEspSpi,
    /// Optional replacement EPS QoS.
    pub eps_qos: Option<Ikev2EpsQos>,
    /// Optional Extended EPS QoS; requires `eps_qos`.
    pub extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    /// Optional canonical TFT operation.
    pub tft: Option<opc_proto_tft::TrafficFlowTemplate>,
    /// Optional replacement APN-AMBR for a default bearer.
    pub apn_ambr: Option<Ikev2ApnAmbr>,
    /// Optional Extended APN-AMBR; requires `apn_ambr`.
    pub extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
}

impl fmt::Debug for Ikev2DedicatedBearerModificationRequestBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerModificationRequestBuild")
            .field("modified_bearer", &"<redacted>")
            .field("eps_qos_present", &self.eps_qos.is_some())
            .field("extended_eps_qos_present", &self.extended_eps_qos.is_some())
            .field("tft_present", &self.tft.is_some())
            .field("apn_ambr_present", &self.apn_ambr.is_some())
            .field(
                "extended_apn_ambr_present",
                &self.extended_apn_ambr.is_some(),
            )
            .finish()
    }
}

/// Strict borrowed bearer modification INFORMATIONAL request view.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerModificationRequest<'a> {
    /// ePDG-owned ESP SPI identifying the bearer.
    pub modified_bearer: Ikev2DedicatedBearerEspSpi,
    /// Optional replacement EPS QoS.
    pub eps_qos: Option<Ikev2EpsQos>,
    /// Optional Extended EPS QoS.
    pub extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    /// Optional canonical TFT operation.
    pub tft: Option<opc_proto_tft::TrafficFlowTemplate>,
    /// Optional APN-AMBR.
    pub apn_ambr: Option<Ikev2ApnAmbr>,
    /// Optional Extended APN-AMBR.
    pub extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
    /// Unknown non-critical payloads retained in wire order.
    pub unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    /// Unrecognized Notifies retained in wire order.
    pub unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl fmt::Debug for Ikev2DedicatedBearerModificationRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerModificationRequest")
            .field("modified_bearer", &"<redacted>")
            .field("eps_qos_present", &self.eps_qos.is_some())
            .field("extended_eps_qos_present", &self.extended_eps_qos.is_some())
            .field("tft_present", &self.tft.is_some())
            .field("apn_ambr_present", &self.apn_ambr.is_some())
            .field(
                "extended_apn_ambr_present",
                &self.extended_apn_ambr.is_some(),
            )
            .field(
                "unknown_noncritical_payload_count",
                &self.unknown_noncritical_payloads.len(),
            )
            .field(
                "unrecognized_notify_count",
                &self.unrecognized_notifies.len(),
            )
            .finish()
    }
}

/// Strict borrowed dedicated-bearer Delete request view.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DedicatedBearerDeleteRequest<'a> {
    /// ePDG-owned ESP SPI named by the Delete payload.
    pub esp_spi: Ikev2DedicatedBearerEspSpi,
    /// Unknown non-critical payloads retained in wire order.
    pub unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    /// Unrecognized Notifies retained in wire order.
    pub unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl fmt::Debug for Ikev2DedicatedBearerDeleteRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DedicatedBearerDeleteRequest")
            .field("esp_spi", &"<redacted>")
            .field(
                "unknown_noncritical_payload_count",
                &self.unknown_noncritical_payloads.len(),
            )
            .field(
                "unrecognized_notify_count",
                &self.unrecognized_notifies.len(),
            )
            .finish()
    }
}

/// Strict INFORMATIONAL response view for modification or deletion.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2DedicatedBearerInformationalResponse<'a> {
    /// Successful response, normally with an empty opened payload chain.
    Success {
        /// Unknown non-critical payloads retained in wire order.
        unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
        /// Unrecognized status Notifies retained in wire order.
        unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    },
    /// Peer rejection.
    Error(Ikev2DedicatedBearerResponseError<'a>),
}

impl fmt::Debug for Ikev2DedicatedBearerInformationalResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success {
                unknown_noncritical_payloads,
                unrecognized_notifies,
            } => f
                .debug_struct("Ikev2DedicatedBearerInformationalResponse::Success")
                .field(
                    "unknown_noncritical_payload_count",
                    &unknown_noncritical_payloads.len(),
                )
                .field("unrecognized_notify_count", &unrecognized_notifies.len())
                .finish(),
            Self::Error(error) => f
                .debug_tuple("Ikev2DedicatedBearerInformationalResponse::Error")
                .field(error)
                .finish(),
        }
    }
}

/// Build and encode a bearer modification INFORMATIONAL request.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] when no actual update is
/// supplied, an extended value lacks its base value, a Notify is invalid, or
/// the payload chain overflows.
pub fn build_ikev2_dedicated_bearer_modification_request(
    input: &Ikev2DedicatedBearerModificationRequestBuild,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    validate_modification_shape(
        input.eps_qos.as_ref(),
        input.extended_eps_qos,
        input.tft.as_ref(),
        input.apn_ambr,
        input.extended_apn_ambr,
    )?;
    let mut payloads = vec![build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::ModifiedBearer(input.modified_bearer),
    )?];
    if let Some(value) = &input.eps_qos {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::EpsQos(value.clone()),
        )?);
    }
    if let Some(value) = input.extended_eps_qos {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ExtendedEpsQos(value),
        )?);
    }
    if let Some(value) = &input.tft {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::Tft(value.clone()),
        )?);
    }
    if let Some(value) = input.apn_ambr {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ApnAmbr(value),
        )?);
    }
    if let Some(value) = input.extended_apn_ambr {
        payloads.push(build_ikev2_dedicated_bearer_notify(
            &Ikev2DedicatedBearerNotify::ExtendedApnAmbr(value),
        )?);
    }
    Ikev2DedicatedBearerCleartextPayloads::encode(payloads)
}

/// Decode a strict bearer modification INFORMATIONAL request.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] for a malformed header,
/// duplicate/missing MODIFIED_BEARER, invalid optional dependency, no-op
/// request, or prohibited payload.
pub fn decode_ikev2_dedicated_bearer_modification_request<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerModificationRequest<'a>, Ikev2DedicatedBearerExchangeError> {
    validate_exchange_header(header, EXCHANGE_TYPE_INFORMATIONAL, false)?;
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    validate_cleartext_len(cleartext_payloads, context.max_message_len)?;
    let mut parts = InformationalParts::default();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2DedicatedBearerExchangeError::PayloadChain)?;
        parts.decode_modification_payload(raw, context.unknown_ie_policy)?;
    }
    let modified_bearer = required(
        parts.modified_bearer,
        Ikev2DedicatedBearerPayloadRole::ModifiedBearer,
    )?;
    validate_modification_shape(
        parts.eps_qos.as_ref(),
        parts.extended_eps_qos,
        parts.tft.as_ref(),
        parts.apn_ambr,
        parts.extended_apn_ambr,
    )?;
    Ok(Ikev2DedicatedBearerModificationRequest {
        modified_bearer,
        eps_qos: parts.eps_qos,
        extended_eps_qos: parts.extended_eps_qos,
        tft: parts.tft,
        apn_ambr: parts.apn_ambr,
        extended_apn_ambr: parts.extended_apn_ambr,
        unknown_noncritical_payloads: parts.unknown_noncritical_payloads,
        unrecognized_notifies: parts.unrecognized_notifies,
    })
}

/// Build and encode an INFORMATIONAL Delete request for one ePDG-owned ESP SPI.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] if the existing Delete codec
/// rejects the protocol/SPI shape or the payload chain overflows.
pub fn build_ikev2_dedicated_bearer_delete_request(
    esp_spi: Ikev2DedicatedBearerEspSpi,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    let spi = esp_spi.to_be_bytes();
    let body = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&spi],
    )
    .map_err(Ikev2DedicatedBearerExchangeError::Build)?;
    Ikev2DedicatedBearerCleartextPayloads::encode(vec![Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Delete,
        body,
    }])
}

/// Decode a strict INFORMATIONAL Delete request for one ePDG-owned ESP SPI.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] unless there is exactly one
/// ESP Delete payload naming exactly one non-zero four-octet SPI.
pub fn decode_ikev2_dedicated_bearer_delete_request<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerDeleteRequest<'a>, Ikev2DedicatedBearerExchangeError> {
    validate_exchange_header(header, EXCHANGE_TYPE_INFORMATIONAL, false)?;
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    validate_cleartext_len(cleartext_payloads, context.max_message_len)?;
    let mut parts = InformationalParts::default();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2DedicatedBearerExchangeError::PayloadChain)?;
        parts.decode_delete_payload(raw, context.unknown_ie_policy)?;
    }
    let delete = required(parts.delete, Ikev2DedicatedBearerPayloadRole::Delete)?;
    if delete.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP {
        return Err(Ikev2DedicatedBearerExchangeError::ChildSaProtocolNotEsp {
            actual: delete.protocol_id,
        });
    }
    if delete.spis.len() != 1 {
        return Err(Ikev2DedicatedBearerExchangeError::DeleteSpiCount {
            actual: delete.spis.len(),
        });
    }
    let esp_spi = Ikev2DedicatedBearerEspSpi::decode(delete.spis[0])?;
    Ok(Ikev2DedicatedBearerDeleteRequest {
        esp_spi,
        unknown_noncritical_payloads: parts.unknown_noncritical_payloads,
        unrecognized_notifies: parts.unrecognized_notifies,
    })
}

/// Build an empty successful INFORMATIONAL response opened-payload chain.
pub fn build_ikev2_dedicated_bearer_informational_success_response(
) -> Ikev2DedicatedBearerCleartextPayloads {
    Ikev2DedicatedBearerCleartextPayloads::empty()
}

/// Build a TS 24.302 private-error INFORMATIONAL response.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] if the Notify cannot be
/// represented in the IKEv2 payload length.
pub fn build_ikev2_dedicated_bearer_informational_error_response(
    error: Ikev2DedicatedBearerProtocolError,
) -> Result<Ikev2DedicatedBearerCleartextPayloads, Ikev2DedicatedBearerExchangeError> {
    build_ikev2_dedicated_bearer_create_child_sa_error_response(error)
}

/// Decode a strict INFORMATIONAL response for modification or deletion.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] if an error Notify is mixed
/// with other payloads, duplicate errors occur, or a prohibited payload appears.
pub fn decode_ikev2_dedicated_bearer_informational_response<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerInformationalResponse<'a>, Ikev2DedicatedBearerExchangeError> {
    validate_exchange_header(header, EXCHANGE_TYPE_INFORMATIONAL, true)?;
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    validate_cleartext_len(cleartext_payloads, context.max_message_len)?;
    let mut parts = InformationalParts::default();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|_| Ikev2DedicatedBearerExchangeError::PayloadChain)?;
        parts.decode_response_payload(raw, context.unknown_ie_policy)?;
    }
    if let Some(error) = parts.error {
        if !parts.unknown_noncritical_payloads.is_empty()
            || !parts.unrecognized_notifies.is_empty()
            || parts.modified_bearer.is_some()
            || parts.eps_qos.is_some()
            || parts.extended_eps_qos.is_some()
            || parts.tft.is_some()
            || parts.apn_ambr.is_some()
            || parts.extended_apn_ambr.is_some()
            || parts.delete.is_some()
        {
            return Err(Ikev2DedicatedBearerExchangeError::ErrorResponseMixedWithPayloads);
        }
        Ok(Ikev2DedicatedBearerInformationalResponse::Error(error))
    } else {
        Ok(Ikev2DedicatedBearerInformationalResponse::Success {
            unknown_noncritical_payloads: parts.unknown_noncritical_payloads,
            unrecognized_notifies: parts.unrecognized_notifies,
        })
    }
}

/// Validate exact request/response IKE SPI, exchange, and Message-ID correlation.
///
/// This helper is independent of retransmission timing. Callers can pair it
/// with [`crate::Ikev2InitiatorMessageIdWindow`] and the immutable cleartext
/// representation returned by the builders.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch`]
/// unless the response exactly matches a valid CREATE_CHILD_SA or
/// INFORMATIONAL request header.
pub fn validate_ikev2_dedicated_bearer_response_correlation(
    request: &Header,
    response: &Header,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if request.flags.response()
        || !response.flags.response()
        || request.exchange_type != response.exchange_type
        || !matches!(
            request.exchange_type,
            EXCHANGE_TYPE_CREATE_CHILD_SA | EXCHANGE_TYPE_INFORMATIONAL
        )
        || request.initiator_spi == 0
        || request.responder_spi == 0
        || request.initiator_spi != response.initiator_spi
        || request.responder_spi != response.responder_spi
        || request.message_id != response.message_id
        // RFC 7296's I flag names the original IKE-SA endpoint sending this
        // message. A response is sent by the opposite endpoint, so it must be
        // the inverse of the request's I flag.
        || request.flags.initiator() == response.flags.initiator()
    {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch);
    }
    Ok(())
}

/// Validate CREATE_CHILD_SA header and successful selection correlation.
///
/// Besides the two IKE SPIs, Message ID, exchange type, and response flag, a
/// successful response must select an offered proposal number and transforms,
/// retain the request's KE group when PFS is used, and narrow rather than
/// expand both traffic-selector sets. A protocol-error response needs only the
/// exact header correlation because it does not select a Child SA.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError`] if the header or any selected
/// proposal, transform, KE group, or traffic selector does not correlate.
pub fn validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
    request_header: &Header,
    response_header: &Header,
    request: &Ikev2DedicatedBearerCreateChildSaRequest<'_>,
    response: &Ikev2DedicatedBearerCreateChildSaResponse<'_>,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    validate_ikev2_dedicated_bearer_response_correlation(request_header, response_header)?;
    if request_header.exchange_type != EXCHANGE_TYPE_CREATE_CHILD_SA {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch);
    }
    let Ikev2DedicatedBearerCreateChildSaResponse::Success {
        security_association,
        key_exchange,
        traffic_selectors_initiator,
        traffic_selectors_responder,
        ..
    } = response
    else {
        return Ok(());
    };
    let selected = security_association
        .proposals
        .first()
        .ok_or(Ikev2DedicatedBearerExchangeError::ResponseProposalNotOffered)?;
    let offered = request
        .security_association
        .proposals
        .iter()
        .find(|proposal| {
            proposal.proposal_number == selected.proposal_number
                && proposal.protocol_id == selected.protocol_id
        })
        .ok_or(Ikev2DedicatedBearerExchangeError::ResponseProposalNotOffered)?;
    let mut selected_types = BTreeSet::new();
    for transform in &selected.transforms {
        if !selected_types.insert(transform.transform_type)
            || !offered
                .transforms
                .iter()
                .any(|candidate| candidate == transform)
        {
            return Err(Ikev2DedicatedBearerExchangeError::ResponseTransformNotOffered);
        }
    }
    match (request.key_exchange.as_ref(), key_exchange.as_ref()) {
        (Some(request_ke), Some(response_ke)) if request_ke.dh_group == response_ke.dh_group => {}
        (None, None) => {}
        _ => return Err(Ikev2DedicatedBearerExchangeError::ResponseKeyExchangeMismatch),
    }
    if !traffic_selector_payload_is_narrowed(
        &request.traffic_selectors_initiator,
        traffic_selectors_initiator,
    ) || !traffic_selector_payload_is_narrowed(
        &request.traffic_selectors_responder,
        traffic_selectors_responder,
    ) {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseTrafficSelectorsExpanded);
    }
    Ok(())
}

/// Validate exact correlation of a bearer-modification INFORMATIONAL response.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch`]
/// for any SPI, Message-ID, flag, or exchange mismatch.
pub fn validate_ikev2_dedicated_bearer_modification_response_correlation(
    request_header: &Header,
    response_header: &Header,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    validate_informational_header_correlation(request_header, response_header)
}

/// Validate exact correlation of a bearer-deletion INFORMATIONAL response.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch`]
/// for any SPI, Message-ID, flag, or exchange mismatch.
pub fn validate_ikev2_dedicated_bearer_delete_response_correlation(
    request_header: &Header,
    response_header: &Header,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    validate_informational_header_correlation(request_header, response_header)
}

fn validate_informational_header_correlation(
    request_header: &Header,
    response_header: &Header,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    validate_ikev2_dedicated_bearer_response_correlation(request_header, response_header)?;
    if request_header.exchange_type != EXCHANGE_TYPE_INFORMATIONAL {
        return Err(Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch);
    }
    Ok(())
}

fn traffic_selector_payload_is_narrowed(
    requested: &Ikev2TrafficSelectorPayload<'_>,
    selected: &Ikev2TrafficSelectorPayload<'_>,
) -> bool {
    selected.selectors.iter().all(|selected| {
        requested.selectors.iter().any(|requested| {
            selected.ts_type == requested.ts_type
                && (requested.ip_protocol_id == 0
                    || selected.ip_protocol_id == requested.ip_protocol_id)
                && selected.start_port >= requested.start_port
                && selected.end_port <= requested.end_port
                && selected.start_address >= requested.start_address
                && selected.end_address <= requested.end_address
        })
    })
}

#[derive(Default)]
struct InformationalParts<'a> {
    modified_bearer: Option<Ikev2DedicatedBearerEspSpi>,
    eps_qos: Option<Ikev2EpsQos>,
    extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    tft: Option<opc_proto_tft::TrafficFlowTemplate>,
    apn_ambr: Option<Ikev2ApnAmbr>,
    extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
    delete: Option<Ikev2DeletePayload<'a>>,
    error: Option<Ikev2DedicatedBearerResponseError<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
}

impl<'a> InformationalParts<'a> {
    fn decode_modification_payload(
        &mut self,
        raw: RawPayload<'a>,
        policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        match raw.payload_type {
            PayloadType::Notify => self.decode_modification_notify(raw, policy),
            PayloadType::Unknown(value) => preserve_unknown(
                &mut self.unknown_noncritical_payloads,
                value,
                raw.body,
                policy,
            ),
            _ => Err(Ikev2DedicatedBearerExchangeError::UnexpectedPayloadType {
                payload_type: raw.payload_type.as_u8(),
            }),
        }
    }

    fn decode_modification_notify(
        &mut self,
        raw: RawPayload<'a>,
        policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        let notify =
            Ikev2NotifyPayload::decode(raw).map_err(Ikev2DedicatedBearerExchangeError::Notify)?;
        match decode_ikev2_dedicated_bearer_notify(notify)? {
            Some(Ikev2DedicatedBearerNotify::ModifiedBearer(value)) => set_once(
                &mut self.modified_bearer,
                value,
                Ikev2DedicatedBearerPayloadRole::ModifiedBearer,
            ),
            Some(Ikev2DedicatedBearerNotify::EpsQos(value)) => set_once(
                &mut self.eps_qos,
                value,
                Ikev2DedicatedBearerPayloadRole::EpsQos,
            ),
            Some(Ikev2DedicatedBearerNotify::ExtendedEpsQos(value)) => set_once(
                &mut self.extended_eps_qos,
                value,
                Ikev2DedicatedBearerPayloadRole::ExtendedEpsQos,
            ),
            Some(Ikev2DedicatedBearerNotify::Tft(value)) => {
                set_once(&mut self.tft, value, Ikev2DedicatedBearerPayloadRole::Tft)
            }
            Some(Ikev2DedicatedBearerNotify::ApnAmbr(value)) => set_once(
                &mut self.apn_ambr,
                value,
                Ikev2DedicatedBearerPayloadRole::ApnAmbr,
            ),
            Some(Ikev2DedicatedBearerNotify::ExtendedApnAmbr(value)) => set_once(
                &mut self.extended_apn_ambr,
                value,
                Ikev2DedicatedBearerPayloadRole::ExtendedApnAmbr,
            ),
            Some(
                Ikev2DedicatedBearerNotify::ProtocolError(_)
                | Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity,
            ) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                notify_message_type: notify.notify_message_type,
            }),
            None => preserve_notify(&mut self.unrecognized_notifies, notify, policy),
        }
    }

    fn decode_delete_payload(
        &mut self,
        raw: RawPayload<'a>,
        policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        match raw.payload_type {
            PayloadType::Delete => set_once(
                &mut self.delete,
                Ikev2DeletePayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::Payload)?,
                Ikev2DedicatedBearerPayloadRole::Delete,
            ),
            PayloadType::Notify => {
                let notify = Ikev2NotifyPayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::Notify)?;
                match decode_ikev2_dedicated_bearer_notify(notify)? {
                    Some(_) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                        notify_message_type: notify.notify_message_type,
                    }),
                    None => preserve_notify(&mut self.unrecognized_notifies, notify, policy),
                }
            }
            PayloadType::Unknown(value) => preserve_unknown(
                &mut self.unknown_noncritical_payloads,
                value,
                raw.body,
                policy,
            ),
            _ => Err(Ikev2DedicatedBearerExchangeError::UnexpectedPayloadType {
                payload_type: raw.payload_type.as_u8(),
            }),
        }
    }

    fn decode_response_payload(
        &mut self,
        raw: RawPayload<'a>,
        policy: UnknownIePolicy,
    ) -> Result<(), Ikev2DedicatedBearerExchangeError> {
        match raw.payload_type {
            PayloadType::Notify => {
                let notify = Ikev2NotifyPayload::decode(raw)
                    .map_err(Ikev2DedicatedBearerExchangeError::Notify)?;
                if notify.notify_message_type < 16_384 {
                    let error = match decode_ikev2_dedicated_bearer_notify(notify)? {
                        Some(Ikev2DedicatedBearerNotify::ProtocolError(error)) => {
                            Ikev2DedicatedBearerResponseError::DedicatedBearer(error)
                        }
                        Some(_) => {
                            return Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                                notify_message_type: notify.notify_message_type,
                            })
                        }
                        None => Ikev2DedicatedBearerResponseError::Peer(
                            Ikev2DedicatedBearerPeerErrorNotify {
                                notify_message_type: notify.notify_message_type,
                                protocol_id: notify.protocol_id,
                                spi: notify.spi,
                                notification_data: notify.notification_data,
                            },
                        ),
                    };
                    set_once(
                        &mut self.error,
                        error,
                        Ikev2DedicatedBearerPayloadRole::ErrorNotify,
                    )
                } else {
                    match decode_ikev2_dedicated_bearer_notify(notify)? {
                        Some(_) => Err(Ikev2DedicatedBearerExchangeError::UnexpectedNotifyType {
                            notify_message_type: notify.notify_message_type,
                        }),
                        None => preserve_notify(&mut self.unrecognized_notifies, notify, policy),
                    }
                }
            }
            PayloadType::Unknown(value) => preserve_unknown(
                &mut self.unknown_noncritical_payloads,
                value,
                raw.body,
                policy,
            ),
            _ => Err(Ikev2DedicatedBearerExchangeError::UnexpectedPayloadType {
                payload_type: raw.payload_type.as_u8(),
            }),
        }
    }
}

fn validate_modification_shape(
    eps_qos: Option<&Ikev2EpsQos>,
    extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    tft: Option<&opc_proto_tft::TrafficFlowTemplate>,
    apn_ambr: Option<Ikev2ApnAmbr>,
    extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
) -> Result<(), Ikev2DedicatedBearerExchangeError> {
    if extended_eps_qos.is_some() && eps_qos.is_none() {
        return Err(Ikev2DedicatedBearerExchangeError::ExtendedEpsQosWithoutEpsQos);
    }
    validate_extended_ambr_dependency(apn_ambr, extended_apn_ambr)?;
    if eps_qos.is_none() && tft.is_none() && apn_ambr.is_none() {
        return Err(Ikev2DedicatedBearerExchangeError::ModificationHasNoUpdates);
    }
    Ok(())
}
