//! Complete SDK composition for one dedicated-bearer create/delete lifecycle.
//!
//! The SDK owns wire validation, request/response correlation, and exact GTP
//! response replay. The application remains responsible for admission policy,
//! allocating EBI/TEID/SPI values, and installing or deleting the Child SA.

use std::{error::Error, io::Error as IoError};

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    correlate_create_bearer_response, correlate_delete_bearer_response, s2b_create_bearer_request,
    s2b_create_bearer_response, s2b_delete_bearer_request, s2b_delete_bearer_response, BearerQos,
    CauseValue, ChargingId, EpsBearerId, FullyQualifiedTeid, Gtpv2cMonotonicMillis,
    Gtpv2cPeerToken, Gtpv2cTriggeredCompletion, Gtpv2cTriggeredRequestDisposition,
    Gtpv2cTriggeredTransactions, Gtpv2cTriggeredWorkToken, OwnedMessage, S2bCreateBearerRequest,
    S2bCreateBearerRequestContext, S2bCreateBearerResponse, S2bCreateBearerResult,
    S2bDeleteBearerRequest, S2bDeleteBearerResponse, S2bDeleteBearerResponseBody,
    S2bDeleteBearerResult, S2bDeleteBearerTarget, S2bMessage, INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
    INTERFACE_TYPE_S2B_U_PGW_GTP_U,
};
use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_create_child_sa_request,
    build_ikev2_dedicated_bearer_create_child_sa_response,
    build_ikev2_dedicated_bearer_delete_request, build_ikev2_dedicated_bearer_delete_response,
    decode_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    decode_ikev2_dedicated_bearer_delete_request, decode_ikev2_dedicated_bearer_delete_response,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    validate_ikev2_dedicated_bearer_delete_response_correlation, Header, HeaderFlags,
    Ikev2DedicatedBearerCreateChildSaRequestBuild, Ikev2DedicatedBearerCreateChildSaResponseBuild,
    Ikev2DedicatedBearerDeleteResponseExpectation, Ikev2DedicatedBearerEspSpi, Ikev2EpsQosKbps,
    Ikev2EpsQosMapping, Ikev2NoncePayloadBuild, Ikev2QosQuantization, Ikev2SaPayloadBuild,
    Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild,
    Ikev2TrafficSelectorPayloadBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_INFORMATIONAL, IKEV2_SECURITY_PROTOCOL_ID_ESP, IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TrafficFlowTemplate,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext};

const GTP_REQUEST_TEID: u32 = 0x1020_3040;
const GTP_RESPONSE_TEID: u32 = 0x5060_7080;
const GTP_SEQUENCE: u32 = 0x01_02_03;
const DEDICATED_EBI: EpsBearerId = EpsBearerId { value: 6 };
const UE_CHILD_SPI: [u8; 4] = [1, 2, 3, 4];
const EPDG_CHILD_SPI: [u8; 4] = [5, 6, 7, 8];

fn main() -> Result<(), Box<dyn Error>> {
    let peer = Gtpv2cPeerToken::new(7);
    let mut transactions = Gtpv2cTriggeredTransactions::default();

    create_dedicated_bearer(&mut transactions, peer)?;
    delete_dedicated_bearer(&mut transactions, peer)?;
    Ok(())
}

fn create_dedicated_bearer(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
) -> Result<(), Box<dyn Error>> {
    let tft = create_tft()?;
    let request_message = s2b_create_bearer_request(S2bCreateBearerRequest {
        sequence_number: GTP_SEQUENCE,
        teid: GTP_REQUEST_TEID,
        message_priority: None,
        linked_ebi: EpsBearerId { value: 5 },
        bearer_contexts: vec![S2bCreateBearerRequestContext {
            tft,
            // QCI-only EPS QoS is lossless for this non-GBR example because
            // every optional GTP bearer bit-rate is explicitly zero.
            bearer_qos: BearerQos {
                priority_flags: 0x4f,
                qci: 9,
                maximum_bitrate_uplink: 0,
                maximum_bitrate_downlink: 0,
                guaranteed_bitrate_uplink: 0,
                guaranteed_bitrate_downlink: 0,
            },
            pgw_f_teid: FullyQualifiedTeid {
                interface_type: INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                teid: 0x1000_0001,
                ipv4: Some([192, 0, 2, 11]),
                ipv6: None,
            },
            charging_id: ChargingId { value: 0x2000_0001 },
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    })?;
    let encoded_request = encode_gtp(&request_message)?;
    let key = observe_dispatch(transactions, peer, encoded_request.clone(), 1_000)?;
    let decoded = decode_gtp(&encoded_request)?;
    let view = decoded
        .as_view()
        .ok_or_else(|| invalid_data("Create Bearer request used raw fallback"))?;
    let request = view.create_bearer_request()?;
    let context = request
        .bearer_contexts
        .first()
        .ok_or_else(|| invalid_data("Create Bearer request contained no context"))?;

    // Admission and identifier allocation happen once, only after Dispatch.
    // The typed GTP TFT is passed unchanged into the typed IKEv2 Notify.
    let mapped_qos = Ikev2EpsQosMapping::from_kbps(
        Ikev2EpsQosKbps::NonGbr {
            qci: context.bearer_qos.qci,
        },
        Ikev2QosQuantization::Exact,
    )?;
    let ike_request_build = Ikev2DedicatedBearerCreateChildSaRequestBuild {
        // An SA proposal carries the sending endpoint's inbound SPI. This
        // request is sent by the ePDG, so it advertises the ePDG-owned SPI.
        security_association: child_sa(EPDG_CHILD_SPI),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: selectors(),
        traffic_selectors_responder: selectors(),
        eps_qos: mapped_qos.eps_qos().clone(),
        extended_eps_qos: mapped_qos.extended_eps_qos(),
        tft: context.tft.clone(),
        apn_ambr: None,
        extended_apn_ambr: None,
    };
    let ike_request_payloads =
        build_ikev2_dedicated_bearer_create_child_sa_request(&ike_request_build)?;
    let ike_request_header = ike_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7, false);
    let ike_request = decode_ikev2_dedicated_bearer_create_child_sa_request(
        &ike_request_header,
        ike_request_payloads.first_payload(),
        ike_request_payloads.bytes(),
    )?;

    let ike_response_build = Ikev2DedicatedBearerCreateChildSaResponseBuild {
        // The UE response advertises the UE-owned inbound SPI.
        security_association: child_sa(UE_CHILD_SPI),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x22; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: selectors(),
        traffic_selectors_responder: selectors(),
    };
    let ike_response_payloads =
        build_ikev2_dedicated_bearer_create_child_sa_response(&ike_response_build)?;
    let ike_response_header = ike_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7, true);
    let ike_response = decode_ikev2_dedicated_bearer_create_child_sa_response(
        &ike_response_header,
        ike_response_payloads.first_payload(),
        ike_response_payloads.bytes(),
    )?;
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
        &ike_request_header,
        &ike_response_header,
        &ike_request,
        &ike_response,
    )?;

    // Only now does the application install the negotiated Child SA and
    // publish its ePDG-side GTP-U endpoint. The SDK validates the GTP reply.
    let response = S2bCreateBearerResponse {
        sequence_number: request.sequence_number,
        teid: GTP_RESPONSE_TEID,
        message_priority: request.message_priority,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bCreateBearerResult::Accepted {
            ebi: DEDICATED_EBI,
            epdg_f_teid: FullyQualifiedTeid {
                interface_type: INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
                teid: 0x3000_0001,
                ipv4: Some([192, 0, 2, 21]),
                ipv6: None,
            },
            pgw_f_teid: context.pgw_f_teid.clone(),
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    correlate_create_bearer_response(&request, &response)?;
    let encoded_response = encode_gtp(&s2b_create_bearer_response(response)?)?;
    transactions.commit_response(
        key,
        Gtpv2cTriggeredCompletion::Accepted(encoded_response.clone()),
        Gtpv2cMonotonicMillis::new(1_001),
        DecodeContext::default(),
    )?;
    verify_replay(transactions, peer, encoded_request, encoded_response, 1_002)
}

fn delete_dedicated_bearer(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
) -> Result<(), Box<dyn Error>> {
    let request_message = s2b_delete_bearer_request(S2bDeleteBearerRequest {
        sequence_number: GTP_SEQUENCE.wrapping_add(1),
        teid: GTP_REQUEST_TEID,
        message_priority: None,
        target: S2bDeleteBearerTarget::Dedicated(vec![DEDICATED_EBI]),
        cause: None,
        additional_ies: Vec::new(),
    })?;
    let encoded_request = encode_gtp(&request_message)?;
    let key = observe_dispatch(transactions, peer, encoded_request.clone(), 2_000)?;
    let decoded = decode_gtp(&encoded_request)?;
    let view = decoded
        .as_view()
        .ok_or_else(|| invalid_data("Delete Bearer request used raw fallback"))?;
    let request = view.delete_bearer_request()?;
    if request.target != S2bDeleteBearerTarget::Dedicated(vec![DEDICATED_EBI]) {
        return Err(invalid_data("unexpected Delete Bearer target").into());
    }

    // The application looks up the ePDG-owned SPI bound to EBI 6 and performs
    // the IKE delete exactly once for this dispatched GTP transaction.
    let epdg_inbound_spi = Ikev2DedicatedBearerEspSpi::new(u32::from_be_bytes(EPDG_CHILD_SPI))?;
    let ue_inbound_spi = Ikev2DedicatedBearerEspSpi::new(u32::from_be_bytes(UE_CHILD_SPI))?;
    let ike_delete_payloads = build_ikev2_dedicated_bearer_delete_request(epdg_inbound_spi)?;
    let ike_delete_header = ike_header(EXCHANGE_TYPE_INFORMATIONAL, 8, false);
    let ike_delete_request = decode_ikev2_dedicated_bearer_delete_request(
        &ike_delete_header,
        ike_delete_payloads.first_payload(),
        ike_delete_payloads.bytes(),
    )?;
    let ike_response_payloads = build_ikev2_dedicated_bearer_delete_response(ue_inbound_spi)?;
    let ike_response_header = ike_header(EXCHANGE_TYPE_INFORMATIONAL, 8, true);
    let ike_delete_response = decode_ikev2_dedicated_bearer_delete_response(
        &ike_response_header,
        ike_response_payloads.first_payload(),
        ike_response_payloads.bytes(),
    )?;
    validate_ikev2_dedicated_bearer_delete_response_correlation(
        &ike_delete_header,
        &ike_response_header,
        &ike_delete_request,
        &ike_delete_response,
        Ikev2DedicatedBearerDeleteResponseExpectation::PairedSa {
            local_inbound_esp_spi: epdg_inbound_spi,
            peer_inbound_esp_spi: ue_inbound_spi,
        },
    )?;

    let response = S2bDeleteBearerResponse {
        sequence_number: request.sequence_number,
        teid: GTP_RESPONSE_TEID,
        message_priority: request.message_priority,
        cause: CauseValue::RequestAccepted,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![S2bDeleteBearerResult {
            ebi: DEDICATED_EBI,
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        }]),
        additional_ies: Vec::new(),
    };
    correlate_delete_bearer_response(&request, &response)?;
    let encoded_response = encode_gtp(&s2b_delete_bearer_response(response)?)?;
    transactions.commit_response(
        key,
        Gtpv2cTriggeredCompletion::Accepted(encoded_response.clone()),
        Gtpv2cMonotonicMillis::new(2_001),
        DecodeContext::default(),
    )?;
    verify_replay(transactions, peer, encoded_request, encoded_response, 2_002)
}

fn create_tft() -> Result<TrafficFlowTemplate, Box<dyn Error>> {
    let filter = PacketFilter::new(
        PacketFilterIdentifier::new(1)?,
        PacketFilterDirection::Bidirectional,
        10,
        vec![
            PacketFilterComponent::ProtocolIdentifierNextHeader(17),
            PacketFilterComponent::SingleRemotePort(4_500),
        ],
    )?;
    Ok(TrafficFlowTemplate::create_new(vec![filter], vec![])?)
}

fn child_sa(spi: [u8; 4]) -> Ikev2SaPayloadBuild {
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
            spi: spi.to_vec(),
            transforms: vec![
                Ikev2SaTransformBuild {
                    transform_type: 1,
                    transform_id: 20,
                    attributes: vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(256),
                    }],
                },
                Ikev2SaTransformBuild {
                    transform_type: 5,
                    transform_id: 0,
                    attributes: Vec::new(),
                },
            ],
        }],
    }
}

fn selectors() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: [0, 0, 0, 0].to_vec(),
            end_address: [255, 255, 255, 255].to_vec(),
        }],
    }
}

fn ike_header(exchange_type: u8, message_id: u32, response: bool) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        exchange_type,
        // The UE is the original IKE initiator; ePDG requests therefore have
        // I=0/R=0 and UE responses have I=1/R=1.
        HeaderFlags::from_bits(response, response, false),
        message_id,
    )
}

fn observe_dispatch(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
    request: Bytes,
    now: u64,
) -> Result<Gtpv2cTriggeredWorkToken, Box<dyn Error>> {
    match transactions.observe_request(
        peer,
        request,
        GTP_RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(now),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => Ok(key),
        _ => Err(invalid_data("first GTP request did not dispatch").into()),
    }
}

fn verify_replay(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
    request: Bytes,
    expected_response: Bytes,
    now: u64,
) -> Result<(), Box<dyn Error>> {
    match transactions.observe_request(
        peer,
        request,
        GTP_RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(now),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Replay { response, .. }
            if response == expected_response =>
        {
            Ok(())
        }
        _ => Err(invalid_data("GTP retransmission did not replay exact response").into()),
    }
}

fn decode_gtp(encoded: &[u8]) -> Result<S2bMessage<'_>, Box<dyn Error>> {
    let (tail, message) = S2bMessage::decode(encoded, DecodeContext::default())?;
    if tail.is_empty() {
        Ok(message)
    } else {
        Err(invalid_data("GTPv2-C message left trailing bytes").into())
    }
}

fn encode_gtp(message: &OwnedMessage) -> Result<Bytes, Box<dyn Error>> {
    let mut encoded = BytesMut::new();
    message.encode(&mut encoded, EncodeContext::default())?;
    Ok(encoded.freeze())
}

fn invalid_data(message: &'static str) -> IoError {
    IoError::other(message)
}
