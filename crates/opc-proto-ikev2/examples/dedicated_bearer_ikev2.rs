//! Minimal IKEv2 opened-payload dedicated-bearer establishment and deletion flow.

use std::error::Error;

use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_create_child_sa_request,
    build_ikev2_dedicated_bearer_create_child_sa_response,
    build_ikev2_dedicated_bearer_delete_request,
    build_ikev2_dedicated_bearer_informational_success_response,
    decode_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    decode_ikev2_dedicated_bearer_delete_request,
    decode_ikev2_dedicated_bearer_informational_response,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    validate_ikev2_dedicated_bearer_delete_response_correlation, Header, HeaderFlags,
    Ikev2DedicatedBearerCreateChildSaRequestBuild, Ikev2DedicatedBearerCreateChildSaResponseBuild,
    Ikev2DedicatedBearerEspSpi, Ikev2EpsQos, Ikev2NoncePayloadBuild, Ikev2SaPayloadBuild,
    Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild,
    Ikev2TrafficSelectorPayloadBuild, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_INFORMATIONAL, IKEV2_SECURITY_PROTOCOL_ID_ESP, IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TrafficFlowTemplate,
};

fn header(exchange_type: u8, message_id: u32, response: bool) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(response, response, false),
        message_id,
    )
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
                    attributes: vec![],
                },
                Ikev2SaTransformBuild {
                    transform_type: 5,
                    transform_id: 0,
                    attributes: vec![],
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

fn main() -> Result<(), Box<dyn Error>> {
    let filter = PacketFilter::new(
        PacketFilterIdentifier::new(1)?,
        PacketFilterDirection::Bidirectional,
        10,
        vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
    )?;
    let tft = TrafficFlowTemplate::create_new(vec![filter], vec![])?;
    let request_build = Ikev2DedicatedBearerCreateChildSaRequestBuild {
        security_association: child_sa([1, 2, 3, 4]),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: selectors(),
        traffic_selectors_responder: selectors(),
        eps_qos: Ikev2EpsQos::new(1, None, None, None)?,
        extended_eps_qos: None,
        tft,
        apn_ambr: None,
        extended_apn_ambr: None,
    };
    let request_payloads = build_ikev2_dedicated_bearer_create_child_sa_request(&request_build)?;
    let request_header = header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7, false);
    let request = decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_payloads.first_payload(),
        request_payloads.bytes(),
    )?;

    let response_build = Ikev2DedicatedBearerCreateChildSaResponseBuild {
        security_association: child_sa([5, 6, 7, 8]),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x22; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: selectors(),
        traffic_selectors_responder: selectors(),
    };
    let response_payloads = build_ikev2_dedicated_bearer_create_child_sa_response(&response_build)?;
    let response_header = header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7, true);
    let response = decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        response_payloads.first_payload(),
        response_payloads.bytes(),
    )?;
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
        &request_header,
        &response_header,
        &request,
        &response,
    )?;

    let child_spi = Ikev2DedicatedBearerEspSpi::new(0x1020_3040)?;
    let delete_payloads = build_ikev2_dedicated_bearer_delete_request(child_spi)?;
    let delete_header = header(EXCHANGE_TYPE_INFORMATIONAL, 8, false);
    decode_ikev2_dedicated_bearer_delete_request(
        &delete_header,
        delete_payloads.first_payload(),
        delete_payloads.bytes(),
    )?;
    let delete_response = build_ikev2_dedicated_bearer_informational_success_response();
    let delete_response_header = header(EXCHANGE_TYPE_INFORMATIONAL, 8, true);
    decode_ikev2_dedicated_bearer_informational_response(
        &delete_response_header,
        delete_response.first_payload(),
        delete_response.bytes(),
    )?;
    validate_ikev2_dedicated_bearer_delete_response_correlation(
        &delete_header,
        &delete_response_header,
    )?;

    Ok(())
}
