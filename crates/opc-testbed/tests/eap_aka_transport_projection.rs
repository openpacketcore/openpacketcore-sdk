use std::{error::Error, num::NonZeroU64};

use opc_proto_diameter::apps::swm::{
    build_swm_diameter_eap_answer_for, build_swm_diameter_eap_request,
    parse_swm_diameter_eap_request_envelope,
    parse_swm_diameter_eap_response_envelope_from_connection, AuthRequestType,
    SwmDiameterConnectionToken, SwmDiameterEapAnswer, SwmDiameterEapRequest, SwmDiameterResult,
    SwmExpectedAnswerPeer, APPLICATION_ID,
};
use opc_proto_diameter::Message as DiameterMessage;
use opc_proto_eap::{EapAkaError, EapAkaMethod, EapAkaPacketKind};
use opc_proto_ikev2::ike_auth::Ikev2EapPayload;
use opc_protocol::{DecodeContext, EncodeContext};

fn fixed(attribute_type: u8, length_units: u8) -> Vec<u8> {
    let mut attribute = vec![0; usize::from(length_units) * 4];
    attribute[0] = attribute_type;
    attribute[1] = length_units;
    attribute
}

fn kdf_input() -> Vec<u8> {
    vec![23, 2, 0, 4, b'W', b'L', b'A', b'N']
}

fn aka_prime_challenge_request() -> Vec<u8> {
    let attributes = [
        fixed(1, 5),
        fixed(2, 5),
        vec![24, 1, 0, 1],
        kdf_input(),
        fixed(11, 5),
    ];
    let len = 8 + attributes.iter().map(Vec::len).sum::<usize>();
    let mut packet = Vec::with_capacity(len);
    packet.extend_from_slice(&[1, 41]);
    packet.extend_from_slice(&(len as u16).to_be_bytes());
    packet.extend_from_slice(&[50, 1, 0, 0]);
    for attribute in attributes {
        packet.extend_from_slice(&attribute);
    }
    packet
}

fn aka_prime_challenge_response() -> Vec<u8> {
    let mut response = vec![3, 3, 0, 64];
    response.extend_from_slice(&[0xa5; 8]);
    let attributes = [response, fixed(11, 5)];
    let len = 8 + attributes.iter().map(Vec::len).sum::<usize>();
    let mut packet = Vec::with_capacity(len);
    packet.extend_from_slice(&[2, 41]);
    packet.extend_from_slice(&(len as u16).to_be_bytes());
    packet.extend_from_slice(&[50, 1, 0, 0]);
    for attribute in attributes {
        packet.extend_from_slice(&attribute);
    }
    packet
}

fn sample_der(eap_payload: Vec<u8>) -> SwmDiameterEapRequest {
    SwmDiameterEapRequest {
        session_id: "synthetic-session".into(),
        auth_application_id: APPLICATION_ID.get(),
        origin_host: "epdg.invalid".into(),
        origin_realm: "visited.invalid".into(),
        destination_realm: "home.invalid".into(),
        destination_host: Some("aaa.invalid".into()),
        user_name: None,
        rat_type: None,
        service_selection: None,
        mip6_feature_vector: None,
        qos_capability: None,
        visited_network_identifier: None,
        aaa_failure_indication: None,
        supported_features: Vec::new(),
        ue_local_ip_address: None,
        oc_supported_features: None,
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: eap_payload.into(),
        emergency_services: None,
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: Vec::new(),
        route_records: Vec::new(),
        extensions: Default::default(),
    }
}

fn sample_dea(eap_payload: Vec<u8>) -> SwmDiameterEapAnswer {
    SwmDiameterEapAnswer {
        session_id: "synthetic-session".into(),
        auth_application_id: APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(1001),
        origin_host: "aaa.invalid".into(),
        origin_realm: "home.invalid".into(),
        user_name: None,
        subscriber_authorization: Default::default(),
        mip6_feature_vector: None,
        supported_features: Vec::new(),
        oc_supported_features: None,
        oc_olr: None,
        load_reports: Vec::new(),
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: None,
        session_timeout: None,
        multi_round_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(eap_payload.into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
        extensions: Default::default(),
    }
}

fn correlated_dea_projection_kind(
    eap_payload: Vec<u8>,
) -> Result<Result<EapAkaPacketKind, EapAkaError>, Box<dyn Error>> {
    let request = sample_der(aka_prime_challenge_response());
    let request_owned = build_swm_diameter_eap_request(
        &request,
        0x1000_0029,
        0x2000_0029,
        EncodeContext::default(),
    )?;
    let request_message = DiameterMessage {
        header: request_owned.header.clone(),
        raw_avps: &request_owned.raw_avps,
        tail: &[],
    };
    let connection = SwmDiameterConnectionToken::new(NonZeroU64::MIN);
    let request_envelope =
        parse_swm_diameter_eap_request_envelope(&request_message, DecodeContext::conservative())?
            .with_expected_answer_peer(SwmExpectedAnswerPeer::direct(
                connection,
                "aaa.invalid",
                "home.invalid",
            ));

    let answer = sample_dea(eap_payload);
    let answer_owned =
        build_swm_diameter_eap_answer_for(&request_envelope, &answer, EncodeContext::default())?;
    let answer_message = DiameterMessage {
        header: answer_owned.header.clone(),
        raw_avps: &answer_owned.raw_avps,
        tail: &[],
    };
    let response = parse_swm_diameter_eap_response_envelope_from_connection(
        &answer_message,
        connection,
        DecodeContext::conservative(),
    )?;
    let correlated = request_envelope.correlate_response(response)?;
    match correlated.project_eap_payload_aka() {
        Ok(Some(projection)) => Ok(Ok(projection.kind())),
        Ok(None) => Err("correlated EAP payload is absent".into()),
        Err(error) => Ok(Err(error)),
    }
}

#[test]
fn ikev2_and_swm_use_identical_aka_projection_in_each_real_direction() {
    let challenge = aka_prime_challenge_request();
    let ike_challenge =
        Ikev2EapPayload::decode_body(&challenge).expect("synthetic EAP payload is nonempty");
    let ike_challenge = ike_challenge
        .project_aka()
        .expect("synthetic AKA-prime request is valid");
    let dea = sample_dea(challenge.clone());
    let dea_projection = dea
        .project_eap_payload_aka()
        .expect("DEA uses the canonical parser")
        .expect("DEA payload is present");

    assert_eq!(ike_challenge.method(), EapAkaMethod::AkaPrime);
    assert_eq!(ike_challenge.kind(), dea_projection.kind());
    assert!(matches!(
        dea_projection.kind(),
        EapAkaPacketKind::ChallengeRequest(_)
    ));

    let response = aka_prime_challenge_response();
    let ike_response =
        Ikev2EapPayload::decode_body(&response).expect("synthetic EAP payload is nonempty");
    let ike_response = ike_response
        .project_aka()
        .expect("synthetic AKA-prime response is valid");
    let der = sample_der(response.clone());
    let der_projection = der
        .project_eap_aka()
        .expect("DER uses the canonical parser");

    assert_eq!(ike_response.kind(), der_projection.kind());
    assert!(matches!(
        der_projection.kind(),
        EapAkaPacketKind::FullChallengeResponse(_)
    ));
}

#[test]
fn every_transport_preserves_the_same_redaction_safe_error() {
    let malformed_request = vec![1, 7, 0, 8, 50, 1, 0, 1];
    let ike = Ikev2EapPayload::decode_body(&malformed_request)
        .expect("outer IKE EAP payload is nonempty");
    let dea = sample_dea(malformed_request.clone());

    let ike_error = ike
        .project_aka()
        .expect_err("method reserved field is nonzero");
    let dea_error = dea
        .project_eap_payload_aka()
        .expect_err("method reserved field is nonzero");
    assert_eq!(ike_error, dea_error);
    assert_eq!(ike_error.code(), "eap_aka_reserved_field_nonzero");

    let malformed_response = vec![2, 7, 0, 8, 50, 1, 0, 1];
    let ike = Ikev2EapPayload::decode_body(&malformed_response)
        .expect("outer IKE EAP payload is nonempty");
    let der = sample_der(malformed_response.clone());
    let ike_error = ike
        .project_aka()
        .expect_err("method reserved field is nonzero");
    let der_error = der
        .project_eap_aka()
        .expect_err("method reserved field is nonzero");
    assert_eq!(ike_error, der_error);
    assert_eq!(ike_error.code(), "eap_aka_reserved_field_nonzero");
}

#[test]
fn authenticated_correlated_swm_response_exposes_canonical_projection() -> Result<(), Box<dyn Error>>
{
    let eap_request = aka_prime_challenge_request();
    let correlated_kind = correlated_dea_projection_kind(eap_request.clone())??;
    let ike_projection = Ikev2EapPayload::decode_body(&eap_request)?.project_aka()?;

    assert_eq!(correlated_kind, ike_projection.kind());
    Ok(())
}

#[test]
fn authenticated_correlated_swm_response_preserves_projection_errors() -> Result<(), Box<dyn Error>>
{
    let malformed = vec![1, 7, 0, 8, 50, 1, 0, 1];
    let error =
        correlated_dea_projection_kind(malformed)?.expect_err("method reserved field is nonzero");
    assert_eq!(error, EapAkaError::ReservedFieldNonZero);
    Ok(())
}
