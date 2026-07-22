//! Deterministic public-API acceptance evidence for the complete SWm lifecycle.
//!
//! The two synthetic sessions use only exported `opc-proto-diameter` types and
//! functions. Product session lookup, authorization, teardown ordering, retry
//! timers, transport dispatch, and side effects deliberately remain outside
//! this fixture.

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{self, AuthRequestType};
use opc_proto_diameter::avp::dictionary::{Redacted, Sensitive};
use opc_proto_diameter::base;
use opc_proto_diameter::{CommandCode, Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use std::num::NonZeroU64;

const EPDG_HOST: &str = "epdg.lifecycle.private.invalid";
const EPDG_REALM: &str = "visited.lifecycle.private.invalid";
const AAA_HOST: &str = "aaa.lifecycle.private.invalid";
const AAA_REALM: &str = "home.lifecycle.private.invalid";
const SESSION_UPDATE: &str = "session;private;lifecycle-update-351";
const USER_UPDATE: &str = "subscriber-update@private.invalid";
const SESSION_ABORT: &str = "session;private;lifecycle-abort-351";
const USER_ABORT: &str = "subscriber-abort@private.invalid";
const DER_EAP_PAYLOAD: [u8; 8] = [0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03];
const DEA_EAP_PAYLOAD: [u8; 4] = [0x03, 0x17, 0x00, 0x04];
const DEA_MSK: [u8; 32] = [0xa5; 32];

const CONNECTION: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const DER_UPDATE: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0001, 0x3510_0002);
const RAR_UPDATE: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0011, 0x3510_0012);
const AAR_UPDATE: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0021, 0x3510_0022);
const STR_UPDATE: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0031, 0x3510_0032);
const DER_ABORT: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0101, 0x3510_0102);
const ASR_ABORT: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0111, 0x3510_0112);
const STR_ABORT: swm::SwmDiameterTransaction =
    swm::SwmDiameterTransaction::new(0x3510_0121, 0x3510_0122);

fn expected_aaa() -> swm::SwmExpectedAnswerPeer {
    swm::SwmExpectedAnswerPeer::direct(CONNECTION, AAA_HOST, AAA_REALM)
}

fn expected_epdg() -> swm::SwmExpectedAnswerPeer {
    swm::SwmExpectedAnswerPeer::direct(CONNECTION, EPDG_HOST, EPDG_REALM)
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("public typed message must encode");
    wire.to_vec()
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) =
        Message::decode(wire, DecodeContext::default()).expect("public typed message must frame");
    assert!(tail.is_empty(), "fixture must contain exactly one message");
    message
}

fn assert_header(
    wire: &[u8],
    command: CommandCode,
    request: bool,
    transaction: swm::SwmDiameterTransaction,
) {
    let message = decode(wire);
    assert_eq!(message.header.version, 1);
    assert_eq!(message.header.length as usize, wire.len());
    assert_eq!(message.header.command_code, command);
    assert_eq!(message.header.application_id, swm::APPLICATION_ID);
    assert_eq!(message.header.flags.is_request(), request);
    assert!(message.header.flags.is_proxiable());
    assert!(!message.header.flags.is_error());
    assert!(!message.header.flags.is_potentially_retransmitted());
    assert_eq!(
        message.header.hop_by_hop_identifier,
        transaction.hop_by_hop_identifier()
    );
    assert_eq!(
        message.header.end_to_end_identifier,
        transaction.end_to_end_identifier()
    );
}

fn assert_redacted(debug: &str, session: &str, user: &str) {
    assert!(!debug.contains(session));
    assert!(!debug.contains(user));
    assert!(!debug.contains(EPDG_HOST));
    assert!(!debug.contains(EPDG_REALM));
    assert!(!debug.contains(AAA_HOST));
    assert!(!debug.contains(AAA_REALM));
    for sensitive_bytes in [
        DER_EAP_PAYLOAD.as_slice(),
        DEA_EAP_PAYLOAD.as_slice(),
        DEA_MSK.as_slice(),
    ] {
        assert!(!debug.contains(&format!("{sensitive_bytes:?}")));
    }
}

fn establish_session(
    session: &str,
    user: &str,
    transaction: swm::SwmDiameterTransaction,
) -> swm::SwmCorrelatedDiameterEapExchange {
    let outbound = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        swm::SwmDiameterEapRequest {
            session_id: Redacted::from(session.to_owned()),
            auth_application_id: swm::APPLICATION_ID.get(),
            origin_host: Redacted::from(EPDG_HOST.to_owned()),
            origin_realm: Redacted::from(EPDG_REALM.to_owned()),
            destination_realm: Redacted::from(AAA_REALM.to_owned()),
            destination_host: Some(Redacted::from(AAA_HOST.to_owned())),
            user_name: Some(Redacted::from(user.to_owned())),
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
            eap_payload: Redacted::from(DER_EAP_PAYLOAD.to_vec()),
            emergency_services: None,
            terminal_information: None,
            high_priority_access_info: None,
            state_avps: Vec::new(),
            route_records: Vec::new(),
            extensions: Default::default(),
        },
        transaction,
    );
    let der = swm::build_swm_diameter_eap_request(
        outbound.request(),
        transaction.hop_by_hop_identifier(),
        transaction.end_to_end_identifier(),
        EncodeContext::default(),
    )
    .expect("public DER builder must accept the synthetic establishment");
    let der_wire = encode(&der);
    assert_header(&der_wire, swm::COMMAND_DIAMETER_EAP, true, transaction);
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_request(
                outbound.request(),
                transaction.hop_by_hop_identifier(),
                transaction.end_to_end_identifier(),
                EncodeContext::default(),
            )
            .expect("rebuilding the same DER must remain deterministic")
        ),
        der_wire
    );

    let inbound =
        swm::parse_swm_diameter_eap_request_envelope(&decode(&der_wire), DecodeContext::default())
            .expect("AAA boundary must parse the public DER envelope");
    assert_eq!(inbound.transaction(), transaction);
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_request(
                inbound.request(),
                transaction.hop_by_hop_identifier(),
                transaction.end_to_end_identifier(),
                EncodeContext::default(),
            )
            .expect("parsed DER must rebuild canonically")
        ),
        der_wire
    );

    let answer = swm::SwmDiameterEapAnswer {
        session_id: inbound.request().session_id.clone(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: inbound.request().auth_request_type,
        result: swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
        origin_host: Redacted::from(AAA_HOST.to_owned()),
        origin_realm: Redacted::from(AAA_REALM.to_owned()),
        user_name: inbound.request().user_name.clone(),
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
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(Redacted::from(DEA_EAP_PAYLOAD.to_vec())),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: Some(Redacted::from(DEA_MSK.to_vec())),
        extensions: Default::default(),
    };
    let dea = swm::build_swm_diameter_eap_answer_for(&inbound, &answer, EncodeContext::default())
        .expect("AAA boundary must build the request-bound DEA");
    let dea_wire = encode(&dea);
    assert_header(&dea_wire, swm::COMMAND_DIAMETER_EAP, false, transaction);
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer_for(&inbound, &answer, EncodeContext::default(),)
                .expect("rebuilding the same DEA must remain deterministic")
        ),
        dea_wire
    );

    let received =
        swm::parse_swm_diameter_eap_answer_envelope(&decode(&dea_wire), DecodeContext::default())
            .expect("ePDG boundary must parse the public DEA envelope");
    let correlated = outbound
        .correlate_answer(received)
        .expect("public DER/DEA envelopes must correlate");
    assert_eq!(correlated.transaction(), transaction);
    assert_eq!(
        correlated.answer().result,
        swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS)
    );
    assert_redacted(&format!("{correlated:?}"), session, user);
    correlated
}

fn terminate_session(
    request: swm::SwmSessionTerminationRequest,
    transaction: swm::SwmDiameterTransaction,
) -> swm::SwmCorrelatedSessionTerminationExchange {
    let session = request.session_id.as_ref().to_owned();
    let user = request.user_name.as_ref().to_owned();
    let outbound = swm::SwmSessionTerminationRequestEnvelope::for_outbound(
        request,
        transaction,
        expected_aaa(),
    );
    let str_message =
        swm::build_swm_session_termination_request(&outbound, EncodeContext::default())
            .expect("ePDG boundary must build the STR");
    let str_wire = encode(&str_message);
    assert_header(
        &str_wire,
        swm::COMMAND_SESSION_TERMINATION,
        true,
        transaction,
    );

    let inbound = swm::parse_swm_session_termination_request_envelope(
        &decode(&str_wire),
        DecodeContext::default(),
    )
    .expect("AAA boundary must parse the STR envelope");
    let canonical = inbound.clone().with_expected_answer_peer(expected_aaa());
    assert_eq!(
        encode(
            &swm::build_swm_session_termination_request(&canonical, EncodeContext::default(),)
                .expect("parsed STR must rebuild canonically")
        ),
        str_wire
    );

    let answer = swm::SwmSessionTerminationAnswer::for_request(
        &inbound,
        swm::SwmSessionTerminationResult::Success,
        Redacted::from(AAA_HOST.to_owned()),
        Redacted::from(AAA_REALM.to_owned()),
    );
    let sta_message =
        swm::build_swm_session_termination_answer(&inbound, &answer, EncodeContext::default())
            .expect("AAA boundary must build the request-bound STA");
    let sta_wire = encode(&sta_message);
    assert_header(
        &sta_wire,
        swm::COMMAND_SESSION_TERMINATION,
        false,
        transaction,
    );
    assert_eq!(
        encode(
            &swm::build_swm_session_termination_answer(
                &inbound,
                &answer,
                EncodeContext::default(),
            )
            .expect("rebuilding the same STA must remain deterministic")
        ),
        sta_wire
    );

    let received = swm::parse_swm_session_termination_answer_envelope_from_connection(
        &decode(&sta_wire),
        CONNECTION,
        DecodeContext::default(),
    )
    .expect("ePDG boundary must parse the STA envelope");
    let correlated = outbound
        .correlate_answer(received)
        .expect("public STR/STA envelopes must correlate");
    assert_eq!(correlated.transaction(), transaction);
    assert_eq!(
        correlated.answer().result,
        swm::SwmSessionTerminationResult::Success
    );
    assert_redacted(&format!("{correlated:?}"), &session, &user);
    correlated
}

#[test]
fn complete_swm_lifecycle_uses_only_public_sdk_boundaries() {
    let update_establishment = establish_session(SESSION_UPDATE, USER_UPDATE, DER_UPDATE);
    assert_eq!(
        update_establishment.request().session_id.as_ref(),
        SESSION_UPDATE
    );

    let outbound_rar = swm::SwmReAuthRequestEnvelope::for_outbound(
        swm::SwmReAuthRequest {
            session_id: Redacted::from(SESSION_UPDATE.to_owned()),
            origin_host: Redacted::from(AAA_HOST.to_owned()),
            origin_realm: Redacted::from(AAA_REALM.to_owned()),
            destination_realm: Redacted::from(EPDG_REALM.to_owned()),
            destination_host: Redacted::from(EPDG_HOST.to_owned()),
            re_auth_request_type: swm::SwmReAuthRequestType::AuthorizeOnly,
            user_name: Redacted::from(USER_UPDATE.to_owned()),
            drmp: None,
            route_records: Vec::new(),
            additional_avps: Vec::new(),
        },
        RAR_UPDATE,
        expected_epdg(),
    );
    let rar_message = swm::build_swm_re_auth_request(&outbound_rar, EncodeContext::default())
        .expect("AAA boundary must build the RAR");
    let rar_wire = encode(&rar_message);
    assert_header(&rar_wire, swm::COMMAND_RE_AUTH, true, RAR_UPDATE);
    let inbound_rar =
        swm::parse_swm_re_auth_request_envelope(&decode(&rar_wire), DecodeContext::default())
            .expect("ePDG boundary must parse the RAR envelope");
    let canonical_rar = inbound_rar
        .clone()
        .with_expected_answer_peer(expected_epdg());
    assert_eq!(
        encode(
            &swm::build_swm_re_auth_request(&canonical_rar, EncodeContext::default())
                .expect("parsed RAR must rebuild canonically")
        ),
        rar_wire
    );

    let raa = swm::SwmReAuthAnswer::for_request(
        &inbound_rar,
        swm::SwmReAuthResult::Success,
        Redacted::from(EPDG_HOST.to_owned()),
        Redacted::from(EPDG_REALM.to_owned()),
    );
    let accepted =
        swm::SwmAcceptedAuthorizationUpdate::accept(inbound_rar, raa, EncodeContext::default())
            .expect("ePDG boundary must commit the successful request-bound RAA");
    let raa_wire = encode(&accepted.replay_re_auth_answer());
    assert_header(&raa_wire, swm::COMMAND_RE_AUTH, false, RAR_UPDATE);
    assert_eq!(
        encode(&accepted.replay_re_auth_answer()),
        raa_wire,
        "committed duplicate RAR response must replay byte-identically"
    );
    let received_raa = swm::parse_swm_re_auth_answer_envelope_from_connection(
        &decode(&raa_wire),
        CONNECTION,
        DecodeContext::default(),
    )
    .expect("AAA boundary must parse the RAA envelope");
    let correlated_raa = outbound_rar
        .correlate_answer(received_raa)
        .expect("public RAR/RAA envelopes must correlate");
    assert_eq!(correlated_raa.transaction(), RAR_UPDATE);
    assert_eq!(
        correlated_raa.answer().result,
        swm::SwmReAuthResult::Success
    );
    assert_redacted(&format!("{correlated_raa:?}"), SESSION_UPDATE, USER_UPDATE);

    let pending = accepted
        .begin_authorization(
            swm::SwmAuthorizationRequest {
                session_id: Redacted::from(SESSION_UPDATE.to_owned()),
                origin_host: Redacted::from(EPDG_HOST.to_owned()),
                origin_realm: Redacted::from(EPDG_REALM.to_owned()),
                destination_realm: Redacted::from(AAA_REALM.to_owned()),
                destination_host: Some(Redacted::from(AAA_HOST.to_owned())),
                user_name: Redacted::from(USER_UPDATE.to_owned()),
                auth_request_type: AuthRequestType::AuthorizeOnly,
                authorization_lifetime: Some(600),
                auth_grace_period: Some(30),
                aar_flags: None,
                ue_local_ip_address: None,
                high_priority_access_info: None,
                drmp: None,
                route_records: Vec::new(),
                additional_avps: Vec::new(),
            },
            AAR_UPDATE,
            expected_aaa(),
            EncodeContext::default(),
        )
        .expect("accepted RAR must advance to the matching public AAR");
    let aar_wire = encode(&pending.initial_authorization_request());
    assert_header(&aar_wire, swm::COMMAND_AA, true, AAR_UPDATE);
    assert_eq!(
        encode(&pending.retransmit_authorization_request()),
        aar_wire,
        "ordinary AAR retry must replay the committed request exactly"
    );
    let inbound_aar =
        swm::parse_swm_authorization_request_envelope(&decode(&aar_wire), DecodeContext::default())
            .expect("AAA boundary must parse the AAR envelope");
    let canonical_aar = inbound_aar
        .clone()
        .with_expected_answer_peer(expected_aaa());
    assert_eq!(
        encode(
            &swm::build_swm_authorization_request(&canonical_aar, EncodeContext::default())
                .expect("parsed AAR must rebuild canonically")
        ),
        aar_wire
    );

    let mut aaa = swm::SwmAuthorizationAnswer::for_request(
        &inbound_aar,
        swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
        Redacted::from(AAA_HOST.to_owned()),
        Redacted::from(AAA_REALM.to_owned()),
    );
    aaa.re_auth_request_type = Some(swm::SwmReAuthRequestType::AuthorizeOnly);
    aaa.authorization_lifetime = Some(300);
    aaa.auth_grace_period = Some(30);
    aaa.session_timeout = Some(900);
    let aaa_message =
        swm::build_swm_authorization_answer(&inbound_aar, &aaa, EncodeContext::default())
            .expect("AAA boundary must build the request-bound AAA");
    let aaa_wire = encode(&aaa_message);
    assert_header(&aaa_wire, swm::COMMAND_AA, false, AAR_UPDATE);
    assert_eq!(
        encode(
            &swm::build_swm_authorization_answer(&inbound_aar, &aaa, EncodeContext::default(),)
                .expect("rebuilding the same AAA must remain deterministic")
        ),
        aaa_wire
    );
    let received_aaa = swm::parse_swm_authorization_answer_envelope_from_connection(
        &decode(&aaa_wire),
        CONNECTION,
        DecodeContext::default(),
    )
    .expect("ePDG boundary must parse the AAA envelope");
    let completed_update = pending
        .complete(received_aaa)
        .expect("public RAR/RAA then AAR/AAA sequence must complete");
    assert_eq!(completed_update.authorization().transaction(), AAR_UPDATE);
    assert_eq!(
        completed_update
            .authorization()
            .answer()
            .authorization_lifetime,
        Some(300)
    );
    assert_redacted(
        &format!("{completed_update:?}"),
        SESSION_UPDATE,
        USER_UPDATE,
    );

    let terminated_update = terminate_session(
        swm::SwmSessionTerminationRequest {
            session_id: Sensitive::from(SESSION_UPDATE.to_owned()),
            origin_host: Redacted::from(EPDG_HOST.to_owned()),
            origin_realm: Redacted::from(EPDG_REALM.to_owned()),
            destination_realm: Redacted::from(AAA_REALM.to_owned()),
            destination_host: Some(Redacted::from(AAA_HOST.to_owned())),
            termination_cause: swm::SwmTerminationCause::Logout,
            user_name: Sensitive::from(USER_UPDATE.to_owned()),
            drmp: None,
            route_records: Vec::new(),
            additional_avps: Vec::new(),
        },
        STR_UPDATE,
    );
    assert_eq!(
        terminated_update.request().termination_cause,
        swm::SwmTerminationCause::Logout
    );

    let abort_establishment = establish_session(SESSION_ABORT, USER_ABORT, DER_ABORT);
    assert_eq!(
        abort_establishment.request().session_id.as_ref(),
        SESSION_ABORT
    );
    assert_ne!(
        abort_establishment.request().session_id.as_ref(),
        update_establishment.request().session_id.as_ref(),
        "abort proof must use a separate established session"
    );

    let outbound_asr = swm::SwmAbortSessionRequestEnvelope::for_outbound(
        swm::SwmAbortSessionRequest {
            session_id: Redacted::from(SESSION_ABORT.to_owned()),
            origin_host: Redacted::from(AAA_HOST.to_owned()),
            origin_realm: Redacted::from(AAA_REALM.to_owned()),
            destination_realm: Redacted::from(EPDG_REALM.to_owned()),
            destination_host: Redacted::from(EPDG_HOST.to_owned()),
            user_name: Redacted::from(USER_ABORT.to_owned()),
            auth_session_state: Some(swm::SwmAuthSessionState::StateMaintained),
            origin_state_id: Some(351),
            drmp: None,
            route_records: Vec::new(),
            additional_avps: Vec::new(),
        },
        ASR_ABORT,
        expected_epdg(),
    );
    let asr_message = swm::build_swm_abort_session_request(&outbound_asr, EncodeContext::default())
        .expect("AAA boundary must build the ASR");
    let asr_wire = encode(&asr_message);
    assert_header(&asr_wire, swm::COMMAND_ABORT_SESSION, true, ASR_ABORT);
    let inbound_asr =
        swm::parse_swm_abort_session_request_envelope(&decode(&asr_wire), DecodeContext::default())
            .expect("ePDG boundary must parse the ASR envelope");
    let canonical_asr = inbound_asr
        .clone()
        .with_expected_answer_peer(expected_epdg());
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_request(&canonical_asr, EncodeContext::default())
                .expect("parsed ASR must rebuild canonically")
        ),
        asr_wire
    );

    let asa = swm::SwmAbortSessionAnswer::for_request(
        &inbound_asr,
        swm::SwmAbortSessionResult::Success,
        Redacted::from(EPDG_HOST.to_owned()),
        Redacted::from(EPDG_REALM.to_owned()),
    );
    let asa_message =
        swm::build_swm_abort_session_answer(&inbound_asr, &asa, EncodeContext::default())
            .expect("ePDG boundary must build the request-bound ASA");
    // The retained bytes model the consumer's commit boundary. The SDK
    // deliberately validates them but cannot prove external durability.
    let committed_asa_wire = encode(&asa_message);
    assert_header(
        &committed_asa_wire,
        swm::COMMAND_ABORT_SESSION,
        false,
        ASR_ABORT,
    );
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_answer(&inbound_asr, &asa, EncodeContext::default(),)
                .expect("rebuilding the same ASA must remain deterministic")
        ),
        committed_asa_wire
    );

    let post_abort = inbound_asr
        .post_abort_session_termination(&asa, EncodeContext::default())
        .expect("committed state-maintained ASA must derive a disposition");
    let administrative_str = match post_abort {
        swm::SwmPostAbortSessionTermination::Required(request) => *request,
        swm::SwmPostAbortSessionTermination::NotRequiredNoState
        | swm::SwmPostAbortSessionTermination::NotRequiredAbortUnsuccessful => {
            panic!("successful state-maintained abort must require administrative STR")
        }
    };
    assert_eq!(
        administrative_str.termination_cause,
        swm::SwmTerminationCause::Administrative
    );
    assert_eq!(administrative_str.session_id.as_ref(), SESSION_ABORT);
    assert_eq!(administrative_str.user_name.as_ref(), USER_ABORT);

    let received_asa = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&committed_asa_wire),
        CONNECTION,
        DecodeContext::default(),
    )
    .expect("AAA boundary must parse the ASA envelope");
    let correlated_abort = outbound_asr
        .correlate_answer(received_asa)
        .expect("public ASR/ASA envelopes must correlate");
    assert_eq!(correlated_abort.transaction(), ASR_ABORT);
    assert_eq!(
        correlated_abort.answer().result,
        swm::SwmAbortSessionResult::Success
    );
    assert_redacted(&format!("{correlated_abort:?}"), SESSION_ABORT, USER_ABORT);

    let terminated_abort = terminate_session(administrative_str, STR_ABORT);
    assert_eq!(
        terminated_abort.request().termination_cause,
        swm::SwmTerminationCause::Administrative
    );
    assert_eq!(
        terminated_abort.request().session_id.as_ref(),
        SESSION_ABORT
    );
}
