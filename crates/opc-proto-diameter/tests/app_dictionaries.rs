use std::net::{IpAddr, Ipv4Addr};

use bytes::BytesMut;
use opc_proto_diameter::apps::rf::{
    AccountingRecordType, MultipleServicesCreditControl, PsInformation, RfAccountingAnswer,
    RfAccountingRequest, SubscriptionId, SubscriptionIdType, UsedServiceUnit,
};
use opc_proto_diameter::apps::swm::{
    AllocationRetentionPriority, Ambr, ApnConfiguration, AuthRequestType, EpsSubscribedQosProfile,
    PdnType, SwmAuthorizationOutcome, SwmCorrelatedDiameterEapExchange, SwmDiameterEapAnswer,
    SwmDiameterEapAnswerEnvelope, SwmDiameterEapRequest, SwmDiameterEapRequestEnvelope,
    SwmDiameterResult, SwmDiameterTransaction, SwmEmergencyAuthorizationError,
    SwmEmergencyAuthorizationEvidence, SwmEmergencyAuthorizationPath, SwmEmergencyServices,
    SwmResultCategory, SwmTerminalInformation,
};
use opc_proto_diameter::{
    apps, base, ApplicationId, AvpCode, AvpDataType, AvpFlags, AvpHeader, AvpKey, CommandCode,
    CommandFlags, CommandKind, DictionarySet, FlagRequirement, Header, Message, OwnedMessage,
    RawAvp, VendorId, DIAMETER_HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DuplicateIePolicy, Encode, EncodeContext, UnknownIePolicy,
};
use opc_types::{Imei, Imei15};

#[cfg(feature = "app-swm")]
static SWM_BASELINE_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), apps::swm::dictionary()]);

#[cfg(feature = "app-swm")]
static SWM_AMBIGUOUS_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&[
    base::dictionary(),
    apps::swm::dictionary(),
    apps::swm::projected_profile_dictionary(),
]);

#[cfg(feature = "app-swm")]
static BASE_ONLY_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&[base::dictionary()]);

fn encode_message(message: &opc_proto_diameter::OwnedMessage) -> BytesMut {
    let mut encoded = BytesMut::new();
    message
        .encode(&mut encoded, EncodeContext::default())
        .expect("message encode must succeed");
    encoded
}

fn decode_message(encoded: &[u8]) -> Message<'_> {
    let (tail, message) =
        Message::decode(encoded, DecodeContext::default()).expect("message decode must succeed");
    assert!(tail.is_empty());
    message
}

#[cfg(feature = "app-swm")]
fn request_envelope(
    request: &SwmDiameterEapRequest,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
) -> SwmDiameterEapRequestEnvelope {
    SwmDiameterEapRequestEnvelope::for_outbound(
        request.clone(),
        SwmDiameterTransaction::new(hop_by_hop_identifier, end_to_end_identifier),
    )
}

#[cfg(feature = "app-swm")]
fn answer_envelope(
    answer: &SwmDiameterEapAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
) -> SwmDiameterEapAnswerEnvelope {
    SwmDiameterEapAnswerEnvelope::for_outbound(
        answer.clone(),
        SwmDiameterTransaction::new(hop_by_hop_identifier, end_to_end_identifier),
    )
}

#[cfg(feature = "app-swm")]
fn correlate_exchange(
    request: &SwmDiameterEapRequest,
    answer: &SwmDiameterEapAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
) -> Result<SwmCorrelatedDiameterEapExchange, SwmEmergencyAuthorizationError> {
    request_envelope(request, hop_by_hop_identifier, end_to_end_identifier).correlate_answer(
        answer_envelope(answer, hop_by_hop_identifier, end_to_end_identifier),
    )
}

#[cfg(feature = "app-swm")]
fn emergency_imsi_nai() -> &'static str {
    "0234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org"
}

#[cfg(feature = "app-swm")]
fn eap_response_identity(identifier: u8, identity: &str) -> Vec<u8> {
    apps::swm::build_eap_response_identity(identifier, identity.as_bytes())
        .expect("bounded test EAP identity")
}

#[cfg(feature = "app-swm")]
fn prepare_recovery_request(request: &mut SwmDiameterEapRequest) {
    request.emergency_services = Some(SwmEmergencyServices::emergency_indication());
    request.user_name = Some(emergency_imsi_nai().into());
    request.eap_payload = eap_response_identity(0x17, emergency_imsi_nai()).into();
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_dictionary_contains_application_command_and_avps() {
    let dictionary = apps::rf::dictionary();
    assert_eq!(dictionary.name(), "diameter-3gpp-rf-subset");

    let app = dictionary
        .find_application(apps::rf::APPLICATION_ID)
        .expect("Rf application must be present");
    assert_eq!(app.name(), "3GPP Rf accounting over Diameter accounting");

    let acr = dictionary
        .find_command(
            apps::rf::APPLICATION_ID,
            apps::rf::COMMAND_ACCOUNTING,
            CommandKind::Request,
        )
        .expect("ACR command must be present");
    assert_eq!(acr.name(), "Accounting-Request");

    let record_type = dictionary
        .find_avp(AvpKey::ietf(apps::rf::AVP_ACCOUNTING_RECORD_TYPE))
        .expect("Accounting-Record-Type must be present");
    assert_eq!(record_type.data_type(), AvpDataType::Enumerated);

    let ps_info = dictionary
        .find_avp(AvpKey::vendor(
            apps::rf::AVP_PS_INFORMATION,
            apps::VENDOR_ID_3GPP,
        ))
        .expect("PS-Information must be present");
    assert_eq!(ps_info.data_type(), AvpDataType::Grouped);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dictionary_contains_application_command_and_avps() {
    let dictionary = apps::swm::dictionary();
    assert_eq!(dictionary.name(), "diameter-3gpp-swm-subset");

    let app = dictionary
        .find_application(apps::swm::APPLICATION_ID)
        .expect("SWm application must be present");
    assert_eq!(app.name(), "3GPP SWm");

    let der = dictionary
        .find_command(
            apps::swm::APPLICATION_ID,
            apps::swm::COMMAND_DIAMETER_EAP,
            CommandKind::Request,
        )
        .expect("DER command must be present");
    assert_eq!(der.name(), "Diameter-EAP-Request");

    let eap_payload = dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_EAP_PAYLOAD))
        .expect("EAP-Payload must be present");
    assert_eq!(eap_payload.data_type(), AvpDataType::OctetString);

    let emergency_key = AvpKey::vendor(apps::swm::AVP_EMERGENCY_SERVICES, apps::VENDOR_ID_3GPP);
    let emergency = dictionary
        .find_avp(emergency_key)
        .expect("Emergency-Services must be present");
    assert_eq!(emergency.data_type(), AvpDataType::Unsigned32);
    assert_eq!(emergency.flags().vendor(), FlagRequirement::MustBeSet);
    assert_eq!(emergency.flags().mandatory(), FlagRequirement::MustBeUnset);
    assert_eq!(emergency.flags().protected(), FlagRequirement::MustBeUnset);
    assert!(der.find_avp_rule(emergency_key).is_some());
    assert!(!der.allows_multiple(emergency_key));

    let terminal_key = AvpKey::vendor(apps::swm::AVP_TERMINAL_INFORMATION, apps::VENDOR_ID_3GPP);
    let terminal = dictionary
        .find_avp(terminal_key)
        .expect("Terminal-Information must be present");
    assert_eq!(terminal.data_type(), AvpDataType::Grouped);
    assert!(der.find_avp_rule(terminal_key).is_some());
    assert!(!der.allows_multiple(terminal_key));

    let dea = dictionary
        .find_command(
            apps::swm::APPLICATION_ID,
            apps::swm::COMMAND_DIAMETER_EAP,
            CommandKind::Answer,
        )
        .expect("DEA command must be present");
    assert!(dea.find_avp_rule(emergency_key).is_none());
    assert!(dea
        .find_avp_rule(AvpKey::ietf(base::AVP_RESULT_CODE))
        .is_some());
    assert!(dea
        .find_avp_rule(AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT))
        .is_some());
    assert!(dea
        .find_avp_rule(AvpKey::vendor(
            apps::swm::AVP_MOBILE_NODE_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
        ))
        .is_none());
    let mobile_node_identifier = dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_MOBILE_NODE_IDENTIFIER))
        .expect("Mobile-Node-Identifier must be present");
    assert_eq!(mobile_node_identifier.data_type(), AvpDataType::Utf8String);
    assert!(dea
        .find_avp_rule(AvpKey::ietf(apps::swm::AVP_MOBILE_NODE_IDENTIFIER))
        .is_some());
}

#[test]
#[cfg(all(feature = "app-rf", feature = "app-swm"))]
fn app_dictionaries_layer_includes_rf_and_swm() {
    let set = apps::APP_DICTIONARIES;
    assert!(set.find_application(apps::rf::APPLICATION_ID).is_some());
    assert!(set.find_application(apps::swm::APPLICATION_ID).is_some());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_start_record_round_trip() {
    let request = sample_rf_request(AccountingRecordType::StartRecord, 0);
    let answer = sample_rf_answer(AccountingRecordType::StartRecord, 0);
    round_trip_rf(&request, &answer);
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_interim_record_round_trip() {
    let request = sample_rf_request(AccountingRecordType::InterimRecord, 1);
    let answer = sample_rf_answer(AccountingRecordType::InterimRecord, 1);
    round_trip_rf(&request, &answer);
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_stop_record_round_trip() {
    let request = sample_rf_request(AccountingRecordType::StopRecord, 2);
    let answer = sample_rf_answer(AccountingRecordType::StopRecord, 2);
    round_trip_rf(&request, &answer);
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_event_record_round_trip() {
    let request = sample_rf_request(AccountingRecordType::EventRecord, 0);
    let answer = sample_rf_answer(AccountingRecordType::EventRecord, 0);
    round_trip_rf(&request, &answer);
}

#[cfg(feature = "app-rf")]
fn round_trip_rf(request: &RfAccountingRequest, answer: &RfAccountingAnswer) {
    let built_request = apps::rf::build_rf_accounting_request(
        request,
        0x0102_0304,
        0x0506_0708,
        EncodeContext::default(),
    )
    .expect("Rf ACR build must succeed");
    let encoded = encode_message(&built_request);
    let message = decode_message(&encoded);
    let parsed_request = apps::rf::parse_rf_accounting_request(&message, DecodeContext::default())
        .expect("Rf ACR parse must succeed");
    assert_eq!(parsed_request, *request);

    let built_answer = apps::rf::build_rf_accounting_answer(
        answer,
        0x090A_0B0C,
        0x0D0E_0F10,
        EncodeContext::default(),
    )
    .expect("Rf ACA build must succeed");
    let encoded = encode_message(&built_answer);
    let message = decode_message(&encoded);
    let parsed_answer = apps::rf::parse_rf_accounting_answer(&message, DecodeContext::default())
        .expect("Rf ACA parse must succeed");
    assert_eq!(parsed_answer, *answer);
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_dictionary_validation_recognizes_grouped_avps() {
    let request = sample_rf_request(AccountingRecordType::StartRecord, 0);
    let built = apps::rf::build_rf_accounting_request(&request, 1, 2, EncodeContext::default())
        .expect("Rf ACR build must succeed");
    let encoded = encode_message(&built);
    let message = decode_message(&encoded);
    assert!(message
        .validate_avps_with_dictionary(
            DecodeContext::default(),
            DictionarySet::new(&[apps::rf::dictionary()]),
        )
        .is_ok());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_debug_does_not_leak_subscriber_identifiers() {
    let request = sample_rf_request(AccountingRecordType::StartRecord, 0);
    let debug = format!("{:?}", request);
    assert!(!debug.contains("001010123456789"));
    assert!(!debug.contains("session;rf"));
    assert!(!debug.contains("epdg.example"));
    assert!(debug.contains("REDACTED"));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_dea_round_trip() {
    let request = sample_swm_request();
    let answer = sample_swm_answer();

    let built_request = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("SWm DER build must succeed");
    let encoded = encode_message(&built_request);
    let message = decode_message(&encoded);
    assert!(message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("normal DER AVP"))
        .all(|avp| avp.header.code != apps::swm::AVP_EMERGENCY_SERVICES));
    let parsed_request =
        apps::swm::parse_swm_diameter_eap_request(&message, DecodeContext::default())
            .expect("SWm DER parse must succeed");
    assert_eq!(parsed_request, request);

    let built_answer = apps::swm::build_swm_diameter_eap_answer(
        &answer,
        0x5555_6666,
        0x7777_8888,
        EncodeContext::default(),
    )
    .expect("SWm DEA build must succeed");
    let encoded = encode_message(&built_answer);
    let message = decode_message(&encoded);
    assert!(message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("normal DEA AVP"))
        .all(|avp| avp.header.code != apps::swm::AVP_EMERGENCY_SERVICES));
    let parsed_answer =
        apps::swm::parse_swm_diameter_eap_answer(&message, DecodeContext::default())
            .expect("SWm DEA parse must succeed");
    assert_eq!(parsed_answer, answer);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_indication_round_trips_on_der_and_emits_exact_flags() {
    let mut request = sample_swm_request();
    request.emergency_services = Some(SwmEmergencyServices::emergency_indication());
    let built = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("emergency DER build");
    let encoded = encode_message(&built);

    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("emergency DER dictionary decode");
    assert!(tail.is_empty());
    let emergency_avp = decoded
        .avps(DecodeContext::conservative())
        .map(|avp| avp.expect("valid AVP"))
        .find(|avp| {
            avp.header.code == apps::swm::AVP_EMERGENCY_SERVICES
                && avp.header.vendor_id == Some(apps::VENDOR_ID_3GPP)
        })
        .expect("Emergency-Services AVP");
    assert!(emergency_avp.header.flags.is_vendor_specific());
    assert!(!emergency_avp.header.flags.is_mandatory());
    assert!(!emergency_avp.header.flags.is_protected());
    assert_eq!(emergency_avp.value, 1u32.to_be_bytes());

    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("emergency DER parse");
    assert_eq!(parsed, request);
    assert!(parsed.requests_emergency_services());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_experimental_identity_recovery_round_trips_without_base_result() {
    let mut answer = sample_swm_answer();
    answer.result = SwmDiameterResult::Experimental {
        vendor_id: apps::VENDOR_ID_3GPP,
        code: apps::swm::DIAMETER_ERROR_USER_UNKNOWN,
    };
    answer.eap_payload = None;
    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = None;

    let built = apps::swm::build_swm_diameter_eap_answer(
        &answer,
        0x5555_6666,
        0x7777_8888,
        EncodeContext::default(),
    )
    .expect("identity-recovery DEA build");
    assert!(!built.header.flags.is_error());
    let encoded = encode_message(&built);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("identity-recovery DEA dictionary decode");
    assert!(tail.is_empty());
    let avps = decoded
        .avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("valid DEA AVPs");
    assert_eq!(
        avps.iter()
            .filter(|avp| avp.header.code == base::AVP_EXPERIMENTAL_RESULT)
            .count(),
        1
    );
    assert!(avps
        .iter()
        .all(|avp| avp.header.code != base::AVP_RESULT_CODE));
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative())
        .expect("identity-recovery DEA parse");

    assert_eq!(parsed, answer);
    assert!(parsed.result.requests_emergency_identity_recovery());
    assert_eq!(
        parsed.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );

    let mut wrong_error_bit = built;
    wrong_error_bit.header.flags = CommandFlags::answer(true, true);
    let encoded = encode_message(&wrong_error_bit);
    let decoded = decode_message(&encoded);
    assert!(
        apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative(),).is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_der_discards_undefined_bits_and_reencodes_canonically() {
    let emergency = encode_raw_vendor_avp(
        apps::swm::AVP_EMERGENCY_SERVICES,
        apps::VENDOR_ID_3GPP,
        false,
        &0xffff_ffffu32.to_be_bytes(),
    );
    let message = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        &[emergency],
    );
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("undefined bits are discarded");
    assert_eq!(
        parsed.emergency_services,
        Some(SwmEmergencyServices::emergency_indication())
    );

    let rebuilt =
        apps::swm::build_swm_diameter_eap_request(&parsed, 1, 2, EncodeContext::default())
            .expect("canonical emergency DER rebuild");
    let encoded = encode_message(&rebuilt);
    let decoded = decode_message(&encoded);
    let value = decoded
        .avps(DecodeContext::conservative())
        .map(|avp| avp.expect("valid AVP"))
        .find(|avp| avp.header.code == apps::swm::AVP_EMERGENCY_SERVICES)
        .expect("rebuilt Emergency-Services")
        .value;
    assert_eq!(value, 1u32.to_be_bytes());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_indication_is_singleton_under_both_decode_layers() {
    let emergency = encode_raw_vendor_avp(
        apps::swm::AVP_EMERGENCY_SERVICES,
        apps::VENDOR_ID_3GPP,
        false,
        &1u32.to_be_bytes(),
    );
    let message = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        &[emergency.clone(), emergency],
    );
    let encoded = encode_message(&message);

    assert!(Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .is_err());

    let decoded = decode_message(&encoded);
    assert!(
        apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default(),).is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_indication_rejects_forbidden_m_and_p_flags() {
    for flags in [
        AvpFlags::new(true, true, false),
        AvpFlags::new(true, false, true),
    ] {
        let value = 1u32.to_be_bytes();
        let avp = RawAvp {
            header: AvpHeader::vendor(
                apps::swm::AVP_EMERGENCY_SERVICES,
                apps::VENDOR_ID_3GPP,
                false,
            )
            .with_flags(flags),
            value: &value,
            padding: &[],
        };
        let mut emergency = BytesMut::new();
        avp.encode(&mut emergency, EncodeContext::default())
            .expect("raw flag-violation fixture");
        let message = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
            &[emergency],
        );
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);
        assert!(
            apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative(),)
                .is_err()
        );
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_unauthenticated_emergency_msk_matches_annex_a4_vector() {
    let imei = emergency_imei();
    let msk = apps::swm::derive_unauthenticated_emergency_msk(&imei);
    assert_eq!(
        msk.as_bytes(),
        &[
            0xe0, 0x33, 0x1e, 0x12, 0x1c, 0xc1, 0xb8, 0xf4, 0x68, 0xf0, 0x8e, 0x24, 0xf4, 0xe7,
            0xb8, 0xda, 0xe3, 0xc8, 0xf7, 0xa8, 0xb5, 0xe7, 0x14, 0x76, 0x13, 0xae, 0xdf, 0xce,
            0x21, 0xd9, 0xd6, 0xac,
        ]
    );
    let debug = format!("{msk:?}");
    assert!(!debug.contains("e0331e"));
    assert!(debug.contains("redacted"));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_identity_builders_match_wire_contract_and_fail_closed() {
    let imei = emergency_imei();
    let identity = apps::swm::emergency_nai(&imei);
    assert_eq!(identity, "imei490154203237518@sos.invalid");

    let payload = apps::swm::build_eap_response_identity(0x17, identity.as_bytes())
        .expect("canonical emergency identity fits EAP");
    assert_eq!(
        payload,
        b"\x02\x17\x00\x24\x01imei490154203237518@sos.invalid"
    );

    let maximum_identity = vec![b'x'; apps::swm::EAP_RESPONSE_IDENTITY_MAX_IDENTITY_LEN];
    let maximum_payload = apps::swm::build_eap_response_identity(0xff, &maximum_identity)
        .expect("maximum EAP identity must fit");
    assert_eq!(maximum_payload.len(), usize::from(u16::MAX));
    assert_eq!(&maximum_payload[..5], &[0x02, 0xff, 0xff, 0xff, 0x01]);

    let oversized_identity = vec![b'x'; apps::swm::EAP_RESPONSE_IDENTITY_MAX_IDENTITY_LEN + 1];
    let error = apps::swm::build_eap_response_identity(0x17, &oversized_identity)
        .expect_err("oversized EAP identity must fail before wire construction");
    assert_eq!(
        error,
        apps::swm::SwmEapResponseIdentityBuildError::IdentityTooLong
    );
    assert_eq!(error.as_str(), "swm_eap_response_identity_too_long");
    assert_eq!(error.to_string(), error.as_str());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_direct_emergency_evidence_requires_correlated_exact_success() {
    let imei = emergency_imei();
    let mut request = sample_swm_request();
    request.emergency_services = Some(SwmEmergencyServices::emergency_indication());
    let direct_identity = apps::swm::emergency_nai(&imei);
    request.user_name = Some(direct_identity.clone().into());
    request.eap_payload = eap_response_identity(0x17, &direct_identity).into();
    let answer = sample_final_emergency_answer(&imei);

    let request_message = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("direct emergency DER build");
    let request_wire = encode_message(&request_message);
    let request_decoded = decode_message(&request_wire);
    let parsed_request = apps::swm::parse_swm_diameter_eap_request_envelope(
        &request_decoded,
        DecodeContext::conservative(),
    )
    .expect("direct emergency DER parse");
    let answer_message = apps::swm::build_swm_diameter_eap_answer(
        &answer,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("final emergency DEA build");
    let answer_wire = encode_message(&answer_message);
    let answer_decoded = decode_message(&answer_wire);
    let parsed_answer = apps::swm::parse_swm_diameter_eap_answer_envelope(
        &answer_decoded,
        DecodeContext::conservative(),
    )
    .expect("final emergency DEA parse");

    let exchange = parsed_request
        .correlate_answer(parsed_answer)
        .expect("Diameter transaction correlation");
    let evidence = SwmEmergencyAuthorizationEvidence::verify_direct(exchange, &imei)
        .expect("exact direct emergency exchange");
    assert_eq!(
        evidence.path(),
        SwmEmergencyAuthorizationPath::DirectEmergencyIdentity
    );
    assert_eq!(evidence.as_str(), "emergency_imei_msk_authorized");
    assert_eq!(
        evidence.msk().as_bytes(),
        apps::swm::derive_unauthenticated_emergency_msk(&imei).as_bytes()
    );

    let mut wrong_request = request.clone();
    wrong_request.user_name = Some("anonymous@sos.invalid".into());
    let exchange = correlate_exchange(&wrong_request, &answer, 1, 2)
        .expect("unrelated identity does not break Diameter correlation");
    assert_eq!(
        SwmEmergencyAuthorizationEvidence::verify_direct(exchange, &imei)
            .expect_err("answer-local material must not authorize an unrelated request"),
        SwmEmergencyAuthorizationError::InitialIdentityMismatch
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_identity_recovery_evidence_accepts_only_the_complete_correlated_sequence() {
    let imei = emergency_imei();
    let mut initial = sample_swm_request();
    prepare_recovery_request(&mut initial);

    let identity_response = sample_identity_recovery_answer();
    let mut retry = initial.clone();
    retry.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&imei),
        software_version: Some("01".to_string().into()),
    });
    let final_answer = sample_final_emergency_answer(&imei);
    let initial = request_envelope(&initial, 1, 2);
    let identity_response = answer_envelope(&identity_response, 1, 2);
    let retry = request_envelope(&retry, 3, 4);
    let final_answer = answer_envelope(&final_answer, 3, 4);
    let initial_exchange = initial
        .correlate_answer(identity_response)
        .expect("initial Diameter correlation");
    let retry_exchange = retry
        .correlate_answer(final_answer)
        .expect("retry Diameter correlation");

    let evidence = SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
        initial_exchange,
        retry_exchange,
        &imei,
    )
    .expect("complete identity-recovery sequence");
    assert_eq!(
        evidence.path(),
        SwmEmergencyAuthorizationPath::RecoveredDeviceIdentity
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_identity_recovery_evidence_fails_closed_at_every_boundary() {
    let imei = emergency_imei();
    let other_imei = Imei::new("356938035643709").expect("valid alternate IMEI");
    let mut initial = sample_swm_request();
    prepare_recovery_request(&mut initial);
    let identity_response = sample_identity_recovery_answer();
    let mut retry = initial.clone();
    retry.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&imei),
        software_version: None,
    });
    let final_answer = sample_final_emergency_answer(&imei);

    let verify = |identity_response: &SwmDiameterEapAnswer,
                  retry: &SwmDiameterEapRequest,
                  final_answer: &SwmDiameterEapAnswer| {
        let initial = request_envelope(&initial, 1, 2);
        let identity_response = answer_envelope(identity_response, 1, 2);
        let retry = request_envelope(retry, 3, 4);
        let final_answer = answer_envelope(final_answer, 3, 4);
        let initial_exchange = initial.correlate_answer(identity_response)?;
        let retry_exchange = retry.correlate_answer(final_answer)?;
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
    };

    let mut changed = identity_response.clone();
    changed.result = SwmDiameterResult::Experimental {
        vendor_id: VendorId::new(0),
        code: apps::swm::DIAMETER_ERROR_USER_UNKNOWN,
    };
    assert_eq!(
        verify(&changed, &retry, &final_answer).expect_err("wrong vendor"),
        SwmEmergencyAuthorizationError::IdentityRecoveryNotRequested
    );
    changed.result = SwmDiameterResult::Experimental {
        vendor_id: apps::VENDOR_ID_3GPP,
        code: 5002,
    };
    assert_eq!(
        verify(&changed, &retry, &final_answer).expect_err("wrong code"),
        SwmEmergencyAuthorizationError::IdentityRecoveryNotRequested
    );
    changed = identity_response.clone();
    changed.session_id = "other-session".into();
    assert_eq!(
        verify(&changed, &retry, &final_answer).expect_err("identity response session mismatch"),
        SwmEmergencyAuthorizationError::SessionMismatch
    );
    changed = identity_response.clone();
    changed.auth_application_id = 0;
    assert_eq!(
        verify(&changed, &retry, &final_answer).expect_err("answer application mismatch"),
        SwmEmergencyAuthorizationError::AnswerRequestMismatch
    );
    changed = identity_response.clone();
    changed.eap_payload = Some(vec![0x01].into());
    assert_eq!(
        verify(&changed, &retry, &final_answer)
            .expect_err("recovery response authorization material"),
        SwmEmergencyAuthorizationError::IdentityRecoveryResponseHasAuthorizationMaterial
    );

    let mut changed_retry = retry.clone();
    changed_retry.session_id = "other-session".into();
    assert_eq!(
        verify(&identity_response, &changed_retry, &final_answer)
            .expect_err("retry session mismatch"),
        SwmEmergencyAuthorizationError::SessionMismatch
    );
    changed_retry = retry.clone();
    changed_retry.user_name = Some("different@example.invalid".into());
    assert_eq!(
        verify(&identity_response, &changed_retry, &final_answer)
            .expect_err("retry identity mismatch"),
        SwmEmergencyAuthorizationError::RetryUserIdentityMismatch
    );
    changed_retry = retry.clone();
    changed_retry.destination_realm = "other.example".into();
    assert_eq!(
        verify(&identity_response, &changed_retry, &final_answer)
            .expect_err("retry changed an original parameter"),
        SwmEmergencyAuthorizationError::RetryRequestMismatch
    );
    changed_retry = retry.clone();
    changed_retry.terminal_information = None;
    assert_eq!(
        verify(&identity_response, &changed_retry, &final_answer)
            .expect_err("missing Terminal-Information"),
        SwmEmergencyAuthorizationError::RetryTerminalInformationMissing
    );
    changed_retry = retry.clone();
    changed_retry.terminal_information = Some(SwmTerminalInformation {
        imei: other_imei,
        software_version: None,
    });
    assert_eq!(
        verify(&identity_response, &changed_retry, &final_answer).expect_err("wrong IMEI"),
        SwmEmergencyAuthorizationError::RetryDeviceIdentityMismatch
    );

    let mut changed_final = final_answer.clone();
    changed_final.result = SwmDiameterResult::Base(2002);
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("non-success result"),
        SwmEmergencyAuthorizationError::FinalResultNotSuccess
    );
    changed_final = final_answer.clone();
    changed_final.eap_payload = Some(vec![0x03, 0x18, 0x00, 0x05].into());
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("malformed EAP-Success"),
        SwmEmergencyAuthorizationError::FinalEapSuccessMissing
    );
    changed_final = final_answer.clone();
    changed_final.eap_master_session_key = None;
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("missing MSK"),
        SwmEmergencyAuthorizationError::FinalMskMissing
    );
    changed_final = final_answer.clone();
    changed_final.eap_reissued_payload = Some(vec![0x01].into());
    assert_eq!(
        verify(&identity_response, &retry, &changed_final)
            .expect_err("ambiguous final EAP material"),
        SwmEmergencyAuthorizationError::FinalEapMaterialAmbiguous
    );
    changed_final = final_answer.clone();
    changed_final.eap_master_session_key = Some(vec![0x55; 32].into());
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("wrong MSK"),
        SwmEmergencyAuthorizationError::FinalMskMismatch
    );
    changed_final = final_answer.clone();
    changed_final.mobile_node_identifier = None;
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("missing permanent identity"),
        SwmEmergencyAuthorizationError::FinalPermanentIdentityMissing
    );
    changed_final = final_answer;
    changed_final.mobile_node_identifier = Some("imei000000000000000@sos.invalid".into());
    assert_eq!(
        verify(&identity_response, &retry, &changed_final).expect_err("wrong permanent identity"),
        SwmEmergencyAuthorizationError::FinalPermanentIdentityMismatch
    );

    let mut changed_initial = initial.clone();
    changed_initial.user_name = None;
    let changed_initial = request_envelope(&changed_initial, 1, 2);
    let initial_exchange = changed_initial
        .correlate_answer(answer_envelope(&identity_response, 1, 2))
        .expect("Diameter correlation");
    let retry_exchange = request_envelope(&retry, 3, 4)
        .correlate_answer(answer_envelope(&changed_final, 3, 4))
        .expect("Diameter correlation");
    assert_eq!(
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
        .expect_err("identity recovery requires an initial subscriber identity"),
        SwmEmergencyAuthorizationError::IdentityRecoveryInitialIdentityInvalid
    );
    let mut changed_initial = initial.clone();
    let direct_identity = apps::swm::emergency_nai(&imei);
    changed_initial.user_name = Some(direct_identity.clone().into());
    changed_initial.eap_payload = eap_response_identity(0x17, &direct_identity).into();
    let changed_initial = request_envelope(&changed_initial, 1, 2);
    let initial_exchange = changed_initial
        .correlate_answer(answer_envelope(&identity_response, 1, 2))
        .expect("Diameter correlation");
    let retry_exchange = request_envelope(&retry, 3, 4)
        .correlate_answer(answer_envelope(&changed_final, 3, 4))
        .expect("Diameter correlation");
    assert_eq!(
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
        .expect_err("an IMEI-based initial identity uses the direct path"),
        SwmEmergencyAuthorizationError::IdentityRecoveryInitialIdentityInvalid
    );

    let mut changed_initial = initial.clone();
    changed_initial.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&imei),
        software_version: None,
    });
    let changed_initial = request_envelope(&changed_initial, 1, 2);
    let initial_exchange = changed_initial
        .correlate_answer(answer_envelope(&identity_response, 1, 2))
        .expect("Diameter correlation");
    let retry_exchange = request_envelope(&retry, 3, 4)
        .correlate_answer(answer_envelope(&changed_final, 3, 4))
        .expect("Diameter correlation");
    assert_eq!(
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
        .expect_err("initial request must not already contain Terminal-Information"),
        SwmEmergencyAuthorizationError::InitialTerminalInformationUnexpected
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_emergency_evidence_binds_diameter_eap_and_imsi_emergency_nai() {
    let imei = emergency_imei();
    let mut initial = sample_swm_request();
    prepare_recovery_request(&mut initial);
    let identity_answer = sample_identity_recovery_answer();
    let mut retry = initial.clone();
    retry.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&imei),
        software_version: None,
    });
    let final_answer = sample_final_emergency_answer(&imei);

    let initial_envelope = request_envelope(&initial, 1, 2);
    let correlated_answer = apps::swm::build_swm_diameter_eap_answer_for(
        &initial_envelope,
        &identity_answer,
        EncodeContext::default(),
    )
    .expect("answer-for helper must copy request identifiers");
    assert_eq!(correlated_answer.header.hop_by_hop_identifier, 1);
    assert_eq!(correlated_answer.header.end_to_end_identifier, 2);
    let mut unrelated_answer = identity_answer.clone();
    unrelated_answer.session_id = "unrelated-session".into();
    assert!(apps::swm::build_swm_diameter_eap_answer_for(
        &initial_envelope,
        &unrelated_answer,
        EncodeContext::default(),
    )
    .is_err());

    let verify = |initial: &SwmDiameterEapRequest,
                  identity: &SwmDiameterEapAnswer,
                  initial_transaction: (u32, u32),
                  retry: &SwmDiameterEapRequest,
                  final_answer: &SwmDiameterEapAnswer,
                  retry_transaction: (u32, u32)| {
        let initial_exchange = correlate_exchange(
            initial,
            identity,
            initial_transaction.0,
            initial_transaction.1,
        )?;
        let retry_exchange = correlate_exchange(
            retry,
            final_answer,
            retry_transaction.0,
            retry_transaction.1,
        )?;
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
    };

    assert_eq!(
        request_envelope(&initial, 1, 2)
            .correlate_answer(answer_envelope(&identity_answer, 9, 2))
            .expect_err("5001 answer must match the initial Diameter transaction"),
        SwmEmergencyAuthorizationError::DiameterTransactionMismatch
    );

    assert_eq!(
        request_envelope(&retry, 3, 4)
            .correlate_answer(answer_envelope(&final_answer, 3, 9))
            .expect_err("final answer must match the retry Diameter transaction"),
        SwmEmergencyAuthorizationError::DiameterTransactionMismatch
    );

    assert_eq!(
        verify(
            &initial,
            &identity_answer,
            (1, 2),
            &retry,
            &final_answer,
            (1, 2),
        )
        .expect_err("the retry is a new Diameter request"),
        SwmEmergencyAuthorizationError::RetryRequestMismatch
    );

    let mut mismatched_success = final_answer.clone();
    mismatched_success.eap_payload = Some(vec![3, 0x18, 0, 4].into());
    assert_eq!(
        verify(
            &initial,
            &identity_answer,
            (1, 2),
            &retry,
            &mismatched_success,
            (3, 4),
        )
        .expect_err("EAP Success must answer the EAP Response identifier"),
        SwmEmergencyAuthorizationError::FinalEapIdentifierMismatch
    );

    for invalid_nai in [
        "0234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org",
        "1234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org",
        "0234150999999999@sos.nai.epc.mnc016.mcc234.3gppnetwork.org",
        "0234150999999999@sos.nai.epc.mnc015.mcc235.3gppnetwork.org",
        "0234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org.extra",
    ] {
        let mut changed = initial.clone();
        changed.user_name = Some(invalid_nai.into());
        changed.eap_payload = eap_response_identity(0x17, invalid_nai).into();
        assert_eq!(
            verify(
                &changed,
                &identity_answer,
                (1, 2),
                &retry,
                &final_answer,
                (3, 4),
            )
            .expect_err("noncanonical IMSI emergency NAI must fail"),
            SwmEmergencyAuthorizationError::IdentityRecoveryInitialIdentityInvalid
        );
    }

    let mut wrong_eap_type = initial.clone();
    let mut payload = eap_response_identity(0x17, emergency_imsi_nai());
    payload[4] = 0x32;
    wrong_eap_type.eap_payload = payload.into();
    assert_eq!(
        verify(
            &wrong_eap_type,
            &identity_answer,
            (1, 2),
            &retry,
            &final_answer,
            (3, 4),
        )
        .expect_err("initial payload must be EAP-Response/Identity"),
        SwmEmergencyAuthorizationError::InitialEapIdentityInvalid
    );

    let mut wrong_eap_length = initial.clone();
    let mut payload = eap_response_identity(0x17, emergency_imsi_nai());
    payload[3] = payload[3].saturating_sub(1);
    wrong_eap_length.eap_payload = payload.into();
    assert_eq!(
        verify(
            &wrong_eap_length,
            &identity_answer,
            (1, 2),
            &retry,
            &final_answer,
            (3, 4),
        )
        .expect_err("EAP length must cover the exact payload"),
        SwmEmergencyAuthorizationError::InitialEapIdentityInvalid
    );

    let mut mismatched_eap_identity = initial.clone();
    mismatched_eap_identity.eap_payload = eap_response_identity(
        0x17,
        "6234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org",
    )
    .into();
    assert_eq!(
        verify(
            &mismatched_eap_identity,
            &identity_answer,
            (1, 2),
            &retry,
            &final_answer,
            (3, 4),
        )
        .expect_err("EAP Identity must equal Diameter User-Name"),
        SwmEmergencyAuthorizationError::InitialEapIdentityMismatch
    );

    let aka_prime_nai = "6310260123456789@sos.nai.epc.mnc260.mcc310.3gppnetwork.org";
    let mut aka_prime_initial = initial.clone();
    aka_prime_initial.user_name = Some(aka_prime_nai.into());
    aka_prime_initial.eap_payload = eap_response_identity(0x17, aka_prime_nai).into();
    let mut aka_prime_retry = aka_prime_initial.clone();
    aka_prime_retry.terminal_information = retry.terminal_information.clone();
    verify(
        &aka_prime_initial,
        &identity_answer,
        (10, 11),
        &aka_prime_retry,
        &final_answer,
        (12, 13),
    )
    .expect("AKA-prime three-digit-MNC emergency NAI must be accepted");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_terminal_information_round_trips_with_exact_3gpp_flags() {
    let mut request = sample_swm_request();
    request.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(emergency_imei()),
        software_version: Some("01".to_string().into()),
    });
    let built = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("Terminal-Information DER build");
    let encoded = encode_message(&built);
    let decoded = decode_message(&encoded);
    let terminal = decoded
        .avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("valid DER AVPs")
        .into_iter()
        .find(|avp| {
            avp.header.code == apps::swm::AVP_TERMINAL_INFORMATION
                && avp.header.vendor_id == Some(apps::VENDOR_ID_3GPP)
        })
        .expect("Terminal-Information AVP");
    assert!(terminal.header.flags.is_vendor_specific());
    assert!(terminal.header.flags.is_mandatory());
    assert!(!terminal.header.flags.is_protected());
    let children = terminal
        .grouped_avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("valid Terminal-Information children");
    assert_eq!(children.len(), 2);
    assert!(children.iter().all(|child| {
        child.header.vendor_id == Some(apps::VENDOR_ID_3GPP)
            && child.header.flags.is_vendor_specific()
            && child.header.flags.is_mandatory()
            && !child.header.flags.is_protected()
    }));

    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("Terminal-Information DER parse");
    assert_eq!(parsed, request);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_terminal_information_preserves_fourteen_and_fifteen_digit_imei() {
    for digits in ["49015420323751", "490154203237510", "490154203237519"] {
        let mut request = sample_swm_request();
        request.terminal_information = Some(SwmTerminalInformation {
            imei: Imei::new(digits).expect("standards-valid Terminal-Information IMEI"),
            software_version: None,
        });
        let built = apps::swm::build_swm_diameter_eap_request(
            &request,
            0x1111_2222,
            0x3333_4444,
            EncodeContext::default(),
        )
        .expect("Terminal-Information build");
        let wire = encode_message(&built);
        let decoded = decode_message(&wire);
        let parsed =
            apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
                .expect("Terminal-Information parse");
        assert_eq!(
            parsed
                .terminal_information
                .as_ref()
                .map(|terminal| terminal.imei.as_str()),
            Some(digits)
        );
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_terminal_information_rejects_missing_duplicate_or_malformed_children() {
    let imei = encode_raw_vendor_avp(
        apps::swm::AVP_IMEI,
        apps::VENDOR_ID_3GPP,
        true,
        b"490154203237518",
    );
    let software = encode_raw_vendor_avp(
        apps::swm::AVP_SOFTWARE_VERSION,
        apps::VENDOR_ID_3GPP,
        true,
        b"01",
    );
    let malformed_imei = encode_raw_vendor_avp(
        apps::swm::AVP_IMEI,
        apps::VENDOR_ID_3GPP,
        true,
        b"49015420323751x",
    );
    let malformed_software = encode_raw_vendor_avp(
        apps::swm::AVP_SOFTWARE_VERSION,
        apps::VENDOR_ID_3GPP,
        true,
        b"1",
    );
    let mut duplicate_imei = BytesMut::new();
    duplicate_imei.extend_from_slice(&imei);
    duplicate_imei.extend_from_slice(&imei);
    let mut malformed_software_children = BytesMut::new();
    malformed_software_children.extend_from_slice(&imei);
    malformed_software_children.extend_from_slice(&malformed_software);

    for children in [
        software,
        malformed_imei,
        malformed_software_children,
        duplicate_imei,
    ] {
        let terminal = encode_raw_vendor_avp(
            apps::swm::AVP_TERMINAL_INFORMATION,
            apps::VENDOR_ID_3GPP,
            true,
            &children,
        );
        let message = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
            &[terminal],
        );
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);
        assert!(
            apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative(),)
                .is_err()
        );
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_result_rejects_base_and_experimental_result_together() {
    let mut grouped = BytesMut::new();
    grouped.extend_from_slice(&encode_raw_avp(
        base::AVP_VENDOR_ID,
        true,
        &apps::VENDOR_ID_3GPP.get().to_be_bytes(),
    ));
    grouped.extend_from_slice(&encode_raw_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        true,
        &apps::swm::DIAMETER_ERROR_USER_UNKNOWN.to_be_bytes(),
    ));
    let experimental = encode_raw_avp(base::AVP_EXPERIMENTAL_RESULT, true, &grouped);
    let message = build_raw_swm_dea_with_extras(&[experimental]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(
        apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative(),).is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_experimental_result_rejects_missing_duplicate_and_bad_flag_children() {
    let vendor = encode_raw_avp(
        base::AVP_VENDOR_ID,
        true,
        &apps::VENDOR_ID_3GPP.get().to_be_bytes(),
    );
    let code = encode_raw_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        true,
        &apps::swm::DIAMETER_ERROR_USER_UNKNOWN.to_be_bytes(),
    );
    let mut duplicate_vendor = BytesMut::new();
    duplicate_vendor.extend_from_slice(&vendor);
    duplicate_vendor.extend_from_slice(&vendor);
    duplicate_vendor.extend_from_slice(&code);
    let code_without_m = encode_raw_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        false,
        &apps::swm::DIAMETER_ERROR_USER_UNKNOWN.to_be_bytes(),
    );
    let mut bad_flags = BytesMut::new();
    bad_flags.extend_from_slice(&vendor);
    bad_flags.extend_from_slice(&code_without_m);

    for children in [vendor, code, duplicate_vendor, bad_flags] {
        let experimental = encode_raw_avp(base::AVP_EXPERIMENTAL_RESULT, true, &children);
        let message = build_raw_swm_dea_with_result_avp_and_extras(&experimental, &[]);
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);
        assert!(
            apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative(),)
                .is_err()
        );
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_debug_does_not_leak_subscriber_identifiers() {
    let request = sample_swm_request();
    let debug = format!("{:?}", request);
    assert!(!debug.contains("601010123456789"));
    assert!(!debug.contains("sess;swm"));
    assert!(!debug.contains("epdg.example"));
    assert!(debug.contains("REDACTED"));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_answer_result_category_is_classified() {
    let answer = SwmDiameterEapAnswer {
        session_id: "sess;swm;001".into(),
        auth_application_id: apps::swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(2001),
        origin_host: "aaa.home.example".into(),
        origin_realm: "home.example".into(),
        user_name: None,
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: vec![],
        mobile_node_identifier: None,
        eap_payload: None,
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: None,
    };
    assert_eq!(answer.result_category(), SwmResultCategory::Success);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_answer_eap_material_predicate_requires_non_empty_material() {
    let mut answer = sample_swm_answer();
    assert!(answer.carries_eap_material());

    answer.eap_payload = Some(Vec::new().into());
    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = None;
    assert!(!answer.carries_eap_material());

    answer.eap_reissued_payload = Some(vec![0x01].into());
    assert!(answer.carries_eap_material());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rejects_invalid_eap_request_semantics_in_builder() {
    let mut request = sample_swm_request();
    request.auth_request_type = AuthRequestType::Other(1);
    assert!(
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .is_err()
    );

    request = sample_swm_request();
    request.eap_payload = Vec::new().into();
    assert!(
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .is_err()
    );

    request = sample_swm_request();
    request.state_avps = vec![Vec::new()];
    assert!(
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .is_err()
    );

    request = sample_swm_request();
    request.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(emergency_imei()),
        software_version: Some("1".to_string().into()),
    });
    assert!(
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_mobile_node_identifier_rejects_non_utf8_wire_value() {
    let mobile_node_identifier =
        encode_raw_avp(apps::swm::AVP_MOBILE_NODE_IDENTIFIER, true, &[0xff, 0xfe]);
    let message = build_raw_swm_dea_with_extras(&[mobile_node_identifier]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(
        apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative(),).is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rejects_invalid_eap_request_semantics_in_parser() {
    let message = build_raw_swm_der_with(
        Some(apps::swm::APPLICATION_ID.get()),
        1,
        &[0x02, 0x17, 0x00, 0x04],
    );
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default()).is_err());

    let message = build_raw_swm_der_with(Some(apps::swm::APPLICATION_ID.get()), 3, &[]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_success_without_eap_material() {
    let mut answer = sample_swm_answer();
    answer.eap_payload = None;
    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = None;
    assert!(
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default()).is_err()
    );

    let message = build_raw_swm_dea(Some(apps::swm::APPLICATION_ID.get()));
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_allows_failure_without_eap_material() {
    let mut answer = sample_swm_answer();
    answer.result = SwmDiameterResult::Experimental {
        vendor_id: apps::VENDOR_ID_3GPP,
        code: apps::swm::DIAMETER_ERROR_USER_UNKNOWN,
    };
    answer.eap_payload = None;
    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = None;
    assert!(
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default()).is_ok()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_invalid_optional_material() {
    let mut answer = sample_swm_answer();
    answer.eap_payload = Some(Vec::new().into());
    assert!(
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default()).is_err()
    );

    answer = sample_swm_answer();
    answer.auth_request_type = AuthRequestType::Other(1);
    assert!(
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default()).is_err()
    );

    answer = sample_swm_answer();
    answer.state_avps = vec![Vec::new()];
    assert!(
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default()).is_err()
    );
}

#[cfg(feature = "app-rf")]
fn sample_rf_request(record_type: AccountingRecordType, record_number: u32) -> RfAccountingRequest {
    RfAccountingRequest {
        session_id: "session;rf;001".into(),
        origin_host: "epdg.example".into(),
        origin_realm: "epc.example.org".into(),
        destination_realm: "epc.example.org".into(),
        destination_host: Some("cdf.example".into()),
        accounting_record_type: record_type,
        accounting_record_number: record_number,
        acct_application_id: apps::rf::APPLICATION_ID.get(),
        user_name: Some("001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org".into()),
        origin_state_id: Some(99),
        event_timestamp: Some(1_700_000_000),
        service_context_id: "32260@3gpp.org".to_string(),
        subscription_ids: vec![SubscriptionId {
            subscription_id_type: SubscriptionIdType::EndUserImsi,
            subscription_id_data: "001010123456789".into(),
        }],
        multiple_services_credit_controls: vec![MultipleServicesCreditControl {
            used_service_unit: Some(UsedServiceUnit {
                cc_time: Some(3600),
                cc_total_octets: Some(1_000_000),
                cc_input_octets: Some(200_000),
                cc_output_octets: Some(800_000),
            }),
            rating_group: Some(1),
            service_identifier: Some(42),
        }],
        ps_information: Some(PsInformation {
            charging_id: Some(0x12345678),
            pdp_type: Some(0),
            sgsn_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)).into()),
            ggsn_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)).into()),
        }),
    }
}

#[cfg(feature = "app-rf")]
fn sample_rf_answer(record_type: AccountingRecordType, record_number: u32) -> RfAccountingAnswer {
    RfAccountingAnswer {
        session_id: "session;rf;001".into(),
        result_code: 2001,
        origin_host: "cdf.example".into(),
        origin_realm: "epc.example.org".into(),
        accounting_record_type: record_type,
        accounting_record_number: record_number,
        acct_application_id: apps::rf::APPLICATION_ID.get(),
        origin_state_id: Some(88),
        event_timestamp: Some(1_700_000_001),
    }
}

#[cfg(feature = "app-swm")]
fn sample_swm_request() -> SwmDiameterEapRequest {
    SwmDiameterEapRequest {
        session_id: "sess;swm;001".into(),
        auth_application_id: apps::swm::APPLICATION_ID.get(),
        origin_host: "epdg.example".into(),
        origin_realm: "visited.example".into(),
        destination_realm: "home.example".into(),
        destination_host: Some("aaa.home.example".into()),
        user_name: Some("601010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org".into()),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: vec![0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03].into(),
        emergency_services: None,
        terminal_information: None,
        state_avps: vec![b"opaque-state".to_vec()],
    }
}

#[cfg(feature = "app-swm")]
fn sample_swm_answer() -> SwmDiameterEapAnswer {
    SwmDiameterEapAnswer {
        session_id: "sess;swm;001".into(),
        auth_application_id: apps::swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(2001),
        origin_host: "aaa.home.example".into(),
        origin_realm: "home.example".into(),
        user_name: None,
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: vec![],
        mobile_node_identifier: None,
        eap_payload: Some(vec![0x03, 0x18, 0x00, 0x04].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: Some(vec![0xAA; 32].into()),
    }
}

#[cfg(feature = "app-swm")]
fn emergency_imei() -> Imei15 {
    Imei15::new("490154203237518").expect("3GPP example IMEI")
}

#[cfg(feature = "app-swm")]
fn sample_identity_recovery_answer() -> SwmDiameterEapAnswer {
    let mut answer = sample_swm_answer();
    answer.result = SwmDiameterResult::Experimental {
        vendor_id: apps::VENDOR_ID_3GPP,
        code: apps::swm::DIAMETER_ERROR_USER_UNKNOWN,
    };
    answer.eap_payload = None;
    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = None;
    answer
}

#[cfg(feature = "app-swm")]
fn sample_final_emergency_answer(imei: &Imei15) -> SwmDiameterEapAnswer {
    let mut answer = sample_swm_answer();
    answer.eap_payload = Some(vec![0x03, 0x17, 0x00, 0x04].into());
    answer.eap_master_session_key = Some(
        apps::swm::derive_unauthenticated_emergency_msk(imei)
            .as_bytes()
            .to_vec()
            .into(),
    );
    answer.mobile_node_identifier = Some(apps::swm::emergency_nai(imei).into());
    answer
}

#[cfg(feature = "app-swm")]
fn sample_apn_configuration() -> ApnConfiguration {
    ApnConfiguration {
        context_identifier: 7,
        service_selection: "internet.mnc001.mcc001.gprs".into(),
        pdn_type: PdnType::Ipv4v6,
        eps_subscribed_qos_profile: Some(EpsSubscribedQosProfile {
            qos_class_identifier: 9,
            allocation_retention_priority: AllocationRetentionPriority {
                priority_level: 15,
                pre_emption_capability: Some(1),
                pre_emption_vulnerability: Some(0),
            },
        }),
        ambr: Some(Ambr {
            max_requested_bandwidth_ul: 50_000_000,
            max_requested_bandwidth_dl: 150_000_000,
        }),
    }
}

#[cfg(feature = "app-swm")]
fn sample_ims_apn_configuration() -> ApnConfiguration {
    ApnConfiguration {
        context_identifier: 8,
        service_selection: "ims.mnc001.mcc001.gprs".into(),
        pdn_type: PdnType::Ipv6,
        eps_subscribed_qos_profile: None,
        ambr: None,
    }
}

#[cfg(feature = "app-rf")]
fn encode_raw_avp(code: AvpCode, mandatory: bool, value: &[u8]) -> BytesMut {
    let avp = RawAvp {
        header: AvpHeader::ietf(code, mandatory),
        value,
        padding: &[],
    };
    let mut dst = BytesMut::new();
    avp.encode(&mut dst, EncodeContext::default())
        .expect("raw AVP encode must succeed");
    dst
}

#[cfg(feature = "app-rf")]
fn encode_raw_vendor_avp(
    code: AvpCode,
    vendor_id: VendorId,
    mandatory: bool,
    value: &[u8],
) -> BytesMut {
    let avp = RawAvp {
        header: AvpHeader::vendor(code, vendor_id, mandatory),
        value,
        padding: &[],
    };
    let mut dst = BytesMut::new();
    avp.encode(&mut dst, EncodeContext::default())
        .expect("raw vendor AVP encode must succeed");
    dst
}

#[cfg(feature = "app-swm")]
fn nth_top_level_avp_offset(
    raw_avps: &[u8],
    code: AvpCode,
    vendor_id: Option<VendorId>,
    occurrence: usize,
) -> usize {
    let mut offset = 0usize;
    let mut matched = 0usize;
    while offset < raw_avps.len() {
        let flags = raw_avps[offset + 4];
        let length = ((raw_avps[offset + 5] as usize) << 16)
            | ((raw_avps[offset + 6] as usize) << 8)
            | raw_avps[offset + 7] as usize;
        let encoded_code = AvpCode::new(u32::from_be_bytes([
            raw_avps[offset],
            raw_avps[offset + 1],
            raw_avps[offset + 2],
            raw_avps[offset + 3],
        ]));
        let encoded_vendor = if flags & 0x80 != 0 {
            Some(VendorId::new(u32::from_be_bytes([
                raw_avps[offset + 8],
                raw_avps[offset + 9],
                raw_avps[offset + 10],
                raw_avps[offset + 11],
            ])))
        } else {
            None
        };
        if encoded_code == code && encoded_vendor == vendor_id {
            if matched == occurrence {
                return DIAMETER_HEADER_LEN + offset;
            }
            matched += 1;
        }
        offset += (length + 3) & !3;
    }
    panic!("constructed message must contain the requested AVP occurrence")
}

#[cfg(feature = "app-rf")]
fn build_raw_rf_acr(acct_application_id: Option<u32>, extras: &[BytesMut]) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_SESSION_ID,
        true,
        b"session;rf;001",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_HOST,
        true,
        b"epdg.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_REALM,
        true,
        b"epc.example.org",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_DESTINATION_REALM,
        true,
        b"epc.example.org",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_ACCOUNTING_RECORD_TYPE,
        true,
        &2u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_ACCOUNTING_RECORD_NUMBER,
        true,
        &0u32.to_be_bytes(),
    ));
    if let Some(id) = acct_application_id {
        raw_avps.extend_from_slice(&encode_raw_avp(
            base::AVP_ACCT_APPLICATION_ID,
            true,
            &id.to_be_bytes(),
        ));
    }
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SERVICE_CONTEXT_ID,
        true,
        b"32260@3gpp.org",
    ));
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(271),
            ApplicationId::new(3),
            1,
            2,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

#[cfg(feature = "app-rf")]
fn build_raw_rf_aca(acct_application_id: Option<u32>, extras: &[BytesMut]) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_SESSION_ID,
        true,
        b"session;rf;001",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_RESULT_CODE,
        true,
        &2001u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(base::AVP_ORIGIN_HOST, true, b"cdf.example"));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_REALM,
        true,
        b"epc.example.org",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_ACCOUNTING_RECORD_TYPE,
        true,
        &2u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_ACCOUNTING_RECORD_NUMBER,
        true,
        &0u32.to_be_bytes(),
    ));
    if let Some(id) = acct_application_id {
        raw_avps.extend_from_slice(&encode_raw_avp(
            base::AVP_ACCT_APPLICATION_ID,
            true,
            &id.to_be_bytes(),
        ));
    }
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            CommandCode::new(271),
            ApplicationId::new(3),
            1,
            2,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

#[cfg(feature = "app-swm")]
fn build_raw_swm_der(auth_application_id: Option<u32>) -> OwnedMessage {
    build_raw_swm_der_with(
        auth_application_id,
        3,
        &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
    )
}

#[cfg(feature = "app-swm")]
fn build_raw_swm_der_with(
    auth_application_id: Option<u32>,
    auth_request_type: u32,
    eap_payload: &[u8],
) -> OwnedMessage {
    build_raw_swm_der_with_extras(auth_application_id, auth_request_type, eap_payload, &[])
}

#[cfg(feature = "app-swm")]
fn build_raw_swm_der_with_extras(
    auth_application_id: Option<u32>,
    auth_request_type: u32,
    eap_payload: &[u8],
    extras: &[BytesMut],
) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    raw_avps.extend_from_slice(&encode_raw_avp(base::AVP_SESSION_ID, true, b"sess;swm;001"));
    if let Some(id) = auth_application_id {
        raw_avps.extend_from_slice(&encode_raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            true,
            &id.to_be_bytes(),
        ));
    }
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_HOST,
        true,
        b"epdg.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_REALM,
        true,
        b"visited.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_DESTINATION_REALM,
        true,
        b"home.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_AUTH_REQUEST_TYPE,
        true,
        &auth_request_type.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_EAP_PAYLOAD,
        true,
        eap_payload,
    ));
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(268),
            ApplicationId::new(16_777_264),
            1,
            2,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

/// Raw success DEA carrying EAP material plus caller-provided extra AVPs.
#[cfg(feature = "app-swm")]
fn build_raw_swm_dea_with_extras(extras: &[BytesMut]) -> OwnedMessage {
    build_raw_swm_dea_with_result_and_extras(2001, extras)
}

/// Raw DEA carrying EAP material, an explicit result code, and extra AVPs.
#[cfg(feature = "app-swm")]
fn build_raw_swm_dea_with_result_and_extras(result_code: u32, extras: &[BytesMut]) -> OwnedMessage {
    let result = encode_raw_avp(base::AVP_RESULT_CODE, true, &result_code.to_be_bytes());
    build_raw_swm_dea_with_result_avp_and_extras(&result, extras)
}

/// Raw DEA carrying EAP material, a caller-provided result AVP, and extras.
#[cfg(feature = "app-swm")]
fn build_raw_swm_dea_with_result_avp_and_extras(
    result_avp: &[u8],
    extras: &[BytesMut],
) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    raw_avps.extend_from_slice(&encode_raw_avp(base::AVP_SESSION_ID, true, b"sess;swm;001"));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_AUTH_APPLICATION_ID,
        true,
        &apps::swm::APPLICATION_ID.get().to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_AUTH_REQUEST_TYPE,
        true,
        &3u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(result_avp);
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_HOST,
        true,
        b"aaa.home.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_REALM,
        true,
        b"home.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_EAP_PAYLOAD,
        true,
        &[0x03, 0x18, 0x00, 0x04],
    ));
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            CommandCode::new(268),
            ApplicationId::new(16_777_264),
            1,
            2,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

/// Raw APN-Configuration grouped value with the three required children.
#[cfg(feature = "app-swm")]
fn raw_apn_configuration_children(context_identifier: u32, apn: &[u8], pdn_type: u32) -> BytesMut {
    let mut value = BytesMut::new();
    value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &context_identifier.to_be_bytes(),
    ));
    value.extend_from_slice(&encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, true, apn));
    value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PDN_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &pdn_type.to_be_bytes(),
    ));
    value
}

#[cfg(feature = "app-swm")]
fn raw_apn_configuration_avp(context_identifier: u32, apn: &[u8], pdn_type: u32) -> BytesMut {
    encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &raw_apn_configuration_children(context_identifier, apn, pdn_type),
    )
}

#[cfg(feature = "app-swm")]
fn build_raw_swm_dea(auth_application_id: Option<u32>) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    raw_avps.extend_from_slice(&encode_raw_avp(base::AVP_SESSION_ID, true, b"sess;swm;001"));
    if let Some(id) = auth_application_id {
        raw_avps.extend_from_slice(&encode_raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            true,
            &id.to_be_bytes(),
        ));
    }
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_AUTH_REQUEST_TYPE,
        true,
        &3u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_RESULT_CODE,
        true,
        &2001u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_HOST,
        true,
        b"aaa.home.example",
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        base::AVP_ORIGIN_REALM,
        true,
        b"home.example",
    ));
    OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            CommandCode::new(268),
            ApplicationId::new(16_777_264),
            1,
            2,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_acr_rejects_wrong_acct_application_id_in_builder() {
    let mut request = sample_rf_request(AccountingRecordType::StartRecord, 0);
    request.acct_application_id = 0;
    assert!(
        apps::rf::build_rf_accounting_request(&request, 1, 2, EncodeContext::default()).is_err()
    );
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_acr_rejects_wrong_acct_application_id_in_parser() {
    let message = build_raw_rf_acr(Some(0), &[]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_acr_rejects_missing_acct_application_id_in_parser() {
    let message = build_raw_rf_acr(None, &[]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_aca_rejects_wrong_acct_application_id_in_builder() {
    let mut answer = sample_rf_answer(AccountingRecordType::StartRecord, 0);
    answer.acct_application_id = 0;
    assert!(apps::rf::build_rf_accounting_answer(&answer, 1, 2, EncodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_aca_rejects_wrong_acct_application_id_in_parser() {
    let message = build_raw_rf_aca(Some(0), &[]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_aca_rejects_missing_acct_application_id_in_parser() {
    let message = build_raw_rf_aca(None, &[]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rejects_wrong_auth_application_id_in_builder() {
    let mut request = sample_swm_request();
    request.auth_application_id = 0;
    assert!(
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .is_err()
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rejects_wrong_auth_application_id_in_parser() {
    let message = build_raw_swm_der(Some(0));
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rejects_missing_auth_application_id_in_parser() {
    let message = build_raw_swm_der(None);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_wrong_auth_application_id_in_builder() {
    let mut answer = sample_swm_answer();
    answer.auth_application_id = 0;
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("wrong Auth-Application-Id must fail DEA encode");
    let spec_ref = err
        .spec_ref()
        .expect("DEA encode error must cite a spec ref");
    assert_eq!(spec_ref.section(), "DEA");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_wrong_auth_application_id_in_parser() {
    let message = build_raw_swm_dea(Some(0));
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_missing_auth_application_id_in_parser() {
    let message = build_raw_swm_dea(None);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_rejects_duplicate_child() {
    let mut sub_value = BytesMut::new();
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        true,
        &1u32.to_be_bytes(),
    ));
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
        true,
        b"001010123456789",
    ));
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
        true,
        b"duplicate",
    ));
    let extras = [encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID,
        true,
        &sub_value,
    )];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_rejects_unknown_mandatory_child() {
    let mut sub_value = BytesMut::new();
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        true,
        &1u32.to_be_bytes(),
    ));
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
        true,
        b"001010123456789",
    ));
    sub_value.extend_from_slice(&encode_raw_avp(AvpCode::new(999), true, b"unknown"));
    let extras = [encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID,
        true,
        &sub_value,
    )];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_rejects_too_many_children() {
    let mut sub_value = BytesMut::new();
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        true,
        &1u32.to_be_bytes(),
    ));
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
        true,
        b"001010123456789",
    ));
    // Add enough non-mandatory children inside Subscription-Id to overflow the
    // grouped IE-count guard while keeping the top-level count below the limit.
    for i in 0..10 {
        sub_value.extend_from_slice(&encode_raw_avp(AvpCode::new(990 + i), false, b"extra"));
    }
    let extras = [encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID,
        true,
        &sub_value,
    )];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let ctx = DecodeContext {
        max_ies: 10,
        ..DecodeContext::default()
    };
    let err = apps::rf::parse_rf_accounting_request(&decoded, ctx)
        .expect_err("grouped IE-count guard must fire");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::IeCountExceeded
    ));
    // The failure must be inside the Subscription-Id grouped value, not at top level.
    assert!(err.offset() > 120);
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_acr_rejects_duplicate_ps_information() {
    let ps_value = encode_raw_vendor_avp(
        apps::rf::AVP_3GPP_CHARGING_ID,
        apps::VENDOR_ID_3GPP,
        true,
        &0x12345678u32.to_be_bytes(),
    );
    let ps_info = encode_raw_vendor_avp(
        apps::rf::AVP_PS_INFORMATION,
        apps::VENDOR_ID_3GPP,
        true,
        &ps_value,
    );
    let extras = [ps_info.clone(), ps_info];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default())
        .expect_err("duplicate PS-Information must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_mscc_rejects_excessive_nesting_depth() {
    let mut usu_value = BytesMut::new();
    usu_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_CC_TIME,
        true,
        &3600u32.to_be_bytes(),
    ));
    let mut mscc_value = BytesMut::new();
    mscc_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_USED_SERVICE_UNIT,
        true,
        &usu_value,
    ));
    let extras = [encode_raw_avp(
        apps::rf::AVP_MULTIPLE_SERVICES_CREDIT_CONTROL,
        true,
        &mscc_value,
    )];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let ctx = DecodeContext {
        max_depth: 1,
        ..DecodeContext::default()
    };
    assert!(apps::rf::parse_rf_accounting_request(&decoded, ctx).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dictionary_contains_subscription_avps() {
    let dictionary = apps::swm::dictionary();

    let service_selection = dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_SERVICE_SELECTION))
        .expect("Service-Selection must be present");
    assert_eq!(service_selection.data_type(), AvpDataType::Utf8String);

    let apn_configuration = dictionary
        .find_avp(AvpKey::vendor(
            apps::swm::AVP_APN_CONFIGURATION,
            apps::VENDOR_ID_3GPP,
        ))
        .expect("APN-Configuration must be present");
    assert_eq!(apn_configuration.data_type(), AvpDataType::Grouped);

    let context_identifier = dictionary
        .find_avp(AvpKey::vendor(
            apps::swm::AVP_CONTEXT_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
        ))
        .expect("Context-Identifier must be present");
    assert_eq!(context_identifier.data_type(), AvpDataType::Unsigned32);

    let pdn_type = dictionary
        .find_avp(AvpKey::vendor(
            apps::swm::AVP_PDN_TYPE,
            apps::VENDOR_ID_3GPP,
        ))
        .expect("PDN-Type must be present");
    assert_eq!(pdn_type.data_type(), AvpDataType::Enumerated);

    // Vendor-specific AVP keys must not shadow or match the vendor-neutral space.
    assert!(dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_APN_CONFIGURATION))
        .is_none());
}

/// Defect regression: an M-flagged vendor-specific APN-Configuration in the
/// DEA must be matched by (vendor-id, code) and surfaced, not routed to the
/// unknown-AVP rejection path.
#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_parses_mandatory_vendor_apn_configuration() {
    let mut apn_value = raw_apn_configuration_children(7, b"internet.mnc001.mcc001.gprs", 2);
    let mut arp_value = BytesMut::new();
    arp_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PRIORITY_LEVEL,
        apps::VENDOR_ID_3GPP,
        true,
        &15u32.to_be_bytes(),
    ));
    arp_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PRE_EMPTION_CAPABILITY,
        apps::VENDOR_ID_3GPP,
        true,
        &1u32.to_be_bytes(),
    ));
    arp_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PRE_EMPTION_VULNERABILITY,
        apps::VENDOR_ID_3GPP,
        true,
        &0u32.to_be_bytes(),
    ));
    let mut qos_value = BytesMut::new();
    qos_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_QOS_CLASS_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &9u32.to_be_bytes(),
    ));
    qos_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_ALLOCATION_RETENTION_PRIORITY,
        apps::VENDOR_ID_3GPP,
        true,
        &arp_value,
    ));
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
        apps::VENDOR_ID_3GPP,
        true,
        &qos_value,
    ));
    let mut ambr_value = BytesMut::new();
    ambr_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_MAX_REQUESTED_BANDWIDTH_UL,
        apps::VENDOR_ID_3GPP,
        true,
        &50_000_000u32.to_be_bytes(),
    ));
    ambr_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_MAX_REQUESTED_BANDWIDTH_DL,
        apps::VENDOR_ID_3GPP,
        true,
        &150_000_000u32.to_be_bytes(),
    ));
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_AMBR,
        apps::VENDOR_ID_3GPP,
        true,
        &ambr_value,
    ));
    let extras = [
        encode_raw_vendor_avp(
            apps::swm::AVP_APN_CONFIGURATION,
            apps::VENDOR_ID_3GPP,
            true,
            &apn_value,
        ),
        encode_raw_avp(
            apps::swm::AVP_SERVICE_SELECTION,
            true,
            b"internet.mnc001.mcc001.gprs",
        ),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let answer = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect("DEA with vendor subscription AVPs must parse");
    assert_eq!(
        answer
            .service_selection
            .as_ref()
            .map(|s| s.as_ref().as_str()),
        Some("internet.mnc001.mcc001.gprs")
    );
    assert_eq!(answer.default_context_identifier, None);
    assert!(answer.default_apn_configuration().is_none());
    assert_eq!(answer.apn_configurations, vec![sample_apn_configuration()]);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_default_context_identifier_round_trip() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(8);
    answer.apn_configurations = vec![sample_apn_configuration(), sample_ims_apn_configuration()];

    let selected = answer
        .default_apn_configuration()
        .expect("context identifier 8 must select the IMS configuration");
    assert_eq!(selected.context_identifier, 8);
    assert_eq!(
        selected.service_selection.as_ref(),
        "ims.mnc001.mcc001.gprs"
    );

    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("SWm DEA build must succeed");
    let encoded = encode_message(&built);
    let message = decode_message(&encoded);
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&message, DecodeContext::default())
        .expect("SWm DEA parse must succeed");
    assert_eq!(parsed, answer);
    assert_eq!(
        parsed
            .default_apn_configuration()
            .map(|apn| apn.service_selection.as_ref().as_str()),
        Some("ims.mnc001.mcc001.gprs")
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_cardinality_accepts_repeated_state_conservatively() {
    let mut request = sample_swm_request();
    request.state_avps = vec![b"state-one".to_vec(), b"state-two".to_vec()];
    let built = apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
        .expect("repeatable State AVPs must encode");
    let encoded = encode_message(&built);

    let raw_error = Message::decode(&encoded, DecodeContext::conservative())
        .expect_err("raw conservative decode must retain reject-all behavior");
    assert!(matches!(
        raw_error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));

    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("SWm grammar must permit repeated State AVPs");
    assert!(tail.is_empty());
    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("typed singleton guards must coexist with repeatable State");
    assert_eq!(parsed.state_avps, request.state_avps);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_command_cardinality_accepts_repeated_state_conservatively() {
    let mut answer = sample_swm_answer();
    answer.state_avps = vec![b"state-one".to_vec(), b"state-two".to_vec()];
    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("repeatable DEA State AVPs must encode");
    let encoded = encode_message(&built);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("baseline SWm DEA grammar must permit repeated State AVPs");
    assert!(tail.is_empty());
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative())
        .expect("typed DEA parser must retain repeated State values");
    assert_eq!(parsed.state_avps, answer.state_avps);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_projected_profile_alone_permits_repeated_apn_configuration() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(8);
    answer.apn_configurations = vec![sample_apn_configuration(), sample_ims_apn_configuration()];
    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("projected APN profile must encode");
    let encoded = encode_message(&built);
    let expected_second = nth_top_level_avp_offset(
        &built.raw_avps,
        apps::swm::AVP_APN_CONFIGURATION,
        Some(apps::VENDOR_ID_3GPP),
        1,
    );

    let baseline_error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect_err("baseline SWm DEA permits at most one APN-Configuration");
    assert!(matches!(
        baseline_error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    assert_eq!(baseline_error.offset(), expected_second);

    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect("opt-in projected profile must permit repeated APN-Configuration");
    assert!(tail.is_empty());
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative())
        .expect("typed DEA parser must accept the projected repeatable field");
    assert_eq!(parsed, answer);

    let owned = OwnedMessage::decode_owned_with_dictionary(
        encoded.clone().freeze(),
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect("owned projected-profile decode must use the same command cardinality");
    assert_eq!(owned.header, built.header);
    assert_eq!(owned.raw_avps, built.raw_avps);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_projected_answer_repeatability_does_not_apply_to_request() {
    let request = apps::swm::build_swm_diameter_eap_request(
        &sample_swm_request(),
        1,
        2,
        EncodeContext::default(),
    )
    .expect("sample DER must encode");
    let mut raw_avps = BytesMut::from(request.raw_avps.as_ref());
    raw_avps.extend_from_slice(&raw_apn_configuration_avp(
        7,
        b"internet.mnc001.mcc001.gprs",
        2,
    ));
    raw_avps.extend_from_slice(&raw_apn_configuration_avp(8, b"ims.mnc001.mcc001.gprs", 1));
    let message = OwnedMessage {
        header: request.header,
        raw_avps: raw_avps.freeze(),
    };
    let expected = nth_top_level_avp_offset(
        &message.raw_avps,
        apps::swm::AVP_APN_CONFIGURATION,
        Some(apps::VENDOR_ID_3GPP),
        1,
    );
    let encoded = encode_message(&message);
    let error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect_err("answer-only APN repeatability must not apply to a DER");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    assert_eq!(error.offset(), expected);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_cardinality_rejects_singletons_at_second_offset() {
    let context_identifier = encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    );
    let message = build_raw_swm_dea_with_extras(&[context_identifier.clone(), context_identifier]);
    let expected = nth_top_level_avp_offset(
        &message.raw_avps,
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        Some(apps::VENDOR_ID_3GPP),
        1,
    );
    let encoded = encode_message(&message);
    let error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect_err("top-level default Context-Identifier must remain singleton");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    assert_eq!(error.offset(), expected);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_cardinality_rejects_base_singletons_at_second_offset() {
    let cases = [
        (
            encode_raw_avp(base::AVP_SESSION_ID, true, b"second-session"),
            base::AVP_SESSION_ID,
        ),
        (
            encode_raw_avp(base::AVP_RESULT_CODE, true, &2001u32.to_be_bytes()),
            base::AVP_RESULT_CODE,
        ),
    ];

    for (duplicate, code) in cases {
        let message = build_raw_swm_dea_with_extras(&[duplicate]);
        let expected = nth_top_level_avp_offset(&message.raw_avps, code, None, 1);
        let encoded = encode_message(&message);
        let error = Message::decode_with_dictionary(
            &encoded,
            DecodeContext::conservative(),
            apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
        )
        .expect_err("base command AVPs must remain singleton");
        assert!(matches!(
            error.code(),
            opc_protocol::DecodeErrorCode::DuplicateIe
        ));
        assert_eq!(error.offset(), expected);
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_cardinality_rejects_grouped_singleton_child() {
    let first_child = encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    );
    let mut children = BytesMut::new();
    children.extend_from_slice(&first_child);
    children.extend_from_slice(&first_child);
    let grouped = encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &children,
    );
    let message = build_raw_swm_dea_with_extras(&[grouped]);
    let grouped_offset = nth_top_level_avp_offset(
        &message.raw_avps,
        apps::swm::AVP_APN_CONFIGURATION,
        Some(apps::VENDOR_ID_3GPP),
        0,
    );
    let expected = grouped_offset + 12 + first_child.len();
    let encoded = encode_message(&message);
    let error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect_err("grouped singleton children must retain reject-all behavior");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    assert_eq!(error.offset(), expected);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_grammar_rejects_duplicate_unknown_vendor_key() {
    let unknown = encode_raw_vendor_avp(
        AvpCode::new(60_001),
        VendorId::new(60_002),
        false,
        b"opaque",
    );
    let message = build_raw_swm_dea_with_extras(&[unknown.clone(), unknown]);
    let expected = nth_top_level_avp_offset(
        &message.raw_avps,
        AvpCode::new(60_001),
        Some(VendorId::new(60_002)),
        1,
    );
    let encoded = encode_message(&message);
    let error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect_err("unknown vendor-specific AVPs must not gain repeatability");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    assert_eq!(error.offset(), expected);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_grammar_rejects_unknown_mandatory_avp() {
    let unknown =
        encode_raw_vendor_avp(AvpCode::new(60_003), VendorId::new(60_004), true, b"opaque");
    let message = build_raw_swm_dea_with_extras(&[unknown]);
    let encoded = encode_message(&message);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect("command-cardinality validation leaves unknown policy to the typed parser");
    assert!(tail.is_empty());
    let error = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative())
        .expect_err("unknown mandatory AVPs must remain fail closed in the typed parser");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::UnknownCriticalIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_command_grammar_fails_closed_when_missing_or_ambiguous() {
    let built = apps::swm::build_swm_diameter_eap_answer(
        &sample_swm_answer(),
        1,
        2,
        EncodeContext::default(),
    )
    .expect("sample DEA must encode");
    let encoded = encode_message(&built);

    let missing_error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        BASE_ONLY_DICTIONARIES,
    )
    .expect_err("missing application grammar must fail closed");
    assert!(matches!(
        missing_error.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));

    for mismatched in [
        {
            let mut message = built.clone();
            message.header.application_id = ApplicationId::new(apps::swm::APPLICATION_ID.get() + 1);
            message
        },
        {
            let mut message = built.clone();
            message.header.command_code =
                CommandCode::new(apps::swm::COMMAND_DIAMETER_EAP.get() + 1);
            message
        },
    ] {
        let mismatched_encoded = encode_message(&mismatched);
        let error = Message::decode_with_dictionary(
            &mismatched_encoded,
            DecodeContext::conservative(),
            apps::SWM_PROJECTED_PROFILE_DICTIONARIES,
        )
        .expect_err("application and command mismatches must fail closed");
        assert!(matches!(
            error.code(),
            opc_protocol::DecodeErrorCode::Structural { .. }
        ));
        assert_eq!(error.offset(), 5);
    }

    let ambiguous_error = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_AMBIGUOUS_DICTIONARIES,
    )
    .expect_err("multiple command profiles must fail closed");
    assert!(matches!(
        ambiguous_error.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_parses_raw_two_apn_default_context_identifier() {
    let extras = [
        encode_raw_vendor_avp(
            apps::swm::AVP_CONTEXT_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
            true,
            &8u32.to_be_bytes(),
        ),
        raw_apn_configuration_avp(7, b"internet.mnc001.mcc001.gprs", 2),
        raw_apn_configuration_avp(8, b"ims.mnc001.mcc001.gprs", 1),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Last,
        ..DecodeContext::default()
    };
    let (tail, decoded) = Message::decode(&encoded, ctx).expect("multi-APN DEA must decode");
    assert!(tail.is_empty());
    let answer = apps::swm::parse_swm_diameter_eap_answer(&decoded, ctx)
        .expect("raw two-APN DEA with an exact default pointer must parse");

    assert_eq!(answer.service_selection, None);
    assert_eq!(answer.default_context_identifier, Some(8));
    assert_eq!(answer.apn_configurations.len(), 2);
    assert_eq!(
        answer
            .default_apn_configuration()
            .map(|apn| apn.service_selection.as_ref().as_str()),
        Some("ims.mnc001.mcc001.gprs")
    );

    let rebuilt = apps::swm::build_swm_diameter_eap_answer(&answer, 3, 4, EncodeContext::default())
        .expect("parsed two-APN DEA must re-encode");
    let reencoded = encode_message(&rebuilt);
    let redecoded = decode_message(&reencoded);
    let reparsed = apps::swm::parse_swm_diameter_eap_answer(&redecoded, DecodeContext::default())
        .expect("re-encoded two-APN DEA must parse");
    assert_eq!(reparsed, answer);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_duplicate_top_level_context_identifier() {
    let context_identifier = encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    );
    let extras = [context_identifier.clone(), context_identifier];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("duplicate top-level Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_malformed_top_level_context_identifier() {
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &[0x00, 0x00, 0x08],
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("non-u32 top-level Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::InvalidLength { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_zero_default_and_child_context_identifiers() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(0);
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("zero default Context-Identifier must be rejected by the builder");
    assert!(matches!(
        err.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));

    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &0u32.to_be_bytes(),
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("zero wire default Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));

    answer = sample_swm_answer();
    let mut zero_child = sample_apn_configuration();
    zero_child.context_identifier = 0;
    answer.apn_configurations = vec![zero_child];
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("zero child Context-Identifier must be rejected by the builder");
    assert!(matches!(
        err.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));

    let extras = [raw_apn_configuration_avp(
        0,
        b"internet.mnc001.mcc001.gprs",
        2,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("zero wire child Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_dangling_default_context_identifier() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(8);
    answer.apn_configurations = vec![sample_apn_configuration()];
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("dangling default Context-Identifier must be rejected by the builder");
    assert!(matches!(
        err.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));
    assert!(answer.default_apn_configuration().is_none());

    let extras = [
        encode_raw_vendor_avp(
            apps::swm::AVP_CONTEXT_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
            true,
            &8u32.to_be_bytes(),
        ),
        raw_apn_configuration_avp(7, b"internet.mnc001.mcc001.gprs", 2),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("dangling wire default Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_default_context_identifier_without_configurations() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(7);
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("default Context-Identifier without configurations must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));
    assert!(answer.default_apn_configuration().is_none());

    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("wire default Context-Identifier without configurations must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_apn_profile_material_without_diameter_success() {
    for result_code in [2002, 5005] {
        let mut answer = sample_swm_answer();
        answer.result = SwmDiameterResult::Base(result_code);
        answer.default_context_identifier = Some(7);
        answer.apn_configurations = vec![sample_apn_configuration()];
        let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
            .expect_err("only DIAMETER_SUCCESS may carry APN profile material");
        assert!(matches!(
            err.code(),
            opc_protocol::EncodeErrorCode::Structural { .. }
        ));
        assert!(answer.default_apn_configuration().is_none());

        let extras = [
            encode_raw_vendor_avp(
                apps::swm::AVP_CONTEXT_IDENTIFIER,
                apps::VENDOR_ID_3GPP,
                true,
                &7u32.to_be_bytes(),
            ),
            raw_apn_configuration_avp(7, b"internet.mnc001.mcc001.gprs", 2),
        ];
        let message = build_raw_swm_dea_with_result_and_extras(result_code, &extras);
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);
        let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
            .expect_err("wire APN profile material requires DIAMETER_SUCCESS");
        assert!(matches!(
            err.code(),
            opc_protocol::DecodeErrorCode::Structural { .. }
        ));
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_duplicate_apn_context_identifiers() {
    let mut answer = sample_swm_answer();
    let mut duplicate = sample_ims_apn_configuration();
    duplicate.context_identifier = 7;
    answer.apn_configurations = vec![sample_apn_configuration(), duplicate];
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("duplicate child Context-Identifier must be rejected by the builder");
    assert!(matches!(
        err.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));
    assert!(answer.default_apn_configuration().is_none());

    let extras = [
        raw_apn_configuration_avp(7, b"internet.mnc001.mcc001.gprs", 2),
        raw_apn_configuration_avp(7, b"ims.mnc001.mcc001.gprs", 1),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("duplicate wire child Context-Identifier must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_duplicate_apn_service_selections_without_disclosure() {
    const APN: &str = "private.operator.example";

    let mut answer = sample_swm_answer();
    let mut first = sample_apn_configuration();
    first.service_selection = APN.into();
    let mut second = sample_ims_apn_configuration();
    second.service_selection = APN.into();
    answer.apn_configurations = vec![first, second];
    let err = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("duplicate APN Service-Selection values must be rejected");
    assert!(!format!("{err:?}").contains(APN));
    assert!(answer.default_apn_configuration().is_none());

    let extras = [
        raw_apn_configuration_avp(7, APN.as_bytes(), 2),
        raw_apn_configuration_avp(8, APN.as_bytes(), 1),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("wire duplicate APN Service-Selection values must be rejected");
    assert!(!format!("{err:?}").contains(APN));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_duplicate_top_level_service_selection() {
    let service_selection = encode_raw_avp(
        apps::swm::AVP_SERVICE_SELECTION,
        true,
        b"internet.mnc001.mcc001.gprs",
    );
    let extras = [service_selection.clone(), service_selection];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("duplicate top-level Service-Selection must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dictionary_validation_recognizes_grouped_subscription_avps() {
    let mut answer = sample_swm_answer();
    answer.default_context_identifier = Some(7);
    answer.apn_configurations = vec![sample_apn_configuration()];
    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("SWm DEA build must succeed");
    let encoded = encode_message(&built);
    let message = decode_message(&encoded);
    assert!(message
        .validate_avps_with_dictionary(
            DecodeContext::default(),
            DictionarySet::new(&[apps::swm::dictionary()]),
        )
        .is_ok());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_unknown_mandatory_vendor_avp() {
    let extras = [
        encode_raw_vendor_avp(
            apps::swm::AVP_CONTEXT_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
            true,
            &7u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(AvpCode::new(9999), apps::VENDOR_ID_3GPP, true, b"unknown"),
    ];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("unknown mandatory vendor AVP must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::UnknownCriticalIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_rejects_context_identifier_code_from_wrong_vendor() {
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        VendorId::new(4_242),
        true,
        &7u32.to_be_bytes(),
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("Context-Identifier under the wrong vendor must remain unknown");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::UnknownCriticalIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_unknown_vendor_avp_policy_matrix() {
    let extras = [encode_raw_vendor_avp(
        AvpCode::new(9999),
        apps::VENDOR_ID_3GPP,
        false,
        b"unknown",
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);

    for policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        let ctx = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::default()
        };
        let answer = apps::swm::parse_swm_diameter_eap_answer(&decoded, ctx)
            .expect("non-mandatory unknown vendor AVP must be tolerated");
        // The typed projection does not retain the opaque unknown AVP.
        assert!(answer.apn_configurations.is_empty());
        assert!(answer.service_selection.is_none());
    }

    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert!(apps::swm::parse_swm_diameter_eap_answer(&decoded, ctx).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_rejects_missing_required_child() {
    // Context-Identifier and PDN-Type present, Service-Selection missing.
    let mut apn_value = BytesMut::new();
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    ));
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PDN_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &2u32.to_be_bytes(),
    ));
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &apn_value,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("APN-Configuration without Service-Selection must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_rejects_duplicate_child() {
    let mut apn_value = raw_apn_configuration_children(7, b"internet.mnc001.mcc001.gprs", 2);
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PDN_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &0u32.to_be_bytes(),
    ));
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &apn_value,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("duplicate PDN-Type child must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_rejects_unknown_mandatory_child() {
    let mut apn_value = raw_apn_configuration_children(7, b"internet.mnc001.mcc001.gprs", 2);
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        AvpCode::new(9999),
        apps::VENDOR_ID_3GPP,
        true,
        b"unknown",
    ));
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &apn_value,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("unknown mandatory child AVP must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::UnknownCriticalIe
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_tolerates_unknown_optional_child() {
    let mut apn_value = raw_apn_configuration_children(7, b"internet.mnc001.mcc001.gprs", 2);
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        AvpCode::new(9999),
        apps::VENDOR_ID_3GPP,
        false,
        b"unknown",
    ));
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &apn_value,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let answer = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect("unknown optional child AVP must be tolerated");
    assert_eq!(answer.apn_configurations.len(), 1);
    assert_eq!(answer.apn_configurations[0].context_identifier, 7);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_rejects_malformed_child_value() {
    // PDN-Type value shorter than the four-octet Enumerated encoding.
    let mut apn_value = BytesMut::new();
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_CONTEXT_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        true,
        &7u32.to_be_bytes(),
    ));
    apn_value.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_SERVICE_SELECTION,
        true,
        b"internet.mnc001.mcc001.gprs",
    ));
    apn_value.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_PDN_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &[0x00, 0x00, 0x02],
    ));
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &apn_value,
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    let err = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default())
        .expect_err("malformed PDN-Type child must be rejected");
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::InvalidLength { .. }
    ));

    // A grouped value that is not valid AVP framing must also fail closed.
    let extras = [encode_raw_vendor_avp(
        apps::swm::AVP_APN_CONFIGURATION,
        apps::VENDOR_ID_3GPP,
        true,
        &[0xFF, 0xFF, 0xFF],
    )];
    let message = build_raw_swm_dea_with_extras(&extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_debug_redacts_subscription_data() {
    let mut answer = sample_swm_answer();
    answer.service_selection = Some("operator-policy.mnc001.mcc001.gprs".into());
    answer.default_context_identifier = Some(8);
    answer.apn_configurations = vec![sample_apn_configuration(), sample_ims_apn_configuration()];

    let debug = format!("{:?}", answer);
    assert!(!debug.contains("internet.mnc001"));
    assert!(!debug.contains("ims.mnc001"));
    assert!(!debug.contains("operator-policy.mnc001"));
    assert!(debug.contains("REDACTED"));
    assert!(debug.contains("default_context_identifier: Some(8)"));
    // Grouped subscription entries appear only as a count.
    assert!(debug.contains("apn_configurations: 2"));

    let debug = format!("{:?}", sample_apn_configuration());
    assert!(!debug.contains("internet.mnc001"));
    assert!(debug.contains("REDACTED"));
}
