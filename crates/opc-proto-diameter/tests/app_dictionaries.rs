use std::net::{IpAddr, Ipv4Addr};

use bytes::BytesMut;
use opc_proto_diameter::apps::rf::{
    AccountingRecordType, MultipleServicesCreditControl, PsInformation, RfAccountingAnswer,
    RfAccountingRequest, SubscriptionId, SubscriptionIdType, UsedServiceUnit,
};
use opc_proto_diameter::apps::swm::{
    AllocationRetentionPriority, Ambr, ApnConfiguration, AuthRequestType, EpsSubscribedQosProfile,
    PdnType, SwmAaaFailureIndication, SwmAuthorizationOutcome, SwmConditionalValue,
    SwmConditionalValueSource, SwmCorrelatedDiameterEapExchange, SwmDerAccessContext,
    SwmDerAccessContextErrorCode, SwmDerAccessContextField, SwmDiameterEapAnswer,
    SwmDiameterEapAnswerEnvelope, SwmDiameterEapRequest, SwmDiameterEapRequestEnvelope,
    SwmDiameterResult, SwmDiameterTransaction, SwmEmergencyAuthorizationError,
    SwmEmergencyAuthorizationEvidence, SwmEmergencyAuthorizationPath, SwmEmergencyServices,
    SwmHighPriorityAccessInfo, SwmMip6FeatureVector, SwmPreemptionCapability,
    SwmPreemptionVulnerability, SwmPriorityLevel, SwmQosCapability, SwmQosClassIdentifier,
    SwmQosProfileTemplate, SwmRatType, SwmRequestedSupportedFeatures, SwmResultCategory,
    SwmSupportedFeatureList, SwmSupportedFeaturesRequirement, SwmTerminalInformation,
    SwmVisitedNetworkIdentifier,
};
use opc_proto_diameter::{
    apps, base, ApplicationId, AvpCardinality, AvpCode, AvpDataType, AvpFlags, AvpHeader, AvpKey,
    CommandCode, CommandFlags, CommandKind, DictionarySet, FlagRequirement, Header, Message,
    OwnedMessage, RawAvp, VendorId, DIAMETER_HEADER_LEN,
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

    let state = dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_STATE))
        .expect("State must be present");
    assert_eq!(state.data_type(), AvpDataType::OctetString);
    assert_eq!(state.flags().vendor(), FlagRequirement::MustBeUnset);
    assert_eq!(state.flags().mandatory(), FlagRequirement::MustBeSet);
    assert_eq!(state.flags().protected(), FlagRequirement::MayBeSet);

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

    let remaining_access_avps = [
        (
            AvpKey::ietf(apps::swm::AVP_QOS_CAPABILITY),
            AvpDataType::Grouped,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
        ),
        (
            AvpKey::vendor(
                apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
                apps::VENDOR_ID_3GPP,
            ),
            AvpDataType::OctetString,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        (
            AvpKey::vendor(apps::swm::AVP_AAA_FAILURE_INDICATION, apps::VENDOR_ID_3GPP),
            AvpDataType::Unsigned32,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        (
            AvpKey::vendor(
                apps::swm::AVP_HIGH_PRIORITY_ACCESS_INFO,
                apps::VENDOR_ID_3GPP,
            ),
            AvpDataType::Unsigned32,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
    ];
    for (key, data_type, vendor, mandatory) in remaining_access_avps {
        let definition = dictionary
            .find_avp(key)
            .expect("remaining DER access AVP definition");
        assert_eq!(definition.data_type(), data_type);
        assert_eq!(definition.flags().vendor(), vendor);
        assert_eq!(definition.flags().mandatory(), mandatory);
        assert_eq!(definition.flags().protected(), FlagRequirement::MustBeUnset);
        assert!(der.find_avp_rule(key).is_some());
        assert!(!der.allows_multiple(key));
    }

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

    // Rf is intentionally registered before SWm. Both application definitions
    // permit P, while Rf retains RFC 4006's required outer M bit and SWm keeps
    // its understood-M-mismatch tolerance local.
    for code in [
        apps::swm::AVP_SUBSCRIPTION_ID,
        apps::swm::AVP_SUBSCRIPTION_ID_TYPE,
        apps::swm::AVP_SUBSCRIPTION_ID_DATA,
    ] {
        assert_eq!(
            set.find_avp(AvpKey::ietf(code))
                .expect("shared Subscription-Id definition")
                .flags()
                .protected(),
            FlagRequirement::MayBeSet
        );
    }
    assert_eq!(
        set.find_avp(AvpKey::ietf(apps::swm::AVP_SUBSCRIPTION_ID))
            .expect("shared Subscription-Id definition")
            .flags()
            .mandatory(),
        FlagRequirement::MustBeSet
    );
    assert_eq!(
        apps::swm::dictionary()
            .find_avp(AvpKey::ietf(apps::swm::AVP_SUBSCRIPTION_ID))
            .expect("SWm Subscription-Id definition")
            .flags()
            .mandatory(),
        FlagRequirement::MayBeSet
    );
    for child in [
        apps::swm::AVP_SUBSCRIPTION_ID_TYPE,
        apps::swm::AVP_SUBSCRIPTION_ID_DATA,
    ] {
        assert_eq!(
            set.find_avp(AvpKey::ietf(child))
                .expect("shared Subscription-Id child definition")
                .flags()
                .mandatory(),
            FlagRequirement::MustBeSet
        );
    }

    let protected_child_flags = AvpFlags::new(false, true, true);
    let mut grouped = BytesMut::new();
    grouped.extend_from_slice(&encode_raw_avp_with_header(
        AvpHeader::ietf(apps::swm::AVP_SUBSCRIPTION_ID_TYPE, true)
            .with_flags(protected_child_flags),
        &0_u32.to_be_bytes(),
    ));
    grouped.extend_from_slice(&encode_raw_avp_with_header(
        AvpHeader::ietf(apps::swm::AVP_SUBSCRIPTION_ID_DATA, true)
            .with_flags(protected_child_flags),
        b"15550100001",
    ));
    for outer_mandatory in [false, true] {
        let subscription = encode_raw_avp_with_header(
            AvpHeader::ietf(apps::swm::AVP_SUBSCRIPTION_ID, outer_mandatory)
                .with_flags(AvpFlags::new(false, outer_mandatory, true)),
            &grouped,
        );
        let owned = build_raw_swm_dea_with_extras(&[subscription]);
        let encoded = encode_message(&owned);
        let message = decode_message(&encoded);
        assert!(message
            .validate_command_avps_with_dictionary(DecodeContext::conservative(), set)
            .is_ok());
        assert!(
            apps::swm::parse_swm_diameter_eap_answer(&message, DecodeContext::conservative(),)
                .is_ok()
        );
    }
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
    for code in [
        apps::rf::AVP_SUBSCRIPTION_ID,
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
    ] {
        assert_eq!(
            apps::rf::dictionary()
                .find_avp(AvpKey::ietf(code))
                .expect("RFC 4006 Subscription-Id definition")
                .flags()
                .protected(),
            FlagRequirement::MayBeSet
        );
    }
    assert_eq!(
        apps::rf::dictionary()
            .find_avp(AvpKey::ietf(apps::rf::AVP_SUBSCRIPTION_ID))
            .expect("RFC 4006 Subscription-Id definition")
            .flags()
            .mandatory(),
        FlagRequirement::MustBeSet
    );
    for child in [
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
    ] {
        assert_eq!(
            apps::rf::dictionary()
                .find_avp(AvpKey::ietf(child))
                .expect("RFC 4006 Subscription-Id child definition")
                .flags()
                .mandatory(),
            FlagRequirement::MustBeSet
        );
    }
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
fn swm_new_access_fields_are_wire_compatible_when_absent() {
    let request = sample_swm_request();
    let built_request = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("legacy-shaped DER");
    let mut expected_request_avps = BytesMut::new();
    for avp in [
        encode_raw_avp(base::AVP_SESSION_ID, true, b"sess;swm;001"),
        encode_raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            true,
            &apps::swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        encode_raw_avp(base::AVP_ORIGIN_HOST, true, b"epdg.example"),
        encode_raw_avp(base::AVP_ORIGIN_REALM, true, b"visited.example"),
        encode_raw_avp(base::AVP_DESTINATION_REALM, true, b"home.example"),
        encode_raw_avp(base::AVP_DESTINATION_HOST, true, b"aaa.home.example"),
        encode_raw_avp(apps::swm::AVP_AUTH_REQUEST_TYPE, true, &3u32.to_be_bytes()),
        encode_raw_avp(
            base::AVP_USER_NAME,
            true,
            b"601010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
        ),
        encode_raw_avp(apps::swm::AVP_STATE, true, b"opaque-state"),
        encode_raw_avp(
            apps::swm::AVP_EAP_PAYLOAD,
            true,
            &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        ),
    ] {
        expected_request_avps.extend_from_slice(&avp);
    }
    let expected_request = OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            apps::swm::COMMAND_DIAMETER_EAP,
            apps::swm::APPLICATION_ID,
            0x1111_2222,
            0x3333_4444,
        ),
        raw_avps: expected_request_avps.freeze(),
    };
    assert_eq!(
        encode_message(&built_request),
        encode_message(&expected_request)
    );

    let answer = sample_swm_answer();
    let built_answer = apps::swm::build_swm_diameter_eap_answer(
        &answer,
        0x5555_6666,
        0x7777_8888,
        EncodeContext::default(),
    )
    .expect("legacy-shaped DEA");
    let mut expected_answer_avps = BytesMut::new();
    for avp in [
        encode_raw_avp(base::AVP_SESSION_ID, true, b"sess;swm;001"),
        encode_raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            true,
            &apps::swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        encode_raw_avp(apps::swm::AVP_AUTH_REQUEST_TYPE, true, &3u32.to_be_bytes()),
        encode_raw_avp(base::AVP_RESULT_CODE, true, &2001u32.to_be_bytes()),
        encode_raw_avp(base::AVP_ORIGIN_HOST, true, b"aaa.home.example"),
        encode_raw_avp(base::AVP_ORIGIN_REALM, true, b"home.example"),
        encode_raw_avp(apps::swm::AVP_EAP_PAYLOAD, true, &[0x03, 0x18, 0x00, 0x04]),
        encode_raw_avp(apps::swm::AVP_EAP_MASTER_SESSION_KEY, false, &[0xaa; 32]),
    ] {
        expected_answer_avps.extend_from_slice(&avp);
    }
    let expected_answer = OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            apps::swm::COMMAND_DIAMETER_EAP,
            apps::swm::APPLICATION_ID,
            0x5555_6666,
            0x7777_8888,
        ),
        raw_avps: expected_answer_avps.freeze(),
    };
    assert_eq!(
        encode_message(&built_answer),
        encode_message(&expected_answer)
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_has_exact_wire_profile_and_round_trips() {
    const APN: &str = "ims";

    let mut request = sample_swm_request();
    request.rat_type = Some(SwmRatType::Wlan);
    request.service_selection = Some(APN.into());
    let built = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )
    .expect("SWm DER access context build");
    let encoded = encode_message(&built);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("SWm DER access context dictionary decode");
    assert!(tail.is_empty());

    let avps = decoded
        .avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("valid SWm DER AVPs");
    let rat_type = avps
        .iter()
        .find(|avp| {
            avp.header.code == apps::swm::AVP_RAT_TYPE
                && avp.header.vendor_id == Some(apps::VENDOR_ID_3GPP)
        })
        .expect("RAT-Type AVP");
    assert!(rat_type.header.flags.is_vendor_specific());
    assert!(rat_type.header.flags.is_mandatory());
    assert!(!rat_type.header.flags.is_protected());
    assert_eq!(rat_type.value, 0u32.to_be_bytes());

    let service_selection = avps
        .iter()
        .find(|avp| avp.header.code == apps::swm::AVP_SERVICE_SELECTION)
        .expect("Service-Selection AVP");
    assert_eq!(service_selection.header.vendor_id, None);
    assert!(service_selection.header.flags.is_mandatory());
    assert!(!service_selection.header.flags.is_protected());
    assert_eq!(service_selection.value, APN.as_bytes());

    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("SWm DER access context parse");
    assert_eq!(parsed, request);
    assert_eq!(parsed.rat_type, Some(SwmRatType::Wlan));
    assert_eq!(
        parsed
            .service_selection
            .as_ref()
            .map(|value| value.as_ref().as_str()),
        Some(APN)
    );
    assert!(!format!("{parsed:?}").contains(APN));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_remaining_access_context_round_trips_with_canonical_wire() {
    const PROFILE_ID: u32 = 424_242;
    let visited =
        SwmVisitedNetworkIdentifier::new("234", "15").expect("synthetic two-digit MNC is valid");
    assert_eq!(visited.as_str(), "mnc015.mcc234.3gppnetwork.org");
    let qos = SwmQosCapability::new(vec![
        SwmQosProfileTemplate::ietf_diameter(),
        SwmQosProfileTemplate::new(VendorId::new(55_555), PROFILE_ID),
    ])
    .expect("distinct synthetic QoS profiles");
    let context = SwmDerAccessContext {
        qos_capability: SwmConditionalValue::LocallyConfigured(qos),
        visited_network_identifier: SwmConditionalValue::LocallyConfigured(visited),
        aaa_failure_indication: SwmConditionalValue::AaaDerived(
            SwmAaaFailureIndication::previously_assigned_server_unavailable(),
        ),
        high_priority_access_info: SwmConditionalValue::UeProvided(
            SwmHighPriorityAccessInfo::configured(),
        ),
        ..SwmDerAccessContext::default()
    };
    assert_eq!(
        context.qos_capability.source(),
        Some(SwmConditionalValueSource::LocallyConfigured)
    );
    assert_eq!(
        context.aaa_failure_indication.source(),
        Some(SwmConditionalValueSource::AaaDerived)
    );
    let context_debug = format!("{context:?}");
    assert!(!context_debug.contains("mnc015"));
    assert!(!context_debug.contains(&PROFILE_ID.to_string()));

    let base_request = sample_swm_request();
    let checked = apps::swm::build_swm_diameter_eap_request_with_access_context(
        &base_request,
        context,
        0x1020_3040,
        0x5060_7080,
        EncodeContext::default(),
    )
    .expect("normative source matrix builds atomically");
    let snapshot = checked.source_snapshot();
    assert_eq!(
        snapshot.qos_capability(),
        Some(SwmConditionalValueSource::LocallyConfigured)
    );
    assert_eq!(
        snapshot.visited_network_identifier(),
        Some(SwmConditionalValueSource::LocallyConfigured)
    );
    assert_eq!(
        snapshot.aaa_failure_indication(),
        Some(SwmConditionalValueSource::AaaDerived)
    );
    assert_eq!(
        snapshot.high_priority_access_info(),
        Some(SwmConditionalValueSource::UeProvided)
    );
    let checked_debug = format!("{checked:?}");
    assert!(!checked_debug.contains("mnc015"));
    assert!(!checked_debug.contains(&PROFILE_ID.to_string()));
    let request = checked.request().clone();
    let encoded = encode_message(checked.message());
    let built = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1020_3040,
        0x5060_7080,
        EncodeContext::default(),
    )
    .expect("remaining DER access context builds");
    assert_eq!(encoded, encode_message(&built));
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("dictionary accepts canonical remaining DER access context");
    assert!(tail.is_empty());
    let avps = decoded
        .avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("canonical DER AVPs");

    let qos_avp = avps
        .iter()
        .find(|avp| avp.header.key() == AvpKey::ietf(apps::swm::AVP_QOS_CAPABILITY))
        .expect("QoS-Capability");
    assert!(qos_avp.header.flags.is_mandatory());
    assert!(!qos_avp.header.flags.is_vendor_specific());
    assert!(!qos_avp.header.flags.is_protected());
    let templates = qos_avp
        .grouped_avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("QoS-Capability children");
    assert_eq!(templates.len(), 2);
    assert!(templates.iter().all(|template| {
        template.header.key() == AvpKey::ietf(apps::swm::AVP_QOS_PROFILE_TEMPLATE)
            && template.header.flags.is_mandatory()
            && !template.header.flags.is_vendor_specific()
            && !template.header.flags.is_protected()
    }));
    let second_children = templates[1]
        .grouped_avps(DecodeContext::conservative())
        .collect::<Result<Vec<_>, _>>()
        .expect("QoS profile children");
    assert_eq!(second_children.len(), 2);
    assert_eq!(
        second_children[0].header.key(),
        AvpKey::ietf(base::AVP_VENDOR_ID)
    );
    assert_eq!(
        second_children[1].header.key(),
        AvpKey::ietf(apps::swm::AVP_QOS_PROFILE_ID)
    );
    assert!(second_children
        .iter()
        .all(|child| child.header.flags.is_mandatory()));

    let visited_avp = avps
        .iter()
        .find(|avp| {
            avp.header.key()
                == AvpKey::vendor(
                    apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
                    apps::VENDOR_ID_3GPP,
                )
        })
        .expect("Visited-Network-Identifier");
    assert!(visited_avp.header.flags.is_mandatory());
    assert_eq!(visited_avp.value, b"mnc015.mcc234.3gppnetwork.org");

    for code in [
        apps::swm::AVP_AAA_FAILURE_INDICATION,
        apps::swm::AVP_HIGH_PRIORITY_ACCESS_INFO,
    ] {
        let avp = avps
            .iter()
            .find(|avp| avp.header.key() == AvpKey::vendor(code, apps::VENDOR_ID_3GPP))
            .expect("defined access-context indication");
        assert!(!avp.header.flags.is_mandatory());
        assert!(avp.header.flags.is_vendor_specific());
        assert!(!avp.header.flags.is_protected());
        assert_eq!(avp.value, 1u32.to_be_bytes());
    }

    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("remaining DER access context parses");
    assert_eq!(parsed, request);
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("mnc015"));
    assert!(!debug.contains(&PROFILE_ID.to_string()));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_provenance_matrix_is_fail_closed_and_atomic() {
    let visited = SwmVisitedNetworkIdentifier::new("001", "01").expect("synthetic PLMN");
    let qos = SwmQosCapability::new(vec![SwmQosProfileTemplate::ietf_diameter()])
        .expect("one required profile");
    let cases = [
        (
            SwmDerAccessContext {
                qos_capability: SwmConditionalValue::UeProvided(qos.clone()),
                ..SwmDerAccessContext::default()
            },
            SwmDerAccessContextField::QosCapability,
        ),
        (
            SwmDerAccessContext {
                visited_network_identifier: SwmConditionalValue::AaaDerived(visited.clone()),
                ..SwmDerAccessContext::default()
            },
            SwmDerAccessContextField::VisitedNetworkIdentifier,
        ),
        (
            SwmDerAccessContext {
                aaa_failure_indication: SwmConditionalValue::LocallyConfigured(
                    SwmAaaFailureIndication::previously_assigned_server_unavailable(),
                ),
                ..SwmDerAccessContext::default()
            },
            SwmDerAccessContextField::AaaFailureIndication,
        ),
        (
            SwmDerAccessContext {
                high_priority_access_info: SwmConditionalValue::LocallyConfigured(
                    SwmHighPriorityAccessInfo::configured(),
                ),
                ..SwmDerAccessContext::default()
            },
            SwmDerAccessContextField::HighPriorityAccessInfo,
        ),
    ];
    for (context, expected_field) in cases {
        let request = sample_swm_request();
        let error = apps::swm::build_swm_diameter_eap_request_with_access_context(
            &request,
            context,
            1,
            2,
            EncodeContext::default(),
        )
        .expect_err("invalid provenance must fail closed");
        let error = error.context_error().expect("context failure");
        assert_eq!(
            error.code(),
            SwmDerAccessContextErrorCode::InvalidProvenance
        );
        assert_eq!(error.field(), expected_field);
        assert!(!format!("{error:?}").contains("mnc001"));
    }
    let request = sample_swm_request();
    let inactive = apps::swm::build_swm_diameter_eap_request_with_access_context(
        &request,
        SwmDerAccessContext {
            high_priority_access_info: SwmConditionalValue::UeProvided(
                SwmHighPriorityAccessInfo::from_value(0),
            ),
            ..SwmDerAccessContext::default()
        },
        1,
        2,
        EncodeContext::default(),
    )
    .expect_err("present HPA without HPA_Configured is contradictory")
    .context_error()
    .expect("context failure");
    assert_eq!(
        inactive.code(),
        SwmDerAccessContextErrorCode::InactiveIndication
    );
    assert_eq!(
        inactive.field(),
        SwmDerAccessContextField::HighPriorityAccessInfo
    );

    let mut prepopulated_qos = sample_swm_request();
    prepopulated_qos.qos_capability = Some(qos.clone());
    let mut prepopulated_visited = sample_swm_request();
    prepopulated_visited.visited_network_identifier = Some(visited.clone());
    let mut prepopulated_aaa = sample_swm_request();
    prepopulated_aaa.aaa_failure_indication =
        Some(SwmAaaFailureIndication::previously_assigned_server_unavailable());
    let mut prepopulated_priority = sample_swm_request();
    prepopulated_priority.high_priority_access_info = Some(SwmHighPriorityAccessInfo::configured());
    for (prepopulated, expected_field) in [
        (prepopulated_qos, SwmDerAccessContextField::QosCapability),
        (
            prepopulated_visited,
            SwmDerAccessContextField::VisitedNetworkIdentifier,
        ),
        (
            prepopulated_aaa,
            SwmDerAccessContextField::AaaFailureIndication,
        ),
        (
            prepopulated_priority,
            SwmDerAccessContextField::HighPriorityAccessInfo,
        ),
    ] {
        let conflict = apps::swm::build_swm_diameter_eap_request_with_access_context(
            &prepopulated,
            SwmDerAccessContext::default(),
            1,
            2,
            EncodeContext::default(),
        )
        .expect_err("prepopulated raw context field must fail closed")
        .context_error()
        .expect("context failure");
        assert_eq!(
            conflict.code(),
            SwmDerAccessContextErrorCode::PrepopulatedField
        );
        assert_eq!(conflict.field(), expected_field);
    }

    for (mcc, mnc) in [("01", "001"), ("001", "1"), ("0x1", "01")] {
        let error =
            SwmVisitedNetworkIdentifier::new(mcc, mnc).expect_err("malformed PLMN component");
        assert_eq!(
            error.code(),
            SwmDerAccessContextErrorCode::InvalidVisitedNetworkIdentifier
        );
    }
    let empty = SwmQosCapability::new(Vec::new()).expect_err("empty capability");
    assert_eq!(
        empty.code(),
        SwmDerAccessContextErrorCode::EmptyQosCapability
    );
    let excessive_profiles = SwmQosCapability::new(
        (0..129)
            .map(|id| SwmQosProfileTemplate::new(VendorId::new(0), id))
            .collect(),
    )
    .expect_err("profile-template count must remain bounded");
    assert_eq!(
        excessive_profiles.code(),
        SwmDerAccessContextErrorCode::TooManyQosProfiles
    );
    let request = sample_swm_request();
    let before = encode_message(
        &apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .expect("baseline DER"),
    );
    let checked = apps::swm::build_swm_diameter_eap_request_with_access_context(
        &request,
        SwmDerAccessContext::default(),
        1,
        2,
        EncodeContext::default(),
    )
    .expect("all-absent DER");
    let absent_snapshot = checked.source_snapshot();
    assert_eq!(absent_snapshot.qos_capability(), None);
    assert_eq!(absent_snapshot.visited_network_identifier(), None);
    assert_eq!(absent_snapshot.aaa_failure_indication(), None);
    assert_eq!(absent_snapshot.high_priority_access_info(), None);
    let after = encode_message(checked.message());
    assert_eq!(after, before, "absent access context is byte-compatible");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_accepts_known_m_mismatch_and_canonicalizes_reserved_bits() {
    let profile = encode_qos_profile_template_avp(VendorId::new(0), 0, &[]);
    let qos = encode_qos_capability_avp(false, &[profile], &[]);
    let visited = encode_raw_vendor_avp(
        apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
        apps::VENDOR_ID_3GPP,
        false,
        b"mnc015.mcc234.3gppnetwork.org",
    );
    let aaa_failure = encode_raw_vendor_avp(
        apps::swm::AVP_AAA_FAILURE_INDICATION,
        apps::VENDOR_ID_3GPP,
        true,
        &3u32.to_be_bytes(),
    );
    let high_priority = encode_raw_vendor_avp(
        apps::swm::AVP_HIGH_PRIORITY_ACCESS_INFO,
        apps::VENDOR_ID_3GPP,
        true,
        &3u32.to_be_bytes(),
    );
    let raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[qos, visited, aaa_failure, high_priority],
    );
    let wire = encode_message(&raw);
    let (tail, message) =
        Message::decode_with_dictionary(&wire, DecodeContext::default(), SWM_BASELINE_DICTIONARIES)
            .expect("known SWm M mismatches are receive-compatible");
    assert!(tail.is_empty());
    let parsed = apps::swm::parse_swm_diameter_eap_request(&message, DecodeContext::default())
        .expect("known SWm M mismatches parse");
    assert_eq!(
        parsed
            .qos_capability
            .as_ref()
            .map(|qos| qos.profiles().len()),
        Some(1)
    );
    assert_eq!(
        parsed
            .visited_network_identifier
            .as_ref()
            .map(SwmVisitedNetworkIdentifier::as_str),
        Some("mnc015.mcc234.3gppnetwork.org")
    );
    assert_eq!(
        parsed.aaa_failure_indication,
        Some(SwmAaaFailureIndication::previously_assigned_server_unavailable())
    );
    assert_eq!(
        parsed.high_priority_access_info,
        Some(SwmHighPriorityAccessInfo::configured())
    );

    let canonical =
        apps::swm::build_swm_diameter_eap_request(&parsed, 1, 2, EncodeContext::default())
            .expect("canonical rebuild");
    let canonical_wire = encode_message(&canonical);
    let canonical_message = decode_message(&canonical_wire);
    let canonical_avps = canonical_message
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("canonical AVPs");
    let canonical_qos = canonical_avps
        .iter()
        .find(|avp| avp.header.code == apps::swm::AVP_QOS_CAPABILITY)
        .expect("canonical QoS");
    let canonical_visited = canonical_avps
        .iter()
        .find(|avp| avp.header.code == apps::swm::AVP_VISITED_NETWORK_IDENTIFIER)
        .expect("canonical visited network");
    assert!(canonical_qos.header.flags.is_mandatory());
    assert!(canonical_visited.header.flags.is_mandatory());
    for code in [
        apps::swm::AVP_AAA_FAILURE_INDICATION,
        apps::swm::AVP_HIGH_PRIORITY_ACCESS_INFO,
    ] {
        let avp = canonical_avps
            .iter()
            .find(|avp| avp.header.code == code)
            .expect("canonical indication");
        assert!(!avp.header.flags.is_mandatory());
        assert_eq!(avp.value, 1u32.to_be_bytes());
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_rejects_malformed_shapes_and_preserves_optional_extensions() {
    let parse_extra = |extra: &BytesMut, ctx: DecodeContext| {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            std::slice::from_ref(extra),
        );
        let wire = encode_message(&raw);
        apps::swm::parse_swm_diameter_eap_request(&decode_message(&wire), ctx)
    };

    for invalid in [
        encode_raw_vendor_avp(
            apps::swm::AVP_AAA_FAILURE_INDICATION,
            apps::VENDOR_ID_3GPP,
            false,
            &0u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_HIGH_PRIORITY_ACCESS_INFO,
            apps::VENDOR_ID_3GPP,
            false,
            &0u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_AAA_FAILURE_INDICATION,
            apps::VENDOR_ID_3GPP,
            false,
            &[0, 0, 1],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
            true,
            b"visited.example",
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
            VendorId::new(9_999),
            true,
            b"mnc015.mcc234.3gppnetwork.org",
        ),
    ] {
        parse_extra(&invalid, DecodeContext::default())
            .expect_err("malformed access-context AVP must fail closed");
    }

    let empty_qos = encode_qos_capability_avp(true, &[], &[]);
    let empty_template = encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &[]);
    let qos_with_empty_template = encode_qos_capability_avp(true, &[empty_template], &[]);
    let vendor_only_template = {
        let vendor = encode_raw_avp(base::AVP_VENDOR_ID, true, &0u32.to_be_bytes());
        encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &vendor)
    };
    let qos_missing_profile_id = encode_qos_capability_avp(true, &[vendor_only_template], &[]);
    let profile_id_only_template = {
        let profile_id = encode_raw_avp(apps::swm::AVP_QOS_PROFILE_ID, true, &0u32.to_be_bytes());
        encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &profile_id)
    };
    let qos_missing_vendor_id = encode_qos_capability_avp(true, &[profile_id_only_template], &[]);
    let malformed_profile_id = {
        let mut children = BytesMut::new();
        children.extend_from_slice(&encode_raw_avp(
            base::AVP_VENDOR_ID,
            true,
            &0u32.to_be_bytes(),
        ));
        children.extend_from_slice(&encode_raw_avp(
            apps::swm::AVP_QOS_PROFILE_ID,
            true,
            &[0, 0, 0],
        ));
        encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &children)
    };
    let qos_malformed_profile_id = encode_qos_capability_avp(true, &[malformed_profile_id], &[]);
    let duplicated_profile = encode_qos_profile_template_avp(VendorId::new(0), 0, &[]);
    let middle_profile = encode_qos_profile_template_avp(VendorId::new(55_555), 7, &[]);
    let qos_repeated_identity = encode_qos_capability_avp(
        true,
        &[
            duplicated_profile.clone(),
            middle_profile,
            duplicated_profile,
        ],
        &[],
    );
    for invalid in [
        empty_qos,
        qos_with_empty_template,
        qos_missing_vendor_id,
        qos_missing_profile_id,
        qos_malformed_profile_id,
    ] {
        parse_extra(&invalid, DecodeContext::default())
            .expect_err("invalid QoS grouped cardinality or width must fail closed");
    }
    let repeated = parse_extra(&qos_repeated_identity, DecodeContext::default())
        .expect("RFC 5777 permits repeated complete profile templates");
    assert_eq!(
        repeated
            .qos_capability
            .as_ref()
            .map(|capability| capability.profiles().len()),
        Some(3)
    );
    let repeated_raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[qos_repeated_identity],
    );
    let repeated_wire = encode_message(&repeated_raw);
    Message::decode_with_dictionary(
        &repeated_wire,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("grouped dictionary cardinality permits repeatable profile templates");
    let repeated_rebuilt =
        apps::swm::build_swm_diameter_eap_request(&repeated, 1, 2, EncodeContext::default())
            .expect("repeated QoS profiles rebuild");
    let repeated_rebuilt_wire = encode_message(&repeated_rebuilt);
    let repeated_reparsed = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&repeated_rebuilt_wire),
        DecodeContext::default(),
    )
    .expect("repeated QoS profiles reparse");
    let identities = repeated_reparsed
        .qos_capability
        .as_ref()
        .expect("reparsed QoS capability")
        .profiles()
        .iter()
        .map(|profile| (profile.vendor_id(), profile.profile_id()))
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        vec![
            (VendorId::new(0), 0),
            (VendorId::new(55_555), 7),
            (VendorId::new(0), 0),
        ],
        "rebuild must preserve repeated identities and wire order"
    );

    let vendor = encode_raw_avp(base::AVP_VENDOR_ID, true, &0u32.to_be_bytes());
    let profile_id = encode_raw_avp(apps::swm::AVP_QOS_PROFILE_ID, true, &0u32.to_be_bytes());
    let malformed_templates = [
        {
            let mut children = BytesMut::new();
            children.extend_from_slice(&vendor);
            children.extend_from_slice(&vendor);
            children.extend_from_slice(&profile_id);
            encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &children)
        },
        {
            let mut children = BytesMut::new();
            children.extend_from_slice(&vendor);
            children.extend_from_slice(&profile_id);
            children.extend_from_slice(&profile_id);
            encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &children)
        },
        encode_raw_avp(
            apps::swm::AVP_QOS_PROFILE_TEMPLATE,
            true,
            &[
                encode_raw_avp(base::AVP_VENDOR_ID, true, &[0, 0, 0]).as_ref(),
                profile_id.as_ref(),
            ]
            .concat(),
        ),
        encode_raw_avp(
            apps::swm::AVP_QOS_PROFILE_TEMPLATE,
            false,
            &[vendor.as_ref(), profile_id.as_ref()].concat(),
        ),
        encode_raw_avp_with_header(
            AvpHeader::vendor(
                apps::swm::AVP_QOS_PROFILE_TEMPLATE,
                VendorId::new(9_999),
                true,
            ),
            &[vendor.as_ref(), profile_id.as_ref()].concat(),
        ),
        encode_raw_avp_with_header(
            AvpHeader::ietf(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true).with_flags(
                AvpFlags::from_bits(AvpFlags::MANDATORY | AvpFlags::PROTECTED),
            ),
            &[vendor.as_ref(), profile_id.as_ref()].concat(),
        ),
    ];
    for template in malformed_templates {
        let qos = encode_qos_capability_avp(true, &[template], &[]);
        parse_extra(&qos, DecodeContext::default())
            .expect_err("QoS-Profile-Template requires exact M/V/P flags and cardinality");
    }

    for invalid_vendor in [
        encode_raw_avp(base::AVP_VENDOR_ID, false, &0u32.to_be_bytes()),
        encode_raw_avp_with_header(
            AvpHeader::vendor(base::AVP_VENDOR_ID, VendorId::new(9_999), true),
            &0u32.to_be_bytes(),
        ),
        encode_raw_avp_with_header(
            AvpHeader::ietf(base::AVP_VENDOR_ID, true).with_flags(AvpFlags::from_bits(
                AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            )),
            &0u32.to_be_bytes(),
        ),
    ] {
        let template = encode_raw_avp(
            apps::swm::AVP_QOS_PROFILE_TEMPLATE,
            true,
            &[invalid_vendor.as_ref(), profile_id.as_ref()].concat(),
        );
        let qos = encode_qos_capability_avp(true, &[template], &[]);
        parse_extra(&qos, DecodeContext::default())
            .expect_err("Vendor-Id child requires exact M/V/P flags");
    }

    for invalid_profile_id in [
        encode_raw_avp(apps::swm::AVP_QOS_PROFILE_ID, false, &0u32.to_be_bytes()),
        encode_raw_avp_with_header(
            AvpHeader::vendor(apps::swm::AVP_QOS_PROFILE_ID, VendorId::new(9_999), true),
            &0u32.to_be_bytes(),
        ),
        encode_raw_avp_with_header(
            AvpHeader::ietf(apps::swm::AVP_QOS_PROFILE_ID, true).with_flags(AvpFlags::from_bits(
                AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            )),
            &0u32.to_be_bytes(),
        ),
    ] {
        let template = encode_raw_avp(
            apps::swm::AVP_QOS_PROFILE_TEMPLATE,
            true,
            &[vendor.as_ref(), invalid_profile_id.as_ref()].concat(),
        );
        let qos = encode_qos_capability_avp(true, &[template], &[]);
        parse_extra(&qos, DecodeContext::default())
            .expect_err("QoS-Profile-Id child requires exact M/V/P flags");
    }

    let bounded_profiles = (0..127)
        .map(|id| encode_qos_profile_template_avp(VendorId::new(0), id, &[]))
        .collect::<Vec<_>>();
    let overflow_extensions = [
        encode_raw_avp(AvpCode::new(900_010), false, &[]),
        encode_raw_avp(AvpCode::new(900_011), false, &[]),
    ];
    let excessive_total_children =
        encode_qos_capability_avp(true, &bounded_profiles, &overflow_extensions);
    parse_extra(
        &excessive_total_children,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect_err("QoS-Capability total grouped-child bound must include dropped extensions");

    let optional_profile_extension = encode_raw_avp(AvpCode::new(900_001), false, &[0xaa]);
    let optional_capability_extension = encode_raw_avp(AvpCode::new(900_002), false, &[0xbb]);
    let profile =
        encode_qos_profile_template_avp(VendorId::new(0), 0, &[optional_profile_extension]);
    let qos = encode_qos_capability_avp(true, &[profile], &[optional_capability_extension]);
    let preserve_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    let preserved = parse_extra(&qos, preserve_ctx).expect("optional extensions preserve");
    let preserved_qos = preserved.qos_capability.as_ref().expect("typed QoS");
    assert_eq!(preserved_qos.additional_avps().len(), 1);
    assert_eq!(preserved_qos.profiles()[0].additional_avps().len(), 1);
    let replay =
        apps::swm::build_swm_diameter_eap_request(&preserved, 1, 2, EncodeContext::default())
            .expect("preserved extensions replay");
    let replay_wire = encode_message(&replay);
    let replay_message = decode_message(&replay_wire);
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_request(&replay_message, preserve_ctx)
            .expect("replayed extensions parse"),
        preserved
    );

    let drop_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    let dropped = parse_extra(&qos, drop_ctx).expect("optional extensions drop");
    let dropped_qos = dropped.qos_capability.as_ref().expect("typed QoS");
    assert!(dropped_qos.additional_avps().is_empty());
    assert!(dropped_qos.profiles()[0].additional_avps().is_empty());
    parse_extra(&qos, DecodeContext::conservative())
        .expect_err("strict unknown policy rejects optional extensions");

    let mandatory_unknown = encode_raw_avp(AvpCode::new(900_003), true, &[0xcc]);
    let profile = encode_qos_profile_template_avp(VendorId::new(0), 0, &[]);
    let qos = encode_qos_capability_avp(true, &[profile], &[mandatory_unknown]);
    parse_extra(&qos, drop_ctx).expect_err("unknown mandatory extension always fails");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_mobility_supported_features_and_ue_ip_round_trip_with_exact_flags() {
    let second_list = SwmSupportedFeatureList::new(VendorId::new(55_555), 9, 0x0000_0005);
    let mut request = sample_swm_request();
    request.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
    request.supported_features = vec![
        SwmRequestedSupportedFeatures::swm_discovery(),
        SwmRequestedSupportedFeatures::required(second_list.clone()),
    ];
    request.ue_local_ip_address = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));

    let built = apps::swm::build_swm_diameter_eap_request(
        &request,
        0x1020_3040,
        0x5060_7080,
        EncodeContext::default(),
    )
    .expect("typed mobility DER build");
    let encoded = encode_message(&built);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::default(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("dictionary validates typed mobility DER");
    assert!(tail.is_empty());

    let avps = decoded
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("typed mobility AVPs");
    let mip6 = avps
        .iter()
        .find(|avp| avp.header.code == apps::swm::AVP_MIP6_FEATURE_VECTOR)
        .expect("MIP6-Feature-Vector");
    assert_eq!(mip6.header.vendor_id, None);
    assert!(mip6.header.flags.is_mandatory());
    assert!(!mip6.header.flags.is_protected());
    assert_eq!(
        mip6.value,
        &[0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    let supported = avps
        .iter()
        .filter(|avp| avp.header.code == apps::swm::AVP_SUPPORTED_FEATURES)
        .collect::<Vec<_>>();
    assert_eq!(supported.len(), 2);
    assert!(!supported[0].header.flags.is_mandatory());
    assert!(supported[1].header.flags.is_mandatory());

    let ue_ip = avps
        .iter()
        .find(|avp| avp.header.code == apps::swm::AVP_UE_LOCAL_IP_ADDRESS)
        .expect("UE-Local-IP-Address");
    assert_eq!(ue_ip.header.vendor_id, Some(apps::VENDOR_ID_3GPP));
    assert!(!ue_ip.header.flags.is_mandatory());
    assert!(!ue_ip.header.flags.is_protected());
    assert_eq!(ue_ip.value, &[0x00, 0x01, 198, 51, 100, 7]);

    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::default())
        .expect("typed mobility DER parse");
    assert_eq!(parsed, request);
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("198.51.100.7"));
    assert!(!debug.contains("18014398509481984"));

    let mut answer = sample_swm_answer();
    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::PMIP6_SUPPORTED | SwmMip6FeatureVector::GTPV2_SUPPORTED,
    ));
    answer.supported_features = vec![SwmSupportedFeatureList::swm(), second_list];
    let answer_built = apps::swm::build_swm_diameter_eap_answer_for(
        &request_envelope(&request, 0x1020_3040, 0x5060_7080),
        &answer,
        EncodeContext::default(),
    )
    .expect("GTPv2-only offer authorizes the collective NBM answer");
    let answer_encoded = encode_message(&answer_built);
    let answer_decoded = decode_message(&answer_encoded);
    let answer_avps = answer_decoded
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("typed mobility DEA AVPs");
    assert!(answer_avps
        .iter()
        .filter(|avp| avp.header.code == apps::swm::AVP_SUPPORTED_FEATURES)
        .all(|avp| !avp.header.flags.is_mandatory()));
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_answer(&answer_decoded, DecodeContext::default())
            .expect("typed mobility DEA parse"),
        answer
    );
    correlate_exchange(&request, &answer, 0x1020_3040, 0x5060_7080)
        .expect("collective NBM selection correlates to GTPv2-only offer");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_understood_m_bits_are_interoperable_and_encoding_is_canonical() {
    let mip6_m_clear = encode_raw_avp(
        apps::swm::AVP_MIP6_FEATURE_VECTOR,
        false,
        &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
    );
    let ue_ip_m_set = encode_raw_vendor_avp(
        apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
        apps::VENDOR_ID_3GPP,
        true,
        &[0x00, 0x01, 192, 0, 2, 10],
    );

    for child_mandatory in [false, true] {
        let mut children = BytesMut::new();
        children.extend_from_slice(&encode_raw_avp(
            base::AVP_VENDOR_ID,
            true,
            &apps::VENDOR_ID_3GPP.get().to_be_bytes(),
        ));
        children.extend_from_slice(&encode_raw_vendor_avp(
            apps::swm::AVP_FEATURE_LIST_ID,
            apps::VENDOR_ID_3GPP,
            child_mandatory,
            &apps::swm::SWM_FEATURE_LIST_ID.to_be_bytes(),
        ));
        children.extend_from_slice(&encode_raw_vendor_avp(
            apps::swm::AVP_FEATURE_LIST,
            apps::VENDOR_ID_3GPP,
            child_mandatory,
            &apps::swm::SWM_FEATURE_LIST.to_be_bytes(),
        ));
        let supported = encode_raw_vendor_avp(
            apps::swm::AVP_SUPPORTED_FEATURES,
            apps::VENDOR_ID_3GPP,
            false,
            &children,
        );
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[mip6_m_clear.clone(), ue_ip_m_set.clone(), supported],
        );
        let wire = encode_message(&raw);
        let (tail, dictionary_decoded) = Message::decode_with_dictionary(
            &wire,
            DecodeContext::default(),
            SWM_BASELINE_DICTIONARIES,
        )
        .expect("dictionary accepts understood M-bit variants");
        assert!(tail.is_empty());
        let parsed = apps::swm::parse_swm_diameter_eap_request(
            &dictionary_decoded,
            DecodeContext::default(),
        )
        .expect("typed parser accepts understood M-bit variants");
        assert_eq!(
            parsed.mip6_feature_vector,
            Some(SwmMip6FeatureVector::gtpv2_only())
        );
        assert_eq!(
            parsed.ue_local_ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(
            parsed.supported_features[0].requirement(),
            SwmSupportedFeaturesRequirement::Discovery
        );

        let canonical =
            apps::swm::build_swm_diameter_eap_request(&parsed, 1, 2, EncodeContext::default())
                .expect("canonical DER rebuild");
        let canonical_wire = encode_message(&canonical);
        let canonical_message = decode_message(&canonical_wire);
        let canonical_avps = canonical_message
            .avps(DecodeContext::default())
            .collect::<Result<Vec<_>, _>>()
            .expect("canonical DER AVPs");
        assert!(canonical_avps
            .iter()
            .find(|avp| avp.header.code == apps::swm::AVP_MIP6_FEATURE_VECTOR)
            .expect("canonical MIP6")
            .header
            .flags
            .is_mandatory());
        assert!(!canonical_avps
            .iter()
            .find(|avp| avp.header.code == apps::swm::AVP_UE_LOCAL_IP_ADDRESS)
            .expect("canonical UE IP")
            .header
            .flags
            .is_mandatory());
    }

    let raw_answer = build_raw_swm_dea_with_extras(&[mip6_m_clear]);
    let answer_wire = encode_message(&raw_answer);
    let (tail, answer_message) = Message::decode_with_dictionary(
        &answer_wire,
        DecodeContext::default(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("dictionary accepts M-clear MIP6 in DEA");
    assert!(tail.is_empty());
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_answer(&answer_message, DecodeContext::default())
            .expect("typed parser accepts M-clear MIP6 in DEA")
            .mip6_feature_vector,
        Some(SwmMip6FeatureVector::gtpv2_only())
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_mip6_feature_vector_rejects_malformed_and_uncorrelated_values() {
    let encode_with_header = |header: AvpHeader, value: &[u8]| {
        let mut encoded = BytesMut::new();
        RawAvp {
            header,
            value,
            padding: &[],
        }
        .encode(&mut encoded, EncodeContext::default())
        .expect("synthetic MIP6 AVP");
        encoded
    };
    let valid = encode_raw_avp(
        apps::swm::AVP_MIP6_FEATURE_VECTOR,
        true,
        &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
    );
    let vendor_collision = encode_raw_vendor_avp(
        apps::swm::AVP_MIP6_FEATURE_VECTOR,
        apps::VENDOR_ID_3GPP,
        false,
        &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
    );
    let invalid = [
        encode_with_header(
            AvpHeader::ietf(apps::swm::AVP_MIP6_FEATURE_VECTOR, true)
                .with_flags(AvpFlags::new(false, true, true)),
            &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
        ),
        encode_raw_avp(apps::swm::AVP_MIP6_FEATURE_VECTOR, true, &[0x00; 7]),
        encode_raw_avp(apps::swm::AVP_MIP6_FEATURE_VECTOR, true, &[0x00; 9]),
    ];
    for invalid_avp in invalid {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[invalid_avp],
        );
        let wire = encode_message(&raw);
        apps::swm::parse_swm_diameter_eap_request(&decode_message(&wire), DecodeContext::default())
            .expect_err("malformed MIP6-Feature-Vector must fail");
    }

    let collision = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        std::slice::from_ref(&vendor_collision),
    );
    let collision_wire = encode_message(&collision);
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&collision_wire),
            DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            },
        )
        .expect("M-clear numeric collision follows Drop policy")
        .mip6_feature_vector,
        None
    );
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&collision_wire),
        DecodeContext::conservative(),
    )
    .expect_err("strict unknown policy rejects a numeric collision");
    let critical_collision = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[encode_raw_vendor_avp(
            apps::swm::AVP_MIP6_FEATURE_VECTOR,
            apps::VENDOR_ID_3GPP,
            true,
            &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
        )],
    );
    let critical_collision_wire = encode_message(&critical_collision);
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&critical_collision_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect_err("M-set numeric collision remains critical");

    let duplicate = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[valid.clone(), valid],
    );
    let duplicate_wire = encode_message(&duplicate);
    assert!(matches!(
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&duplicate_wire),
            DecodeContext::default(),
        )
        .expect_err("duplicate MIP6 vector")
        .code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));

    let mut invalid_request = sample_swm_request();
    invalid_request.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::ASSIGN_LOCAL_IP,
    ));
    apps::swm::build_swm_diameter_eap_request(&invalid_request, 1, 2, EncodeContext::default())
        .expect_err("DER cannot advertise answer-only ASSIGN_LOCAL_IP");

    let request = sample_swm_request();
    let mut answer = sample_swm_answer();
    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
    assert!(matches!(
        correlate_exchange(&request, &answer, 1, 2),
        Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch)
    ));

    let mut request = sample_swm_request();
    request.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    assert!(matches!(
        correlate_exchange(&request, &answer, 1, 2),
        Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch)
    ));

    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::LOCAL_HOME_AGENT_ASSIGNMENT,
    ));
    assert!(matches!(
        correlate_exchange(&request, &answer, 1, 2),
        Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch)
    ));

    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::ASSIGN_LOCAL_IP | SwmMip6FeatureVector::GTPV2_SUPPORTED,
    ));
    apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect_err("ASSIGN_LOCAL_IP and NBM are mutually exclusive");
    let conflicting_answer = build_raw_swm_dea_with_extras(&[encode_raw_avp(
        apps::swm::AVP_MIP6_FEATURE_VECTOR,
        true,
        &(SwmMip6FeatureVector::ASSIGN_LOCAL_IP | SwmMip6FeatureVector::GTPV2_SUPPORTED)
            .to_be_bytes(),
    )]);
    let conflicting_wire = encode_message(&conflicting_answer);
    apps::swm::parse_swm_diameter_eap_answer(
        &decode_message(&conflicting_wire),
        DecodeContext::default(),
    )
    .expect_err("received ASSIGN_LOCAL_IP and NBM combination fails");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_mip6_authorization_is_collective_success_and_request_conditioned() {
    let mut offered_request = sample_swm_request();
    offered_request.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());

    let success_without_vector = sample_swm_answer();
    assert!(matches!(
        correlate_exchange(&offered_request, &success_without_vector, 1, 2),
        Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch)
    ));

    let mut success_with_vector = sample_swm_answer();
    success_with_vector.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
    correlate_exchange(&offered_request, &success_with_vector, 1, 2)
        .expect("exact success returns authorization for an offered vector");

    let mut pmip_only_request = sample_swm_request();
    pmip_only_request.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::PMIP6_SUPPORTED,
    ));
    correlate_exchange(&pmip_only_request, &success_with_vector, 1, 2)
        .expect("a PMIPv6 DER offer permits the collective GTPv2 NBM selection");

    let mut pmip_only_answer = sample_swm_answer();
    pmip_only_answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::PMIP6_SUPPORTED,
    ));
    correlate_exchange(&offered_request, &pmip_only_answer, 1, 2)
        .expect("a GTPv2 DER offer permits the collective PMIPv6 NBM selection");

    let mut unoffered_request = sample_swm_request();
    unoffered_request.mip6_feature_vector = None;
    assert!(matches!(
        correlate_exchange(&unoffered_request, &success_with_vector, 1, 2),
        Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch)
    ));

    let mut multi_round = sample_swm_answer();
    multi_round.result = SwmDiameterResult::Base(1001);
    multi_round.eap_payload = Some(vec![0x01, 0x18, 0x00, 0x05, 0x01].into());
    multi_round.eap_master_session_key = None;
    correlate_exchange(&offered_request, &multi_round, 1, 2)
        .expect("non-success response omits authorization while EAP continues");

    multi_round.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
    apps::swm::build_swm_diameter_eap_answer(&multi_round, 1, 2, EncodeContext::default())
        .expect_err("multi-round answer cannot carry mobility authorization");

    let raw_multi_round = build_raw_swm_dea_with_result_and_extras(
        1001,
        &[encode_raw_avp(
            apps::swm::AVP_MIP6_FEATURE_VECTOR,
            true,
            &SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes(),
        )],
    );
    let raw_multi_round_wire = encode_message(&raw_multi_round);
    apps::swm::parse_swm_diameter_eap_answer(
        &decode_message(&raw_multi_round_wire),
        DecodeContext::default(),
    )
    .expect_err("received non-success answer cannot carry mobility authorization");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_supported_features_wire_fixture_enforces_group_semantics() {
    let discovery = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[],
    );
    let raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        std::slice::from_ref(&discovery),
    );
    let wire = encode_message(&raw);
    let parsed =
        apps::swm::parse_swm_diameter_eap_request(&decode_message(&wire), DecodeContext::default())
            .expect("independent SWm Supported-Features request fixture");
    assert_eq!(
        parsed.supported_features,
        vec![SwmRequestedSupportedFeatures::swm_discovery()]
    );

    let answer = build_raw_swm_dea_with_extras(std::slice::from_ref(&discovery));
    let answer_wire = encode_message(&answer);
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_answer(
            &decode_message(&answer_wire),
            DecodeContext::default(),
        )
        .expect("independent SWm Supported-Features answer fixture")
        .supported_features,
        vec![SwmSupportedFeatureList::swm()]
    );

    let invalid_discovery = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        1,
        &[],
    );
    let mandatory_answer = encode_supported_features_avp(
        true,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[],
    );
    let wrong_child_vendor = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[encode_raw_vendor_avp(
            apps::swm::AVP_FEATURE_LIST_ID,
            VendorId::new(9_999),
            false,
            &1u32.to_be_bytes(),
        )],
    );
    let wrong_child_v = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[encode_raw_avp(
            apps::swm::AVP_FEATURE_LIST_ID,
            false,
            &1u32.to_be_bytes(),
        )],
    );
    let mut protected_child = BytesMut::new();
    RawAvp {
        header: AvpHeader::vendor(apps::swm::AVP_FEATURE_LIST, apps::VENDOR_ID_3GPP, false)
            .with_flags(AvpFlags::new(true, false, true)),
        value: &0u32.to_be_bytes(),
        padding: &[],
    }
    .encode(&mut protected_child, EncodeContext::default())
    .expect("protected Feature-List fixture");
    let wrong_child_p = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[protected_child],
    );
    let wrong_child_length = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[encode_raw_vendor_avp(
            apps::swm::AVP_FEATURE_LIST,
            apps::VENDOR_ID_3GPP,
            false,
            &[0, 0, 0],
        )],
    );
    let wrong_list_id_length = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[encode_raw_vendor_avp(
            apps::swm::AVP_FEATURE_LIST_ID,
            apps::VENDOR_ID_3GPP,
            false,
            &[0, 0, 0],
        )],
    );
    let wrong_vendor_id_length = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[encode_raw_avp(base::AVP_VENDOR_ID, true, &[0, 0, 0])],
    );
    let mut missing_children = BytesMut::new();
    missing_children.extend_from_slice(&encode_raw_avp(
        base::AVP_VENDOR_ID,
        true,
        &apps::VENDOR_ID_3GPP.get().to_be_bytes(),
    ));
    let missing_feature_list = encode_raw_vendor_avp(
        apps::swm::AVP_SUPPORTED_FEATURES,
        apps::VENDOR_ID_3GPP,
        false,
        &missing_children,
    );

    for (index, invalid_group) in [
        invalid_discovery,
        wrong_child_p,
        wrong_child_length,
        wrong_list_id_length,
        wrong_vendor_id_length,
        missing_feature_list,
    ]
    .into_iter()
    .enumerate()
    {
        let invalid = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[invalid_group],
        );
        let invalid_wire = encode_message(&invalid);
        let error = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&invalid_wire),
            DecodeContext::default(),
        )
        .expect_err("malformed Supported-Features request must fail");
        if index == 2 || index == 3 {
            let spec_ref = error
                .spec_ref()
                .expect("Feature-List width error must cite its defining specification");
            assert_eq!(spec_ref.doc(), "TS29229");
            assert_eq!(
                spec_ref.section(),
                if index == 2 { "6.3.31" } else { "6.3.30" }
            );
        }
    }

    for collision in [wrong_child_vendor, wrong_child_v] {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            std::slice::from_ref(&collision),
        );
        let wire = encode_message(&raw);
        assert_eq!(
            apps::swm::parse_swm_diameter_eap_request(
                &decode_message(&wire),
                DecodeContext::default(),
            )
            .expect("M-clear child numeric collision is preserved")
            .supported_features[0]
                .features()
                .additional_avps()
                .len(),
            1
        );
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("strict unknown policy rejects child numeric collision");
    }

    let invalid_answer = build_raw_swm_dea_with_extras(&[mandatory_answer]);
    let invalid_answer_wire = encode_message(&invalid_answer);
    apps::swm::parse_swm_diameter_eap_answer(
        &decode_message(&invalid_answer_wire),
        DecodeContext::default(),
    )
    .expect_err("Supported-Features answer must clear M");

    let duplicate = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[discovery.clone(), discovery.clone()],
    );
    let duplicate_wire = encode_message(&duplicate);
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&duplicate_wire),
        DecodeContext::default(),
    )
    .expect_err("duplicate Supported-Features identity must fail");

    let duplicate_child_groups = [
        encode_supported_features_avp(
            false,
            apps::VENDOR_ID_3GPP,
            apps::swm::SWM_FEATURE_LIST_ID,
            0,
            &[encode_raw_avp(
                base::AVP_VENDOR_ID,
                true,
                &apps::VENDOR_ID_3GPP.get().to_be_bytes(),
            )],
        ),
        encode_supported_features_avp(
            false,
            apps::VENDOR_ID_3GPP,
            apps::swm::SWM_FEATURE_LIST_ID,
            0,
            &[encode_raw_vendor_avp(
                apps::swm::AVP_FEATURE_LIST_ID,
                apps::VENDOR_ID_3GPP,
                false,
                &apps::swm::SWM_FEATURE_LIST_ID.to_be_bytes(),
            )],
        ),
        encode_supported_features_avp(
            false,
            apps::VENDOR_ID_3GPP,
            apps::swm::SWM_FEATURE_LIST_ID,
            0,
            &[encode_raw_vendor_avp(
                apps::swm::AVP_FEATURE_LIST,
                apps::VENDOR_ID_3GPP,
                false,
                &apps::swm::SWM_FEATURE_LIST.to_be_bytes(),
            )],
        ),
    ];
    for (index, duplicate_children) in duplicate_child_groups.into_iter().enumerate() {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[duplicate_children],
        );
        let wire = encode_message(&raw);
        let error = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::default(),
        )
        .expect_err("each required Supported-Features child is singleton");
        assert!(matches!(
            error.code(),
            opc_protocol::DecodeErrorCode::DuplicateIe
        ));
        let spec_ref = error
            .spec_ref()
            .expect("Supported-Features duplicate must cite its defining specification");
        assert_eq!(spec_ref.doc(), "TS29229");
        assert_eq!(spec_ref.section(), ["6.3.29", "6.3.30", "6.3.31"][index]);
    }

    let (_, discovery_avp) = RawAvp::decode(&discovery, DecodeContext::default())
        .expect("synthetic Supported-Features fixture");
    let wrong_outer_vendor = encode_raw_vendor_avp(
        apps::swm::AVP_SUPPORTED_FEATURES,
        VendorId::new(9_999),
        false,
        discovery_avp.value,
    );
    let wrong_outer_v = encode_raw_avp(
        apps::swm::AVP_SUPPORTED_FEATURES,
        false,
        discovery_avp.value,
    );
    for collision in [wrong_outer_vendor, wrong_outer_v] {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            std::slice::from_ref(&collision),
        );
        let wire = encode_message(&raw);
        assert!(apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            },
        )
        .expect("M-clear outer numeric collision follows Drop policy")
        .supported_features
        .is_empty());
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("strict unknown policy rejects outer numeric collision");
    }

    let optional_unknown = encode_raw_vendor_avp(
        AvpCode::new(65_000),
        apps::VENDOR_ID_3GPP,
        false,
        b"synthetic-extension",
    );
    let with_optional_unknown = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        std::slice::from_ref(&optional_unknown),
    );
    let unknown_raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        std::slice::from_ref(&with_optional_unknown),
    );
    let unknown_wire = encode_message(&unknown_raw);
    let preserved = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&unknown_wire),
        DecodeContext::default(),
    )
    .expect("Preserve retains optional Supported-Features extension");
    assert_eq!(
        preserved.supported_features[0]
            .features()
            .additional_avps()
            .len(),
        1
    );
    assert!(!format!("{preserved:?}").contains("synthetic-extension"));
    let preserved_rebuild =
        apps::swm::build_swm_diameter_eap_request(&preserved, 1, 2, EncodeContext::default())
            .expect("preserved Supported-Features rebuild");
    let preserved_wire = encode_message(&preserved_rebuild);
    let preserved_message = decode_message(&preserved_wire);
    let preserved_group = preserved_message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("preserved DER AVP"))
        .find(|avp| {
            avp.header.key()
                == AvpKey::vendor(apps::swm::AVP_SUPPORTED_FEATURES, apps::VENDOR_ID_3GPP)
        })
        .expect("preserved Supported-Features group");
    let mut preserved_group_wire = BytesMut::new();
    preserved_group
        .encode(&mut preserved_group_wire, EncodeContext::default())
        .expect("preserved group encoding");
    assert_eq!(preserved_group_wire, with_optional_unknown);

    let dropped = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&unknown_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect("bounded optional Supported-Features extension is ignored by policy");
    assert!(dropped.supported_features[0]
        .features()
        .additional_avps()
        .is_empty());
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&unknown_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        },
    )
    .expect_err("Reject policy refuses optional unknown Supported-Features child");

    let mandatory_unknown = encode_raw_vendor_avp(
        AvpCode::new(65_000),
        apps::VENDOR_ID_3GPP,
        true,
        b"synthetic-extension",
    );
    let with_mandatory_unknown = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[mandatory_unknown],
    );
    let unknown_raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[with_mandatory_unknown],
    );
    let unknown_wire = encode_message(&unknown_raw);
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&unknown_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect_err("mandatory unknown Supported-Features child fails closed");

    let duplicate_unknown = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[optional_unknown.clone(), optional_unknown.clone()],
    );
    let duplicate_unknown_raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[duplicate_unknown],
    );
    let duplicate_unknown_wire = encode_message(&duplicate_unknown_raw);
    for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&duplicate_unknown_wire),
            DecodeContext {
                unknown_ie_policy,
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                ..DecodeContext::default()
            },
        )
        .expect_err("duplicate unknown child key is rejected before preserve/drop policy");
    }

    let other_vendor_unknown = encode_raw_vendor_avp(
        AvpCode::new(65_000),
        VendorId::new(77_777),
        false,
        b"synthetic-extension-2",
    );
    let distinct_vendor_keys = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &[optional_unknown, other_vendor_unknown],
    );
    let distinct_vendor_raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[distinct_vendor_keys],
    );
    let distinct_vendor_wire = encode_message(&distinct_vendor_raw);
    for (unknown_ie_policy, retained) in
        [(UnknownIePolicy::Preserve, 2), (UnknownIePolicy::Drop, 0)]
    {
        assert_eq!(
            apps::swm::parse_swm_diameter_eap_request(
                &decode_message(&distinct_vendor_wire),
                DecodeContext {
                    unknown_ie_policy,
                    duplicate_ie_policy: DuplicateIePolicy::Reject,
                    ..DecodeContext::default()
                },
            )
            .expect("same numeric child code under distinct vendors is not duplicate")
            .supported_features[0]
                .features()
                .additional_avps()
                .len(),
            retained
        );
    }

    let many_unknown = (0..11)
        .map(|index| {
            encode_raw_vendor_avp(
                AvpCode::new(64_000 + index),
                apps::VENDOR_ID_3GPP,
                false,
                &[],
            )
        })
        .collect::<Vec<_>>();
    let oversized_group = encode_supported_features_avp(
        false,
        apps::VENDOR_ID_3GPP,
        apps::swm::SWM_FEATURE_LIST_ID,
        0,
        &many_unknown,
    );
    let oversized = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[oversized_group],
    );
    let oversized_wire = encode_message(&oversized);
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&oversized_wire),
        DecodeContext {
            max_ies: 10,
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect_err("Supported-Features child count is bounded");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_ue_local_ip_fixture_enforces_address_vendor_and_cardinality() {
    for address in [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V6("2001:db8::5".parse().expect("synthetic IPv6")),
    ] {
        let mut request = sample_swm_request();
        request.ue_local_ip_address = Some(address);
        let built =
            apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
                .expect("UE local address DER build");
        let wire = encode_message(&built);
        assert_eq!(
            apps::swm::parse_swm_diameter_eap_request(
                &decode_message(&wire),
                DecodeContext::default(),
            )
            .expect("UE local address DER parse")
            .ue_local_ip_address,
            Some(address)
        );
    }

    let valid = encode_raw_vendor_avp(
        apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
        apps::VENDOR_ID_3GPP,
        false,
        &[0x00, 0x01, 192, 0, 2, 1],
    );
    let vendor_collision = encode_raw_vendor_avp(
        apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
        VendorId::new(9_999),
        false,
        &[0x00, 0x01, 192, 0, 2, 1],
    );
    let mut protected = BytesMut::new();
    RawAvp {
        header: AvpHeader::vendor(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
        )
        .with_flags(AvpFlags::new(true, false, true)),
        value: &[0x00, 0x01, 192, 0, 2, 1],
        padding: &[],
    }
    .encode(&mut protected, EncodeContext::default())
    .expect("protected UE IP fixture");
    let invalid = [
        protected,
        encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
            &[0x00, 0x01, 192, 0, 2],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
            &[0x00, 0x01, 192, 0, 2, 1, 9],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
            &[0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
            &[
                0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            apps::VENDOR_ID_3GPP,
            false,
            &[0x00, 0x03, 192, 0, 2, 1],
        ),
    ];
    for (index, invalid_avp) in invalid.into_iter().enumerate() {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[invalid_avp],
        );
        let wire = encode_message(&raw);
        let error = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::default(),
        )
        .expect_err("invalid UE-Local-IP-Address must fail");
        if index > 0 {
            let spec_ref = error
                .spec_ref()
                .expect("UE address error must cite its defining specification");
            assert_eq!(spec_ref.doc(), "TS29212");
            assert_eq!(spec_ref.section(), "5.3.96");
        }
    }
    let collision = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        std::slice::from_ref(&vendor_collision),
    );
    let collision_wire = encode_message(&collision);
    assert_eq!(
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&collision_wire),
            DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            },
        )
        .expect("M-clear UE-IP numeric collision follows Drop policy")
        .ue_local_ip_address,
        None
    );
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&collision_wire),
        DecodeContext::conservative(),
    )
    .expect_err("strict unknown policy rejects UE-IP numeric collision");
    let critical_collision = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[encode_raw_vendor_avp(
            apps::swm::AVP_UE_LOCAL_IP_ADDRESS,
            VendorId::new(9_999),
            true,
            &[0x00, 0x01, 192, 0, 2, 1],
        )],
    );
    let critical_collision_wire = encode_message(&critical_collision);
    apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&critical_collision_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect_err("M-set UE-IP numeric collision remains critical");
    let duplicate = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[valid.clone(), valid],
    );
    let duplicate_wire = encode_message(&duplicate);
    let duplicate_error = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&duplicate_wire),
        DecodeContext::default(),
    )
    .expect_err("duplicate UE-Local-IP-Address");
    assert!(matches!(
        duplicate_error.code(),
        opc_protocol::DecodeErrorCode::DuplicateIe
    ));
    let spec_ref = duplicate_error
        .spec_ref()
        .expect("UE duplicate error must cite its defining specification");
    assert_eq!(spec_ref.doc(), "TS29212");
    assert_eq!(spec_ref.section(), "5.3.96");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_parser_enforces_flags_cardinality_and_emergency_exclusion() {
    const APN: &[u8] = b"ims";
    let rat_type = encode_raw_vendor_avp(
        apps::swm::AVP_RAT_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &1u32.to_be_bytes(),
    );
    let service_selection = encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, true, APN);

    let raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[rat_type.clone(), service_selection.clone()],
    );
    let wire = encode_message(&raw);
    let parsed = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&wire),
        DecodeContext::conservative(),
    )
    .expect("independently encoded access context parses");
    assert_eq!(parsed.rat_type, Some(SwmRatType::Virtual));
    assert_eq!(
        parsed
            .service_selection
            .as_ref()
            .map(|value| value.as_ref().as_str()),
        Some("ims")
    );

    for extras in [
        vec![rat_type.clone(), rat_type],
        vec![service_selection.clone(), service_selection.clone()],
    ] {
        let duplicate = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &extras,
        );
        let duplicate_wire = encode_message(&duplicate);
        let error = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&duplicate_wire),
            DecodeContext::conservative(),
        )
        .expect_err("duplicate access context must fail");
        assert!(matches!(
            error.code(),
            opc_protocol::DecodeErrorCode::DuplicateIe
        ));
    }

    let wrong_flags = [
        encode_raw_vendor_avp(
            apps::swm::AVP_RAT_TYPE,
            apps::VENDOR_ID_3GPP,
            false,
            &1u32.to_be_bytes(),
        ),
        encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, false, APN),
    ];
    for extra in wrong_flags {
        let invalid = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[extra],
        );
        let invalid_wire = encode_message(&invalid);
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&invalid_wire),
            DecodeContext::conservative(),
        )
        .expect_err("incorrect access-context flags must fail");
    }

    let emergency = encode_raw_vendor_avp(
        apps::swm::AVP_EMERGENCY_SERVICES,
        apps::VENDOR_ID_3GPP,
        false,
        &1u32.to_be_bytes(),
    );
    let invalid = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[service_selection, emergency],
    );
    let invalid_wire = encode_message(&invalid);
    let error = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&invalid_wire),
        DecodeContext::conservative(),
    )
    .expect_err("emergency DER with Service-Selection must fail");
    assert!(!format!("{error:?}").contains("ims"));

    let mut request = sample_swm_request();
    request.service_selection = Some("ims".into());
    request.emergency_services = Some(SwmEmergencyServices::emergency_indication());
    apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
        .expect_err("builder must reject emergency Service-Selection");
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_access_context_rejects_wrong_vendor_flags_and_width() {
    let encode_with_header = |header: AvpHeader, value: &[u8]| {
        let avp = RawAvp {
            header,
            value,
            padding: &[],
        };
        let mut encoded = BytesMut::new();
        avp.encode(&mut encoded, EncodeContext::default())
            .expect("raw access-context AVP");
        encoded
    };

    let invalid_avps = [
        encode_raw_vendor_avp(
            apps::swm::AVP_RAT_TYPE,
            VendorId::new(9_999),
            true,
            &0u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_SERVICE_SELECTION,
            apps::VENDOR_ID_3GPP,
            true,
            b"ims.example",
        ),
        encode_with_header(
            AvpHeader::vendor(apps::swm::AVP_RAT_TYPE, apps::VENDOR_ID_3GPP, true)
                .with_flags(AvpFlags::new(true, true, true)),
            &0u32.to_be_bytes(),
        ),
        encode_with_header(
            AvpHeader::ietf(apps::swm::AVP_SERVICE_SELECTION, true)
                .with_flags(AvpFlags::new(false, true, true)),
            b"ims.example",
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_RAT_TYPE,
            apps::VENDOR_ID_3GPP,
            true,
            &[0, 0, 0],
        ),
        encode_raw_vendor_avp(
            apps::swm::AVP_RAT_TYPE,
            apps::VENDOR_ID_3GPP,
            true,
            &[0, 0, 0, 0, 0],
        ),
    ];

    for invalid_avp in invalid_avps {
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[invalid_avp],
        );
        let wire = encode_message(&raw);
        apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("invalid access-context encoding must fail closed");
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rat_type_preserves_unknown_values() {
    let rat_type = encode_raw_vendor_avp(
        apps::swm::AVP_RAT_TYPE,
        apps::VENDOR_ID_3GPP,
        true,
        &42u32.to_be_bytes(),
    );
    let raw = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        3,
        &[0x02, 0x17, 0x00, 0x04],
        &[rat_type],
    );
    let wire = encode_message(&raw);
    let parsed = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&wire),
        DecodeContext::conservative(),
    )
    .expect("future RAT-Type values remain forward compatible");
    assert_eq!(parsed.rat_type, Some(SwmRatType::Other(42)));
    let rebuilt =
        apps::swm::build_swm_diameter_eap_request(&parsed, 1, 2, EncodeContext::default())
            .expect("a genuinely unknown RAT-Type remains originatable");
    let reparsed = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&encode_message(&rebuilt)),
        DecodeContext::conservative(),
    )
    .expect("a genuinely unknown RAT-Type remains stable");
    assert_eq!(reparsed.rat_type, Some(SwmRatType::Other(42)));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_rat_type_aliases_parse_canonically_and_cannot_be_originated() {
    for (wire_value, canonical) in [(0_u32, SwmRatType::Wlan), (1, SwmRatType::Virtual)] {
        let rat_type = encode_raw_vendor_avp(
            apps::swm::AVP_RAT_TYPE,
            apps::VENDOR_ID_3GPP,
            true,
            &wire_value.to_be_bytes(),
        );
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[rat_type],
        );
        let parsed = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&encode_message(&raw)),
            DecodeContext::conservative(),
        )
        .expect("assigned RAT-Type values parse through their canonical variants");
        assert_eq!(parsed.rat_type, Some(canonical));

        let mut request = sample_swm_request();
        request.rat_type = Some(SwmRatType::Other(wire_value));
        apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
            .expect_err("typed aliases of assigned RAT-Type values must not originate");
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_service_selection_enforces_apn_label_grammar() {
    let overlong_label = vec![b'a'; 64];
    let overlong_name = [
        vec![b'a'; 63],
        vec![b'.'],
        vec![b'b'; 63],
        vec![b'.'],
        vec![b'c'; 63],
        vec![b'.'],
        vec![b'd'; 63],
    ]
    .concat();
    let invalid_values = [
        Vec::new(),
        b"ims..example".to_vec(),
        b".ims".to_vec(),
        b"ims.".to_vec(),
        b"-ims.example".to_vec(),
        b"ims-.example".to_vec(),
        b"ims_example".to_vec(),
        "ims.\u{00e9}xample".as_bytes().to_vec(),
        vec![0xff],
        overlong_label,
        overlong_name,
    ];

    for invalid_value in invalid_values {
        let service_selection =
            encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, true, &invalid_value);
        let raw = build_raw_swm_der_with_extras(
            Some(apps::swm::APPLICATION_ID.get()),
            3,
            &[0x02, 0x17, 0x00, 0x04],
            &[service_selection],
        );
        let wire = encode_message(&raw);
        let error = apps::swm::parse_swm_diameter_eap_request(
            &decode_message(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("malformed Service-Selection must fail closed");
        assert!(!format!("{error:?}").contains("ims..example"));
    }

    for invalid_value in [
        "",
        "ims..example",
        "-ims.example",
        "ims_example",
        "ims.\u{00e9}xample",
    ] {
        let mut request = sample_swm_request();
        request.service_selection = Some(invalid_value.to_owned().into());
        let error =
            apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
                .expect_err("builder must reject malformed Service-Selection");
        if !invalid_value.is_empty() {
            assert!(!format!("{error:?}").contains(invalid_value));
        }
    }
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
        subscriber_authorization: Default::default(),
        mip6_feature_vector: None,
        supported_features: vec![],
        oc_supported_features: None,
        oc_olr: None,
        load_reports: vec![],
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: vec![],
        mobile_node_identifier: None,
        session_timeout: None,
        multi_round_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: None,
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: None,
        extensions: Default::default(),
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
fn swm_authorization_outcome_rejects_terminal_eap_failure() {
    let mut answer = sample_swm_answer();
    answer.result = SwmDiameterResult::Base(4001);
    answer.eap_payload = Some(vec![0x04, 0x2a, 0x00, 0x04].into());
    answer.eap_master_session_key = None;

    let built = apps::swm::build_swm_diameter_eap_answer(
        &answer,
        0x4410_0001,
        0x4410_0002,
        EncodeContext::default(),
    )
    .expect("synthetic authentication-rejected DEA");
    let encoded = encode_message(&built);
    let decoded = decode_message(&encoded);
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&decoded, DecodeContext::conservative())
        .expect("typed authentication-rejected DEA");

    assert_eq!(
        parsed.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );
    let diagnostic = format!("{parsed:?}");
    assert!(diagnostic.contains("eap_payload: Some(REDACTED)"));
    assert!(!diagnostic.contains("[4, 42, 0, 4]"));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_authorization_outcome_requires_valid_request_for_multi_round() {
    const MULTI_ROUND_AUTH: u32 = 1001;
    const EAP_REQUEST: &[u8] = &[0x01, 0x2a, 0x00, 0x05, 0x01];

    let mut answer = sample_swm_answer();
    answer.result = SwmDiameterResult::Base(MULTI_ROUND_AUTH);
    answer.eap_payload = Some(EAP_REQUEST.to_vec().into());
    answer.eap_master_session_key = None;
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::EapInProgress
    );

    answer.eap_payload = None;
    answer.eap_reissued_payload = Some(EAP_REQUEST.to_vec().into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::EapInProgress
    );

    let invalid_packets: &[&[u8]] = &[
        &[0x02, 0x2a, 0x00, 0x05, 0x01],
        &[0x03, 0x2a, 0x00, 0x04],
        &[0x04, 0x2a, 0x00, 0x04],
        &[0x05, 0x2a, 0x00, 0x05, 0x01],
        &[0x01, 0x2a, 0x00],
        &[0x01, 0x2a, 0x00, 0x04],
        &[0x01, 0x2a, 0x00, 0x06, 0x01],
        &[0x03, 0x2a, 0x00, 0x05, 0x00],
        &[0x04, 0x2a, 0x00, 0x05, 0x00],
    ];
    for invalid_packet in invalid_packets {
        answer.eap_payload = Some(invalid_packet.to_vec().into());
        answer.eap_reissued_payload = None;
        assert_eq!(
            answer.authorization_outcome(),
            SwmAuthorizationOutcome::NotAuthorized
        );
    }

    answer.eap_payload = Some(EAP_REQUEST.to_vec().into());
    answer.eap_reissued_payload = Some(EAP_REQUEST.to_vec().into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );

    answer.eap_reissued_payload = None;
    answer.eap_master_session_key = Some(vec![0xaa; 32].into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );

    answer.eap_master_session_key = Some(Vec::new().into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_authorization_outcome_requires_consistent_success_material() {
    let mut answer = sample_swm_answer();
    answer.eap_master_session_key = None;
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );

    answer.eap_master_session_key = Some(vec![0xaa; 32].into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::MskBearingSuccess
    );

    answer.eap_payload = None;
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::MskBearingSuccess
    );

    for contradictory_packet in [
        vec![0x01, 0x2a, 0x00, 0x05, 0x01],
        vec![0x04, 0x2a, 0x00, 0x04],
        vec![0x03, 0x2a, 0x00, 0x05, 0x00],
    ] {
        answer.eap_payload = Some(contradictory_packet.into());
        assert_eq!(
            answer.authorization_outcome(),
            SwmAuthorizationOutcome::NotAuthorized
        );
    }

    answer.eap_payload = Some(vec![0x03, 0x2a, 0x00, 0x04].into());
    answer.eap_reissued_payload = Some(vec![0x01, 0x2a, 0x00, 0x05, 0x01].into());
    assert_eq!(
        answer.authorization_outcome(),
        SwmAuthorizationOutcome::NotAuthorized
    );
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
        rat_type: None,
        service_selection: None,
        mip6_feature_vector: None,
        qos_capability: None,
        visited_network_identifier: None,
        aaa_failure_indication: None,
        supported_features: vec![],
        ue_local_ip_address: None,
        oc_supported_features: None,
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: vec![0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03].into(),
        emergency_services: None,
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: vec![b"opaque-state".to_vec()],
        route_records: Vec::new(),
        extensions: Default::default(),
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
        subscriber_authorization: Default::default(),
        mip6_feature_vector: None,
        supported_features: vec![],
        oc_supported_features: None,
        oc_olr: None,
        load_reports: vec![],
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: vec![],
        mobile_node_identifier: None,
        session_timeout: None,
        multi_round_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(vec![0x03, 0x18, 0x00, 0x04].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: Some(vec![0xAA; 32].into()),
        extensions: Default::default(),
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
        service_selection: "internet".into(),
        pdn_type: PdnType::Ipv4v6,
        eps_subscribed_qos_profile: Some(EpsSubscribedQosProfile {
            qos_class_identifier: SwmQosClassIdentifier::new(9).expect("standard QCI"),
            allocation_retention_priority: AllocationRetentionPriority {
                priority_level: SwmPriorityLevel::new(15).expect("valid priority"),
                pre_emption_capability: Some(SwmPreemptionCapability::Disabled),
                pre_emption_vulnerability: Some(SwmPreemptionVulnerability::Enabled),
            },
        }),
        ambr: Some(Ambr::new(50_000_000, 150_000_000).expect("valid AMBR")),
    }
}

#[cfg(feature = "app-swm")]
fn sample_ims_apn_configuration() -> ApnConfiguration {
    ApnConfiguration {
        context_identifier: 8,
        service_selection: "ims".into(),
        pdn_type: PdnType::Ipv6,
        eps_subscribed_qos_profile: None,
        ambr: None,
    }
}

#[cfg(feature = "app-rf")]
fn encode_raw_avp(code: AvpCode, mandatory: bool, value: &[u8]) -> BytesMut {
    encode_raw_avp_with_header(AvpHeader::ietf(code, mandatory), value)
}

#[cfg(feature = "app-rf")]
fn encode_raw_avp_with_header(header: AvpHeader, value: &[u8]) -> BytesMut {
    let avp = RawAvp {
        header,
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
fn encode_supported_features_avp(
    mandatory: bool,
    vendor_id: VendorId,
    feature_list_id: u32,
    feature_list: u32,
    extra_children: &[BytesMut],
) -> BytesMut {
    let mut children = BytesMut::new();
    children.extend_from_slice(&encode_raw_avp(
        base::AVP_VENDOR_ID,
        true,
        &vendor_id.get().to_be_bytes(),
    ));
    children.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_FEATURE_LIST_ID,
        apps::VENDOR_ID_3GPP,
        false,
        &feature_list_id.to_be_bytes(),
    ));
    children.extend_from_slice(&encode_raw_vendor_avp(
        apps::swm::AVP_FEATURE_LIST,
        apps::VENDOR_ID_3GPP,
        false,
        &feature_list.to_be_bytes(),
    ));
    for child in extra_children {
        children.extend_from_slice(child);
    }
    encode_raw_vendor_avp(
        apps::swm::AVP_SUPPORTED_FEATURES,
        apps::VENDOR_ID_3GPP,
        mandatory,
        &children,
    )
}

#[cfg(feature = "app-swm")]
fn encode_qos_profile_template_avp(
    vendor_id: VendorId,
    profile_id: u32,
    extra_children: &[BytesMut],
) -> BytesMut {
    let mut children = BytesMut::new();
    children.extend_from_slice(&encode_raw_avp(
        base::AVP_VENDOR_ID,
        true,
        &vendor_id.get().to_be_bytes(),
    ));
    children.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_QOS_PROFILE_ID,
        true,
        &profile_id.to_be_bytes(),
    ));
    for child in extra_children {
        children.extend_from_slice(child);
    }
    encode_raw_avp(apps::swm::AVP_QOS_PROFILE_TEMPLATE, true, &children)
}

#[cfg(feature = "app-swm")]
fn encode_qos_capability_avp(
    mandatory: bool,
    profiles: &[BytesMut],
    extra_children: &[BytesMut],
) -> BytesMut {
    let mut children = BytesMut::new();
    for profile in profiles {
        children.extend_from_slice(profile);
    }
    for child in extra_children {
        children.extend_from_slice(child);
    }
    encode_raw_avp(apps::swm::AVP_QOS_CAPABILITY, mandatory, &children)
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
fn rf_grouped_subscription_id_preserves_established_child_flag_tolerance() {
    let mut sub_value = BytesMut::new();
    sub_value.extend_from_slice(&encode_raw_avp_with_header(
        AvpHeader::ietf(apps::rf::AVP_SUBSCRIPTION_ID_TYPE, false)
            .with_flags(AvpFlags::new(false, false, true)),
        &1_u32.to_be_bytes(),
    ));
    sub_value.extend_from_slice(&encode_raw_avp_with_header(
        AvpHeader::ietf(apps::rf::AVP_SUBSCRIPTION_ID_DATA, false),
        b"001010123456789",
    ));
    let extras = [encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID,
        true,
        &sub_value,
    )];
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);

    let parsed = apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default())
        .expect("Rf child flag tolerance is an established parser behavior");
    assert_eq!(parsed.subscription_ids.len(), 1);
    assert_eq!(
        parsed.subscription_ids[0].subscription_id_type,
        apps::rf::SubscriptionIdType::EndUserImsi
    );
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_preserves_optional_vendor_child_tolerance() {
    for vendor_child in [
        encode_raw_vendor_avp(
            apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
            VendorId::new(42_424),
            false,
            &0_u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(
            apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
            VendorId::new(0),
            false,
            &0_u32.to_be_bytes(),
        ),
        encode_raw_vendor_avp(AvpCode::new(998_001), VendorId::new(0), false, b"optional"),
    ] {
        let mut sub_value = BytesMut::new();
        sub_value.extend_from_slice(&encode_raw_avp(
            apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
            true,
            &1_u32.to_be_bytes(),
        ));
        sub_value.extend_from_slice(&encode_raw_avp(
            apps::rf::AVP_SUBSCRIPTION_ID_DATA,
            true,
            b"001010123456789",
        ));
        sub_value.extend_from_slice(&vendor_child);
        let extras = [encode_raw_avp(
            apps::rf::AVP_SUBSCRIPTION_ID,
            true,
            &sub_value,
        )];
        let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &extras);
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);
        for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
            let parsed = apps::rf::parse_rf_accounting_request(
                &decoded,
                DecodeContext {
                    unknown_ie_policy,
                    ..DecodeContext::default()
                },
            )
            .expect("Rf preserves its established optional vendor-child tolerance");
            assert_eq!(parsed.subscription_ids.len(), 1);
        }
    }
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_rejects_noncanonical_outer_flags() {
    let mut sub_value = BytesMut::new();
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_TYPE,
        true,
        &1_u32.to_be_bytes(),
    ));
    sub_value.extend_from_slice(&encode_raw_avp(
        apps::rf::AVP_SUBSCRIPTION_ID_DATA,
        true,
        b"001010123456789",
    ));
    let outer = encode_raw_avp(apps::rf::AVP_SUBSCRIPTION_ID, false, &sub_value);
    let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &[outer]);
    let encoded = encode_message(&message);
    let decoded = decode_message(&encoded);
    assert!(apps::rf::parse_rf_accounting_request(&decoded, DecodeContext::default()).is_err());
}

#[test]
#[cfg(feature = "app-rf")]
fn rf_grouped_subscription_id_tolerates_optional_foreign_vendor_outer_code() {
    for vendor_id in [VendorId::new(42_424), VendorId::new(0)] {
        let outer =
            encode_raw_vendor_avp(apps::rf::AVP_SUBSCRIPTION_ID, vendor_id, false, b"optional");
        let message = build_raw_rf_acr(Some(apps::rf::APPLICATION_ID.get()), &[outer]);
        let encoded = encode_message(&message);
        let decoded = decode_message(&encoded);

        for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
            let parsed = apps::rf::parse_rf_accounting_request(
                &decoded,
                DecodeContext {
                    unknown_ie_policy,
                    ..DecodeContext::default()
                },
            )
            .expect("optional foreign-vendor code collisions remain unknown Rf AVPs");
            assert!(parsed.subscription_ids.is_empty());
        }
    }
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

    let specific_apn_info = dictionary
        .find_avp(AvpKey::vendor(
            apps::swm::AVP_SPECIFIC_APN_INFO,
            apps::VENDOR_ID_3GPP,
        ))
        .expect("Specific-APN-Info must be present");
    assert_eq!(specific_apn_info.data_type(), AvpDataType::Grouped);
    assert_eq!(
        specific_apn_info.flags().vendor(),
        FlagRequirement::MustBeSet
    );
    assert_eq!(
        specific_apn_info.flags().mandatory(),
        FlagRequirement::MayBeSet
    );
    assert_eq!(
        specific_apn_info.flags().protected(),
        FlagRequirement::MustBeUnset
    );
    assert_eq!(specific_apn_info.grouped_avp_rules().len(), 3);
    for key in [
        AvpKey::ietf(apps::swm::AVP_SERVICE_SELECTION),
        AvpKey::ietf(apps::swm::AVP_MIP6_AGENT_INFO),
        AvpKey::vendor(
            apps::swm::AVP_VISITED_NETWORK_IDENTIFIER,
            apps::VENDOR_ID_3GPP,
        ),
    ] {
        assert_eq!(
            specific_apn_info
                .find_grouped_avp_rule(key)
                .expect("typed Specific-APN-Info child rule")
                .cardinality(),
            AvpCardinality::ZeroOrOne
        );
    }
    assert_eq!(
        apn_configuration
            .find_grouped_avp_rule(AvpKey::vendor(
                apps::swm::AVP_SPECIFIC_APN_INFO,
                apps::VENDOR_ID_3GPP,
            ))
            .expect("APN-Configuration permits Specific-APN-Info")
            .cardinality(),
        AvpCardinality::ZeroOrMore
    );

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
    let mut apn_value = raw_apn_configuration_children(7, b"internet", 2);
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
        encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, true, b"internet"),
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
        Some("internet")
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
    assert_eq!(selected.service_selection.as_ref(), "ims");

    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("SWm DEA build must succeed");
    let encoded = encode_message(&built);
    let message = decode_message(&encoded);
    let parsed = apps::swm::parse_swm_diameter_eap_answer(&message, DecodeContext::default())
        .expect("SWm DEA parse must succeed");
    assert_eq!(parsed.apn_configurations, answer.apn_configurations);
    assert_eq!(
        parsed.default_context_identifier,
        answer.default_context_identifier
    );
    let rebuilt = apps::swm::build_swm_diameter_eap_answer(&parsed, 1, 2, EncodeContext::default())
        .expect("parsed projected profile must rebuild");
    assert_eq!(encode_message(&rebuilt), encoded);
    assert_eq!(
        parsed
            .default_apn_configuration()
            .map(|apn| apn.service_selection.as_ref().as_str()),
        Some("ims")
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
fn swm_der_emits_mandatory_unprotected_state() {
    const STATE: &[u8] = b"\0synthetic-der-state\xff";

    let mut request = sample_swm_request();
    request.state_avps = vec![STATE.to_vec()];
    let built = apps::swm::build_swm_diameter_eap_request(&request, 1, 2, EncodeContext::default())
        .expect("DER with binary State must encode");
    let encoded = encode_message(&built);
    let decoded = decode_message(&encoded);
    let state = decoded
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("DER AVPs must decode")
        .into_iter()
        .find(|avp| avp.header.code == apps::swm::AVP_STATE)
        .expect("DER must contain State");

    assert_eq!(state.header.vendor_id, None);
    assert!(state.header.flags.is_mandatory());
    assert!(!state.header.flags.is_vendor_specific());
    assert!(!state.header.flags.is_protected());
    assert_eq!(state.value, STATE);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_der_state_accepts_rfc_4005_protected_bit() {
    const STATE: &[u8] = b"\0synthetic-protected-state\xfd";

    let state = RawAvp {
        header: AvpHeader::ietf(apps::swm::AVP_STATE, true)
            .with_flags(AvpFlags::new(false, true, true)),
        value: STATE,
        padding: &[],
    };
    let mut encoded_state = BytesMut::new();
    state
        .encode(&mut encoded_state, EncodeContext::default())
        .expect("protected State AVP must encode");
    let built = build_raw_swm_der_with_extras(
        Some(apps::swm::APPLICATION_ID.get()),
        AuthRequestType::AuthorizeAuthenticate.value(),
        &[0x02, 0x17, 0x00, 0x04],
        &[encoded_state],
    );
    let encoded = encode_message(&built);
    let (tail, decoded) = Message::decode_with_dictionary(
        &encoded,
        DecodeContext::conservative(),
        SWM_BASELINE_DICTIONARIES,
    )
    .expect("RFC 4005 permits protected State on receive");
    assert!(tail.is_empty());
    let parsed = apps::swm::parse_swm_diameter_eap_request(&decoded, DecodeContext::conservative())
        .expect("typed DER parser must retain protected State opaquely");
    assert_eq!(parsed.state_avps, vec![STATE]);
    assert!(!format!("{parsed:?}").contains("synthetic-protected-state"));
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
fn swm_dea_emits_mandatory_unprotected_state() {
    const STATE: &[u8] = b"\0synthetic-dea-state\xfe";

    let mut answer = sample_swm_answer();
    answer.state_avps = vec![STATE.to_vec()];
    let built = apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
        .expect("DEA with binary State must encode");
    let encoded = encode_message(&built);
    let decoded = decode_message(&encoded);
    let state = decoded
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("DEA AVPs must decode")
        .into_iter()
        .find(|avp| avp.header.code == apps::swm::AVP_STATE)
        .expect("DEA must contain State");

    assert_eq!(state.header.vendor_id, None);
    assert!(state.header.flags.is_mandatory());
    assert!(!state.header.flags.is_vendor_specific());
    assert!(!state.header.flags.is_protected());
    assert_eq!(state.value, STATE);
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_state_round_trips_opaquely_into_continuation_der() {
    const FIRST: &[u8] = b"\0synthetic-state-first\xff";
    const SECOND: &[u8] = b"\x80synthetic-state-second\0";

    let mut answer = sample_swm_answer();
    answer.state_avps = vec![FIRST.to_vec(), SECOND.to_vec()];
    let built_answer =
        apps::swm::build_swm_diameter_eap_answer(&answer, 1, 2, EncodeContext::default())
            .expect("multi-round DEA must encode");
    let encoded_answer = encode_message(&built_answer);
    let decoded_answer = decode_message(&encoded_answer);
    let parsed_answer =
        apps::swm::parse_swm_diameter_eap_answer(&decoded_answer, DecodeContext::conservative())
            .expect("multi-round DEA must parse");
    assert_eq!(parsed_answer.state_avps, vec![FIRST, SECOND]);

    let answer_debug = format!("{parsed_answer:?}");
    assert!(!answer_debug.contains("synthetic-state-first"));
    assert!(!answer_debug.contains("synthetic-state-second"));

    let mut continuation = sample_swm_request();
    continuation.state_avps = parsed_answer.state_avps.clone();
    continuation.eap_payload = vec![0x02, 0x18, 0x00, 0x04].into();
    let built_continuation =
        apps::swm::build_swm_diameter_eap_request(&continuation, 3, 4, EncodeContext::default())
            .expect("continuation DER must encode");
    let encoded_continuation = encode_message(&built_continuation);
    let decoded_continuation = decode_message(&encoded_continuation);
    let states = decoded_continuation
        .avps(DecodeContext::default())
        .collect::<Result<Vec<_>, _>>()
        .expect("continuation DER AVPs must decode")
        .into_iter()
        .filter(|avp| avp.header.code == apps::swm::AVP_STATE)
        .collect::<Vec<_>>();

    assert_eq!(states.len(), 2);
    assert_eq!(states[0].value, FIRST);
    assert_eq!(states[1].value, SECOND);
    assert!(states.iter().all(|state| state.header.vendor_id.is_none()));
    assert!(states.iter().all(|state| state.header.flags.is_mandatory()));

    let request_debug = format!("{continuation:?}");
    assert!(!request_debug.contains("synthetic-state-first"));
    assert!(!request_debug.contains("synthetic-state-second"));

    continuation.eap_payload = Vec::new().into();
    let error =
        apps::swm::build_swm_diameter_eap_request(&continuation, 5, 6, EncodeContext::default())
            .expect_err("invalid continuation must fail without exposing State");
    for diagnostic in [format!("{error}"), format!("{error:?}")] {
        assert!(!diagnostic.contains("synthetic-state-first"));
        assert!(!diagnostic.contains("synthetic-state-second"));
    }
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_mip6_feature_vector_is_stable_across_continuation_der_rounds() {
    let mut initial = sample_swm_request();
    initial.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());

    let initial_wire = encode_message(
        &apps::swm::build_swm_diameter_eap_request(
            &initial,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        )
        .expect("initial DER must encode"),
    );
    let parsed_initial = apps::swm::parse_swm_diameter_eap_request(
        &decode_message(&initial_wire),
        DecodeContext::conservative(),
    )
    .expect("initial DER must parse");

    let mut challenge = sample_swm_answer();
    challenge.result = SwmDiameterResult::Base(1001);
    challenge.eap_payload = Some(vec![0x01, 0x20, 0x00, 0x05, 0x01].into());
    challenge.eap_master_session_key = None;
    challenge.state_avps = vec![b"synthetic-continuation-state".to_vec()];
    let challenge_wire = encode_message(
        &apps::swm::build_swm_diameter_eap_answer(
            &challenge,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        )
        .expect("multi-round DEA must encode"),
    );
    let parsed_challenge = apps::swm::parse_swm_diameter_eap_answer(
        &decode_message(&challenge_wire),
        DecodeContext::conservative(),
    )
    .expect("multi-round DEA must parse");

    let mut continuation = parsed_initial;
    continuation.eap_payload = vec![0x02, 0x20, 0x00, 0x04].into();
    continuation.state_avps = parsed_challenge.state_avps;
    let continuation_wire = encode_message(
        &apps::swm::build_swm_diameter_eap_request(
            &continuation,
            0x1112_1314,
            0x1516_1718,
            EncodeContext::default(),
        )
        .expect("continuation DER must encode"),
    );

    let mip6_value = |wire: &[u8]| {
        decode_message(wire)
            .avps(DecodeContext::default())
            .collect::<Result<Vec<_>, _>>()
            .expect("DER AVPs must decode")
            .into_iter()
            .find(|avp| avp.header.code == apps::swm::AVP_MIP6_FEATURE_VECTOR)
            .expect("DER must carry MIP6-Feature-Vector")
            .value
            .to_vec()
    };
    assert_eq!(mip6_value(&initial_wire), mip6_value(&continuation_wire));
    assert_eq!(
        mip6_value(&continuation_wire),
        SwmMip6FeatureVector::GTPV2_SUPPORTED.to_be_bytes()
    );
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
    assert_eq!(parsed.apn_configurations, answer.apn_configurations);
    assert_eq!(
        parsed.default_context_identifier,
        answer.default_context_identifier
    );
    let rebuilt = apps::swm::build_swm_diameter_eap_answer(&parsed, 1, 2, EncodeContext::default())
        .expect("parsed projected profile must rebuild");
    assert_eq!(encode_message(&rebuilt), encoded);

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
    raw_avps.extend_from_slice(&raw_apn_configuration_avp(7, b"internet", 2));
    raw_avps.extend_from_slice(&raw_apn_configuration_avp(8, b"ims", 1));
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
        raw_apn_configuration_avp(7, b"internet", 2),
        raw_apn_configuration_avp(8, b"ims", 1),
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
        Some("ims")
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

    let extras = [raw_apn_configuration_avp(0, b"internet", 2)];
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
        raw_apn_configuration_avp(7, b"internet", 2),
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
            raw_apn_configuration_avp(7, b"internet", 2),
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
        raw_apn_configuration_avp(7, b"internet", 2),
        raw_apn_configuration_avp(7, b"ims", 1),
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
    let service_selection = encode_raw_avp(apps::swm::AVP_SERVICE_SELECTION, true, b"internet");
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

    let preserved = apps::swm::parse_swm_diameter_eap_answer(
        &decoded,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            ..DecodeContext::default()
        },
    )
    .expect("Preserve retains a non-mandatory unknown vendor AVP");
    assert_eq!(preserved.extensions.len(), 1);
    let metadata = preserved
        .extensions
        .metadata()
        .next()
        .expect("one value-free metadata record");
    assert_eq!(metadata.code(), AvpCode::new(9999));
    assert_eq!(metadata.vendor_id(), Some(apps::VENDOR_ID_3GPP));
    assert_eq!(metadata.value_len(), b"unknown".len());

    let dropped = apps::swm::parse_swm_diameter_eap_answer(
        &decoded,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect("Drop tolerates a non-mandatory unknown vendor AVP");
    assert!(dropped.extensions.is_empty());

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
        opc_protocol::DecodeErrorCode::InvalidLength { .. }
    ));
}

#[test]
#[cfg(feature = "app-swm")]
fn swm_dea_apn_configuration_rejects_duplicate_child() {
    let mut apn_value = raw_apn_configuration_children(7, b"internet", 2);
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
    let mut apn_value = raw_apn_configuration_children(7, b"internet", 2);
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
    let mut apn_value = raw_apn_configuration_children(7, b"internet", 2);
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
        b"internet",
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
    answer.service_selection = Some("operator-policy".into());
    answer.default_context_identifier = Some(8);
    answer.apn_configurations = vec![sample_apn_configuration(), sample_ims_apn_configuration()];

    let debug = format!("{:?}", answer);
    assert!(!debug.contains("internet"));
    assert!(!debug.contains("ims"));
    assert!(!debug.contains("operator-policy"));
    assert!(debug.contains("REDACTED"));
    assert!(debug.contains("default_context_identifier: Some(8)"));
    // Grouped subscription entries appear only as a count.
    assert!(debug.contains("apn_configurations: 2"));

    let debug = format!("{:?}", sample_apn_configuration());
    assert!(!debug.contains("internet"));
    assert!(debug.contains("REDACTED"));
}
