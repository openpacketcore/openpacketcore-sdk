use std::net::{IpAddr, Ipv4Addr};

use bytes::BytesMut;
use opc_proto_diameter::apps::rf::{
    AccountingRecordType, MultipleServicesCreditControl, PsInformation, RfAccountingAnswer,
    RfAccountingRequest, SubscriptionId, SubscriptionIdType, UsedServiceUnit,
};
use opc_proto_diameter::apps::swm::{
    AuthRequestType, SwmDiameterEapAnswer, SwmDiameterEapRequest, SwmResultCategory,
};
use opc_proto_diameter::{
    apps, base, ApplicationId, AvpCode, AvpDataType, AvpHeader, AvpKey, CommandCode, CommandFlags,
    CommandKind, DictionarySet, Header, Message, OwnedMessage, RawAvp, VendorId,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

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
        .find_command(apps::rf::COMMAND_ACCOUNTING, CommandKind::Request)
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
        .find_command(apps::swm::COMMAND_DIAMETER_EAP, CommandKind::Request)
        .expect("DER command must be present");
    assert_eq!(der.name(), "Diameter-EAP-Request");

    let eap_payload = dictionary
        .find_avp(AvpKey::ietf(apps::swm::AVP_EAP_PAYLOAD))
        .expect("EAP-Payload must be present");
    assert_eq!(eap_payload.data_type(), AvpDataType::OctetString);
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
    let parsed_answer =
        apps::swm::parse_swm_diameter_eap_answer(&message, DecodeContext::default())
            .expect("SWm DEA parse must succeed");
    assert_eq!(parsed_answer, answer);
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
        result_code: 2001,
        origin_host: "aaa.home.example".into(),
        origin_realm: "home.example".into(),
        user_name: None,
        eap_payload: None,
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: None,
    };
    assert_eq!(answer.result_category(), SwmResultCategory::Success);
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
        state_avps: vec![b"opaque-state".to_vec()],
    }
}

#[cfg(feature = "app-swm")]
fn sample_swm_answer() -> SwmDiameterEapAnswer {
    SwmDiameterEapAnswer {
        session_id: "sess;swm;001".into(),
        auth_application_id: apps::swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result_code: 2001,
        origin_host: "aaa.home.example".into(),
        origin_realm: "home.example".into(),
        user_name: None,
        eap_payload: Some(vec![0x03, 0x18, 0x00, 0x04].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: vec![],
        eap_master_session_key: Some(vec![0xAA; 32].into()),
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
        &3u32.to_be_bytes(),
    ));
    raw_avps.extend_from_slice(&encode_raw_avp(
        apps::swm::AVP_EAP_PAYLOAD,
        true,
        &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
    ));
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
