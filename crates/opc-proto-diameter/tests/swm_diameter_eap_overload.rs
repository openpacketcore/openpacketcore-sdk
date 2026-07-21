use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, SwmLoad, SwmLoadType, SwmOcOlr, SwmOcReportType, SwmOcSupportedFeatures,
    SwmOverloadControlErrorCode,
};
use opc_proto_diameter::{base, AvpCode, DictionarySet, Message};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x1020_3040;
const END_TO_END: u32 = 0x5060_7080;
const SESSION_ID: &[u8] = b"session;synthetic;overload";
const EPDG_HOST: &[u8] = b"epdg.example.invalid";
const EPDG_REALM: &[u8] = b"visited.example.invalid";
const AAA_HOST: &[u8] = b"aaa.example.invalid";
const AAA_REALM: &[u8] = b"home.example.invalid";

static SWM_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::dictionary()]);

fn put_u24(dst: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("fixture length fits u32");
    dst.extend_from_slice(&value.to_be_bytes()[1..]);
}

fn wire_avp(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    let length = 8 + value.len();
    let padded = (length + 3) & !3;
    let mut wire = Vec::with_capacity(padded);
    wire.extend_from_slice(&code.get().to_be_bytes());
    wire.push(flags);
    put_u24(&mut wire, length);
    wire.extend_from_slice(value);
    wire.resize(padded, 0);
    wire
}

fn wire_vendor_avp(code: AvpCode, flags: u8, vendor_id: u32, value: &[u8]) -> Vec<u8> {
    let length = 12 + value.len();
    let padded = (length + 3) & !3;
    let mut wire = Vec::with_capacity(padded);
    wire.extend_from_slice(&code.get().to_be_bytes());
    wire.push(flags | 0x80);
    put_u24(&mut wire, length);
    wire.extend_from_slice(&vendor_id.to_be_bytes());
    wire.extend_from_slice(value);
    wire.resize(padded, 0);
    wire
}

fn wire_message(request: bool, avps: Vec<Vec<u8>>) -> Vec<u8> {
    let raw_avps: Vec<u8> = avps.into_iter().flatten().collect();
    let length = 20 + raw_avps.len();
    let mut wire = Vec::with_capacity(length);
    wire.push(1);
    put_u24(&mut wire, length);
    wire.push(if request { 0xc0 } else { 0x40 });
    put_u24(
        &mut wire,
        usize::try_from(swm::COMMAND_DIAMETER_EAP.get()).expect("command code fits usize"),
    );
    wire.extend_from_slice(&swm::APPLICATION_ID.get().to_be_bytes());
    wire.extend_from_slice(&HOP_BY_HOP.to_be_bytes());
    wire.extend_from_slice(&END_TO_END.to_be_bytes());
    wire.extend_from_slice(&raw_avps);
    wire
}

fn der_avps(oc_supported_features: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut avps = vec![
        wire_avp(base::AVP_SESSION_ID, 0x40, SESSION_ID),
        wire_avp(
            base::AVP_AUTH_APPLICATION_ID,
            0x40,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        wire_avp(base::AVP_ORIGIN_HOST, 0x40, EPDG_HOST),
        wire_avp(base::AVP_ORIGIN_REALM, 0x40, EPDG_REALM),
        wire_avp(base::AVP_DESTINATION_REALM, 0x40, AAA_REALM),
        wire_avp(swm::AVP_AUTH_REQUEST_TYPE, 0x40, &3_u32.to_be_bytes()),
    ];
    if let Some(value) = oc_supported_features {
        avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x00, &value));
    }
    avps.push(wire_avp(swm::AVP_EAP_PAYLOAD, 0x40, &[2, 23, 0, 4]));
    avps
}

fn dea_avps(
    oc_supported_features: Option<Vec<u8>>,
    oc_olr: Option<Vec<u8>>,
    loads: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut avps = vec![
        wire_avp(base::AVP_SESSION_ID, 0x40, SESSION_ID),
        wire_avp(
            base::AVP_AUTH_APPLICATION_ID,
            0x40,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        wire_avp(swm::AVP_AUTH_REQUEST_TYPE, 0x40, &3_u32.to_be_bytes()),
        wire_avp(
            base::AVP_RESULT_CODE,
            0x40,
            &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
        ),
        wire_avp(base::AVP_ORIGIN_HOST, 0x40, AAA_HOST),
        wire_avp(base::AVP_ORIGIN_REALM, 0x40, AAA_REALM),
    ];
    if let Some(value) = oc_supported_features {
        avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x00, &value));
    }
    if let Some(value) = oc_olr {
        avps.push(wire_avp(swm::AVP_OC_OLR, 0x00, &value));
    }
    avps.extend(
        loads
            .into_iter()
            .map(|value| wire_avp(swm::AVP_LOAD, 0x00, &value)),
    );
    avps.push(wire_avp(swm::AVP_EAP_PAYLOAD, 0x40, &[3, 23, 0, 4]));
    avps
}

fn oc_supported_value(feature_vector: Option<u64>) -> Vec<u8> {
    feature_vector.map_or_else(Vec::new, |value| {
        wire_avp(swm::AVP_OC_FEATURE_VECTOR, 0x00, &value.to_be_bytes())
    })
}

fn loss_olr_value(reduction_percentage: Option<u32>) -> Vec<u8> {
    let mut children = vec![
        wire_avp(swm::AVP_OC_SEQUENCE_NUMBER, 0x00, &7_u64.to_be_bytes()),
        wire_avp(swm::AVP_OC_REPORT_TYPE, 0x00, &0_u32.to_be_bytes()),
    ];
    if let Some(reduction_percentage) = reduction_percentage {
        children.push(wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE,
            0x00,
            &reduction_percentage.to_be_bytes(),
        ));
    }
    children.push(wire_avp(
        swm::AVP_OC_VALIDITY_DURATION,
        0x00,
        &60_u32.to_be_bytes(),
    ));
    children.into_iter().flatten().collect()
}

fn load_value(load_type: u32, load_value: u64, source_id: &[u8]) -> Vec<u8> {
    [
        wire_avp(swm::AVP_LOAD_TYPE, 0x00, &load_type.to_be_bytes()),
        wire_avp(swm::AVP_LOAD_VALUE, 0x00, &load_value.to_be_bytes()),
        wire_avp(swm::AVP_SOURCE_ID, 0x00, source_id),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn decode(wire: &[u8], ctx: DecodeContext) -> Message<'_> {
    let (tail, message) = Message::decode_with_dictionary(wire, ctx, SWM_DICTIONARIES)
        .expect("fixture message framing");
    assert!(tail.is_empty());
    message
}

fn encode(message: &opc_proto_diameter::OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("typed message encode");
    wire.to_vec()
}

#[test]
fn der_oc_supported_features_fixture_is_typed_and_absence_is_byte_compatible() {
    for feature_vector in [None, Some(1)] {
        let wire = wire_message(true, der_avps(Some(oc_supported_value(feature_vector))));
        let parsed = swm::parse_swm_diameter_eap_request(
            &decode(&wire, DecodeContext::conservative()),
            DecodeContext::conservative(),
        )
        .expect("independent DER overload fixture");
        let features = parsed
            .oc_supported_features
            .as_ref()
            .expect("typed capability");
        assert_eq!(features.feature_vector(), feature_vector);
        assert_eq!(features.effective_feature_vector(), 1);
        assert!(features.selects_loss());
        assert_eq!(features.extension_count(), 0);
        assert_eq!(
            encode(
                &swm::build_swm_diameter_eap_request(
                    &parsed,
                    HOP_BY_HOP,
                    END_TO_END,
                    EncodeContext::default(),
                )
                .expect("typed DER replay")
            ),
            wire
        );
    }

    let absent_wire = wire_message(true, der_avps(None));
    let absent = swm::parse_swm_diameter_eap_request(
        &decode(&absent_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("legacy DER without overload capability");
    assert!(absent.oc_supported_features.is_none());
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_request(
                &absent,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("legacy DER replay")
        ),
        absent_wire
    );
}

#[test]
fn grouped_unknown_policy_is_preserved_without_a_raw_public_field() {
    let value = [
        oc_supported_value(Some(1)),
        wire_avp(AvpCode::new(9_901), 0x00, b"extension"),
    ]
    .concat();
    let wire = wire_message(true, der_avps(Some(value)));

    let preserve = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    let parsed = swm::parse_swm_diameter_eap_request(&decode(&wire, preserve), preserve)
        .expect("unknown optional grouped child is preserved");
    assert_eq!(
        parsed
            .oc_supported_features
            .as_ref()
            .expect("capability")
            .extension_count(),
        1
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_request(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("preserved extension replay")
        ),
        wire
    );

    let drop = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    let dropped = swm::parse_swm_diameter_eap_request(&decode(&wire, drop), drop)
        .expect("unknown optional grouped child is dropped by policy");
    assert_eq!(
        dropped
            .oc_supported_features
            .as_ref()
            .expect("capability")
            .extension_count(),
        0
    );

    let reject = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert!(swm::parse_swm_diameter_eap_request(&decode(&wire, reject), reject).is_err());
}

#[test]
fn dea_fixture_round_trips_typed_olr_and_ordered_load_reports() {
    let loads = vec![
        load_value(0, 50_000, b"host-load.example.invalid"),
        load_value(1, 40_000, b"peer-load.example.invalid"),
    ];
    let wire = wire_message(
        false,
        dea_avps(
            Some(oc_supported_value(None)),
            Some(loss_olr_value(Some(25))),
            loads,
        ),
    );
    let parsed = swm::parse_swm_diameter_eap_answer(
        &decode(&wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("independent DEA overload fixture");

    let olr = parsed.oc_olr.as_ref().expect("typed overload report");
    assert_eq!(olr.sequence_number(), 7);
    assert_eq!(olr.report_type(), SwmOcReportType::Host);
    assert_eq!(olr.wire_validity_duration(), Some(60));
    assert_eq!(olr.effective_validity_duration(), 60);
    assert_eq!(olr.effective_reduction_percentage(), Some(25));
    assert_eq!(parsed.load_reports.len(), 2);
    assert_eq!(
        parsed.load_reports[0].complete_tuple(),
        Some((SwmLoadType::Host, 50_000, "host-load.example.invalid"))
    );
    assert_eq!(
        parsed.load_reports[1].complete_tuple(),
        Some((SwmLoadType::Peer, 40_000, "peer-load.example.invalid"))
    );
    assert!(!format!("{:?}", parsed.load_reports[0]).contains("host-load.example.invalid"));
    let request_wire = wire_message(true, der_avps(Some(oc_supported_value(None))));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("correlated DER offer");
    assert!(swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer_for(&request, &parsed, EncodeContext::default(),)
                .expect("request-bound typed DEA replay")
        ),
        wire
    );
}

#[test]
fn answer_overload_control_is_conditioned_on_the_request_offer() {
    let der_with_offer = wire_message(true, der_avps(Some(oc_supported_value(None))));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&der_with_offer, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("request envelope with offer");
    let answer_wire = wire_message(
        false,
        dea_avps(
            Some(oc_supported_value(None)),
            Some(loss_olr_value(Some(10))),
            Vec::new(),
        ),
    );
    let answer = swm::parse_swm_diameter_eap_answer(
        &decode(&answer_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("answer with selected loss algorithm");
    swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default())
        .expect("offered answer overload control");

    let der_without_offer = wire_message(true, der_avps(None));
    let request_without_offer = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&der_without_offer, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("request envelope without offer");
    assert!(swm::build_swm_diameter_eap_answer_for(
        &request_without_offer,
        &answer,
        EncodeContext::default(),
    )
    .is_err());
    let answer_envelope = swm::SwmDiameterEapAnswerEnvelope::for_outbound(
        answer.clone(),
        request_without_offer.transaction(),
    );
    assert!(request_without_offer
        .correlate_answer(answer_envelope)
        .is_err());

    let mut no_report = answer;
    no_report.oc_supported_features = None;
    no_report.oc_olr = None;
    swm::build_swm_diameter_eap_answer_for(&request, &no_report, EncodeContext::default())
        .expect("non-reporting node may omit answer overload control after an offer");
}

#[test]
fn received_extension_bits_can_offer_loss_but_cannot_be_reoriginated() {
    let request_wire = wire_message(true, der_avps(Some(oc_supported_value(Some(3)))));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("request may advertise loss plus an extension algorithm");
    let offered = request
        .request()
        .oc_supported_features
        .as_ref()
        .expect("typed offer");
    assert_eq!(offered.feature_vector(), Some(3));
    assert!(offered.selects_loss());
    assert!(swm::build_swm_diameter_eap_request(
        request.request(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());

    let answer_wire = wire_message(
        false,
        dea_avps(
            Some(oc_supported_value(None)),
            Some(loss_olr_value(Some(5))),
            Vec::new(),
        ),
    );
    let answer = swm::parse_swm_diameter_eap_answer(
        &decode(&answer_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("loss selection answer");
    swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default())
        .expect("loss is a subset of the received extension-bearing offer");
}

#[test]
fn received_olr_defaults_are_safe_but_out_of_range_values_cannot_be_originated() {
    let olr = [
        wire_avp(swm::AVP_OC_SEQUENCE_NUMBER, 0x00, &9_u64.to_be_bytes()),
        wire_avp(swm::AVP_OC_REPORT_TYPE, 0x00, &1_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE,
            0x00,
            &101_u32.to_be_bytes(),
        ),
        wire_avp(
            swm::AVP_OC_VALIDITY_DURATION,
            0x00,
            &86_401_u32.to_be_bytes(),
        ),
    ]
    .concat();
    let answer_wire = wire_message(
        false,
        dea_avps(Some(oc_supported_value(None)), Some(olr), Vec::new()),
    );
    let answer = swm::parse_swm_diameter_eap_answer(
        &decode(&answer_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("RFC defaults safely handle received out-of-range OLR values");
    let parsed_olr = answer.oc_olr.as_ref().expect("typed OLR");
    assert_eq!(parsed_olr.wire_validity_duration(), Some(86_401));
    assert_eq!(parsed_olr.effective_validity_duration(), 30);
    assert_eq!(parsed_olr.wire_reduction_percentage(), Some(101));
    assert_eq!(parsed_olr.effective_reduction_percentage(), None);

    let request_wire = wire_message(true, der_avps(Some(oc_supported_value(None))));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("correlated offer");
    assert!(
        swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default(),)
            .is_err()
    );
}

#[test]
fn malformed_overload_values_fail_closed_with_stable_decode_codes() {
    let duplicate = wire_message(true, {
        let mut avps = der_avps(Some(oc_supported_value(None)));
        let insert_at = avps.len() - 1;
        avps.insert(
            insert_at,
            wire_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x00, &[]),
        );
        avps
    });
    let duplicate_error = match Message::decode_with_dictionary(
        &duplicate,
        DecodeContext::conservative(),
        SWM_DICTIONARIES,
    ) {
        Ok(_) => panic!("duplicate OC-Supported-Features must fail command validation"),
        Err(error) => error,
    };
    assert_eq!(duplicate_error.code(), &DecodeErrorCode::DuplicateIe);

    let wrong_flags = wire_message(true, {
        let mut avps = der_avps(None);
        let insert_at = avps.len() - 1;
        avps.insert(
            insert_at,
            wire_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x20, &[]),
        );
        avps
    });
    assert!(swm::parse_swm_diameter_eap_request(
        &decode(&wrong_flags, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .is_err());

    let wrong_vendor = wire_message(true, {
        let mut avps = der_avps(None);
        let insert_at = avps.len() - 1;
        avps.insert(
            insert_at,
            wire_vendor_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x00, 10_415, &[]),
        );
        avps
    });
    assert!(swm::parse_swm_diameter_eap_request(
        &decode(&wrong_vendor, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .is_err());

    let m_set = wire_message(true, {
        let mut avps = der_avps(None);
        let insert_at = avps.len() - 1;
        avps.insert(
            insert_at,
            wire_avp(swm::AVP_OC_SUPPORTED_FEATURES, 0x40, &[]),
        );
        avps
    });
    let parsed_m_set = swm::parse_swm_diameter_eap_request(
        &decode(&m_set, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("application-controlled OC M bit may be set");
    assert!(parsed_m_set.oc_supported_features.is_some());

    let missing_loss = wire_message(true, der_avps(Some(oc_supported_value(Some(2)))));
    assert!(swm::parse_swm_diameter_eap_request(
        &decode(&missing_loss, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .is_err());

    let olr_without_features = wire_message(
        false,
        dea_avps(None, Some(loss_olr_value(Some(10))), Vec::new()),
    );
    assert!(swm::parse_swm_diameter_eap_answer(
        &decode(&olr_without_features, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .is_err());

    let loss_without_reduction = wire_message(
        false,
        dea_avps(
            Some(oc_supported_value(None)),
            Some(loss_olr_value(None)),
            Vec::new(),
        ),
    );
    assert!(swm::parse_swm_diameter_eap_answer(
        &decode(&loss_without_reduction, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .is_err());

    let invalid_load = wire_message(
        false,
        dea_avps(None, None, vec![load_value(0, 65_536, AAA_HOST)]),
    );
    let invalid_load_error = swm::parse_swm_diameter_eap_answer(
        &decode(&invalid_load, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect_err("out-of-range Load-Value");
    assert!(matches!(
        invalid_load_error.code(),
        DecodeErrorCode::InvalidEnumValue {
            field: "Load-Value",
            value: 65_536
        }
    ));
}

#[test]
fn load_collection_is_bounded_and_incomplete_received_reports_are_non_actionable() {
    let ctx = DecodeContext {
        max_ies: 1_024,
        ..DecodeContext::default()
    };
    let too_many = wire_message(
        false,
        dea_avps(
            None,
            None,
            (0..129)
                .map(|_| load_value(0, 10, b"load.example.invalid"))
                .collect(),
        ),
    );
    let error = swm::parse_swm_diameter_eap_answer(&decode(&too_many, ctx), ctx)
        .expect_err("129th Load report");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);

    let incomplete_value = wire_avp(swm::AVP_LOAD_TYPE, 0x00, &0_u32.to_be_bytes());
    let incomplete = wire_message(false, dea_avps(None, None, vec![incomplete_value]));
    let parsed = swm::parse_swm_diameter_eap_answer(
        &decode(&incomplete, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("RFC 8583 grouped children are individually optional on receive");
    assert_eq!(parsed.load_reports.len(), 1);
    assert!(parsed.load_reports[0].complete_tuple().is_none());
    assert!(swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());

    let request_wire = wire_message(true, der_avps(None));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("request envelope");
    assert!(
        swm::build_swm_diameter_eap_answer_for(&request, &parsed, EncodeContext::default(),)
            .is_err()
    );
    let outbound_request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("second request envelope");
    let outbound_answer = swm::SwmDiameterEapAnswerEnvelope::for_outbound(
        parsed.clone(),
        outbound_request.transaction(),
    );
    assert!(outbound_request.correlate_answer(outbound_answer).is_err());

    let answer_envelope = swm::parse_swm_diameter_eap_answer_envelope(
        &decode(&incomplete, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("received incomplete Load remains a valid DEA envelope");
    let correlated = request
        .correlate_answer(answer_envelope)
        .expect("correlation must not impose originated Load completeness");
    assert!(correlated.answer().load_reports[0]
        .complete_tuple()
        .is_none());
}

#[test]
fn overload_command_applicability_rejects_known_wrong_level_avps_under_all_policies() {
    let grouped_children = [
        swm::AVP_OC_FEATURE_VECTOR,
        swm::AVP_OC_SEQUENCE_NUMBER,
        swm::AVP_OC_VALIDITY_DURATION,
        swm::AVP_OC_REPORT_TYPE,
        swm::AVP_OC_REDUCTION_PERCENTAGE,
        swm::AVP_LOAD_TYPE,
        swm::AVP_LOAD_VALUE,
        swm::AVP_SOURCE_ID,
    ];
    for policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        let ctx = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::default()
        };
        for code in [swm::AVP_OC_OLR, swm::AVP_LOAD]
            .into_iter()
            .chain(grouped_children)
        {
            let mut avps = der_avps(None);
            avps.insert(avps.len() - 1, wire_avp(code, 0x00, &[]));
            let wire = wire_message(true, avps);
            let (tail, message) = Message::decode(&wire, ctx).expect("raw DER framing");
            assert!(tail.is_empty());
            let error = swm::parse_swm_diameter_eap_request(&message, ctx)
                .expect_err("known answer-only or grouped child AVP must fail in DER");
            assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
        }

        for code in grouped_children {
            let mut avps = dea_avps(None, None, Vec::new());
            avps.insert(avps.len() - 1, wire_avp(code, 0x00, &[]));
            let wire = wire_message(false, avps);
            let (tail, message) = Message::decode(&wire, ctx).expect("raw DEA framing");
            assert!(tail.is_empty());
            let error = swm::parse_swm_diameter_eap_answer(&message, ctx)
                .expect_err("known grouped child AVP must fail at DEA top level");
            assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
        }
    }
}

#[test]
fn load_m_bit_is_ignored_on_receive_and_canonicalized_on_origin() {
    let load = load_value(1, 123, AAA_HOST);
    let mut m_set_avps = dea_avps(None, None, Vec::new());
    let insert_at = m_set_avps.len() - 1;
    m_set_avps.insert(insert_at, wire_avp(swm::AVP_LOAD, 0x40, &load));
    let m_set_wire = wire_message(false, m_set_avps);
    let parsed = swm::parse_swm_diameter_eap_answer(
        &decode(&m_set_wire, DecodeContext::conservative()),
        DecodeContext::conservative(),
    )
    .expect("TS 29.273 requires understood Load M mismatch to be ignored");
    let canonical = encode(
        &swm::build_swm_diameter_eap_answer(
            &parsed,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("Load is independent of the overload request offer"),
    );
    assert_eq!(
        canonical,
        wire_message(false, dea_avps(None, None, vec![load]))
    );
}

#[test]
fn source_id_must_be_nonempty_ascii() {
    for source_id in [b"".as_slice(), &[0xc3, 0xa9][..]] {
        let wire = wire_message(
            false,
            dea_avps(None, None, vec![load_value(0, 1, source_id)]),
        );
        assert!(swm::parse_swm_diameter_eap_answer(
            &decode(&wire, DecodeContext::conservative()),
            DecodeContext::conservative(),
        )
        .is_err());
    }
}

#[test]
fn constructors_enforce_originated_bounds_and_redact_source_identity() {
    assert_eq!(
        SwmOcSupportedFeatures::explicit_loss().feature_vector(),
        Some(1)
    );
    assert_eq!(
        SwmOcOlr::new_loss(1, SwmOcReportType::Host, Some(86_401), 10)
            .expect_err("validity bound")
            .code(),
        SwmOverloadControlErrorCode::ValidityDurationOutOfRange
    );
    assert_eq!(
        SwmOcOlr::new_loss(1, SwmOcReportType::Realm, Some(60), 101)
            .expect_err("reduction bound")
            .code(),
        SwmOverloadControlErrorCode::ReductionPercentageOutOfRange
    );
    assert_eq!(
        SwmLoad::new(SwmLoadType::Host, 1, "")
            .expect_err("empty SourceID")
            .code(),
        SwmOverloadControlErrorCode::InvalidSourceId
    );
    assert_eq!(
        SwmLoad::new(SwmLoadType::Host, 1, "nonascii-\u{e9}.invalid")
            .expect_err("non-ASCII SourceID")
            .code(),
        SwmOverloadControlErrorCode::InvalidSourceId
    );
    let load =
        SwmLoad::new(SwmLoadType::Peer, 65_535, "peer.example.invalid").expect("valid load report");
    assert!(load.actionable_for_peer("PEER.EXAMPLE.INVALID").is_some());
    assert!(load.actionable_for_peer("other.example.invalid").is_none());
    assert!(!format!("{load:?}").contains("peer.example.invalid"));
}
