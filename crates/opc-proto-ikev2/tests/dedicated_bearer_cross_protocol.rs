use bytes::BytesMut;
use opc_proto_gtpv2c::{
    s2b_create_bearer_request, BearerQos, ChargingId, EpsBearerId, FullyQualifiedTeid,
    RawIeIterator, S2bCreateBearerRequest, S2bCreateBearerRequestContext, S2bMessage,
    IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_TFT, INTERFACE_TYPE_S2B_U_PGW_GTP_U,
};
use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_notify, decode_ikev2_dedicated_bearer_notify,
    Ikev2DedicatedBearerNotify, Ikev2NotifyPayload,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TrafficFlowTemplate,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext, ValidationLevel};

fn must_ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn canonical_tft() -> TrafficFlowTemplate {
    let packet_filter = must_ok(PacketFilter::new(
        must_ok(PacketFilterIdentifier::new(3)),
        PacketFilterDirection::Bidirectional,
        10,
        vec![
            PacketFilterComponent::ProtocolIdentifierNextHeader(17),
            PacketFilterComponent::SingleRemotePort(4_500),
        ],
    ));
    must_ok(TrafficFlowTemplate::create_new(vec![packet_filter], vec![]))
}

#[test]
fn gtp_bearer_tft_and_ike_tft_notify_embed_identical_value_bytes() {
    let canonical = canonical_tft();
    let gtp_message = must_ok(s2b_create_bearer_request(S2bCreateBearerRequest {
        sequence_number: 0x12_3456,
        teid: 0x0102_0304,
        message_priority: None,
        linked_ebi: EpsBearerId { value: 5 },
        bearer_contexts: vec![S2bCreateBearerRequestContext {
            tft: canonical.clone(),
            bearer_qos: BearerQos {
                priority_flags: 0x49,
                qci: 1,
                maximum_bitrate_uplink: 1_000,
                maximum_bitrate_downlink: 2_000,
                guaranteed_bitrate_uplink: 500,
                guaranteed_bitrate_downlink: 750,
            },
            pgw_f_teid: FullyQualifiedTeid {
                interface_type: INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                teid: 0x1122_3344,
                ipv4: Some([192, 0, 2, 10]),
                ipv6: None,
            },
            charging_id: ChargingId { value: 0x5566_7788 },
            additional_ies: vec![],
        }],
        additional_ies: vec![],
    }));
    let mut gtp_wire = BytesMut::new();
    must_ok(gtp_message.encode(&mut gtp_wire, EncodeContext::default()));

    let procedure_context = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    let (gtp_tail, decoded_gtp) = must_ok(S2bMessage::decode(&gtp_wire, procedure_context));
    assert!(gtp_tail.is_empty());
    let gtp_view = match decoded_gtp.as_view() {
        Some(value) => value,
        None => panic!("Create Bearer Request decoded as a raw GTP message"),
    };
    let typed_request = must_ok(gtp_view.create_bearer_request());
    assert_eq!(typed_request.bearer_contexts.len(), 1);
    assert_eq!(typed_request.bearer_contexts[0].tft, canonical);

    // Bearer Context is a grouped IE. Its nested Bearer TFT IE value is the
    // TS 24.008 value itself: no NAS IEI and no NAS length octet.
    let mut bearer_context_value = None;
    for raw_ie in RawIeIterator::new(gtp_view.raw_ies, procedure_context) {
        let raw_ie = must_ok(raw_ie);
        if raw_ie.ie_type == IE_TYPE_BEARER_CONTEXT && raw_ie.instance == 0 {
            bearer_context_value = Some(raw_ie.value);
            break;
        }
    }
    let bearer_context_value = match bearer_context_value {
        Some(value) => value,
        None => panic!("encoded Create Bearer Request omitted Bearer Context"),
    };
    let mut gtp_tft_value = None;
    for nested_ie in RawIeIterator::new(bearer_context_value, procedure_context) {
        let nested_ie = must_ok(nested_ie);
        if nested_ie.ie_type == IE_TYPE_BEARER_TFT && nested_ie.instance == 0 {
            gtp_tft_value = Some(nested_ie.value);
            break;
        }
    }
    let gtp_tft_value = match gtp_tft_value {
        Some(value) => value,
        None => panic!("encoded Bearer Context omitted Bearer TFT"),
    };

    let ike_payload = must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::Tft(canonical.clone()),
    ));
    let ike_notify = must_ok(Ikev2NotifyPayload::decode_body(&ike_payload.body));
    let typed_ike_tft = match must_ok(decode_ikev2_dedicated_bearer_notify(ike_notify)) {
        Some(Ikev2DedicatedBearerNotify::Tft(value)) => value,
        other => panic!("IKE TFT Notify decoded as an unexpected value: {other:?}"),
    };
    assert_eq!(typed_ike_tft, canonical);

    // TS 24.302 adds one inner length octet before the TS 24.008 TFT value.
    let (ike_declared_length, ike_tft_value) = match ike_notify.notification_data.split_first() {
        Some(value) => value,
        None => panic!("IKE TFT Notify omitted its inner length"),
    };
    assert_eq!(usize::from(*ike_declared_length), ike_tft_value.len());
    assert_eq!(gtp_tft_value, ike_tft_value);
}
