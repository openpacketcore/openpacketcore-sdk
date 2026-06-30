use bytes::BytesMut;
use opc_proto_pfcp::ie::{
    ApplyAction, Cause, CauseValue, CreateFar, CreatePdr, DestinationInterface, FSeid, FarId,
    ForwardingParameters, NetworkInstance, NodeId, NodeIdType, Pdi, PdrId, Precedence,
    RecoveryTimeStamp, ReportType, SourceInterface, TypedIe, UrSeqn, UsageReport,
};
use opc_proto_pfcp::{
    association_setup_request, session_establishment_request,
    session_report_request_with_report_type, OwnedMessage,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

fn recovery_time_stamp() -> RecoveryTimeStamp {
    RecoveryTimeStamp { seconds: 42 }
}

fn node_id() -> NodeId {
    NodeId {
        node_id_type: NodeIdType::Fqdn,
        value: b"upf.local".to_vec(),
    }
}

fn cp_fseid() -> FSeid {
    FSeid {
        v4: true,
        v6: false,
        seid: 1,
        ipv4: Some([127, 0, 0, 1]),
        ipv6: None,
    }
}

fn accepted_cause() -> Cause {
    Cause {
        value: CauseValue::RequestAccepted,
    }
}

fn forwarding_action() -> ApplyAction {
    ApplyAction {
        drop: false,
        forward: true,
        buffer: false,
        notify_cp: false,
        duplicate: false,
        ip_masquerade: false,
        ip_masquerade_decap: false,
        dfrt: false,
        edrt: false,
        bdpn: false,
        ddpn: false,
        spare: 0,
    }
}

fn create_pdr_with_far(far_id: u32) -> CreatePdr {
    CreatePdr {
        members: vec![
            TypedIe::PdrId(PdrId { value: 1 }),
            TypedIe::Precedence(Precedence { value: 1 }),
            TypedIe::Pdi(Pdi {
                members: vec![
                    TypedIe::SourceInterface(SourceInterface { value: 0, spare: 0 }),
                    TypedIe::NetworkInstance(NetworkInstance {
                        value: b"internet".to_vec(),
                    }),
                ],
            }),
            TypedIe::FarId(FarId { value: far_id }),
        ],
    }
}

fn create_far(far_id: u32) -> CreateFar {
    CreateFar {
        members: vec![
            TypedIe::FarId(FarId { value: far_id }),
            TypedIe::ApplyAction(forwarding_action()),
            TypedIe::ForwardingParameters(ForwardingParameters {
                members: vec![TypedIe::DestinationInterface(DestinationInterface {
                    value: 0,
                    spare: 0,
                })],
            }),
        ],
    }
}

fn encode_decode_validate(message: OwnedMessage) -> OwnedMessage {
    message
        .validate_production_v1(DecodeContext::default())
        .expect("builder returns profile-valid message");

    let mut encoded = BytesMut::new();
    message
        .encode(&mut encoded, EncodeContext::default())
        .expect("profile message encodes");

    let decoded = OwnedMessage::decode_owned(encoded.freeze(), DecodeContext::default())
        .expect("profile message decodes");
    decoded
        .validate_production_v1(DecodeContext::default())
        .expect("decoded message remains profile-valid");
    decoded
}

#[test]
fn association_setup_profile_uses_typed_constructor_only() {
    let message = association_setup_request(1, node_id(), recovery_time_stamp())
        .expect("association setup request builds");

    let decoded = encode_decode_validate(message);
    assert_eq!(decoded.ies.len(), 2);
}

#[test]
fn session_establishment_profile_uses_typed_constructor_only() {
    let message =
        session_establishment_request(2, 10, cp_fseid(), create_pdr_with_far(7), create_far(7))
            .expect("session establishment request builds");

    let decoded = encode_decode_validate(message);
    assert_eq!(decoded.ies.len(), 3);
}

#[test]
fn session_report_profile_requires_usage_report_when_flagged() {
    let report_type = ReportType {
        downlink_data_report: false,
        usage_report: true,
        error_indication_report: false,
        user_plane_inactivity_report: false,
        tsc_management_info_report: false,
        session_report: false,
        up_initiated_session_request: false,
    };
    let usage_report = UsageReport {
        members: vec![
            TypedIe::UrSeqn(UrSeqn { value: 1 }),
            TypedIe::Cause(accepted_cause()),
        ],
    };

    let message = session_report_request_with_report_type(3, 10, report_type, vec![usage_report])
        .expect("session report request builds");

    let decoded = encode_decode_validate(message);
    assert_eq!(decoded.ies.len(), 2);
}
