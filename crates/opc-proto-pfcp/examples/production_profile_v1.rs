use bytes::BytesMut;
use opc_proto_pfcp::ie::{
    ApplyAction, CreateFar, CreatePdr, DestinationInterface, FSeid, FarId, ForwardingParameters,
    NetworkInstance, NodeId, NodeIdType, Pdi, PdrId, Precedence, RecoveryTimeStamp,
    SourceInterface, TypedIe,
};
use opc_proto_pfcp::{association_setup_request, session_establishment_request, OwnedMessage};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let association_setup = association_setup_request(
        1,
        NodeId {
            node_id_type: NodeIdType::Fqdn,
            value: b"upf.local".to_vec(),
        },
        RecoveryTimeStamp { seconds: 42 },
    )?;
    round_trip_profile_message(association_setup)?;

    let session_establishment = session_establishment_request(
        2,
        10,
        FSeid {
            v4: true,
            v6: false,
            seid: 1,
            ipv4: Some([127, 0, 0, 1]),
            ipv6: None,
        },
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
                TypedIe::FarId(FarId { value: 7 }),
            ],
        },
        CreateFar {
            members: vec![
                TypedIe::FarId(FarId { value: 7 }),
                TypedIe::ApplyAction(ApplyAction {
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
                }),
                TypedIe::ForwardingParameters(ForwardingParameters {
                    members: vec![TypedIe::DestinationInterface(DestinationInterface {
                        value: 0,
                        spare: 0,
                    })],
                }),
            ],
        },
    )?;
    round_trip_profile_message(session_establishment)?;

    Ok(())
}

fn round_trip_profile_message(
    message: OwnedMessage,
) -> Result<OwnedMessage, Box<dyn std::error::Error>> {
    message.validate_production_v1(DecodeContext::default())?;

    let mut encoded = BytesMut::new();
    message.encode(&mut encoded, EncodeContext::default())?;

    let decoded = OwnedMessage::decode_owned(encoded.freeze(), DecodeContext::default())?;
    decoded.validate_production_v1(DecodeContext::default())?;
    Ok(decoded)
}
