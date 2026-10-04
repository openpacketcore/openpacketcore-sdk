//! Shared bounded replay of caller-classified Setup admission.
use opc_proto_ngap::n3iwf::{
    context_fields::SecurityAlgorithmMasks,
    qos_fields::{QosResourceType, QosResourceTypes},
    resource_fields::QosFlowId,
    resource_request::SetupRequestTransfer,
    resource_setup::ResourceSetupMessage,
    session_lists::{SessionId, SessionResourceTypes},
};
use opc_proto_ngap::{decode, encode};
use opc_protocol::{DecodeContext, EncodeContext};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: ctx.max_depth.min(18),
        max_ies: ctx.max_ies.min(64),
        ..ctx
    };
    let pdu = decode(data, ctx).ok();
    for count in [1, 2, 3, 64] {
        // Synthetic caller policies, independent of GBR field presence.
        let types = QosResourceTypes::new(
            (0..count).map(|qfi| (QosFlowId::new(qfi).unwrap(), QosResourceType::Gbr)),
        )
        .unwrap();
        if let Ok(value) = SetupRequestTransfer::decode_classified(data, &types, ctx) {
            let raw = value.transfer.encode_classified(&types, output).unwrap();
            assert!(
                SetupRequestTransfer::decode_classified(raw.as_bytes(), &types, ctx)
                    .unwrap()
                    .transfer
                    == value.transfer
            );
        }
        let sessions = SessionResourceTypes::new(vec![
            (SessionId::new(1), types),
            (
                SessionId::new(255),
                QosResourceTypes::new([(QosFlowId::new(0).unwrap(), QosResourceType::NonGbr)])
                    .unwrap(),
            ),
        ])
        .unwrap();
        let Some(pdu) = &pdu else { continue };
        if let Ok(admitted) = ResourceSetupMessage::from_pdu_classified(pdu, &sessions, ctx) {
            let constructed = match admitted.message {
                ResourceSetupMessage::InitialRequest(value) => value.construct_classified(
                    SecurityAlgorithmMasks::new(0, 0, 0, 0),
                    &sessions,
                    ctx,
                ),
                ResourceSetupMessage::SessionRequest(value) => {
                    value.construct_classified(&sessions, ctx)
                }
                _ => panic!("classified non-request"),
            }
            .unwrap();
            let raw = encode(&constructed, output).unwrap();
            let decoded = decode(&raw, ctx).unwrap();
            assert!(ResourceSetupMessage::from_pdu_classified(&decoded, &sessions, ctx).is_ok());
        }
    }
}
