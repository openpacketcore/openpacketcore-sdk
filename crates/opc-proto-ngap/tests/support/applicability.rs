//! Shared bounded routing replay and fuzz assertions; bodies stay opaque.
use opc_proto_ngap::n3iwf::applicability::{
    inspect, Endpoint, ReceiveDisposition, TriggerGate, UnsupportedAction,
};
use opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics;
use opc_protocol::{DecodeContext, EncodeContext};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    for (receiver, sender) in [
        (Endpoint::N3iwf, Endpoint::Amf),
        (Endpoint::Amf, Endpoint::N3iwf),
    ] {
        let Ok(value) = inspect(data, receiver, ctx) else {
            continue;
        };
        match value {
            ReceiveDisposition::Qualified(message) => {
                assert_eq!(
                    message.local_trigger(sender),
                    TriggerGate::CodecAvailable(message.rule().codec.unwrap())
                );
            }
            ReceiveDisposition::HandlerRequired(message) => {
                assert!(message.rule().codec.is_none());
                assert_eq!(
                    message.local_trigger(sender),
                    TriggerGate::DisabledPendingHandler
                );
            }
            ReceiveDisposition::Unsupported(value) => {
                if let Some(d) = value.diagnostics() {
                    assert_ne!(value.action(), UnsupportedAction::Ignore);
                    assert!(
                        d.procedure_code.is_some()
                            && d.triggering_outcome.is_some()
                            && d.procedure_criticality.is_some()
                            && d.ies.is_none()
                    );
                    let encoded = d.encode(output).unwrap();
                    assert!(
                        CriticalityDiagnostics::decode(
                            encoded.as_bytes(),
                            DecodeContext {
                                max_depth: 2,
                                max_ies: 0,
                                ..ctx
                            }
                        )
                        .unwrap()
                            == d
                    );
                } else {
                    assert_eq!(value.action(), UnsupportedAction::Ignore);
                }
            }
        }
        assert_eq!(
            inspect(
                data,
                receiver,
                DecodeContext {
                    max_message_len: data.len(),
                    max_depth: 3,
                    ..ctx
                }
            )
            .unwrap(),
            value
        );
        assert!(inspect(
            data,
            receiver,
            DecodeContext {
                max_message_len: data.len() - 1,
                ..ctx
            }
        )
        .is_err());
    }
}
