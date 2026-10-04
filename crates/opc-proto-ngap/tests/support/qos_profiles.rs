//! Shared bounded fuzz/replay for independently qualified QoS roots.
use opc_proto_ngap::n3iwf::{
    modify_fields::QosFlowModifications, qos_fields::QosParameters,
    resource_fields::QosFlowSetupList,
};
use opc_protocol::{DecodeContext, EncodeContext};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: 7,
        max_ies: 64,
        ..ctx
    };
    macro_rules! field {
        ($ty:ty) => {
            if let Ok(value) = <$ty>::decode(data, ctx) {
                let wire = value.encode(output).unwrap();
                assert!(<$ty>::decode(wire.as_bytes(), ctx).unwrap() == value);
            }
        };
    }
    field!(QosParameters);
    field!(QosFlowSetupList);
    field!(QosFlowModifications);
}
