//! Shared Modify field fuzz/replay assertions.
use opc_proto_ngap::n3iwf::modify_fields::{
    ModifiedQosFlows, QosFlowCauses, QosFlowModifications, UplinkModifications,
};
use opc_protocol::{DecodeContext, EncodeContext};
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 64,
        max_depth: 6,
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
    field!(QosFlowModifications);
    field!(ModifiedQosFlows);
    field!(QosFlowCauses);
    field!(UplinkModifications);
}
