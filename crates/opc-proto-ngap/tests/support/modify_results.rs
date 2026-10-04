//! Shared Modify result transfer fuzz/replay assertions.
use opc_proto_ngap::n3iwf::modify_results::{ModifyFailureTransfer, ModifyResponseTransfer};
use opc_protocol::{DecodeContext, EncodeContext};
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 320,
        max_depth: 8,
        ..ctx
    };
    macro_rules! transfer {
        ($ty:ty) => {
            if let Ok(value) = <$ty>::decode(data, ctx) {
                let wire = value.encode(output).unwrap();
                assert!(<$ty>::decode(wire.as_bytes(), ctx).unwrap() == value);
            }
        };
    }
    transfer!(ModifyResponseTransfer);
    transfer!(ModifyFailureTransfer);
}
