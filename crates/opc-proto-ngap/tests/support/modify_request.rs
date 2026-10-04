//! Shared Modify Request Transfer fuzz/replay assertions.
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_protocol::{DecodeContext, EncodeContext};
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 64,
        max_depth: 10,
        ..ctx
    };
    if let Ok(value) = ModifyRequestTransfer::decode(data, ctx) {
        let wire = value.transfer.encode(output).unwrap();
        let canonical = ModifyRequestTransfer::decode(wire.as_bytes(), ctx).unwrap();
        assert!(canonical.transfer == value.transfer);
        assert_eq!(canonical.ignored_ie_count, 0);
        assert!(canonical.notify_ie_ids.is_empty());
    }
}
