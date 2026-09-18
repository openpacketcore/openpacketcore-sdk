//! Shared bounded Modify list/message replay and fuzz assertions.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::modify::ModifyMessage;
use opc_proto_ngap::n3iwf::modify_lists::{
    FailedModifications, ModifiedSessions, SessionModifications,
};
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: 20,
        max_ies: 256,
        ..ctx
    };
    if let Ok(value) = SessionModifications::decode(data, ctx) {
        let wire = value.requests.encode(output).unwrap();
        let next = SessionModifications::decode(wire.as_bytes(), ctx).unwrap();
        assert!(next.requests.encode(output).unwrap().as_bytes() == wire.as_bytes());
    }
    macro_rules! list {
        ($ty:ty) => {
            if let Ok(value) = <$ty>::decode(data, ctx) {
                let wire = value.encode(output).unwrap();
                assert!(<$ty>::decode(wire.as_bytes(), ctx).unwrap() == value);
            }
        };
    }
    list!(ModifiedSessions);
    list!(FailedModifications);
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(value) = ModifyMessage::from_pdu(&pdu, ctx) else {
        return;
    };
    let constructed = match value.message {
        ModifyMessage::Request(v) => v.construct(ctx),
        ModifyMessage::Response(v) => v.construct(ctx),
    }
    .unwrap();
    let wire = encode(&constructed, output).unwrap();
    let decoded = Pdu::decode_owned(Bytes::from(wire.clone()), ctx).unwrap();
    let next = ModifyMessage::from_pdu(&decoded, ctx).unwrap();
    let rebuilt = match next.message {
        ModifyMessage::Request(v) => v.construct(ctx),
        ModifyMessage::Response(v) => v.construct(ctx),
    }
    .unwrap();
    assert!(encode(&rebuilt, output).unwrap() == wire);
}
