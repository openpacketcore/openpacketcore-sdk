//! Shared Notify field/message fuzz and corpus-replay assertions.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::notify::ResourceNotify;
use opc_proto_ngap::n3iwf::notify_fields::{
    NotifiedSessions, NotifyReleasedTransfer, NotifyTransfer, ReleasedSessions,
};
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 256,
        max_depth: 16,
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
    field!(NotifyTransfer);
    field!(NotifyReleasedTransfer);
    field!(NotifiedSessions);
    field!(ReleasedSessions);
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(admitted) = ResourceNotify::from_pdu(&pdu, ctx) else {
        return;
    };
    let constructed = admitted.message.construct(ctx).unwrap();
    let wire = encode(&constructed, output).unwrap();
    let pdu = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
    let next = ResourceNotify::from_pdu(&pdu, ctx).unwrap();
    assert!(next.message == admitted.message);
    assert_eq!(next.ignored_ie_count, 0);
    assert!(next.notify_ie_ids.is_empty());
}
