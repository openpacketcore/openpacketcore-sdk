//! Shared bounded release-session replay and fuzz checks, with no value dumps.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::ReleaseMessage;
use opc_proto_ngap::n3iwf::release_sessions::ContextReleasedSessions;
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: 16,
        max_ies: 256,
        ..ctx
    };
    if let Ok(value) = ContextReleasedSessions::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ContextReleasedSessions::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(value) = ReleaseMessage::from_pdu(&pdu, ctx) else {
        return;
    };
    let ReleaseMessage::Complete {
        sessions: before, ..
    } = &value.message
    else {
        return;
    };
    let wire = encode(&value.message.construct(ctx).unwrap(), output).unwrap();
    let next = Pdu::decode_owned(Bytes::from(wire.clone()), ctx).unwrap();
    let admitted = ReleaseMessage::from_pdu(&next, ctx).unwrap();
    let ReleaseMessage::Complete {
        sessions: after, ..
    } = &admitted.message
    else {
        panic!("release outcome changed")
    };
    assert!(before == after);
    assert!(admitted.ignored_ie_count == 0 && admitted.notify_ie_ids.is_empty());
    assert!(encode(&admitted.message.construct(ctx).unwrap(), output).unwrap() == wire);
}
