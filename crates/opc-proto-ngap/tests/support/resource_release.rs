//! Shared bounded release fuzz/replay assertions over synthetic inputs.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::resource_release::{
    ReleaseCommandTransfer, ReleaseResponseTransfer, ReleasedSessions, ResourceReleaseMessage,
    SessionReleaseRequests,
};
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 256,
        ..ctx
    };
    if let Ok(value) = ReleaseCommandTransfer::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ReleaseCommandTransfer::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = ReleaseResponseTransfer::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ReleaseResponseTransfer::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = SessionReleaseRequests::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(SessionReleaseRequests::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = ReleasedSessions::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ReleasedSessions::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(admitted) = ResourceReleaseMessage::from_pdu(&pdu, ctx) else {
        return;
    };
    let constructed = admitted.message.construct(ctx).unwrap();
    let wire = encode(&constructed, output).unwrap();
    let pdu = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
    let readmitted = ResourceReleaseMessage::from_pdu(&pdu, ctx).unwrap();
    assert!(readmitted.notify_ie_ids.is_empty());
    assert_eq!(readmitted.ignored_ie_count, 0);
    match (&admitted.message, &readmitted.message) {
        (ResourceReleaseMessage::Command(a), ResourceReleaseMessage::Command(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran && a.sessions == b.sessions);
            assert!(a.nas.as_ref().map(|v| v.as_bytes()) == b.nas.as_ref().map(|v| v.as_bytes()));
        }
        (ResourceReleaseMessage::Response(a), ResourceReleaseMessage::Response(b)) => {
            assert!(a == b)
        }
        _ => panic!("resource release outcome changed"),
    }
}
