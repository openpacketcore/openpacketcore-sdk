//! Shared UE request fuzz/replay assertions over synthetic inputs.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::ue_requests::{ContextReleaseSessions, UeRequestMessage};
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_ies: 256,
        ..ctx
    };
    if let Ok(value) = ContextReleaseSessions::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ContextReleaseSessions::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(admitted) = UeRequestMessage::from_pdu(&pdu, ctx) else {
        return;
    };
    let constructed = admitted.message.construct(ctx).unwrap();
    let wire = encode(&constructed, output).unwrap();
    let pdu = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
    let readmitted = UeRequestMessage::from_pdu(&pdu, ctx).unwrap();
    assert!(readmitted.notify_ie_ids.is_empty());
    assert_eq!(readmitted.ignored_ie_count, 0);
    match (&admitted.message, &readmitted.message) {
        (UeRequestMessage::NasNonDelivery(a), UeRequestMessage::NasNonDelivery(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran && a.cause == b.cause);
            assert!(a.nas.as_bytes() == b.nas.as_bytes());
        }
        (UeRequestMessage::ContextRelease(a), UeRequestMessage::ContextRelease(b)) => {
            assert!(a == b)
        }
        _ => panic!("ue request procedure changed"),
    }
}
