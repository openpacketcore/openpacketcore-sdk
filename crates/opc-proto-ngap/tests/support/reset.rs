//! Shared bounded Reset/Error field and message fuzz/replay assertions.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::reset::{ResetMessage, Signalling};
use opc_proto_ngap::n3iwf::reset_fields::{Connections, CriticalityDiagnostics, ResetType};
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    // Fuzz limits are caller policy, not the connection list's ASN.1 maximum.
    // Independent ordinary tests separately qualify the full 65536-item root.
    let ctx = DecodeContext {
        max_ies: 256,
        ..ctx
    };
    if let Ok(value) = Connections::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(Connections::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = ResetType::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(ResetType::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = CriticalityDiagnostics::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(CriticalityDiagnostics::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    for signalling in [Signalling::NonUe, Signalling::UeAssociated] {
        let Ok(admitted) = ResetMessage::from_pdu(&pdu, signalling, ctx) else {
            continue;
        };
        let constructed = admitted.message.construct(signalling, ctx).unwrap();
        let wire = encode(&constructed, output).unwrap();
        let pdu = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
        let readmitted = ResetMessage::from_pdu(&pdu, signalling, ctx).unwrap();
        assert!(readmitted.message == admitted.message);
        assert_eq!(
            readmitted.ignored_empty_connection_count,
            admitted.ignored_empty_connection_count
        );
        assert_eq!(readmitted.ignored_ie_count, 0);
        assert!(readmitted.notify_ie_ids.is_empty());
    }
}
