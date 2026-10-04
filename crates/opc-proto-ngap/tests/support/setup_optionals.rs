use opc_proto_ngap::n3iwf::setup::*;
use opc_proto_ngap::{decode, encode};
use opc_protocol::{DecodeContext, EncodeContext};

fn served(value: &ServedGuamiList) -> ServedGuamiList {
    ServedGuamiList::with_backups(
        value
            .entries()
            .map(|(id, name)| {
                (
                    Guami::new(id.plmn().clone(), id.region(), id.set(), id.pointer()).unwrap(),
                    name.map(|v| AmfName::new(v.as_str()).unwrap()),
                )
            })
            .collect(),
    )
    .unwrap()
}

/// Reconstruct new fields from semantic accessors before canonical encoding.
pub fn reconstruct(message: &mut SetupMessage) {
    match message {
        SetupMessage::Request(value) => {
            value.node_name = value
                .node_name
                .as_ref()
                .map(|v| RanNodeName::new(v.as_str()).unwrap());
            value.extended_node_name = value
                .extended_node_name
                .as_ref()
                .map(|v| ExtendedRanNodeName::new(v.visible(), v.utf8()).unwrap());
        }
        SetupMessage::Response(value) => {
            value.served = served(&value.served);
            value.extended_name = value
                .extended_name
                .as_ref()
                .map(|v| ExtendedAmfName::new(v.visible(), v.utf8()).unwrap());
        }
        SetupMessage::Failure(_) => (),
    }
}

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = RanNodeName::decode(data, ctx) {
        let rebuilt = RanNodeName::new(value.as_str()).unwrap();
        let wire = rebuilt.encode(output).unwrap();
        assert!(RanNodeName::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = ExtendedRanNodeName::decode(data, ctx) {
        let rebuilt = ExtendedRanNodeName::new(value.visible(), value.utf8()).unwrap();
        let wire = rebuilt.encode(output).unwrap();
        assert!(ExtendedRanNodeName::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = UeRetentionInformation::decode(data, ctx) {
        let wire = value.encode(output).unwrap();
        assert!(UeRetentionInformation::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = ServedGuamiList::decode(data, ctx) {
        let wire = served(&value).encode(output).unwrap();
        assert!(ServedGuamiList::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(pdu) = decode(data, ctx) {
        if let Ok(admitted) = SetupMessage::from_pdu(&pdu, ctx) {
            let mut rebuilt = admitted.message.clone();
            reconstruct(&mut rebuilt);
            assert!(rebuilt == admitted.message);
            let pdu = match &rebuilt {
                SetupMessage::Request(value) => value.construct(PagingDrx::v128, ctx),
                SetupMessage::Response(value) => value.construct(ctx),
                SetupMessage::Failure(value) => value.construct(ctx),
            }
            .unwrap();
            let wire = encode(&pdu, output).unwrap();
            let readmitted = SetupMessage::from_pdu(&decode(&wire, ctx).unwrap(), ctx).unwrap();
            assert!(readmitted.message == admitted.message);
            assert!(readmitted.notify_ie_ids.is_empty());
        }
    }
}
