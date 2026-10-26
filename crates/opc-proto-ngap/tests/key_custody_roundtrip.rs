//! The typed view must retain the same SecurityKey as the received wire.
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{DecodeContext, EncodeContext};

#[test]
fn rebuilding_the_typed_view_preserves_the_security_key() {
    let key = [0xab; 32];
    let original = Pdu::from_protocol_ies(
        MessageType::InitialContextSetupRequest,
        &[ProtocolIe::new(94, Criticality::reject, &key)],
        DecodeContext::default(),
    )
    .unwrap();
    let wire = encode(&original, EncodeContext::default()).unwrap();
    let decoded = decode(&wire, DecodeContext::default()).unwrap();
    let PduKind::Initiating {
        message: Message::InitialContextSetupRequest(request),
        ..
    } = &decoded.kind
    else {
        panic!("wrong message");
    };
    let ie = &request.protocol_ies.0[0];
    assert_eq!(ie.id, 94);
    assert_eq!(ie.criticality as u8, Criticality::reject as u8);
    assert_eq!(ie.value.as_bytes(), &key);
    let rebuilt = Pdu::from_protocol_ies(
        MessageType::InitialContextSetupRequest,
        &[ProtocolIe::new(
            ie.id,
            Criticality::reject,
            ie.value.as_bytes(),
        )],
        DecodeContext::default(),
    )
    .unwrap();
    assert_eq!(encode(&rebuilt, EncodeContext::default()).unwrap(), wire);
}
