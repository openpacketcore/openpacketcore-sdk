use opc_proto_pfcp::{ie::TypedIe, IeType};
use opc_protocol::DecodeContext;

#[test]
fn public_type_constants_address_the_registry_and_typed_timer() {
    // TS 29.244 Table 8.1.2-1: public constructors can name the assigned IEs.
    for (kind, wire) in [
        (IeType::NodeReportType, &[0, 101, 0, 1, 0][..]),
        (
            IeType::UserPlaneInactivityTimer,
            &[0, 117, 0, 4, 0, 0, 0, 60][..],
        ),
        (IeType::PfcpSessionChangeInfo, &[1, 34, 0, 0][..]),
    ] {
        let (_, decoded) = TypedIe::decode(wire, DecodeContext::default(), 0).unwrap();
        assert_eq!(decoded.ie_type(), kind as u16);
        if let TypedIe::UserPlaneInactivityTimer(timer) = decoded {
            assert_eq!(timer.seconds, 60);
        }
    }
}
