use opc_proto_gtpu::{GtpuControlCodecErrorCode, GtpuControlMessage};
use opc_protocol::{DecodeContext, EncodeContext};

#[test]
fn tunnel_status_with_spoc_decodes_and_encodes_spec_bytes() {
    let wire = [0x30, 253, 0, 4, 0, 0, 0x10, 1, 230, 0, 1, 1];
    let value = GtpuControlMessage::decode_datagram(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.message_type(), 253);
    assert_eq!(value.sequence_number(), None);
    assert_eq!(
        value.to_bytes(EncodeContext::default()).unwrap().as_ref(),
        wire
    );
}

#[test]
fn tunnel_status_requires_its_ie_and_zero_s_flag() {
    let missing = [0x30, 253, 0, 0, 0, 0, 0x10, 1];
    assert_eq!(
        GtpuControlMessage::decode_datagram(&missing, DecodeContext::default())
            .unwrap_err()
            .code(),
        &GtpuControlCodecErrorCode::MissingMandatoryIe { ie_type: 230 }
    );
    let wrong_s = [0x32, 253, 0, 8, 0, 0, 0x10, 1, 0, 1, 0, 0, 230, 0, 1, 1];
    assert_eq!(
        GtpuControlMessage::decode_datagram(&wrong_s, DecodeContext::default())
            .unwrap_err()
            .code(),
        &GtpuControlCodecErrorCode::InvalidHeaderFlags
    );
}

#[test]
fn tunnel_status_builder_and_receiver_spares_are_explicit() {
    use bytes::Bytes;
    use opc_proto_gtpu::{
        GtpuPrivateExtension, GtpuTunnelEndpointId, GtpuTunnelStatus, GtpuTunnelStatusInformation,
    };
    let mut status = GtpuTunnelStatus::new(
        GtpuTunnelEndpointId::new(0x1001),
        GtpuTunnelStatusInformation::new(true),
    );
    status.push_private_extension(GtpuPrivateExtension::new(1, Bytes::from_static(&[0xaa])));
    status.push_private_extension(GtpuPrivateExtension::new(2, Bytes::new()));
    let message = GtpuControlMessage::TunnelStatus(status);
    let wire = [
        0x30, 253, 0, 15, 0, 0, 0x10, 1, 230, 0, 1, 1, 255, 0, 3, 0, 1, 0xaa, 255, 0, 2, 0, 2,
    ];
    assert_eq!(
        message.to_bytes(EncodeContext::default()).unwrap().as_ref(),
        wire
    );
    assert_eq!(
        GtpuControlMessage::decode_datagram(&wire, DecodeContext::default()).unwrap(),
        message
    );
    for flags in 0..=255u8 {
        let wire = [0x30, 253, 0, 5, 0, 0, 0x10, 1, 230, 0, 2, flags, 0xaa];
        let message = GtpuControlMessage::decode_datagram(&wire, DecodeContext::default()).unwrap();
        let GtpuControlMessage::TunnelStatus(status) = &message else {
            panic!()
        };
        assert_eq!(status.teid().value(), 0x1001);
        let info = status.tunnel_status_information();
        assert_eq!(info.spoc(), flags & 1 != 0);
        assert_eq!(info.received_spare(), flags & 0xfe);
        assert_eq!(info.additional_data(), &[0xaa]);
        let mut canonical = wire;
        canonical[11] &= 1;
        assert_eq!(
            message.to_bytes(EncodeContext::default()).unwrap().as_ref(),
            canonical
        );
        assert!(!format!("{message:?}").contains("4097"));
    }
}

#[test]
fn tunnel_status_rejects_empty_and_truncated_values_but_uses_first_repeat() {
    for (wire, expected) in [
        (
            vec![0x30, 253, 0, 3, 0, 0, 0, 1, 230, 0, 0],
            GtpuControlCodecErrorCode::InvalidIeLength { ie_type: 230 },
        ),
        (
            vec![0x30, 253, 0, 3, 0, 0, 0, 1, 230, 0, 1],
            GtpuControlCodecErrorCode::TruncatedIe,
        ),
    ] {
        assert_eq!(
            GtpuControlMessage::decode_datagram(&wire, DecodeContext::default())
                .unwrap_err()
                .code(),
            &expected
        );
    }
    let repeated = [0x30, 253, 0, 8, 0, 0, 0, 1, 230, 0, 1, 1, 230, 0, 1, 0];
    let actual = GtpuControlMessage::decode_datagram(&repeated, DecodeContext::default()).unwrap();
    let first = [0x30, 253, 0, 4, 0, 0, 0, 1, 230, 0, 1, 1];
    assert_eq!(
        actual.to_bytes(EncodeContext::default()).unwrap().as_ref(),
        first
    );
}
