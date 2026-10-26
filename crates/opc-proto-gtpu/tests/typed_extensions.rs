use opc_proto_gtpu::{GtpuExtensionHeaderType, GtpuMessage};
use opc_protocol::{BorrowDecode, DecodeContext, UnknownIePolicy};

#[test]
fn standardized_fixed_and_opaque_extension_types_are_supported() {
    for kind in [0xc0, 0x03, 0x82, 0x20, 0x81, 0x83, 0x84] {
        assert!(
            GtpuExtensionHeaderType::new(kind).is_supported_by_codec(),
            "type {kind:#x}"
        );
    }
    assert!(!GtpuExtensionHeaderType::new(0xc4).is_supported_by_codec());
}

#[test]
fn short_pdcp_followed_by_psc_decodes_but_unknown_required_still_fails() {
    let mut wire = [
        0x34, 255, 0, 13, 0, 0, 0, 1, 0, 0, 0, 0xc0, 1, 0x01, 0x23, 0x85, 1, 0, 9, 0, 0x45,
    ];
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    let (_, message) = GtpuMessage::decode(&wire, ctx).unwrap();
    let headers: Vec<_> = message.extensions().map(Result::unwrap).collect();
    assert_eq!(headers.len(), 2);
    use opc_proto_gtpu::GtpuTypedExtension as E;
    assert_eq!(
        E::decode(&headers[0]).unwrap(),
        Some(E::PdcpPduNumber(0x123))
    );
    assert_eq!(
        E::decode(&headers[1]).unwrap(),
        Some(E::PduSessionContainer(
            opc_proto_gtpu::PduSessionContainer::new_downlink(9, None, false).unwrap()
        ))
    );
    wire[11] = 0xc4;
    assert!(GtpuMessage::decode(&wire, ctx).is_err());
}

#[test]
fn fixed_and_opaque_extensions_match_independent_golden_bytes() {
    use opc_proto_gtpu::{GtpuExtensionHeaderIterator, GtpuTypedExtension as E};
    for (value, golden) in [
        (E::UdpPort(2152), vec![1, 8, 0x68, 0]),
        (E::PdcpPduNumber(0x1234), vec![1, 0x12, 0x34, 0]),
        (
            E::LongPdcpPduNumber(0x23456),
            vec![2, 2, 0x34, 0x56, 0, 0, 0, 0],
        ),
        (
            E::LegacyLongPdcpPduNumber(0x23456),
            vec![2, 2, 0x34, 0x56, 0, 0, 0, 0],
        ),
        (E::ServiceClassIndicator(31), vec![1, 31, 0, 0]),
        (E::RanContainer(&[1, 2]), vec![1, 1, 2, 0]),
        (
            E::XwRanContainer(&[1, 2, 3, 4, 5, 6]),
            vec![2, 1, 2, 3, 4, 5, 6, 0],
        ),
        (E::NrRanContainer(&[1, 2]), vec![1, 1, 2, 0]),
    ] {
        let encoded = value.encode(0).unwrap();
        assert_eq!(encoded.as_ref(), golden);
        let header = GtpuExtensionHeaderIterator::new(&golden, value.extension_type())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(E::decode(&header).unwrap(), Some(value.clone()));
        let mut chained = golden;
        *chained.last_mut().unwrap() = 0x85;
        assert_eq!(value.encode(0x85).unwrap().as_ref(), chained);
    }
}

#[test]
fn extension_value_bounds_spares_and_lengths_are_checked() {
    use opc_proto_gtpu::{GtpuExtensionHeader as H, GtpuTypedExtension as E};
    for kind in [0x03, 0x82] {
        let header = H {
            ext_type: kind,
            content: &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            next_ext_type: 0,
        };
        let decoded = E::decode(&header).unwrap().unwrap();
        assert_eq!(
            decoded.encode(0).unwrap().as_ref(),
            &[2, 3, 0xff, 0xff, 0, 0, 0, 0]
        );
    }
    let sci = E::decode(&H {
        ext_type: 0x20,
        content: &[7, 0xff],
        next_ext_type: 0,
    })
    .unwrap()
    .unwrap();
    assert_eq!(sci.encode(0).unwrap().as_ref(), &[1, 7, 0, 0]);
    assert!(E::LongPdcpPduNumber(0x40000).encode(0).is_err());
    assert!(E::LegacyLongPdcpPduNumber(u32::MAX).encode(0).is_err());
    for sci in 32..=255 {
        let bytes = [sci, 0];
        let decoded = E::decode(&H {
            ext_type: 0x20,
            content: &bytes,
            next_ext_type: 0,
        })
        .unwrap()
        .unwrap();
        assert!(decoded.encode(0).is_err());
    }
    for kind in [0x03, 0x82, 0x20, 0x40, 0xc0, 0x81, 0x83, 0x84] {
        for len in [0, 1, 3, 5, 7, 1019, 1022] {
            let bytes = vec![0; len];
            assert!(E::decode(&H {
                ext_type: kind,
                content: &bytes,
                next_ext_type: 0
            })
            .is_err());
        }
    }
    for len in [0, 1, 3, 1019, 1022] {
        assert!(E::RanContainer(&vec![0; len]).encode(0).is_err());
    }
    assert_eq!(
        E::NrRanContainer(&vec![0; 1018]).encode(0).unwrap().len(),
        1020
    );
    assert_eq!(
        E::decode(&H {
            ext_type: 0xc4,
            content: &[0, 0],
            next_ext_type: 0
        })
        .unwrap(),
        None
    );
}

#[test]
fn procedure_validation_and_comprehension_scan_reject_malformed_known_lengths() {
    use opc_proto_gtpu::GtpuExtensionHeaderRecipient;
    use opc_protocol::ValidationLevel;
    for kind in [0x03, 0x82, 0x20, 0x40, 0xc0] {
        let mut wire = vec![
            0x34, 255, 0, 12, 0, 0, 0, 1, 0, 0, 0, kind, 2, 0, 0, 0, 0, 0, 0, 0,
        ];
        if matches!(kind, 0x03 | 0x82) {
            wire.truncate(16);
            wire[3] = 8;
            wire[12] = 1;
        }
        let (_, raw) = GtpuMessage::decode(&wire, DecodeContext::default()).unwrap();
        assert!(raw
            .first_unsupported_required_extension(GtpuExtensionHeaderRecipient::Endpoint)
            .is_err());
        let ctx = DecodeContext {
            validation_level: ValidationLevel::ProcedureAware,
            ..DecodeContext::default()
        };
        assert!(GtpuMessage::decode(&wire, ctx).is_err());
    }
}
