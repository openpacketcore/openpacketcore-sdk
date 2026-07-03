use bytes::{Bytes, BytesMut};
use opc_proto_gtpu::{
    GtpuExtensionChain, GtpuExtensionChainError, GtpuExtensionChainMalformedReason, GtpuHeader,
    GtpuMessage, OwnedGtpuMessage, PduSessionContainer, GTPU_EXT_PDU_SESSION_CONTAINER,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, OwnedDecode,
    UnknownIePolicy, ValidationLevel,
};

// Helper to construct a basic valid packet
fn make_basic_packet(payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![
        0x30, // Version=1, PT=1, E=0, S=0, PN=0
        0xFF, // Msg Type = 255 (G-PDU)
        0x00, 0x00, // Length (will fill)
        0x12, 0x34, 0x56, 0x78, // TEID
    ];
    let len = payload_len;
    pkt[2] = ((len >> 8) & 0xFF) as u8;
    pkt[3] = (len & 0xFF) as u8;
    pkt.extend(vec![0xAA; payload_len]);
    pkt
}

#[test]
fn test_decode_basic_valid() {
    let raw = make_basic_packet(10);
    let ctx = DecodeContext::default();
    let (tail, msg) = GtpuMessage::decode(&raw, ctx).expect("failed to decode");

    assert!(tail.is_empty());
    assert_eq!(msg.header.version, 1);
    assert!(msg.header.protocol_type);
    assert_eq!(msg.header.message_type, 255);
    assert_eq!(msg.header.teid, 0x12345678);
    assert_eq!(msg.header.length, 10);
    assert_eq!(msg.payload.len(), 10);
    assert_eq!(msg.raw_extension_headers.len(), 0);
}

#[test]
fn test_decode_with_seq() {
    let raw = vec![
        0x32, // Version=1, PT=1, E=0, S=1, PN=0 (S flag set)
        0x01, // Msg Type = 1 (Echo Request)
        0x00, 0x04, // Length = 4 (Sequence number + NPDU + Next Ext)
        0x00, 0x00, 0x00, 0x00, // TEID = 0
        0x00, 0x2A, // Sequence Number = 42
        0x00, // N-PDU Number
        0x00, // Next Extension Header Type = 0
    ];
    let ctx = DecodeContext::default();
    let (tail, msg) = GtpuMessage::decode(&raw, ctx).expect("failed to decode");
    assert!(tail.is_empty());
    assert_eq!(msg.header.sequence_number, Some(42));
    assert_eq!(msg.header.npdu_number, None); // PN is 0, so npdu_number is None
    assert_eq!(msg.header.next_ext_type, Some(0));

    // Roundtrip encode
    let mut dst = BytesMut::new();
    msg.encode(&mut dst, EncodeContext::default())
        .expect("encode failed");
    assert_eq!(dst.to_vec(), raw);
}

#[test]
fn test_decode_with_extension_headers() {
    let raw = vec![
        0x36, // Version=1, PT=1, E=1, S=1, PN=0
        0xFF, // G-PDU
        0x00, 0x08, // Length = 8 (4 optional fields + 4 extension header bytes)
        0x11, 0x22, 0x33, 0x44, // TEID
        0x00, 0x05, // Seq = 5
        0x00, // NPDU
        0x85, // Next Ext = 0x85 (PDU Session Container)
        // Extension Header
        0x01, // Extension Length Units = 1 (4 octets)
        0x00, 0x09, // Content: DL PDU Type=0, QFI=9, PPI=None, RQI=false
        0x00, // Next Extension Header = 0 (ends)
    ];

    let ctx = DecodeContext::default();
    let (tail, msg) = GtpuMessage::decode(&raw, ctx).expect("failed to decode");
    assert!(tail.is_empty());
    assert_eq!(msg.header.next_ext_type, Some(0x85));
    assert_eq!(msg.raw_extension_headers.len(), 4);

    let exts: Result<Vec<_>, _> = msg.extensions().collect();
    let exts = exts.expect("failed to parse extensions");
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].ext_type, 0x85);
    assert_eq!(exts[0].next_ext_type, 0);

    let psc =
        PduSessionContainer::decode(&exts[0]).expect("failed to decode PDU session container");
    assert_eq!(psc.pdu_type, 0);
    assert_eq!(psc.qfi, 9);
    assert_eq!(psc.ppi, None);
    assert!(!psc.rqi);
}

#[test]
fn unknown_extension_header_reject_policy_fails_closed() {
    let raw = vec![
        0x36, // Version=1, PT=1, E=1, S=1, PN=0
        0xFF, // G-PDU
        0x00, 0x08, // Length = 8 (4 optional fields + 4 extension header bytes)
        0x11, 0x22, 0x33, 0x44, // TEID
        0x00, 0x05, // Seq = 5
        0x00, // NPDU
        0x84, // unsupported Next Ext
        0x01, // Extension Length Units = 1 (4 octets)
        0xAA, 0xBB, // Opaque extension content
        0x00, // Next Extension Header = 0 (ends)
    ];
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };

    let err = GtpuMessage::decode(&raw, ctx).unwrap_err();

    assert_eq!(err.code(), &DecodeErrorCode::UnknownCriticalIe);
}

#[test]
fn test_pdu_session_container_with_ppi() {
    let ext_content = vec![
        0x00,               // PDU Type = 0 (DL), Spare = 0
        0x80 | 0x40 | 0x0C, // PPP = 1, RQI = 1, QFI = 12
        0x05,               // PPI = 5
        0x00,
        0x00,
        0x00, // Padding to 6 content bytes (so total size of ext header is 8 octets)
    ];
    let ext = opc_proto_gtpu::GtpuExtensionHeader {
        ext_type: 0x85,
        content: &ext_content,
        next_ext_type: 0,
    };

    let psc = PduSessionContainer::decode(&ext).expect("failed to decode Paging Policy");
    assert_eq!(psc.pdu_type, 0);
    assert_eq!(psc.qfi, 12);
    assert_eq!(psc.ppi, Some(5));
    assert!(psc.rqi);

    // Roundtrip encode
    let encoded = psc.encode();
    assert_eq!(encoded, ext_content);
}

#[test]
fn extension_chain_summary_decodes_pdu_session_container_and_redacts_raw_debug() {
    let raw_headers = Bytes::from_static(&[0x01, 0x00, 0x09, 0x00]);

    let chain = match GtpuExtensionChain::from_raw(
        Some(GTPU_EXT_PDU_SESSION_CONTAINER),
        raw_headers.clone(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("extension chain summary failed: {error:?}"),
    };

    assert_eq!(
        chain.first_extension_type,
        Some(GTPU_EXT_PDU_SESSION_CONTAINER)
    );
    assert_eq!(chain.raw_headers, raw_headers);
    assert_eq!(chain.header_count, 1);
    assert_eq!(
        chain.pdu_session_container,
        Some(PduSessionContainer {
            pdu_type: 0,
            qfi: 9,
            ppi: None,
            rqi: false,
        })
    );
    assert!(chain.has_headers());
    assert!(chain.validate_consistency().is_ok());

    let debug = format!("{chain:?}");
    assert!(debug.contains("raw_headers_len"));
    assert!(!debug.contains("09, 00"));
}

#[test]
fn extension_chain_builder_emits_raw_headers_and_first_type() {
    let container = PduSessionContainer {
        pdu_type: 0,
        qfi: 12,
        ppi: Some(5),
        rqi: true,
    };

    let chain = match GtpuExtensionChain::from_pdu_session_container(container.clone()) {
        Ok(value) => value,
        Err(error) => panic!("extension chain build failed: {error:?}"),
    };

    assert_eq!(
        chain.first_extension_type,
        Some(GTPU_EXT_PDU_SESSION_CONTAINER)
    );
    assert_eq!(chain.header_count, 1);
    assert_eq!(chain.pdu_session_container, Some(container));
    assert_eq!(chain.raw_headers.as_ref()[0], 2);
    assert_eq!(chain.raw_headers.as_ref()[chain.raw_headers.len() - 1], 0);

    let reparsed =
        match GtpuExtensionChain::from_raw(chain.first_extension_type, chain.raw_headers.clone()) {
            Ok(value) => value,
            Err(error) => panic!("built extension chain did not reparse: {error:?}"),
        };
    assert_eq!(reparsed, chain);
}

#[test]
fn extension_chain_rejects_missing_inconsistent_duplicate_and_trailing_headers() {
    let missing = match GtpuExtensionChain::from_raw(None, Bytes::from_static(&[0x01, 0, 9, 0])) {
        Ok(value) => panic!("missing first extension type unexpectedly parsed: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(missing, GtpuExtensionChainError::MissingFirstExtensionType);
    assert_eq!(missing.as_str(), "gtpu_extension_chain_missing_first_type");

    let inconsistent =
        match GtpuExtensionChain::from_raw(Some(GTPU_EXT_PDU_SESSION_CONTAINER), Bytes::new()) {
            Ok(value) => panic!("first type without headers unexpectedly parsed: {value:?}"),
            Err(error) => error,
        };
    assert_eq!(
        inconsistent,
        GtpuExtensionChainError::FirstExtensionTypeWithoutHeaders
    );

    let duplicate_raw = Bytes::from_static(&[
        0x01,
        0x00,
        0x09,
        GTPU_EXT_PDU_SESSION_CONTAINER,
        0x01,
        0x00,
        0x0a,
        0x00,
    ]);
    let duplicate =
        match GtpuExtensionChain::from_raw(Some(GTPU_EXT_PDU_SESSION_CONTAINER), duplicate_raw) {
            Ok(value) => panic!("duplicate PDU Session Container unexpectedly parsed: {value:?}"),
            Err(error) => error,
        };
    assert_eq!(
        duplicate,
        GtpuExtensionChainError::DuplicatePduSessionContainer
    );

    let trailing = match GtpuExtensionChain::from_raw(
        Some(GTPU_EXT_PDU_SESSION_CONTAINER),
        Bytes::from_static(&[0x01, 0x00, 0x09, 0x00, 0xff]),
    ) {
        Ok(value) => panic!("trailing extension bytes unexpectedly parsed: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(
        trailing,
        GtpuExtensionChainError::MalformedRawChain {
            reason: GtpuExtensionChainMalformedReason::TrailingBytes,
        }
    );
    assert_eq!(trailing.as_str(), "gtpu_extension_chain_malformed_raw");
}

#[test]
fn test_truncated_packets() {
    // Basic packet of 18 bytes
    let raw = make_basic_packet(10);

    // Truncate at every single byte boundary
    for len in 0..raw.len() {
        let ctx = DecodeContext::default();
        let res = GtpuMessage::decode(&raw[..len], ctx);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().code(), DecodeErrorCode::Truncated);
    }
}

#[test]
fn test_unsupported_version_and_pt() {
    let mut raw = make_basic_packet(10);

    // Set version to 2
    raw[0] = (raw[0] & 0x1F) | (2 << 5);
    let res = GtpuMessage::decode(&raw, DecodeContext::default());
    assert!(res.is_err());
    matches!(
        res.err().unwrap().code(),
        DecodeErrorCode::InvalidEnumValue {
            field: "version",
            ..
        }
    );

    // Set PT to 0
    let mut raw2 = make_basic_packet(10);
    raw2[0] &= 0xEF; // clear PT bit
    let res2 = GtpuMessage::decode(&raw2, DecodeContext::default());
    assert!(res2.is_err());
    matches!(
        res2.err().unwrap().code(),
        DecodeErrorCode::InvalidEnumValue {
            field: "protocol_type",
            ..
        }
    );
}

#[test]
fn test_validation_levels() {
    // Reserved bit set to 1
    let mut raw = make_basic_packet(10);
    raw[0] |= 0x08; // set Reserved bit

    // Structural level should pass
    let ctx_struct = DecodeContext {
        validation_level: ValidationLevel::Structural,
        ..DecodeContext::default()
    };
    assert!(GtpuMessage::decode(&raw, ctx_struct).is_ok());

    // Strict level should reject
    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let res = GtpuMessage::decode(&raw, ctx_strict);
    assert!(res.is_err());
    assert_eq!(
        *res.err().unwrap().code(),
        DecodeErrorCode::Structural {
            reason: "reserved bit must be zero"
        }
    );

    // ProcedureAware level with malformed PDU Session Container
    let malformed_raw = vec![
        0x36, // Version=1, PT=1, E=1, S=1, PN=0
        0xFF, // G-PDU
        0x00, 0x08, // Length = 8
        0x11, 0x22, 0x33, 0x44, // TEID
        0x00, 0x05, // Seq = 5
        0x00, // NPDU
        0x85, // Next Ext = 0x85 (PDU Session Container)
        // Extension Header with units=1 but empty content
        0x01, // Extension Length Units = 1
        // Zero/missing content for DL type
        0x00, 0x80, // PPP set but missing PPI
        0x00, // Next Ext
    ];

    // Structural should pass outer decode (ignores inner semantic failure)
    let ctx_struct_malformed = DecodeContext {
        validation_level: ValidationLevel::Structural,
        ..DecodeContext::default()
    };
    assert!(GtpuMessage::decode(&malformed_raw, ctx_struct_malformed).is_ok());

    // ProcedureAware should fail outer decode due to inner semantic validation
    let ctx_proc = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    let res = GtpuMessage::decode(&malformed_raw, ctx_proc);
    assert!(res.is_err());
    assert_eq!(
        *res.err().unwrap().code(),
        DecodeErrorCode::Structural {
            reason: "malformed PDU Session Container"
        }
    );
}

#[test]
fn test_decoder_limits() {
    // Circular extension header chain: Ext 1 -> Ext 1
    let raw = vec![
        0x36, 0xFF, 0x00, 0x0C, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x85,
        // Ext 1: Length=1, Type=0x85, Next=0x85 (circular!)
        0x01, 0x00, 0x00, 0x85, // Ext 2: Length=1, Type=0x85, Next=0
        0x01, 0x00, 0x00, 0x00,
    ];

    let ctx_depth = DecodeContext {
        max_depth: 1,
        ..DecodeContext::default()
    };
    let res = GtpuMessage::decode(&raw, ctx_depth);
    assert!(res.is_err());
    assert_eq!(*res.err().unwrap().code(), DecodeErrorCode::DepthExceeded);

    let ctx_ies = DecodeContext {
        max_depth: 10,
        max_ies: 1,
        ..DecodeContext::default()
    };
    let res2 = GtpuMessage::decode(&raw, ctx_ies);
    assert!(res2.is_err());
    assert_eq!(
        *res2.err().unwrap().code(),
        DecodeErrorCode::IeCountExceeded
    );
}

#[test]
fn test_oversized_payload() {
    let raw = make_basic_packet(100);
    let ctx = DecodeContext {
        max_message_len: 50, // smaller than packet (108 bytes)
        ..DecodeContext::default()
    };
    let res = GtpuMessage::decode(&raw, ctx);
    assert!(res.is_err());
    assert_eq!(
        *res.err().unwrap().code(),
        DecodeErrorCode::MessageLengthExceeded
    );
}

#[test]
fn test_owned_message_slicing() {
    let raw = make_basic_packet(20);
    let bytes_buf = Bytes::copy_from_slice(&raw);
    let ctx = DecodeContext::default();

    let owned =
        OwnedGtpuMessage::decode_owned(bytes_buf.clone(), ctx).expect("failed to decode owned");
    assert_eq!(owned.payload.len(), 20);
    assert_eq!(owned.header.teid, 0x12345678);

    // Verify slicing shares memory under the hood
    assert_eq!(
        owned.payload.as_ptr() as usize,
        bytes_buf.as_ptr() as usize + 8
    );
}

#[test]
fn test_canonical_vs_raw_preserving_roundtrip() {
    // Manually construct a GtpuMessage with flags set in GtpuHeader but actual optional fields are None.
    // This represents a scenario where the parsed header contains flags enabled but values absent,
    // which canonical mode should normalize by clearing the flags and removing optional fields.
    let msg = GtpuMessage {
        header: GtpuHeader {
            version: 1,
            protocol_type: true,
            reserved: 0,
            ext_hdr_flag: true,
            seq_num_flag: true,
            npdu_num_flag: true,
            message_type: 0xFF,
            length: 4,
            teid: 0x11223344,
            sequence_number: None,
            npdu_number: None,
            next_ext_type: None,
            raw_sequence_number: None,
            raw_npdu_number: None,
            raw_next_ext_type: None,
        },
        raw_extension_headers: &[],
        payload: &[],
    };

    // Canonical roundtrip
    let mut canonical_dst = BytesMut::new();
    let canonical_ctx = EncodeContext::default(); // raw_preserving = false
    msg.encode(&mut canonical_dst, canonical_ctx)
        .expect("canonical encode failed");

    // In canonical, since there are no optional fields actually populated, they are stripped.
    // So b1 becomes 0x30 (Version=1, PT=1, E=0, S=0, PN=0), length becomes 0, and no optional bytes written.
    let expected_canonical = vec![0x30, 0xFF, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44];
    assert_eq!(canonical_dst.to_vec(), expected_canonical);

    // Raw-preserving roundtrip
    let mut raw_dst = BytesMut::new();
    let raw_ctx = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    msg.encode(&mut raw_dst, raw_ctx)
        .expect("raw-preserving encode failed");

    // In raw-preserving, it keeps the header flags and outputs the 12-byte header with zeros for missing optional fields.
    let expected_raw = vec![
        0x37, // E=1, S=1, PN=1
        0xFF, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, // Seq
        0x00, // NPDU
        0x00, // Next Ext
    ];
    assert_eq!(raw_dst.to_vec(), expected_raw);
}

#[test]
fn test_raw_preserving_reserved_bit() {
    // 0x38 = Version 1, PT 1, Reserved 1, E=0, S=0, PN=0
    let data = vec![0x38, 0xFF, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44];
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Structural,
        ..DecodeContext::default()
    };
    let (tail, msg) = GtpuMessage::decode(&data, ctx).unwrap();
    assert_eq!(msg.header.reserved, 1);
    assert!(tail.is_empty());

    // Verify raw-preserving roundtrip preserves the reserved bit
    let mut raw_dst = BytesMut::new();
    let raw_ctx = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    msg.encode(&mut raw_dst, raw_ctx).unwrap();
    assert_eq!(raw_dst.to_vec(), data);

    // Verify canonical mode clears the reserved bit
    let mut canonical_dst = BytesMut::new();
    msg.encode(&mut canonical_dst, EncodeContext::default())
        .unwrap();
    assert_eq!(
        canonical_dst.to_vec(),
        vec![0x30, 0xFF, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44]
    );
}

#[test]
fn test_raw_preserving_inactive_optional_fields() {
    // 0x31 = Version 1, PT 1, Reserved 0, E=0, S=0, PN=1
    // Optional fields: Seq = 0x1234 (seq_num_flag false), NPDU = 0x56 (npdu_num_flag true), Next Ext = 0x00
    let data = vec![
        0x31, 0xFF, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x12, 0x34, 0x56, 0x00,
    ];
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let (tail, msg) = GtpuMessage::decode(&data, ctx).unwrap();
    assert!(!msg.header.seq_num_flag);
    assert!(msg.header.npdu_num_flag);
    assert_eq!(msg.header.sequence_number, None);
    assert_eq!(msg.header.npdu_number, Some(0x56));
    assert_eq!(msg.header.raw_sequence_number, Some(0x1234));
    assert_eq!(msg.header.raw_npdu_number, Some(0x56));
    assert_eq!(msg.header.raw_next_ext_type, Some(0x00));
    assert!(tail.is_empty());

    // Verify raw-preserving roundtrip preserves the exact optional field bytes
    let mut raw_dst = BytesMut::new();
    let raw_ctx = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    msg.encode(&mut raw_dst, raw_ctx).unwrap();
    assert_eq!(raw_dst.to_vec(), data);

    // Verify canonical mode clears inactive fields
    let mut canonical_dst = BytesMut::new();
    msg.encode(&mut canonical_dst, EncodeContext::default())
        .unwrap();
    // In canonical, since sequence_number is None, it gets cleared to 0x0000
    assert_eq!(
        canonical_dst.to_vec(),
        vec![0x31, 0xFF, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x56, 0x00]
    );
}

#[test]
fn test_regression_raw_preserving_fuzz_inputs() {
    let cases = [
        [
            0x35, 0xff, 0x00, 0x0a, 0x13, 0x34, 0x00, 0x00, 0x08, 0x00, 0x3f, 0x00, 0x00, 0x00,
            0xaa, 0x01, 0xaa, 0xaa,
        ],
        [
            0x35, 0xff, 0x00, 0x0a, 0x00, 0x12, 0x00, 0x56, 0x3d, 0xf7, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x64, 0xaa, 0xaa,
        ],
    ];

    for data in cases {
        let ctx = DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..DecodeContext::default()
        };
        let (tail, msg) = GtpuMessage::decode(&data, ctx).expect("regression input decodes");
        assert!(tail.is_empty());

        let mut raw_dst = BytesMut::new();
        let raw_ctx = EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        };
        msg.encode(&mut raw_dst, raw_ctx)
            .expect("regression input re-encodes");
        assert_eq!(raw_dst.as_ref(), data);
    }
}
