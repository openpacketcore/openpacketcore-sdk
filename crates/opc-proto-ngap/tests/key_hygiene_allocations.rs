//! Allocation-level hygiene checks for the N3IWF security-key receive path.
//!
//! `allocation_counter` observes allocation counts and bytes only; it cannot
//! inspect freed contents. These tests therefore prove there is no *retained*
//! allocation (leak) on the decode/drop and error paths, and that the counter
//! does observe both `Vec` and `bytes::Bytes` retention (positive controls).
//! Content clearing is proven by the safe drop-audit unit tests on
//! `opc_protocol::SensitiveBytes`, which is the carrier for the raw receive
//! copy, the extracted key octets and the SCTP payload.

use allocation_counter::measure;
use bytes::Bytes;
use opc_proto_ngap::{decode, encode, Criticality, MessageType, Pdu, ProtocolIe};
use opc_protocol::{DecodeContext, EncodeContext, SensitiveBytes};
use zeroize::Zeroizing;

const KEY_IE_ID: u16 = 94;
const FILLER_IE_ID: u16 = 65_535;
const KEY: [u8; 32] = [
    0x5a, 0xa5, 0x3c, 0xc3, 0x69, 0x96, 0x0f, 0xf0, 0x17, 0x71, 0x2b, 0xb2, 0x4d, 0xd4, 0x8e, 0xe8,
    0x1c, 0xc1, 0x95, 0x59, 0x6a, 0xa6, 0x73, 0x37, 0xbe, 0xeb, 0x40, 0x04, 0x88, 0x8b, 0x2e, 0xe2,
];

fn key_bearing_wire() -> Zeroizing<Vec<u8>> {
    let pdu = Pdu::from_protocol_ies(
        MessageType::InitialContextSetupRequest,
        &[
            ProtocolIe::new(KEY_IE_ID, Criticality::reject, &KEY),
            ProtocolIe::new(FILLER_IE_ID, Criticality::ignore, &[0x11]),
        ],
        DecodeContext::default(),
    )
    .expect("structural key-bearing PDU");
    Zeroizing::new(encode(&pdu, EncodeContext::default()).expect("canonical encode"))
}

#[test]
fn allocation_counter_observes_retained_vec_and_bytes() {
    // Positive controls: `mem::forget` is the safe way to retain one allocation
    // so the counter must report a positive current delta. The test process
    // intentionally retains these small buffers to prove the probe is live.
    let vec_info = measure(|| {
        let retained = vec![0x5a_u8; 4096];
        core::mem::forget(retained);
    });
    assert!(vec_info.count_total > 0);
    assert!(
        vec_info.count_current > 0,
        "Vec retention must be observable"
    );
    assert!(vec_info.bytes_current > 0);

    let bytes_info = measure(|| {
        let retained = Bytes::copy_from_slice(&[0x5a_u8; 4096]);
        core::mem::forget(retained);
    });
    assert!(bytes_info.count_total > 0);
    assert!(
        bytes_info.count_current > 0,
        "bytes::Bytes retention must be observable"
    );
    assert!(bytes_info.bytes_current > 0);
}

#[test]
fn decoded_key_bearing_pdu_drop_retains_no_allocation() {
    let wire = key_bearing_wire();
    let info = measure(|| {
        for _ in 0..8 {
            let pdu = decode(&wire, DecodeContext::default()).expect("decode");
            drop(pdu);
        }
    });
    assert!(info.count_total > 0, "decode path allocated nothing?");
    assert_eq!(info.count_current, 0, "decoded PDU retained an allocation");
    assert_eq!(info.bytes_current, 0, "decoded PDU retained bytes");
}

#[test]
fn decode_error_after_key_ie_retains_no_allocation() {
    let wire = key_bearing_wire();
    // Corrupt the filler IE's inner open-type length while leaving the outer
    // open type consistent: the key IE is parsed and extracted before the inner
    // framing error, exercising the error-path scrub.
    let mut corrupted = wire.to_vec();
    let filler = corrupted
        .windows(5)
        .position(|window| window == [0xff, 0xff, 0x40, 0x01, 0x11])
        .expect("filler IE framing");
    corrupted[filler + 3] = 0x7f;
    let truncated = Zeroizing::new(corrupted);
    let info = measure(|| {
        for _ in 0..8 {
            assert!(
                decode(&truncated, DecodeContext::default()).is_err(),
                "truncated PDU must be rejected"
            );
        }
    });
    assert!(info.count_total > 0);
    assert_eq!(info.count_current, 0);
    assert_eq!(info.bytes_current, 0);
}

#[test]
fn key_free_pdu_is_an_allocation_negative_control() {
    let wire = Zeroizing::new(
        encode(
            &Pdu::from_protocol_ies(
                MessageType::InitialContextSetupRequest,
                &[ProtocolIe::new(FILLER_IE_ID, Criticality::ignore, &[0x11])],
                DecodeContext::default(),
            )
            .expect("structural PDU"),
            EncodeContext::default(),
        )
        .expect("canonical encode"),
    );
    let info = measure(|| {
        for _ in 0..8 {
            drop(decode(&wire, DecodeContext::default()).expect("decode"));
        }
    });
    assert_eq!(info.count_current, 0);
    assert_eq!(info.bytes_current, 0);
}

#[test]
fn sensitive_bytes_drop_retains_no_allocation() {
    let info = measure(|| {
        for _ in 0..8 {
            drop(SensitiveBytes::from_slice(&KEY));
        }
    });
    assert!(info.count_total > 0);
    assert_eq!(info.count_current, 0);
    assert_eq!(info.bytes_current, 0);
}
