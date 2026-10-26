//! Allocation-level hygiene checks for SCTP inbound payload custody.
//!
//! `allocation_counter` observes counts/bytes, not freed contents. These tests
//! prove the sensitive carrier and the N2 admission path retain no allocation,
//! with positive controls for `Vec` and `bytes::Bytes` retention. Content
//! clearing is asserted by the SCTP receive-owner drop-audit unit tests.

use allocation_counter::measure;
use bytes::Bytes;
use opc_sctp::n2::{N2Inbound, UnprotectedN2Profile};
use opc_sctp::{DataChunk, InboundMessage, OutboundMessage, PayloadProtocolIdentifier, NGAP_PPID};

const KEY: [u8; 32] = [
    0x5a, 0xa5, 0x3c, 0xc3, 0x69, 0x96, 0x0f, 0xf0, 0x17, 0x71, 0x2b, 0xb2, 0x4d, 0xd4, 0x8e, 0xe8,
    0x1c, 0xc1, 0x95, 0x59, 0x6a, 0xa6, 0x73, 0x37, 0xbe, 0xeb, 0x40, 0x04, 0x88, 0x8b, 0x2e, 0xe2,
];

fn keyed_inbound() -> InboundMessage {
    let mut chunk = [0u8; 48];
    chunk[1] = 3; // Unfragmented DATA: B and E.
    chunk[2..4].copy_from_slice(&48u16.to_be_bytes());
    chunk[8..10].copy_from_slice(&7u16.to_be_bytes());
    chunk[12..16].copy_from_slice(&NGAP_PPID.get().to_be_bytes());
    chunk[16..].copy_from_slice(&KEY);
    DataChunk::decode(&chunk)
        .expect("synthetic DATA")
        .into_inbound_message(41)
        .expect("unfragmented DATA")
}

#[test]
fn allocation_counter_observes_retained_vec_and_bytes() {
    let vec_info = measure(|| {
        let retained = vec![0x5a_u8; 4096];
        core::mem::forget(retained);
    });
    assert!(vec_info.count_total > 0);
    assert!(vec_info.count_current > 0);
    assert!(vec_info.bytes_current > 0);

    let bytes_info = measure(|| {
        let retained = Bytes::copy_from_slice(&[0x5a_u8; 4096]);
        core::mem::forget(retained);
    });
    assert!(bytes_info.count_total > 0);
    assert!(bytes_info.count_current > 0);
    assert!(bytes_info.bytes_current > 0);
}

#[test]
fn inbound_message_and_admitted_payload_drop_retain_no_allocation() {
    let profile = UnprotectedN2Profile::new(64).expect("profile");
    let info = measure(|| {
        for _ in 0..8 {
            let admitted = profile.admit(keyed_inbound()).expect("admit N2 DATA");
            let N2Inbound::Payload(payload) = admitted else {
                panic!("DATA became a notification");
            };
            drop(payload);
        }
    });
    assert!(info.count_total > 0);
    assert_eq!(info.count_current, 0, "N2 payload retained an allocation");
    assert_eq!(info.bytes_current, 0);
}

#[test]
fn sensitive_payload_and_outbound_debug_shape_retain_no_allocation() {
    let debug_info = measure(|| {
        let message = OutboundMessage::ordered(
            Bytes::from_static(&[0x90, 0x91, 0x92, 0x93]),
            7,
            PayloadProtocolIdentifier::new(NGAP_PPID.get()),
        );
        let rendered = format!("{message:?}");
        assert!(!rendered.contains("144") && !rendered.contains("9091"));
        assert!(rendered.contains("payload_len"));
    });
    assert_eq!(debug_info.count_current, 0);

    let info = measure(|| {
        for _ in 0..8 {
            drop(keyed_inbound().payload);
        }
    });
    assert!(info.count_total > 0);
    assert_eq!(info.count_current, 0);
    assert_eq!(info.bytes_current, 0);
}
