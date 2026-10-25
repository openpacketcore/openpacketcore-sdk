//! Allocator-level drop probes for NGAP key hygiene (#1262).
//!
//! The probe increments a hit counter whenever a freed heap block still
//! contains the 32-octet key marker. Positive controls prove the probe sees
//! both `Vec`/`bytes::Bytes` frees; the negative cases exercise the decode,
//! error and drop paths.

use bytes::Bytes;
use opc_key_hygiene_probe as probe;
use std::sync::{Mutex, MutexGuard};

/// Serializes probe-arm/drop windows: the allocator is process-global.
static PROBE_LOCK: Mutex<()> = Mutex::new(());

fn probe_lock() -> MutexGuard<'static, ()> {
    PROBE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
use opc_proto_ngap::{decode, encode, Criticality, MessageType, Pdu, ProtocolIe};
use opc_protocol::{DecodeContext, EncodeContext};
use zeroize::Zeroizing;

const KEY_IE_ID: u16 = 94;
const FILLER_IE_ID: u16 = 65_535;

fn key_ie() -> ProtocolIe<'static> {
    ProtocolIe::new(KEY_IE_ID, Criticality::reject, &probe::KEY_MARKER)
}

fn filler_ie() -> ProtocolIe<'static> {
    ProtocolIe::new(FILLER_IE_ID, Criticality::ignore, &[0x11, 0x22])
}

fn key_bearing_pdu() -> Pdu {
    Pdu::from_protocol_ies(
        MessageType::InitialContextSetupRequest,
        &[key_ie(), filler_ie()],
        DecodeContext::default(),
    )
    .expect("structural key-bearing PDU")
}

#[test]
fn probe_detects_uncleared_vec_and_bytes() {
    let _guard = probe_lock();
    probe::arm();
    drop(Vec::<u8>::from(probe::KEY_MARKER));
    let vec_hits = probe::hits();
    probe::disarm();
    assert!(vec_hits > 0, "probe must observe Vec deallocation");

    probe::arm();
    drop(Bytes::copy_from_slice(&probe::KEY_MARKER));
    let bytes_hits = probe::hits();
    probe::disarm();
    assert!(
        bytes_hits > 0,
        "probe must observe bytes::Bytes deallocation"
    );
}

#[test]
fn decoded_key_bearing_pdu_drop_leaves_no_marker() {
    let _guard = probe_lock();
    let wire =
        Zeroizing::new(encode(&key_bearing_pdu(), EncodeContext::default()).expect("encode"));
    // Decode twice: the raw receive copy, the extracted key owner and the
    // placeholder IE copies must all clear on drop.
    probe::arm();
    for _ in 0..2 {
        let pdu = decode(&wire, DecodeContext::default()).expect("decode");
        assert!(pdu.has_raw());
        drop(pdu);
    }
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "decoded PDU released a block containing key bytes");
}

#[test]
fn key_free_pdu_is_a_negative_control() {
    let _guard = probe_lock();
    let pdu = Pdu::from_protocol_ies(
        MessageType::InitialContextSetupRequest,
        &[filler_ie()],
        DecodeContext::default(),
    )
    .expect("structural PDU");
    probe::arm();
    drop(pdu);
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "key-free PDU must not produce probe hits");
}

#[test]
fn decode_error_after_key_ie_leaves_no_marker() {
    let _guard = probe_lock();
    let wire =
        Zeroizing::new(encode(&key_bearing_pdu(), EncodeContext::default()).expect("encode"));
    // Drop the last octet of the filler IE's open type: the key IE has been
    // parsed and extracted before the framing error, exercising the error-path
    // scrub in the decode macro.
    let truncated = Zeroizing::new(wire[..wire.len() - 1].to_vec());
    probe::arm();
    let error = decode(&truncated, DecodeContext::default());
    let result = error.is_err();
    let hits = probe::hits();
    probe::disarm();
    assert!(result, "truncated PDU must be rejected");
    assert_eq!(
        hits, 0,
        "decode error released a block containing key bytes"
    );
}

#[test]
fn canonical_encode_preserves_key_ie_bytes_without_retaining_them_in_the_view() {
    let _guard = probe_lock();
    let pdu = key_bearing_pdu();
    let wire = Zeroizing::new(encode(&pdu, EncodeContext::default()).expect("encode"));
    let decoded = decode(&wire, DecodeContext::default()).expect("decode");
    let reencoded = Zeroizing::new(encode(&decoded, EncodeContext::default()).expect("re-encode"));
    assert_eq!(
        reencoded.as_slice(),
        wire.as_slice(),
        "canonical re-encoding must reproduce the key IE bytes"
    );
}

#[test]
fn security_key_zeroizing_handoff_clears_on_drop() {
    let _guard = probe_lock();
    let security =
        opc_proto_ngap::n3iwf::SecurityKey::decode(&probe::KEY_MARKER, DecodeContext::default())
            .expect("key");
    let handoff = security.copy_into_zeroizing();
    assert_eq!(handoff.as_slice(), &probe::KEY_MARKER);
    probe::arm();
    drop(handoff);
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "zeroizing hand-off released key bytes");
}

#[test]
fn received_pdu_debug_never_prints_key_bytes() {
    let _guard = probe_lock();
    let wire =
        Zeroizing::new(encode(&key_bearing_pdu(), EncodeContext::default()).expect("encode"));
    let pdu = decode(&wire, DecodeContext::default()).expect("decode");
    let rendered = format!("{pdu:?}");
    let marker_debug = format!("{:?}", &probe::KEY_MARKER[..]);
    assert!(
        !rendered.contains(&marker_debug),
        "Pdu Debug leaked key bytes: {rendered}"
    );
    assert!(rendered.contains("raw_len:"), "{rendered}");
}
