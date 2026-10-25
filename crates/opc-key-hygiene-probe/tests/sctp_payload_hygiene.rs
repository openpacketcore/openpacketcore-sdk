//! Allocator-level drop probes for SCTP payload hygiene (#1262).

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
use opc_protocol::SensitiveBytes;
use opc_sctp::n2::{N2Inbound, UnprotectedN2Profile};
use opc_sctp::{
    DeliveryOrder, InboundMessage, OutboundMessage, PayloadProtocolIdentifier, NGAP_PPID,
};

fn keyed_inbound() -> InboundMessage {
    InboundMessage {
        payload: SensitiveBytes::from_slice(&probe::KEY_MARKER),
        stream_id: 7,
        ppid: PayloadProtocolIdentifier::new(NGAP_PPID.get()),
        order: DeliveryOrder::Ordered,
        assoc_id: 41,
        notification: false,
        event: None,
        truncated: false,
        control_truncated: false,
    }
}

#[test]
fn sensitive_payload_drop_leaves_no_marker() {
    let _guard = probe_lock();
    probe::arm();
    drop(SensitiveBytes::from_slice(&probe::KEY_MARKER));
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "SensitiveBytes released key-bearing memory");
}

#[test]
fn inbound_message_drop_leaves_no_marker() {
    let _guard = probe_lock();
    probe::arm();
    drop(keyed_inbound());
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "InboundMessage released key-bearing memory");
}

#[test]
fn admitted_n2_payload_drop_leaves_no_marker() {
    let _guard = probe_lock();
    let profile = UnprotectedN2Profile::new(64).expect("profile");
    let admitted = profile.admit(keyed_inbound()).expect("admit N2 DATA");
    let N2Inbound::Payload(payload) = admitted else {
        panic!("DATA became a notification");
    };
    assert_eq!(payload.payload().as_slice(), &probe::KEY_MARKER);
    probe::arm();
    drop(payload);
    let hits = probe::hits();
    probe::disarm();
    assert_eq!(hits, 0, "N2Payload released key-bearing memory");
}

#[test]
fn outbound_debug_never_prints_payload_bytes() {
    let _guard = probe_lock();
    let message = OutboundMessage::ordered(
        Bytes::from_static(&[0x90, 0x91, 0x92, 0x93]),
        7,
        PayloadProtocolIdentifier::new(NGAP_PPID.get()),
    );
    let rendered = format!("{message:?}");
    assert!(
        !rendered.contains("144") && !rendered.contains("9091"),
        "OutboundMessage Debug leaked payload bytes: {rendered}"
    );
    assert!(rendered.contains("payload_len"), "{rendered}");
}
