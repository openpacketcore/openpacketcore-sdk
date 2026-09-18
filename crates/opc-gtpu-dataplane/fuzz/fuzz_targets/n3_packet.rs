#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_gtpu_dataplane::{
    n3::{
        N3Direction, N3PacketError, N3PacketView, N3Qfi, N3UplinkEncapsulation, ReceivedN3UplinkTnl,
    },
    Teid,
};
use opc_protocol::DecodeContext;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let ctx = DecodeContext {
        max_message_len: 4096,
        max_ies: 64,
        max_depth: 64,
        ..DecodeContext::default()
    };
    for direction in [N3Direction::Uplink, N3Direction::Downlink] {
        if let Ok(view) = N3PacketView::decode(data, direction, ctx) {
            assert_eq!(view.datagram(), data);
            assert_eq!(view.qos().direction(), direction);
            assert!(view.qos().qfi().get() <= 63);
            assert!(!view.payload().is_empty());
            assert_ne!(view.teid().get(), 0);
            if direction == N3Direction::Uplink {
                assert!(!view.qos().rqi());
                assert!(view.qos().ppi().is_none());
            }
            assert_eq!(
                N3PacketView::decode(
                    data,
                    direction,
                    DecodeContext {
                        max_message_len: data.len() - 1,
                        ..ctx
                    }
                )
                .unwrap_err(),
                N3PacketError::MessageTooLarge
            );
        }
    }
    if let Some(qfi_byte) = data.first() {
        let qfi = N3Qfi::new(qfi_byte & 63).unwrap();
        let tunnel = ReceivedN3UplinkTnl::new(
            "192.0.2.1".parse().unwrap(),
            Teid::new(0x1122_3344).unwrap(),
        )
        .unwrap();
        let insertion = N3UplinkEncapsulation::new(tunnel, qfi);
        let mut dst = BytesMut::from(&b"prefix"[..]);
        match insertion.encode_gpdu(data, &mut dst, 4096) {
            Ok(()) => {
                assert_eq!(&dst[..6], b"prefix");
                let view = N3PacketView::decode(&dst[6..], N3Direction::Uplink, ctx).unwrap();
                assert_eq!(view.qos().qfi(), qfi);
                assert_eq!(view.payload(), data);
                assert_eq!(dst[6], 0x34);
            }
            Err(reason) => {
                assert_eq!(reason, N3PacketError::MessageTooLarge);
                assert_eq!(&dst[..], b"prefix");
            }
        }
    }
});
