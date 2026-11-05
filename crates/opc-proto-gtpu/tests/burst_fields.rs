//! TS 38.415 V19.1.0 figure 5.5.2.1-1: unsupported burst fields are not padding.

use opc_proto_gtpu::{GtpuExtensionHeader, PduSessionContainer, GTPU_EXT_PDU_SESSION_CONTAINER};
use opc_protocol::DecodeErrorCode;

#[test]
fn downlink_burst_fields_are_not_silently_discarded() {
    for content in [
        &[0x00, 0x89, 0xa2, 0x00, 0x10, 0x00][..], // BSSI, BSSize=4096
        &[0x00, 0x89, 0xa1, 0x00, 0x64, 0x00],     // TTNBI, TTNB=100
        &[0x00, 0x89, 0xa3, 0x00, 0x10, 0x00, 0x00, 0x64, 0x00, 0x00],
    ] {
        let extension = GtpuExtensionHeader {
            ext_type: GTPU_EXT_PDU_SESSION_CONTAINER,
            content,
            next_ext_type: 0,
        };
        let error = PduSessionContainer::decode(&extension).unwrap_err();
        assert_eq!(error.offset(), 2);
        assert_eq!(
            error.code(),
            &DecodeErrorCode::Structural {
                reason: "DL PDU Session Container uses unsupported conditional fields",
            }
        );
    }
}
