//! Execute the catalog against existing SDK codecs at its declared boundary.

use opc_n3iwf_fixtures::FixtureCatalog;
use opc_proto_gtpu::{GtpuControlMessage, GtpuMessage, PduSessionContainer};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, EncodeContext, UnknownIePolicy,
};

#[test]
fn every_gtpu_wire_obeys_its_codec_contract() {
    let catalog = FixtureCatalog::load().expect("catalog");
    for (manifest, wire) in catalog.manifests().filter(|(m, _)| m.subset == "n3-gtpu") {
        let context = DecodeContext {
            max_message_len: manifest.context["max_message_len"].as_u64().expect("bound") as usize,
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        let name = manifest.sdk_fixture_id.split(".v1.").nth(1).expect("name");
        if name == "bounded-length-overflow" {
            let error = GtpuMessage::decode(wire, context).expect_err("caller bound");
            assert_eq!(error.code(), &DecodeErrorCode::MessageLengthExceeded);
        } else if name == "unknown-required-extension" {
            let error = GtpuMessage::decode(wire, context).expect_err("critical extension");
            assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
        } else if wire.get(1) == Some(&255) {
            let (tail, message) = GtpuMessage::decode(wire, context).expect("G-PDU");
            assert!(tail.is_empty());
            let extensions = message
                .extensions()
                .collect::<Result<Vec<_>, _>>()
                .expect("extensions");
            assert_eq!(extensions.len(), 1);
            let psc = PduSessionContainer::decode(&extensions[0]).expect("PSC");
            assert_eq!(psc.qfi, 9);
            assert_eq!(psc.pdu_type, u8::from(name == "positive-ul-psc"));
            assert!(!psc.rqi);
            assert_eq!(psc.ppi, None);
        } else {
            let result = GtpuControlMessage::decode_datagram(wire, context);
            if manifest.expected_outcome == "reject" {
                assert!(result.is_err(), "{}", manifest.sdk_fixture_id);
                continue;
            }
            let message = result.expect("control message");
            if name == "ordering-end-marker-psc-first" {
                assert_eq!(message.message_type(), 254);
                let (_, frame) = GtpuMessage::decode(wire, context).expect("frame");
                let extensions = frame
                    .extensions()
                    .collect::<Result<Vec<_>, _>>()
                    .expect("chain");
                assert_eq!(
                    extensions.iter().map(|e| e.ext_type).collect::<Vec<_>>(),
                    [0x85, 7, 6]
                );
            } else {
                assert_eq!(message.sequence_number(), Some(0x1234));
                let encoded = message.to_bytes(EncodeContext::default()).expect("encode");
                let mut expected = wire.to_vec();
                if name == "receive-recovery-ignored" {
                    expected[13] = 0;
                }
                assert_eq!(encoded.as_ref(), expected);
            }
        }
    }
}

#[test]
fn ngap_dispatch_is_structural_and_rejects_malformed_containers() {
    let catalog = FixtureCatalog::load().expect("catalog");
    for (manifest, wire) in catalog
        .manifests()
        .filter(|(m, _)| m.subset == "ngap" && m.validation_scope == "aper-structural-dispatch")
    {
        assert_eq!(manifest.validation_scope, "aper-structural-dispatch");
        assert_eq!(manifest.context["mandatory_presence_validation"], false);
        assert_eq!(manifest.context["inner_ie_validation"], false);
        let context = DecodeContext {
            max_ies: manifest.context["max_ies"].as_u64().expect("bound") as usize,
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        assert_eq!(manifest.context["duplicate_ie_policy"], "reject");
        assert_eq!(manifest.context["unknown_ie_policy"], "reject");
        let result = opc_proto_ngap::decode(wire, context);
        if manifest.expected_outcome == "reject" {
            let error = result.expect_err("negative container");
            if manifest
                .sdk_fixture_id
                .ends_with("bounded-ie-count-overflow")
            {
                assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
            }
            if manifest.sdk_fixture_id.ends_with("unknown-critical-ie") {
                assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
            }
        } else {
            let pdu = result.expect("structural APER dispatch");
            assert_eq!(pdu.raw.as_ref(), wire);
            // Empty mandatory-IE containers deliberately demonstrate only
            // dispatch. Admission to a real N3IWF procedure is unproven.
        }
    }
}
