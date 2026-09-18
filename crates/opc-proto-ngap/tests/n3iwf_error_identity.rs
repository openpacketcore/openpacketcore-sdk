use bytes::Bytes;
use opc_proto_ngap::n3iwf::nas_fields::{AmfSetId, FiveGStmsi};
use opc_proto_ngap::n3iwf::reset::{ResetMessage, Signalling};
use opc_proto_ngap::{encode, Message, Pdu, PduKind};
use opc_protocol::{DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, ValidationLevel};
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-reset.json")).unwrap()
}
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}

#[test]
fn independent_error_indication_identity_is_admitted() {
    // Existing independently produced Release 18 Error Indication IE 26/ignore.
    let wire = [
        0x00, 0x09, 0x40, 0x14, 0x00, 0x00, 0x02, 0x00, 0x0f, 0x40, 0x02, 0x00, 0x00, 0x00, 0x1a,
        0x40, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];
    let ctx = DecodeContext::default();
    let pdu = Pdu::decode_owned(Bytes::copy_from_slice(&wire), ctx).unwrap();
    assert!(
        ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).is_ok(),
        "applicable Error Indication identity remains unsupported"
    );
}

#[test]
fn identity_duplicates_follow_selected_view_and_mutable_criticality_is_rechecked() {
    let reference = reference();
    let row = reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "identity-duplicate")
        .unwrap();
    let wire = bytes(row["wire_hex"].as_str().unwrap());
    assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire), context()).is_err());
    for (policy, set, pointer, tmsi) in [
        (DuplicateIePolicy::First, 731, 41, [1, 2, 3, 4]),
        (DuplicateIePolicy::Last, 1023, 63, [255; 4]),
    ] {
        let ctx = DecodeContext {
            duplicate_ie_policy: policy,
            ..context()
        };
        let mut pdu = Pdu::decode_owned(Bytes::copy_from_slice(&wire), ctx).unwrap();
        let admitted = ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).unwrap();
        let ResetMessage::Error(error) = &admitted.message else {
            panic!()
        };
        let identity = FiveGStmsi::new(AmfSetId::new(set).unwrap(), pointer, tmsi).unwrap();
        assert!(
            error.fiveg_s_tmsi == Some(identity),
            "selected identity changed"
        );
        assert!(format!("{admitted:?}").contains("REDACTED"));
        let PduKind::Initiating {
            message: Message::ErrorIndication(value),
            ..
        } = &mut pdu.kind
        else {
            panic!()
        };
        value
            .protocol_ies
            .0
            .iter_mut()
            .find(|ie| ie.id == 26)
            .unwrap()
            .criticality = rasn::aper::decode(&[0]).unwrap();
        assert!(
            ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).is_err(),
            "mutable wrong criticality passed admission"
        );
    }
}

#[test]
fn identity_is_retained_with_diagnostics_and_cannot_replace_error_authority() {
    let reference = reference();
    let row = reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "identity-context-non-ue-0-2")
        .unwrap();
    let wire = bytes(row["wire_hex"].as_str().unwrap());
    let ctx = DecodeContext {
        max_depth: 6,
        max_message_len: wire.len(),
        ..context()
    };
    let pdu = Pdu::decode_owned(Bytes::copy_from_slice(&wire), ctx).unwrap();
    let admitted = ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).unwrap();
    let ResetMessage::Error(mut error) = admitted.message else {
        panic!()
    };
    assert!(error.fiveg_s_tmsi.is_some() && error.diagnostics.is_some() && error.cause.is_none());
    let constructed = ResetMessage::Error(error.clone())
        .construct(Signalling::NonUe, ctx)
        .unwrap();
    assert!(encode(&constructed, EncodeContext::default()).unwrap() == wire);
    assert!(ResetMessage::Error(error.clone())
        .construct(Signalling::UeAssociated, ctx)
        .is_err());
    error.diagnostics = None;
    assert!(ResetMessage::Error(error)
        .construct(Signalling::NonUe, ctx)
        .is_err());
}

#[test]
fn identity_mutations_replay_bounded_semantic_reconstruction() {
    let reference = reference();
    let mut count = 0;
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["name"].as_str().unwrap().starts_with("identity-"))
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for index in 0..wire.len() {
            for mask in [1, 0x40, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                for ctx in [
                    context(),
                    DecodeContext {
                        max_message_len: 256,
                        max_ies: 8,
                        max_depth: 8,
                        ..context()
                    },
                ] {
                    reset::exercise(&changed, ctx, EncodeContext::default());
                }
                count += 1;
            }
        }
    }
    assert!(count > 20_000, "identity mutation coverage decreased");
}

#[path = "support/reset.rs"]
mod reset;
