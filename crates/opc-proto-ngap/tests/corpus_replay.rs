//! Deterministic corpus-replay regression guard.
//!
//! Replays every committed fuzz corpus input — plus byte-truncations of each
//! entry and a set of hostile constant inputs — through the same decode entry
//! point as the libFuzzer target in `fuzz/fuzz_targets/decode_ngap.rs`.
//!
//! Unlike the fuzzer, this runs on stable Rust in ordinary `cargo test`/CI:
//! it requires no nightly toolchain and no libFuzzer. Its job is regression
//! protection — if a future change makes the decode path panic on a known
//! input, this test fails and names the offending input.

#[path = "support/network_instance.rs"]
mod network_instance;
#[path = "support/qos_admission.rs"]
mod qos_admission;
#[path = "support/qos_profiles.rs"]
mod qos_profiles;
#[path = "support/resource_release.rs"]
mod resource_release;
#[path = "support/resource_setup.rs"]
mod resource_setup;
#[path = "support/setup_optionals.rs"]
mod setup_optionals;

#[path = "support/ue_requests.rs"]
mod ue_requests;

#[path = "support/modify_fields.rs"]
mod modify_fields;

#[path = "support/notify.rs"]
mod notify;

#[path = "support/reset.rs"]
mod reset;

#[path = "support/nas.rs"]
mod nas;

use bytes::Bytes;
use opc_proto_ngap::n3iwf::context_fields::{AllowedNssai, Guami, SecurityAlgorithmMasks};
use opc_proto_ngap::n3iwf::nas::{NasMessage, UeAggregateBitRate};
use opc_proto_ngap::n3iwf::release::{Cause, ReleaseMessage, UeIdentifiers};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
#[path = "support/setup_failure_diagnostics.rs"]
mod setup_failure_diagnostics;
use opc_proto_ngap::n3iwf::session_lists::{
    FailedSessions, SessionResults, SessionSetupRequests, SuccessfulSessions,
};
use opc_proto_ngap::n3iwf::setup::{
    AmfName, GlobalN3iwfId, PagingDrx, PlmnSupportList, ServedGuamiList, SetupMessage,
    SupportedTaList,
};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId, SecurityKey, TrackingArea};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, ProtocolIe};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode, ValidationLevel};
use resource_setup::resource_security::setup_tunnels;

/// The decode entry point the fuzz target exercises. Must never panic,
/// regardless of input. Decode returning `Err` is expected and fine.
fn exercise(data: &[u8]) {
    let ctx = DecodeContext {
        max_message_len: 200_000,
        max_ies: 32,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    qos_admission::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    qos_profiles::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    network_instance::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    modify_fields::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    notify::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    reset::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    ue_requests::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    resource_setup::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    resource_release::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    // Exercise all admitted field receivers on corpus/truncation inputs too.
    let _ = AmfUeId::decode(data, ctx);
    let _ = RanUeId::decode(data, ctx);
    let _ = NasPdu::decode(data, ctx);
    let _ = SecurityKey::decode(data, ctx);
    let _ = TrackingArea::decode(data, ctx);
    let _ = N3iwfLocation::decode(data, ctx);
    let _ = UeAggregateBitRate::decode(data, ctx);
    let _ = Cause::decode(data, ctx);
    let _ = UeIdentifiers::decode(data, ctx);
    if let Ok(field) = UplinkTransport::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(UplinkTransport::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = DownlinkTransport::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(DownlinkTransport::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = SessionAggregateBitRate::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(SessionAggregateBitRate::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = SessionType::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(SessionType::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = QosFlowSetupList::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(QosFlowSetupList::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(admitted) = SetupRequestTransfer::decode(data, ctx) {
        let wire = admitted.transfer.encode(EncodeContext::default()).unwrap();
        let received = SetupRequestTransfer::decode(wire.as_bytes(), ctx).unwrap();
        assert!(received.transfer == admitted.transfer);
        assert_eq!(received.ignored_ie_count, 0);
        assert!(received.notify_ie_ids.is_empty());
    }
    let result_ctx = DecodeContext { max_ies: 64, ..ctx };
    setup_tunnels::exercise(
        data,
        DecodeContext {
            max_ies: 320,
            ..result_ctx
        },
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    setup_failure_diagnostics::exercise(
        data,
        DecodeContext {
            max_ies: 256,
            ..result_ctx
        },
        EncodeContext::default(),
    );
    let list_ctx = DecodeContext {
        max_ies: 256,
        ..ctx
    };
    let list_output = EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    };
    if let Ok(value) = SessionSetupRequests::decode(data, list_ctx) {
        let wire = value.requests.encode(list_output).unwrap();
        let admitted = SessionSetupRequests::decode(wire.as_bytes(), list_ctx).unwrap();
        assert!(admitted.diagnostics.is_empty());
        assert_eq!(
            admitted.requests.values().len(),
            value.requests.values().len()
        );
        for (got, expected) in admitted
            .requests
            .values()
            .iter()
            .zip(value.requests.values())
        {
            assert_eq!(got.id.value(), expected.id.value());
            assert!(got.slice == expected.slice);
            assert!(got.transfer == expected.transfer);
            assert!(
                got.nas.as_ref().map(|v| v.as_bytes())
                    == expected.nas.as_ref().map(|v| v.as_bytes())
            );
        }
    }
    let successful = SuccessfulSessions::decode(data, list_ctx).ok();
    let failed = FailedSessions::decode(data, list_ctx).ok();
    if let Some(value) = &successful {
        let wire = value.encode(list_output).unwrap();
        assert!(SuccessfulSessions::decode(wire.as_bytes(), list_ctx).unwrap() == *value);
    }
    if let Some(value) = &failed {
        let wire = value.encode(list_output).unwrap();
        assert!(FailedSessions::decode(wire.as_bytes(), list_ctx).unwrap() == *value);
    }
    let _ = SessionResults::new(successful, failed);
    if let Ok(field) = Guami::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(Guami::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = AllowedNssai::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(AllowedNssai::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Some(bytes) = data.get(..8) {
        let masks = bytes.as_chunks::<2>().0;
        let value = SecurityAlgorithmMasks::new(
            u16::from_be_bytes(masks[0]),
            u16::from_be_bytes(masks[1]),
            u16::from_be_bytes(masks[2]),
            u16::from_be_bytes(masks[3]),
        );
        assert_eq!(
            value
                .encode(EncodeContext::default())
                .unwrap()
                .as_bytes()
                .len(),
            9
        );
    }
    setup_optionals::exercise(
        data,
        ctx,
        EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        },
    );
    if let Ok(field) = GlobalN3iwfId::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(GlobalN3iwfId::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = ServedGuamiList::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(ServedGuamiList::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = PlmnSupportList::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(PlmnSupportList::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = SupportedTaList::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(SupportedTaList::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(field) = AmfName::decode(data, ctx) {
        let wire = field.encode(EncodeContext::default()).unwrap();
        assert!(AmfName::decode(wire.as_bytes(), ctx).unwrap() == field);
    }
    if let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) {
        if let Ok(admitted) = SetupMessage::from_pdu(&pdu, ctx) {
            let constructed = match &admitted.message {
                SetupMessage::Request(value) => value.construct(PagingDrx::v128, ctx),
                SetupMessage::Response(value) => value.construct(ctx),
                SetupMessage::Failure(value) => value.construct(ctx),
            }
            .unwrap();
            let wire = encode(&constructed, EncodeContext::default()).unwrap();
            let received = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
            let readmitted = SetupMessage::from_pdu(&received, ctx).unwrap();
            assert!(readmitted.message == admitted.message);
            assert!(readmitted.notify_ie_ids.is_empty());
        }
        if let Ok(admitted) = ReleaseMessage::from_pdu(&pdu, ctx) {
            let constructed = admitted.message.construct(ctx).unwrap();
            let wire = encode(&constructed, EncodeContext::default()).unwrap();
            let received = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
            assert!(ReleaseMessage::from_pdu(&received, ctx).is_ok());
        }
        if let Ok(admitted) = NasMessage::from_pdu(&pdu, ctx) {
            nas::reconstruct(&admitted.message, ctx, EncodeContext::default());
        }
        if let Ok(wire) = encode(&pdu, EncodeContext::default()) {
            assert_eq!(pdu.wire_len(EncodeContext::default()).unwrap(), wire.len());
            assert!(Pdu::decode_owned(Bytes::from(wire), ctx).unwrap().kind == pdu.kind);
        }
    }
    let ies: Vec<_> = data
        .chunks(256)
        .take(32)
        .filter(|chunk| chunk.len() >= 3)
        .map(|chunk| {
            ProtocolIe::new(
                u16::from_be_bytes([chunk[0], chunk[1]]),
                if chunk[2] & 1 == 0 {
                    Criticality::reject
                } else {
                    Criticality::ignore
                },
                &chunk[3..],
            )
        })
        .collect();
    if let Ok(pdu) = Pdu::from_protocol_ies(MessageType::NgSetupRequest, &ies, ctx) {
        let wire = encode(&pdu, EncodeContext::default()).unwrap();
        assert!(Pdu::decode_owned(Bytes::from(wire), ctx).unwrap().kind == pdu.kind);
    }
}

// --- shared replay harness (kept self-contained per crate) ---------------

/// Read every committed corpus file under `<crate>/fuzz/corpus`, recursively.
fn corpus_files() -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push((path, bytes));
            }
        }
    }
    out
}

/// Hostile constant inputs that should never appear in a real corpus but must
/// still decode without panicking: empty, single bytes, long zero/0xFF runs,
/// a byte ramp, and a header-shaped probe claiming a large length over a short
/// body.
fn adversarial_seeds() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0x00; 8],
        vec![0xFF; 8],
        vec![0x00; 4096],
        vec![0xFF; 4096],
        (0..=255u8).collect(),
        vec![0x20, 0x01, 0xFF, 0xFF, 0x00, 0x00],
    ]
}

#[test]
fn corpus_and_adversarial_inputs_never_panic() {
    let corpus = corpus_files();
    assert!(
        !corpus.is_empty(),
        "expected committed seed corpus under fuzz/corpus; found none"
    );

    let mut failures: Vec<String> = Vec::new();
    let mut checked: usize = 0;

    for (path, data) in &corpus {
        if std::panic::catch_unwind(|| exercise(data)).is_err() {
            failures.push(format!("corpus:{}", path.display()));
        }
        checked += 1;
        // Truncations of each corpus entry exercise "length says N, only M
        // bytes present" paths, the classic source of decode panics.
        for i in 0..=data.len().min(256) {
            let slice = &data[..i];
            if std::panic::catch_unwind(|| exercise(slice)).is_err() {
                failures.push(format!("truncation:{}[..{}]", path.display(), i));
            }
            checked += 1;
        }
    }

    for (idx, seed) in adversarial_seeds().iter().enumerate() {
        if std::panic::catch_unwind(|| exercise(seed)).is_err() {
            failures.push(format!("adversarial#{idx}"));
        }
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "decode panicked on {} of {} known input(s): {:#?}",
        failures.len(),
        checked,
        failures
    );
}
