//! Shared fuzz/replay assertions. Synthetic key and NAS comparisons never
//! print values, including on failure.

#[path = "context_optionals.rs"]
pub mod context_optionals;

use bytes::Bytes;
use opc_proto_ngap::n3iwf::context_fields::SecurityAlgorithmMasks;
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::n3iwf::session_lists::SessionSetupRequests;
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: 24,
        max_ies: 256,
        ..ctx
    };
    exercise_bounded(data, ctx, output);
}

pub fn exercise_bounded(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    context_optionals::exercise_leaf(data, ctx, output);
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok(mut admitted) = ResourceSetupMessage::from_pdu(&pdu, ctx) else {
        return;
    };
    if let ResourceSetupMessage::InitialRequest(value) = &mut admitted.message {
        context_optionals::reconstruct(value);
    }
    let constructed = match &admitted.message {
        ResourceSetupMessage::InitialRequest(value) => {
            value.construct(SecurityAlgorithmMasks::new(1, 2, 4, 8), ctx)
        }
        ResourceSetupMessage::InitialResponse(value) => value.construct(ctx),
        ResourceSetupMessage::InitialFailure(value) => value.construct(ctx),
        ResourceSetupMessage::SessionRequest(value) => value.construct(ctx),
        ResourceSetupMessage::SessionResponse(value) => value.construct(ctx),
    }
    .unwrap();
    let wire = encode(&constructed, output).unwrap();
    let received = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
    let readmitted = ResourceSetupMessage::from_pdu(&received, ctx).unwrap();
    assert!(readmitted.notify_ie_ids.is_empty());
    assert!(readmitted.transfer_diagnostics.is_empty());
    assert_eq!(
        readmitted.ignored_ie_count,
        usize::from(matches!(
            readmitted.message,
            ResourceSetupMessage::InitialRequest(_)
        ))
    );
    match (&admitted.message, &readmitted.message) {
        (ResourceSetupMessage::InitialRequest(a), ResourceSetupMessage::InitialRequest(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran);
            assert!(a.guami == b.guami && a.allowed == b.allowed);
            assert!(a.key.expose_bytes() == b.key.expose_bytes());
            assert!(a.aggregate_bit_rate == b.aggregate_bit_rate);
            assert!(a.old_amf == b.old_amf && a.extended_old_amf == b.extended_old_amf);
            assert!(a.trace == b.trace && a.masked_imeisv == b.masked_imeisv);
            assert!(a.partially_allowed_nssai == b.partially_allowed_nssai);
            assert!(a.nas.as_ref().map(|n| n.as_bytes()) == b.nas.as_ref().map(|n| n.as_bytes()));
            match (&a.sessions, &b.sessions) {
                (Some(a), Some(b)) => same_requests(a, b),
                (None, None) => {}
                _ => panic!("context session presence changed"),
            }
        }
        (ResourceSetupMessage::InitialResponse(a), ResourceSetupMessage::InitialResponse(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran && a.sessions == b.sessions);
        }
        (ResourceSetupMessage::InitialFailure(a), ResourceSetupMessage::InitialFailure(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran && a.cause == b.cause && a.failed == b.failed);
        }
        (ResourceSetupMessage::SessionRequest(a), ResourceSetupMessage::SessionRequest(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran);
            assert!(a.aggregate_bit_rate == b.aggregate_bit_rate);
            assert!(a.nas.as_ref().map(|n| n.as_bytes()) == b.nas.as_ref().map(|n| n.as_bytes()));
            same_requests(&a.sessions, &b.sessions);
        }
        (ResourceSetupMessage::SessionResponse(a), ResourceSetupMessage::SessionResponse(b)) => {
            assert!(a.amf == b.amf && a.ran == b.ran);
            assert!(a.sessions == b.sessions && a.location == b.location);
        }
        _ => panic!("resource setup outcome changed"),
    }
}

fn same_requests(a: &SessionSetupRequests<'_>, b: &SessionSetupRequests<'_>) {
    assert_eq!(a.values().len(), b.values().len());
    for (a, b) in a.values().iter().zip(b.values()) {
        assert!(a.id == b.id && a.slice == b.slice && a.transfer == b.transfer);
        assert!(a.nas.as_ref().map(|n| n.as_bytes()) == b.nas.as_ref().map(|n| n.as_bytes()));
    }
}
