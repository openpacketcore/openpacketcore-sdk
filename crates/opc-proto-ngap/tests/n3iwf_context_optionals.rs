use opc_proto_ngap::decode;
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_protocol::{DecodeContext, DuplicateIePolicy, ValidationLevel};
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-context-optionals.json")).unwrap()
}
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_depth: 24,
        max_ies: 256,
        max_message_len: 131072,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}

#[test]
fn independent_initial_context_optionals_are_admitted() {
    for row in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["admit"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        assert!(
            ResourceSetupMessage::from_pdu(&pdu, context()).is_ok(),
            "applicable Initial Context optional field remains unsupported: {}",
            row["name"]
        );
    }
}

use opc_proto_ngap::n3iwf::context_fields::{
    AllowedNssai, PartiallyAllowedNssai, SecurityAlgorithmMasks,
};
use opc_proto_ngap::n3iwf::nas_fields::{ExtendedAmfName, MaskedImeisv};
use opc_proto_ngap::n3iwf::resource_setup::InitialContextRequest;
use opc_proto_ngap::n3iwf::setup_fields::AmfName;
use opc_proto_ngap::n3iwf::trace_fields::{TraceActivation, TraceDepth};
use opc_proto_ngap::{encode, Message, PduKind};
use opc_protocol::EncodeContext;
use opc_types::Snssai;

fn slices(model: &Value) -> Vec<Snssai> {
    model
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let sst = v["sst"].as_u64().unwrap() as u8;
            match v["sd"].as_str() {
                None => Snssai::without_sd(sst),
                Some(sd) => Snssai::new(sst, Some(sd)).unwrap(),
            }
        })
        .collect()
}
fn trace(model: &Value) -> TraceActivation {
    let bits = model["bits"].as_u64().unwrap() as u8;
    let width = usize::from(bits).div_ceil(8) * 2;
    let mut address = bytes(&format!("{:0>width$}", model["address"].as_str().unwrap()));
    let padding = (8 - bits % 8) % 8;
    if padding != 0 {
        let mut carry = 0;
        for byte in address.iter_mut().rev() {
            let next = *byte >> (8 - padding);
            *byte = (*byte << padding) | carry;
            carry = next;
        }
        assert_eq!(carry, 0);
    }
    TraceActivation::new(
        bytes(model["id"].as_str().unwrap()).try_into().unwrap(),
        model["interfaces"].as_u64().unwrap() as u8,
        TraceDepth::new(model["depth"].as_u64().unwrap() as u8).unwrap(),
        bits,
        &address,
    )
    .unwrap()
}
fn model_fields(value: &mut InitialContextRequest<'_>, model: &Value) {
    value.allowed = AllowedNssai::new(
        model
            .get("allowed")
            .map(slices)
            .unwrap_or_else(|| vec![Snssai::without_sd(1)]),
    )
    .unwrap();
    value.old_amf = model["old_amf"].as_str().map(|v| AmfName::new(v).unwrap());
    value.extended_old_amf = model
        .get("extended")
        .map(|v| ExtendedAmfName::new(v["visible"].as_str(), v["utf8"].as_str()).unwrap());
    value.masked_imeisv = model["masked"]
        .as_str()
        .map(|v| MaskedImeisv::new(bytes(v).try_into().unwrap()));
    value.partially_allowed_nssai = model
        .get("partial")
        .map(|v| PartiallyAllowedNssai::new(slices(v)).unwrap());
    value.trace = model.get("trace").map(trace);
}
fn same_fields(actual: &InitialContextRequest<'_>, wanted: &InitialContextRequest<'_>) {
    // Never print identities, key/NAS data, trace parameters or peer addresses.
    assert!(actual.amf == wanted.amf && actual.ran == wanted.ran && actual.guami == wanted.guami);
    assert!(actual.key.expose_bytes() == wanted.key.expose_bytes());
    assert!(
        actual.allowed == wanted.allowed
            && actual.partially_allowed_nssai == wanted.partially_allowed_nssai
    );
    assert!(actual.old_amf == wanted.old_amf && actual.extended_old_amf == wanted.extended_old_amf);
    assert!(actual.masked_imeisv == wanted.masked_imeisv && actual.trace == wanted.trace);
    assert!(
        actual.nas.is_none() && actual.sessions.is_none() && actual.aggregate_bit_rate.is_none()
    );
}
fn masks(reference: &Value) -> SecurityAlgorithmMasks {
    let v: Vec<_> = reference["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u16)
        .collect();
    SecurityAlgorithmMasks::new(v[0], v[1], v[2], v[3])
}

#[test]
fn independent_semantics_and_construction_match_all_outcomes() {
    let reference = reference();
    let base = decode(
        &bytes(reference["base_wire_hex"].as_str().unwrap()),
        context(),
    )
    .unwrap();
    let ResourceSetupMessage::InitialRequest(mut expected) =
        ResourceSetupMessage::from_pdu(&base, context())
            .unwrap()
            .message
    else {
        panic!()
    };
    assert_eq!(reference["cases"].as_array().unwrap().len(), 453);
    let mut admitted_count = 0;
    let mut constructed_count = 0;
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context());
        let result = pdu
            .as_ref()
            .ok()
            .and_then(|pdu| ResourceSetupMessage::from_pdu(pdu, context()).ok());
        model_fields(&mut expected, &row["model"]);
        context_optionals::reconstruct(&mut expected);
        if row["admit"] != true {
            assert!(result.is_none(), "negative case admitted: {}", row["name"]);
            if matches!(
                row["reference_error"].as_str(),
                Some("combined-slice-count" | "overlapping-slice-lists")
            ) {
                assert!(expected.construct(masks(&reference), context()).is_err());
            }
            continue;
        }
        let received = result.unwrap();
        let ResourceSetupMessage::InitialRequest(actual) = received.message else {
            panic!()
        };
        same_fields(&actual, &expected);
        assert_eq!(
            received.ignored_ie_count,
            1 + usize::from(row["unknown"] == "ignore")
        );
        assert_eq!(
            received.notify_ie_ids,
            if row["unknown"] == "notify" {
                vec![65530]
            } else {
                vec![]
            }
        );
        admitted_count += 1;
        if row["construct"] == true {
            let constructed = expected.construct(masks(&reference), context()).unwrap();
            assert!(
                encode(&constructed, EncodeContext::default()).unwrap() == wire,
                "independent construction mismatch: {}",
                row["name"]
            );
            assert!(expected
                .construct(
                    masks(&reference),
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..context()
                    }
                )
                .is_err());
            assert!(expected
                .construct(
                    masks(&reference),
                    DecodeContext {
                        max_depth: 7,
                        ..context()
                    }
                )
                .is_err());
            constructed_count += 1;
        }
    }
    assert_eq!(admitted_count, 378);
    assert_eq!(constructed_count, 375);
}

#[test]
fn independent_trace_layout_and_every_root_bit_length_match() {
    let reference = reference();
    let mut widths = [false; 160];
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("trace_wire_hex").is_some())
    {
        let value = trace(&row["model"]["trace"]);
        let wire = bytes(row["trace_wire_hex"].as_str().unwrap());
        assert!(
            value.encode(EncodeContext::default()).unwrap().as_bytes() == wire,
            "independent trace construction mismatch: {}",
            row["name"]
        );
        assert!(TraceActivation::decode(&wire, context()).unwrap() == value);
        widths[usize::from(value.address_bits()) - 1] = true;
        assert!(value
            .encode(EncodeContext {
                max_message_len: wire.len() - 1,
                ..EncodeContext::default()
            })
            .is_err());
        assert!(TraceActivation::decode(
            &wire,
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..context()
            }
        )
        .is_err());
        assert!(TraceActivation::decode(
            &wire,
            DecodeContext {
                max_depth: 1,
                ..context()
            }
        )
        .is_err());
        for length in 0..wire.len() {
            assert!(TraceActivation::decode(&wire[..length], context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(TraceActivation::decode(&trailing, context()).is_err());
    }
    assert!(widths.into_iter().all(|v| v));
    for depth in [6, 7, 255] {
        assert!(TraceDepth::new(depth).is_err());
    }
    for (bits, raw) in [
        (0, vec![]),
        (161, vec![0; 21]),
        (1, vec![1]),
        (8, vec![]),
        (8, vec![0; 2]),
        (159, vec![1; 20]),
    ] {
        assert!(TraceActivation::new([0; 8], 0, TraceDepth::Minimum, bits, &raw).is_err());
    }
    let value = TraceActivation::new([0; 8], 0xff, TraceDepth::Maximum, 8, &[0]).unwrap();
    assert_eq!(format!("{value:?}"), "TraceActivation([REDACTED])");
    assert_eq!(format!("{:?}", value.depth()), "TraceDepth([REDACTED])");
    let wire = value.encode(EncodeContext::default()).unwrap();
    for (offset, mask) in [
        (0, 0x80),
        (0, 0x40),
        (0, 1),
        (10, 0x80),
        (10, 0x60),
        (10, 8),
        (11, 1),
    ] {
        let mut changed = wire.as_bytes().to_vec();
        changed[offset] |= mask;
        assert!(TraceActivation::decode(&changed, context()).is_err());
    }
}

#[test]
fn duplicate_selection_and_mutable_criticalities_remain_authoritative() {
    let reference = reference();
    let base = decode(
        &bytes(reference["base_wire_hex"].as_str().unwrap()),
        context(),
    )
    .unwrap();
    let ResourceSetupMessage::InitialRequest(mut expected) =
        ResourceSetupMessage::from_pdu(&base, context())
            .unwrap()
            .message
    else {
        panic!()
    };
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("duplicate").is_some())
    {
        let id = row["duplicate"].as_u64().unwrap() as u16;
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        assert!(decode(&wire, context()).is_err());
        for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy: policy,
                ..context()
            };
            let mut pdu = decode(&wire, ctx).unwrap();
            if policy == DuplicateIePolicy::Last && row["last_reject"] == true {
                assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err());
                model_fields(&mut expected, &row["last_model"]);
                assert!(expected.construct(masks(&reference), ctx).is_err());
                continue;
            }
            let ResourceSetupMessage::InitialRequest(actual) =
                ResourceSetupMessage::from_pdu(&pdu, ctx).unwrap().message
            else {
                panic!()
            };
            model_fields(
                &mut expected,
                if policy == DuplicateIePolicy::Last {
                    &row["last_model"]
                } else {
                    &row["model"]
                },
            );
            same_fields(&actual, &expected);
            let PduKind::Initiating {
                message: Message::InitialContextSetupRequest(value),
                ..
            } = &mut pdu.kind
            else {
                panic!()
            };
            value
                .protocol_ies
                .0
                .iter_mut()
                .find(|v| v.id == id)
                .unwrap()
                .criticality = rasn::aper::decode(&[if id == 48 { 0x40 } else { 0 }]).unwrap();
            assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err());
        }
    }
}

#[path = "support/resource_setup.rs"]
mod resource_setup;
use resource_setup::context_optionals;

#[test]
fn complete_wire_and_leaf_mutations_remain_bounded() {
    let output = EncodeContext {
        max_message_len: 131072,
        ..EncodeContext::default()
    };
    let mut mutations = 0;
    for row in reference()["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        resource_setup::exercise(&wire, context(), output);
        for ctx in [
            context(),
            DecodeContext {
                max_depth: 8,
                max_ies: 8,
                ..context()
            },
        ] {
            resource_setup::exercise_bounded(&wire, ctx, output);
            let stride = (wire.len() / 64).max(1);
            for length in (0..wire.len()).step_by(stride) {
                resource_setup::exercise_bounded(&wire[..length], ctx, output);
                for mask in [1, 0x80, 0xff] {
                    let mut changed = wire.clone();
                    changed[length] ^= mask;
                    resource_setup::exercise_bounded(&changed, ctx, output);
                    mutations += 1;
                }
            }
            if let Some(raw) = row["trace_wire_hex"].as_str() {
                let leaf = bytes(raw);
                context_optionals::exercise_leaf(&leaf, ctx, output);
                for length in 0..leaf.len() {
                    context_optionals::exercise_leaf(&leaf[..length], ctx, output);
                    for mask in [1, 0x80, 0xff] {
                        let mut changed = leaf.clone();
                        changed[length] ^= mask;
                        context_optionals::exercise_leaf(&changed, ctx, output);
                        mutations += 1;
                    }
                }
            }
        }
    }
    assert!(mutations > 100_000);
    eprintln!("Initial Context optional-field bounded byte mutations: {mutations}");
}
