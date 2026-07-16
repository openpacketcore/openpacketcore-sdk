use std::panic::{catch_unwind, AssertUnwindSafe};

use bytes::BytesMut;
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TftParameter, TrafficFlowTemplate, UnknownTftParameter,
};
use quickcheck::{QuickCheck, TestResult};

fn property_model_roundtrip(seed: Vec<(u8, u8, u16)>, operation_selector: u8) -> TestResult {
    let mut seen_identifiers = [false; 16];
    let mut seen_precedence = [false; 256];
    let mut filters = Vec::new();
    for (raw_identifier, precedence, port) in seed.into_iter().take(15) {
        let identifier_value = raw_identifier & 0x0f;
        let identifier_index = usize::from(identifier_value);
        let precedence_index = usize::from(precedence);
        if seen_identifiers[identifier_index] || seen_precedence[precedence_index] {
            continue;
        }
        seen_identifiers[identifier_index] = true;
        seen_precedence[precedence_index] = true;
        let identifier = match PacketFilterIdentifier::new(identifier_value) {
            Ok(value) => value,
            Err(_) => return TestResult::failed(),
        };
        let filter = match PacketFilter::new(
            identifier,
            PacketFilterDirection::Bidirectional,
            precedence,
            vec![PacketFilterComponent::SingleRemotePort(port)],
        ) {
            Ok(value) => value,
            Err(_) => return TestResult::failed(),
        };
        filters.push(filter);
    }
    if filters.is_empty() {
        let identifier = match PacketFilterIdentifier::new(0) {
            Ok(value) => value,
            Err(_) => return TestResult::failed(),
        };
        let filter = match PacketFilter::new(
            identifier,
            PacketFilterDirection::Bidirectional,
            0,
            vec![PacketFilterComponent::SingleRemotePort(0)],
        ) {
            Ok(value) => value,
            Err(_) => return TestResult::failed(),
        };
        filters.push(filter);
    }

    let model = match operation_selector % 3 {
        0 => TrafficFlowTemplate::create_new(filters, Vec::new()),
        1 => TrafficFlowTemplate::add_packet_filters(filters, Vec::new()),
        _ => TrafficFlowTemplate::replace_packet_filters(filters, Vec::new()),
    };
    let model = match model {
        Ok(value) => value,
        Err(_) => return TestResult::failed(),
    };
    let mut encoded = BytesMut::new();
    if model.encode_value(&mut encoded).is_err() {
        return TestResult::failed();
    }
    TestResult::from_bool(TrafficFlowTemplate::decode_value(&encoded) == Ok(model))
}

fn property_unknown_parameters_roundtrip(identifier: u8, bytes: Vec<u8>) -> TestResult {
    if matches!(identifier, 1..=3) {
        return TestResult::discard();
    }
    let bounded = bytes.into_iter().take(64).collect::<Vec<_>>();
    let parameter = match UnknownTftParameter::new(identifier, bounded) {
        Ok(value) => TftParameter::Unknown(value),
        Err(_) => return TestResult::failed(),
    };
    let model = match TrafficFlowTemplate::no_operation(vec![parameter]) {
        Ok(value) => value,
        Err(_) => return TestResult::failed(),
    };
    let mut encoded = BytesMut::new();
    if model.encode_value(&mut encoded).is_err() {
        return TestResult::failed();
    }
    TestResult::from_bool(TrafficFlowTemplate::decode_value(&encoded) == Ok(model))
}

fn property_arbitrary_input_never_panics(bytes: Vec<u8>) -> bool {
    let bounded = bytes.into_iter().take(512).collect::<Vec<_>>();
    catch_unwind(AssertUnwindSafe(|| {
        if let Ok(value) = TrafficFlowTemplate::decode_value(&bounded) {
            let mut encoded = BytesMut::new();
            let _ = value.encode_value(&mut encoded);
        }
    }))
    .is_ok()
}

#[test]
fn generated_valid_models_roundtrip() {
    QuickCheck::new()
        .tests(10_000)
        .quickcheck(property_model_roundtrip as fn(Vec<(u8, u8, u16)>, u8) -> TestResult);
}

#[test]
fn generated_unknown_parameters_preserve_bytes() {
    QuickCheck::new()
        .tests(10_000)
        .quickcheck(property_unknown_parameters_roundtrip as fn(u8, Vec<u8>) -> TestResult);
}

#[test]
fn arbitrary_bounded_inputs_have_stable_rejection() {
    QuickCheck::new()
        .tests(50_000)
        .quickcheck(property_arbitrary_input_never_panics as fn(Vec<u8>) -> bool);
}
