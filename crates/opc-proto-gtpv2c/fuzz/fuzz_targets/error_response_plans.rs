#![no_main]

use core::num::NonZeroU32;

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{
    Gtpv2cErrorResponseDecision, Gtpv2cErrorResponsePlanner, Gtpv2cOffendingIe,
    Gtpv2cProtocolError, Gtpv2cProtocolErrorKind, Gtpv2cProtocolErrorResponseTeid,
    Gtpv2cRequestFailure, Gtpv2cSequenceNumber, Recovery,
    MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN,
};
use opc_protocol::{Encode, EncodeContext};

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or_default();
    let instance = data.get(1).copied().unwrap_or_default() & 0x0f;
    let Some(offending_ie) = Gtpv2cOffendingIe::new(selector, instance).ok() else {
        return;
    };
    let kind = match selector % 5 {
        0 => Gtpv2cProtocolErrorKind::InvalidMessageLength,
        1 => Gtpv2cProtocolErrorKind::MissingMandatoryIe(offending_ie),
        2 => Gtpv2cProtocolErrorKind::MissingConditionalIe(offending_ie),
        3 => Gtpv2cProtocolErrorKind::InvalidIeLength(offending_ie),
        _ => Gtpv2cProtocolErrorKind::IncorrectIe(offending_ie),
    };
    let response_teid = if selector & 1 == 0 {
        Gtpv2cProtocolErrorResponseTeid::NoLookup
    } else {
        let raw_teid = u32::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
            data.get(4).copied().unwrap_or_default(),
            data.get(5).copied().unwrap_or_default(),
        ]) | 1;
        let Some(non_zero) = NonZeroU32::new(raw_teid) else {
            return;
        };
        Gtpv2cProtocolErrorResponseTeid::Remote(non_zero)
    };
    let failure = if selector % 7 == 0 {
        Gtpv2cRequestFailure::UnknownReceivedTeid
    } else {
        Gtpv2cRequestFailure::Protocol(Gtpv2cProtocolError::new(kind, response_teid))
    };
    let local_sequence = ((data.get(6).copied().unwrap_or_default() as u32) << 16)
        | ((data.get(7).copied().unwrap_or_default() as u32) << 8)
        | data.get(8).copied().unwrap_or_default() as u32;
    let Some(local_sequence) = Gtpv2cSequenceNumber::new(local_sequence).ok() else {
        return;
    };
    let planner = Gtpv2cErrorResponsePlanner::new(
        local_sequence,
        Recovery {
            restart_counter: data.get(9).copied().unwrap_or_default(),
        },
    );

    if let Gtpv2cErrorResponseDecision::Respond(plan) = planner.plan(data, failure) {
        assert!(plan.planned_output_len() <= MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN);
        assert_eq!(
            plan.amplification_metadata().planned_output_len,
            plan.planned_output_len()
        );
        let mut encoded = BytesMut::new();
        if plan
            .encode(&mut encoded, EncodeContext::default())
            .is_ok()
        {
            assert_eq!(encoded.len(), plan.planned_output_len());
        }
    }
});
