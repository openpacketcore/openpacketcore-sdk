#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_eap::eap5g::{
    AnParameters, BootstrapRequirements, DuplicatePolicy, Limits, Message, NasPdu, Packet,
    Presence, RequestedNssai,
};

fn nas(message: Message<'_>) -> Option<&[u8]> {
    match message {
        Message::NasRequest(nas) | Message::NasResponse { nas, .. } => Some(nas.as_bytes()),
        _ => None,
    }
}

fn check(data: &[u8], limits: Limits) {
    match Packet::parse(data, limits) {
        Ok(packet) => {
            let encoded = packet
                .encode(limits)
                .expect("canonical encoding must fit receive limits");
            let reparsed = Packet::parse(&encoded, limits).expect("canonical packet must parse");
            assert!(
                nas(packet.message()) == nas(reparsed.message()),
                "opaque NAS changed"
            );
            assert!(
                reparsed.encode(limits).expect("encode") == encoded,
                "canonicalization unstable"
            );
            let _ = format!("{packet:?}");
            if let Message::NasResponse { parameters, .. } = packet.message() {
                for presence in [Presence::Required, Presence::Optional, Presence::Absent] {
                    let _ = parameters.validate_bootstrap(BootstrapRequirements {
                        guami: presence,
                        requested_nssai: presence,
                        selected_nid: presence,
                        onboarding: presence,
                    });
                }
            }
        }
        Err(error) => {
            // Errors consist solely of stable static metadata.
            assert!(format!("{error} {error:?}").len() < 100);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    for duplicates in [DuplicatePolicy::Reject, DuplicatePolicy::FirstWins] {
        let limits = Limits {
            duplicates,
            ..Default::default()
        };
        check(data, limits);
        if data.len() >= 4 {
            check(
                data,
                Limits {
                    max_packet_len: u16::from_be_bytes([data[0], data[1]]),
                    max_an_bytes: u16::from(data[2]),
                    max_parameters: u16::from(data[3]),
                    ..limits
                },
            );
        }
        // Reach nested framing without needing to rediscover the expanded header.
        if data.len() <= 65521 {
            let length = (14 + data.len()) as u16;
            for (code, id) in [(1, 2), (2, 2), (1, 3)] {
                let mut wire = vec![code, 0, 0, 0, 254, 0, 0x28, 0xaf, 0, 0, 0, 3, id, 0];
                wire[2..4].copy_from_slice(&length.to_be_bytes());
                wire.extend_from_slice(data);
                check(&wire, limits);
            }
        }
        if let Ok(nas) = NasPdu::new(data) {
            for message in [
                Message::NasRequest(nas),
                Message::NasResponse {
                    parameters: AnParameters::default(),
                    nas,
                },
            ] {
                let packet = Packet::new(0, message);
                let mut output = [0xa5; 32];
                if packet.encode_into(&mut output, limits).is_err() {
                    assert!(output == [0xa5; 32], "failed encode changed output");
                }
                if let Ok(encoded) = packet.encode(limits) {
                    check(&encoded, limits);
                }
            }
        }
    }
    let _ = RequestedNssai::from_value(data);
});
