#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_diameter::apps::{self, APP_DICTIONARIES, SWM_PROJECTED_PROFILE_DICTIONARIES};
use opc_proto_diameter::error_answer::{
    inspect_diameter_request, DiameterRequestFailure, DiameterRequestInspection,
};
use opc_proto_diameter::peer::{
    parse_capabilities_exchange_request_with_provenance,
    parse_device_watchdog_request_with_provenance,
    parse_disconnect_peer_request_with_provenance,
};
use opc_proto_diameter::{Message, OwnedMessage};
use opc_protocol::{
    BorrowDecode, DecodeContext, EncodeContext, OwnedDecode, ValidationLevel,
};

fuzz_target!(|data: &[u8]| {
    // Bounded request inspection and error-context capture.
    if let DiameterRequestInspection::Request(envelope) =
        inspect_diameter_request(data, DecodeContext::conservative())
    {
        let _ = envelope.classify(data, APP_DICTIONARIES);
    }
    let _ = inspect_diameter_request(
        data,
        DecodeContext {
            max_depth: 0,
            ..DecodeContext::conservative()
        },
    );
    let _ = inspect_diameter_request(
        data,
        DecodeContext {
            max_ies: 1,
            ..DecodeContext::conservative()
        },
    );

    // Borrowed decode at the default (Structural) level.
    let ctx = DecodeContext::default();
    let _ = Message::decode(data, ctx);

    // Strict decode (reserved flag-bit / zero-padding enforcement).
    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_strict);

    // Header-only decode (exercises framing without AVP validation).
    let ctx_header = DecodeContext {
        validation_level: ValidationLevel::HeaderOnly,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_header);

    // Owned decode path.
    let _ = OwnedMessage::decode_owned(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::default(),
    );

    // Application-aware command resolution and cardinality validation.
    let _ = Message::decode_with_dictionary(
        data,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
    );
    let _ = OwnedMessage::decode_owned_with_dictionary(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::conservative(),
        APP_DICTIONARIES,
    );
    let _ = Message::decode_with_dictionary(
        data,
        DecodeContext::conservative(),
        SWM_PROJECTED_PROFILE_DICTIONARIES,
    );
    let _ = OwnedMessage::decode_owned_with_dictionary(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::conservative(),
        SWM_PROJECTED_PROFILE_DICTIONARIES,
    );

    // Dictionary-aware validation (grouped AVP recursion, depth-limited).
    if let Ok((_, message)) = Message::decode(data, DecodeContext::default()) {
        let _ = message.validate_avps_with_dictionary(
            DecodeContext::default(),
            APP_DICTIONARIES,
        );
        let ctx_shallow = DecodeContext {
            max_depth: 2,
            ..Default::default()
        };
        let _ = message.validate_avps_with_dictionary(ctx_shallow, APP_DICTIONARIES);

        // SDK-owned missing-field provenance and request-bound 5005 mapping.
        let parser_error = if message.header.application_id
            == opc_proto_diameter::base::APPLICATION_ID_COMMON_MESSAGES
            && message.header.flags.is_request()
        {
            if message.header.command_code
                == opc_proto_diameter::base::COMMAND_CAPABILITIES_EXCHANGE
            {
                parse_capabilities_exchange_request_with_provenance(
                    &message,
                    DecodeContext::conservative(),
                )
                .err()
            } else if message.header.command_code
                == opc_proto_diameter::base::COMMAND_DEVICE_WATCHDOG
            {
                parse_device_watchdog_request_with_provenance(
                    &message,
                    DecodeContext::conservative(),
                )
                .err()
            } else if message.header.command_code
                == opc_proto_diameter::base::COMMAND_DISCONNECT_PEER
            {
                parse_disconnect_peer_request_with_provenance(
                    &message,
                    DecodeContext::conservative(),
                )
                .err()
            } else {
                None
            }
        } else if message.header.application_id == apps::swm::APPLICATION_ID
            && message.header.command_code == apps::swm::COMMAND_DIAMETER_EAP
            && message.header.flags.is_request()
        {
            apps::swm::parse_swm_diameter_eap_request_with_provenance(
                &message,
                DecodeContext::conservative(),
            )
            .err()
        } else {
            None
        };
        if let (
            Some(parser_error),
            DiameterRequestInspection::Request(envelope),
        ) = (
            parser_error,
            inspect_diameter_request(data, DecodeContext::conservative()),
        ) {
            let _ = DiameterRequestFailure::from_parser_error(
                &envelope,
                data,
                &parser_error,
                DecodeContext::conservative(),
                APP_DICTIONARIES,
                EncodeContext::default(),
            );
        }
    }
});
