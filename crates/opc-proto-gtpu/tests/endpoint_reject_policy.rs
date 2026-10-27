//! Independent TS 29.281 5.2.1 endpoint-admission vectors.

use opc_proto_gtpu::GtpuMessage;
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, UnknownIePolicy, ValidationLevel,
};

const REQUIRED: &[(u8, &[u8])] = &[
    (
        0x81,
        &[
            0x36, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0x81, 1, 0xaa, 0xbb, 0,
        ],
    ),
    (
        0x82,
        &[
            0x36, 0xff, 0, 12, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0x82, 2, 2, 0x34, 0x56, 0, 0, 0, 0,
        ],
    ),
    (
        0x83,
        &[
            0x36, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0x83, 1, 0xaa, 0xbb, 0,
        ],
    ),
    (
        0x84,
        &[
            0x36, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0x84, 1, 0xaa, 0xbb, 0,
        ],
    ),
    (
        0xc0,
        &[
            0x36, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0xc0, 1, 0xaa, 0xbb, 0,
        ],
    ),
];

#[test]
fn reject_refuses_parseable_required_extensions_by_endpoint_profile() {
    for validation_level in [
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        let context = DecodeContext {
            validation_level,
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        // Collect the whole domain before asserting, so a failure records every
        // required type rather than stopping at the first admitted format.
        let outcomes: Vec<_> = REQUIRED
            .iter()
            .map(|(kind, wire)| {
                let result = GtpuMessage::decode(wire, context)
                    .map(|_| ())
                    .map_err(|error| error.code().clone());
                eprintln!("{validation_level:?} type={kind:#04x}: {result:?}");
                (*kind, result)
            })
            .collect();
        let expected: Vec<_> = REQUIRED
            .iter()
            .map(|(kind, _)| (*kind, Err(DecodeErrorCode::UnknownCriticalIe)))
            .collect();
        assert_eq!(outcomes, expected);
    }
}

#[test]
fn preserve_and_drop_keep_parseable_required_extension_bytes() {
    for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        for validation_level in [
            ValidationLevel::Structural,
            ValidationLevel::Strict,
            ValidationLevel::ProcedureAware,
        ] {
            let context = DecodeContext {
                validation_level,
                unknown_ie_policy,
                ..DecodeContext::default()
            };
            for (kind, wire) in REQUIRED {
                let (tail, message) = GtpuMessage::decode(wire, context).unwrap();
                assert!(tail.is_empty());
                assert_eq!(message.raw_extension_headers, &wire[12..]);
                let headers: Vec<_> = message.extensions().map(Result::unwrap).collect();
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].ext_type, *kind);
                assert_eq!(headers[0].content, &wire[13..wire.len() - 1]);
                assert_eq!(headers[0].next_ext_type, 0);
            }
        }
    }
}
