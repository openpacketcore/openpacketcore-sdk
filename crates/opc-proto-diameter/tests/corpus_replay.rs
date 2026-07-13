//! Deterministic corpus-replay regression guard for Diameter decode paths.
//!
//! Replays every committed fuzz corpus input — plus byte-truncations of each
//! entry and a set of hostile constant inputs — through the same decode entry
//! points as the libFuzzer targets in `fuzz/fuzz_targets/`.
//!
//! This runs on stable Rust in ordinary `cargo test`/CI and requires no nightly
//! toolchain or libFuzzer. Its job is regression protection: if a future change
//! makes any decode path panic on a known input, this test fails and names the
//! offending input.

use bytes::Bytes;
use opc_proto_diameter::{validate_avp_region, Message, OwnedMessage, RawAvp, DIAMETER_HEADER_LEN};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

#[cfg(any(
    feature = "app-gx",
    feature = "app-rf",
    feature = "app-s6a",
    feature = "app-s6b",
    feature = "app-swm",
    feature = "app-swx"
))]
use opc_proto_diameter::apps::APP_DICTIONARIES;

#[cfg(feature = "app-swm")]
use opc_proto_diameter::apps::SWM_PROJECTED_PROFILE_DICTIONARIES;

/// Every decode entry point the fuzz targets exercise. Must never panic,
/// regardless of input. Decode returning `Err` is expected and fine.
fn exercise_message(data: &[u8]) {
    // Borrowed decode at the default (Structural) level.
    let _ = Message::decode(data, DecodeContext::default());

    // Strict decode (reserved flag-bit / zero-padding enforcement).
    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_strict);

    // Header-only decode (framing without AVP validation).
    let ctx_header = DecodeContext {
        validation_level: ValidationLevel::HeaderOnly,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_header);

    // Owned decode path.
    let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());

    // Application-aware command/cardinality paths.
    #[cfg(any(
        feature = "app-gx",
        feature = "app-rf",
        feature = "app-s6a",
        feature = "app-s6b",
        feature = "app-swm",
        feature = "app-swx"
    ))]
    {
        let _ =
            Message::decode_with_dictionary(data, DecodeContext::conservative(), APP_DICTIONARIES);
        let _ = OwnedMessage::decode_owned_with_dictionary(
            Bytes::copy_from_slice(data),
            DecodeContext::conservative(),
            APP_DICTIONARIES,
        );
        #[cfg(feature = "app-swm")]
        {
            let _ = Message::decode_with_dictionary(
                data,
                DecodeContext::conservative(),
                SWM_PROJECTED_PROFILE_DICTIONARIES,
            );
            let _ = OwnedMessage::decode_owned_with_dictionary(
                Bytes::copy_from_slice(data),
                DecodeContext::conservative(),
                SWM_PROJECTED_PROFILE_DICTIONARIES,
            );
        }
    }

    // Dictionary-aware validation (grouped AVP recursion, depth-limited).
    #[cfg(any(
        feature = "app-gx",
        feature = "app-rf",
        feature = "app-s6a",
        feature = "app-s6b",
        feature = "app-swm",
        feature = "app-swx"
    ))]
    if let Ok((_, message)) = Message::decode(data, DecodeContext::default()) {
        let _ = message.validate_avps_with_dictionary(DecodeContext::default(), APP_DICTIONARIES);
        let ctx_shallow = DecodeContext {
            max_depth: 2,
            ..Default::default()
        };
        let _ = message.validate_avps_with_dictionary(ctx_shallow, APP_DICTIONARIES);
    }
}

/// AVP-region entry points exercised by the `decode_avp` fuzz target.
fn exercise_avp(data: &[u8]) {
    let _ = validate_avp_region(data, DecodeContext::default());

    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let _ = validate_avp_region(data, ctx_strict);

    #[cfg(any(
        feature = "app-gx",
        feature = "app-rf",
        feature = "app-s6a",
        feature = "app-s6b",
        feature = "app-swm",
        feature = "app-swx"
    ))]
    {
        let _ =
            validate_avp_region_with_dictionary(data, DecodeContext::default(), APP_DICTIONARIES);

        let ctx_strict = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..Default::default()
        };
        let _ = validate_avp_region_with_dictionary(data, ctx_strict, APP_DICTIONARIES);
    }

    let mut remaining = data;
    while !remaining.is_empty() {
        match RawAvp::decode(remaining, DecodeContext::default()) {
            Ok((next, _avp)) => {
                #[cfg(any(
                    feature = "app-gx",
                    feature = "app-rf",
                    feature = "app-s6a",
                    feature = "app-s6b",
                    feature = "app-swm",
                    feature = "app-swx"
                ))]
                let _ = _avp.validate_grouped_value_with_dictionary(
                    DecodeContext::default(),
                    APP_DICTIONARIES,
                );
                let consumed = remaining.len() - next.len();
                if consumed == 0 {
                    break;
                }
                remaining = next;
            }
            Err(_) => break,
        }
    }
}

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
/// still decode without panicking.
fn adversarial_seeds() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0x00; 8],
        vec![0xFF; 8],
        vec![0x00; DIAMETER_HEADER_LEN],
        vec![0xFF; DIAMETER_HEADER_LEN],
        vec![0x00; 4096],
        vec![0xFF; 4096],
        (0..=255u8).collect(),
        // Header claiming a 24-bit length of 0xFF_FFFF over a short body.
        {
            let mut v = vec![0x01, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x01, 0x00];
            v.extend_from_slice(&[0x00; 20]);
            v
        },
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
        if std::panic::catch_unwind(|| exercise_message(data)).is_err() {
            failures.push(format!("message: {}", path.display()));
        }
        checked += 1;

        if std::panic::catch_unwind(|| exercise_avp(data)).is_err() {
            failures.push(format!("avp: {}", path.display()));
        }
        checked += 1;

        // Truncations of each corpus entry exercise "length says N, only M
        // bytes present" paths, the classic source of decode panics.
        for i in 0..=data.len().min(256) {
            let slice = &data[..i];
            if std::panic::catch_unwind(|| exercise_message(slice)).is_err() {
                failures.push(format!("message truncation: {}[..{}]", path.display(), i));
            }
            if std::panic::catch_unwind(|| exercise_avp(slice)).is_err() {
                failures.push(format!("avp truncation: {}[..{}]", path.display(), i));
            }
            checked += 2;
        }
    }

    for (idx, seed) in adversarial_seeds().iter().enumerate() {
        if std::panic::catch_unwind(|| exercise_message(seed)).is_err() {
            failures.push(format!("message adversarial#{idx}"));
        }
        if std::panic::catch_unwind(|| exercise_avp(seed)).is_err() {
            failures.push(format!("avp adversarial#{idx}"));
        }
        checked += 2;
    }

    assert!(
        failures.is_empty(),
        "decode panicked on {} of {} known input(s): {:#?}",
        failures.len(),
        checked,
        failures
    );
}

// -----------------------------------------------------------------------------
// Targeted malformed-input tests
// -----------------------------------------------------------------------------

use bytes::BufMut;
use opc_proto_diameter::{
    dictionary::{AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, Dictionary, DictionarySet},
    validate_avp_region_with_dictionary, ApplicationId, AvpCode, AvpFlags, AvpHeader, CommandCode,
    CommandFlags, Header, VendorId, AVP_HEADER_LEN, AVP_VENDOR_HEADER_LEN,
};
use opc_protocol::{DuplicateIePolicy, Encode, EncodeContext, SpecRef};

/// Minimal dictionary that marks Failed-AVP (279) as grouped, used by the depth-bomb
/// test so it does not depend on any `app-*` feature.
static FAILED_AVP_DICTIONARY: [AvpDefinition; 1] = [AvpDefinition::new(
    AvpKey::ietf(AvpCode::new(279)),
    "Failed-AVP",
    AvpDataType::Grouped,
    AvpFlagRules::base_mandatory(),
    SpecRef::new("ietf", "RFC6733", "7.5"),
)];

fn failed_avp_dictionary_set() -> DictionarySet<'static> {
    static DICTIONARY: Dictionary =
        Dictionary::new("corpus-replay-depth-bomb", &[], &[], &FAILED_AVP_DICTIONARY);
    static DICTIONARIES: [&Dictionary; 1] = [&DICTIONARY];
    DictionarySet::new(&DICTIONARIES)
}

fn encode_raw_avp(header: AvpHeader, value: &[u8]) -> Vec<u8> {
    let avp = RawAvp {
        header,
        value,
        padding: &[],
    };
    let mut encoded = bytes::BytesMut::new();
    avp.encode(&mut encoded, EncodeContext::default())
        .expect("raw AVP encode must succeed");
    encoded.to_vec()
}

fn encode_message(raw_avps: &[u8]) -> Vec<u8> {
    let header = Header::new(
        CommandFlags::request(false),
        CommandCode::new(257),
        ApplicationId::new(0),
        0x0102_0304,
        0xA0B0_C0D0,
    )
    .with_length((DIAMETER_HEADER_LEN + raw_avps.len()) as u32);
    let mut encoded = bytes::BytesMut::new();
    header
        .encode(&mut encoded, EncodeContext::default())
        .expect("message header encode must succeed");
    encoded.put_slice(raw_avps);
    encoded.to_vec()
}

#[test]
fn arbitrary_avp_tree_does_not_panic() {
    // A sequence of random-looking but structurally plausible AVPs: vendor,
    // mandatory, padded, and empty values.
    let mut region = bytes::BytesMut::new();
    region.put_slice(&encode_raw_avp(
        AvpHeader::ietf(AvpCode::new(1), true),
        b"u",
    ));
    region.put_slice(&encode_raw_avp(
        AvpHeader::vendor(AvpCode::new(7000), VendorId::new(10415), false),
        b"vendor",
    ));
    region.put_slice(&encode_raw_avp(
        AvpHeader::ietf(AvpCode::new(9999), false),
        b"",
    ));

    // Should not panic; the raw region validator tolerates unknown AVPs and only
    // rejects structural problems (length, count, duplicates).
    let _ = validate_avp_region(&region, DecodeContext::default());
}

#[test]
fn grouped_depth_bomb_is_rejected() {
    // Build a nested Failed-AVP chain: each parent wraps the previous child.
    // With max_depth=2, three levels (leaf + two grouped parents) exceed the
    // allowed recursion for dictionary-marked grouped AVPs.
    let leaf = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let mut nested = leaf.clone();
    for _ in 0..3 {
        nested = encode_raw_avp(AvpHeader::ietf(AvpCode::new(279), true), &nested);
    }

    let ctx = DecodeContext {
        max_depth: 2,
        ..Default::default()
    };
    let result = validate_avp_region_with_dictionary(&nested, ctx, failed_avp_dictionary_set());
    assert!(
        matches!(
            result,
            Err(ref error) if matches!(error.code(), opc_protocol::DecodeErrorCode::DepthExceeded)
        ),
        "expected DepthExceeded for grouped depth bomb, got {result:?}"
    );
}

#[test]
fn invalid_avp_lengths_are_rejected() {
    // AVP length shorter than its header.
    let too_short = [0, 0, 1, 8, 0x40, 0, 0, AVP_HEADER_LEN as u8 - 1];
    let result = validate_avp_region(&too_short, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::InvalidLength { .. })
    ));

    // AVP length claims more bytes than are present.
    let truncated = [0, 0, 1, 8, 0x40, 0, 0x00, 0x20];
    let result = validate_avp_region(&truncated, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::Truncated)
    ));

    // Vendor-specific AVP with length shorter than the vendor header.
    let bad_vendor = [
        0,
        0,
        1,
        8,
        0x80,
        0,
        0,
        AVP_VENDOR_HEADER_LEN as u8 - 1,
        0,
        0,
        0x28,
        0xCF,
    ];
    let result = validate_avp_region(&bad_vendor, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::InvalidLength { .. })
    ));
}

#[test]
fn duplicate_mandatory_avps_are_rejected() {
    let origin_host = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let mut region = bytes::BytesMut::new();
    region.put_slice(&origin_host);
    region.put_slice(&origin_host);

    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..Default::default()
    };
    let result = validate_avp_region(&region, ctx);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::DuplicateIe)
    ));
}

#[test]
fn bad_padding_is_rejected_in_strict_mode() {
    // Value length 1 with non-zero padding bytes.
    let avp = [
        0,
        0,
        1,
        8,
        AvpFlags::MANDATORY,
        0,
        0,
        (AVP_HEADER_LEN + 1) as u8,
        b'x',
        0xFF,
        0xFF,
        0xFF,
    ];
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let result = validate_avp_region(&avp, ctx);
    assert!(matches!(
        result,
        Err(error) if matches!(
            error.code(),
            opc_protocol::DecodeErrorCode::Structural {
                reason: "diameter AVP padding must be zero"
            }
        )
    ));
}

#[test]
fn message_length_truncation_is_rejected() {
    let raw_avps = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let mut encoded = encode_message(&raw_avps);

    // Claim the message is longer than the actual bytes, but still within the
    // default max_message_len so the decoder reaches the Incomplete check.
    let actual_len = encoded.len();
    let claimed = actual_len + 64;
    encoded[1] = ((claimed >> 16) & 0xFF) as u8;
    encoded[2] = ((claimed >> 8) & 0xFF) as u8;
    encoded[3] = (claimed & 0xFF) as u8;
    let result = Message::decode(&encoded, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::Incomplete)
    ));

    // Claim the message is shorter than the header itself.
    let mut short = encoded.clone();
    short[1] = 0x00;
    short[2] = 0x00;
    short[3] = 0x0F;
    let result = Message::decode(&short, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), opc_protocol::DecodeErrorCode::InvalidLength { .. })
    ));
}

#[test]
fn owned_message_decode_rejects_truncation_without_panic() {
    let raw_avps = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let mut encoded = encode_message(&raw_avps);
    encoded.truncate(DIAMETER_HEADER_LEN + 4);
    let result = OwnedMessage::decode_owned(Bytes::from(encoded), DecodeContext::default());
    assert!(result.is_err());
}
