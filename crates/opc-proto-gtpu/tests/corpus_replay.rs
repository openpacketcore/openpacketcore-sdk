//! Deterministic corpus-replay regression guard.
//!
//! Replays every committed fuzz corpus input — plus byte-truncations of each
//! entry and a set of hostile constant inputs — through the same decode entry
//! points and round-trip invariants as the libFuzzer targets in
//! `fuzz/fuzz_targets/decode.rs` and `fuzz/fuzz_targets/roundtrip.rs`.
//!
//! Unlike the fuzzer, this runs on stable Rust in ordinary `cargo test`/CI:
//! it requires no nightly toolchain and no libFuzzer. Its job is regression
//! protection — if a future change makes a decode path panic, or breaks a
//! round-trip invariant, on a known input, this test fails and names it.

use bytes::BytesMut;
use opc_proto_gtpu::{GtpuControlCodecErrorCode, GtpuControlMessage, GtpuMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, ValidationLevel};

/// Every decode entry point and round-trip invariant the fuzz targets
/// exercise. Must never panic and never violate a round-trip invariant,
/// regardless of input. Decode returning `Err` is expected and fine.
fn exercise(data: &[u8]) {
    if let Ok((_, control)) = GtpuControlMessage::decode(data, DecodeContext::default()) {
        let encode_context = EncodeContext::default();
        if let Ok(canonical) = control.to_bytes(encode_context) {
            if let Ok((tail, reparsed)) =
                GtpuControlMessage::decode(&canonical, DecodeContext::default())
            {
                assert!(tail.is_empty());
                assert_eq!(control, reparsed);
                if let Ok(second) = reparsed.to_bytes(encode_context) {
                    assert_eq!(canonical, second);
                }
            }
        }
    }

    // Decode at every validation level.
    let _ = GtpuMessage::decode(data, DecodeContext::default());

    let ctx_hdr = DecodeContext {
        validation_level: ValidationLevel::HeaderOnly,
        ..Default::default()
    };
    let _ = GtpuMessage::decode(data, ctx_hdr);

    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let _ = GtpuMessage::decode(data, ctx_strict);

    let ctx_proc = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..Default::default()
    };
    let _ = GtpuMessage::decode(data, ctx_proc);

    // Round-trip invariants (mirror fuzz_targets/roundtrip.rs).
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Structural,
        ..Default::default()
    };
    if let Ok((tail, msg)) = GtpuMessage::decode(data, ctx) {
        let parsed_len = data.len() - tail.len();
        let original_parsed_bytes = &data[..parsed_len];

        // 1. Raw-preserving: encode(decode(input)) == input over parsed bytes.
        let mut buf = BytesMut::new();
        let raw_ctx = EncodeContext {
            raw_preserving: true,
            ..Default::default()
        };
        if msg.encode(&mut buf, raw_ctx).is_ok() {
            assert_eq!(
                buf.as_ref(),
                original_parsed_bytes,
                "raw-preserving roundtrip failed: encode(decode(input)) != input"
            );
        }

        // 2. Canonical: encode(decode(encode(model))) == encode(model).
        let mut canonical_buf = BytesMut::new();
        let canonical_ctx = EncodeContext::default();
        if msg.encode(&mut canonical_buf, canonical_ctx).is_ok() {
            if let Ok((tail_can, msg_can)) =
                GtpuMessage::decode(&canonical_buf, DecodeContext::default())
            {
                assert!(
                    tail_can.is_empty(),
                    "canonical encoding left unconsumed tail bytes after decoding"
                );
                let mut canonical_buf_2 = BytesMut::new();
                msg_can
                    .encode(&mut canonical_buf_2, canonical_ctx)
                    .expect("re-encode of canonical message failed");
                assert_eq!(
                    canonical_buf.as_ref(),
                    canonical_buf_2.as_ref(),
                    "canonical roundtrip failed: encode(decode(encode(model))) != encode(model)"
                );
            }
        }
    }
}

fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let mut high = None;
    for byte in encoded.iter().copied() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if let Some(upper) = high.take() {
            decoded.push((upper << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() {
        None
    } else {
        Some(decoded)
    }
}

fn corpus_seed(input: &[u8]) -> Vec<u8> {
    decode_hex_seed(input).unwrap_or_else(|| input.to_vec())
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
                out.push((path, corpus_seed(&bytes)));
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
fn named_control_corpus_entries_are_valid_and_canonicalize() {
    const CANONICAL_REQUEST: &[u8] = &[0x32, 0x01, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    const CANONICAL_RESPONSE: &[u8] = &[0x32, 0x02, 0, 6, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 14, 0];
    const ERROR_INDICATION: &[u8] = &[
        0x36, 0x1a, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0x08, 0x68, 0, 16, 0x11, 0x22, 0x33, 0x44,
        133, 0, 4, 192, 0, 2, 10,
    ];
    const SUPPORTED_EXTENSIONS: &[u8] = &[
        0x32, 0x1f, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 141, 0, 2, 0x40, 0x85,
    ];
    const END_MARKER: &[u8] = &[
        0x34, 0xfe, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, 0, 9, 0,
    ];
    const UNKNOWN_OPTIONAL: &[u8] = &[
        0x36, 0x01, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0x07, 1, 0xaa, 0xbb, 0,
    ];
    let seeds: [(&str, &[u8], &[u8]); 12] = [
        (
            "decode/control_echo_request",
            include_bytes!("../fuzz/corpus/decode/control_echo_request"),
            CANONICAL_REQUEST,
        ),
        (
            "decode/control_echo_response",
            include_bytes!("../fuzz/corpus/decode/control_echo_response"),
            CANONICAL_RESPONSE,
        ),
        (
            "roundtrip/control_echo_request",
            include_bytes!("../fuzz/corpus/roundtrip/control_echo_request"),
            CANONICAL_REQUEST,
        ),
        (
            "roundtrip/control_echo_response",
            include_bytes!("../fuzz/corpus/roundtrip/control_echo_response"),
            CANONICAL_RESPONSE,
        ),
        (
            "decode/control_error_indication",
            include_bytes!("../fuzz/corpus/decode/control_error_indication"),
            ERROR_INDICATION,
        ),
        (
            "roundtrip/control_error_indication",
            include_bytes!("../fuzz/corpus/roundtrip/control_error_indication"),
            ERROR_INDICATION,
        ),
        (
            "decode/control_supported_extensions",
            include_bytes!("../fuzz/corpus/decode/control_supported_extensions"),
            SUPPORTED_EXTENSIONS,
        ),
        (
            "roundtrip/control_supported_extensions",
            include_bytes!("../fuzz/corpus/roundtrip/control_supported_extensions"),
            SUPPORTED_EXTENSIONS,
        ),
        (
            "decode/control_end_marker_pdu_session",
            include_bytes!("../fuzz/corpus/decode/control_end_marker_pdu_session"),
            END_MARKER,
        ),
        (
            "roundtrip/control_end_marker_pdu_session",
            include_bytes!("../fuzz/corpus/roundtrip/control_end_marker_pdu_session"),
            END_MARKER,
        ),
        (
            "decode/control_unknown_optional_extension",
            include_bytes!("../fuzz/corpus/decode/control_unknown_optional_extension"),
            UNKNOWN_OPTIONAL,
        ),
        (
            "roundtrip/control_unknown_optional_extension",
            include_bytes!("../fuzz/corpus/roundtrip/control_unknown_optional_extension"),
            UNKNOWN_OPTIONAL,
        ),
    ];

    for (name, seed, expected) in seeds {
        let seed = corpus_seed(seed);
        let message = GtpuControlMessage::decode_datagram(&seed, DecodeContext::default())
            .unwrap_or_else(|error| panic!("{name} must be a valid control datagram: {error:?}"));
        let canonical = message
            .to_bytes(EncodeContext::default())
            .unwrap_or_else(|error| panic!("{name} canonical encode failed: {error:?}"));
        assert_eq!(canonical.as_ref(), expected, "seed: {name}");
    }
}

#[test]
fn named_negative_control_corpus_entries_reach_the_expected_typed_failures() {
    let seeds = [
        (
            "decode/control_malformed_tlv",
            include_bytes!("../fuzz/corpus/decode/control_malformed_tlv").as_slice(),
            GtpuControlCodecErrorCode::TruncatedIe,
        ),
        (
            "roundtrip/control_malformed_tlv",
            include_bytes!("../fuzz/corpus/roundtrip/control_malformed_tlv").as_slice(),
            GtpuControlCodecErrorCode::TruncatedIe,
        ),
        (
            "decode/control_unknown_required_extension",
            include_bytes!("../fuzz/corpus/decode/control_unknown_required_extension").as_slice(),
            GtpuControlCodecErrorCode::UnsupportedRequiredExtension {
                extension_type: 0x87,
            },
        ),
        (
            "roundtrip/control_unknown_required_extension",
            include_bytes!("../fuzz/corpus/roundtrip/control_unknown_required_extension")
                .as_slice(),
            GtpuControlCodecErrorCode::UnsupportedRequiredExtension {
                extension_type: 0x87,
            },
        ),
    ];

    for (name, seed, expected) in seeds {
        let seed = corpus_seed(seed);
        let error = GtpuControlMessage::decode_datagram(&seed, DecodeContext::default())
            .expect_err("negative corpus seed must remain rejected");
        assert_eq!(error.code(), &expected, "seed: {name}");
    }
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
