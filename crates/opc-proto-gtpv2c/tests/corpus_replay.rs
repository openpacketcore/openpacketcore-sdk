//! Deterministic GTPv2-C fixture and fuzz-corpus replay guard.
//!
//! Replays the committed provenance-labeled fixture corpus and cargo-fuzz seed
//! corpus through the same decode, typed-view, IE-iteration, and raw-preserving
//! encode surfaces used by the fuzz targets. This test is stable-Rust CI
//! coverage for ADR 0015 hostile-input and byte-exact forwarding guarantees.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, validate_ie_region, Message, OwnedMessage, RawIeIterator, S2bMessage,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, OwnedDecode,
    ValidationLevel,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureClass {
    Spec,
    Independent,
    EpdgParity,
    Malformed,
}

const FUZZ_TARGETS: &[&str] = &[
    "decode_message",
    "decode_s2b",
    "error_response_plans",
    "roundtrip",
];
const FUZZ_SEED_PROVENANCE_DIRS: &[&str] = &["spec", "epdg-parity", "malformed"];
const INDEPENDENT_EMPTY_README_MARKER: &str = "No independent GTPv2-C capture is committed yet.";
const INDEPENDENT_METADATA_REQUIRED_KEYS: &[&str] = &[
    "capture_kind",
    "independent_implementation",
    "implementation_version",
    "capture_permission",
    "redaction_review",
    "redacted_fields",
    "synthetic_replacements",
    "expected_message",
    "expected_raw_preserving_reencode",
    "fuzz_seed_policy",
    "reviewer",
];

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fuzz_corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus")
}

fn read_files(root: &Path, only_bin: bool) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => panic!(
                "failed to read fixture directory {}: {error}",
                dir.display()
            ),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => panic!("failed to read fixture entry in {}: {error}", dir.display()),
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if only_bin && path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => panic!("failed to read fixture file {}: {error}", path.display()),
            };
            files.push((path, bytes));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn class_for(path: &Path) -> Option<FixtureClass> {
    let relative = path.strip_prefix(fixture_root()).ok()?;
    let first = relative.components().next()?;
    match first.as_os_str().to_string_lossy().as_ref() {
        "spec" => Some(FixtureClass::Spec),
        "independent" => Some(FixtureClass::Independent),
        "epdg-parity" => Some(FixtureClass::EpdgParity),
        "malformed" => Some(FixtureClass::Malformed),
        _ => None,
    }
}

fn fixture_files(class: FixtureClass) -> Vec<(PathBuf, Vec<u8>)> {
    read_files(&fixture_root(), true)
        .into_iter()
        .filter(|(path, _bytes)| class_for(path) == Some(class))
        .collect()
}

fn fuzz_provenance_seed_files() -> Vec<(PathBuf, Vec<u8>)> {
    let root = fuzz_corpus_root();
    let mut files = Vec::new();
    for dir in FUZZ_SEED_PROVENANCE_DIRS {
        files.extend(read_files(&root.join(dir), true));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn fuzz_target_seed_name(path: &Path) -> String {
    let Some(provenance) = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
    else {
        panic!(
            "fuzz seed path has no provenance directory: {}",
            path.display()
        );
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        panic!("fuzz seed path has no UTF-8 file name: {}", path.display());
    };
    format!("{provenance}__{file_name}")
}

fn assert_raw_preserving_message_roundtrip(path: &Path, data: &[u8]) {
    let (_, message) = match Message::decode(data, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!(
            "{} did not decode as a raw message: {error:?}",
            path.display()
        ),
    };
    let mut encoded = BytesMut::new();
    let result = message.encode(
        &mut encoded,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    );
    match result {
        Ok(()) => assert_eq!(
            encoded.as_ref(),
            data,
            "{} failed raw-preserving Message encode(decode(input))",
            path.display()
        ),
        Err(error) => panic!(
            "{} failed raw-preserving Message encode: {error:?}",
            path.display()
        ),
    }
}

fn assert_canonical_message_idempotence(path: &Path, data: &[u8]) {
    let Ok((tail, message)) = Message::decode(data, DecodeContext::default()) else {
        return;
    };
    let parsed_len = data.len() - tail.len();
    let original_parsed = &data[..parsed_len];

    let mut raw_encoded = BytesMut::new();
    if message
        .encode(
            &mut raw_encoded,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .is_ok()
    {
        assert_eq!(
            raw_encoded.as_ref(),
            original_parsed,
            "{} raw-preserving roundtrip changed parsed bytes",
            path.display()
        );
    }

    let mut canonical = BytesMut::new();
    if message
        .encode(&mut canonical, EncodeContext::default())
        .is_err()
    {
        return;
    }
    let Ok((canonical_tail, canonical_message)) =
        Message::decode(canonical.as_ref(), DecodeContext::default())
    else {
        panic!(
            "{} canonical Message encoding did not decode",
            path.display()
        );
    };
    assert!(
        canonical_tail.is_empty(),
        "{} canonical Message encoding left a tail",
        path.display()
    );
    let mut canonical_again = BytesMut::new();
    match canonical_message.encode(&mut canonical_again, EncodeContext::default()) {
        Ok(()) => assert_eq!(
            canonical_again.as_ref(),
            canonical.as_ref(),
            "{} canonical Message encode/decode/encode is not idempotent",
            path.display()
        ),
        Err(error) => panic!(
            "{} canonical Message re-encode failed: {error:?}",
            path.display()
        ),
    }
}

fn assert_spec_s2b_roundtrip(path: &Path, data: &[u8]) {
    let (_, message) = match S2bMessage::decode(data, procedure_context()) {
        Ok(decoded) => decoded,
        Err(error) => panic!(
            "{} did not decode as a ProcedureAware S2b fixture: {error:?}",
            path.display()
        ),
    };
    assert!(
        message.as_view().is_some(),
        "{} decoded as raw fallback instead of S2b typed view",
        path.display()
    );

    let mut canonical = BytesMut::new();
    match message.encode(&mut canonical, EncodeContext::default()) {
        Ok(())
            if path.file_name().and_then(|name| name.to_str())
                == Some("modify_bearer_request_bearer_context.bin") =>
        {
            // This legacy fixture is retained as independent byte evidence for
            // TS 29.274 clause 7.7.9. Bearer Context is known but unexpected
            // in the S2b UE-initiated IPsec tunnel-update profile, so receive
            // discards it and canonical encode emits the remaining empty
            // request. Raw-preserving encode below must still be byte-exact.
            assert_eq!(
                canonical.as_ref(),
                &[72, 34, 0, 8, 1, 2, 3, 4, 0, 16, 3, 0],
                "{} did not canonically discard unexpected Bearer Context",
                path.display()
            );
        }
        Ok(()) => assert_eq!(
            canonical.as_ref(),
            data,
            "{} canonical S2b encode changed spec fixture bytes",
            path.display()
        ),
        Err(error) => panic!("{} canonical S2b encode failed: {error:?}", path.display()),
    }

    let mut raw_preserving = BytesMut::new();
    match message.encode(
        &mut raw_preserving,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    ) {
        Ok(()) => assert_eq!(
            raw_preserving.as_ref(),
            data,
            "{} raw-preserving S2b encode changed spec fixture bytes",
            path.display()
        ),
        Err(error) => panic!(
            "{} raw-preserving S2b encode failed: {error:?}",
            path.display()
        ),
    }
}

fn metadata_path_for_capture(path: &Path) -> PathBuf {
    path.with_extension("metadata")
}

fn independent_metadata_fields(path: &Path) -> BTreeMap<String, String> {
    let metadata_path = metadata_path_for_capture(path);
    let content = match std::fs::read_to_string(&metadata_path) {
        Ok(content) => content,
        Err(error) => panic!(
            "{} is missing independent-capture metadata sidecar {}: {error}",
            path.display(),
            metadata_path.display()
        ),
    };

    let mut fields = BTreeMap::new();
    for (line_index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            panic!(
                "{} metadata line {} must use `key: value` form",
                metadata_path.display(),
                line_index + 1
            );
        };
        let key = key.trim();
        let value = value.trim();
        assert!(
            !key.is_empty() && !value.is_empty(),
            "{} metadata line {} has an empty key or value",
            metadata_path.display(),
            line_index + 1
        );
        fields.insert(key.to_string(), value.to_string());
    }
    fields
}

fn assert_independent_capture_metadata(path: &Path) {
    let fields = independent_metadata_fields(path);
    for required in INDEPENDENT_METADATA_REQUIRED_KEYS {
        let Some(value) = fields.get(*required) else {
            panic!(
                "{} independent-capture metadata is missing required key `{required}`",
                path.display()
            );
        };
        let lower_value = value.to_ascii_lowercase();
        assert!(
            !matches!(lower_value.as_str(), "todo" | "tbd" | "pending" | "unknown"),
            "{} independent-capture metadata key `{required}` must be finalized before commit",
            path.display()
        );
    }
    assert_eq!(
        fields
            .get("expected_raw_preserving_reencode")
            .map(String::as_str),
        Some("byte_exact"),
        "{} independent capture must document byte-exact raw-preserving re-encode behavior",
        path.display()
    );
}

fn assert_independent_s2b_roundtrip(path: &Path, data: &[u8]) {
    assert_raw_preserving_message_roundtrip(path, data);
    let (tail, message) = match S2bMessage::decode(data, procedure_context()) {
        Ok(decoded) => decoded,
        Err(error) => panic!(
            "{} did not decode as a ProcedureAware independent S2b capture: {error:?}",
            path.display()
        ),
    };
    assert!(
        tail.is_empty(),
        "{} independent S2b capture must contain exactly one datagram",
        path.display()
    );
    assert!(
        message.as_view().is_some(),
        "{} independent S2b capture decoded as raw fallback instead of typed view",
        path.display()
    );

    let mut raw_preserving = BytesMut::new();
    match message.encode(
        &mut raw_preserving,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    ) {
        Ok(()) => assert_eq!(
            raw_preserving.as_ref(),
            data,
            "{} raw-preserving S2b encode changed independent capture bytes",
            path.display()
        ),
        Err(error) => panic!(
            "{} raw-preserving S2b encode failed for independent capture: {error:?}",
            path.display()
        ),
    }
}

fn exercise_decode_surfaces(data: &[u8]) {
    let decoded_message = Message::decode(data, DecodeContext::default());

    for level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let _ = Message::decode(data, ctx);
    }

    let _ = S2bMessage::decode(data, DecodeContext::default());
    let _ = S2bMessage::decode(data, procedure_context());
    let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());

    let shallow = DecodeContext {
        max_ies: 4,
        ..DecodeContext::default()
    };
    let _ = validate_ie_region(data, shallow);
    for item in RawIeIterator::new(data, shallow) {
        if item.is_err() {
            break;
        }
    }
    let _ = decode_typed_ie_sequence(data, shallow, 0);

    if let Ok((_tail, message)) = decoded_message {
        let _ = validate_ie_region(message.raw_ies, shallow);
        for item in RawIeIterator::new(message.raw_ies, shallow) {
            if item.is_err() {
                break;
            }
        }
        let _ = decode_typed_ie_sequence(message.raw_ies, shallow, 0);
    }

    assert_canonical_message_idempotence(Path::new("<in-memory>"), data);
}

fn adversarial_seeds() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0xff],
        vec![0x00; 8],
        vec![0xff; 8],
        vec![0x00; 4096],
        vec![0xff; 4096],
        (0..=255u8).collect(),
        vec![0x40, 0x01, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00],
        vec![0x48, 0x20, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04],
    ]
}

#[test]
fn fixture_corpus_is_split_by_provenance() {
    let root = fixture_root();
    for subdir in ["spec", "independent", "epdg-parity", "malformed"] {
        assert!(
            root.join(subdir).is_dir(),
            "missing fixture provenance directory {subdir}"
        );
    }
    assert_eq!(fixture_files(FixtureClass::Spec).len(), 19);
    assert!(fixture_files(FixtureClass::EpdgParity).len() >= 3);
    assert!(fixture_files(FixtureClass::Malformed).len() >= 16);
    assert!(
        root.join("independent/README.md").is_file(),
        "independent capture gap must remain documented"
    );
}

#[test]
fn fuzz_target_corpora_mirror_provenance_seed_corpus() {
    let root = fuzz_corpus_root();
    let seeds = fuzz_provenance_seed_files();

    for target in FUZZ_TARGETS {
        let target_dir = root.join(target);
        assert!(
            target_dir.is_dir(),
            "missing cargo-fuzz target corpus directory {}",
            target_dir.display()
        );
        let target_files = read_files(&target_dir, true);
        assert_eq!(
            target_files.len(),
            seeds.len(),
            "{} must contain one flat copy of every provenance seed",
            target_dir.display()
        );

        for (source_path, source_bytes) in &seeds {
            let target_path = target_dir.join(fuzz_target_seed_name(source_path));
            let target_bytes = match std::fs::read(&target_path) {
                Ok(bytes) => bytes,
                Err(error) => panic!(
                    "{} is missing mirrored seed for {}: {error}",
                    target_path.display(),
                    source_path.display()
                ),
            };
            assert_eq!(
                &target_bytes,
                source_bytes,
                "{} does not match source seed {}",
                target_path.display(),
                source_path.display()
            );
        }
    }
}

#[test]
fn spec_fixture_corpus_roundtrips_byte_exact() {
    let fixtures = fixture_files(FixtureClass::Spec);
    assert!(!fixtures.is_empty(), "spec fixture corpus is empty");
    for (path, data) in fixtures {
        assert_raw_preserving_message_roundtrip(&path, &data);
        assert_spec_s2b_roundtrip(&path, &data);
    }
}

#[test]
fn independent_capture_corpus_has_metadata_or_declared_gap() {
    let fixtures = fixture_files(FixtureClass::Independent);
    if fixtures.is_empty() {
        let readme_path = fixture_root().join("independent/README.md");
        let readme = match std::fs::read_to_string(&readme_path) {
            Ok(readme) => readme,
            Err(error) => panic!("failed to read {}: {error}", readme_path.display()),
        };
        assert!(
            readme.contains(INDEPENDENT_EMPTY_README_MARKER),
            "empty independent-capture corpus must keep the no-capture gap explicit"
        );
        return;
    }

    for (path, data) in fixtures {
        assert_independent_capture_metadata(&path);
        assert_independent_s2b_roundtrip(&path, &data);
    }
}

#[test]
fn epdg_parity_corpus_roundtrips_but_is_not_conformance() {
    let fixtures = fixture_files(FixtureClass::EpdgParity);
    assert!(!fixtures.is_empty(), "ePDG parity fixture corpus is empty");
    for (path, data) in fixtures {
        assert_raw_preserving_message_roundtrip(&path, &data);
        assert_canonical_message_idempotence(&path, &data);
    }
}

fn one_ie_limit_context() -> DecodeContext {
    DecodeContext {
        max_ies: 1,
        ..DecodeContext::default()
    }
}

fn assert_error_code(
    path: &Path,
    actual: Result<(), opc_protocol::DecodeError>,
    expected: fn(&DecodeErrorCode) -> bool,
    expectation: &str,
) {
    match actual {
        Ok(()) => panic!("{} unexpectedly passed {expectation}", path.display()),
        Err(error) => assert!(
            expected(error.code()),
            "{} returned {error:?} for {expectation}",
            path.display()
        ),
    }
}

fn assert_message_decode_error(
    path: &Path,
    data: &[u8],
    ctx: DecodeContext,
    expected: fn(&DecodeErrorCode) -> bool,
    expectation: &str,
) {
    assert_error_code(
        path,
        Message::decode(data, ctx).map(|(_tail, _message)| ()),
        expected,
        expectation,
    );
}

fn assert_raw_ie_region_error(
    path: &Path,
    data: &[u8],
    ctx: DecodeContext,
    expected: fn(&DecodeErrorCode) -> bool,
    expectation: &str,
) {
    let (_tail, message) = match Message::decode(data, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!(
            "{} could not be decoded before raw IE-region check {expectation}: {error:?}",
            path.display()
        ),
    };
    assert_error_code(
        path,
        validate_ie_region(message.raw_ies, ctx),
        expected,
        expectation,
    );
}

fn assert_typed_ie_region_error(
    path: &Path,
    data: &[u8],
    ctx: DecodeContext,
    expected: fn(&DecodeErrorCode) -> bool,
    expectation: &str,
) {
    let (_tail, message) = match Message::decode(data, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!(
            "{} could not be decoded before typed IE-region check {expectation}: {error:?}",
            path.display()
        ),
    };
    assert_error_code(
        path,
        decode_typed_ie_sequence(message.raw_ies, ctx, 0).map(|_ies| ()),
        expected,
        expectation,
    );
}

fn assert_s2b_profile_error(
    path: &Path,
    data: &[u8],
    expected: fn(&DecodeErrorCode) -> bool,
    expectation: &str,
) {
    assert_error_code(
        path,
        S2bMessage::decode(data, procedure_context()).map(|(_tail, _message)| ()),
        expected,
        expectation,
    );
}

fn fixture_file_name(path: &Path) -> &str {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        panic!("fixture path has no UTF-8 file name: {}", path.display());
    };
    name
}

fn assert_malformed_fixture_rejection(path: &Path, data: &[u8]) {
    match fixture_file_name(path) {
        "declared_length_overrun.bin" => assert_message_decode_error(
            path,
            data,
            DecodeContext::default(),
            |code| matches!(code, DecodeErrorCode::MessageLengthExceeded),
            "declared message length limit rejection",
        ),
        "empty.bin"
        | "truncated_no_teid_header.bin"
        | "truncated_teid_header.bin"
        | "truncated_ie_value.bin" => assert_message_decode_error(
            path,
            data,
            DecodeContext::default(),
            |code| matches!(code, DecodeErrorCode::Truncated),
            "truncation rejection",
        ),
        "strict_header_spare_bits.bin" => assert_message_decode_error(
            path,
            data,
            strict_context(),
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "strict header spare-bit rejection",
        ),
        "strict_ie_spare_bits.bin" => {
            assert_message_decode_error(
                path,
                data,
                strict_context(),
                |code| matches!(code, DecodeErrorCode::Structural { .. }),
                "strict message IE spare-bit rejection",
            );
            assert_raw_ie_region_error(
                path,
                data,
                strict_context(),
                |code| matches!(code, DecodeErrorCode::Structural { .. }),
                "strict raw IE-region spare-bit rejection",
            );
        }
        "too_many_small_ies.bin" => {
            assert_message_decode_error(
                path,
                data,
                one_ie_limit_context(),
                |code| matches!(code, DecodeErrorCode::IeCountExceeded),
                "low-limit message IE-count rejection",
            );
            assert_raw_ie_region_error(
                path,
                data,
                one_ie_limit_context(),
                |code| matches!(code, DecodeErrorCode::IeCountExceeded),
                "low-limit raw IE-region count rejection",
            );
        }
        "nested_bearer_context_depth_limit.bin" => {
            let ctx = DecodeContext {
                max_depth: 1,
                ..DecodeContext::default()
            };
            assert_typed_ie_region_error(
                path,
                data,
                ctx,
                |code| matches!(code, DecodeErrorCode::DepthExceeded),
                "low-limit grouped IE recursion-depth rejection",
            );
        }
        "profile_echo_request_missing_recovery.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Echo Request Recovery rejection",
        ),
        "profile_create_session_request_missing_paa.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Create Session Request PAA rejection",
        ),
        "profile_create_session_request_bearer_context_missing_ebi.bin" => {
            assert_s2b_profile_error(
                path,
                data,
                |code| matches!(code, DecodeErrorCode::Structural { .. }),
                "ProcedureAware Create Session Request Bearer Context EBI rejection",
            );
        }
        "profile_create_session_request_sender_fteid_no_address.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Create Session Request malformed Sender F-TEID rejection",
        ),
        "profile_create_session_request_paa_non_ip_trailing.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::InvalidLength { .. }),
            "ProcedureAware Create Session Request malformed PAA rejection",
        ),
        "profile_create_session_response_accepted_missing_pgw_control_fteid.bin" => {
            assert_s2b_profile_error(
                path,
                data,
                |code| matches!(code, DecodeErrorCode::Structural { .. }),
                "ProcedureAware accepted Create Session Response PGW control F-TEID rejection",
            );
        }
        "profile_update_bearer_response_missing_cause.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Update Bearer Response Cause rejection",
        ),
        "profile_create_bearer_request_missing_tft.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Create Bearer Request TFT rejection",
        ),
        "profile_delete_bearer_request_conflicting_targets.bin" => assert_s2b_profile_error(
            path,
            data,
            |code| matches!(code, DecodeErrorCode::Structural { .. }),
            "ProcedureAware Delete Bearer mutually exclusive target rejection",
        ),
        name => panic!("unclassified malformed fixture {name}: {}", path.display()),
    }
}

#[test]
fn malformed_fixture_corpus_rejects_without_panics() {
    let fixtures = fixture_files(FixtureClass::Malformed);
    assert!(!fixtures.is_empty(), "malformed fixture corpus is empty");

    let mut failures = Vec::new();
    for (path, data) in fixtures {
        if std::panic::catch_unwind(|| exercise_decode_surfaces(&data)).is_err() {
            failures.push(format!("panic:{}", path.display()));
            continue;
        }
        if std::panic::catch_unwind(|| assert_malformed_fixture_rejection(&path, &data)).is_err() {
            failures.push(format!("unexpected-rejection-path:{}", path.display()));
        }
    }

    assert!(
        failures.is_empty(),
        "malformed fixture corpus failures: {failures:#?}"
    );
}

#[test]
fn fuzz_corpus_and_adversarial_inputs_never_panic() {
    let mut corpus = read_files(&fuzz_corpus_root(), false);
    assert!(
        !corpus.is_empty(),
        "expected committed seed corpus under fuzz/corpus; found none"
    );
    for (idx, seed) in adversarial_seeds().into_iter().enumerate() {
        corpus.push((PathBuf::from(format!("adversarial#{idx}")), seed));
    }

    let mut failures = Vec::new();
    let mut checked = 0usize;
    for (path, data) in &corpus {
        if std::panic::catch_unwind(|| exercise_decode_surfaces(data)).is_err() {
            failures.push(format!("input:{}", path.display()));
        }
        checked += 1;

        for len in 0..=data.len().min(256) {
            if std::panic::catch_unwind(|| exercise_decode_surfaces(&data[..len])).is_err() {
                failures.push(format!("truncation:{}[..{len}]", path.display()));
            }
            checked += 1;
        }
    }

    assert!(
        failures.is_empty(),
        "decode panicked on {} of {checked} known input(s): {failures:#?}",
        failures.len()
    );
}
