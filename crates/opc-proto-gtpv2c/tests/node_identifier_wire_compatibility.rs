//! Encoder differential guarding the Node Identifier (IE 176) admission change.
//!
//! Typing a previously preserved-unknown IE can only change emitted bytes
//! through the canonical `TypedIe` encoder. This harness enumerates a closed
//! encoder point space over every committed fixture plus a synthetic injection
//! grid, and records each point's exact outcome. Running the same enumeration
//! before and after the change and diffing the two dumps is what proves that
//! no message which already round-tripped changed on the wire.
//!
//! The dump itself is far too large to commit, so the committed regression
//! guard is a digest over the ordered `(label, outcome)` list: every emitted
//! byte, every decode failure code, every axis size, and the ordering all feed
//! it. Enumerating the space without asserting its outcomes would leave the
//! wire claims untested, so the digest is asserted, not merely computed.
//!
//! Set `GTPV2C_ENCODER_DUMP=<path>` to write the ordered point dump used for
//! that differential; the committed assertions below run unconditionally.

use bytes::BytesMut;
use opc_proto_gtpv2c::{Message, S2bMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, ValidationLevel};
use std::path::{Path, PathBuf};

/// Node Identifier IE type under change, plus its numeric neighbours and the
/// two control classes: a known-but-untyped IE and a known-and-typed IE.
const INJECTED_IE_TYPES: &[(&str, u8)] = &[
    ("twan_identifier_169_known_typed", 169),
    ("unknown_175", 175),
    ("node_identifier_176", 176),
    ("unknown_177", 177),
    ("pgw_change_info_214_known_untyped", 214),
];

/// Both spare-nibble classes. Canonical `TypedIe` encoding zeroes the spare
/// nibble while `RawIe` encoding preserves it, so this axis is the one that
/// exposes spare-nibble drift when an IE becomes typed.
const INJECTED_SPARE_NIBBLES: &[u8] = &[0x0, 0x5];

const LEVELS: &[(&str, ValidationLevel)] = &[
    ("structural", ValidationLevel::Structural),
    ("procedure_aware", ValidationLevel::ProcedureAware),
    ("strict", ValidationLevel::Strict),
];

const ENCODE_MODES: &[(&str, bool)] = &[("canonical", false), ("raw_preserving", true)];

/// Carrier message for the injection grid: a spec-authored S2b Create Session
/// Request, the one message TS 29.274 Table 7.2.1-1 lists IE 176 on.
const INJECTION_CARRIER: &str = "spec/create_session_request_s2b_subset.bin";

/// Committed axis sizes. `fixture_corpus` and `injected_values` are the very
/// functions the enumerator iterates, so a count derived from them cannot
/// notice either one shrinking. These literals can.
const FIXTURE_CORPUS_LEN: usize = 40;
const INJECTED_VALUE_CLASSES: usize = 11;
const BLOCK_A_POINTS: usize = 480;
const BLOCK_B_POINTS: usize = 10_560;

/// Digest of the ordered Block A `(label, outcome)` list: every committed
/// fixture, decoded and re-encoded across both surfaces, all three validation
/// levels, and both encode modes. No fixture carries IE 176, so this is the
/// "zero byte changes for every committed fixture" claim, frozen.
///
/// Regenerate deliberately, never to make a red run green: run the suite with
/// `GTPV2C_ENCODER_DUMP=<path>`, diff the dump against the previous one, and
/// only then update this literal.
const BLOCK_A_DIGEST: u64 = 10_922_305_812_464_877_325;

/// Digest of the ordered Block B `(label, outcome)` list. This is where the
/// IE 176 canonical-encode deltas live: spare-nibble zeroing, Extendable
/// suffix stripping, the clause 7.7.9 instance discard, and the clause 7.7.8
/// malformed-value discard. Regenerate under the same discipline as
/// `BLOCK_A_DIGEST`.
///
/// Block B enumerates all three validation levels. It previously stopped at
/// two, which left the 96 `Strict` canonical points that IE 176 actually
/// changes outside the digest: the whole-PR canonical delta is 539 points, of
/// which only 443 were guarded. `Strict` is the level
/// `DecodeContext::conservative()` selects, so it was the one level a wire
/// guard could least afford to skip.
const BLOCK_B_DIGEST: u64 = 15_588_910_344_812_376_123;

/// Injection points whose carrier actually decodes, and whose raw-preserving
/// re-encode is therefore checkable. Pinned exactly so a change that made most
/// points fail decode cannot quietly shrink the guard.
///
/// This is unchanged from the pre-change baseline at `dae1919a`, on the same
/// three-level grid: typing IE 176 narrowed the set of injected values that
/// decode at all, and the clause 7.7.8 discard restores it exactly. Every one
/// of these points re-encodes byte-exact, which is the half of the discard
/// that says the untouched octets must still be there.
const RAW_PRESERVING_CHECKED_POINTS: usize = 3079;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// TS 29.274 Figure 8.107-1 shaped and deliberately malformed value payloads.
fn injected_values() -> Vec<(String, Vec<u8>)> {
    let mut values: Vec<(String, Vec<u8>)> = vec![
        ("zero_length_value".to_owned(), Vec::new()),
        ("name_length_octet_only".to_owned(), vec![0x00]),
        ("both_lengths_zero".to_owned(), vec![0x00, 0x00]),
        (
            "name_only_empty_realm".to_owned(),
            vec![0x04, b'a', b'a', b'a', b'a', 0x00],
        ),
        (
            "empty_name_realm_only".to_owned(),
            vec![0x00, 0x03, b'o', b'r', b'g'],
        ),
        (
            "well_formed_pair".to_owned(),
            vec![0x03, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'],
        ),
        (
            "well_formed_pair_with_extension".to_owned(),
            vec![0x03, b'a', b'a', b'a', 0x03, b'o', b'r', b'g', 0xde, 0xad],
        ),
        (
            "name_length_overruns_value".to_owned(),
            vec![0x09, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'],
        ),
        (
            "realm_length_overruns_value".to_owned(),
            vec![0x03, b'a', b'a', b'a', 0x09, b'o', b'r', b'g'],
        ),
        (
            "realm_length_octet_absent".to_owned(),
            vec![0x03, b'a', b'a', b'a'],
        ),
    ];

    let mut maximum = Vec::with_capacity(512);
    maximum.push(0xff);
    maximum.extend(std::iter::repeat_n(b'n', 255));
    maximum.push(0xff);
    maximum.extend(std::iter::repeat_n(b'r', 255));
    values.push(("maximum_length_pair".to_owned(), maximum));

    values
}

fn context(level: ValidationLevel) -> DecodeContext {
    DecodeContext {
        validation_level: level,
        ..DecodeContext::default()
    }
}

fn encode_context(raw_preserving: bool) -> EncodeContext {
    EncodeContext {
        raw_preserving,
        ..EncodeContext::default()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Encode one TLIV with an explicit spare nibble.
fn tliv(ie_type: u8, spare: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("injected IE value length fits u16");
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(ie_type);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.push(((spare & 0x0f) << 4) | (instance & 0x0f));
    encoded.extend_from_slice(value);
    encoded
}

/// Append a TLIV to a complete message and repair the header length field,
/// which per TS 29.274 clause 5.5 excludes the first four octets.
fn append_ie(message: &[u8], ie: &[u8]) -> Vec<u8> {
    let mut extended = message.to_vec();
    extended.extend_from_slice(ie);
    let declared = u16::from_be_bytes([extended[2], extended[3]]);
    let widened = declared
        .checked_add(u16::try_from(ie.len()).expect("injected IE fits u16"))
        .expect("extended message length fits u16");
    extended[2..4].copy_from_slice(&widened.to_be_bytes());
    extended
}

fn read_fixture(relative: &str) -> Vec<u8> {
    let path = fixture_root().join(relative);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read fixture {}: {error}", path.display());
    })
}

/// Every committed fixture, ordered deterministically by relative path.
fn fixture_corpus() -> Vec<(String, Vec<u8>)> {
    let root = fixture_root();
    let mut found = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("fixture entry unreadable: {error}"));
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("bin") {
                let relative = path
                    .strip_prefix(&root)
                    .expect("fixture path is rooted at the fixture directory")
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
                found.push((relative, bytes));
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// Record one encoder point: the exact bytes emitted, or the exact failure.
fn record(input: &[u8], level: ValidationLevel, raw_preserving: bool, s2b: bool) -> String {
    let ctx = context(level);
    let encode_ctx = encode_context(raw_preserving);
    let mut encoded = BytesMut::new();
    let outcome = if s2b {
        match S2bMessage::decode(input, ctx) {
            Err(error) => return format!("decode_err:{:?}", error.code()),
            Ok((_, message)) => message.encode(&mut encoded, encode_ctx),
        }
    } else {
        match Message::decode(input, ctx) {
            Err(error) => return format!("decode_err:{:?}", error.code()),
            Ok((_, message)) => message.encode(&mut encoded, encode_ctx),
        }
    };
    match outcome {
        Ok(()) => format!("ok:{}", hex(&encoded)),
        Err(error) => format!("encode_err:{:?}", error.code()),
    }
}

/// The closed encoder point space this differential covers.
fn enumerate_points() -> Vec<(String, String)> {
    let mut points = Vec::new();

    // Block A: collateral stability. Every committed fixture across both
    // decode surfaces, all validation levels, and both encode modes. None of
    // these inputs carries IE 176, so every point must be unchanged.
    for (name, bytes) in fixture_corpus() {
        for (level_name, level) in LEVELS {
            for (mode_name, raw_preserving) in ENCODE_MODES {
                for (surface_name, s2b) in [("message", false), ("s2b", true)] {
                    points.push((
                        format!("A|{name}|{level_name}|{mode_name}|{surface_name}"),
                        record(&bytes, *level, *raw_preserving, s2b),
                    ));
                }
            }
        }
    }

    // Block B: injection grid. A spec Create Session Request carrying one
    // extra IE across the type, spare, instance, value, level, and encode-mode
    // axes. Only the IE 176 rows may differ between the two dumps.
    let carrier = read_fixture(INJECTION_CARRIER);
    let values = injected_values();
    for (type_name, ie_type) in INJECTED_IE_TYPES {
        for spare in INJECTED_SPARE_NIBBLES {
            for instance in 0u8..16 {
                for (value_name, value) in &values {
                    let injected = append_ie(&carrier, &tliv(*ie_type, *spare, instance, value));
                    for (level_name, level) in LEVELS {
                        for (mode_name, raw_preserving) in ENCODE_MODES {
                            points.push((
                                format!(
                                    "B|{type_name}|spare{spare}|inst{instance}|{value_name}|{level_name}|{mode_name}"
                                ),
                                record(&injected, *level, *raw_preserving, true),
                            ));
                        }
                    }
                }
            }
        }
    }

    points
}

/// FNV-1a over the exact octets the dump would contain, so the digest below is
/// a hash of the committed dump rather than of some derived summary.
fn absorb(hash: u64, bytes: &[u8]) -> u64 {
    let mut hash = hash;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Digest the ordered `(label, outcome)` list exactly as `GTPV2C_ENCODER_DUMP`
/// would serialise it.
fn digest<'a>(points: impl Iterator<Item = &'a (String, String)>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (label, outcome) in points {
        hash = absorb(hash, label.as_bytes());
        hash = absorb(hash, b"\t");
        hash = absorb(hash, outcome.as_bytes());
        hash = absorb(hash, b"\n");
    }
    hash
}

fn block<'a>(points: &'a [(String, String)], prefix: &str) -> Vec<&'a (String, String)> {
    points
        .iter()
        .filter(|(label, _)| label.starts_with(prefix))
        .collect()
}

/// The point space must stay closed and its outcomes must be asserted: a
/// dropped axis shrinks the count, a collapsed axis makes two labels collide,
/// and any change to an emitted byte or a decode failure moves the digest.
#[test]
fn encoder_point_space_is_closed_and_its_outcomes_are_pinned() {
    // Pinned as literals rather than recomputed from the enumerator's own
    // inputs: a self-referential count cannot detect its axis shrinking.
    assert_eq!(
        fixture_corpus().len(),
        FIXTURE_CORPUS_LEN,
        "committed fixture corpus changed size"
    );
    assert_eq!(
        injected_values().len(),
        INJECTED_VALUE_CLASSES,
        "injected value class count changed"
    );
    assert_eq!(INJECTED_IE_TYPES.len(), 5, "injected IE type axis changed");
    assert_eq!(
        INJECTED_SPARE_NIBBLES.len(),
        2,
        "injected spare nibble axis changed"
    );
    assert_eq!(LEVELS.len(), 3, "validation level axis changed");
    assert_eq!(ENCODE_MODES.len(), 2, "encode mode axis changed");

    let points = enumerate_points();
    assert_eq!(
        points.len(),
        BLOCK_A_POINTS + BLOCK_B_POINTS,
        "encoder differential point count drifted"
    );

    let mut labels: Vec<&str> = points.iter().map(|(label, _)| label.as_str()).collect();
    labels.sort_unstable();
    let unique = labels.len();
    labels.dedup();
    assert_eq!(labels.len(), unique, "encoder differential labels collide");

    if let Ok(path) = std::env::var("GTPV2C_ENCODER_DUMP") {
        let dump: String = points
            .iter()
            .map(|(label, outcome)| format!("{label}\t{outcome}\n"))
            .collect();
        std::fs::write(&path, dump)
            .unwrap_or_else(|error| panic!("failed to write encoder dump {path}: {error}"));
    }

    let block_a = block(&points, "A|");
    let block_b = block(&points, "B|");
    assert_eq!(block_a.len(), BLOCK_A_POINTS, "Block A point count drifted");
    assert_eq!(block_b.len(), BLOCK_B_POINTS, "Block B point count drifted");
    assert_eq!(
        digest(block_a.into_iter()),
        BLOCK_A_DIGEST,
        "collateral encoder stability changed: a committed fixture no longer \
         decodes or re-encodes to the same bytes"
    );
    assert_eq!(
        digest(block_b.into_iter()),
        BLOCK_B_DIGEST,
        "IE 176 injection grid outcomes changed: re-dump with \
         GTPV2C_ENCODER_DUMP and diff before touching this literal"
    );
}

/// The canonical-encode deltas the CHANGELOG and CONFORMANCE entries claim,
/// read back out of the harness itself so a harness that stopped recording real
/// outcomes cannot satisfy them.
#[test]
fn recorded_outcomes_match_the_documented_canonical_deltas() {
    let points = enumerate_points();
    let outcome = |label: &str| -> String {
        points
            .iter()
            .find(|(candidate, _)| candidate == label)
            .map(|(_, outcome)| outcome.clone())
            .unwrap_or_else(|| panic!("point {label} is not in the enumerated space"))
    };

    // TLIV for a canonically re-encoded instance-0 Node Identifier: type 0xb0,
    // length 0x0008, spare 0 / instance 0, then `03 "aaa" 03 "org"`.
    const CANONICAL_IE: &str = "b000080003616161036f7267";
    // The clause 8.107 payload alone, which the carrier fixture does not carry.
    const PAYLOAD: &str = "616161036f7267";

    // Canonical encoding of an instance-0 Node Identifier emits the understood
    // Release 18 prefix only: the `dead` extension suffix is dropped and the
    // IE length shrinks from 0x000a to 0x0008.
    let extended = outcome(
        "B|node_identifier_176|spare0|inst0|well_formed_pair_with_extension|procedure_aware|canonical",
    );
    assert!(
        extended.contains(CANONICAL_IE),
        "canonical encoding did not strip the Extendable suffix: {extended}"
    );
    assert!(
        !extended.contains("dead"),
        "canonical encoding kept the extension octets: {extended}"
    );

    // A non-zero spare nibble is zeroed by canonical encoding.
    let spare = outcome("B|node_identifier_176|spare5|inst0|well_formed_pair|structural|canonical");
    assert!(
        spare.contains(CANONICAL_IE),
        "canonical encoding did not zero the IE spare nibble: {spare}"
    );

    // Clause 7.7.9 discards an instance Table 7.2.1-1 does not list, so the IE
    // is absent from the canonical re-encode entirely.
    let unlisted =
        outcome("B|node_identifier_176|spare0|inst5|well_formed_pair|procedure_aware|canonical");
    assert!(
        unlisted.starts_with("ok:") && !unlisted.contains(PAYLOAD),
        "an unlisted instance survived canonical re-encoding: {unlisted}"
    );

    // TLIV of the injected malformed IE: type 0xb0, length 0x0008, spare 0 /
    // instance 0, then a Node Name length of 9 inside an eight-octet value.
    // One nibble apart from `CANONICAL_IE`, which is the well-formed pair.
    const MALFORMED_IE: &str = "b000080009616161036f7267";

    // Clause 7.7.8: a malformed *optional* IE is discarded and the rest of the
    // message is processed as if it was absent. The canonical re-encode is
    // therefore byte-identical to the same carrier decoded with no IE 176 at
    // all -- the Block A point for the bare fixture -- which is a far stronger
    // claim than "the decode returned ok".
    let malformed_zero = outcome(
        "B|node_identifier_176|spare0|inst0|name_length_overruns_value|procedure_aware|canonical",
    );
    let bare_carrier = outcome(&format!(
        "A|{INJECTION_CARRIER}|procedure_aware|canonical|s2b"
    ));
    assert!(
        bare_carrier.starts_with("ok:"),
        "the bare carrier must encode for the comparison to mean anything: {bare_carrier}"
    );
    assert_eq!(
        malformed_zero, bare_carrier,
        "a malformed instance-0 Node Identifier was not treated as absent"
    );
    assert!(
        !malformed_zero.contains(MALFORMED_IE),
        "the discarded IE survived canonical re-encoding: {malformed_zero}"
    );

    // The same discard leaves the received octets alone: raw-preserving encode
    // blits the parsed region, so the malformed IE is still there byte-exact.
    let preserved = outcome(
        "B|node_identifier_176|spare0|inst0|name_length_overruns_value|procedure_aware|raw_preserving",
    );
    assert!(
        preserved.contains(MALFORMED_IE),
        "raw-preserving encode dropped the discarded IE's octets: {preserved}"
    );

    // The same malformed value at an unlisted instance reaches the same
    // disposition by the earlier clause 7.7.9 route, before the value is typed.
    assert_eq!(
        outcome("B|node_identifier_176|spare0|inst5|name_length_overruns_value|procedure_aware|canonical"),
        bare_carrier,
        "clause 7.7.9 disposition must precede typing and reach the same result"
    );
}

/// Raw-preserving encoding blits the originally parsed IE region, so typing an
/// IE can never move those bytes. Asserted directly rather than inferred.
#[test]
fn raw_preserving_encoding_is_byte_exact_for_every_injected_point() {
    let carrier = read_fixture(INJECTION_CARRIER);
    let values = injected_values();
    let mut checked = 0usize;
    for (_, ie_type) in INJECTED_IE_TYPES {
        for spare in INJECTED_SPARE_NIBBLES {
            for instance in 0u8..16 {
                for (_, value) in &values {
                    let injected = append_ie(&carrier, &tliv(*ie_type, *spare, instance, value));
                    for (_, level) in LEVELS {
                        let Ok((tail, message)) = S2bMessage::decode(&injected, context(*level))
                        else {
                            continue;
                        };
                        let parsed = &injected[..injected.len() - tail.len()];
                        let mut encoded = BytesMut::new();
                        message
                            .encode(&mut encoded, encode_context(true))
                            .expect("raw-preserving encode of a decoded message succeeds");
                        assert_eq!(
                            encoded.as_ref(),
                            parsed,
                            "raw-preserving encode changed bytes for IE type {ie_type}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    // Pinned exactly, not as a floor. A change that made most injected points
    // fail decode would silently gut this guard under `checked > 0` while
    // still reporting ok.
    assert_eq!(
        checked, RAW_PRESERVING_CHECKED_POINTS,
        "raw-preserving differential point coverage drifted"
    );
}
