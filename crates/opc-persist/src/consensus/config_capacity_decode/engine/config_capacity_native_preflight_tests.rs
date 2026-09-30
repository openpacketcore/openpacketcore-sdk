//! Independent grammar checks before a native byte-array descriptor can exist.

use super::*;

fn oracle(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Vec<u8>>();
    let values = stream.next()?.ok()?;
    let end = stream.byte_offset();
    let canonical = serde_json::to_vec(&values).unwrap();
    (bytes.get(..end)? == canonical).then_some((end, values.len()))
}

#[test]
fn config_capacity_native_preflight_matches_independent_numeric_grammar() {
    let mut mismatches = Vec::new();
    let mut cases = 0;
    let mut compare = |bytes: &[u8]| {
        let expected = oracle(bytes);
        let actual = array_extent(bytes);
        cases += 1;
        if expected != actual {
            mismatches.push((bytes.to_vec(), expected, actual));
        }
    };
    for value in 0..=1024 {
        for token in [
            format!("{value}"),
            format!("{value:02}"),
            format!("{value:03}"),
        ] {
            compare(format!("[{token}]").as_bytes());
            compare(format!("[0,{token},255]").as_bytes());
        }
    }
    for token in [
        "0", "9", "10", "99", "100", "199", "200", "249", "250", "255",
    ] {
        let original = format!("[{token}]").into_bytes();
        for index in 1..original.len() - 1 {
            for byte in 0..=255 {
                let mut changed = original.clone();
                changed[index] = byte;
                compare(&changed);
            }
        }
        for suffix in [b"".as_slice(), b",\"metadata\":true}", b" trailing", b"\0"] {
            let mut bytes = original.clone();
            bytes.extend_from_slice(suffix);
            compare(&bytes);
        }
    }
    for bytes in [
        b"[]".as_slice(),
        b"[] suffix",
        b"[",
        b"[,]",
        b"[1,]",
        b"[ 1]",
        b"[1 ]",
        b"[1.0]",
        b"[1e2]",
        b"[true]",
        b"[null]",
        b"[[1]]",
        b"[\"1\"]",
        b"[-1]",
        b"[+1]",
    ] {
        compare(bytes);
    }
    assert!(cases > 10_000, "exhaustive token and non-ASCII mutations");
    assert!(
        mismatches.is_empty(),
        "CONFIG_CAPACITY_NATIVE_PREFLIGHT_GRAMMAR_RED: independent decode and compact re-encoding completed for {cases} cases; mismatches={mismatches:?}"
    );
}

#[test]
fn config_capacity_native_preflight_checks_exact_extent_before_descriptor() {
    let values = vec![0_u8; CONFIG_CAPACITY_V1_ENVELOPE_BYTES];
    let mut bytes = serde_json::to_vec(&values).unwrap();
    let array = ValidatedArray::new(&bytes).expect("exact admitted envelope bound");
    assert_eq!(array.count, values.len());
    assert_eq!(array.encoded, bytes);
    assert_eq!(
        serde_json::from_slice::<Vec<u8>>(array.encoded).unwrap(),
        values
    );

    let end = bytes.len();
    bytes.extend_from_slice(b",\"metadata\":true}");
    let array = ValidatedArray::new(&bytes).expect("borrow only the exact array");
    assert_eq!(array.count, values.len());
    assert_eq!(array.encoded, &bytes[..end]);

    let mut over = bytes[..end - 1].to_vec();
    over.extend_from_slice(b",0]");
    assert_eq!(
        serde_json::from_slice::<Vec<u8>>(&over).unwrap().len(),
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1
    );
    assert!(
        ValidatedArray::new(&over).is_none(),
        "CONFIG_CAPACITY_NATIVE_PREFLIGHT_BOUND_RED: no descriptor beyond the admitted envelope, after exact-bound and suffix oracles"
    );
}

#[test]
fn config_capacity_native_preflight_preserves_original_late_invalid_token_behavior() {
    for source in [fixture(4096, None), audited_fixture(4096)] {
        let bytes = serde_json::to_vec(&source).unwrap();
        let expected = original(&bytes).expect("original valid complete command");
        let (actual, work) = observe_validated_fill(|| entry(&bytes));
        let actual = actual.expect("current valid complete command");
        assert!(actual == expected);
        assert_eq!(serde_json::to_vec(&actual).unwrap(), bytes);
        assert_eq!(work.bytes, 4096);
        assert_eq!(work.arrays, 1);

        let start = bytes
            .windows(FIELD.len())
            .position(|part| part == FIELD)
            .unwrap()
            + FIELD.len();
        let (extent, count) = array_extent(&bytes[start..]).unwrap();
        assert_eq!(count, 4096);
        for position in [0, 2048, 4095] {
            for token in [
                "00", "01", "099", "256", "259", "260", "299", "1000", "-1", "+1", "1.0", "1e2",
                "null", "true", "\"1\"", "[1]", "{}", "", " 1",
            ] {
                let mut tokens = vec!["0"; 4096];
                tokens[position] = token;
                let array = format!("[{}]", tokens.join(","));
                assert!(
                    ValidatedArray::new(array.as_bytes()).is_none(),
                    "CONFIG_CAPACITY_NATIVE_PREFLIGHT_DESCRIPTOR_RED: malformed or noncanonical token at {position}: {token:?}"
                );
                let mut input = bytes[..start].to_vec();
                input.extend_from_slice(array.as_bytes());
                input.extend_from_slice(&bytes[start + extent..]);
                let expected = original(&input);
                let (actual, work) = observe_validated_fill(|| entry(&input));
                assert_eq!(actual.is_ok(), expected.is_ok());
                if let (Ok(actual), Ok(expected)) = (actual, expected) {
                    assert!(actual == expected, "unchanged noncanonical fallback");
                    assert_eq!(
                        serde_json::to_vec(&actual).unwrap(),
                        serde_json::to_vec(&expected).unwrap()
                    );
                }
                assert_eq!(
                    work.arrays, 0,
                    "rejected preflight cannot enter bounded fill"
                );
            }
        }
    }
}
