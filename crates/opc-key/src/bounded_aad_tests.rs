use super::*;
use std::io::Write;
use std::str::FromStr;

fn fixture(principal: &str) -> (EnvelopeAad, KeyId) {
    let aad = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            TxId::from_str("11111111-1111-4111-8111-111111111111").unwrap(),
            None,
            Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
            principal,
            SchemaDigest::from_bytes([0; 32]),
            "running",
        )
        .unwrap(),
    );
    (aad, KeyId::new("synthetic-key").unwrap())
}

#[test]
fn canonical_stream_preserves_legacy_bytes_and_rejections() {
    let bytes = br#"{"tenant":"synthetic","purpose":"config","version":1,"key_id":"synthetic-key","metadata":{"kind":"config","tx_id":"11111111-1111-4111-8111-111111111111","parent_tx_id":null,"committed_at":"2026-01-01T00:00:00Z","principal":"writer","schema_digest":"0000000000000000000000000000000000000000000000000000000000000000","store_kind":"running"}}"#;
    let (aad, key) = fixture("writer");
    assert_eq!(serialize_bound_aad(&aad, &key).unwrap(), bytes);
    assert_eq!(decode_bound_aad(bytes).unwrap(), (aad, key));
    // Both encodings are valid equivalent JSON, but are not canonical bytes.
    let whitespace = [bytes.as_slice(), b" "].concat();
    let escaped = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace("writer", "\\u0077riter");
    let reordered = String::from_utf8(bytes.to_vec()).unwrap().replace(
        "\"tenant\":\"synthetic\",\"purpose\":\"config\"",
        "\"purpose\":\"config\",\"tenant\":\"synthetic\"",
    );
    assert_eq!(reordered.len(), bytes.len());
    for rejected in [whitespace, escaped.into_bytes(), reordered.into_bytes()] {
        let error = decode_bound_aad(&rejected).unwrap_err();
        assert_eq!(
            error.to_string(),
            KeyError::invalid_metadata("aad", "must be canonical").to_string()
        );
    }
}

#[test]
fn canonical_stream_handles_bounded_size_and_larger_legacy_aad() {
    for size in [65_536, 65_537] {
        let prefix = "escaped/\"\\\n\u{1}/🙂/";
        let (base, key) = fixture(prefix);
        let padding = size - serialize_bound_aad(&base, &key).unwrap().len();
        let (aad, key) = fixture(&format!("{prefix}{}", "p".repeat(padding)));
        let encoded = serialize_bound_aad(&aad, &key).unwrap();
        assert_eq!(encoded.len(), size);
        assert_eq!(decode_bound_aad(&encoded).unwrap(), (aad, key));
        let mut noncanonical = encoded;
        noncanonical.insert(1, b' ');
        assert_eq!(
            decode_bound_aad(&noncanonical).unwrap_err().to_string(),
            KeyError::invalid_metadata("aad", "must be canonical").to_string()
        );
    }
}

#[test]
fn canonical_mismatch_does_not_mask_a_later_serialization_error() {
    let (aad, key) = fixture("writer");
    let canonical = String::from_utf8(serialize_bound_aad(&aad, &key).unwrap()).unwrap();
    let input = canonical
        .replacen("{", "{ ", 1)
        .replace("2026-01-01T00:00:00Z", "0000-01-01T00:00:00+01:00");
    assert_eq!(
        decode_bound_aad(input.as_bytes()).unwrap_err().to_string(),
        KeyError::invalid_metadata("aad", "failed to serialize").to_string()
    );
}

#[test]
fn canonical_comparison_mismatch_stays_sticky_and_consumes_all_chunks() {
    for input in [b"axcdef".as_slice(), b"abc", b"abcdefg"] {
        let mut comparison = CanonicalAadComparison {
            remaining: input,
            equal: true,
        };
        for chunk in [b"ab", b"cd", b"ef"] {
            assert_eq!(comparison.write(chunk).unwrap(), chunk.len());
        }
        comparison.flush().unwrap();
        assert!(!comparison.equal || !comparison.remaining.is_empty());
    }
    let mut comparison = CanonicalAadComparison {
        remaining: b"abcdef",
        equal: true,
    };
    for chunk in [b"ab", b"cd", b"ef"] {
        comparison.write_all(chunk).unwrap();
    }
    assert!(comparison.equal && comparison.remaining.is_empty());
}
