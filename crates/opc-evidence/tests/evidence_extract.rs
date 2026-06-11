mod evidence_common;
use evidence_common::*;

#[test]
fn tag_parser_extracts_known_tags() {
    let doc = r#"
        /// @spec 3GPP TS 29.281 R18 5.1 Table 5.1-1
        /// @req REQ-3GPP-TS29281-R18-5.1-001
        /// @conformance partial
        /// @gap GAP-000123
    "#;

    let tags = parse_tags(doc, true).unwrap();
    assert_eq!(tags.len(), 4);
    assert_eq!(tags[0].key, "spec");
    assert_eq!(tags[1].key, "req");
    assert_eq!(tags[2].key, "conformance");
    assert_eq!(tags[3].key, "gap");
}

#[test]
fn tag_parser_rejects_unknown_key_in_strict_mode() {
    let doc = "/// @unknown foo";
    assert!(parse_tags(doc, true).is_err());
}

#[test]
fn tag_parser_allows_unknown_key_in_non_strict_mode() {
    let doc = "/// @unknown foo";
    let tags = parse_tags(doc, false).unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].key, "unknown");
}

#[test]
fn tag_parser_rejects_empty_key() {
    assert!(parse_tags("/// @", true).is_err());
}

#[test]
fn tag_parser_rejects_valueless_strict_tags_in_strict_mode() {
    assert!(parse_tags("/// @req", true).is_err());
    assert!(parse_tags("/// @spec", true).is_err());
    assert!(parse_tags("/// @req   ", true).is_err());
    assert!(parse_tags("/// @spec\n", true).is_err());
}

#[test]
fn test_gap_006_001_source_extraction() {
    use std::fs;
    let temp_dir = tempfile::tempdir().unwrap();
    let file1_path = temp_dir.path().join("a_first.rs");
    let file2_path = temp_dir.path().join("b_second.rs");

    fs::write(
        &file1_path,
        "/// @spec 3GPP TS 29.281\n/// @req REQ-3GPP-TS29281-R18-5.1-001\npub fn test() {}\n",
    )
    .unwrap();
    fs::write(
        &file2_path,
        "/// @conformance partial\n/// @gap GAP-000123\n// @test test_ref\nstruct Foo;\n",
    )
    .unwrap();

    let (extracted, errors) = scan_directory(temp_dir.path(), true).unwrap();
    assert!(errors.is_empty());
    assert_eq!(extracted.len(), 5);

    assert_eq!(extracted[0].file_path, "a_first.rs");
    assert_eq!(extracted[0].line_number, 1);
    assert_eq!(extracted[0].tag.key, "spec");
    assert_eq!(extracted[0].tag.value, "3GPP TS 29.281");
    assert_eq!(extracted[0].context, Some("pub fn test() {}".to_string()));

    assert_eq!(extracted[1].file_path, "a_first.rs");
    assert_eq!(extracted[1].line_number, 2);
    assert_eq!(extracted[1].tag.key, "req");
    assert_eq!(extracted[1].context, Some("pub fn test() {}".to_string()));

    assert_eq!(extracted[2].file_path, "b_second.rs");
    assert_eq!(extracted[2].line_number, 1);
    assert_eq!(extracted[2].tag.key, "conformance");
    assert_eq!(extracted[2].context, Some("struct Foo;".to_string()));

    assert_eq!(extracted[3].file_path, "b_second.rs");
    assert_eq!(extracted[3].line_number, 2);
    assert_eq!(extracted[3].tag.key, "gap");

    assert_eq!(extracted[4].file_path, "b_second.rs");
    assert_eq!(extracted[4].line_number, 3);
    assert_eq!(extracted[4].tag.key, "test");

    let bad_file = temp_dir.path().join("bad.rs");
    fs::write(&bad_file, "/// @unknown-tag value\n").unwrap();
    let res = scan_file(&bad_file, temp_dir.path(), true);
    assert!(res.is_err());

    let bad_file_err = temp_dir.path().join("bad_err.rs");
    fs::write(&bad_file_err, "/// @\n").unwrap();
    let (extracted_bad, errors_bad) = scan_file(&bad_file_err, temp_dir.path(), false).unwrap();
    assert!(extracted_bad.is_empty());
    assert_eq!(errors_bad.len(), 1);
    assert_eq!(errors_bad[0].line_number, 1);
    assert!(errors_bad[0].error.contains("invalid tag"));
}

#[test]
fn evidence_extraction_errors_do_not_leak_absolute_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_file = temp_dir.path().join("missing.rs");
    let err = scan_file(&missing_file, temp_dir.path(), true).unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("missing.rs"));
    assert!(!rendered.contains(&temp_dir.path().to_string_lossy().to_string()));

    let missing_dir = temp_dir.path().join("does-not-exist");
    let err = scan_directory(&missing_dir, true).unwrap_err();
    assert!(matches!(err, EvidenceError::MissingArtifact(_)));
}
