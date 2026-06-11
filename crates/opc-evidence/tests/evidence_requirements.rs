mod evidence_common;
use evidence_common::*;
use std::str::FromStr;

#[test]
fn requirement_id_parses_valid() {
    let req = RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1-001").unwrap();
    assert_eq!(req.source(), "3GPP");
    assert_eq!(req.document(), "TS29281");
    assert_eq!(req.release(), "R18");
    assert_eq!(req.section(), "5.1");
    assert_eq!(req.ordinal(), 1);
    assert_eq!(req.to_string(), "REQ-3GPP-TS29281-R18-5.1-001");
}

#[test]
fn requirement_id_rejects_missing_prefix() {
    assert!(RequirementId::from_str("3GPP-TS29281-R18-5.1-001").is_err());
}

#[test]
fn requirement_id_rejects_too_few_segments() {
    assert!(RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1").is_err());
}

#[test]
fn requirement_id_rejects_too_many_segments() {
    assert!(RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1-001-extra").is_err());
}

#[test]
fn requirement_id_rejects_non_numeric_ordinal() {
    assert!(RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1-abc").is_err());
}

#[test]
fn requirement_id_rejects_empty_field() {
    assert!(RequirementId::from_str("REQ--TS29281-R18-5.1-001").is_err());
}

#[test]
fn requirement_id_roundtrips_serde() {
    let req = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-042").unwrap();
    let json = serde_json::to_string(&req).unwrap();
    assert_eq!(json, "\"REQ-IETF-RFC7951-V1-4.2-042\"");
    let back: RequirementId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

#[test]
fn requirement_id_new_validation() {
    let req = RequirementId::new("3GPP", "TS29281", "R18", "5.1", 1).unwrap();
    assert_eq!(req.to_string(), "REQ-3GPP-TS29281-R18-5.1-001");

    assert!(RequirementId::new("", "TS29281", "R18", "5.1", 1).is_err());
    assert!(RequirementId::new("3GPP", "TS-29281", "R18", "5.1", 1).is_err());
    assert!(RequirementId::new("3GPP", "TS29281", "", "5.1", 1).is_err());
    assert!(RequirementId::new("3GPP", "TS29281", "R18", "5-1", 1).is_err());
}

#[test]
fn requirement_id_from_str_and_new_consistency() {
    assert!(RequirementId::new("", "TS29281", "R18", "5.1", 1).is_err());
    assert!(RequirementId::from_str("REQ--TS29281-R18-5.1-001").is_err());

    let req_from_new = RequirementId::new("3GPP", "TS29281", "R18", "5.1", 1).unwrap();
    let req_from_str = RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1-001").unwrap();
    assert_eq!(req_from_new, req_from_str);
}
