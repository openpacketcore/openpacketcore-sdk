mod testbed_common;
use testbed_common::*;

fn valid_fixture() -> FixtureProvenance {
    FixtureProvenance {
        id: "fx-001".into(),
        source: "gen".into(),
        standard_ref: "3GPP TS 24.501".into(),
        release: "R17".into(),
        synthetic: true,
        sanitization: "none".into(),
        expected_decode: "DecodeSuccess(RegistrationRequest)".into(),
        requirements: vec!["REQ-3GPP-TS24501-R17-5.2-001".into()],
        notes: None,
    }
}

#[test]
fn fixture_provenance_json_roundtrip() {
    let json = include_str!("fixtures/fake_fixture_provenance.json");
    let prov: FixtureProvenance = serde_json::from_str(json).expect("parse provenance json");

    assert_eq!(prov.id, "nas-reg-request-v1");
    assert_eq!(prov.standard_ref, "3GPP TS 24.501");
    assert_eq!(prov.expected_decode, "DecodeSuccess(RegistrationRequest)");

    let back = serde_json::to_string(&prov).unwrap();
    let prov2: FixtureProvenance = serde_json::from_str(&back).unwrap();
    assert_eq!(prov2.standard_ref, prov.standard_ref);
    assert_eq!(prov2.expected_decode, prov.expected_decode);
}

#[test]
fn fixture_provenance_validation() {
    let prov = valid_fixture();
    prov.validate().expect("valid synthetic fixture passes");

    let mut bad = prov.clone();
    bad.synthetic = false;
    bad.sanitization = "none".into();
    assert!(bad.validate().is_err());

    let mut blank = prov.clone();
    blank.synthetic = false;
    blank.sanitization = "   ".into();
    assert!(blank.validate().is_err());

    let mut empty = prov.clone();
    empty.synthetic = false;
    empty.sanitization = "".into();
    assert!(empty.validate().is_err());

    let mut syn_blank = prov.clone();
    syn_blank.synthetic = true;
    syn_blank.sanitization = "".into();
    assert!(syn_blank.validate().is_err());

    let mut no_release = prov.clone();
    no_release.release = "   ".into();
    assert!(no_release.validate().is_err());

    let mut no_std = prov.clone();
    no_std.standard_ref = "".into();
    assert!(no_std.validate().is_err());

    let mut no_reqs = prov.clone();
    no_reqs.requirements = vec![];
    assert!(no_reqs.validate().is_err());

    let mut blank_reqs = prov.clone();
    blank_reqs.requirements = vec!["   ".into(), "".into()];
    assert!(blank_reqs.validate().is_err());

    let mut mixed_blank = prov.clone();
    mixed_blank.requirements = vec!["REQ-3GPP-TS24501-R17-5.2-001".into(), "".into()];
    assert!(mixed_blank.validate().is_err());

    let mut bad_req = prov.clone();
    bad_req.requirements = vec!["NOT-A-VALID-REQ-ID".into()];
    assert!(bad_req.validate().is_err());

    let mut no_decode = prov.clone();
    no_decode.expected_decode = "   ".into();
    assert!(no_decode.validate().is_err());
}

#[test]
fn fixture_registry_rejects_duplicate_id() {
    let mut reg = FixtureRegistry::default();
    let prov = valid_fixture();
    reg.register(prov.clone()).expect("register valid fixture");
    assert!(reg.get("fx-001").is_some());

    let err = reg.register(prov).expect_err("duplicate id must fail");
    assert!(err.to_string().contains("already registered"));
}

#[test]
fn fixture_registry_roundtrip() {
    let mut reg = FixtureRegistry::default();
    let prov = valid_fixture();
    reg.register(prov.clone()).expect("register valid fixture");
    assert!(reg.get("fx-001").is_some());
    assert!(reg.get("missing").is_none());
}
