mod testbed_common;
use testbed_common::*;

#[test]
fn scenario_yaml_roundtrip_and_validate() {
    let yaml = include_str!("fixtures/ue_registration.yaml");
    let scenario = Scenario::from_yaml(yaml).expect("parse scenario yaml");
    assert_eq!(scenario.id, "AMF-REG-001");
    assert_eq!(scenario.schema_version, DSL_VERSION);
    assert!(!scenario.steps.is_empty());
    assert!(!scenario.assertions.is_empty());

    scenario
        .validate()
        .expect("structural validation should pass");

    let json = serde_json::to_string(&scenario).unwrap();
    let back: Scenario = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, scenario.id);

    assert_eq!(back.steps.len(), scenario.steps.len());
    for (orig, rt) in scenario.steps.iter().zip(back.steps.iter()) {
        assert_eq!(std::mem::discriminant(orig), std::mem::discriminant(rt));
    }
}

#[test]
fn scenario_fixture_matches_versioned_schema() {
    schema_support::validate_yaml_str_against_schema(
        SCENARIO_SCHEMA,
        include_str!("fixtures/ue_registration.yaml"),
    )
    .expect("fixture scenario must satisfy the committed RFC 012 schema");
}

#[test]
fn scenario_canonical_rfc012_wire_format() {
    let yaml = r#"
id: AMF-REG-001
title: UE registration success
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { image: opc-amf:test }
    nrf: { simulator: nrf-basic }
steps:
  - send_ngap:
      from: gnb-1
      to: amf
      message: InitialUEMessage.registration_request
  - expect_sbi:
      from: amf
      to: ausf
      operation: Nausf_UEAuthentication.Authenticate
assertions:
  - amf.ue_context.state == REGISTERED
"#;

    let scenario = Scenario::from_yaml(yaml).expect("parse canonical RFC 012 yaml");
    assert_eq!(scenario.id, "AMF-REG-001");
    assert_eq!(scenario.steps.len(), 2);

    match &scenario.steps[0] {
        Step::SendNgap { from, to, message } => {
            assert_eq!(from, "gnb-1");
            assert_eq!(to, "amf");
            assert_eq!(message, "InitialUEMessage.registration_request");
        }
        other => panic!("expected SendNgap, got {other:?}"),
    }

    match &scenario.steps[1] {
        Step::ExpectSbi {
            from,
            to,
            operation,
        } => {
            assert_eq!(from, "amf");
            assert_eq!(to, "ausf");
            assert_eq!(operation, "Nausf_UEAuthentication.Authenticate");
        }
        other => panic!("expected ExpectSbi, got {other:?}"),
    }

    assert_eq!(scenario.assertions.len(), 1);
    assert_eq!(
        scenario.assertions[0].expr,
        "amf.ue_context.state == REGISTERED"
    );
    assert!(!scenario.assertions[0].order_independent);

    scenario.validate().unwrap();
}

#[test]
fn scenario_canonical_rfc012_fixture_matches_versioned_schema() {
    let yaml = r#"
id: AMF-REG-001
title: UE registration success
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { image: opc-amf:test }
    nrf: { simulator: nrf-basic }
steps:
  - send_ngap:
      from: gnb-1
      to: amf
      message: InitialUEMessage.registration_request
  - expect_sbi:
      from: amf
      to: ausf
      operation: Nausf_UEAuthentication.Authenticate
assertions:
  - amf.ue_context.state == REGISTERED
"#;

    schema_support::validate_yaml_str_against_schema(SCENARIO_SCHEMA, yaml)
        .expect("canonical RFC 012 scenario form must satisfy the committed schema");
}

#[test]
fn epdg_swu_attach_skeleton_parses_and_validates() {
    let yaml = r#"
id: EPDG-SWU-ATTACH-001
title: SWu IKEv2 attach skeleton
schema_version: "0.1.0"
topology:
  nfs:
    ue: { simulator: ue-basic }
    epdg: { image: opc-epdg:test }
steps:
  - kind: send_ikev2
    from: ue
    to: epdg
    fixture: fixtures/swu/ike-sa-init.hex
    label: ike-sa-init
    transport: udp/500
  - kind: expect_ikev2
    from: epdg
    to: ue
    fixture: fixtures/swu/ike-sa-init-response.hex
    transport: udp/500
  - kind: packet_loss
    target: epdg
    protocol: ikev2
    packet_count: 1
  - kind: retransmission
    target: ue
    protocol: ikev2
    attempts: 1
"#;

    let scenario = Scenario::from_yaml(yaml).expect("parse SWu skeleton");
    scenario.validate().expect("validate SWu skeleton");
}

#[test]
fn diameter_success_skeleton_parses_and_validates() {
    let yaml = r#"
id: EPC-DIAMETER-AAA-001
title: Diameter AAA success skeleton
schema_version: "0.1.0"
topology:
  nfs:
    epdg: { image: opc-epdg:test }
    aaa: { simulator: diameter-aaa-basic }
steps:
  - kind: send_diameter
    from: epdg
    to: aaa
    fixture: fixtures/diameter/swm-auth-request.json
    label: swm-auth-request
  - kind: expect_diameter
    from: aaa
    to: epdg
    fixture: fixtures/diameter/swm-auth-answer.json
    label: swm-auth-answer
"#;

    let scenario = Scenario::from_yaml(yaml).expect("parse Diameter skeleton");
    scenario.validate().expect("validate Diameter skeleton");
}

#[test]
fn s2b_gtpv2c_create_session_skeleton_parses_and_validates() {
    let yaml = r#"
id: EPC-S2B-GTPV2C-001
title: S2b GTPv2-C create session skeleton
schema_version: "0.1.0"
topology:
  nfs:
    epdg: { image: opc-epdg:test }
    pgw: { simulator: gtpv2c-pgw-basic }
steps:
  - kind: send_gtpv2c
    from: epdg
    to: pgw
    fixture: fixtures/s2b/create-session-request.bin
    label: create-session-request
  - kind: expect_gtpv2c
    from: pgw
    to: epdg
    fixture: fixtures/s2b/create-session-response.bin
    label: create-session-response
  - kind: timeout
    target: pgw
    protocol: gtpv2c
"#;

    let scenario = Scenario::from_yaml(yaml).expect("parse S2b skeleton");
    scenario.validate().expect("validate S2b skeleton");
}

#[test]
fn gtpu_continuity_skeleton_parses_and_validates() {
    let yaml = r#"
id: EPC-GTPU-CONTINUITY-001
title: GTP-U and ESP continuity skeleton
schema_version: "0.1.0"
topology:
  nfs:
    ue: { simulator: ue-basic }
    epdg: { image: opc-epdg:test }
    pgw-u: { simulator: gtpu-peer-basic }
steps:
  - kind: send_gtpu
    from: epdg
    to: pgw-u
    fixture: fixtures/user-plane/gtpu-uplink.bin
    label: uplink-user-plane
  - kind: expect_gtpu
    from: pgw-u
    to: epdg
    fixture: fixtures/user-plane/gtpu-downlink.bin
    label: downlink-user-plane
  - kind: expect_esp
    from: epdg
    to: ue
    fixture: fixtures/user-plane/esp-downlink.bin
    label: esp-continuity-evidence
  - kind: duplicate_packet
    target: epdg
    protocol: gtpu
    packet_count: 1
"#;

    let scenario = Scenario::from_yaml(yaml).expect("parse GTP-U skeleton");
    scenario.validate().expect("validate GTP-U skeleton");
}

#[test]
fn malformed_protocol_step_fixture_reference_is_rejected() {
    let yaml = r#"
id: BAD-PROTOCOL-FIXTURE
title: malformed fixture ref
schema_version: "0.1.0"
topology:
  nfs:
    ue: { simulator: ue-basic }
    epdg: { image: opc-epdg:test }
steps:
  - kind: send_ikev2
    from: ue
    to: epdg
    fixture: ../secrets/ike-sa-init.hex
"#;

    let scenario = Scenario::from_yaml(yaml).expect("schema accepts opaque fixture string");
    let err = scenario
        .validate()
        .expect_err("unsafe fixture reference must fail validation");
    assert!(err.to_string().contains("fixture reference"));
}

#[test]
fn unsupported_epc_protocol_step_kind_fails_closed() {
    let yaml = r#"
id: BAD-PROTOCOL-KIND
title: unknown protocol step kind
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_swu
    from: ue
    to: epdg
    fixture: fixtures/swu/unknown.hex
"#;

    let err = Scenario::from_yaml(yaml).expect_err("unknown protocol kind must fail parse");
    assert!(
        err.to_string().contains("send_swu")
            || err.to_string().contains("oneOf")
            || err.to_string().contains("kind")
    );
}

#[test]
fn scenario_validate_rejects_empty_id() {
    let yaml = r#"
id: ""
title: bad
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("id"));
}

#[test]
fn scenario_validate_rejects_empty_title() {
    let yaml = r#"
id: BAD-TITLE
title: "   "
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let err = scenario.validate().unwrap_err();
    assert!(err.to_string().contains("scenario title required"));
}

#[test]
fn scenario_validate_rejects_empty_steps() {
    let yaml = r#"
id: NO-STEPS
title: bad
schema_version: "0.1.0"
topology:
  nfs: {}
steps: []
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("steps"));
}

#[test]
fn scenario_validate_rejects_missing_schema_version() {
    let yaml = r#"
id: NO-VERSION
title: bad
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("schema_version"));
}

#[test]
fn scenario_schema_rejects_missing_schema_version() {
    let yaml = r#"
id: NO-VERSION
title: bad
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = schema_support::validate_yaml_str_against_schema(SCENARIO_SCHEMA, yaml).unwrap_err();
    assert!(err.contains("missing required property 'schema_version'"));
}

#[test]
fn scenario_parse_rejects_unknown_top_level_key() {
    let yaml = r#"
id: BAD-KEY
title: bad
schema_version: "0.1.0"
requirments:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).expect_err("typoed top-level key must fail parse");
    assert!(err.to_string().contains("unexpected property"));
}

#[test]
fn scenario_parse_rejects_unknown_tagged_step_key() {
    let yaml = r#"
id: BAD-STEP
title: bad
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    mesage: typo
"#;
    let err = Scenario::from_yaml(yaml).expect_err("typoed step key must fail parse");
    let msg = err.to_string();
    assert!(
        msg.contains("unexpected property")
            || msg.contains("oneOf branch")
            || msg.contains("missing required property"),
        "error should indicate schema mismatch: {msg}"
    );
}

#[test]
fn scenario_parse_rejects_unknown_canonical_step_key() {
    let yaml = r#"
id: BAD-CANON
title: bad
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - send_ngap:
      from: a
      to: b
      message: m
      mesage: typo
"#;
    let err = Scenario::from_yaml(yaml).expect_err("typoed canonical step key must fail parse");
    assert!(err.to_string().contains("unexpected property"));
}

#[test]
fn scenario_validate_rejects_bad_schema_version() {
    let yaml = r#"
id: BAD-VERSION
title: bad
schema_version: "9.9.9"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("schema_version") || err.to_string().contains("unsupported"));
    assert!(err.to_string().contains("9.9.9"));
}

#[test]
fn scenario_validate_rejects_unknown_step_kind() {
    let yaml = r#"
id: TYPO-STEP
title: bad
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: expect_sbb
    from: a
    to: b
    operation: o
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("expect_sbb")
            || err.to_string().contains("oneOf")
            || err.to_string().contains("kind")
    );
}

#[test]
fn scenario_validate_rejects_invalid_requirement_id() {
    let yaml = r#"
id: BAD-REQ
title: bad
schema_version: "0.1.0"
requirements:
  - NOT-A-VALID-REQ-ID
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("invalid requirement id") || err.to_string().contains("format")
    );
    assert!(err.to_string().contains("NOT-A-VALID-REQ-ID"));
}

#[test]
fn scenario_from_str_trait() {
    let yaml = r#"
id: FROM-STR-TEST
title: from str trait
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let scenario = Scenario::from_str(yaml).unwrap();
    assert_eq!(scenario.id, "FROM-STR-TEST");
}

#[test]
fn scenario_validate_rejects_blank_image() {
    let yaml = r#"
id: BLANK-IMAGE
title: blank image
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      image: ""
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("image"),
        "expected error to mention 'image', got: {err_str}"
    );
}

#[test]
fn scenario_validate_rejects_blank_simulator() {
    let yaml = r#"
id: BLANK-SIMULATOR
title: blank simulator
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      image: "amf-image"
      simulator: ""
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("simulator"),
        "expected error to mention 'simulator', got: {err_str}"
    );
}

#[test]
fn scenario_validate_rejects_null_seed() {
    let yaml = r#"
id: NULL-SEED
title: null seed
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
seed: ~
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("seed") || err.to_string().contains("type"));
}

#[test]
fn scenario_validate_rejects_null_image() {
    let yaml = r#"
id: NULL-IMAGE
title: null image
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      image: ~
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("image") || err.to_string().contains("type"));
}

#[test]
fn scenario_validate_rejects_null_simulator() {
    let yaml = r#"
id: NULL-SIMULATOR
title: null simulator
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      simulator: ~
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let err = Scenario::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("simulator") || err.to_string().contains("type"));
}

#[test]
fn scenario_validate_rejects_json_null_seed() {
    let json = r#"{
        "id": "JSON-NULL-SEED",
        "title": "json null seed",
        "schema_version": "0.1.0",
        "topology": { "nfs": {} },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ],
        "seed": null
    }"#;
    let err = Scenario::from_json(json).unwrap_err();
    assert!(err.to_string().contains("seed") || err.to_string().contains("type"));
}

#[test]
fn scenario_validate_rejects_json_null_image() {
    let json = r#"{
        "id": "JSON-NULL-IMAGE",
        "title": "json null image",
        "schema_version": "0.1.0",
        "topology": {
            "nfs": {
                "amf": { "image": null }
            }
        },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ]
    }"#;
    let err = Scenario::from_json(json).unwrap_err();
    assert!(err.to_string().contains("image") || err.to_string().contains("type"));
}

#[test]
fn scenario_validate_rejects_json_null_simulator() {
    let json = r#"{
        "id": "JSON-NULL-SIMULATOR",
        "title": "json null simulator",
        "schema_version": "0.1.0",
        "topology": {
            "nfs": {
                "amf": { "simulator": null }
            }
        },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ]
    }"#;
    let err = Scenario::from_json(json).unwrap_err();
    assert!(err.to_string().contains("simulator") || err.to_string().contains("type"));
}

#[test]
fn direct_json_deserialize_rejects_null_seed() {
    let json = r#"{
        "id": "DIRECT-NULL-SEED",
        "title": "direct null seed",
        "schema_version": "0.1.0",
        "topology": { "nfs": {} },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ],
        "seed": null
    }"#;
    let result: Result<Scenario, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "direct JSON deserialization must reject seed: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("seed") || err.contains("type"),
        "error should mention seed or type mismatch: {err}"
    );
}

#[test]
fn direct_yaml_deserialize_rejects_null_seed() {
    let yaml = r#"
id: DIRECT-NULL-SEED
title: direct null seed
schema_version: "0.1.0"
topology:
  nfs: {}
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
seed: null
"#;
    let result: Result<Scenario, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "direct YAML deserialization must reject seed: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("seed") || err.contains("type"),
        "error should mention seed or type mismatch: {err}"
    );
}

#[test]
fn direct_json_deserialize_rejects_null_image() {
    let json = r#"{
        "id": "DIRECT-NULL-IMAGE",
        "title": "direct null image",
        "schema_version": "0.1.0",
        "topology": {
            "nfs": {
                "amf": { "image": null }
            }
        },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ]
    }"#;
    let result: Result<Scenario, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "direct JSON deserialization must reject image: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("image") || err.contains("type"),
        "error should mention image or type mismatch: {err}"
    );
}

#[test]
fn direct_yaml_deserialize_rejects_null_image() {
    let yaml = r#"
id: DIRECT-NULL-IMAGE
title: direct null image
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      image: null
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let result: Result<Scenario, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "direct YAML deserialization must reject image: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("image") || err.contains("type"),
        "error should mention image or type mismatch: {err}"
    );
}

#[test]
fn direct_json_deserialize_rejects_null_simulator() {
    let json = r#"{
        "id": "DIRECT-NULL-SIMULATOR",
        "title": "direct null simulator",
        "schema_version": "0.1.0",
        "topology": {
            "nfs": {
                "amf": { "simulator": null }
            }
        },
        "steps": [
            { "kind": "send_ngap", "from": "a", "to": "b", "message": "m" }
        ]
    }"#;
    let result: Result<Scenario, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "direct JSON deserialization must reject simulator: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("simulator") || err.contains("type"),
        "error should mention simulator or type mismatch: {err}"
    );
}

#[test]
fn direct_yaml_deserialize_rejects_null_simulator() {
    let yaml = r#"
id: DIRECT-NULL-SIMULATOR
title: direct null simulator
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      simulator: null
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let result: Result<Scenario, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "direct YAML deserialization must reject simulator: null"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("simulator") || err.contains("type"),
        "error should mention simulator or type mismatch: {err}"
    );
}

#[test]
fn scenario_validate_rejects_mutation() {
    let yaml = r#"
id: VALID-MUTATION
title: will be mutated
schema_version: "0.1.0"
topology:
  nfs:
    amf:
      image: "valid-image"
steps:
  - kind: send_ngap
    from: a
    to: b
    message: m
"#;
    let mut scenario = Scenario::from_yaml(yaml).unwrap();
    scenario.validate().expect("initial scenario is valid");

    scenario.topology.nfs.get_mut("amf").unwrap().image = Some("".to_string());

    let err = scenario.validate().unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("image"),
        "expected error to mention 'image', got: {err_str}"
    );
    assert!(
        err_str.contains("string length"),
        "expected error to mention 'string length', got: {err_str}"
    );
}
