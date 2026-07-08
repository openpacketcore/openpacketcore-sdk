mod testbed_common;
use testbed_common::*;

#[test]
fn scenario_evidence_pass_emits_rfc006_records() {
    let mut ev = ScenarioEvidence::new("AMF-REG-001", ScenarioOutcome::Pass);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-001".into()];
    ev.seed = Some(1234);
    ev.mode = Some("in-process".into());
    ev.artifacts = vec!["trace.json".into(), "metrics.prom".into()];

    let records = ev
        .to_evidence_records()
        .expect("evidence generation succeeds");
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.status, ConformanceStatus::Tested);
    assert_eq!(
        rec.test_refs,
        vec![
            "crates/opc-testbed/scenario/AMF-REG-001:run",
            "trace.json",
            "metrics.prom"
        ]
    );
    assert!(rec.artifact_digests.is_empty());
}

#[test]
fn scenario_evidence_fail_emits_partial_status() {
    let mut ev = ScenarioEvidence::new("AMF-REG-002", ScenarioOutcome::Fail);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-002".into()];

    let records = ev
        .to_evidence_records()
        .expect("evidence generation succeeds");
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.status, ConformanceStatus::Partial);
}

#[test]
fn scenario_evidence_skipped_emits_gap_status() {
    let mut ev = ScenarioEvidence::new("AMF-REG-003", ScenarioOutcome::Skipped);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-003".into()];

    let records = ev
        .to_evidence_records()
        .expect("evidence generation succeeds");
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.status, ConformanceStatus::Gap);
}

#[test]
fn scenario_evidence_error_emits_gap_status() {
    let mut ev = ScenarioEvidence::new("AMF-REG-004", ScenarioOutcome::Error);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-004".into()];

    let records = ev
        .to_evidence_records()
        .expect("evidence generation succeeds");
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.status, ConformanceStatus::Gap);
}

#[test]
fn scenario_evidence_fail_closed_on_bad_requirement_id() {
    let mut ev = ScenarioEvidence::new("BAD-REQ", ScenarioOutcome::Pass);
    ev.requirements = vec!["NOT-A-VALID-REQ-ID".into()];

    let err = ev
        .to_evidence_records()
        .expect_err("bad requirement id must fail");
    assert!(err.to_string().contains("malformed requirement id"));
    assert!(err.to_string().contains("NOT-A-VALID-REQ-ID"));
}

#[test]
fn scenario_evidence_fail_closed_on_empty_requirements() {
    let ev = ScenarioEvidence::new("NO-REQS", ScenarioOutcome::Pass);

    let err = ev
        .to_evidence_records()
        .expect_err("empty requirements must fail");
    assert!(err.to_string().contains("no linked requirements"));
    assert!(err.to_string().contains("NO-REQS"));
}

#[test]
fn scenario_evidence_fail_closed_on_all_blank_requirements() {
    let mut ev = ScenarioEvidence::new("BLANK-REQS", ScenarioOutcome::Pass);
    ev.requirements = vec!["   ".into(), "".into()];

    let err = ev
        .to_evidence_records()
        .expect_err("blank requirements must fail");
    assert!(err.to_string().contains("no linked requirements"));
}

#[test]
fn scenario_evidence_fail_closed_on_mixed_blank_requirements() {
    let mut ev = ScenarioEvidence::new("MIXED-BLANK", ScenarioOutcome::Pass);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-001".into(), "  ".into()];

    let err = ev
        .to_evidence_records()
        .expect_err("mixed blank requirements must fail");
    assert!(err.to_string().contains("no linked requirements"));
}

#[test]
fn scenario_evidence_json_roundtrip() {
    let mut ev = ScenarioEvidence::new("TEST-EV-001", ScenarioOutcome::Pass);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-001".into()];
    ev.mode = Some("in-process".into());
    ev.seed = Some(42);
    ev.artifacts = vec!["trace.json".into()];

    let json = serde_json::to_string(&ev).expect("serialize evidence");
    let back: ScenarioEvidence = serde_json::from_str(&json).expect("deserialize evidence");
    assert_eq!(back.scenario_id, ev.scenario_id);
    assert_eq!(back.outcome, ev.outcome);
    assert_eq!(back.seed, ev.seed);
    assert_eq!(back.mode, ev.mode);
}

#[test]
fn local_runner_executes_scenario_successfully() {
    let yaml = r#"
id: LOCAL-TEST-001
title: Local execution success
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - clock_jump:
      duration_ms: 1000
  - send_ngap:
      from: gnb
      to: amf
      message: registration
assertions:
  - amf.state == REGISTERED
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);
    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Pass);
    assert_eq!(
        runner.state.get("amf.state").map(|s| s.as_str()),
        Some("REGISTERED")
    );
}

#[test]
fn local_runner_rejects_unregistered_protocol_fixture() {
    let yaml = r#"
id: LOCAL-FIXTURE-MISSING
title: Missing fixture provenance fails closed
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    epdg: { image: opc-epdg:test }
    pgw: { image: opc-pgw:test }
steps:
  - kind: send_gtpv2c
    from: epdg
    to: pgw
    fixture: fixtures/s2b/create-session-request.bin
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);

    let err = runner
        .run(&scenario)
        .expect_err("missing fixture provenance must fail closed");
    assert!(matches!(err, TestbedError::Fixture(_)));
    assert!(err.to_string().contains("not registered"));
}

#[test]
fn local_runner_records_registered_fixture_provenance() {
    let yaml = r#"
id: LOCAL-FIXTURE-RECORDED
title: Fixture provenance is emitted
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    epdg: { image: opc-epdg:test }
    pgw: { image: opc-pgw:test }
steps:
  - kind: send_gtpv2c
    from: epdg
    to: pgw
    fixture: fixtures/s2b/create-session-request.bin
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let mut registry = FixtureRegistry::default();
    registry
        .register(FixtureProvenance {
            id: "fixtures/s2b/create-session-request.bin".into(),
            source: "synthetic-generator".into(),
            standard_ref: "3GPP TS 29.274".into(),
            release: "R17".into(),
            synthetic: true,
            sanitization: "none".into(),
            expected_decode: "DecodeSuccess(CreateSessionRequest)".into(),
            requirements: vec!["REQ-3GPP-TS23502-R17-4.2.2-001".into()],
            notes: None,
        })
        .unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock).with_fixture_registry(registry);

    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Pass);
    assert_eq!(evidence.fixture_provenance.len(), 1);
    assert_eq!(
        evidence.fixture_provenance[0].id,
        "fixtures/s2b/create-session-request.bin"
    );
}

#[test]
fn local_runner_rejects_missing_simulator_endpoint() {
    let yaml = r#"
id: LOCAL-MISSING-SIM
title: Missing simulator fails closed
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { image: opc-amf:latest }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);
    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Fail);
    assert!(evidence
        .failure_summary
        .as_deref()
        .unwrap_or_default()
        .contains("unknown or non-simulated endpoint"));
}

#[test]
fn local_runner_records_failure_injection_steps() {
    let yaml = r#"
id: LOCAL-CHAOS-001
title: Local failure controls
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
    smf: { simulator: smf }
steps:
  - delayed_response:
      target: amf
      delay_ms: 25
  - malformed_response:
      target: amf
  - network_partition:
      node_a: amf
      node_b: smf
assertions:
  - amf.delayed_response_ms == 25
  - amf.malformed_response == true
  - amf.partitioned_from.smf == true
  - smf.partitioned_from.amf == true
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);
    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Pass);
}

#[test]
fn local_runner_epc_malformed_response_updates_simulator_state() {
    let yaml = r#"
id: LOCAL-EPC-MALFORMED-001
title: EPC malformed response updates simulator state
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    pgw: { simulator: pgw-s2b }
steps:
  - malformed_response:
      target: pgw
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let clock = VirtualClock::new(Timestamp::now_utc());
    let mut runner = LocalRunner::new(clock);
    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Fail);
    assert_eq!(
        runner.state.get("pgw.state").map(|s| s.as_str()),
        Some("MALFORMED_REJECTED")
    );
}

#[test]
fn scenario_evidence_redacts_failure_summary() {
    let mut ev = ScenarioEvidence::new("AMF-REG-001", ScenarioOutcome::Fail);
    ev.requirements = vec!["REQ-3GPP-TS23502-R17-4.2.2-001".into()];

    let raw_msg = "Failed with SUPI imsi-123456789012345 and spiffe://test/trust-domain/instance/1 and token jwt.secret.token";
    ev.set_failure_summary(raw_msg);

    let summary = ev.failure_summary.unwrap();
    assert!(!summary.contains("123456789012345"));
    assert!(!summary.contains("jwt.secret.token"));
    assert!(
        summary.contains("[REDACTED_SUPI]")
            || summary.contains("[REDACTED_")
            || summary.contains("[REDACTED_LINE_CONTAINING_SECRET]")
    );
}
