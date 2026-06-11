mod testbed_common;
use testbed_common::*;

#[test]
fn kind_runner_manifests_generation_and_dry_run() {
    let config = KindRunnerConfig {
        namespace: "openpacketcore".to_string(),
        service_account: "opc-sa".to_string(),
        image_pull_policy: "IfNotPresent".to_string(),
        dry_run: true,
    };
    let runner = KindRunner::new(config);

    let yaml = r#"
id: KIND-TEST-001
title: Kind dry run
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
    let manifests = runner.generate_manifests(&scenario).unwrap();
    assert!(manifests.contains("namespace: openpacketcore"));
    assert!(manifests.contains("serviceAccountName: opc-sa"));
    assert!(manifests.contains("image: opc-amf:latest"));

    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Pass);
}

#[test]
fn kind_runner_live_execution_is_skipped_not_passed() {
    let config = KindRunnerConfig {
        namespace: "openpacketcore".to_string(),
        service_account: "opc-sa".to_string(),
        image_pull_policy: "IfNotPresent".to_string(),
        dry_run: false,
    };
    let runner = KindRunner::new(config);
    let yaml = r#"
id: KIND-LIVE-001
title: Kind live boundary
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
    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Skipped);
    assert!(evidence
        .failure_summary
        .as_deref()
        .unwrap_or_default()
        .contains("live kind execution"));
}

#[test]
fn kind_runner_validation_failures_fail_closed() {
    let config = KindRunnerConfig {
        namespace: "".to_string(), // invalid namespace
        service_account: "opc-sa".to_string(),
        image_pull_policy: "IfNotPresent".to_string(),
        dry_run: true,
    };
    let runner = KindRunner::new(config);
    let yaml = r#"
id: KIND-TEST-001
title: Kind dry run
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
    assert!(runner.run(&scenario).is_err());
}
