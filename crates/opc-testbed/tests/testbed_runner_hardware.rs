mod testbed_common;
use testbed_common::*;

#[test]
fn hardware_lab_runner_preflight_and_dry_run() {
    let config = HardwareLabRunnerConfig {
        node_selectors: [(
            "kubernetes.io/hostname".to_string(),
            "hw-node-1".to_string(),
        )]
        .into_iter()
        .collect(),
        nic_requirements: vec!["10G-NIC".to_string()],
        hugepages: "1Gi".to_string(),
        cpu_layout_expectations: "isolated=2-4".to_string(),
        sriov_xdp_expectations: "sriov".to_string(),
        dry_run: true,
        hardware_evidence_ids: vec!["hw-ev-123".to_string()],
    };
    let runner = HardwareLabRunner::new(config);

    let yaml = r#"
id: HW-TEST-001
title: Hardware lab dry run
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let plan = runner.generate_dry_run_plan(&scenario).unwrap();
    assert!(plan.contains("Hardware Evidence IDs:"));
    assert!(plan.contains("Provisioning hardware resources"));

    let evidence = runner.run(&scenario).unwrap();
    assert_eq!(evidence.outcome, ScenarioOutcome::Pass);
}

#[test]
fn hardware_lab_runner_redacts_plan_material() {
    let config = HardwareLabRunnerConfig {
        node_selectors: [("node".to_string(), "/Users/alice/private-node".to_string())]
            .into_iter()
            .collect(),
        nic_requirements: vec!["ens5f0".to_string()],
        hugepages: "1Gi".to_string(),
        cpu_layout_expectations: "isolated=2-4".to_string(),
        sriov_xdp_expectations: "sriov".to_string(),
        dry_run: true,
        hardware_evidence_ids: vec!["/Users/alice/hw-evidence.json".to_string()],
    };
    let runner = HardwareLabRunner::new(config);
    let yaml = r#"
id: HW-REDACT-001
title: Hardware lab plan redaction
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let plan = runner.generate_dry_run_plan(&scenario).unwrap();
    assert!(!plan.contains("/Users/alice"));
    assert!(plan.contains("REDACTED") || plan.contains("<redacted>"));
}

#[test]
fn hardware_lab_runner_sriov_requires_interface_evidence() {
    let config = HardwareLabRunnerConfig {
        node_selectors: HashMap::new(),
        nic_requirements: vec![],
        hugepages: "1Gi".to_string(),
        cpu_layout_expectations: "isolated=2-4".to_string(),
        sriov_xdp_expectations: "sriov".to_string(),
        dry_run: true,
        hardware_evidence_ids: vec!["hw-ev-123".to_string()],
    };
    let runner = HardwareLabRunner::new(config);

    let yaml = r#"
id: HW-SRIOV-NO-NIC
title: Hardware lab SR-IOV missing NIC
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    let err = runner
        .run(&scenario)
        .expect_err("SR-IOV dry-run must fail when no NIC evidence is present");
    assert!(err.to_string().contains("resource preflight failed"));
}

#[test]
fn hardware_lab_runner_rejection_on_missing_evidence() {
    let config = HardwareLabRunnerConfig {
        node_selectors: HashMap::new(),
        nic_requirements: vec![],
        hugepages: "1Gi".to_string(),
        cpu_layout_expectations: "isolated=2-4".to_string(),
        sriov_xdp_expectations: "sriov".to_string(),
        dry_run: true,
        hardware_evidence_ids: vec![], // Missing evidence!
    };
    let runner = HardwareLabRunner::new(config);

    let yaml = r#"
id: HW-TEST-001
title: Hardware lab dry run
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    assert!(
        runner.run(&scenario).is_err(),
        "Must fail closed on missing hardware evidence"
    );
}

#[test]
fn hardware_lab_runner_preflight_rejection_on_invalid_cpu() {
    let config = HardwareLabRunnerConfig {
        node_selectors: HashMap::new(),
        nic_requirements: vec![],
        hugepages: "1Gi".to_string(),
        cpu_layout_expectations: "invalid".to_string(),
        sriov_xdp_expectations: "sriov".to_string(),
        dry_run: true,
        hardware_evidence_ids: vec!["hw-ev-123".to_string()],
    };
    let runner = HardwareLabRunner::new(config);

    let yaml = r#"
id: HW-TEST-001
title: Hardware lab dry run
schema_version: "0.1.0"
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    amf: { simulator: amf }
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#;
    let scenario = Scenario::from_yaml(yaml).unwrap();
    assert!(
        runner.run(&scenario).is_err(),
        "Must fail closed when CPU layout preflight check fails"
    );
}
