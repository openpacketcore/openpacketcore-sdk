use std::process::{Command, Stdio};

fn cli_path() -> String {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests and guarantees
    // the binary is built for this test run, regardless of target-dir
    // configuration. A hand-assembled target path can resolve to a stale
    // binary when a target-dir override is in effect.
    env!("CARGO_BIN_EXE_operator-lifecycle-cli").to_string()
}

fn run_json(subcommand: &str, input: &str) -> (String, i32) {
    let mut child = Command::new(cli_path())
        .arg(subcommand)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn CLI");

    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait on CLI");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

#[test]
fn test_version_subcommand() {
    let output = Command::new(cli_path())
        .arg("version")
        .output()
        .expect("failed to run version subcommand");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
    assert_eq!(
        parsed["crateVersion"].as_str().unwrap(),
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn test_admission_matching_contract_version() {
    let input = r#"{
        "expectedContractVersion": 1,
        "uid": "test-uid",
        "runtime_mode": "lab",
        "claims_ha": false,
        "config_backend": "consensus",
        "session_backend": "quorum",
        "admin_auth": {"token_enabled": true, "admin_token": "secure-token-value-with-long-length-12345"},
        "identity": {"kms_enabled": true, "spiffe_enabled": true}
    }"#;

    let (stdout, code) = run_json("admission", input);
    assert_eq!(code, 0, "expected exit 0, got {code}. stdout: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
    assert!(parsed["allowed"].as_bool().unwrap());
}

#[test]
fn test_admission_mismatching_contract_version() {
    let input = r#"{
        "expectedContractVersion": 999,
        "uid": "test-uid",
        "runtime_mode": "lab",
        "claims_ha": false,
        "config_backend": "consensus",
        "session_backend": "quorum",
        "admin_auth": {"token_enabled": true, "admin_token": "secure-token-value-with-long-length-12345"},
        "identity": {"kms_enabled": true, "spiffe_enabled": true}
    }"#;

    let (stdout, code) = run_json("admission", input);
    assert_eq!(code, 2, "expected exit 2, got {code}. stdout: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
    assert!(parsed["error"]
        .as_str()
        .unwrap()
        .contains("Contract version mismatch"));
}

#[test]
fn test_admission_absent_contract_version_backward_compat() {
    let input = r#"{
        "uid": "test-uid",
        "runtime_mode": "lab",
        "claims_ha": false,
        "config_backend": "consensus",
        "session_backend": "quorum",
        "admin_auth": {"token_enabled": true, "admin_token": "secure-token-value-with-long-length-12345"},
        "identity": {"kms_enabled": true, "spiffe_enabled": true}
    }"#;

    let (stdout, code) = run_json("admission", input);
    assert_eq!(code, 0, "expected exit 0, got {code}. stdout: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
    assert!(parsed["allowed"].as_bool().unwrap());
}

#[test]
fn test_config_apply_matching_contract_version() {
    let input = r#"{
        "expectedContractVersion": 1,
        "desired_generation": 2,
        "current_observed_generation": 2,
        "current_version": 1,
        "current_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        "lifecycle_status": {"phase": "Ready", "conditions": [], "observedGeneration": 2},
        "active_alarms": []
    }"#;

    let (stdout, code) = run_json("config-apply", input);
    assert_eq!(code, 0, "expected exit 0, got {code}. stdout: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
    assert_eq!(parsed["NoOp"], serde_json::Value::Null);
}

#[test]
fn test_preflight_matching_contract_version() {
    let input = r#"{
        "expectedContractVersion": 1,
        "resource_profile": {
            "nf_kind": "upf",
            "data_plane_profile": "AfXdpFastPath",
            "numa_policy": "Require",
            "generic_xdp_fallback_allowed": false,
            "isolated_cores": [2, 3],
            "require_exclusive_cores": true,
            "data_plane_interfaces": ["ens5f0"],
            "data_plane_numa_node": 0,
            "hugepage_numa_node": 0,
            "bpf_artifacts": [{
                "name": "upf-xdp-fastpath",
                "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "signature_ref": "cosign://registry.example/upf-xdp-fastpath@sha256:012345",
                "signer_identity": "spiffe://openpacketcore.test/ns/platform/sa/release-signer",
                "program_type": "xdp",
                "expected_attach_point": "ens5f0",
                "allowed_capabilities": ["CapBpf", "CapNetAdmin", "CapNetRaw"],
                "evidence_id": "platform-preflight-ev-1"
            }]
        },
        "node_capabilities": {
            "kernel": {"major": 6, "minor": 8, "patch": 0},
            "bpf": {
                "cap_bpf": true,
                "xdp_supported": true,
                "btf_available": true,
                "cap_sys_admin_required": false,
                "available_xdp_modes": ["Native"]
            },
            "cpu": {
                "manager_policy": "Static",
                "isolated_cores": [2, 3],
                "numa_nodes": 1,
                "cpu_ids": [0, 1, 2, 3],
                "reserved_cores": [0, 1],
                "topology_manager_policy": "SingleNumaNode",
                "cpu_numa_map": {"0": 0, "1": 0, "2": 0, "3": 0}
            },
            "memory": {
                "hugepages_2mi": 1024,
                "hugepages_1gi": 4,
                "hugepage_pools": [
                    {"numa_node": 0, "size": "2Mi", "total": 512, "free": 512}
                ]
            },
            "nics": [
                {"name": "ens5f0", "driver": "ice", "sriov_vfs": 4, "xdp_modes": ["Native"], "queues": 4, "numa_node": 0}
            ]
        }
    }"#;

    let (stdout, code) = run_json("preflight", input);
    assert_eq!(code, 0, "expected exit 0, got {code}. stdout: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["contractVersion"], 1);
}
