use std::process::Command;

use serde_json::Value;

fn renderer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_opc-session-kubernetes-manifest"))
}

fn digest_image() -> String {
    format!(
        "registry.invalid/opc-session-quorum-node@sha256:{}",
        "a".repeat(64)
    )
}

#[test]
fn renderer_emits_strict_three_and_five_member_lists() {
    for member_count in [3, 5] {
        let output = renderer()
            .args([
                "--members",
                &member_count.to_string(),
                "--namespace",
                "session-ha-qualification",
                "--image",
                &digest_image(),
                "--trust-domain",
                "qualification.openpacketcore.invalid",
            ])
            .output()
            .expect("run manifest renderer");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let manifest: Value = serde_json::from_slice(&output.stdout).expect("Kubernetes JSON list");
        let items = manifest["items"].as_array().expect("manifest items");
        let config_map_name = items
            .iter()
            .find(|item| item["kind"] == "ConfigMap")
            .expect("configuration map")["metadata"]["name"]
            .as_str()
            .expect("content-addressed configuration map");
        assert_eq!(config_map_name.len(), "opc-session-ha-config-".len() + 64);
        assert!(config_map_name.starts_with("opc-session-ha-config-"));
        let stateful_sets = items
            .iter()
            .filter(|item| item["kind"] == "StatefulSet")
            .collect::<Vec<_>>();
        assert_eq!(stateful_sets.len(), member_count);
        for (node_index, stateful_set) in stateful_sets.into_iter().enumerate() {
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["containers"][0]["image"],
                digest_image()
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["containers"][0]["stdin"],
                true
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["readinessGates"][0]["conditionType"],
                "opc.openpacketcore.io/durable-quorum-ready"
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["volumes"][1]["configMap"]["name"],
                config_map_name
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["volumes"][2]["projected"]["sources"][0]
                    ["secret"]["name"],
                format!("opc-session-ha-node-{node_index}-svid")
            );
            assert_eq!(
                stateful_set["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"][0],
                "ReadWriteOnce"
            );
        }
    }
}

#[test]
fn renderer_fails_closed_without_echoing_rejected_inputs() {
    for rejected in [
        "registry.invalid/private/session-node:latest".to_owned(),
        format!("team/session-node@sha256:{}", "a".repeat(64)),
    ] {
        let output = renderer()
            .args([
                "--members",
                "3",
                "--namespace",
                "session-ha-qualification",
                "--image",
                &rejected,
                "--trust-domain",
                "qualification.openpacketcore.invalid",
            ])
            .output()
            .expect("run manifest renderer");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert_eq!(
            stderr,
            "qualification Kubernetes manifest rendering failed\n"
        );
        assert!(!stderr.contains(&rejected));
    }
}
