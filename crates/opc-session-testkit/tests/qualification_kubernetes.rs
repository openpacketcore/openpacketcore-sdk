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
            let container = &stateful_set["spec"]["template"]["spec"]["containers"][0];
            assert_eq!(container["image"], digest_image());
            assert_eq!(
                container["args"],
                serde_json::json!([
                    "--config",
                    "/etc/opc-session/config/node.json",
                    "--node-index",
                    node_index.to_string(),
                    "--bind-addr",
                    "0.0.0.0:7443",
                    "--control-socket",
                    "/var/lib/opc-session-qualification/control/node.sock",
                ])
            );
            for removed in ["stdin", "stdinOnce", "tty"] {
                assert!(container.get(removed).is_none());
            }
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["readinessGates"][0]["conditionType"],
                "opc.openpacketcore.io/durable-quorum-ready"
            );
            let volumes = stateful_set["spec"]["template"]["spec"]["volumes"]
                .as_array()
                .expect("pod volumes");
            let volume = |name: &str| {
                volumes
                    .iter()
                    .find(|volume| volume["name"] == name)
                    .expect("named pod volume")
            };
            assert_eq!(volume("config")["configMap"]["name"], config_map_name);
            assert_eq!(
                volume("identity")["projected"]["sources"][0]["secret"]["name"],
                format!("opc-session-ha-node-{node_index}-svid")
            );
            assert_eq!(volume("workspace")["emptyDir"], serde_json::json!({}));
            assert!(volumes.iter().all(|volume| volume["name"] != "control"));
            assert!(container["volumeMounts"].as_array().is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    mount["name"] == "workspace"
                        && mount["mountPath"] == "/var/lib/opc-session-qualification"
                }) && mounts
                    .iter()
                    .all(|mount| mount["mountPath"] != "/var/lib/opc-session-qualification/control")
            }));
            assert!(container["ports"]
                .as_array()
                .is_some_and(|ports| { ports.len() == 1 && ports[0]["name"] == "consensus-mtls" }));
            assert_eq!(
                stateful_set["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"][0],
                "ReadWriteOnce"
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["automountServiceAccountToken"],
                false
            );
            assert_eq!(
                stateful_set["spec"]["template"]["spec"]["nodeSelector"],
                serde_json::json!({"kubernetes.io/os": "linux"})
            );
        }
        assert!(items.iter().all(|item| !matches!(
            item["kind"].as_str(),
            Some("Role" | "RoleBinding" | "ClusterRole" | "ClusterRoleBinding")
        )));
        let service_accounts = items
            .iter()
            .filter(|item| item["kind"] == "ServiceAccount")
            .collect::<Vec<_>>();
        assert_eq!(service_accounts.len(), 1);
        assert_eq!(service_accounts[0]["automountServiceAccountToken"], false);
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
