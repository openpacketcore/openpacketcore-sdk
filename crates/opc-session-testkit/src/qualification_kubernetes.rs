//! Deterministic Kubernetes manifest foundation for session-HA qualification.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use opc_session_net::{
    DEFAULT_MAX_AUTHENTICATION_AGE, DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN,
    DEFAULT_ROTATION_DRAIN_WINDOW, DEFAULT_ROTATION_JITTER,
};
use opc_session_store::ReplicaEndpoint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::qualification::{
    qualification_traffic_schedule_sha256, QualificationConnectionLifecycleConfig,
    QualificationMember, QualificationNodeConfig, QualificationPeerRouting,
    QualificationProjectedMtlsConfig, QualificationTransportConfig,
    QUALIFICATION_NODE_SCHEMA_VERSION, QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
};

const FLEET_NAME: &str = "opc-session-ha";
const PEER_SERVICE_NAME: &str = "opc-session-ha-peer";
const CONFIG_MAP_NAME_PREFIX: &str = "opc-session-ha-config";
const SERVICE_ACCOUNT_NAME: &str = "opc-session-ha";
const CONSENSUS_PORT: u16 = 7443;
const WORKSPACE_DIRECTORY: &str = "/var/lib/opc-session-qualification";
const DATABASE_PATH: &str = "/var/lib/opc-session-qualification/state/session.sqlite";
const SNAPSHOT_DIRECTORY: &str = "/var/lib/opc-session-qualification/state/snapshots";
const PROJECTED_IDENTITY_ROOT: &str = "/var/lib/opc-session-qualification/identity";

/// Fixed-input request for one deterministic Kubernetes fleet manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationKubernetesManifestConfig {
    /// Exact supported voter count.
    pub member_count: usize,
    /// Kubernetes namespace embedded in every canonical peer FQDN.
    pub namespace: String,
    /// Exact immutable release image reference, including a SHA-256 digest.
    pub image: String,
    /// Canonical SPIFFE trust domain used by the pre-provisioned SVID Secrets.
    pub trust_domain: String,
}

/// Redaction-safe manifest input or rendering failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesManifestError {
    /// Only the production-profile three- and five-member topologies exist.
    #[error("qualification Kubernetes topology is invalid")]
    InvalidTopology,
    /// Namespace is not one canonical Kubernetes DNS label.
    #[error("qualification Kubernetes namespace is invalid")]
    InvalidNamespace,
    /// Image is not pinned to one lower-case SHA-256 digest.
    #[error("qualification Kubernetes image is invalid")]
    InvalidImage,
    /// Trust domain is not one canonical DNS name.
    #[error("qualification Kubernetes trust domain is invalid")]
    InvalidTrustDomain,
    /// An internally rendered node configuration failed strict validation.
    #[error("qualification Kubernetes node configuration is invalid")]
    InvalidNodeConfiguration,
}

impl QualificationKubernetesManifestConfig {
    /// Validate every operator-controlled manifest input.
    pub fn validate(&self) -> Result<(), QualificationKubernetesManifestError> {
        if !matches!(self.member_count, 3 | 5) {
            return Err(QualificationKubernetesManifestError::InvalidTopology);
        }
        if !is_kubernetes_dns_label(&self.namespace) {
            return Err(QualificationKubernetesManifestError::InvalidNamespace);
        }
        if !is_digest_pinned_image(&self.image) {
            return Err(QualificationKubernetesManifestError::InvalidImage);
        }
        let endpoint = ReplicaEndpoint::new(self.trust_domain.clone(), 1)
            .map_err(|_| QualificationKubernetesManifestError::InvalidTrustDomain)?;
        if endpoint.host() != self.trust_domain
            || !self.trust_domain.contains('.')
            || self.trust_domain.parse::<IpAddr>().is_ok()
            || self.trust_domain.ends_with(".localhost")
        {
            return Err(QualificationKubernetesManifestError::InvalidTrustDomain);
        }
        Ok(())
    }
}

/// Render one Kubernetes `List` with exact 3/5-node identity, storage, and
/// projected-Secret wiring.
///
/// The result remains an experimental campaign foundation. It deliberately
/// contains Secret references but no private key or certificate material.
pub fn render_qualification_kubernetes_manifest(
    config: &QualificationKubernetesManifestConfig,
) -> Result<Value, QualificationKubernetesManifestError> {
    config.validate()?;
    let members = qualification_members(config);
    let release_generation = format!(
        "release-sha256-{}",
        config
            .image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .ok_or(QualificationKubernetesManifestError::InvalidImage)?
    );
    let mut node_configs = BTreeMap::new();
    let mut items = vec![
        service_account(config),
        peer_service(config),
        network_policy(config),
        disruption_budget(config),
    ];

    for node_index in 0..config.member_count {
        let node_config = QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index,
            cluster_id: format!("{FLEET_NAME}-release-qualification"),
            configuration_generation: release_generation.clone(),
            configuration_epoch: 1,
            backend_namespace: format!("{FLEET_NAME}-release-qualification"),
            workload_schedule_sha256: qualification_traffic_schedule_sha256(config.member_count)
                .ok_or(QualificationKubernetesManifestError::InvalidTopology)?,
            members: members.clone(),
            workspace_directory: PathBuf::from(WORKSPACE_DIRECTORY),
            database_path: PathBuf::from(DATABASE_PATH),
            snapshot_directory: PathBuf::from(SNAPSHOT_DIRECTORY),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::ProjectedMtls(
                QualificationProjectedMtlsConfig {
                    projected_volume_root: PathBuf::from(PROJECTED_IDENTITY_ROOT),
                    certificate_file: PathBuf::from("tls.crt"),
                    private_key_file: PathBuf::from("tls.key"),
                    trust_bundle_files: vec![PathBuf::from("ca.crt")],
                    poll_interval_millis: 1_000,
                    lifecycle: production_lifecycle()?,
                    peer_routing: QualificationPeerRouting::CanonicalEndpointDns,
                },
            ),
        };
        node_config
            .validate()
            .map_err(|_| QualificationKubernetesManifestError::InvalidNodeConfiguration)?;
        let encoded = serde_json::to_string_pretty(&node_config)
            .map_err(|_| QualificationKubernetesManifestError::InvalidNodeConfiguration)?;
        node_configs.insert(format!("node-{node_index}.json"), encoded);
    }

    let config_map_name = content_addressed_config_map_name(&node_configs)?;
    items.push(json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": object_metadata(&config_map_name, config),
        "immutable": true,
        "data": node_configs,
    }));
    for node_index in 0..config.member_count {
        items.push(member_stateful_set(config, node_index, &config_map_name));
    }

    Ok(json!({
        "apiVersion": "v1",
        "kind": "List",
        "metadata": {
            "annotations": qualification_annotations(),
        },
        "items": items,
    }))
}

fn content_addressed_config_map_name(
    node_configs: &BTreeMap<String, String>,
) -> Result<String, QualificationKubernetesManifestError> {
    let encoded = serde_json::to_vec(node_configs)
        .map_err(|_| QualificationKubernetesManifestError::InvalidNodeConfiguration)?;
    let digest = Sha256::digest(encoded);
    Ok(format!("{CONFIG_MAP_NAME_PREFIX}-{digest:x}"))
}

fn production_lifecycle(
) -> Result<QualificationConnectionLifecycleConfig, QualificationKubernetesManifestError> {
    Ok(QualificationConnectionLifecycleConfig {
        maximum_authentication_age_millis: duration_millis(DEFAULT_MAX_AUTHENTICATION_AGE)?,
        rotation_drain_window_millis: duration_millis(DEFAULT_ROTATION_DRAIN_WINDOW)?,
        reconnect_backoff_min_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MIN)?,
        reconnect_backoff_max_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MAX)?,
        rotation_jitter_millis: duration_millis(DEFAULT_ROTATION_JITTER)?,
    })
}

fn duration_millis(duration: Duration) -> Result<u64, QualificationKubernetesManifestError> {
    u64::try_from(duration.as_millis())
        .map_err(|_| QualificationKubernetesManifestError::InvalidNodeConfiguration)
}

fn qualification_members(
    config: &QualificationKubernetesManifestConfig,
) -> Vec<QualificationMember> {
    (0..config.member_count)
        .map(|node_index| QualificationMember {
            node_index,
            replica_id: format!("node-{node_index}"),
            endpoint_host: member_fqdn(config, node_index),
            endpoint_port: CONSENSUS_PORT,
            dial_addr: None,
            tls_identity: format!(
                "spiffe://{}/tenant/session-ha/ns/{}/sa/{}/nf/qualification/instance/node-{node_index}",
                config.trust_domain, config.namespace, SERVICE_ACCOUNT_NAME
            ),
            // The scheduler enforces distinct hosts. A real campaign must bind
            // these slots to collected node/failure-domain evidence.
            failure_domain: format!("required-kubernetes-host-slot-{node_index}"),
            backing_identity: format!("state-{FLEET_NAME}-{node_index}-0"),
        })
        .collect()
}

fn member_fqdn(config: &QualificationKubernetesManifestConfig, node_index: usize) -> String {
    format!(
        "{FLEET_NAME}-{node_index}-0.{PEER_SERVICE_NAME}.{}.svc.cluster.local",
        config.namespace
    )
}

fn common_labels() -> Value {
    json!({
        "app.kubernetes.io/name": "opc-session-ha-qualification",
        "app.kubernetes.io/component": "session-quorum",
        "opc.openpacketcore.io/session-ha-fleet": "release-qualification",
    })
}

fn member_labels(node_index: usize) -> Value {
    let mut labels = common_labels().as_object().cloned().unwrap_or_default();
    labels.insert(
        "opc.openpacketcore.io/session-ha-member".to_owned(),
        Value::String(format!("node-{node_index}")),
    );
    Value::Object(labels)
}

fn qualification_annotations() -> Value {
    json!({
        "opc.openpacketcore.io/qualification-status": "experimental",
        "opc.openpacketcore.io/production-evidence": "false",
    })
}

fn object_metadata(name: &str, config: &QualificationKubernetesManifestConfig) -> Value {
    json!({
        "name": name,
        "namespace": config.namespace,
        "labels": common_labels(),
        "annotations": qualification_annotations(),
    })
}

fn service_account(config: &QualificationKubernetesManifestConfig) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": object_metadata(SERVICE_ACCOUNT_NAME, config),
        "automountServiceAccountToken": false,
    })
}

fn peer_service(config: &QualificationKubernetesManifestConfig) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": object_metadata(PEER_SERVICE_NAME, config),
        "spec": {
            "clusterIP": "None",
            "ipFamilyPolicy": "SingleStack",
            "ipFamilies": ["IPv4"],
            "publishNotReadyAddresses": true,
            "selector": common_labels(),
            "ports": [{
                "name": "consensus-mtls",
                "port": CONSENSUS_PORT,
                "protocol": "TCP",
                "targetPort": "consensus-mtls",
            }],
        },
    })
}

fn network_policy(config: &QualificationKubernetesManifestConfig) -> Value {
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": object_metadata("opc-session-ha-peer-only", config),
        "spec": {
            "podSelector": { "matchLabels": common_labels() },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{ "podSelector": { "matchLabels": common_labels() } }],
                "ports": [{ "port": CONSENSUS_PORT, "protocol": "TCP" }],
            }],
            "egress": [
                {
                    "to": [{ "podSelector": { "matchLabels": common_labels() } }],
                    "ports": [{ "port": CONSENSUS_PORT, "protocol": "TCP" }],
                },
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": { "kubernetes.io/metadata.name": "kube-system" },
                        },
                        "podSelector": {
                            "matchLabels": { "k8s-app": "kube-dns" },
                        },
                    }],
                    "ports": [
                        { "port": 53, "protocol": "UDP" },
                        { "port": 53, "protocol": "TCP" },
                    ],
                },
            ],
        },
    })
}

fn disruption_budget(config: &QualificationKubernetesManifestConfig) -> Value {
    json!({
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": object_metadata("opc-session-ha", config),
        "spec": {
            "maxUnavailable": 1,
            "selector": { "matchLabels": common_labels() },
        },
    })
}

fn member_stateful_set(
    config: &QualificationKubernetesManifestConfig,
    node_index: usize,
    config_map_name: &str,
) -> Value {
    let name = format!("{FLEET_NAME}-{node_index}");
    let labels = member_labels(node_index);
    let secret_name = format!("{FLEET_NAME}-node-{node_index}-svid");
    let config_key = format!("node-{node_index}.json");
    json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": object_metadata(&name, config),
        "spec": {
            "replicas": 1,
            "serviceName": PEER_SERVICE_NAME,
            "podManagementPolicy": "Parallel",
            "updateStrategy": { "type": "OnDelete" },
            "persistentVolumeClaimRetentionPolicy": {
                "whenDeleted": "Retain",
                "whenScaled": "Retain",
            },
            "selector": { "matchLabels": labels },
            "template": {
                "metadata": {
                    "labels": labels,
                    "annotations": qualification_annotations(),
                },
                "spec": {
                    "serviceAccountName": SERVICE_ACCOUNT_NAME,
                    "automountServiceAccountToken": false,
                    "readinessGates": [{
                        "conditionType": "opc.openpacketcore.io/durable-quorum-ready",
                    }],
                    "terminationGracePeriodSeconds": 90,
                    "securityContext": {
                        "runAsNonRoot": true,
                        "fsGroup": 65532,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": { "type": "RuntimeDefault" },
                    },
                    "affinity": {
                        "podAntiAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": [{
                                "labelSelector": { "matchLabels": common_labels() },
                                "topologyKey": "kubernetes.io/hostname",
                            }],
                        },
                    },
                    "containers": [{
                        "name": "session-quorum",
                        "image": config.image,
                        "imagePullPolicy": "IfNotPresent",
                        "args": [
                            "--config",
                            "/etc/opc-session/config/node.json",
                            "--node-index",
                            node_index.to_string(),
                            "--bind-addr",
                            format!("0.0.0.0:{CONSENSUS_PORT}"),
                        ],
                        "stdin": true,
                        "stdinOnce": false,
                        "tty": false,
                        "ports": [{
                            "name": "consensus-mtls",
                            "containerPort": CONSENSUS_PORT,
                            "protocol": "TCP",
                        }],
                        "securityContext": {
                            "allowPrivilegeEscalation": false,
                            "readOnlyRootFilesystem": true,
                            "runAsNonRoot": true,
                            "runAsUser": 65532,
                            "runAsGroup": 65532,
                            "capabilities": { "drop": ["ALL"] },
                        },
                        "resources": {
                            "requests": { "cpu": "250m", "memory": "256Mi" },
                            "limits": { "cpu": "2", "memory": "1Gi" },
                        },
                        "volumeMounts": [
                            { "name": "workspace", "mountPath": WORKSPACE_DIRECTORY },
                            { "name": "state", "mountPath": format!("{WORKSPACE_DIRECTORY}/state") },
                            { "name": "identity", "mountPath": PROJECTED_IDENTITY_ROOT, "readOnly": true },
                            { "name": "config", "mountPath": "/etc/opc-session/config", "readOnly": true },
                        ],
                    }],
                    "volumes": [
                        { "name": "workspace", "emptyDir": {} },
                        {
                            "name": "config",
                            "configMap": {
                                "name": config_map_name,
                                "defaultMode": 288,
                                "items": [{ "key": config_key, "path": "node.json", "mode": 288 }],
                            },
                        },
                        {
                            "name": "identity",
                            "projected": {
                                "defaultMode": 288,
                                "sources": [{
                                    "secret": {
                                        "name": secret_name,
                                        "items": [
                                            { "key": "tls.crt", "path": "tls.crt", "mode": 288 },
                                            { "key": "tls.key", "path": "tls.key", "mode": 288 },
                                            { "key": "ca.crt", "path": "ca.crt", "mode": 288 },
                                        ],
                                    },
                                }],
                            },
                        },
                    ],
                },
            },
            "volumeClaimTemplates": [{
                "metadata": { "name": "state", "labels": labels },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "volumeMode": "Filesystem",
                    "resources": { "requests": { "storage": "10Gi" } },
                },
            }],
        },
    })
}

fn is_kubernetes_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn is_digest_pinned_image(value: &str) -> bool {
    let Some((repository, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    is_qualification_oci_repository(repository)
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_qualification_oci_repository(value: &str) -> bool {
    // Qualification deliberately requires an explicit lower-case registry so
    // no runtime-specific default registry or namespace can change the image.
    const OCI_NAME_MAX_BYTES: usize = 255;

    if value.is_empty() || value.len() > OCI_NAME_MAX_BYTES || value.contains('@') {
        return false;
    }
    let Some((registry, path)) = value.split_once('/') else {
        return false;
    };
    is_qualification_oci_registry(registry)
        && !path.is_empty()
        && path.split('/').all(is_oci_repository_component)
}

fn is_qualification_oci_registry(value: &str) -> bool {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if host.is_empty()
        || host.len() > 253
        || host.contains(':')
        || !host.split('.').all(is_kubernetes_dns_label)
    {
        return false;
    }
    let is_explicit_registry = host == "localhost" || host.contains('.') || port.is_some();
    is_explicit_registry
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        })
}

fn is_oci_repository_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    if !bytes
        .first()
        .copied()
        .is_some_and(is_oci_lower_alphanumeric)
    {
        return false;
    }
    while index < bytes.len() {
        while bytes
            .get(index)
            .copied()
            .is_some_and(is_oci_lower_alphanumeric)
        {
            index += 1;
        }
        if index == bytes.len() {
            return true;
        }
        match bytes[index] {
            b'.' => index += 1,
            b'_' => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                }
            }
            b'-' => {
                while bytes.get(index) == Some(&b'-') {
                    index += 1;
                }
            }
            _ => return false,
        }
        if !bytes
            .get(index)
            .copied()
            .is_some_and(is_oci_lower_alphanumeric)
        {
            return false;
        }
    }
    false
}

fn is_oci_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(member_count: usize) -> QualificationKubernetesManifestConfig {
        QualificationKubernetesManifestConfig {
            member_count,
            namespace: "session-ha-qualification".to_owned(),
            image: format!(
                "registry.invalid/opc-session-quorum-node@sha256:{}",
                "a".repeat(64)
            ),
            trust_domain: "qualification.openpacketcore.invalid".to_owned(),
        }
    }

    #[test]
    fn render_is_exact_for_three_and_five_member_fleets() {
        for member_count in [3, 5] {
            let manifest = render_qualification_kubernetes_manifest(&config(member_count))
                .expect("render manifest");
            assert_eq!(
                manifest,
                render_qualification_kubernetes_manifest(&config(member_count))
                    .expect("repeat deterministic render")
            );
            assert_eq!(manifest["kind"], "List");
            assert_eq!(
                manifest["metadata"]["annotations"]["opc.openpacketcore.io/qualification-status"],
                "experimental"
            );
            let items = manifest["items"].as_array().expect("manifest items");
            assert_eq!(items.len(), member_count + 5);
            assert_eq!(
                items
                    .iter()
                    .filter(|item| item["kind"] == "StatefulSet")
                    .count(),
                member_count
            );
            assert!(!items.iter().any(|item| item["kind"] == "Secret"));

            let config_map = items
                .iter()
                .find(|item| item["kind"] == "ConfigMap")
                .expect("configuration map");
            let config_map_name = config_map["metadata"]["name"]
                .as_str()
                .expect("content-addressed configuration map");
            let config_digest = config_map_name
                .strip_prefix(&format!("{CONFIG_MAP_NAME_PREFIX}-"))
                .expect("configuration map prefix");
            assert_eq!(config_digest.len(), 64);
            assert!(config_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            let data = config_map["data"].as_object().expect("node configs");
            assert_eq!(data.len(), member_count);
            for node_index in 0..member_count {
                let encoded = data[&format!("node-{node_index}.json")]
                    .as_str()
                    .expect("encoded node config");
                let node: QualificationNodeConfig =
                    serde_json::from_str(encoded).expect("strict node config");
                assert_eq!(node.schema_version, 3);
                assert_eq!(node.node_index, node_index);
                assert_eq!(
                    node.configuration_generation,
                    format!("release-sha256-{}", "a".repeat(64))
                );
                assert!(node.members.iter().all(|member| member.dial_addr.is_none()));
                assert!(node.members.iter().all(|member| member
                    .endpoint_host
                    .ends_with(".opc-session-ha-peer.session-ha-qualification.svc.cluster.local")));
                assert_eq!(node.validate(), Ok(()));
                assert_eq!(
                    node.members[node_index].backing_identity,
                    format!("state-opc-session-ha-{node_index}-0")
                );
                assert_eq!(
                    node.validate_bind_addr(
                        "0.0.0.0:7443".parse().expect("deployed wildcard listener")
                    ),
                    Ok(())
                );
            }
            assert!(items
                .iter()
                .filter(|item| item["kind"] == "StatefulSet")
                .all(
                    |item| item["spec"]["template"]["spec"]["volumes"][1]["configMap"]["name"]
                        == config_map_name
                ));
        }
    }

    #[test]
    fn immutable_config_map_name_tracks_complete_node_data() {
        let initial = render_qualification_kubernetes_manifest(&config(3)).expect("initial render");
        let mut changed_config = config(3);
        changed_config.trust_domain = "rotated.openpacketcore.invalid".to_owned();
        let changed =
            render_qualification_kubernetes_manifest(&changed_config).expect("changed render");

        let config_map_name = |manifest: &Value| {
            manifest["items"]
                .as_array()
                .expect("manifest items")
                .iter()
                .find(|item| item["kind"] == "ConfigMap")
                .expect("configuration map")["metadata"]["name"]
                .as_str()
                .expect("configuration map name")
                .to_owned()
        };
        assert_ne!(config_map_name(&initial), config_map_name(&changed));
    }

    #[test]
    fn dns_egress_is_scoped_to_the_declared_cluster_resolver() {
        let manifest = render_qualification_kubernetes_manifest(&config(3)).expect("render");
        let policy = manifest["items"]
            .as_array()
            .expect("manifest items")
            .iter()
            .find(|item| item["kind"] == "NetworkPolicy")
            .expect("network policy");
        let egress = policy["spec"]["egress"].as_array().expect("egress rules");
        let dns_rule = egress
            .iter()
            .find(|rule| {
                rule["ports"].as_array().is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|port| port["port"] == 53 && port["protocol"] == "UDP")
                })
            })
            .expect("DNS rule");
        for protocol in ["TCP", "UDP"] {
            assert!(dns_rule["ports"].as_array().is_some_and(|ports| {
                ports
                    .iter()
                    .any(|port| port["port"] == 53 && port["protocol"] == protocol)
            }));
        }
        assert_eq!(dns_rule["to"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            dns_rule["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "kube-system"
        );
        assert_eq!(
            dns_rule["to"][0]["podSelector"]["matchLabels"]["k8s-app"],
            "kube-dns"
        );
        assert!(egress.iter().all(|rule| {
            let admits_dns = rule["ports"]
                .as_array()
                .is_some_and(|ports| ports.iter().any(|port| port["port"] == 53));
            !admits_dns || rule["to"].as_array().is_some_and(|peers| !peers.is_empty())
        }));
    }

    #[test]
    fn image_validation_enforces_the_qualification_oci_subset() {
        let digest = "a".repeat(64);
        for repository in [
            "registry.invalid/session-node",
            "registry:5000/team/session-node",
            "localhost/session-node",
            "localhost:5000/team/session-node",
            "127.0.0.1:5000/team/session-node",
            "registry.invalid:5000/team/session_node",
            "registry.invalid/team/session__node",
            "registry.invalid/team/session---node",
        ] {
            assert!(is_digest_pinned_image(&format!(
                "{repository}@sha256:{digest}"
            )));
        }

        for repository in [
            "session-node",
            "team/session-node",
            "registry/session-node",
            "registry_invalid/session-node",
            "registry.invalid:port/session-node",
            "registry.invalid:0/session-node",
            "registry.invalid:70000/session-node",
            "registry.invalid/session-node:release",
            "registry.invalid/team/Session-node",
            "registry.invalid/team//session-node",
            "registry.invalid/team/.session-node",
            "registry.invalid/team/session-node.",
            "registry.invalid/team/session..node",
            "registry.invalid/team/session___node",
        ] {
            assert!(!is_digest_pinned_image(&format!(
                "{repository}@sha256:{digest}"
            )));
        }
    }

    #[test]
    fn render_rejects_mutable_or_aliased_operator_inputs() {
        let mut candidate = config(3);
        candidate.image = "registry.invalid/opc-session-quorum-node:latest".to_owned();
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidImage)
        );
        candidate = config(3);
        candidate.image = format!("team/session-node@sha256:{}", "a".repeat(64));
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidImage)
        );
        candidate = config(3);
        candidate.namespace = "Qualification".to_owned();
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidNamespace)
        );
        candidate = config(3);
        candidate.trust_domain = "QUALIFICATION.OPENPACKETCORE.INVALID".to_owned();
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidTrustDomain)
        );
        candidate = config(3);
        candidate.image = format!("registry.invalid/../session-node@sha256:{}", "a".repeat(64));
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidImage)
        );
        candidate = config(3);
        candidate.image = format!("Registry.invalid/session-node@sha256:{}", "a".repeat(64));
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidImage)
        );
        candidate = config(3);
        candidate.image = format!(
            "registry.invalid/session-node:release@sha256:{}",
            "a".repeat(64)
        );
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidImage)
        );
        candidate = config(4);
        assert_eq!(
            candidate.validate(),
            Err(QualificationKubernetesManifestError::InvalidTopology)
        );
    }
}
