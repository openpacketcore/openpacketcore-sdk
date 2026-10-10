//! Namespaced, exact-name platform observations independent of worker claims.
use super::{proof::BootObservation, wire::ScopeBinding};
use opc_types::SpiffeId;
use std::{net::SocketAddr, sync::Arc};
/// A trusted platform read failed or its exact observation changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// Enrollment, ownership or response structure is invalid.
    #[error("invalid scope platform observation")]
    Invalid,
    /// An authoritative read is temporarily unavailable.
    #[error("scope platform unavailable")]
    Unavailable,
    /// The previously verified Pod or opaque authority revision changed.
    #[error("scope platform observation changed")]
    Changed,
}
/// Installed namespaced enrollment. No request chooses these names or identity.
#[derive(Clone)]
pub struct PodEnrollment {
    pub(super) scope: ScopeBinding,
    namespace: String,
    pod_name: String,
    service_account: String,
    service_account_uid: [u8; 16],
    container: String,
    owner_uid: [u8; 16],
    pub(super) worker: SpiffeId,
    port: u16,
}
impl PodEnrollment {
    /// Bind an exact Pod, service-account UID, controlling owner and responder.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeBinding,
        namespace: String,
        pod_name: String,
        service_account: String,
        service_account_uid: [u8; 16],
        container: String,
        owner_uid: [u8; 16],
        worker: SpiffeId,
        port: u16,
    ) -> Result<Self, PlatformError> {
        if [&namespace, &pod_name, &service_account, &container]
            .iter()
            .any(|name| !name_valid(name))
            || service_account_uid == [0; 16]
            || owner_uid == [0; 16]
            || port == 0
        {
            return Err(PlatformError::Invalid);
        }
        Ok(Self {
            scope,
            namespace,
            pod_name,
            service_account,
            service_account_uid,
            container,
            owner_uid,
            worker,
            port,
        })
    }
}
/// Trusted Kubernetes API adapter; use the configured API CA and own credential.
/// Read the exact namespaced Pod consistently, with no informer/cache snapshot,
/// no `resourceVersion=0`, no proxy, and at most 1 MiB before body allocation.
#[async_trait::async_trait]
pub trait KubernetesPodSource: Send + Sync {
    /// A most-recent GET for exactly these configured namespace and name values.
    async fn get_pod_consistent(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<u8>, PlatformError>;
}
/// Checked current running Pod observation. It grants no admission or closure.
#[derive(Clone)]
pub struct RunningPodObservation {
    pub(super) boot: BootObservation,
    pub(super) address: SocketAddr,
    revision: String,
}
impl RunningPodObservation {
    /// Exact Pod UID, independently read from the API.
    pub const fn workload(&self) -> &[u8; 16] {
        &self.boot.pod_uid
    }
    /// Route hint to the independently authenticated worker endpoint.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}
/// Exact current-observation reader and equality-only revision revalidator.
pub struct KubernetesBootReader {
    source: Arc<dyn KubernetesPodSource>,
}
impl KubernetesBootReader {
    /// Install the trusted API read adapter.
    pub fn new(source: Arc<dyn KubernetesPodSource>) -> Self {
        Self { source }
    }
    /// Check enrollment and the actual running container in a consistent read.
    pub async fn observe(
        &self,
        enrollment: &PodEnrollment,
    ) -> Result<RunningPodObservation, PlatformError> {
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.source
                .get_pod_consistent(&enrollment.namespace, &enrollment.pod_name),
        )
        .await
        .map_err(|_| PlatformError::Unavailable)??;
        if bytes.len() > 1024 * 1024 {
            return Err(PlatformError::Invalid);
        }
        let pod: Pod = serde_json::from_slice(&bytes).map_err(|_| PlatformError::Invalid)?;
        if pod.metadata.name != enrollment.pod_name
            || pod.metadata.namespace != enrollment.namespace
            || pod.spec.service_account_name != enrollment.service_account
            || pod.metadata.deletion_timestamp.is_some()
            || pod.metadata.resource_version.is_empty()
            || pod.metadata.resource_version.len() > 256
            || pod.metadata.resource_version.chars().any(char::is_control)
            || pod
                .metadata
                .owner_references
                .iter()
                .filter(|owner| owner.controller == Some(true))
                .count()
                != 1
            || !pod.metadata.owner_references.iter().any(|owner| {
                owner.controller == Some(true) && parse_uid(&owner.uid) == Ok(enrollment.owner_uid)
            })
        {
            return Err(PlatformError::Invalid);
        }
        let pod_uid = parse_uid(&pod.metadata.uid)?;
        let mut containers = pod
            .status
            .container_statuses
            .into_iter()
            .filter(|container| container.name == enrollment.container);
        let container = containers.next().ok_or(PlatformError::Unavailable)?;
        if containers.next().is_some() {
            return Err(PlatformError::Invalid);
        }
        if container.state.waiting.is_some() || container.state.terminated.is_some() {
            return Err(PlatformError::Unavailable);
        }
        let running = container.state.running.ok_or(PlatformError::Unavailable)?;
        let boot = BootObservation {
            namespace: enrollment.namespace.clone(),
            pod_name: enrollment.pod_name.clone(),
            pod_uid,
            service_account: enrollment.service_account.clone(),
            service_account_uid: enrollment.service_account_uid,
            container_name: container.name,
            container_id: container.container_id,
            started_at: running.started_at,
        };
        boot.input().map_err(|_| PlatformError::Invalid)?;
        if pod.status.pod_ip.is_empty() {
            return Err(PlatformError::Unavailable);
        }
        let address = SocketAddr::new(
            pod.status
                .pod_ip
                .parse()
                .map_err(|_| PlatformError::Invalid)?,
            enrollment.port,
        );
        if address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(PlatformError::Invalid);
        }
        Ok(RunningPodObservation {
            boot,
            address,
            revision: pod.metadata.resource_version,
        })
    }
    /// Repeat the exact read; no ordering or clocks are inferred from revisions.
    pub async fn revalidate(
        &self,
        enrollment: &PodEnrollment,
        observed: &RunningPodObservation,
    ) -> Result<(), PlatformError> {
        let current = self.observe(enrollment).await?;
        if current.revision != observed.revision
            || current.boot.digest().map_err(|_| PlatformError::Invalid)?
                != observed.boot.digest().map_err(|_| PlatformError::Invalid)?
            || current.address != observed.address
        {
            return Err(PlatformError::Changed);
        }
        Ok(())
    }
}
fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
}
fn parse_uid(value: &str) -> Result<[u8; 16], PlatformError> {
    let uid = uuid::Uuid::parse_str(value).map_err(|_| PlatformError::Invalid)?;
    if uid.is_nil() || uid.to_string() != value {
        return Err(PlatformError::Invalid);
    }
    Ok(*uid.as_bytes())
}
use serde::Deserialize;
#[derive(Deserialize)]
struct Pod {
    metadata: Metadata,
    spec: Spec,
    #[serde(default)]
    status: Status,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    name: String,
    namespace: String,
    uid: String,
    resource_version: String,
    deletion_timestamp: Option<String>,
    owner_references: Vec<Owner>,
}
#[derive(Deserialize)]
struct Owner {
    uid: String,
    controller: Option<bool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Spec {
    service_account_name: String,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    #[serde(default, rename = "podIP")]
    pod_ip: String,
    #[serde(default)]
    container_statuses: Vec<Container>,
}
#[derive(Deserialize)]
struct Container {
    name: String,
    #[serde(default, rename = "containerID")]
    container_id: String,
    state: ContainerState,
}
#[derive(Deserialize)]
struct ContainerState {
    running: Option<Running>,
    terminated: Option<serde_json::Value>,
    waiting: Option<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Running {
    started_at: String,
}
