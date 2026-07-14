//! Immutable, topology-derived identity bindings for session replication.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::Arc;

pub use opc_consensus::ConsensusConfigurationEpoch as SessionConfigurationEpoch;
use opc_consensus::{
    derive_configuration_id, derive_node_id, ConsensusClusterId as SessionConsensusClusterId,
    ConsensusIdentity as SessionConsensusIdentity, ConsensusNodeId as SessionConsensusNodeId,
};
#[cfg(any(
    all(feature = "insecure-test", feature = "legacy-session-net-compat"),
    test
))]
use opc_session_store::ReplicaBackingIdentity;
#[cfg(any(feature = "legacy-session-net-compat", test))]
use opc_session_store::{BackendPeerBinding, BackendPeerScopeIdentity};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    QUORUM_TOPOLOGY_MAX_MEMBERS,
};
use opc_types::SpiffeId;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum encoded cluster identity accepted by session replication.
pub const SESSION_CLUSTER_ID_MAX_BYTES: usize = 128;
/// Maximum encoded configuration generation accepted by session replication.
pub const SESSION_CONFIGURATION_GENERATION_MAX_BYTES: usize = 253;

/// Redaction-safe manifest construction or binding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionManifestError {
    #[error("invalid session cluster identity")]
    InvalidClusterId,
    #[error("invalid session configuration generation")]
    InvalidConfigurationGeneration,
    #[error("session replication manifest is empty")]
    EmptyMembership,
    #[error("session replication manifest has too many members")]
    TooManyMembers,
    #[error("session replication manifest contains a duplicate replica ID")]
    DuplicateReplicaId,
    #[error("session replication manifest contains a duplicate consensus node ID")]
    DuplicateConsensusNodeId,
    #[error("session replication manifest contains a duplicate TLS identity")]
    DuplicateTlsIdentity,
    #[error("session replication manifest contains a duplicate endpoint")]
    DuplicateEndpoint,
    #[error("session replication manifest contains a duplicate failure domain")]
    DuplicateFailureDomain,
    #[error("session replication manifest contains a duplicate backing identity")]
    DuplicateBackingIdentity,
    #[error("session replication manifest contains a malformed SPIFFE identity")]
    MalformedSpiffeIdentity,
    #[error("local replica is not present in the session replication manifest")]
    MissingLocalReplica,
    #[error("remote replica is not present in the session replication manifest")]
    MissingRemoteReplica,
}

fn validate_opaque(value: String, max_bytes: usize) -> Result<String, ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(value)
}

/// Stable cluster identity shared by every member of one replication fleet.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionClusterId(String);

impl SessionClusterId {
    pub fn new(value: impl Into<String>) -> Result<Self, SessionManifestError> {
        validate_opaque(value.into(), SESSION_CLUSTER_ID_MAX_BYTES)
            .map(Self)
            .map_err(|()| SessionManifestError::InvalidClusterId)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionClusterId(<redacted>)")
    }
}

/// Legacy operator-controlled generation mixed into the protocol-v5 backend
/// manifest ID.
///
/// New consensus composition must use [`SessionConfigurationEpoch`] for its
/// monotonic authority boundary. This value remains only to preserve the
/// legacy remote-backend handshake identity during migration.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionConfigurationGeneration(String);

impl SessionConfigurationGeneration {
    pub fn new(value: impl Into<String>) -> Result<Self, SessionManifestError> {
        validate_opaque(value.into(), SESSION_CONFIGURATION_GENERATION_MAX_BYTES)
            .map(Self)
            .map_err(|()| SessionManifestError::InvalidConfigurationGeneration)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionConfigurationGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionConfigurationGeneration(<redacted>)")
    }
}

/// Fixed-width identity of one complete, order-independent member manifest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionConfigurationId([u8; 32]);

impl SessionConfigurationId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        encoded
    }
}

impl fmt::Debug for SessionConfigurationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionConfigurationId(<redacted>)")
    }
}

/// One immutable member identity retained by the authenticated manifest.
#[derive(Clone)]
struct ManifestMember {
    descriptor: QuorumReplicaDescriptor,
    spiffe_id: SpiffeId,
}

/// Immutable identity map from which client and server bindings are issued.
#[derive(Clone)]
pub struct SessionReplicationManifest {
    cluster_id: SessionClusterId,
    configuration_id: SessionConfigurationId,
    configuration_epoch: SessionConfigurationEpoch,
    consensus_identity: SessionConsensusIdentity,
    members: BTreeMap<ReplicaId, ManifestMember>,
    node_ids: BTreeMap<ReplicaId, SessionConsensusNodeId>,
}

impl SessionReplicationManifest {
    /// Validate a complete descriptor set and derive its configuration ID.
    #[deprecated(
        since = "0.2.0",
        note = "use try_new_with_epoch; the compatibility constructor fixes epoch to 1"
    )]
    pub fn try_new(
        cluster_id: SessionClusterId,
        generation: SessionConfigurationGeneration,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> Result<Self, SessionManifestError> {
        Self::try_new_with_epoch(
            cluster_id,
            generation,
            SessionConfigurationEpoch::new(1)
                .expect("the fixed compatibility configuration epoch is non-zero"),
            descriptors,
        )
    }

    /// Validate a complete descriptor set and derive its consensus identity.
    ///
    /// Node IDs are stable cluster-scoped hashes of logical [`ReplicaId`] and
    /// therefore do not change when another member is added or removed.
    pub fn try_new_with_epoch(
        cluster_id: SessionClusterId,
        generation: SessionConfigurationGeneration,
        configuration_epoch: SessionConfigurationEpoch,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> Result<Self, SessionManifestError> {
        if descriptors.is_empty() {
            return Err(SessionManifestError::EmptyMembership);
        }
        if descriptors.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
            return Err(SessionManifestError::TooManyMembers);
        }

        let mut replica_ids = HashSet::with_capacity(descriptors.len());
        let mut tls_identities = HashSet::with_capacity(descriptors.len());
        let mut endpoints = HashSet::<ReplicaEndpoint>::with_capacity(descriptors.len());
        let mut failure_domains = HashSet::<ReplicaFailureDomain>::with_capacity(descriptors.len());
        let mut backing_identities = HashSet::with_capacity(descriptors.len());
        let mut members = BTreeMap::new();

        for descriptor in descriptors {
            if !replica_ids.insert(descriptor.replica_id().clone()) {
                return Err(SessionManifestError::DuplicateReplicaId);
            }
            if !tls_identities.insert(descriptor.tls_identity().clone()) {
                return Err(SessionManifestError::DuplicateTlsIdentity);
            }
            if !endpoints.insert(descriptor.endpoint().clone()) {
                return Err(SessionManifestError::DuplicateEndpoint);
            }
            if !failure_domains.insert(descriptor.failure_domain().clone()) {
                return Err(SessionManifestError::DuplicateFailureDomain);
            }
            if !backing_identities.insert(descriptor.backing_identity().clone()) {
                return Err(SessionManifestError::DuplicateBackingIdentity);
            }
            let spiffe_id = SpiffeId::new(descriptor.tls_identity().as_str())
                .map_err(|_| SessionManifestError::MalformedSpiffeIdentity)?;
            members.insert(
                descriptor.replica_id().clone(),
                ManifestMember {
                    descriptor,
                    spiffe_id,
                },
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(b"opc-session-net/configuration/v1\0");
        hash_field(&mut hasher, cluster_id.as_str().as_bytes());
        hash_field(&mut hasher, generation.as_str().as_bytes());
        let member_count =
            u16::try_from(members.len()).expect("validated manifest member count fits u16");
        hash_field(&mut hasher, &member_count.to_be_bytes());
        for member in members.values() {
            hash_field(&mut hasher, &member.descriptor.configuration_fingerprint());
        }
        let configuration_id = SessionConfigurationId(hasher.finalize().into());

        let consensus_cluster_id = SessionConsensusClusterId::new(cluster_id.as_str())
            .map_err(|_| SessionManifestError::InvalidClusterId)?;
        let consensus_epoch = configuration_epoch;
        let component_fingerprints = members
            .values()
            .map(|member| member.descriptor.configuration_fingerprint())
            .collect::<Vec<_>>();
        let consensus_configuration_id = derive_configuration_id(
            consensus_cluster_id,
            consensus_epoch,
            &component_fingerprints,
        );
        let consensus_identity = SessionConsensusIdentity::new(
            consensus_cluster_id,
            consensus_configuration_id,
            consensus_epoch,
        );
        let mut node_ids = BTreeMap::new();
        let mut admitted_node_ids = HashSet::with_capacity(members.len());
        for replica_id in members.keys() {
            let node_id = derive_node_id(consensus_cluster_id, replica_id.as_str().as_bytes())
                .map_err(|_| SessionManifestError::DuplicateConsensusNodeId)?;
            if !admitted_node_ids.insert(node_id) {
                return Err(SessionManifestError::DuplicateConsensusNodeId);
            }
            node_ids.insert(replica_id.clone(), node_id);
        }

        Ok(Self {
            cluster_id,
            configuration_id,
            configuration_epoch,
            consensus_identity,
            members,
            node_ids,
        })
    }

    pub fn cluster_id(&self) -> &SessionClusterId {
        &self.cluster_id
    }

    pub const fn configuration_id(&self) -> SessionConfigurationId {
        self.configuration_id
    }

    /// Monotonic operator-controlled consensus configuration epoch.
    pub const fn configuration_epoch(&self) -> SessionConfigurationEpoch {
        self.configuration_epoch
    }

    /// Exact cluster/configuration/epoch identity carried on consensus RPCs.
    pub const fn consensus_identity(&self) -> SessionConsensusIdentity {
        self.consensus_identity
    }

    /// Return the canonical consensus node ordinal for one admitted replica.
    pub fn consensus_node_id(&self, replica_id: &ReplicaId) -> Option<SessionConsensusNodeId> {
        self.node_ids.get(replica_id).copied()
    }

    pub fn configured_members(&self) -> usize {
        self.members.len()
    }

    /// Bind this immutable manifest to one exact local member.
    pub fn bind_local(
        self: &Arc<Self>,
        local_replica_id: ReplicaId,
    ) -> Result<LocalReplicaBinding, SessionManifestError> {
        if !self.members.contains_key(&local_replica_id) {
            return Err(SessionManifestError::MissingLocalReplica);
        }
        Ok(LocalReplicaBinding {
            manifest: self.clone(),
            local_replica_id,
        })
    }

    fn member(&self, replica_id: &ReplicaId) -> Option<&ManifestMember> {
        self.members.get(replica_id)
    }
}

impl fmt::Debug for SessionReplicationManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReplicationManifest")
            .field("cluster_id", &self.cluster_id)
            .field("configuration_id", &self.configuration_id)
            .field("configuration_epoch", &self.configuration_epoch)
            .field("configured_members", &self.members.len())
            .finish()
    }
}

/// Server-side binding for one exact local member and authorized manifest.
#[derive(Clone)]
pub struct LocalReplicaBinding {
    manifest: Arc<SessionReplicationManifest>,
    local_replica_id: ReplicaId,
}

impl LocalReplicaBinding {
    pub fn local_replica_id(&self) -> &ReplicaId {
        &self.local_replica_id
    }

    pub fn local_tls_identity(&self) -> &ReplicaTlsIdentity {
        self.local_member().descriptor.tls_identity()
    }

    pub fn cluster_id(&self) -> &SessionClusterId {
        self.manifest.cluster_id()
    }

    pub fn configuration_id(&self) -> SessionConfigurationId {
        self.manifest.configuration_id()
    }

    pub fn configured_members(&self) -> usize {
        self.manifest.configured_members()
    }

    /// Operator-controlled configuration epoch for this binding.
    pub fn configuration_epoch(&self) -> SessionConfigurationEpoch {
        self.manifest.configuration_epoch()
    }

    /// Exact consensus identity derived from the immutable manifest and epoch.
    pub fn consensus_identity(&self) -> SessionConsensusIdentity {
        self.manifest.consensus_identity()
    }

    /// Canonical non-zero node ordinal for this local replica.
    pub fn local_consensus_node_id(&self) -> SessionConsensusNodeId {
        self.manifest
            .consensus_node_id(&self.local_replica_id)
            .expect("validated local replica binding has a canonical node ID")
    }

    /// Canonical node ordinal for an admitted replica.
    pub fn consensus_node_id(&self, replica_id: &ReplicaId) -> Option<SessionConsensusNodeId> {
        self.manifest.consensus_node_id(replica_id)
    }

    pub fn bind_remote(
        &self,
        remote_replica_id: ReplicaId,
    ) -> Result<RemoteReplicaBinding, SessionManifestError> {
        if self.manifest.member(&remote_replica_id).is_none() {
            return Err(SessionManifestError::MissingRemoteReplica);
        }
        Ok(RemoteReplicaBinding {
            local: self.clone(),
            remote_replica_id,
        })
    }

    pub(crate) fn member_spiffe_id(&self, replica_id: &ReplicaId) -> Option<&SpiffeId> {
        self.manifest
            .member(replica_id)
            .map(|member| &member.spiffe_id)
    }

    #[cfg(any(feature = "legacy-session-net-compat", test))]
    pub(crate) fn local_descriptor(&self) -> &QuorumReplicaDescriptor {
        &self.local_member().descriptor
    }

    fn local_member(&self) -> &ManifestMember {
        self.manifest
            .member(&self.local_replica_id)
            .expect("validated local replica binding")
    }
}

impl fmt::Debug for LocalReplicaBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalReplicaBinding")
            .field("local_replica_id", &self.local_replica_id)
            .field("manifest", &self.manifest)
            .finish()
    }
}

/// Client-side binding to one exact remote member of an immutable manifest.
#[derive(Clone)]
pub struct RemoteReplicaBinding {
    local: LocalReplicaBinding,
    remote_replica_id: ReplicaId,
}

impl RemoteReplicaBinding {
    pub fn local_replica_id(&self) -> &ReplicaId {
        self.local.local_replica_id()
    }

    pub fn remote_replica_id(&self) -> &ReplicaId {
        &self.remote_replica_id
    }

    pub fn remote_tls_identity(&self) -> &ReplicaTlsIdentity {
        self.remote_member().descriptor.tls_identity()
    }

    pub fn remote_spiffe_id(&self) -> &SpiffeId {
        &self.remote_member().spiffe_id
    }

    pub fn remote_endpoint(&self) -> &ReplicaEndpoint {
        self.remote_member().descriptor.endpoint()
    }

    pub fn cluster_id(&self) -> &SessionClusterId {
        self.local.cluster_id()
    }

    pub fn configuration_id(&self) -> SessionConfigurationId {
        self.local.configuration_id()
    }

    pub fn configured_members(&self) -> usize {
        self.local.configured_members()
    }

    /// Operator-controlled configuration epoch for this binding.
    pub fn configuration_epoch(&self) -> SessionConfigurationEpoch {
        self.local.configuration_epoch()
    }

    /// Exact consensus identity derived from the immutable manifest and epoch.
    pub fn consensus_identity(&self) -> SessionConsensusIdentity {
        self.local.consensus_identity()
    }

    /// Canonical node ordinal claimed by this authenticated client.
    pub fn local_consensus_node_id(&self) -> SessionConsensusNodeId {
        self.local.local_consensus_node_id()
    }

    /// Canonical node ordinal expected for the authenticated remote server.
    pub fn remote_consensus_node_id(&self) -> SessionConsensusNodeId {
        self.local
            .consensus_node_id(&self.remote_replica_id)
            .expect("validated remote replica binding has a canonical node ID")
    }

    #[cfg(any(feature = "legacy-session-net-compat", test))]
    pub(crate) fn local_descriptor(&self) -> &QuorumReplicaDescriptor {
        self.local.local_descriptor()
    }

    #[cfg(any(feature = "legacy-session-net-compat", test))]
    pub(crate) fn remote_descriptor(&self) -> &QuorumReplicaDescriptor {
        &self.remote_member().descriptor
    }

    #[cfg(any(feature = "legacy-session-net-compat", test))]
    pub(crate) fn backend_peer_binding(&self) -> BackendPeerBinding {
        BackendPeerBinding::new(
            self.local_replica_id().clone(),
            self.remote_replica_id().clone(),
            self.remote_tls_identity().clone(),
            self.local_descriptor().configuration_fingerprint(),
            self.remote_descriptor().configuration_fingerprint(),
            u16::try_from(self.configured_members())
                .expect("session manifest member count is bounded below u16::MAX"),
            BackendPeerScopeIdentity::new(*self.configuration_id().as_bytes()),
        )
    }

    fn remote_member(&self) -> &ManifestMember {
        self.local
            .manifest
            .member(&self.remote_replica_id)
            .expect("validated remote replica binding")
    }
}

impl fmt::Debug for RemoteReplicaBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteReplicaBinding")
            .field("local_replica_id", self.local_replica_id())
            .field("remote_replica_id", &self.remote_replica_id)
            .field("cluster_id", self.cluster_id())
            .field("configuration_id", &self.configuration_id())
            .finish()
    }
}

fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    let field_len = u32::try_from(field.len()).expect("validated manifest field length fits u32");
    hasher.update(field_len.to_be_bytes());
    hasher.update(field);
}

#[cfg(all(
    feature = "legacy-session-net-compat",
    any(test, feature = "insecure-test")
))]
fn insecure_test_manifest() -> Arc<SessionReplicationManifest> {
    let descriptor = |id: &str, instance: &str, port| {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(id).expect("fixed insecure-test replica ID"),
            ReplicaEndpoint::new("insecure.test", port).expect("fixed insecure-test endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://insecure.test/tenant/test/ns/test/sa/session/nf/test/instance/{instance}"
            ))
            .expect("fixed insecure-test TLS identity"),
            ReplicaFailureDomain::new(format!("insecure-test/{instance}"))
                .expect("fixed insecure-test failure domain"),
            ReplicaBackingIdentity::new(format!("insecure-test/{instance}"))
                .expect("fixed insecure-test backing identity"),
        )
    };
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("insecure-test").expect("fixed insecure-test cluster"),
            SessionConfigurationGeneration::new("v3").expect("fixed insecure-test generation"),
            SessionConfigurationEpoch::new(1).expect("fixed insecure-test epoch"),
            vec![
                descriptor("insecure-client", "client", 1),
                descriptor("insecure-server", "server", 2),
            ],
        )
        .expect("fixed insecure-test manifest"),
    )
}

#[cfg(all(
    feature = "legacy-session-net-compat",
    any(test, feature = "insecure-test")
))]
pub(crate) fn insecure_test_client_binding() -> RemoteReplicaBinding {
    insecure_test_manifest()
        .bind_local(ReplicaId::new("insecure-client").expect("fixed insecure-test client"))
        .expect("fixed insecure-test local binding")
        .bind_remote(ReplicaId::new("insecure-server").expect("fixed insecure-test server"))
        .expect("fixed insecure-test remote binding")
}

#[cfg(all(
    feature = "legacy-session-net-compat",
    any(test, feature = "insecure-test")
))]
pub(crate) fn insecure_test_server_binding() -> LocalReplicaBinding {
    insecure_test_manifest()
        .bind_local(ReplicaId::new("insecure-server").expect("fixed insecure-test server"))
        .expect("fixed insecure-test server binding")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(index: u16) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("replica-{index}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("replica-{index}.session.invalid"), 7443)
                .expect("endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://test.example/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
            ))
            .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("zone-{index}")).expect("failure domain"),
            ReplicaBackingIdentity::new(format!("disk-{index}")).expect("backing identity"),
        )
    }

    fn manifest(
        cluster: &str,
        generation: &str,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> SessionReplicationManifest {
        manifest_with_epoch(cluster, generation, 1, descriptors)
    }

    fn manifest_with_epoch(
        cluster: &str,
        generation: &str,
        epoch: u64,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> SessionReplicationManifest {
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new(generation).expect("generation"),
            SessionConfigurationEpoch::new(epoch).expect("configuration epoch"),
            descriptors,
        )
        .expect("manifest")
    }

    #[test]
    fn manifest_identity_is_order_independent_and_scope_sensitive() {
        let descriptors = vec![descriptor(1), descriptor(2), descriptor(3)];
        let mut reversed = descriptors.clone();
        reversed.reverse();

        let original = manifest("cluster-a", "generation-7", descriptors.clone());
        assert_eq!(
            original.configuration_id().to_hex(),
            "f29bf07f10d0fc7c0af0edc2647fa374ad2989a6068c4d1ae35edb9480a851c1",
            "manifest encoding must stay architecture-independent and versioned"
        );
        let reordered = manifest("cluster-a", "generation-7", reversed);
        assert_eq!(original.configuration_id(), reordered.configuration_id());

        let changed_cluster = manifest("cluster-b", "generation-7", descriptors.clone());
        let changed_generation = manifest("cluster-a", "generation-8", descriptors.clone());
        let mut changed_descriptors = descriptors;
        changed_descriptors[2] = QuorumReplicaDescriptor::new(
            changed_descriptors[2].replica_id().clone(),
            ReplicaEndpoint::new("replacement.session.invalid", 7443).expect("endpoint"),
            changed_descriptors[2].tls_identity().clone(),
            changed_descriptors[2].failure_domain().clone(),
            changed_descriptors[2].backing_identity().clone(),
        );
        let changed_descriptor = manifest("cluster-a", "generation-7", changed_descriptors);

        assert_ne!(
            original.configuration_id(),
            changed_cluster.configuration_id()
        );
        assert_ne!(
            original.configuration_id(),
            changed_generation.configuration_id()
        );
        assert_ne!(
            original.configuration_id(),
            changed_descriptor.configuration_id()
        );
    }

    #[test]
    fn consensus_identity_uses_shared_cluster_epoch_and_descriptor_derivation() {
        let descriptors = vec![descriptor(1), descriptor(2), descriptor(3)];
        let mut reordered = descriptors.clone();
        reordered.reverse();
        let original = manifest_with_epoch("cluster-a", "legacy-a", 7, descriptors.clone());
        let same_scope = manifest_with_epoch("cluster-a", "legacy-b", 7, reordered);
        assert_eq!(
            original.consensus_identity(),
            same_scope.consensus_identity()
        );

        let changed_epoch = manifest_with_epoch("cluster-a", "legacy-a", 8, descriptors.clone());
        let changed_cluster = manifest_with_epoch("cluster-b", "legacy-a", 7, descriptors.clone());
        let mut changed_descriptors = descriptors;
        changed_descriptors[0] = QuorumReplicaDescriptor::new(
            changed_descriptors[0].replica_id().clone(),
            ReplicaEndpoint::new("replacement.session.invalid", 7443).expect("endpoint"),
            changed_descriptors[0].tls_identity().clone(),
            changed_descriptors[0].failure_domain().clone(),
            changed_descriptors[0].backing_identity().clone(),
        );
        let changed_descriptor =
            manifest_with_epoch("cluster-a", "legacy-a", 7, changed_descriptors);

        assert_ne!(
            original.consensus_identity(),
            changed_epoch.consensus_identity()
        );
        assert_ne!(
            original.consensus_identity(),
            changed_cluster.consensus_identity()
        );
        assert_ne!(
            original.consensus_identity(),
            changed_descriptor.consensus_identity()
        );
    }

    #[test]
    fn consensus_node_ids_survive_reorder_add_remove_and_epoch_changes() {
        let baseline = manifest_with_epoch(
            "cluster-a",
            "legacy-a",
            7,
            vec![descriptor(2), descriptor(3)],
        );
        let expanded = manifest_with_epoch(
            "cluster-a",
            "legacy-a",
            8,
            vec![descriptor(3), descriptor(1), descriptor(2)],
        );
        let reduced = manifest_with_epoch("cluster-a", "legacy-a", 9, vec![descriptor(2)]);
        let replica_2 = ReplicaId::new("replica-2").expect("replica ID");
        assert_eq!(
            baseline.consensus_node_id(&replica_2),
            expanded.consensus_node_id(&replica_2)
        );
        assert_eq!(
            baseline.consensus_node_id(&replica_2),
            reduced.consensus_node_id(&replica_2)
        );
        assert!(baseline
            .consensus_node_id(&replica_2)
            .is_some_and(|node_id| node_id.get() != 0));
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_manifest_constructor_is_exactly_epoch_one() {
        let descriptors = vec![descriptor(1), descriptor(2), descriptor(3)];
        let legacy = SessionReplicationManifest::try_new(
            SessionClusterId::new("cluster-a").expect("cluster"),
            SessionConfigurationGeneration::new("legacy-a").expect("generation"),
            descriptors.clone(),
        )
        .expect("legacy manifest");
        let explicit = manifest_with_epoch("cluster-a", "legacy-a", 1, descriptors);

        assert_eq!(legacy.configuration_epoch().get(), 1);
        assert_eq!(legacy.consensus_identity(), explicit.consensus_identity());
    }

    #[test]
    fn manifest_scope_identifiers_enforce_exact_byte_bounds() {
        assert!(SessionClusterId::new("a".repeat(SESSION_CLUSTER_ID_MAX_BYTES)).is_ok());
        assert_eq!(
            SessionClusterId::new("a".repeat(SESSION_CLUSTER_ID_MAX_BYTES + 1)),
            Err(SessionManifestError::InvalidClusterId)
        );
        assert!(SessionConfigurationGeneration::new(
            "g".repeat(SESSION_CONFIGURATION_GENERATION_MAX_BYTES)
        )
        .is_ok());
        assert_eq!(
            SessionConfigurationGeneration::new(
                "g".repeat(SESSION_CONFIGURATION_GENERATION_MAX_BYTES + 1)
            ),
            Err(SessionManifestError::InvalidConfigurationGeneration)
        );
        assert_eq!(
            SessionConfigurationEpoch::new(0),
            Err(opc_consensus::ConsensusIdentityError::InvalidConfigurationEpoch)
        );
    }

    #[test]
    fn manifest_rejects_duplicate_and_malformed_peer_authority() {
        let first = descriptor(1);
        let duplicate_id = QuorumReplicaDescriptor::new(
            first.replica_id().clone(),
            ReplicaEndpoint::new("replica-2.session.invalid", 7443).expect("endpoint"),
            descriptor(2).tls_identity().clone(),
            ReplicaFailureDomain::new("zone-2").expect("failure domain"),
            ReplicaBackingIdentity::new("disk-2").expect("backing identity"),
        );
        assert!(matches!(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("cluster-a").expect("cluster ID"),
                SessionConfigurationGeneration::new("generation-1").expect("generation"),
                SessionConfigurationEpoch::new(1).expect("configuration epoch"),
                vec![first, duplicate_id],
            ),
            Err(SessionManifestError::DuplicateReplicaId)
        ));

        let first = descriptor(1);
        let duplicate_tls = QuorumReplicaDescriptor::new(
            ReplicaId::new("replica-2").expect("replica ID"),
            ReplicaEndpoint::new("replica-2.session.invalid", 7443).expect("endpoint"),
            first.tls_identity().clone(),
            ReplicaFailureDomain::new("zone-2").expect("failure domain"),
            ReplicaBackingIdentity::new("disk-2").expect("backing identity"),
        );
        assert!(matches!(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("cluster-a").expect("cluster ID"),
                SessionConfigurationGeneration::new("generation-1").expect("generation"),
                SessionConfigurationEpoch::new(1).expect("configuration epoch"),
                vec![first, duplicate_tls],
            ),
            Err(SessionManifestError::DuplicateTlsIdentity)
        ));

        let malformed = QuorumReplicaDescriptor::new(
            ReplicaId::new("replica-malformed").expect("replica ID"),
            ReplicaEndpoint::new("malformed.session.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("not-a-spiffe-id").expect("opaque topology identity"),
            ReplicaFailureDomain::new("zone-malformed").expect("failure domain"),
            ReplicaBackingIdentity::new("disk-malformed").expect("backing identity"),
        );
        assert!(matches!(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("cluster-a").expect("cluster ID"),
                SessionConfigurationGeneration::new("generation-1").expect("generation"),
                SessionConfigurationEpoch::new(1).expect("configuration epoch"),
                vec![malformed],
            ),
            Err(SessionManifestError::MalformedSpiffeIdentity)
        ));
    }

    #[test]
    fn remote_binding_carries_exact_redacted_topology_evidence() {
        let manifest = Arc::new(manifest(
            "cluster-a",
            "generation-7",
            vec![descriptor(1), descriptor(2), descriptor(3)],
        ));
        let local = manifest
            .bind_local(ReplicaId::new("replica-1").expect("local ID"))
            .expect("local binding");
        let remote = local
            .bind_remote(ReplicaId::new("replica-2").expect("remote ID"))
            .expect("remote binding");
        let evidence = remote.backend_peer_binding();

        assert_eq!(evidence.local_replica_id().as_str(), "replica-1");
        assert_eq!(evidence.remote_replica_id().as_str(), "replica-2");
        assert_eq!(usize::from(evidence.configured_member_count()), 3);
        assert_eq!(
            evidence.scope().as_bytes(),
            remote.configuration_id().as_bytes()
        );

        let debug = format!("{manifest:?} {local:?} {remote:?} {evidence:?}");
        assert!(!debug.contains("spiffe://"));
        assert!(!debug.contains("session.invalid"));
        assert!(!debug.contains(&remote.configuration_id().to_hex()));
    }
}
