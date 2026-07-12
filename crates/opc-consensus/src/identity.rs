//! Redaction-safe identities shared by consensus storage and transport.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum accepted byte length of a caller-supplied cluster name.
pub const CONSENSUS_CLUSTER_ID_MAX_BYTES: usize = 128;

/// Maximum accepted byte length of a stable member identity used to derive a
/// consensus node ID.
pub const CONSENSUS_MEMBER_ID_MAX_BYTES: usize = 253;

/// Largest portable node ID. The shared SQLite adapters persist numeric Raft
/// metadata as signed 64-bit integers, so admitted IDs must fit that domain.
pub const CONSENSUS_NODE_ID_MAX: u64 = i64::MAX as u64;

const CLUSTER_ID_DOMAIN: &[u8] = b"openpacketcore/consensus/cluster-id/v1\0";
const CONFIGURATION_ID_DOMAIN: &[u8] = b"openpacketcore/consensus/configuration-id/v1\0";
const NODE_ID_DOMAIN: &[u8] = b"openpacketcore/consensus/node-id/v1\0";

/// Redaction-safe validation failure for consensus identity material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConsensusIdentityError {
    /// Cluster name is empty, oversized, or non-canonical.
    #[error("invalid consensus cluster identity")]
    InvalidClusterId,
    /// Configuration epochs are strictly positive.
    #[error("invalid consensus configuration epoch")]
    InvalidConfigurationEpoch,
    /// Canonical node ordinals are strictly positive.
    #[error("invalid consensus node ID")]
    InvalidNodeId,
}

/// Fixed-width, domain-separated identity of one consensus cluster.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsensusClusterId([u8; 32]);

impl ConsensusClusterId {
    /// Validate and hash an operator-controlled cluster name.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ConsensusIdentityError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > CONSENSUS_CLUSTER_ID_MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ConsensusIdentityError::InvalidClusterId);
        }
        let mut hasher = Sha256::new();
        hasher.update(CLUSTER_ID_DOMAIN);
        hasher.update(value.as_bytes());
        Ok(Self(hasher.finalize().into()))
    }

    /// Reconstruct from the persisted fixed-width representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fixed-width persisted/wire representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ConsensusClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusClusterId(<redacted>)")
    }
}

/// Fixed-width identity of one exact order-independent configuration.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsensusConfigurationId([u8; 32]);

impl ConsensusConfigurationId {
    /// Construct from an SDK-owned deterministic configuration digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fixed-width persisted/wire representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive one order-independent configuration identity from its cluster,
/// monotonic epoch, and fixed-width member/component fingerprints.
///
/// Callers own the component-count admission bound. The function sorts a
/// private copy so descriptor input order cannot change authority.
pub fn derive_configuration_id(
    cluster_id: ConsensusClusterId,
    epoch: ConsensusConfigurationEpoch,
    component_fingerprints: &[[u8; 32]],
) -> ConsensusConfigurationId {
    let mut components = component_fingerprints.to_vec();
    components.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(CONFIGURATION_ID_DOMAIN);
    hasher.update(cluster_id.as_bytes());
    hasher.update(epoch.get().to_be_bytes());
    hasher.update(
        u32::try_from(components.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for component in components {
        hasher.update(component);
    }
    ConsensusConfigurationId::from_bytes(hasher.finalize().into())
}

impl fmt::Debug for ConsensusConfigurationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusConfigurationId(<redacted>)")
    }
}

/// Monotonic operator-controlled membership/configuration epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ConsensusConfigurationEpoch(u64);

impl ConsensusConfigurationEpoch {
    /// Validate a strictly positive epoch.
    pub const fn new(value: u64) -> Result<Self, ConsensusIdentityError> {
        if value == 0 {
            return Err(ConsensusIdentityError::InvalidConfigurationEpoch);
        }
        Ok(Self(value))
    }

    /// Numeric epoch.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ConsensusConfigurationEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identity scope bound into topology, storage, snapshots, and every RPC.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusIdentity {
    cluster_id: ConsensusClusterId,
    configuration_id: ConsensusConfigurationId,
    configuration_epoch: ConsensusConfigurationEpoch,
}

impl ConsensusIdentity {
    /// Bind one cluster, exact configuration, and monotonic epoch.
    pub const fn new(
        cluster_id: ConsensusClusterId,
        configuration_id: ConsensusConfigurationId,
        configuration_epoch: ConsensusConfigurationEpoch,
    ) -> Self {
        Self {
            cluster_id,
            configuration_id,
            configuration_epoch,
        }
    }

    /// Cluster identity digest.
    pub const fn cluster_id(self) -> ConsensusClusterId {
        self.cluster_id
    }

    /// Exact configuration digest.
    pub const fn configuration_id(self) -> ConsensusConfigurationId {
        self.configuration_id
    }

    /// Monotonic configuration epoch.
    pub const fn configuration_epoch(self) -> ConsensusConfigurationEpoch {
        self.configuration_epoch
    }
}

impl fmt::Debug for ConsensusIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusIdentity")
            .field("cluster_id", &self.cluster_id)
            .field("configuration_id", &self.configuration_id)
            .field("configuration_epoch", &self.configuration_epoch)
            .finish()
    }
}

/// Canonical architecture-independent Raft node ordinal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ConsensusNodeId(u64);

impl ConsensusNodeId {
    /// Construct a non-zero, storage-portable ordinal.
    pub const fn new(value: u64) -> Result<Self, ConsensusIdentityError> {
        if value == 0 || value > CONSENSUS_NODE_ID_MAX {
            return Err(ConsensusIdentityError::InvalidNodeId);
        }
        Ok(Self(value))
    }

    /// Numeric representation used by Openraft and fixed-width DTOs.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ConsensusNodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Derive a stable cluster-scoped Openraft node ID from an immutable logical
/// member identity.
///
/// Unlike a sorted-set ordinal, this value does not change when another member
/// is added or removed. Callers must reject duplicate derived IDs when
/// admitting a membership set. A logical member rename is intentionally a
/// remove/add operation from the consensus engine's perspective.
pub fn derive_node_id(
    cluster_id: ConsensusClusterId,
    stable_member_id: &[u8],
) -> Result<ConsensusNodeId, ConsensusIdentityError> {
    if stable_member_id.is_empty() || stable_member_id.len() > CONSENSUS_MEMBER_ID_MAX_BYTES {
        return Err(ConsensusIdentityError::InvalidNodeId);
    }

    let mut hasher = Sha256::new();
    hasher.update(NODE_ID_DOMAIN);
    hasher.update(cluster_id.as_bytes());
    hasher.update(
        u32::try_from(stable_member_id.len())
            .map_err(|_| ConsensusIdentityError::InvalidNodeId)?
            .to_be_bytes(),
    );
    hasher.update(stable_member_id);
    let digest: [u8; 32] = hasher.finalize().into();

    for chunk in digest.chunks_exact(8) {
        let value = u64::from_be_bytes(
            chunk
                .try_into()
                .expect("SHA-256 chunks are exactly eight bytes"),
        ) & CONSENSUS_NODE_ID_MAX;
        if let Ok(node_id) = ConsensusNodeId::new(value) {
            return Ok(node_id);
        }
    }

    Err(ConsensusIdentityError::InvalidNodeId)
}

impl fmt::Display for ConsensusNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Durable fixed-width identity of one submitted command.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusRequestId([u8; 16]);

impl ConsensusRequestId {
    /// Generate a new request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct from its fixed-width representation.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Fixed-width persisted/wire representation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for ConsensusRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConsensusRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusRequestId(<redacted>)")
    }
}

/// Integrity digest chaining committed application commands.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusEntryDigest([u8; 32]);

impl ConsensusEntryDigest {
    /// Genesis predecessor before the first application command.
    pub const GENESIS: Self = Self([0; 32]);

    /// Reconstruct from its fixed-width representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fixed-width persisted/wire representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ConsensusEntryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusEntryDigest(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_epoch_is_rejected_during_deserialization() {
        assert!(serde_json::from_str::<ConsensusConfigurationEpoch>("0").is_err());
        assert_eq!(
            serde_json::from_str::<ConsensusConfigurationEpoch>("7")
                .expect("positive epoch")
                .get(),
            7
        );
    }

    #[test]
    fn zero_node_id_is_rejected_during_deserialization() {
        assert!(serde_json::from_str::<ConsensusNodeId>("0").is_err());
        assert!(ConsensusNodeId::new(CONSENSUS_NODE_ID_MAX + 1).is_err());
        assert_eq!(
            serde_json::from_str::<ConsensusNodeId>("9")
                .expect("positive node ID")
                .get(),
            9
        );
    }

    #[test]
    fn derived_node_id_is_stable_across_membership_shapes() {
        let cluster = ConsensusClusterId::new("cluster-a").expect("cluster");
        let before = derive_node_id(cluster, b"replica-b").expect("node ID");

        let mut initial = [b"replica-a".as_slice(), b"replica-b".as_slice()]
            .into_iter()
            .map(|member| derive_node_id(cluster, member).expect("node ID"))
            .collect::<Vec<_>>();
        initial.sort_unstable();
        let mut expanded = [
            b"replica-0".as_slice(),
            b"replica-a".as_slice(),
            b"replica-b".as_slice(),
            b"replica-c".as_slice(),
        ]
        .into_iter()
        .map(|member| derive_node_id(cluster, member).expect("node ID"))
        .collect::<Vec<_>>();
        expanded.sort_unstable();

        assert_eq!(
            before,
            derive_node_id(cluster, b"replica-b").expect("node ID")
        );
        assert!(initial.contains(&before));
        assert!(expanded.contains(&before));
    }

    #[test]
    fn derived_node_id_is_cluster_scoped_and_input_bounded() {
        let first = derive_node_id(
            ConsensusClusterId::new("cluster-a").expect("cluster"),
            b"replica-a",
        )
        .expect("node ID");
        let second = derive_node_id(
            ConsensusClusterId::new("cluster-b").expect("cluster"),
            b"replica-a",
        )
        .expect("node ID");

        assert_ne!(first, second);
        assert!(first.get() <= CONSENSUS_NODE_ID_MAX);
        assert!(second.get() <= CONSENSUS_NODE_ID_MAX);
        assert_eq!(
            derive_node_id(ConsensusClusterId::new("cluster-a").expect("cluster"), b""),
            Err(ConsensusIdentityError::InvalidNodeId)
        );
        assert_eq!(
            derive_node_id(
                ConsensusClusterId::new("cluster-a").expect("cluster"),
                &vec![b'x'; CONSENSUS_MEMBER_ID_MAX_BYTES + 1]
            ),
            Err(ConsensusIdentityError::InvalidNodeId)
        );
    }
}
