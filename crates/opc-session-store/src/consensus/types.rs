//! Session state-machine commands built on the shared consensus substrate.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSet, CompareAndSetResult};
use crate::error::StoreError;
use crate::lease::LeaseGuard;
use crate::model::{OwnerId, SessionKey};

pub use opc_consensus::{
    ConsensusClusterId as SessionConsensusClusterId,
    ConsensusConfigurationEpoch as SessionConsensusConfigurationEpoch,
    ConsensusConfigurationId as SessionConsensusConfigurationId,
    ConsensusEntryDigest as SessionConsensusEntryDigest,
    ConsensusIdentity as SessionConsensusIdentity,
    ConsensusIdentityError as SessionConsensusIdentityError,
    ConsensusNodeId as SessionConsensusNodeId, ConsensusRequestId as SessionConsensusRequestId,
};

/// Current durable command and consensus-RPC schema.
pub const SESSION_CONSENSUS_SCHEMA_VERSION: u16 = opc_consensus::CONSENSUS_SCHEMA_VERSION;

/// Maximum accepted byte length of a caller-supplied cluster name.
pub const SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES: usize =
    opc_consensus::CONSENSUS_CLUSTER_ID_MAX_BYTES;

const COMMAND_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command/v1\0";

/// High-level mutation submitted to the current consensus leader.
///
/// Allocation of fences, credentials, effective logical time, application
/// sequence, and the digest predecessor remains committed state-machine work
/// and cannot be chosen by an authenticated follower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationIntent {
    /// Advance the persisted logical clock without changing session data.
    ///
    /// Consensus-backed reads use this barrier before evaluating TTLs so a
    /// leader failover cannot move observed time backwards and resurrect an
    /// expired lease or record.
    AdvanceLogicalTime,
    /// Compare and set one record under a fenced lease.
    CompareAndSet(Box<CompareAndSet>),
    /// Delete one record under a fenced lease.
    DeleteFenced(LeaseGuard),
    /// Refresh a record TTL under a fenced lease.
    RefreshTtl {
        /// Existing fenced lease.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Acquire a new lease and allocate the next fence/credential pair.
    AcquireLease {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Renew an existing lease.
    RenewLease {
        /// Existing fenced lease.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Release an existing lease.
    ReleaseLease(LeaseGuard),
    /// SDK-internal operator recovery fence committed only through the local
    /// leader's authorized admin boundary.
    #[doc(hidden)]
    FinalizeOperatorRecovery {
        /// Monotonic operator recovery epoch.
        recovery_epoch: u64,
        /// Digest of the exact inspected and confirmed recovery plan.
        plan_digest: [u8; 32],
        /// Highest fence observed across every inspected replica.
        fence_high_water: u64,
        /// Highest credential ID observed across every inspected replica.
        credential_high_water: u64,
    },
}

/// Application command carried by one normal Openraft log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusCommand {
    /// Exact durable command schema.
    pub schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub identity: SessionConsensusIdentity,
    /// Durable request identity used for idempotent outcome lookup.
    pub request_id: SessionConsensusRequestId,
    /// Leader-observed time carried as deterministic command input. The state
    /// machine takes the maximum of this value and its last committed logical
    /// time, so an in-flight proposal or clock rollback cannot regress expiry.
    pub logical_time: opc_types::Timestamp,
    /// High-level deterministic mutation.
    pub intent: SessionMutationIntent,
}

impl SessionConsensusCommand {
    /// Calculate the domain-separated digest of the committed application
    /// chain position and its command.
    pub fn calculate_applied_digest(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
    ) -> Result<SessionConsensusEntryDigest, StoreError> {
        let encoded =
            serde_json::to_vec(&(sequence, previous_digest, effective_logical_time, self))
                .map_err(|_| {
                    StoreError::Serialization("session consensus command encoding failed".into())
                })?;
        let mut hasher = Sha256::new();
        hasher.update(COMMAND_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(SessionConsensusEntryDigest::from_bytes(
            hasher.finalize().into(),
        ))
    }
}

/// Successful state-machine result returned after durable quorum commit and
/// local application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationOutcome {
    /// Result of a compare-and-set command.
    CompareAndSet(CompareAndSetResult),
    /// Lease allocated or renewed by the committed command.
    Lease(LeaseGuard),
    /// Mutation completed without a value result.
    Unit,
}

/// Persisted command outcome returned by Openraft client writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusResponse {
    /// Deterministic state-machine result. Errors are persisted so an exact
    /// retry returns the original outcome after restart or leader failover.
    pub result: Result<SessionMutationOutcome, StoreError>,
    /// Committed application sequence when admitted, or zero for a rejection.
    pub sequence: u64,
    /// Digest of the admitted application command.
    pub digest: Option<SessionConsensusEntryDigest>,
    /// Persisted logical time at which the original request was applied.
    /// Exact retries recover this value even after leader failover.
    pub logical_time: Option<opc_types::Timestamp>,
    /// Original Openraft log index that durably applied this request.
    /// Followers use it to wait for their local state machine before reading.
    pub raft_log_index: u64,
}

impl SessionConsensusResponse {
    /// Construct a failed response that made no application-sequence advance.
    pub fn rejected(error: StoreError) -> Self {
        Self {
            result: Err(error),
            sequence: 0,
            digest: None,
            logical_time: None,
            raft_log_index: 0,
        }
    }
}

/// Typed in-process envelope used before conversion to the shared bounded wire
/// request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusRpc<T> {
    /// Exact consensus schema.
    pub schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub identity: SessionConsensusIdentity,
    /// Canonical sender ordinal.
    pub sender: SessionConsensusNodeId,
    /// Private engine RPC or SDK-owned forwarded request.
    pub payload: T,
}

impl<T> SessionConsensusRpc<T> {
    /// Bind a payload to the current consensus scope.
    pub const fn new(
        identity: SessionConsensusIdentity,
        sender: SessionConsensusNodeId,
        payload: T,
    ) -> Self {
        Self {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            sender,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    use super::*;
    use crate::{OwnerId, SessionKeyType, StableId, STABLE_ID_MAX_BYTES};

    #[test]
    fn consensus_intent_serde_enforces_stable_id_before_admission() {
        let key = SessionKey {
            tenant: TenantId::from_static("consensus-stable-id-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from(vec![0xa5; STABLE_ID_MAX_BYTES]))
                .expect("maximum stable ID"),
        };
        let intent = SessionMutationIntent::AcquireLease {
            key,
            owner: OwnerId::new("owner-a").expect("owner"),
            ttl: Duration::from_secs(60),
        };
        let valid = serde_json::to_value(intent).expect("valid intent");

        for (width, accepted) in [
            (0, false),
            (1, true),
            (STABLE_ID_MAX_BYTES, true),
            (STABLE_ID_MAX_BYTES + 1, false),
        ] {
            let mut wire = valid.clone();
            wire["AcquireLease"]["key"]["stable_id"] = serde_json::json!(vec![0xa5_u8; width]);
            let decoded = serde_json::from_value::<SessionMutationIntent>(wire);
            assert_eq!(decoded.is_ok(), accepted, "stable ID width {width}");
            if let Err(error) = decoded {
                assert!(!error.to_string().contains("165"));
            }
        }
    }
}
