//! Session state-machine commands built on the shared consensus substrate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSet, CompareAndSetResult};
use crate::error::StoreError;
use crate::fenced_transition::{FencedTransitionOutcome, FencedTransitionRequest};
use crate::lease::LeaseGuard;
use crate::model::{OwnerId, SessionKey};
use crate::record::StoredSessionRecord;

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
const FENCED_TRANSITION_VOTER_SET_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition-voter-set/v1\0";

/// Produce the canonical, non-describing binding of one exact voter scope.
///
/// The durable activation certificate stores this digest rather than a second
/// copy of membership descriptors.  The current scope remains authoritative
/// for the actual members, while this fixed-width value prevents a certificate
/// from being reused after a configuration or voter-set change.
pub(crate) fn fenced_transition_voter_set_digest(
    identity: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_VOTER_SET_DIGEST_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    for voter in voters {
        hasher.update(voter.get().to_be_bytes());
    }
    hasher.finalize().into()
}

/// Redacted fixed-width binding of one topology member's admitted identities.
///
/// The SDK persists only domain-separated fingerprints. Raw endpoints, TLS
/// identities, and backing-store identities never enter transition evidence
/// or diagnostic rendering.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTopologyMemberBinding {
    descriptor: [u8; 32],
    endpoint: [u8; 32],
    tls_identity: [u8; 32],
    backing_identity: [u8; 32],
}

impl SessionTopologyMemberBinding {
    pub(crate) const fn new(
        descriptor: [u8; 32],
        endpoint: [u8; 32],
        tls_identity: [u8; 32],
        backing_identity: [u8; 32],
    ) -> Self {
        Self {
            descriptor,
            endpoint,
            tls_identity,
            backing_identity,
        }
    }

    pub(crate) const fn descriptor(self) -> [u8; 32] {
        self.descriptor
    }

    pub(crate) const fn endpoint(self) -> [u8; 32] {
        self.endpoint
    }

    pub(crate) const fn tls_identity(self) -> [u8; 32] {
        self.tls_identity
    }

    pub(crate) const fn backing_identity(self) -> [u8; 32] {
        self.backing_identity
    }
}

impl fmt::Debug for SessionTopologyMemberBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTopologyMemberBinding(<redacted>)")
    }
}

/// High-level mutation submitted to the current consensus leader.
///
/// Allocation of fences, credentials, effective logical time, application
/// sequence, and the digest predecessor remains committed state-machine work
/// and cannot be chosen by an authenticated follower.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationIntent {
    /// Advance the persisted logical clock without changing session data.
    ///
    /// Consensus-backed reads use this barrier before evaluating TTLs so a
    /// leader failover cannot move observed time backwards and resurrect an
    /// expired lease or record.
    AdvanceLogicalTime,
    /// Compare and set one record under a fenced lease.
    ///
    /// The shared ownership is runtime-only: serde still emits exactly the
    /// wrapped operation.  It lets a forwarding request survive a proven
    /// before-transmission leader reroute without cloning sealed ciphertext.
    CompareAndSet(Arc<CompareAndSet>),
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
    /// SDK-internal quorum-durable binding of a caller-owned consumer request
    /// ID to one full request commitment.
    #[doc(hidden)]
    BindConsumerRequest {
        /// SHA-256 commitment to the complete typed consumer request.
        request_commitment: [u8; 32],
    },
    /// SDK-internal durable receipt for a consumer batch point read.
    ///
    /// A batch is retryable only if every slot has a stable durable outcome.
    /// The result is retained only in the consensus idempotency receipt and
    /// never becomes a replication entry or consumer-controlled replay API.
    #[doc(hidden)]
    ReadConsumerRecord {
        /// Key read at the command's committed logical time.
        key: SessionKey,
    },
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
    /// SDK-internal durable preparation for one exact topology transition.
    #[doc(hidden)]
    PrepareTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
        /// Exact successor cluster/configuration/epoch identity.
        desired_identity: SessionConsensusIdentity,
        /// Exact successor voter IDs.
        desired_members: BTreeSet<SessionConsensusNodeId>,
        /// Redacted exact descriptor and uniqueness bindings by voter ID.
        desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    },
    /// SDK-internal durable proof that every added learner caught up.
    #[doc(hidden)]
    MarkTopologyLearnersReady {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal authority cutover committed before joint consensus.
    #[doc(hidden)]
    FenceTopologyAuthority {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal rollback of a transition that never committed joint state.
    #[doc(hidden)]
    AbortTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal terminal marker after the desired uniform epoch commits.
    #[doc(hidden)]
    FinalizeTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal authenticated application-authority envelope.
    ///
    /// The consensus store constructs this only after authenticating the
    /// forwarding replica. Callers submit the enclosed mutation directly and
    /// cannot assert their own topology authority.
    #[doc(hidden)]
    Authorized {
        /// Authenticated logical origin of the application mutation.
        origin: SessionConsensusNodeId,
        /// Exact cluster/configuration/epoch authority that admitted `origin`.
        authority_identity: SessionConsensusIdentity,
        /// Original caller mutation. Nested authority or topology-control
        /// intents are rejected by the state machine.
        mutation: Box<SessionMutationIntent>,
    },
    /// Atomically acquire or renew one exact fence and mutate the same record.
    FencedTransition(Box<FencedTransitionRequest>),
    /// The first V1 fenced transition for one exact voter scope.
    ///
    /// This is intentionally an internal command shape rather than a separate
    /// admin request: its receipt, activation certificate, lease, and record
    /// effect commit at exactly the caller's one transition log position.
    #[doc(hidden)]
    ActivateFencedTransition {
        /// Original caller-owned transition.
        request: Box<FencedTransitionRequest>,
        /// Exact current authority scope observed during unanimous V1 proof.
        scope_identity: SessionConsensusIdentity,
        /// Canonical digest of the exact voter IDs in that scope.
        voter_set_digest: [u8; 32],
    },
}

impl fmt::Debug for SessionMutationIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionMutationIntent(<redacted>)")
    }
}

/// Application command carried by one normal Openraft log entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for SessionConsensusCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusCommand(<redacted>)")
    }
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationOutcome {
    /// Result of a compare-and-set command.
    CompareAndSet(CompareAndSetResult),
    /// Durable result of an SDK-internal consumer batch point read.
    #[doc(hidden)]
    ConsumerRecord(Option<StoredSessionRecord>),
    /// Lease allocated or renewed by the committed command.
    Lease(LeaseGuard),
    /// Mutation completed without a value result.
    Unit,
    /// Result of one atomic single-record fenced transition.
    FencedTransition(FencedTransitionOutcome),
}

impl fmt::Debug for SessionMutationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionMutationOutcome(<redacted>)")
    }
}

/// Persisted command outcome returned by Openraft client writes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for SessionConsensusResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusResponse(<redacted>)")
    }
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl<T> fmt::Debug for SessionConsensusRpc<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusRpc(<redacted>)")
    }
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
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    use super::*;
    use crate::{
        EncryptedSessionPayload, FenceToken, FencedTransitionLease, FencedTransitionMutation,
        FencedTransitionRequestId, Generation, OwnerId, SessionKeyType, StableId, StateClass,
        StateType, STABLE_ID_MAX_BYTES,
    };

    #[derive(Clone, Serialize, Deserialize)]
    enum LegacySessionMutationIntent684 {
        AdvanceLogicalTime,
        CompareAndSet(Box<CompareAndSet>),
        DeleteFenced(LeaseGuard),
        RefreshTtl {
            lease: LeaseGuard,
            ttl: Duration,
        },
        AcquireLease {
            key: SessionKey,
            owner: OwnerId,
            ttl: Duration,
        },
        RenewLease {
            lease: LeaseGuard,
            ttl: Duration,
        },
        ReleaseLease(LeaseGuard),
        BindConsumerRequest {
            request_commitment: [u8; 32],
        },
        ReadConsumerRecord {
            key: SessionKey,
        },
        FinalizeOperatorRecovery {
            recovery_epoch: u64,
            plan_digest: [u8; 32],
            fence_high_water: u64,
            credential_high_water: u64,
        },
        PrepareTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
            desired_identity: SessionConsensusIdentity,
            desired_members: BTreeSet<SessionConsensusNodeId>,
            desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        },
        MarkTopologyLearnersReady {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        FenceTopologyAuthority {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        AbortTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        FinalizeTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        Authorized {
            origin: SessionConsensusNodeId,
            authority_identity: SessionConsensusIdentity,
            mutation: Box<LegacySessionMutationIntent684>,
        },
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum LegacySessionMutationOutcome684 {
        CompareAndSet(CompareAndSetResult),
        ConsumerRecord(Option<StoredSessionRecord>),
        Lease(LeaseGuard),
        Unit,
    }

    fn assert_postcard_cross_decode<T, U>(label: &str, current: T, legacy: U)
    where
        T: Serialize + DeserializeOwned,
        U: Serialize + DeserializeOwned,
    {
        let current_bytes =
            opc_consensus::encode_bounded(&current).expect("current postcard encoding");
        let legacy_bytes =
            opc_consensus::encode_bounded(&legacy).expect("legacy postcard encoding");
        assert_eq!(current_bytes, legacy_bytes, "{label}: encoding changed");
        opc_consensus::decode_bounded::<U>(&current_bytes).expect("legacy decode of current bytes");
        opc_consensus::decode_bounded::<T>(&legacy_bytes).expect("current decode of legacy bytes");
    }

    fn legacy_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("legacy-postcard"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"legacy-key")).expect("stable ID"),
        }
    }

    fn legacy_time(seconds: i64) -> opc_types::Timestamp {
        opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds),
        )
    }

    fn legacy_lease(key: SessionKey, owner: OwnerId) -> LeaseGuard {
        LeaseGuard::new(
            key,
            owner,
            FenceToken::new(7),
            legacy_time(1),
            legacy_time(61),
            9,
        )
    }

    fn legacy_record(key: SessionKey, owner: OwnerId) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(3),
            owner,
            fence: FenceToken::new(7),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("legacy-state"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"legacy-payload"),
        }
    }

    fn legacy_identity() -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("legacy-cluster").expect("cluster"),
            SessionConsensusConfigurationId::from_bytes([0x41; 32]),
            SessionConsensusConfigurationEpoch::new(2).expect("epoch"),
        )
    }

    #[test]
    fn schema_v1_legacy_intent_and_outcome_postcard_parity() {
        let key = legacy_key();
        let owner = OwnerId::new("legacy-owner").expect("owner");
        let lease = legacy_lease(key.clone(), owner.clone());
        let record = legacy_record(key.clone(), owner.clone());
        let cas = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: record.clone(),
        };
        let identity = legacy_identity();
        let node = SessionConsensusNodeId::new(1).expect("node");
        let mut members = BTreeSet::new();
        members.insert(node);
        let mut bindings = BTreeMap::new();
        bindings.insert(
            node,
            SessionTopologyMemberBinding::new([1; 32], [2; 32], [3; 32], [4; 32]),
        );

        assert_postcard_cross_decode(
            "AdvanceLogicalTime",
            SessionMutationIntent::AdvanceLogicalTime,
            LegacySessionMutationIntent684::AdvanceLogicalTime,
        );
        assert_postcard_cross_decode(
            "CompareAndSet",
            SessionMutationIntent::CompareAndSet(Arc::new(cas.clone())),
            LegacySessionMutationIntent684::CompareAndSet(Box::new(cas)),
        );
        assert_postcard_cross_decode(
            "DeleteFenced",
            SessionMutationIntent::DeleteFenced(lease.clone()),
            LegacySessionMutationIntent684::DeleteFenced(lease.clone()),
        );
        assert_postcard_cross_decode(
            "RefreshTtl",
            SessionMutationIntent::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "AcquireLease",
            SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "RenewLease",
            SessionMutationIntent::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "ReleaseLease",
            SessionMutationIntent::ReleaseLease(lease.clone()),
            LegacySessionMutationIntent684::ReleaseLease(lease.clone()),
        );
        assert_postcard_cross_decode(
            "BindConsumerRequest",
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: [5; 32],
            },
            LegacySessionMutationIntent684::BindConsumerRequest {
                request_commitment: [5; 32],
            },
        );
        assert_postcard_cross_decode(
            "ReadConsumerRecord",
            SessionMutationIntent::ReadConsumerRecord { key: key.clone() },
            LegacySessionMutationIntent684::ReadConsumerRecord { key: key.clone() },
        );
        assert_postcard_cross_decode(
            "FinalizeOperatorRecovery",
            SessionMutationIntent::FinalizeOperatorRecovery {
                recovery_epoch: 4,
                plan_digest: [6; 32],
                fence_high_water: 7,
                credential_high_water: 8,
            },
            LegacySessionMutationIntent684::FinalizeOperatorRecovery {
                recovery_epoch: 4,
                plan_digest: [6; 32],
                fence_high_water: 7,
                credential_high_water: 8,
            },
        );
        assert_postcard_cross_decode(
            "PrepareTopologyTransition",
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: [9; 16],
                request_digest: [10; 32],
                desired_identity: identity,
                desired_members: members.clone(),
                desired_bindings: bindings.clone(),
            },
            LegacySessionMutationIntent684::PrepareTopologyTransition {
                transition_id: [9; 16],
                request_digest: [10; 32],
                desired_identity: identity,
                desired_members: members,
                desired_bindings: bindings,
            },
        );
        assert_postcard_cross_decode(
            "MarkTopologyLearnersReady",
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: [11; 16],
                request_digest: [12; 32],
            },
            LegacySessionMutationIntent684::MarkTopologyLearnersReady {
                transition_id: [11; 16],
                request_digest: [12; 32],
            },
        );
        assert_postcard_cross_decode(
            "FenceTopologyAuthority",
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id: [13; 16],
                request_digest: [14; 32],
            },
            LegacySessionMutationIntent684::FenceTopologyAuthority {
                transition_id: [13; 16],
                request_digest: [14; 32],
            },
        );
        assert_postcard_cross_decode(
            "AbortTopologyTransition",
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: [15; 16],
                request_digest: [16; 32],
            },
            LegacySessionMutationIntent684::AbortTopologyTransition {
                transition_id: [15; 16],
                request_digest: [16; 32],
            },
        );
        assert_postcard_cross_decode(
            "FinalizeTopologyTransition",
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: [17; 16],
                request_digest: [18; 32],
            },
            LegacySessionMutationIntent684::FinalizeTopologyTransition {
                transition_id: [17; 16],
                request_digest: [18; 32],
            },
        );
        assert_postcard_cross_decode(
            "Authorized",
            SessionMutationIntent::Authorized {
                origin: node,
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
            },
            LegacySessionMutationIntent684::Authorized {
                origin: node,
                authority_identity: identity,
                mutation: Box::new(LegacySessionMutationIntent684::AdvanceLogicalTime),
            },
        );

        assert_postcard_cross_decode(
            "Outcome::CompareAndSet",
            SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success),
            LegacySessionMutationOutcome684::CompareAndSet(CompareAndSetResult::Success),
        );
        assert_postcard_cross_decode(
            "Outcome::ConsumerRecord",
            SessionMutationOutcome::ConsumerRecord(None),
            LegacySessionMutationOutcome684::ConsumerRecord(None),
        );
        assert_postcard_cross_decode(
            "Outcome::Lease",
            SessionMutationOutcome::Lease(lease),
            LegacySessionMutationOutcome684::Lease(legacy_lease(key, owner)),
        );
        assert_postcard_cross_decode(
            "Outcome::Unit",
            SessionMutationOutcome::Unit,
            LegacySessionMutationOutcome684::Unit,
        );
    }

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

    #[test]
    fn consensus_command_and_response_debug_are_non_identifying() {
        let key = SessionKey {
            tenant: TenantId::from_static("debug-secret-tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"debug-secret-key")).expect("stable ID"),
        };
        let owner = OwnerId::new("debug-secret-owner").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0xA7; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("debug-secret-type"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(b"debug-secret-payload"),
            }),
        )
        .expect("transition request");
        let logical_time = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_234_567),
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: SessionConsensusIdentity::new(
                SessionConsensusClusterId::new("debug-secret-cluster").expect("cluster"),
                SessionConsensusConfigurationId::from_bytes([0xA8; 32]),
                SessionConsensusConfigurationEpoch::new(7).expect("epoch"),
            ),
            request_id: SessionConsensusRequestId::from_bytes([0xA7; 16]),
            logical_time,
            intent: SessionMutationIntent::FencedTransition(Box::new(request)),
        };
        let response = SessionConsensusResponse {
            result: Err(StoreError::BackendUnavailable(
                "debug-secret-diagnostic".into(),
            )),
            sequence: 9,
            digest: Some(SessionConsensusEntryDigest::from_bytes([0xA9; 32])),
            logical_time: Some(logical_time),
            raft_log_index: 10,
        };

        assert_eq!(
            format!("{command:?}"),
            "SessionConsensusCommand(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", command.intent),
            "SessionMutationIntent(<redacted>)"
        );
        assert_eq!(
            format!("{response:?}"),
            "SessionConsensusResponse(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", SessionMutationOutcome::Unit),
            "SessionMutationOutcome(<redacted>)"
        );
        let rpc = SessionConsensusRpc::new(
            command.identity,
            SessionConsensusNodeId::new(3).expect("sender"),
            b"debug-secret-rpc".to_vec(),
        );
        assert_eq!(format!("{rpc:?}"), "SessionConsensusRpc(<redacted>)");
        for secret in [
            "debug-secret",
            "1234567",
            "A7",
            "A8",
            "A9",
            "ConsensusIdentity",
        ] {
            assert!(!format!("{command:?}{response:?}{rpc:?}").contains(secret));
        }
    }
}
