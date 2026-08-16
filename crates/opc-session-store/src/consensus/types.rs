//! Session state-machine commands built on the shared consensus substrate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSet, CompareAndSetResult};
use crate::consumer::validate_compare_and_set_profile;
use crate::error::StoreError;
use crate::lease::{validate_lease_guard_profile, LeaseGuard};
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

/// Admission revision decoded for commands written before strict payload
/// admission was introduced. It is never emitted by current leaders.
pub(crate) const SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY: u8 = 0;

/// Admission revision emitted by current leaders and required for every new
/// command. Legacy revision zero is accepted only below the separately
/// durable historical activation watermark.
pub(crate) const SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT: u8 = 1;

/// Fixed idempotency key for the replicated admission-cutover marker. Keeping
/// it SDK-internal and constant prevents an arbitrary marker-shaped command
/// from moving or colliding with the durable boundary.
pub(crate) const SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID: [u8; 16] = [0x43; 16];

/// Canonical logical time for the fixed admission-cutover command.
///
/// The marker is retried with one fixed request ID across leaders. Its full
/// command digest must therefore be byte-identical regardless of wall-clock
/// time or the logical clock observed by the proposing node.
pub(crate) fn command_admission_cutover_logical_time() -> opc_types::Timestamp {
    opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH)
}

/// Identify the public command shape reserved for the strict-admission
/// cutover before its canonical logical time and private durable revision are
/// attached by the local leader.
pub(crate) fn is_command_admission_cutover_request(
    request_id: SessionConsensusRequestId,
    intent: &SessionMutationIntent,
) -> bool {
    request_id.as_bytes() == &SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID
        && matches!(intent, SessionMutationIntent::AdvanceLogicalTime)
}

/// Maximum accepted byte length of a caller-supplied cluster name.
pub const SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES: usize =
    opc_consensus::CONSENSUS_CLUSTER_ID_MAX_BYTES;

const COMMAND_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command/v1\0";
const COMMAND_RESULT_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command-result/v2\0";

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
}

/// Validate one unwrapped mutation's time-independent semantic profile.
///
/// This is shared by leader preproposal and follower log admission. It never
/// reads lease state, so fence freshness, credential ownership, and record
/// conflicts remain deterministic state-machine checks.
pub(crate) fn validate_mutation_intent_profile(
    intent: &SessionMutationIntent,
) -> Result<(), StoreError> {
    match intent {
        SessionMutationIntent::CompareAndSet(op) => validate_compare_and_set_profile(op),
        SessionMutationIntent::DeleteFenced(lease) | SessionMutationIntent::ReleaseLease(lease) => {
            validate_lease_guard_profile(lease)
        }
        SessionMutationIntent::RefreshTtl { lease, ttl }
        | SessionMutationIntent::RenewLease { lease, ttl } => {
            validate_lease_guard_profile(lease)?;
            crate::validate_session_ttl(*ttl)
        }
        SessionMutationIntent::AcquireLease { ttl, .. } => crate::validate_session_ttl(*ttl),
        SessionMutationIntent::PrepareTopologyTransition {
            desired_identity,
            desired_members,
            desired_bindings,
            ..
        } => {
            if i64::try_from(desired_identity.configuration_epoch().get()).is_err()
                || desired_members
                    .iter()
                    .any(|node| i64::try_from(node.get()).is_err())
                || desired_bindings
                    .keys()
                    .any(|node| i64::try_from(node.get()).is_err())
            {
                return Err(StoreError::InvalidKey(
                    "topology transition exceeds consensus storage bounds".into(),
                ));
            }
            Ok(())
        }
        SessionMutationIntent::AdvanceLogicalTime
        | SessionMutationIntent::BindConsumerRequest { .. }
        | SessionMutationIntent::ReadConsumerRecord { .. }
        | SessionMutationIntent::FinalizeOperatorRecovery { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::Authorized { .. } => Ok(()),
    }
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

    /// Calculate the application-chain digest for a command written by the
    /// current SDK, including the exact deterministic result and committed
    /// log position.
    ///
    /// This models the SDK's private current admission revision, so public
    /// callers can reproduce a current [`SessionConsensusResponse::digest`]
    /// without exposing that internal representation. To verify a retained
    /// pre-cutover command, use [`Self::calculate_applied_digest`], whose
    /// command-only input remains byte-for-byte compatible with that history.
    pub fn calculate_applied_result_digest(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
        raft_log_index: u64,
        result: &Result<SessionMutationOutcome, StoreError>,
    ) -> Result<SessionConsensusEntryDigest, StoreError> {
        DurableSessionConsensusCommand::current(self.clone()).calculate_applied_result_digest(
            sequence,
            previous_digest,
            effective_logical_time,
            raft_log_index,
            result,
        )
    }
}

/// Crate-private Openraft payload that records the payload-admission revision
/// without changing `SessionConsensusCommand`'s stable public Rust shape.
///
/// The command is flattened first to keep historical log JSON decodable. A
/// missing trailing revision is the frozen legacy representation; current
/// leaders always emit the current revision. This wrapper is deliberately not
/// re-exported: applications construct and serialize the public command shape
/// they used before strict admission was introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableSessionConsensusCommand {
    command: SessionConsensusCommand,
    admission_revision: u8,
}

/// JSON compatibility view for the private durable command wrapper.
///
/// `serde(flatten)` is intentionally confined to human-readable formats:
/// postcard cannot size a flattened map, while existing log and receipt JSON
/// must retain its historical flattened representation.
#[derive(Serialize)]
struct HumanReadableDurableSessionConsensusCommandRef<'a> {
    #[serde(flatten)]
    command: &'a SessionConsensusCommand,
    admission_revision: u8,
}

/// Owned JSON compatibility view for the private durable command wrapper.
#[derive(Deserialize)]
struct HumanReadableDurableSessionConsensusCommand {
    #[serde(flatten)]
    command: SessionConsensusCommand,
    #[serde(default)]
    admission_revision: u8,
}

impl Serialize for DurableSessionConsensusCommand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            return HumanReadableDurableSessionConsensusCommandRef {
                command: &self.command,
                admission_revision: self.admission_revision,
            }
            .serialize(serializer);
        }

        // Postcard requires a statically known sequence length. A tuple keeps
        // the private binary Openraft payload fixed-length while the command
        // itself retains its existing derived binary representation.
        (&self.command, self.admission_revision).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DurableSessionConsensusCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let HumanReadableDurableSessionConsensusCommand {
                command,
                admission_revision,
            } = HumanReadableDurableSessionConsensusCommand::deserialize(deserializer)?;
            return Ok(Self {
                command,
                admission_revision,
            });
        }

        let (command, admission_revision) =
            <(SessionConsensusCommand, u8)>::deserialize(deserializer)?;
        Ok(Self {
            command,
            admission_revision,
        })
    }
}

impl DurableSessionConsensusCommand {
    pub(crate) fn legacy(command: SessionConsensusCommand) -> Self {
        Self {
            command,
            admission_revision: SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY,
        }
    }

    pub(crate) fn current(command: SessionConsensusCommand) -> Self {
        Self {
            command,
            admission_revision: SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT,
        }
    }

    pub(crate) const fn admission_revision(&self) -> u8 {
        self.admission_revision
    }

    pub(crate) fn is_command_admission_cutover(&self) -> bool {
        self.admission_revision == SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            && is_command_admission_cutover_request(self.command.request_id, &self.command.intent)
            && self.command.logical_time == command_admission_cutover_logical_time()
    }

    pub(crate) fn calculate_applied_result_digest(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
        raft_log_index: u64,
        result: &Result<SessionMutationOutcome, StoreError>,
    ) -> Result<SessionConsensusEntryDigest, StoreError> {
        if self.admission_revision == SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY {
            return self.command.calculate_applied_digest(
                sequence,
                previous_digest,
                effective_logical_time,
            );
        }
        let encoded = serde_json::to_vec(&(
            sequence,
            previous_digest,
            effective_logical_time,
            raft_log_index,
            self,
            result,
        ))
        .map_err(|_| {
            StoreError::Serialization("session consensus command result encoding failed".into())
        })?;
        let mut hasher = Sha256::new();
        hasher.update(COMMAND_RESULT_DIGEST_DOMAIN);
        hasher.update(encoded);
        Ok(SessionConsensusEntryDigest::from_bytes(
            hasher.finalize().into(),
        ))
    }
}

impl Deref for DurableSessionConsensusCommand {
    type Target = SessionConsensusCommand;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

impl DerefMut for DurableSessionConsensusCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.command
    }
}

/// Successful state-machine result returned after durable quorum commit and
/// local application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// Persisted command outcome returned by Openraft client writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusResponse {
    /// Deterministic state-machine result. Errors are persisted so an exact
    /// retry returns the original outcome after restart or leader failover.
    pub result: Result<SessionMutationOutcome, StoreError>,
    /// Committed application sequence when admitted, or zero for a rejection.
    pub sequence: u64,
    /// Digest binding the admitted application outcome.
    ///
    /// Current commands bind the predecessor chain position, effective
    /// logical time, Raft log index, private durable command representation,
    /// and deterministic result. Retained pre-cutover commands preserve their
    /// historical command-only digest.
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
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

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

    #[test]
    fn public_command_shape_and_digest_contract_remain_compatible() {
        let identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("public-command-compat").expect("cluster ID"),
            SessionConsensusConfigurationId::from_bytes([0x71; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([0x72; 16]),
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        };
        let frozen_public_json = serde_json::to_vec(&command).expect("encode public command");
        let decoded_legacy: DurableSessionConsensusCommand =
            serde_json::from_slice(&frozen_public_json).expect("decode frozen public command");
        assert_eq!(
            SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY,
            decoded_legacy.admission_revision(),
            "a missing internal revision remains legacy history"
        );
        assert_eq!(command, *decoded_legacy);
        let current = DurableSessionConsensusCommand::current(command.clone());
        let mut expected_current_json = frozen_public_json.clone();
        assert_eq!(Some(b'}'), expected_current_json.pop());
        expected_current_json.extend_from_slice(b",\"admission_revision\":1}");
        assert_eq!(
            expected_current_json,
            serde_json::to_vec(&current).expect("encode current durable command"),
            "current JSON retains the flattened command representation"
        );
        let decoded_current_json: DurableSessionConsensusCommand =
            serde_json::from_slice(&expected_current_json)
                .expect("decode current durable command JSON");
        assert_eq!(current, decoded_current_json);
        let encoded_current =
            opc_consensus::encode_bounded(&current).expect("encode current durable command");
        let decoded_current: DurableSessionConsensusCommand =
            opc_consensus::decode_bounded(&encoded_current)
                .expect("decode current durable command");
        assert_eq!(
            current, decoded_current,
            "postcard round-trips current commands"
        );
        let legacy_encoded = serde_json::to_vec(&(
            1_u64,
            SessionConsensusEntryDigest::GENESIS,
            command.logical_time,
            &command,
        ))
        .expect("encode frozen public command");
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(COMMAND_DIGEST_DOMAIN);
        legacy_hasher.update(legacy_encoded);
        assert_eq!(
            SessionConsensusEntryDigest::from_bytes(legacy_hasher.finalize().into()),
            command
                .calculate_applied_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    command.logical_time,
                )
                .expect("calculate frozen public digest"),
            "the legacy public command JSON is the command-only digest input"
        );

        let result = Ok(SessionMutationOutcome::Unit);
        assert_eq!(
            current
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    command.logical_time,
                    7,
                    &result,
                )
                .expect("calculate durable current digest"),
            command
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    command.logical_time,
                    7,
                    &result,
                )
                .expect("calculate public current digest"),
            "public callers can reproduce a current response digest"
        );

        // This deliberately exhaustive match is a compile-time regression
        // test: adding another public variant or a hidden cutover variant
        // breaks callers that exhaustively match this stable enum.
        match command.intent {
            SessionMutationIntent::AdvanceLogicalTime
            | SessionMutationIntent::CompareAndSet(_)
            | SessionMutationIntent::DeleteFenced(_)
            | SessionMutationIntent::RefreshTtl { .. }
            | SessionMutationIntent::AcquireLease { .. }
            | SessionMutationIntent::RenewLease { .. }
            | SessionMutationIntent::ReleaseLease(_)
            | SessionMutationIntent::BindConsumerRequest { .. }
            | SessionMutationIntent::ReadConsumerRecord { .. }
            | SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | SessionMutationIntent::PrepareTopologyTransition { .. }
            | SessionMutationIntent::MarkTopologyLearnersReady { .. }
            | SessionMutationIntent::FenceTopologyAuthority { .. }
            | SessionMutationIntent::AbortTopologyTransition { .. }
            | SessionMutationIntent::FinalizeTopologyTransition { .. }
            | SessionMutationIntent::Authorized { .. } => {}
        }
    }
}
