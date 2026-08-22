//! Session state-machine commands built on the shared consensus substrate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSet, CompareAndSetResult};
use crate::error::StoreError;
use crate::fenced_transition::{
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2Request,
};
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
const COMMAND_V2_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command/v2-fixed\0";
const COMMAND_V2_DIGEST_MAGIC: &[u8] = b"OPC-SC-V2-APPLIED\0";
/// Fixed V2 applied-command digest encoding revision.
///
/// This applies only to commands which carry a V2 intent (directly or in the
/// one permitted [`SessionMutationIntent::Authorized`] envelope). Older
/// commands retain their byte-for-byte JSON digest encoding.
pub const SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION: u16 = 2;
/// Frozen descriptor of V2's fixed applied-command digest input.
///
/// The V2 fenced-transition profile must bind this descriptor: changing any
/// tag, width, field order, or domain changes the replicated digest chain.
pub const SESSION_CONSENSUS_V2_APPLIED_DIGEST_SCHEMA_DESCRIPTOR: &str = concat!(
    "domain=openpacketcore/session-consensus/command/v2-fixed\\0;",
    "magic=OPC-SC-V2-APPLIED\\0;revision:u16be=2;",
    "prefix=sequence:u64be|previous-digest:bytes32|effective-time:timestamp;",
    "command=schema:u16be|storage-identity:identity|outer-id:bytes16|logical-time:timestamp|intent;",
    "timestamp=unix-secs:i64be|nanos:u32be;identity=cluster:bytes32|configuration:bytes32|epoch:u64be;",
    "intent=fenced-v2(tag=1,id:bytes56)|activate-v2(tag=2,id:bytes56,scope:identity,voters:bytes32,profile:bytes32)|",
    "maintain-v2(tag=3,generation:u64be,active:option-tag-u8+epoch:u64be,retired:u64be,bound:u64be)|",
    "authorized(tag=4,origin:u64be,authority:identity,mutation:intent)|",
    "fenced-v2-batch(tag=5,count:u16be,items:ordered-full-id:bytes56)"
);
/// Frozen Postcard command-wire shape for V2 replicated intents.
///
/// Normal Openraft payloads and peer forwarding retain the generic bounded
/// Postcard codec. These appended intent discriminants are therefore profile
/// material in addition to the fixed applied-digest encoding.
pub const SESSION_CONSENSUS_V2_COMMAND_WIRE_SCHEMA_DESCRIPTOR: &str = concat!(
    "wire-profile=1;raft-rpc-codec=postcard;durable-log-codec=serde-json;",
    "command-fields=schema-version,identity,request-id,logical-time,intent;",
    "intent-discriminants=authorized:15|fenced-v1:16|activate-v1:17|",
    "fenced-v2:18|activate-v2:19|maintain-v2:20|fenced-v2-batch:21;",
    "postcard=derive-serde,struct-fields-declaration-order,enum-tags=varint;",
    "json=derive-serde,struct-field-names-declaration-order,enum-names-exact;",
    "fenced-v2=box(request-fields=request-id:epoch:u64,nonce:bytes16,commitment:bytes32|lease|mutation);",
    "lease-discriminants=acquire:0(key,owner,fence,ttl)|renew:1(guard,ttl);",
    "mutation-discriminants=create:0(record)|update:1(generation,record)|delete:2(generation)|refresh-ttl:3(generation,ttl);",
    "activate-v2=box(request)|scope:identity|voters:bytes32|profile:bytes32;",
    "maintain-v2=generation:u64|active:option(epoch:u64)|retired:u64|bound:u64;",
    "fenced-v2-batch=vec(request-fields=request-id:epoch:u64,nonce:bytes16,commitment:bytes32|lease|mutation),",
    "count=1..=256,ordered,unique-full-ids,single-history-epoch,postcard-bytes<=1048576,",
    "outer-id=sha256(domain=openpacketcore/session-consensus/fenced-transition/v2/batch/outer-id/v1\\0,",
    "count:u16be,ordered-full-ids:bytes56)[0..16];",
    "authorized=origin:node-id|authority:identity|box(intent)"
);
const FENCED_TRANSITION_VOTER_SET_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition-voter-set/v1\0";
const FENCED_TRANSITION_V2_BATCH_OUTER_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition/v2/batch/outer-id/v1\0";

/// Maximum ordered V2 transitions admitted by one replicated batch command.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS: usize = 256;

/// Maximum fully Postcard-encoded V2 batch request bytes.
///
/// This leaves one MiB of deterministic command-envelope headroom beneath
/// the existing two MiB consensus RPC ceiling.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES: usize = 1024 * 1024;

/// Maximum fully Postcard-encoded V2 batch outcome bytes.
///
/// The same fixed cap keeps a complete correlated outcome vector within the
/// existing consensus response and consumer frame profiles.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES: usize = 1024 * 1024;

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
    /// Atomically apply one V2 fenced transition.
    ///
    /// This is deliberately a distinct replicated intent rather than a V1
    /// command selected by local apply state.  Every replica therefore applies
    /// the fixed V2 receipt/history semantics encoded by this log entry.
    FencedTransitionV2(Box<FencedTransitionV2Request>),
    /// The first V2 fenced transition for one exact voter scope and immutable
    /// V2 history profile.
    ///
    /// The activation certificate, exact request receipt, and transition
    /// effect are one replicated command.  `profile_digest` binds the fixed
    /// V2 schema and limits that all voters freshly confirmed before proposal.
    #[doc(hidden)]
    ActivateFencedTransitionV2 {
        /// Original caller-owned V2 transition.
        request: Box<FencedTransitionV2Request>,
        /// Exact current authority scope observed during unanimous V2 proof.
        scope_identity: SessionConsensusIdentity,
        /// Canonical digest of the exact voter IDs in that scope.
        voter_set_digest: [u8; 32],
        /// Digest of V2's fixed serialized schema and history limits.
        profile_digest: [u8; 32],
    },
    /// SDK-internal bounded V2 receipt-history maintenance.
    ///
    /// This is an explicit replicated maintenance command with compare-and-set
    /// state, never a local compaction side effect.  Only the existing local
    /// operator-recovery authority may submit it.
    #[doc(hidden)]
    MaintainFencedTransitionV2History {
        /// Durable V2 history generation observed before maintenance admission.
        expected_generation: u64,
        /// Active V2 history epoch observed before maintenance admission.
        expected_active_epoch: Option<FencedTransitionV2HistoryEpoch>,
        /// Highest permanently retired V2 history epoch observed before
        /// maintenance admission.
        expected_retired_through: u64,
        /// Number of bound receipts observed in the active epoch before
        /// maintenance admission. This makes the maintenance CAS fail closed
        /// if a concurrently committed V2 request filled or extended the
        /// active epoch without changing the lifecycle generation.
        expected_bound_entries: u64,
    },
    /// Coalesce an ordered, same-epoch batch of independent V2 fenced
    /// transitions into one replicated command.
    ///
    /// Each item retains its complete self-authenticating 56-byte request ID.
    /// The store layer derives the command's outer id from those ordered full
    /// IDs; this replicated vocabulary deliberately never truncates or
    /// replaces them with a batch-local identity. One physical log entry is a
    /// throughput optimization only: items have independent logical effects,
    /// results, and singleton status identities. This is not an inter-item
    /// conditional or all-or-nothing distributed transaction.
    FencedTransitionV2Batch(Vec<FencedTransitionV2Request>),
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
        let (domain, encoded) = if self.intent.contains_fenced_transition_v2() {
            (
                COMMAND_V2_DIGEST_DOMAIN,
                self.encode_v2_applied_digest_input(
                    sequence,
                    previous_digest,
                    effective_logical_time,
                )?,
            )
        } else {
            (
                COMMAND_DIGEST_DOMAIN,
                serde_json::to_vec(&(sequence, previous_digest, effective_logical_time, self))
                    .map_err(|_| {
                        StoreError::Serialization(
                            "session consensus command encoding failed".into(),
                        )
                    })?,
            )
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(encoded);
        Ok(SessionConsensusEntryDigest::from_bytes(
            hasher.finalize().into(),
        ))
    }

    fn encode_v2_applied_digest_input(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
    ) -> Result<Vec<u8>, StoreError> {
        let mut encoded = Vec::with_capacity(256);
        encoded.extend_from_slice(COMMAND_V2_DIGEST_MAGIC);
        encoded
            .extend_from_slice(&SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION.to_be_bytes());
        encoded.extend_from_slice(&sequence.to_be_bytes());
        encoded.extend_from_slice(previous_digest.as_bytes());
        append_v2_applied_timestamp(&mut encoded, effective_logical_time);
        encoded.extend_from_slice(&self.schema_version.to_be_bytes());
        append_v2_applied_identity(&mut encoded, self.identity);
        encoded.extend_from_slice(self.request_id.as_bytes());
        append_v2_applied_timestamp(&mut encoded, self.logical_time);
        append_v2_applied_intent(&mut encoded, &self.intent)?;
        Ok(encoded)
    }
}

impl SessionMutationIntent {
    fn contains_fenced_transition_v2(&self) -> bool {
        matches!(
            self,
            Self::FencedTransitionV2(_)
                | Self::FencedTransitionV2Batch(_)
                | Self::ActivateFencedTransitionV2 { .. }
                | Self::MaintainFencedTransitionV2History { .. }
        ) || matches!(self, Self::Authorized { mutation, .. } if mutation.contains_fenced_transition_v2())
    }
}

/// Validate the fixed V2 batch request profile before a command can have an
/// effect.
///
/// The full vector is encoded with the same bounded Postcard codec used by
/// consensus transport.  This intentionally measures the whole encoded input
/// rather than summing estimates of nested request bodies.
pub(crate) fn validate_fenced_transition_v2_batch(
    requests: &[FencedTransitionV2Request],
) -> Result<(), StoreError> {
    if requests.is_empty() || requests.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
        return Err(StoreError::InvalidKey(
            "fenced_transition_v2_batch_count_invalid".into(),
        ));
    }
    let epoch = requests[0].request_id().epoch();
    let mut ids = BTreeSet::new();
    for request in requests {
        // Retain an otherwise structurally valid substituted body for
        // deterministic request-conflict handling, matching singleton V2.
        match request.validate() {
            Ok(()) | Err(StoreError::FencedTransitionRequestConflict) => {}
            Err(error) => return Err(error),
        }
        if request.request_id().epoch() != epoch {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_epoch_mismatch".into(),
            ));
        }
        if !ids.insert(request.request_id().to_bytes()) {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_duplicate_request_id".into(),
            ));
        }
    }
    validate_fenced_transition_v2_batch_encoded_bytes(
        requests,
        MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
        "fenced_transition_v2_batch_request_encoding_failed",
    )
}

/// Derive the durable outer request ID for one validated ordered V2 batch.
///
/// This is intentionally not a caller-controlled batch identity. It binds
/// the ordered complete 56-byte item IDs (and the count) under a dedicated
/// domain so a reordered batch or any substituted item cannot reuse a
/// consensus idempotency receipt.
pub(crate) fn fenced_transition_v2_batch_outer_request_id(
    requests: &[FencedTransitionV2Request],
) -> Result<[u8; 16], StoreError> {
    validate_fenced_transition_v2_batch(requests)?;
    let count = u16::try_from(requests.len()).map_err(|_| {
        StoreError::Serialization("session consensus V2 batch count encoding failed".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_V2_BATCH_OUTER_REQUEST_ID_DOMAIN);
    hasher.update(count.to_be_bytes());
    for request in requests {
        hasher.update(request.request_id().to_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut outer = [0_u8; 16];
    outer.copy_from_slice(&digest[..16]);
    Ok(outer)
}

/// Validate the persisted V2 batch outcome vector before it is returned or
/// retained by a consensus adapter.
pub(crate) fn validate_fenced_transition_v2_batch_outcomes(
    outcomes: &[Result<FencedTransitionOutcome, StoreError>],
) -> Result<(), StoreError> {
    if outcomes.is_empty() || outcomes.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
        return Err(StoreError::InvalidKey(
            "fenced_transition_v2_batch_outcome_count_invalid".into(),
        ));
    }
    validate_fenced_transition_v2_batch_encoded_bytes(
        outcomes,
        MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES,
        "fenced_transition_v2_batch_outcome_encoding_failed",
    )
}

fn validate_fenced_transition_v2_batch_encoded_bytes<T>(
    value: &T,
    maximum: usize,
    encoding_error: &'static str,
) -> Result<(), StoreError>
where
    T: Serialize + ?Sized,
{
    let encoded = opc_consensus::encode_bounded(value)
        .map_err(|_| StoreError::InvalidKey(encoding_error.into()))?;
    if encoded.len() > maximum {
        return Err(StoreError::PayloadTooLarge {
            actual: encoded.len(),
            max: maximum,
        });
    }
    Ok(())
}

fn append_v2_applied_timestamp(out: &mut Vec<u8>, timestamp: opc_types::Timestamp) {
    let timestamp = timestamp.as_offset_datetime();
    out.extend_from_slice(&timestamp.unix_timestamp().to_be_bytes());
    out.extend_from_slice(&timestamp.nanosecond().to_be_bytes());
}

fn append_v2_applied_identity(out: &mut Vec<u8>, identity: SessionConsensusIdentity) {
    out.extend_from_slice(identity.cluster_id().as_bytes());
    out.extend_from_slice(identity.configuration_id().as_bytes());
    out.extend_from_slice(&identity.configuration_epoch().get().to_be_bytes());
}

fn append_v2_applied_intent(
    out: &mut Vec<u8>,
    intent: &SessionMutationIntent,
) -> Result<(), StoreError> {
    match intent {
        SessionMutationIntent::FencedTransitionV2(request) => {
            out.push(1);
            out.extend_from_slice(&request.request_id().to_bytes());
        }
        SessionMutationIntent::FencedTransitionV2Batch(requests) => {
            validate_fenced_transition_v2_batch(requests)?;
            out.push(5);
            out.extend_from_slice(
                &u16::try_from(requests.len())
                    .map_err(|_| {
                        StoreError::Serialization(
                            "session consensus V2 batch count encoding failed".into(),
                        )
                    })?
                    .to_be_bytes(),
            );
            for request in requests {
                out.extend_from_slice(&request.request_id().to_bytes());
            }
        }
        SessionMutationIntent::ActivateFencedTransitionV2 {
            request,
            scope_identity,
            voter_set_digest,
            profile_digest,
        } => {
            out.push(2);
            out.extend_from_slice(&request.request_id().to_bytes());
            append_v2_applied_identity(out, *scope_identity);
            out.extend_from_slice(voter_set_digest);
            out.extend_from_slice(profile_digest);
        }
        SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation,
            expected_active_epoch,
            expected_retired_through,
            expected_bound_entries,
        } => {
            out.push(3);
            out.extend_from_slice(&expected_generation.to_be_bytes());
            match expected_active_epoch {
                None => out.push(0),
                Some(epoch) => {
                    out.push(1);
                    out.extend_from_slice(&epoch.get().to_be_bytes());
                }
            }
            out.extend_from_slice(&expected_retired_through.to_be_bytes());
            out.extend_from_slice(&expected_bound_entries.to_be_bytes());
        }
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            mutation,
        } if mutation.contains_fenced_transition_v2() => {
            out.push(4);
            out.extend_from_slice(&origin.get().to_be_bytes());
            append_v2_applied_identity(out, *authority_identity);
            append_v2_applied_intent(out, mutation)?;
        }
        _ => {
            return Err(StoreError::Serialization(
                "session consensus V2 digest intent is invalid".into(),
            ));
        }
    }
    Ok(())
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
    /// Ordered exact outcomes for one coalesced V2 fenced-transition batch.
    ///
    /// Position `n` corresponds to position `n` in the replicated batch
    /// intent. Consumer projections additionally carry each full request ID
    /// so callers never infer correlation from a truncated identifier. A
    /// successful item does not make sibling logical effects conditional or
    /// all-or-nothing.
    FencedTransitionV2Batch(Vec<Result<FencedTransitionOutcome, StoreError>>),
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
        FencedTransitionMutationResult, FencedTransitionRequestId, FencedTransitionV2CallerNonce,
        Generation, OwnerId, SessionKeyType, StableId, StateClass, StateType, STABLE_ID_MAX_BYTES,
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
        FencedTransition(Box<FencedTransitionRequest>),
        ActivateFencedTransition {
            request: Box<FencedTransitionRequest>,
            scope_identity: SessionConsensusIdentity,
            voter_set_digest: [u8; 32],
        },
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum LegacySessionMutationOutcome684 {
        CompareAndSet(CompareAndSetResult),
        ConsumerRecord(Option<StoredSessionRecord>),
        Lease(LeaseGuard),
        Unit,
        FencedTransition(FencedTransitionOutcome),
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

    fn v2_digest_command(intent: SessionMutationIntent) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: legacy_identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xD1; 16]),
            logical_time: legacy_time(37),
            intent,
        }
    }

    fn v2_digest_request() -> FencedTransitionV2Request {
        let key = legacy_key();
        let owner = OwnerId::new("v2-digest-owner").expect("owner");
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xD2; 16]),
            FencedTransitionLease::acquire(key, owner, FenceToken::new(0), Duration::from_secs(60))
                .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("V2 request")
    }

    fn v2_digest_variant_requests() -> [FencedTransitionV2Request; 4] {
        let key = legacy_key();
        let owner = OwnerId::new("v2-digest-owner").expect("owner");
        let record = |generation, payload| StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(generation),
            owner: owner.clone(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("v2-digest"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(payload),
        };
        let renew_guard = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            legacy_time(1),
            legacy_time(61),
            2,
        );
        [
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD6; 16]),
                FencedTransitionLease::acquire(
                    key.clone(),
                    owner.clone(),
                    FenceToken::new(0),
                    Duration::from_secs(60),
                )
                .expect("acquire"),
                FencedTransitionMutation::create(record(1, b"create")),
            )
            .expect("create request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD7; 16]),
                FencedTransitionLease::renew(renew_guard.clone(), Duration::from_secs(60))
                    .expect("renew"),
                FencedTransitionMutation::update(Generation::new(1), record(2, b"update")),
            )
            .expect("update request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD8; 16]),
                FencedTransitionLease::renew(renew_guard.clone(), Duration::from_secs(60))
                    .expect("renew"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("delete request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD9; 16]),
                FencedTransitionLease::renew(renew_guard, Duration::from_secs(60)).expect("renew"),
                FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(20))
                    .expect("refresh"),
            )
            .expect("refresh request"),
        ]
    }

    #[test]
    fn v2_batch_validation_binds_ordered_full_ids_and_one_epoch() {
        let [first, second, ..] = v2_digest_variant_requests();
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), second.clone()]).is_ok());
        assert!(validate_fenced_transition_v2_batch(&[]).is_err());
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), first.clone()]).is_err());

        let mismatched_epoch = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(8).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xDA; 16]),
            second.lease().clone(),
            second.mutation().clone(),
        )
        .expect("different epoch request");
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), mismatched_epoch]).is_err());

        let first_outer =
            fenced_transition_v2_batch_outer_request_id(&[first.clone(), second.clone()])
                .expect("batch outer ID");
        assert_eq!(
            first_outer,
            fenced_transition_v2_batch_outer_request_id(&[first.clone(), second.clone()])
                .expect("stable batch outer ID")
        );
        assert_ne!(
            first_outer,
            fenced_transition_v2_batch_outer_request_id(&[second, first])
                .expect("reordered batch outer ID"),
            "ordered full IDs, rather than a set, define the durable batch identity"
        );
    }

    #[test]
    fn v2_batch_intent_uses_a_fixed_full_id_digest_shape() {
        let [first, second, ..] = v2_digest_variant_requests();
        let command = v2_digest_command(SessionMutationIntent::FencedTransitionV2Batch(vec![
            first.clone(),
            second.clone(),
        ]));
        let encoded = command
            .encode_v2_applied_digest_input(
                5,
                SessionConsensusEntryDigest::from_bytes([0xD3; 32]),
                legacy_time(41),
            )
            .expect("batch digest encoding");
        let suffix = &encoded[encoded.len() - (1 + 2 + (2 * 56))..];
        assert_eq!(suffix[0], 5, "V2 batch applied-digest tag");
        assert_eq!(&suffix[1..3], &2_u16.to_be_bytes());
        assert_eq!(&suffix[3..59], &first.request_id().to_bytes());
        assert_eq!(&suffix[59..115], &second.request_id().to_bytes());

        let outcomes = vec![Err(StoreError::LeaseHeld), Err(StoreError::LeaseExpired)];
        assert!(validate_fenced_transition_v2_batch_outcomes(&outcomes).is_ok());
        let outcome = SessionMutationOutcome::FencedTransitionV2Batch(outcomes);
        assert!(opc_consensus::encode_bounded(&outcome).is_ok());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn v2_applied_digest_uses_fixed_golden_encoding_for_each_intent_shape() {
        let previous = SessionConsensusEntryDigest::from_bytes([0xD3; 32]);
        let effective = legacy_time(41);
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::FencedTransitionV2(Box::new(request))),
            }),
        ];
        let expected_digests = [
            "2da22c549efc00b3757fd393a6afd6eaeb58f26b92a63e2393fe47e92ade8be7",
            "0486c039d926654753bf5641cb55c345813212a1df3371f0338822c9e65cccc4",
            "137599aca38dbb4142f99d49016f80dc2b27d2930026d25096adeaa0a062f067",
            "34aaad50947be0d34959ebf15b900bfbc86f966ed378a99f5c5897a79124734d",
        ];
        for (index, (command, expected_digest)) in commands.iter().zip(expected_digests).enumerate()
        {
            let encoded = command
                .encode_v2_applied_digest_input(5, previous, effective)
                .expect("fixed V2 digest encoding");
            let digest = command
                .calculate_applied_digest(5, previous, effective)
                .expect("V2 digest");
            assert!(encoded.starts_with(COMMAND_V2_DIGEST_MAGIC));
            assert_eq!(
                hex(digest.as_bytes()),
                expected_digest,
                "V2 applied digest golden shape {index}"
            );
        }
    }

    #[test]
    fn v2_applied_digest_is_domain_separated_and_rejects_non_v2_inner_intent() {
        let previous = SessionConsensusEntryDigest::from_bytes([0xD3; 32]);
        let effective = legacy_time(41);
        let legacy = v2_digest_command(SessionMutationIntent::AdvanceLogicalTime);
        let legacy_encoded =
            serde_json::to_vec(&(5_u64, previous, effective, &legacy)).expect("legacy JSON");
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(COMMAND_DIGEST_DOMAIN);
        legacy_hasher.update(legacy_encoded);
        assert_eq!(
            legacy.calculate_applied_digest(5, previous, effective),
            Ok(SessionConsensusEntryDigest::from_bytes(
                legacy_hasher.finalize().into()
            )),
            "non-V2 command digest remains byte-for-byte V1 JSON"
        );
        let non_v2_authorized = SessionMutationIntent::Authorized {
            origin: SessionConsensusNodeId::new(9).expect("origin"),
            authority_identity: legacy_identity(),
            mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
        };
        let mut malformed = Vec::new();
        assert!(matches!(
            append_v2_applied_intent(&mut malformed, &non_v2_authorized),
            Err(StoreError::Serialization(_))
        ));
    }

    #[test]
    fn v2_command_json_log_wire_is_pinned() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                }),
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
        ];
        let expected_hashes = [
            "1c5fcc60eca9d4b0de38c83442695b63b2693ab5eab24d6ce8ac78481fae011f",
            "4961aaad86f407d643818d5fb963a62372ce167c1aeaa47b0f45a9dc792a7f63",
            "eaf23c0230cffc5b3a3c62fa949a1fb3e90904dd589e4d2b09dc694ec0e2e746",
            "4983e341ace6866148883f4c64921a2a1f252e4468a61ddd4a5da02aadff1a7d",
        ];
        for (index, (command, expected_hash)) in commands.iter().zip(expected_hashes).enumerate() {
            let encoded = serde_json::to_vec(command).expect("V2 log JSON");
            assert_eq!(
                hex(&Sha256::digest(encoded)),
                expected_hash,
                "V2 durable-log JSON {index}"
            );
        }
    }

    #[test]
    fn v2_request_variant_postcard_and_json_wire_hashes_are_pinned() {
        let expected_postcard_hashes = [
            "70b226d2cd91eb9d586181053af8489132ddf4f6810811b693034f6bb9e46015",
            "226aff8df1e01e92a1a3cef0c3388bdfb9cb381d7dba1faad7ca554d84cc8f37",
            "c0b046501b7a10a1a817e332ae36f0d8b67378077859c22c5ef339bea83a87d4",
            "37796b2b363700ac9200dbddb49436d9757dbe69dcd66e10ae142fca4fc65b9f",
        ];
        let expected_json_hashes = [
            "768ddb1eb21a40e9b6a3c46e1cfc29768be38311f05f1674205365fa5ac52499",
            "da789ecbab52199cf546b2150222dd03cd3e05b97e9a0656b6dcce1e979f97a2",
            "fa8b8ae5f5ca1b5dbf5ed14e7f12f8104ea9661f40b84038d96d9290de8db826",
            "e53aa37aafb7b5e100be93d0418b43b0b719b21098e723966dc7c9286a264dfd",
        ];
        for (index, ((request, expected_postcard_hash), expected_json_hash)) in
            v2_digest_variant_requests()
                .into_iter()
                .zip(expected_postcard_hashes)
                .zip(expected_json_hashes)
                .enumerate()
        {
            let command =
                v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(request)));
            let postcard = opc_consensus::encode_bounded(&command).expect("postcard");
            let json = serde_json::to_vec(&command).expect("JSON");
            assert_eq!(
                hex(&Sha256::digest(postcard)),
                expected_postcard_hash,
                "V2 peer/Raft postcard request shape {index}",
            );
            assert_eq!(
                hex(&Sha256::digest(json)),
                expected_json_hash,
                "V2 durable-log JSON request shape {index}",
            );
        }
    }

    #[test]
    fn v2_command_postcard_wire_ordinals_are_pinned() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                }),
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
        ];
        let expected = [
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a1207d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a1407d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a0f09e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a383864141414141414141414141414141414141414141414141414141414141414141021407d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a150b01070617",
        ];
        let mut expected = expected.map(str::to_owned);
        expected[1] = expected[1].replacen("5a14", "5a13", 1);
        expected[2] = expected[2].replacen("0214", "0213", 1);
        expected[3] = expected[3].replacen("5a15", "5a14", 1);
        for (index, (command, expected)) in commands.iter().zip(expected).enumerate() {
            let encoded = opc_consensus::encode_bounded(command).expect("V2 command postcard");
            assert_eq!(hex(&encoded), expected, "V2 command postcard {index}");
        }
    }

    #[test]
    fn v2_command_postcard_wire_ordinals_match_the_frozen_descriptor() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let intents = [
            (
                "fenced-v2",
                18,
                SessionMutationIntent::FencedTransitionV2(Box::new(request.clone())),
            ),
            (
                "activate-v2",
                19,
                SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request.clone()),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                },
            ),
            (
                "maintain-v2",
                20,
                SessionMutationIntent::MaintainFencedTransitionV2History {
                    expected_generation: 11,
                    expected_active_epoch: Some(
                        FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                    ),
                    expected_retired_through: 6,
                    expected_bound_entries: 23,
                },
            ),
            (
                "fenced-v2-batch",
                21,
                SessionMutationIntent::FencedTransitionV2Batch(vec![request]),
            ),
        ];
        for (label, expected_tag, intent) in intents {
            let intent_bytes =
                opc_consensus::encode_bounded(&intent).expect("V2 intent postcard encoding");
            assert_eq!(
                intent_bytes.first().copied(),
                Some(expected_tag),
                "{label} Postcard discriminator must match the frozen V2 command wire descriptor",
            );

            let command = v2_digest_command(intent);
            let command_bytes =
                opc_consensus::encode_bounded(&command).expect("V2 command postcard encoding");
            assert!(command_bytes.ends_with(&intent_bytes));
            assert_eq!(
                &command_bytes[command_bytes.len() - intent_bytes.len()..],
                intent_bytes.as_slice(),
                "{label} must retain its exact intent bytes in the replicated command",
            );
        }
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
            SessionMutationIntent::CompareAndSet(Box::new(cas.clone())),
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
        let fenced_request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x31; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(20),
            )
            .expect("legacy fenced lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("legacy fenced request");
        assert_postcard_cross_decode(
            "FencedTransition",
            SessionMutationIntent::FencedTransition(Box::new(fenced_request.clone())),
            LegacySessionMutationIntent684::FencedTransition(Box::new(fenced_request.clone())),
        );
        assert_postcard_cross_decode(
            "ActivateFencedTransition",
            SessionMutationIntent::ActivateFencedTransition {
                request: Box::new(fenced_request.clone()),
                scope_identity: identity,
                voter_set_digest: [0x32; 32],
            },
            LegacySessionMutationIntent684::ActivateFencedTransition {
                request: Box::new(fenced_request),
                scope_identity: identity,
                voter_set_digest: [0x32; 32],
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
            LegacySessionMutationOutcome684::Lease(legacy_lease(key.clone(), owner.clone())),
        );
        assert_postcard_cross_decode(
            "Outcome::Unit",
            SessionMutationOutcome::Unit,
            LegacySessionMutationOutcome684::Unit,
        );
        let fenced_outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key,
                owner,
                FenceToken::new(1),
                legacy_time(3),
                legacy_time(23),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            legacy_time(3),
        )
        .expect("legacy fenced outcome");
        assert_postcard_cross_decode(
            "Outcome::FencedTransition",
            SessionMutationOutcome::FencedTransition(fenced_outcome.clone()),
            LegacySessionMutationOutcome684::FencedTransition(fenced_outcome),
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
