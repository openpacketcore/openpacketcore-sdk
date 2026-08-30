//! Networked session replication transport for OpenPacketCore (experimental).
//!
//! Provides bounded length-prefixed transports for session state. The
//! production consensus boundary is [`SessionConsensusServer`] and
//! [`RemoteSessionConsensusPeer`] over a dedicated ALPN; those types expose
//! only the shared consensus handler/peer ports and cannot perform raw backend
//! mutation or rebuild operations. The legacy remote-backend client, server,
//! and public protocol surface are quarantined behind the non-default
//! `legacy-session-net-compat` feature for controlled migration work.
//! Endpoints derive their local/remote authority from one immutable
//! [`SessionReplicationManifest`]. Consensus peers bind the claimed stable
//! replica IDs and manifest scope to the canonical SPIFFE identities extracted
//! from the live mutual-TLS connection, and prove the exact same
//! [`SessionConsensusContractProfile`] before an operation is dispatched.
//! [`SessionMembershipAdmission`] may additionally stage one exact validated
//! successor for Raft catch-up. It revalidates every request and atomically
//! removes stale scopes on finalize or abort; existing immutable bindings and
//! constructors retain their single-manifest behavior.
//!
//! Every authenticated direct and consensus connection also has one finite
//! [`ConnectionLifecyclePolicy`]. The transport records the completed
//! handshake's material epoch and local/peer leaf plus presented-chain expiry
//! evidence, stops
//! admitting new work at the earliest retirement boundary, and bounds the
//! transport wait plus connection-slot lifetime by the hard deadline. A
//! supervised backend mutation may still finish after its caller future is
//! dropped, so transport retirement reports typed ambiguity and never proves
//! rollback or permits an automatic replay. Material publication or an explicit
//! [`SessionReauthenticationControl`] request drains existing connections;
//! replacements always repeat the complete mutual-TLS and application-profile
//! handshake. Post-bootstrap byte-idle listeners retire through a fixed
//! lifecycle reason; bootstrap silence and partial active frames remain
//! timeout failures. Direct watch streams reconnect from the exact next
//! caller-visible sequence. Protocol-profile upgrades remain coordinated
//! stop/upgrade/start operations; this lifecycle provides seamless credential
//! rotation only after every participant already runs the same profile.
//!
//! ```compile_fail
//! use opc_session_net::SessionConsumerPreparedCheckpointRouter;
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "legacy-session-net-compat")]
pub mod client;
pub mod consensus;
pub mod consumer;
pub mod error;
mod fenced_mutation_roster;
pub mod identity;
mod lifecycle;
pub mod membership;
#[cfg(not(feature = "legacy-session-net-compat"))]
mod protocol;
#[cfg(feature = "legacy-session-net-compat")]
pub mod protocol;
#[cfg(feature = "legacy-session-net-compat")]
pub mod server;
#[cfg(test)]
mod test_support;

#[cfg(feature = "legacy-session-net-compat")]
pub use client::RemoteSessionBackend;
pub use consensus::{
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionConsensusServer,
    SessionConsensusServerHandle,
};
pub use consumer::{
    session_consumer_payload_budget, PersistentSessionConsumerClient,
    PersistentSessionConsumerConfig, PersistentSessionConsumerConfigError,
    PersistentSessionConsumerDiagnostics, PersistentSessionConsumerExecuteError,
    PersistentSessionConsumerReadiness, PersistentSessionConsumerShutdownReport,
    PersistentSessionConsumerV2Diagnostics, PersistentSessionConsumerV2ExecuteError,
    RosterIngressSigner, RosterIngressSignerError, SessionConsumerAuthorizationError,
    SessionConsumerAuthorizer, SessionConsumerClientError, SessionConsumerFencedTransitionBackend,
    SessionConsumerFencedTransitionBackendError, SessionConsumerFencedTransitionMutationError,
    SessionConsumerLeaseMutationError, SessionConsumerMutationError,
    SessionConsumerPreparedCheckpointBackend, SessionConsumerPreparedCheckpointBackendError,
    SessionConsumerPreparedCompareAndSet, SessionConsumerPreparedFencedTransition,
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionStatusError, SessionConsumerPreparedLeaseAcquire,
    SessionConsumerRecoveredFencedTransitionStatus, SessionQuorumConsumerServer,
    SessionQuorumConsumerServerAdmissionSnapshot, SessionQuorumConsumerServerHandle,
    StatelessSessionConsumerClient, DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
    MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
    MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
    MAX_SESSION_QUORUM_CONSUMER_IN_FLIGHT_PER_CONNECTION,
    MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION,
    MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS,
    PERSISTENT_SESSION_CONSUMER_MAINTENANCE_TASKS_PER_POOL, SESSION_QUORUM_CONSUMER_ALPN,
    SESSION_QUORUM_CONSUMER_CORRELATION_ID_BYTES, SESSION_QUORUM_CONSUMER_ROSTER_ALPN,
    SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION, SESSION_QUORUM_CONSUMER_ROSTER_V2_ALPN,
    SESSION_QUORUM_CONSUMER_ROSTER_V2_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION, SESSION_QUORUM_CONSUMER_V2_ALPN,
    SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
};
pub use error::ProtocolError;
pub use fenced_mutation_roster::{
    fenced_mutation_roster_compact_terminal_member_signing_digest_v2,
    fenced_mutation_roster_terminal_attestation_signing_digest_v1,
    FencedMutationRosterAbortedTerminal, FencedMutationRosterAbsentAdmissionProposal,
    FencedMutationRosterAbsentRecoveryInput, FencedMutationRosterActive,
    FencedMutationRosterAdmissionInput, FencedMutationRosterAdmissionOutcome,
    FencedMutationRosterAdmissionProposal, FencedMutationRosterAdmissionUnknown,
    FencedMutationRosterAttestationTrustRootV1, FencedMutationRosterClient,
    FencedMutationRosterClientError, FencedMutationRosterCompactTerminalMemberSigningInputV2,
    FencedMutationRosterCompleteProofSet, FencedMutationRosterDiagnostics,
    FencedMutationRosterEstablishedMutation, FencedMutationRosterEstablishedPublication,
    FencedMutationRosterEstablishedPublicationCall,
    FencedMutationRosterEstablishedPublicationProvider, FencedMutationRosterEstablishedTerminal,
    FencedMutationRosterExecuteOutcome, FencedMutationRosterExecutorAttestor,
    FencedMutationRosterExecutorAttestorAdapter, FencedMutationRosterExecutorCertificatePartsV1,
    FencedMutationRosterExecutorError, FencedMutationRosterExecutorTerminalSigner,
    FencedMutationRosterId, FencedMutationRosterMember, FencedMutationRosterMemberAdoption,
    FencedMutationRosterMemberCall, FencedMutationRosterMemberDisposition,
    FencedMutationRosterMemberOperationId, FencedMutationRosterMemberOrdinal,
    FencedMutationRosterMemberPrepareOutcome, FencedMutationRosterMemberProof,
    FencedMutationRosterMemberProvider, FencedMutationRosterMemberRecoveryOutcome,
    FencedMutationRosterMemberRecoveryStatus, FencedMutationRosterPhase,
    FencedMutationRosterPreparedTerminal, FencedMutationRosterProfile,
    FencedMutationRosterProviderAdapter, FencedMutationRosterProviderAdapterDiagnostics,
    FencedMutationRosterProviderCallOutcome, FencedMutationRosterProviderReceiptCapsule,
    FencedMutationRosterProviderReceiptChallenge, FencedMutationRosterPublicationError,
    FencedMutationRosterPublicationEvidence, FencedMutationRosterPublicationId,
    FencedMutationRosterPublicationProviderOutcome, FencedMutationRosterReadyMember,
    FencedMutationRosterRecoverableMember, FencedMutationRosterRecovered,
    FencedMutationRosterRecoveryInput, FencedMutationRosterRecoveryOutcome,
    FencedMutationRosterTerminal, FencedMutationRosterTerminalAttestationSigningInputV1,
    FencedMutationRosterTerminalReceipt, FencedMutationRosterTerminalStatus,
    FencedMutationRosterTerminalizationOutcome, ProtectedRosterTransportError,
    FENCED_MUTATION_ROSTER_CONSUMER_ALPN, FENCED_MUTATION_ROSTER_CONSUMER_ALPN_V2,
    FENCED_MUTATION_ROSTER_CONSUMER_REVISION, FENCED_MUTATION_ROSTER_CONSUMER_REVISION_V2,
    FENCED_MUTATION_ROSTER_FRESH_MEMBERS, FENCED_MUTATION_ROSTER_ID_BYTES,
    FENCED_MUTATION_ROSTER_INITIAL_GENERATION, FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES,
    FENCED_MUTATION_ROSTER_MAX_DESCRIPTOR_BYTES, FENCED_MUTATION_ROSTER_MAX_HISTORY_EPOCH,
    FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS, FENCED_MUTATION_ROSTER_MAX_MEMBERS,
    FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES, FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
    FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES, FENCED_MUTATION_ROSTER_MAX_STATUS_BYTES,
    FENCED_MUTATION_ROSTER_MEMBER_OPERATION_ID_BYTES, FENCED_MUTATION_ROSTER_OPERATIONAL_TARGET,
    FENCED_MUTATION_ROSTER_SCHEMA_V1, FENCED_MUTATION_ROSTER_SCHEMA_V2,
    MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES, MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
};
pub use identity::{
    LocalReplicaBinding, RemoteReplicaBinding, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConfigurationId, SessionManifestError,
    SessionPlacementDisposition, SessionPlacementPolicy, SessionReplicationManifest,
};
pub use lifecycle::{
    ConnectionLifecycleError, ConnectionLifecyclePolicy, SessionReauthenticationControl,
    DEFAULT_MAX_AUTHENTICATION_AGE, DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN,
    DEFAULT_ROTATION_DRAIN_WINDOW, DEFAULT_ROTATION_JITTER,
};
pub use membership::{
    SessionMembershipAdmission, SessionMembershipAdmissionError,
    SessionMembershipAdmissionSnapshot, SessionMembershipTransitionResult,
    SessionTopologyAbortAdmissionProof, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionId,
    SessionTopologyUniformCommitAdmissionProof,
};
pub use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusNodeId,
};
pub use opc_types::Timestamp;
pub use protocol::{
    conservative_payload_budget, SessionConsensusContractProfile,
    CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE, MAX_NEGOTIATED_FRAME_SIZE,
    MIN_SESSION_CONSENSUS_FRAME_SIZE, RESTORE_SCAN_MAX_WIRE_PAGE_PAYLOAD_BYTES,
    SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use protocol::{
    ContractProfile, HelloRejectReason, Request, Response, CURRENT_CONTRACT_PROFILE,
    MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES, MAX_SESSION_NET_REPLICATION_TX_ID_BYTES,
    MAX_SESSION_NET_STABLE_ID_BYTES, MIN_NEGOTIATED_FRAME_SIZE, SESSION_NET_CAS_REQUEST_ID_BYTES,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use server::SessionReplicationServer;
