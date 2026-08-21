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

#![forbid(unsafe_code)]

#[cfg(feature = "legacy-session-net-compat")]
pub mod client;
pub mod consensus;
pub mod consumer;
pub mod error;
pub mod identity;
mod lifecycle;
pub mod managed_provider;
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
    FencedMutationRosterServicePort, FencedMutationRosterServicePortError,
    FencedMutationRosterTenant, PersistentFencedMutationRosterClient,
    PersistentFencedMutationRosterConfig, PersistentFencedMutationRosterConfigError,
    PersistentFencedMutationRosterDiagnostics, PersistentFencedMutationRosterExecuteError,
    PersistentFencedMutationRosterProviderExecuteError, PersistentFencedMutationRosterReadiness,
    PersistentFencedMutationRosterSetupPhase, PersistentFencedMutationRosterShutdownReport,
    PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
    PersistentSessionConsumerConfigError, PersistentSessionConsumerDiagnostics,
    PersistentSessionConsumerExecuteError, PersistentSessionConsumerReadiness,
    PersistentSessionConsumerShutdownReport, SessionConsumerAuthorizationError,
    SessionConsumerAuthorizer, SessionConsumerClientError, SessionConsumerFencedTransitionBackend,
    SessionConsumerFencedTransitionBackendError, SessionConsumerFencedTransitionMutationError,
    SessionConsumerLeaseMutationError, SessionConsumerMutationError, SessionQuorumConsumerServer,
    SessionQuorumConsumerServerHandle, StatelessSessionConsumerClient,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_CALLS_PER_CONNECTION,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_LANES,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_PENDING,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_REQUEST_BYTES,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_RESPONSE_BYTES,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_RESPONSE_CELLS,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_SETUP_RETRIES,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_SETUP_TIMEOUT,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_SHUTDOWN_DRAIN,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_TENANTS,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_TENANT_QUEUE,
    DEFAULT_PERSISTENT_FENCED_MUTATION_ROSTER_TERMINAL_ADOPTION_ENTRIES,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
    DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
    MAX_FENCED_MUTATION_ROSTER_V3_CALL_BYTES, MAX_FENCED_MUTATION_ROSTER_V3_RESPONSE_BYTES,
    MAX_FENCED_MUTATION_ROSTER_V4_CALL_BYTES, MAX_FENCED_MUTATION_ROSTER_V4_RESPONSE_BYTES,
    MAX_PERSISTENT_FENCED_MUTATION_ROSTER_LANES, MAX_PERSISTENT_FENCED_MUTATION_ROSTER_PENDING,
    MAX_PERSISTENT_FENCED_MUTATION_ROSTER_TENANTS,
    MAX_PERSISTENT_FENCED_MUTATION_ROSTER_TENANT_QUEUE,
    MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
    MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
    MAX_SESSION_QUORUM_CONSUMER_IN_FLIGHT_PER_CONNECTION,
    MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION,
    MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
    MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS,
    PERSISTENT_SESSION_CONSUMER_MAINTENANCE_TASKS_PER_POOL, SESSION_QUORUM_CONSUMER_ALPN,
    SESSION_QUORUM_CONSUMER_CORRELATION_ID_BYTES, SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_V2_ALPN, SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_V3_ALPN, SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_V4_ALPN, SESSION_QUORUM_CONSUMER_V4_TRANSPORT_REVISION,
};
pub use error::ProtocolError;
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
pub use managed_provider::{
    ManagedProviderClientAuthority, ManagedProviderClientError, ManagedProviderJobNetworkFacade,
    ManagedProviderJobServer, ManagedProviderJobServerHandle, ManagedProviderPoolConfig,
    ManagedProviderPoolConfigError, ManagedProviderPoolDiagnostics, ManagedProviderReadiness,
    ManagedProviderShutdownReport, ManagedVoterEndpoint, PersistentManagedProviderJobClient,
    DEFAULT_MANAGED_PROVIDER_POOL_LANES, DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES,
    DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES, MANAGED_PROVIDER_JOB_ALPN,
    MANAGED_PROVIDER_JOB_SEMANTIC_REVISION, MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
    MANAGED_PROVIDER_JOB_VOTERS, MANAGED_PROVIDER_POOL_QUEUE_CAPACITY,
    MAX_MANAGED_PROVIDER_POOL_LANES,
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
#[cfg(feature = "legacy-session-net-compat")]
pub use protocol::{
    conservative_payload_budget, ContractProfile, HelloRejectReason, Request, Response,
    CURRENT_CONTRACT_PROFILE, MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES, MAX_SESSION_NET_REPLICATION_TX_ID_BYTES,
    MAX_SESSION_NET_STABLE_ID_BYTES, MIN_NEGOTIATED_FRAME_SIZE, SESSION_NET_CAS_REQUEST_ID_BYTES,
};
pub use protocol::{
    SessionConsensusContractProfile, SessionConsumerRosterCapabilities, SessionConsumerRosterError,
    SessionConsumerRosterExecuteError, SessionConsumerRosterProfile, SessionConsumerRosterRequest,
    SessionConsumerRosterRequestId, SessionConsumerRosterResponse, SessionConsumerRosterStatus,
    CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE, MAX_NEGOTIATED_FRAME_SIZE,
    MAX_SESSION_CONSUMER_ROSTER_ADMISSION_BYTES, MAX_SESSION_CONSUMER_ROSTER_TERMINAL_BYTES,
    MIN_SESSION_CONSENSUS_FRAME_SIZE, RESTORE_SCAN_MAX_WIRE_PAGE_PAYLOAD_BYTES,
    SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
    SESSION_CONSUMER_ROSTER_REQUEST_ID_BYTES, SESSION_CONSUMER_ROSTER_TRANSPORT_REVISION,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use server::SessionReplicationServer;
