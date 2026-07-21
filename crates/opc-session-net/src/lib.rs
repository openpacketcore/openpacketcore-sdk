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
pub mod error;
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
pub use error::ProtocolError;
pub use identity::{
    LocalReplicaBinding, RemoteReplicaBinding, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConfigurationId, SessionManifestError,
    SessionReplicationManifest,
};
pub use lifecycle::{
    ConnectionLifecycleError, ConnectionLifecyclePolicy, SessionReauthenticationControl,
    DEFAULT_MAX_AUTHENTICATION_AGE, DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN,
    DEFAULT_ROTATION_DRAIN_WINDOW, DEFAULT_ROTATION_JITTER,
};
pub use membership::{
    SessionMembershipAdmission, SessionMembershipAdmissionError,
    SessionMembershipAdmissionSnapshot, SessionMembershipTransitionResult,
    SessionTopologyTransitionId,
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
    SessionConsensusContractProfile, CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
    MAX_NEGOTIATED_FRAME_SIZE, MIN_SESSION_CONSENSUS_FRAME_SIZE, SESSION_CONSENSUS_ALPN,
    SESSION_CONSENSUS_TRANSPORT_REVISION,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use server::SessionReplicationServer;
