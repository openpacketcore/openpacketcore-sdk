//! Checked scope calls over live class-specific mutual-TLS connections.
use super::{
    AuthenticationClock, BootTicket, ProofBudgets, ScopeBootAuthority, ScopeClosureSource,
    ScopeLocalClosurePublisher, ScopePolicy, ScopeProcess,
};
use opc_session_store::{
    scope_authority::*, scope_scheduler::ScopeScheduler, ConsensusSessionStore,
};
use std::{net::SocketAddr, sync::Arc};

/// Bounded transport result. Authentication failures never transfer ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRpcError {
    /// Malformed or mismatched immutable request/response.
    #[error("invalid scope RPC")]
    Invalid,
    /// Live principal/scope or independently verified boot does not match.
    #[error("scope RPC unauthorized")]
    Unauthorized,
    /// This attempt did not submit; a prior unknown attempt remains unknown.
    #[error("scope RPC retry")]
    Retry,
    /// The trusted authentication interval is unavailable or invalid.
    #[error("scope RPC authentication time unavailable")]
    AuthTimeUnavailable,
    /// The exact installation/profile is not active.
    #[error("scope RPC profile unavailable")]
    ProfileUnavailable,
    /// Submission was possible. Retain and resolve the exact request.
    #[error("scope RPC outcome unknown")]
    OutcomeUnknown,
    /// The boot has been positively superseded by committed state.
    #[error("scope RPC superseded")]
    Superseded,
    /// The exact retained execution is closed.
    #[error("scope RPC closed")]
    Closed,
    /// The execution's cohort has been permanently retired.
    #[error("scope RPC retired")]
    Retired,
    /// An exact old receipt is no longer retained; this is not NotApplied.
    #[error("scope RPC receipt unavailable")]
    ReceiptUnavailable,
}

/// Locally configured independent readers and scheduling for a scope server.
pub struct ScopeServerConfig {
    /// Constrained scope-profile TLS material.
    pub tls: opc_tls::AuthenticatedServerConfig,
    /// Trusted certificate authentication interval source.
    pub clock: Arc<dyn AuthenticationClock>,
    /// Live exact principal/role/slot authorization.
    pub policy: ScopePolicy,
    /// The actual durable quorum service, including follower forwarding.
    pub store: Arc<ConsensusSessionStore>,
    /// Immutable native scopes under the configured store identity.
    pub scopes: Vec<ScopeId>,
    /// Independently current and retained boot issuance.
    pub boots: Arc<dyn ScopeBootAuthority>,
    /// Independent positive closure evidence.
    pub closures: Arc<dyn ScopeClosureSource>,
    /// Class/scope admission. Its owner must outlive this server.
    pub scheduler: ScopeScheduler,
    /// Independent class/role/peer challenge budgets.
    pub proofs: ProofBudgets,
}
/// One process-bound worker client; configuration is not admission authority.
pub struct ScopeClientConfig {
    /// SDK-owned process key, exclusion and irreversible submission gates.
    pub process: Arc<ScopeProcess>,
    /// Native scope from the configured installation topology.
    pub scope: ScopeId,
    /// Bounded issuer-delivered/read hints for this exact boot.
    pub ticket: BootTicket,
    /// Constrained scope-profile mutual TLS material.
    pub tls: opc_tls::AuthenticatedClientConfig,
    /// Exact expected quorum endpoint SPIFFE identity.
    pub server: opc_types::SpiffeId,
    /// SC/E/classification/Normal/Maintenance addresses; no shared connection FIFO.
    pub addresses: [SocketAddr; 5],
    /// Trusted authentication interval source.
    pub clock: Arc<dyn AuthenticationClock>,
    /// Scheduler producer used before building request bodies.
    pub scheduler: ScopeScheduler,
    /// Trusted local evidence publication before final Close.
    pub local_closure: Arc<dyn ScopeLocalClosurePublisher>,
}
/// A checked result for this own boot's authority operation.
#[derive(Clone, Debug)]
pub enum ScopeAuthorityReply {
    /// An own admission/succession verified committed and current on the channel.
    Admitted(Box<CommittedScopeAuthority>),
    /// The exact Close committed; this never constructs an effect capability.
    Closed(Box<ScopeAuthorityStamp>),
}

pub use super::rpc_client::{PendingScopeAuthority, ScopeClient};
pub use super::rpc_server::{ScopeServer, ScopeServerHandle};
