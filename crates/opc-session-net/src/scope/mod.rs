//! Authenticated untimed scope transport (RFC026).
//!
//! Wire values are bounded claims. They never construct committed authority.
//! The store owns request canonicalization, durable authority and capabilities.

mod boot;
mod clock;
mod notice;
mod policy;
mod pool;
mod proof;
mod socket;
mod wire;

pub use boot::{BootError, BootIdentity};
pub use clock::{
    AuthenticationClock, AuthenticationTimeError, AuthenticationTimeSource, IntervalClock,
    RealtimeReading,
};
pub use policy::{PolicyError, PrincipalGrant, ScopePolicy, ScopeRole};
pub use pool::{ProofBudgets, ProofPoolError};
pub use wire::{Class, ScopeBinding, WireError};

#[cfg(test)]
mod wire_tests;

#[cfg(test)]
mod proof_tests;

#[cfg(test)]
mod notice_tests;

#[cfg(test)]
mod clock_tests;

#[cfg(test)]
mod policy_tests;

#[cfg(test)]
mod pool_tests;

mod credential;
pub use credential::{BootstrapCredentialError, BootstrapCredentialVerifier, IssuerKeySource};
#[cfg(test)]
mod credential_tests;

mod lifecycle;
pub use lifecycle::{ScopeEffectPermit, ScopeGateError};
#[cfg(test)]
mod lifecycle_tests;

mod startup;
pub use startup::{
    BootProofResponder, BootTicket, BootstrapCredential, BootstrapCredentialSource, ClosureNotice,
    ProjectedBootstrapToken, ScopeProcess, StartupError, StartupSession,
};
#[cfg(test)]
mod startup_tests;

mod platform;
pub use platform::{
    KubernetesBootReader, KubernetesPodSource, PlatformError, PodEnrollment, RunningPodObservation,
};
#[cfg(test)]
mod platform_tests;

mod issuer;
pub use issuer::{
    BootstrapIssuerClient, BootstrapProofMode, IssuerStartupSession, VerifiedBootstrapProof,
};
#[cfg(test)]
mod issuer_tests;

mod evidence;
pub use evidence::{
    BootAuthorityRecord, FinalTerminationRecord, LocalClosurePublication, LocalClosureRecord,
    ScopeBootAuthority, ScopeClosureSource, ScopeEvidenceError, ScopeLocalClosurePublisher,
};
#[cfg(test)]
mod evidence_tests;

mod issuer_notice;
pub use issuer_notice::{IssuedTicketNotice, TicketNoticeEntry, TicketNoticeSource};

mod rpc;
pub use rpc::{
    PendingScopeAuthority, ScopeAuthorityReply, ScopeClient, ScopeClientConfig, ScopeRpcError,
    ScopeServer, ScopeServerConfig, ScopeServerHandle,
};

mod rpc_client;
pub use rpc_client::scans::{ScopeScanPort, ScopeScanRemoteView};
#[cfg(all(test, target_os = "linux"))]
mod rpc_client_tests;
mod rpc_server;

#[cfg(test)]
pub(crate) mod attack_test_support;
#[cfg(test)]
pub(crate) mod protocol_test_support;

mod read_client;
pub use read_client::{ScopeAuthorityReceipt, ScopeReadClient, ScopeReadClientConfig};
