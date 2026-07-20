//! Typed route-advertisement intent and health telemetry toward an external
//! routing stack.
//!
//! Standing boundary: BGP and BFD wire protocols, timers, and state machines
//! belong to an established routing component (FRR, BIRD, GoBGP). This module
//! never implements them. It only transports caller-supplied
//! advertise/withdraw intent for exact host prefixes to that component and
//! relays the per-peer session and BFD path-health evidence the component
//! reports.
//!
//! The failure pairing is explicit:
//!
//! - Death or authority loss of the gating component (the caller's election,
//!   quorum, and health boundary, see [`crate::vip::VipOwnershipCoordinator`])
//!   stops lease renewal; the service withdraws every gated prefix within one
//!   configured poll interval of lease expiry.
//! - Death of the routing component closes its BGP sessions, so upstream
//!   peers withdraw this instance's paths. The service reflects that by
//!   presuming sessions closed whenever the stack becomes unobservable.
//!
//! The adapter never originates anything outside the exact set the caller
//! requested: there is no connected-route or kernel-table redistribution in
//! this tier. All prefix and peer address `Debug`/`Display` output is
//! redacted; routing-domain tags are opaque integers and are shown in clear.

pub mod bird;
pub mod fake;
pub mod service;

pub use bird::{BirdAdapterConfig, BirdControlSocketAdapter, BirdDomainBinding};
pub use fake::{
    ApplyGate, ConformanceFakeRoutingStack, FakeApplyFailure, RecordedAdvertisementApply,
    RecordedStackMutation,
};
pub use service::{
    PrefixAdvertiserConfig, PrefixAdvertiserService, PrefixReconcileReport, ReconcileDisposition,
};

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use async_trait::async_trait;
use opc_types::Timestamp;

use crate::error::IpsecLbError;
use crate::model::IpAddress;
use crate::ownership::RoutingDomainTag;

/// Maximum prefixes admitted to one routing-domain reconcile.
///
/// This mirrors the bounded-membership posture of the ownership primitives:
/// an unbounded intent set is rejected before any adapter mutation.
pub const MAX_ADVERTISED_PREFIXES_PER_DOMAIN: usize = 1_024;

/// An exact host prefix (`/32` or `/128`) offered for advertisement.
///
/// Only host prefixes are representable: an ePDG ingress instance advertises
/// its own service addresses, not arbitrary aggregates. `Debug` and `Display`
/// redact the address octets.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPrefix(IpAddress);

impl HostPrefix {
    /// Build a host prefix from a public service address.
    #[must_use]
    pub const fn new(address: IpAddress) -> Self {
        Self(address)
    }

    /// Return the host address.
    #[must_use]
    pub const fn address(self) -> IpAddress {
        self.0
    }

    /// Return the exact prefix length (`32` or `128`).
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        match self.0 {
            IpAddress::V4(_) => 32,
            IpAddress::V6(_) => 128,
        }
    }
}

impl fmt::Debug for HostPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostPrefix(<redacted>/{})", self.prefix_len())
    }
}

impl fmt::Display for HostPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix=<redacted>/{}", self.prefix_len())
    }
}

/// One host prefix bound to its opaque routing-domain tag.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdvertisedPrefix {
    domain: RoutingDomainTag,
    prefix: HostPrefix,
}

impl AdvertisedPrefix {
    /// Bind a host prefix to a routing domain.
    #[must_use]
    pub const fn new(domain: RoutingDomainTag, prefix: HostPrefix) -> Self {
        Self { domain, prefix }
    }

    /// Return the opaque routing-domain tag.
    #[must_use]
    pub const fn domain(self) -> RoutingDomainTag {
        self.domain
    }

    /// Return the host prefix.
    #[must_use]
    pub const fn prefix(self) -> HostPrefix {
        self.prefix
    }
}

impl fmt::Debug for AdvertisedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvertisedPrefix")
            .field("domain", &self.domain)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl fmt::Display for AdvertisedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} routing_domain={}", self.prefix, self.domain.get())
    }
}

/// Identity of one routing-stack peer session.
///
/// The protocol-instance name is operator-chosen routing configuration and is
/// shown in clear; the peer address is always redacted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerIdentity {
    name: String,
    address: Option<IpAddress>,
}

impl PeerIdentity {
    /// Build a peer identity from its routing-stack instance name.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: None,
        }
    }

    /// Attach the peer address reported by the routing stack.
    #[must_use]
    pub fn with_address(mut self, address: IpAddress) -> Self {
        self.address = Some(address);
        self
    }

    /// Return the operator-chosen instance name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the peer address, when the stack reported one.
    #[must_use]
    pub const fn address(&self) -> Option<IpAddress> {
        self.address
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("name", &self.name)
            .field("address", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer={} address=<redacted>", self.name)
    }
}

/// BGP session state as relayed from the routing stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerSessionState {
    /// The session is fully established and exchanges routes.
    Established,
    /// The session is trying to come up (idle, connect, active, open states).
    Connecting,
    /// The session is down (closed, administratively down, or unobservable).
    Down,
}

impl PeerSessionState {
    /// Stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::Connecting => "connecting",
            Self::Down => "down",
        }
    }
}

/// Machine-readable reason for a peer-session transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerSessionChangeReason {
    /// The session reached the established state.
    SessionEstablished,
    /// The session closed (peer reset, transport error, or hold expiry as
    /// reported by the stack).
    SessionClosed,
    /// The stack-reported BFD session went down and forced the session down.
    BfdPathDown,
    /// The peer appeared in stack observations for the first time in a
    /// non-established state.
    PeerObserved,
    /// The peer was administratively disabled in the routing stack.
    AdministrativelyDown,
    /// The routing stack became unobservable, so sessions are presumed closed.
    ObservationLost,
}

impl PeerSessionChangeReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionEstablished => "session_established",
            Self::SessionClosed => "session_closed",
            Self::BfdPathDown => "bfd_path_down",
            Self::PeerObserved => "peer_observed",
            Self::AdministrativelyDown => "administratively_down",
            Self::ObservationLost => "observation_lost",
        }
    }
}

impl fmt::Display for PeerSessionChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// BFD path health as reported by the routing stack.
///
/// The SDK relays this state; it never implements BFD itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathHealth {
    /// The BFD session is up.
    Up,
    /// The BFD session is down.
    Down,
    /// The BFD session is administratively down.
    AdminDown,
    /// The stack reports no usable BFD state for the peer.
    Unknown,
}

impl PathHealth {
    /// Stable machine-readable health code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::AdminDown => "admin_down",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for PathHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One peer observation reported by the routing stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerObservation {
    /// Routing domain the peer session belongs to.
    pub domain: RoutingDomainTag,
    /// Peer identity; the address is redacted in all formatted output.
    pub peer: PeerIdentity,
    /// Session state as reported by the stack.
    pub session: PeerSessionState,
    /// BFD path health as reported by the stack.
    pub path_health: PathHealth,
}

/// Typed per-prefix result of one advertisement-set apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrefixApplyOutcome {
    /// The routing stack accepted and originates the prefix.
    Accepted,
    /// The routing stack rejected the prefix with a machine-readable reason.
    Rejected(PrefixRejectReason),
    /// The routing stack could not be reached for this prefix; its external
    /// state is unknown and must be treated as unconfirmed.
    Unreachable,
}

/// Machine-readable rejection reason for one prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrefixRejectReason {
    /// The intent carried a lease generation that cannot authorize a new
    /// advertisement (stale, or already consumed by a drain or fence loss).
    StaleGeneration,
    /// The routing stack's own policy denied the prefix.
    PolicyDenied,
    /// The routing stack rejected the prefix as malformed or unsupported.
    InvalidPrefix,
    /// The routing stack refused the configuration carrying the prefix.
    ConfigureFailed,
    /// The prefix was absent from the stack after a successful apply.
    StackRejected,
}

impl PrefixRejectReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "stale_generation",
            Self::PolicyDenied => "policy_denied",
            Self::InvalidPrefix => "invalid_prefix",
            Self::ConfigureFailed => "configure_failed",
            Self::StackRejected => "stack_rejected",
        }
    }
}

impl fmt::Display for PrefixRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Machine-readable reason for one prefix withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrefixWithdrawReason {
    /// The caller reconciled the prefix out of the desired set or drained the
    /// routing domain.
    CallerDrain,
    /// The caller's health lease expired before renewal.
    LeaseExpired,
    /// A newer drain or fence loss revoked the generation that authorized the
    /// advertisement.
    StaleGeneration,
    /// The last established peer session carrying the prefix went down.
    PeerSessionDown,
    /// The routing stack rejected a set that previously carried the prefix.
    AdapterRejected,
    /// The routing stack became unreachable; the prefix is unconfirmed.
    RoutingStackUnreachable,
    /// The service is shutting down.
    ServiceShutdown,
}

impl PrefixWithdrawReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerDrain => "caller_drain",
            Self::LeaseExpired => "lease_expired",
            Self::StaleGeneration => "stale_generation",
            Self::PeerSessionDown => "peer_session_down",
            Self::AdapterRejected => "adapter_rejected",
            Self::RoutingStackUnreachable => "routing_stack_unreachable",
            Self::ServiceShutdown => "service_shutdown",
        }
    }
}

impl fmt::Display for PrefixWithdrawReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coordinator knowledge of one prefix's advertisement state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PrefixAdvertisementState {
    /// Originated by the stack and reachable through at least one established
    /// peer session in its routing domain.
    Advertised,
    /// Known to be withdrawn (or never advertised by this service).
    #[default]
    Withdrawn,
    /// The routing stack rejected the prefix.
    Rejected,
    /// An adapter mutation was ambiguous; external state is unconfirmed.
    Unknown,
}

impl PrefixAdvertisementState {
    /// Stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Withdrawn => "withdrawn",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }
}

/// Point-in-time per-prefix status snapshot.
///
/// `advertised_to` is derived from the peer sessions the routing stack
/// currently reports as established in the prefix's routing domain; peer
/// addresses inside it are redacted in all formatted output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixStatusSnapshot {
    /// Prefix and routing domain this snapshot describes.
    pub prefix: AdvertisedPrefix,
    /// Coordinator-known advertisement state.
    pub state: PrefixAdvertisementState,
    /// Established peers currently carrying the prefix (empty unless
    /// `state` is [`PrefixAdvertisementState::Advertised`]).
    pub advertised_to: BTreeSet<PeerIdentity>,
    /// Timestamp of the last state transition, from the injected clock.
    pub last_transition: Option<Timestamp>,
    /// Machine-readable reason of the last withdrawal, when any.
    pub last_withdraw_reason: Option<PrefixWithdrawReason>,
}

/// Monotonic lease generation supplied by the caller's gating component.
///
/// A strictly newer generation is required for every new advertisement epoch,
/// including any ABA return to the same node. This mirrors the
/// [`crate::vip::LeadershipFence`] rule: once a generation has been drained or
/// expired, it can never authorize a re-advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseGeneration(NonZeroU64);

impl LeaseGeneration {
    /// Build a non-zero lease generation.
    pub fn new(value: u64) -> Result<Self, IpsecLbError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(IpsecLbError::invalid_config(
                "lease_generation",
                "lease generation must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Caller-supplied health lease authorizing prefix origination.
///
/// The deadline is computed from the service's injected clock as
/// `now + ttl_secs` at reconcile time. While the lease is unexpired and its
/// generation is current, the gated prefixes may be originated; on expiry the
/// service withdraws them within one configured poll interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdvertisementLease {
    generation: LeaseGeneration,
    ttl_secs: u32,
}

impl AdvertisementLease {
    /// Build a lease with a strictly positive time-to-live in seconds.
    pub fn new(generation: LeaseGeneration, ttl_secs: u32) -> Result<Self, IpsecLbError> {
        if ttl_secs == 0 {
            return Err(IpsecLbError::invalid_config(
                "lease_ttl",
                "lease time-to-live must be non-zero",
            ));
        }
        Ok(Self {
            generation,
            ttl_secs,
        })
    }

    /// Return the lease generation.
    #[must_use]
    pub const fn generation(self) -> LeaseGeneration {
        self.generation
    }

    /// Return the time-to-live in seconds.
    #[must_use]
    pub const fn ttl_secs(self) -> u32 {
        self.ttl_secs
    }
}

/// Typed health/readiness event emitted by the advertisement service.
///
/// Events carry a strictly increasing per-service `sequence`, so subscribers
/// can assert ordering guarantees such as "session-down is observed before
/// the corresponding prefix-withdrawn for the same cause".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingEvent {
    /// Strictly increasing per-service sequence number.
    pub sequence: u64,
    /// Event timestamp from the injected clock.
    pub at: Timestamp,
    /// Event payload; prefixes and peer addresses are redacted in `Debug`.
    pub kind: RoutingEventKind,
}

/// Event payload for routing health/readiness telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoutingEventKind {
    /// A peer routing session changed state.
    PeerSessionChanged {
        /// Peer identity (address redacted in formatted output).
        peer: PeerIdentity,
        /// New session state.
        state: PeerSessionState,
        /// Machine-readable transition reason.
        reason: PeerSessionChangeReason,
    },
    /// BFD path health for one peer changed, as relayed from the stack.
    PathHealthChanged {
        /// Peer identity (address redacted in formatted output).
        peer: PeerIdentity,
        /// New path health.
        health: PathHealth,
    },
    /// A prefix transitioned to advertised.
    PrefixAdvertised {
        /// Prefix and routing domain (address redacted in formatted output).
        prefix: AdvertisedPrefix,
        /// Number of established peers in the domain at transition time.
        peers: usize,
    },
    /// A prefix transitioned to withdrawn with a machine-readable reason.
    PrefixWithdrawn {
        /// Prefix and routing domain (address redacted in formatted output).
        prefix: AdvertisedPrefix,
        /// Machine-readable withdrawal reason.
        reason: PrefixWithdrawReason,
    },
    /// A prefix's external state became unconfirmed (for example after an
    /// ambiguous adapter mutation or loss of stack observability).
    ///
    /// This is deliberately distinct from [`Self::PrefixWithdrawn`]: the
    /// prefix may still be originated by the routing stack.
    PrefixUnconfirmed {
        /// Prefix and routing domain (address redacted in formatted output).
        prefix: AdvertisedPrefix,
        /// Machine-readable cause.
        reason: PrefixWithdrawReason,
    },
}

/// Kind of routing stack behind an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RoutingStackKind {
    /// BIRD Internet Routing Daemon via its control socket.
    Bird,
    /// Deterministic conformance fake.
    ConformanceFake,
}

/// Adapter capability and readiness probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingStackProbe {
    /// Adapter kind.
    pub kind: RoutingStackKind,
    /// The routing stack control channel is reachable.
    pub stack_reachable: bool,
    /// The adapter can apply advertisement-set mutations.
    pub mutation_ready: bool,
    /// Optional static detail string.
    pub details: Option<String>,
}

/// Adapter port toward an established routing component.
///
/// Implementations translate the exact desired host-prefix set into the
/// routing component's own control protocol and relay its observations. They
/// must satisfy the conformance contract proven by
/// [`fake::ConformanceFakeRoutingStack`]:
///
/// - after a successful [`Self::apply_advertisement_set`], the adapter
///   originates exactly the accepted subset of `desired` for `domain` and
///   nothing else — no connected or kernel-table redistribution, ever;
/// - mutations are idempotent: re-applying the same set is a no-op;
/// - observations are relayed, never synthesized by the adapter itself.
///
/// Implementations MUST bound the duration of every call (for example with
/// a per-command timeout): the advertisement service serializes adapter
/// mutations on its apply lock, so an unbounded adapter call would stall
/// lease-expiry withdrawals for every routing domain.
#[async_trait]
pub trait RoutingStackAdapter: Send + Sync + std::fmt::Debug {
    /// Reconcile the exact originated host-prefix set for one routing domain.
    ///
    /// The returned map carries one typed outcome for every prefix in
    /// `desired`. Prefixes absent from the map after success were not part of
    /// the request; originating anything outside `desired` violates the port
    /// contract.
    async fn apply_advertisement_set(
        &self,
        domain: RoutingDomainTag,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<std::collections::BTreeMap<HostPrefix, PrefixApplyOutcome>, IpsecLbError>;

    /// Withdraw everything this adapter originates for one routing domain.
    ///
    /// Must be idempotent: withdrawing an already-empty domain succeeds.
    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError>;

    /// Return the current per-peer session and BFD path-health observations
    /// as reported by the routing stack.
    async fn poll_observations(&self) -> Result<Vec<PeerObservation>, IpsecLbError>;

    /// Probe adapter capability and routing-stack reachability.
    async fn probe(&self) -> Result<RoutingStackProbe, IpsecLbError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_prefix_and_peer_formatting_is_redacted() {
        let v4 = HostPrefix::new(IpAddress::V4([203, 0, 113, 10]));
        let v6 = HostPrefix::new(IpAddress::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
        ]));
        assert_eq!(v4.prefix_len(), 32);
        assert_eq!(v6.prefix_len(), 128);
        for rendered in [
            format!("{v4:?}"),
            format!("{v4}"),
            format!("{v6:?}"),
            format!("{v6}"),
        ] {
            assert!(!rendered.contains("203.0.113"), "{rendered}");
            assert!(!rendered.contains("2001"), "{rendered}");
            assert!(!rendered.contains("0xb8"), "{rendered}");
        }

        let advertised = AdvertisedPrefix::new(RoutingDomainTag::new(64512), v4);
        let peer = PeerIdentity::named("edge-a").with_address(IpAddress::V4([192, 0, 2, 1]));
        for rendered in [
            format!("{advertised:?}"),
            format!("{advertised}"),
            format!("{peer:?}"),
            format!("{peer}"),
        ] {
            assert!(
                rendered.contains("edge-a") || rendered.contains("64512"),
                "{rendered}"
            );
            assert!(!rendered.contains("203.0.113"), "{rendered}");
            assert!(!rendered.contains("192.0.2"), "{rendered}");
        }
    }

    #[test]
    fn lease_generation_and_ttl_are_validated() {
        assert!(LeaseGeneration::new(0).is_err());
        assert_eq!(LeaseGeneration::new(7).unwrap().get(), 7);
        assert!(AdvertisementLease::new(LeaseGeneration::new(1).unwrap(), 0).is_err());
        let lease = AdvertisementLease::new(LeaseGeneration::new(1).unwrap(), 30).unwrap();
        assert_eq!(lease.generation().get(), 1);
        assert_eq!(lease.ttl_secs(), 30);
    }

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(PrefixWithdrawReason::LeaseExpired.as_str(), "lease_expired");
        assert_eq!(
            PeerSessionChangeReason::BfdPathDown.as_str(),
            "bfd_path_down"
        );
        assert_eq!(
            PrefixRejectReason::StaleGeneration.as_str(),
            "stale_generation"
        );
        assert_eq!(PathHealth::AdminDown.to_string(), "admin_down");
    }
}
