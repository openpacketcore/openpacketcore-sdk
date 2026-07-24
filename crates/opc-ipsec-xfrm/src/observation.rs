//! Authenticated ESP peer outer-source observations for NAT rebinding.
//!
//! An [`EspPeerObservationBoundary`] turns kernel-attributed ESP decap events
//! into bounded, typed observations: an established inbound ESP-in-UDP SA that
//! starts arriving from a new outer source produces exactly one
//! [`EspPeerObservation`] retaining only the minimum routing facts needed for
//! policy (address family, ingress interface identity, encapsulation source
//! address and port, a monotonic per-SA generation, and an explicit loss
//! status). This is the observation authority a product needs before an
//! RFC 7296 section 2.23 recovery procedure can update the path; it is
//! deliberately distinct from applying a caller-supplied relocation
//! ([`crate::RelocateSaRequest`]). The boundary never applies a relocation and
//! never infers one from packet sources: it only reports.
//!
//! # Trust anchor
//!
//! "Authenticated" here means the Linux kernel ESP decap path verified the
//! packet integrity (ICV or AEAD) **and** the packet won the final anti-replay
//! advance on the exact SA the event names. Only an
//! [`EspPeerObservationSource`] whose events carry
//! [`EspPeerEventProvenance::PostFinalReplayAccepted`] may feed this boundary;
//! anything weaker (raw sockets, tc/XDP ingress copies, or the stock
//! `XFRM_MSG_MAPPING` notification) is rejected and must never be adapted
//! upward, because none of those can exclude unauthenticated or replay-losing
//! traffic:
//!
//! - Stock `XFRM_MSG_MAPPING` is emitted from the ESP input completion path
//!   after ICV verification but *before* the final replay recheck in
//!   `xfrm_input`, so two concurrent copies of one valid sequence can both
//!   reach the notification while only one wins replay. A replayed packet can
//!   therefore still emit a mapping.
//! - The same notification is allocated with `GFP_ATOMIC` and its failure is
//!   ignored by ESP input, so producer-side loss has no receiver-visible
//!   signal, and it carries no ESP sequence, ingress ifindex, XFRM `if_id`,
//!   or lookup mark.
//!
//! For that reason this crate ships the boundary, the provenance contract, and
//! a scripted test source, but no stock-kernel event source: no stock Linux
//! UAPI today satisfies the contract (post-final-replay emission with exact SA
//! mark/`if_id`/direction, ingress ifindex, outer source/port, ESP sequence
//! including ESN high bits, and a queryable loss/generation cursor). A
//! platform event that does satisfy it (for example a qualified kernel or
//! eBPF packet-path mechanism observing the post-recheck accept path)
//! implements [`EspPeerObservationSource`] without boundary changes.
//!
//! # Acceptance rules
//!
//! The boundary rejects, with a value-free [`EspPeerObservationRejection`]:
//! events from a foreign scope (namespace cross-combination), events for
//! unknown or cross-SA identities, wrong-direction events, address-family
//! mismatches, malformed or interface-scope-less events, insufficient
//! provenance (unauthenticated or pre-final-replay), stale cursors (replay or
//! reorder), events for torn-down SAs, and events that would overflow a slot
//! that still holds an undrained observation (explicit, fail-closed). Memory
//! is bounded: one outstanding observation and at most two retained addresses
//! (current baseline and last reported) per SA, and a capacity-bounded
//! registry; teardown drains and removes all observation state for the SA.
//!
//! # Redaction
//!
//! Following the crate's redaction idiom, `Debug` and `Display` for every
//! public type here emit only stable labels and non-sensitive metadata
//! (generation numbers, family, direction, loss status). Raw addresses,
//! ports, SPIs, marks, interface indexes, and interface identifiers are never
//! printed. The routing facts themselves remain available through typed
//! fields for policy decisions; they are simply never formatted.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::XfrmError;
use crate::model::{IpAddress, XfrmDirection, XfrmId, XfrmMark};

/// Default maximum number of SAs tracked by one observation boundary.
///
/// The registry is bounded so observation state can never grow with
/// attacker-controlled SA churn. Each tracked SA holds at most one
/// outstanding observation plus its current/last-reported baseline, so total
/// memory is linear in this capacity.
pub const DEFAULT_ESP_PEER_OBSERVATION_CAPACITY: usize = 1024;

/// Opaque scope token pinning an observation boundary to one event source.
///
/// A scope identifies a single network-namespace observation domain without
/// exposing any filesystem or namespace identity. Events minted under a
/// different scope are rejected, so observations cannot be cross-combined
/// across namespaces or sources.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EspPeerObservationScope(NonZeroU64);

impl EspPeerObservationScope {
    /// Mint a fresh process-unique scope.
    #[must_use]
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let raw = NEXT.fetch_add(1, Ordering::Relaxed);
        // The counter starts at 1 and only advances, so it is never zero.
        Self(NonZeroU64::new(raw).expect("observation scope counter is nonzero"))
    }

    /// Return the raw process-local scope number. This is correlation-only
    /// metadata and is never authority.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Default for EspPeerObservationScope {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EspPeerObservationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationScope")
            .field("id", &"<opaque>")
            .finish()
    }
}

/// Provenance grade of a raw ESP peer event.
///
/// The ordering is significant: only [`Self::PostFinalReplayAccepted`] is an
/// acceptable trust anchor for observations. See the module-level trust-anchor
/// documentation for why weaker grades exist and are rejected.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspPeerEventProvenance {
    /// An unauthenticated packet-path signal (raw socket, tc/XDP ingress copy,
    /// or any pre-decryption observation). Never acceptable.
    UnauthenticatedPacketPath,
    /// Kernel ESP decap verified integrity, but the packet may still lose the
    /// final anti-replay recheck (the stock `XFRM_MSG_MAPPING` grade). Never
    /// acceptable: replayed traffic could produce an observation.
    PostIntegrityPreFinalReplay,
    /// Kernel ESP decap verified integrity and the packet won the final
    /// anti-replay advance on the exact SA named by the event.
    PostFinalReplayAccepted,
}

/// Exact SA identity and direction an observation is keyed by.
///
/// This mirrors the exact Linux single-SA identity used by relocation: an SA
/// sharing a destination/SPI/protocol under a different lookup mark or XFRM
/// interface identifier is a *different* SA, so cross-SA attribution is
/// rejected by exact key comparison.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EspPeerObservationKey {
    /// Destination/protocol/SPI identity; the address family is derived from
    /// the destination and can never be dropped or mixed.
    pub id: XfrmId,
    /// Linux lookup mark selecting a marked SA, when configured.
    pub mark: Option<XfrmMark>,
    /// XFRM interface identifier, when configured.
    pub if_id: Option<u32>,
    /// Traffic direction. Only inbound SAs produce decap observations; the
    /// direction is part of the key so it cannot be dropped.
    pub direction: XfrmDirection,
}

impl EspPeerObservationKey {
    /// Address family of the SA outer path, derived from the destination.
    #[must_use]
    pub const fn address_family(&self) -> EspPeerAddressFamily {
        match self.id.destination {
            IpAddress::Ipv4(_) => EspPeerAddressFamily::Ipv4,
            IpAddress::Ipv6(_) => EspPeerAddressFamily::Ipv6,
        }
    }

    /// True when another key names the same kernel identity fields but a
    /// different direction.
    fn same_identity_other_direction(&self, other: &Self) -> bool {
        self.id == other.id
            && self.mark == other.mark
            && self.if_id == other.if_id
            && self.direction != other.direction
    }
}

impl fmt::Debug for EspPeerObservationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationKey")
            .field("address_family", &self.address_family())
            .field("direction", &self.direction)
            .field("has_mark", &self.mark.is_some())
            .field("has_if_id", &self.if_id.is_some())
            .field("identity", &"<redacted>")
            .finish()
    }
}

/// Address family of an observed outer path.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerAddressFamily {
    /// IPv4 outer path.
    Ipv4,
    /// IPv6 outer path.
    Ipv6,
}

/// Registration of one inbound integrity-protected SA with the boundary.
///
/// The `current_outer_source` pair is the baseline the caller proved when the
/// SA was established (or last rebased via
/// [`EspPeerObservationBoundary::update_current_source`]); authenticated
/// traffic from that source produces no observation. The registration is
/// refused for crypt-only SAs: post-decrypt delivery on an SA without
/// integrity is not authentication and cannot anchor an observation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationRegistration {
    /// Exact SA identity and direction.
    pub key: EspPeerObservationKey,
    /// Current authenticated encapsulation source address.
    pub current_outer_source: IpAddress,
    /// Current authenticated encapsulation source port (host byte order).
    pub current_outer_source_port: u16,
    /// Caller assertion that the SA is integrity- or AEAD-protected.
    pub integrity_protected: bool,
}

impl fmt::Debug for EspPeerObservationRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationRegistration")
            .field("key", &self.key)
            .field("integrity_protected", &self.integrity_protected)
            .field("current_outer_source", &"<redacted>")
            .finish()
    }
}

/// A raw kernel-attributed ESP decap event presented to the boundary.
///
/// Sources must construct this only for packets the kernel accepted on the
/// exact SA after integrity verification and the final replay advance, in the
/// same network namespace the scope was minted for. `cursor` is the source's
/// monotonic event sequence for this SA stream; `dropped_since_previous`
/// reports producer-side loss the source itself detected since the previous
/// event for this SA (zero when none).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationEvent {
    /// Scope the event was observed in; must match the boundary scope.
    pub scope: EspPeerObservationScope,
    /// Exact SA identity and direction the kernel attributed the packet to.
    pub key: EspPeerObservationKey,
    /// Trust-anchor grade of the event.
    pub provenance: EspPeerEventProvenance,
    /// Observed encapsulation source address.
    pub outer_source: IpAddress,
    /// Observed encapsulation source port (host byte order).
    pub outer_source_port: u16,
    /// Physical ingress interface index, when the source captured one. The
    /// interface scope cannot be dropped: events without it are rejected.
    pub ingress_ifindex: Option<u32>,
    /// Source-monotonic per-SA event cursor used for staleness rejection.
    pub cursor: u64,
    /// Producer-side events the source knows were lost since the previous
    /// event for this SA. Zero asserts no known loss.
    pub dropped_since_previous: u64,
}

impl fmt::Debug for EspPeerObservationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationEvent")
            .field("scope", &self.scope)
            .field("key", &self.key)
            .field("provenance", &self.provenance)
            .field("cursor", &self.cursor)
            .field("dropped_since_previous", &self.dropped_since_previous)
            .field("has_ingress_ifindex", &self.ingress_ifindex.is_some())
            .field("outer_source", &"<redacted>")
            .finish()
    }
}

/// Explicit loss status retained on an observation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerObservationLoss {
    /// No loss was detected for this observation.
    None,
    /// The event source reported producer-side loss before the observed
    /// packet; earlier new-source traffic for this SA may have been missed.
    SourceAttributed,
    /// A previous observation for this SA was still undrained when further
    /// distinct-source traffic arrived; the boundary closed the slot
    /// (fail-closed) and newer candidate sources were rejected, so this
    /// observation may not name the newest source.
    OverflowClosed,
}

/// One bounded, typed observation of an authenticated new outer source.
///
/// Produced exactly once per distinct new source per SA (see the boundary
/// rules), retaining only the minimum routing facts needed for policy. The
/// facts are exposed as typed fields; `Debug` and `Display` never print them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservation {
    /// Exact SA identity and direction this observation belongs to.
    pub key: EspPeerObservationKey,
    /// Address family of the observed outer source.
    pub address_family: EspPeerAddressFamily,
    /// Physical ingress interface index the packet arrived on.
    pub ingress_ifindex: u32,
    /// Observed encapsulation source address.
    pub outer_source: IpAddress,
    /// Observed encapsulation source port (host byte order).
    pub outer_source_port: u16,
    /// Per-SA monotonic generation, starting at 1 for the first observation
    /// after registration and incrementing by one per observation. A gap in
    /// generations observed by the consumer indicates missed observations.
    pub generation: u64,
    /// Explicit loss status for this observation.
    pub loss: EspPeerObservationLoss,
}

impl fmt::Debug for EspPeerObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservation")
            .field("key", &self.key)
            .field("address_family", &self.address_family)
            .field("generation", &self.generation)
            .field("loss", &self.loss)
            .field("outer_source", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for EspPeerObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ESP peer observation (family: {:?}, generation: {}, loss: {:?})",
            self.address_family, self.generation, self.loss
        )
    }
}

/// Exact lifecycle termination record returned when an SA is torn down.
///
/// Teardown drains any pending observation, removes all observation state for
/// the SA, and reports the final per-SA generation so the consumer can close
/// its own generation tracking deterministically.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationTeardown {
    /// Exact SA identity and direction that was terminated.
    pub key: EspPeerObservationKey,
    /// Final per-SA observation generation at termination.
    pub final_generation: u64,
    /// The drained pending observation, when one was still outstanding.
    pub drained: Option<EspPeerObservation>,
}

impl fmt::Debug for EspPeerObservationTeardown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationTeardown")
            .field("key", &self.key)
            .field("final_generation", &self.final_generation)
            .field("drained", &self.drained.is_some())
            .finish()
    }
}

/// Value-free rejection label for an event the boundary refused.
///
/// Variants deliberately carry no payload: no addresses, ports, SPIs, marks,
/// or interface identities ever appear in diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerObservationRejection {
    /// The boundary was closed (namespace teardown) and no longer accepts
    /// events.
    BoundaryClosed,
    /// The event scope does not match the boundary scope; observations from
    /// different namespaces or sources cannot be cross-combined.
    ScopeMismatch,
    /// No SA is registered for the event's exact identity, including
    /// post-teardown arrivals (teardown removes all state).
    UnknownSa,
    /// The identity fields match a registered SA but the direction differs.
    WrongDirection,
    /// The observed outer source family differs from the SA family.
    FamilyMismatch,
    /// The observed source is unspecified or the port is zero.
    MalformedSource,
    /// The event carries no ingress interface identity; interface scope
    /// cannot be dropped.
    MissingIngressScope,
    /// The event's provenance is below the required post-final-replay
    /// accepted grade (unauthenticated or replay-losing traffic).
    InsufficientProvenance,
    /// The event cursor is not newer than the last accepted cursor for this
    /// SA (replayed, duplicated, or reordered traffic).
    StaleCursor,
    /// The SA slot still holds an undrained observation and is closed
    /// fail-closed; drain it before further candidates can be accepted.
    SlotOverflowClosed,
}

impl EspPeerObservationRejection {
    /// Stable payload-free label suitable for metrics and logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BoundaryClosed => "boundary_closed",
            Self::ScopeMismatch => "scope_mismatch",
            Self::UnknownSa => "unknown_sa",
            Self::WrongDirection => "wrong_direction",
            Self::FamilyMismatch => "family_mismatch",
            Self::MalformedSource => "malformed_source",
            Self::MissingIngressScope => "missing_ingress_scope",
            Self::InsufficientProvenance => "insufficient_provenance",
            Self::StaleCursor => "stale_cursor",
            Self::SlotOverflowClosed => "slot_overflow_closed",
        }
    }
}

impl fmt::Display for EspPeerObservationRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Outcome of presenting one event to the boundary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerIngestOutcome {
    /// The event was authenticated, attributed, and named a new outer source;
    /// exactly one observation is now pending for the SA.
    ObservationQueued,
    /// The event was authenticated and attributed but named the current or
    /// already-reported source; no observation was produced.
    NoChange,
    /// The event was rejected.
    Rejected(EspPeerObservationRejection),
}

/// A source of kernel-attributed ESP decap events.
///
/// # Contract
///
/// Implementations must only yield events that are: observed in the same
/// network namespace the [`EspPeerObservationScope`] was minted for (with the
/// transport's sender verified, so local spoofed notifications are excluded);
/// attributed by the kernel to the exact SA identity (destination, SPI,
/// protocol, family, lookup mark, and XFRM `if_id`) and direction; emitted
/// after integrity verification *and* the final anti-replay advance for that
/// SA (`PostFinalReplayAccepted`); captured with the physical ingress
/// interface index and outer encapsulation source address/port; and sequenced
/// by a monotonic per-SA cursor with explicit producer-side loss accounting.
/// Sources must never yield events for crypt-only SAs. See the module-level
/// trust-anchor documentation for why stock `XFRM_MSG_MAPPING` does not meet
/// this contract.
pub trait EspPeerObservationSource {
    /// Pull the next available event, or `None` when no event is pending.
    fn next_event(&mut self) -> Option<EspPeerObservationEvent>;
}

/// Scripted in-memory [`EspPeerObservationSource`] for tests and fixtures.
///
/// This mirrors the crate's mock-backend idiom: it replays caller-supplied
/// (captured or synthetic) events verbatim and performs no provenance
/// judgment of its own. It must not be used to mint events from unverified
/// traffic in production paths.
#[derive(Debug, Default)]
pub struct ScriptedEspPeerObservationSource {
    events: VecDeque<EspPeerObservationEvent>,
}

impl ScriptedEspPeerObservationSource {
    /// Create an empty scripted source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue an event for replay.
    pub fn push(&mut self, event: EspPeerObservationEvent) {
        self.events.push_back(event);
    }

    /// Number of queued events not yet consumed.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.events.len()
    }
}

impl EspPeerObservationSource for ScriptedEspPeerObservationSource {
    fn next_event(&mut self) -> Option<EspPeerObservationEvent> {
        self.events.pop_front()
    }
}

/// Per-SA bounded observation slot.
#[derive(Debug)]
struct ObservationSlot {
    current_source: (IpAddress, u16),
    last_reported: Option<(IpAddress, u16)>,
    last_cursor: Option<u64>,
    source_loss: bool,
    generation: u64,
    pending: Option<EspPeerObservation>,
    overflow_closed: bool,
}

impl ObservationSlot {
    fn new(current_source: (IpAddress, u16)) -> Self {
        Self {
            current_source,
            last_reported: None,
            last_cursor: None,
            source_loss: false,
            generation: 0,
            pending: None,
            overflow_closed: false,
        }
    }
}

/// Bounded registry of authenticated ESP peer outer-source observations.
///
/// One boundary is pinned to one [`EspPeerObservationScope`]. See the module
/// documentation for the trust anchor, acceptance rules, and bounds.
#[derive(Debug)]
pub struct EspPeerObservationBoundary {
    scope: EspPeerObservationScope,
    capacity: usize,
    slots: HashMap<EspPeerObservationKey, ObservationSlot>,
    closed: bool,
}

impl EspPeerObservationBoundary {
    /// Create a boundary with the default registry capacity.
    #[must_use]
    pub fn new(scope: EspPeerObservationScope) -> Self {
        Self::with_capacity(scope, DEFAULT_ESP_PEER_OBSERVATION_CAPACITY)
    }

    /// Create a boundary with an explicit registry capacity.
    #[must_use]
    pub fn with_capacity(scope: EspPeerObservationScope, capacity: usize) -> Self {
        Self {
            scope,
            capacity,
            slots: HashMap::new(),
            closed: false,
        }
    }

    /// The scope this boundary is pinned to.
    #[must_use]
    pub const fn scope(&self) -> EspPeerObservationScope {
        self.scope
    }

    /// Number of SAs currently tracked.
    #[must_use]
    pub fn tracked_len(&self) -> usize {
        self.slots.len()
    }

    /// Register one inbound integrity-protected SA for observation.
    ///
    /// Fails for non-inbound directions, crypt-only SAs, zero SPIs, non-ESP
    /// protocols, unspecified baseline addresses, zero baseline ports,
    /// family-inconsistent baselines, duplicate registrations, a closed
    /// boundary, and a full registry. All failures are value-free.
    pub fn register_sa(
        &mut self,
        registration: EspPeerObservationRegistration,
    ) -> Result<(), XfrmError> {
        if self.closed {
            return Err(XfrmError::Unavailable);
        }
        if !matches!(registration.key.direction, XfrmDirection::In) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.direction",
                "only inbound SAs produce decap observations",
            ));
        }
        if !registration.integrity_protected {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.integrity",
                "crypt-only SAs cannot anchor authenticated observations",
            ));
        }
        if registration.key.id.spi == 0 {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.spi",
                "spi must be nonzero",
            ));
        }
        if registration.key.id.protocol != 50 {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.protocol",
                "peer observations support ESP only",
            ));
        }
        if registration.current_outer_source.is_unspecified()
            || registration.current_outer_source_port == 0
        {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.current_source",
                "current outer source must be specified with a nonzero port",
            ));
        }
        if registration.key.address_family() != family_of(registration.current_outer_source) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.current_source",
                "current outer source family must match the SA family",
            ));
        }
        if self.slots.contains_key(&registration.key) {
            return Err(XfrmError::AlreadyExists);
        }
        if self.slots.len() >= self.capacity {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.capacity",
                "observation registry capacity reached",
            ));
        }
        self.slots.insert(
            registration.key,
            ObservationSlot::new((
                registration.current_outer_source,
                registration.current_outer_source_port,
            )),
        );
        Ok(())
    }

    /// Rebase the authenticated current outer source after the consumer
    /// applied its own authenticated path update (for example an RFC 7296
    /// section 2.23 recovery followed by [`crate::RelocateSaRequest`]).
    ///
    /// The last-reported marker is cleared so traffic from the previous
    /// source is once again observation-worthy; any pending observation is
    /// left for the consumer to drain.
    pub fn update_current_source(
        &mut self,
        key: &EspPeerObservationKey,
        new_source: IpAddress,
        new_source_port: u16,
    ) -> Result<(), XfrmError> {
        if new_source.is_unspecified() || new_source_port == 0 {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.current_source",
                "current outer source must be specified with a nonzero port",
            ));
        }
        if key.address_family() != family_of(new_source) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.current_source",
                "current outer source family must match the SA family",
            ));
        }
        let slot = self.slots.get_mut(key).ok_or(XfrmError::NotFound)?;
        slot.current_source = (new_source, new_source_port);
        slot.last_reported = None;
        Ok(())
    }

    /// Present one event to the boundary.
    pub fn ingest_event(&mut self, event: EspPeerObservationEvent) -> EspPeerIngestOutcome {
        if self.closed {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::BoundaryClosed);
        }
        if event.scope != self.scope {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::ScopeMismatch);
        }
        let Some(slot) = self.slots.get_mut(&event.key) else {
            if self
                .slots
                .keys()
                .any(|key| key.same_identity_other_direction(&event.key))
            {
                return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::WrongDirection);
            }
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::UnknownSa);
        };
        if family_of(event.outer_source) != event.key.address_family() {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::FamilyMismatch);
        }
        if event.outer_source.is_unspecified() || event.outer_source_port == 0 {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::MalformedSource);
        }
        let Some(ingress_ifindex) = event.ingress_ifindex else {
            return EspPeerIngestOutcome::Rejected(
                EspPeerObservationRejection::MissingIngressScope,
            );
        };
        if event.provenance != EspPeerEventProvenance::PostFinalReplayAccepted {
            return EspPeerIngestOutcome::Rejected(
                EspPeerObservationRejection::InsufficientProvenance,
            );
        }
        if slot.last_cursor.is_some_and(|last| event.cursor <= last) {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::StaleCursor);
        }
        slot.last_cursor = Some(event.cursor);
        if event.dropped_since_previous > 0 {
            slot.source_loss = true;
        }
        let source = (event.outer_source, event.outer_source_port);
        if source == slot.current_source || slot.last_reported == Some(source) {
            return EspPeerIngestOutcome::NoChange;
        }
        if slot.pending.is_some() || slot.overflow_closed {
            // One outstanding observation per SA: a further distinct source
            // closes the slot fail-closed until the consumer drains it.
            slot.overflow_closed = true;
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed);
        }
        slot.generation += 1;
        let loss = if slot.source_loss {
            EspPeerObservationLoss::SourceAttributed
        } else {
            EspPeerObservationLoss::None
        };
        let observation = EspPeerObservation {
            key: event.key,
            address_family: event.key.address_family(),
            ingress_ifindex,
            outer_source: event.outer_source,
            outer_source_port: event.outer_source_port,
            generation: slot.generation,
            loss,
        };
        slot.pending = Some(observation);
        slot.last_reported = Some(source);
        EspPeerIngestOutcome::ObservationQueued
    }

    /// Drain every event a source currently has queued, returning how many
    /// were consumed (accepted or rejected).
    pub fn ingest_available<S: EspPeerObservationSource + ?Sized>(
        &mut self,
        source: &mut S,
    ) -> usize {
        let mut consumed = 0;
        while let Some(event) = source.next_event() {
            self.ingest_event(event);
            consumed += 1;
        }
        consumed
    }

    /// Take the pending observation for an SA, if one is outstanding.
    ///
    /// Draining clears the slot: if it was overflow-closed, the returned
    /// observation carries [`EspPeerObservationLoss::OverflowClosed`] and the
    /// last-reported marker is cleared so the next distinct source produces a
    /// fresh observation (explicit recovery after suspected loss).
    #[must_use]
    pub fn drain(&mut self, key: &EspPeerObservationKey) -> Option<EspPeerObservation> {
        let slot = self.slots.get_mut(key)?;
        let mut observation = slot.pending.take()?;
        if slot.overflow_closed {
            observation.loss = EspPeerObservationLoss::OverflowClosed;
            slot.overflow_closed = false;
            slot.last_reported = None;
        }
        Some(observation)
    }

    /// Take every pending observation. The result is bounded by the registry
    /// capacity.
    #[must_use]
    pub fn drain_all(&mut self) -> Vec<EspPeerObservation> {
        let keys: Vec<EspPeerObservationKey> = self.slots.keys().copied().collect();
        let mut out = Vec::new();
        for key in keys {
            if let Some(observation) = self.drain(&key) {
                out.push(observation);
            }
        }
        out
    }

    /// Drain and remove all observation state for one SA, returning the exact
    /// termination record. Events for the SA are rejected afterwards.
    pub fn teardown(
        &mut self,
        key: &EspPeerObservationKey,
    ) -> Result<EspPeerObservationTeardown, XfrmError> {
        let mut slot = self.slots.remove(key).ok_or(XfrmError::NotFound)?;
        let mut drained = slot.pending.take();
        if let (Some(observation), true) = (&mut drained, slot.overflow_closed) {
            observation.loss = EspPeerObservationLoss::OverflowClosed;
        }
        Ok(EspPeerObservationTeardown {
            key: *key,
            final_generation: slot.generation,
            drained,
        })
    }

    /// Tear down every tracked SA and close the boundary (for example on
    /// namespace teardown). All later events and registrations are rejected.
    pub fn close(&mut self) -> Vec<EspPeerObservationTeardown> {
        let keys: Vec<EspPeerObservationKey> = self.slots.keys().copied().collect();
        let mut out = Vec::new();
        for key in keys {
            if let Ok(record) = self.teardown(&key) {
                out.push(record);
            }
        }
        self.closed = true;
        out
    }
}

const fn family_of(address: IpAddress) -> EspPeerAddressFamily {
    match address {
        IpAddress::Ipv4(_) => EspPeerAddressFamily::Ipv4,
        IpAddress::Ipv6(_) => EspPeerAddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5737 / RFC 3849 documentation-only fixture addresses.
    const CURRENT: IpAddress = IpAddress::Ipv4([192, 0, 2, 1]);
    const NEW_SOURCE: IpAddress = IpAddress::Ipv4([198, 51, 100, 23]);
    const THIRD_SOURCE: IpAddress = IpAddress::Ipv4([203, 0, 113, 7]);
    const LOCAL: IpAddress = IpAddress::Ipv4([192, 0, 2, 2]);
    const CURRENT_PORT: u16 = 4500;
    const NEW_PORT: u16 = 32768;
    const IFINDEX: u32 = 42;

    fn key() -> EspPeerObservationKey {
        EspPeerObservationKey {
            id: XfrmId {
                destination: LOCAL,
                spi: 0x0abc_1234,
                protocol: 50,
            },
            mark: None,
            if_id: None,
            direction: XfrmDirection::In,
        }
    }

    fn registration() -> EspPeerObservationRegistration {
        EspPeerObservationRegistration {
            key: key(),
            current_outer_source: CURRENT,
            current_outer_source_port: CURRENT_PORT,
            integrity_protected: true,
        }
    }

    fn event(
        scope: EspPeerObservationScope,
        source: IpAddress,
        port: u16,
        cursor: u64,
    ) -> EspPeerObservationEvent {
        EspPeerObservationEvent {
            scope,
            key: key(),
            provenance: EspPeerEventProvenance::PostFinalReplayAccepted,
            outer_source: source,
            outer_source_port: port,
            ingress_ifindex: Some(IFINDEX),
            cursor,
            dropped_since_previous: 0,
        }
    }

    fn boundary() -> (EspPeerObservationScope, EspPeerObservationBoundary) {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::new(scope);
        boundary.register_sa(registration()).unwrap();
        (scope, boundary)
    }

    #[test]
    fn authenticated_current_source_produces_no_observation() {
        let (scope, mut boundary) = boundary();
        let outcome = boundary.ingest_event(event(scope, CURRENT, CURRENT_PORT, 1));
        assert_eq!(outcome, EspPeerIngestOutcome::NoChange);
        assert_eq!(boundary.drain(&key()), None);
    }

    #[test]
    fn authenticated_new_source_produces_exactly_one_typed_observation() {
        let (scope, mut boundary) = boundary();
        let outcome = boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1));
        assert_eq!(outcome, EspPeerIngestOutcome::ObservationQueued);
        // Same source again (fresh cursor) is deduplicated: still exactly one.
        let outcome = boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2));
        assert_eq!(outcome, EspPeerIngestOutcome::NoChange);

        let observation = boundary.drain(&key()).expect("one observation pending");
        assert_eq!(observation.key, key());
        assert_eq!(observation.address_family, EspPeerAddressFamily::Ipv4);
        assert_eq!(observation.ingress_ifindex, IFINDEX);
        assert_eq!(observation.outer_source, NEW_SOURCE);
        assert_eq!(observation.outer_source_port, NEW_PORT);
        assert_eq!(observation.generation, 1);
        assert_eq!(observation.loss, EspPeerObservationLoss::None);
        assert_eq!(boundary.drain(&key()), None, "exactly one observation");
    }

    #[test]
    fn unauthenticated_and_pre_final_replay_events_are_rejected() {
        let (scope, mut boundary) = boundary();
        for provenance in [
            EspPeerEventProvenance::UnauthenticatedPacketPath,
            EspPeerEventProvenance::PostIntegrityPreFinalReplay,
        ] {
            let mut spoof = event(scope, NEW_SOURCE, NEW_PORT, 1);
            spoof.provenance = provenance;
            assert_eq!(
                boundary.ingest_event(spoof),
                EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::InsufficientProvenance)
            );
        }
        assert_eq!(boundary.drain(&key()), None);
    }

    #[test]
    fn unknown_and_cross_sa_events_are_rejected() {
        let (scope, mut boundary) = boundary();
        // Unknown SPI.
        let mut unknown = event(scope, NEW_SOURCE, NEW_PORT, 1);
        unknown.key.id.spi = 0x0abc_9999;
        assert_eq!(
            boundary.ingest_event(unknown),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::UnknownSa)
        );
        // Cross-SA: same SPI under a different XFRM interface identifier.
        let mut cross = event(scope, NEW_SOURCE, NEW_PORT, 1);
        cross.key.if_id = Some(7);
        assert_eq!(
            boundary.ingest_event(cross),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::UnknownSa)
        );
        // Cross-SA: same SPI under a different lookup mark.
        let mut marked = event(scope, NEW_SOURCE, NEW_PORT, 1);
        marked.key.mark = Some(XfrmMark {
            value: 1,
            mask: u32::MAX,
        });
        assert_eq!(
            boundary.ingest_event(marked),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::UnknownSa)
        );
        assert_eq!(boundary.drain(&key()), None);
    }

    #[test]
    fn wrong_direction_is_rejected_at_registration_and_ingest() {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::new(scope);
        boundary.register_sa(registration()).unwrap();

        let mut out_registration = registration();
        out_registration.key.direction = XfrmDirection::Out;
        assert!(matches!(
            boundary.register_sa(out_registration),
            Err(XfrmError::InvalidConfig { .. })
        ));

        let mut out_event = event(scope, NEW_SOURCE, NEW_PORT, 1);
        out_event.key.direction = XfrmDirection::Out;
        assert_eq!(
            boundary.ingest_event(out_event),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::WrongDirection)
        );
        assert_eq!(boundary.drain(&key()), None);
    }

    #[test]
    fn stale_and_replayed_cursors_are_rejected() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 10)),
            EspPeerIngestOutcome::ObservationQueued
        );
        // A replayed/duplicated cursor is rejected.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 10)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::StaleCursor)
        );
        // An older cursor (reorder) is rejected.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 9)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::StaleCursor)
        );
    }

    #[test]
    fn post_teardown_events_are_rejected_and_termination_is_exact() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let record = boundary.teardown(&key()).expect("registered");
        assert_eq!(record.key, key());
        assert_eq!(record.final_generation, 1);
        let drained = record.drained.expect("pending observation drained");
        assert_eq!(drained.outer_source, NEW_SOURCE);
        assert_eq!(boundary.tracked_len(), 0, "state removed deterministically");

        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::UnknownSa)
        );
        assert!(
            matches!(boundary.teardown(&key()), Err(XfrmError::NotFound)),
            "teardown is exact and terminal"
        );
        // Re-registration starts a fresh lifecycle with a fresh generation.
        boundary.register_sa(registration()).unwrap();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(boundary.drain(&key()).unwrap().generation, 1);
    }

    #[test]
    fn overflow_is_explicit_and_fail_closed() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        // A further distinct source while the first observation is undrained
        // closes the slot explicitly instead of overwriting.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );
        // Fail-closed: subsequent distinct sources are rejected until drain.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );

        let observation = boundary.drain(&key()).expect("pending");
        assert_eq!(
            observation.outer_source, NEW_SOURCE,
            "first observation kept"
        );
        assert_eq!(
            observation.loss,
            EspPeerObservationLoss::OverflowClosed,
            "overflow is explicit on the drained observation"
        );
        // After drain the slot recovers: the next distinct source queues fresh.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 4)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let recovered = boundary.drain(&key()).unwrap();
        assert_eq!(recovered.outer_source, THIRD_SOURCE);
        assert_eq!(recovered.generation, 2, "generation stays monotonic");
    }

    #[test]
    fn source_attributed_loss_is_explicit() {
        let (scope, mut boundary) = boundary();
        let mut lossy = event(scope, NEW_SOURCE, NEW_PORT, 1);
        lossy.dropped_since_previous = 2;
        assert_eq!(
            boundary.ingest_event(lossy),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.drain(&key()).unwrap().loss,
            EspPeerObservationLoss::SourceAttributed
        );
    }

    #[test]
    fn scope_and_interface_scope_cannot_be_dropped_or_cross_combined() {
        let (scope, mut boundary) = boundary();
        // Foreign scope (different namespace/source) cannot cross-combine.
        let foreign = event(EspPeerObservationScope::new(), NEW_SOURCE, NEW_PORT, 1);
        assert_eq!(
            boundary.ingest_event(foreign),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::ScopeMismatch)
        );
        // Interface scope cannot be dropped.
        let mut no_ifindex = event(scope, NEW_SOURCE, NEW_PORT, 1);
        no_ifindex.ingress_ifindex = None;
        assert_eq!(
            boundary.ingest_event(no_ifindex),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::MissingIngressScope)
        );
        // Family scope cannot be mixed.
        let mut v6 = event(scope, NEW_SOURCE, NEW_PORT, 1);
        // RFC 3849 documentation prefix 2001:db8::/32.
        v6.outer_source =
            IpAddress::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            boundary.ingest_event(v6),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::FamilyMismatch)
        );
        // Whole-boundary close (namespace teardown) rejects everything.
        let records = boundary.close();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].final_generation, 0);
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::BoundaryClosed)
        );
        assert!(matches!(
            boundary.register_sa(registration()),
            Err(XfrmError::Unavailable)
        ));
    }

    #[test]
    fn registry_capacity_is_bounded() {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::with_capacity(scope, 1);
        boundary.register_sa(registration()).unwrap();
        let mut second = registration();
        second.key.id.spi = 0x0abc_9999;
        assert!(matches!(
            boundary.register_sa(second),
            Err(XfrmError::InvalidConfig { field, .. }) if field == "esp_peer_observation.capacity"
        ));
    }

    #[test]
    fn crypt_only_sa_cannot_anchor_observations() {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::new(scope);
        let mut crypt_only = registration();
        crypt_only.integrity_protected = false;
        assert!(matches!(
            boundary.register_sa(crypt_only),
            Err(XfrmError::InvalidConfig { field, .. }) if field == "esp_peer_observation.integrity"
        ));
    }

    #[test]
    fn update_current_source_rebases_after_authenticated_path_update() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let observation = boundary.drain(&key()).unwrap();
        // The consumer applies its own authenticated relocation, then rebases.
        boundary
            .update_current_source(
                &key(),
                observation.outer_source,
                observation.outer_source_port,
            )
            .unwrap();
        // Traffic from the new current source produces nothing.
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::NoChange
        );
        // Traffic from the previous source is observation-worthy again.
        assert_eq!(
            boundary.ingest_event(event(scope, CURRENT, CURRENT_PORT, 3)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(boundary.drain(&key()).unwrap().generation, 2);
    }

    #[test]
    fn scripted_source_feeds_the_boundary() {
        let (scope, mut boundary) = boundary();
        let mut source = ScriptedEspPeerObservationSource::new();
        source.push(event(scope, CURRENT, CURRENT_PORT, 1));
        source.push(event(scope, NEW_SOURCE, NEW_PORT, 2));
        let mut foreign = event(scope, THIRD_SOURCE, NEW_PORT, 3);
        foreign.scope = EspPeerObservationScope::new();
        source.push(foreign);
        assert_eq!(source.pending_len(), 3);

        assert_eq!(boundary.ingest_available(&mut source), 3);
        assert_eq!(source.pending_len(), 0);
        let drained = boundary.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].outer_source, NEW_SOURCE);
    }

    #[test]
    fn malformed_sources_are_rejected() {
        let (scope, mut boundary) = boundary();
        let mut unspecified = event(scope, NEW_SOURCE, NEW_PORT, 1);
        unspecified.outer_source = IpAddress::Ipv4([0, 0, 0, 0]);
        assert_eq!(
            boundary.ingest_event(unspecified),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::MalformedSource)
        );
        let mut zero_port = event(scope, NEW_SOURCE, 0, 1);
        zero_port.outer_source_port = 0;
        assert_eq!(
            boundary.ingest_event(zero_port),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::MalformedSource)
        );
    }

    #[test]
    fn diagnostics_remain_value_free() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let observation = boundary.drain(&key()).unwrap();
        let teardown = boundary.teardown(&key()).unwrap();
        let rejection = EspPeerObservationRejection::StaleCursor;
        let ev = event(scope, NEW_SOURCE, NEW_PORT, 2);
        let reg = registration();

        let haystack = format!(
            "{observation:?}\n{observation}\n{teardown:?}\n{rejection:?}\n{rejection}\n{ev:?}\n{reg:?}\n{:?}\n{boundary:?}",
            key()
        );
        for forbidden in [
            "192.0.2",
            "198.51.100",
            "203.0.113",
            "4500",
            "32768",
            "0xabc1234",
            "abc1234",
            "180171828", // spi decimal
            "42",        // ingress ifindex
        ] {
            assert!(
                !haystack.contains(forbidden),
                "diagnostics leaked {forbidden:?}: {haystack}"
            );
        }
        // Labels and non-sensitive metadata remain useful.
        assert!(haystack.contains("PostFinalReplayAccepted"));
        assert!(haystack.contains("stale_cursor"));
        assert!(haystack.contains("generation"));
    }
}
