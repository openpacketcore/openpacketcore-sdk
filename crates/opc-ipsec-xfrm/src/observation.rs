//! Authenticated ESP peer outer-source observations for NAT rebinding.
//!
//! A [`LinuxEspPeerObservationMonitor`] turns kernel-attributed ESP decap
//! events into bounded, typed observations: an established inbound ESP-in-UDP
//! SA that starts arriving from a new outer source produces one
//! [`EspPeerObservation`] retaining only the routing facts needed for policy
//! (address family, kernel ingress-interface identity, encapsulation source
//! address and port, a monotonic per-SA generation, and explicit loss
//! status). This is the observation authority a product needs before an
//! RFC 7296 section 2.23 recovery procedure can update the path. It is
//! deliberately distinct from applying a caller-supplied relocation
//! ([`crate::RelocateSaRequest`]): the monitor reports; product policy decides
//! whether to relocate.
//!
//! # Trust anchor
//!
//! "Authenticated" means the Linux ESP input path verified ICV/AEAD and
//! `xfrm_replay_recheck` returned success for the exact SA. The CO-RE source
//! observes that final decision while the SA lock remains held immediately
//! before Linux advances replay state, so a concurrent duplicate cannot also
//! win. Raw sockets, tc/XDP ingress copies, and stock `XFRM_MSG_MAPPING` must
//! not be adapted into this authority:
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
//! The production Linux source loads a committed CO-RE object inside the
//! namespace-bound XFRM actor. It owns all required tracing-link file
//! descriptors, binds source scope to `SO_NETNS_COOKIE`, keys maps by the
//! exact raw GETSA identity, and admits only integrity/AEAD-protected,
//! replay-enabled, non-offloaded inbound ESP-in-UDP SAs. Legacy states whose
//! kernel direction is unspecified (`0`) are treated as inbound only at the
//! input/replay hook; explicit outbound states are refused. Insert, delete,
//! update, offload, counter exhaustion, link loss, malformed packet shape,
//! and map-authority loss terminate the source fail-closed.
//!
//! Registration is staged: publish lifecycle state and an unarmed
//! registration, perform a second exact GETSA, verify the kernel lifecycle
//! generation, then arm. Teardown unpublishes first, waits for admitted hooks
//! to quiesce, reconciles the exact `cursor - dropped` record count, and
//! removes state deterministically. An authenticated post-relocation refresh
//! uses the same quiescent protocol, adopts only the expected lifecycle-change
//! reason, clears kernel and userspace dedup state together, and repeats the
//! unarmed/double-GETSA proof. Cancellation leaves teardown or refresh
//! resumable while the SA remains unpublished.
//!
//! # Acceptance rules
//!
//! The boundary rejects, with a value-free [`EspPeerObservationRejection`]:
//! events from a foreign scope (namespace cross-combination), events for
//! unknown or cross-SA identities, wrong-direction events, address-family
//! mismatches, malformed or interface-scope-less events, insufficient
//! provenance (unauthenticated or pre-final-replay), stale cursors (replay or
//! reorder), events for torn-down SAs, and events that would overflow a slot
//! that still holds an undrained observation (explicit, fail-closed). Draining
//! an overflowed slot does not reopen it: only a successful authenticated
//! refresh or teardown can recover, because the kernel may already suppress
//! the overflowed tuple. Memory, map capacity, ring capacity, and work per
//! poll are bounded; teardown drains and removes all state for the SA.
//!
//! # Source and lifecycle caveats
//!
//! - Cursors and generations are scoped to one registration lifecycle:
//!   registration starts a fresh lifecycle, and teardown is the epoch
//!   boundary. Consumers must not correlate generations across lifecycles.
//! - The boundary burns its accepted cursor for every event that passes
//!   attribution and staleness checks, including candidates later rejected by
//!   the fail-closed overflow rule. Source implementors must not retry a
//!   rejected cursor value; retry with a fresh cursor.
//! - Deduplication is keyed on the outer source address/port tuple only. An
//!   interface-only move (same source tuple, new ingress ifindex) is a
//!   deliberate `NoChange`; MOBIKE-style multihoming consumers must treat
//!   the ingress ifindex as an informational routing fact, not a change
//!   trigger.
//! - After a normal drain the drained source stays the last-reported marker,
//!   so further events from it are `NoChange` until the monitor completes an
//!   authenticated refresh. There is no public forget or caller-supplied
//!   baseline API.
//! - Each poll validates every tracked lifecycle both before and after record
//!   ingestion. The successful return is its authority linearization point.
//!   A later product-owned XFRM mutation is a new event; consumers must
//!   serialize those writers with poll/drain/relocation decisions rather than
//!   treating an earlier observation as perpetual SA authority.
//!
//! # Redaction
//!
//! Following the crate's redaction idiom, `Debug` and `Display` for every
//! public type here emit only stable labels and non-sensitive metadata
//! (generation numbers, family, direction, loss status). Raw addresses,
//! ports, SPIs, marks, interface indexes, and interface identifiers are never
//! printed. The routing facts themselves remain available through typed
//! fields for policy decisions; they are simply never formatted.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::XfrmError;
use crate::model::{IpAddress, XfrmDirection, XfrmId, XfrmMark};

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    LinuxEspPeerObservationConfig, LinuxEspPeerObservationHandle, LinuxEspPeerObservationMonitor,
};

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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationScope(NonZeroU64);

impl EspPeerObservationScope {
    /// Mint a fresh process-unique scope for a crate-owned source factory.
    ///
    /// The constructor is deliberately not public: callers cannot mint a
    /// source identity and use it to forge trusted events. Exhaustion fails
    /// closed instead of wrapping to an already-issued scope.
    fn try_new() -> Result<Self, XfrmError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let raw = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| XfrmError::Unavailable)?;
        NonZeroU64::new(raw).map(Self).ok_or(XfrmError::Unavailable)
    }

    #[cfg(test)]
    fn new() -> Self {
        match Self::try_new() {
            Ok(scope) => scope,
            Err(error) => panic!("test scope allocation failed: {error}"),
        }
    }
}

impl fmt::Debug for EspPeerObservationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationScope")
            .field("id", &"<opaque>")
            .finish()
    }
}

/// Opaque registration-lifecycle epoch.
///
/// A fresh epoch is assigned on every successful registration, including
/// re-registration of the same SA key. It prevents queued pre-teardown events
/// from entering a later lifecycle whose cursor and generation restarted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationEpoch(NonZeroU64);

impl fmt::Debug for EspPeerObservationEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationEpoch")
            .field("id", &"<opaque>")
            .finish()
    }
}

/// Provenance grade of a raw ESP peer event.
///
/// This type is private so downstream callers cannot assert the trusted grade.
/// A crate-owned source must construct every event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EspPeerEventProvenance {
    /// An unauthenticated packet-path signal (raw socket, tc/XDP ingress copy,
    /// or any pre-decryption observation). Never acceptable.
    #[cfg(test)]
    UnauthenticatedPacketPath,
    /// Kernel ESP decap verified integrity, but the packet may still lose the
    /// final anti-replay recheck (the stock `XFRM_MSG_MAPPING` grade). Never
    /// acceptable: replayed traffic could produce an observation.
    #[cfg(test)]
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
/// rejected by exact key comparison. Registration rejects the zero-forms
/// (unspecified destination, mask-0 mark, `if_id` 0) so boundary identity
/// cannot diverge from kernel identity.
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
/// The `current_outer_source` pair is the exact GETSA-proven baseline from SA
/// establishment or the monitor's last authenticated refresh. Authenticated
/// traffic from that source produces no observation. Registration is refused
/// for crypt-only SAs: post-decrypt delivery on an SA without integrity is not
/// authentication and cannot anchor an observation.
///
/// Identity fields must be in canonical kernel form: the SA destination must
/// be specified (an unspecified destination can never attribute a decap
/// event and would be a dead slot consuming registry capacity), a configured
/// mark must have a nonzero mask (mask 0 is equivalent to no mark), and a
/// configured `if_id` must be nonzero (0 is equivalent to unbound). The
/// boundary rejects the zero-forms instead of normalizing them so its identity
/// can never become broader than the kernel SA.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationRegistration {
    /// Exact SA identity and direction, in canonical kernel form.
    pub key: EspPeerObservationKey,
    /// Current authenticated encapsulation source address.
    pub current_outer_source: IpAddress,
    /// Current authenticated encapsulation source port (host byte order).
    pub current_outer_source_port: u16,
    /// Exact GETSA admission proved that the SA is integrity- or AEAD-protected.
    ///
    /// Production callers cannot construct this registration directly; the
    /// namespace-bound Linux coordinator derives it from kernel readback.
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
    scope: EspPeerObservationScope,
    /// Exact registration lifecycle the source observed.
    epoch: EspPeerObservationEpoch,
    /// Exact SA identity and direction the kernel attributed the packet to.
    key: EspPeerObservationKey,
    /// Trust-anchor grade of the event.
    provenance: EspPeerEventProvenance,
    /// Observed encapsulation source address.
    outer_source: IpAddress,
    /// Observed encapsulation source port (host byte order).
    outer_source_port: u16,
    /// Kernel `skb_iif` ingress-interface index, when the source captured one.
    /// The interface scope cannot be dropped: both `None` and `Some(0)` are
    /// rejected, because 0 is not a valid Linux interface index.
    ingress_ifindex: Option<u32>,
    /// Source-monotonic per-SA event cursor used for staleness rejection.
    ///
    /// The boundary burns its accepted cursor for every event that passes
    /// attribution and staleness checks, including candidates later rejected
    /// by the fail-closed overflow rule: implementors must not retry a
    /// rejected cursor value. Cursors are scoped to one registration
    /// lifecycle; a source restart that resets cursors wedges the slot into
    /// [`EspPeerObservationRejection::StaleCursor`], and recovery is teardown
    /// plus re-registration.
    cursor: u64,
    /// Producer-side events the source knows were lost since the previous
    /// event for this SA. Zero asserts no known loss.
    dropped_since_previous: u64,
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
///
/// The status is compositional: source-attributed loss and boundary overflow
/// can both apply to one observation and are never overwritten by each
/// other. Use [`Self::source_attributed`] and [`Self::overflow_closed`]
/// rather than exact variant matching.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerObservationLoss {
    /// No loss was detected for this observation.
    None,
    /// The event source reported producer-side loss since the previous
    /// observation for this SA; earlier new-source traffic may have been
    /// missed.
    SourceAttributed,
    /// A previous observation for this SA was still undrained when further
    /// distinct-source traffic arrived; the boundary closed the slot
    /// (fail-closed) and newer candidate sources were rejected, so this
    /// observation may not name the newest source.
    OverflowClosed,
    /// Both [`Self::SourceAttributed`] and [`Self::OverflowClosed`] apply.
    SourceAttributedOverflowClosed,
}

impl EspPeerObservationLoss {
    /// Whether the event source reported producer-side loss.
    #[must_use]
    pub const fn source_attributed(self) -> bool {
        matches!(
            self,
            Self::SourceAttributed | Self::SourceAttributedOverflowClosed
        )
    }

    /// Whether the boundary closed the slot fail-closed before this
    /// observation was drained.
    #[must_use]
    pub const fn overflow_closed(self) -> bool {
        matches!(
            self,
            Self::OverflowClosed | Self::SourceAttributedOverflowClosed
        )
    }

    /// Combine the boundary overflow fact into this status without erasing a
    /// source-attributed loss.
    const fn with_overflow(self) -> Self {
        match self {
            Self::None => Self::OverflowClosed,
            Self::SourceAttributed => Self::SourceAttributedOverflowClosed,
            overflowed => overflowed,
        }
    }

    /// Combine source-attributed loss without erasing an overflow fact.
    const fn with_source_attributed(self) -> Self {
        match self {
            Self::None => Self::SourceAttributed,
            Self::OverflowClosed => Self::SourceAttributedOverflowClosed,
            attributed => attributed,
        }
    }
}

/// One bounded, typed observation of an authenticated new outer source.
///
/// Produced exactly once per distinct new source per SA (see the boundary
/// rules), retaining only the minimum routing facts needed for policy. The
/// facts are exposed as typed fields; `Debug` and `Display` never print them.
///
/// Deduplication is keyed on the outer source address/port tuple only: an
/// interface-only move (same tuple, new ingress ifindex) produces no new
/// observation. MOBIKE-style multihoming consumers must therefore treat
/// [`Self::ingress_ifindex`] as an informational routing fact, not a change
/// trigger.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservation {
    /// Exact SA identity and direction this observation belongs to.
    pub key: EspPeerObservationKey,
    /// Opaque lifecycle epoch assigned when this SA registration began.
    pub epoch: EspPeerObservationEpoch,
    /// Address family of the observed outer source.
    pub address_family: EspPeerAddressFamily,
    /// Physical ingress interface index the packet arrived on.
    pub ingress_ifindex: u32,
    /// Observed encapsulation source address.
    pub outer_source: IpAddress,
    /// Observed encapsulation source port (host byte order).
    pub outer_source_port: u16,
    /// Per-SA monotonic generation, starting at 1 for the first observation
    /// after registration and incrementing by one per queued observation.
    /// Because a slot queues at most one outstanding observation, the
    /// generations a consumer drains are gapless within one registration
    /// lifecycle; missed observations are signaled explicitly through
    /// [`Self::loss`], never through generation gaps. Generations restart at
    /// 1 after teardown and re-registration, so consumers must treat
    /// teardown as the epoch boundary and never correlate generations across
    /// lifecycles.
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
/// its own generation tracking deterministically. The final generation is
/// scoped to the terminated registration lifecycle: it correlates with the
/// generations of observations drained during that lifecycle only, and a
/// later re-registration starts a fresh lifecycle at generation 1. Any known
/// loss not already carried by the drained observation remains explicit in
/// [`Self::residual_loss`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationTeardown {
    /// Exact SA identity and direction that was terminated.
    pub key: EspPeerObservationKey,
    /// Opaque epoch of the terminated registration lifecycle.
    pub epoch: EspPeerObservationEpoch,
    /// Final per-SA observation generation of the terminated registration
    /// lifecycle.
    pub final_generation: u64,
    /// The drained pending observation, when one was still outstanding.
    pub drained: Option<EspPeerObservation>,
    /// Known lifecycle loss not already carried by [`Self::drained`].
    ///
    /// This preserves producer loss reported after the pending observation
    /// was queued, and loss reported without any later changed-source event.
    pub residual_loss: EspPeerObservationLoss,
}

impl fmt::Debug for EspPeerObservationTeardown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspPeerObservationTeardown")
            .field("key", &self.key)
            .field("epoch", &self.epoch)
            .field("final_generation", &self.final_generation)
            .field("drained", &self.drained.is_some())
            .field("residual_loss", &self.residual_loss)
            .finish()
    }
}

/// Value-free rejection label for an event the boundary refused.
///
/// Variants deliberately carry no payload: no addresses, ports, SPIs, marks,
/// or interface identities ever appear in diagnostics.
///
/// The labels also constitute a limited SA-existence oracle: whoever can
/// present events can distinguish [`Self::UnknownSa`] from
/// [`Self::WrongDirection`] and thereby learn whether an identity is
/// registered. Treat exported rejection metrics as internal telemetry, not a
/// tenant-facing surface.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerObservationRejection {
    /// The boundary was closed (namespace teardown) and no longer accepts
    /// events.
    BoundaryClosed,
    /// The event scope does not match the boundary scope; observations from
    /// different namespaces or sources cannot be cross-combined.
    ScopeMismatch,
    /// The event belongs to an earlier or otherwise different registration
    /// lifecycle for the same SA key.
    LifecycleMismatch,
    /// No SA is registered for the event's exact identity, including
    /// post-teardown arrivals (teardown removes all state).
    UnknownSa,
    /// The identity fields match a registered SA but the direction differs.
    /// Distinguishing this from [`Self::UnknownSa`] costs a registry scan
    /// (O(capacity)) on the unknown-SA path only; attributed events never
    /// scan.
    WrongDirection,
    /// The observed outer source family differs from the SA family.
    FamilyMismatch,
    /// The observed source is unspecified or the port is zero.
    MalformedSource,
    /// The event carries no usable ingress interface identity (`None` or
    /// `Some(0)`); interface scope cannot be dropped.
    MissingIngressScope,
    /// The event's provenance is below the required post-final-replay
    /// accepted grade (unauthenticated or replay-losing traffic).
    InsufficientProvenance,
    /// The event cursor is not newer than the last accepted cursor for this
    /// SA (replayed, duplicated, or reordered traffic).
    StaleCursor,
    /// The SA slot still holds an undrained observation and is closed
    /// fail-closed; drain it before further candidates can be accepted. The
    /// rejected event's cursor is still consumed and must not be retried.
    SlotOverflowClosed,
    /// The per-lifecycle observation generation could no longer increase.
    /// The slot is closed fail-closed instead of repeating or wrapping a
    /// generation.
    GenerationOverflowClosed,
}

/// Number of [`EspPeerObservationRejection`] labels used for tally indexing.
const REJECTION_LABEL_COUNT: usize = 12;

const fn rejection_index(label: EspPeerObservationRejection) -> usize {
    match label {
        EspPeerObservationRejection::BoundaryClosed => 0,
        EspPeerObservationRejection::ScopeMismatch => 1,
        EspPeerObservationRejection::LifecycleMismatch => 2,
        EspPeerObservationRejection::UnknownSa => 3,
        EspPeerObservationRejection::WrongDirection => 4,
        EspPeerObservationRejection::FamilyMismatch => 5,
        EspPeerObservationRejection::MalformedSource => 6,
        EspPeerObservationRejection::MissingIngressScope => 7,
        EspPeerObservationRejection::InsufficientProvenance => 8,
        EspPeerObservationRejection::StaleCursor => 9,
        EspPeerObservationRejection::SlotOverflowClosed => 10,
        EspPeerObservationRejection::GenerationOverflowClosed => 11,
    }
}

impl EspPeerObservationRejection {
    /// Stable payload-free label suitable for metrics and logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BoundaryClosed => "boundary_closed",
            Self::ScopeMismatch => "scope_mismatch",
            Self::LifecycleMismatch => "lifecycle_mismatch",
            Self::UnknownSa => "unknown_sa",
            Self::WrongDirection => "wrong_direction",
            Self::FamilyMismatch => "family_mismatch",
            Self::MalformedSource => "malformed_source",
            Self::MissingIngressScope => "missing_ingress_scope",
            Self::InsufficientProvenance => "insufficient_provenance",
            Self::StaleCursor => "stale_cursor",
            Self::SlotOverflowClosed => "slot_overflow_closed",
            Self::GenerationOverflowClosed => "generation_overflow_closed",
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

/// Aggregate result of one bounded production-source poll.
///
/// Counts only: no per-event values are retained. Rejections are tallied per
/// label so a silent stream of one rejection kind (for example
/// [`EspPeerObservationRejection::InsufficientProvenance`]) is visible to
/// consumers without exposing provenance-bearing source records.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EspPeerIngestTally {
    /// Total events consumed from the source.
    pub events: usize,
    /// Events that queued an observation.
    pub observations_queued: usize,
    /// Events accepted without producing an observation.
    pub no_change: usize,
    /// Events rejected under any label.
    pub rejected: usize,
    /// Standalone source-loss records consumed.
    pub source_loss_records: usize,
    /// Terminal source state observed while draining, if any.
    ///
    /// Successful production-monitor polls always report `None`: a terminal
    /// source makes the monitor fail closed with an error and discard queued
    /// observations. This field remains available to internal source
    /// aggregation and deterministic boundary tests.
    pub source_terminal: Option<EspPeerObservationSourceTerminal>,
    rejections_by_label: [usize; REJECTION_LABEL_COUNT],
}

impl EspPeerIngestTally {
    /// Number of events rejected with the given label.
    #[must_use]
    pub fn rejections(&self, label: EspPeerObservationRejection) -> usize {
        self.rejections_by_label[rejection_index(label)]
    }

    fn record(&mut self, outcome: EspPeerIngestOutcome) {
        self.events += 1;
        match outcome {
            EspPeerIngestOutcome::ObservationQueued => self.observations_queued += 1,
            EspPeerIngestOutcome::NoChange => self.no_change += 1,
            EspPeerIngestOutcome::Rejected(label) => {
                self.rejected += 1;
                self.rejections_by_label[rejection_index(label)] += 1;
            }
        }
    }

    fn record_source_rejection(&mut self, label: EspPeerObservationRejection) {
        self.rejected += 1;
        self.rejections_by_label[rejection_index(label)] += 1;
    }
}

/// Redaction-safe terminal state of an observation source.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspPeerObservationSourceTerminal {
    /// The producer closed normally and will emit no further records.
    Closed,
    /// The producer failed to read its authenticated kernel channel.
    IoFailure,
    /// The producer observed a malformed or unauthenticated record.
    ProtocolFailure,
    /// The producer lost its kernel/program authority or lifecycle binding.
    AuthorityLost,
}

impl EspPeerObservationSourceTerminal {
    /// Stable value-free label suitable for metrics and logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IoFailure => "io_failure",
            Self::ProtocolFailure => "protocol_failure",
            Self::AuthorityLost => "authority_lost",
        }
    }
}

impl fmt::Display for EspPeerObservationSourceTerminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Source-attributed loss independent of a later packet event.
///
/// Fields are private because only a crate-owned, admitted source may bind
/// loss to an exact scope, SA, and registration epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationSourceLoss {
    scope: EspPeerObservationScope,
    epoch: EspPeerObservationEpoch,
    key: EspPeerObservationKey,
    dropped: NonZeroU64,
}

/// One pull result from a crate-owned observation source.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspPeerObservationSourceRecord {
    /// One authenticated, post-final-replay event.
    Event(EspPeerObservationEvent),
    /// Producer-side loss not dependent on a subsequent event.
    Loss(EspPeerObservationSourceLoss),
    /// No record is currently available; the source remains usable.
    Idle,
    /// The source is terminal and will emit no further trustworthy records.
    Terminal(EspPeerObservationSourceTerminal),
}

mod source_sealed {
    pub trait Sealed {}
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
/// after integrity verification and at the successful final anti-replay
/// decision for that SA (`PostFinalReplayAccepted`); captured with the kernel
/// `skb_iif` ingress-interface index and outer encapsulation source
/// address/port; and sequenced by a monotonic per-SA cursor with explicit
/// producer-side loss accounting.
/// Sources must never yield events for crypt-only SAs, and must not retry a
/// rejected cursor value (the boundary burns accepted cursors even for
/// overflow-rejected candidates). See the module-level trust-anchor
/// documentation for why stock `XFRM_MSG_MAPPING` does not meet this
/// contract.
pub trait EspPeerObservationSource: source_sealed::Sealed {
    /// Pull the next source record.
    ///
    /// [`EspPeerObservationSourceRecord::Idle`] is temporary. A terminal
    /// record is explicit and permanently closes the paired boundary.
    fn next_record(&mut self) -> EspPeerObservationSourceRecord;
}

/// Scripted in-memory [`EspPeerObservationSource`] for this crate's tests.
///
/// This is deliberately unavailable from feature-enabled library builds:
/// Cargo features are additive and therefore cannot form a production trust
/// boundary for provenance-bearing observations.
#[cfg(test)]
#[derive(Debug)]
struct ScriptedEspPeerObservationSource {
    records: VecDeque<EspPeerObservationSourceRecord>,
}

#[cfg(test)]
impl ScriptedEspPeerObservationSource {
    fn new() -> Self {
        Self {
            records: VecDeque::new(),
        }
    }

    /// Queue one scripted authenticated event.
    fn push(&mut self, event: EspPeerObservationEvent) {
        self.records
            .push_back(EspPeerObservationSourceRecord::Event(event));
    }

    /// Queue a source record, including explicit loss or termination.
    fn push_record(&mut self, record: EspPeerObservationSourceRecord) {
        self.records.push_back(record);
    }

    /// Number of queued records not yet consumed.
    #[must_use]
    fn pending_len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
impl source_sealed::Sealed for ScriptedEspPeerObservationSource {}

#[cfg(test)]
impl EspPeerObservationSource for ScriptedEspPeerObservationSource {
    fn next_record(&mut self) -> EspPeerObservationSourceRecord {
        self.records
            .pop_front()
            .unwrap_or(EspPeerObservationSourceRecord::Idle)
    }
}

/// Per-SA bounded observation slot.
struct ObservationSlot {
    epoch: EspPeerObservationEpoch,
    current_source: (IpAddress, u16),
    last_reported: Option<(IpAddress, u16)>,
    last_cursor: Option<u64>,
    /// Loss the source reported since the last queued observation. Consumed
    /// (and cleared) when the next observation is queued.
    source_loss: bool,
    generation: u64,
    pending: Option<EspPeerObservation>,
    overflow_closed: bool,
}

impl ObservationSlot {
    fn new(epoch: EspPeerObservationEpoch, current_source: (IpAddress, u16)) -> Self {
        Self {
            epoch,
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

impl fmt::Debug for ObservationSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservationSlot")
            .field("epoch", &self.epoch)
            .field("generation", &self.generation)
            .field("last_cursor", &self.last_cursor)
            .field("source_loss", &self.source_loss)
            .field("has_pending", &self.pending.is_some())
            .field("has_last_reported", &self.last_reported.is_some())
            .field("overflow_closed", &self.overflow_closed)
            .field("current_source", &"<redacted>")
            .finish()
    }
}

/// Bounded registry of authenticated ESP peer outer-source observations.
///
/// One boundary is pinned to one [`EspPeerObservationScope`]. See the module
/// documentation for the trust anchor, acceptance rules, and bounds.
#[derive(Debug)]
pub struct EspPeerObservationBoundary {
    scope: EspPeerObservationScope,
    next_epoch: u64,
    capacity: usize,
    slots: HashMap<EspPeerObservationKey, ObservationSlot>,
    closed: bool,
}

impl EspPeerObservationBoundary {
    /// Create a boundary with the default registry capacity.
    #[cfg(test)]
    fn new(scope: EspPeerObservationScope) -> Self {
        Self::with_capacity(scope, DEFAULT_ESP_PEER_OBSERVATION_CAPACITY)
    }

    /// Create a boundary with an explicit registry capacity.
    fn with_capacity(scope: EspPeerObservationScope, capacity: usize) -> Self {
        Self {
            scope,
            next_epoch: 1,
            capacity,
            slots: HashMap::new(),
            closed: false,
        }
    }

    #[cfg(test)]
    const fn scope(&self) -> EspPeerObservationScope {
        self.scope
    }

    /// Number of SAs currently tracked.
    #[must_use]
    #[cfg(test)]
    pub fn tracked_len(&self) -> usize {
        self.slots.len()
    }

    /// Register one inbound integrity-protected SA for observation.
    ///
    /// Each registration starts a fresh observation lifecycle: generation and
    /// cursor state begin empty, and generations are scoped to this
    /// lifecycle (see [`EspPeerObservation::generation`]).
    ///
    /// Fails for non-inbound directions, crypt-only SAs, zero SPIs, non-ESP
    /// protocols, unspecified SA destinations, non-canonical identity
    /// zero-forms (mask-0 mark, `if_id` 0), unspecified baseline addresses,
    /// zero baseline ports, family-inconsistent baselines, duplicate
    /// registrations, a closed boundary, and a full registry. All failures
    /// are value-free.
    pub fn register_sa(
        &mut self,
        registration: EspPeerObservationRegistration,
    ) -> Result<EspPeerObservationEpoch, XfrmError> {
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
        if registration.key.id.destination.is_unspecified() {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.destination",
                "SA destination must be specified",
            ));
        }
        if matches!(registration.key.mark, Some(XfrmMark { mask: 0, .. })) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.mark",
                "lookup-mark mask must be nonzero; use None for an unmarked SA",
            ));
        }
        if registration.key.if_id == Some(0) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.if_id",
                "if_id must be nonzero; use None for an unbound SA",
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
        let epoch_raw = self.next_epoch;
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(XfrmError::Unavailable)?;
        let epoch = NonZeroU64::new(epoch_raw)
            .map(EspPeerObservationEpoch)
            .ok_or(XfrmError::Unavailable)?;
        self.slots.insert(
            registration.key,
            ObservationSlot::new(
                epoch,
                (
                    registration.current_outer_source,
                    registration.current_outer_source_port,
                ),
            ),
        );
        Ok(epoch)
    }

    /// Rebase the authenticated current outer source after the coordinator
    /// proved the post-relocation kernel state with exact GETSA.
    ///
    /// With no pending observation, the last-reported marker is cleared so
    /// traffic from the previous source becomes observation-worthy again. A
    /// retained pending source remains marked as already reported until it is
    /// drained, preventing that same source from manufacturing an overflow
    /// during refresh. If the slot overflowed before refresh, that loss fact is
    /// first folded into the pending observation so refresh cannot erase it.
    ///
    /// # Misuse hazard
    ///
    /// This method is intentionally reachable only inside the crate: it is a
    /// rebaseline oracle, so exposing a caller-supplied tuple would let a
    /// consumer suppress future observations for an unverified source. The
    /// production monitor invokes it only inside its quiescent,
    /// double-GETSA-validated refresh transaction.
    pub(crate) fn update_current_source(
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
        if let (Some(observation), true) = (&mut slot.pending, slot.overflow_closed) {
            observation.loss = observation.loss.with_overflow();
        }
        slot.current_source = (new_source, new_source_port);
        slot.last_reported = slot
            .pending
            .as_ref()
            .map(|pending| (pending.outer_source, pending.outer_source_port));
        slot.overflow_closed = false;
        Ok(())
    }

    /// Present one event to the boundary.
    ///
    /// Checks run in a fixed order: boundary-open, scope, exact SA
    /// attribution (with a one-shot O(capacity) wrong-direction
    /// disambiguation on the unknown-SA path only), family, source shape,
    /// ingress scope, provenance, staleness, then the slot rules. See
    /// [`EspPeerObservationEvent::cursor`] for the cursor-burn semantics that
    /// apply once an event passes attribution and staleness.
    pub(crate) fn ingest_event(&mut self, event: EspPeerObservationEvent) -> EspPeerIngestOutcome {
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
        if event.epoch != slot.epoch {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::LifecycleMismatch);
        }
        if family_of(event.outer_source) != event.key.address_family() {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::FamilyMismatch);
        }
        if event.outer_source.is_unspecified() || event.outer_source_port == 0 {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::MalformedSource);
        }
        let Some(ingress_ifindex) = event.ingress_ifindex.filter(|ifindex| *ifindex != 0) else {
            return EspPeerIngestOutcome::Rejected(
                EspPeerObservationRejection::MissingIngressScope,
            );
        };
        if !matches!(
            event.provenance,
            EspPeerEventProvenance::PostFinalReplayAccepted
        ) {
            return EspPeerIngestOutcome::Rejected(
                EspPeerObservationRejection::InsufficientProvenance,
            );
        }
        if slot.last_cursor.is_some_and(|last| event.cursor <= last) {
            return EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::StaleCursor);
        }
        slot.last_cursor = Some(event.cursor);
        if event.dropped_since_previous > 0 {
            note_source_loss(slot);
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
        let Some(next_generation) = slot.generation.checked_add(1) else {
            slot.overflow_closed = true;
            return EspPeerIngestOutcome::Rejected(
                EspPeerObservationRejection::GenerationOverflowClosed,
            );
        };
        slot.generation = next_generation;
        let loss = if slot.source_loss {
            EspPeerObservationLoss::SourceAttributed
        } else {
            EspPeerObservationLoss::None
        };
        // The reported loss is now attributed to this observation; later
        // observations must not inherit it without new loss evidence.
        slot.source_loss = false;
        let observation = EspPeerObservation {
            key: event.key,
            epoch: event.epoch,
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

    /// Drain every event a source currently has queued, returning an
    /// aggregate tally of queued/no-change/per-label-rejection outcomes.
    ///
    /// The tally deliberately retains counts only. Consumers that need the
    /// exact event an outcome belongs to must loop [`Self::ingest_event`]
    /// themselves instead.
    pub fn ingest_available<S: EspPeerObservationSource + ?Sized>(
        &mut self,
        source: &mut S,
    ) -> EspPeerIngestTally {
        self.ingest_up_to(source, usize::MAX)
    }

    /// Drain at most `max_records` source records.
    ///
    /// Production sources use this bounded form so a continuously replenished
    /// kernel queue cannot monopolize an executor thread. `Idle` and
    /// `Terminal` do not consume the budget.
    fn ingest_up_to<S: EspPeerObservationSource + ?Sized>(
        &mut self,
        source: &mut S,
        max_records: usize,
    ) -> EspPeerIngestTally {
        let mut tally = EspPeerIngestTally::default();
        for _ in 0..max_records {
            match source.next_record() {
                EspPeerObservationSourceRecord::Event(event) => {
                    tally.record(self.ingest_event(event));
                }
                EspPeerObservationSourceRecord::Loss(loss) => {
                    tally.source_loss_records += 1;
                    if let Some(rejection) = self.ingest_source_loss(loss) {
                        tally.record_source_rejection(rejection);
                    }
                }
                EspPeerObservationSourceRecord::Idle => break,
                EspPeerObservationSourceRecord::Terminal(terminal) => {
                    self.closed = true;
                    tally.source_terminal = Some(terminal);
                    break;
                }
            }
        }
        tally
    }

    /// Attribute a standalone producer-loss record to its exact live slot.
    ///
    /// Returns a rejection label when the record is stale, foreign, or no
    /// longer attributable. A valid record updates a pending observation
    /// immediately, so the fact cannot disappear if no later packet arrives.
    fn ingest_source_loss(
        &mut self,
        loss: EspPeerObservationSourceLoss,
    ) -> Option<EspPeerObservationRejection> {
        if self.closed {
            return Some(EspPeerObservationRejection::BoundaryClosed);
        }
        if loss.scope != self.scope {
            return Some(EspPeerObservationRejection::ScopeMismatch);
        }
        let Some(slot) = self.slots.get_mut(&loss.key) else {
            return Some(EspPeerObservationRejection::UnknownSa);
        };
        if loss.epoch != slot.epoch {
            return Some(EspPeerObservationRejection::LifecycleMismatch);
        }
        let _dropped = loss.dropped;
        note_source_loss(slot);
        None
    }

    /// Take the pending observation for an SA, if one is outstanding.
    ///
    /// If the slot was overflow-closed, the returned observation's loss
    /// status gains the [`EspPeerObservationLoss::OverflowClosed`] fact
    /// (compositionally, see [`EspPeerObservationLoss`]), but draining alone
    /// does not reopen the slot. The producer may already have suppressed the
    /// overflowed tuple, so pretending a later packet can always recover
    /// would lose an authenticated path change silently. Only an
    /// authenticated [`Self::update_current_source`] rebase or teardown
    /// reopens/removes the slot.
    ///
    /// After a normal drain the drained source stays the last-reported
    /// marker: further events from that same source are `NoChange` until
    /// [`Self::update_current_source`] rebases. There is deliberately no
    /// forget API; rebaseline is the only way to clear dedup state.
    #[must_use]
    pub fn drain(&mut self, key: &EspPeerObservationKey) -> Option<EspPeerObservation> {
        let slot = self.slots.get_mut(key)?;
        let mut observation = slot.pending.take()?;
        if slot.overflow_closed {
            observation.loss = observation.loss.with_overflow();
        }
        Some(observation)
    }

    /// Take every pending observation in deterministic key order. The result
    /// is bounded by the registry capacity.
    #[must_use]
    pub fn drain_all(&mut self) -> Vec<EspPeerObservation> {
        let mut keys: Vec<EspPeerObservationKey> = self.slots.keys().copied().collect();
        keys.sort_by_key(observation_key_order);
        let mut out = Vec::new();
        for key in keys {
            if let Some(observation) = self.drain(&key) {
                out.push(observation);
            }
        }
        out
    }

    /// Drain and remove all observation state for one SA, returning the exact
    /// termination record. Events for the SA are rejected afterwards
    /// (including replayed pre-teardown traffic), and a later re-registration
    /// starts a fresh lifecycle: teardown is the epoch boundary.
    pub fn teardown(
        &mut self,
        key: &EspPeerObservationKey,
    ) -> Result<EspPeerObservationTeardown, XfrmError> {
        let mut slot = self.slots.remove(key).ok_or(XfrmError::NotFound)?;
        let mut drained = slot.pending.take();
        let mut residual_loss = if slot.source_loss {
            EspPeerObservationLoss::SourceAttributed
        } else {
            EspPeerObservationLoss::None
        };
        if let (Some(observation), true) = (&mut drained, slot.overflow_closed) {
            observation.loss = observation.loss.with_overflow();
        } else if slot.overflow_closed {
            residual_loss = residual_loss.with_overflow();
        }
        Ok(EspPeerObservationTeardown {
            key: *key,
            epoch: slot.epoch,
            final_generation: slot.generation,
            drained,
            residual_loss,
        })
    }

    /// Tear down every tracked SA in deterministic key order and close the
    /// boundary (for example on namespace teardown). All later events and
    /// registrations are rejected.
    pub fn close(&mut self) -> Vec<EspPeerObservationTeardown> {
        let mut keys: Vec<EspPeerObservationKey> = self.slots.keys().copied().collect();
        keys.sort_by_key(observation_key_order);
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

fn note_source_loss(slot: &mut ObservationSlot) {
    if let Some(observation) = &mut slot.pending {
        observation.loss = observation.loss.with_source_attributed();
    } else {
        slot.source_loss = true;
    }
}

const fn family_of(address: IpAddress) -> EspPeerAddressFamily {
    match address {
        IpAddress::Ipv4(_) => EspPeerAddressFamily::Ipv4,
        IpAddress::Ipv6(_) => EspPeerAddressFamily::Ipv6,
    }
}

const fn direction_order(direction: XfrmDirection) -> u8 {
    match direction {
        XfrmDirection::In => 0,
        XfrmDirection::Out => 1,
        XfrmDirection::Forward => 2,
    }
}

/// Total ordering for deterministic drains/teardowns. Keys with equal
/// identity fields sort by family, destination octets, SPI, protocol, mark,
/// `if_id`, then direction; this ordering is an implementation detail and is
/// not a stable API.
type ObservationKeyOrder = (u8, [u8; 16], u32, u8, (u32, u32), u32, u8);

fn observation_key_order(key: &EspPeerObservationKey) -> ObservationKeyOrder {
    let (family, octets) = match key.id.destination {
        IpAddress::Ipv4(v4) => {
            let mut padded = [0u8; 16];
            padded[..4].copy_from_slice(&v4);
            (0, padded)
        }
        IpAddress::Ipv6(v6) => (1, v6),
    };
    (
        family,
        octets,
        key.id.spi,
        key.id.protocol,
        key.mark.map_or((0, 0), |mark| (mark.value, mark.mask)),
        key.if_id.unwrap_or(0),
        direction_order(key.direction),
    )
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
    const FIRST_EPOCH: EspPeerObservationEpoch = EspPeerObservationEpoch(NonZeroU64::MIN);

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
            epoch: FIRST_EPOCH,
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
        assert!(!observation.loss.source_attributed());
        assert!(!observation.loss.overflow_closed());
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
        assert_eq!(record.epoch, FIRST_EPOCH);
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
        // Re-registration starts a fresh lifecycle with a fresh epoch and
        // generation. A queued event from the terminated epoch cannot enter.
        let new_epoch = boundary.register_sa(registration()).unwrap();
        assert_ne!(new_epoch, FIRST_EPOCH);
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::LifecycleMismatch)
        );
        let mut current_epoch_event = event(scope, NEW_SOURCE, NEW_PORT, 3);
        current_epoch_event.epoch = new_epoch;
        assert_eq!(
            boundary.ingest_event(current_epoch_event),
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
        // Fail-closed: subsequent distinct sources are rejected until an
        // authenticated rebase or teardown.
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
        assert!(observation.loss.overflow_closed());
        assert!(!observation.loss.source_attributed());
        // Drain alone cannot recover because a kernel producer may already
        // suppress the overflowed tuple.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 4)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );
        boundary
            .update_current_source(&key(), NEW_SOURCE, NEW_PORT)
            .unwrap();
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 5)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let recovered = boundary.drain(&key()).unwrap();
        assert_eq!(recovered.outer_source, THIRD_SOURCE);
        assert_eq!(recovered.generation, 2, "generation stays monotonic");
    }

    #[test]
    fn authenticated_refresh_preserves_pending_overflow_and_source_loss() {
        let (scope, mut boundary) = boundary();
        let mut lossy_current = event(scope, CURRENT, CURRENT_PORT, 1);
        lossy_current.dropped_since_previous = 1;
        assert_eq!(
            boundary.ingest_event(lossy_current),
            EspPeerIngestOutcome::NoChange
        );
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );

        // A separately authenticated relocation may finish before the
        // consumer drains the already-pending observation. Rebaseline must
        // not erase either explicit loss fact.
        boundary
            .update_current_source(&key(), NEW_SOURCE, NEW_PORT)
            .unwrap();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 4)),
            EspPeerIngestOutcome::NoChange,
            "the retained pending source is not a distinct overflow"
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 5)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed),
            "a genuinely distinct post-refresh source still closes the slot"
        );
        let pending = boundary.drain(&key()).unwrap();
        assert_eq!(pending.outer_source, NEW_SOURCE);
        assert_eq!(
            pending.loss,
            EspPeerObservationLoss::SourceAttributedOverflowClosed
        );
    }

    #[test]
    fn overflow_rejected_cursor_is_burned() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );
        assert!(boundary.drain(&key()).is_some());
        // The overflow-rejected candidate burned its cursor: a raw retry is
        // stale; the source must retry with a fresh cursor.
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::StaleCursor)
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );
        boundary
            .update_current_source(&key(), NEW_SOURCE, NEW_PORT)
            .unwrap();
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 4)),
            EspPeerIngestOutcome::ObservationQueued
        );
    }

    #[test]
    fn source_attributed_loss_is_explicit_and_attributed_once() {
        let (scope, mut boundary) = boundary();
        let mut lossy = event(scope, NEW_SOURCE, NEW_PORT, 1);
        lossy.dropped_since_previous = 2;
        assert_eq!(
            boundary.ingest_event(lossy),
            EspPeerIngestOutcome::ObservationQueued
        );
        let first = boundary.drain(&key()).unwrap();
        assert_eq!(first.loss, EspPeerObservationLoss::SourceAttributed);
        assert!(first.loss.source_attributed());

        // The reported loss was attributed to that observation; the next
        // observation without new loss evidence is clean (not sticky).
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.drain(&key()).unwrap().loss,
            EspPeerObservationLoss::None
        );
    }

    #[test]
    fn source_loss_and_overflow_compose() {
        let (scope, mut boundary) = boundary();
        // Source-reported loss on an otherwise unremarkable event, then a
        // queued observation that attributes the loss, then overflow.
        let mut lossy = event(scope, CURRENT, CURRENT_PORT, 1);
        lossy.dropped_since_previous = 1;
        assert_eq!(boundary.ingest_event(lossy), EspPeerIngestOutcome::NoChange);
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 3)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::SlotOverflowClosed)
        );
        let drained = boundary.drain(&key()).unwrap();
        assert_eq!(
            drained.loss,
            EspPeerObservationLoss::SourceAttributedOverflowClosed,
            "overflow must not erase source-attributed loss"
        );
        assert!(drained.loss.source_attributed());
        assert!(drained.loss.overflow_closed());
    }

    #[test]
    fn interface_only_move_is_no_change() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert!(boundary.drain(&key()).is_some());
        // Same source tuple from a different ingress interface: dedup is
        // keyed on the tuple only (documented MOBIKE caveat).
        let mut moved = event(scope, NEW_SOURCE, NEW_PORT, 2);
        moved.ingress_ifindex = Some(IFINDEX + 1);
        assert_eq!(boundary.ingest_event(moved), EspPeerIngestOutcome::NoChange);
        assert_eq!(boundary.drain(&key()), None);
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
        // A zero ifindex is not a valid Linux interface index and does not
        // launder the missing-scope rule.
        let mut zero_ifindex = event(scope, NEW_SOURCE, NEW_PORT, 1);
        zero_ifindex.ingress_ifindex = Some(0);
        assert_eq!(
            boundary.ingest_event(zero_ifindex),
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
    fn registration_rejects_invalid_identities() {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::new(scope);

        let mut expect_invalid = |mut reg: EspPeerObservationRegistration, field: &'static str| {
            reg.key.direction = XfrmDirection::In;
            match boundary.register_sa(reg) {
                Err(XfrmError::InvalidConfig { field: got, .. }) => {
                    assert_eq!(got, field, "wrong rejection field")
                }
                other => panic!("expected InvalidConfig for {field}, got {other:?}"),
            }
        };

        // Zero SPI.
        let mut reg = registration();
        reg.key.id.spi = 0;
        expect_invalid(reg, "esp_peer_observation.spi");
        // Non-ESP protocol.
        let mut reg = registration();
        reg.key.id.protocol = 51;
        expect_invalid(reg, "esp_peer_observation.protocol");
        // Unspecified SA destination: a dead slot that can never attribute.
        let mut reg = registration();
        reg.key.id.destination = IpAddress::Ipv4([0, 0, 0, 0]);
        expect_invalid(reg, "esp_peer_observation.destination");
        // Mask-0 mark is equivalent to no mark and must be normalized by the
        // caller, not silently accepted.
        let mut reg = registration();
        reg.key.mark = Some(XfrmMark { value: 1, mask: 0 });
        expect_invalid(reg, "esp_peer_observation.mark");
        let mut reg = registration();
        reg.key.mark = Some(XfrmMark { value: 0, mask: 0 });
        expect_invalid(reg, "esp_peer_observation.mark");
        // if_id 0 is equivalent to unbound.
        let mut reg = registration();
        reg.key.if_id = Some(0);
        expect_invalid(reg, "esp_peer_observation.if_id");
        // Unspecified baseline address.
        let mut reg = registration();
        reg.current_outer_source = IpAddress::Ipv4([0, 0, 0, 0]);
        expect_invalid(reg, "esp_peer_observation.current_source");
        // Zero baseline port.
        let mut reg = registration();
        reg.current_outer_source_port = 0;
        expect_invalid(reg, "esp_peer_observation.current_source");
        // Family-inconsistent baseline.
        let mut reg = registration();
        reg.current_outer_source =
            IpAddress::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        expect_invalid(reg, "esp_peer_observation.current_source");

        // Canonical marked/if_id-bound identities register fine.
        let mut marked = registration();
        marked.key.mark = Some(XfrmMark {
            value: 1,
            mask: u32::MAX,
        });
        marked.key.if_id = Some(7);
        boundary.register_sa(marked).unwrap();

        // Duplicate registration.
        boundary.register_sa(registration()).unwrap();
        assert!(matches!(
            boundary.register_sa(registration()),
            Err(XfrmError::AlreadyExists)
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
    fn scripted_source_feeds_the_boundary_with_visible_tally() {
        let (scope, mut boundary) = boundary();
        let mut source = ScriptedEspPeerObservationSource::new();
        source.push(event(scope, CURRENT, CURRENT_PORT, 1));
        source.push(event(scope, NEW_SOURCE, NEW_PORT, 2));
        let mut foreign = event(scope, THIRD_SOURCE, NEW_PORT, 3);
        foreign.scope = EspPeerObservationScope::new();
        source.push(foreign);
        assert_eq!(source.pending_len(), 3);

        let tally = boundary.ingest_available(&mut source);
        assert_eq!(source.pending_len(), 0);
        assert_eq!(tally.events, 3);
        assert_eq!(tally.observations_queued, 1);
        assert_eq!(tally.no_change, 1);
        assert_eq!(tally.rejected, 1);
        assert_eq!(
            tally.rejections(EspPeerObservationRejection::ScopeMismatch),
            1,
            "rejections are visible per label, not silently discarded"
        );
        assert_eq!(
            tally.rejections(EspPeerObservationRejection::StaleCursor),
            0
        );

        let drained = boundary.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].outer_source, NEW_SOURCE);
    }

    #[test]
    fn bounded_source_ingest_yields_with_records_still_queued() {
        let (scope, mut boundary) = boundary();
        let mut source = ScriptedEspPeerObservationSource::new();
        source.push(event(scope, CURRENT, CURRENT_PORT, 1));
        source.push(event(scope, NEW_SOURCE, NEW_PORT, 2));
        source.push(event(scope, THIRD_SOURCE, NEW_PORT, 3));

        let first = boundary.ingest_up_to(&mut source, 2);
        assert_eq!(first.events, 2);
        assert_eq!(source.pending_len(), 1);

        let second = boundary.ingest_up_to(&mut source, 2);
        assert_eq!(second.events, 1);
        assert_eq!(source.pending_len(), 0);
    }

    #[test]
    fn standalone_source_loss_updates_pending_without_a_later_event() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );

        let mut source = ScriptedEspPeerObservationSource::new();
        source.push_record(EspPeerObservationSourceRecord::Loss(
            EspPeerObservationSourceLoss {
                scope,
                epoch: FIRST_EPOCH,
                key: key(),
                dropped: NonZeroU64::MIN,
            },
        ));
        source.push_record(EspPeerObservationSourceRecord::Terminal(
            EspPeerObservationSourceTerminal::Closed,
        ));

        let tally = boundary.ingest_available(&mut source);
        assert_eq!(tally.events, 0);
        assert_eq!(tally.source_loss_records, 1);
        assert_eq!(
            tally.source_terminal,
            Some(EspPeerObservationSourceTerminal::Closed)
        );
        assert_eq!(tally.rejected, 0);

        let observation = boundary.drain(&key()).expect("pending observation");
        assert!(
            observation.loss.source_attributed(),
            "loss is retained even though no later event exists"
        );
        assert!(
            matches!(
                boundary.register_sa(registration()),
                Err(XfrmError::Unavailable)
            ),
            "source termination closes admission fail-closed"
        );
    }

    #[test]
    fn standalone_source_loss_survives_teardown_without_an_observation() {
        let (scope, mut boundary) = boundary();
        let mut source = ScriptedEspPeerObservationSource::new();
        source.push_record(EspPeerObservationSourceRecord::Loss(
            EspPeerObservationSourceLoss {
                scope,
                epoch: FIRST_EPOCH,
                key: key(),
                dropped: NonZeroU64::MIN,
            },
        ));

        let tally = boundary.ingest_available(&mut source);
        assert_eq!(tally.source_loss_records, 1);
        assert_eq!(tally.rejected, 0);

        let teardown = boundary.teardown(&key()).expect("registered");
        assert_eq!(teardown.drained, None);
        assert_eq!(
            teardown.residual_loss,
            EspPeerObservationLoss::SourceAttributed,
            "known producer loss must not disappear at lifecycle termination"
        );
    }

    #[test]
    fn generation_exhaustion_closes_instead_of_repeating() {
        let (scope, mut boundary) = boundary();
        boundary
            .slots
            .get_mut(&key())
            .expect("registered")
            .generation = u64::MAX;

        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::Rejected(EspPeerObservationRejection::GenerationOverflowClosed)
        );

        let teardown = boundary.teardown(&key()).expect("registered");
        assert_eq!(teardown.final_generation, u64::MAX);
        assert_eq!(teardown.drained, None);
        assert_eq!(
            teardown.residual_loss,
            EspPeerObservationLoss::OverflowClosed
        );
    }

    #[test]
    fn standalone_loss_from_a_previous_epoch_is_rejected() {
        let (scope, mut boundary) = boundary();
        let record = boundary.teardown(&key()).expect("registered");
        let current_epoch = boundary.register_sa(registration()).expect("re-register");
        assert_ne!(current_epoch, record.epoch);

        let mut source = ScriptedEspPeerObservationSource::new();
        source.push_record(EspPeerObservationSourceRecord::Loss(
            EspPeerObservationSourceLoss {
                scope,
                epoch: record.epoch,
                key: key(),
                dropped: NonZeroU64::MIN,
            },
        ));
        let tally = boundary.ingest_available(&mut source);
        assert_eq!(tally.source_loss_records, 1);
        assert_eq!(tally.rejected, 1);
        assert_eq!(
            tally.rejections(EspPeerObservationRejection::LifecycleMismatch),
            1
        );
    }

    #[test]
    fn drain_all_and_close_are_deterministically_ordered() {
        let scope = EspPeerObservationScope::new();
        let mut boundary = EspPeerObservationBoundary::new(scope);
        let mut high_spi = registration();
        high_spi.key.id.spi = 0x0abc_9999;
        boundary.register_sa(registration()).unwrap();
        let high_epoch = boundary.register_sa(high_spi).unwrap();

        let mut high_event = event(scope, NEW_SOURCE, NEW_PORT, 1);
        high_event.key.id.spi = 0x0abc_9999;
        high_event.epoch = high_epoch;
        assert_eq!(
            boundary.ingest_event(high_event),
            EspPeerIngestOutcome::ObservationQueued
        );
        assert_eq!(
            boundary.ingest_event(event(scope, THIRD_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );

        let drained = boundary.drain_all();
        assert_eq!(drained.len(), 2);
        assert!(
            drained[0].key.id.spi < drained[1].key.id.spi,
            "drain order is deterministic (sorted by key)"
        );

        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 2)),
            EspPeerIngestOutcome::ObservationQueued
        );
        let records = boundary.close();
        assert_eq!(records.len(), 2);
        assert!(records[0].key.id.spi < records[1].key.id.spi);
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
        let zero_port = event(scope, NEW_SOURCE, 0, 1);
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
        // The boundary is formatted while it holds a LIVE registered SA with
        // a pending observation: its Debug must not leak the retained
        // baseline, last-reported, or pending-observation tuples.
        let live_boundary_debug = format!("{boundary:?}");

        let observation = boundary.drain(&key()).unwrap();
        let teardown = boundary.teardown(&key()).unwrap();
        let rejection = EspPeerObservationRejection::StaleCursor;
        let ev = event(scope, NEW_SOURCE, NEW_PORT, 2);
        let reg = registration();

        let haystack = format!(
            "{live_boundary_debug}\n{observation:?}\n{observation}\n{teardown:?}\n{rejection:?}\n{rejection}\n{ev:?}\n{reg:?}\n{:?}\n{boundary:?}",
            key()
        );
        for forbidden in [
            // Dotted and octet-array forms of every fixture address.
            "192.0.2",
            "192, 0, 2",
            "198.51.100",
            "198, 51, 100",
            "203.0.113",
            "203, 0, 113",
            // Ports.
            "4500",
            "32768",
            // SPI, hex and decimal (0x0abc1234 == 180097588).
            "abc1234",
            "ABC1234",
            "180097588",
            // Ingress ifindex.
            "42",
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

    #[test]
    fn exhaustive_redaction_surface_is_value_free() {
        let (scope, mut boundary) = boundary();
        assert_eq!(
            boundary.ingest_event(event(scope, NEW_SOURCE, NEW_PORT, 1)),
            EspPeerIngestOutcome::ObservationQueued
        );

        let mut source = ScriptedEspPeerObservationSource::new();
        source.push(event(scope, THIRD_SOURCE, NEW_PORT, 2));
        let source_debug = format!("{source:?}");

        let error = XfrmError::io(
            "esp_peer_observation_ingest",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "peer 192.0.2.1:4500 spi 180097588",
            ),
        );

        let haystack = format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{error:?}\n{error}\n{source_debug}",
            EspPeerEventProvenance::UnauthenticatedPacketPath,
            EspPeerEventProvenance::PostIntegrityPreFinalReplay,
            EspPeerEventProvenance::PostFinalReplayAccepted,
            EspPeerObservationLoss::None,
            EspPeerObservationLoss::SourceAttributed,
            EspPeerObservationLoss::OverflowClosed,
            EspPeerObservationLoss::SourceAttributedOverflowClosed,
            EspPeerAddressFamily::Ipv4,
            scope,
            boundary.scope(),
        );
        for forbidden in [
            "192.0.2",
            "192, 0, 2",
            "198, 51, 100",
            "203, 0, 113",
            "4500",
            "32768",
            "180097588",
            "42",
        ] {
            assert!(
                !haystack.contains(forbidden),
                "diagnostics leaked {forbidden:?}: {haystack}"
            );
        }
    }
}
