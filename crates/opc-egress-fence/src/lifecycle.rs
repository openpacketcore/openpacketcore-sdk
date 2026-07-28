//! Lease-operation ordering and fail-closed socket lifecycle.

use std::{cmp, fmt, num::NonZeroU64, sync::Arc, time::Duration};

use async_trait::async_trait;
use opc_session_store::{LeaseGuard, OwnerId, SessionKey};

// This is the frozen common-ABI ceiling assigned to the eBPF implementation
// lane. Import the common constant when that lane is integrated.
pub(crate) const MAX_GATE_LIFETIME_NS: u64 = 300_000_000_000;
const DEFAULT_BOOT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const INITIAL_CONTROL_EPOCH: u64 = 1;
const ATTACHMENT_IDENTITY_MAGIC: [u8; 4] = *b"OFA1";
const ATTACHMENT_IDENTITY_LEN: usize = 36;

/// Opaque identity of one exact, live-read root-cgroup fence generation.
///
/// The digest is constructed by the Linux installer from the immutable
/// prepared/committed manifest, nonzero root-cgroup revision transition,
/// exact program IDs and tags, exact map IDs and schemas, and canonical
/// protected-endpoint configuration. A pin path or cgroup query alone is never
/// an attachment identity. Formatting is always redacted.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FenceAttachmentIdentity {
    digest: [u8; 32],
}

impl FenceAttachmentIdentity {
    /// Canonical encoded width for durable storage.
    pub const ENCODED_LEN: usize = ATTACHMENT_IDENTITY_LEN;

    /// Decode an identity previously produced by [`Self::encode`].
    ///
    /// The downstream durable authority must still bind this identity to the
    /// exact record generation and fence token returned atomically with an
    /// acquisition. Decoding bytes is not, by itself, fresh-install or
    /// terminal-close evidence.
    #[must_use]
    pub const fn decode(encoded: &[u8; ATTACHMENT_IDENTITY_LEN]) -> Option<Self> {
        if encoded[0] != ATTACHMENT_IDENTITY_MAGIC[0]
            || encoded[1] != ATTACHMENT_IDENTITY_MAGIC[1]
            || encoded[2] != ATTACHMENT_IDENTITY_MAGIC[2]
            || encoded[3] != ATTACHMENT_IDENTITY_MAGIC[3]
        {
            return None;
        }
        let mut digest = [0_u8; 32];
        let mut index = 0;
        let mut nonzero = false;
        while index < digest.len() {
            digest[index] = encoded[4 + index];
            nonzero |= digest[index] != 0;
            index += 1;
        }
        if !nonzero {
            return None;
        }
        Some(Self { digest })
    }

    /// Encode for downstream durable storage.
    #[must_use]
    pub const fn encode(self) -> [u8; ATTACHMENT_IDENTITY_LEN] {
        let mut encoded = [0_u8; ATTACHMENT_IDENTITY_LEN];
        encoded[0] = ATTACHMENT_IDENTITY_MAGIC[0];
        encoded[1] = ATTACHMENT_IDENTITY_MAGIC[1];
        encoded[2] = ATTACHMENT_IDENTITY_MAGIC[2];
        encoded[3] = ATTACHMENT_IDENTITY_MAGIC[3];
        let mut index = 0;
        while index < self.digest.len() {
            encoded[4 + index] = self.digest[index];
            index += 1;
        }
        encoded
    }

    pub(crate) const fn from_live_digest(digest: [u8; 32]) -> Option<Self> {
        let mut index = 0;
        let mut nonzero = false;
        while index < digest.len() {
            nonzero |= digest[index] != 0;
            index += 1;
        }
        if nonzero {
            Some(Self { digest })
        } else {
            None
        }
    }
}

impl fmt::Debug for FenceAttachmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FenceAttachmentIdentity(<redacted>)")
    }
}

/// How the installer recovered the root-cgroup generation used for this socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachmentInventory {
    /// Exact committed objects and root inventory were adopted after complete
    /// live readback.
    AdoptedExact,
    /// One complete prepared generation was atomically published, attached
    /// under an exact revision guard, read back, and committed by this process.
    InstalledUnderRevisionGuard,
}

/// Exact root-cgroup generation identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachmentIdentity {
    pub(crate) durable: FenceAttachmentIdentity,
    pub(crate) inventory: AttachmentInventory,
}

impl fmt::Debug for AttachmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttachmentIdentity(<redacted>)")
    }
}

/// Redaction-safe internal kernel failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelFailure {
    Mutation,
    Readback,
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelEntryState {
    InitialClosed,
    Active,
    TerminalClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelFenceEntry {
    pub(crate) state: KernelEntryState,
    pub(crate) socket_cookie: u64,
    pub(crate) lifecycle_token: u64,
    pub(crate) deadline_boot_ns: u64,
    pub(crate) control_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelCurrentPhase {
    Uninitialized,
    LifecycleOpen,
    RetirementClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelCurrentFence {
    pub(crate) phase: KernelCurrentPhase,
    pub(crate) lifecycle_token: u64,
    pub(crate) registered_socket_cookie: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelInspection {
    pub(crate) current: KernelCurrentFence,
    pub(crate) entry: Option<KernelFenceEntry>,
}

/// Suspend-aware boot clock used by both deterministic tests and Linux.
#[async_trait]
pub(crate) trait BootClock: Send + Sync {
    fn now_boot_ns(&self) -> Result<u64, KernelFailure>;

    /// Wait for at most one short poll interval.
    ///
    /// The caller always rereads `CLOCK_BOOTTIME`; this wait is only a bounded
    /// wakeup mechanism and is never the authority for elapsed time.
    async fn wait_poll(&self, duration: Duration) -> Result<(), KernelFailure>;
}

/// Exact, readback-verifying kernel control boundary.
pub(crate) trait KernelControl: Send + Sync {
    fn inspect(
        &self,
        identity: AttachmentIdentity,
        entry_key: Option<(u64, u64)>,
    ) -> Result<KernelInspection, KernelFailure>;

    fn publish_lifecycle(
        &self,
        identity: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure>;

    fn publish_retirement(
        &self,
        identity: AttachmentIdentity,
        retirement_lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure>;

    fn register_closed(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
    ) -> Result<KernelFenceEntry, KernelFailure>;

    fn activate(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure>;

    fn refresh(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure>;

    fn close(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure>;

    fn reclaim(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<(), KernelFailure>;
}

/// Validated timing policy for one durable lease transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LeaseFenceTiming {
    ttl: Duration,
    safety_margin: Duration,
}

impl LeaseFenceTiming {
    /// Construct a timing policy with a nonzero margin smaller than the TTL.
    ///
    /// # Errors
    ///
    /// Returns [`FenceError::InvalidTiming`] for a zero TTL, zero margin,
    /// margin greater than or equal to the TTL, or a duration that cannot be
    /// represented by the kernel's nanosecond clock.
    ///
    /// The active kernel lifetime (`ttl - safety_margin`) may not exceed the
    /// frozen SDK/kernel ceiling. Takeover delay is not derived from the new
    /// TTL: durable prior state supplies the actual preceding bound, and
    /// unknown state waits the full ceiling.
    pub fn new(ttl: Duration, safety_margin: Duration) -> Result<Self, FenceError> {
        if ttl.is_zero()
            || safety_margin.is_zero()
            || safety_margin >= ttl
            || ttl.as_nanos() > u128::from(u64::MAX)
            || safety_margin.as_nanos() > u128::from(u64::MAX)
        {
            return Err(FenceError::InvalidTiming);
        }
        let timing = Self { ttl, safety_margin };
        if timing.active_gate_lifetime_ns()? > MAX_GATE_LIFETIME_NS {
            return Err(FenceError::InvalidTiming);
        }
        Ok(timing)
    }

    /// Lease TTL passed verbatim to the durable authority.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        self.ttl
    }

    /// Time removed from the kernel deadline to cover scheduling and
    /// cross-clock uncertainty.
    #[must_use]
    pub const fn safety_margin(self) -> Duration {
        self.safety_margin
    }

    /// Maximum lifetime requested for a newly activated kernel gate.
    #[must_use]
    pub fn active_gate_lifetime(self) -> Duration {
        self.ttl
            .checked_sub(self.safety_margin)
            .unwrap_or(Duration::ZERO)
    }

    fn deadline_from(self, operation_start_boot_ns: u64) -> Result<u64, FenceError> {
        let budget_ns = self.active_gate_lifetime_ns()?;
        operation_start_boot_ns
            .checked_add(budget_ns)
            .ok_or(FenceError::DeadlineOverflow)
    }

    fn active_gate_lifetime_ns(self) -> Result<u64, FenceError> {
        let budget = self
            .ttl
            .checked_sub(self.safety_margin)
            .ok_or(FenceError::InvalidTiming)?;
        u64::try_from(budget.as_nanos()).map_err(|_| FenceError::DeadlineOverflow)
    }

    fn closed_renew_interval(self) -> Duration {
        self.ttl / 2
    }

    fn boot_poll_interval(self) -> Duration {
        cmp::min(DEFAULT_BOOT_POLL_INTERVAL, self.ttl / 4)
    }
}

impl fmt::Debug for LeaseFenceTiming {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseFenceTiming")
            .field("ttl_present", &!self.ttl.is_zero())
            .field("safety_margin_present", &!self.safety_margin.is_zero())
            .field("gate_lifetime_bounded", &true)
            .finish()
    }
}

/// Atomic durable evidence about the attachment that preceded an acquisition.
///
/// The authority implementation is the trust boundary for these constructors.
/// It must return the state from the same durable transaction that minted the
/// returned [`LeaseGuard`], and bind it to that transaction's nonzero record
/// generation. A separate read is stale evidence and violates the contract.
pub struct DurablePriorFenceState {
    kind: DurablePriorFenceKind,
}

enum DurablePriorFenceKind {
    FreshInstall {
        bootstrap_generation: NonZeroU64,
    },
    VerifiedTerminal {
        attachment: FenceAttachmentIdentity,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        terminal_generation: NonZeroU64,
    },
    LastAttachment {
        attachment: FenceAttachmentIdentity,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        gate_lifetime: Duration,
        record_generation: NonZeroU64,
    },
    Unknown,
}

impl DurablePriorFenceState {
    /// Record a one-shot, cluster-continuous namespace bootstrap.
    ///
    /// Missing data is not fresh-install evidence. The authority may use this
    /// constructor only after durable namespace initialization proves that no
    /// earlier record can exist. The SDK additionally requires an exclusive,
    /// conflict-free live kernel inventory before taking the fast path.
    #[must_use]
    pub const fn fresh_install(bootstrap_generation: NonZeroU64) -> Self {
        Self {
            kind: DurablePriorFenceKind::FreshInstall {
                bootstrap_generation,
            },
        }
    }

    /// Record a preceding attachment closed by a monotonic durable terminal
    /// transition under the exact guard.
    ///
    /// This is valid only when the authority consumed
    /// [`TerminalClosureEvidence`] after kernel close/readback and made the
    /// terminal transition irreversible before releasing the lease.
    ///
    /// # Errors
    ///
    /// Returns [`FenceError::InvalidPriorEvidence`] unless the socket token is
    /// odd and the retirement token is its exact even successor.
    pub fn verified_terminal(
        attachment: FenceAttachmentIdentity,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        terminal_generation: NonZeroU64,
    ) -> Result<Self, FenceError> {
        validate_lifecycle_token_pair(socket_lifecycle_token, retirement_lifecycle_token)?;
        Ok(Self {
            kind: DurablePriorFenceKind::VerifiedTerminal {
                attachment,
                socket_lifecycle_token,
                retirement_lifecycle_token,
                terminal_generation,
            },
        })
    }

    /// Record the exact last live attachment, token and configured kernel-gate
    /// lifetime from the preceding durable generation.
    ///
    /// # Errors
    ///
    /// Returns [`FenceError::InvalidPriorEvidence`] when the lifetime is zero,
    /// exceeds the frozen SDK/kernel ceiling, is not nanosecond representable,
    /// or the token pair is not an odd socket token followed by its exact even
    /// retirement successor.
    pub fn last_attachment(
        attachment: FenceAttachmentIdentity,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        gate_lifetime: Duration,
        record_generation: NonZeroU64,
    ) -> Result<Self, FenceError> {
        validate_prior_gate_lifetime(gate_lifetime)?;
        validate_lifecycle_token_pair(socket_lifecycle_token, retirement_lifecycle_token)?;
        Ok(Self {
            kind: DurablePriorFenceKind::LastAttachment {
                attachment,
                socket_lifecycle_token,
                retirement_lifecycle_token,
                gate_lifetime,
                record_generation,
            },
        })
    }

    /// Treat only prior attachment evidence as unknown under one continuous
    /// durable authority namespace.
    ///
    /// This always forces the frozen maximum delay. It is invalid when the
    /// authority namespace, external root, or epoch credentials are missing,
    /// replaced, split, or unproved: those conditions must make acquisition
    /// fail closed and must not return a grant. In particular, loss of state
    /// after an immutable external `ever_initialized` bit became true cannot
    /// be recovered with this variant or a timed wait.
    #[must_use]
    pub const fn attachment_unknown_under_continuous_authority() -> Self {
        Self {
            kind: DurablePriorFenceKind::Unknown,
        }
    }
}

impl fmt::Debug for DurablePriorFenceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            DurablePriorFenceKind::FreshInstall { .. } => "fresh_install",
            DurablePriorFenceKind::VerifiedTerminal { .. } => "verified_terminal",
            DurablePriorFenceKind::LastAttachment { .. } => "last_attachment",
            DurablePriorFenceKind::Unknown => "unknown",
        };
        formatter
            .debug_struct("DurablePriorFenceState")
            .field("kind", &kind)
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Lease and prior-attachment evidence returned by one atomic acquisition.
pub struct FenceLeaseGrant {
    guard: LeaseGuard,
    socket_lifecycle_token: NonZeroU64,
    retirement_lifecycle_token: NonZeroU64,
    prior: DurablePriorFenceState,
    durable_record_generation: NonZeroU64,
}

impl FenceLeaseGrant {
    /// Bind a lease guard to prior evidence from one verified authority
    /// transaction.
    ///
    /// This constructor exists for downstream authority adapters. Ordinary
    /// product code must not synthesize grants. The adapter's conformance
    /// detectors must prove non-reentrant acquisition, immutable
    /// `ever_initialized` handling, namespace/epoch continuity, and exact
    /// generation binding.
    ///
    /// # Errors
    ///
    /// Returns [`FenceError::InvalidPriorEvidence`] unless the socket token is
    /// odd and the retirement token is its exact even successor.
    pub fn from_verified_authority_transaction(
        guard: LeaseGuard,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        prior: DurablePriorFenceState,
        durable_record_generation: NonZeroU64,
    ) -> Result<Self, FenceError> {
        validate_lifecycle_token_pair(socket_lifecycle_token, retirement_lifecycle_token)?;
        Ok(Self {
            guard,
            socket_lifecycle_token,
            retirement_lifecycle_token,
            prior,
            durable_record_generation,
        })
    }

    fn into_parts(
        self,
    ) -> (
        LeaseGuard,
        NonZeroU64,
        NonZeroU64,
        DurablePriorFenceState,
        NonZeroU64,
    ) {
        (
            self.guard,
            self.socket_lifecycle_token,
            self.retirement_lifecycle_token,
            self.prior,
            self.durable_record_generation,
        )
    }
}

impl fmt::Debug for FenceLeaseGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FenceLeaseGrant(<redacted>)")
    }
}

/// Opaque proof produced only after exact terminal kernel readback.
///
/// The durable authority consumes this in its monotonic terminal-CAS and
/// release operation. There is intentionally no public constructor or byte
/// decoder: downstream code cannot turn stored bytes or caller claims into
/// terminal evidence.
pub struct TerminalClosureEvidence {
    attachment: FenceAttachmentIdentity,
    lease_fence_token: NonZeroU64,
    socket_lifecycle_token: NonZeroU64,
    retirement_lifecycle_token: NonZeroU64,
    control_epoch: NonZeroU64,
}

impl TerminalClosureEvidence {
    /// Exact attachment whose cookie was terminally closed.
    #[must_use]
    pub const fn attachment(&self) -> FenceAttachmentIdentity {
        self.attachment
    }

    /// Session-store fencing token of the exact lease being retired.
    #[must_use]
    pub const fn lease_fence_token(&self) -> NonZeroU64 {
        self.lease_fence_token
    }

    /// Socket-lifecycle token retained by the terminal tombstone.
    #[must_use]
    pub const fn socket_lifecycle_token(&self) -> NonZeroU64 {
        self.socket_lifecycle_token
    }

    /// Higher token published before reclaiming the closed socket entry.
    #[must_use]
    pub const fn retirement_lifecycle_token(&self) -> NonZeroU64 {
        self.retirement_lifecycle_token
    }

    /// Monotonic cookie control epoch observed after close.
    #[must_use]
    pub const fn control_epoch(&self) -> NonZeroU64 {
        self.control_epoch
    }
}

impl fmt::Debug for TerminalClosureEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalClosureEvidence(<redacted>)")
    }
}

/// Exact terminal readback retained until the owning socket fd is closed.
pub(crate) struct PendingTerminalClosure {
    attachment: FenceAttachmentIdentity,
    socket_cookie: u64,
    lease_fence_token: NonZeroU64,
    socket_lifecycle_token: NonZeroU64,
    retirement_lifecycle_token: NonZeroU64,
    control_epoch: NonZeroU64,
}

impl fmt::Debug for PendingTerminalClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingTerminalClosure(<redacted>)")
    }
}

/// Protocol-neutral durable authority used by the fence.
///
/// Acquisition must atomically mint the [`LeaseGuard`], return the preceding
/// attachment record, persist `current_attachment` and
/// `current_gate_lifetime`, and bind all of them to one nonzero record
/// generation.
///
/// Acquisition is non-reentrant: it must reject every active predecessor
/// guard, including one carrying byte-identical [`OwnerId`] or incarnation
/// fields. An ambiguous retry is permitted only after exact authoritative
/// readback proves the winning credential. A successful acquisition must also
/// make all predecessor renewals impossible in the same continuous authority
/// epoch before returning a grant. Store/namespace replacement, a split
/// authority epoch, lost external-root continuity, or missing state after an
/// immutable external `ever_initialized` bit became true must fail closed;
/// neither a fresh-install claim nor a 300-second wait repairs those states.
///
/// Unknown prior *attachment* evidence under a verified continuous authority
/// uses [`DurablePriorFenceState::attachment_unknown_under_continuous_authority`].
/// Implementations must preserve key, owner, fence token and credential across
/// renewal.
///
/// The same transaction must reserve and persist a consecutive, nonwrapping
/// token pair `(socket T, retirement R)` where `T` is odd and `R = T + 1` is
/// even. The socket token is published in lifecycle-open phase before
/// registration. After terminal close and exclusive fd death, the retirement
/// token is published in retirement-closed phase before the socket entry may
/// be reclaimed. Every socket lifecycle burns both tokens, including crash and
/// cancellation paths. Exhaustion fails closed. These tokens are distinct from
/// the session-store fence token.
///
/// Terminal release is one consuming operation ordered after SDK kernel
/// close/readback. It must durably and monotonically record terminal state
/// under the exact guard before releasing authority. An ambiguous result is
/// safe only because the kernel gate and socket fd are already closed.
#[async_trait]
pub trait EgressFenceLeaseAuthority: Send + Sync {
    /// Authority-specific error retained for caller policy but never formatted
    /// by this crate.
    type Error: Send;

    /// Acquire exclusive durable authority and its atomic prior evidence.
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
        current_attachment: FenceAttachmentIdentity,
        current_gate_lifetime: Duration,
    ) -> Result<FenceLeaseGrant, Self::Error>;

    /// Renew an existing exact guard.
    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, Self::Error>;

    /// Persist irreversible terminal state, then release exact authority.
    async fn release_with_terminal(
        &self,
        lease: LeaseGuard,
        evidence: TerminalClosureEvidence,
    ) -> Result<(), Self::Error>;
}

/// Static, value-free fence failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FenceError {
    /// TTL or safety margin is unusable.
    InvalidTiming,
    /// Durable prior-attachment evidence is malformed or exceeds the ceiling.
    InvalidPriorEvidence,
    /// Deadline arithmetic exceeded the kernel clock domain.
    DeadlineOverflow,
    /// Suspend-aware clock lookup failed or moved backwards.
    ClockUnavailable,
    /// The lease operation consumed the safe activation budget.
    OperationOverBudget,
    /// Returned guard changed key, owner, token, or credential unexpectedly.
    LeaseContinuity,
    /// Kernel mutation failed or its outcome remained ambiguous.
    KernelMutation,
    /// Exact kernel readback did not match the requested state.
    KernelReadback,
    /// This cookie has entered terminal close and cannot reopen.
    TerminalClosed,
}

impl FenceError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidTiming => "egress_fence_invalid_timing",
            Self::InvalidPriorEvidence => "egress_fence_invalid_prior_evidence",
            Self::DeadlineOverflow => "egress_fence_deadline_overflow",
            Self::ClockUnavailable => "egress_fence_clock_unavailable",
            Self::OperationOverBudget => "egress_fence_operation_over_budget",
            Self::LeaseContinuity => "egress_fence_lease_continuity",
            Self::KernelMutation => "egress_fence_kernel_mutation",
            Self::KernelReadback => "egress_fence_kernel_readback",
            Self::TerminalClosed => "egress_fence_terminal_closed",
        }
    }
}

impl fmt::Display for FenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FenceError {}

fn validate_prior_gate_lifetime(gate_lifetime: Duration) -> Result<u64, FenceError> {
    if gate_lifetime.is_zero() || gate_lifetime.as_nanos() > u128::from(MAX_GATE_LIFETIME_NS) {
        return Err(FenceError::InvalidPriorEvidence);
    }
    u64::try_from(gate_lifetime.as_nanos()).map_err(|_| FenceError::InvalidPriorEvidence)
}

fn validate_lifecycle_token_pair(
    socket_lifecycle_token: NonZeroU64,
    retirement_lifecycle_token: NonZeroU64,
) -> Result<(), FenceError> {
    if socket_lifecycle_token.get() & 1 == 1
        && socket_lifecycle_token.get().checked_add(1) == Some(retirement_lifecycle_token.get())
    {
        Ok(())
    } else {
        Err(FenceError::InvalidPriorEvidence)
    }
}

const fn max_gate_lifetime() -> Duration {
    Duration::from_nanos(MAX_GATE_LIFETIME_NS)
}

#[path = "lifecycle_engine.rs"]
mod lifecycle_engine;

pub(crate) use lifecycle_engine::LeaseBoundFence;
pub use lifecycle_engine::LeaseFenceError;
