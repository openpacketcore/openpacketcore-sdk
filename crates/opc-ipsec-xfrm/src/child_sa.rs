//! Caller-selected traffic classes and exact Child-SA selection intentions.
//!
//! Overlapping traffic selectors cannot identify which Child SA the caller
//! intends. This module maps opaque caller classes and an explicit default to
//! one selected outbound SA per logical child, while retaining inbound identities
//! during rekey overlap. It neither examines packets nor changes selectors.
//!
//! These are freely constructible **intentions**, not installed capabilities or
//! authenticated packet evidence. A plan performs no backend I/O. Its incarnation
//! comparison can reject mismatched caller metadata; it cannot establish the
//! provenance or freshness of that metadata. A live adapter must separately
//! authenticate packet provenance after integrity and final replay acceptance,
//! bind incarnations to lifecycle events, fence every writer, read back the
//! complete resource roster, and publish one current generation atomically.
//! In particular, this module cannot issue [`crate::InstalledOutboundSaBinding`]
//! or authorize relocation. PDU/QFI interpretation and eligibility for a default
//! belong to the caller.

use std::{fmt, num::NonZeroU64};

use crate::{QuerySaRequest, XfrmId, XfrmLookupMark};

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    )+};
}

macro_rules! token {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Construct a caller-assigned nonzero label. This grants no authority.
            #[must_use]
            pub const fn new(value: u64) -> Option<Self> {
                match NonZeroU64::new(value) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            /// Return the caller-assigned label for explicit correlation.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
        redacted_debug!($name);
    };
}

token! {
    /// Logical Child-SA label within a caller-owned selection scope.
    ///
    /// A child may have multiple incarnations during rekey overlap. This is not
    /// an IKE SPI, a PDU session identifier, or a globally unique backend handle.
    ChildSaId
}

token! {
    /// Opaque result of the caller's packet-classification policy.
    ///
    /// Several classes can select one child. The SDK assigns no meaning to the
    /// label and does not derive it from packet bytes, PDU sessions or QFIs.
    ChildSaClass
}

token! {
    /// Caller-assigned incarnation of a logical child pair.
    ///
    /// Assign a new value after rekey or removal/reinstall. The label is data,
    /// not proof that the kernel or any packet source observed that lifecycle.
    ChildSaIncarnation
}

impl ChildSaIncarnation {
    /// Advance without wrapping or reusing an exhausted incarnation space.
    ///
    /// `None` requires the caller to refuse a successor in this scope. This
    /// arithmetic helper is not a shared writer fence or persistent counter.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(next) => Self::new(next),
            None => None,
        }
    }
}

/// Exact ESP lookup identity plus the expected XFRM interface scope.
///
/// Only unmarked and full-mask identities are admitted. An unmarked stored SA
/// can match every incoming lookup mark; a plan rejects that overlap with any
/// other SA having the same destination/protocol/SPI. Linux SA lookup does not
/// use the interface ID to disambiguate two such entries, although inbound
/// metadata must still match the expected interface ID exactly.
///
/// This shape contains no keys, selectors or packet contents. It is an intent
/// or correlation value, never authenticated provenance by itself. Namespace
/// identity, exclusion of foreign overlapping SAs and trustworthy readback
/// remain obligations of a live adapter.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildSaTrafficIdentity {
    id: XfrmId,
    mark: Option<XfrmLookupMark>,
    if_id: Option<u32>,
}

impl ChildSaTrafficIdentity {
    /// Validate a concrete ESP SPI/destination and exact optional mark/scope.
    ///
    /// Unspecified destinations, non-ESP protocols, zero SPIs, partial mark
    /// masks and a present zero interface ID return
    /// [`ChildSaSelectionError::InvalidSaIdentity`].
    pub fn new(
        id: XfrmId,
        mark: Option<XfrmLookupMark>,
        if_id: Option<u32>,
    ) -> Result<Self, ChildSaSelectionError> {
        if id.spi == 0
            || id.protocol != 50
            || id.destination.is_unspecified()
            || mark.is_some_and(|mark| !mark.is_exact_profile())
            || if_id == Some(0)
        {
            return Err(ChildSaSelectionError::InvalidSaIdentity);
        }
        Ok(Self { id, mark, if_id })
    }

    /// Exact intended destination, protocol and SPI.
    #[must_use]
    pub const fn id(self) -> XfrmId {
        self.id
    }

    /// Build an observation-only SA query using the exact lookup mark.
    ///
    /// Linux's SA query key excludes `if_id`; the caller must compare the
    /// returned interface scope separately using [`Self::if_id`]. A successful
    /// query does not establish installed ownership or publication authority.
    #[must_use]
    pub const fn query(self) -> QuerySaRequest {
        QuerySaRequest {
            destination: self.id.destination,
            protocol: self.id.protocol,
            spi: self.id.spi,
            mark: self.mark,
        }
    }

    /// Expected XFRM interface scope, compared exactly by inbound matching.
    #[must_use]
    pub const fn if_id(self) -> Option<u32> {
        self.if_id
    }

    fn overlaps(self, other: Self) -> bool {
        self.id == other.id
            && match (self.mark, other.mark) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

/// Whether an incarnation can be chosen for outbound selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSaOutboundUse {
    /// The one selected outbound incarnation for this logical child.
    Selected,
    /// Retain inbound matching during overlap without selecting this outbound SA.
    ReceiveOnly,
}

/// Caller-declared directional SA pair for one incarnation of a logical child.
///
/// Pair membership, endpoint authentication, compatible selectors and crypto
/// installation are caller/adapter obligations. Constructing a pair performs
/// no validation of those facts; the selection plan validates only its own
/// identity, overlap and reference invariants.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildSaPair {
    child: ChildSaId,
    incarnation: ChildSaIncarnation,
    inbound: ChildSaTrafficIdentity,
    outbound: ChildSaTrafficIdentity,
    outbound_use: ChildSaOutboundUse,
}

impl ChildSaPair {
    /// Declare a pair; admission into a plan checks cross-pair invariants.
    #[must_use]
    pub const fn new(
        child: ChildSaId,
        incarnation: ChildSaIncarnation,
        inbound: ChildSaTrafficIdentity,
        outbound: ChildSaTrafficIdentity,
        outbound_use: ChildSaOutboundUse,
    ) -> Self {
        Self {
            child,
            incarnation,
            inbound,
            outbound,
            outbound_use,
        }
    }

    /// Logical child selected by the caller.
    #[must_use]
    pub const fn child(&self) -> ChildSaId {
        self.child
    }

    /// Caller-assigned lifecycle incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> ChildSaIncarnation {
        self.incarnation
    }

    /// Exact inbound identity intention.
    #[must_use]
    pub const fn inbound(&self) -> ChildSaTrafficIdentity {
        self.inbound
    }

    /// Exact outbound identity intention, including a concrete SPI.
    #[must_use]
    pub const fn outbound(&self) -> ChildSaTrafficIdentity {
        self.outbound
    }

    /// Explicit outbound eligibility, independent of list or incarnation order.
    #[must_use]
    pub const fn outbound_use(&self) -> ChildSaOutboundUse {
        self.outbound_use
    }
}

/// One caller-selected traffic class mapped to a logical child.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChildSaClassBinding {
    class: ChildSaClass,
    child: ChildSaId,
}

impl ChildSaClassBinding {
    /// Declare a class mapping; plan construction validates the target.
    #[must_use]
    pub const fn new(class: ChildSaClass, child: ChildSaId) -> Self {
        Self { class, child }
    }

    /// The opaque caller class.
    #[must_use]
    pub const fn class(self) -> ChildSaClass {
        self.class
    }

    /// The intended logical child.
    #[must_use]
    pub const fn child(self) -> ChildSaId {
        self.child
    }
}

/// Explicit result of the caller's outbound policy evaluation.
///
/// An unknown `Class` fails; it never silently chooses `Default`. The caller
/// must choose `Default` only within its already-selected policy scope. A plan
/// has exactly one default child; separate fallback scopes need separate plans.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChildSaOutboundSelection {
    /// Use the exact class binding.
    Class(ChildSaClass),
    /// Use the single explicitly selected default child.
    Default,
}

/// Caller-selected bounds on plan validation and retained data.
///
/// These are SDK resource policies, not protocol limits. Construction reuses
/// the supplied vectors without allocating or sorting. Validation is quadratic
/// in pair/class counts; lookups are linear. Choose bounds accordingly.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChildSaSelectionLimits {
    /// Inclusive number of directional pairs, including rekey overlap; nonzero.
    pub max_pairs: usize,
    /// Inclusive class count. Zero permits a default-only plan.
    pub max_classes: usize,
}

/// Immutable, validated selection intentions for one caller-owned scope.
///
/// All children must have exactly one selected outbound incarnation. Duplicate
/// incarnations, duplicate class labels, dangling references and overlapping
/// kernel lookup identities are refused. Receive-only incarnations are admitted
/// for rekey overlap. No order or numeric preference is inferred.
///
/// Cloning or retaining this value preserves intentions only. It supplies no
/// installed-state, generation-fence, authentication or freshness guarantee.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildSaSelectionPlan {
    pairs: Vec<ChildSaPair>,
    classes: Vec<ChildSaClassBinding>,
    default: ChildSaId,
}

impl ChildSaSelectionPlan {
    /// Validate the complete plan without backend effects or new allocations.
    pub fn new(
        pairs: Vec<ChildSaPair>,
        classes: Vec<ChildSaClassBinding>,
        default: ChildSaId,
        limits: ChildSaSelectionLimits,
    ) -> Result<Self, ChildSaSelectionError> {
        use ChildSaSelectionError as Error;
        if limits.max_pairs == 0 {
            return Err(Error::InvalidLimits);
        }
        if pairs.is_empty() {
            return Err(Error::EmptyRoster);
        }
        if pairs.len() > limits.max_pairs || classes.len() > limits.max_classes {
            return Err(Error::CapacityExceeded);
        }
        for (index, pair) in pairs.iter().enumerate() {
            if pair.inbound.overlaps(pair.outbound) {
                return Err(Error::AmbiguousSaIdentity);
            }
            for prior in &pairs[..index] {
                if prior.child == pair.child && prior.incarnation == pair.incarnation {
                    return Err(Error::DuplicateIncarnation);
                }
                for identity in [pair.inbound, pair.outbound] {
                    if identity.overlaps(prior.inbound) || identity.overlaps(prior.outbound) {
                        return Err(Error::AmbiguousSaIdentity);
                    }
                }
            }
            match pairs
                .iter()
                .filter(|candidate| {
                    candidate.child == pair.child
                        && candidate.outbound_use == ChildSaOutboundUse::Selected
                })
                .count()
            {
                0 => return Err(Error::MissingOutbound),
                1 => {}
                _ => return Err(Error::MultipleOutbound),
            }
        }
        if !pairs.iter().any(|pair| pair.child == default) {
            return Err(Error::UnknownChild);
        }
        for (index, binding) in classes.iter().enumerate() {
            if classes[..index]
                .iter()
                .any(|prior| prior.class == binding.class)
            {
                return Err(Error::DuplicateClass);
            }
            if !pairs.iter().any(|pair| pair.child == binding.child) {
                return Err(Error::UnknownChild);
            }
        }
        Ok(Self {
            pairs,
            classes,
            default,
        })
    }

    /// All declared pairs, including receive-only incarnations, in input order.
    #[must_use]
    pub fn pairs(&self) -> &[ChildSaPair] {
        &self.pairs
    }

    /// All validated class bindings in input order.
    #[must_use]
    pub fn classes(&self) -> &[ChildSaClassBinding] {
        &self.classes
    }

    /// The one explicitly selected default child.
    #[must_use]
    pub const fn default_child(&self) -> ChildSaId {
        self.default
    }

    /// Resolve an explicit outbound intention without I/O or allocation.
    ///
    /// The returned pair includes the exact intended outbound SPI. It does not
    /// prove that any packet was sent on that SA or grant egress authority.
    pub fn select_outbound(
        &self,
        selection: ChildSaOutboundSelection,
    ) -> Result<&ChildSaPair, ChildSaSelectionError> {
        let child = match selection {
            ChildSaOutboundSelection::Class(class) => {
                self.classes
                    .iter()
                    .find(|binding| binding.class == class)
                    .ok_or(ChildSaSelectionError::UnknownClass)?
                    .child
            }
            ChildSaOutboundSelection::Default => self.default,
        };
        self.pairs
            .iter()
            .find(|pair| pair.child == child && pair.outbound_use == ChildSaOutboundUse::Selected)
            .ok_or(ChildSaSelectionError::MissingOutbound)
    }

    /// Match caller-supplied inbound identity and incarnation metadata exactly.
    ///
    /// There is no default or outbound fallback. A known identity with an old
    /// incarnation fails with [`ChildSaSelectionError::StaleIncarnation`]. A
    /// successful comparison proves only equality with declared intentions;
    /// it does not authenticate a packet or validate the source of the metadata.
    pub fn match_inbound_intent(
        &self,
        identity: ChildSaTrafficIdentity,
        incarnation: ChildSaIncarnation,
    ) -> Result<&ChildSaPair, ChildSaSelectionError> {
        let pair = self
            .pairs
            .iter()
            .find(|pair| pair.inbound == identity)
            .ok_or(ChildSaSelectionError::UnknownInbound)?;
        if pair.incarnation != incarnation {
            return Err(ChildSaSelectionError::StaleIncarnation);
        }
        Ok(pair)
    }
}

/// Bounded, value-free selection or plan-validation failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSaSelectionError {
    /// A pair capacity of zero cannot hold a plan.
    InvalidLimits,
    /// A plan requires at least one pair.
    EmptyRoster,
    /// A caller-selected bound was exceeded.
    CapacityExceeded,
    /// An identity is not concrete ESP in the admitted exact profile.
    InvalidSaIdentity,
    /// Two directional entries can name the same kernel SA.
    AmbiguousSaIdentity,
    /// A logical child repeats an incarnation label.
    DuplicateIncarnation,
    /// A logical child has no selected outbound incarnation.
    MissingOutbound,
    /// A logical child has multiple selected outbound incarnations.
    MultipleOutbound,
    /// A class label appears more than once.
    DuplicateClass,
    /// A default or class references a child absent from the plan.
    UnknownChild,
    /// No exact binding exists for the requested class.
    UnknownClass,
    /// No exact inbound identity exists in the plan.
    UnknownInbound,
    /// The supplied incarnation differs from the declared inbound pair.
    StaleIncarnation,
}

impl fmt::Display for ChildSaSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid Child-SA selection limits",
            Self::EmptyRoster => "empty Child-SA selection roster",
            Self::CapacityExceeded => "Child-SA selection capacity exceeded",
            Self::InvalidSaIdentity => "invalid Child-SA traffic identity",
            Self::AmbiguousSaIdentity => "ambiguous Child-SA traffic identity",
            Self::DuplicateIncarnation => "duplicate Child-SA incarnation",
            Self::MissingOutbound => "missing selected outbound Child-SA incarnation",
            Self::MultipleOutbound => "multiple selected outbound Child-SA incarnations",
            Self::DuplicateClass => "duplicate Child-SA traffic class",
            Self::UnknownChild => "unknown Child-SA selection target",
            Self::UnknownClass => "unknown Child-SA traffic class",
            Self::UnknownInbound => "unknown inbound Child-SA identity",
            Self::StaleIncarnation => "stale inbound Child-SA incarnation",
        })
    }
}

impl std::error::Error for ChildSaSelectionError {}

redacted_debug!(
    ChildSaTrafficIdentity,
    ChildSaPair,
    ChildSaClassBinding,
    ChildSaOutboundSelection,
    ChildSaSelectionLimits,
    ChildSaSelectionPlan
);
