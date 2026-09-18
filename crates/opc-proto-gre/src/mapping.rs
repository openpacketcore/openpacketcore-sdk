//! @spec 3GPP TS24.502 8.3.1
//! @req REQ-3GPP-TS24502-NWU-GRE-MAPPING-001

use crate::Qfi;
use std::fmt;
use thiserror::Error;

/// Allocation-free set of QFIs; duplicate insertion is idempotent.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct QfiSet(u64);

impl QfiSet {
    /// Create an empty set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return a set containing this QFI as well as the existing entries.
    pub const fn with(self, qfi: Qfi) -> Self {
        Self(self.0 | (1u64 << qfi.value()))
    }

    /// Test membership without allocation.
    pub const fn contains(self, qfi: Qfi) -> bool {
        self.0 & (1u64 << qfi.value()) != 0
    }
}

impl fmt::Debug for QfiSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QfiSet([REDACTED])")
    }
}

/// Caller-declared eligibility for fallback when no explicit QFI matches.
/// This records intent, not authorization or a dataplane action.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DefaultFallbackIntent {
    /// This association is not a default fallback candidate.
    Ineligible,
    /// The caller identifies this as a default association for this session.
    Eligible,
}

impl fmt::Debug for DefaultFallbackIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DefaultFallbackIntent([REDACTED])")
    }
}

/// Caller-owned association identifier, multiple QFIs, and default intent.
/// The identifier is opaque and is never formatted, installed, or validated.
#[derive(Clone, PartialEq, Eq)]
pub struct FlowAssociation<T> {
    association: T,
    qfis: QfiSet,
    fallback: DefaultFallbackIntent,
}

impl<T> FlowAssociation<T> {
    /// Record caller-supplied associations without selecting QoS/SA policy.
    pub const fn new(association: T, qfis: QfiSet, fallback: DefaultFallbackIntent) -> Self {
        Self {
            association,
            qfis,
            fallback,
        }
    }

    /// Explicitly access the opaque caller identifier.
    pub const fn association(&self) -> &T {
        &self.association
    }

    /// Explicitly access the QFI set.
    pub const fn qfis(&self) -> QfiSet {
        self.qfis
    }

    /// Explicitly access the caller-declared fallback intent.
    pub const fn fallback_intent(&self) -> DefaultFallbackIntent {
        self.fallback
    }
}

impl<T> fmt::Debug for FlowAssociation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowAssociation([REDACTED])")
    }
}

/// A mapping limit failed without retaining identifiers or configured bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("association count exceeds limit")]
pub struct MappingError;

/// Bounded borrowed associations for **one caller-scoped PDU session and
/// direction**. The caller must filter and authenticate that scope first.
/// No allocation, association liveness check, or policy action occurs here.
pub struct FlowMapping<'a, T> {
    entries: &'a [FlowAssociation<T>],
}

impl<'a, T> FlowMapping<'a, T> {
    /// Check the caller-selected association count bound before traversal.
    pub fn new(
        entries: &'a [FlowAssociation<T>],
        max_associations: usize,
    ) -> Result<Self, MappingError> {
        if entries.len() > max_associations {
            return Err(MappingError);
        }
        Ok(Self { entries })
    }

    /// Return every explicit QFI match, or every default candidate if none
    /// match. Multiple matches remain visible for caller policy; input order
    /// is preserved but has no preference meaning. At most two bounded scans
    /// determine the kind; each iteration then scans at most the entry count.
    pub fn select(&self, qfi: Qfi) -> FlowSelection<'a, T> {
        let kind = if self.entries.iter().any(|entry| entry.qfis.contains(qfi)) {
            SelectionKind::Exact
        } else if self
            .entries
            .iter()
            .any(|entry| entry.fallback == DefaultFallbackIntent::Eligible)
        {
            SelectionKind::DefaultFallback
        } else {
            SelectionKind::Unmapped
        };
        FlowSelection {
            entries: self.entries,
            qfi,
            kind,
        }
    }
}

impl<T> fmt::Debug for FlowMapping<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowMapping([REDACTED])")
    }
}

/// Selection disposition, without packet, subscriber, or association values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionKind {
    /// At least one association explicitly contains the QFI.
    Exact,
    /// No exact match; caller-declared default candidates exist.
    DefaultFallback,
    /// Neither an exact match nor a default candidate exists.
    Unmapped,
}

/// Bounded selection whose candidates still require caller policy.
pub struct FlowSelection<'a, T> {
    entries: &'a [FlowAssociation<T>],
    qfi: Qfi,
    kind: SelectionKind,
}

impl<'a, T> FlowSelection<'a, T> {
    /// Access the value-free disposition.
    pub const fn kind(&self) -> SelectionKind {
        self.kind
    }

    /// Iterate all matching candidates without allocating or cloning IDs.
    pub fn candidates(&self) -> AssociationCandidates<'a, T> {
        AssociationCandidates {
            remaining: self.entries.iter(),
            qfi: self.qfi,
            kind: self.kind,
        }
    }
}

impl<T> fmt::Debug for FlowSelection<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowSelection([REDACTED])")
    }
}

/// Allocation-free iterator. Debug never invokes the identifier's formatter.
pub struct AssociationCandidates<'a, T> {
    remaining: std::slice::Iter<'a, FlowAssociation<T>>,
    qfi: Qfi,
    kind: SelectionKind,
}

impl<'a, T> Iterator for AssociationCandidates<'a, T> {
    type Item = &'a FlowAssociation<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining.find(|entry| match self.kind {
            SelectionKind::Exact => entry.qfis.contains(self.qfi),
            SelectionKind::DefaultFallback => entry.fallback == DefaultFallbackIntent::Eligible,
            SelectionKind::Unmapped => false,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining.len()))
    }
}

impl<T> std::iter::FusedIterator for AssociationCandidates<'_, T> {}

impl<T> fmt::Debug for AssociationCandidates<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AssociationCandidates([REDACTED])")
    }
}
