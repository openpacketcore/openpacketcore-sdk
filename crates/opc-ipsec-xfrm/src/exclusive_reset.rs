//! Explicit startup reset of an exclusively owned XFRM namespace.

use crate::XfrmError;

/// Acknowledges exclusive XFRM ownership and abandonment of all predecessor state.
///
/// The caller must be the namespace's only XFRM writer, and nothing else may
/// rely on any SA or policy there. It must retain no predecessor object or
/// recovery record for adoption, recovery, or finalization in this process.
/// The SDK cannot verify these obligations.
///
/// Bind every recovery-store family ever used in the namespace. Unbound stores
/// are untouched. Stop plaintext sources before resetting: even protective
/// block policies disappear. Reinstall protection before reopening sources.
#[derive(Debug, Clone, Copy)]
pub struct ExclusiveNamespaceResetAcknowledgement {
    _private: (),
}

impl ExclusiveNamespaceResetAcknowledgement {
    /// Assert that this caller is the sole XFRM writer, nothing else relies on
    /// the namespace's SAs/policies, and no predecessor state will be retained.
    #[must_use]
    pub const fn sole_xfrm_writer_and_retains_no_predecessor_state() -> Self {
        Self { _private: () }
    }
}

/// Value-free evidence of a completed namespace reset and durable store reset.
///
/// Success proves fresh empty SAD/SPD readback before any store was reset.
/// Object counts are omitted because obtaining them would require an extra
/// dump before flushing. Per-socket policies are outside the namespace SPD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveNamespaceResetReport {
    /// Number of bound recovery-store families durably reset (zero to three).
    pub stores_reset: usize,
}

#[derive(Debug, Default)]
pub(crate) struct NamespaceResetGate {
    ordinary_admitted: bool,
    pub(crate) required: bool,
}

impl NamespaceResetGate {
    pub(crate) fn start(&mut self) -> Result<(), XfrmError> {
        if self.ordinary_admitted {
            return Err(XfrmError::StateMismatch {
                operation: "exclusive_namespace_reset_startup",
            });
        }
        self.required = true;
        Ok(())
    }

    pub(crate) fn admit(&mut self) -> Result<(), XfrmError> {
        if self.required {
            return Err(XfrmError::Unavailable);
        }
        self.ordinary_admitted = true;
        Ok(())
    }
}
