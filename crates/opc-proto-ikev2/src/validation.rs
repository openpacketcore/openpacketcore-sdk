//! IKEv2-specific receive and sender-canonical validation profiles.
//!
//! RFC 7296 deliberately distinguishes fields that a sender writes as zero
//! from fields that a receiver validates. [`Ikev2ValidationProfile`] keeps
//! that distinction separate from [`opc_protocol::ValidationLevel`], which
//! continues to control structural and semantic validation of untrusted input.

/// Validation policy for RFC 7296 fields that are canonical on transmission
/// but explicitly ignored on receipt.
///
/// This profile does not weaken message-length, payload-chain, major-version,
/// cardinality, unknown-critical-payload, integrity, or authentication checks.
/// Those checks remain mandatory at their existing decode and crypto
/// boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Ikev2ValidationProfile {
    /// Standards-conforming network receive behavior.
    ///
    /// Higher IKEv2 minor versions and RFC-defined reserved fields are
    /// accepted where RFC 7296 says receivers ignore them. Raw fixed and
    /// generic headers retain those octets, and ID payload views retain the
    /// exact reserved octets required for AUTH transcript fidelity.
    #[default]
    NetworkReceive,
    /// Validate that bytes are canonical for an IKEv2 sender.
    ///
    /// Use this opt-in profile for generated fixtures and outbound conformance
    /// tests, not as a network admission policy. Production encoders already
    /// emit zero for the covered reserved fields and IKEv2 minor version 0.
    SenderCanonical,
}

impl Ikev2ValidationProfile {
    pub(crate) const fn requires_sender_canonical_fields(self) -> bool {
        matches!(self, Self::SenderCanonical)
    }
}
