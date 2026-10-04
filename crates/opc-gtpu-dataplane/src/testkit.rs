//! Structural consumer fixtures, without kernel or TrafficReady authority.
//!
//! The selector simulation runs the real protected coordinator against an
//! isolated backend. Downlink factories supply unvalidated structural inputs
//! for consumer fakes. None issue trusted traffic proofs or forwarding
//! authority, or qualify Linux forwarding, kernel IO cancellation or continuity.
//! This module is always available, so outcome types alone do not establish
//! receive authorization or validity. The production injector validates packet
//! structure and fragment ordering again, but cannot grant receive authority.

pub use crate::ebpf::grouped_simulation::GroupedGtpuDataplaneSimulation;

/// Construct one structural downlink input for a consumer test or fake.
///
/// The bytes and family are not validated and no receive authorization is
/// granted. Production inputs must come from the control port. The injector
/// still validates these bytes if a test deliberately passes them to it.
#[must_use]
pub fn decapsulated_downlink(
    packet: bytes::Bytes,
    mark: Option<crate::GtpBearerMark>,
    family: crate::GtpAddressFamily,
) -> crate::GtpuDecapsulatedDownlink {
    crate::GtpuDecapsulatedDownlink::new(packet, mark, family)
}

/// Construct a structural fragment-batch input for a consumer test or fake.
///
/// No byte validation, ordering check or forwarding authority is supplied.
/// Production batches must come from the control port; this factory permits
/// malformed fixtures to exercise consumer refusal paths too.
#[must_use]
pub fn fragmented_downlink(
    fragments: Vec<bytes::Bytes>,
    mark: Option<crate::GtpBearerMark>,
    mtu: u16,
) -> crate::GtpuFragmentedDownlink {
    crate::GtpuFragmentedDownlink::new(fragments, mark, mtu)
}
