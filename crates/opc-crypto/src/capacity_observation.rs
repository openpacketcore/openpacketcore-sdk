//! Numeric original-buffer observations for bounded encryption qualification.
//!
//! Re-exported here so callers need not couple to key-provider internals.
//! See [`BufferObservation`] for callback lifetime and measurement exclusions.

pub use opc_key::capacity_observation::{
    capture_current, checkpoint, scope, AllocationIdentity, BufferBorrow, BufferEvent, BufferKind,
    BufferObservation, BufferReceipt, BufferSnapshot, MAX_BUFFER_ROWS,
};

/// Observe the identity of the real destination-store reservation without
/// cloning it or extending its ownership lifetime.
pub fn observe_reservation(reservation: &crate::ConfigPreparationReservation) {
    opc_key::capacity_observation::reservation(std::sync::Arc::as_ptr(&reservation.lease) as usize);
}
