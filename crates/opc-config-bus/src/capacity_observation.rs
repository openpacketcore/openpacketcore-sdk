//! Original adapter/encryption buffer observations for capacity qualification.
//!
//! Wrap actual adapter operations in [`scope`]. Callbacks can synchronously
//! join independent native or transport observations while originals are held.
//! Arc envelope aliases share one row; `RecordBlob` is a separate Vec allocation.
//! After the adapter transfers its record, the destination owns that Vec and
//! must borrow/register it at its own boundary to extend its measured lifetime.
//!
//! The callbacks measure data capacity only. They do not establish a 32 MiB
//! operation or 256 MiB fleet ceiling; provider-private memory, caller-owned config,
//! allocator overhead and internal conversion overlap still need qualification.

pub use opc_crypto::capacity_observation::{
    capture_current, checkpoint, scope, AllocationIdentity, BufferBorrow, BufferEvent, BufferKind,
    BufferObservation, BufferReceipt, BufferSnapshot, MAX_BUFFER_ROWS,
};
