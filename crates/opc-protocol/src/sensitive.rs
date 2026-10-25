//! Owned byte buffers whose contents are cleared when they are dropped.
//!
//! Protocol crates receive bytes from transports that own the underlying
//! allocation (for example SCTP or a copied NGAP PDU prefix). A shared
//! `bytes::Bytes` handle cannot be cleared safely on drop: clones share one
//! allocation and the buffer is immutable. [`SensitiveBytes`] instead owns a
//! unique mutable buffer and zeroizes its initialized prefix on drop.
//!
//! It deliberately implements neither `Clone` nor equality: duplicating a
//! secret buffer must be an explicit, visible operation with its own custody.
//! `Debug` never prints contents.

use std::fmt;
use std::ops::Deref;

use bytes::BytesMut;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// An owned byte buffer that is zeroized when dropped.
///
/// The buffer is uniquely owned, so clearing on drop covers the complete
/// initialized prefix. Wire copies, caller-owned copies and copies made through
/// a separate API must be cleared by their owners. `Debug` reports only the
/// length.
///
/// ```compile_fail
/// let bytes = opc_protocol::SensitiveBytes::from_slice(b"secret");
/// let _duplicate = bytes.clone();
/// ```
#[derive(Default)]
pub struct SensitiveBytes(BytesMut);

impl SensitiveBytes {
    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self(BytesMut::new())
    }

    /// Copy a borrowed slice into a new owned buffer.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(BytesMut::from(bytes))
    }

    /// Adopt an existing uniquely owned buffer without copying.
    ///
    /// The caller must not retain another handle to the same allocation; a
    /// `BytesMut` has no shared clones by construction.
    #[must_use]
    pub fn from_bytes_mut(bytes: BytesMut) -> Self {
        Self(bytes)
    }

    /// Borrow the initialized contents.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Return the initialized length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Move the contents into a [`Zeroizing`] container.
    ///
    /// This is an explicit copy for APIs that require a `Zeroizing<Vec<u8>>`;
    /// the source buffer remains cleared when this value is dropped.
    #[must_use]
    pub fn copy_into_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        // Zeroize every initialized octet before the allocation is released.
        self.0.as_mut().zeroize();
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("len", &self.0.len())
            .finish()
    }
}
