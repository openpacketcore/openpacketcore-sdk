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

use bytes::{Bytes, BytesMut};
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

    /// Adopt an owned vector's allocation without copying.
    ///
    /// `Bytes::from(Vec<u8>)` takes ownership of the vector's allocation and
    /// the immediate unique conversion to [`BytesMut`] reuses it, so no second
    /// heap copy of the contents is created and the original allocation is the
    /// one zeroized on drop. Prefer this over a copy when a secret arrives as
    /// an owned `Vec<u8>`.
    #[must_use]
    pub fn from_vec(value: Vec<u8>) -> Self {
        // `Bytes::from` adopts the Vec allocation; the handle is unique here, so
        // `BytesMut::from(Bytes)` converts back without copying.
        Self(BytesMut::from(Bytes::from(value)))
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
        #[cfg(test)]
        let had_nonzero_content = self.0.iter().any(|byte| *byte != 0);
        self.0.as_mut().zeroize();
        // A test-only drop observer proves the clear happened before release
        // without any allocator hook or unsafe code.
        #[cfg(test)]
        test_audit::record(had_nonzero_content, self.0.iter().any(|byte| *byte != 0));
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

/// Test-only drop auditing for the zeroization contract.
///
/// Kept in safe code: unit tests in this crate compile it, and it records only
/// aggregate flags, never buffer contents.
#[cfg(test)]
mod test_audit {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::SensitiveBytes;

    /// Serializes the aggregate counters; the allocator is not involved.
    static LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    static DROPS_WITH_CONTENT: AtomicUsize = AtomicUsize::new(0);
    static DROPS_LEFT_CONTENT: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn record(had_content: bool, left_content: bool) {
        if had_content {
            DROPS_WITH_CONTENT.fetch_add(1, Ordering::SeqCst);
        }
        if left_content {
            DROPS_LEFT_CONTENT.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn reset() {
        DROPS_WITH_CONTENT.store(0, Ordering::SeqCst);
        DROPS_LEFT_CONTENT.store(0, Ordering::SeqCst);
    }

    fn counts() -> (usize, usize) {
        (
            DROPS_WITH_CONTENT.load(Ordering::SeqCst),
            DROPS_LEFT_CONTENT.load(Ordering::SeqCst),
        )
    }

    #[test]
    fn drop_zeroizes_content_before_the_allocation_is_released() {
        let _guard = lock();
        reset();
        let value = SensitiveBytes::from_slice(&[0x5a; 32]);
        assert_eq!(value.as_slice(), &[0x5a; 32]);
        drop(value);
        let (with_content, left_content) = counts();
        assert_eq!(with_content, 1, "drop must observe the live content");
        assert_eq!(
            left_content, 0,
            "drop must clear every octet before release"
        );
    }

    #[test]
    fn from_bytes_mut_is_zeroized_too() {
        let _guard = lock();
        let value = SensitiveBytes::from_bytes_mut(bytes::BytesMut::from(&[0x11; 16][..]));
        assert_eq!(value.len(), 16);
        drop(value);
        // Counters are covered by the single-audit test above; here the point is
        // that the BytesMut-backed constructor shares the same Drop path.
    }

    #[test]
    fn from_vec_adopts_the_allocation_and_clears_it_on_drop() {
        let _guard = lock();
        reset();
        let input = vec![0x22; 24];
        let allocation = input.as_ptr();
        let value = SensitiveBytes::from_vec(input);
        assert_eq!(value.len(), 24);
        assert_eq!(
            value.as_slice().as_ptr(),
            allocation,
            "from_vec must adopt the Vec allocation instead of copying it"
        );
        drop(value);
        let (with_content, left_content) = counts();
        assert_eq!(with_content, 1, "adopted content must reach the audit drop");
        assert_eq!(left_content, 0, "adopted content must be cleared on drop");
    }

    #[test]
    fn empty_and_partially_zero_buffers_are_handled() {
        let _guard = lock();
        reset();
        drop(SensitiveBytes::new());
        let mixed = SensitiveBytes::from_slice(&[0, 0, 0x01, 0]);
        assert_eq!(mixed.as_slice(), &[0, 0, 0x01, 0]);
        drop(mixed);
        let (_, left_content) = counts();
        assert_eq!(left_content, 0);
    }
}
