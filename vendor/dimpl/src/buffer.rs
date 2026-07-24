//! Buffer management for efficient memory reuse.
//!
//! This module provides buffer types used throughout dimpl for managing byte data
//! with minimal allocations. The [`BufferPool`] allows reusing buffers, and [`Buf`]
//! wraps `Vec<u8>` with convenient operations for protocol data handling.

use std::collections::VecDeque;
use std::fmt;
use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// Buffer pool for reusing allocated buffers.
///
/// This pool manages a collection of reusable `Buf` instances to reduce allocations
/// during DTLS operations. Buffers are returned to the pool when no longer needed
/// and can be reused for subsequent operations.
#[derive(Default)]
pub struct BufferPool {
    free: VecDeque<Buf>,
}

impl BufferPool {
    /// Take a Buffer from the pool.
    ///
    /// Creates a new buffer if none is free.
    pub fn pop(&mut self) -> Buf {
        match self.free.pop_front() {
            Some(buffer) => buffer,
            None => Buf::new(),
        }
    }

    /// Return a buffer to the pool.
    pub fn push(&mut self, mut buffer: Buf) {
        buffer.zeroize();
        self.free.push_front(buffer);
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool")
            .field("free", &self.free.len())
            .finish()
    }
}

/// Growable buffer wrapper used throughout dimpl for efficient memory management.
///
/// This is a newtype around `Vec<u8>` that provides convenient access to byte buffers
/// and integrates with dimpl's buffer pooling system.
#[derive(Default)]
pub struct Buf(Vec<u8>);

impl Buf {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the buffer, removing all data.
    pub fn clear(&mut self) {
        self.clear_after_wipe(|_| {});
    }

    fn clear_after_wipe<F>(&mut self, after_wipe: F)
    where
        F: FnOnce(&[u8]),
    {
        self.0.as_mut_slice().zeroize();
        after_wipe(&self.0);
        self.0.clear();
    }

    /// Extend the buffer with a slice of bytes.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.0.extend_from_slice(other);
    }

    /// Push a single byte onto the buffer.
    pub fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    /// Resize the buffer to the specified length, filling with the given value.
    pub fn resize(&mut self, len: usize, value: u8) {
        if len < self.0.len() {
            self.0[len..].zeroize();
            self.0.truncate(len);
        } else {
            self.0.resize(len, value);
        }
    }

    /// Convert the buffer into the underlying `Vec<u8>`.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Zeroize for Buf {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// aws-lc-rs AEAD operations require Extend<&u8> for appending authentication tags
impl<'a> Extend<&'a u8> for Buf {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.0.extend(iter.into_iter().copied());
    }
}

impl Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Buf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Buf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buf").field("len", &self.0.len()).finish()
    }
}

/// Trait for types that can be converted into a `Buf`.
pub trait ToBuf {
    /// Convert this value into a `Buf`.
    fn to_buf(self) -> Buf;
}

impl ToBuf for Vec<u8> {
    fn to_buf(self) -> Buf {
        Buf(self)
    }
}

impl ToBuf for &[u8] {
    fn to_buf(self) -> Buf {
        self.to_vec().to_buf()
    }
}

/// Temporary mutable buffer wrapper for in-place operations.
///
/// Used primarily for decryption operations where data needs to be modified in-place.
/// Provides mutable access to a slice with tracked length.
#[allow(clippy::len_without_is_empty)]
pub struct TmpBuf<'a>(&'a mut [u8], usize);

impl core::fmt::Debug for TmpBuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TmpBuf").field("data_len", &self.1).finish()
    }
}

impl<'a> TmpBuf<'a> {
    /// Create a new temporary buffer from a mutable slice.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf, buf.len())
    }
}

impl<'a> TmpBuf<'a> {
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.1
    }

    /// Truncate the buffer to the specified length
    pub fn truncate(&mut self, len: usize) {
        if len < self.1 {
            self.0[len..self.1].zeroize();
            self.1 = len;
        }
    }
}

impl<'a> AsRef<[u8]> for TmpBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

impl<'a> AsMut<[u8]> for TmpBuf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..self.1]
    }
}

#[cfg(feature = "rust-crypto")]
impl<'a> aes_gcm::aead::Buffer for TmpBuf<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), aes_gcm::aead::Error> {
        // Check if there's enough capacity in the underlying slice
        let available = self.0.len() - self.1;
        if available < other.len() {
            return Err(aes_gcm::aead::Error);
        }
        // Copy the data into the buffer
        self.0[self.1..self.1 + other.len()].copy_from_slice(other);
        self.1 += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.1 {
            self.0[len..self.1].zeroize();
            self.1 = len;
        }
    }
}

/// Implement the `aead::Buffer` trait for `Buf` to support in-place AEAD operations.
#[cfg(feature = "rust-crypto")]
impl aes_gcm::aead::Buffer for Buf {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), aes_gcm::aead::Error> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            self.0[len..].zeroize();
            self.0.truncate(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_buffers_are_zeroized_and_reused_empty() {
        let mut pool = BufferPool::default();
        let mut secret = Buf::new();
        secret.extend_from_slice(&[0xa5; 64]);
        let capacity = secret.0.capacity();

        pool.push(secret);

        let reused = pool.pop();
        assert!(reused.is_empty(), "pooled buffer must be returned empty");
        assert!(
            reused.0.capacity() >= capacity,
            "zeroization must retain the allocation for safe reuse"
        );
    }

    #[test]
    fn zeroize_clears_secret_buffer_contents() {
        let mut secret = Buf::new();
        secret.extend_from_slice(&[0x5a; 32]);
        secret.zeroize();
        assert!(secret.is_empty());
    }

    #[test]
    fn clear_wipes_initialized_storage_before_length_reset() {
        let mut secret = Buf::new();
        secret.extend_from_slice(&[0x5a; 32]);
        secret.clear_after_wipe(|initialized| {
            assert!(
                initialized.iter().all(|byte| *byte == 0),
                "initialized storage must be wiped before Vec::clear"
            );
        });
        assert!(secret.is_empty());
    }

    #[test]
    fn temporary_buffer_truncate_wipes_removed_tail() {
        let mut storage = [0xA5; 32];
        {
            let mut temporary = TmpBuf::new(&mut storage);
            temporary.truncate(12);
            assert_eq!(temporary.len(), 12);
        }
        assert!(storage[..12].iter().all(|byte| *byte == 0xA5));
        assert!(storage[12..].iter().all(|byte| *byte == 0));
    }
}
