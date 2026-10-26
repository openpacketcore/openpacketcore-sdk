//! Ownership for opaque NGAP bytes, including unrecognized key-bearing IEs.

use std::{fmt, ops::Deref};

use zeroize::{Zeroize, Zeroizing};

/// Opaque bytes cleared before their allocation is released.
///
/// Diagnostics expose only the length. There is deliberately no `Clone`,
/// equality, hashing or serialization implementation. Explicit copies made
/// through the borrowed slice remain the caller's responsibility.
///
/// ```compile_fail
/// let bytes = opc_proto_ngap::SensitiveBytes::new(b"secret".to_vec());
/// let _duplicate = bytes.clone();
/// ```
#[derive(Default)]
pub struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    /// Take custody of an existing allocation without copying its contents.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the contents for an authorized codec or key consumer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveBytes")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        audit::observe(&self.0);
        // Zeroizing also clears spare capacity before freeing the allocation.
    }
}

/// Borrow unfragmented values; keep coalesced fragments under wiping ownership.
pub(crate) enum SensitiveValue<'a> {
    Borrowed(&'a [u8]),
    Owned(SensitiveBytes),
}

impl SensitiveValue<'_> {
    pub(crate) fn into_sensitive(self) -> SensitiveBytes {
        match self {
            Self::Borrowed(value) => SensitiveBytes::new(value.to_vec()),
            Self::Owned(value) => value,
        }
    }
}

impl Deref for SensitiveValue<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}

#[cfg(test)]
pub(crate) mod audit {
    use std::cell::RefCell;

    thread_local! {
        static DROPS: RefCell<Option<Vec<(usize, usize, bool)>>> = const { RefCell::new(None) };
    }

    pub(super) fn observe(bytes: &[u8]) {
        DROPS.with(|drops| {
            if let Some(drops) = drops.borrow_mut().as_mut() {
                drops.push((
                    bytes.as_ptr() as usize,
                    bytes.len(),
                    bytes.iter().all(|byte| *byte == 0),
                ));
            }
        });
    }

    pub(crate) fn take() -> Vec<(usize, usize, bool)> {
        DROPS.with(|drops| drops.borrow_mut().replace(Vec::new()).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_zeroizes_content_before_the_allocation_is_released() {
        audit::take();
        let value = SensitiveBytes::new(vec![0x5a; 32]);
        let pointer = value.as_ptr() as usize;
        assert_eq!(value.as_bytes(), &[0x5a; 32]);
        drop(value);
        assert_eq!(audit::take(), vec![(pointer, 32, true)]);
    }

    #[test]
    fn from_zeroizing_is_zeroized_too() {
        audit::take();
        let value = SensitiveBytes::from_zeroizing(Zeroizing::new(vec![0x11; 16]));
        let pointer = value.as_ptr() as usize;
        assert_eq!(value.len(), 16);
        drop(value);
        assert_eq!(audit::take(), vec![(pointer, 16, true)]);
    }

    #[test]
    fn from_vec_adopts_the_allocation_and_clears_it_on_drop() {
        audit::take();
        let input = vec![0x22; 24];
        let allocation = input.as_ptr();
        let value = SensitiveBytes::new(input);
        assert_eq!(value.len(), 24);
        assert_eq!(value.as_ptr(), allocation);
        drop(value);
        assert_eq!(audit::take(), vec![(allocation as usize, 24, true)]);
    }

    #[test]
    fn empty_and_partially_zero_buffers_are_handled() {
        audit::take();
        drop(SensitiveBytes::default());
        let mixed = SensitiveBytes::new(vec![0, 0, 1, 0]);
        let pointer = mixed.as_ptr() as usize;
        assert_eq!(mixed.as_bytes(), &[0, 0, 1, 0]);
        drop(mixed);
        let observations = audit::take();
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|(_, _, cleared)| *cleared));
        assert!(observations.contains(&(pointer, 4, true)));
    }
}
