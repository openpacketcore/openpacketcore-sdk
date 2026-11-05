//! Wiping ownership retained by Bytes through the N2 payload handoff.

use bytes::Bytes;
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(super) struct ReceivePayload(Zeroizing<Vec<u8>>);

impl ReceivePayload {
    pub(super) fn copy_from_slice(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn extend_from_slice(&mut self, bytes: &[u8], limit: usize) {
        let length = self.0.len() + bytes.len();
        if length > self.0.capacity() {
            // Vec growth would free the old allocation without wiping it.
            // Allocate first, copy, then drop the old owner while still live.
            let capacity = length.max(self.0.capacity().saturating_mul(2).min(limit));
            let mut next = Self(Zeroizing::new(Vec::with_capacity(capacity)));
            next.0.extend_from_slice(&self.0);
            std::mem::swap(self, &mut next);
        }
        self.0.extend_from_slice(bytes);
    }

    pub(super) fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

impl AsRef<[u8]> for ReceivePayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ReceivePayload {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        audit::observe(&self.0);
    }
}

#[cfg(test)]
pub(super) mod audit {
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
