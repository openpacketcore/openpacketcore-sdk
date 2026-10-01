//! Test-only observation of the actual sealed-reader ciphertext object.
//! SQLite pages, metadata, returned records and other copies are outside scope.

use std::borrow::Cow;
use std::cell::Cell;

#[derive(Clone, Copy, Default)]
pub(super) struct Sample {
    pub calls: usize,
    pub peak_owned_ciphertext: usize,
}

thread_local! {
    static CURRENT: Cell<Option<Sample>> = const { Cell::new(None) };
}

pub(super) trait CiphertextBuffer {
    fn owned_capacity(&self) -> usize;
}

impl CiphertextBuffer for Vec<u8> {
    fn owned_capacity(&self) -> usize {
        self.capacity()
    }
}

impl CiphertextBuffer for Cow<'_, [u8]> {
    fn owned_capacity(&self) -> usize {
        match self {
            Cow::Borrowed(_) => 0,
            Cow::Owned(bytes) => bytes.capacity(),
        }
    }
}

pub(super) fn observe(ciphertext: &impl CiphertextBuffer) {
    let capacity = ciphertext.owned_capacity();
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.calls += 1;
            sample.peak_owned_ciphertext = sample.peak_owned_ciphertext.max(capacity);
            current.set(Some(sample));
        }
    });
}

pub(super) struct Observation;

impl Observation {
    pub fn start() -> Self {
        CURRENT.with(|current| {
            assert!(current.replace(Some(Sample::default())).is_none());
        });
        Self
    }

    pub fn finish(self) -> Sample {
        CURRENT.with(|current| current.take().expect("active sealed-reader observation"))
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        CURRENT.with(|current| current.set(None));
    }
}
