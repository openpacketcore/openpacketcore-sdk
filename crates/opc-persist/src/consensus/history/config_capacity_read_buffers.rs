//! Test-only observations of the four history-authentication ciphertext copies.
//! SQLite pages, returned records and other Rust buffers are outside this probe.

use std::cell::Cell;

#[derive(Clone, Copy, Default)]
pub(in crate::consensus) struct Sample {
    pub calls: [usize; 4],
    pub peak_owned_ciphertext: usize,
}

thread_local! {
    static CURRENT: Cell<Option<Sample>> = const { Cell::new(None) };
}

pub(in crate::consensus) fn observe(site: usize, owned_capacity: usize) {
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.calls[site] += 1;
            sample.peak_owned_ciphertext = sample.peak_owned_ciphertext.max(owned_capacity);
            current.set(Some(sample));
        }
    });
}

pub(in crate::consensus) struct Observation;

impl Observation {
    pub fn start() -> Self {
        CURRENT.with(|current| {
            assert!(current.replace(Some(Sample::default())).is_none());
        });
        Self
    }

    pub fn finish(self) -> Sample {
        CURRENT.with(|current| current.take().expect("active history buffer observation"))
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        CURRENT.with(|current| current.set(None));
    }
}
