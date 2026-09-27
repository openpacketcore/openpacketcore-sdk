//! Test-only observations of history-authentication Rust buffers.
//! Fixed-width projections report actual heap capacity (arrays own none).
//! SQLite pages, returned records and other Rust buffers are outside this probe.

use std::borrow::Cow;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::consensus) struct Sample {
    pub calls: [usize; 4],
    pub ciphertext_hash_calls: [usize; 4],
    pub ciphertext_hash_bytes: [usize; 4],
    pub completed_checks: [usize; 5],
    pub peak_owned_ciphertext: usize,
    pub fixed_width_calls: [usize; 9],
    pub peak_owned_fixed_width: [usize; 9],
}

thread_local! {
    static CURRENT: Cell<Option<Sample>> = const { Cell::new(None) };
}

pub(in crate::consensus) trait CiphertextBuffer {
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

pub(in crate::consensus) fn observe(site: usize, ciphertext: &impl CiphertextBuffer) {
    let owned_capacity = ciphertext.owned_capacity();
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.calls[site] += 1;
            sample.peak_owned_ciphertext = sample.peak_owned_ciphertext.max(owned_capacity);
            current.set(Some(sample));
        }
    });
}

pub(in crate::consensus) trait FixedWidthBuffer {
    fn owned_capacity(&self) -> usize;
}

impl FixedWidthBuffer for Vec<u8> {
    fn owned_capacity(&self) -> usize {
        self.capacity()
    }
}

impl<const N: usize> FixedWidthBuffer for [u8; N] {
    fn owned_capacity(&self) -> usize {
        0
    }
}

impl<T: FixedWidthBuffer> FixedWidthBuffer for Option<T> {
    fn owned_capacity(&self) -> usize {
        self.as_ref().map_or(0, FixedWidthBuffer::owned_capacity)
    }
}

// Sites: head UUID; chain UUID/hash; boundary UUID/parent; append hash;
// retention UUID/parent/predecessor. Observe after projection, before use.
pub(in crate::consensus) fn observe_fixed_width(site: usize, value: &impl FixedWidthBuffer) {
    let owned_capacity = value.owned_capacity();
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.fixed_width_calls[site] += 1;
            sample.peak_owned_fixed_width[site] =
                sample.peak_owned_fixed_width[site].max(owned_capacity);
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

// Raw ciphertext hashing is separate from the small chain/HMAC transcripts.
#[derive(Clone, Copy)]
pub(in crate::consensus) enum CiphertextHashSite {
    Head,
    Chain,
    Capacity,
    Boundary,
}

#[derive(Clone, Copy)]
pub(in crate::consensus) enum CompletedCheck {
    CapacityMac,
    AuditAnchor,
    Metadata,
    ChainExtension,
    ChainComparison,
}

// Called after the real SHA operation with the very slice it consumed. This
// observer owns no ciphertext and never estimates work from profile limits.
pub(in crate::consensus) fn ciphertext_hashed(site: CiphertextHashSite, bytes: &[u8]) {
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.ciphertext_hash_calls[site as usize] += 1;
            sample.ciphertext_hash_bytes[site as usize] += bytes.len();
            current.set(Some(sample));
        }
    });
}

// Each caller records a completed real check/contribution, never an expected
// number of records. Negative fixtures separately require authentication errors.
pub(in crate::consensus) fn completed(check: CompletedCheck) {
    CURRENT.with(|current| {
        if let Some(mut sample) = current.get() {
            sample.completed_checks[check as usize] += 1;
            current.set(Some(sample));
        }
    });
}
