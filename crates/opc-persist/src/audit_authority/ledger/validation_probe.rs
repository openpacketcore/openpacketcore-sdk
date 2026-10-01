//! Scoped counters/fault at the real validation-index allocation and comparisons.

use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Counts {
    pub(super) comparisons: usize,
    pub(super) outcome_entry_visits: usize,
    pub(super) reserves: usize,
    pub(super) intents: usize,
    pub(super) capacity: usize,
    pub(super) heap_bytes: usize,
    pub(super) bitmap_bytes: usize,
    pub(super) live_indexes: usize,
    pub(super) peak_indexes: usize,
}

thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static INJECTED: Cell<bool> = const { Cell::new(false) };
}

pub(super) struct Probe;

impl Probe {
    pub(super) fn start(fail_after: Option<usize>) -> Self {
        COUNTS.with(|slot| assert!(slot.replace(Some(Counts::default())).is_none()));
        FAIL_AFTER.with(|slot| assert!(slot.replace(fail_after).is_none()));
        INJECTED.with(|slot| assert!(!slot.replace(false)));
        Self
    }

    pub(super) fn counts(&self) -> Counts {
        COUNTS.with(|slot| slot.get().expect("active validation probe"))
    }

    pub(super) fn injected(&self) -> bool {
        INJECTED.with(Cell::get)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        COUNTS.with(|slot| {
            assert_eq!(
                slot.take().expect("active validation probe").live_indexes,
                0
            );
        });
        FAIL_AFTER.with(|slot| slot.set(None));
        INJECTED.with(|slot| slot.set(false));
    }
}

pub(super) fn comparison() {
    COUNTS.with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.comparisons = counts.comparisons.checked_add(1).expect("bounded count");
            slot.set(Some(counts));
        }
    });
}

pub(super) fn outcome_entry_visit() {
    COUNTS.with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.outcome_entry_visits = counts
                .outcome_entry_visits
                .checked_add(1)
                .expect("bounded entry visits");
            slot.set(Some(counts));
        }
    });
}

pub(super) fn requested(count: usize) -> usize {
    COUNTS.with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.reserves += 1;
            slot.set(Some(counts));
        }
    });
    FAIL_AFTER.with(|slot| match slot.get() {
        Some(0) => {
            slot.set(None);
            INJECTED.with(|slot| slot.set(true));
            usize::MAX
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            count
        }
        None => count,
    })
}

pub(super) struct IndexOwner(bool);

impl IndexOwner {
    pub(super) fn new(intents: usize, capacity: usize, element: usize, bitmap: usize) -> Self {
        Self(COUNTS.with(|slot| {
            let Some(mut counts) = slot.get() else {
                return false;
            };
            counts.intents = intents;
            counts.capacity = capacity;
            counts.heap_bytes = capacity.checked_mul(element).expect("real vector extent");
            counts.bitmap_bytes = bitmap;
            counts.live_indexes += 1;
            counts.peak_indexes = counts.peak_indexes.max(counts.live_indexes);
            slot.set(Some(counts));
            true
        }))
    }
}

impl Drop for IndexOwner {
    fn drop(&mut self) {
        if self.0 {
            COUNTS.with(|slot| {
                let mut counts = slot.get().expect("observer outlives index");
                counts.live_indexes = counts.live_indexes.checked_sub(1).expect("live owner");
                slot.set(Some(counts));
            });
        }
    }
}
