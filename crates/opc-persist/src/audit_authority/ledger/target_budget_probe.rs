//! Observe traversal at the real target-budget serialization, without an
//! allocator replacement or changing serde's fields, bytes or return value.
//! The operations field follows entries. A full-row temporary necessarily
//! visits it even when earlier retained recovery strings already exceed the
//! byte budget. A bounded writer stops before it on that same input.

use super::LedgerOperation;
use serde::{Serialize, Serializer};
use std::cell::Cell;

#[derive(Clone, Copy, Default)]
pub(crate) struct Sample {
    pub(crate) checks: usize,
    pub(crate) operations_started: usize,
    pub(crate) stopped_before_operations: usize,
}

thread_local! {
    static SAMPLE: Cell<Option<Sample>> = const { Cell::new(None) };
    static CURRENT: Cell<Option<bool>> = const { Cell::new(None) };
}

pub(crate) struct Observation;

impl Observation {
    pub(crate) fn start() -> Self {
        assert!(SAMPLE
            .with(|slot| slot.replace(Some(Sample::default())))
            .is_none());
        assert!(CURRENT.with(Cell::get).is_none());
        Self
    }

    pub(crate) fn sample(&self) -> Sample {
        SAMPLE.with(Cell::get).expect("live budget observation")
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        assert!(CURRENT.with(Cell::get).is_none());
        SAMPLE.with(|slot| slot.set(None));
    }
}

pub(super) struct Serialization(bool);

impl Serialization {
    pub(super) fn enter() -> Self {
        let active = SAMPLE.with(|slot| {
            let Some(mut sample) = slot.get() else {
                return false;
            };
            sample.checks += 1;
            slot.set(Some(sample));
            true
        });
        if active {
            assert!(CURRENT.with(|slot| slot.replace(Some(false))).is_none());
        }
        Self(active)
    }
}

impl Drop for Serialization {
    fn drop(&mut self) {
        if self.0 {
            let visited = CURRENT
                .with(|slot| slot.take())
                .expect("active serialization");
            SAMPLE.with(|slot| {
                let mut sample = slot.get().expect("live budget observation");
                if visited {
                    sample.operations_started += 1;
                } else {
                    sample.stopped_before_operations += 1;
                }
                slot.set(Some(sample));
            });
        }
    }
}

pub(super) fn operations<S: Serializer>(
    value: &[LedgerOperation],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    CURRENT.with(|slot| {
        if slot.get().is_some() {
            slot.set(Some(true));
        }
    });
    value.serialize(serializer)
}
