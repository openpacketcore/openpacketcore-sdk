//! Temporary ordering of complete generic receipt IDs by admitted offsets.

use super::{invalid, SessionConsensusRequestId, VerificationMemory};
use std::io;
use std::mem::size_of;

pub(super) struct Order {
    pub(super) ids: Vec<SessionConsensusRequestId>,
    // The vector is destroyed before its reservation is returned.
    pub(super) memory: VerificationMemory,
}

pub(super) fn new(
    ids: impl ExactSizeIterator<Item = SessionConsensusRequestId>,
    offset: impl FnMut(&SessionConsensusRequestId) -> Option<u64>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Order> {
    with_reservation(ids, offset, check, &VerificationMemory::reserve)
}

fn with_reservation(
    ids: impl ExactSizeIterator<Item = SessionConsensusRequestId>,
    mut offset: impl FnMut(&SessionConsensusRequestId) -> Option<u64>,
    check: &impl Fn() -> io::Result<()>,
    reserve: &impl Fn(usize) -> io::Result<VerificationMemory>,
) -> io::Result<Order> {
    let count = ids.len();
    let bytes = count
        .checked_mul(size_of::<SessionConsensusRequestId>())
        .ok_or_else(|| invalid("native generic conversion order overflows"))?;
    let memory = reserve(bytes)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(count)
        .map_err(|_| invalid("native generic conversion order allocation failed"))?;
    // This cache is optional scratch. Charge the actual tuple layout before
    // allocation, including Option/padding, under the same process budget.
    // If either admission or allocation fails, preserve the original path.
    let extra = count.checked_mul(size_of::<(SessionConsensusRequestId, Option<u64>)>());
    if let Some(cache_memory) = extra.and_then(|bytes| reserve(bytes).ok()) {
        let mut cached = Vec::new();
        if cached.try_reserve_exact(count).is_ok() {
            for id in ids {
                check()?;
                cached.push((id, offset(&id)));
            }
            cached.sort_unstable_by_key(|(_, offset)| *offset);
            ordered.extend(cached.iter().map(|(id, _)| *id));
            // Restore the original IDs-only footprint before any subsequent
            // decoder can request its scratch. Release bytes only after the
            // optional allocation is gone, then retain the original check.
            drop(cached);
            drop(cache_memory);
            check()?;
            return Ok(Order {
                ids: ordered,
                memory,
            });
        }
        drop(cached);
        drop(cache_memory);
    }
    for id in ids {
        check()?;
        ordered.push(id);
    }
    ordered.sort_unstable_by_key(offset);
    check()?;
    Ok(Order {
        ids: ordered,
        memory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn id(value: usize) -> SessionConsensusRequestId {
        SessionConsensusRequestId::from_bytes((value as u128).to_be_bytes())
    }

    fn value(id: &SessionConsensusRequestId) -> u64 {
        u64::try_from(u128::from_be_bytes(*id.as_bytes())).unwrap()
    }

    fn values(order: &Order) -> Vec<u64> {
        order.ids.iter().map(value).collect()
    }

    #[test]
    fn generic_source_order_does_not_repeat_offset_lookups_while_sorting() {
        const ROWS: usize = 256;
        let ids = (0..ROWS)
            .map(|index| {
                SessionConsensusRequestId::from_bytes(((index * 137 % ROWS) as u128).to_be_bytes())
            })
            .collect::<Vec<_>>();
        let calls = Cell::new(0);
        let order = new(
            ids.into_iter(),
            |id| {
                calls.set(calls.get() + 1);
                Some(u64::try_from(u128::from_be_bytes(*id.as_bytes())).unwrap())
            },
            &|| Ok(()),
        )
        .unwrap();
        let expected = (0..ROWS)
            .map(|index| SessionConsensusRequestId::from_bytes((index as u128).to_be_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(order.ids, expected);
        assert!(
            calls.get() <= ROWS,
            "sorting {ROWS} complete IDs looked up admitted offsets {} times",
            calls.get()
        );
    }

    #[test]
    fn original_scratch_capacity_preserves_order_when_the_optional_cache_cannot_fit() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let original = 4 * size_of::<SessionConsensusRequestId>();
        let cached = original + 4 * size_of::<(SessionConsensusRequestId, Option<u64>)>();
        for limit in [original, cached] {
            let order = with_reservation(
                [id(2), id(3), id(1), id(4)].into_iter(),
                |id| match value(id) {
                    1 => None,
                    2 => Some(9),
                    3 => Some(2),
                    4 => Some(5),
                    _ => unreachable!(),
                },
                &|| Ok(()),
                &|bytes| VerificationMemory::reserve_for_test(&COUNTER, bytes, limit),
            )
            .unwrap();
            assert_eq!(values(&order), [1, 3, 4, 2]);
            assert_eq!(COUNTER.load(Ordering::Acquire), original);
            drop(order);
            assert_eq!(COUNTER.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn cached_sort_preserves_the_original_memory_headroom_for_decoding() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let original = 4 * size_of::<SessionConsensusRequestId>();
        let limit = original + 4 * size_of::<(SessionConsensusRequestId, Option<u64>)>();
        let order = with_reservation(
            [id(4), id(3), id(2), id(1)].into_iter(),
            |id| Some(value(id)),
            &|| Ok(()),
            &|bytes| VerificationMemory::reserve_for_test(&COUNTER, bytes, limit),
        )
        .unwrap();
        assert_eq!(values(&order), [1, 2, 3, 4]);
        let decoder = VerificationMemory::reserve_for_test(&COUNTER, limit - original, limit);
        assert!(
            decoder.is_ok(),
            "optional sort cache consumed the original decoder headroom: {} bytes remain reserved",
            COUNTER.load(Ordering::Acquire)
        );
        drop(decoder);
        drop(order);
        assert_eq!(COUNTER.load(Ordering::Acquire), 0);
    }

    #[test]
    fn returned_order_owns_only_the_original_ids_allocation() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        const ROWS: usize = 64;
        let original = ROWS * size_of::<SessionConsensusRequestId>();
        let limit = original + ROWS * size_of::<(SessionConsensusRequestId, Option<u64>)>();
        let mut held = None;
        let allocation = allocation_counter::measure(|| {
            held = Some(std::hint::black_box(
                with_reservation(
                    (0..ROWS).rev().map(id),
                    |id| Some(value(id)),
                    &|| Ok(()),
                    &|bytes| VerificationMemory::reserve_for_test(&COUNTER, bytes, limit),
                )
                .unwrap(),
            ));
        });
        assert_eq!(allocation.bytes_current, i64::try_from(original).unwrap());
        assert_eq!(COUNTER.load(Ordering::Acquire), original);
        let order = held.unwrap();
        assert_eq!(values(&order), (0..ROWS as u64).collect::<Vec<_>>());
        drop(order);
        assert_eq!(COUNTER.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancellation_at_every_original_check_releases_all_sort_scratch() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        const ROWS: usize = 8;
        for limit in [
            ROWS * size_of::<SessionConsensusRequestId>(),
            ROWS * (size_of::<SessionConsensusRequestId>()
                + size_of::<(SessionConsensusRequestId, Option<u64>)>()),
        ] {
            for fail_at in 0..=ROWS {
                let calls = Cell::new(0);
                let result = with_reservation(
                    (0..ROWS).rev().map(id),
                    |id| Some(value(id)),
                    &|| {
                        let index = calls.get();
                        calls.set(index + 1);
                        if index == fail_at {
                            Err(io::Error::new(io::ErrorKind::TimedOut, "original deadline"))
                        } else {
                            Ok(())
                        }
                    },
                    &|bytes| VerificationMemory::reserve_for_test(&COUNTER, bytes, limit),
                );
                assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
                assert_eq!(calls.get(), fail_at + 1);
                assert_eq!(COUNTER.load(Ordering::Acquire), 0);
            }
        }
    }

    #[test]
    fn original_admission_failure_and_overflow_do_not_allocate_or_read_offsets() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let reads = Cell::new(0);
        let result = with_reservation(
            [id(1)].into_iter(),
            |_| {
                reads.set(reads.get() + 1);
                Some(1)
            },
            &|| Ok(()),
            &|bytes| VerificationMemory::reserve_for_test(&COUNTER, bytes, 0),
        );
        assert!(result.is_err());
        assert_eq!(reads.get(), 0);
        assert_eq!(COUNTER.load(Ordering::Acquire), 0);
        assert_eq!(
            new((0..usize::MAX).map(id), |_| None, &|| Ok(()))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn empty_order_keeps_the_original_post_sort_deadline_check() {
        let calls = Cell::new(0);
        let order = new(std::iter::empty(), |_| None, &|| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert!(order.ids.is_empty());
        assert_eq!(calls.get(), 1);
    }
}
