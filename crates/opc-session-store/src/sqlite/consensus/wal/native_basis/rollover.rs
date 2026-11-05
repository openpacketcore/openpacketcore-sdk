//! Size-triggered replacement of the selected append file. Preparation owns
//! only immutable roots; CURRENT and retirement remain the sole writer's job.

use super::*;
use crate::consensus::native::generation::{BaseParameters, StreamingBase};
use crate::consensus::native::SnapshotCapture;

const MINIMUM_ROLLOVER_BYTES: u64 = 64 * 1024 * 1024;

mod compactor;
pub(in crate::sqlite::consensus::wal) use compactor::Coordinator;
pub(super) use compactor::{build_pending, Built, Capacity, Cut, Frame, Job, Take};

pub(super) fn maximum(mode: SessionPersistenceMode, block_bytes: usize) -> io::Result<u64> {
    let maximum = crate::consensus::native::prefix::maximum_length(block_bytes)?.min(MAX_BASIS);
    Ok(if mode == SessionPersistenceMode::Async {
        maximum.min(async_persistence::MAX_GENERATION_BYTES)
    } else {
        maximum
    })
}

pub(super) fn limit(
    mode: SessionPersistenceMode,
    block_bytes: usize,
    control: &IoControl,
) -> io::Result<u64> {
    let maximum = maximum(mode, block_bytes)?;
    #[cfg(test)]
    let maximum = control
        .native_rollover_maximum
        .unwrap_or(maximum)
        .min(maximum);
    #[cfg(not(test))]
    let _ = control;
    Ok(maximum)
}

pub(super) fn threshold(
    selected: &Selected,
    mode: SessionPersistenceMode,
    control: &IoControl,
) -> io::Result<u64> {
    let prefix = selected.append.current().identity();
    let maximum = limit(mode, prefix.block_bytes, control)?;
    // Keep ordinary append files within twice their compact base, with a
    // 64 MiB floor to avoid rewriting small stores at every checkpoint.
    // The trigger is capped at half the hard ceiling. The selected cut can
    // cross it by one padded frame before scheduling, so actual build headroom
    // is maximum minus that cut's extent, not a guaranteed half ceiling.
    let threshold = selected
        .base_bytes
        .saturating_mul(2)
        .max(MINIMUM_ROLLOVER_BYTES)
        .min(maximum / 2);
    #[cfg(test)]
    let threshold = control
        .native_rollover_bytes
        .unwrap_or(threshold)
        .min(threshold);
    #[cfg(not(test))]
    let _ = control;
    Ok(threshold)
}

pub(super) fn needed(
    selected: &Selected,
    payload_bytes: u64,
    mode: SessionPersistenceMode,
    control: &IoControl,
) -> io::Result<bool> {
    let prefix = selected.append.current().identity();
    let threshold = threshold(selected, mode, control)?;
    let block = prefix.block_bytes as u64;
    let next = prefix
        .length
        .checked_add(payload_bytes)
        .and_then(|bytes| bytes.checked_add(block - 1))
        .map(|bytes| bytes / block * block);
    let needed = next.is_none_or(|bytes| bytes > threshold);
    Ok(needed)
}
