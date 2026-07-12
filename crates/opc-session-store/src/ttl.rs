//! Bounded, panic-free session TTL validation and deadline arithmetic.
//!
//! Session TTLs are accepted from direct callers and authenticated peers, so
//! they are input-boundary values rather than trusted clock arithmetic. This
//! module defines one SDK-wide upper bound and converts durations without
//! floating point or panicking timestamp addition.

use std::time::Duration;

use opc_types::Timestamp;

use crate::error::StoreError;

/// Largest lease or record-refresh TTL accepted by the session-store APIs.
///
/// A 365-day bound accommodates long-lived packet-core sessions and planned
/// maintenance or disaster-recovery windows while preventing one malformed or
/// mistaken request from creating an effectively permanent lease. Ownership
/// leases should normally be seconds or minutes, and products may enforce a
/// smaller policy limit. [`Duration::ZERO`] remains valid and produces an
/// immediately expired deadline.
pub const MAX_SESSION_TTL: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Validate a caller-supplied session TTL without inspecting or mutating state.
///
/// The error is deliberately a unit variant: raw durations, timestamps, keys,
/// paths, and backend details are not exposed to logs or authenticated peers.
pub fn validate_session_ttl(ttl: Duration) -> Result<(), StoreError> {
    if ttl > MAX_SESSION_TTL {
        return Err(StoreError::InvalidSessionTtl);
    }
    Ok(())
}

/// Compute `now + ttl` exactly, returning a typed error instead of unwinding.
///
/// Seconds and nanoseconds are converted with checked integer arithmetic.
/// Timestamp overflow is reported with the same redaction-safe validation
/// error as an out-of-range TTL.
pub fn checked_session_deadline(now: Timestamp, ttl: Duration) -> Result<Timestamp, StoreError> {
    validate_session_ttl(ttl)?;
    let seconds = i64::try_from(ttl.as_secs()).map_err(|_| StoreError::InvalidSessionTtl)?;
    let delta = time::Duration::seconds(seconds)
        .checked_add(time::Duration::nanoseconds(i64::from(ttl.subsec_nanos())))
        .ok_or(StoreError::InvalidSessionTtl)?;
    now.as_offset_datetime()
        .checked_add(delta)
        .map(Timestamp::from_offset_datetime)
        .ok_or(StoreError::InvalidSessionTtl)
}

/// Add elapsed monotonic time to a UTC anchor without panicking.
///
/// Built-in clocks cannot return a fallible result through [`crate::Clock`].
/// If an elapsed duration or timestamp is no longer representable, they clamp
/// to the largest supported timestamp. This keeps the clock nondecreasing and
/// causes existing finite deadlines to fail closed as expired.
pub(crate) fn saturating_add_elapsed(
    anchor: time::OffsetDateTime,
    elapsed: Duration,
) -> time::OffsetDateTime {
    let maximum = time::PrimitiveDateTime::MAX.assume_utc();
    let Ok(seconds) = i64::try_from(elapsed.as_secs()) else {
        return maximum;
    };
    let Some(delta) = time::Duration::seconds(seconds).checked_add(time::Duration::nanoseconds(
        i64::from(elapsed.subsec_nanos()),
    )) else {
        return maximum;
    };
    anchor.checked_add(delta).unwrap_or(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn timestamp(seconds: i64, nanoseconds: i128) -> Timestamp {
        let value = time::OffsetDateTime::from_unix_timestamp(seconds)
            .expect("test timestamp")
            .checked_add(time::Duration::nanoseconds_i128(nanoseconds))
            .expect("test nanoseconds");
        Timestamp::from_offset_datetime(value)
    }

    #[test]
    fn ttl_boundaries_are_exact_and_panic_free() {
        let now = timestamp(1_900_000_000, 123);

        assert_eq!(checked_session_deadline(now, Duration::ZERO), Ok(now));

        let fractional =
            checked_session_deadline(now, Duration::new(1, 456)).expect("fractional TTL");
        assert_eq!(
            fractional,
            Timestamp::from_offset_datetime(
                now.as_offset_datetime()
                    .checked_add(time::Duration::new(1, 456))
                    .expect("representable test deadline")
            )
        );

        assert!(checked_session_deadline(now, MAX_SESSION_TTL).is_ok());
        assert_eq!(
            checked_session_deadline(now, MAX_SESSION_TTL + Duration::from_nanos(1)),
            Err(StoreError::InvalidSessionTtl)
        );
        assert_eq!(
            checked_session_deadline(now, Duration::MAX),
            Err(StoreError::InvalidSessionTtl)
        );
    }

    #[test]
    fn timestamp_overflow_is_typed_and_elapsed_clock_math_saturates() {
        let maximum = time::PrimitiveDateTime::MAX.assume_utc();
        let max = Timestamp::from_offset_datetime(maximum);
        assert_eq!(checked_session_deadline(max, Duration::ZERO), Ok(max));
        assert_eq!(
            checked_session_deadline(max, Duration::from_nanos(1)),
            Err(StoreError::InvalidSessionTtl)
        );
        assert_eq!(
            saturating_add_elapsed(maximum, Duration::from_nanos(1)),
            maximum
        );
        assert_eq!(
            saturating_add_elapsed(time::OffsetDateTime::UNIX_EPOCH, Duration::MAX),
            maximum
        );
    }

    proptest! {
        #[test]
        fn arbitrary_std_durations_have_a_total_typed_outcome(
            seconds in any::<u64>(),
            nanoseconds in 0_u32..1_000_000_000,
        ) {
            let now = timestamp(1_900_000_000, 123);
            let ttl = Duration::new(seconds, nanoseconds);
            let result = checked_session_deadline(now, ttl);

            prop_assert_eq!(result.is_ok(), ttl <= MAX_SESSION_TTL);
        }
    }
}
