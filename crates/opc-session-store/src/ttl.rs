//! Bounded, panic-free session TTL validation and deadline arithmetic.
//!
//! Session TTLs are accepted from direct callers and authenticated peers, so
//! they are input-boundary values rather than trusted clock arithmetic. This
//! module defines one SDK-wide upper bound and converts durations without
//! floating point or panicking timestamp addition.

use std::time::Duration;

use opc_types::Timestamp;

use crate::{error::StoreError, model::StateClass, record::StoredSessionRecord};

/// Largest lease or record-refresh TTL accepted by the session-store APIs.
///
/// A 365-day bound accommodates long-lived packet-core sessions and planned
/// maintenance or disaster-recovery windows while preventing one malformed or
/// mistaken request from creating an effectively permanent lease. Ownership
/// leases should normally be seconds or minutes, and products may enforce a
/// smaller policy limit. [`Duration::ZERO`] remains valid and produces an
/// immediately expired deadline.
pub const MAX_SESSION_TTL: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Forward clock-skew allowance for caller-authored absolute record expiry.
///
/// The production coordinator is the sole time authority for a mutation, so
/// the SDK deliberately grants no additional forward allowance. Deployments
/// must keep coordinator clocks synchronized; a deadline authored from a clock
/// ahead of the coordinator is rejected rather than silently extending the
/// one-year retention bound. Replicas validate committed operations against
/// immutable coordinator metadata, never their own wall clocks.
pub const MAX_RECORD_EXPIRY_CLOCK_SKEW: Duration = Duration::ZERO;

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

/// Validate one caller-authored absolute record deadline at its authority time.
///
/// Finite deadlines may be in the past, equal to `reference_timestamp`, or at
/// most [`MAX_SESSION_TTL`] in the future. The exact maximum is accepted and a
/// value one nanosecond later is rejected. Arithmetic saturates at the largest
/// representable timestamp, so boundary input cannot unwind.
///
/// `None` is intentional non-expiring state and remains valid for every class
/// except [`StateClass::EphemeralProcedure`]. That class's existing capability
/// profile requires per-key TTL specifically to garbage-collect abandoned
/// procedures, so admitting an immortal record would contradict the profile.
///
/// Direct adapters pass one captured backend clock value. Openraft passes the
/// leader-authored time embedded in the committed command; compatibility
/// replication passes [`crate::ReplicationEntry::timestamp`].
pub fn validate_record_expiry_at(
    expires_at: Option<Timestamp>,
    state_class: StateClass,
    reference_timestamp: Timestamp,
) -> Result<(), StoreError> {
    validate_record_expiry_profile(expires_at, state_class)?;
    let Some(expires_at) = expires_at else {
        return Ok(());
    };

    let maximum = checked_record_expiry_limit(reference_timestamp);
    if expires_at > maximum {
        return Err(StoreError::InvalidRecordExpiry);
    }
    Ok(())
}

/// Validate the time-independent record-expiry profile.
///
/// Forwarding wrappers and clients may use this before provider or network
/// work without claiming time authority. Finite bounds must be checked only by
/// the mutation coordinator through [`validate_record_expiry_at`].
pub fn validate_record_expiry_profile(
    expires_at: Option<Timestamp>,
    state_class: StateClass,
) -> Result<(), StoreError> {
    if expires_at.is_none() && state_class == StateClass::EphemeralProcedure {
        return Err(StoreError::InvalidRecordExpiry);
    }
    Ok(())
}

/// Validate the absolute expiry carried by a stored record.
pub fn validate_stored_record_expiry_at(
    record: &StoredSessionRecord,
    reference_timestamp: Timestamp,
) -> Result<(), StoreError> {
    validate_record_expiry_at(record.expires_at, record.state_class, reference_timestamp)
}

/// Validate only a record's time-independent expiry profile.
pub fn validate_stored_record_expiry_profile(
    record: &StoredSessionRecord,
) -> Result<(), StoreError> {
    validate_record_expiry_profile(record.expires_at, record.state_class)
}

fn checked_record_expiry_limit(reference_timestamp: Timestamp) -> Timestamp {
    let maximum = time::PrimitiveDateTime::MAX.assume_utc();
    // MAX_SESSION_TTL is an exact whole-second compile-time constant that is
    // many orders of magnitude below i64::MAX.
    let delta = time::Duration::seconds(365 * 24 * 60 * 60);
    Timestamp::from_offset_datetime(
        reference_timestamp
            .as_offset_datetime()
            .checked_add(delta)
            .unwrap_or(maximum),
    )
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

    #[test]
    fn absolute_record_expiry_boundaries_and_profiles_are_exact() {
        let now = timestamp(1_900_000_000, 123);
        let maximum = checked_session_deadline(now, MAX_SESSION_TTL).expect("maximum deadline");
        let maximum_plus_one = Timestamp::from_offset_datetime(
            maximum
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("maximum plus one"),
        );
        let past = Timestamp::from_offset_datetime(
            now.as_offset_datetime()
                .checked_sub(time::Duration::nanoseconds(1))
                .expect("past"),
        );

        for deadline in [past, now, maximum] {
            assert_eq!(
                validate_record_expiry_at(Some(deadline), StateClass::AuthoritativeSession, now,),
                Ok(())
            );
        }
        assert_eq!(
            validate_record_expiry_at(
                Some(maximum_plus_one),
                StateClass::AuthoritativeSession,
                now,
            ),
            Err(StoreError::InvalidRecordExpiry)
        );

        for class in [
            StateClass::AuthoritativeSession,
            StateClass::DataplaneLookup,
            StateClass::ReplicatedDr,
            StateClass::TelemetryDerived,
        ] {
            assert_eq!(validate_record_expiry_at(None, class, now), Ok(()));
        }
        assert_eq!(
            validate_record_expiry_at(None, StateClass::EphemeralProcedure, now),
            Err(StoreError::InvalidRecordExpiry)
        );
    }

    #[test]
    fn absolute_record_expiry_timestamp_extremes_are_total() {
        let minimum = Timestamp::from_offset_datetime(time::PrimitiveDateTime::MIN.assume_utc());
        let maximum = Timestamp::from_offset_datetime(time::PrimitiveDateTime::MAX.assume_utc());

        assert_eq!(
            validate_record_expiry_at(Some(maximum), StateClass::AuthoritativeSession, maximum,),
            Ok(())
        );
        assert_eq!(
            validate_record_expiry_at(Some(maximum), StateClass::AuthoritativeSession, minimum,),
            Err(StoreError::InvalidRecordExpiry)
        );
        assert_eq!(
            validate_record_expiry_at(Some(minimum), StateClass::AuthoritativeSession, minimum,),
            Ok(())
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
