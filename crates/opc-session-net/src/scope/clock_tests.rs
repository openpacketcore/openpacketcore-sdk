use super::clock::*;
use opc_types::Timestamp;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

struct Source(Mutex<Result<RealtimeReading, AuthenticationTimeError>>);
impl AuthenticationTimeSource for Source {
    fn read(&self) -> Result<RealtimeReading, AuthenticationTimeError> {
        *self.0.lock().unwrap()
    }
}
fn setup() -> (Arc<Source>, IntervalClock, Timestamp) {
    let now = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
    );
    let source = Arc::new(Source(Mutex::new(Ok(RealtimeReading {
        now,
        uncertainty: Duration::from_millis(100),
        synchronization_generation: 1,
    }))));
    let clock = IntervalClock::new(source.clone(), Duration::from_millis(200)).unwrap();
    (source, clock, now)
}

#[tokio::test(start_paused = true)]
async fn clock_interval_covers_the_declared_uncertainty_without_widening_it() {
    let (source, clock, now) = setup();
    let bounds = clock.interval().unwrap();
    assert!(bounds.is_within(now.add_seconds(-1).unwrap(), now.add_seconds(1).unwrap()));
    assert!(!bounds.is_within(now, now.add_seconds(1).unwrap()));
    tokio::time::advance(Duration::from_secs(1)).await;
    source.0.lock().unwrap().as_mut().unwrap().now = now.add_seconds(1).unwrap();
    assert!(clock.interval().is_ok());
    source.0.lock().unwrap().as_mut().unwrap().uncertainty = Duration::from_millis(201);
    assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
}

#[tokio::test(start_paused = true)]
async fn clock_unavailable_regression_and_detected_skew_only_refuse_authentication() {
    let (source, clock, now) = setup();
    clock.interval().unwrap();
    *source.0.lock().unwrap() = Err(AuthenticationTimeError);
    assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
    *source.0.lock().unwrap() = Ok(RealtimeReading {
        now: now.add_seconds(-1).unwrap(),
        uncertainty: Duration::from_millis(100),
        synchronization_generation: 1,
    });
    assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
    source.0.lock().unwrap().as_mut().unwrap().now = now.add_seconds(10).unwrap();
    assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
    // Only a trusted, new synchronization generation establishes a new baseline.
    source
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .synchronization_generation = 2;
    assert!(clock.interval().is_ok());
    source
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .synchronization_generation = 1;
    assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
}

#[tokio::test(start_paused = true)]
async fn clock_recovers_from_a_step_without_a_new_synchronization_generation() {
    for offset in [-10, 10] {
        let (source, clock, now) = setup();
        clock.interval().unwrap();
        source.0.lock().unwrap().as_mut().unwrap().now = now.add_seconds(offset).unwrap();
        assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
        // Repeated calls cannot turn a stepped clock into a trustworthy interval.
        for _ in 0..10 {
            assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
        }
        for elapsed in 1..=3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            source.0.lock().unwrap().as_mut().unwrap().now =
                now.add_seconds(offset + elapsed).unwrap();
            let result = clock.interval();
            if elapsed < 3 {
                assert_eq!(result.unwrap_err(), AuthenticationTimeError);
            } else {
                assert!(
                    result.is_ok(),
                    "consistent readings recover without a generation change"
                );
            }
        }
    }
}
