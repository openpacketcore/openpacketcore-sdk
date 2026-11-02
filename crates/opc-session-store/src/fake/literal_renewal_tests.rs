use super::*;

#[tokio::test]
async fn rejected_expired_renewal_stays_rejected_after_rewind() {
    #[derive(Debug)]
    struct ReviewClock(std::sync::Mutex<Timestamp>);
    impl Clock for ReviewClock {
        fn now_utc(&self) -> Timestamp {
            *self.0.lock().unwrap()
        }
    }
    let start = Timestamp::now_utc();
    let clock = Arc::new(ReviewClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key("review-expired-renew", b"already-rejected-credential");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("review-owner").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    let rejected = backend.renew(&lease, Duration::from_secs(60)).await;
    assert!(
        matches!(rejected, Err(LeaseError::Expired)),
        "first renewal must observe expiry: {rejected:?}"
    );
    *clock.0.lock().unwrap() = start;
    let retried = backend.renew(&lease, Duration::from_secs(60)).await;
    eprintln!("initial={rejected:?}, after_rewind={retried:?}");
    assert!(retried.is_err(), "a credential already rejected as expired must not regain renewal authority after a clock rewind");
}
