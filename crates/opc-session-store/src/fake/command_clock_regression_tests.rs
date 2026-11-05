use super::*;

#[derive(Debug)]
struct FailedRenewClock(std::sync::Mutex<Timestamp>);

impl Clock for FailedRenewClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[tokio::test]
async fn expired_renewal_cannot_regain_authority_after_clock_rewind() {
    let start = TokioVirtualClock::new().now_utc();
    let clock = Arc::new(FailedRenewClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key("lease-rewind", b"failed-renewal");
    let lease = backend
        .acquire(&key, OwnerId::new("owner").unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    let before = backend.get_replication_log(1, 16).await.unwrap();
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    assert_eq!(
        backend.renew(&lease, Duration::from_secs(60)).await,
        Err(LeaseError::Expired)
    );
    assert_eq!(backend.get_replication_log(1, 16).await.unwrap(), before);
    *clock.0.lock().unwrap() = start;
    assert!(
        matches!(
            backend.clone().renew(&lease, Duration::from_secs(60)).await,
            Err(LeaseError::Expired | LeaseError::StaleFence)
        ),
        "an expired credential cannot regain renewal authority"
    );
    assert_eq!(backend.get_replication_log(1, 16).await.unwrap(), before);
}
