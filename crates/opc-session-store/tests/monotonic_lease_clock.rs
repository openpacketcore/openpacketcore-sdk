use bytes::Bytes;
use opc_session_store::{
    Clock, FakeSessionBackend, MonotonicClock, OwnerId, SessionKey, SessionKeyType,
    SessionLeaseManager,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct SteppingWallClock {
    now: Mutex<Timestamp>,
}

impl SteppingWallClock {
    fn new(now: Timestamp) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    fn step_backward(&self, duration: Duration) {
        let mut guard = self.now.lock().expect("clock lock");
        let stepped =
            *guard.as_offset_datetime() - time::Duration::seconds_f64(duration.as_secs_f64());
        *guard = Timestamp::from_offset_datetime(stepped);
    }
}

impl Clock for SteppingWallClock {
    fn now_utc(&self) -> Timestamp {
        *self.now.lock().expect("clock lock")
    }
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(b"monotonic-lease"),
    }
}

#[tokio::test]
async fn monotonic_clock_allows_takeover_after_ttl_despite_backward_wall_step() {
    let wall_clock = Arc::new(SteppingWallClock::new(Timestamp::now_utc()));
    let lease_clock = Arc::new(MonotonicClock::anchored_at(wall_clock.now_utc()));
    let backend = FakeSessionBackend::new().with_clock(lease_clock);
    let key = test_key();

    let first = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_millis(20),
        )
        .await
        .expect("first owner acquires lease");

    wall_clock.step_backward(Duration::from_secs(30));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let second = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").expect("owner"),
            Duration::from_secs(1),
        )
        .await
        .expect("successor acquires after monotonic ttl elapsed");

    assert!(second.fence() > first.fence());
}
