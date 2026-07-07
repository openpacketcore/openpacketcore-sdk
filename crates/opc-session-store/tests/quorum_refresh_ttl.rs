use bytes::Bytes;
use opc_session_store::{
    Clock, CompareAndSet, EncryptedSessionPayload, FakeSessionBackend, FencedSessionReplica,
    Generation, OwnerId, QuorumSessionStore, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, StateClass, StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct FixedClock {
    now: Timestamp,
}

impl FixedClock {
    fn new(now: Timestamp) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now_utc(&self) -> Timestamp {
        self.now
    }
}

fn timestamp_after(base: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_offset_datetime(*base.as_offset_datetime() + time::Duration::seconds(seconds))
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id),
    }
}

fn test_record(key: SessionKey, generation: u64, owner: OwnerId) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner,
        fence: opc_session_store::FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"session-payload"),
    }
}

#[tokio::test]
async fn refresh_ttl_replicates_one_deadline_across_skewed_replicas() {
    let base = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_893_456_000).expect("valid timestamp"),
    );
    let coordinator_clock = Arc::new(FixedClock::new(base));

    let replicas = (0..3)
        .map(|idx| {
            let replica_clock = Arc::new(FixedClock::new(timestamp_after(base, idx)));
            let backend = Arc::new(FakeSessionBackend::new().with_clock(replica_clock));
            FencedSessionReplica::new(idx as usize, backend)
        })
        .collect();
    let quorum = QuorumSessionStore::new(replicas).with_clock(coordinator_clock);

    let key = test_key(b"quorum-refresh-ttl");
    let owner = OwnerId::new("owner-a").expect("owner");
    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(300))
        .await
        .expect("acquire quorum lease");

    let mut record = test_record(key.clone(), 1, owner);
    record.fence = lease.fence();
    record.expires_at = Some(lease.expires_at());
    let cas = CompareAndSet {
        key: key.clone(),
        expected_generation: None,
        lease,
        new_record: record,
    };
    assert!(matches!(
        quorum
            .compare_and_set(cas)
            .await
            .expect("replicate initial record"),
        opc_session_store::CompareAndSetResult::Success
    ));

    let lease = quorum
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(300),
        )
        .await
        .expect("reacquire lease");
    quorum
        .refresh_ttl(&lease, Duration::from_secs(60))
        .await
        .expect("refresh ttl");

    let refreshed = quorum.get(&key).await.expect("quorum read after refresh");
    assert_eq!(
        refreshed.and_then(|record| record.expires_at),
        Some(timestamp_after(base, 60))
    );
}
