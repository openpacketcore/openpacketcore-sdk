use bytes::Bytes;
use opc_session_store::{
    EncryptedSessionPayload, FakeSessionBackend, Generation, OwnerId, ReplicationEntry,
    ReplicationOp, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::time::Duration;

#[derive(Clone, Copy)]
enum Mismatch {
    CredentialId,
    GuardExpiresAt,
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn test_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("smf-pdu-context"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"payload"),
    }
}

fn timestamp_after(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_offset_datetime(
        *timestamp.as_offset_datetime() + time::Duration::seconds(seconds),
    )
}

async fn assert_replicated_cas_rejects_mismatch<B>(backend: B, mismatch: Mismatch)
where
    B: SessionBackend + SessionLeaseManager,
{
    let key = test_key(match mismatch {
        Mismatch::CredentialId => b"bad-credential",
        Mismatch::GuardExpiresAt => b"bad-guard-expiry",
    });
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("acquire lease");
    let sequence = backend
        .max_replication_sequence()
        .await
        .expect("replication sequence")
        + 1;
    let credential_id = match mismatch {
        Mismatch::CredentialId => 2,
        Mismatch::GuardExpiresAt => 1,
    };
    let guard_expires_at = match mismatch {
        Mismatch::CredentialId => lease.expires_at(),
        Mismatch::GuardExpiresAt => timestamp_after(lease.expires_at(), 1),
    };

    let err = backend
        .replicate_entry(ReplicationEntry {
            sequence,
            tx_id: format!("replicated-cas-{sequence}"),
            op: ReplicationOp::CompareAndSet {
                key: key.clone(),
                expected_generation: None,
                credential_id,
                guard_expires_at,
                new_record: test_record(key.clone(), 1, &lease),
            },
            timestamp: Timestamp::now_utc(),
        })
        .await
        .expect_err("replicated CAS must reject mismatched lease binding");
    assert_eq!(err, StoreError::StaleFence);
    assert_eq!(backend.get(&key).await.expect("get after reject"), None);
}

#[tokio::test]
async fn fake_replicated_cas_rejects_mismatched_lease_binding() {
    for mismatch in [Mismatch::CredentialId, Mismatch::GuardExpiresAt] {
        assert_replicated_cas_rejects_mismatch(FakeSessionBackend::new(), mismatch).await;
    }
}

#[tokio::test]
async fn sqlite_replicated_cas_rejects_mismatched_lease_binding() {
    for mismatch in [Mismatch::CredentialId, Mismatch::GuardExpiresAt] {
        assert_replicated_cas_rejects_mismatch(
            SqliteSessionBackend::in_memory().expect("sqlite backend"),
            mismatch,
        )
        .await;
    }
}
