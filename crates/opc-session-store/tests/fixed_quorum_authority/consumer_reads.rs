//! Public scoped reads on real three-voter native and retained SQL owners.
//! Raw storage positions make the no-proposal check independent of SDK status.

use super::*;
use futures_util::FutureExt;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend,
    Generation, SessionConsumerAuthorization, SessionConsumerOperation, SessionConsumerRequest,
    SessionConsumerRequestId, SessionConsumerResponse, StateClass, StateType, StoredSessionRecord,
};
use std::panic::AssertUnwindSafe;

fn key(label: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("fixed-consumer"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: label.try_into().expect("bounded fixture key"),
    }
}

async fn get(
    store: &ConsensusSessionStore,
    authorization: &SessionConsumerAuthorization,
    key: &SessionKey,
) -> SessionConsumerResponse {
    store
        .consumer_service()
        .execute(
            authorization,
            SessionConsumerRequest::new(
                store.consumer_scope().expect("exact live consumer scope"),
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Get { key: key.clone() },
            ),
        )
        .await
}

fn witness(store: &ConsensusSessionStore, database: &std::path::Path) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    if let Some(raw) =
        opc_session_store::test_support::consensus_native_activation_facts_for_test(store)
            .expect("independent bounded native observation")
    {
        return serde_json::json!({
            "last_log": raw["last_log"], "committed": raw["durable_committed"],
            "applied": raw["business"]["applied"], "business_digest": raw["business_digest"],
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = store;
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("independent read-only SQL connection");
    connection
        .busy_timeout(Duration::ZERO)
        .expect("no hidden SQL witness wait");
    let tx = connection
        .unchecked_transaction()
        .expect("one SQL witness transaction");
    let mut tables = BTreeMap::new();
    for table in [
        "consensus_log",
        "consensus_committed",
        "consensus_applied",
        "consensus_machine",
        "session_records",
    ] {
        let mut statement = tx
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("raw SQL witness table");
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| {
                        let value = row.get_ref(index)?;
                        Ok(match value {
                            rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                            rusqlite::types::ValueRef::Integer(value) => serde_json::json!(value),
                            rusqlite::types::ValueRef::Real(value) => serde_json::json!(value),
                            rusqlite::types::ValueRef::Text(value)
                            | rusqlite::types::ValueRef::Blob(value) => serde_json::json!(value),
                        })
                    })
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("raw SQL rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("complete raw SQL rows");
        tables.insert(table, rows);
    }
    tx.commit().expect("finish read-only witness");
    // Hash complete bytes rather than exposing encrypted records or opaque keys.
    use sha2::{Digest, Sha256};
    serde_json::json!({"sql_rows_sha256": Sha256::digest(serde_json::to_vec(&tables).expect("canonical raw rows")).to_vec()})
}

async fn non_expiring_read_is_read_only(legacy_sqlite: bool) {
    let (_directory, databases, stores, paths) = open_fixed_authority_fault_cluster(
        PlacementResiliencePolicy::AllowReducedResilience,
        legacy_sqlite,
    )
    .await;
    let result = AssertUnwindSafe(async {
        let provider = Arc::new(MemoryKeyProvider::new());
        provider.insert_active_key(
            KeyId::new("fixed-read-key").expect("key ID"), KeyPurpose::Session,
            TenantId::from_static("fixed-consumer"), Zeroizing::new([0x4b; 32]),
        ).expect("real fixture AEAD key");
        let encrypted = EncryptingSessionBackend::new(Arc::new(stores[0].clone()), provider, "fixed-read");
        let present = key(b"non-expiring");
        let absent = key(b"absent");
        let lease = encrypted.acquire(&present, OwnerId::new("fixed-read-owner").expect("owner"), Duration::from_secs(30))
            .await.expect("real quorum lease");
        let record = StoredSessionRecord {
            key: present.clone(), generation: Generation::new(1), owner: lease.owner().clone(), fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession, state_type: StateType::from_static("fixed-read"),
            expires_at: None, payload: EncryptedSessionPayload::new(b"exact encrypted read witness"),
        };
        assert_eq!(encrypted.compare_and_set(CompareAndSet {
            key: present.clone(), lease, expected_generation: None, new_record: record,
        }).await.expect("real encrypted CAS"), CompareAndSetResult::Success);
        let expected = SessionBackend::get(&stores[0], &present).await.expect("independent generic record read").expect("committed record");
        let mut authorizations = Vec::new();
        for store in &stores {
            let manifest = store.consumer_authorization_manifest([fixed_consumer_grant()]).await.expect("exact roster");
            authorizations.push(manifest.authorize(&fixed_consumer_identity()).expect("scoped authorization"));
            assert!(store.probe_durable_readiness().await.is_ready(), "settle each local applied cut");
        }
        let before = stores.iter().zip(&databases).map(|(store, path)| witness(store, path)).collect::<Vec<_>>();
        for (slot, store) in stores.iter().enumerate() {
            assert!(matches!(get(store, &authorizations[slot], &present).await, SessionConsumerResponse::Get(Ok(Some(record))) if record == expected), "exact public non-expiring record on every ingress");
            assert!(matches!(get(store, &authorizations[slot], &absent).await, SessionConsumerResponse::Get(Ok(None))), "exact public absence on every ingress");
        }
        let after = stores.iter().zip(&databases).map(|(store, path)| witness(store, path)).collect::<Vec<_>>();
        assert_eq!(after, before, "clock-independent public reads must not append, apply, or change durable business state");
    }).catch_unwind().await;
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_sql_non_expiring_and_absent_reads_do_not_propose() {
    non_expiring_read_is_read_only(cfg!(target_os = "linux")).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_native_non_expiring_and_absent_reads_do_not_propose() {
    non_expiring_read_is_read_only(false).await;
}
