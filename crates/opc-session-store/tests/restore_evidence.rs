use bytes::Bytes;
mod support;

use opc_session_store::{
    summarize_restore_records, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, OwnerId,
    QuorumSessionStore, RestoreBlockReason, RestoreBlockReasonCode, RestoreRecordSummary,
    RestoreScanCursor, RestoreScanPage, RestoreScanRequest, RestoreScanScope, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionStoreBackend, SqliteSessionBackend,
    StateClass, StateType, StoreError, StoredSessionRecord, RESTORE_SCAN_MAX_PAGE_SIZE,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::{sync::Arc, time::Duration};

fn record(
    owner: &str,
    stable_id: &'static [u8],
    state_class: StateClass,
    generation: u64,
    fence: u64,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: SessionKey {
            tenant: TenantId::from_static("tenant-a"),
            nf_kind: NetworkFunctionKind::upf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(stable_id),
        },
        generation: Generation::new(generation),
        owner: OwnerId::new(owner).unwrap(),
        fence: FenceToken::new(fence),
        state_class,
        state_type: StateType::from_static("pdu-session"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([1, 2, 3]),
    }
}

fn key(tenant: &'static str, nf_kind: &'static str, stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static(tenant),
        nf_kind: NetworkFunctionKind::from_static(nf_kind),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(stable_id),
    }
}

async fn write_record<B>(
    backend: &B,
    key: SessionKey,
    owner: &'static str,
    state_class: StateClass,
    state_type: &'static str,
    payload: &'static [u8],
    expires_at: Option<Timestamp>,
) where
    B: SessionBackend + SessionLeaseManager,
{
    write_record_fields(
        backend,
        WriteRecordFields {
            key,
            owner,
            state_class,
            state_type,
            payload,
            expires_at,
            generation: 1,
        },
    )
    .await;
}

async fn write_record_generation<B>(
    backend: &B,
    key: SessionKey,
    owner: &'static str,
    state_class: StateClass,
    state_type: &'static str,
    payload: &'static [u8],
    generation: u64,
) where
    B: SessionBackend + SessionLeaseManager,
{
    write_record_fields(
        backend,
        WriteRecordFields {
            key,
            owner,
            state_class,
            state_type,
            payload,
            expires_at: None,
            generation,
        },
    )
    .await;
}

struct WriteRecordFields {
    key: SessionKey,
    owner: &'static str,
    state_class: StateClass,
    state_type: &'static str,
    payload: &'static [u8],
    expires_at: Option<Timestamp>,
    generation: u64,
}

async fn write_record_fields<B>(backend: &B, fields: WriteRecordFields)
where
    B: SessionBackend + SessionLeaseManager,
{
    let owner = OwnerId::new(fields.owner).unwrap();
    let lease = backend
        .acquire(&fields.key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("lease");
    let result = backend
        .compare_and_set(CompareAndSet {
            key: fields.key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                key: fields.key,
                generation: Generation::new(fields.generation),
                owner,
                fence: lease.fence(),
                state_class: fields.state_class,
                state_type: StateType::from_static(fields.state_type),
                expires_at: fields.expires_at,
                payload: EncryptedSessionPayload::new(Bytes::from_static(fields.payload)),
            },
        })
        .await
        .expect("cas");
    assert_eq!(result, CompareAndSetResult::Success);
}

fn sqlite_quorum(size: usize) -> (QuorumSessionStore, Vec<Arc<SqliteSessionBackend>>) {
    let backends = (0..size)
        .map(|_| Arc::new(SqliteSessionBackend::in_memory().expect("sqlite replica")))
        .collect::<Vec<_>>();
    let replicas = backends
        .iter()
        .enumerate()
        .map(|(idx, backend)| {
            let backend: Arc<dyn SessionStoreBackend> = backend.clone();
            support::member(idx, backend)
        })
        .collect();

    (support::validated_ha(replicas), backends)
}

#[test]
fn restore_record_summary_counts_headers_without_payload_identity() {
    let raw_id = b"imsi-001010000000001";
    let records = vec![
        record("owner-b", raw_id, StateClass::AuthoritativeSession, 3, 30),
        record("owner-a", b"teid-100", StateClass::DataplaneLookup, 9, 50),
        record("owner-a", b"pdu-2", StateClass::AuthoritativeSession, 5, 40),
    ];

    let summary = summarize_restore_records(&records, 2);

    assert_eq!(summary.loaded_count, 3);
    assert_eq!(summary.authoritative_count, 2);
    assert_eq!(summary.excluded_count, 2);
    assert_eq!(summary.highest_generation, Some(9));
    assert_eq!(summary.highest_fence, Some(50));
    assert_eq!(summary.owner_fence_metadata.len(), 2);
    assert_eq!(summary.owner_fence_metadata[0].owner, "owner-a");
    assert_eq!(summary.owner_fence_metadata[0].record_count, 2);
    assert_eq!(summary.owner_fence_metadata[0].authoritative_count, 1);
    assert_eq!(summary.owner_fence_metadata[0].highest_fence, 50);

    let rendered = format!("{summary:?}");
    assert!(!rendered.contains("imsi-001010000000001"));
    assert!(summary
        .headers
        .iter()
        .all(|header| header.key_digest.len() == 64));
}

#[test]
fn restore_record_summary_handles_empty_load() {
    let summary = RestoreRecordSummary::from_records(&[], 4);

    assert_eq!(summary.loaded_count, 0);
    assert_eq!(summary.authoritative_count, 0);
    assert_eq!(summary.excluded_count, 4);
    assert_eq!(summary.highest_generation, None);
    assert_eq!(summary.highest_fence, None);
    assert!(summary.owner_fence_metadata.is_empty());
}

#[test]
fn restore_block_reasons_are_redaction_safe_and_traffic_blocking() {
    let reason = RestoreBlockReason::stale_owner_rejected(
        "stale owner from 192.0.2.10 tried /var/lib/opc/session.db",
    );

    assert_eq!(reason.code, RestoreBlockReasonCode::StaleOwnerRejected);
    assert!(reason.blocks_traffic());
    assert!(reason.message.contains("[REDACTED_IPV4]"));
    assert!(reason.message.contains("[REDACTED_DB_FILE]"));
    assert!(!reason.message.contains("192.0.2.10"));
    assert!(!reason.message.contains("/var/lib/opc/session.db"));
}

#[tokio::test]
async fn restore_scan_filters_pages_and_summarizes_fake_backend() {
    let backend = FakeSessionBackend::new();
    write_record(
        &backend,
        key("tenant-a", "upf", b"session-b"),
        "owner-b",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-b",
        None,
    )
    .await;
    write_record(
        &backend,
        key("tenant-a", "upf", b"session-a"),
        "owner-a",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-a",
        None,
    )
    .await;
    write_record(
        &backend,
        key("tenant-b", "upf", b"session-c"),
        "owner-c",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-c",
        None,
    )
    .await;
    write_record(
        &backend,
        key("tenant-a", "smf", b"session-d"),
        "owner-d",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-d",
        None,
    )
    .await;
    write_record(
        &backend,
        key("tenant-a", "upf", b"expired-session"),
        "owner-expired",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"expired",
        Some(Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH,
        )),
    )
    .await;

    let request = RestoreScanRequest {
        scope: RestoreScanScope {
            tenant: Some(TenantId::from_static("tenant-a")),
            nf_kind: Some(NetworkFunctionKind::from_static("upf")),
            state_class: Some(StateClass::AuthoritativeSession),
            ..RestoreScanScope::all()
        },
        cursor: None,
        limit: 1,
    };
    let first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("first page");

    assert_eq!(first.loaded_count, 1);
    assert_eq!(first.excluded_count, 2);
    assert!(!first.complete);
    assert_eq!(first.next_cursor, Some(RestoreScanCursor::from_offset(1)));
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"session-a");
    assert_eq!(first.record_summary().loaded_count, 1);

    let second = backend
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("second page");

    assert_eq!(second.loaded_count, 1);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"session-b");
    assert!(second.complete);
    assert_eq!(second.next_cursor, None);

    let rendered = format!("{second:?}");
    assert!(!rendered.contains("payload-b"));
}

#[tokio::test]
async fn restore_scan_rejects_bad_page_sizes() {
    let backend = FakeSessionBackend::new();

    let zero = backend
        .scan_restore_records(RestoreScanRequest::all(0))
        .await
        .unwrap_err();
    assert!(matches!(zero, StoreError::InvalidRestoreScanRequest(_)));

    let oversized = backend
        .scan_restore_records(RestoreScanRequest::all(RESTORE_SCAN_MAX_PAGE_SIZE + 1))
        .await
        .unwrap_err();
    assert!(matches!(
        oversized,
        StoreError::RestoreScanPageTooLarge { requested, max }
            if requested == RESTORE_SCAN_MAX_PAGE_SIZE + 1 && max == RESTORE_SCAN_MAX_PAGE_SIZE
    ));
}

#[test]
fn restore_scan_page_validation_rejects_untrusted_contract_violations() {
    let request = RestoreScanRequest::all(2);
    let first = record("owner-a", b"a", StateClass::AuthoritativeSession, 1, 1);
    let second = record("owner-a", b"b", StateClass::AuthoritativeSession, 1, 1);
    RestoreScanPage::new(vec![first.clone(), second.clone()], 0, None)
        .validate_for_request(&request)
        .expect("valid deterministic page");

    let assert_invalid = |page: RestoreScanPage| {
        assert!(matches!(
            page.validate_for_request(&request),
            Err(StoreError::InvalidRestoreScanResponse(_))
        ));
    };

    let mut wrong_count = RestoreScanPage::new(vec![first.clone()], 0, None);
    wrong_count.loaded_count = 2;
    assert_invalid(wrong_count);

    assert_invalid(RestoreScanPage::new(
        vec![first.clone(), first.clone()],
        0,
        None,
    ));
    assert_invalid(RestoreScanPage::new(vec![second, first.clone()], 0, None));

    let mut nonadvancing = RestoreScanPage::new(
        vec![first.clone()],
        0,
        Some(RestoreScanCursor::from_offset(2)),
    );
    nonadvancing.complete = false;
    assert_invalid(nonadvancing);

    let invalid_owner: OwnerId = serde_json::from_str("\"\"").expect("deserialize owner");
    let mut invalid_record = first.clone();
    invalid_record.owner = invalid_owner;
    assert_invalid(RestoreScanPage::new(vec![invalid_record], 0, None));

    let mut invalid_key_type = first;
    invalid_key_type.key.key_type = SessionKeyType::Other("x".repeat(129));
    assert_invalid(RestoreScanPage::new(vec![invalid_key_type], 0, None));
}

#[tokio::test]
async fn restore_scan_capability_is_enforced_and_quorum_aggregated() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.restore_scan = false;
    let backend = FakeSessionBackend::with_capabilities(caps);

    let err = backend
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("restore_scan".into())
    );

    let quorum = support::validated_ha(vec![
        support::member(0, Arc::new(FakeSessionBackend::new())),
        support::member(1, Arc::new(FakeSessionBackend::with_capabilities(caps))),
        support::member(2, Arc::new(FakeSessionBackend::new())),
    ]);

    assert!(!quorum.capabilities().await.restore_scan);
}

#[tokio::test]
async fn restore_scan_sqlite_matches_live_scope_semantics() {
    let backend = opc_session_store::SqliteSessionBackend::in_memory().expect("sqlite");
    write_record(
        &backend,
        key("tenant-a", "upf", b"sqlite-a"),
        "owner-a",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-a",
        None,
    )
    .await;
    write_record(
        &backend,
        key("tenant-a", "upf", b"sqlite-b"),
        "owner-b",
        StateClass::DataplaneLookup,
        "teid-map",
        b"payload-b",
        None,
    )
    .await;

    let page = backend
        .scan_restore_records(RestoreScanRequest {
            scope: RestoreScanScope {
                state_class: Some(StateClass::DataplaneLookup),
                ..RestoreScanScope::all()
            },
            cursor: None,
            limit: 16,
        })
        .await
        .expect("scan");

    assert_eq!(page.loaded_count, 1);
    assert_eq!(page.excluded_count, 1);
    assert_eq!(
        page.records[0].state_type,
        StateType::from_static("teid-map")
    );
    assert!(page.complete);
}

#[tokio::test]
async fn restore_scan_quorum_sqlite_merges_filters_pages_and_deduplicates_generations() {
    let (quorum, replicas) = sqlite_quorum(3);
    let scope = RestoreScanScope {
        tenant: Some(TenantId::from_static("tenant-a")),
        nf_kind: Some(NetworkFunctionKind::from_static("upf")),
        state_class: Some(StateClass::DataplaneLookup),
        ..RestoreScanScope::all()
    };

    for replica in &replicas {
        write_record(
            replica.as_ref(),
            key("tenant-a", "upf", b"scan-a"),
            "owner-a",
            StateClass::DataplaneLookup,
            "teid-map",
            b"payload-a",
            None,
        )
        .await;
    }
    write_record_generation(
        replicas[0].as_ref(),
        key("tenant-a", "upf", b"scan-b"),
        "owner-old",
        StateClass::DataplaneLookup,
        "teid-map",
        b"payload-old",
        1,
    )
    .await;
    write_record_generation(
        replicas[1].as_ref(),
        key("tenant-a", "upf", b"scan-b"),
        "owner-new",
        StateClass::DataplaneLookup,
        "teid-map",
        b"payload-new",
        3,
    )
    .await;
    write_record(
        replicas[2].as_ref(),
        key("tenant-a", "upf", b"scan-c"),
        "owner-c",
        StateClass::DataplaneLookup,
        "teid-map",
        b"payload-c",
        None,
    )
    .await;
    write_record(
        replicas[0].as_ref(),
        key("tenant-b", "upf", b"excluded-tenant"),
        "owner-excluded",
        StateClass::DataplaneLookup,
        "teid-map",
        b"payload-excluded",
        None,
    )
    .await;
    write_record(
        replicas[1].as_ref(),
        key("tenant-a", "upf", b"excluded-class"),
        "owner-excluded",
        StateClass::AuthoritativeSession,
        "pdu-session",
        b"payload-excluded",
        None,
    )
    .await;

    let request = RestoreScanRequest {
        scope,
        cursor: None,
        limit: 2,
    };
    let first = quorum
        .scan_restore_records(request.clone())
        .await
        .expect("first quorum restore-scan page");

    assert_eq!(first.loaded_count, 2);
    assert_eq!(first.excluded_count, 2);
    assert!(!first.complete);
    assert_eq!(first.next_cursor, Some(RestoreScanCursor::from_offset(2)));
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"scan-a");
    assert_eq!(first.records[1].key.stable_id.as_ref(), b"scan-b");
    assert_eq!(first.records[1].generation, Generation::new(3));
    assert_eq!(first.records[1].owner, OwnerId::new("owner-new").unwrap());

    let second = quorum
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("second quorum restore-scan page");

    assert_eq!(second.loaded_count, 1);
    assert_eq!(second.excluded_count, 2);
    assert!(second.complete);
    assert_eq!(second.next_cursor, None);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"scan-c");
}
