use bytes::Bytes;
use opc_session_store::{
    summarize_restore_records, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload,
    FakeSessionBackend, FenceToken, Generation, OwnerId, RestoreBlockReason,
    RestoreBlockReasonCode, RestoreRecordSummary, RestoreScanCursor, RestoreScanRequest,
    RestoreScanScope, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, StateClass,
    StateType, StoreError, StoredSessionRecord, RESTORE_SCAN_MAX_PAGE_SIZE,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::time::Duration;

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
    let owner = OwnerId::new(owner).unwrap();
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("lease");
    let result = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: lease.fence(),
                state_class,
                state_type: StateType::from_static(state_type),
                expires_at,
                payload: EncryptedSessionPayload::new(Bytes::from_static(payload)),
            },
        })
        .await
        .expect("cas");
    assert_eq!(result, CompareAndSetResult::Success);
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
