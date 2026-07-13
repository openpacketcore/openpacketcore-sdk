use bytes::Bytes;

use opc_session_store::{
    summarize_restore_records, BackendCapabilities, Clock, CompareAndSet, CompareAndSetResult,
    EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, OwnerId,
    RestoreBlockReason, RestoreBlockReasonCode, RestoreRecordSummary, RestoreScanCursor,
    RestoreScanCursorProfile, RestoreScanPage, RestoreScanRequest, RestoreScanScope,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, StateClass, StateType,
    StoreError, StoredSessionRecord, RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
    RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES, RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
    RESTORE_SCAN_MAX_PAGE_SIZE,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now_utc(&self) -> Timestamp {
        self.0
    }
}

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
            stable_id: Bytes::from_static(stable_id)
                .try_into()
                .expect("valid stable ID"),
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
        stable_id: Bytes::from_static(stable_id)
            .try_into()
            .expect("valid stable ID"),
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
            payload: Bytes::from_static(payload),
            expires_at,
            generation: 1,
        },
    )
    .await;
}

struct WriteRecordFields {
    key: SessionKey,
    owner: &'static str,
    state_class: StateClass,
    state_type: &'static str,
    payload: Bytes,
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
                payload: EncryptedSessionPayload::new(fields.payload),
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
    assert_eq!(first.excluded_count, 0);
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
async fn fake_restore_pages_follow_raw_tuple_order_for_prefix_tenants() {
    let backend = FakeSessionBackend::new();
    for tenant in ["a-b", "a"] {
        write_record(
            &backend,
            key(tenant, "upf", b"same-session"),
            "restore-owner",
            StateClass::AuthoritativeSession,
            "pdu-session",
            b"sealed",
            None,
        )
        .await;
    }

    let request = RestoreScanRequest::all(1);
    let first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("first prefix-sensitive page");
    assert_eq!(first.records[0].key.tenant.as_str(), "a");
    first
        .validate_for_request(&request)
        .expect("first fake page is structurally valid");

    let second_request = RestoreScanRequest {
        cursor: first.next_cursor,
        ..request
    };
    let second = backend
        .scan_restore_records(second_request.clone())
        .await
        .expect("second prefix-sensitive page");
    assert_eq!(second.records[0].key.tenant.as_str(), "a-b");
    assert!(second.complete);
    second
        .validate_for_request(&second_request)
        .expect("second fake page is structurally valid");
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

    let mut mixed_profile = RestoreScanPage::new(
        vec![first.clone()],
        0,
        Some(RestoreScanCursor::from_offset(1)),
    );
    mixed_profile.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    assert_invalid(mixed_profile);

    assert_invalid(RestoreScanPage::new(
        vec![first.clone()],
        RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
        None,
    ));

    let mut empty_nonadvancing =
        RestoreScanPage::new(Vec::new(), 0, Some(RestoreScanCursor::from_offset(1)));
    empty_nonadvancing.complete = false;
    assert_invalid(empty_nonadvancing);

    let page = RestoreScanPage::new(vec![first], 0, None);
    let mut invalid_owner = serde_json::to_value(&page).expect("serialize page");
    invalid_owner["records"][0]["owner"] = serde_json::json!("");
    assert!(serde_json::from_value::<RestoreScanPage>(invalid_owner).is_err());

    let mut invalid_key_type = serde_json::to_value(&page).expect("serialize page");
    invalid_key_type["records"][0]["key"]["key_type"] = serde_json::json!("x".repeat(129));
    assert!(serde_json::from_value::<RestoreScanPage>(invalid_key_type).is_err());
}

#[test]
fn bounded_stable_ids_keep_maximum_payload_page_below_retained_ceiling() {
    let payload_per_record = RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES / RESTORE_SCAN_MAX_PAGE_SIZE;
    let mut records = (0..RESTORE_SCAN_MAX_PAGE_SIZE)
        .map(|index| {
            let mut record = record(
                "restore-owner",
                b"placeholder",
                StateClass::AuthoritativeSession,
                1,
                1,
            );
            let mut stable_id = vec![0_u8; opc_session_store::STABLE_ID_MAX_BYTES];
            stable_id[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("restore index fits u64")
                    .to_be_bytes(),
            );
            record.key.stable_id = stable_id.try_into().expect("maximum stable ID");
            record.payload = EncryptedSessionPayload::new(vec![0_u8; payload_per_record]);
            record
        })
        .collect::<Vec<_>>();
    let exact = RestoreScanPage::new(records.clone(), 0, None);
    assert!(
        exact.retained_bytes().expect("bounded retained size")
            < RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
    );
    exact
        .validate_for_request(&RestoreScanRequest::all(records.len()))
        .expect("maximum profile page is valid");

    records[0].payload = EncryptedSessionPayload::new(vec![0_u8; payload_per_record + 1]);
    let one_over = RestoreScanPage::new(records, 0, None);
    assert!(matches!(
        one_over.validate_for_request(&RestoreScanRequest::all(RESTORE_SCAN_MAX_PAGE_SIZE)),
        Err(StoreError::InvalidRestoreScanResponse(_))
    ));
}

#[tokio::test]
async fn restore_scan_capability_is_enforced() {
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

fn dynamic_key(stable_id: impl Into<Bytes>) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("tenant-a"),
        nf_kind: NetworkFunctionKind::upf(),
        key_type: SessionKeyType::PduSession,
        stable_id: stable_id.into().try_into().expect("valid stable ID"),
    }
}

async fn write_dynamic_sqlite_record(
    backend: &opc_session_store::SqliteSessionBackend,
    stable_id: impl Into<Bytes>,
    payload: Bytes,
) {
    write_record_fields(
        backend,
        WriteRecordFields {
            key: dynamic_key(stable_id),
            owner: "restore-owner",
            state_class: StateClass::AuthoritativeSession,
            state_type: "pdu-session",
            payload,
            expires_at: None,
            generation: 1,
        },
    )
    .await;
}

#[tokio::test]
async fn sqlite_restore_cursor_is_scope_and_revision_bound() {
    let fixed_time = Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000),
    );
    let backend = opc_session_store::SqliteSessionBackend::in_memory()
        .expect("sqlite")
        .with_clock(Arc::new(FixedClock(fixed_time)));
    write_dynamic_sqlite_record(&backend, Bytes::from_static(b"a"), Bytes::from_static(b"a")).await;
    write_dynamic_sqlite_record(&backend, Bytes::from_static(b"b"), Bytes::from_static(b"b")).await;

    let request = RestoreScanRequest::all(1);
    let first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("first page");
    let retried_first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("retry the same first page");
    assert_eq!(
        retried_first, first,
        "the same semantic position must produce one canonical retry page"
    );
    let cursor = first.next_cursor.clone().expect("continuation cursor");
    first
        .validate_for_request(&request)
        .expect("backend cursor advances by exactly the returned record count");

    let encoded_token: String =
        serde_json::from_str(&serde_json::to_string(&cursor).expect("serialize cursor"))
            .expect("cursor is one opaque string");
    let mut unsupported_version = encoded_token.clone().into_bytes();
    unsupported_version[0] = b'0';
    unsupported_version[1] = b'2';
    let unsupported_version =
        String::from_utf8(unsupported_version).expect("version edit remains UTF-8");
    assert!(serde_json::from_str::<RestoreScanCursor>(
        &serde_json::to_string(&unsupported_version).expect("encode unsupported cursor")
    )
    .is_err());

    for index in (2..encoded_token.len()).step_by(37) {
        let mut tampered = encoded_token.as_bytes().to_vec();
        tampered[index] = if tampered[index] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(tampered).expect("hex token remains UTF-8");
        let tampered_cursor: RestoreScanCursor =
            serde_json::from_str(&serde_json::to_string(&tampered).expect("encode tampered token"))
                .expect("tampered token retains its bounded wire shape");
        let error = backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(tampered_cursor),
                ..request.clone()
            })
            .await
            .expect_err("any opaque cursor edit must fail closed");
        assert_eq!(error, StoreError::RestoreScanCursorStale);
    }

    let changed_scope = backend
        .scan_restore_records(RestoreScanRequest {
            scope: RestoreScanScope {
                owner: Some(OwnerId::new("restore-owner").expect("owner")),
                ..RestoreScanScope::all()
            },
            cursor: Some(cursor.clone()),
            limit: 1,
        })
        .await
        .expect_err("scope replay must fail closed");
    assert_eq!(changed_scope, StoreError::RestoreScanCursorStale);

    write_dynamic_sqlite_record(&backend, Bytes::from_static(b"c"), Bytes::from_static(b"c")).await;
    let changed_state = backend
        .scan_restore_records(RestoreScanRequest {
            cursor: Some(cursor.clone()),
            ..request
        })
        .await
        .expect_err("mutated snapshot must fail closed");
    assert_eq!(changed_state, StoreError::RestoreScanCursorStale);

    let rendered = format!("{cursor:?}");
    let encoded = serde_json::to_string(&cursor).expect("serialize cursor");
    assert!(rendered.contains("[redacted]"));
    assert!(!encoded.contains("tenant-a"));
    assert!(!encoded.contains("restore-owner"));
}

#[tokio::test]
async fn sqlite_restore_cursor_survives_backend_restart() {
    let directory = tempfile::tempdir().expect("restore cursor directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    write_dynamic_sqlite_record(&backend, Bytes::from_static(b"a"), Bytes::from_static(b"a")).await;
    write_dynamic_sqlite_record(&backend, Bytes::from_static(b"b"), Bytes::from_static(b"b")).await;
    let request = RestoreScanRequest::all(1);
    let first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("first page");
    drop(backend);

    let restarted = opc_session_store::SqliteSessionBackend::open(&path).expect("reopen sqlite");
    let second = restarted
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("resume after restart");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"b");
    assert!(second.complete);
}

#[tokio::test]
async fn sqlite_restore_cursor_is_node_bound_and_restart_from_first_page_is_typed() {
    let source = opc_session_store::SqliteSessionBackend::in_memory().expect("source sqlite");
    let other_node =
        opc_session_store::SqliteSessionBackend::in_memory().expect("other-node sqlite");
    for backend in [&source, &other_node] {
        write_dynamic_sqlite_record(backend, Bytes::from_static(b"a"), Bytes::from_static(b"a"))
            .await;
        write_dynamic_sqlite_record(backend, Bytes::from_static(b"b"), Bytes::from_static(b"b"))
            .await;
    }

    let request = RestoreScanRequest::all(1);
    let source_first = source
        .scan_restore_records(request.clone())
        .await
        .expect("source first page");
    let error = other_node
        .scan_restore_records(RestoreScanRequest {
            cursor: source_first.next_cursor,
            ..request.clone()
        })
        .await
        .expect_err("another node cannot consume a node-bound cursor");
    assert_eq!(error, StoreError::RestoreScanCursorStale);

    let restarted = other_node
        .scan_restore_records(request)
        .await
        .expect("typed stale recovery restarts from the first page");
    assert_eq!(restarted.records.len(), 1);
    assert!(restarted.next_cursor.is_some());
}

#[tokio::test]
async fn sqlite_restore_rejects_legacy_stable_id_above_production_width() {
    let directory = tempfile::tempdir().expect("legacy stable ID directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    let raw = rusqlite::Connection::open(&path).expect("raw sqlite");
    raw.execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("allow legacy-invalid stable ID fixture");
    raw.execute(
        r#"
        INSERT INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence,
            state_class, state_type, expires_at, payload, encoding
        ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                  'authoritative-session', 'pdu-session', NULL, X'', 0)
        "#,
        rusqlite::params![vec![0x61_u8; opc_session_store::STABLE_ID_MAX_BYTES + 1]],
    )
    .expect("insert legacy oversized identifier");
    drop(raw);

    let error = backend
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect_err("legacy oversized identifier must fail hydration");
    assert_eq!(
        error,
        StoreError::Serialization("persisted stable session identifier is invalid".into())
    );
}

#[tokio::test]
async fn sqlite_existing_store_gets_only_the_bounded_cursor_key_migration() {
    let directory = tempfile::tempdir().expect("legacy restore directory");
    let path = directory.path().join("session.sqlite");
    let raw = rusqlite::Connection::open(&path).expect("raw legacy sqlite");
    raw.execute_batch(
        r#"
        CREATE TABLE session_records (
            tenant TEXT NOT NULL,
            nf_kind TEXT NOT NULL,
            key_type TEXT NOT NULL,
            stable_id BLOB NOT NULL,
            generation INTEGER NOT NULL,
            owner TEXT NOT NULL,
            fence INTEGER NOT NULL,
            state_class TEXT NOT NULL,
            state_type TEXT NOT NULL,
            expires_at TEXT,
            payload BLOB NOT NULL,
            encoding INTEGER NOT NULL,
            PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
        );
        CREATE TABLE restore_scan_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            epoch BLOB NOT NULL CHECK (length(epoch) = 16),
            revision INTEGER NOT NULL CHECK (revision >= 0)
        );
        "#,
    )
    .expect("create pre-cursor-key schema");
    raw.execute(
        "INSERT INTO restore_scan_state (singleton, epoch, revision) VALUES (1, ?1, 7)",
        [uuid::Uuid::from_u128(1).as_bytes().as_slice()],
    )
    .expect("insert old restore metadata");
    for stable_id in [b"a".as_slice(), b"b".as_slice()] {
        raw.execute(
            r#"
            INSERT INTO session_records (
                tenant, nf_kind, key_type, stable_id, generation, owner, fence,
                state_class, state_type, expires_at, payload, encoding
            ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                      'authoritative-session', 'pdu-session', NULL, ?2, 0)
            "#,
            rusqlite::params![stable_id, b"sealed".as_slice()],
        )
        .expect("insert legacy fixture record");
    }
    drop(raw);

    let backend = opc_session_store::SqliteSessionBackend::open(&path)
        .expect("open and migrate existing store");
    let first = backend
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect("scan migrated store");
    assert!(first.next_cursor.is_some());
    drop(backend);

    let raw = rusqlite::Connection::open(&path).expect("inspect migrated sqlite");
    let cursor_key_len: i64 = raw
        .query_row(
            "SELECT length(cursor_key) FROM restore_scan_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("cursor key is persisted");
    assert_eq!(cursor_key_len, 32);
    let record_columns = raw
        .prepare("PRAGMA table_info(session_records)")
        .expect("record schema")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("record columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("read record columns");
    assert!(!record_columns
        .iter()
        .any(|name| name == "restore_order_key"));
}

#[tokio::test]
async fn sqlite_restore_page_stops_before_payload_byte_budget() {
    let backend = opc_session_store::SqliteSessionBackend::in_memory().expect("sqlite");
    let payload_size = RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES / 4;
    for index in 0..5 {
        write_dynamic_sqlite_record(
            &backend,
            Bytes::from(format!("record-{index}")),
            Bytes::from(vec![
                u8::try_from(index).expect("small index");
                payload_size
            ]),
        )
        .await;
    }

    let request = RestoreScanRequest::all(16);
    let first = backend
        .scan_restore_records(request.clone())
        .await
        .expect("bounded first page");
    assert_eq!(first.records.len(), 4);
    assert_eq!(
        first
            .records
            .iter()
            .map(|record| record.payload.len())
            .sum::<usize>(),
        RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES
    );
    let second = backend
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("bounded second page");
    assert_eq!(second.records.len(), 1);
    assert!(second.complete);
}

#[tokio::test]
async fn sqlite_restore_rejects_one_record_over_the_payload_byte_budget() {
    let directory = tempfile::tempdir().expect("oversized restore directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    let raw = rusqlite::Connection::open(&path).expect("raw sqlite");
    raw.execute(
        r#"
        INSERT INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence,
            state_class, state_type, expires_at, payload, encoding
        ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                  'authoritative-session', 'pdu-session', NULL, ?2, 0)
        "#,
        rusqlite::params![
            b"oversized".as_slice(),
            vec![0_u8; RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES + 1]
        ],
    )
    .expect("insert one-over payload");
    drop(raw);

    let error = backend
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect_err("one oversized record must fail before payload decode");
    assert_eq!(
        error,
        StoreError::RestoreScanResponseTooLarge {
            max_bytes: RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES,
        }
    );
}

#[tokio::test]
async fn sqlite_restore_key_preflight_accepts_exact_and_rejects_one_over() {
    async fn scan_key_of_size(stable_id_bytes: usize) -> Result<RestoreScanPage, StoreError> {
        let directory = tempfile::tempdir().expect("key-bound restore directory");
        let path = directory.path().join("session.sqlite");
        let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
        let raw = rusqlite::Connection::open(&path).expect("raw sqlite");
        raw.execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow raw boundary fixture");
        raw.execute(
            r#"
            INSERT INTO session_records (
                tenant, nf_kind, key_type, stable_id, generation, owner, fence,
                state_class, state_type, expires_at, payload, encoding
            ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                      'authoritative-session', 'pdu-session', NULL, ?2, 0)
            "#,
            rusqlite::params![vec![0_u8; stable_id_bytes], b"sealed".as_slice()],
        )
        .expect("insert key-bound row");
        drop(raw);
        backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
    }

    let minimum = scan_key_of_size(opc_session_store::STABLE_ID_MIN_BYTES)
        .await
        .expect("the minimum production stable ID is accepted");
    assert_eq!(minimum.records[0].key.stable_id.len(), 1);

    let exact = scan_key_of_size(opc_session_store::STABLE_ID_MAX_BYTES)
        .await
        .expect("the production stable ID ceiling is accepted");
    assert_eq!(
        exact.records[0].key.stable_id.len(),
        opc_session_store::STABLE_ID_MAX_BYTES
    );
    assert!(exact.complete);

    let empty = scan_key_of_size(0)
        .await
        .expect_err("empty key is rejected before row-owned allocation");
    assert_eq!(
        empty,
        StoreError::Serialization("persisted stable session identifier is invalid".into())
    );

    let one_over = scan_key_of_size(opc_session_store::STABLE_ID_MAX_BYTES + 1)
        .await
        .expect_err("one-over key is rejected before row-owned allocation");
    assert_eq!(
        one_over,
        StoreError::Serialization("persisted stable session identifier is invalid".into())
    );
}

#[tokio::test]
async fn sqlite_sparse_scope_does_not_load_excluded_oversized_payloads() {
    let directory = tempfile::tempdir().expect("sparse-payload restore directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    let raw = rusqlite::Connection::open(&path).expect("raw sqlite");
    for index in 0..3 {
        raw.execute(
            r#"
            INSERT INTO session_records (
                tenant, nf_kind, key_type, stable_id, generation, owner, fence,
                state_class, state_type, expires_at, payload, encoding
            ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                      'authoritative-session', 'pdu-session', NULL, zeroblob(?2), 0)
            "#,
            rusqlite::params![
                format!("excluded-{index}").into_bytes(),
                i64::try_from(RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES + 1)
                    .expect("payload bound fits SQLite")
            ],
        )
        .expect("insert excluded huge-payload row");
    }
    raw.execute(
        r#"
        INSERT INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence,
            state_class, state_type, expires_at, payload, encoding
        ) VALUES ('tenant-z', 'upf', 'pdu-session', ?1, 1, 'restore-owner', 1,
                  'authoritative-session', 'pdu-session', NULL, ?2, 0)
        "#,
        rusqlite::params![b"target".as_slice(), b"sealed".as_slice()],
    )
    .expect("insert sparse target row");
    drop(raw);

    let request = RestoreScanRequest {
        scope: RestoreScanScope {
            tenant: Some(TenantId::from_static("tenant-z")),
            ..RestoreScanScope::all()
        },
        cursor: None,
        limit: 1,
    };
    let page = backend
        .scan_restore_records(request.clone())
        .await
        .expect("excluded payload blobs are not selected or decoded");
    assert_eq!(page.excluded_count, 3);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].key.stable_id.as_ref(), b"target");
    assert!(page.complete);
    page.validate_for_request(&request)
        .expect("sparse huge-payload page is structurally valid");
}

#[tokio::test]
async fn sqlite_limit_one_does_not_decode_a_later_malformed_record() {
    let directory = tempfile::tempdir().expect("bounded restore directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    write_dynamic_sqlite_record(
        &backend,
        Bytes::from_static(b"a-valid"),
        Bytes::from_static(b"valid"),
    )
    .await;

    let raw = rusqlite::Connection::open(&path).expect("raw sqlite");
    raw.execute(
        r#"
        INSERT INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence,
            state_class, state_type, expires_at, payload, encoding
        ) VALUES ('tenant-a', 'upf', 'pdu-session', ?1, 1, '', 1,
                  'authoritative-session', 'pdu-session', NULL, ?2, 0)
        "#,
        rusqlite::params![b"z-malformed".as_slice(), b"malformed".as_slice()],
    )
    .expect("insert malformed later row");
    drop(raw);

    let first = backend
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect("bounded page must not decode later row");
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"a-valid");
    assert!(first.next_cursor.is_some());
}

#[tokio::test]
async fn sqlite_sparse_and_large_scans_make_bounded_seek_progress_without_gaps() {
    const RECORDS: usize = RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE + 905;

    let directory = tempfile::tempdir().expect("large restore directory");
    let path = directory.path().join("session.sqlite");
    let backend = opc_session_store::SqliteSessionBackend::open(&path).expect("sqlite");
    let mut raw = rusqlite::Connection::open(&path).expect("raw sqlite");
    let tx = raw.transaction().expect("bulk insert transaction");
    {
        let mut insert = tx
            .prepare(
                r#"
                INSERT INTO session_records (
                    tenant, nf_kind, key_type, stable_id, generation, owner, fence,
                    state_class, state_type, expires_at, payload, encoding
                ) VALUES (?1, 'upf', 'pdu-session', ?2, 1, 'restore-owner', 1,
                          'authoritative-session', 'pdu-session', NULL, ?3, 0)
                "#,
            )
            .expect("prepare bulk insert");
        for index in 0..RECORDS {
            let tenant = if index + 1 == RECORDS {
                "tenant-z"
            } else {
                "tenant-a"
            };
            let stable_id = format!("session-{index:08}");
            insert
                .execute(rusqlite::params![
                    tenant,
                    stable_id.as_bytes(),
                    b"sealed".as_slice()
                ])
                .expect("insert bounded fixture row");
        }
    }
    tx.commit().expect("commit bounded fixture");
    drop(raw);

    let sparse_request = RestoreScanRequest {
        scope: RestoreScanScope {
            tenant: Some(TenantId::from_static("tenant-z")),
            ..RestoreScanScope::all()
        },
        cursor: None,
        limit: 8,
    };
    let sparse_first = backend
        .scan_restore_records(sparse_request.clone())
        .await
        .expect("bounded sparse first page");
    assert!(sparse_first.records.is_empty());
    assert_eq!(
        sparse_first.excluded_count,
        RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
    );
    assert_eq!(
        sparse_first.cursor_profile,
        RestoreScanCursorProfile::DurableOpaqueV1
    );
    assert!(!sparse_first.complete);
    sparse_first
        .validate_for_request(&sparse_request)
        .expect("empty sparse page proves bounded cursor progress");

    let sparse_second = backend
        .scan_restore_records(RestoreScanRequest {
            cursor: sparse_first.next_cursor,
            ..sparse_request
        })
        .await
        .expect("bounded sparse second page");
    assert_eq!(sparse_second.records.len(), 1);
    assert_eq!(sparse_second.excluded_count, 904);
    assert!(sparse_second.complete);

    let mut expected = None;
    for limit in [127, 512, RESTORE_SCAN_MAX_PAGE_SIZE] {
        let mut cursor = None;
        let mut keys = Vec::with_capacity(RECORDS);
        loop {
            let request = RestoreScanRequest {
                cursor,
                ..RestoreScanRequest::all(limit)
            };
            let page = backend
                .scan_restore_records(request.clone())
                .await
                .expect("bounded large page");
            page.validate_for_request(&request)
                .expect("large page satisfies hostile-response checks");
            keys.extend(page.records.iter().map(|record| record.key.digest()));
            cursor = page.next_cursor;
            if page.complete {
                break;
            }
        }
        assert_eq!(keys.len(), RECORDS);
        let unique = keys
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), RECORDS, "seek pages must not duplicate keys");
        if let Some(previous) = &expected {
            assert_eq!(&keys, previous, "page size cannot alter scan order");
        } else {
            expected = Some(keys);
        }
    }
}
