use bytes::Bytes;
use opc_session_store::{
    summarize_restore_records, EncryptedSessionPayload, FenceToken, Generation, OwnerId,
    RestoreBlockReason, RestoreBlockReasonCode, RestoreRecordSummary, SessionKey, SessionKeyType,
    StateClass, StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};

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
