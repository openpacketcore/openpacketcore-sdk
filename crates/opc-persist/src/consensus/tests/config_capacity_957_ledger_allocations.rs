//! Capacity-specific inventory of authenticated retained ledger allocations.
//! This observes real serde container capacities for one reachable legacy ledger
//! shape. It is neither a process peak nor a whole-operation memory bound.

use std::io::Write;

use super::*;
use crate::audit_authority::ledger::{EntryPayload, HandleBody, LedgerEntry, LedgerOperation};
use crate::audit_authority::{
    AuditOperationBinding, AuditPrivacyKey, AuditPrivacyProjection, AuditPrivacyPurpose,
    ProjectedAuditEvent,
};

fn event(number: u64) -> crate::ManagementAuditEventRecord {
    let mut request = [0xD0; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    crate::ManagementAuditEventRecord::try_new(
        request,
        crate::ManagementAuditInstant::try_new(
            100,
            999_999_999,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some("synthetic-retained-allocation-control"),
    )
    .expect("bounded synthetic event")
}

fn decoded_owned_bytes(stored: &StoredLedger) -> usize {
    let ledger = stored.ledger.as_ref().expect("populated ledger");
    assert!(
        ledger.continuity.is_none(),
        "this control has no signing history"
    );
    // Every nested type used in this fixture has only inline fields except
    // for the two Vec allocations and each explicitly counted payload Box.
    // Re-audit this inventory if those source types change.
    let boxed_bytes = ledger
        .entries
        .iter()
        .map(|entry| match &entry.payload {
            EntryPayload::Intent(_) => std::mem::size_of::<AuditOperationHandle>(),
            EntryPayload::Event(_) | EntryPayload::KeyTransition(_) => {
                panic!("fixture must contain only admitted operations and their resolutions")
            }
            EntryPayload::Outcome { .. } | EntryPayload::Terminal { .. } => 0,
        })
        .sum::<usize>();
    std::mem::size_of::<StoredLedger>()
        + ledger.entries.capacity() * std::mem::size_of::<LedgerEntry>()
        + ledger.operations.capacity() * std::mem::size_of::<LedgerOperation>()
        + boxed_bytes
}

#[test]
fn config_capacity_957_retained_ledger_buffer_inventory() {
    let key = AuditKey::new([0xD1; 32]).expect("synthetic authentication key");
    let privacy = AuditPrivacyKey::new([0xD2; 32]).expect("synthetic projection key");
    let identity = ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0xD3; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0xD4; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    );
    let mut ledger = LedgerState::new(
        identity,
        privacy
            .project(AuditPrivacyPurpose::KeyIdentity, &[])
            .expect("key projection"),
        AuditLedgerLimits::new(4096, 1024).expect("existing ledger limits"),
    );
    // Use real authenticated admission, rejection and terminal transitions.
    // No test-only append_event shortcut or forged canonical state is used.
    // This fills the operation bound and reaches 3072 of 4096 event slots;
    // it makes no claim that the two maxima are jointly reachable.
    for number in 0_u64..1024 {
        let event = ProjectedAuditEvent::project(&privacy, &event(number))
            .expect("actual event projection");
        let binding = AuditOperationBinding::project(&privacy, &event, 0, b"synthetic operation")
            .expect("actual operation projection");
        let mut nonce = [0xD5; 16];
        nonce[..8].copy_from_slice(&number.to_be_bytes());
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity,
                binding,
                event,
                issued_at: 100,
                expires_at: 160,
                nonce,
                key_epoch: key.epoch(),
                mutation: None,
            },
            &key,
        )
        .expect("authenticated original handle");
        ledger.admit(&key, &handle, 100).expect("intent admission");
        ledger
            .resolve(&key, &handle, AuditOperationState::Rejected)
            .expect("authoritative rejection");
        ledger
            .acknowledge_terminal(&key, &handle)
            .expect("terminal acknowledgement");
    }
    ledger
        .validate(&key, identity)
        .expect("entire valid history");
    assert_eq!(ledger.entries.len(), 3072);
    assert_eq!(ledger.operations.len(), 1024);
    assert!(ledger
        .operations
        .iter()
        .all(|operation| operation.terminal_recorded));

    // In-memory SQL is intentional for this encoder/container measurement.
    // Native WAL, fs-verity, transport and durability require separate tests.
    let connection = Connection::open_in_memory().expect("unit SQL control");
    connection
        .execute_batch(
            "CREATE TABLE config_raft_management_audit \
             (singleton INTEGER PRIMARY KEY, state_json BLOB, state_hmac BLOB); \
             CREATE TABLE config_raft_identity \
             (singleton INTEGER PRIMARY KEY, cluster_id BLOB, configuration_id BLOB, configuration_epoch INTEGER);",
        )
        .expect("minimal encoder control tables");
    connection
        .execute(
            "INSERT INTO config_raft_identity VALUES (1, ?1, ?2, ?3)",
            params![
                identity.cluster_id().as_bytes().as_slice(),
                identity.configuration_id().as_bytes().as_slice(),
                identity.configuration_epoch().get() as i64,
            ],
        )
        .expect("exact source identity");
    write_sync(&connection, &key, identity, Some(ledger), true)
        .expect("actual authenticated canonical storage encoding");
    let validated = read_sync(&connection, &key, identity)
        .expect("actual full read verification")
        .expect("retained history");
    assert_eq!(validated.operations.len(), 1024);
    drop(validated);

    let encoded: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("actual SQL-owned JSON allocation");
    let decoded: StoredLedger = serde_json::from_slice(&encoded).expect("actual decoded state");
    let canonical = serde_json::to_vec(&decoded).expect("original authentication encoder");
    assert!(canonical == encoded, "canonical bytes stay exact");
    assert!(canonical.len() <= MAX_STATE_BYTES);
    let original_mac = crate::audit_authority::ledger::authenticate(&key, STATE_DOMAIN, &decoded)
        .expect("original authenticated transcript");
    let (streamed, streamed_mac) = encode_state(&decoded, &key).expect("streamed state output");
    assert!(
        streamed == encoded,
        "complete populated encoding stays exact"
    );
    assert!(
        streamed_mac == original_mac,
        "populated authenticator stays exact"
    );
    stream_state(
        &decoded,
        &key,
        canonical_state_len(&decoded).expect("actual canonical length"),
        None,
    )
    .expect("verification without a canonical output buffer")
    .verify_slice(&original_mac)
    .expect("original populated authentication remains valid");
    let decoded_bytes = decoded_owned_bytes(&decoded);
    let original_canonical_capacity = canonical.capacity();
    let streamed_write_capacity = streamed.capacity();
    // The extra outputs above are compatibility oracles, not live buffers in
    // the streaming read path. Release them before recording the inventory.
    drop(canonical);
    drop(streamed);
    let read_known_live_bytes = encoded.capacity() + decoded_bytes;
    let write_known_live_bytes = streamed_write_capacity + decoded_bytes;
    // Keep these value-free measurements visible in the required quiet CI
    // harness even when this test passes; ordinary println output is captured.
    writeln!(
        std::io::stdout().lock(),
        "CONFIG_CAPACITY_LEDGER_STREAMED_BUFFERS encoded_len={} encoded_capacity={} original_canonical_capacity={} streamed_write_capacity={} decoded_owned_bytes={} read_known_live_bytes={} write_known_live_bytes={}",
        encoded.len(), encoded.capacity(), original_canonical_capacity, streamed_write_capacity,
        decoded_bytes, read_known_live_bytes, write_known_live_bytes,
    )
    .expect("emit value-free allocation inventory");
    // No unmeasured 32 MiB assertion: this excludes allocator overhead, SQL,
    // validation temporaries (including derived operations), commands,
    // transport, replication and continuity.
}
