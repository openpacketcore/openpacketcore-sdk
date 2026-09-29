//! Same-read ciphertext hashing must preserve both independent authenticators.

use super::*;
use crate::consensus::history::config_capacity_read_buffers::{CiphertextHashSite, Observation};

async fn populated() -> Fixture {
    let fixture = fixture(PROFILE).await;
    initialize(&fixture).await;
    let entries = (1..=3)
        .map(|version| {
            entry(
                &fixture,
                version,
                append_intent(&fixture, version, 96 * 1024, 0, false, None),
            )
        })
        .collect();
    let responses = apply(&fixture, entries).await;
    assert_eq!(responses.len(), 3);
    assert!(responses.iter().all(|response| response.result.is_ok()));
    fixture
}

fn validate(conn: &Connection, fixture: &Fixture) -> io::Result<()> {
    crate::consensus::history::validate_access_for_profile_sync(
        conn,
        &fixture.key,
        true,
        Some(fixture.topology.identity()),
        crate::consensus::RetainedConfigMode::try_from(PROFILE).expect("supported fixture mode"),
        &SqliteWorkCancellation::new(),
    )
}

#[tokio::test]
async fn config_capacity_history_same_read_hashes_each_proof_ciphertext_once() {
    let fixture = populated().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let before = authority_digest(&conn);
    let changes = conn.total_changes();
    let expected_bytes: i64 = conn
        .query_row(
            "SELECT SUM(length(encrypted_blob)) FROM config_history",
            [],
            |row| row.get(0),
        )
        .expect("exact retained ciphertext extent");
    let tx = conn.unchecked_transaction().expect("pinned read");
    let mut samples = Vec::new();
    // Repeat within one transaction: each call must freshly authenticate all
    // rows; a previous call is not an authorization or cached hash result.
    for _ in 0..2 {
        let observation = Observation::start();
        validate(&tx, &fixture).expect("full history and capacity authentication");
        samples.push(observation.finish());
        assert_eq!(authority_digest(&tx), before, "validation is read-only");
        assert_eq!(tx.total_changes(), changes, "no transient writes");
    }
    tx.commit().expect("finish read");
    drop(conn);
    drop(shared);
    let expected = fixture
        .backend
        .load_latest()
        .await
        .expect("native readback")
        .expect("retained head");
    assert_eq!(expected.record.version, ConfigVersion::new(3));
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key)
        .await
        .expect("durable retained reopen");
    let actual = reopened
        .load_latest()
        .await
        .expect("reopened native readback")
        .expect("same retained head");
    assert_eq!(actual.record, expected.record);
    assert_eq!(actual.audit, expected.audit);
    let shared = reopened.conn();
    let conn = shared.lock().await;
    assert_eq!(authority_digest(&conn), before, "exact retained authority");
    // Work assertions follow real authentication, readback and retained reopen.
    for sample in samples {
        assert_eq!(sample.peak_owned_ciphertext, 0);
        assert_eq!(sample.peak_owned_fixed_width, [0; 9]);
        assert_eq!(
            [sample.calls[0], sample.calls[2]],
            [0, 0],
            "CONFIG_CAPACITY_ENDPOINT_SCAN_RED: no separate head or boundary ciphertext projection"
        );
        assert_eq!(
            [
                sample.ciphertext_hash_calls[CiphertextHashSite::Chain as usize],
                sample.ciphertext_hash_calls[CiphertextHashSite::Capacity as usize],
            ],
            [0, 3],
            "CONFIG_CAPACITY_SAME_READ_HASH_RED: one fresh proof hash per row, no repeated chain hash"
        );
        assert_eq!(
            [
                sample.ciphertext_hash_bytes[CiphertextHashSite::Chain as usize],
                sample.ciphertext_hash_bytes[CiphertextHashSite::Capacity as usize],
            ],
            [
                0,
                usize::try_from(expected_bytes).expect("bounded fixture extent")
            ]
        );
    }
}

enum Corruption {
    Ciphertext,
    CapacityMac,
    ChainMetadata,
}

async fn rejects_fresh_corruption(corruption: Corruption) {
    let fixture = populated().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let original = authority_digest(&conn);
    let tx = conn
        .unchecked_transaction()
        .expect("pinned read and tamper");
    validate(&tx, &fixture).expect("first full authenticated read");
    match corruption {
        Corruption::Ciphertext => {
            let mut bytes: Vec<u8> = tx
                .query_row(
                    "SELECT encrypted_blob FROM config_history WHERE version = 2",
                    [],
                    |row| row.get(0),
                )
                .expect("middle record ciphertext");
            *bytes.last_mut().expect("nonempty encrypted envelope") ^= 1;
            assert_eq!(
                tx.execute(
                    "UPDATE config_history SET encrypted_blob = ?1 WHERE version = 2",
                    [bytes],
                )
                .expect("same-length ciphertext corruption"),
                1
            );
        }
        Corruption::CapacityMac => {
            let mut proof: Vec<u8> = tx
                .query_row(
                    "SELECT binding FROM config_raft_capacity_records WHERE tx_id = ?1",
                    [tx_id(2).as_uuid().as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("middle record proof");
            *proof.last_mut().expect("fixed proof MAC") ^= 1;
            assert_eq!(
                tx.execute(
                    "UPDATE config_raft_capacity_records SET binding = ?1 WHERE tx_id = ?2",
                    params![proof, tx_id(2).as_uuid().as_bytes().as_slice()],
                )
                .expect("same-length wrong capacity MAC"),
                1
            );
            // The fixture owns its signing key. Reauthenticate only the history
            // chain so rejection must come from the independent capacity MAC.
            // Ordinary corruption cannot reauthenticate this enclosing state.
            crate::consensus::history::refresh_sync(
                &tx,
                &fixture.key,
                true,
                &SqliteWorkCancellation::new(),
            )
            .expect("synthetic history signer")
            .expect("unchanged history bounds");
        }
        Corruption::ChainMetadata => {
            assert_eq!(
                tx.execute(
                    "UPDATE config_history SET rollback_point = 1 WHERE version = 2",
                    [],
                )
                .expect("capacity-valid but unauthenticated metadata"),
                1
            );
        }
    }
    let changed = authority_digest(&tx);
    assert_ne!(changed, original);
    let changes = tx.total_changes();
    let error = validate(&tx, &fixture).expect_err(
        "CONFIG_CAPACITY_FRESH_HISTORY_RED: authenticate again after same-transaction tamper",
    );
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        authority_digest(&tx),
        changed,
        "rejection leaves exact bytes"
    );
    assert_eq!(tx.total_changes(), changes, "rejection makes no writes");
    tx.rollback().expect("restore all original bytes");
    assert_eq!(authority_digest(&conn), original);
    validate(&conn, &fixture).expect("restored original authority");
}

#[tokio::test]
async fn config_capacity_history_same_read_reauthenticates_changed_ciphertext() {
    rejects_fresh_corruption(Corruption::Ciphertext).await;
}

#[tokio::test]
async fn config_capacity_history_same_read_checks_independent_capacity_mac() {
    rejects_fresh_corruption(Corruption::CapacityMac).await;
}

#[tokio::test]
async fn config_capacity_history_same_read_checks_complete_chain_metadata() {
    rejects_fresh_corruption(Corruption::ChainMetadata).await;
}

async fn retained() -> Fixture {
    let fixture = populated().await;
    let retention = ConfigHistoryRetention::new(
        tx_id(3),
        ConfigVersion::new(3),
        ConfigVersion::new(1),
        ConfigVersion::new(2),
        ConfigHistoryLimits::new(2, 8 * 1024 * 1024).expect("retained limits"),
    )
    .expect("explicit prefix acknowledgement");
    assert!(apply(
        &fixture,
        vec![entry(
            &fixture,
            4,
            ConfigMutationIntent::RetainHistory(retention)
        )]
    )
    .await[0]
        .result
        .is_ok());
    fixture
}

#[tokio::test]
async fn config_capacity_history_same_read_retained_endpoints_survive_reopen() {
    let fixture = retained().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let before = authority_digest(&conn);
    let changes = conn.total_changes();
    let expected_bytes: i64 = conn
        .query_row(
            "SELECT SUM(length(encrypted_blob)) FROM config_history",
            [],
            |row| row.get(0),
        )
        .expect("retained ciphertext extent");
    let tx = conn.unchecked_transaction().expect("pinned retained read");
    let mut samples = Vec::new();
    for _ in 0..2 {
        let observation = Observation::start();
        validate(&tx, &fixture).expect("fresh authenticated retained endpoints");
        samples.push(observation.finish());
        assert_eq!(authority_digest(&tx), before);
        assert_eq!(tx.total_changes(), changes);
    }
    tx.commit().expect("finish pinned read");
    drop(conn);
    drop(shared);
    let expected = fixture
        .backend
        .load_since(ConfigVersion::new(1), 2)
        .await
        .expect("first retained row and head");
    assert_eq!(expected.len(), 2);
    assert_eq!(expected[0].record.version, ConfigVersion::new(2));
    assert_eq!(expected[0].record.parent_tx_id, Some(tx_id(1)));
    assert_eq!(expected[1].record.version, ConfigVersion::new(3));
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key)
        .await
        .expect("retained endpoint reopen");
    let actual = reopened
        .load_since(ConfigVersion::new(1), 2)
        .await
        .expect("same retained projections after reopen");
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(&expected) {
        assert_eq!(actual.record, expected.record);
        assert_eq!(actual.audit, expected.audit);
    }
    let shared = reopened.conn();
    let conn = shared.lock().await;
    assert_eq!(authority_digest(&conn), before);
    for sample in samples {
        assert_eq!(sample.peak_owned_ciphertext, 0);
        assert_eq!(sample.peak_owned_fixed_width, [0; 9]);
        assert_eq!(
            [
                sample.ciphertext_hash_calls[CiphertextHashSite::Chain as usize],
                sample.ciphertext_hash_calls[CiphertextHashSite::Capacity as usize],
            ],
            [0, 2]
        );
        assert_eq!(
            [
                sample.ciphertext_hash_bytes[CiphertextHashSite::Chain as usize],
                sample.ciphertext_hash_bytes[CiphertextHashSite::Capacity as usize],
            ],
            [0, usize::try_from(expected_bytes).unwrap()]
        );
        assert_eq!(
            [sample.calls[0], sample.calls[2]],
            [0, 0],
            "CONFIG_CAPACITY_ENDPOINT_SCAN_RED: retained endpoint hashes share the fresh row proof"
        );
    }
}

fn sign_synthetic_state(
    conn: &Connection,
    key: &AuditKey,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    use hmac::{Hmac, KeyInit, Mac};
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_history_retention WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("authenticated fixture state");
    let mut state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    mutate(&mut state);
    let bytes = serde_json::to_vec(&state).unwrap();
    // This fixture owns its synthetic signing key. Keep the MAC valid so that
    // inconsistent endpoint/count metadata must fail its independent check.
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(b"openpacketcore/config-consensus/history-retention/v1\0");
    mac.update(&bytes);
    let tag = mac.finalize().into_bytes();
    assert_eq!(
        conn.execute(
            "UPDATE config_raft_history_retention SET state_json = ?1, state_hmac = ?2 WHERE singleton = 1",
            params![bytes, tag.as_slice()],
        )
        .expect("synthetic authenticated inconsistent state"),
        1
    );
}

fn rejects_signed_inconsistency(
    conn: &Connection,
    fixture: &Fixture,
    mutate: impl FnOnce(&mut serde_json::Value),
    marker: &str,
) {
    let before = authority_digest(conn);
    let tx = conn
        .unchecked_transaction()
        .expect("pinned read and change");
    validate(&tx, fixture).expect("original consistent authenticated state");
    sign_synthetic_state(&tx, &fixture.key, mutate);
    let changed = authority_digest(&tx);
    assert_ne!(changed, before);
    let changes = tx.total_changes();
    let error = validate(&tx, fixture).expect_err(marker);
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(authority_digest(&tx), changed);
    assert_eq!(tx.total_changes(), changes, "rejection performs no writes");
    tx.rollback().expect("restore original authority");
    assert_eq!(authority_digest(conn), before);
    validate(conn, fixture).expect("restored original remains readable");
}

#[tokio::test]
async fn config_capacity_history_same_read_checks_authenticated_head() {
    let fixture = populated().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let marker = "CONFIG_CAPACITY_AUTHENTICATED_HEAD_RED";
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| s["head"] = serde_json::Value::Null,
        marker,
    );
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| s["head"]["tx_id"] = serde_json::to_value(tx_id(2)).unwrap(),
        marker,
    );
    rejects_signed_inconsistency(&conn, &fixture, |s| s["head"]["version"] = 2.into(), marker);
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| {
            let byte = s["head"]["encrypted_digest"][0].as_u64().unwrap();
            s["head"]["encrypted_digest"][0] = (byte ^ 1).into();
        },
        marker,
    );
    drop(conn);
    drop(shared);
    drop(fixture);

    // The terminal comparison must also authenticate a history with no rows.
    let empty = super::fixture(PROFILE).await;
    initialize(&empty).await;
    let shared = empty.backend.conn();
    let conn = shared.lock().await;
    rejects_signed_inconsistency(
        &conn,
        &empty,
        |s| {
            s["head"] = serde_json::json!({
                "tx_id": tx_id(1),
                "version": ConfigVersion::new(1),
                "encrypted_digest": vec![0_u8; 32],
            });
        },
        "CONFIG_CAPACITY_AUTHENTICATED_EMPTY_HEAD_RED",
    );
}

#[tokio::test]
async fn config_capacity_history_same_read_checks_authenticated_record_count() {
    let fixture = populated().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    for count in [0, 2, 4, u64::MAX] {
        rejects_signed_inconsistency(
            &conn,
            &fixture,
            |s| s["records"] = count.into(),
            "CONFIG_CAPACITY_AUTHENTICATED_COUNT_RED",
        );
    }
    drop(conn);
    drop(shared);
    drop(fixture);

    let empty = super::fixture(PROFILE).await;
    initialize(&empty).await;
    let shared = empty.backend.conn();
    let conn = shared.lock().await;
    for count in [1, u64::MAX] {
        rejects_signed_inconsistency(
            &conn,
            &empty,
            |s| s["records"] = count.into(),
            "CONFIG_CAPACITY_AUTHENTICATED_EMPTY_COUNT_RED",
        );
    }
}

#[tokio::test]
async fn config_capacity_history_same_read_checks_actual_first_retained_boundary() {
    let fixture = retained().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let marker = "CONFIG_CAPACITY_AUTHENTICATED_BOUNDARY_RED";
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| {
            let byte = s["boundary"]["first"]["encrypted_digest"][0]
                .as_u64()
                .unwrap();
            s["boundary"]["first"]["encrypted_digest"][0] = (byte ^ 1).into();
        },
        marker,
    );
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| s["boundary"]["first"]["tx_id"] = serde_json::to_value(tx_id(3)).unwrap(),
        marker,
    );
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| {
            s["boundary"]["first"]["version"] = 3.into();
            s["acknowledged_through"] = 2.into();
        },
        marker,
    );
    rejects_signed_inconsistency(
        &conn,
        &fixture,
        |s| s["boundary"]["original_parent"] = serde_json::to_value(tx_id(2)).unwrap(),
        marker,
    );
}
