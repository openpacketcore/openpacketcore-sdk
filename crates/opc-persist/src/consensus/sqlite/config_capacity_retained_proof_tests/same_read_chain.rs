//! Same-read ciphertext hashing must preserve both independent authenticators.

use super::*;
use crate::consensus::history::config_capacity_read_buffers::Observation;

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
        PROFILE,
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
            sample.ciphertext_hashes,
            [0, 3],
            "CONFIG_CAPACITY_SAME_READ_HASH_RED: one fresh proof hash per row, no repeated chain hash"
        );
        assert_eq!(
            sample.ciphertext_hash_bytes,
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
