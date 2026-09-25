//! Existing history reads must consume the independently admitted profile.
//! These are inactive-store checks, not activation or target-effect evidence.

use super::*;
use opc_persist::{ConfigStore, PersistErrorKind};
use opc_types::ConfigVersion;

async fn empty_reads(backend: &SqliteBackend) {
    assert!(
        backend
            .load_latest()
            .await
            .expect("admitted latest read")
            .is_none()
    );
    assert!(
        backend
            .load_committed_latest()
            .await
            .expect("admitted committed read")
            .is_none()
    );
    assert!(
        backend
            .load_since(ConfigVersion::new(0), 1)
            .await
            .expect("admitted history page")
            .is_empty()
    );
    assert!(
        backend
            .load_since(ConfigVersion::new(u64::MAX), 0)
            .await
            .expect("admitted empty page")
            .is_empty()
    );
    assert!(
        backend
            .retained_history_floor()
            .await
            .expect("admitted history floor")
            .is_none()
    );
    assert!(
        backend
            .load_by_replay_lookup_digest(&"51".repeat(32))
            .await
            .expect("admitted absent lookup")
            .is_none()
    );
}

async fn rejected_reads(backend: &SqliteBackend) {
    let errors = [
        backend.load_latest().await.map(|_| ()),
        backend.load_committed_latest().await.map(|_| ()),
        backend
            .load_since(ConfigVersion::new(0), 1)
            .await
            .map(|_| ()),
        backend
            .load_since(ConfigVersion::new(u64::MAX), 0)
            .await
            .map(|_| ()),
        backend.retained_history_floor().await.map(|_| ()),
        backend
            .load_by_replay_lookup_digest(&"51".repeat(32))
            .await
            .map(|_| ()),
    ];
    for result in errors {
        let error = result.expect_err("altered retained authority was treated as empty history");
        assert!(matches!(error.kind(), PersistErrorKind::CorruptBlob));
    }
}

async fn empty_profile(profile: RetainedConfigProfile) {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.sqlite");
    let options = options_for_profile(&path, fixture, 0x41, profile);
    let backend = SqliteBackend::provision_config_authority(options.clone(), key(fixture))
        .await
        .unwrap();
    empty_reads(&backend).await;
    drop(backend);
    let reopened = SqliteBackend::reopen_config_authority(options, key(fixture))
        .await
        .unwrap();
    empty_reads(&reopened).await;
}

#[tokio::test]
async fn legacy_history_reads_keep_their_existing_empty_result() {
    empty_profile(RetainedConfigProfile::Legacy).await;
}

#[tokio::test]
async fn target_history_reads_use_the_profile_admitted_before_opening() {
    empty_profile(RetainedConfigProfile::NetconfTargetsV1).await;
}

#[tokio::test]
async fn target_history_revalidates_rows_before_even_an_empty_lookup() {
    let fixture = &fixtures()[0];
    for mutation in [
        "DELETE FROM config_netconf_profile",
        "DELETE FROM config_netconf_targets WHERE target=0",
        "DELETE FROM config_netconf_targets WHERE target=1",
        "DELETE FROM config_netconf_lifecycle",
        "UPDATE config_netconf_profile SET state_hmac=zeroblob(32)",
        "UPDATE config_netconf_targets SET state_hmac=zeroblob(32) WHERE target=0",
        "UPDATE config_netconf_targets SET state_hmac=zeroblob(32) WHERE target=1",
        "UPDATE config_netconf_lifecycle SET state_hmac=zeroblob(32)",
        "UPDATE config_netconf_targets SET state_json=(SELECT state_json FROM config_netconf_targets WHERE target=0), state_hmac=(SELECT state_hmac FROM config_netconf_targets WHERE target=0) WHERE target=1",
        "UPDATE config_raft_identity SET schema_version=5",
        "UPDATE config_raft_identity SET schema_manifest_digest=zeroblob(32)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        let options = options_for_profile(
            &path,
            fixture,
            0x41,
            RetainedConfigProfile::NetconfTargetsV1,
        );
        let backend = SqliteBackend::provision_config_authority(options, key(fixture))
            .await
            .unwrap();
        let independent = rusqlite::Connection::open(&path).unwrap();
        independent.execute_batch(mutation).unwrap();
        rejected_reads(&backend).await;
    }
}

#[tokio::test]
async fn target_history_revalidates_catalog_on_every_live_connection_read() {
    let fixture = &fixtures()[0];
    for mutation in [
        "DROP TABLE config_netconf_lifecycle",
        "CREATE INDEX unrelated ON config_netconf_targets(state_json)",
        "CREATE TRIGGER unrelated AFTER UPDATE ON config_netconf_targets BEGIN SELECT 1; END",
        "ALTER TABLE config_netconf_targets ADD COLUMN unrelated INTEGER",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        let options = options_for_profile(
            &path,
            fixture,
            0x41,
            RetainedConfigProfile::NetconfTargetsV1,
        );
        let backend = SqliteBackend::provision_config_authority(options, key(fixture))
            .await
            .unwrap();
        let independent = rusqlite::Connection::open(&path).unwrap();
        independent.execute_batch(mutation).unwrap();
        rewrite_supplied_catalog_digest(&independent);
        rejected_reads(&backend).await;
    }
}
