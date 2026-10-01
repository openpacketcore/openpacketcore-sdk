//! Legacy retained-opening compatibility controls for RFC 019 target profiles.
//! All identities and key material are synthetic. These controls do not qualify
//! the new target profile, checkpoint freshness, or configuration effects.

use hmac::{Hmac, KeyInit, Mac};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigError,
    RetainedConfigOptions, RetainedConfigProfile, SqliteBackend,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

struct LegacyBinding {
    key_epoch: u64,
    local_node: u64,
    members: &'static [u64],
    digest: &'static str,
}

fn fixtures() -> [LegacyBinding; 3] {
    [
        LegacyBinding {
            key_epoch: 1,
            local_node: 1,
            members: &[1],
            digest: "bbdef764b01c8f7e6ff1a0324d1af0170bf9bf4119d785d11c2a6aafe4aacb1a",
        },
        LegacyBinding {
            key_epoch: 2,
            local_node: 1,
            members: &[1],
            digest: "2829fcdc17f46e5416259fb1f984e900b66089532e0ec84a924b4576fb64ee55",
        },
        LegacyBinding {
            key_epoch: 1,
            local_node: 3,
            members: &[1, 3, 5],
            digest: "022923f3bb65068c4f5a8c1a702e622535eec974c79acdd24040053d9a4f7733",
        },
    ]
}

fn options(path: &Path, fixture: &LegacyBinding, backing: u8) -> RetainedConfigOptions {
    options_for_profile(path, fixture, backing, RetainedConfigProfile::Legacy)
}

fn options_for_profile(
    path: &Path,
    fixture: &LegacyBinding,
    backing: u8,
    profile: RetainedConfigProfile,
) -> RetainedConfigOptions {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology = ConfigConsensusTopology::try_new(
        identity,
        ConfigConsensusNodeId::new(fixture.local_node).unwrap(),
        fixture
            .members
            .iter()
            .map(|node| ConfigConsensusNodeId::new(*node).unwrap())
            .collect::<BTreeSet<_>>(),
    )
    .unwrap();
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [backing; 32], [0x42; 32])
            .unwrap()
            .with_profile(profile),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap()
}

fn key(fixture: &LegacyBinding) -> AuditKey {
    AuditKey::new_with_epoch([0x71; 32], fixture.key_epoch).unwrap()
}

fn assert_legacy_record(record: &[u8], fixture: &LegacyBinding, repair: bool) {
    assert_eq!(record.len(), 153, "legacy admission size changed");
    assert_eq!(&record[..8], b"OPCRET01");
    let expected: Vec<u8> = fixture
        .digest
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(&record[8..40], expected.as_slice());
    assert_eq!(record[72], u8::from(repair));
    // The nonce and filesystem identity vary. Authenticate the actual bytes
    // with the frozen predecessor domain and the synthetic fixture key.
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x71; 32]).unwrap();
    mac.update(b"openpacketcore/config-retained-admission/v1\0");
    mac.update(&record[..121]);
    mac.verify_slice(&record[121..]).unwrap();
}

#[tokio::test]
async fn legacy_retained_binding_bytes_and_disposition_survive_reopen() {
    for fixture in fixtures() {
        for repair in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.sqlite");
            let options = options(&path, &fixture, 0x41);
            let backend = if repair {
                SqliteBackend::provision_config_member_repair(options.clone(), key(&fixture))
                    .await
                    .unwrap()
            } else {
                SqliteBackend::provision_config_authority(options.clone(), key(&fixture))
                    .await
                    .unwrap()
            };
            drop(backend);
            let record_path = dir.path().join("legacy.sqlite.opc-retained");
            let before = std::fs::read(&record_path).unwrap();
            assert_legacy_record(&before, &fixture, repair);
            let reopened = SqliteBackend::reopen_config_authority(options, key(&fixture))
                .await
                .unwrap();
            drop(reopened);
            assert_eq!(std::fs::read(&record_path).unwrap(), before);
        }
    }
}

#[tokio::test]
async fn legacy_wrong_backing_rejection_preserves_storage_and_releases_admission() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite");
    drop(
        SqliteBackend::provision_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
    let snapshot = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = snapshot();
    let rejected =
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x43), key(fixture)).await;
    assert!(matches!(rejected, Err(RetainedConfigError::Rejected)));
    assert_eq!(snapshot(), before, "rejection changed original storage");
    drop(
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn retained_target_profile_provisions_and_reopens_with_exact_selection() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    // A removed refusal guard alone must not satisfy this detector. Require
    // the RFC format and complete bounded inactive target row set as well.
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let revision: u16 = conn
        .query_row(
            "SELECT schema_version FROM config_raft_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revision, 7, "target storage revision was not admitted");
    for (table, expected_rows) in [
        ("config_netconf_profile", 1),
        ("config_netconf_targets", 2),
        ("config_netconf_lifecycle", 1),
    ] {
        let count: u64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected_rows, "target row set is incomplete");
    }
    drop(conn);
    let record_path = dir.path().join("targets.sqlite.opc-retained");
    let before = std::fs::read(&record_path).unwrap();
    drop(
        SqliteBackend::reopen_config_authority(options, key(fixture))
            .await
            .unwrap(),
    );
    assert_eq!(std::fs::read(&record_path).unwrap(), before);
}

#[tokio::test]
async fn retained_target_selection_cannot_adopt_legacy_storage() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite");
    drop(
        SqliteBackend::provision_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
    let snapshot = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = snapshot();
    let selected = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    assert!(matches!(
        SqliteBackend::reopen_config_authority(selected, key(fixture)).await,
        Err(RetainedConfigError::Rejected)
    ));
    assert_eq!(
        snapshot(),
        before,
        "profile refusal changed original storage"
    );
    drop(
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
}

fn directory_bytes(path: &Path) -> std::collections::BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read(entry.path()).unwrap())
        })
        .collect()
}

// An attacker may rewrite the compatibility digest along with supplied DDL.
// Reproduce its historical byte formula independently; it must not replace
// comparison with the SDK-authored catalog.
fn rewrite_supplied_catalog_digest(conn: &rusqlite::Connection) {
    use sha2::Digest;
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL \
         AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'consensus_%' \
         AND name NOT LIKE 'config_raft_%' AND name != 'config_history_replay_lookup_idx' \
         ORDER BY type, name",
        )
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    let mut digest = Sha256::new();
    while let Some(row) = rows.next().unwrap() {
        for column in 0..3 {
            digest.update(row.get::<_, String>(column).unwrap().as_bytes());
            digest.update([if column == 2 { 0xff } else { 0 }]);
        }
    }
    let digest: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    conn.execute(
        "UPDATE schema_version SET schema_digest=?1 WHERE id=1",
        [digest],
    )
    .unwrap();
}

#[tokio::test]
async fn target_profile_catalog_tampering_is_rejected_before_original_wal_access() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    let pristine = std::fs::read(&path).unwrap();
    for mutation in [
        "DROP TABLE config_netconf_profile",
        "DROP TABLE config_netconf_targets",
        "DROP TABLE config_netconf_lifecycle",
        "ALTER TABLE config_netconf_targets ADD COLUMN unrelated INTEGER",
        "ALTER TABLE config_history ADD COLUMN unrelated INTEGER",
        "CREATE TABLE config_netconf_unrelated (value INTEGER)",
        "CREATE TABLE unrelated (value INTEGER)",
        "CREATE INDEX config_netconf_extra ON config_netconf_targets(state_json)",
        "CREATE INDEX unrelated ON config_netconf_targets(state_json)",
        "CREATE VIEW config_netconf_view AS SELECT 1",
        "CREATE TRIGGER config_netconf_extra AFTER UPDATE ON config_netconf_targets BEGIN SELECT 1; END",
        "CREATE TRIGGER unrelated AFTER UPDATE ON config_netconf_lifecycle BEGIN SELECT 1; END",
        "DROP TABLE config_netconf_lifecycle; CREATE VIEW config_netconf_lifecycle AS SELECT 1 AS singleton, X'00' AS state_json, zeroblob(32) AS state_hmac",
        "DROP INDEX config_history_replay_lookup_idx",
    ] {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(mutation).unwrap();
        rewrite_supplied_catalog_digest(&conn);
        drop(conn);
        let before = directory_bytes(dir.path());
        assert!(matches!(
            SqliteBackend::reopen_config_authority(options.clone(), key(fixture)).await,
            Err(RetainedConfigError::Rejected)
        ), "altered catalog was admitted");
        assert_eq!(directory_bytes(dir.path()), before, "rejection changed retained files");
        // Restore only this fixture's original bytes/inode. A successful exact
        // reopen also proves the failed attempt released its admission lock.
        std::fs::write(&path, &pristine).unwrap();
        drop(SqliteBackend::reopen_config_authority(options.clone(), key(fixture)).await.unwrap());
    }
}

#[tokio::test]
async fn target_profile_rejects_missing_substituted_and_unauthenticated_rows() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    let pristine = std::fs::read(&path).unwrap();
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
        "UPDATE config_netconf_lifecycle SET state_json=(SELECT state_json FROM config_netconf_profile), state_hmac=(SELECT state_hmac FROM config_netconf_profile)",
        "UPDATE config_netconf_profile SET state_json=CAST(replace(CAST(state_json AS TEXT),'\"format\":1','\"format\":2') AS BLOB)",
        "UPDATE config_netconf_targets SET state_json=substr(state_json,1,length(state_json)-1) WHERE target=0",
        "UPDATE config_raft_identity SET schema_version=5",
        "UPDATE config_raft_identity SET schema_manifest_digest=zeroblob(32)",
    ] {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(mutation).unwrap();
        drop(conn);
        let before = directory_bytes(dir.path());
        assert!(matches!(
            SqliteBackend::reopen_config_authority(options.clone(), key(fixture)).await,
            Err(RetainedConfigError::Rejected)
        ), "altered target state was admitted");
        assert_eq!(directory_bytes(dir.path()), before, "rejection changed retained files");
        std::fs::write(&path, &pristine).unwrap();
        drop(SqliteBackend::reopen_config_authority(options.clone(), key(fixture)).await.unwrap());
    }
}

#[tokio::test]
async fn valid_mac_cannot_authorize_an_unknown_or_noninactive_target_body() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    let pristine = std::fs::read(&path).unwrap();
    for (table, column, slot, domain, before, after) in [
        (
            "config_netconf_profile",
            "singleton",
            1,
            "profile",
            "\"format\":1",
            "\"format\":2",
        ),
        (
            "config_netconf_profile",
            "singleton",
            1,
            "profile",
            "\"capacity_profile\":0",
            "\"capacity_profile\":1",
        ),
        (
            "config_netconf_targets",
            "target",
            0,
            "target",
            "\"generation\":0",
            "\"generation\":18446744073709551615",
        ),
        (
            "config_netconf_targets",
            "target",
            1,
            "target",
            "\"present\":false",
            "\"present\":true",
        ),
        (
            "config_netconf_lifecycle",
            "singleton",
            1,
            "lifecycle",
            "\"format\":1",
            "\"format\":1,\"unknown\":0",
        ),
        (
            "config_netconf_lifecycle",
            "singleton",
            1,
            "lifecycle",
            "\"device_ownership\":null",
            "\"device_ownership\":{}",
        ),
    ] {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let encoded: Vec<u8> = conn
            .query_row(
                &format!("SELECT state_json FROM {table} WHERE {column}=?1"),
                [slot],
                |row| row.get(0),
            )
            .unwrap();
        let original = String::from_utf8(encoded).unwrap();
        assert_eq!(
            original.matches(before).count(),
            1,
            "control did not select one field"
        );
        let mutated = original.replace(before, after).into_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x71; 32]).unwrap();
        mac.update(format!("openpacketcore/config-netconf/{domain}/v1\0").as_bytes());
        mac.update(&(mutated.len() as u64).to_be_bytes());
        mac.update(&mutated);
        let mac = mac.finalize().into_bytes();
        conn.execute(
            &format!("UPDATE {table} SET state_json=?1, state_hmac=?2 WHERE {column}=?3"),
            rusqlite::params![mutated, mac.as_slice(), slot],
        )
        .unwrap();
        drop(conn);
        let before = directory_bytes(dir.path());
        assert!(matches!(
            SqliteBackend::reopen_config_authority(options.clone(), key(fixture)).await,
            Err(RetainedConfigError::Rejected)
        ));
        assert_eq!(
            directory_bytes(dir.path()),
            before,
            "rejection changed retained files"
        );
        std::fs::write(&path, &pristine).unwrap();
        drop(
            SqliteBackend::reopen_config_authority(options.clone(), key(fixture))
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn legacy_selection_cannot_open_target_profile_storage() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let target_options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(target_options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    let before = directory_bytes(dir.path());
    assert!(matches!(
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x41), key(fixture)).await,
        Err(RetainedConfigError::Rejected)
    ));
    assert_eq!(
        directory_bytes(dir.path()),
        before,
        "legacy refusal changed retained files"
    );
    drop(
        SqliteBackend::reopen_config_authority(target_options, key(fixture))
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn target_profile_rejects_an_internal_named_index_with_valid_sqlite_integrity() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.sqlite");
    let options = options_for_profile(
        &path,
        fixture,
        0x41,
        RetainedConfigProfile::NetconfTargetsV1,
    );
    drop(
        SqliteBackend::provision_config_authority(options.clone(), key(fixture))
            .await
            .unwrap(),
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE INDEX extra ON config_netconf_targets(state_json); \
         PRAGMA writable_schema=ON; \
         UPDATE sqlite_schema SET name='sqlite_autoindex_config_netconf_targets_1', \
         sql='CREATE INDEX sqlite_autoindex_config_netconf_targets_1 ON config_netconf_targets(state_json)' \
         WHERE name='extra'; \
         PRAGMA writable_schema=OFF;",
    ).unwrap();
    drop(conn);
    // This is valid SQLite, not an earlier malformed-schema refusal. Its
    // executable catalog still differs from the SDK's exact three tables.
    let check = rusqlite::Connection::open(&path).unwrap();
    let integrity: String = check
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let count: u64 = check.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name='sqlite_autoindex_config_netconf_targets_1' AND type='index'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 1);
    drop(check);
    let before = directory_bytes(dir.path());
    let result = SqliteBackend::reopen_config_authority(options, key(fixture)).await;
    assert!(
        matches!(result, Err(RetainedConfigError::Rejected)),
        "unrecognized internal-named index was admitted"
    );
    assert_eq!(
        directory_bytes(dir.path()),
        before,
        "rejection changed retained files"
    );
}

mod profile_reads;
