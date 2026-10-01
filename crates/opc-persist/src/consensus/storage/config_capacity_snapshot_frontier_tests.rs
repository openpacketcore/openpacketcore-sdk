//! Snapshot installation must preserve durable commit and apply ordering.

use super::*;

fn entry(term: u64, index: u64) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(term, ConsensusNodeId::new(1).expect("node")),
            index,
        ),
        payload: if index == 0 {
            EntryPayload::Membership(Membership::new(vec![members()], None))
        } else {
            EntryPayload::Blank
        },
    }
}

#[tokio::test]
async fn config_capacity_957_snapshot_advances_commit_and_reopens_before_or_after_purge() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let root = disk_fixture();
        let (_source, mut source_storage, _initial) = source_snapshot(&root, profile).await;
        source_storage
            .1
            .apply([entry(1, 1), entry(1, 2)])
            .await
            .expect("source committed snapshot prefix");
        let snapshot = source_storage
            .1
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("advanced native snapshot");
        for established in [false, true] {
            for purge in [false, true] {
                let directory = root.join(format!("target-{established}-{purge}"));
                std::fs::create_dir(&directory).expect("target directory");
                let options = options(&directory.join("state.sqlite"), profile, 0xA3);
                let target = SqliteBackend::provision_config_member_repair(options.clone(), key())
                    .await
                    .expect("native Durable target");
                let local_binding = binding(&target).await;
                let mut storage = open(
                    &target,
                    directory.join("snapshots"),
                    identity(0x92),
                    members(),
                )
                .await
                .expect("target storage");
                if established {
                    storage.1.apply([entry(1, 0)]).await.expect("old prefix");
                    storage
                        .0
                        .save_committed(Some(entry(1, 0).log_id))
                        .await
                        .expect("old committed prefix");
                }
                transfer(snapshot.snapshot.path(), &mut storage.1, &snapshot.meta)
                    .await
                    .expect("authenticated snapshot install");
                assert_eq!(
                    storage.0.read_committed().await.expect("durable committed"),
                    Some(entry(1, 2).log_id),
                    "CONFIG_CAPACITY_SNAPSHOT_COMMIT_RED: install must durably cover applied state"
                );
                assert_eq!(
                    storage.2.committed_index(),
                    Some(2),
                    "CONFIG_CAPACITY_SNAPSHOT_LIVE_COMMIT: status must cover the installed prefix before reopen"
                );
                if purge {
                    storage
                        .0
                        .purge(entry(1, 2).log_id)
                        .await
                        .expect("purge installed prefix");
                }
                assert_eq!(binding(&target).await, local_binding);
                drop(storage);
                drop(target);
                let reopened = SqliteBackend::reopen_config_authority(options, key())
                    .await
                    .expect("native retained reopen at either install boundary");
                let mut storage = open(
                    &reopened,
                    directory.join("snapshots"),
                    identity(0x92),
                    members(),
                )
                .await
                .expect("reopened native storage");
                assert_eq!(
                    storage.0.read_committed().await.expect("retained commit"),
                    Some(entry(1, 2).log_id)
                );
                assert_eq!(
                    storage.1.applied_state().await.expect("retained apply").0,
                    Some(entry(1, 2).log_id)
                );
                assert_eq!(binding(&reopened).await, local_binding);
            }
        }
    }
}

#[tokio::test]
async fn config_capacity_957_snapshot_preserves_newer_committed_log_suffix() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let root = disk_fixture();
        let (_source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
        let options = options(&root.join("target.sqlite"), profile, 0xA3);
        let target = SqliteBackend::provision_config_member_repair(options.clone(), key())
            .await
            .expect("native Durable target");
        let mut storage = open(
            &target,
            root.join("target-snapshots"),
            identity(0x92),
            members(),
        )
        .await
        .expect("target storage");
        storage
            .0
            .core
            .run_sqlite(move |conn| {
                sqlite::append_logs_sync(
                    conn,
                    identity(0x92),
                    &members(),
                    &[entry(1, 0), entry(1, 1), entry(1, 2)],
                    profile,
                )
            })
            .await
            .expect("native log suffix");
        storage
            .0
            .save_committed(Some(entry(1, 2).log_id))
            .await
            .expect("newer committed suffix");
        transfer(snapshot.snapshot.path(), &mut storage.1, &snapshot.meta)
            .await
            .expect("snapshot before committed suffix");
        assert_eq!(
            storage.0.read_committed().await.expect("committed suffix"),
            Some(entry(1, 2).log_id),
            "CONFIG_CAPACITY_SNAPSHOT_SUFFIX_RED: snapshot must never regress known commit"
        );
        assert_eq!(
            storage.2.committed_index(),
            Some(2),
            "snapshot status must preserve the newer committed suffix"
        );
        drop(storage);
        drop(target);
        let reopened = SqliteBackend::reopen_config_authority(options, key())
            .await
            .expect("reopen snapshot with committed suffix");
        let mut storage = open(
            &reopened,
            root.join("target-snapshots"),
            identity(0x92),
            members(),
        )
        .await
        .expect("reopened suffix storage");
        storage
            .1
            .apply([entry(1, 1), entry(1, 2)])
            .await
            .expect("apply original committed suffix exactly once");
        assert_eq!(
            storage.1.applied_state().await.expect("complete prefix").0,
            Some(entry(1, 2).log_id)
        );
    }
}

async fn reject_snapshot_behind_floor(term: u64, index: u64) {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let root = disk_fixture();
        let (_source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
        let target = SqliteBackend::provision_config_member_repair(
            options(&root.join("target.sqlite"), profile, 0xA3),
            key(),
        )
        .await
        .expect("native Durable target");
        let mut storage = open(
            &target,
            root.join("target-snapshots"),
            identity(0x92),
            members(),
        )
        .await
        .expect("target storage");
        storage
            .1
            .apply((0..=index).map(|index| entry(term, index)))
            .await
            .expect("newer applied authority");
        storage
            .0
            .save_committed(Some(entry(term, index).log_id))
            .await
            .expect("known committed authority");
        let before = authority_digest(&target).await;
        assert!(
            transfer(snapshot.snapshot.path(), &mut storage.1, &snapshot.meta)
                .await
                .is_err(),
            "CONFIG_CAPACITY_SNAPSHOT_FLOOR_RED: stale or conflicting snapshot must be rejected"
        );
        assert_eq!(
            before,
            authority_digest(&target).await,
            "rejection before effects"
        );
    }
}

#[tokio::test]
async fn config_capacity_957_snapshot_rejects_older_applied_prefix_before_effects() {
    reject_snapshot_behind_floor(1, 1).await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_rejects_conflicting_applied_prefix_before_effects() {
    reject_snapshot_behind_floor(2, 0).await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_rejects_conflicting_committed_prefix_before_effects() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let root = disk_fixture();
        let (_source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
        let target = SqliteBackend::provision_config_member_repair(
            options(&root.join("target.sqlite"), profile, 0xA3),
            key(),
        )
        .await
        .expect("native Durable target");
        let mut storage = open(
            &target,
            root.join("target-snapshots"),
            identity(0x92),
            members(),
        )
        .await
        .expect("target storage");
        storage
            .0
            .core
            .run_sqlite(move |conn| {
                sqlite::append_logs_sync(
                    conn,
                    identity(0x92),
                    &members(),
                    &[entry(2, 0), entry(2, 1), entry(2, 2)],
                    profile,
                )
            })
            .await
            .expect("independent committed log identity");
        storage
            .0
            .save_committed(Some(entry(2, 2).log_id))
            .await
            .expect("committed suffix before state-machine apply");
        let before = authority_digest(&target).await;
        assert!(
            transfer(snapshot.snapshot.path(), &mut storage.1, &snapshot.meta)
                .await
                .is_err(),
            "CONFIG_CAPACITY_SNAPSHOT_COMMITTED_IDENTITY_RED: imported prefix must match committed log"
        );
        assert_eq!(
            before,
            authority_digest(&target).await,
            "rejection before effects"
        );
    }
}

#[tokio::test]
async fn config_capacity_957_snapshot_reopen_keeps_hole_floor_and_identity_rejections() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        for fault in ["hole", "detached", "conflict"] {
            let root = disk_fixture();
            let (_source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
            let path = root.join("target.sqlite");
            let options = options(&path, profile, 0xA3);
            let target = SqliteBackend::provision_config_member_repair(options.clone(), key())
                .await
                .expect("native Durable target");
            let mut storage = open(
                &target,
                root.join("target-snapshots"),
                identity(0x92),
                members(),
            )
            .await
            .expect("target storage");
            storage
                .0
                .core
                .run_sqlite(move |conn| {
                    sqlite::append_logs_sync(
                        conn,
                        identity(0x92),
                        &members(),
                        &[entry(1, 0), entry(1, 1), entry(1, 2), entry(1, 3)],
                        profile,
                    )
                })
                .await
                .expect("intact committed log prefix");
            storage
                .0
                .save_committed(Some(entry(1, 3).log_id))
                .await
                .expect("known committed suffix");
            transfer(snapshot.snapshot.path(), &mut storage.1, &snapshot.meta)
                .await
                .expect("install snapshot without purging prefix");
            {
                let conn = target.conn();
                let conn = conn.lock().await;
                match fault {
                    "hole" => conn
                        .execute("DELETE FROM config_raft_log WHERE log_index = 1", [])
                        .expect("controlled interior hole"),
                    "detached" => conn
                        .execute("DELETE FROM config_raft_log WHERE log_index < 2", [])
                        .expect("controlled detached prefix"),
                    "conflict" => conn
                        .execute(
                            "UPDATE config_raft_log SET term = 2, entry_json = ?1 WHERE log_index = 0",
                            [serde_json::to_vec(&entry(2, 0)).expect("valid conflicting log encoding")],
                        )
                        .expect("controlled snapshot boundary conflict"),
                    _ => unreachable!("closed synthetic fault set"),
                };
            }
            drop(storage);
            drop(target);
            let retained_files = || {
                ["", "-wal", "-shm", "-journal", ".opc-retained"].map(|suffix| {
                    let mut name = path.as_os_str().to_os_string();
                    name.push(suffix);
                    match std::fs::read(PathBuf::from(name)) {
                        Ok(bytes) => Some(<[u8; 32]>::from(Sha256::digest(bytes))),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(_) => panic!("retained file observation failed"),
                    }
                })
            };
            let before = retained_files();
            assert!(
                matches!(
                    SqliteBackend::reopen_config_authority(options, key()).await,
                    Err(crate::RetainedConfigError::Rejected)
                ),
                "CONFIG_CAPACITY_SNAPSHOT_LINEAGE_RED: malformed retained prefix must be rejected"
            );
            assert_eq!(
                before,
                retained_files(),
                "rejection precedes retained effects"
            );
        }
    }
}
