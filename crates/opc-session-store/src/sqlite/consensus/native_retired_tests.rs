use super::*;
use crate::sqlite::SqliteSessionBackend;

fn fixture() -> (SqliteSessionBackend, SessionKey) {
    let (storage, lease) = crate::consensus::native::key_retention_tests::acquired_fixture();
    let backend = SqliteSessionBackend::in_memory().unwrap();
    {
        let conn = backend.conn.blocking_lock();
        initialize_schema_with_profile(
            &conn,
            storage.business.identity(),
            storage.business.members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
    }
    (backend, lease.key().clone())
}

fn tagged(conn: &mut Connection, key: &SessionKey, value: u64, tag: u64) {
    let tx = conn.transaction().unwrap();
    create(&tx).unwrap();
    ops::insert_or_replace_fence_sync(&tx, key, value).unwrap();
    insert(&tx, key, tag).unwrap();
    tx.commit().unwrap();
}

#[test]
fn native_epoch_admission_rejects_missing_tag_namespace() {
    let (backend, key) = fixture();
    let conn = backend.conn.blocking_lock();
    ops::insert_or_replace_fence_sync(&conn, &key, 7).unwrap();
    let retention = KeyRetention {
        retired_count: 1,
        retired_max: 7,
        ..KeyRetention::default()
    };
    assert!(
        validate(&conn, retention, &|| Ok(())).is_err(),
        "a snapshot with committed retirement metadata must carry its exact tag namespace"
    );
    assert!(
        !exists(&conn).unwrap(),
        "validation must not manufacture a missing namespace"
    );
}

#[test]
fn native_epoch_snapshot_tags_preserve_unsigned_epochs_and_complete_keys() {
    let (backend, key) = fixture();
    let mut conn = backend.conn.blocking_lock();
    let mut other = key.clone();
    other.tenant = TenantId::from_static("retired-key-other-tenant");
    let current_epoch = u64::MAX - 1;
    tagged(&mut conn, &key, 7, current_epoch);
    tagged(&mut conn, &other, 5, current_epoch - 1);
    let retention = KeyRetention {
        epoch: current_epoch,
        floor_prev: 6,
        floor_cur: 8,
        retired_count: 1,
        retired_max: 7,
        last_rotation: Some(crate::key_retention::RotationReason::Threshold),
    };
    validate(&conn, retention, &|| Ok(())).unwrap();
    assert_eq!(read(&conn, &key).unwrap(), Some(current_epoch));
    assert_eq!(read(&conn, &other).unwrap(), Some(current_epoch - 1));
    let before = conn.total_changes();
    for _ in 0..3 {
        validate(&conn, retention, &|| Ok(())).unwrap();
        assert_eq!(read(&conn, &key).unwrap(), Some(current_epoch));
    }
    assert_eq!(
        conn.total_changes(),
        before,
        "reads and validation are side-effect free"
    );
    let (target, _) = fixture();
    let mut target = target.conn.blocking_lock();
    ops::insert_or_replace_fence_sync(&target, &key, 7).unwrap();
    ops::insert_or_replace_fence_sync(&target, &other, 5).unwrap();
    let tx = target.transaction().unwrap();
    replace(&tx, &conn, &|| Ok(())).unwrap();
    tx.commit().unwrap();
    validate(&target, retention, &|| Ok(())).unwrap();
    assert_eq!(read(&target, &key).unwrap(), Some(current_epoch));
    assert_eq!(read(&target, &other).unwrap(), Some(current_epoch - 1));
}

#[test]
fn native_epoch_snapshot_tag_copy_rolls_back_on_cancellation() {
    let (source, key) = fixture();
    let mut source = source.conn.blocking_lock();
    let mut second = key.clone();
    second.tenant = TenantId::from_static("retired-key-second");
    tagged(&mut source, &key, 7, 2);
    tagged(&mut source, &second, 5, 1);
    let (target, _) = fixture();
    let mut target = target.conn.blocking_lock();
    tagged(&mut target, &key, 7, 0);
    let visits = std::cell::Cell::new(0);
    {
        let tx = target.transaction().unwrap();
        let error = replace(&tx, &source, &|| {
            visits.set(visits.get() + 1);
            if visits.get() == 2 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "copy cancelled"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
    assert_eq!(visits.get(), 2);
    assert_eq!(read(&target, &key).unwrap(), Some(0));
    assert_eq!(read(&target, &second).unwrap(), None);
    assert_eq!(read(&source, &key).unwrap(), Some(2));
    assert_eq!(read(&source, &second).unwrap(), Some(1));
}

#[test]
fn native_epoch_snapshot_tags_reject_age_type_orphan_and_counter_mismatches() {
    for case in 0..7 {
        let (backend, key) = fixture();
        let mut conn = backend.conn.blocking_lock();
        tagged(&mut conn, &key, 7, 2);
        let retention = KeyRetention {
            epoch: 2,
            floor_prev: 3,
            floor_cur: 5,
            retired_count: 1,
            retired_max: 7,
            last_rotation: Some(crate::key_retention::RotationReason::Threshold),
        };
        validate(&conn, retention, &|| Ok(())).unwrap();
        match case {
            0 => {
                conn.execute(
                    "UPDATE consensus_native_retired_keys SET epoch=?1",
                    [0u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            1 => {
                conn.execute(
                    "UPDATE consensus_native_retired_keys SET epoch=?1",
                    [3u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            2 => {
                conn.execute(
                    "UPDATE consensus_native_retired_keys SET epoch='abcdefgh'",
                    [],
                )
                .unwrap();
            }
            3 => {
                conn.execute("DELETE FROM key_fences", []).unwrap();
            }
            4 => {
                conn.execute("UPDATE key_fences SET fence=8", []).unwrap();
            }
            5 => {
                conn.execute_batch("DROP INDEX consensus_native_retired_epoch")
                    .unwrap();
            }
            6 => {
                conn.execute(
                    "UPDATE consensus_native_retired_keys SET epoch=?1",
                    [1u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let before = conn.total_changes();
        assert!(
            validate(&conn, retention, &|| Ok(())).is_err(),
            "case {case}"
        );
        assert_eq!(conn.total_changes(), before);
    }
}
