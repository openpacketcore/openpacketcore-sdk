use super::*;
use crate::consensus::native::generation::BaseParameters;
use crate::sqlite::consensus::native_snapshot::{Scope, ValidatedSource};
use rusqlite::backup::Backup;

#[test]
fn native_installed_sql_validated_source_matches_original_bytes_and_cold_state() {
    for phase in [Phase::Established, Phase::Aborted] {
        let (directory, producer, signed, wal) = fresh(phase);
        parity(
            &wal,
            &producer,
            &signed,
            &[admission(&signed), terminal(&signed, 4)],
        );
        let incoming =
            IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
        let destination = empty(&signed);
        let mut oracle = copy(&destination.conn.blocking_lock());
        let mut actual = copy(&destination.conn.blocking_lock());
        let incarnation = RestoreScanIncarnation::new().unwrap();
        let original_origin = incoming
            .source()
            .unwrap()
            .apply_native_original(
                &oracle,
                wal.binding(),
                Some(&signed.root),
                &incarnation,
                &|| Ok(()),
            )
            .unwrap();
        let expected_path = directory.path().join("original.native");
        let expected_prefix = written(
            &mut oracle,
            &expected_path,
            wal.binding(),
            original_origin,
            &signed,
        );
        let source = incoming.source().unwrap();
        let (origin, validated) = source
            .apply_native_validated(
                &mut actual,
                wal.binding(),
                Some(&signed.root),
                &incarnation,
                &|| Ok(()),
            )
            .unwrap();
        let actual_path = directory.path().join("validated.native");
        let members = fixed_members();
        let bindings = test_member_bindings(&members);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&actual_path)
            .unwrap();
        let prefix = {
            let prepared = SqlitePreparedBase::prepare_validated(
                validated,
                Scope {
                    identity: signed.identity,
                    members: &members,
                    bindings: &bindings,
                    placement: FIXED_TEST_PLACEMENT_POLICY.unwrap(),
                    root: Some(&signed.root),
                },
                Some(Arc::clone(&origin)),
                BaseParameters {
                    binding: wal.binding().digest().unwrap(),
                    file_epoch: 1,
                    checkpoint_epoch: 1,
                    operation_sequence: 0,
                    cut_binding: CUT,
                    block_bytes: BLOCK,
                    maximum: MAXIMUM,
                },
                &|| Ok(()),
            )
            .unwrap();
            prepared.write_to(&mut file, &|| Ok(())).unwrap()
        };
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(prefix, expected_prefix);
        assert_eq!(
            fs::read(&actual_path).unwrap(),
            fs::read(&expected_path).unwrap()
        );
        assert!(actual.is_autocommit());
        assert_eq!(database(&actual), database(&oracle));
        let storage = admitted(&actual_path, prefix, origin, &signed);
        complete_equal(&oracle, &storage, &signed);
    }
}

#[test]
fn native_installed_sql_validated_source_rejects_every_changed_scope() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let backend = empty(&signed);
    let members = fixed_members();
    let bindings = test_member_bindings(&members);
    let mut fewer_members = members.clone();
    fewer_members.pop_first();
    let mut fewer_bindings = bindings.clone();
    fewer_bindings.pop_first();
    let other_root = wrong_root(&signed);
    let scope = Scope {
        identity: signed.identity,
        members: &members,
        bindings: &bindings,
        placement: FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        root: Some(&signed.root),
    };
    for changed in 0..6 {
        let mut conn = copy(&backend.conn.blocking_lock());
        let before = database(&conn);
        let validated = ValidatedSource::new(&mut conn, scope, &|| Ok(())).unwrap();
        assert!(
            validated
                .connection()
                .execute(
                    "UPDATE lease_globals SET val=val+1 WHERE key='next_fence'",
                    [],
                )
                .is_err(),
            "the retained read source cannot modify its image"
        );
        let mut expected = scope;
        match changed {
            0 => {
                expected.identity = SessionConsensusIdentity::new(
                    crate::consensus::SessionConsensusClusterId::new("different-validated-source")
                        .unwrap(),
                    crate::consensus::SessionConsensusConfigurationId::from_bytes([0xF1; 32]),
                    crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
                )
            }
            1 => expected.members = &fewer_members,
            2 => expected.bindings = &fewer_bindings,
            3 => expected.placement = PlacementResiliencePolicy::AllowReducedResilience,
            4 => expected.root = None,
            5 => expected.root = Some(&other_root),
            _ => unreachable!(),
        }
        assert!(
            validated.into_parts(expected, &|| Ok(())).is_err(),
            "scope field {changed}"
        );
        assert!(conn.is_autocommit());
        assert_eq!(database(&conn), before);
    }
}

#[test]
fn native_installed_sql_validated_source_keeps_one_read_image_and_releases_on_cancel() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let backend = empty(&signed);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let mut conn = Connection::open(&path).unwrap();
    Backup::new(&backend.conn.blocking_lock(), &mut conn)
        .unwrap()
        .run_to_completion(128, Duration::ZERO, None)
        .unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    let members = fixed_members();
    let bindings = test_member_bindings(&members);
    let scope = Scope {
        identity: signed.identity,
        members: &members,
        bindings: &bindings,
        placement: FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        root: Some(&signed.root),
    };
    let read_fence = |conn: &Connection| {
        conn.query_row(
            "SELECT val FROM lease_globals WHERE key='next_fence'",
            [],
            |row| row.get::<_, u64>(0),
        )
        .unwrap()
    };
    let before = read_fence(&conn);
    let validated = ValidatedSource::new(&mut conn, scope, &|| Ok(())).unwrap();
    let external = Connection::open(&path).unwrap();
    external
        .execute(
            "UPDATE lease_globals SET val=val+1 WHERE key='next_fence'",
            [],
        )
        .unwrap();
    assert_eq!(read_fence(&external), before + 1);
    let (tx, _metadata, _memory) = validated.into_parts(scope, &|| Ok(())).unwrap();
    assert_eq!(
        read_fence(&tx),
        before,
        "later conversion reads retain the complete audited SQL image"
    );
    drop(tx);
    assert!(conn.is_autocommit());
    assert_eq!(read_fence(&conn), before + 1);
    let validated = ValidatedSource::new(&mut conn, scope, &|| Ok(())).unwrap();
    let error =
        match validated.into_parts(scope, &|| Err(io::Error::from(io::ErrorKind::Interrupted))) {
            Ok(_) => panic!("cancelled source was consumed"),
            Err(error) => error,
        };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(conn.is_autocommit());
    assert!(
        ValidatedSource::new(&mut conn, scope, &|| Err(io::Error::from(
            io::ErrorKind::Interrupted
        )))
        .is_err()
    );
    assert!(conn.is_autocommit());
}
