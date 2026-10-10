//! Every current reserved scope row must reach a freshly installed replica.
//! Compare complete persisted records, independently of the snapshot reader's
//! key-fence enumeration, and retain the same floors through later installs.

use super::*;
use crate::consensus::types::fenced_transition_voter_set_digest;
use crate::scope_authority::{
    ScopeAuthorityCheckpoint, ScopeAuthorityCommand, ScopeAuthorityOperation,
    ScopeAuthorityRequest, ScopeAuthorityStamp, ScopeClosureEvidence, ScopeClosureKind, ScopeId,
    ScopeProfileActivation, ScopeProfileContinuation,
};
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::{
    ScopeBatchCommand, ScopeBatchOutcome, ScopeBatchRequest, ScopeChildMutation,
    ScopeChildRevision, ScopeCounterMutation, SCOPE_BATCH_LANES, SCOPE_COUNTERS,
};
use crate::scope_storage::{self as rows, ContinuationRow, ScopeRow};
use crate::sqlite::consensus::wal::integration::PrivateWalTest;
use std::ops::Bound::Unbounded;

type RowKey = (String, String, String, Vec<u8>);
type Records = BTreeMap<RowKey, StoredSessionRecord>;

fn row_key(key: &SessionKey) -> RowKey {
    (
        key.tenant.to_string(),
        key.nf_kind.to_string(),
        key.key_type.to_string(),
        key.stable_id.as_ref().to_vec(),
    )
}

struct Store {
    directory: FixedRawReadStoreFixture,
    token: Option<Arc<PrivateWalTest>>,
    backend: Option<SqliteSessionBackend>,
    log: SqliteConsensusLogStore,
    machine: SqliteConsensusStateMachine,
}

impl Store {
    async fn open(native: bool) -> Self {
        let directory = portable_fixed_fixture();
        let token = native.then(|| {
            Arc::new(PrivateWalTest::new_native(
                directory.path().join("wal"),
                [0x93; 32],
            ))
        });
        Self::at(directory, token).await
    }

    async fn at(directory: FixedRawReadStoreFixture, token: Option<Arc<PrivateWalTest>>) -> Self {
        let (backend, log, machine) = if let Some(token) = &token {
            let (backend, log, machine) = Box::pin(open_private_snapshot_store_with_integrity(
                &directory,
                Arc::clone(token),
                SnapshotIntegrityPolicy::PortableVerified,
            ))
            .await
            .unwrap();
            (Some(backend), log, machine)
        } else {
            let (log, machine, _) = Box::pin(open_fixed_raw_read_store_with_integrity(
                &directory,
                None,
                SnapshotIntegrityPolicy::PortableVerified,
            ))
            .await;
            (None, log, machine)
        };
        Self {
            directory,
            token,
            backend,
            log,
            machine,
        }
    }

    async fn reopen(self, refused_install: bool) -> Self {
        if let Some(token) = &self.token {
            let shutdown = token.current().unwrap().shutdown();
            if refused_install {
                assert!(
                    shutdown.is_err(),
                    "a failed native installation fences its owner"
                );
            } else {
                shutdown.unwrap();
            }
        }
        let Self {
            directory,
            token,
            backend,
            log,
            machine,
        } = self;
        drop(machine);
        drop(log);
        drop(backend);
        Self::at(directory, token).await
    }

    fn shutdown(&self) {
        if let Some(token) = &self.token {
            token.current().unwrap().shutdown().unwrap();
        }
    }

    async fn records(&self) -> Records {
        if let Some(wal) = self.machine.core.private_wal.as_ref() {
            let capture = wal
                .native_scope_capture(&|| Ok(()), |_| Ok(true))
                .unwrap()
                .unwrap();
            wal.native_scope_read(&capture, &|| Ok(()), |captured, _| {
                Ok(captured
                    .records()
                    .range(Unbounded, Unbounded)
                    .map(|(key, record)| (row_key(key), record.clone()))
                    .collect())
            })
            .unwrap()
        } else {
            let conn = self.machine.core.conn.lock().await;
            // Enumerate the entire table rather than reusing the converter's
            // reserved-kind query or relying on ordinary key_fences rows.
            let mut statement = conn
                .prepare("SELECT tenant,nf_kind,key_type,stable_id FROM session_records")
                .unwrap();
            let keys = statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap();
            let mut records = Records::new();
            for key in keys {
                let (tenant, nf, kind, stable) = key.unwrap();
                let key =
                    crate::sqlite::ops::persisted_session_key(tenant, nf, kind, stable).unwrap();
                if rows::is_scope_record_key(&key) {
                    let record = crate::sqlite::ops::get_raw_sync(&conn, &key)
                        .unwrap()
                        .unwrap();
                    assert!(records.insert(row_key(&key), record).is_none());
                }
            }
            records
        }
    }

    async fn apply(&mut self, index: u64, intent: SessionMutationIntent) -> SessionMutationOutcome {
        let request_id = match &intent {
            SessionMutationIntent::ScopeAuthority(command) => *command.request.request_id(),
            SessionMutationIntent::ScopeBatch(command) => *command.request.request_id(),
            _ => (0x1193_0000 + u128::from(index)).to_be_bytes(),
        };
        let entry = normal_entry(
            index,
            SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(1),
                request_id: SessionConsensusRequestId::from_bytes(request_id),
                logical_time: timestamp(1),
                intent: SessionMutationIntent::Authorized {
                    origin: *fixed_raw_read_members().first().unwrap(),
                    authority_identity: identity(1),
                    mutation: Box::new(intent),
                },
            },
        );
        append_and_commit(&mut self.log, [entry.clone()], "scope snapshot leader").await;
        let response = self.machine.apply([entry]).await.unwrap().remove(0);
        assert_eq!(response.raft_log_index, index);
        response.result.unwrap()
    }

    async fn batch(&mut self, index: u64, request: ScopeBatchRequest) -> ScopeBatchOutcome {
        match self
            .apply(
                index,
                SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand { request })),
            )
            .await
        {
            SessionMutationOutcome::ScopeBatch(Ok(outcome)) => outcome,
            other => panic!("scope snapshot fixture batch must commit: {other:?}"),
        }
    }

    async fn authority(
        &mut self,
        index: u64,
        request: ScopeAuthorityRequest,
    ) -> ScopeAuthorityStamp {
        match self
            .apply(
                index,
                SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand { request })),
            )
            .await
        {
            SessionMutationOutcome::ScopeAuthority(Ok(checkpoint)) => {
                checkpoint.state().unwrap().view.stamp().unwrap().clone()
            }
            other => panic!("scope snapshot fixture authority must commit: {other:?}"),
        }
    }

    async fn snapshot(&mut self) -> Snapshot<SessionRaftTypeConfig> {
        self.machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap()
    }

    async fn install(
        &mut self,
        snapshot: &mut Snapshot<SessionRaftTypeConfig>,
    ) -> Result<(), Box<StorageError<SessionConsensusNodeId>>> {
        let receiving = receive_private_install_snapshot(&mut self.machine, snapshot).await;
        install_private_snapshot(&mut self.machine, &snapshot.meta, receiving)
            .await
            .map_err(Box::new)
    }
}

fn assert_same_records(leader: &Records, replica: &Records) {
    assert_eq!(
        replica.keys().collect::<Vec<_>>(),
        leader.keys().collect::<Vec<_>>(),
        "installed scope row keys must equal the leader, including system-tenant rows"
    );
    for (key, expected) in leader {
        assert_eq!(
            replica.get(key),
            Some(expected),
            "installed {} row must retain all metadata and exact payload bytes",
            key.2
        );
    }
}

fn assert_complete_fixture(records: &Records, round: u64) {
    let kinds: BTreeSet<_> = records.keys().map(|key| key.2.as_str()).collect();
    // The legacy lease kind is refusal-only. No current command creates it.
    assert_eq!(
        kinds,
        rows::RESERVED_KEY_TYPES
            .into_iter()
            .filter(|kind| *kind != "opc-scope-lease")
            .collect()
    );
    let mut children = [0; 2];
    let mut claims = [0; 2];
    for record in records.values() {
        assert_eq!(record.fence.get(), 0);
        if record.key.key_type.as_str() == "opc-scope-authority" {
            let state = ScopeAuthorityCheckpoint::from_record(record)
                .unwrap()
                .state()
                .unwrap();
            assert_eq!(state.view.revision(), round);
            assert_eq!(state.view.admission_generation_floor(), round);
            // Incarnation retirement is not an operation in the active profile.
            assert_eq!(state.view.retired_through(), 0);
            assert_eq!(state.view.current_incarnation().unwrap().get(), 1);
            continue;
        }
        match ScopeRow::from_record(record).unwrap() {
            ScopeRow::Batch(checkpoint) => {
                assert_eq!(checkpoint.revision, round * 2 * SCOPE_BATCH_LANES as u64);
                assert_eq!(checkpoint.birth_floor, round + 1);
                for (index, counter) in checkpoint.counters.into_iter().enumerate() {
                    assert_eq!(counter, round * 20 + index as u64);
                }
                for (sequence, floor, _) in checkpoint.lane_floors().unwrap() {
                    assert_eq!(sequence, round * 2);
                    assert_eq!(floor, round * 2 - 1);
                }
            }
            ScopeRow::Child(child) => children[usize::from(child.value.is_some())] += 1,
            ScopeRow::Claim(claim) => claims[usize::from(claim.owner.is_some())] += 1,
            ScopeRow::Activation(_) | ScopeRow::Continuation(_) => {}
        }
    }
    assert_eq!(
        children,
        [1, 1],
        "deleted and live children are both retained"
    );
    assert_eq!(claims, [1, 1], "released and held claims are both retained");
}

fn assert_floors_rise(before: &Records, after: &Records) {
    assert_eq!(before.len(), after.len());
    for (key, old) in before {
        let new = after.get(key).unwrap();
        if key.2 == "opc-scope-authority" {
            let view = |record| {
                ScopeAuthorityCheckpoint::from_record(record)
                    .unwrap()
                    .state()
                    .unwrap()
                    .view
            };
            let (old, new) = (view(old), view(new));
            assert!(new.revision() > old.revision());
            assert!(new.admission_generation_floor() > old.admission_generation_floor());
            assert!(new.retired_through() >= old.retired_through());
            assert!(
                new.current_incarnation().unwrap().get()
                    >= old.current_incarnation().unwrap().get()
            );
            continue;
        }
        match (
            ScopeRow::from_record(old).unwrap(),
            ScopeRow::from_record(new).unwrap(),
        ) {
            (ScopeRow::Batch(old), ScopeRow::Batch(new)) => {
                assert!(new.revision > old.revision);
                assert!(new.birth_floor > old.birth_floor);
                for (old, new) in old.counters.into_iter().zip(new.counters) {
                    assert!(new > old);
                }
                for (old, new) in old
                    .lane_floors()
                    .unwrap()
                    .into_iter()
                    .zip(new.lane_floors().unwrap())
                {
                    assert!(new.0 > old.0);
                    assert!(new.1 > old.1);
                }
            }
            (ScopeRow::Child(old), ScopeRow::Child(new)) => {
                assert!(new.batch_revision > old.batch_revision);
                assert!(new.revision.birth() >= old.revision.birth());
                if new.revision.birth() == old.revision.birth() {
                    assert!(new.revision.generation() > old.revision.generation());
                }
            }
            (ScopeRow::Claim(old), ScopeRow::Claim(new)) => assert!(new.revision > old.revision),
            (ScopeRow::Continuation(old), ScopeRow::Continuation(new)) => {
                assert!(new.log_index > old.log_index);
            }
            (ScopeRow::Activation(old), ScopeRow::Activation(new)) => assert_eq!(new, old),
            _ => panic!("scope row cannot change kind"),
        }
    }
}

async fn advance_rows(
    leader: &mut Store,
    stamp: &ScopeAuthorityStamp,
    index: &mut u64,
    round: u64,
) {
    for lane in 0..SCOPE_BATCH_LANES {
        let mut created = None;
        for step in 1..=2 {
            *index += 1;
            let operations = if lane != 0 {
                vec![]
            } else if step == 2 {
                vec![ScopeChildMutation::Delete {
                    key: key(2),
                    expected: created.unwrap(),
                }]
            } else if round == 1 {
                vec![create(1, &[1]), create(2, &[2])]
            } else {
                vec![
                    ScopeChildMutation::CompareAndSet {
                        key: key(1),
                        expected: ScopeChildRevision::new(1, 1).unwrap(),
                        value: value(3),
                        claims: vec![claim(1)],
                    },
                    create(2, &[2]),
                ]
            };
            let counters = (lane * 2..lane * 2 + 2)
                .map(|counter| {
                    let previous = if round == 1 && step == 1 {
                        0
                    } else {
                        ((round - 1) * 2 + step - 1) * 10 + counter as u64
                    };
                    ScopeCounterMutation::new(
                        counter as u8,
                        previous,
                        ((round - 1) * 2 + step) * 10 + counter as u64,
                    )
                    .unwrap()
                })
                .collect();
            let request = ScopeBatchRequest::in_lane(
                stamp,
                (0x1193_1000 + u128::from(*index)).to_be_bytes(),
                lane as u8,
                (round - 1) * 2 + step,
                operations,
                counters,
            )
            .unwrap();
            let outcome = leader.batch(*index, request).await;
            if lane == 0 && step == 1 {
                created = Some(outcome.rows()[1]);
            }
        }
    }
    assert_eq!(SCOPE_COUNTERS, SCOPE_BATCH_LANES * 2);

    // Fixed-quorum stores do not admit topology commands. Seed a valid retained
    // continuation solely to exercise that sixth row kind through the real
    // snapshot transport, including the native backend. This is not a claim of
    // native topology support; its ordinary creation is covered by the dynamic
    // SQLite scope-continuity tests. All active scope mutations above committed.
    let desired = SessionConsensusIdentity::new(
        identity(1).cluster_id(),
        SessionConsensusConfigurationId::from_bytes([0xA0 + round as u8; 32]),
        SessionConsensusConfigurationEpoch::new(2).unwrap(),
    );
    let continuation = ScopeRow::Continuation(Box::new(ContinuationRow {
        certificate: ScopeProfileContinuation {
            transition_id: [0xA0 + round as u8; 16],
            transition_digest: [0xA0 + round as u8; 32],
            predecessor: ScopeProfileActivation::new(
                identity(1),
                fenced_transition_voter_set_digest(identity(1), &fixed_raw_read_members()),
            ),
            successor: ScopeProfileActivation::new(
                desired,
                fenced_transition_voter_set_digest(desired, &fixed_raw_read_members()),
            ),
        },
        log_index: *index,
    }));
    let record = continuation.to_record().unwrap();
    assert_eq!(ScopeRow::from_record(&record).unwrap(), continuation);
    let conn = leader.machine.core.conn.lock().await;
    crate::sqlite::ops::insert_or_replace_scope_record_sync(&conn, &record).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM key_fences", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        0,
        "scope state has no ordinary key-fence entries"
    );
}

async fn scope_snapshot_all_rows(native: bool) {
    let mut leader = Store::open(false).await;
    append_commit_and_apply(
        &mut leader.log,
        &mut leader.machine,
        [fixed_initial_membership_entry()],
        "scope snapshot initial membership",
    )
    .await;
    assert_eq!(
        leader
            .apply(
                1,
                SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
                    identity(1),
                    fenced_transition_voter_set_digest(identity(1), &fixed_raw_read_members()),
                ))),
            )
            .await,
        SessionMutationOutcome::Unit
    );
    let scope = ScopeId::new(
        identity(1),
        TenantId::from_static("snapshot-scope-rows"),
        NetworkFunctionKind::smf(),
        [0x93; 32],
    )
    .unwrap();
    let mut stamp = leader
        .authority(
            2,
            ScopeAuthorityRequest::new(
                scope.clone(),
                [1; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: crate::scope_authority::tests::execution(1),
                },
            )
            .unwrap(),
        )
        .await;
    let mut index = 2;
    advance_rows(&mut leader, &stamp, &mut index, 1).await;
    let first = leader.records().await;
    assert_complete_fixture(&first, 1);
    let mut old_snapshot = leader.snapshot().await;

    let mut replica = Store::open(native).await;
    assert_eq!(replica.machine.applied_state().await.unwrap().0, None);
    assert!(
        replica.records().await.is_empty(),
        "fresh replica has no scope rows"
    );
    replica.install(&mut old_snapshot).await.unwrap();
    assert_same_records(&first, &replica.records().await);
    assert_eq!(
        replica.machine.applied_state().await.unwrap().0,
        Some(log_id(index))
    );

    index += 1;
    stamp = leader
        .authority(
            index,
            ScopeAuthorityRequest::new(
                scope,
                [2; 16],
                1,
                ScopeAuthorityOperation::SucceedClosed {
                    predecessor: stamp,
                    execution: crate::scope_authority::tests::execution(2),
                    evidence: ScopeClosureEvidence::new(
                        ScopeClosureKind::FinalTermination,
                        [2; 32],
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        )
        .await;
    advance_rows(&mut leader, &stamp, &mut index, 2).await;
    let second = leader.records().await;
    assert_complete_fixture(&second, 2);
    assert_floors_rise(&first, &second);
    let mut latest = leader.snapshot().await;
    replica.install(&mut latest).await.unwrap();
    assert_same_records(&second, &replica.records().await);

    // A native-installed replica must also be a complete snapshot donor. This
    // covers native-to-native as well as SQLite-to-native and SQLite-to-SQLite.
    let mut relay = replica.snapshot().await;
    let mut fresh = Store::open(native).await;
    assert!(fresh.records().await.is_empty());
    fresh.install(&mut relay).await.unwrap();
    assert_same_records(&second, &fresh.records().await);
    fresh = fresh.reopen(false).await;
    assert_same_records(&second, &fresh.records().await);
    fresh.shutdown();

    // A larger Raft cut is not permission to lower scope floors. Start another
    // honest store from the old snapshot and advance its command sequence and
    // log past the newer cut without mutating scope state. Generic sequence/log
    // checks alone cannot reject this otherwise valid image.
    let mut rollback = Store::open(false).await;
    rollback.install(&mut old_snapshot).await.unwrap();
    let old_index = old_snapshot.meta.last_log_id.unwrap().index;
    for next in old_index + 1..=index + 1 {
        assert_eq!(
            rollback
                .apply(next, SessionMutationIntent::AdvanceLogicalTime)
                .await,
            SessionMutationOutcome::Unit
        );
    }
    assert_same_records(&first, &rollback.records().await);
    let current_sequence = replica.machine.proposal_state().await.unwrap().0;
    assert!(rollback.machine.proposal_state().await.unwrap().0 > current_sequence);
    let mut regressing = rollback.snapshot().await;
    assert!(regressing.meta.last_log_id > latest.meta.last_log_id);
    assert!(
        replica.install(&mut regressing).await.is_err(),
        "a newer log and command sequence cannot lower retained scope floors"
    );
    // Native installation fails closed after a validation refusal. Reopening
    // the actual selected store, rather than consulting a cache or the donor,
    // proves that no durable scope row or floor changed on that failure.
    replica = replica.reopen(true).await;
    assert_same_records(&second, &replica.records().await);
    assert_eq!(
        replica.machine.applied_state().await.unwrap().0,
        Some(log_id(index))
    );
    assert_eq!(
        replica.machine.proposal_state().await.unwrap().0,
        current_sequence
    );
    replica.shutdown();
}

#[tokio::test]
async fn scope_snapshot_all_rows_native_install_and_reopen_preserve_rising_floors() {
    Box::pin(scope_snapshot_all_rows(true)).await;
}

#[tokio::test]
async fn scope_snapshot_all_rows_sqlite_install_and_reopen_preserve_rising_floors() {
    Box::pin(scope_snapshot_all_rows(false)).await;
}
