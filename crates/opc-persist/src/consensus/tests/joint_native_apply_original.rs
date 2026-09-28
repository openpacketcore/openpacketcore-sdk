//! Count actual retained-original work only inside the watched Apply reducer.
//! The native caller asserts after its unchanged durable/reopen/join lifecycle.

use super::*;
use std::sync::{Mutex, Weak};

#[derive(Clone, Copy, Debug, Default)]
struct Work {
    entered: usize,
    completed: usize,
    rows: usize,
    row_bytes: usize,
    identities: usize,
    continuities: usize,
    owned: usize,
    owned_bytes: usize,
    verified: usize,
    verified_bytes: usize,
    borrowed: usize,
    borrowed_bytes: usize,
    other_owned: usize,
    other_verified: usize,
}

struct Observation {
    handle: AuditOperationHandle,
    work: Mutex<Work>,
}

static WATCHES: Mutex<Vec<Weak<Observation>>> = Mutex::new(Vec::new());
thread_local! {
    static APPLY: RefCell<Option<Arc<Observation>>> = const { RefCell::new(None) };
}

pub(in crate::consensus) struct ApplyWatch(Arc<Observation>);

impl ApplyWatch {
    pub(in crate::consensus) fn start(handle: &AuditOperationHandle) -> Self {
        let mut watches = WATCHES.lock().unwrap();
        watches.retain(|watch| watch.strong_count() != 0);
        assert!(watches
            .iter()
            .filter_map(Weak::upgrade)
            .all(|watch| watch.handle != *handle));
        let observation = Arc::new(Observation {
            handle: handle.clone(),
            work: Mutex::new(Work::default()),
        });
        watches.push(Arc::downgrade(&observation));
        Self(observation)
    }

    fn finish(self) -> Work {
        let work = *self.0.work.lock().unwrap();
        drop(self);
        work
    }

    pub(in crate::consensus) fn assert_native_after_cleanup(self, retained_bytes: usize) {
        let work = self.finish();
        eprintln!("APPLY_ORIGINAL_NATIVE_DURABLE_REOPEN_JOIN_CLEANUP_COMPLETED {work:?}");
        // These independent live-operation/verification checks precede cost.
        assert_eq!(
            (work.entered, work.completed),
            (1, 1),
            "APPLY_ORIGINAL_NATIVE_ENTERED_AND_COMPLETED"
        );
        assert_eq!((work.rows, work.identities, work.continuities), (2, 2, 2));
        assert!(work.row_bytes > retained_bytes);
        assert!(work.other_owned > 0 && work.other_owned == work.other_verified);
        assert_eq!(work.owned, work.verified);
        assert_eq!(work.owned_bytes, work.verified_bytes);
        assert_eq!(work.verified + work.borrowed, 7);
        assert_eq!(
            work.verified_bytes + work.borrowed_bytes,
            7 * retained_bytes
        );
        assert_eq!(work.owned, 4, "APPLY_ORIGINAL_NATIVE_OWNED_DECODES");
        assert_eq!(work.borrowed, 3);
        assert_eq!(work.owned_bytes, 4 * retained_bytes);
        assert_eq!(work.borrowed_bytes, 3 * retained_bytes);
    }
}

impl Drop for ApplyWatch {
    fn drop(&mut self) {
        let registration = Arc::downgrade(&self.0);
        WATCHES
            .lock()
            .unwrap()
            .retain(|watch| !Weak::ptr_eq(watch, &registration));
    }
}

pub(in crate::consensus) struct ApplyScope {
    previous: Option<Arc<Observation>>,
    watched: Option<Arc<Observation>>,
}

impl ApplyScope {
    pub(in crate::consensus) fn enter(handle: &AuditOperationHandle) -> Self {
        let watched = WATCHES
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .find(|watch| watch.handle == *handle);
        if let Some(watch) = &watched {
            watch.work.lock().unwrap().entered += 1;
        }
        Self {
            previous: APPLY.with(|slot| slot.replace(watched.clone())),
            watched,
        }
    }

    pub(in crate::consensus) fn complete(&self) {
        if let Some(watch) = &self.watched {
            watch.work.lock().unwrap().completed += 1;
        }
    }
}

impl Drop for ApplyScope {
    fn drop(&mut self) {
        APPLY.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}

fn update(f: impl FnOnce(&AuditOperationHandle, &mut Work)) {
    APPLY.with(|slot| {
        if let Some(watch) = slot.borrow().as_ref() {
            f(&watch.handle, &mut watch.work.lock().unwrap());
        }
    });
}

pub(in crate::consensus) fn row_authenticated(bytes: usize) {
    update(|_, work| {
        work.rows += 1;
        work.row_bytes += bytes;
    });
}

pub(in crate::consensus) fn identity_verified(identity: ConfigConsensusIdentity) {
    update(|handle, work| {
        assert_eq!(identity, handle.body.identity);
        work.identities += 1;
    });
}

pub(in crate::consensus) fn continuity_verified() {
    update(|_, work| work.continuities += 1);
}

pub(in crate::consensus) fn owned_decoded(handle: &AuditOperationHandle, bytes: usize) {
    update(|watched, work| {
        if watched == handle {
            work.owned += 1;
            work.owned_bytes += bytes;
        } else {
            work.other_owned += 1;
        }
    });
}

pub(in crate::consensus) fn owned_verified(handle: &AuditOperationHandle, bytes: usize) {
    update(|watched, work| {
        if watched == handle {
            work.verified += 1;
            work.verified_bytes += bytes;
        } else {
            work.other_verified += 1;
        }
    });
}

pub(in crate::consensus) fn borrowed_verified(handle: &AuditOperationHandle, bytes: usize) {
    update(|watched, work| {
        if watched == handle {
            work.borrowed += 1;
            work.borrowed_bytes += bytes;
        }
    });
}

fn apply(
    conn: &Connection,
    f: &Fixture,
    keys: Option<&AuditKeyRing>,
    cancellation: &SqliteWorkCancellation,
    mode: RetainedConfigMode,
) -> io::Result<Result<(), crate::consensus::ConfigMutationFailure>> {
    apply_target_for_mode_sync(
        conn,
        &key(),
        identity(),
        f.original.command(),
        keys,
        &ApplyContext {
            logical_time: opc_types::Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(100).unwrap(),
            ),
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xc1; 16]),
            cancellation,
        },
        mode,
    )
}

fn apply_rejection(f: &Fixture) {
    let tx = f.conn.unchecked_transaction().unwrap();
    assert_eq!(
        apply(
            &tx,
            f,
            Some(&f.keys),
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1
        )
        .unwrap(),
        Err(crate::consensus::ConfigMutationFailure::Conflict),
        "the genuine missing-session reducer result",
    );
    tx.commit().unwrap();
}

fn settle(f: Fixture) {
    let ledger = f.ledger();
    let original = ledger
        .recover_target(
            &key(),
            f.original.handle(),
            f.original.command().effect.caller,
        )
        .unwrap();
    assert_eq!(original.command(), f.original.command());
    assert_eq!(
        ledger
            .lookup(
                &key(),
                f.original.handle(),
                f.original.command().effect.caller
            )
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
    drop(original);
    drop(ledger);
    f.apply(AuditCommand::Terminal(f.original.handle().clone()));
    f.checkpoint();
    assert!(f
        .ledger()
        .operations
        .iter()
        .all(|operation| operation.terminal_recorded));
    drop(f);
}

#[test]
fn joint_apply_original_rejection_finishes_before_cost_assertion() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let bytes = serde_json::to_vec(f.original.command()).unwrap().len();
    let watch = ApplyWatch::start(f.original.handle());
    apply_rejection(&f);
    let work = watch.finish();
    settle(f);
    eprintln!("APPLY_ORIGINAL_COMPONENT_RECOVERY_CHECKPOINT_CLEANUP_COMPLETED {work:?}");
    assert_eq!(
        (work.entered, work.completed),
        (1, 1),
        "APPLY_ORIGINAL_COMPONENT_ENTERED_AND_COMPLETED"
    );
    assert_eq!((work.rows, work.identities, work.continuities), (1, 1, 2));
    assert!(work.row_bytes > bytes);
    assert_eq!((work.other_owned, work.other_verified), (4, 4));
    assert_eq!(work.owned, work.verified);
    assert_eq!(work.owned_bytes, work.verified_bytes);
    assert_eq!(work.verified + work.borrowed, 5);
    assert_eq!(work.verified_bytes + work.borrowed_bytes, 5 * bytes);
    assert_eq!(work.owned, 2, "APPLY_ORIGINAL_COMPONENT_OWNED_DECODES");
    assert_eq!(work.borrowed, 3);
}

fn resign(ledger: &mut LedgerState, keys: &AuditKeyRing) {
    let mut previous = ledger.predecessor;
    for entry in &mut ledger.entries {
        entry.previous = previous;
        entry.mac = original_mac(
            &key(),
            b"openpacketcore/management-audit/replicated-entry/v1\0",
            &(
                identity(),
                entry.sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
        );
        previous = entry.mac;
    }
    ledger.terminal = previous;
    ledger.continuity = Some(ContinuityState::new(1));
    ledger.seal_continuity(Some(keys)).unwrap();
    ledger.validate_continuity(Some(keys)).unwrap();
}

#[test]
fn joint_apply_original_noncanonical_matching_bytes_use_real_fallback() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let mut ledger = f.ledger();
    let retained = ledger
        .entries
        .iter_mut()
        .find_map(|entry| match &mut entry.payload {
            EntryPayload::TargetIntent(retained) if &retained.handle == f.original.handle() => {
                Some(retained)
            }
            _ => None,
        })
        .unwrap();
    retained.recovery.push(' ');
    let actual_bytes = retained.recovery.len();
    resign(&mut ledger, &f.keys);
    let tx = f.conn.unchecked_transaction().unwrap();
    audit::write_sync(&tx, &key(), identity(), Some(ledger), false).unwrap();
    assert_row_mac(&tx, &key());
    let watch = ApplyWatch::start(f.original.handle());
    let result = apply(
        &tx,
        &f,
        Some(&f.keys),
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    );
    let work = watch.finish();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    tx.rollback().unwrap();
    assert_eq!(snapshot(&f.conn).rows, before.rows);
    // A matching hint with different bytes must run the real owned decoder;
    // canonical rejection occurs after that decoder and full retained verifier.
    assert_eq!(
        (work.rows, work.owned, work.owned_bytes),
        (1, 1, actual_bytes)
    );
    assert_eq!((work.verified, work.borrowed, work.completed), (0, 0, 0));
    assert_eq!(
        f.ledger()
            .lookup(
                &key(),
                f.original.handle(),
                f.original.command().effect.caller
            )
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Intent
    );
}

#[test]
fn joint_apply_original_fresh_authenticated_faults_roll_back() {
    for fault in 0..5 {
        let f = Fixture::new(4096);
        f.checkpoint();
        let before = snapshot(&f.conn);
        let mut bad_entry = f.ledger();
        bad_entry.entries[0].mac[0] ^= 1;
        let wrong_keys =
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0xc2; 32]).unwrap()]).unwrap();
        let tx = f.conn.unchecked_transaction().unwrap();
        match fault {
            0 => {
                tx.execute("UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1", []).unwrap();
            }
            1 => {
                audit::write_sync(&tx, &key(), identity(), Some(bad_entry), false).unwrap();
            }
            2 => {}
            3 => {
                let other = ConfigConsensusIdentity::new(
                    crate::ConfigConsensusClusterId::from_bytes([0xc3; 32]),
                    identity().configuration_id(),
                    identity().configuration_epoch(),
                );
                audit::write_sync(&tx, &key(), other, None, false).unwrap();
            }
            4 => {
                tx.execute(
                    "UPDATE config_raft_identity SET cluster_id=?1 WHERE singleton=1",
                    [[0xc4_u8; 32].as_slice()],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        if fault != 0 {
            assert_row_mac(&tx, &key());
        }
        let watch = ApplyWatch::start(f.original.handle());
        let result = apply(
            &tx,
            &f,
            Some(if fault == 2 { &wrong_keys } else { &f.keys }),
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        );
        let work = watch.finish();
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "fault={fault}"
        );
        tx.rollback().unwrap();
        assert_eq!(snapshot(&f.conn).rows, before.rows, "fault={fault}");
        assert_eq!(work.entered, 1);
        assert_eq!(work.completed, 0);
        assert_eq!(work.rows, usize::from(fault != 0));
        assert_eq!(work.continuities, 0);
        if fault == 2 {
            assert_eq!(work.identities, 1);
            assert_eq!(work.verified + work.borrowed, 1);
        }
        if matches!(fault, 3 | 4) {
            assert_eq!(work.identities, 0);
        }
        assert_eq!(
            f.ledger()
                .lookup(
                    &key(),
                    f.original.handle(),
                    f.original.command().effect.caller
                )
                .unwrap()
                .unwrap()
                .state(),
            AuditOperationState::Intent
        );
    }
}

#[test]
fn joint_apply_original_cancellation_rolls_back_then_retries() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let cancellation = SqliteWorkCancellation::audit_test();
    cancellation.cancel_for_history_gate_test();
    let tx = f.conn.unchecked_transaction().unwrap();
    let watch = ApplyWatch::start(f.original.handle());
    let result = apply(
        &tx,
        &f,
        Some(&f.keys),
        &cancellation,
        RetainedConfigMode::NetconfRunningV1,
    );
    let work = watch.finish();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    tx.rollback().unwrap();
    assert_eq!(snapshot(&f.conn).rows, before.rows);
    assert_eq!((work.entered, work.completed), (1, 0));
    apply_rejection(&f);
    settle(f);
}

#[test]
fn joint_apply_original_next_call_reauthenticates_changed_row() {
    let f = Fixture::new(4096);
    f.checkpoint();
    apply_rejection(&f);
    let good: (Vec<u8>, Vec<u8>) = f
        .conn
        .query_row(
            "SELECT state_json,state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    f.conn
        .execute(
            "UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1",
            [],
        )
        .unwrap();
    let tx = f.conn.unchecked_transaction().unwrap();
    let watch = ApplyWatch::start(f.original.handle());
    let result = apply(
        &tx,
        &f,
        Some(&f.keys),
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    );
    let work = watch.finish();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    tx.rollback().unwrap();
    assert_eq!(
        (work.entered, work.completed, work.rows, work.borrowed),
        (1, 0, 0, 0)
    );
    f.conn
        .execute(
            "UPDATE config_raft_management_audit SET state_json=?1,state_hmac=?2 WHERE singleton=1",
            rusqlite::params![good.0, good.1],
        )
        .unwrap();
    settle(f);
}

#[test]
fn joint_apply_original_autocommit_and_wrong_mode_do_not_lend() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let watch = ApplyWatch::start(f.original.handle());
    assert_eq!(
        apply(
            &f.conn,
            &f,
            Some(&f.keys),
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
    let work = watch.finish();
    assert_eq!((work.entered, work.borrowed, work.completed), (0, 0, 0));
    let tx = f.conn.unchecked_transaction().unwrap();
    let watch = ApplyWatch::start(f.original.handle());
    assert!(apply(
        &tx,
        &f,
        Some(&f.keys),
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfTargetsV1
    )
    .unwrap()
    .is_err());
    let work = watch.finish();
    tx.rollback().unwrap();
    assert_eq!((work.entered, work.borrowed, work.completed), (1, 0, 0));
    assert_eq!(snapshot(&f.conn).rows, before.rows);
}
