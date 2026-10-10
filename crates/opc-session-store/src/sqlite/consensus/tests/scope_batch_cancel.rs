use super::*;

impl Both {
    fn cut(&self) -> ScopeBatchReadCut {
        let conn = self.sql.conn.blocking_lock();
        let tx = conn.unchecked_transaction().unwrap();
        let cut = super::super::super::scope_batch::read_cut(&tx, identity(), &self.scope)
            .unwrap()
            .unwrap();
        tx.commit().unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(
            self.native
                .scope_batch_cut(identity(), &self.scope)
                .unwrap()
                .unwrap(),
            cut
        );
        cut
    }
    fn cancel_attempt(
        &mut self,
        request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        let result = self.apply(
            SessionMutationIntent::ScopeBatchCancel(Box::new(ScopeBatchCancelCommand {
                attempt: request.attempt().unwrap(),
            })),
            timestamp(4),
        );
        self.assert_rows();
        match result {
            SessionMutationOutcome::ScopeBatchCancel(result) => result,
            other => panic!("cancel result: {other:?}"),
        }
    }
}

#[test]
fn native_sqlite_cut_binds_reopen_and_negative_outcome_to_one_authority() {
    let mut both = Both::new(true);
    assert_eq!(both.cut(), ScopeBatchReadCut::Uninitialized);
    let stamp = both.admit();
    let request =
        ScopeBatchRequest::in_lane(&stamp, [1; 16], 7, 1, vec![create(1, &[])], vec![]).unwrap();
    let before = both.cut();
    assert_eq!(
        before.lookup(&request.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
    both.authority(
        stamp.revision(),
        ScopeAuthorityOperation::Close {
            current: stamp.clone(),
            evidence: crate::scope_authority::tests::evidence(
                crate::scope_authority::ScopeClosureKind::LocalQuiescence,
                2,
            ),
        },
        4,
    );
    let closed = both.cut();
    assert_eq!(
        closed.lookup(&request.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::NotApplied
    );
    assert_eq!(
        before.lookup(&request.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
    let ScopeBatchReopen::Initialized(view) = closed.reopen() else {
        panic!("initialized");
    };
    assert!(!view.authority().is_active());
    assert_eq!(view.revision(), 0);
    assert!(view
        .lanes()
        .iter()
        .all(|lane| lane.sequence() == 0 && lane.receipt().is_none()));
    let conn = both.sql.conn.blocking_lock();
    conn.execute(
        "DELETE FROM session_records WHERE key_type='opc-scope-batch'",
        [],
    )
    .unwrap();
    assert!(
        super::super::super::scope_batch::read_cut(&conn, identity(), &both.scope).is_err(),
        "required ledger loss cannot become Uninitialized or a negative outcome"
    );
}

#[test]
fn native_sqlite_apply_cancel_have_one_winner_and_no_ordinary_receipt() {
    for lane in [0, 7] {
        for apply_first in [true, false] {
            let mut both = Both::new(true);
            let stamp = both.admit();
            let request = ScopeBatchRequest::in_lane(
                &stamp,
                [1; 16],
                lane,
                1,
                vec![create(1, &[1])],
                vec![ScopeCounterMutation::new(0, 0, 5).unwrap()],
            )
            .unwrap();
            let command = ScopeBatchCommand {
                request: request.clone(),
            };
            let applied = apply_first.then(|| both.batch(&command, 4).unwrap());
            let receipt = both.cancel_attempt(&request).unwrap();
            assert_eq!(receipt.attempt(), &request.attempt().unwrap());
            assert_eq!(receipt.revision(), 1);
            match applied {
                Some(outcome) => {
                    assert_eq!(
                        receipt.terminal(),
                        &ScopeBatchTerminal::Applied(Box::new(outcome.clone()))
                    );
                    assert_eq!(both.batch(&command, 4), Ok(outcome));
                }
                None => {
                    assert_eq!(receipt.terminal(), &ScopeBatchTerminal::Cancelled);
                    assert_eq!(both.batch(&command, 4), Err(ScopeBatchError::Cancelled));
                    assert!(both
                        .row(&rows::child_key(stamp.namespace(), key(1)).unwrap())
                        .is_none());
                    assert!(both
                        .row(&rows::claim_key(stamp.namespace(), claim(1)).unwrap())
                        .is_none());
                }
            }
            let bytes = both.bytes();
            assert_eq!(both.cancel_attempt(&request).unwrap(), receipt);
            assert_eq!(
                both.bytes(),
                bytes,
                "replay cannot mutate any protected row"
            );
            let Some(ScopeRow::Batch(checkpoint)) =
                both.row(&rows::batch_key(&both.scope).unwrap())
            else {
                panic!("ledger required");
            };
            assert_eq!(checkpoint.counters[0], if apply_first { 5 } else { 0 });
            assert_eq!(checkpoint.birth_floor, u64::from(apply_first));
        }
    }
}

#[test]
fn native_sqlite_cancel_resolves_conflict_without_mutating_or_rebinding() {
    let mut both = Both::new(true);
    let stamp = both.admit();
    let first = both.command(&stamp, 1, 0, vec![create(1, &[])], vec![]);
    let outcome = both.batch(&first, 4).unwrap();
    let request = ScopeBatchRequest::in_lane(&stamp, [2; 16], 7, 1, vec![create(2, &[2])], vec![])
        .unwrap()
        .with_read_conditions(
            vec![ScopeChildCondition::new(
                key(1),
                ScopeChildRevision::new(outcome.rows()[0].birth(), 2).unwrap(),
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
    let command = ScopeBatchCommand {
        request: request.clone(),
    };
    let before = both.bytes();
    assert!(matches!(
        both.batch(&command, 4),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(
        both.bytes(),
        before,
        "a read conflict has no terminal receipt"
    );
    let receipt = both.cancel_attempt(&request).unwrap();
    assert_eq!(receipt.terminal(), &ScopeBatchTerminal::Cancelled);
    assert_eq!(receipt.revision(), 2);
    let before = both.bytes();
    let changed =
        ScopeBatchRequest::in_lane(&stamp, [2; 16], 6, 1, vec![create(3, &[])], vec![]).unwrap();
    assert_eq!(
        both.cancel_attempt(&changed),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    assert_eq!(both.batch(&command, 4), Err(ScopeBatchError::Cancelled));
    assert_eq!(both.bytes(), before);
}
