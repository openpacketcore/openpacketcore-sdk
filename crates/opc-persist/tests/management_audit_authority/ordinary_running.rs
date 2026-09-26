//! Ordinary running effects must share retained target and checkpoint fences.
use super::*;
use crate::consensus::audit_mutation::AuditedConfigEffect;

type RunningRow = (Vec<u8>, u64, Vec<u8>, Option<String>, bool, Option<String>);

fn running_rows(conn: &Connection) -> Vec<RunningRow> {
    conn.prepare("SELECT tx_id,version,encrypted_blob,confirmed_at,rollback_point,confirmed_deadline FROM config_history ORDER BY version")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn settle_ordinary(
    fixture: &Fixture,
    conn: &Connection,
    prepared: &crate::consensus::PreparedAuditedMutation,
) {
    fixture
        .apply(conn, AuditCommand::Terminal(prepared.handle.clone()), 100)
        .unwrap();
    fixture.checkpoint(conn);
}

#[tokio::test]
async fn ordinary_running_apply_requires_active_target_authority() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let before = target_rows(&conn);
    let prepared = fixture.ordinary_running(&conn, 210);
    fixture.admit_ordinary(&conn, &prepared);
    assert!(
        matches!(
            fixture.apply_ordinary(&conn, &prepared),
            Ok(Err(ConfigMutationFailure::Conflict))
        ),
        "inactive target authority allowed ordinary running effect"
    );
    assert!(target_rows(&conn) == before);
    assert!(running_rows(&conn).is_empty());
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(
                &fixture.key,
                prepared.handle(),
                prepared.handle.body.binding.caller
            )
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
}

#[tokio::test]
async fn ordinary_running_apply_preserves_unrelated_candidate_and_startup_locks() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    for slot in [1, 2] {
        let lock = fixture.request(&conn, 210 + slot, 2, 0x61 + slot, slot);
        assert!(matches!(
            fixture.submit(&conn, &lock),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &lock);
    }
    let before = target_rows(&conn);
    let prepared = fixture.ordinary_running(&conn, 213);
    fixture.admit_ordinary(&conn, &prepared);
    assert!(
        matches!(fixture.apply_ordinary(&conn, &prepared), Ok(Ok(()))),
        "unrelated target locks refused ordinary running effect"
    );
    assert!(target_rows(&conn) == before);
    assert_eq!(running_rows(&conn).len(), 1);
}

#[tokio::test]
async fn ordinary_running_apply_cannot_install_untracked_confirmation() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let before = target_rows(&conn);
    let deadline = opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(130).unwrap(),
    );
    let tentative = fixture.ordinary_running_at(0, None, Some(deadline), 210);
    fixture.admit_ordinary(&conn, &tentative);
    assert!(
        matches!(
            fixture.apply_ordinary(&conn, &tentative),
            Ok(Err(ConfigMutationFailure::Conflict))
        ),
        "ordinary append installed an untracked confirmed deadline"
    );
    assert!(target_rows(&conn) == before);
    assert!(running_rows(&conn).is_empty());
    settle_ordinary(&fixture, &conn, &tentative);
    let permanent = fixture.ordinary_running(&conn, 211);
    fixture.admit_ordinary(&conn, &permanent);
    assert!(matches!(
        fixture.apply_ordinary(&conn, &permanent),
        Ok(Ok(()))
    ));
}

#[tokio::test]
async fn ordinary_running_apply_preserves_original_pending_and_cleanup() {
    for cleanup in [false, true] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tentative = fixture.pending_fixture(&conn, false);
        assert!(matches!(
            fixture.submit(&conn, &tentative),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &tentative);
        if cleanup {
            let end = fixture.request(&conn, 210, 13, 0x61, 0);
            let end = fixture.rebind_at(&conn, end, 100);
            assert!(matches!(
                fixture.submit(&conn, &end),
                AuditOperationState::TargetV1(_)
            ));
            fixture.settle(&conn, &end);
            assert!(
                !row(&conn, "config_netconf_lifecycle", "singleton", 1)["cleanup"][0].is_null()
            );
        }
        let before = target_rows(&conn);
        let before_running = running_rows(&conn);
        assert_eq!(before_running.len(), 2);
        let pending_tx_id =
            opc_types::TxId::from_uuid(uuid::Uuid::from_slice(&before_running[1].0).unwrap());
        for choice in 0..5 {
            let prepared = fixture.ordinary_running(&conn, 220 + choice);
            let effect = match choice {
                0 => prepared.effect,
                1 => AuditedConfigEffect::Confirm {
                    tx_id: pending_tx_id,
                },
                2 => AuditedConfigEffect::RollbackPoint {
                    tx_id: pending_tx_id,
                    label: None,
                },
                _ => {
                    let AuditedConfigEffect::Append { commit, .. } = prepared.effect else {
                        panic!("ordinary append fixture");
                    };
                    AuditedConfigEffect::Append {
                        commit,
                        resolution: Some(if choice == 3 {
                            crate::ConfirmedCommitResolution::Confirm { pending_tx_id }
                        } else {
                            crate::ConfirmedCommitResolution::Rollback { pending_tx_id }
                        }),
                    }
                }
            };
            let prepared = fixture.ordinary_with_effect(effect, 2, 220 + choice);
            fixture.admit_ordinary(&conn, &prepared);
            assert!(
                matches!(
                    fixture.apply_ordinary(&conn, &prepared),
                    Ok(Err(ConfigMutationFailure::Conflict))
                ),
                "ordinary effect bypassed retained pending ownership"
            );
            assert!(target_rows(&conn) == before);
            assert!(running_rows(&conn) == before_running);
            settle_ordinary(&fixture, &conn, &prepared);
        }
        // The exact closed target resolution still succeeds after these refusals.
        let exact = fixture.resolve_fixture(&conn, 230, 11, cleanup, 100);
        assert!(matches!(
            fixture.submit(&conn, &exact),
            AuditOperationState::TargetV1(_)
        ));
        fixture.assert_no_pending(&conn);
        fixture.assert_running_plaintext(&conn, &exact);
    }
}

#[tokio::test]
async fn ordinary_running_apply_fences_already_admitted_effect_until_original_checkpoint() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let first = fixture.ordinary_running(&conn, 210);
    let AuditedConfigEffect::Append { commit, .. } = &first.effect else {
        panic!("ordinary append fixture");
    };
    let later = fixture.ordinary_running_at(1, Some(commit.record.tx_id), None, 211);
    fixture.admit_ordinary(&conn, &first);
    fixture.admit_ordinary(&conn, &later);
    assert!(matches!(fixture.apply_ordinary(&conn, &first), Ok(Ok(()))));
    let before = target_rows(&conn);
    let before_running = running_rows(&conn);
    for terminal_recorded in [false, true] {
        if terminal_recorded {
            fixture
                .apply(&conn, AuditCommand::Terminal(first.handle.clone()), 100)
                .unwrap();
        }
        let ledger = serde_json::to_vec(&fixture.ledger(&conn)).unwrap();
        assert!(
            matches!(fixture.apply_ordinary(&conn, &first), Ok(Ok(()))),
            "known commit was relabeled while terminal checkpoint was owed"
        );
        assert!(
            matches!(
                fixture.apply_ordinary(&conn, &later),
                Ok(Err(ConfigMutationFailure::InvalidInput))
            ),
            "already-admitted effect bypassed original terminal checkpoint debt"
        );
        assert!(serde_json::to_vec(&fixture.ledger(&conn)).unwrap() == ledger);
        assert!(target_rows(&conn) == before);
        assert!(running_rows(&conn) == before_running);
    }
    fixture.checkpoint(&conn);
    // Recover the identical admitted operation; no replacement or fresh intent.
    assert!(matches!(fixture.apply_ordinary(&conn, &later), Ok(Ok(()))));
    assert_eq!(running_rows(&conn).len(), 2);
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(
                &fixture.key,
                later.handle(),
                later.handle.body.binding.caller
            )
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Committed { version: 2 }
    );
    assert!(target_rows(&conn) == before);
}
