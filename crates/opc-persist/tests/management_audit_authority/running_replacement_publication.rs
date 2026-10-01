//! Real native Running effect and export, with the production prune reducer
//! checked at an expired logical time in rollback-only transactions.

use super::*;
use crate::consensus::audit::{self, ApplyContext, AuditCommand};

async fn acknowledged_export(f: &Fixture) -> AuditCheckpoint {
    let keys = f.store.inner.backend.management_audit_keys().unwrap();
    let export = f
        .store
        .freeze_audit_export(caller(), 0, LIFETIME)
        .await
        .unwrap();
    let mut verifier = AuditExportVerifier::new(
        keys,
        export.manifest().clone(),
        f.store.inner.identity,
        caller(),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let mut cursor = None;
    loop {
        let page = export.page(cursor.as_ref(), 1, caller()).unwrap();
        verifier
            .accept(&AuditExportPage::decode(&page.encode().unwrap()).unwrap())
            .unwrap();
        cursor = page.next_cursor().cloned();
        if cursor.is_none() {
            break;
        }
    }
    f.store
        .acknowledge_audit_export(&verifier.finish().unwrap(), caller())
        .await
        .unwrap();
    let shared = f.store.inner.backend.conn();
    let conn = shared.lock().await;
    audit::read_with_keys_sync(
        &conn,
        f.store.inner.backend.audit_key(),
        Some(&f.store.inner.backend.management_audit_keys().unwrap()),
        f.store.inner.identity,
    )
    .unwrap()
    .unwrap()
    .continuity
    .unwrap()
    .export_checkpoint
    .unwrap()
}

async fn prune_decision(f: &Fixture, checkpoint: &AuditCheckpoint, tx_id: TxId, protected: bool) {
    let backend = &f.store.inner.backend;
    let keys = backend.management_audit_keys().unwrap();
    let shared = backend.conn();
    let conn = shared.lock().await;
    let tx = conn.unchecked_transaction().unwrap();
    let ledger = audit::read_with_keys_sync(
        &tx,
        backend.audit_key(),
        Some(&keys),
        f.store.inner.identity,
    )
    .unwrap()
    .unwrap();
    let now = ledger
        .operations
        .iter()
        .map(|op| op.handle.body.expires_at)
        .max()
        .unwrap()
        + 1;
    // Prove every ordinary retention condition permits this exact cut. No
    // expiry/checkpoint/export refusal may impersonate the publication guard.
    let mut otherwise_prunable = ledger.clone();
    otherwise_prunable
        .prune(&keys, checkpoint.sequence(), checkpoint, now)
        .unwrap();
    assert!(otherwise_prunable.operations.is_empty());
    let cancellation = SqliteWorkCancellation::audit_test();
    let result = audit::apply_cancellable_for_mode_sync(
        &tx,
        backend.audit_key(),
        f.store.inner.identity,
        &AuditCommand::Prune {
            through: checkpoint.sequence(),
            checkpoint: checkpoint.clone(),
        },
        Some(&keys),
        &ApplyContext {
            logical_time: Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(now).unwrap(),
            ),
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xc3; 16]),
            cancellation: &cancellation,
        },
        RetainedConfigMode::NetconfRunningV1,
    )
    .unwrap();
    let after = audit::read_with_keys_sync(
        &tx,
        backend.audit_key(),
        Some(&keys),
        f.store.inner.identity,
    )
    .unwrap()
    .unwrap();
    if protected {
        assert!(
            result.is_err() && after == ledger,
            "BOUNDED_MARKER_RETAINS_PRUNABLE_ORIGINAL"
        );
    } else {
        assert!(
            result.is_ok() && after == otherwise_prunable,
            "BOUNDED_MARKER_RELEASES_PRUNABLE_ORIGINAL"
        );
        assert_eq!(
            crate::consensus::audit_targets::publication::authorize_clear_sync(
                &tx,
                backend.audit_key(),
                f.store.inner.identity,
                Some(&keys),
                tx_id,
                &cancellation,
            )
            .unwrap(),
            Ok(()),
            "BOUNDED_MARKER_PRUNED_EXACT_REPLAY"
        );
    }
    tx.rollback().unwrap();
}

#[tokio::test]
async fn joint_native_running_publication_requires_terminal_and_protects_pruning() {
    let f = fixture().await;
    let session = f.session().await;
    let plaintext = br#"{"enabled":true}"#;
    let (prepared, record) = prepare_with_marker(&f, &session, 2, plaintext, true).await;
    let intent = applied(
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, caller())
            .await,
    );
    let result = applied(
        f.store
            .submit_netconf_target_local(&prepared, &intent, caller())
            .await,
    );
    assert!(!result.terminal_recorded());
    // An independently checkpointed outcome is still not a terminal record.
    f.store.checkpoint_audit_tail().await.unwrap();
    let before = effect_rows(&f.store).await;
    let refused = f.store.clear_recovery_required(record.tx_id).await.is_err();
    assert!(
        refused && effect_rows(&f.store).await == before,
        "BOUNDED_MARKER_REQUIRES_TERMINAL"
    );
    f.store
        .complete_required_audit_outcome(&result, caller())
        .await
        .unwrap();
    let checkpoint = acknowledged_export(&f).await;
    prune_decision(&f, &checkpoint, record.tx_id, true).await;
    f.store.clear_recovery_required(record.tx_id).await.unwrap();
    let mut published = record.clone();
    published.principal = crate::types::clear_config_recovery_required(&record.principal)
        .unwrap()
        .unwrap();
    readback(&f.store, &f.provider, &published, plaintext).await;
    prune_decision(&f, &checkpoint, record.tx_id, false).await;
    drop(session);
    f.close().await;
}
