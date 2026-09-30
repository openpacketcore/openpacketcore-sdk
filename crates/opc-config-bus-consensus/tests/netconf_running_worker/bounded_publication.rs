//! Exercise the actual bounded Running adapter, without a publication substitute.

use super::*;

#[tokio::test]
async fn bounded_running_worker_clears_durable_marker_and_recovers_publication() {
    let f = Fixture::with_profiles(
        RetainedConfigProfile::NetconfRunningV1,
        opc_crypto::ConfigCapacityProfile::BoundedV1,
    )
    .await;
    let bus = ConfigBus::new_with_authorizer(
        Settings {
            label: "initial".into(),
        },
        f.encrypted.clone(),
        Arc::new(Authorizer::default()),
    )
    .await
    .unwrap();
    let audit = bus.required_netconf_audit().unwrap();
    let session = audit.open_session(&principal()).await.unwrap();
    let mut published = true;
    let mut marker_cleared = true;
    let mut same_original = true;
    let mut previous = None;
    for version in 0..2 {
        let request = request(version);
        let event = request_event(&request);
        let original = audit
            .replace_running(&session, &principal(), request, event)
            .await
            .unwrap();
        let NetconfMutationResult::Applied(receipt) = original else {
            published = false;
            break;
        };
        let stored = f.encrypted.load_latest().await.unwrap().unwrap();
        marker_cleared &= !stored.recovery_required;
        published &= receipt.published_commit().is_some_and(|commit| {
            commit.tx_id == stored.tx_id
                && commit.new_version == Some(ConfigVersion::new(version + 1))
        }) && !receipt.publication_pending()
            && !receipt.completion_pending()
            && bus.current_snapshot().tx_id == Some(stored.tx_id)
            && stored.config.label == format!("revision-{}", version + 1);
        let before = f.rows();
        let recovered = audit.recover(receipt.recovery_handle(), &principal()).await;
        same_original &= matches!(recovered, NetconfMutationResult::Applied(ref recovered)
            if recovered.outcome() == receipt.outcome()
                && recovered.published_commit().is_some_and(|commit| commit.tx_id == stored.tx_id)
                && !recovered.completion_pending()
                && !recovered.publication_pending());
        same_original &= f.rows() == before && history_count(&f) == version + 1;
        if !published || !marker_cleared {
            break;
        }
        // An unrelated or older transaction must not acknowledge this head.
        let before = f.rows();
        assert!(f
            .encrypted
            .clear_recovery_required(previous.unwrap_or_else(TxId::new))
            .await
            .is_err());
        assert_eq!(f.rows(), before, "BOUNDED_MARKER_WRONG_ORIGINAL");
        f.encrypted
            .clear_recovery_required(stored.tx_id)
            .await
            .unwrap();
        assert_eq!(f.rows(), before, "BOUNDED_MARKER_EXACT_REPLAY");
        previous = Some(stored.tx_id);
    }
    let two_commits = history_count(&f) == 2;
    drop(session);
    let drained = audit.shutdown().await.unwrap();
    drop(audit);
    drop(bus);
    f.close().await;
    assert!(
        published && marker_cleared && same_original && two_commits,
        "BOUNDED_RUNNING_PUBLICATION_MARKER: published={published} marker_cleared={marker_cleared} same_original={same_original} two_commits={two_commits}"
    );
    assert_eq!(drained, NetconfWorkerExit::Drained);
}

#[tokio::test]
async fn bounded_running_marker_refuses_uncheckpointed_outcome() {
    let f = Fixture::with_profiles(
        RetainedConfigProfile::NetconfRunningV1,
        opc_crypto::ConfigCapacityProfile::BoundedV1,
    )
    .await;
    let bus = ConfigBus::new_with_authorizer(
        Settings {
            label: "initial".into(),
        },
        f.encrypted.clone(),
        Arc::new(Authorizer::default()),
    )
    .await
    .unwrap();
    let audit = bus.required_netconf_audit().unwrap();
    let session = audit.open_session(&principal()).await.unwrap();
    // A fully settled earlier Running operation cannot authorize the new head.
    let first = request(0);
    let event = request_event(&first);
    let earlier = known(
        audit
            .replace_running(&session, &principal(), first, event)
            .await
            .unwrap(),
    );
    assert!(!earlier.completion_pending() && !earlier.publication_pending());
    f.checkpoint
        .fail_after_history_count
        .store(2, Ordering::Release);
    f.checkpoint
        .fail_after_effect
        .store(true, Ordering::Release);
    let request = request(1);
    let event = request_event(&request);
    let receipt = known(
        audit
            .replace_running(&session, &principal(), request, event)
            .await
            .unwrap(),
    );
    assert!(receipt.completion_pending() && receipt.publication_pending());
    let stored = f.encrypted.load_latest().await.unwrap().unwrap();
    assert!(stored.recovery_required);
    let before = f.rows();
    let refused = f
        .encrypted
        .clear_recovery_required(stored.tx_id)
        .await
        .is_err();
    let unchanged = f.rows() == before;
    f.checkpoint
        .fail_after_effect
        .store(false, Ordering::Release);
    let recovered = known(audit.recover(receipt.recovery_handle(), &principal()).await);
    let recovered_exactly = recovered.outcome() == receipt.outcome()
        && recovered
            .published_commit()
            .is_some_and(|commit| commit.tx_id == stored.tx_id)
        && !recovered.completion_pending()
        && !recovered.publication_pending()
        && !f
            .encrypted
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .recovery_required;
    drop(session);
    let drained = audit.shutdown().await.unwrap();
    drop(audit);
    drop(bus);
    f.close().await;
    assert!(
        refused && unchanged,
        "BOUNDED_MARKER_REQUIRES_CHECKPOINT: refused={refused} unchanged={unchanged}"
    );
    assert!(
        recovered_exactly,
        "BOUNDED_MARKER_ORIGINAL_RECOVERS_AFTER_CHECKPOINT"
    );
    assert_eq!(drained, NetconfWorkerExit::Drained);
}
