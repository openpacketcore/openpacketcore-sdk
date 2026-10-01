//! Ordinary Patch keeps its request operation through the retained worker.
//! This reuses the real singleton, Ephemeral retained store and key provider.
//! It does not qualify native quorum, Durable/Async or protocol dispatch.

use super::*;
use opc_persist::audit_authority::{
    AuditOperationHandle, AuditOperationState, ProjectedAuditEvent,
};

type Checks = Vec<(&'static str, bool)>;

struct Expected {
    request: RequestId,
    operation: ConfigOperation,
    transport: TransportType,
    base: ConfigVersion,
    parent: Option<TxId>,
    label: String,
    event: AuditEvent,
}

impl Expected {
    fn new(
        request: &CommitRequest<Settings>,
        operation: AuditOperation,
        parent: Option<TxId>,
    ) -> Self {
        Self {
            request: request.request_id,
            operation: request.operation,
            transport: request.transport,
            base: request.base_version,
            parent,
            label: request.candidate.as_ref().unwrap().label.clone(),
            event: AuditEvent::new(
                request.request_id,
                &request.principal,
                request.transport,
                operation,
                AuditOutcome::Intent,
            ),
        }
    }
}

fn patch_request(version: u64) -> CommitRequest<Settings> {
    let mut request = request(version);
    request.operation = ConfigOperation::Patch;
    request.transport = TransportType::NetconfTls;
    request
}

fn capture(
    result: NetconfMutationResult,
    checks: &mut Checks,
    marker: &'static str,
) -> Option<NetconfAppliedReceipt> {
    if let NetconfMutationResult::Applied(receipt) = result {
        checks.push((marker, true));
        Some(receipt)
    } else {
        checks.push((marker, false));
        None
    }
}

fn finish(checks: Checks, marker: &str) {
    let total = checks.len();
    let failures: Vec<_> = checks
        .into_iter()
        .filter_map(|(name, passed)| (!passed).then_some(name))
        .collect();
    eprintln!("{marker}_OBSERVATIONS total={total} failures={failures:?}");
    assert!(failures.is_empty(), "{marker}: {failures:?}");
    eprintln!("{marker}_PASS");
}

async fn close_worker(worker: Worker) -> NetconfWorkerExit {
    let exit = worker.audit.shutdown().await.unwrap();
    drop(worker);
    exit
}

// The protected token is inspected only after the real SDK authenticates it.
// SQL then counts retained originals; it supplies no effect, receipt or authority.
async fn observe_audit(
    f: &Fixture,
    receipt: &NetconfAppliedReceipt,
    expected: &Expected,
    checks: &mut Checks,
) {
    let privacy = AuditPrivacyKey::new([0x39; 32]).unwrap();
    let caller = AuditCaller::project(
        &privacy,
        principal().tenant.as_str(),
        &opc_mgmt_audit::principal_descriptor(&principal()),
    )
    .unwrap();
    let encoded = receipt.recovery_handle().encode().unwrap();
    let handle = AuditOperationHandle::decode(&encoded).unwrap();
    let authenticated = f
        .store
        .lookup_audit_operation(&handle, caller)
        .await
        .unwrap()
        .unwrap();
    checks.push((
        "RUNNING_PATCH_AUTHENTICATED_OUTCOME",
        authenticated.handle() == &handle
            && authenticated.terminal_recorded()
            && matches!(authenticated.state(), AuditOperationState::TargetV1(target)
                if target.outcome() == receipt.outcome()),
    ));
    let actual: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let projected = serde_json::to_value(
        ProjectedAuditEvent::project(&privacy, &sdk_event(&expected.event)).unwrap(),
    )
    .unwrap();
    checks.push((
        "RUNNING_PATCH_ORIGINAL_AUDIT_EVENT",
        actual["body"]["event"] == projected,
    ));
    let conn = rusqlite::Connection::open_with_flags(
        f.directory.path().join("authority.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_management_audit WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let operations = state["ledger"]["operations"].as_array().unwrap();
    let same_request = operations
        .iter()
        .filter(|original| original["handle"]["body"]["event"]["request"] == projected["request"])
        .count();
    let replace = serde_json::to_value(ManagementAuditOperationCode::Replace).unwrap();
    let update = serde_json::to_value(ManagementAuditOperationCode::Update).unwrap();
    let ordinary = operations
        .iter()
        .filter(|original| {
            let event = &original["handle"]["body"]["event"];
            event["caller"] == projected["caller"]
                && (event["operation"] == replace || event["operation"] == update)
        })
        .count();
    checks.push(("RUNNING_PATCH_ONE_ORIGINAL_REQUEST", same_request == 1));
    checks.push((
        "RUNNING_PATCH_NO_INVENTED_ORIGINAL",
        u64::try_from(ordinary).unwrap() == history_count(f),
    ));
}

async fn observe_readback(
    f: &Fixture,
    w: &Worker,
    receipt: &NetconfAppliedReceipt,
    expected: &Expected,
    checks: &mut Checks,
) {
    let NetconfAppliedOutcome::RunningReplaced {
        tx_id,
        running_version,
        plaintext_digest,
    } = receipt.outcome()
    else {
        checks.push(("RUNNING_PATCH_RUNNING_OUTCOME", false));
        return;
    };
    checks.push((
        "RUNNING_PATCH_PUBLICATION",
        !receipt.completion_pending()
            && !receipt.publication_pending()
            && receipt.terminal_recorded()
            && receipt.published_commit().is_some_and(|result| {
                result.tx_id == tx_id
                    && result.new_version == Some(ConfigVersion::new(running_version))
            }),
    ));
    let raw = f.store.load_latest().await.unwrap().unwrap();
    checks.push((
        "RUNNING_PATCH_EXACT_ENCRYPTED_EFFECT",
        raw.record.tx_id == tx_id
            && raw.record.version.get() == running_version
            && raw.record.plaintext_digest.as_slice() == plaintext_digest.as_slice()
            && !raw.record.encrypted_blob.is_empty(),
    ));
    let decoded = f.encrypted.load_latest().await.unwrap().unwrap();
    checks.push((
        "RUNNING_PATCH_DECRYPTED_ORIGINAL",
        decoded.tx_id == tx_id
            && decoded.version.get() == expected.base.get() + 1
            && decoded.parent_tx_id == expected.parent
            && decoded.principal == principal()
            && decoded.source == RequestSource::Northbound
            && decoded.request_id == Some(expected.request)
            && decoded.plaintext_digest == Some(plaintext_digest)
            && decoded.config.label == expected.label,
    ));
    checks.push((
        "RUNNING_PATCH_DURABLE_MARKER_CLEARED",
        !decoded.recovery_required,
    ));
    checks.push((
        "RUNNING_PATCH_PROVIDER_DECRYPTED",
        f.provider.lookup.load(Ordering::Acquire) > 0,
    ));
    checks.push((
        "RUNNING_PATCH_ENCRYPTED_FINGERPRINT_OPERATION",
        decoded
            .request_fingerprint
            .as_ref()
            .is_some_and(|fingerprint| {
                fingerprint.operation == expected.operation
                    && fingerprint.transport == expected.transport
                    && fingerprint.base_version == Some(expected.base)
                    && matches!(fingerprint.mode, opc_config_bus::StoredRequestMode::Commit)
            }),
    ));
    let snapshot = w.bus.current_snapshot();
    checks.push((
        "RUNNING_PATCH_EXACT_PUBLISHED_MODEL",
        snapshot.tx_id == Some(tx_id)
            && snapshot.version == decoded.version
            && snapshot.config.as_ref() == &decoded.config,
    ));
    let by_request = f
        .encrypted
        .load_by_request_id(expected.request)
        .await
        .unwrap();
    checks.push((
        "RUNNING_PATCH_ENCRYPTED_REQUEST_LOOKUP",
        by_request.is_some_and(|record| {
            record.tx_id == tx_id && record.request_fingerprint == decoded.request_fingerprint
        }),
    ));
    observe_audit(f, receipt, expected, checks).await;
}

#[tokio::test]
async fn ordinary_patch_keeps_encrypted_operation_and_original_recovery() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let mut checks = Checks::new();
    // The first genuine Replace establishes a nonempty frozen base. Both Patch
    // transports must then preserve their distinct original operation.
    for (version, (operation, audit, transport)) in [
        (
            ConfigOperation::Replace,
            AuditOperation::Replace,
            TransportType::NetconfSsh,
        ),
        (
            ConfigOperation::Patch,
            AuditOperation::Update,
            TransportType::NetconfTls,
        ),
        (
            ConfigOperation::Patch,
            AuditOperation::Update,
            TransportType::NetconfSsh,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = request(u64::try_from(version).unwrap());
        request.operation = operation;
        request.transport = transport;
        let expected = Expected::new(&request, audit, w.bus.current_snapshot().tx_id);
        let result = w
            .audit
            .replace_running(&owner, &principal(), request, expected.event.clone())
            .await
            .unwrap();
        let Some(receipt) = capture(result, &mut checks, "RUNNING_PATCH_ORIGINAL_EFFECT") else {
            break;
        };
        observe_readback(&f, &w, &receipt, &expected, &mut checks).await;
        let before = f.rows();
        let recovered = w
            .audit
            .recover(receipt.recovery_handle(), &principal())
            .await;
        if let Some(recovered) = capture(recovered, &mut checks, "RUNNING_PATCH_HANDLE_RECOVERY") {
            checks.push((
                "RUNNING_PATCH_SAME_HANDLE_OUTCOME",
                recovered.outcome() == receipt.outcome(),
            ));
        }
        let recovered = w
            .audit
            .recover_request(expected.request, &principal())
            .await
            .unwrap();
        checks.push((
            "RUNNING_PATCH_REQUEST_RECOVERY_PRESENT",
            recovered.is_some(),
        ));
        if let Some(recovered) = recovered {
            if let Some(recovered) =
                capture(recovered, &mut checks, "RUNNING_PATCH_REQUEST_RECOVERY")
            {
                checks.push((
                    "RUNNING_PATCH_SAME_REQUEST_OUTCOME",
                    recovered.outcome() == receipt.outcome(),
                ));
            }
        }
        checks.push(("RUNNING_PATCH_RECOVERY_NO_NEW_EFFECT", f.rows() == before));
    }
    checks.push(("RUNNING_PATCH_EXACT_EFFECT_COUNT", history_count(&f) == 3));
    checks.push((
        "RUNNING_PATCH_ENCRYPT_ONCE",
        f.provider.active.load(Ordering::Acquire) == 3,
    ));
    checks.push((
        "RUNNING_PATCH_NACM_EACH_MODEL",
        w.authorizer.calls.load(Ordering::Acquire) == 3,
    ));
    drop(owner);
    let exit = close_worker(w).await;
    checks.push((
        "RUNNING_PATCH_CLEAN_DRAIN",
        exit == NetconfWorkerExit::Drained,
    ));
    f.close().await;
    eprintln!("RUNNING_PATCH_LIFECYCLE case=original worker_joined=true storage_closed=true exit={exit:?}");
    finish(checks, "RUNNING_PATCH_ORIGINAL_DETECTOR");
}

#[tokio::test]
async fn ordinary_patch_wrong_operation_pairs_refuse_before_provider_or_intent() {
    let mut checks = Checks::new();
    for (operation, audit) in [
        (ConfigOperation::Patch, AuditOperation::Replace),
        (ConfigOperation::Replace, AuditOperation::Update),
        (ConfigOperation::Patch, AuditOperation::Delete),
        (ConfigOperation::Delete, AuditOperation::Delete),
        (ConfigOperation::Rollback, AuditOperation::Rollback),
    ] {
        let f = Fixture::new().await;
        let w = Worker::new(&f).await;
        let owner = w.audit.open_session(&principal()).await.unwrap();
        let mut request = request(0);
        request.operation = operation;
        let expected = Expected::new(&request, audit, None);
        let before = f.rows();
        let calls = f.provider.calls();
        let result = w
            .audit
            .replace_running(&owner, &principal(), request, expected.event)
            .await
            .unwrap();
        checks.push(("RUNNING_PATCH_PAIRING_REFUSED", matches!(result,
            NetconfMutationResult::Refused(ref error) if error.code == CommitErrorCode::AdmissionRejected)));
        checks.push((
            "RUNNING_PATCH_PAIRING_BEFORE_PROVIDER",
            f.provider.calls() == calls,
        ));
        checks.push(("RUNNING_PATCH_PAIRING_BEFORE_INTENT", f.rows() == before));
        // A real valid Replace still succeeds in this same worker. In the
        // relabeling control it follows the unintended effect at its actual base.
        let valid = request_for_current(&w);
        let valid_expected = Expected::new(
            &valid,
            AuditOperation::Replace,
            w.bus.current_snapshot().tx_id,
        );
        let result = w
            .audit
            .replace_running(&owner, &principal(), valid, valid_expected.event.clone())
            .await
            .unwrap();
        if let Some(receipt) = capture(result, &mut checks, "RUNNING_PATCH_BINDING_VALID_CONTROL") {
            observe_readback(&f, &w, &receipt, &valid_expected, &mut checks).await;
        }
        drop(owner);
        let exit = close_worker(w).await;
        checks.push((
            "RUNNING_PATCH_BINDING_DRAIN",
            exit == NetconfWorkerExit::Drained,
        ));
        f.close().await;
        eprintln!("RUNNING_PATCH_LIFECYCLE case=binding worker_joined=true storage_closed=true exit={exit:?}");
    }
    finish(checks, "RUNNING_PATCH_BINDING_DETECTOR");
}

fn request_for_current(w: &Worker) -> CommitRequest<Settings> {
    request(w.bus.current_snapshot().version.get())
}

#[tokio::test]
async fn ordinary_patch_known_effect_debt_recovers_without_new_request_or_failure() {
    let mut checks = Checks::new();
    for fault in ["checkpoint", "readback", "marker"] {
        let f = Fixture::new().await;
        let mut w = Worker::new(&f).await;
        let mut owner = Some(w.audit.open_session(&principal()).await.unwrap());
        f.checkpoint
            .fail_after_effect
            .store(fault == "checkpoint", Ordering::Release);
        f.provider
            .fail_lookup
            .store(fault == "readback", Ordering::Release);
        w.publication
            .fail_marker
            .store(fault == "marker", Ordering::Release);
        let request = patch_request(0);
        let expected = Expected::new(&request, AuditOperation::Update, None);
        let result = w
            .audit
            .replace_running(
                owner.as_ref().unwrap(),
                &principal(),
                request,
                expected.event.clone(),
            )
            .await
            .unwrap();
        let original = capture(result, &mut checks, "RUNNING_PATCH_KNOWN_WITH_DEBT");
        if let Some(receipt) = &original {
            checks.push((
                "RUNNING_PATCH_PUBLICATION_DEBT",
                receipt.publication_pending() && receipt.published_commit().is_none(),
            ));
            checks.push((
                "RUNNING_PATCH_AUDIT_DEBT",
                receipt.completion_pending() == (fault == "checkpoint"),
            ));
            checks.push(("RUNNING_PATCH_DEBT_REAL_EFFECT", history_count(&f) == 1));
            checks.push((
                "RUNNING_PATCH_DEBT_SNAPSHOT_ORDER",
                w.bus.current_snapshot().version.get() == u64::from(fault == "marker"),
            ));
            let before = f.rows();
            let calls = f.provider.active.load(Ordering::Acquire);
            let next = patch_request(w.bus.current_snapshot().version.get());
            let next_event = Expected::new(&next, AuditOperation::Update, None).event;
            let blocked = w
                .audit
                .replace_running(owner.as_ref().unwrap(), &principal(), next, next_event)
                .await
                .unwrap();
            checks.push(("RUNNING_PATCH_DEBT_FENCE", matches!(blocked,
                NetconfMutationResult::Refused(ref error) if error.code == CommitErrorCode::RecoveryRequired)));
            checks.push((
                "RUNNING_PATCH_DEBT_NO_NEW_ENCRYPTION",
                f.provider.active.load(Ordering::Acquire) == calls,
            ));
            checks.push(("RUNNING_PATCH_DEBT_NO_NEW_INTENT", f.rows() == before));
            // With the fault still active, request recovery must retain this
            // known outcome, never invent a failed effect or a replacement ID.
            let held = w
                .audit
                .recover_request(expected.request, &principal())
                .await
                .unwrap();
            checks.push(("RUNNING_PATCH_DEBT_REQUEST_RETAINED", held.is_some()));
            if let Some(held) = held {
                if let Some(held) = capture(held, &mut checks, "RUNNING_PATCH_DEBT_STILL_KNOWN") {
                    checks.push((
                        "RUNNING_PATCH_DEBT_SAME_ORIGINAL",
                        held.outcome() == receipt.outcome()
                            && held.recovery_handle() == receipt.recovery_handle(),
                    ));
                    checks.push((
                        "RUNNING_PATCH_DEBT_NO_FALSE_PUBLICATION",
                        held.publication_pending() && held.published_commit().is_none(),
                    ));
                }
            }
        }
        f.checkpoint
            .fail_after_effect
            .store(false, Ordering::Release);
        f.provider.fail_lookup.store(false, Ordering::Release);
        if fault == "marker" && original.is_some() {
            // Keep marker debt in the first worker. Replacing that worker must
            // recover the protected original from actual retained storage.
            drop(owner.take());
            let exit = close_worker(w).await;
            checks.push((
                "RUNNING_PATCH_DEBT_JOIN",
                exit == NetconfWorkerExit::RecoveryRequired,
            ));
            w = Worker::new(&f).await;
        } else {
            w.publication.fail_marker.store(false, Ordering::Release);
        }
        if let Some(receipt) = original {
            let recovered = w
                .audit
                .recover(receipt.recovery_handle(), &principal())
                .await;
            if let Some(recovered) =
                capture(recovered, &mut checks, "RUNNING_PATCH_DEBT_RECOVERED_KNOWN")
            {
                checks.push((
                    "RUNNING_PATCH_DEBT_RECOVERED_ORIGINAL",
                    recovered.outcome() == receipt.outcome()
                        && recovered.recovery_handle() == receipt.recovery_handle(),
                ));
                observe_readback(&f, &w, &recovered, &expected, &mut checks).await;
                let before = f.rows();
                let again = w
                    .audit
                    .recover(receipt.recovery_handle(), &principal())
                    .await;
                if let Some(again) =
                    capture(again, &mut checks, "RUNNING_PATCH_DEBT_REPEATED_KNOWN")
                {
                    checks.push((
                        "RUNNING_PATCH_DEBT_REPEAT_ORIGINAL",
                        again.outcome() == receipt.outcome(),
                    ));
                }
                checks.push(("RUNNING_PATCH_DEBT_REPEAT_READ_ONLY", f.rows() == before));
            }
        }
        checks.push((
            "RUNNING_PATCH_DEBT_EXACTLY_ONE_ENCRYPTION",
            f.provider.active.load(Ordering::Acquire) == 1,
        ));
        checks.push((
            "RUNNING_PATCH_DEBT_EXACTLY_ONE_EFFECT",
            history_count(&f) == 1,
        ));
        drop(owner.take());
        let exit = close_worker(w).await;
        checks.push((
            "RUNNING_PATCH_RECOVERED_DRAIN",
            exit == NetconfWorkerExit::Drained,
        ));
        f.close().await;
        eprintln!("RUNNING_PATCH_LIFECYCLE case={fault} worker_joined=true storage_closed=true exit={exit:?}");
    }
    finish(checks, "RUNNING_PATCH_DEBT_DETECTOR");
}

#[tokio::test]
async fn ordinary_patch_cancelled_reply_recovers_the_original_request() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let request = patch_request(0);
    let expected = Expected::new(&request, AuditOperation::Update, None);
    let authenticated = principal();
    let release = f.provider.encrypt_gate.arm();
    let mut call =
        Box::pin(
            w.audit
                .replace_running(&owner, &authenticated, request, expected.event.clone()),
        );
    let entered = tokio::select! {
        _ = f.provider.encrypt_gate.entered() => true,
        _ = &mut call => false,
        _ = tokio::time::sleep(Duration::from_secs(30)) => false,
    };
    let mut checks = vec![("RUNNING_PATCH_CANCEL_ENTERED_REAL_PROVIDER", entered)];
    checks.push(("RUNNING_PATCH_CANCEL_BEFORE_EFFECT", history_count(&f) == 0));
    drop(call);
    drop(release);
    let recovered = w
        .audit
        .recover_request(expected.request, &principal())
        .await
        .unwrap();
    checks.push(("RUNNING_PATCH_CANCEL_ORIGINAL_PRESENT", recovered.is_some()));
    if let Some(recovered) = recovered {
        if let Some(receipt) = capture(recovered, &mut checks, "RUNNING_PATCH_CANCEL_KNOWN") {
            observe_readback(&f, &w, &receipt, &expected, &mut checks).await;
            let before = f.rows();
            let again = w
                .audit
                .recover(receipt.recovery_handle(), &principal())
                .await;
            if let Some(again) = capture(again, &mut checks, "RUNNING_PATCH_CANCEL_HANDLE_KNOWN") {
                checks.push((
                    "RUNNING_PATCH_CANCEL_SAME_ORIGINAL",
                    again.outcome() == receipt.outcome()
                        && again.recovery_handle() == receipt.recovery_handle(),
                ));
            }
            checks.push(("RUNNING_PATCH_CANCEL_NO_NEW_EFFECT", f.rows() == before));
        }
    }
    checks.push((
        "RUNNING_PATCH_CANCEL_ENCRYPT_ONCE",
        f.provider.active.load(Ordering::Acquire) == 1,
    ));
    checks.push(("RUNNING_PATCH_CANCEL_APPLIED_ONCE", history_count(&f) == 1));
    drop(owner);
    let exit = close_worker(w).await;
    checks.push((
        "RUNNING_PATCH_CANCEL_DRAIN",
        exit == NetconfWorkerExit::Drained,
    ));
    f.close().await;
    eprintln!(
        "RUNNING_PATCH_LIFECYCLE case=cancel worker_joined=true storage_closed=true exit={exit:?}"
    );
    finish(checks, "RUNNING_PATCH_CANCEL_DETECTOR");
}
