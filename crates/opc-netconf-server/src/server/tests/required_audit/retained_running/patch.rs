//! Partial ordinary Running edits keep their original Patch/Update binding.
//! Real session runners, encryption, native Apply and checkpoints are reused.
//! These local synthetic cases do not qualify deployment, timing or full #958.

use super::*;
use opc_config_bus::StoredRequestMode;
use opc_persist::audit_authority::{
    AuditOperationHandle, AuditOperationState, ProjectedAuditEvent,
};
use opc_persist::{
    ConfigStore, ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};
use opc_types::TxId;

const PATCH_CLEAN: &str = "RETAINED_RUNNING_PATCH_PROTOCOL_CLEANUP_COMPLETE";

fn partial(label: &str, nmda: bool, descendant_replace: bool) -> String {
    let operation = if descendant_replace {
        " nc:operation=\"replace\""
    } else {
        ""
    };
    let xml = format!(
        r#"<sys:system xmlns:sys="urn:opc:demo" xmlns:nc="{NETCONF_BASE_NS}"><sys:hostname{operation}>{label}</sys:hostname></sys:system>"#
    );
    if nmda {
        edit_data_rpc("running", &xml, "merge")
    } else {
        edit_config_rpc_to("running", &xml, "merge")
    }
}

// Preserve the authorizer's Create + Update requirements for Patch, while
// denying Replace. The root-replace counterexample must fail before preparation.
fn patch_only_policy() -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("demo-system", "sys").unwrap();
    register_netconf_module(&mut modules);
    register_netconf_nmda_module(&mut modules);
    NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::deny(
            NacmAction::Replace,
            YangPathPattern::parse("/sys:system/**", &modules).unwrap(),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Create,
            YangPathPattern::parse("/sys:system/**", &modules).unwrap(),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Update,
            YangPathPattern::parse("/sys:system/**", &modules).unwrap(),
        ))
        .add_rule(allow_edit_config_rule(&modules))
        .add_rule(allow_edit_data_rule(&modules))
        .add_rule(allow_close_session_rule(&modules))
        .build()
}

// Compare semantic fields against literal wire expectations, not a projection
// derived from the returned operation. Timestamp/projection are authenticated by
// the SDK and export verifier; the runner's clock is deliberately not guessed.
async fn patch_binding(f: &Fixture, record: &StoredConfig<DemoConfig>, version: u64) -> bool {
    let Some(request) = record.request_id else {
        return false;
    };
    let Some(receipt) = recovered(f, record).await else {
        return false;
    };
    let privacy = AuditPrivacyKey::new([0x39; 32]).unwrap();
    let caller = AuditCaller::project(
        &privacy,
        principal().tenant.as_str(),
        &opc_mgmt_audit::principal_descriptor(&principal()),
    )
    .unwrap();
    let handle =
        AuditOperationHandle::decode(&receipt.recovery_handle().encode().unwrap()).unwrap();
    let authenticated = f
        .store
        .lookup_audit_operation(&handle, caller)
        .await
        .unwrap();
    let original = authenticated.is_some_and(|original| {
        original.handle() == &handle
            && original.terminal_recorded()
            && matches!(original.state(), AuditOperationState::TargetV1(target)
                if target.outcome() == receipt.outcome())
    });
    let expected = ManagementAuditEventRecord::try_new(
        *request.as_uuid().as_bytes(),
        ManagementAuditInstant::try_new(1, 0, 1, ManagementAuditTimeSourceCode::NodeClock).unwrap(),
        principal().tenant.as_str(),
        opc_mgmt_audit::principal_descriptor(&principal()),
        ManagementAuditTransportCode::NetconfTls,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/sys:system/sys:hostname"],
        None::<&str>,
    )
    .unwrap();
    let expected =
        serde_json::to_value(ProjectedAuditEvent::project(&privacy, &expected).unwrap()).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&handle.encode().unwrap()).unwrap();
    let event = &actual["body"]["event"];
    let event_matches = [
        "caller",
        "request",
        "transaction",
        "paths",
        "reason",
        "transport",
        "operation",
        "outcome",
    ]
    .iter()
    .all(|field| event[*field] == expected[*field]);
    let fingerprint = record
        .request_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| {
            fingerprint.operation == ConfigOperation::Patch
                && fingerprint.transport == TransportType::NetconfTls
                && fingerprint.base_version == Some(ConfigVersion::new(version - 1))
                && matches!(fingerprint.mode, StoredRequestMode::Commit)
                && fingerprint.changed_paths
                    == vec![YangPath::new("/sys:system/sys:hostname").unwrap()]
        });
    let by_request = f.encrypted.load_by_request_id(request).await.unwrap();
    let lookup = by_request.is_some_and(|original| {
        original.tx_id == record.tx_id && original.request_fingerprint == record.request_fingerprint
    });
    // Finish the real export verification even when a semantic control changed
    // the operation; the late binding assertion must not skip this lifecycle.
    let audited = original_audit(f, &receipt).await;
    original && event_matches && fingerprint && lookup && audited
}

async fn observe_patch(
    f: &Fixture,
    label: &str,
    version: u64,
    parent: Option<TxId>,
) -> (bool, bool, Option<TxId>, Option<RequestId>) {
    let record = f.encrypted.load_committed_latest().await.unwrap();
    let Some(record) = record else {
        return (false, false, None, None);
    };
    let raw = f.store.load_latest().await.unwrap();
    let encrypted = raw.is_some_and(|raw| {
        raw.record.tx_id == record.tx_id
            && !raw.record.encrypted_blob.is_empty()
            && record
                .plaintext_digest
                .is_some_and(|digest| raw.record.plaintext_digest.as_slice() == digest.as_slice())
    });
    let prepared_request = *f.checkpoint.prepared_request.lock().unwrap();
    let effect = encrypted
        && record.parent_tx_id == parent
        && record.request_id == prepared_request
        && exact_record(f, &record, label, version).await;
    let binding = patch_binding(f, &record, version).await;
    (effect, binding, Some(record.tx_id), record.request_id)
}

#[tokio::test]
async fn retained_running_patch_protocol_native_edit_and_nmda_keep_update_original() {
    let f = Fixture::new().await;
    let server = f.server(patch_only_policy()).unwrap();
    let mut client = Client::start(server.clone(), SessionRegistry::new(), 81).await;
    let before = f.provider.calls();
    let replacement = client
        .rpc(&edit("fixture-forbidden-replace", false, "replace"))
        .await;
    let denied_before_prepare =
        replacement.contains("access-denied") && before == f.provider.calls();
    let mut effects = true;
    let mut bindings = true;
    let mut replies = true;
    let mut parent = None;
    let mut requests = BTreeSet::new();
    // Descendant replace is still a Patch; omitted secret must survive all three.
    for (label, nmda, descendant, version) in [
        ("fixture-partial", false, false, 1),
        ("fixture-descendant", false, true, 2),
        ("fixture-nmda-partial", true, false, 3),
    ] {
        let reply = client.rpc(&partial(label, nmda, descendant)).await;
        let (effect, binding, tx, request) = observe_patch(&f, label, version, parent).await;
        effects &= effect;
        bindings &= binding;
        replies &= reply.contains("<ok/>");
        parent = tx;
        if let Some(request) = request {
            requests.insert(*request.as_uuid().as_bytes());
        }
    }
    let encrypted = f.provider.active.load(Ordering::Acquire);
    let closed = client.close().await;
    drop(server);
    let drained = f.close().await;
    eprintln!("{PATCH_CLEAN}: native closed={closed} drained={drained} encryptions={encrypted}");
    eprintln!("RETAINED_RUNNING_PATCH_PROTOCOL_OBSERVED: effects={effects} bindings={bindings} replies={replies} requests={}", requests.len());
    assert!(closed && drained, "RETAINED_RUNNING_PATCH_PROTOCOL_CLEANUP");
    assert!(
        denied_before_prepare,
        "RETAINED_RUNNING_PATCH_PROTOCOL_NACM_RED"
    );
    assert!(
        effects && encrypted == 3 && requests.len() == 3,
        "RETAINED_RUNNING_PATCH_PROTOCOL_HANDOFF_RED"
    );
    assert!(bindings, "RETAINED_RUNNING_PATCH_PROTOCOL_BINDING_RED");
    assert!(replies, "RETAINED_RUNNING_PATCH_PROTOCOL_KNOWN_RESULT_RED");
}

#[tokio::test]
async fn retained_running_patch_protocol_wrong_owner_and_denied_path_have_no_effect() {
    let f = Fixture::new().await;
    let server = f.server(policy_allow_system_but_deny_secret()).unwrap();
    let registry = SessionRegistry::new();
    let mut owner = Client::start(server.clone(), registry.clone(), 82).await;
    let mut other = Client::start(server.clone(), registry.clone(), 83).await;
    let locked = owner.rpc(&lock_rpc("running")).await;
    let before = f.provider.calls();
    let wrong_owner = other
        .rpc(&partial("fixture-other-owner", false, false))
        .await;
    let numeric = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &partial("fixture-numeric-owner", false, false),
            &MgmtLimits::default(),
            82,
            &registry,
        )
        .await;
    let denied_xml = edit_config_rpc_to(
        "running",
        r#"<sys:system xmlns:sys="urn:opc:demo"><sys:secret>fixture-denied-secret</sys:secret></sys:system>"#,
        "merge",
    );
    let denied = owner.rpc(&denied_xml).await;
    let untouched = before == f.provider.calls()
        && f.encrypted.load_latest().await.unwrap().is_none()
        && f.bus.current_snapshot().version.get() == 0;
    // Same retained owner and original lock can perform a permitted partial edit.
    let allowed = owner
        .rpc(&partial("fixture-owner-patch", false, false))
        .await;
    let (effect, binding, _, _) = observe_patch(&f, "fixture-owner-patch", 1, None).await;
    let unlocked = owner.rpc(&unlock_rpc("running")).await;
    let encrypted = f.provider.active.load(Ordering::Acquire);
    let closed_owner = owner.close().await;
    let closed_other = other.close().await;
    drop(server);
    let drained = f.close().await;
    eprintln!(
        "{PATCH_CLEAN}: authority owner={closed_owner} other={closed_other} drained={drained}"
    );
    assert!(
        closed_owner && closed_other && drained,
        "RETAINED_RUNNING_PATCH_PROTOCOL_CLEANUP"
    );
    assert!(
        locked.contains("<ok/>")
            && unlocked.contains("<ok/>")
            && wrong_owner.contains("<rpc-error>")
            && numeric.reply_xml.contains("<rpc-error>")
            && denied.contains("access-denied")
            && untouched
            && allowed.contains("<ok/>")
            && effect
            && binding
            && encrypted == 1,
        "RETAINED_RUNNING_PATCH_PROTOCOL_AUTHORITY_RED"
    );
}

#[tokio::test]
async fn retained_running_patch_protocol_applied_debt_recovers_original_update() {
    for checkpoint_fault in [true, false] {
        let f = Fixture::new().await;
        let server = f.server(patch_only_policy()).unwrap();
        let mut client = Client::start(server.clone(), SessionRegistry::new(), 84).await;
        if checkpoint_fault {
            f.checkpoint
                .inner
                .refuse_from
                .store(f.checkpoint.inner.sequence() + 2, Ordering::Release);
        } else {
            f.provider.fail_lookup.store(true, Ordering::Release);
        }
        let reply = client
            .rpc(&partial("fixture-patch-debt", false, false))
            .await;
        // Observe the real native row without restoring the worker's key lookup.
        // Its automatic recovery pass must remain faulted until the checks finish.
        let record = f.store.load_latest().await.unwrap();
        let hidden = f.store.load_committed_latest().await.unwrap().is_none();
        let prepared_request = *f.checkpoint.prepared_request.lock().unwrap();
        let original = match prepared_request {
            Some(request) => recovered_request(&f, request).await,
            None => None,
        };
        let known = original.as_ref().is_some_and(|receipt| {
            matches!(
                receipt.outcome(),
                NetconfAppliedOutcome::RunningReplaced { .. }
            ) && receipt.publication_pending()
                && receipt.completion_pending() == checkpoint_fault
                && receipt.published_commit().is_none()
        });
        let fenced = client
            .rpc(&partial("fixture-patch-fenced", true, false))
            .await;
        let encrypted = f.provider.active.load(Ordering::Acquire);
        let version_before_restore = f.bus.current_snapshot().version.get();
        f.checkpoint.inner.refuse_from.store(0, Ordering::Release);
        f.provider.fail_lookup.store(false, Ordering::Release);
        let mut same = false;
        if let Some(original) = &original {
            if let NetconfMutationResult::Applied(receipt) = f
                .audit
                .recover(original.recovery_handle(), &principal())
                .await
            {
                same = receipt.outcome() == original.outcome()
                    && receipt.recovery_handle() == original.recovery_handle();
            }
        }
        let (effect, binding, tx, _) = observe_patch(&f, "fixture-patch-debt", 1, None).await;
        let same_tx = record
            .as_ref()
            .is_some_and(|record| Some(record.record.tx_id) == tx);
        let closed = client.close().await;
        drop(server);
        let drained = f.close().await;
        eprintln!(
            "{PATCH_CLEAN}: debt checkpoint={checkpoint_fault} closed={closed} drained={drained}"
        );
        eprintln!(
            "RETAINED_RUNNING_PATCH_PROTOCOL_DEBT_OBSERVED: checkpoint={checkpoint_fault} \
             reply_error={} reply_ok={} known={known} hidden={hidden} \
             fenced_error={} encrypted={encrypted} same={same} same_tx={same_tx} effect={effect} binding={binding} \
             version_before_restore={version_before_restore} \
             receipt_flags=(terminal,completion_pending,publication_pending,published)={:?}",
            reply.contains("<rpc-error>"),
            reply.contains("<ok/>"),
            fenced.contains("<rpc-error>"),
            original.as_ref().map(|receipt| (
                receipt.terminal_recorded(),
                receipt.completion_pending(),
                receipt.publication_pending(),
                receipt.published_commit().is_some(),
            )),
        );
        assert!(closed && drained, "RETAINED_RUNNING_PATCH_PROTOCOL_CLEANUP");
        assert!(
            reply.contains("<rpc-error>")
                && !reply.contains("<ok/>")
                && known
                && hidden
                && fenced.contains("<rpc-error>")
                && encrypted == 1
                && same
                && same_tx
                && effect
                && binding,
            "RETAINED_RUNNING_PATCH_PROTOCOL_ORIGINAL_DEBT_RED"
        );
    }
}

async fn no_patch_intent(f: &Fixture) -> bool {
    let privacy = AuditPrivacyKey::new([0x39; 32]).unwrap();
    let caller = AuditCaller::project(
        &privacy,
        principal().tenant.as_str(),
        &opc_mgmt_audit::principal_descriptor(&principal()),
    )
    .unwrap();
    let export = f
        .store
        .freeze_audit_export(caller, 0, Duration::from_secs(60))
        .await
        .unwrap();
    let page = export.page(None, 256, caller).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&page.encode().unwrap()).unwrap();
    let update = serde_json::to_value(ManagementAuditOperationCode::Update).unwrap();
    page.next_cursor().is_none()
        && value["rows"].as_array().unwrap().iter().all(|row| {
            row["entry"]["payload"]["target-intent"]["handle"]["body"]["event"]["operation"]
                != update
                && row["entry"]["payload"]["intent"]["body"]["event"]["operation"] != update
        })
}

#[tokio::test]
async fn retained_running_patch_protocol_runner_drop_preserves_admission_and_original() {
    // Before encrypted preparation, after native admission's wait, after effect.
    for phase in 0..3 {
        let f = Fixture::new().await;
        let server = f.server(patch_only_policy()).unwrap();
        let mut client = Client::start(server.clone(), SessionRegistry::new(), 85).await;
        let gate = match phase {
            0 => f.provider.encrypt_gate.clone(),
            1 => f.checkpoint.admission_gate.clone(),
            _ => f.provider.readback_gate.clone(),
        };
        let release = gate.arm();
        f.checkpoint
            .after_prepare
            .store(phase == 1, Ordering::Release);
        client
            .send(&partial("fixture-patch-cancelled", false, false))
            .await;
        let reached = tokio::time::timeout(WAIT, gate.entered()).await.is_ok();
        let cancelled = client.cancel().await;
        drop(release);
        let barrier = f
            .audit
            .recover_request(RequestId::new(), &principal())
            .await;
        let request = *f.checkpoint.prepared_request.lock().unwrap();
        let original = match request {
            Some(request) => f.audit.recover_request(request, &principal()).await,
            None => Ok(None),
        };
        let checked = if phase == 2 {
            let (effect, binding, _, _) =
                observe_patch(&f, "fixture-patch-cancelled", 1, None).await;
            effect && binding
        } else {
            let refused = matches!(original, Ok(Some(NetconfMutationResult::Refused(ref error)))
                if error.code == CommitErrorCode::AdmissionRejected);
            f.encrypted.load_latest().await.unwrap().is_none()
                && f.bus.current_snapshot().version.get() == 0
                && no_patch_intent(&f).await
                && (phase == 0
                    || (f.checkpoint.observed_loads.load(Ordering::Acquire) == 3 && refused))
        };
        let encrypted = f.provider.active.load(Ordering::Acquire);
        drop(server);
        let drained = f.close().await;
        eprintln!("{PATCH_CLEAN}: cancelled phase={phase} drained={drained}");
        assert!(drained, "RETAINED_RUNNING_PATCH_PROTOCOL_CLEANUP");
        assert!(
            reached
                && cancelled
                && barrier.is_ok()
                && request.is_some()
                && checked
                && encrypted == 1,
            "RETAINED_RUNNING_PATCH_PROTOCOL_CANCELLED_OWNER_RED"
        );
    }
}
