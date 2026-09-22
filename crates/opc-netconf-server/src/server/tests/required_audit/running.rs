//! Required writable-running profile, including the real observation port.

use super::*;
use std::sync::atomic::AtomicU8;

pub(super) struct RunningBinding {
    bus: Arc<Mutex<Arc<ConfigBus<DemoConfig>>>>,
    capabilities: Arc<AtomicU8>,
}

impl RunningBinding {
    fn new(bus: Arc<ConfigBus<DemoConfig>>) -> Self {
        Self {
            bus: Arc::new(Mutex::new(bus)),
            capabilities: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl NetconfConfigBinding<DemoConfig> for RunningBinding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.bus.lock().unwrap().clone()
    }

    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        &REGISTRY
    }

    fn generated_xml_edit_applicator(&self) -> Option<&dyn NetconfXmlEditApplicator<DemoConfig>> {
        Some(&DEMO_EDIT_APPLICATOR)
    }

    fn writable_running_capability(&self) -> bool {
        true
    }

    fn nmda_edit_data_supported(&self) -> bool {
        true
    }

    fn candidate_datastore_capability(&self) -> bool {
        self.capabilities.load(Ordering::Acquire) & 1 != 0
    }

    fn confirmed_commit_capability(&self) -> bool {
        self.capabilities.load(Ordering::Acquire) & 2 != 0
    }

    fn startup_datastore_capability(&self) -> bool {
        self.capabilities.load(Ordering::Acquire) & 4 != 0
    }

    fn render_running_config(
        &self,
        config: &DemoConfig,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        DEMO_RENDERER
            .render_running_config(config, selection.schema_paths(), DefaultReport::Trim)
            .map_err(|_| BindingError::projection("synthetic projection failed"))
    }
}

pub(super) struct RefusingOriginalSink;

impl AuditSink for RefusingOriginalSink {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::unavailable("original sink must be replaced"))
    }
}

type RequiredServer =
    ReadOnlyNetconfServer<DemoConfig, RunningBinding, FixedPolicy, RefusingOriginalSink>;

fn unattached(binding: RunningBinding) -> RequiredServer {
    ReadOnlyNetconfServer::new(
        binding,
        FixedPolicy(policy_allow_system_with_secret_writes()),
        RefusingOriginalSink,
        TransportType::NetconfTls,
    )
    .unwrap()
}

pub(super) fn required_server(h: &Harness) -> RequiredServer {
    unattached(RunningBinding::new(h.bus.clone()))
        .with_required_config_audit(h.bus.required_config_audit().unwrap())
        .unwrap()
}

fn edit() -> String {
    edit_config_rpc_to(
        "running",
        r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-edited</sys:hostname></sys:system>"#,
        "merge",
    )
}

async fn rpc(server: &RequiredServer, sessions: &SessionRegistry, xml: &str) -> RpcHandlingResult {
    server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            xml,
            &MgmtLimits::default(),
            1,
            sessions,
        )
        .await
}

#[tokio::test]
async fn attachment_refuses_each_unsupported_composition_without_hiding_it() {
    let h = Harness::start().await;
    for bits in [1, 2, 4, 7] {
        let binding = RunningBinding::new(h.bus.clone());
        binding.capabilities.store(bits, Ordering::Release);
        let result =
            unattached(binding).with_required_config_audit(h.bus.required_config_audit().unwrap());
        assert!(matches!(
            result,
            Err(ServerInitError::RequiredAuditProfileUnsupported)
        ));
    }
    assert_eq!(h.checkpoints.sequence(), 3);
    h.shutdown().await;
}

#[tokio::test]
async fn attachment_and_submission_refuse_a_different_worker_over_the_same_store() {
    let h = Harness::start().await;
    let other = Arc::new(
        ConfigBus::restore_or_new_dev_only(
            h.bus.current_snapshot().config.as_ref().clone(),
            h.source.clone(),
        )
        .await
        .unwrap(),
    );
    let result = unattached(RunningBinding::new(other.clone()))
        .with_required_config_audit(h.bus.required_config_audit().unwrap());
    assert!(matches!(
        result,
        Err(ServerInitError::RequiredAuditWorkerMismatch)
    ));

    let binding = RunningBinding::new(h.bus.clone());
    let selected_bus = binding.bus.clone();
    let server = unattached(binding)
        .with_required_config_audit(h.bus.required_config_audit().unwrap())
        .unwrap();
    *selected_bus.lock().unwrap() = other.clone();
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    assert!(rpc(&server, &sessions, &edit())
        .await
        .reply_xml
        .contains("resource-denied"));
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(1));
    assert_eq!(stored.config.hostname, "fixture-initial");
    drop(registration);
    drop(server);
    drop(selected_bus);
    drop(other);
    h.shutdown().await;
}

#[tokio::test]
async fn capability_changes_after_attachment_permit_no_local_or_running_mutation() {
    let h = Harness::start().await;
    let binding = RunningBinding::new(h.bus.clone());
    let capabilities = binding.capabilities.clone();
    let server = unattached(binding)
        .with_required_config_audit(h.bus.required_config_audit().unwrap())
        .unwrap();
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    for bits in [1, 2, 4] {
        capabilities.store(bits, Ordering::Release);
        assert!(rpc(&server, &sessions, &edit())
            .await
            .reply_xml
            .contains("operation-failed"));
        assert!(server.candidate.lock().unwrap().snapshot().is_none());
        assert_eq!(
            h.source
                .load_committed_latest()
                .await
                .unwrap()
                .unwrap()
                .version,
            ConfigVersion::new(1)
        );
    }
    drop(registration);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn required_edit_data_and_inline_copy_bind_their_real_operations_once() {
    let xml = r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-edited</sys:hostname><sys:secret>synthetic-secret</sys:secret></sys:system>"#;
    for request in [
        edit_data_rpc("running", xml, "merge"),
        format!(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="synthetic"><copy-config><target><running/></target><source><config>{xml}</config></source></copy-config></rpc>"#
        ),
    ] {
        let h = Harness::start().await;
        let server = required_server(&h);
        let sessions = SessionRegistry::new();
        let registration = sessions.register(1).unwrap();
        assert!(rpc(&server, &sessions, &request)
            .await
            .reply_xml
            .contains("<ok/>"));
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(2));
        assert_eq!(stored.config.hostname, "fixture-edited");
        assert_eq!(h.checkpoints.sequence(), 6);
        drop(registration);
        drop(server);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn reads_and_atomic_running_locks_use_real_observations_without_config_effects() {
    let h = Harness::start().await;
    let server = required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    let read = rpc(&server, &sessions, &get_config_rpc("running")).await;
    assert!(!read.reply_xml.contains("rpc-error"));
    assert!(rpc(&server, &sessions, &lock_rpc("running"))
        .await
        .reply_xml
        .contains("<ok/>"));
    assert!(rpc(&server, &sessions, &unlock_rpc("running"))
        .await
        .reply_xml
        .contains("<ok/>"));
    assert_eq!(h.checkpoints.sequence(), 6);
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    drop(registration);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn rejected_registry_observation_permits_no_running_lock() {
    let h = Harness::start().await;
    let server = required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    h.checkpoints.refuse_from.store(4, Ordering::Release);
    assert!(rpc(&server, &sessions, &lock_rpc("running"))
        .await
        .reply_xml
        .contains("operation-failed"));
    assert!(sessions.running_lock_owner_for_test().is_none());
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    drop(registration);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn cancelled_registry_caller_does_not_retract_the_admitted_atomic_lock() {
    let h = Harness::start().await;
    let server = required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    let rpc_sessions = sessions.clone();
    h.checkpoints.pause_at.store(4, Ordering::Release);
    let task = tokio::spawn(async move { rpc(&server, &rpc_sessions, &lock_rpc("running")).await });
    tokio::time::timeout(Duration::from_secs(5), h.checkpoints.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    h.checkpoints.resume.notify_one();
    // The existing hook owns the registry mutex across the checkpoint barrier.
    // Observe completion through that mutex on a blocking thread, not by sleep
    // or by blocking this async executor while the authority needs to run.
    let observed = sessions.clone();
    let owner = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || observed.running_lock_owner_for_test()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        owner == Some(1),
        "admitted running lock was lost with its caller"
    );
    assert_eq!(h.checkpoints.sequence(), 4);
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    drop(registration);
    h.shutdown().await;
}

#[tokio::test]
async fn required_kill_records_its_observation_before_signalling_the_exact_session() {
    let h = Harness::start().await;
    let server = required_server(&h);
    let sessions = SessionRegistry::new();
    let caller = sessions.register(1).unwrap();
    let target = sessions.register(2).unwrap();
    assert!(rpc(&server, &sessions, &kill_session_rpc(2))
        .await
        .reply_xml
        .contains("<ok/>"));
    assert!(target.is_terminated());
    assert_eq!(h.checkpoints.sequence(), 4);
    assert_eq!(
        h.source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap()
            .version,
        ConfigVersion::new(1)
    );
    drop(target);
    drop(caller);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn required_protocol_refuses_unavailable_and_unknown_intent_without_effects() {
    for unknown in [false, true] {
        let h = Harness::start().await;
        let server = required_server(&h);
        if unknown {
            h.checkpoints.unknown_from.store(4, Ordering::Release);
        } else {
            h.checkpoints.refuse_from.store(4, Ordering::Release);
        }
        let sessions = SessionRegistry::new();
        let registration = sessions.register(1).unwrap();
        assert!(rpc(&server, &sessions, &edit())
            .await
            .reply_xml
            .contains("operation-failed"));
        h.checkpoints
            .readback_unavailable
            .store(false, Ordering::Release);
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(1));
        assert_eq!(stored.config.hostname, "fixture-initial");
        assert_eq!(h.checkpoints.sequence(), if unknown { 4 } else { 3 });
        assert_eq!(
            h.authority
                .reconcile_audit_obligations(30)
                .await
                .unwrap()
                .pending,
            1
        );
        drop(registration);
        drop(server);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn required_protocol_preserves_success_with_terminal_debt_and_fences_the_next_write() {
    let h = Harness::start().await;
    let server = required_server(&h);
    h.checkpoints.refuse_from.store(6, Ordering::Release);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    assert!(rpc(&server, &sessions, &edit())
        .await
        .reply_xml
        .contains("<ok/>"));
    let first = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(first.version, ConfigVersion::new(2));
    assert_eq!(h.checkpoints.sequence(), 4);
    let later = edit().replace("fixture-edited", "fixture-fenced");
    assert!(rpc(&server, &sessions, &later)
        .await
        .reply_xml
        .contains("operation-failed"));
    h.checkpoints.refuse_from.store(0, Ordering::Release);
    let recovered = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    let exact = h
        .bus
        .resolve_request_id(first.request_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == first.tx_id,
        "terminal recovery changed transaction"
    );
    assert_eq!(h.checkpoints.sequence(), 6);
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert!(
        latest.tx_id == first.tx_id,
        "fenced write changed transaction"
    );
    drop(registration);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn cancelled_netconf_rpc_leaves_its_exact_admitted_effect_with_the_worker() {
    let h = Harness::start().await;
    let server = required_server(&h);
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    h.checkpoints.pause_at.store(4, Ordering::Release);
    let request_id = RequestId::new();
    let task = tokio::spawn(async move {
        server
            .handle_rpc_for_session_async(
                request_id,
                &principal(),
                &edit(),
                &MgmtLimits::default(),
                1,
                &sessions,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), h.checkpoints.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    h.checkpoints.resume.notify_one();
    let (mut barrier, _) = exact_replace(RequestId::new(), 2);
    barrier.mode = CommitMode::ValidateOnly;
    tokio::time::timeout(Duration::from_secs(5), h.bus.submit(barrier))
        .await
        .unwrap()
        .unwrap();
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    let recovered = h.bus.resolve_request_id(request_id).await.unwrap().unwrap();
    assert!(
        stored.tx_id == recovered.tx_id,
        "cancelled NETCONF result binding mismatch"
    );
    assert!(
        stored.request_id == Some(request_id),
        "cancelled NETCONF request changed"
    );
    assert_eq!(stored.version, ConfigVersion::new(2));
    assert_eq!(h.checkpoints.sequence(), 6);
    drop(registration);
    h.shutdown().await;
}

#[tokio::test]
async fn required_capability_does_not_grant_protocol_write_authorization() {
    let h = Harness::start().await;
    let server = ReadOnlyNetconfServer::new(
        RunningBinding::new(h.bus.clone()),
        FixedPolicy(policy_allow_system_but_deny_edit_config()),
        RefusingOriginalSink,
        TransportType::NetconfTls,
    )
    .unwrap()
    .with_required_config_audit(h.bus.required_config_audit().unwrap())
    .unwrap();
    let sessions = SessionRegistry::new();
    let registration = sessions.register(1).unwrap();
    assert!(rpc(&server, &sessions, &edit())
        .await
        .reply_xml
        .contains("<error-tag>access-denied</error-tag>"));
    // One denial observation, with no required intent/result/terminal tuple.
    assert_eq!(h.checkpoints.sequence(), 4);
    let stored = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(1));
    assert_eq!(stored.config.hostname, "fixture-initial");
    assert_eq!(
        h.authority
            .reconcile_audit_obligations(30)
            .await
            .unwrap()
            .inspected,
        0
    );
    drop(registration);
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn required_capability_does_not_override_the_current_authority_gate() {
    for outcome in [
        ConfigAuthorityOutcome::Unavailable,
        ConfigAuthorityOutcome::Retry { leader_hint: None },
    ] {
        let h = Harness::start().await;
        let gate = Arc::new(ScriptedConfigAuthority::fixed(outcome));
        let server = required_server(&h)
            .with_config_authority(gate.clone())
            .unwrap();
        let sessions = SessionRegistry::new();
        let registration = sessions.register(1).unwrap();
        assert!(rpc(&server, &sessions, &edit())
            .await
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert_eq!(gate.operations(), vec![ConfigAuthorityOperation::Write]);
        assert_eq!(h.checkpoints.sequence(), 4);
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert_eq!(stored.version, ConfigVersion::new(1));
        assert_eq!(stored.config.hostname, "fixture-initial");
        assert_eq!(
            h.authority
                .reconcile_audit_obligations(30)
                .await
                .unwrap()
                .inspected,
            0
        );
        drop(registration);
        drop(server);
        h.shutdown().await;
    }
}
