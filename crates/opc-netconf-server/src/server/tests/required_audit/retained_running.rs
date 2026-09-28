//! Root replacement on the real transport runner and encrypted retained worker.
//! These synthetic local-native tests do not qualify TLS deployment, multi-voter
//! durability, timing, recipient-only exports, or the complete retained lifecycle.
use super::*;
use opc_config_bus::{
    NetconfAppliedReceipt, NetconfMutationResult, NetconfWorkerExit, RequiredNetconfAudit,
};
use opc_persist::audit_authority::continuity::AuditExportVerifier;
use opc_persist::audit_authority::{AuditCaller, NetconfAppliedOutcome};
use opc_persist::ConfigStore;
use std::sync::atomic::AtomicU8;

mod fixture;
mod patch;
use fixture::Fixture;

// Outer test hang guard only. The real request and frame deadlines are unchanged.
const WAIT: Duration = Duration::from_secs(30);
const CLEAN: &str = "RETAINED_RUNNING_PROTOCOL_CLEANUP_COMPLETE";

struct Binding {
    bus: Arc<ConfigBus<DemoConfig>>,
    capabilities: Arc<AtomicU8>,
    startup: Option<Arc<MemoryStartupDatastore>>,
}
impl Binding {
    fn new(bus: Arc<ConfigBus<DemoConfig>>) -> Self {
        Self {
            bus,
            capabilities: Arc::new(AtomicU8::new(0)),
            startup: None,
        }
    }
}
impl NetconfConfigBinding<DemoConfig> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.bus.clone()
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
    fn startup_datastore(&self) -> Option<&dyn StartupDatastore<DemoConfig>> {
        self.startup
            .as_deref()
            .map(|startup| startup as &dyn StartupDatastore<DemoConfig>)
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

type NativeServer =
    ReadOnlyNetconfServer<DemoConfig, Binding, FixedPolicy, running::RefusingOriginalSink>;
fn unattached(binding: Binding, policy: NacmPolicy) -> NativeServer {
    ReadOnlyNetconfServer::new(
        binding,
        FixedPolicy(policy),
        running::RefusingOriginalSink,
        TransportType::NetconfTls,
    )
    .unwrap()
}
fn edit(label: &str, nmda: bool, operation: &str) -> String {
    let config = format!(
        r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{label}</sys:hostname><sys:secret>synthetic-secret</sys:secret></sys:system>"#
    );
    if nmda {
        edit_data_rpc("running", &config, operation)
    } else {
        edit_config_rpc_to("running", &config, operation)
    }
}
struct Client {
    stream: tokio::io::DuplexStream,
    runner: tokio::task::JoinHandle<
        Result<crate::session::SessionResult, crate::session::SessionError>,
    >,
}
impl Client {
    async fn start(server: Arc<NativeServer>, sessions: SessionRegistry, id: u64) -> Self {
        let (mut stream, client) = tokio::io::duplex(8192);
        let runner = tokio::spawn(async move {
            crate::session::run_read_only_session_with_registry(
                &server,
                &principal(),
                &mut stream,
                SessionConfig::default(),
                id,
                &sessions,
            )
            .await
        });
        let mut client = Self {
            stream: client,
            runner,
        };
        let hello = client.reply().await;
        // The binding's standard capability is preserved, not silently masked.
        // Ordinary Replace and Patch use that same capability. This assertion
        // does not qualify unsupported datastores or the complete lifecycle.
        assert!(hello.contains(":writable-running"));
        assert!(
            !hello.contains(":candidate")
                && !hello.contains(":startup")
                && !hello.contains(":confirmed-commit")
        );
        client.send(&format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#)).await;
        client
    }
    async fn send(&mut self, xml: &str) {
        self.stream
            .write_all(&base10::encode_message(xml.as_bytes(), &MgmtLimits::default()).unwrap())
            .await
            .unwrap();
    }
    async fn reply(&mut self) -> String {
        String::from_utf8(
            tokio::time::timeout(WAIT, read_base10_frame(&mut self.stream))
                .await
                .unwrap(),
        )
        .unwrap()
    }
    async fn rpc(&mut self, xml: &str) -> String {
        self.send(xml).await;
        self.reply().await
    }
    async fn close(mut self) -> bool {
        let reply = self.rpc(&close_session_rpc()).await;
        let joined = tokio::time::timeout(WAIT, self.runner).await;
        reply.contains("<ok/>") && matches!(joined, Ok(Ok(Ok(_))))
    }
    async fn cancel(self) -> bool {
        self.runner.abort();
        matches!(self.runner.await, Err(error) if error.is_cancelled())
    }
}

async fn recovered(
    f: &Fixture,
    record: &StoredConfig<DemoConfig>,
) -> Option<NetconfAppliedReceipt> {
    recovered_request(f, record.request_id?).await
}

async fn recovered_request(f: &Fixture, request: RequestId) -> Option<NetconfAppliedReceipt> {
    match f
        .audit
        .recover_request(request, &principal())
        .await
        .ok()??
    {
        NetconfMutationResult::Applied(receipt) => Some(receipt),
        _ => None,
    }
}
async fn exact_record(
    f: &Fixture,
    record: &StoredConfig<DemoConfig>,
    label: &str,
    version: u64,
) -> bool {
    let Some(receipt) = recovered(f, record).await else {
        return false;
    };
    let original = matches!(receipt.outcome(), NetconfAppliedOutcome::RunningReplaced {
        tx_id, running_version, plaintext_digest,
    } if tx_id == record.tx_id && running_version == version && Some(plaintext_digest) == record.plaintext_digest);
    let published = receipt.published_commit().is_some_and(|commit| {
        commit.tx_id == record.tx_id && commit.new_version == Some(record.version)
    });
    let snapshot = f.bus.current_snapshot();
    original
        && published
        && receipt.terminal_recorded()
        && !receipt.completion_pending()
        && !receipt.publication_pending()
        && !record.recovery_required
        && record.version.get() == version
        && record.config.hostname == label
        && record.config.secret == "synthetic-secret"
        && record.principal == principal()
        && record.source == RequestSource::Northbound
        && record.request_id.is_some()
        && snapshot.tx_id == Some(record.tx_id)
        && snapshot.version == record.version
        && snapshot.config.hostname == label
}

async fn original_audit(f: &Fixture, receipt: &NetconfAppliedReceipt) -> bool {
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
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    // Trusted authority-side verification using synthetic signing material. This
    // is not the separate recipient-only evidence contract.
    let mut verifier = AuditExportVerifier::new(
        Arc::new(AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x38; 32]).unwrap()]).unwrap()),
        export.manifest().clone(),
        identity,
        caller,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    verifier.accept(&page).unwrap();
    let verified = verifier.finish().is_ok();
    let value: serde_json::Value = serde_json::from_slice(&page.encode().unwrap()).unwrap();
    let handle: serde_json::Value =
        serde_json::from_slice(&receipt.recovery_handle().encode().unwrap()).unwrap();
    let rows = value["rows"].as_array().unwrap();
    let intents = rows
        .iter()
        .filter(|row| row["entry"]["payload"]["target-intent"]["handle"] == handle)
        .count();
    let outcomes = rows
        .iter()
        .filter(|row| row["entry"]["payload"]["outcome"]["operation"] == handle["mac"])
        .count();
    let terminals = rows
        .iter()
        .filter(|row| row["entry"]["payload"]["terminal"]["operation"] == handle["mac"])
        .count();
    let observations = rows
        .iter()
        .filter(|row| {
            row["entry"]["payload"]["event"]["request"] == handle["body"]["event"]["request"]
        })
        .count();
    verified
        && page.next_cursor().is_none()
        && intents == 1
        && outcomes == 1
        && terminals == 1
        && observations == 0
}

async fn no_running_intent(f: &Fixture) -> bool {
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
    let replace = serde_json::to_value(opc_persist::ManagementAuditOperationCode::Replace).unwrap();
    page.next_cursor().is_none()
        && value["rows"].as_array().unwrap().iter().all(|row| {
            row["entry"]["payload"]["target-intent"]["handle"]["body"]["event"]["operation"]
                != replace
                && row["entry"]["payload"]["intent"]["body"]["event"]["operation"] != replace
        })
}

#[tokio::test]
async fn retained_running_protocol_native_replace_and_nmda_publish_exact_original() {
    let f = Fixture::new().await;
    let server = f.server(policy_allow_system_with_secret_writes());
    let attached = server.is_ok();
    let Ok(server) = server else {
        let drained = f.close().await;
        eprintln!("{CLEAN}: unattached={drained}");
        assert!(attached && drained, "RETAINED_RUNNING_PROTOCOL_HANDOFF_RED");
        return;
    };
    let mut client = Client::start(server.clone(), SessionRegistry::new(), 71).await;
    let mut results = Vec::new();
    let mut previous = None;
    for (label, nmda, version) in [("fixture-first", false, 1), ("fixture-second", true, 2)] {
        let reply = client.rpc(&edit(label, nmda, "replace")).await;
        let record = f.encrypted.load_committed_latest().await.unwrap();
        let mut exact = false;
        let mut audit = false;
        let mut chain = false;
        if let Some(record) = &record {
            exact = exact_record(&f, record, label, version).await;
            chain = record.parent_tx_id == previous;
            if let Some(receipt) = recovered(&f, record).await {
                audit = original_audit(&f, &receipt).await;
            }
            previous = Some(record.tx_id);
        }
        results.push((reply.contains("<ok/>"), exact, audit, chain));
    }
    let encrypted = f.provider.active.load(Ordering::Acquire);
    let closed = client.close().await;
    drop(server);
    let drained = f.close().await;
    eprintln!("{CLEAN}: published closed={closed} drained={drained}");
    assert!(closed && drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
    assert!(
        results
            .iter()
            .all(|(_, exact, audit, chain)| *exact && *audit && *chain)
            && encrypted == 2,
        "RETAINED_RUNNING_PROTOCOL_HANDOFF_RED"
    );
    assert!(
        results.iter().all(|(ok, _, _, _)| *ok),
        "RETAINED_RUNNING_PROTOCOL_KNOWN_RESULT_RED"
    );
}

#[tokio::test]
async fn retained_running_protocol_known_applied_debt_recovers_same_original() {
    for checkpoint_fault in [true, false] {
        let f = Fixture::new().await;
        let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
        let mut client = Client::start(server.clone(), SessionRegistry::new(), 72).await;
        let sequence = f.checkpoint.inner.sequence();
        if checkpoint_fault {
            // Intent is acknowledged first. Stop the next checkpoint advance,
            // after the native effect; never synthesize an Apply response.
            f.checkpoint
                .inner
                .refuse_from
                .store(sequence + 2, Ordering::Release);
        } else {
            f.provider.fail_lookup.store(true, Ordering::Release);
        }
        let reply = client.rpc(&edit("fixture-debt", false, "replace")).await;
        // Observe the real native row without restoring the worker's key lookup.
        // Its automatic recovery pass must remain faulted until the checks finish.
        let record = f.store.load_latest().await.unwrap();
        let hidden = f.store.load_committed_latest().await.unwrap().is_none();
        let prepared_request = *f.checkpoint.prepared_request.lock().unwrap();
        let original = match prepared_request {
            Some(request) => recovered_request(&f, request).await,
            None => None,
        };
        let known_debt = original.as_ref().is_some_and(|receipt| {
            receipt.publication_pending()
                && receipt.completion_pending() == checkpoint_fault
                && receipt.published_commit().is_none()
        });
        let fenced = client.rpc(&edit("fixture-fenced", false, "replace")).await;
        let one_encryption = f.provider.active.load(Ordering::Acquire) == 1;
        let version_before_restore = f.bus.current_snapshot().version.get();
        f.checkpoint.inner.refuse_from.store(0, Ordering::Release);
        f.provider.fail_lookup.store(false, Ordering::Release);
        let mut same = false;
        let mut exact = false;
        let mut audited = false;
        if let (Some(original), Some(record)) = (&original, &record) {
            if let NetconfMutationResult::Applied(receipt) = f
                .audit
                .recover(original.recovery_handle(), &principal())
                .await
            {
                same = receipt.outcome() == original.outcome()
                    && receipt.recovery_handle() == original.recovery_handle();
                audited = original_audit(&f, &receipt).await;
                let readback = f.encrypted.load_committed_latest().await.unwrap().unwrap();
                exact = readback.tx_id == record.record.tx_id
                    && exact_record(&f, &readback, "fixture-debt", 1).await;
            }
        }
        let closed = client.close().await;
        drop(server);
        let drained = f.close().await;
        eprintln!("{CLEAN}: debt checkpoint={checkpoint_fault} closed={closed} drained={drained}");
        eprintln!(
            "RETAINED_RUNNING_PROTOCOL_DEBT_OBSERVED: checkpoint={checkpoint_fault} \
             reply_error={} reply_ok={} known_debt={known_debt} hidden={hidden} \
             fenced_error={} one_encryption={one_encryption} same={same} exact={exact} audited={audited} \
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
        assert!(closed && drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
        assert!(
            reply.contains("<rpc-error>")
                && !reply.contains("<ok/>")
                && known_debt
                && hidden
                && fenced.contains("<rpc-error>")
                && one_encryption
                && same
                && exact
                && audited,
            "RETAINED_RUNNING_PROTOCOL_ORIGINAL_DEBT_RED"
        );
    }
}

#[tokio::test]
async fn retained_running_protocol_requires_owner_and_preserves_nacm_and_profile_refusals() {
    let f = Fixture::new().await;
    let mut refusals = true;
    for bits in [1, 2, 4, 7, 8] {
        let mut binding = Binding::new(f.bus.clone());
        binding.capabilities.store(bits, Ordering::Release);
        if bits == 8 {
            // An unadvertised startup facade is still an unsupported owner.
            binding.startup = Some(Arc::new(MemoryStartupDatastore::new(None, true)));
        }
        refusals &= matches!(
            unattached(binding, policy_allow_system_with_secret_writes())
                .with_retained_running_audit(f.audit.clone()),
            Err(ServerInitError::RequiredAuditProfileUnsupported)
        );
    }
    let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
    let registry = SessionRegistry::new();
    let mut first = Client::start(server.clone(), registry.clone(), 73).await;
    let mut second = Client::start(server.clone(), registry.clone(), 74).await;
    let locked = first.rpc(&lock_rpc("running")).await;
    let calls = f.provider.calls();
    let other = second
        .rpc(&edit("fixture-wrong-owner", false, "replace"))
        .await;
    let numeric = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &edit("fixture-numeric-only", false, "replace"),
            &MgmtLimits::default(),
            73,
            &registry,
        )
        .await;
    // Patch is supported; the existing explicit edit-option refusal remains.
    let unsupported_xml = edit("fixture-unsupported-option", false, "merge").replace(
        "<config>",
        "<error-option>continue-on-error</error-option><config>",
    );
    let unsupported = first.rpc(&unsupported_xml).await;
    let unlocked = first.rpc(&unlock_rpc("running")).await;
    let denied_server = f
        .server(policy_allow_system_but_deny_edit_config())
        .unwrap();
    let mut denied = Client::start(denied_server.clone(), registry, 75).await;
    let denial = denied.rpc(&edit("fixture-nacm", false, "replace")).await;
    let no_provider = calls == f.provider.calls();
    let no_history = f.encrypted.load_latest().await.unwrap().is_none();
    let closed_first = first.close().await;
    let closed_second = second.close().await;
    let closed_denied = denied.close().await;
    let closed = closed_first && closed_second && closed_denied;
    drop(server);
    drop(denied_server);
    let drained = f.close().await;
    eprintln!("{CLEAN}: refusals closed={closed} drained={drained}");
    assert!(closed && drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
    assert!(
        refusals
            && locked.contains("<ok/>")
            && unlocked.contains("<ok/>")
            && other.contains("<rpc-error>")
            && numeric.reply_xml.contains("<rpc-error>")
            && unsupported.contains("operation-not-supported")
            && denial.contains("access-denied")
            && no_provider
            && no_history,
        "RETAINED_RUNNING_PROTOCOL_AUTHORITY_RED"
    );
}

#[tokio::test]
async fn retained_running_protocol_final_runner_drop_before_intent_and_after_native_wait() {
    for native_wait in [false, true] {
        let f = Fixture::new().await;
        let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
        let mut client = Client::start(server.clone(), SessionRegistry::new(), 76).await;
        let gate = if native_wait {
            f.checkpoint.admission_gate.clone()
        } else {
            f.provider.encrypt_gate.clone()
        };
        let release = gate.arm();
        f.checkpoint
            .after_prepare
            .store(native_wait, Ordering::Release);
        client
            .send(&edit("fixture-revoked", false, "replace"))
            .await;
        let reached = tokio::time::timeout(WAIT, gate.entered()).await.is_ok();
        let cancelled = client.cancel().await;
        drop(release);
        // FIFO worker barrier waits for the actual admitted work and owner-drop
        // cleanup. A random absent request cannot invent a mutation outcome.
        let barrier = f
            .audit
            .recover_request(RequestId::new(), &principal())
            .await;
        let request = *f.checkpoint.prepared_request.lock().unwrap();
        let original = match request {
            Some(request) => f.audit.recover_request(request, &principal()).await,
            None => Ok(None),
        };
        let refused = matches!(original, Ok(Some(NetconfMutationResult::Refused(ref error)))
            if error.code == CommitErrorCode::AdmissionRejected);
        let no_history = f.encrypted.load_latest().await.unwrap().is_none();
        let empty = f.bus.current_snapshot().version.get() == 0;
        let no_intent = no_running_intent(&f).await;
        let loads = f.checkpoint.observed_loads.load(Ordering::Acquire);
        let encrypted = f.provider.active.load(Ordering::Acquire);
        drop(server);
        let drained = f.close().await;
        eprintln!("{CLEAN}: revoked native_wait={native_wait} drained={drained}");
        assert!(drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
        assert!(
            reached
                && cancelled
                && barrier.is_ok()
                && request.is_some()
                && no_history
                && empty
                && no_intent
                && encrypted == 1
                && (!native_wait || (loads == 3 && refused)),
            "RETAINED_RUNNING_PROTOCOL_FINAL_OWNER_RED"
        );
    }
}

#[tokio::test]
async fn retained_running_protocol_runner_drop_after_effect_keeps_original_publication() {
    let f = Fixture::new().await;
    let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
    let mut client = Client::start(server.clone(), SessionRegistry::new(), 77).await;
    let release = f.provider.readback_gate.arm();
    client
        .send(&edit("fixture-cancelled", false, "replace"))
        .await;
    let reached = tokio::time::timeout(WAIT, f.provider.readback_gate.entered())
        .await
        .is_ok();
    let cancelled = client.cancel().await;
    drop(release);
    let barrier = f
        .audit
        .recover_request(RequestId::new(), &principal())
        .await;
    let record = f.encrypted.load_committed_latest().await.unwrap();
    let mut exact = false;
    let mut audited = false;
    if let Some(record) = &record {
        exact = exact_record(&f, record, "fixture-cancelled", 1).await;
        if let Some(receipt) = recovered(&f, record).await {
            audited = original_audit(&f, &receipt).await;
        }
    }
    let encrypted = f.provider.active.load(Ordering::Acquire);
    drop(server);
    let drained = f.close().await;
    eprintln!("{CLEAN}: cancelled-after-effect drained={drained}");
    assert!(drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
    assert!(
        reached && cancelled && barrier.is_ok() && exact && audited && encrypted == 1,
        "RETAINED_RUNNING_PROTOCOL_CANCELLED_REPLY_RED"
    );
}
