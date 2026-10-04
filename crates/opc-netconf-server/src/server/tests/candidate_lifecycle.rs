//! Candidate lifecycle baseline for SDK #958 and RFC 019.
//!
//! These exercise the existing volatile candidate profile with its existing
//! capturing fixture. They do not qualify required-audit admission, encryption,
//! retained generations, transport authentication, or restart recovery. The
//! replicated observation sink and the running-only required profile are
//! unchanged. RFC 6241 section 8.3.5.2 requires pending candidate changes to be
//! discarded on both explicit and implicit release of the candidate lock.

use super::*;
use crate::session_registry::SessionRegistration;

type CandidateServer =
    ReadOnlyNetconfServer<DemoConfig, GeneratedEditBinding, FixedPolicy, CapturingAudit>;

struct Fixture {
    server: CandidateServer,
    bus: Arc<ConfigBus<DemoConfig>>,
    sessions: SessionRegistry,
    owner: Option<SessionRegistration>,
    _other: SessionRegistration,
    initial_version: ConfigVersion,
}

impl Fixture {
    async fn staged() -> Self {
        let (server, bus, _audit) = generated_edit_server_fixture().await;
        let sessions = SessionRegistry::new();
        let owner = sessions.register(1).unwrap();
        let other = sessions.register(2).unwrap();
        let initial_version = bus.current_snapshot().version;
        let fixture = Self {
            server,
            bus,
            sessions,
            owner: Some(owner),
            _other: other,
            initial_version,
        };
        assert!(fixture.server.binding.candidate_datastore_capability());
        assert!(
            fixture
                .rpc(1, &lock_rpc("candidate"))
                .await
                .reply_xml
                .contains("<ok/>"),
            "candidate lock setup failed"
        );
        assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
        assert!(fixture
            .rpc(1, &edit_config_rpc_to(
                "candidate",
                r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-staged</sys:hostname></sys:system>"#,
                "merge",
            ))
            .await
            .reply_xml
            .contains("<ok/>"), "candidate stage setup failed");
        fixture.assert_staged().await;
        fixture
    }

    async fn rpc(&self, session: u64, xml: &str) -> RpcHandlingResult {
        self.server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                xml,
                &MgmtLimits::default(),
                session,
                &self.sessions,
            )
            .await
    }

    async fn assert_staged(&self) {
        let readback = self.rpc(2, &get_config_rpc("candidate")).await;
        assert!(
            readback
                .reply_xml
                .contains("<sys:hostname>fixture-staged</sys:hostname>"),
            "candidate stage is not independently readable"
        );
        self.assert_running_unchanged();
    }

    fn assert_running_unchanged(&self) {
        let current = self.bus.current_snapshot();
        assert_eq!(current.version, self.initial_version);
        assert!(
            current.config.hostname == "amf-1",
            "running content changed"
        );
    }

    async fn assert_discarded(&self) {
        self.assert_running_unchanged();
        let readback = self.rpc(2, &get_config_rpc("candidate")).await;
        assert!(
            readback
                .reply_xml
                .contains("<sys:hostname>amf-1</sys:hostname>"),
            "released candidate retains uncommitted content"
        );
        assert!(
            !readback.reply_xml.contains("fixture-staged"),
            "discarded candidate content remains visible"
        );
    }
}

#[tokio::test]
async fn asynchronous_candidate_unlock_discards_uncommitted_changes() {
    let fixture = Fixture::staged().await;
    let unlocked = fixture.rpc(1, &unlock_rpc("candidate")).await;
    assert!(unlocked.reply_xml.contains("<ok/>"), "unlock failed");
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), None);
    fixture.assert_discarded().await;
}

#[tokio::test]
async fn synchronous_candidate_unlock_discards_uncommitted_changes() {
    let fixture = Fixture::staged().await;
    let unlocked = fixture.server.handle_rpc_for_session(
        RequestId::new(),
        &principal(),
        &unlock_rpc("candidate"),
        &MgmtLimits::default(),
        1,
        &fixture.sessions,
    );
    assert!(unlocked.reply_xml.contains("<ok/>"), "unlock failed");
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), None);
    fixture.assert_discarded().await;
}

#[tokio::test]
async fn candidate_owner_registration_drop_discards_uncommitted_changes() {
    let mut fixture = Fixture::staged().await;
    // Exercise the registry's actual implicit-release boundary. This is not
    // evidence of an authenticated transport disconnect or process restart.
    drop(fixture.owner.take());
    assert!(!fixture.sessions.contains_session_for_test(1));
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), None);
    fixture.assert_discarded().await;
}

#[tokio::test]
async fn explicit_discard_control_resets_candidate_and_preserves_its_lock() {
    let fixture = Fixture::staged().await;
    let discarded = fixture.rpc(1, &discard_changes_rpc()).await;
    assert!(discarded.reply_xml.contains("<ok/>"), "discard failed");
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
    fixture.assert_discarded().await;
}

#[tokio::test]
async fn other_session_unlock_control_preserves_candidate_and_ownership() {
    let fixture = Fixture::staged().await;
    let denied = fixture.rpc(2, &unlock_rpc("candidate")).await;
    assert!(
        denied
            .reply_xml
            .contains("<error-tag>lock-denied</error-tag>"),
        "non-owner unlock was not refused"
    );
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
    fixture.assert_staged().await;
}

#[tokio::test]
async fn running_unlock_control_preserves_a_distinct_locked_candidate() {
    let fixture = Fixture::staged().await;
    assert!(
        fixture
            .rpc(1, &lock_rpc("running"))
            .await
            .reply_xml
            .contains("<ok/>"),
        "running lock setup failed"
    );
    assert!(
        fixture
            .rpc(1, &unlock_rpc("running"))
            .await
            .reply_xml
            .contains("<ok/>"),
        "running unlock failed"
    );
    assert_eq!(fixture.sessions.running_lock_owner_for_test(), None);
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
    fixture.assert_staged().await;
}

#[tokio::test]
async fn non_owner_registration_drop_control_preserves_locked_candidate() {
    let fixture = Fixture::staged().await;
    let unrelated = fixture.sessions.register(3).unwrap();
    drop(unrelated);
    assert!(!fixture.sessions.contains_session_for_test(3));
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
    fixture.assert_staged().await;
}

// Only the legacy fixture's next intent can pause. The real replicated
// observation sink is not used or modified by these lifecycle controls.
#[derive(Clone, Default)]
struct PausedCandidateAudit {
    inner: CapturingAudit,
    pause_next: Arc<AtomicBool>,
    refuse_next_success: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl AuditSink for PausedCandidateAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if event.outcome == AuditOutcome::Success
            && self.refuse_next_success.swap(false, Ordering::AcqRel)
        {
            return Err(AuditError::unavailable(
                "synthetic candidate observation unavailable",
            ));
        }
        self.inner.record(event)
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        Box::pin(async move {
            if event.outcome == AuditOutcome::Intent
                && self.pause_next.swap(false, Ordering::AcqRel)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.record(event)
        })
    }
}

type PausedCandidateServer =
    ReadOnlyNetconfServer<DemoConfig, GeneratedEditBinding, FixedPolicy, PausedCandidateAudit>;

struct PausedFixture {
    server: Arc<PausedCandidateServer>,
    bus: Arc<ConfigBus<DemoConfig>>,
    audit: PausedCandidateAudit,
    sessions: SessionRegistry,
    owner: Option<SessionRegistration>,
    _observer: SessionRegistration,
}

impl PausedFixture {
    async fn staged() -> Self {
        let (server, bus, audit) =
            generated_edit_server_with_audit(PausedCandidateAudit::default()).await;
        let sessions = SessionRegistry::new();
        let owner = sessions.register(1).unwrap();
        let observer = sessions.register(2).unwrap();
        let fixture = Self {
            server: Arc::new(server),
            bus,
            audit,
            sessions,
            owner: Some(owner),
            _observer: observer,
        };
        fixture.assert_ok(&lock_rpc("candidate")).await;
        fixture.assert_ok(&candidate_edit("fixture-staged")).await;
        fixture.assert_candidate("fixture-staged").await;
        fixture
    }

    async fn rpc(&self, session: u64, xml: &str) -> RpcHandlingResult {
        self.server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                xml,
                &MgmtLimits::default(),
                session,
                &self.sessions,
            )
            .await
    }

    async fn assert_ok(&self, xml: &str) {
        assert!(
            self.rpc(1, xml).await.reply_xml.contains("<ok/>"),
            "candidate setup failed"
        );
    }

    async fn assert_candidate(&self, hostname: &str) {
        let readback = self.rpc(2, &get_config_rpc("candidate")).await;
        assert!(
            readback
                .reply_xml
                .contains(&format!("<sys:hostname>{hostname}</sys:hostname>")),
            "candidate generation content changed"
        );
    }

    async fn pause_rpc(&self, xml: String) -> tokio::task::JoinHandle<RpcHandlingResult> {
        self.audit.pause_next.store(true, Ordering::Release);
        let server = Arc::clone(&self.server);
        let sessions = self.sessions.clone();
        let task = tokio::spawn(async move {
            server
                .handle_rpc_for_session_async(
                    RequestId::new(),
                    &principal(),
                    &xml,
                    &MgmtLimits::default(),
                    1,
                    &sessions,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), self.audit.entered.notified())
            .await
            .expect("candidate intent was not reached");
        task
    }

    async fn replace_owner(&mut self, replace_session: bool) {
        if replace_session {
            drop(self.owner.take());
            self.owner = Some(self.sessions.register(1).expect("replacement registration"));
        } else {
            self.assert_ok(&unlock_rpc("candidate")).await;
        }
        self.assert_ok(&lock_rpc("candidate")).await;
        self.assert_candidate("amf-1").await;
        self.assert_ok(&candidate_edit("fixture-new")).await;
        self.assert_candidate("fixture-new").await;
    }

    async fn finish(&self, task: tokio::task::JoinHandle<RpcHandlingResult>) -> RpcHandlingResult {
        self.audit.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("candidate RPC did not finish")
            .expect("candidate RPC task")
    }
}

fn candidate_edit(hostname: &str) -> String {
    edit_config_rpc_to(
        "candidate",
        &format!(
            r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{hostname}</sys:hostname></sys:system>"#,
        ),
        "merge",
    )
}

async fn check_delayed_local_mutations(replace_session: bool) {
    for xml in [
        candidate_edit("fixture-old"),
        edit_data_rpc(
            "candidate",
            r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-old</sys:hostname></sys:system>"#,
            "merge",
        ),
        copy_config_rpc("candidate", "running"),
        discard_changes_rpc(),
    ] {
        let mut fixture = PausedFixture::staged().await;
        let old = fixture.pause_rpc(xml).await;
        fixture.replace_owner(replace_session).await;
        let result = fixture.finish(old).await;
        assert!(
            result
                .reply_xml
                .contains("<error-tag>operation-failed</error-tag>"),
            "obsolete candidate write lease was accepted"
        );
        fixture.assert_candidate("fixture-new").await;
        assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
        assert_eq!(
            fixture.bus.current_snapshot().version,
            ConfigVersion::new(1)
        );
        assert!(
            fixture.bus.current_snapshot().config.hostname == "amf-1",
            "running changed"
        );
    }
}

#[tokio::test]
async fn delayed_candidate_mutations_cannot_change_a_replacement_session() {
    check_delayed_local_mutations(true).await;
}

#[tokio::test]
async fn delayed_candidate_mutations_cannot_change_a_replacement_lock() {
    check_delayed_local_mutations(false).await;
}

#[tokio::test]
async fn completed_commit_retires_only_the_candidate_it_consumed() {
    let mut fixture = PausedFixture::staged().await;
    let old = fixture.pause_rpc(commit_rpc()).await;
    fixture.replace_owner(true).await;
    let result = fixture.finish(old).await;
    assert!(
        result.reply_xml.contains("<ok/>"),
        "known commit result changed"
    );
    assert_eq!(
        fixture.bus.current_snapshot().version,
        ConfigVersion::new(2)
    );
    assert!(
        fixture.bus.current_snapshot().config.hostname == "fixture-staged",
        "commit content changed"
    );
    let candidate = fixture
        .server
        .candidate
        .lock()
        .expect("candidate")
        .snapshot();
    let candidate = candidate.expect("newer candidate was discarded by an older commit");
    assert!(
        candidate.config.hostname == "fixture-new",
        "newer candidate content changed"
    );
    // The new stage is deliberately based on the old running version. Preserve
    // it as stale; this test does not claim it can be committed without rebase.
    assert_eq!(candidate.base_version, ConfigVersion::new(1));
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
}

#[tokio::test]
async fn refused_candidate_unlock_preserves_ownership_and_content() {
    for synchronous in [false, true] {
        let fixture = PausedFixture::staged().await;
        fixture
            .audit
            .refuse_next_success
            .store(true, Ordering::Release);
        let result = if synchronous {
            fixture.server.handle_rpc_for_session(
                RequestId::new(),
                &principal(),
                &unlock_rpc("candidate"),
                &MgmtLimits::default(),
                1,
                &fixture.sessions,
            )
        } else {
            fixture.rpc(1, &unlock_rpc("candidate")).await
        };
        assert!(
            result
                .reply_xml
                .contains("<error-tag>operation-failed</error-tag>"),
            "refused unlock was reported as successful"
        );
        assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), Some(1));
        fixture.assert_candidate("fixture-staged").await;
        assert_eq!(
            fixture.bus.current_snapshot().version,
            ConfigVersion::new(1)
        );
    }
}

#[tokio::test]
async fn owner_drop_invalidates_candidate_before_registry_can_reap_it() {
    let mut fixture = Fixture::staged().await;
    let owner = fixture.owner.take().expect("owner");
    let candidate = Arc::clone(&fixture.server.candidate);
    let result = fixture.sessions.terminate_after(1, move || {
        // The registry mutex is held by this hook. Registration::drop must
        // remain nonblocking and invalidate reads without waiting for reaping.
        drop(owner);
        assert!(
            candidate.lock().expect("candidate").snapshot().is_none(),
            "inactive owner retained a usable candidate before registry reaping"
        );
        Ok::<(), ()>(())
    });
    assert_eq!(result, Ok(KillSessionResult::Terminated));
    fixture.assert_discarded().await;
}

#[tokio::test]
async fn owner_drop_between_admission_and_effect_cannot_restore_released_candidate() {
    let mut fixture = Fixture::staged().await;
    let guard = match fixture.sessions.begin_candidate_write_async(1).await {
        Ok(CandidateWriteResult::Acquired(guard)) => guard,
        _ => panic!("candidate write admission failed"),
    };
    let owner = fixture.owner.take().expect("owner");
    let candidate = Arc::clone(&fixture.server.candidate);
    let mut replacement = fixture.bus.current_snapshot().config.as_ref().clone();
    replacement.hostname = "fixture-staged".to_owned();
    assert_eq!(
        guard
            .apply_if_current(move |lock| {
                // Admission has succeeded and the registry mutex is held.
                // Drop still invalidates the owner without waiting for it.
                drop(owner);
                candidate
                    .lock()
                    .expect("candidate")
                    .apply_local_effect(lock, Some((replacement, ConfigVersion::new(1))));
            })
            .await,
        Ok(true)
    );
    fixture.assert_discarded().await;
    assert_eq!(fixture.sessions.candidate_lock_owner_for_test(), None);
}
