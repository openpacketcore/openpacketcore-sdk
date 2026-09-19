//! Configuration mutations outside the running ConfigBus path must obey the
//! same required-intent and truthful-result boundary. These process-local
//! fixtures prove protocol ordering, not replicated persistence.

use super::*;

#[derive(Clone, Copy, Debug)]
enum LocalMutation {
    CandidateEdit,
    CandidateEditData,
    StartupEdit,
    StartupEditData,
    CandidateCopy,
    StartupCopy,
    CandidateDiscard,
    StartupDelete,
}

const MUTATIONS: [LocalMutation; 8] = [
    LocalMutation::CandidateEdit,
    LocalMutation::CandidateEditData,
    LocalMutation::StartupEdit,
    LocalMutation::StartupEditData,
    LocalMutation::CandidateCopy,
    LocalMutation::StartupCopy,
    LocalMutation::CandidateDiscard,
    LocalMutation::StartupDelete,
];

impl LocalMutation {
    fn rpc(self) -> String {
        let edit = r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>changed</sys:hostname></sys:system>"#;
        match self {
            Self::CandidateEdit => edit_config_rpc_to("candidate", edit, "merge"),
            Self::CandidateEditData => edit_data_rpc("candidate", edit, "merge"),
            Self::StartupEdit => edit_config_rpc_to("startup", edit, "merge"),
            Self::StartupEditData => edit_data_rpc("startup", edit, "merge"),
            Self::CandidateCopy => copy_config_rpc("candidate", "running"),
            Self::StartupCopy => copy_config_rpc("startup", "running"),
            Self::CandidateDiscard => discard_changes_rpc(),
            Self::StartupDelete => delete_config_rpc("startup"),
        }
    }

    fn result(self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Self::CandidateEdit | Self::CandidateEditData => (Some("changed"), Some("boot-1")),
            Self::StartupEdit | Self::StartupEditData => {
                (Some("candidate-before"), Some("changed"))
            }
            Self::CandidateCopy => (Some("amf-1"), Some("boot-1")),
            Self::StartupCopy => (Some("candidate-before"), Some("amf-1")),
            Self::CandidateDiscard => (None, Some("boot-1")),
            Self::StartupDelete => (Some("candidate-before"), None),
        }
    }
}

async fn check_local_mutation<A: AuditSink + Clone + 'static>(
    audit: A,
    mutation: LocalMutation,
    expect_applied: bool,
) {
    let (server, bus, startup, _) =
        generated_edit_server_with_startup_audit(policy_allow_system_with_secret_writes(), audit)
            .await;
    // Fixture setup must not consume the injected failure intended for the RPC.
    let mut candidate = bus.current_snapshot().config.as_ref().clone();
    candidate.hostname = "candidate-before".into();
    server
        .candidate
        .lock()
        .expect("candidate")
        .replace(candidate, ConfigVersion::new(1));
    let sessions = SessionRegistry::new();
    let _registration = sessions.register(1).expect("registered session");
    let result = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &mutation.rpc(),
            &MgmtLimits::default(),
            1,
            &sessions,
        )
        .await;

    let expected = if expect_applied {
        mutation.result()
    } else {
        (Some("candidate-before"), Some("boot-1"))
    };
    let candidate = server
        .candidate
        .lock()
        .expect("candidate")
        .snapshot()
        .map(|snapshot| snapshot.config.hostname);
    let startup = startup.current().map(|config| config.hostname);
    assert_eq!(
        (candidate.as_deref(), startup.as_deref()),
        expected,
        "{mutation:?}: authoritative local state"
    );
    assert_eq!(bus.current_snapshot().version, ConfigVersion::new(1));
    assert_eq!(bus.current_snapshot().config.hostname, "amf-1");
    assert_eq!(
        result.reply_xml.contains("<ok/>"),
        expect_applied,
        "{mutation:?}: {}",
        result.reply_xml
    );
    assert_eq!(result.reply_xml.contains("<rpc-error>"), !expect_applied);
    assert!(!result.reply_xml.contains("synthetic private audit payload"));
}

#[tokio::test]
async fn all_local_mutations_require_sync_and_async_intent() {
    for mutation in MUTATIONS {
        for failure in [
            CommitAuditFailure::IntentError,
            CommitAuditFailure::IntentPanic,
        ] {
            check_local_mutation(ScriptedCommitAudit::new(failure), mutation, false).await;
            check_local_mutation(
                NativeAsyncCommitAudit(ScriptedCommitAudit::new(failure)),
                mutation,
                false,
            )
            .await;
        }
        check_local_mutation(CommitConstructionPanicAudit, mutation, false).await;
    }
}

#[derive(Clone, Copy)]
struct LocalTerminalFailure {
    native_async: bool,
    panic: bool,
    construction_panic: bool,
}

impl LocalTerminalFailure {
    fn result(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if event.outcome == AuditOutcome::Success {
            assert!(!self.panic, "synthetic private audit payload");
            return Err(AuditError::unavailable("synthetic private audit payload"));
        }
        Ok(())
    }
}

impl AuditSink for LocalTerminalFailure {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        assert!(!self.native_async, "native async sink called synchronously");
        self.result(event)
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        assert!(
            !(self.construction_panic && event.outcome == AuditOutcome::Success),
            "synthetic private audit payload"
        );
        Box::pin(async move {
            if self.native_async {
                tokio::task::yield_now().await;
                self.result(event)
            } else {
                self.record(event)
            }
        })
    }
}

#[tokio::test]
async fn all_local_mutations_preserve_applied_result_when_terminal_audit_fails() {
    for mutation in MUTATIONS {
        for native_async in [false, true] {
            for (panic, construction_panic) in [(false, false), (true, false), (false, true)] {
                let before = METRICS
                    .netconf_terminal_audit_failures_total
                    .load(Ordering::Relaxed);
                check_local_mutation(
                    LocalTerminalFailure {
                        native_async,
                        panic,
                        construction_panic,
                    },
                    mutation,
                    true,
                )
                .await;
                assert!(
                    METRICS
                        .netconf_terminal_audit_failures_total
                        .load(Ordering::Relaxed)
                        > before
                );
            }
        }
    }
}

#[derive(Clone, Default)]
struct PendingIntent {
    entered: Arc<tokio::sync::Notify>,
}

impl AuditSink for PendingIntent {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        panic!("pending fixture must use async admission")
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        Box::pin(async move {
            if event.outcome == AuditOutcome::Intent {
                self.entered.notify_one();
                std::future::pending().await
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn cancelled_local_intent_preserves_state_and_releases_write_reservation() {
    for mutation in MUTATIONS {
        let audit = PendingIntent::default();
        let (server, bus, startup, _) = generated_edit_server_with_startup_audit(
            policy_allow_system_with_secret_writes(),
            audit.clone(),
        )
        .await;
        let mut candidate = bus.current_snapshot().config.as_ref().clone();
        candidate.hostname = "candidate-before".into();
        server
            .candidate
            .lock()
            .expect("candidate")
            .replace(candidate, ConfigVersion::new(1));
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(1).expect("session");
        let principal = principal();
        let limits = MgmtLimits::default();
        let rpc = mutation.rpc();
        {
            let operation = server.handle_rpc_for_session_async(
                RequestId::new(),
                &principal,
                &rpc,
                &limits,
                1,
                &sessions,
            );
            tokio::pin!(operation);
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::select! {
                    _ = &mut operation => panic!("mutation completed before intent acknowledgement"),
                    _ = audit.entered.notified() => {}
                }
            }).await.expect("intent polled");
            // Cancel an admitted-but-unacknowledged audit future. It grants no
            // permission for the local configuration mutation.
        }
        assert_eq!(
            server
                .candidate
                .lock()
                .expect("candidate")
                .snapshot()
                .expect("unchanged candidate")
                .config
                .hostname,
            "candidate-before"
        );
        assert_eq!(
            startup.current().expect("unchanged startup").hostname,
            "boot-1"
        );
        assert_eq!(bus.current_snapshot().version, ConfigVersion::new(1));
        let candidate = tokio::time::timeout(
            Duration::from_secs(5),
            sessions.begin_candidate_write_async(1),
        )
        .await
        .expect("candidate reservation released")
        .expect("session");
        assert!(matches!(candidate, CandidateWriteResult::Acquired(_)));
        let startup = tokio::time::timeout(
            Duration::from_secs(5),
            sessions.begin_startup_write_async(1),
        )
        .await
        .expect("startup reservation released")
        .expect("session");
        assert!(matches!(startup, StartupWriteResult::Acquired(_)));
    }
}

#[tokio::test]
async fn session_exit_rollback_requires_intent_and_preserves_retry_state() {
    for failure in [
        CommitAuditFailure::IntentError,
        CommitAuditFailure::IntentPanic,
        CommitAuditFailure::TerminalError,
        CommitAuditFailure::TerminalPanic,
    ] {
        let audit = ScriptedCommitAudit::new(failure);
        *audit.failure.lock().expect("failure") = None;
        let (server, bus, _) = generated_edit_server_with_audit(audit.clone()).await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(1).expect("session");
        let mut candidate = bus.current_snapshot().config.as_ref().clone();
        candidate.hostname = "pending".into();
        server
            .candidate
            .lock()
            .expect("candidate")
            .replace(candidate, ConfigVersion::new(1));
        let reply = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &confirmed_commit_rpc(30),
                &MgmtLimits::default(),
                1,
                &sessions,
            )
            .await;
        assert!(reply.reply_xml.contains("<ok/>"));
        let pending_version = bus.current_snapshot().version;
        *audit.failure.lock().expect("failure") = Some(failure);
        audit.attempts.lock().expect("attempts").clear();
        server
            .rollback_pending_confirmed_commit_for_session(1, &principal())
            .await;
        if failure.is_intent() {
            assert_eq!(
                bus.current_snapshot().version,
                pending_version,
                "failed intent must prevent session-exit rollback"
            );
            assert!(
                server
                    .confirmed_commit
                    .lock()
                    .expect("pending")
                    .active(Instant::now())
                    .is_some(),
                "retry authority retained"
            );
            assert_eq!(audit.attempts.lock().expect("attempts").len(), 1);
            server
                .rollback_pending_confirmed_commit_for_session(1, &principal())
                .await;
        }
        assert!(bus.current_snapshot().version > pending_version);
        assert_eq!(bus.current_snapshot().config.hostname, "amf-1");
        assert!(server
            .confirmed_commit
            .lock()
            .expect("pending")
            .active(Instant::now())
            .is_none());
        let attempts = audit.attempts.lock().expect("attempts");
        assert_eq!(attempts[attempts.len() - 2].outcome, AuditOutcome::Intent);
        assert_eq!(attempts[attempts.len() - 1].outcome, AuditOutcome::Success);
    }
}
