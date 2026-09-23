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
