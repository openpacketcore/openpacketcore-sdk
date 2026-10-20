use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const CHILD: &str =
    "consumer::prepared_fenced_v2::tests::settlement_crash::preflight_settlement_crash_child";
const DIRECTORY: &str = "OPC_V2_SETTLEMENT_CRASH_DIRECTORY";
const OWNED: &str = "OPC_V2_SETTLEMENT_CRASH_OWNED";

fn backend(
    journal: FencedTransitionV2RecoveryJournal,
) -> (
    Arc<dyn ProtectedFencedTransitionV2Backend>,
    Arc<ScriptedV2Physical>,
    Arc<PreparedFencedTransitionV2Route>,
) {
    let route = Arc::new(PreparedFencedTransitionV2Route::new(ORIGIN));
    let physical = ScriptedV2Physical::new(Arc::clone(&route), vec![]);
    let erased: Arc<dyn SessionBackend> = physical.clone();
    let backend = Arc::new(
        EncryptingSessionBackend::new(
            erased,
            Arc::new(MemoryKeyProvider::new()),
            "prepared-fenced-v2-unit",
        )
        .with_fenced_transition_v2_recovery_journal(Arc::new(journal))
        .with_fenced_transition_v2_journal_scope(
            FencedTransitionV2JournalScope::from_bytes([0x73; 32]),
        ),
    );
    (backend, physical, route)
}

fn journal(path: &Path, owned: bool, create: bool) -> FencedTransitionV2RecoveryJournal {
    let key = FencedTransitionV2RecoveryJournalKey::from_bytes([0x71; 32]);
    match (owned, create) {
        (false, true) => FencedTransitionV2RecoveryJournal::create_new(path, key),
        (true, true) => FencedTransitionV2RecoveryJournal::create_new_owned(path, key),
        (false, false) => FencedTransitionV2RecoveryJournal::open_existing(path, key),
        (true, false) => FencedTransitionV2RecoveryJournal::open_existing_owned(path, key),
    }
    .expect("recovery journal")
}

fn token(
    backend: Arc<dyn ProtectedFencedTransitionV2Backend>,
    prepared: PreparedFencedTransitionV2,
    route: Arc<PreparedFencedTransitionV2Route>,
    original: bool,
) -> PersistentPreparedFencedTransitionV2Token {
    let state = PreparedRequestState::new(0);
    if !original {
        state.receipt_only();
    }
    PersistentPreparedFencedTransitionV2Token::new(
        backend,
        prepared,
        budget(),
        PreparedFencedV2HandleRouting {
            voter_count: VOTERS,
            route,
            history: Arc::new(PreparedFencedV2HistoryCache::primed(Some(history_state(
                1, 1, 0,
            )))),
        },
        state,
        original,
    )
}

#[tokio::test]
#[ignore = "controlled subprocess killed during local settlement"]
async fn preflight_settlement_crash_child() {
    let directory = std::path::PathBuf::from(std::env::var_os(DIRECTORY).expect("child directory"));
    let path = directory.join("recovery.sqlite3");
    let owned = std::env::var_os(OWNED).is_some();
    let (backend, physical, route) = backend(journal(&path, owned, true));
    let prepared = backend
        .prepare_protected_fenced_transition_v2(delete_request(
            FencedTransitionRequestId::from_bytes([0x74; 16]),
        ))
        .await
        .unwrap();
    let token = token(Arc::clone(&backend), prepared, route, true);
    // The missing pathname fails preflight and the following deletion. This
    // holds the decision-to-deletion window open without changing either
    // the journal contents or the production dispatch path.
    std::fs::rename(&path, path.with_extension("moved")).unwrap();
    assert_eq!(
        token.execute_once().await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    );
    assert_eq!(
        token.release_resolved().await,
        Err(SessionConsumerFencedTransitionV2ReleaseError::Unavailable),
        "the no-effect decision must already be resolved in memory"
    );
    std::fs::rename(path.with_extension("moved"), &path).unwrap();
    assert_eq!(
        backend
            .retained_protected_fenced_transitions_v2()
            .await
            .unwrap(),
        1
    );
    assert!(physical.voters().is_empty());
    std::fs::write(directory.join("ready"), b"resolved in memory; row retained").unwrap();
    std::future::pending::<()>().await;
}

struct CrashChild(Child);

impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn preflight_settlement_crash_retains_an_unknown_row() {
    for owned in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let output_path = directory.path().join("child.log");
        let output = std::fs::File::create(&output_path).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", CHILD, "--nocapture"])
            .env(DIRECTORY, directory.path())
            .env_remove(OWNED)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output);
        if owned {
            command.env(OWNED, "1");
        }
        let mut child = CrashChild(command.spawn().unwrap());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !directory.path().join("ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "settlement child exited before the crash point: {}",
                std::fs::read_to_string(&output_path).unwrap()
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "settlement child did not reach the crash point"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));

        let (backend, physical, route) = backend(journal(
            &directory.path().join("recovery.sqlite3"),
            owned,
            false,
        ));
        assert_eq!(
            backend
                .retained_protected_fenced_transitions_v2()
                .await
                .unwrap(),
            1
        );
        let PreparedFencedTransitionV2Lookup::Found(prepared) = backend
            .recover_protected_fenced_transition_v2(FencedTransitionRequestId::from_bytes(
                [0x74; 16],
            ))
            .await
            .unwrap()
        else {
            panic!("process loss must retain the unresolved row");
        };
        assert_eq!(
            backend.protected_fenced_transition_v2_void_eligibility(&prepared),
            if owned {
                opc_session_store::FencedTransitionV2VoidEligibility::Ready
            } else {
                opc_session_store::FencedTransitionV2VoidEligibility::UnsupportedJournal
            }
        );
        let recovered = token(Arc::clone(&backend), prepared, route, false);
        assert_eq!(
            recovered
                .status_once(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Ok(FencedTransitionV2Status::NotFound)
        );
        assert_eq!(
            recovered.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved),
            "a lost in-memory no-effect decision cannot authorize deletion"
        );
        assert_eq!(
            recovered.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert_eq!(
            backend
                .retained_protected_fenced_transitions_v2()
                .await
                .unwrap(),
            1
        );
        assert!(physical.voters().is_empty());
    }
}
