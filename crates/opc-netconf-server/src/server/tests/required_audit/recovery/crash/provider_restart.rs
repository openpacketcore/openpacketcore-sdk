//! Process-restart detector for the existing opaque checkpoint port.
//! This synthetic, serialized fixture is not a production checkpoint backend,
//! power-loss test, separate host security domain, or recipient verifier.

use super::*;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;

const PROVIDER_ROOT: &str = "OPC_NETCONF_CHECKPOINT_RESTART_ROOT";
const REFUSE_FROM: &str = "OPC_NETCONF_CHECKPOINT_RESTART_REFUSE_FROM";
const PROVIDER_TEST: &str = concat!(
    "server::tests::required_audit::recovery::crash::provider_restart::",
    "required_running_checkpoint_provider_child"
);
const READY: &[u8; 6] = b"ready\n";

fn load_checkpoint(root: &Path) -> Option<AuditCheckpoint> {
    match std::fs::File::open(root.join("checkpoint.json")) {
        Ok(file) => {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut std::io::Read::take(file, 4097), &mut bytes).unwrap();
            assert!(bytes.len() <= 4096, "oversized checkpoint fixture state");
            Some(AuditCheckpoint::decode(&bytes).unwrap())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => panic!("checkpoint fixture state unavailable"),
    }
}

fn persist_checkpoint(root: &Path, next: &AuditCheckpoint) {
    // The service has one serialized CAS loop and no signing material. Only the
    // SDK's bounded opaque encoding crosses this boundary. Acknowledgement
    // follows file synchronization, replacement and directory synchronization.
    let bytes = next.encode().unwrap();
    let temporary = root.join("checkpoint.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    std::fs::rename(temporary, root.join("checkpoint.json")).unwrap();
    std::fs::File::open(root).unwrap().sync_all().unwrap();
}

#[tokio::test]
async fn required_running_checkpoint_provider_child() {
    let Some(root) = std::env::var_os(PROVIDER_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let refuse_from: u64 = std::env::var(REFUSE_FROM).unwrap().parse().unwrap();
    let _drop_marker = DropMarker(root.join("provider-orderly-drop"));
    let mut current = load_checkpoint(root);
    let listener = UnixListener::bind(root.join("checkpoint.sock")).unwrap();
    {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(READY).unwrap();
        stdout.flush().unwrap();
    }
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            let request: Request = read_frame(&mut stream).await.unwrap();
            let reply = match request {
                Request::Load => Reply::Loaded(current.clone().map(Box::new)),
                Request::Advance { expected, next } => {
                    let expected = expected.map(|value| *value);
                    if refuse_from != 0 && next.sequence() >= refuse_from {
                        Reply::Unavailable
                    } else if current != expected
                        || current
                            .as_ref()
                            .is_some_and(|old| old.sequence() >= next.sequence())
                    {
                        Reply::Conflict
                    } else {
                        persist_checkpoint(root, &next);
                        current = Some(*next);
                        Reply::Applied
                    }
                }
            };
            write_frame(&mut stream, &reply).await.unwrap();
        })
        .await
        .expect("checkpoint fixture connection did not complete");
    }
}

struct ProviderProcess {
    child: tokio::process::Child,
    socket: PathBuf,
}

impl ProviderProcess {
    async fn start(root: &Path, refuse_from: u64) -> Self {
        let socket = root.join("checkpoint.sock");
        match std::fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => panic!("checkpoint fixture socket unavailable"),
        }
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PROVIDER_TEST, "--nocapture", "--quiet"])
            .env(PROVIDER_ROOT, root)
            .env(REFUSE_FROM, refuse_from.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        // libtest also writes its preamble. Read bounded lines until the child
        // signals that its retained value is loaded and its socket is bound.
        // No sleeps or repeated socket probes guess at process readiness.
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut bytes = Vec::new();
            loop {
                assert!(bytes.len() < 1024, "checkpoint readiness frame oversized");
                let byte = stdout.read_u8().await.unwrap();
                bytes.push(byte);
                if bytes.ends_with(READY) {
                    break;
                }
            }
        })
        .await
        .expect("checkpoint provider did not become ready");
        Self { child, socket }
    }

    async fn crash(mut self) {
        self.child.start_kill().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .expect("checkpoint provider did not stop")
            .unwrap();
        assert_eq!(status.signal(), Some(9));
    }
}

async fn checkpoint(port: &RemoteCheckpoints) -> AuditCheckpoint {
    port.load(topology().identity()).await.unwrap().unwrap()
}

#[tokio::test]
async fn required_running_terminal_fence_survives_checkpoint_provider_process_restart() {
    let directory = tempfile::tempdir().unwrap();
    // Neither provider process owns the configuration directory. Its separate
    // fixture directory survives both process losses without a shared Arc or
    // reconstructing a high-water mark from the configuration database.
    let provider_directory = tempfile::tempdir().unwrap();
    let provider = ProviderProcess::start(provider_directory.path(), 6).await;
    let port = Arc::new(RemoteCheckpoints(provider.socket.clone()));
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ROOT, directory.path())
        .env(CHECKPOINT_SOCKET, &provider.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("NETCONF process-loss fixture did not finish")
        .unwrap();
    assert_eq!(status.code(), Some(91));
    assert!(!directory.path().join("orderly-drop").exists());
    assert!(
        std::fs::metadata(directory.path().join("config.sqlite-wal"))
            .unwrap()
            .len()
            > 0,
        "process loss left no native WAL to recover"
    );
    let original_checkpoint = checkpoint(&port).await;
    assert_eq!(original_checkpoint.sequence(), 4);
    let receipt = std::fs::read(directory.path().join("receipt.json")).unwrap();
    assert!(receipt.len() <= 256);
    let original: CommittedIdentity = serde_json::from_slice(&receipt).unwrap();

    provider.crash().await;
    assert!(
        !provider_directory
            .path()
            .join("provider-orderly-drop")
            .exists(),
        "provider loss ran orderly cleanup"
    );
    assert!(matches!(
        port.load(topology().identity()).await,
        Err(AuditAuthorityError::Unavailable)
    ));
    assert!(matches!(
        open_authority(directory.path(), port.clone(), false).await,
        Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
    ));

    let provider = ProviderProcess::start(provider_directory.path(), 6).await;
    assert!(
        checkpoint(&port).await == original_checkpoint,
        "provider restart changed its exact opaque checkpoint"
    );
    let owner = Owner::open(directory.path(), port.clone(), false).await;
    let exact = owner
        .bus
        .resolve_request_id(original.request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == original.transaction,
        "restart changed transaction"
    );
    assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
    let stored = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(2));
    assert!(
        stored.tx_id == original.transaction,
        "restart changed effect"
    );
    assert!(
        stored.request_id == Some(original.request),
        "restart changed request"
    );
    assert!(
        stored.config.hostname == "fixture-before-crash",
        "restart changed configuration"
    );

    let server = running::required_server_for_bus(owner.bus.clone());
    let sessions = SessionRegistry::new();
    let registration = sessions.register(2).unwrap();
    let later = RequestId::new();
    let refused = server
        .handle_rpc_for_session_async(
            later,
            &principal(),
            &edit("fixture-fenced"),
            &MgmtLimits::default(),
            2,
            &sessions,
        )
        .await;
    assert!(refused.reply_xml.contains("operation-failed"));
    assert!(owner.bus.resolve_request_id(later).await.unwrap().is_none());
    let unchanged = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert!(
        unchanged.tx_id == original.transaction,
        "restart lost the write fence"
    );
    assert_eq!(unchanged.version, ConfigVersion::new(2));
    assert!(
        checkpoint(&port).await == original_checkpoint,
        "refusal changed checkpoint"
    );
    let debt = owner
        .authority
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!((debt.completed, debt.pending, debt.unknown), (0, 0, 1));

    // Restart a second independent provider instance with the fault released.
    // The exact durable high-water mark, not a live service object, transfers.
    provider.crash().await;
    let provider = ProviderProcess::start(provider_directory.path(), 0).await;
    assert!(
        checkpoint(&port).await == original_checkpoint,
        "second restart changed checkpoint"
    );
    let recovered = owner
        .authority
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    let recovered_checkpoint = checkpoint(&port).await;
    assert_eq!(recovered_checkpoint.sequence(), 6);
    let exact = owner
        .bus
        .resolve_request_id(original.request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == original.transaction,
        "reconciliation changed transaction"
    );
    assert_original_terminal(&owner, &original).await;

    // Check the provider's full-value CAS contract as a fixture negative. This
    // is not a claim that the SDK could repair a rollback of both trust domains.
    assert_eq!(
        port.compare_advance(
            topology().identity(),
            Some(recovered_checkpoint.clone()),
            original_checkpoint,
        )
        .await
        .unwrap(),
        AuditCheckpointAdvance::Conflict
    );
    assert!(
        checkpoint(&port).await == recovered_checkpoint,
        "provider accepted a rollback"
    );
    let next_request = RequestId::new();
    let permitted = server
        .handle_rpc_for_session_async(
            next_request,
            &principal(),
            &edit("fixture-after-provider-recovery"),
            &MgmtLimits::default(),
            2,
            &sessions,
        )
        .await;
    assert!(permitted.reply_xml.contains("<ok/>"));
    let stored = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(3));
    assert!(
        stored.request_id == Some(next_request),
        "later write changed request"
    );
    assert!(
        stored.tx_id != original.transaction,
        "later write reused the effect"
    );
    assert!(
        stored.config.hostname == "fixture-after-provider-recovery",
        "later write changed configuration"
    );
    assert_eq!(checkpoint(&port).await.sequence(), 9);
    drop(registration);
    drop(server);
    owner.close().await;
    provider.crash().await;
}
