//! Abrupt process loss of the NETCONF owner, with a surviving checkpoint owner.
//! Synthetic local IPC is fixture plumbing, not a production provider or #959
//! recipient boundary. This does not simulate power loss or checkpoint restart.

use super::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

mod provider_restart;

const CHILD_ROOT: &str = "OPC_NETCONF_AUDIT_CRASH_ROOT";
const CHECKPOINT_SOCKET: &str = "OPC_NETCONF_AUDIT_CHECKPOINT_SOCKET";
const CHILD_TEST: &str =
    "server::tests::required_audit::recovery::crash::required_running_crash_child";
const FRAME_LIMIT: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
enum Request {
    Load,
    Advance {
        expected: Option<Box<AuditCheckpoint>>,
        next: Box<AuditCheckpoint>,
    },
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Loaded(Option<Box<AuditCheckpoint>>),
    Applied,
    Conflict,
    Unknown,
    Unavailable,
}

fn invalid_frame() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid checkpoint fixture frame",
    )
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid_frame())?;
    if bytes.len() > FRAME_LIMIT {
        return Err(invalid_frame());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let length = stream.read_u32().await? as usize;
    if length > FRAME_LIMIT {
        return Err(invalid_frame());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid_frame())
}

struct RemoteCheckpoints(PathBuf);

impl RemoteCheckpoints {
    async fn exchange(&self, request: Request) -> Result<Reply, AuditAuthorityError> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = UnixStream::connect(&self.0).await?;
            write_frame(&mut stream, &request).await?;
            read_frame(&mut stream).await
        })
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?
        .map_err(|_: io::Error| AuditAuthorityError::Unavailable)
    }
}

#[async_trait::async_trait]
impl AuditCheckpointPort for RemoteCheckpoints {
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if identity != topology().identity() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        match self.exchange(Request::Load).await? {
            Reply::Loaded(value) => Ok(value.map(|value| *value)),
            _ => Err(AuditAuthorityError::Unavailable),
        }
    }

    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        if identity != topology().identity() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        match self
            .exchange(Request::Advance {
                expected: expected.map(Box::new),
                next: Box::new(next),
            })
            .await?
        {
            Reply::Applied => Ok(AuditCheckpointAdvance::Applied),
            Reply::Conflict => Ok(AuditCheckpointAdvance::Conflict),
            Reply::Unknown => Ok(AuditCheckpointAdvance::Unknown),
            _ => Err(AuditAuthorityError::Unavailable),
        }
    }
}

struct CheckpointService {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl CheckpointService {
    fn start(checkpoints: Arc<Checkpoints>) -> Self {
        // Separate from the child's retained configuration directory. The parent
        // owns this provider and its exact CAS state for the complete scenario.
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("checkpoint.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    let request = read_frame(&mut stream).await.unwrap();
                    let reply = match request {
                        Request::Load => match checkpoints.load(topology().identity()).await {
                            Ok(value) => Reply::Loaded(value.map(Box::new)),
                            Err(_) => Reply::Unavailable,
                        },
                        Request::Advance { expected, next } => match checkpoints
                            .compare_advance(
                                topology().identity(),
                                expected.map(|value| *value),
                                *next,
                            )
                            .await
                        {
                            Ok(AuditCheckpointAdvance::Applied) => Reply::Applied,
                            Ok(AuditCheckpointAdvance::Conflict) => Reply::Conflict,
                            Ok(AuditCheckpointAdvance::Unknown) => Reply::Unknown,
                            Err(_) => Reply::Unavailable,
                        },
                    };
                    write_frame(&mut stream, &reply).await.unwrap();
                })
                .await
                .expect("checkpoint fixture connection did not complete");
            }
        });
        Self {
            _directory: directory,
            socket,
            task,
        }
    }
}

impl Drop for CheckpointService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Owner {
    authority: Arc<ConsensusConfigStore>,
    source: Arc<Source>,
    bus: Arc<ConfigBus<DemoConfig>>,
    stopped: Arc<tokio::sync::Notify>,
}

impl Owner {
    async fn open(root: &Path, checkpoints: Arc<dyn AuditCheckpointPort>, provision: bool) -> Self {
        let authority = Arc::new(open_authority(root, checkpoints, provision).await.unwrap());
        authority.initialize_cluster().await.unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).unwrap());
        if provision {
            authority
                .initialize_audit_authority(
                    privacy.as_ref(),
                    AuditLedgerLimits::new(90, 30).unwrap(),
                )
                .await
                .unwrap();
        }
        authority.probe_durable_readiness().await.unwrap();
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("netconf-fixture-key").unwrap(),
                KeyPurpose::Config,
                principal().tenant,
                Zeroizing::new([0x6b; AES_256_GCM_SIV_KEY_LEN]),
            )
            .unwrap();
        let source = Arc::new(EncryptingManagedDatastore::new(
            Arc::new(RaftManagedDatastore::new_audited_local_authority(
                authority.clone(),
                ConfigAuditPolicy::new(privacy, Duration::from_secs(60)).unwrap(),
            )),
            provider,
        ));
        let initial = DemoConfig {
            hostname: "fixture-initial".into(),
            secret: "synthetic-secret".into(),
        };
        if provision {
            source
                .append_commit(StoredConfig::new(
                    opc_types::TxId::new(),
                    ConfigVersion::new(1),
                    principal(),
                    RequestSource::Internal,
                    initial.clone(),
                ))
                .await
                .unwrap();
        }
        let stopped = Arc::new(tokio::sync::Notify::new());
        let bus = Arc::new(
            ConfigBus::restore_or_new(
                initial,
                source.clone(),
                Arc::new(WorkerLifetime(stopped.clone())),
            )
            .await
            .unwrap(),
        );
        Self {
            authority,
            source,
            bus,
            stopped,
        }
    }

    async fn close(self) {
        drop(self.bus);
        tokio::time::timeout(Duration::from_secs(5), self.stopped.notified())
            .await
            .unwrap();
        drop(self.source);
        self.authority.shutdown().await.unwrap();
    }
}

#[derive(Serialize, Deserialize)]
struct CommittedIdentity {
    request: RequestId,
    transaction: opc_types::TxId,
}

struct DropMarker(PathBuf);

impl Drop for DropMarker {
    fn drop(&mut self) {
        std::fs::write(&self.0, b"orderly-drop").unwrap();
    }
}

async fn assert_original_terminal(owner: &Owner, original: &CommittedIdentity) {
    use opc_persist::audit_authority::continuity::AuditExportVerifier;
    use opc_persist::audit_authority::{AuditCaller, AuditPrivacyProjection, AuditPrivacyPurpose};

    let privacy = AuditPrivacyKey::new([0x81; 32]).unwrap();
    let principal = principal();
    let descriptor = opc_mgmt_audit::principal_descriptor(&principal);
    let caller = AuditCaller::project(&privacy, principal.tenant.as_str(), &descriptor).unwrap();
    let export = owner
        .authority
        .freeze_audit_export(caller, 0, Duration::from_secs(60))
        .await
        .unwrap();
    let page = export.page(None, 256, caller).unwrap();
    assert!(page.next_cursor().is_none());
    // Authority-side inspection only. These synthetic authority signing keys
    // are never supplied by the checkpoint service or claimed to qualify #959.
    let mut verifier = AuditExportVerifier::new(
        Arc::new(AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap()),
        export.manifest().clone(),
        topology().identity(),
        caller,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    verifier.accept(&page).unwrap();
    verifier.finish().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&page.encode().unwrap()).unwrap();
    let rows = value["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let request = privacy
        .project(
            AuditPrivacyPurpose::Request,
            &[
                principal.tenant.as_str().as_bytes(),
                descriptor.as_bytes(),
                original.request.as_uuid().as_bytes(),
            ],
        )
        .unwrap();
    let request = serde_json::to_value(request).unwrap();
    let matched: Vec<_> = rows
        .iter()
        .filter(|row| row["entry"]["payload"]["intent"]["body"]["event"]["request"] == request)
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "crash recovery duplicated the original intent"
    );
    let handle = &matched[0]["entry"]["payload"]["intent"];
    let transaction = privacy
        .project(
            AuditPrivacyPurpose::Transaction,
            &[
                principal.tenant.as_str().as_bytes(),
                descriptor.as_bytes(),
                original.transaction.to_string().as_bytes(),
            ],
        )
        .unwrap();
    assert!(
        handle["body"]["event"]["caller"] == serde_json::to_value(caller).unwrap(),
        "crash recovery changed the projected caller"
    );
    assert!(
        handle["body"]["event"]["transaction"] == serde_json::to_value(transaction).unwrap(),
        "crash recovery changed the projected effect"
    );
    // The fixture RPC changes this one schema leaf. Check original protocol
    // attribution separately from the request/transaction and completion rows.
    let paths = privacy
        .project(
            AuditPrivacyPurpose::SchemaPaths,
            &[b"/sys:system/sys:hostname"],
        )
        .unwrap();
    assert!(
        handle["body"]["event"]["paths"] == serde_json::to_value(paths).unwrap(),
        "crash recovery lost protocol schema-path attribution"
    );
    for terminal in ["outcome", "terminal"] {
        assert_eq!(
            rows.iter()
                .filter(|row| row["entry"]["payload"][terminal]["operation"] == handle["mac"])
                .count(),
            1,
            "crash recovery lost or duplicated an exact completion row"
        );
    }
}

#[tokio::test]
async fn required_running_crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let socket = std::env::var_os(CHECKPOINT_SOCKET).expect("checkpoint fixture missing");
    let _drop_marker = DropMarker(root.join("orderly-drop"));
    let owner = Owner::open(root, Arc::new(RemoteCheckpoints(socket.into())), true).await;
    let server = running::required_server_for_bus(owner.bus.clone());
    let sessions = SessionRegistry::new();
    let _registration = sessions.register(1).unwrap();
    let request = RequestId::new();
    let reply = server
        .handle_rpc_for_session_async(
            request,
            &principal(),
            &edit("fixture-before-crash"),
            &MgmtLimits::default(),
            1,
            &sessions,
        )
        .await;
    assert!(reply.reply_xml.contains("<ok/>"));
    let committed = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(committed.version, ConfigVersion::new(2));
    assert!(
        committed.request_id == Some(request),
        "commit changed request"
    );
    let identity = CommittedIdentity {
        request,
        transaction: committed.tx_id,
    };
    // This private synthetic receipt is only the parent's comparison input.
    // Reopening must independently recover the exact native-WAL effect.
    std::fs::write(
        root.join("receipt.json"),
        serde_json::to_vec(&identity).unwrap(),
    )
    .unwrap();
    // Same no-Drop process-loss mechanism as the SDK retained-WAL crash test:
    // no ConfigBus shutdown, authority shutdown or SQLite Drop/checkpoint.
    std::process::exit(91);
}

#[tokio::test]
async fn required_running_terminal_fence_survives_abrupt_process_loss() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoints = Arc::new(Checkpoints::default());
    checkpoints.refuse_from.store(6, Ordering::Release);
    let service = CheckpointService::start(checkpoints.clone());
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ROOT, directory.path())
        .env(CHECKPOINT_SOCKET, &service.socket)
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
    assert!(!service.task.is_finished(), "checkpoint fixture stopped");
    assert!(!directory.path().join("orderly-drop").exists());
    assert!(
        std::fs::metadata(directory.path().join("config.sqlite-wal"))
            .unwrap()
            .len()
            > 0,
        "process loss left no native WAL to recover"
    );
    assert_eq!(checkpoints.sequence(), 4);
    let receipt = std::fs::read(directory.path().join("receipt.json")).unwrap();
    assert!(receipt.len() <= 256);
    let original: CommittedIdentity = serde_json::from_slice(&receipt).unwrap();

    let owner = Owner::open(directory.path(), checkpoints.clone(), false).await;
    let exact = owner
        .bus
        .resolve_request_id(original.request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == original.transaction,
        "crash changed transaction"
    );
    assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
    let stored = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(2));
    assert_eq!(stored.config.hostname, "fixture-before-crash");
    assert!(stored.tx_id == original.transaction, "crash changed effect");
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
    let stored = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert!(
        stored.tx_id == original.transaction,
        "crash lost the write fence"
    );
    assert_eq!(stored.config.hostname, "fixture-before-crash");
    assert_eq!(checkpoints.sequence(), 4);
    let debt = owner
        .authority
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!((debt.completed, debt.pending, debt.unknown), (0, 0, 1));
    checkpoints.refuse_from.store(0, Ordering::Release);
    let recovered = owner
        .authority
        .reconcile_audit_obligations(30)
        .await
        .unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(checkpoints.sequence(), 6);
    let exact = owner
        .bus
        .resolve_request_id(original.request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == original.transaction,
        "recovery changed transaction"
    );
    assert_original_terminal(&owner, &original).await;
    let permitted = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &edit("fixture-after-crash-recovery"),
            &MgmtLimits::default(),
            2,
            &sessions,
        )
        .await;
    assert!(permitted.reply_xml.contains("<ok/>"));
    let stored = owner.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(stored.version, ConfigVersion::new(3));
    assert_eq!(stored.config.hostname, "fixture-after-crash-recovery");
    assert!(
        stored.tx_id != original.transaction,
        "recovery reused the effect"
    );
    assert_eq!(checkpoints.sequence(), 9);
    drop(registration);
    drop(server);
    owner.close().await;
}
