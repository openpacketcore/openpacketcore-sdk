//! Real RFC 026 worker endpoint used by both local-kernel adapter fixtures.
use super::*;
use opc_session_net::scope::*;
use opc_session_store::scope_scheduler::{
    ClassBudget, ScopeSchedulerBudgets, ScopeSchedulerOwner, ScopeWorkClass,
};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use std::{collections::HashSet, net::SocketAddr};

struct Clock;
impl AuthenticationClock for Clock {
    fn interval(&self) -> Result<opc_tls::AuthenticationTimeInterval, AuthenticationTimeError> {
        let now = opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::now_utc());
        opc_tls::AuthenticationTimeInterval::new(now, now).map_err(|_| AuthenticationTimeError)
    }
}
struct Boots(BootAuthorityRecord);
#[async_trait]
impl ScopeBootAuthority for Boots {
    async fn read_current(
        &self,
        _: &ScopeBinding,
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        Ok(self.0.clone())
    }
    async fn read_known(
        &self,
        _: &ScopeBinding,
        _: [u8; 32],
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        Ok(self.0.clone())
    }
}
#[derive(Default)]
struct Closures(std::sync::Mutex<BTreeMap<[u8; 32], LocalClosureRecord>>);
#[async_trait]
impl ScopeLocalClosurePublisher for Closures {
    async fn publish(&self, evidence: &LocalClosurePublication) -> Result<(), ScopeEvidenceError> {
        self.0
            .lock()
            .unwrap()
            .insert(evidence.record().digest()?, evidence.record().clone());
        Ok(())
    }
}
#[async_trait]
impl ScopeClosureSource for Closures {
    async fn read_final(
        &self,
        _: &ScopeAuthorityStamp,
        _: [u8; 32],
    ) -> Result<FinalTerminationRecord, ScopeEvidenceError> {
        Err(ScopeEvidenceError::Unavailable)
    }
    async fn read_local(
        &self,
        _: &ScopeAuthorityStamp,
        digest: [u8; 32],
    ) -> Result<LocalClosureRecord, ScopeEvidenceError> {
        self.0
            .lock()
            .unwrap()
            .get(&digest)
            .cloned()
            .ok_or(ScopeEvidenceError::Unavailable)
    }
}

fn spiffe(instance: &str) -> String {
    format!(
        "spiffe://local-scope.test/tenant/test/ns/default/sa/kernel/nf/test/instance/{instance}"
    )
}
struct Pki(rcgen::CertifiedIssuer<'static, rcgen::KeyPair>);
impl Pki {
    fn new() -> Self {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "kernel scope test CA");
        Self(
            rcgen::CertifiedIssuer::self_signed(parameters, rcgen::KeyPair::generate().unwrap())
                .unwrap(),
        )
    }
    fn identity(&self, identity: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(identity).unwrap(),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &self.0).unwrap();
        let certificates =
            opc_identity::parse_certs_pem(&(certificate.pem() + &self.0.pem())).unwrap();
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(opc_identity::TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("local-scope.test").unwrap(),
            certificates: opc_identity::parse_certs_pem(&self.0.pem()).unwrap(),
        });
        opc_identity::build_identity_state(
            certificates,
            opc_identity::parse_key_pem(&key.serialize_pem()).unwrap(),
            bundles,
        )
        .unwrap()
    }
    fn tls(&self, identity: &str, peer: &str) -> TlsConfigBuilder {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity(identity)));
        TlsConfigBuilder::new(receiver).with_policy(PeerPolicy {
            allowed_instances: Some(HashSet::from([opc_types::InstanceId::new(peer).unwrap()])),
            ..Default::default()
        })
    }
}

pub(super) struct NativeTransport {
    pub(super) client: ScopeClient,
    pub(super) committed: CommittedScopeAuthority,
    pub(super) scheduler: ScopeSchedulerOwner,
    _server_scheduler: ScopeSchedulerOwner,
    pub(super) coordinator: ScopeBatchCoordinator,
    pub(super) pending: tokio::sync::Mutex<[Option<Pending>; SCOPE_BATCH_LANES]>,
    server: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    _directory: tempfile::TempDir,
}
impl NativeTransport {
    pub(super) async fn start(store: ConsensusSessionStore, scope: ScopeId) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let binding = ScopeBinding::from_scope(&scope).unwrap();
        let process = Arc::new(
            ScopeProcess::new(
                binding.clone(),
                [1; 16],
                BootIdentity::generate().unwrap(),
                std::fs::File::open(directory.path()).unwrap(),
            )
            .unwrap(),
        );
        let worker = spiffe("worker");
        let server_identity = spiffe("voter");
        let execution = ScopeExecution::new(
            SessionConsumerIdentity::new(worker.clone()).unwrap(),
            1,
            [1; 16],
            *process.boot().process_nonce(),
            process.boot().key_digest(),
        )
        .unwrap();
        let record = BootAuthorityRecord::new(
            binding.clone(),
            execution,
            *process.boot().public_key(),
            b"kernel-test-authority".to_vec(),
            b"rv:1".to_vec(),
        )
        .unwrap();
        let ticket = BootTicket::from_authority_record(&process, &record).unwrap();
        let pki = Pki::new();
        let server_scheduler = ScopeSchedulerOwner::default();
        let scheduler = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
            ScopeWorkClass::Normal,
            ClassBudget {
                queued: 64,
                running: 1,
            },
        ))
        .unwrap();
        let closures = Arc::new(Closures::default());
        let server = Arc::new(
            ScopeServer::new(ScopeServerConfig {
                tls: pki
                    .tls(&server_identity, "worker")
                    .build_authenticated_server_config()
                    .unwrap(),
                clock: Arc::new(Clock),
                policy: ScopePolicy::new(vec![PrincipalGrant::new(
                    opc_types::SpiffeId::new(worker.clone()).unwrap(),
                    ScopeRole::Worker,
                    vec![binding],
                )
                .unwrap()])
                .unwrap(),
                store: Arc::new(store),
                scopes: vec![scope.clone()],
                boots: Arc::new(Boots(record)),
                closures: closures.clone(),
                scheduler: server_scheduler.scheduler(),
                proofs: ProofBudgets::default(),
            })
            .unwrap(),
        );
        // Scope containment deliberately blocks loopback in the kernel tests.
        // Keep worker-to-voter traffic on a distinct management veth, with the
        // server in an owned anonymous namespace, like a remote retained voter.
        let (addresses, stop, thread) = serve_management(server).await;
        let client = ScopeClient::new(ScopeClientConfig {
            process,
            scope,
            ticket,
            tls: pki
                .tls(&worker, "voter")
                .build_authenticated_client_config()
                .unwrap(),
            server: opc_types::SpiffeId::new(server_identity).unwrap(),
            addresses,
            clock: Arc::new(Clock),
            scheduler: scheduler.scheduler(),
            local_closure: closures,
        })
        .unwrap();
        let initial = client.prepare_initial().await.unwrap();
        let ScopeAuthorityReply::Admitted(committed) = client
            .submit(&initial, Duration::from_secs(5))
            .await
            .unwrap()
        else {
            panic!("own native admission must produce the actual committed capability");
        };
        let coordinator = client
            .batches(&committed, ScopeWorkClass::Normal, Duration::from_secs(1))
            .await
            .unwrap();
        Self {
            client,
            committed: *committed,
            coordinator,
            pending: tokio::sync::Mutex::new(std::array::from_fn(|_| None)),
            scheduler,
            _server_scheduler: server_scheduler,
            server: std::sync::Mutex::new(Some(stop)),
            thread: std::sync::Mutex::new(Some(thread)),
            _directory: directory,
        }
    }
    pub(super) async fn close(&self) {
        for pending in self
            .pending
            .lock()
            .await
            .iter_mut()
            .filter_map(Option::take)
        {
            assert!(
                pending.reconciled,
                "unresolved native activation at fixture shutdown"
            );
            assert!(self.coordinator.ack(pending.handle.attempt()));
        }
        if let Some(stop) = self.server.lock().unwrap().take() {
            let _ = stop.send(());
        }
        let thread = self.thread.lock().unwrap().take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join().unwrap())
                .await
                .unwrap();
        }
    }
}
impl Drop for NativeTransport {
    fn drop(&mut self) {
        if let Some(stop) = self.server.get_mut().unwrap().take() {
            let _ = stop.send(());
        }
    }
}
pub(super) struct Pending {
    pub(super) request: ScopeBatchRequest,
    pub(super) handle: ScopeBatchHandle,
    pub(super) reconciled: bool,
}
fn ip(arguments: &[&str]) {
    let output = std::process::Command::new("ip")
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
async fn serve_management(
    server: Arc<ScopeServer>,
) -> (
    [SocketAddr; 5],
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let (identity, remote_identity) = std::sync::mpsc::channel();
    let (configured, configuration) = std::sync::mpsc::channel();
    let (ready, addresses) = tokio::sync::oneshot::channel();
    let (stop, stopping) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        identity.send(nix::unistd::gettid()).unwrap();
        configuration.recv().unwrap();
        ip(&["address", "add", "192.0.2.254/30", "dev", "scope-peer"]);
        ip(&["link", "set", "scope-peer", "up"]);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = server
                    .serve([SocketAddr::from(([192, 0, 2, 254], 0)); 5])
                    .await
                    .unwrap();
                ready.send(handle.addresses()).unwrap();
                let _ = stopping.await;
                handle.shutdown().await;
            });
    });
    let tid = remote_identity.recv().unwrap().to_string();
    ip(&[
        "link",
        "add",
        "scope-rpc",
        "type",
        "veth",
        "peer",
        "name",
        "scope-peer",
    ]);
    ip(&["link", "set", "scope-peer", "netns", &tid]);
    ip(&["address", "add", "192.0.2.253/30", "dev", "scope-rpc"]);
    ip(&["link", "set", "scope-rpc", "up"]);
    configured.send(()).unwrap();
    (addresses.await.unwrap(), stop, thread)
}
