//! Caller-owned acquisition recovery for the fixed, synthetic traffic fixture.
//!
//! An anonymous same-owner acquire is not a retirement barrier for an earlier
//! indeterminate acquire. Retain the exact public request before polling it.
//! Receipt reads never interpret NotFound as retirement. The fixture may then
//! explicitly resubmit only that identical request, as allowed by
//! SessionConsumerRequestId; it cannot allocate a successor until the current
//! request has a terminal result. This is not the receipt-only PreparedLease-
//! AcquireRequest facade and does not change either SDK contract.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opc_session_store::{
    ConsensusSessionStore, LeaseError, LeaseGuard, OwnerId, SessionConsumerAuthorization,
    SessionConsumerAuthorizationGrant, SessionConsumerIdentity, SessionConsumerLeaseError,
    SessionConsumerLeaseMutationOperation, SessionConsumerLeaseMutationRequest,
    SessionConsumerLeaseMutationResult, SessionConsumerLeaseMutationStatus,
    SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerTenantNfScope, SessionKey,
    SessionQuorumConsumer,
};
use opc_session_testkit::qualification::{
    QUALIFICATION_TRAFFIC_ACQUIRE_JOURNAL_MAX_BYTES as JOURNAL_LIMIT,
    QUALIFICATION_TRAFFIC_ACQUIRE_JOURNAL_VERSION as JOURNAL_VERSION,
};
use opc_types::SpiffeId;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

fn unavailable() -> LeaseError {
    LeaseError::Backend("qualification acquisition recovery unavailable".into())
}

fn now_millis() -> Result<u64, LeaseError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable())?
        .as_millis()
        .try_into()
        .map_err(|_| unavailable())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    scope: SessionConsumerScope,
    identity: String,
    key: SessionKey,
    owner: OwnerId,
    ttl: Duration,
}

impl Binding {
    pub(super) fn new(
        scope: SessionConsumerScope,
        node_index: usize,
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Self {
        Self {
            scope,
            identity: format!(
                "spiffe://qualification.example/tenant/session-ha-qualification/ns/test/sa/traffic-acquirer/nf/smf/instance/{node_index}"
            ),
            key,
            owner,
            ttl,
        }
    }

    fn retained(
        &self,
        request_id: SessionConsumerRequestId,
    ) -> SessionConsumerLeaseMutationRequest {
        SessionConsumerLeaseMutationRequest::new(
            request_id,
            SessionConsumerLeaseMutationOperation::Acquire {
                key: self.key.clone(),
                owner: self.owner.clone(),
                ttl: self.ttl,
            },
        )
    }

    fn request(&self, request_id: SessionConsumerRequestId) -> SessionConsumerRequest {
        SessionConsumerRequest::new(
            self.scope,
            request_id,
            SessionConsumerOperation::AcquireLease {
                key: self.key.clone(),
                owner: self.owner.clone(),
                ttl: self.ttl,
            },
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    original: SessionConsumerLeaseMutationRequest,
    started_millis: u64,
    expires_millis: u64,
}

impl Pending {
    fn check_restorable(&self, now: u64, budget_millis: u64) -> Result<(), LeaseError> {
        if self.started_millis > now
            || self.expires_millis <= self.started_millis
            || self.expires_millis - self.started_millis > budget_millis
        {
            return Err(LeaseError::Expired);
        }
        Ok(())
    }

    fn check_live(&self, now: u64, budget_millis: u64) -> Result<(), LeaseError> {
        self.check_restorable(now, budget_millis)?;
        if now >= self.expires_millis {
            return Err(LeaseError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalState {
    version: u8,
    binding: Binding,
    pending: Option<Pending>,
}

/// One private file beside the fixture's database, provisioned before that
/// database can be opened. Missing custody on reopen is never an empty queue.
pub(super) struct Journal {
    path: PathBuf,
    parent: File,
    state: JournalState,
    poisoned: bool,
    budget_millis: u64,
}

impl Journal {
    pub(super) fn open(
        database: &Path,
        binding: Binding,
        budget_millis: u64,
    ) -> Result<Self, LeaseError> {
        let path = database.with_extension("traffic-acquire-v1.json");
        let parent_path = path.parent().ok_or_else(unavailable)?;
        let parent = File::open(parent_path).map_err(|_| unavailable())?;
        let state = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(unavailable());
                }
                let file = open_private(&path)?;
                let mut bytes = Vec::new();
                file.take(JOURNAL_LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| unavailable())?;
                if bytes.len() as u64 > JOURNAL_LIMIT {
                    return Err(unavailable());
                }
                let state: JournalState =
                    serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
                if state.version != JOURNAL_VERSION || state.binding != binding {
                    return Err(unavailable());
                }
                if let Some(pending) = &state.pending {
                    if pending.original != binding.retained(pending.original.request_id()) {
                        return Err(unavailable());
                    }
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // This file is created before the first database open. A
                // missing file beside an existing database is lost custody.
                match fs::symlink_metadata(database) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(unavailable()),
                }
                JournalState {
                    version: JOURNAL_VERSION,
                    binding,
                    pending: None,
                }
            }
            Err(_) => return Err(unavailable()),
        };
        let mut journal = Self {
            path,
            parent,
            state,
            poisoned: false,
            budget_millis,
        };
        // Re-read is already exact. Provision only when absent, and retain
        // the original fixed pending deadline on every reopen.
        if !journal.path.exists() {
            journal.persist(journal.state.clone())?;
        }
        Ok(journal)
    }

    fn persist(&mut self, next: JournalState) -> Result<(), LeaseError> {
        if self.poisoned {
            return Err(unavailable());
        }
        // Any uncertain local write fences this object. Only a new exact
        // read may resolve which complete journal image survived.
        self.poisoned = true;
        let bytes = serde_json::to_vec(&next).map_err(|_| unavailable())?;
        if bytes.len() as u64 > JOURNAL_LIMIT {
            return Err(unavailable());
        }
        let parent = self.path.parent().ok_or_else(unavailable)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".traffic-acquire-")
            .tempfile_in(parent)
            .map_err(|_| unavailable())?;
        temporary.write_all(&bytes).map_err(|_| unavailable())?;
        temporary.as_file().sync_all().map_err(|_| unavailable())?;
        temporary.persist(&self.path).map_err(|_| unavailable())?;
        self.parent.sync_all().map_err(|_| unavailable())?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    fn prepare(&mut self, deadline: Instant) -> Result<(Pending, bool), LeaseError> {
        if self.poisoned || Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        let now = now_millis()?;
        if let Some(pending) = &self.state.pending {
            pending.check_live(now, self.budget_millis)?;
            return Ok((pending.clone(), false));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let remaining_millis = u64::try_from(remaining.as_millis())
            .map_err(|_| unavailable())?
            .min(self.budget_millis);
        let pending = Pending {
            original: self.state.binding.retained(SessionConsumerRequestId::new()),
            started_millis: now,
            expires_millis: now.checked_add(remaining_millis).ok_or_else(unavailable)?,
        };
        pending.check_live(now, self.budget_millis)?;
        let mut next = self.state.clone();
        next.pending = Some(pending.clone());
        self.persist(next)?;
        Ok((pending, true))
    }

    fn finish(&mut self, pending: &Pending, deadline: Instant) -> Result<(), LeaseError> {
        pending.check_live(now_millis()?, self.budget_millis)?;
        self.retire_terminal(pending, deadline)?;
        pending.check_live(now_millis()?, self.budget_millis)
    }

    // A terminal receipt can retire an expired request after restart, but
    // cannot authorize replay or reuse of that request's returned lease.
    fn retire_terminal(&mut self, pending: &Pending, deadline: Instant) -> Result<(), LeaseError> {
        if self.poisoned || Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        if self.state.pending.as_ref() != Some(pending) {
            return Err(unavailable());
        }
        pending.check_restorable(now_millis()?, self.budget_millis)?;
        let mut next = self.state.clone();
        next.pending = None;
        self.persist(next)?;
        if Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        pending.check_restorable(now_millis()?, self.budget_millis)
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> Result<File, LeaseError> {
    use rustix::fs::{open, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| unavailable())?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(unavailable());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private(_path: &Path) -> Result<File, LeaseError> {
    Err(unavailable())
}

#[async_trait::async_trait]
trait RequestPort: Send + Sync {
    async fn execute(&self, request: SessionConsumerRequest) -> SessionConsumerResponse;
}

/// Trusted local fixture caller of the existing consumer request/receipt
/// service. Its identity is purpose-separated from all voters. No new wire
/// consumer, consumer-mTLS authentication, or workload deployment is claimed;
/// the actual replica RPCs retain the scenario's configured transport.
struct FixturePort {
    service: Arc<dyn SessionQuorumConsumer>,
    authorization: SessionConsumerAuthorization,
}

#[async_trait::async_trait]
impl RequestPort for FixturePort {
    async fn execute(&self, request: SessionConsumerRequest) -> SessionConsumerResponse {
        self.service.execute(&self.authorization, request).await
    }
}

pub(super) struct Acquirer {
    journal: Journal,
    port: Arc<dyn RequestPort>,
}

impl Acquirer {
    pub(super) async fn from_store(
        journal: Journal,
        store: &ConsensusSessionStore,
    ) -> Result<Self, LeaseError> {
        let binding = &journal.state.binding;
        let identity =
            SessionConsumerIdentity::new(binding.identity.clone()).map_err(|_| unavailable())?;
        let grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(binding.identity.clone()).map_err(|_| unavailable())?,
            [SessionConsumerTenantNfScope::new(
                binding.key.tenant.clone(),
                binding.key.nf_kind.clone(),
            )],
        )
        .map_err(|_| unavailable())?;
        let manifest = store
            .consumer_authorization_manifest([grant])
            .await
            .map_err(|_| unavailable())?;
        if manifest.scope() != binding.scope {
            return Err(unavailable());
        }
        let authorization = manifest.authorize(&identity).map_err(|_| unavailable())?;
        Ok(Self {
            journal,
            port: Arc::new(FixturePort {
                service: Arc::new(store.consumer_service()),
                authorization,
            }),
        })
    }

    pub(super) async fn acquire_after_start(
        &mut self,
        deadline: Instant,
    ) -> Result<LeaseGuard, LeaseError> {
        if let Some(pending) = self.journal.state.pending.clone() {
            pending.check_restorable(now_millis()?, self.journal.budget_millis)?;
            match self.read_status(&pending, deadline).await? {
                SessionConsumerLeaseMutationStatus::Recorded(recorded) => {
                    let result = acquire_result(*recorded)?;
                    self.validate_result(&result)?;
                    self.journal.retire_terminal(&pending, deadline)?;
                    // Even a live old receipt is only retirement evidence at
                    // startup. Obtain distinct higher-fence restart authority.
                    // Terminal rejections, including StaleFence, stay errors.
                    let _retired = result.map_err(SessionConsumerLeaseError::into_lease_error)?;
                }
                SessionConsumerLeaseMutationStatus::NotFound => {
                    // An expired unknown request remains fenced. A still-live
                    // request may be resolved only by its exact original ID.
                    pending.check_live(now_millis()?, self.journal.budget_millis)?;
                }
                SessionConsumerLeaseMutationStatus::RequestConflict => return Err(unavailable()),
                _ => return Err(unavailable()),
            }
        }
        self.acquire(deadline).await
    }

    async fn read_status(
        &self,
        pending: &Pending,
        deadline: Instant,
    ) -> Result<SessionConsumerLeaseMutationStatus, LeaseError> {
        if Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        let status = SessionConsumerRequest::new(
            self.journal.state.binding.scope,
            pending.original.request_id(),
            SessionConsumerOperation::LeaseMutationStatus {
                request: Box::new(pending.original.clone()),
            },
        );
        let response = self.port.execute(status).await;
        if Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        match response {
            SessionConsumerResponse::LeaseMutationStatus(Ok(status)) => Ok(status),
            SessionConsumerResponse::LeaseMutationStatus(Err(_)) => {
                Err(LeaseError::OperationOutcomeUnavailable)
            }
            _ => Err(unavailable()),
        }
    }

    pub(super) async fn acquire(&mut self, deadline: Instant) -> Result<LeaseGuard, LeaseError> {
        let (pending, first_poll) = self.journal.prepare(deadline)?;
        let binding = self.journal.state.binding.clone();
        if !first_poll {
            match self.read_status(&pending, deadline).await? {
                SessionConsumerLeaseMutationStatus::Recorded(recorded) => {
                    let result = acquire_result(*recorded)?;
                    return self.finish(&pending, deadline, result);
                }
                SessionConsumerLeaseMutationStatus::NotFound => {
                    // NotFound is ambiguous. An explicit same-ID/same-body
                    // replay may resolve a crash before first transmission;
                    // no distinct successor or traffic authority is created.
                }
                SessionConsumerLeaseMutationStatus::RequestConflict => return Err(unavailable()),
                _ => return Err(unavailable()),
            }
        }
        if Instant::now() >= deadline {
            return Err(LeaseError::Expired);
        }
        pending.check_live(now_millis()?, self.journal.budget_millis)?;
        match self
            .port
            .execute(binding.request(pending.original.request_id()))
            .await
        {
            SessionConsumerResponse::AcquireLease(result) => {
                self.finish(&pending, deadline, result)
            }
            SessionConsumerResponse::OutcomeUnknown(_) => {
                Err(LeaseError::OperationOutcomeUnavailable)
            }
            _ => Err(unavailable()),
        }
    }

    fn finish(
        &mut self,
        pending: &Pending,
        deadline: Instant,
        result: Result<LeaseGuard, SessionConsumerLeaseError>,
    ) -> Result<LeaseGuard, LeaseError> {
        self.validate_result(&result)?;
        self.journal.finish(pending, deadline)?;
        result.map_err(SessionConsumerLeaseError::into_lease_error)
    }

    fn validate_result(
        &self,
        result: &Result<LeaseGuard, SessionConsumerLeaseError>,
    ) -> Result<(), LeaseError> {
        match result {
            Err(
                SessionConsumerLeaseError::OutcomeUnavailable
                | SessionConsumerLeaseError::Unavailable,
            ) => {
                // Keep exact custody even when the response says no effect
                // was observed. A later call can resolve/replay only this ID.
                return Err(LeaseError::OperationOutcomeUnavailable);
            }
            Err(SessionConsumerLeaseError::RequestConflict) => return Err(unavailable()),
            Ok(lease)
                if lease.key() != &self.journal.state.binding.key
                    || lease.owner() != &self.journal.state.binding.owner =>
            {
                return Err(unavailable())
            }
            _ => {}
        }
        Ok(())
    }
}

fn acquire_result(
    recorded: Result<SessionConsumerLeaseMutationResult, SessionConsumerLeaseError>,
) -> Result<Result<LeaseGuard, SessionConsumerLeaseError>, LeaseError> {
    match recorded {
        Ok(SessionConsumerLeaseMutationResult::Acquire(lease)) => Ok(Ok(lease)),
        Err(error) => Ok(Err(error)),
        _ => Err(unavailable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_session_store::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsumerOutcomeUnknown,
        SessionConsumerStoreError, SessionLeaseManager, SqliteSessionBackend,
    };
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct Effects {
        receipts: HashMap<SessionConsumerRequestId, LeaseGuard>,
        acquired_ids: Vec<SessionConsumerRequestId>,
        held: Option<SessionConsumerRequest>,
        hold_first: bool,
        lose_first_response: bool,
        status_unavailable: bool,
        status_reads: usize,
        status_reject_stale: bool,
        reject_stale: bool,
    }

    struct Port {
        backend: SqliteSessionBackend,
        effects: Mutex<Effects>,
        journal_path: PathBuf,
    }

    impl Port {
        fn new(path: PathBuf) -> Self {
            Self {
                backend: SqliteSessionBackend::in_memory().expect("synthetic lease backend"),
                effects: Mutex::new(Effects {
                    receipts: HashMap::new(),
                    acquired_ids: Vec::new(),
                    held: None,
                    hold_first: false,
                    lose_first_response: false,
                    status_unavailable: false,
                    status_reads: 0,
                    status_reject_stale: false,
                    reject_stale: false,
                }),
                journal_path: path,
            }
        }

        async fn apply(
            &self,
            request: &SessionConsumerRequest,
            effects: &mut Effects,
        ) -> LeaseGuard {
            if let Some(receipt) = effects.receipts.get(&request.request_id()) {
                return receipt.clone();
            }
            let SessionConsumerOperation::AcquireLease { key, owner, ttl } = request.operation()
            else {
                panic!("only synthetic acquire is sent to apply")
            };
            let lease = self
                .backend
                .acquire(key, owner.clone(), *ttl)
                .await
                .expect("lease apply");
            effects.receipts.insert(request.request_id(), lease.clone());
            lease
        }

        async fn deliver_original_after_successor(&self) {
            let mut effects = self.effects.lock().await;
            let request = effects.held.clone().expect("held original request");
            let _ = self.apply(&request, &mut effects).await;
        }
    }

    #[async_trait::async_trait]
    impl RequestPort for Port {
        async fn execute(&self, request: SessionConsumerRequest) -> SessionConsumerResponse {
            let mut effects = self.effects.lock().await;
            match request.operation() {
                SessionConsumerOperation::AcquireLease { .. } => {
                    let journal: JournalState = serde_json::from_slice(
                        &fs::read(&self.journal_path).expect("durable custody before first poll"),
                    )
                    .expect("complete bounded journal");
                    let pending = journal
                        .pending
                        .expect("request durably pending before send");
                    assert_eq!(pending.original.request_id(), request.request_id());
                    assert!(journal.binding.request(request.request_id()) == request);
                    effects.acquired_ids.push(request.request_id());
                    if effects.reject_stale {
                        return SessionConsumerResponse::AcquireLease(Err(
                            SessionConsumerLeaseError::StaleFence,
                        ));
                    }
                    if effects.hold_first {
                        effects.hold_first = false;
                        effects.held = Some(request);
                        return SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Lease,
                        );
                    }
                    let lease = self.apply(&request, &mut effects).await;
                    if effects.lose_first_response {
                        effects.lose_first_response = false;
                        effects.held = Some(request);
                        return SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Lease,
                        );
                    }
                    SessionConsumerResponse::AcquireLease(Ok(lease))
                }
                SessionConsumerOperation::LeaseMutationStatus { request: retained } => {
                    effects.status_reads += 1;
                    if effects.status_unavailable {
                        return SessionConsumerResponse::LeaseMutationStatus(Err(
                            SessionConsumerStoreError::Unavailable,
                        ));
                    }
                    if effects.status_reject_stale {
                        return SessionConsumerResponse::LeaseMutationStatus(Ok(
                            SessionConsumerLeaseMutationStatus::Recorded(Box::new(Err(
                                SessionConsumerLeaseError::StaleFence,
                            ))),
                        ));
                    }
                    let result = effects.receipts.get(&retained.request_id()).map_or(
                        SessionConsumerLeaseMutationStatus::NotFound,
                        |lease| {
                            SessionConsumerLeaseMutationStatus::Recorded(Box::new(Ok(
                                SessionConsumerLeaseMutationResult::Acquire(lease.clone()),
                            )))
                        },
                    );
                    SessionConsumerResponse::LeaseMutationStatus(Ok(result))
                }
                _ => panic!("unexpected synthetic operation"),
            }
        }
    }

    fn binding() -> Binding {
        Binding::new(
            SessionConsumerScope::new(SessionConsensusIdentity::new(
                SessionConsensusClusterId::new("traffic-acquire-recovery-test").expect("cluster"),
                SessionConsensusConfigurationId::from_bytes([0x23; 32]),
                SessionConsensusConfigurationEpoch::new(1).expect("epoch"),
            )),
            0,
            super::super::qualification_traffic_key(0).expect("synthetic traffic key"),
            OwnerId::new("rotation-traffic-owner-0").expect("synthetic owner"),
            super::super::QUALIFICATION_TRAFFIC_TTL,
        )
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, Acquirer, Arc<Port>) {
        let directory = tempfile::tempdir().expect("isolated fixture directory");
        let database = directory.path().join("replica.sqlite");
        let journal =
            Journal::open(&database, binding(), 26_000).expect("provision before database");
        File::create_new(&database).expect("synthetic existing database marker");
        let port = Arc::new(Port::new(journal.path.clone()));
        let acquirer = Acquirer {
            journal,
            port: port.clone(),
        };
        (directory, database, acquirer, port)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(26)
    }

    fn reopen(database: &Path, port: &Arc<Port>) -> Acquirer {
        Acquirer {
            journal: Journal::open(database, binding(), 26_000)
                .expect("restore exact request custody"),
            port: port.clone(),
        }
    }

    #[tokio::test]
    async fn late_acquire_recovery_keeps_original_id_before_admitting_successor() {
        let (_directory, database, mut acquirer, port) = fixture();
        port.effects.lock().await.hold_first = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        let original = acquirer
            .journal
            .state
            .pending
            .as_ref()
            .expect("pending A")
            .clone();
        drop(acquirer);
        let mut restored = reopen(&database, &port);
        assert_eq!(
            restored
                .journal
                .state
                .pending
                .as_ref()
                .expect("restored A")
                .expires_millis,
            original.expires_millis
        );
        let first = restored
            .acquire(deadline())
            .await
            .expect("resolve only original A after NotFound");
        let second = restored
            .acquire(deadline())
            .await
            .expect("successor B after A is terminal");
        assert!(second.fence().get() > first.fence().get());
        port.deliver_original_after_successor().await;
        port.backend
            .renew(&second, binding().ttl)
            .await
            .expect("late A copy cannot invalidate B");
        let effects = port.effects.lock().await;
        assert_eq!(effects.acquired_ids.len(), 3);
        assert_eq!(effects.acquired_ids[0], effects.acquired_ids[1]);
        assert_ne!(effects.acquired_ids[1], effects.acquired_ids[2]);
    }

    #[tokio::test]
    async fn committed_response_loss_resolves_by_receipt_without_reexecution() {
        let (_directory, database, mut acquirer, port) = fixture();
        port.effects.lock().await.lose_first_response = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        drop(acquirer);
        let lease = reopen(&database, &port)
            .acquire(deadline())
            .await
            .expect("recorded exact outcome");
        assert_eq!(port.effects.lock().await.acquired_ids.len(), 1);
        port.backend
            .renew(&lease, binding().ttl)
            .await
            .expect("restored current authority");
    }

    #[tokio::test]
    async fn expired_recorded_acquire_is_retired_before_distinct_restart_authority() {
        let (_directory, database, mut acquirer, port) = fixture();
        port.effects.lock().await.lose_first_response = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        let mut image = acquirer.journal.state.clone();
        let pending = image.pending.as_mut().expect("original acquire custody");
        let original_id = pending.original.request_id();
        // Model downtime beyond the original deadline without sleeping or
        // changing the request's duration, identity, or body.
        pending.started_millis -= 30_000;
        pending.expires_millis -= 30_000;
        acquirer
            .journal
            .persist(image)
            .expect("expired restart image");
        drop(acquirer);
        let fresh = reopen(&database, &port)
            .acquire_after_start(deadline())
            .await
            .expect("exact recorded A permits a distinct new restart operation B");
        port.deliver_original_after_successor().await;
        port.backend
            .renew(&fresh, binding().ttl)
            .await
            .expect("late A cannot invalidate fresh restart authority");
        let effects = port.effects.lock().await;
        let original = effects.receipts.get(&original_id).expect("recorded A");
        assert!(fresh.fence().get() > original.fence().get());
        assert_eq!(effects.acquired_ids.len(), 2);
        assert_eq!(effects.acquired_ids[0], original_id);
        assert_ne!(effects.acquired_ids[1], original_id);
        assert_eq!(effects.status_reads, 1);
    }

    #[tokio::test]
    async fn expired_unknown_acquire_remains_fenced_after_restart_receipt_read() {
        let (_directory, database, mut acquirer, port) = fixture();
        port.effects.lock().await.hold_first = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        let mut image = acquirer.journal.state.clone();
        let pending = image.pending.as_mut().expect("unknown A");
        pending.started_millis -= 30_000;
        pending.expires_millis -= 30_000;
        acquirer.journal.persist(image).expect("expired custody");
        let before = fs::read(&acquirer.journal.path).expect("exact old custody");
        let path = acquirer.journal.path.clone();
        drop(acquirer);
        assert!(matches!(
            reopen(&database, &port)
                .acquire_after_start(deadline())
                .await,
            Err(LeaseError::Expired)
        ));
        assert_eq!(fs::read(path).expect("retained unresolved custody"), before);
        let effects = port.effects.lock().await;
        assert_eq!(effects.status_reads, 1);
        assert_eq!(effects.acquired_ids.len(), 1);
    }

    #[tokio::test]
    async fn restart_terminal_stale_receipt_never_admits_a_successor() {
        let (_directory, database, mut acquirer, port) = fixture();
        port.effects.lock().await.hold_first = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        port.effects.lock().await.status_reject_stale = true;
        drop(acquirer);
        assert!(matches!(
            reopen(&database, &port)
                .acquire_after_start(deadline())
                .await,
            Err(LeaseError::StaleFence)
        ));
        assert_eq!(port.effects.lock().await.acquired_ids.len(), 1);
    }

    #[tokio::test]
    async fn crash_after_custody_before_first_poll_reuses_exact_request() {
        let (_directory, database, mut acquirer, port) = fixture();
        let (pending, first) = acquirer
            .journal
            .prepare(deadline())
            .expect("durable prepare");
        assert!(first);
        drop(acquirer);
        let _lease = reopen(&database, &port)
            .acquire(deadline())
            .await
            .expect("explicit original retry after receipt read");
        assert_eq!(
            port.effects.lock().await.acquired_ids,
            vec![pending.original.request_id()]
        );
    }

    #[tokio::test]
    async fn repeated_unavailable_status_never_replaces_request_or_extends_expiry() {
        let (_directory, _database, mut acquirer, port) = fixture();
        port.effects.lock().await.hold_first = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        let before = fs::read(&acquirer.journal.path).expect("original custody");
        port.effects.lock().await.status_unavailable = true;
        for _ in 0..3 {
            assert!(matches!(
                acquirer.acquire(deadline()).await,
                Err(LeaseError::OperationOutcomeUnavailable)
            ));
        }
        assert_eq!(
            fs::read(&acquirer.journal.path).expect("unchanged custody"),
            before
        );
        assert_eq!(port.effects.lock().await.acquired_ids.len(), 1);
    }

    #[tokio::test]
    async fn expired_or_backward_time_pending_request_never_sends_after_restore() {
        for backward in [false, true] {
            let (_directory, database, mut acquirer, port) = fixture();
            let _ = acquirer.journal.prepare(deadline()).expect("prepare");
            let mut image = acquirer.journal.state.clone();
            let pending = image.pending.as_mut().expect("pending");
            let now = now_millis().expect("time");
            if backward {
                pending.started_millis = now + 10_000;
                pending.expires_millis = now + 20_000;
            } else {
                pending.started_millis = now - 20_000;
                pending.expires_millis = now - 10_000;
            }
            acquirer
                .journal
                .persist(image)
                .expect("explicit expired fixture image");
            drop(acquirer);
            assert!(matches!(
                reopen(&database, &port).acquire(deadline()).await,
                Err(LeaseError::Expired)
            ));
            assert!(matches!(
                reopen(&database, &port)
                    .acquire_after_start(deadline())
                    .await,
                Err(LeaseError::Expired)
            ));
            assert!(port.effects.lock().await.acquired_ids.is_empty());
            assert_eq!(
                port.effects.lock().await.status_reads,
                usize::from(!backward)
            );
        }
    }

    #[tokio::test]
    async fn terminal_stale_fence_remains_terminal() {
        let (_directory, _database, mut acquirer, port) = fixture();
        port.effects.lock().await.reject_stale = true;
        assert!(matches!(
            acquirer.acquire(deadline()).await,
            Err(LeaseError::StaleFence)
        ));
        assert_eq!(port.effects.lock().await.acquired_ids.len(), 1);
    }

    #[tokio::test]
    async fn custody_failure_prevents_first_poll_and_poisons_current_writer() {
        let (_directory, _database, mut acquirer, port) = fixture();
        fs::remove_file(&acquirer.journal.path).expect("remove only own synthetic journal");
        fs::create_dir(&acquirer.journal.path).expect("inject refused file replacement");
        assert!(acquirer.acquire(deadline()).await.is_err());
        assert!(acquirer.journal.poisoned);
        assert!(port.effects.lock().await.acquired_ids.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reopened_custody_rejects_shared_or_unbounded_files_without_rewrite() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        for case in 0..4 {
            let (_directory, database, acquirer, _port) = fixture();
            let path = acquirer.journal.path.clone();
            drop(acquirer);
            match case {
                0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                    .expect("synthetic non-private mode"),
                1 => fs::hard_link(&path, path.with_extension("second-link"))
                    .expect("synthetic hard link"),
                2 => {
                    let target = path.with_extension("symlink-target");
                    fs::rename(&path, &target).expect("synthetic target");
                    symlink(target, &path).expect("synthetic symlink");
                }
                3 => fs::write(&path, vec![b' '; JOURNAL_LIMIT as usize + 1])
                    .expect("synthetic oversized custody"),
                _ => unreachable!(),
            }
            let before = fs::read(&path).expect("injected fixture contents");
            assert!(Journal::open(&database, binding(), 26_000).is_err());
            assert_eq!(fs::read(&path).expect("preserved rejected file"), before);
        }
    }

    #[test]
    fn lost_or_foreign_custody_is_never_provisioned_over_an_existing_database() {
        let (_directory, database, acquirer, _port) = fixture();
        let path = acquirer.journal.path.clone();
        drop(acquirer);
        let before = fs::read(&path).expect("journal");
        let mut foreign = binding();
        foreign.owner = OwnerId::new("different-synthetic-owner").expect("owner");
        assert!(Journal::open(&database, foreign, 26_000).is_err());
        assert_eq!(fs::read(&path).expect("not rewritten"), before);
        fs::remove_file(&path).expect("remove own journal");
        assert!(Journal::open(&database, binding(), 26_000).is_err());
        assert!(!path.exists());
    }
}
