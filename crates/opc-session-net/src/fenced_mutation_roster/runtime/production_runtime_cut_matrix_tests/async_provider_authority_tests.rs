// Independent controls for the authority missing from protected Async recovery.
// These exercise the production executor and signed provider-receipt verifier.
// CutBackend models the authority lookup; it is not a recovered quorum. The
// real retained-root/mTLS recovery RED lives in opc-session-testkit. No control
// here disables the production ProtectedAuthorityRequired guard.

use super::*;
use opc_session_store::TokioVirtualClock;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};

// The published provider contract requires a durable floor for each exact
// fence_binding_commitment, not one floor shared by every admission in a
// configuration. A synthetic one-slot resource makes that distinction visible.
// Resource mutation, immutable outcome and fence update share one disk commit.
struct JournalProvider {
    path: PathBuf,
    clock: Arc<dyn Clock>,
}

impl JournalProvider {
    fn new(path: &Path, clock: Arc<dyn Clock>) -> Arc<Self> {
        let provider = Arc::new(Self {
            path: path.to_owned(),
            clock,
        });
        provider
            .connection()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS members (
                    binding BLOB PRIMARY KEY, fence INTEGER NOT NULL,
                    outcome INTEGER NOT NULL CHECK (outcome BETWEEN 0 AND 2)
                 );
                 CREATE TABLE IF NOT EXISTS resource (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    fence INTEGER NOT NULL, writes INTEGER NOT NULL
                 );
                 INSERT OR IGNORE INTO resource VALUES (1, 0, 0);",
            )
            .expect("initialize synthetic durable provider journal");
        provider
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).expect("open retained provider journal");
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .expect("require durable provider commits");
        connection
    }

    fn observe(&self, call: &MemberCall<'_>, operation: ProviderOperation) -> Result<u8, ()> {
        let mut connection = self.connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ())?;
        call.validate_current_lease_at(self.clock.now_utc())
            .map_err(|_| ())?;
        let binding = call.fence_binding_commitment();
        let fence = call.current_fence().get();
        let prior: Option<(u64, u8)> = transaction
            .query_row(
                "SELECT fence, outcome FROM members WHERE binding = ?1",
                params![binding.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ())?;
        if prior.is_some_and(|(floor, _)| fence < floor) {
            return Err(());
        }
        let prior_outcome = prior.map_or(0, |(_, outcome)| outcome);
        let outcome = match operation {
            ProviderOperation::Prepare => prior_outcome,
            ProviderOperation::Execute if prior_outcome == 2 => return Err(()),
            ProviderOperation::Execute => 1,
            ProviderOperation::Status | ProviderOperation::Adopt if prior_outcome == 0 => 2,
            ProviderOperation::Status | ProviderOperation::Adopt => prior_outcome,
            _ => return Err(()),
        };
        transaction
            .execute(
                "INSERT INTO members VALUES (?1, ?2, ?3)
                 ON CONFLICT(binding) DO UPDATE SET fence = ?2, outcome = ?3",
                params![binding.as_slice(), fence, outcome],
            )
            .map_err(|_| ())?;
        if operation == ProviderOperation::Execute && prior_outcome == 0 {
            transaction
                .execute(
                    "UPDATE resource SET fence = ?1, writes = writes + 1 WHERE singleton = 1",
                    params![fence],
                )
                .map_err(|_| ())?;
        }
        transaction.commit().map_err(|_| ())?;
        Ok(outcome)
    }

    fn resource(&self) -> (u64, u64) {
        self.connection()
            .query_row(
                "SELECT fence, writes FROM resource WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read synthetic resource after reopening journal")
    }

    fn applied_bindings(&self) -> u64 {
        self.connection()
            .query_row(
                "SELECT count(*) FROM members WHERE outcome = 1",
                [],
                |row| row.get(0),
            )
            .expect("read durable applied bindings")
    }
}

#[async_trait]
impl MemberProvider for JournalProvider {
    type Error = ();

    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        match self.observe(call, ProviderOperation::Prepare)? {
            0 => Ok(ProviderCallOutcome::prepared_not_run()),
            _ => Ok(ProviderCallOutcome::outcome_unknown()),
        }
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.observe(call, ProviderOperation::Execute)?;
        signed_provider_receipt(call, RosterProviderOutcomeV1::AppliedExecuted, vec![0x91])
    }

    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        let (outcome, evidence) = match self.observe(call, ProviderOperation::Status)? {
            1 => (RosterProviderOutcomeV1::AppliedExecuted, vec![0x91]),
            2 => (RosterProviderOutcomeV1::NotAppliedReconciled, vec![0x92]),
            _ => return Err(()),
        };
        signed_provider_receipt(call, outcome, evidence)
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        let (outcome, evidence) = match self.observe(call, ProviderOperation::Adopt)? {
            1 => (RosterProviderOutcomeV1::AppliedAdopted, vec![0x91]),
            2 => (RosterProviderOutcomeV1::NotAppliedReconciled, vec![0x92]),
            _ => return Err(()),
        };
        signed_provider_receipt(call, outcome, evidence)
    }
}

fn journal_executor(
    provider: Arc<JournalProvider>,
    backend: Arc<CutBackend>,
) -> RosterExecutor<JournalProvider, CutBackend> {
    let clock = Arc::clone(&provider.clock);
    RosterExecutor::new_with_clock(
        provider,
        backend,
        CutAttestor::new(request_with_members(1).admission().scope()),
        NonZeroUsize::new(1).expect("bounded provider capacity"),
        clock,
    )
}

fn new_binding_at_higher_fence(original: &RegistrationRequest) -> RegistrationRequest {
    let owner = OwnerId::new("authority-control-successor").expect("synthetic owner");
    let fence = FenceToken::new((1_u64 << 40) + 1);
    let proposal = AdmissionProposal::new(
        Profile::v1(),
        RosterId::from_bytes([0xE1; 16]).expect("synthetic roster"),
        vec![Member::new(
            0,
            MemberOperationId::from_bytes([0xE2; 16]).expect("synthetic member"),
            original.admission().members()[0].descriptor().to_vec(),
            original.admission().members()[0].expected_version(),
        )
        .expect("same opaque resource descriptor")],
        EstablishedMutation::no_op(),
        b"successor-plan".to_vec(),
        b"successor-checkpoint".to_vec(),
        b"successor-result".to_vec(),
    )
    .expect("synthetic successor proposal");
    let admission = Admission::authenticate(
        proposal,
        original.admission().key().clone(),
        original.admission().scope(),
        owner.clone(),
        fence,
        original.admission().expected_generation(),
    )
    .expect("same authenticated key and scope");
    RegistrationRequest::new(admission, owner, fence, fence.get(), Generation::new(1))
        .expect("higher current authority")
}

#[tokio::test]
async fn exact_binding_reconciliation_durably_rejects_delayed_old_execute() {
    let directory = tempfile::tempdir().expect("disk-backed provider directory");
    let provider =
        JournalProvider::new(&directory.path().join("journal.db"), Arc::new(SystemClock));
    let backend = Arc::new(CutBackend::default());
    let request = request_with_members(1);
    let old = journal_executor(Arc::clone(&provider), Arc::clone(&backend));
    let admitted = old
        .register(request.clone())
        .await
        .expect("old exact admission");
    assert!(matches!(
        old.prepare(&admitted, 0).await,
        Ok(CallResult::PreparedNotRun)
    ));

    let recovery = successor(&request, (1_u64 << 40) + 1);
    backend.install_successor_authority(recovery.authority().clone());
    let current = journal_executor(Arc::clone(&provider), Arc::clone(&backend));
    let current_admission = recovered(
        current
            .recover(recovery)
            .await
            .expect("retained exact body"),
    );
    let proof = conclusive(
        current
            .status(&current_admission, 0)
            .await
            .expect("exact negative proof"),
    );
    let terminal = current
        .prepare_terminal(&current_admission, vec![proof])
        .await
        .expect("exact Aborted body");
    assert_eq!(
        current
            .terminalize(&current_admission, &terminal)
            .await
            .expect("current terminal")
            .phase(),
        Phase::Aborted
    );

    // Old local authority is still inside its lease. The provider's persisted
    // exact-binding floor, not a local or clock shortcut, rejects this call.
    assert!(matches!(
        old.execute(&admitted, 0).await,
        Err(ExecutorError::OutcomeUnknown)
    ));
    assert_eq!(provider.resource(), (0, 0));
    assert_eq!(provider.applied_bindings(), 0);
}

#[tokio::test]
async fn higher_fence_for_another_binding_does_not_retire_old_provider_authority() {
    let directory = tempfile::tempdir().expect("disk-backed provider directory");
    let provider =
        JournalProvider::new(&directory.path().join("journal.db"), Arc::new(SystemClock));
    let backend = Arc::new(CutBackend::default());
    let request = request_with_members(1);
    let old = journal_executor(Arc::clone(&provider), Arc::clone(&backend));
    let admitted = old
        .register(request.clone())
        .await
        .expect("old exact admission");
    assert!(matches!(
        old.prepare(&admitted, 0).await,
        Ok(CallResult::PreparedNotRun)
    ));

    // Counterfactual control: this separate backend represents selection of
    // a generation without Q1. Actual protected Async recovery rejects that
    // selection. Keep the old fixture's evidence; never clear a real root.
    let next_request = new_binding_at_higher_fence(&request);
    backend.install_successor_authority(next_request.authority().clone());
    let next_backend = Arc::new(CutBackend::default());
    let current = journal_executor(Arc::clone(&provider), next_backend);
    let next = current
        .register(next_request.clone())
        .await
        .expect("new distinct admission");
    assert!(matches!(
        current.prepare(&next, 0).await,
        Ok(CallResult::PreparedNotRun)
    ));
    let _current_proof = conclusive(
        current
            .execute(&next, 0)
            .await
            .expect("successor provider effect"),
    );
    assert_eq!(
        provider.resource(),
        (next_request.authority().fence().get(), 1)
    );

    let old_proof = conclusive(
        old.execute(&admitted, 0)
            .await
            .expect("different binding has no shared floor"),
    );
    assert_eq!(provider.resource(), (request.authority().fence().get(), 2));
    assert_eq!(provider.applied_bindings(), 2);
    let old_terminal = old
        .prepare_terminal(&admitted, vec![old_proof])
        .await
        .expect("local proof preparation");
    assert!(
        matches!(
            old.terminalize(&admitted, &old_terminal).await,
            Err(ExecutorError::AuthorityRejected)
        ),
        "current consensus still rejects old authority, after the provider effect"
    );
}

// This helper must issue the lease against the provider/executor clock. The
// provider may have completed synchronous disk setup while virtual time stayed
// paused. Its time base must not be replaced with a later wall-clock reading.
fn journal_registration(clock: &dyn Clock) -> RegistrationRequest {
    let request = request_with_members(1);
    let authority = request.authority();
    let acquired_at = clock
        .now_utc()
        .add_seconds(-1)
        .expect("fixture acquisition time");
    RegistrationRequest::new_with_lease_metadata(
        request.admission().clone(),
        authority.owner().clone(),
        authority.fence(),
        authority.credential_id(),
        authority.generation(),
        acquired_at,
        acquired_at.add_seconds(60).expect("fixture lease expiry"),
    )
    .expect("registration on the provider clock")
}

#[derive(Debug)]
struct RetainedProviderClock(Timestamp);

impl Clock for RetainedProviderClock {
    fn now_utc(&self) -> Timestamp {
        self.0
    }
}

#[tokio::test]
async fn journal_registration_uses_the_provider_clock_after_wall_time_advances() {
    // Model disk setup advancing wall time without moving the frozen provider
    // clock. An explicit offset makes the old mismatch deterministic; no sleep
    // or lease deadline is changed.
    let clock: Arc<dyn Clock> = Arc::new(RetainedProviderClock(
        Timestamp::now_utc()
            .add_seconds(-120)
            .expect("synthetic earlier anchor"),
    ));
    let directory = tempfile::tempdir().expect("disk-backed provider directory");
    let provider = JournalProvider::new(&directory.path().join("journal.db"), Arc::clone(&clock));
    let request = journal_registration(clock.as_ref());
    assert_eq!(
        request.authority().acquired_at(),
        clock.now_utc().add_seconds(-1).unwrap()
    );
    assert_eq!(
        request.authority().expires_at(),
        clock.now_utc().add_seconds(59).unwrap()
    );
    let executor = journal_executor(provider, Arc::new(CutBackend::default()));
    let _admitted = executor
        .register(request)
        .await
        .expect("fixture lease must be current on the provider clock");
}

#[tokio::test]
async fn journal_registration_preserves_future_and_expired_lease_rejection() {
    let clock: Arc<dyn Clock> = Arc::new(RetainedProviderClock(Timestamp::now_utc()));
    let directory = tempfile::tempdir().expect("disk-backed provider directory");
    let provider = JournalProvider::new(&directory.path().join("journal.db"), Arc::clone(&clock));
    let request = journal_registration(clock.as_ref());
    let authority = request.authority();
    for offset in [1, -61] {
        let acquired_at = clock.now_utc().add_seconds(offset).unwrap();
        let invalid = RegistrationRequest::new_with_lease_metadata(
            request.admission().clone(),
            authority.owner().clone(),
            authority.fence(),
            authority.credential_id(),
            authority.generation(),
            acquired_at,
            acquired_at.add_seconds(60).unwrap(),
        )
        .unwrap();
        let executor = journal_executor(Arc::clone(&provider), Arc::new(CutBackend::default()));
        assert!(matches!(
            executor.register(invalid).await,
            Err(ExecutorError::AdmissionOutcomeUnknown)
        ));
        assert_eq!(provider.resource(), (0, 0));
        assert_eq!(provider.applied_bindings(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn lease_expiry_does_not_reconstruct_a_lost_admission_or_undo_its_effect() {
    let directory = tempfile::tempdir().expect("disk-backed provider directory");
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let provider = JournalProvider::new(&directory.path().join("journal.db"), Arc::clone(&clock));
    let request = journal_registration(clock.as_ref());
    let old = journal_executor(Arc::clone(&provider), Arc::new(CutBackend::default()));
    let admitted = old
        .register(request.clone())
        .await
        .expect("old exact admission");
    assert!(matches!(
        old.prepare(&admitted, 0).await,
        Ok(CallResult::PreparedNotRun)
    ));
    let _proof = conclusive(
        old.execute(&admitted, 0)
            .await
            .expect("durable old provider effect"),
    );
    tokio::time::advance(Duration::from_secs(65)).await;
    assert!(clock.now_utc() >= request.authority().expires_at());
    assert!(
        matches!(
            old.status(&admitted, 0).await,
            Err(ExecutorError::AuthorityRejected)
        ),
        "an expired permit cannot call the provider"
    );

    let restored_without_q1 = Arc::new(CutBackend::default());
    let current = journal_executor(Arc::clone(&provider), restored_without_q1);
    let now = clock.now_utc();
    let recovery = RecoveryRequest::new_with_lease_metadata(
        RecoveryLookup::new(request.admission().scope(), request.admission().roster_id()),
        request.admission().logical_owner().clone(),
        request.admission().admission_fence(),
        RecoveryLeaseAuthority::new(
            request.admission().key().clone(),
            OwnerId::new("authority-control-successor").expect("synthetic owner"),
            FenceToken::new((1_u64 << 40) + 1),
            (1_u64 << 40) + 1,
            Generation::new(1),
            LeaseMetadata::new(now, now.add_seconds(60).expect("current lease expiry")),
        ),
    )
    .expect("unexpired successor authority");
    assert!(
        matches!(
            current.recover(recovery).await,
            Err(ExecutorError::AuthorityRejected)
        ),
        "a subscriber key and a higher fence cannot recreate exact admitted bytes"
    );
    assert_eq!(provider.resource(), (request.authority().fence().get(), 1));
    assert_eq!(
        provider.applied_bindings(),
        1,
        "expiry is not evidence that the lost operation never happened"
    );
}
