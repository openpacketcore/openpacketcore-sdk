//! Slow, valid quorum replies must survive the fixed transport attempt cap.
//! Every hold follows a successful response from the real three-voter service.

use super::*;
use opc_session_net::SessionConsumerPreparedCheckpointBackend;
use opc_session_store::{
    PreparedCompareAndSetExecuteError, PreparedCompareAndSetOutcome, PreparedCompareAndSetStatus,
    PreparedLeaseAcquireExecuteError, RecordExpiryPreflight, SessionConsumerLeaseMutationResult,
    SessionConsumerLeaseMutationStatus,
};
use opc_types::Timestamp;

mod contention_tests;
mod handoff_tests;

const HOLDS: [u64; 3] = [200, 500, 700];
const GET: usize = 0;
const EXPIRY: usize = 1;
const HISTORY: usize = 2;
const STATUS: usize = 3;
const MUTATION: usize = 4;
const V1_STATUS: usize = 5;
const CAS_STATUS: usize = 6;
const LEASE_STATUS: usize = 7;
const CAS_MUTATION: usize = 8;
const LEASE_MUTATION: usize = 9;

fn read_budget() -> PreparedCheckpointBudget {
    PreparedCheckpointBudget::new(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_millis(100),
    )
    .unwrap()
}

fn hold(fixture: &AuthenticatedPreparedFencedTransitionFixture, kind: usize, millis: u64) {
    for voter in &fixture.voters {
        voter.service.reply_holds[kind].store(millis, Ordering::Release);
    }
}

fn held(fixture: &AuthenticatedPreparedFencedTransitionFixture, kind: usize) -> usize {
    fixture
        .voters
        .iter()
        .map(|voter| voter.service.held_replies[kind].load(Ordering::SeqCst))
        .sum()
}

fn clients(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
) -> Vec<PersistentSessionConsumerClient> {
    fixture
        .voters
        .iter()
        .map(|voter| {
            let client = StatelessSessionConsumerClient::new(
                voter.address,
                rustls_pki_types::ServerName::IpAddress(voter.address.ip().into()),
                voter.authority.clone(),
                fixture.client_config.clone(),
            )
            .with_operation_timeout(Duration::from_millis(250))
            .with_pre_request_connection_timeout(Duration::from_millis(100));
            PersistentSessionConsumerClient::try_from_stateless(
                client,
                PersistentSessionConsumerConfig::try_new(
                    2,
                    16,
                    Duration::from_millis(100),
                    1,
                    Duration::from_millis(600),
                    1,
                    Duration::from_millis(10),
                    Duration::from_secs(1),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect()
}

async fn facade(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    clients: &[PersistentSessionConsumerClient],
) -> SessionConsumerPreparedFencedTransitionV2Backend {
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            clients.to_vec(),
        )
        .await
        .unwrap();
    SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        CountingProvider::new(),
        "read-deadline-fixture",
        fixture.open_recovery_journal().unwrap(),
    )
    .unwrap()
}

fn finite_record(label: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        key: session_key(label),
        generation: Generation::new(1),
        owner: owner(),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("read-deadline-fixture"),
        expires_at: Some(Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc() + time::Duration::seconds(30),
        )),
        payload: EncryptedSessionPayload::new(PAYLOAD),
    }
}

async fn close(
    fixture: AuthenticatedPreparedFencedTransitionFixture,
    clients: Vec<PersistentSessionConsumerClient>,
) {
    for client in clients {
        client.shutdown().await;
    }
    fixture.shutdown().await.unwrap();
}

#[tokio::test]
async fn ordinary_get_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        clients[0].prewarm().await.unwrap();
        hold(&fixture, GET, millis);
        let budget = read_budget();
        let result = clients[0]
            .get_with_budget(session_key(millis), budget)
            .await;
        let in_deadline = tokio::time::Instant::now() < budget.original_deadline();
        evidence.push((
            millis,
            matches!(result, Ok(None)),
            in_deadline,
            held(&fixture, GET),
        ));
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, ok, in_deadline, count)| *ok && *in_deadline && *count == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn ordinary_expiry_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        clients[0].prewarm().await.unwrap();
        hold(&fixture, EXPIRY, millis);
        let budget = read_budget();
        let result = clients[0]
            .preflight_record_expiry_with_budget(
                vec![RecordExpiryPreflight::from_record(&finite_record(millis))],
                budget,
            )
            .await;
        evidence.push((
            millis,
            result.is_ok(),
            tokio::time::Instant::now() < budget.original_deadline(),
            held(&fixture, EXPIRY),
        ));
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, ok, in_deadline, count)| *ok && *in_deadline && *count == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn protected_history_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        for voter in &fixture.voters {
            voter
                .service
                .fail_next_fenced_transition_v2_history_state
                .store(true, Ordering::Release);
        }
        let clients = clients(&fixture);
        let facade = facade(&fixture, &clients).await;
        hold(&fixture, HISTORY, millis);
        let budget = read_budget();
        let result = facade
            .prepare_fenced_transition(create(request_id(millis), millis, PAYLOAD), budget)
            .await;
        evidence.push((
            millis,
            result.is_ok(),
            tokio::time::Instant::now() < budget.original_deadline(),
            held(&fixture, HISTORY),
        ));
        drop(result);
        drop(facade);
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, ok, in_deadline, count)| *ok && *in_deadline && *count == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn protected_expiry_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        let facade = facade(&fixture, &clients).await;
        // The two ALPN pools share capacity. Expiry deliberately starts cold,
        // exercising the unchanged short setup/write budget as well.
        hold(&fixture, EXPIRY, millis);
        let request = FencedTransitionRequest::new(
            request_id(millis),
            FencedTransitionLease::acquire(
                session_key(millis),
                owner(),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .unwrap(),
            FencedTransitionMutation::create(finite_record(millis)),
        )
        .unwrap();
        let budget = read_budget();
        let result = facade.prepare_fenced_transition(request, budget).await;
        evidence.push((
            millis,
            result.is_ok(),
            tokio::time::Instant::now() < budget.original_deadline(),
            held(&fixture, EXPIRY),
        ));
        drop(result);
        drop(facade);
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, ok, in_deadline, count)| *ok && *in_deadline && *count == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn protected_status_keeps_slow_replies_without_extending_mutations() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        let facade = facade(&fixture, &clients).await;
        let budget = read_budget();
        let request = create(request_id(millis), millis, PAYLOAD);
        let mut prepared = facade
            .prepare_fenced_transition(request.clone(), budget)
            .await
            .unwrap();
        hold(&fixture, MUTATION, millis);
        hold(&fixture, STATUS, millis);
        let mutation = prepared.execute_once().await;
        let unknown = matches!(
            mutation,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        );
        let result = prepared
            .status_until_terminal(budget.original_deadline())
            .await;
        let matches = matches!(result, Ok(FencedTransitionV2Status::Recorded(ref outcome)) if outcome.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_request(&request)));
        evidence.push((
            millis,
            unknown,
            matches,
            held(&fixture, MUTATION),
            held(&fixture, STATUS),
            fixture.diagnostics().fenced_transition_v2_calls(),
        ));
        drop(prepared);
        drop(facade);
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, unknown, ok, mutations, reads, calls)| *unknown
                && *ok
                && *mutations == 1
                && *reads == 1
                && *calls == 1),
        "{evidence:?}"
    );
}

async fn legacy_facade(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    clients: &[PersistentSessionConsumerClient],
) -> SessionConsumerPreparedFencedTransitionBackend {
    fixture
        .open_local_aead_from_clients(
            clients.to_vec(),
            CountingProvider::new(),
            "read-deadline-v1",
            fixture.open_journal().unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn legacy_expiry_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        let facade = legacy_facade(&fixture, &clients).await;
        hold(&fixture, EXPIRY, millis);
        let request = FencedTransitionRequest::new(
            request_id(millis),
            FencedTransitionLease::acquire(
                session_key(millis),
                owner(),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .unwrap(),
            FencedTransitionMutation::create(finite_record(millis)),
        )
        .unwrap();
        let budget = read_budget();
        let result = facade.prepare_fenced_transition(request, budget).await;
        evidence.push((
            millis,
            result.is_ok(),
            tokio::time::Instant::now() < budget.original_deadline(),
            held(&fixture, EXPIRY),
        ));
        drop(result);
        drop(facade);
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, ok, in_deadline, count)| *ok && *in_deadline && *count == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn legacy_status_keeps_successful_200_500_700ms_replies() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        let facade = legacy_facade(&fixture, &clients).await;
        let budget = read_budget();
        let request = create(request_id(millis), millis, PAYLOAD);
        let mut prepared = facade
            .prepare_fenced_transition(request.clone(), budget)
            .await
            .unwrap();
        fixture.lose_next_fenced_transition_response();
        hold(&fixture, V1_STATUS, millis);
        let mutation = prepared.execute_once().await;
        let unknown = matches!(
            mutation,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        );
        let result = prepared
            .status_until_terminal(budget.original_deadline())
            .await;
        let matches = matches!(result, Ok(FencedTransitionStatus::Recorded(ref outcome)) if outcome.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_request(&request)));
        evidence.push((
            millis,
            unknown,
            matches,
            held(&fixture, V1_STATUS),
            fixture.diagnostics().fenced_transition_calls(),
        ));
        drop(prepared);
        drop(facade);
        close(fixture, clients).await;
    }
    assert!(
        evidence
            .iter()
            .all(|(_, unknown, ok, reads, mutations)| *unknown
                && *ok
                && *reads == 1
                && *mutations == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn read_setup_silence_keeps_the_shorter_pre_write_limit() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let fixture = with_fixture_protocol_clock("read setup deadline", async move {
        for cap in [Duration::from_millis(50), Duration::from_millis(100)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = PersistentSessionConsumerClient::try_from_stateless(
                StatelessSessionConsumerClient::new(
                    address,
                    rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                    fixture.voters[0].authority.clone(),
                    fixture.client_config.clone(),
                )
                .with_operation_timeout(cap)
                .with_pre_request_connection_timeout(Duration::from_millis(100)),
                PersistentSessionConsumerConfig::default(),
            )
            .unwrap();
            let budget = read_budget();
            let started = tokio::time::Instant::now();
            let read = client.get_with_budget(session_key(900), budget);
            tokio::pin!(read);
            let (socket, _) = tokio::select! {
                result = &mut read => panic!("read completed before TCP setup: {result:?}"),
                accepted = listener.accept() => accepted.unwrap(),
            };
            // The accepted peer never sends TLS or Hello, so no Call can be written.
            tokio::time::advance(cap - FIXTURE_TIMER_TICK).await;
            assert!(futures_util::poll!(&mut read).is_pending());
            tokio::time::advance(FIXTURE_TIMER_TICK * 2).await;
            assert!(read.await.is_err());
            assert_eq!(
                tokio::time::Instant::now() - started,
                cap + FIXTURE_TIMER_TICK
            );
            assert!(tokio::time::Instant::now() < budget.original_deadline());
            assert_eq!(client.diagnostics().await.completed_operations, 1);
            let successor = clients(&fixture).remove(1);
            assert!(
                successor
                    .get_with_budget(session_key(900), budget)
                    .await
                    .is_ok(),
                "a pre-write failure leaves the same immutable budget for the next voter"
            );
            successor.shutdown().await;
            drop(socket);
            client.shutdown().await;
        }
        fixture
    })
    .await;
    fixture.shutdown().await.unwrap();
}

#[tokio::test]
async fn credential_rotation_drops_a_slow_reply_before_the_original_deadline() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let voter = &fixture.voters[0];
    let policy = opc_session_net::ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .unwrap();
    let client = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new(
            voter.address,
            rustls_pki_types::ServerName::IpAddress(voter.address.ip().into()),
            voter.authority.clone(),
            fixture.client_config.clone(),
        )
        .with_operation_timeout(Duration::from_millis(250))
        .with_pre_request_connection_timeout(Duration::from_millis(100))
        .with_connection_lifecycle(policy),
        PersistentSessionConsumerConfig::default(),
    )
    .unwrap();
    client.prewarm().await.unwrap();
    hold(&fixture, GET, 200);
    let budget = read_budget();
    let read = client.get_with_budget(session_key(920), budget);
    tokio::pin!(read);
    tokio::select! {
        result = &mut read => panic!("read returned before the successful reply hold: {result:?}"),
        () = voter.service.held_reply_started[GET].notified() => {}
    }
    client.request_reauthentication().unwrap();
    let result = read.await;
    let count = held(&fixture, GET);
    let calls = client.diagnostics().await;
    client.shutdown().await;
    fixture.shutdown().await.unwrap();
    assert!(
        result.is_err(),
        "a reply after credential retirement must be dropped"
    );
    assert_eq!(count, 1, "rotation must not replay the physical read");
    assert_eq!(calls.completed_operations, 1);
    assert_eq!(calls.overload, 0);
}

#[tokio::test]
async fn ordinary_reads_drop_replies_after_an_earlier_caller_deadline() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let clients = clients(&fixture);
    clients[0].prewarm().await.unwrap();
    let mut evidence = Vec::new();
    for kind in [GET, EXPIRY] {
        hold(&fixture, kind, 700);
        let started = tokio::time::Instant::now();
        let ingress_deadline = started + Duration::from_secs(1);
        let lease_deadline = started + Duration::from_millis(400);
        let budget = PreparedCheckpointBudget::new(
            lease_deadline.min(ingress_deadline),
            Duration::from_millis(100),
        )
        .unwrap();
        let failed = if kind == GET {
            clients[0]
                .get_with_budget(session_key(901), budget)
                .await
                .is_err()
        } else {
            clients[0]
                .preflight_record_expiry_with_budget(
                    vec![RecordExpiryPreflight::from_record(&finite_record(902))],
                    budget,
                )
                .await
                .is_err()
        };
        let completed = tokio::time::Instant::now();
        evidence.push((
            failed,
            completed >= lease_deadline,
            completed < ingress_deadline,
            held(&fixture, kind),
        ));
    }
    close(fixture, clients).await;
    assert!(
        evidence
            .iter()
            .all(|(failed, at_lease, before_ingress, calls)| *failed
                && *at_lease
                && *before_ingress
                && *calls == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn each_voter_including_the_leader_fails_closed_when_a_written_read_is_silent() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let clients = clients(&fixture);
    for client in &clients {
        client.prewarm_v2().await.unwrap();
    }
    hold(&fixture, HISTORY, 1_000);
    let mut evidence = Vec::new();
    // Exercise every real voter, so both the leader and its followers are
    // covered without guessing the current election outcome.
    for client in &clients {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let budget = PreparedCheckpointBudget::new(deadline, Duration::from_millis(100)).unwrap();
        let result = client
            .fenced_transition_v2_history_state_with_budget(budget)
            .await;
        evidence.push((result.is_err(), tokio::time::Instant::now() >= deadline));
    }
    let counts = fixture
        .voters
        .iter()
        .map(|voter| voter.service.held_replies[HISTORY].load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let mutations = fixture.diagnostics().fenced_transition_v2_calls();
    close(fixture, clients).await;
    assert!(
        evidence
            .iter()
            .all(|(failed, reached_deadline)| *failed && *reached_deadline),
        "{evidence:?}"
    );
    assert_eq!(
        counts,
        vec![1, 1, 1],
        "one physical read per caller, without a hedge"
    );
    assert_eq!(mutations, 0);
}

#[tokio::test]
async fn concurrent_slow_receipts_use_one_call_each_with_v2_wait_counters() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let clients = clients(&fixture);
    let facade = facade(&fixture, &clients).await;
    let budget = read_budget();
    let first_request = create(request_id(910), 910, PAYLOAD);
    let second_request = create(request_id(911), 911, PAYLOAD);
    let mut first = facade
        .prepare_fenced_transition(first_request.clone(), budget)
        .await
        .unwrap();
    let mut second = facade
        .prepare_fenced_transition(second_request.clone(), budget)
        .await
        .unwrap();
    hold(&fixture, MUTATION, 700);
    hold(&fixture, STATUS, 700);
    let (first_mutation, second_mutation) =
        tokio::join!(first.execute_once(), second.execute_once());
    let setups_before: u64 = clients
        .iter()
        .map(|client| client.v2_diagnostics().setup_attempts)
        .sum();
    let (first_receipt, second_receipt) = tokio::join!(
        first.status_until_terminal(budget.original_deadline()),
        second.status_until_terminal(budget.original_deadline()),
    );
    let setups_after: u64 = clients
        .iter()
        .map(|client| client.v2_diagnostics().setup_attempts)
        .sum();
    let mut current_waiters = 0;
    let mut max_waiters = 0;
    for client in &clients {
        let diagnostics = client.v2_diagnostics();
        current_waiters += diagnostics.pool_wait_current;
        max_waiters = max_waiters.max(diagnostics.pool_wait_max);
    }
    let exact = |result: &Result<FencedTransitionV2Status, _>,
                 request: &FencedTransitionRequest| {
        matches!(result, Ok(FencedTransitionV2Status::Recorded(outcome))
            if outcome.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_request(request)))
    };
    let evidence = (
        matches!(
            first_mutation,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        ),
        matches!(
            second_mutation,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        ),
        exact(&first_receipt, &first_request),
        exact(&second_receipt, &second_request),
        held(&fixture, MUTATION),
        held(&fixture, STATUS),
        fixture.diagnostics().fenced_transition_v2_calls(),
        setups_after - setups_before,
        current_waiters,
        max_waiters,
    );
    drop(first);
    drop(second);
    drop(facade);
    close(fixture, clients).await;
    eprintln!("concurrent slow receipts (two callers): {evidence:?}");
    assert!(
        evidence.0 && evidence.1 && evidence.2 && evidence.3,
        "{evidence:?}"
    );
    assert_eq!((evidence.4, evidence.5, evidence.6), (2, 2, 2));
    assert!(
        evidence.7 <= 2,
        "each logical read may establish at most one lane"
    );
    assert_eq!(evidence.8, 0, "all V2 pool waiters have completed");
    assert!(
        evidence.9 <= 2,
        "two logical callers never fan out into more waiters"
    );
}

#[tokio::test]
async fn prepared_checkpoint_cas_keeps_successful_200_500_700ms_receipts() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        for client in &clients {
            client.prewarm().await.unwrap();
        }
        let protected = Arc::new(EncryptingSessionBackend::new(
            Arc::new(FixtureGeneralConsumerBackend::new(
                clients.clone(),
                Arc::clone(&fixture.ordinary_cas_fault),
            )),
            CountingProvider::new(),
            "read-deadline-checkpoint",
        ));
        let key = session_key(930);
        let lease = protected
            .acquire(&key, owner(), Duration::from_secs(30))
            .await
            .unwrap();
        let mut record = finite_record(930);
        record.fence = lease.fence();
        let composite =
            SessionConsumerPreparedCheckpointBackend::persistent(protected, clients.clone())
                .unwrap();
        let budget = read_budget();
        let mut prepared = composite
            .prepare_compare_and_set(
                SessionConsumerRequestId::new(),
                CompareAndSet {
                    key,
                    lease,
                    expected_generation: None,
                    new_record: record,
                },
                budget,
            )
            .await
            .unwrap();
        hold(&fixture, CAS_MUTATION, 700);
        hold(&fixture, CAS_STATUS, millis);
        let mutation = prepared.execute_once().await;
        let receipt = prepared.status_once(budget.original_deadline()).await;
        evidence.push((
            millis,
            mutation == Err(PreparedCompareAndSetExecuteError::OutcomeUnknown),
            matches!(
                receipt,
                Ok(PreparedCompareAndSetStatus::Recorded(
                    PreparedCompareAndSetOutcome::Applied
                ))
            ),
            held(&fixture, CAS_MUTATION),
            held(&fixture, CAS_STATUS),
        ));
        drop(prepared);
        drop(composite);
        close(fixture, clients).await;
    }
    eprintln!("prepared CAS slow receipts: {evidence:?}");
    assert!(
        evidence
            .iter()
            .all(|(_, unknown, exact, mutations, reads)| *unknown
                && *exact
                && *mutations == 1
                && *reads == 1),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn prepared_checkpoint_lease_keeps_successful_200_500_700ms_receipts() {
    let mut evidence = Vec::new();
    for millis in HOLDS {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        for client in &clients {
            client.prewarm().await.unwrap();
        }
        let protected = Arc::new(EncryptingSessionBackend::new(
            Arc::new(FixtureGeneralConsumerBackend::new(
                clients.clone(),
                Arc::clone(&fixture.ordinary_cas_fault),
            )),
            CountingProvider::new(),
            "read-deadline-checkpoint",
        ));
        let composite =
            SessionConsumerPreparedCheckpointBackend::persistent(protected, clients.clone())
                .unwrap();
        let key = session_key(931);
        let budget = read_budget();
        let mut prepared = composite
            .prepare_acquire_with_id(
                SessionConsumerRequestId::new(),
                key.clone(),
                owner(),
                Duration::from_secs(30),
                budget,
            )
            .unwrap();
        hold(&fixture, LEASE_MUTATION, 700);
        hold(&fixture, LEASE_STATUS, millis);
        let mutation = prepared.execute_once().await;
        let receipt = prepared.status_once(budget.original_deadline()).await;
        evidence.push((
            millis,
            mutation == Err(PreparedLeaseAcquireExecuteError::OutcomeUnknown),
            matches!(
                receipt,
                Ok(SessionConsumerLeaseMutationStatus::Recorded(result))
                    if matches!(*result, Ok(SessionConsumerLeaseMutationResult::Acquire(ref lease))
                        if lease.key() == &key)
            ),
            held(&fixture, LEASE_MUTATION),
            held(&fixture, LEASE_STATUS),
        ));
        drop(prepared);
        drop(composite);
        close(fixture, clients).await;
    }
    eprintln!("prepared lease slow receipts: {evidence:?}");
    assert!(
        evidence
            .iter()
            .all(|(_, unknown, exact, mutations, reads)| *unknown
                && *exact
                && *mutations == 1
                && *reads == 1),
        "{evidence:?}"
    );
}
