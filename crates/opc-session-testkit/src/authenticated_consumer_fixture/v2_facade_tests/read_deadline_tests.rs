//! Slow, valid quorum replies must survive the fixed transport attempt cap.
//! Every hold follows a successful response from the real three-voter service.

use super::*;
use opc_session_store::RecordExpiryPreflight;
use opc_types::Timestamp;

const HOLDS: [u64; 3] = [200, 500, 700];
const GET: usize = 0;
const EXPIRY: usize = 1;
const HISTORY: usize = 2;
const STATUS: usize = 3;
const MUTATION: usize = 4;

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
