//! Matched shared-pool contention: two written reads and a third caller.

use super::*;
use opc_session_net::{
    PersistentSessionConsumerExecuteError, PersistentSessionConsumerV2ExecuteError,
    SessionConsumerClientError,
};
use opc_session_store::{
    SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

#[derive(Clone, Copy, Debug)]
enum Competitor {
    OrdinaryV1Lease,
    OrdinaryV2Admission,
    EmergencyV2Transition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Success,
    Overloaded,
    Deadline,
    NotTransmitted,
    OutcomeUnknown,
    OtherFailure,
}

fn before_write(cause: SessionConsumerClientError) -> Admission {
    match cause {
        SessionConsumerClientError::Overloaded => Admission::Overloaded,
        SessionConsumerClientError::Deadline => Admission::Deadline,
        _ => Admission::NotTransmitted,
    }
}

// Select a synthetic ID for a known canonical voter. This arranges contention;
// the native service's observed call counts independently check the placement.
fn fixture_origin(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    id: FencedTransitionRequestId,
) -> usize {
    let identity = fixture.voters[0].authority.scope().consensus_identity();
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/prepared-fenced-transition-v2-origin/v1\0");
    digest.update(identity.cluster_id().as_bytes());
    digest.update(identity.configuration_id().as_bytes());
    digest.update(identity.configuration_epoch().get().to_be_bytes());
    digest.update(fixture.voters[0].authority.roster_commitment());
    for voter in &fixture.voters {
        digest.update(voter.authority.node_id().get().to_be_bytes());
    }
    digest.update(id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    u64::from_be_bytes(bytes[..8].try_into().unwrap()) as usize % fixture.voters.len()
}

#[derive(Debug)]
struct Evidence {
    hold_ms: u64,
    competitor: Competitor,
    admission: Admission,
    caller_ms: u128,
    early_read_completions: usize,
    successful_reads: usize,
    physical_reads: usize,
    v2_wait_current_queued: u64,
    v2_wait_max: u64,
    v1_wait_current_queued: u64,
    v1_wait_max: u64,
    v2_setups: u64,
    v2_mutations: usize,
}

async fn competing_case(hold_ms: u64, competitor: Competitor) -> Evidence {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let (fixture, evidence) = with_fixture_protocol_clock("shared read pool contention", async move {
        let clients = clients(&fixture);
        let facade = facade(&fixture, &clients).await;
        let original = create(request_id(1300), 1300, PAYLOAD);
        let budget = read_budget();
        let mut committed = facade.prepare_fenced_transition(original.clone(), budget).await.unwrap();
        committed_v2(&mut committed, &original, budget.original_deadline()).await;
        let origin = fixture.voters.iter().position(|voter| voter.service.fenced_transition_v2_calls.load(Ordering::SeqCst) == 1).unwrap();
        let target = (origin + 1) % fixture.voters.len();
        assert_eq!(fixture_origin(&fixture, original.request_id()), origin);
        drop(committed);
        let mut first = match facade.recover_fenced_transition_status(original.request_id(), budget).await.unwrap().unwrap() {
            SessionConsumerRecoveredFencedTransition::V2(handle) => handle,
            _ => panic!("the fixture retains a V2 receipt"),
        };
        let mut second = match facade.recover_fenced_transition_status(original.request_id(), budget).await.unwrap().unwrap() {
            SessionConsumerRecoveredFencedTransition::V2(handle) => handle,
            _ => panic!("the fixture retains a V2 receipt"),
        };
        let emergency_label = (1400..1500).find(|label| fixture_origin(&fixture, request_id(*label)) == target).unwrap();
        let emergency_request = create(request_id(emergency_label), emergency_label, PAYLOAD);
        let emergency_budget = PreparedCheckpointBudget::new(tokio::time::Instant::now() + Duration::from_millis(250), Duration::from_millis(100)).unwrap();
        let mut emergency = facade.prepare_fenced_transition(emergency_request.clone(), emergency_budget).await.unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        for voter in &fixture.voters { *voter.service.reply_gates[STATUS].lock().unwrap() = Some(Arc::clone(&gate)); }
        let started = tokio::time::Instant::now();
        let mut first_read = Box::pin(first.status_once(budget.original_deadline()));
        let mut second_read = Box::pin(second.status_once(budget.original_deadline()));
        {
        let entered = async {
            loop {
                let notified = fixture.voters[target].service.held_reply_started[STATUS].notified();
                if fixture.voters[target].service.held_replies[STATUS].load(Ordering::SeqCst) == 2 { break; }
                notified.await;
            }
        };
        tokio::pin!(entered);
        tokio::select! {
            result = &mut first_read => panic!("first read completed before its held reply: {result:?}"),
            result = &mut second_read => panic!("second read completed before its held reply: {result:?}"),
            () = &mut entered => {},
        }
        }
        assert_eq!(held(&fixture, STATUS), 2, "both reads occupy this same voter's two lanes");
        assert_eq!(clients[target].v2_diagnostics().idle, 0);
        let setups_before = clients[target].v2_diagnostics().setup_attempts;
        tokio::time::advance(Duration::from_millis(50)).await;
        let caller_started = tokio::time::Instant::now();
        let v1_request = SessionConsumerRequest::new(clients[target].scope(), SessionConsumerRequestId::new(), SessionConsumerOperation::AcquireLease {
            key: session_key(1600), owner: owner(), ttl: Duration::from_secs(30),
        });
        let v2_request = SessionConsumerV2Request::new(clients[target].scope(), SessionConsumerV2Operation::FencedTransitionV2Capability);
        let mut competing: Pin<Box<dyn Future<Output = Admission> + Send + '_>> = match competitor {
            Competitor::OrdinaryV1Lease => Box::pin(async {
                match clients[target].execute(&v1_request).await {
                    Ok(SessionConsumerResponse::AcquireLease(Ok(_))) => Admission::Success,
                    Err(PersistentSessionConsumerExecuteError::NotTransmitted { cause }) => before_write(cause),
                    Err(PersistentSessionConsumerExecuteError::OutcomeUnknown { .. }) => Admission::OutcomeUnknown,
                    _ => Admission::OtherFailure,
                }
            }),
            Competitor::OrdinaryV2Admission => Box::pin(async {
                match clients[target].execute_v2(&v2_request).await {
                    Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(_))) => Admission::Success,
                    Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause }) => before_write(cause),
                    Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { .. }) => Admission::OutcomeUnknown,
                    _ => Admission::OtherFailure,
                }
            }),
            Competitor::EmergencyV2Transition => Box::pin(async {
                match emergency.execute_once().await {
                    Ok(outcome) if outcome.matches_request(&emergency_request) => Admission::Success,
                    Err(FencedTransitionExecuteError::NotTransmitted) => Admission::NotTransmitted,
                    Err(FencedTransitionExecuteError::OutcomeUnknown { .. }) => Admission::OutcomeUnknown,
                    _ => Admission::OtherFailure,
                }
            }),
        };
        loop {
            assert!(futures_util::poll!(competing.as_mut()).is_pending(), "the competing caller must join the occupied pool");
            let waiting = match competitor {
                Competitor::OrdinaryV1Lease => clients[target].diagnostics().await.pool_wait_current,
                _ => clients[target].v2_diagnostics().pool_wait_current,
            };
            if waiting == 1 { break; }
            tokio::task::yield_now().await;
        }
        let v2_wait_current_queued = clients[target].v2_diagnostics().pool_wait_current;
        let v1_wait_current_queued = clients[target].diagnostics().await.pool_wait_current;
        // Poll both readers after the old 100 ms cutoff. On the base this
        // releases their cancelled logical permits. On the head they remain
        // occupied by the same written reads until their real replies arrive.
        tokio::time::advance(Duration::from_millis(51)).await;
        let first_early = match futures_util::poll!(first_read.as_mut()) { Poll::Ready(result) => Some(result), Poll::Pending => None };
        let second_early = match futures_util::poll!(second_read.as_mut()) { Poll::Ready(result) => Some(result), Poll::Pending => None };
        let early_read_completions = usize::from(first_early.is_some()) + usize::from(second_early.is_some());
        assert!(early_read_completions == 0 || early_read_completions == 2, "both reads have the same clock and attempt bound");
        if early_read_completions == 0 {
            // The queued caller still has its original 100 ms admission cap.
            // One timer tick exposes expiry; no caller deadline is extended.
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        let admission = competing.await;
        let caller_ms = caller_started.elapsed().as_millis();
        assert!(tokio::time::Instant::now() < emergency_budget.original_deadline());
        tokio::time::advance(Duration::from_millis(hold_ms) - started.elapsed()).await;
        gate.add_permits(2);
        let first_result = match first_early { Some(result) => result, None => first_read.as_mut().await };
        let second_result = match second_early { Some(result) => result, None => second_read.as_mut().await };
        drop(first_read);
        drop(second_read);
        let exact = |result: &Result<FencedTransitionV2Status, _>| matches!(result,
            Ok(FencedTransitionV2Status::Recorded(outcome)) if outcome.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_request(&original)));
        let successful_reads = usize::from(exact(&first_result)) + usize::from(exact(&second_result));
        let v2 = clients[target].v2_diagnostics();
        let v1 = clients[target].diagnostics().await;
        let evidence = Evidence {
            hold_ms, competitor, admission, caller_ms, early_read_completions, successful_reads,
            physical_reads: held(&fixture, STATUS), v2_wait_current_queued, v2_wait_max: v2.pool_wait_max,
            v1_wait_current_queued, v1_wait_max: v1.pool_wait_max,
            v2_setups: v2.setup_attempts - setups_before,
            v2_mutations: fixture.diagnostics().fenced_transition_v2_calls(),
        };
        assert_eq!(evidence.physical_reads, 2, "neither caller hedges or repeats its read");
        assert_eq!(v2.pool_wait_current, 0);
        assert_eq!(v1.pool_wait_current, 0);
        drop(emergency);
        drop(first);
        drop(second);
        drop(facade);
        for client in clients { client.shutdown().await; }
        (fixture, evidence)
    }).await;
    fixture.shutdown().await.unwrap();
    evidence
}

#[tokio::test]
async fn two_slow_receipts_preserve_competing_admission_including_emergency() {
    let mut evidence = Vec::new();
    for hold_ms in [500, 700] {
        for competitor in [
            Competitor::OrdinaryV1Lease,
            Competitor::OrdinaryV2Admission,
            Competitor::EmergencyV2Transition,
        ] {
            let row = competing_case(hold_ms, competitor).await;
            eprintln!("shared-pool contention: hold_ms={} competitor={:?} admission={:?} caller_ms={} early_read_completions={} successful_reads={} physical_reads={} v2_wait_current_queued={} v2_wait_max={} v1_wait_current_queued={} v1_wait_max={} v2_setups={} v2_mutations={}",
                row.hold_ms, row.competitor, row.admission, row.caller_ms, row.early_read_completions, row.successful_reads,
                row.physical_reads, row.v2_wait_current_queued, row.v2_wait_max, row.v1_wait_current_queued, row.v1_wait_max,
                row.v2_setups, row.v2_mutations);
            evidence.push(row);
        }
    }
    assert!(
        evidence
            .iter()
            .all(|row| row.admission == Admission::Success),
        "slow reads must not introduce any competing admission refusal: {evidence:?}"
    );
}
