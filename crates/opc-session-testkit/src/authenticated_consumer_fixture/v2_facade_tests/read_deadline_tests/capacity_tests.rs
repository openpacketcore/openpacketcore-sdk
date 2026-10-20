//! Extended V1/V2 reads share bounded capacity without filling the last lane.

use super::*;
use opc_session_store::{
    SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
};
use std::task::Poll;

#[derive(Clone, Copy)]
enum ReadKind {
    Get,
    History,
}

impl ReadKind {
    fn other(self) -> Self {
        match self {
            Self::Get => Self::History,
            Self::History => Self::Get,
        }
    }

    fn counter(self) -> usize {
        match self {
            Self::Get => GET,
            Self::History => HISTORY,
        }
    }
}

async fn read(
    client: &PersistentSessionConsumerClient,
    kind: ReadKind,
    budget: PreparedCheckpointBudget,
) -> bool {
    match kind {
        ReadKind::Get => client
            .get_with_budget(session_key(1900), budget)
            .await
            .is_ok(),
        ReadKind::History => client
            .fenced_transition_v2_history_state_with_budget(budget)
            .await
            .is_ok(),
    }
}

async fn prewarm(client: &PersistentSessionConsumerClient, kind: ReadKind) {
    match kind {
        ReadKind::Get => {
            client.prewarm().await.unwrap();
        }
        ReadKind::History => client.prewarm_v2().await.unwrap(),
    }
}

#[tokio::test]
async fn mixed_v1_v2_read_queue_leaves_admission_for_the_other_protocol() {
    for first_kind in [ReadKind::Get, ReadKind::History] {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let fixture =
            with_fixture_protocol_clock("shared read admission reservation", async move {
                let clients = clients_with_capacity(&fixture, 2, 1);
                let client = &clients[0];
                prewarm(client, first_kind).await;
                let gate = Arc::new(tokio::sync::Semaphore::new(0));
                for kind in [GET, HISTORY] {
                    *fixture.voters[0].service.reply_gates[kind].lock().unwrap() =
                        Some(Arc::clone(&gate));
                }
                let budget = read_budget();
                let started = tokio::time::Instant::now();
                let mut first = Box::pin(read(client, first_kind, budget));
                loop {
                    assert!(futures_util::poll!(first.as_mut()).is_pending());
                    if held(&fixture, first_kind.counter()) == 1 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                let mut second = Box::pin(read(client, first_kind.other(), budget));
                loop {
                    assert!(futures_util::poll!(second.as_mut()).is_pending());
                    let waits = client.diagnostics().await.pool_wait_current
                        + client.v2_diagnostics().pool_wait_current;
                    if waits == 1 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                let mut third = Box::pin(read(client, first_kind, budget));
                assert!(
                    matches!(futures_util::poll!(third.as_mut()), Poll::Ready(false)),
                    "the bounded read queue must leave a total-admission slot free"
                );
                drop(third);
                assert_eq!(held(&fixture, GET) + held(&fixture, HISTORY), 1);
                match first_kind {
                    ReadKind::Get => {
                        let request = SessionConsumerV2Request::new(
                            client.scope(),
                            SessionConsumerV2Operation::FencedTransitionV2Capability,
                        );
                        assert!(matches!(
                            client.execute_v2(&request).await,
                            Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                                _
                            )))
                        ));
                    }
                    ReadKind::History => {
                        let request = SessionConsumerRequest::new(
                            client.scope(),
                            SessionConsumerRequestId::new(),
                            SessionConsumerOperation::AcquireLease {
                                key: session_key(1901),
                                owner: owner(),
                                ttl: Duration::from_secs(30),
                            },
                        );
                        assert!(matches!(
                            client.execute(&request).await,
                            Ok(SessionConsumerResponse::AcquireLease(Ok(_)))
                        ));
                    }
                }
                assert!(started.elapsed() < Duration::from_millis(100));
                tokio::time::advance(Duration::from_millis(101) - started.elapsed()).await;
                assert!(
                    !second.await,
                    "the queued read keeps its original pre-write cap"
                );
                assert_eq!(held(&fixture, GET) + held(&fixture, HISTORY), 1);
                assert!(futures_util::poll!(first.as_mut()).is_pending());
                tokio::time::advance(Duration::from_millis(599)).await;
                gate.add_permits(1);
                assert!(first.await, "the written 700 ms reply remains valid");
                assert!(tokio::time::Instant::now() < budget.original_deadline());
                // A fresh caller can use the released read capacity. No permit
                // leaks from the timed-out or refused queue entries.
                gate.add_permits(1);
                assert!(read(client, first_kind.other(), read_budget()).await);
                assert_eq!(held(&fixture, GET), 1);
                assert_eq!(held(&fixture, HISTORY), 1);
                assert_eq!(client.diagnostics().await.pool_wait_current, 0);
                assert_eq!(client.v2_diagnostics().pool_wait_current, 0);
                for client in clients {
                    client.shutdown().await;
                }
                fixture
            })
            .await;
        fixture.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn a_single_configured_lane_remains_usable_for_extended_reads() {
    for kind in [ReadKind::Get, ReadKind::History] {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let fixture = with_fixture_protocol_clock("single read lane", async move {
            let clients = clients_with_capacity(&fixture, 1, 1);
            prewarm(&clients[0], kind).await;
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            *fixture.voters[0].service.reply_gates[kind.counter()]
                .lock()
                .unwrap() = Some(Arc::clone(&gate));
            let budget = read_budget();
            let mut pending = Box::pin(read(&clients[0], kind, budget));
            loop {
                assert!(futures_util::poll!(pending.as_mut()).is_pending());
                if held(&fixture, kind.counter()) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            tokio::time::advance(Duration::from_millis(700)).await;
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            gate.add_permits(1);
            assert!(pending.await);
            assert!(tokio::time::Instant::now() < budget.original_deadline());
            assert_eq!(held(&fixture, kind.counter()), 1);
            for client in clients {
                client.shutdown().await;
            }
            fixture
        })
        .await;
        fixture.shutdown().await.unwrap();
    }
}
