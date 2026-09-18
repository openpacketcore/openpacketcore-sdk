use super::*;
use crate::{SctpPathStatus, SctpResetStreams};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::task::{Context, Poll, Waker};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

#[derive(Default)]
struct Probe {
    aborted: AtomicBool,
    sends: AtomicUsize,
    receives: AtomicUsize,
    reads: AtomicUsize,
    selections: AtomicUsize,
    send_error: Mutex<Option<N2Error>>,
    read_error: Mutex<Option<N2Error>>,
    primary_error: Mutex<Option<N2Error>>,
}

struct Fake {
    probe: Arc<Probe>,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<Result<N2Inbound, N2Error>>>,
    send_ready: watch::Receiver<bool>,
}

// Like the native UnprotectedN2Association, an I/O result still owned by a
// cancelled connector closes even if it never reaches candidate admission.
impl Drop for Fake {
    fn drop(&mut self) {
        self.probe.aborted.store(true, SeqCst);
    }
}

struct Control {
    probe: Arc<Probe>,
    inbound: mpsc::UnboundedSender<Result<N2Inbound, N2Error>>,
    send_ready: watch::Sender<bool>,
}

fn fake() -> (Fake, Control) {
    let probe = Arc::new(Probe::default());
    let (inbound, receiver) = mpsc::unbounded_channel();
    let (send_ready, ready) = watch::channel(true);
    (
        Fake {
            probe: probe.clone(),
            inbound: AsyncMutex::new(receiver),
            send_ready: ready,
        },
        Control {
            probe,
            inbound,
            send_ready,
        },
    )
}

fn addresses() -> Vec<SocketAddr> {
    ["192.0.2.22:38412", "192.0.2.11:38412"]
        .map(|a| a.parse().unwrap())
        .to_vec()
}

impl Transport for Fake {
    async fn send(&self, bytes: Bytes, _: u16) -> Result<usize, N2Error> {
        self.probe.sends.fetch_add(1, SeqCst);
        let mut ready = self.send_ready.clone();
        while !*ready.borrow_and_update() {
            ready.changed().await.unwrap();
        }
        match *self.probe.send_error.lock().unwrap() {
            Some(error) => Err(error),
            None => Ok(bytes.len()),
        }
    }
    async fn recv(&self) -> Result<N2Inbound, N2Error> {
        self.probe.receives.fetch_add(1, SeqCst);
        self.inbound.lock().await.recv().await.unwrap()
    }
    fn readback(&self) -> Result<TransportReadback, N2Error> {
        self.probe.reads.fetch_add(1, SeqCst);
        if let Some(error) = *self.probe.read_error.lock().unwrap() {
            return Err(error);
        }
        Ok(TransportReadback {
            local: addresses(),
            peer: addresses().into_iter().rev().collect(),
            paths: addresses()
                .into_iter()
                .enumerate()
                .map(|(i, peer_addr)| SctpPathHealth {
                    peer_addr,
                    status: SctpPathStatus::Reachable,
                    primary: i == 1,
                })
                .collect(),
        })
    }
    fn set_primary(&self, _: SocketAddr) -> Result<(), N2Error> {
        self.probe.selections.fetch_add(1, SeqCst);
        match *self.probe.primary_error.lock().unwrap() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn abort(&self) {
        self.probe.aborted.store(true, SeqCst);
    }
}

fn install(owner: &Core<Fake>) -> (Generation<Fake>, Control) {
    let (transport, control) = fake();
    let generation = owner.promote(owner.candidate(transport).unwrap()).unwrap();
    (generation, control)
}

fn event(event: SctpEvent) -> N2Inbound {
    N2Inbound::Notification(event)
}
fn data() -> N2Inbound {
    super::super::UnprotectedN2Profile::new(3)
        .unwrap()
        .admit(crate::InboundMessage {
            payload: Bytes::from_static(b"nas"),
            stream_id: 3,
            ppid: crate::NGAP_PPID,
            order: crate::DeliveryOrder::Ordered,
            assoc_id: 41,
            notification: false,
            event: None,
            truncated: false,
            control_truncated: false,
        })
        .unwrap()
}

fn poll_pending<F: Future>(future: std::pin::Pin<&mut F>) {
    assert!(
        matches!(
            future.poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ),
        "operation did not reach its controlled pending point"
    );
}

#[test]
fn two_candidates_have_exactly_one_winner_in_both_orders() {
    for reverse in [false, true] {
        let owner = Core::new();
        let (a, ac) = fake();
        let (b, bc) = fake();
        let a = owner.candidate(a).unwrap();
        let b = owner.candidate(b).unwrap();
        let (winner, loser, wc, lc) = if reverse {
            (b, a, bc, ac)
        } else {
            (a, b, ac, bc)
        };
        let generation = owner.promote(winner).unwrap();
        assert!(generation.number == 1);
        assert!(matches!(
            owner.promote(loser),
            Err(N2Error::CandidateSuperseded)
        ));
        assert!(!wc.probe.aborted.load(SeqCst) && lc.probe.aborted.load(SeqCst));
        drop(generation);
        assert!(wc.probe.aborted.load(SeqCst));
    }
}

#[test]
fn concurrent_promotions_publish_only_one_affine_generation() {
    let owner = Core::new();
    let (a, ac) = fake();
    let (b, bc) = fake();
    let a = owner.candidate(a).unwrap();
    let b = owner.candidate(b).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            owner.promote(a)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            owner.promote(b)
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert!(results.iter().filter(|r| r.is_ok()).count() == 1);
    assert!(
        results
            .iter()
            .filter(|r| matches!(r, Err(N2Error::CandidateSuperseded)))
            .count()
            == 1
    );
    assert!(ac.probe.aborted.load(SeqCst) != bc.probe.aborted.load(SeqCst));
    drop(results);
    assert!(ac.probe.aborted.load(SeqCst) && bc.probe.aborted.load(SeqCst));
}

#[tokio::test]
async fn foreign_and_stale_authority_cannot_touch_any_successor_operation() {
    let owner = Core::new();
    let foreign = Core::new();
    let (old, old_control) = install(&owner);
    let (foreign_token, fc) = install(&foreign);
    assert!(old.number == foreign_token.number);
    let (foreign_transport, candidate_control) = fake();
    let foreign_candidate = foreign.candidate(foreign_transport).unwrap();
    assert!(matches!(
        owner.promote(foreign_candidate),
        Err(N2Error::ForeignOwner)
    ));
    assert!(candidate_control.probe.aborted.load(SeqCst));
    let (current, cc) = install(&owner);
    assert!(current.number == 2 && old_control.probe.aborted.load(SeqCst));
    for (token, error) in [
        (&old, N2Error::GenerationRetired),
        (&foreign_token, N2Error::ForeignOwner),
    ] {
        assert!(owner.send(token, Bytes::from_static(b"nas"), 1).await == Err(error));
        assert!(matches!(owner.recv(token).await, Err(e) if e == error));
        assert!(matches!(owner.readback(token), Err(e) if e == error));
        assert!(owner.set_primary(token, addresses()[0]) == Err(error));
        assert!(owner.retire(token) == Err(error));
    }
    assert!(cc.probe.sends.load(SeqCst) == 0 && cc.probe.receives.load(SeqCst) == 0);
    assert!(cc.probe.reads.load(SeqCst) == 0 && cc.probe.selections.load(SeqCst) == 0);
    drop(old);
    assert!(!cc.probe.aborted.load(SeqCst) && !fc.probe.aborted.load(SeqCst));
    assert!(owner.send(&current, Bytes::from_static(b"nas"), 1).await == Ok(3));
    drop(owner);
    assert!(cc.probe.aborted.load(SeqCst));
    assert!(!fc.probe.aborted.load(SeqCst));
}

#[test]
fn drops_aba_and_generation_exhaustion_preserve_exact_ownership() {
    let owner = Core::new();
    let (discard, dc) = fake();
    drop(owner.candidate(discard).unwrap());
    assert!(dc.probe.aborted.load(SeqCst));
    let (empty, ec) = fake();
    let empty = owner.candidate(empty).unwrap();
    let (first, _) = install(&owner);
    let (active, ac) = fake();
    let active = owner.candidate(active).unwrap();
    owner.retire(&first).unwrap();
    for (candidate, control) in [(empty, ec), (active, ac)] {
        assert!(matches!(
            owner.promote(candidate),
            Err(N2Error::CandidateSuperseded)
        ));
        assert!(control.probe.aborted.load(SeqCst));
    }
    // Force only the finite-number boundary, keeping the real promotion path.
    owner.shared.lock().last_generation = u64::MAX - 1;
    let (last, lc) = install(&owner);
    assert!(last.number == u64::MAX);
    let (overflow, oc) = fake();
    assert!(matches!(
        owner.promote(owner.candidate(overflow).unwrap()),
        Err(N2Error::GenerationExhausted)
    ));
    assert!(oc.probe.aborted.load(SeqCst) && !lc.probe.aborted.load(SeqCst));
    assert!(owner.readback(&last).is_ok());
    owner.shared.close();
    owner.shared.close();
    assert!(lc.probe.aborted.load(SeqCst));
    let (closed, cc) = fake();
    assert!(matches!(owner.candidate(closed), Err(N2Error::OwnerClosed)));
    assert!(cc.probe.aborted.load(SeqCst));
}

#[tokio::test]
async fn replacement_retirement_and_close_cancel_pending_send_and_receive() {
    for transition in 0..3 {
        let owner = Core::new();
        let (generation, control) = install(&owner);
        control.send_ready.send_replace(false);
        let mut send = Box::pin(owner.send(&generation, Bytes::from_static(b"nas"), 3));
        let mut recv = Box::pin(owner.recv(&generation));
        poll_pending(send.as_mut());
        poll_pending(recv.as_mut());
        assert!(control.probe.sends.load(SeqCst) == 1 && control.probe.receives.load(SeqCst) == 1);
        let replacement = match transition {
            0 => Some(install(&owner)),
            1 => {
                owner.retire(&generation).unwrap();
                None
            }
            _ => {
                owner.shared.close();
                None
            }
        };
        // Even ready late completions cannot win over the retirement signal.
        control.send_ready.send_replace(true);
        control.inbound.send(Ok(data())).unwrap();
        assert!(send.await == Err(N2Error::GenerationRetired));
        assert!(matches!(recv.await, Err(N2Error::GenerationRetired)));
        if let Some((new, nc)) = replacement {
            assert!(!nc.probe.aborted.load(SeqCst));
            assert!(owner.send(&new, Bytes::from_static(b"nas"), 3).await == Ok(3));
        }
    }
}

#[tokio::test]
async fn canceled_receive_reuses_transport_and_terminal_event_blocks_queued_receiver() {
    let owner = Core::new();
    let (generation, control) = install(&owner);
    let mut cancelled = Box::pin(owner.recv(&generation));
    poll_pending(cancelled.as_mut());
    drop(cancelled);
    control.inbound.send(Ok(data())).unwrap();
    assert!(matches!(
        owner.recv(&generation).await.unwrap().inbound(),
        N2Inbound::Payload(_)
    ));
    let mut first = Box::pin(owner.recv(&generation));
    let mut queued = Box::pin(owner.recv(&generation));
    poll_pending(first.as_mut());
    poll_pending(queued.as_mut());
    let calls = control.probe.receives.load(SeqCst);
    control
        .inbound
        .send(Ok(event(SctpEvent::Shutdown { assoc_id: 41 })))
        .unwrap();
    control.inbound.send(Ok(data())).unwrap();
    let terminal = first.await.unwrap();
    assert!(terminal.retired() && terminal.generation() == generation.number);
    assert!(matches!(
        terminal.into_inbound(),
        N2Inbound::Notification(SctpEvent::Shutdown { .. })
    ));
    assert!(matches!(queued.await, Err(N2Error::GenerationRetired)));
    assert!(control.probe.receives.load(SeqCst) == calls);
}

#[tokio::test]
async fn lifecycle_admission_distinguishes_terminal_events_from_stream_and_path_metadata() {
    let mut schedules = vec![
        (SctpEvent::Shutdown { assoc_id: 41 }, true),
        (
            SctpEvent::PartialDeliveryAborted {
                assoc_id: 41,
                stream_id: 3,
                sequence: 9,
            },
            true,
        ),
        (
            SctpEvent::Unknown {
                notification_type: 0xffff,
            },
            true,
        ),
    ];
    for state in [0, 1, 2, 3, 4, 5, u16::MAX] {
        for error in [0, 1] {
            schedules.push((
                SctpEvent::AssociationChange {
                    state,
                    error,
                    outbound_streams: 8,
                    inbound_streams: 8,
                    assoc_id: 41,
                },
                state != 0 || error != 0,
            ));
        }
    }
    for status in [
        SctpReconfigurationStatus::Completed,
        SctpReconfigurationStatus::Denied,
        SctpReconfigurationStatus::Failed,
    ] {
        schedules.push((
            SctpEvent::AssociationReset {
                assoc_id: 41,
                status,
                local_tsn: 9,
                remote_tsn: 7,
            },
            status == SctpReconfigurationStatus::Completed,
        ));
        schedules.push((
            SctpEvent::StreamReset {
                assoc_id: 41,
                status,
                incoming: true,
                outgoing: true,
                streams: SctpResetStreams::new(&[3]).unwrap(),
            },
            false,
        ));
        for (inbound_streams, outbound_streams) in [(8, 8), (0, 8), (8, 0)] {
            schedules.push((
                SctpEvent::StreamChange {
                    assoc_id: 41,
                    status,
                    inbound_streams,
                    outbound_streams,
                },
                status == SctpReconfigurationStatus::Completed
                    && (inbound_streams == 0 || outbound_streams == 0),
            ));
        }
    }
    for (notification, terminal) in schedules {
        let owner = Core::new();
        let (generation, control) = install(&owner);
        control.inbound.send(Ok(event(notification))).unwrap();
        let received = owner.recv(&generation).await.unwrap();
        assert!(
            received.generation() == generation.number && received.retired() == terminal,
            "lifecycle disposition changed"
        );
        assert!(matches!(received.inbound(), N2Inbound::Notification(e) if *e == notification));
        assert!(control.probe.aborted.load(SeqCst) == terminal);
        assert!(owner.readback(&generation).is_ok() != terminal);
    }
}

#[tokio::test]
async fn errors_retire_uncertain_transports_but_local_rejections_preserve_them() {
    for error in [
        N2Error::EmptyPayload,
        N2Error::MessageTooLarge,
        N2Error::InvalidConfiguration,
        N2Error::SendFailed,
        N2Error::TransportUnavailable,
    ] {
        let terminal = matches!(error, N2Error::SendFailed | N2Error::TransportUnavailable);
        let owner = Core::new();
        let (generation, control) = install(&owner);
        *control.probe.send_error.lock().unwrap() = Some(error);
        assert!(owner.send(&generation, Bytes::from_static(b"nas"), 1).await == Err(error));
        assert!(control.probe.aborted.load(SeqCst) == terminal);
        let owner = Core::new();
        let (generation, control) = install(&owner);
        *control.probe.primary_error.lock().unwrap() = Some(error);
        assert!(owner.set_primary(&generation, addresses()[0]) == Err(error));
        assert!(control.probe.aborted.load(SeqCst) == terminal);
    }
    let owner = Core::new();
    let (generation, control) = install(&owner);
    *control.probe.read_error.lock().unwrap() = Some(N2Error::ReadbackFailed);
    assert!(matches!(
        owner.readback(&generation),
        Err(N2Error::ReadbackFailed)
    ));
    assert!(control.probe.aborted.load(SeqCst));
    let owner = Core::new();
    let (generation, control) = install(&owner);
    control.inbound.send(Err(N2Error::WrongPpid)).unwrap();
    assert!(matches!(
        owner.recv(&generation).await,
        Err(N2Error::WrongPpid)
    ));
    assert!(control.probe.aborted.load(SeqCst));
}

#[test]
fn readback_preserves_order_and_path_metadata_while_diagnostics_are_redacted() {
    let owner = Core::new();
    let (generation, _) = install(&owner);
    let readback = owner.readback(&generation).unwrap();
    assert!(readback.generation() == 1 && readback.local_addresses() == addresses());
    assert!(readback.peer_addresses() == addresses().into_iter().rev().collect::<Vec<_>>());
    assert!(readback.peer_path_health().len() == 2 && readback.peer_path_health()[1].primary);
    assert!(readback.peer_path_health()[0].peer_addr == addresses()[0]);
    assert!(format!("{readback:?}") == "N2Readback { .. }");
    let received = N2Received {
        generation: 8127,
        retired: false,
        inbound: data(),
    };
    assert!(format!("{received:?}") == "N2Received { .. }");
    assert!(format!("{:?}", N2AssociationOwner::new()) == "N2AssociationOwner { .. }");
    for error in [
        N2Error::OwnerClosed,
        N2Error::ForeignOwner,
        N2Error::CandidateSuperseded,
        N2Error::GenerationRetired,
        N2Error::GenerationExhausted,
        N2Error::ReconnectTimeout,
        N2Error::ReconnectExhausted,
    ] {
        assert!(error.to_string().starts_with("n2_") && !error.to_string().contains(' '));
    }
}

fn policy(attempts: u32, attempt: u64, total: u64, delay: u64) -> N2ReconnectPolicy {
    N2ReconnectPolicy::new(
        attempts,
        Duration::from_secs(attempt),
        Duration::from_secs(total),
        Duration::from_secs(delay),
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn retry_attempts_backoff_total_deadline_and_nonretryable_errors_are_bounded() {
    for delay in [0, 2] {
        let owner: Core<Fake> = Core::new();
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = owner
            .connect_candidate(policy(3, 5, 20, delay), || async {
                calls.fetch_add(1, SeqCst);
                Err(N2Error::ConnectFailed)
            })
            .await;
        assert!(matches!(result, Err(N2Error::ReconnectExhausted)));
        assert!(calls.load(SeqCst) == 3 && started.elapsed() == Duration::from_secs(delay * 2));
    }
    for (attempts, attempt, total, delay, expected_calls, expected_time, error) in [
        (2, 3, 20, 2, 2, 8, N2Error::ReconnectExhausted),
        (9, 3, 5, 0, 2, 5, N2Error::ReconnectTimeout),
        (9, 3, 4, 8, 1, 4, N2Error::ReconnectTimeout),
    ] {
        let owner: Core<Fake> = Core::new();
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = owner
            .connect_candidate(policy(attempts, attempt, total, delay), || async {
                calls.fetch_add(1, SeqCst);
                std::future::pending().await
            })
            .await;
        assert!(matches!(result, Err(e) if e == error));
        assert!(
            calls.load(SeqCst) == expected_calls
                && started.elapsed() == Duration::from_secs(expected_time)
        );
    }
    for error in [
        N2Error::InvalidConfiguration,
        N2Error::UnsupportedPlatform,
        N2Error::TransportUnavailable,
    ] {
        let owner: Core<Fake> = Core::new();
        let calls = AtomicUsize::new(0);
        let result = owner
            .connect_candidate(policy(9, 3, 20, 0), || async {
                calls.fetch_add(1, SeqCst);
                Err(error)
            })
            .await;
        assert!(matches!(result, Err(e) if e == error));
        assert!(calls.load(SeqCst) == 1);
    }
}

struct PendingConnect<'a>(&'a AtomicUsize);
impl Drop for PendingConnect<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn pending_connects_close_on_cancellation_supersession_and_each_timeout() {
    for transition in 0..4 {
        let owner = Core::<Fake>::new();
        let (old, oc) = install(&owner);
        let drops = AtomicUsize::new(0);
        let mut pending = Box::pin(owner.connect_candidate(policy(3, 2, 10, 0), || async {
            let _socket = PendingConnect(&drops);
            std::future::pending().await
        }));
        poll_pending(pending.as_mut());
        match transition {
            0 => {
                drop(pending);
                assert!(!oc.probe.aborted.load(SeqCst));
            }
            1 => {
                let (_new, _) = install(&owner);
                assert!(matches!(pending.await, Err(N2Error::CandidateSuperseded)));
            }
            2 => {
                owner.shared.close();
                assert!(matches!(pending.await, Err(N2Error::OwnerClosed)));
            }
            _ => {
                owner.retire(&old).unwrap();
                assert!(matches!(pending.await, Err(N2Error::CandidateSuperseded)));
            }
        }
        assert!(drops.load(SeqCst) == 1);
    }
    let owner = Core::<Fake>::new();
    let drops = AtomicUsize::new(0);
    let result = owner
        .connect_candidate(policy(3, 2, 10, 0), || async {
            let _socket = PendingConnect(&drops);
            std::future::pending().await
        })
        .await;
    assert!(matches!(result, Err(N2Error::ReconnectExhausted)) && drops.load(SeqCst) == 3);
}

#[tokio::test(start_paused = true)]
async fn connected_candidates_remain_unpublished_and_close_if_completion_loses_race() {
    let owner = Core::new();
    let (old, oc) = install(&owner);
    let (transport, control) = fake();
    let mut transport = Some(transport);
    let candidate = owner
        .connect_candidate(policy(1, 1, 2, 0), || {
            std::future::ready(Ok(transport.take().unwrap()))
        })
        .await
        .unwrap();
    assert!(owner.readback(&old).is_ok() && !oc.probe.aborted.load(SeqCst));
    drop(candidate);
    assert!(control.probe.aborted.load(SeqCst));
    let (transport, control) = fake();
    let mut transport = Some(transport);
    let result = owner
        .connect_candidate(policy(1, 1, 2, 0), || {
            owner.retire(&old).unwrap();
            std::future::ready(Ok(transport.take().unwrap()))
        })
        .await;
    assert!(matches!(result, Err(N2Error::CandidateSuperseded)));
    assert!(control.probe.aborted.load(SeqCst));
}

#[tokio::test]
async fn invalid_and_overflowing_bounds_do_not_open_a_socket() {
    assert!(N2ReconnectPolicy::new(
        0,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::ZERO
    )
    .is_err());
    for (attempt, total, delay) in [
        (Duration::ZERO, Duration::from_secs(1), Duration::ZERO),
        (Duration::from_secs(1), Duration::ZERO, Duration::ZERO),
    ] {
        assert!(N2ReconnectPolicy::new(1, attempt, total, delay).is_err());
    }
    for field in 0..3 {
        let owner = Core::<Fake>::new();
        let calls = AtomicUsize::new(0);
        let mut durations = [Duration::from_secs(1); 3];
        durations[field] = Duration::MAX;
        let bounds = N2ReconnectPolicy::new(1, durations[0], durations[1], durations[2]).unwrap();
        let result = owner
            .connect_candidate(bounds, || async {
                calls.fetch_add(1, SeqCst);
                Err(N2Error::ConnectFailed)
            })
            .await;
        assert!(matches!(result, Err(N2Error::InvalidConfiguration)) && calls.load(SeqCst) == 0);
    }
}

#[test]
fn public_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}
    let owner = N2AssociationOwner::new();
    assert_send(
        owner.connect_candidate(SctpConnectConfig::new(addresses()[0]), policy(1, 1, 1, 0)),
    );
    // No fabricated generation capability is needed to type-check I/O futures.
    fn io(owner: &N2AssociationOwner, generation: &N2Generation) {
        assert_send(owner.send(generation, Bytes::new(), 0));
        assert_send(owner.recv(generation));
    }
    let _ = io;
}
