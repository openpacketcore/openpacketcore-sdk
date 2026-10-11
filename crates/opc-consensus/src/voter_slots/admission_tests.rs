use super::*;
use crate::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusRequestId};

fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: [incarnation as u8; 32],
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}

fn completed_table(incarnation: u64) -> VoterSlotTable {
    let epoch = ConsensusConfigurationEpoch::new(incarnation).unwrap();
    VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: incarnation,
        configuration_epoch: epoch,
        slots: (1..=3)
            .map(|slot| {
                let current = if slot == 3 { incarnation } else { 1 };
                VoterSlotRecord {
                    member: member(slot, current),
                    retired_through: current - 1,
                    phase: VoterSlotPhase::Voting,
                    last_result: (current > 1).then_some(VoterReplacementResult {
                        request_id: ConsensusRequestId::from_bytes([current as u8; 16]),
                        request_digest: [current as u8; 32],
                        incarnation: VoterIncarnation::new(current).unwrap(),
                        revision: incarnation,
                        configuration_epoch: epoch,
                        kind: VoterReplacementResultKind::Completed,
                        terminal: VoterSlotLogId {
                            term: incarnation,
                            index: incarnation,
                        },
                    }),
                }
            })
            .collect(),
        replacement: None,
    }
}

#[derive(Debug)]
struct Reader(Mutex<VoterSlotDurableState>);

#[async_trait]
impl VoterSlotStateReader for Reader {
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Engine(Mutex<BTreeSet<ConsensusNodeId>>);

#[async_trait]
impl VoterResponseFenceEngine for Engine {
    type Receipt = ConsensusNodeId;

    fn disable_application_leases(&self) {}

    async fn effective_members(&self) -> Result<BTreeSet<ConsensusNodeId>, VoterReplacementError> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn fence(&self, peer: ConsensusNodeId) -> Result<Self::Receipt, VoterReplacementError> {
        Ok(peer)
    }

    async fn release(&self, _: Self::Receipt) -> Result<(), VoterReplacementError> {
        Ok(())
    }

    async fn ensure_surviving_quorum(&self, _: Instant) -> Result<(), VoterReplacementError> {
        Ok(())
    }

    fn enable_voting(&self, _: bool) {}
}

#[derive(Debug)]
struct FailingReader {
    state: Reader,
    unavailable: std::sync::atomic::AtomicBool,
    reads: watch::Sender<usize>,
}

#[async_trait]
impl VoterSlotStateReader for FailingReader {
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        self.reads.send_modify(|reads| *reads += 1);
        if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
            Err(VoterReplacementError::Unavailable)
        } else {
            self.state.read_voter_slot_state().await
        }
    }
}

#[tokio::test(start_paused = true)]
async fn unavailable_reconciliation_backs_off_and_fresh_publication_wakes_it() {
    let initial = completed_table(1);
    let (reads, mut observed) = watch::channel(0);
    let reader = Arc::new(FailingReader {
        state: Reader(Mutex::new(
            VoterSlotDurableState::new(initial.clone()).unwrap(),
        )),
        unavailable: std::sync::atomic::AtomicBool::new(false),
        reads,
    });
    let engine = Arc::new(Engine(Mutex::new(known_members(&initial))));
    let admission = VoterAdmission::new(member(1, 1).identity.node_id(), reader.clone())
        .await
        .unwrap();
    admission.attach_engine(engine).await.unwrap();
    reader
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    admission.notify_durable_changed();
    observed.wait_for(|reads| *reads >= 3).await.unwrap();
    // A retained handle to permanently closed storage must not sustain ten
    // failed database reads per second. This also covers a retry already active
    // when the writer exits, even without a final publication notification.
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        observed.wait_for(|reads| *reads >= 8),
    )
    .await
    .is_err());

    // Reach a longer backoff, then prove a real publication interrupts it.
    observed.wait_for(|reads| *reads >= 9).await.unwrap();
    let before = *observed.borrow_and_update();
    reader
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    admission.notify_durable_changed();
    tokio::time::timeout(
        Duration::from_millis(1),
        observed.wait_for(|reads| *reads > before),
    )
    .await
    .expect("a fresh publication must interrupt the retry backoff")
    .unwrap();
    observed.borrow_and_update();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), observed.changed())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn completed_replacements_release_obsolete_gates_without_readmitting_retired_peers() {
    let initial = completed_table(1);
    let reader = Arc::new(Reader(Mutex::new(
        VoterSlotDurableState::new(initial.clone()).unwrap(),
    )));
    let engine = Arc::new(Engine(Mutex::new(known_members(&initial))));
    let survivor = member(1, 1).identity.node_id();
    let admission = VoterAdmission::new(survivor, reader.clone()).await.unwrap();
    admission.attach_engine(engine.clone()).await.unwrap();
    let survivor_gate = admission.state.lock().unwrap().gates[&survivor].clone();

    for incarnation in 2..=32 {
        let retired = member(3, incarnation - 1).identity.node_id();
        let current = member(3, incarnation).identity.node_id();
        let table = completed_table(incarnation);
        let members = known_members(&table);
        *reader.0.lock().unwrap() = VoterSlotDurableState::new(table).unwrap();
        // Publication can precede the engine dropping the retired member.
        admission.reconcile().await.unwrap();
        {
            let state = admission.state.lock().unwrap();
            assert_eq!(state.gates.len(), 4);
            assert!(state.acknowledged.contains(&retired));
        }
        *engine.0.lock().unwrap() = members;
        admission.reconcile().await.unwrap();
        {
            let state = admission.state.lock().unwrap();
            assert_eq!(
                state.gates.len(),
                3,
                "obsolete gate survived reconciliation"
            );
            assert!(state.acknowledged.is_empty());
            assert!(Arc::ptr_eq(&survivor_gate, &state.gates[&survivor]));
        }
        assert!(admission.serial.lock().await.is_empty());
        for old_incarnation in 1..incarnation {
            assert_eq!(
                admission
                    .run_peer(
                        member(3, old_incarnation).identity.node_id(),
                        Instant::now() + Duration::from_secs(1),
                        || async { panic!("retired peer reached the engine") },
                    )
                    .await,
                Err::<(), _>(VoterReplacementError::UnauthorizedReplacement),
            );
        }
        admission
            .run_peer(current, Instant::now() + Duration::from_secs(1), || async {
                Ok(())
            })
            .await
            .unwrap();
    }
}
