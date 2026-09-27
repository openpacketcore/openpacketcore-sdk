//! Real native target admission after two successful read-only preflights.
//! Only delivery of the independent checkpoint observation is held; the SDK
//! prepares, admits, applies, authenticates and settles every actual command.

use super::*;
use crate::audit_authority::{continuity::*, *};
use crate::{
    AuditKey, ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile,
};
use std::sync::{atomic::AtomicUsize, Mutex};

const WAIT: Duration = Duration::from_secs(10);
const LIFETIME: Duration = Duration::from_secs(60);
const TENANT: &str = "synthetic-admission";
const PRINCIPAL: &str = "spiffe://test.invalid/tenant/synthetic-admission/operator";

struct ReadGate {
    claimed: AtomicUsize,
    entered: tokio::sync::Semaphore,
    release: [tokio::sync::Semaphore; 2],
    observations: Mutex<Vec<(usize, Option<AuditCheckpoint>)>>,
}

impl ReadGate {
    fn new() -> Self {
        Self {
            claimed: AtomicUsize::new(0),
            entered: tokio::sync::Semaphore::new(0),
            release: std::array::from_fn(|_| tokio::sync::Semaphore::new(0)),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn claim(&self) -> Option<usize> {
        self.claimed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old < 2).then_some(old + 1)
            })
            .ok()
    }
}

// Every held read is released on failure/cancellation as well as success. The
// test polls both public futures directly and creates no background producer.
struct ReleaseReads(Arc<ReadGate>);
impl Drop for ReleaseReads {
    fn drop(&mut self) {
        for release in &self.0.release {
            release.add_permits(1);
        }
    }
}

#[derive(Default)]
struct Checkpoint {
    value: Mutex<Option<AuditCheckpoint>>,
    gate: Mutex<Option<Arc<ReadGate>>>,
}

#[async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: super::super::ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        let observed = self.value.lock().unwrap().clone();
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            if let Some(ticket) = gate.claim() {
                gate.observations
                    .lock()
                    .unwrap()
                    .push((ticket, observed.clone()));
                gate.entered.add_permits(1);
                gate.release[ticket].acquire().await.unwrap().forget();
            }
        }
        Ok(observed)
    }

    async fn compare_advance(
        &self,
        _: super::super::ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let mut current = self.value.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x53; 32]).unwrap()
}

fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), TENANT, PRINCIPAL).unwrap()
}

fn event(request: u8) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [request; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        TENANT,
        PRINCIPAL,
        ManagementAuditTransportCode::Internal,
        ManagementAuditOperationCode::Exec,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        None::<&str>,
    )
    .unwrap()
}

fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected native authenticated receipt: {other:?}"),
    }
}

struct Fixture {
    store: ConsensusConfigStore,
    device: NetconfDeviceOwner,
    checkpoint: Arc<Checkpoint>,
    dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let node = super::super::ConfigConsensusNodeId::new(1).unwrap();
        let identity = super::super::ConfigConsensusIdentity::new(
            super::super::ConfigConsensusClusterId::from_bytes([0x31; 32]),
            super::super::ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            super::super::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                dir.path().join("authority.sqlite"),
                RetainedConfigBinding::new(topology.clone(), [0x41; 32], [0x42; 32])
                    .unwrap()
                    .with_profile(RetainedConfigProfile::NetconfTargetsV1),
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x51; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoint = Arc::new(Checkpoint::default());
        let policy = AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
            checkpoint.clone(),
            1,
            1,
        )
        .unwrap();
        let store = ConsensusConfigStore::open_with_audit_continuity(
            topology,
            backend,
            dir.path().join("snapshots"),
            BTreeMap::new(),
            policy,
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        store
            .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(96, 32).unwrap())
            .await
            .unwrap();
        let prepared = store
            .prepare_netconf_device(&privacy(), &event(1), LIFETIME)
            .await
            .unwrap();
        let intent = applied(
            store
                .admit_netconf_target_local(prepared.mutation(), caller())
                .await,
        );
        let receipt = applied(
            store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller())
                .await,
        );
        store
            .complete_required_audit_outcome(&receipt, caller())
            .await
            .unwrap();
        let device = store
            .claim_netconf_device_owner(&prepared, &receipt, caller())
            .await
            .unwrap();
        Self {
            store,
            device,
            checkpoint,
            dir,
        }
    }

    async fn prepare_cleanup(&self, request: u8) -> (NetconfSessionOwner, PreparedTargetMutation) {
        let session = self
            .store
            .open_netconf_session(&self.device, caller())
            .await
            .unwrap();
        session.invalidate();
        let original = self
            .store
            .prepare_netconf_session_cleanup(&session, &privacy(), &event(request), LIFETIME)
            .await
            .unwrap();
        (session, original)
    }

    async fn rows(&self) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let conn = self.store.inner.backend.conn();
        let conn = conn.lock().await;
        [
            "config_history",
            "config_raft_management_audit",
            "config_netconf_profile",
            "config_netconf_targets",
            "config_netconf_lifecycle",
        ]
        .into_iter()
        .map(|table| {
            let mut query = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }

    async fn replay_admit_in_apply(
        &self,
        prepared: &PreparedTargetMutation,
        request: u8,
    ) -> super::super::ConfigConsensusResponse {
        // A different transport request reaches consensus apply instead of
        // being answered by the public preflight or outer request-result cache.
        // The target operation's handle, payload, identity and expiry are exact.
        self.store
            .submit_request_on_local_leader(
                opc_consensus::ConsensusRequestId::from_bytes([request; 16]),
                ConfigMutationIntent::ManagementAudit(Box::new(
                    super::super::audit::AuditCommand::NetconfTarget(Box::new(
                        super::super::audit_mutation::TargetAuditCommandV1::Admit(
                            prepared.command().clone(),
                        ),
                    )),
                )),
            )
            .await
            .unwrap()
    }

    async fn settle_cleanup(
        &self,
        prepared: &PreparedTargetMutation,
        intent: &AuditOperationReceipt,
    ) -> AuditOperationReceipt {
        let receipt = applied(
            self.store
                .submit_netconf_target_local(prepared, intent, caller())
                .await,
        );
        assert!(
            matches!(receipt.state(), AuditOperationState::TargetV1(_)),
            "TARGET_WINNER_EFFECT: {receipt:?}"
        );
        self.store
            .complete_required_audit_outcome(&receipt, caller())
            .await
            .unwrap();
        self.store
            .lookup_audit_operation(prepared.handle(), caller())
            .await
            .unwrap()
            .unwrap()
    }

    async fn close(self) {
        self.store.shutdown().await.unwrap();
        drop(self.store);
        drop(self.dir);
    }
}

#[tokio::test]
async fn target_admission_serializes_two_preflighted_cleanup_intents() {
    let f = Fixture::new().await;
    let (_first_owner, first) = f.prepare_cleanup(2).await;
    let (second_owner, second) = f.prepare_cleanup(3).await;
    let before = f.rows().await;
    let settled_checkpoint = f.checkpoint.value.lock().unwrap().clone();
    assert!(settled_checkpoint.is_some());
    let gate = Arc::new(ReadGate::new());
    let release_on_exit = ReleaseReads(gate.clone());
    *f.checkpoint.gate.lock().unwrap() = Some(gate.clone());

    let (first_intent, second_admission, after_first) = {
        let one = f.store.admit_netconf_target_local(&first, caller());
        let two = f.store.admit_netconf_target_local(&second, caller());
        tokio::pin!(one, two);
        // The first checkpoint load in each public admission follows its real
        // quorum read and completed SQLite preflight transaction. No other
        // checkpoint user is polled between arming and these two observations.
        tokio::time::timeout(WAIT, async {
            tokio::select! {
                result = &mut one => panic!("first admission bypassed preflight gate: {result:?}"),
                entered = gate.entered.acquire() => entered.unwrap().forget(),
            }
            tokio::select! {
                result = &mut two => panic!("second admission bypassed preflight gate: {result:?}"),
                entered = gate.entered.acquire() => entered.unwrap().forget(),
            }
        })
        .await
        .unwrap();
        assert_eq!(gate.claimed.load(Ordering::Acquire), 2);
        assert_eq!(
            *gate.observations.lock().unwrap(),
            vec![(0, settled_checkpoint.clone()), (1, settled_checkpoint)],
            "TARGET_BOTH_REAL_PREFLIGHTS_CAPTURED"
        );
        assert_eq!(f.rows().await, before, "TARGET_PREFLIGHT_HAS_NO_EFFECT");

        gate.release[0].add_permits(1);
        let first_intent = applied(tokio::time::timeout(WAIT, &mut one).await.unwrap());
        assert_eq!(first_intent.state(), AuditOperationState::Intent);
        let after_first = f.rows().await;
        assert_eq!(after_first[0], before[0]);
        assert_eq!(after_first[2..], before[2..]);
        assert_ne!(after_first[1], before[1]);

        // The second prediction remains the old valid one. Its later command
        // must meet the first Intent inside the serialized native transaction.
        gate.release[1].add_permits(1);
        let second_admission = tokio::time::timeout(WAIT, &mut two).await.unwrap();
        (first_intent, second_admission, after_first)
    };
    *f.checkpoint.gate.lock().unwrap() = None;
    drop(release_on_exit);

    if !matches!(
        second_admission,
        AuditAdmission::Rejected(AuditAuthorityError::InvalidInput)
    ) {
        // On the unrepaired production source this is a real second Intent.
        // Record both public submit refusals, then join the native store before
        // the intended assertion failure. No timeout constitutes the RED.
        let first_submit = f
            .store
            .submit_netconf_target_local(&first, &first_intent, caller())
            .await;
        let second_submit = match &second_admission {
            AuditAdmission::Applied(receipt) => Some(
                f.store
                    .submit_netconf_target_local(&second, receipt, caller())
                    .await,
            ),
            _ => None,
        };
        let ledger = f.store.read_audit_ledger().await.unwrap();
        let pending = ledger
            .operations
            .iter()
            .filter(|operation| !operation.terminal_recorded)
            .count();
        let cycle = pending == 2
            && matches!(&second_admission, AuditAdmission::Applied(receipt)
                if receipt.state() == AuditOperationState::Intent)
            && matches!(
                first_submit,
                AuditAdmission::Rejected(AuditAuthorityError::RecoveryRequired)
            )
            && matches!(
                second_submit,
                Some(AuditAdmission::Rejected(
                    AuditAuthorityError::RecoveryRequired
                ))
            );
        f.close().await;
        panic!(
            "TARGET_ADMISSION_ATOMIC_EXCLUSION: cycle={cycle}; second={second_admission:?}; pending={pending}; first_submit={first_submit:?}; second_submit={second_submit:?}"
        );
    }

    assert_eq!(
        f.rows().await,
        after_first,
        "TARGET_REFUSED_ADMISSION_LEAVES_LEDGER_HISTORY_AND_TARGETS_UNCHANGED"
    );
    assert!(f
        .store
        .lookup_audit_operation(second.handle(), caller())
        .await
        .unwrap()
        .is_none());
    let ledger = f.store.read_audit_ledger().await.unwrap();
    assert_eq!(
        ledger
            .operations
            .iter()
            .filter(|op| !op.terminal_recorded)
            .count(),
        1,
        "TARGET_ONE_PENDING_ORIGINAL"
    );

    // This executes the new guard while the original itself remains pending.
    let replay = f.replay_admit_in_apply(&first, 0x91).await;
    assert_eq!(replay.result, Ok(()), "TARGET_EXACT_INTENT_REPLAY");
    assert_eq!(f.rows().await, after_first, "TARGET_REPLAY_NO_NEW_INTENT");
    let completed = f.settle_cleanup(&first, &first_intent).await;
    assert!(completed.terminal_recorded());
    let recovered = f
        .store
        .recover_netconf_target(first.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered, first, "TARGET_WINNER_ORIGINAL_RECOVERY");

    // Removing the two-Intent cycle does not refresh a losing cleanup's frozen
    // lifecycle state. Preserve this refusal; never invent a new original.
    let after_completion = f.rows().await;
    assert!(matches!(
        f.store.admit_netconf_target_local(&second, caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(
        f.store
            .prepare_netconf_session_cleanup(&second_owner, &privacy(), &event(3), LIFETIME)
            .await,
        Err(AuditAuthorityError::BindingMismatch),
        "TARGET_LOSER_RETAINS_STALE_ORIGINAL"
    );
    assert_eq!(f.rows().await, after_completion);
    assert!(f.store.load_latest().await.unwrap().is_none());

    // A previously settled original is also replayable while different work
    // is pending; the exception is exact retained payload identity, not expiry
    // extension, fresh preparation, or an arbitrary existing request ID.
    let (_third_owner, third) = f.prepare_cleanup(4).await;
    let third_intent = applied(f.store.admit_netconf_target_local(&third, caller()).await);
    let before_replay = f.rows().await;
    let replay = f.replay_admit_in_apply(&first, 0x92).await;
    assert_eq!(replay.result, Ok(()), "TARGET_SETTLED_ORIGINAL_REPLAY");
    assert_eq!(f.rows().await, before_replay);
    assert_eq!(
        f.store
            .lookup_audit_operation(first.handle(), caller())
            .await
            .unwrap(),
        Some(completed)
    );
    let third_completed = f.settle_cleanup(&third, &third_intent).await;
    assert!(third_completed.terminal_recorded());
    let ledger = f.store.read_audit_ledger().await.unwrap();
    assert!(ledger
        .operations
        .iter()
        .all(|op| { op.terminal_recorded && !ledger.mutation_outcome_needs_checkpoint(op) }));
    f.close().await;
}
