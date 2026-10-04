//! Recovery capability controls over the real native store and Raft transport
//! fixture. Multiprocess /3 provider effects are qualified separately.
use super::*;
use crate::consensus::protected_recovery::{
    ProtectedAsyncRecovery, ProtectedAsyncRecoveryOwner, ProtectedRecoveryChallenge,
    ProtectedRecoveryError, ProtectedRecoveryInventory, ProtectedRecoveryOwner,
    ProtectedRecoveryReceipt,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes((&[byte; 32]).into()).unwrap()
}
fn public(byte: u8) -> [u8; 33] {
    key(byte)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn sign(byte: u8, digest: [u8; 32]) -> [u8; 64] {
    let signature: Signature = key(byte).sign_prehash(&digest).unwrap();
    signature.normalize_s().to_bytes().into()
}

pub(super) struct Owner {
    path: std::path::PathBuf,
    pending: AtomicBool,
    stale: Mutex<Option<ProtectedRecoveryReceipt>>,
    replies: Mutex<Vec<ProtectedRecoveryReceipt>>,
    calls: AtomicU64,
    delay_millis: AtomicU64,
}
impl Owner {
    fn new(path: std::path::PathBuf) -> Arc<Self> {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE scope(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor INTEGER NOT NULL,completion BLOB); INSERT INTO scope VALUES(1,0,NULL);").unwrap();
        Arc::new(Self {
            path,
            pending: AtomicBool::new(false),
            stale: Mutex::new(None),
            replies: Mutex::new(Vec::new()),
            calls: AtomicU64::new(0),
            delay_millis: AtomicU64::new(0),
        })
    }
    fn floor(&self) -> u64 {
        rusqlite::Connection::open(&self.path)
            .unwrap()
            .query_row("SELECT floor FROM scope", [], |r| r.get(0))
            .unwrap()
    }
}
impl Owner {
    async fn retire_as(
        &self,
        challenge: &ProtectedRecoveryChallenge,
        id: u8,
    ) -> Result<ProtectedRecoveryReceipt, ProtectedRecoveryError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        tokio::time::sleep(Duration::from_millis(
            self.delay_millis.load(Ordering::Acquire),
        ))
        .await;
        if self.pending.load(Ordering::Acquire) {
            return Err(ProtectedRecoveryError::OwnerPending);
        }
        if let Some(stale) = self.stale.lock().unwrap().clone() {
            return Ok(stale);
        }
        let mut connection = rusqlite::Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|_| ProtectedRecoveryError::OwnerPending)?;
        connection
            .execute_batch("PRAGMA synchronous=FULL;")
            .unwrap();
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let floor: u64 = tx
            .query_row("SELECT floor FROM scope", [], |r| r.get(0))
            .unwrap();
        if floor > challenge.retire_through() {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        tx.execute(
            "UPDATE scope SET floor=?1,completion=?2",
            rusqlite::params![
                challenge.retire_through(),
                challenge.signing_digest()?.as_slice()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        let reply = challenge.receipt(
            [id; 32],
            sign(0x40 + id, challenge.owner_signing_digest([id; 32])?),
        )?;
        self.replies.lock().unwrap().push(reply.clone());
        Ok(reply)
    }
}

struct OwnerSlot {
    owner: Arc<Owner>,
    id: u8,
}
#[async_trait]
impl ProtectedAsyncRecoveryOwner for OwnerSlot {
    fn identity(&self) -> [u8; 32] {
        [self.id; 32]
    }
    async fn retire(
        &self,
        challenge: &ProtectedRecoveryChallenge,
    ) -> Result<ProtectedRecoveryReceipt, ProtectedRecoveryError> {
        self.owner.retire_as(challenge, self.id).await
    }
}

impl Fleet {
    pub(super) fn with_protected_recovery(voters: usize) -> Self {
        let root = crate::RosterAttestationTrustRootV1::new([0x91; 32], public(0x31)).unwrap();
        let mut fleet = Self::with_roster_root(voters, Some(root));
        fleet.protected_owner = Some(Owner::new(fleet.directory.path().join("provider.db")));
        fleet
    }
    pub(super) fn protected_authority(
        &self,
        store: &ConsensusSessionStore,
    ) -> Arc<ProtectedAsyncRecovery> {
        let root = store
            .inner
            .roster_attestation_trust_root
            .as_ref()
            .unwrap()
            .clone();
        let owners = (1..=self.protected_owner_count)
            .map(|id| ProtectedRecoveryOwner::new([id; 32], public(0x40 + id)).unwrap())
            .collect::<Vec<_>>();
        let signature = sign(
            0x31,
            ProtectedRecoveryInventory::signing_digest(
                store.inner.storage_identity,
                &store.inner.bootstrap_members,
                &root,
                &owners,
            )
            .unwrap(),
        );
        Arc::new(
            ProtectedAsyncRecovery::new(
                ProtectedRecoveryInventory::from_signed_parts(
                    store.inner.storage_identity,
                    &store.inner.bootstrap_members,
                    root,
                    owners,
                    signature,
                )
                .unwrap(),
                (1..=self.protected_owner_count)
                    .map(|id| {
                        Arc::new(OwnerSlot {
                            owner: self.protected_owner.as_ref().unwrap().clone(),
                            id,
                        }) as Arc<dyn ProtectedAsyncRecoveryOwner>
                    })
                    .collect(),
            )
            .unwrap(),
        )
    }
}

async fn reach_owner(fleet: &Fleet, owner: &Owner) {
    use super::majority_protocol::{control, index, prepare};
    use crate::consensus::recovery_types::Action;
    let calls = owner.calls.load(Ordering::Acquire);
    let selection = prepare(fleet).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(control(
                fleet,
                index(fleet, selection.leader),
                Action::Commit(selection.clone())
            )
            .await
            .is_err());
            if owner.calls.load(Ordering::Acquire) > calls {
                break;
            }
        }
    })
    .await
    .expect("actual selected leader reaches provider within recovery bound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_missing_owner_withholds_authority_then_retries_without_reset() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::with_protected_recovery(3);
    let owner = fleet.protected_owner.as_ref().unwrap().clone();
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        for store in fleet.stores.iter().flatten() {
            assert_eq!(
                store.configure_protected_async_recovery(fleet.protected_authority(store)),
                Err(ProtectedRecoveryError::AuthorityRejected),
                "cannot replace ownership at an await boundary"
            );
        }
        super::majority_protocol::cold(&mut fleet).await;
        owner.pending.store(true, Ordering::Release);
        reach_owner(&fleet, &owner).await;
        assert_eq!(owner.floor(), 0);
        assert!(fleet
            .stores
            .iter()
            .flatten()
            .all(|store| !store.inner.persistence_protocol.is_active()));
        assert!(fleet
            .stores
            .iter()
            .flatten()
            .any(|store| store.persistence_health().recovery
                == Some(SessionAsyncRecoveryState::AwaitingProtectedRetirement)));
        owner.pending.store(false, Ordering::Release);
        super::majority_protocol::recover(&fleet).await;
        assert!(owner.floor() > 0);
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 132, &provider()).await;
        let lease = store
            .acquire(
                request.lease().key(),
                OwnerId::new("protected-successor").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(lease.fence().get() > owner.floor());
        store.release(lease).await.unwrap();
        // Reopening a completed protected boundary must validate its proof,
        // then perform ordinary sequential catch-up without retiring again.
        let floor = owner.floor();
        let target = (fleet.leader() + 1) % 3;
        fleet.close(target).await;
        fleet
            .open(target, SessionPersistenceMode::Async)
            .await
            .unwrap();
        super::majority_protocol::recover(&fleet).await;
        assert_eq!(owner.floor(), floor);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_delayed_old_provider_receipt_cannot_authorize_next_round() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::with_protected_recovery(3);
    let owner = fleet.protected_owner.as_ref().unwrap().clone();
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        super::majority_protocol::cold(&mut fleet).await;
        super::majority_protocol::recover(&fleet).await;
        let old = owner.replies.lock().unwrap().last().unwrap().clone();
        *owner.stale.lock().unwrap() = Some(old);
        super::majority_protocol::cold(&mut fleet).await;
        reach_owner(&fleet, &owner).await;
        assert!(fleet
            .stores
            .iter()
            .flatten()
            .all(|store| !store.inner.persistence_protocol.is_active()));
        assert!(fleet
            .stores
            .iter()
            .flatten()
            .any(|store| store.persistence_health().recovery
                == Some(SessionAsyncRecoveryState::ProtectedAuthorityRejected)));
        *owner.stale.lock().unwrap() = None;
        // Rejection stays attached to its exact round. Ordinary initialization
        // selects fresh authority after the provider repairs its reply; neither
        // storage nor any voter process needs replacement.
        super::majority_protocol::recover(&fleet).await;
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 133, &provider()).await;
        let successor = store
            .acquire(
                request.lease().key(),
                OwnerId::new("protected-next-round").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(successor.fence().get() > owner.floor());
        store.delete_fenced(&successor).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_slow_owner_completion_resumes_same_committed_election() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::with_protected_recovery(3);
    let owner = fleet.protected_owner.as_ref().unwrap().clone();
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        super::majority_protocol::cold(&mut fleet).await;
        // Provider disk/reconciliation can outlive one existing 800ms RPC
        // deadline. Repeated initialization must join that exact accepted work
        // instead of making a new challenge whose work times out in turn.
        owner.delay_millis.store(1_600, Ordering::Release);
        super::majority_protocol::recover(&fleet).await;
        assert_eq!(owner.calls.load(Ordering::Acquire), 1);
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 134, &provider()).await;
        let successor = store
            .acquire(
                request.lease().key(),
                OwnerId::new("slow-provider-successor").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(successor.fence().get() > owner.floor());
        store.delete_fenced(&successor).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_maximum_owner_inventory_recovers_and_reopens() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::with_protected_recovery(3);
    fleet.protected_owner_count =
        crate::consensus::protected_recovery::MAX_PROTECTED_RECOVERY_OWNERS as u8;
    let owner = fleet.protected_owner.as_ref().unwrap().clone();
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        super::majority_protocol::cold(&mut fleet).await;
        super::majority_protocol::recover(&fleet).await;
        assert_eq!(
            owner.calls.load(Ordering::Acquire),
            u64::from(fleet.protected_owner_count)
        );
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 135, &provider()).await;
        let successor = store
            .acquire(
                request.lease().key(),
                OwnerId::new("maximum-inventory-successor").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        store.delete_fenced(&successor).await.unwrap();
        let target = (fleet.leader() + 1) % 3;
        fleet.close(target).await;
        fleet
            .open(target, SessionPersistenceMode::Async)
            .await
            .unwrap();
        super::majority_protocol::recover(&fleet).await;
        assert_eq!(
            owner.calls.load(Ordering::Acquire),
            u64::from(fleet.protected_owner_count)
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
