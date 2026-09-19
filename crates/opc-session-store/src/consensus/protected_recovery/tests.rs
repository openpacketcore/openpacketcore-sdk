//! Crypto and supervisor controls. These deliberately use a signing test
//! double; real persistence/recovery qualification is the multiprocess suite.
use super::*;
use crate::consensus::{
    recovery_types::{Capability, Round, Selection, Status},
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusRequestId,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::Notify;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes((&[n; 32]).into()).unwrap()
}
fn public(n: u8) -> [u8; 33] {
    key(n)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn sign(n: u8, digest: [u8; 32]) -> [u8; 64] {
    let signature: Signature = key(n).sign_prehash(&digest).unwrap();
    signature.normalize_s().to_bytes().into()
}

pub(crate) fn fixture() -> (ProtectedRecoveryInventory, Selection) {
    let identity = SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("protected-recovery-fixture").unwrap(),
        SessionConsensusConfigurationId::from_bytes([0x92; 32]),
        SessionConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let voters: BTreeSet<_> = [7, 8, 9]
        .map(|n| SessionConsensusNodeId::new(n).unwrap())
        .into();
    let root = RosterAttestationTrustRootV1::new([0x91; 32], public(0x31)).unwrap();
    let owners = vec![
        ProtectedRecoveryOwner::new([1; 32], public(0x41)).unwrap(),
        ProtectedRecoveryOwner::new([2; 32], public(0x42)).unwrap(),
    ];
    let signature = sign(
        0x31,
        ProtectedRecoveryInventory::signing_digest(identity, &voters, &root, &owners).unwrap(),
    );
    let inventory =
        ProtectedRecoveryInventory::from_signed_parts(identity, &voters, root, owners, signature)
            .unwrap();
    let participants = voters
        .iter()
        .copied()
        .map(|node| {
            (
                node,
                Status {
                    node,
                    boot: SessionConsensusRequestId::new(),
                    root: [0x93; 32],
                    era: 1,
                    promise: [0; 32],
                    active: false,
                    recovering: false,
                    capability: Capability::Reserved,
                    protected_inventory: Some(inventory.commitment().unwrap()),
                },
            )
        })
        .collect();
    // This is a challenge-binding fixture, never sent to a Raft engine. Real
    // selections additionally validate every prepared full vote/log/generation.
    let selection = Selection {
        round: Round {
            identity,
            voters: super::super::types::fenced_transition_voter_set_digest(identity, &voters),
            era: 2,
            nonce: SessionConsensusRequestId::new(),
            participants,
        },
        prepared: BTreeMap::new(),
        leader: *voters.first().unwrap(),
    };
    (inventory, selection)
}

fn proof(inventory: ProtectedRecoveryInventory, selection: &Selection) -> ProtectedRecoveryProof {
    let challenge = ProtectedRecoveryChallenge::new(inventory, selection).unwrap();
    let receipts = challenge
        .inventory
        .owners
        .iter()
        .map(|owner| {
            challenge
                .receipt(
                    owner.id,
                    sign(
                        0x40 + owner.id[0],
                        challenge.owner_signing_digest(owner.id).unwrap(),
                    ),
                )
                .unwrap()
        })
        .collect();
    ProtectedRecoveryProof {
        challenge,
        receipts,
    }
}

#[test]
fn complete_proof_binds_every_owner_and_exact_scope_round_and_selection() {
    let (inventory, selection) = fixture();
    let proof = proof(inventory.clone(), &selection);
    assert!(proof.verify().is_ok());
    assert!(proof.matches_selection(&selection));
    assert_eq!(proof.challenge.retire_through(), (1_u64 << 40) - 1);
    let voters = selection.round.participants.keys().copied().collect();
    assert!(proof
        .matches(
            inventory.identity,
            &voters,
            &inventory.root,
            2,
            selection.round.digest().unwrap()
        )
        .is_ok());
    let mut changed = selection.clone();
    changed.round.nonce = SessionConsensusRequestId::new();
    assert!(!proof.matches_selection(&changed));
    changed = selection.clone();
    changed.leader = SessionConsensusNodeId::new(8).unwrap();
    assert!(!proof.matches_selection(&changed));
    changed = selection.clone();
    changed.round.participants.values_mut().next().unwrap().root[0] ^= 1;
    assert!(!proof.matches_selection(&changed));
    changed = selection.clone();
    changed.round.participants.values_mut().next().unwrap().boot = SessionConsensusRequestId::new();
    assert!(!proof.matches_selection(&changed));
    assert!(proof
        .matches(
            inventory.identity,
            &voters,
            &inventory.root,
            3,
            selection.round.digest().unwrap()
        )
        .is_err());
    let foreign = RosterAttestationTrustRootV1::new([0x91; 32], public(0x32)).unwrap();
    assert!(proof
        .matches(
            inventory.identity,
            &voters,
            &foreign,
            2,
            selection.round.digest().unwrap()
        )
        .is_err());
    let mut incomplete = proof.clone();
    incomplete.receipts.pop();
    assert!(incomplete.verify().is_err());
    let mut duplicate = proof.clone();
    duplicate.receipts[1] = duplicate.receipts[0].clone();
    assert!(duplicate.verify().is_err());
    let mut delayed = proof.clone();
    delayed.challenge.era += 1;
    assert!(delayed.verify().is_err());
    let mut corrupt = proof;
    corrupt.receipts[0].signature.r[0] ^= 1;
    assert!(corrupt.verify().is_err());
}

#[test]
fn unsigned_missing_duplicate_foreign_inventory_and_oversized_carriers_are_rejected() {
    let (inventory, selection) = fixture();
    let mut changed = inventory.clone();
    changed.owners.clear();
    assert!(changed.verify().is_err());
    changed = inventory.clone();
    changed.owners[1] = changed.owners[0].clone();
    assert!(changed.verify().is_err());
    changed = inventory.clone();
    changed.identity = SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("protected-recovery-fixture").unwrap(),
        SessionConsensusConfigurationId::from_bytes([0x92; 32]),
        SessionConsensusConfigurationEpoch::new(2).unwrap(),
    );
    assert!(changed.verify().is_err());
    changed = inventory.clone();
    changed.signature.r[1] ^= 1;
    assert!(changed.verify().is_err());
    let proof = proof(inventory, &selection);
    let bytes = serde_json::to_vec(&proof).unwrap();
    let decoded: ProtectedRecoveryProof = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.verify().is_ok());
    let mut json = serde_json::to_value(&proof).unwrap();
    json["receipts"] = serde_json::Value::Array(vec![
        json["receipts"][0].clone();
        MAX_PROTECTED_RECOVERY_OWNERS + 1
    ]);
    assert!(serde_json::from_value::<ProtectedRecoveryProof>(json).is_err());
}

struct HeldOwner {
    id: u8,
    calls: AtomicU64,
    holding: AtomicBool,
    pending: AtomicBool,
    panicking: AtomicBool,
    entered: Notify,
    release: Notify,
}
impl HeldOwner {
    fn new(id: u8) -> Arc<Self> {
        Arc::new(Self {
            id,
            calls: AtomicU64::new(0),
            holding: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            panicking: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
}
#[async_trait]
impl ProtectedAsyncRecoveryOwner for HeldOwner {
    fn identity(&self) -> [u8; 32] {
        [self.id; 32]
    }
    async fn retire(
        &self,
        challenge: &ProtectedRecoveryChallenge,
    ) -> Result<ProtectedRecoveryReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        if self.holding.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        if self.pending.load(Ordering::SeqCst) {
            return Err(ProtectedRecoveryError::OwnerPending);
        }
        assert!(
            !self.panicking.load(Ordering::SeqCst),
            "synthetic adapter panic"
        );
        challenge.receipt(
            [self.id; 32],
            sign(
                0x40 + self.id,
                challenge.owner_signing_digest([self.id; 32])?,
            ),
        )
    }
}
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn cancellation_deadline_and_replacement_join_all_accepted_owners() {
    let (inventory, selection) = fixture();
    let first = HeldOwner::new(1);
    let second = HeldOwner::new(2);
    first.pending.store(true, Ordering::SeqCst);
    second.holding.store(true, Ordering::SeqCst);
    let recovery = Arc::new(
        ProtectedAsyncRecovery::new(inventory, vec![first.clone(), second.clone()]).unwrap(),
    );
    let caller = {
        let recovery = recovery.clone();
        let selection = selection.clone();
        tokio::spawn(async move { recovery.retire_before(&selection, deadline()).await })
    };
    tokio::time::timeout_at(deadline(), second.entered.notified())
        .await
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let mut next = selection.clone();
    next.round.era += 1;
    let result = recovery
        .retire_before(
            &next,
            tokio::time::Instant::now() + Duration::from_millis(20),
        )
        .await;
    assert_eq!(result, Err(ProtectedRecoveryError::Deadline));
    assert_eq!(
        second.calls.load(Ordering::SeqCst),
        1,
        "replacement must retain old accepted work"
    );
    first.pending.store(false, Ordering::SeqCst);
    second.holding.store(false, Ordering::SeqCst);
    second.release.notify_one();
    let proof = recovery.retire_before(&next, deadline()).await.unwrap();
    assert!(proof.matches_selection(&next));
    assert_eq!(second.calls.load(Ordering::SeqCst), 2);
    let duplicate = recovery.retire_before(&next, deadline()).await.unwrap();
    assert_eq!(proof, duplicate);
    assert_eq!(
        second.calls.load(Ordering::SeqCst),
        2,
        "duplicate must reuse exact owned completion"
    );
}

#[tokio::test]
async fn retry_pending_owner_does_not_reuse_old_or_partial_receipts() {
    let (inventory, selection) = fixture();
    let first = HeldOwner::new(1);
    let second = HeldOwner::new(2);
    second.pending.store(true, Ordering::SeqCst);
    let recovery =
        ProtectedAsyncRecovery::new(inventory, vec![first.clone(), second.clone()]).unwrap();
    assert_eq!(
        recovery.retire_before(&selection, deadline()).await,
        Err(ProtectedRecoveryError::OwnerPending)
    );
    second.pending.store(false, Ordering::SeqCst);
    assert!(recovery
        .retire_before(&selection, deadline())
        .await
        .unwrap()
        .matches_selection(&selection));
    assert_eq!(first.calls.load(Ordering::SeqCst), 2);
    assert_eq!(second.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn panicking_owner_cannot_cancel_another_accepted_owner() {
    let (inventory, selection) = fixture();
    let first = HeldOwner::new(1);
    let second = HeldOwner::new(2);
    first.panicking.store(true, Ordering::SeqCst);
    second.holding.store(true, Ordering::SeqCst);
    let recovery = Arc::new(
        ProtectedAsyncRecovery::new(inventory, vec![first.clone(), second.clone()]).unwrap(),
    );
    let caller = {
        let recovery = recovery.clone();
        let selection = selection.clone();
        tokio::spawn(async move { recovery.retire_before(&selection, deadline()).await })
    };
    tokio::time::timeout_at(deadline(), second.entered.notified())
        .await
        .unwrap();
    assert!(
        !caller.is_finished(),
        "all accepted responsibility must be joined"
    );
    second.holding.store(false, Ordering::SeqCst);
    second.release.notify_one();
    assert_eq!(
        caller.await.unwrap(),
        Err(ProtectedRecoveryError::OwnerPending)
    );
    first.panicking.store(false, Ordering::SeqCst);
    assert!(recovery.retire_before(&selection, deadline()).await.is_ok());
    assert_eq!(second.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn expired_deadline_cannot_accept_work_or_reuse_cached_authority() {
    let (inventory, selection) = fixture();
    let first = HeldOwner::new(1);
    let second = HeldOwner::new(2);
    let recovery =
        ProtectedAsyncRecovery::new(inventory, vec![first.clone(), second.clone()]).unwrap();
    let expired = tokio::time::Instant::now();
    assert_eq!(
        recovery.retire_before(&selection, expired).await,
        Err(ProtectedRecoveryError::Deadline)
    );
    assert_eq!(first.calls.load(Ordering::SeqCst), 0);
    assert!(recovery.retire_before(&selection, deadline()).await.is_ok());
    assert_eq!(
        recovery.retire_before(&selection, expired).await,
        Err(ProtectedRecoveryError::Deadline)
    );
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn owner_receipts_cannot_be_relabelled_even_when_keys_are_shared() {
    let (mut inventory, selection) = fixture();
    inventory.owners[1].key = inventory.owners[0].key.clone();
    inventory.signature = Signed::new(sign(0x31, inventory.unsigned_digest().unwrap()));
    let challenge = ProtectedRecoveryChallenge::new(inventory, &selection).unwrap();
    let first = challenge
        .receipt(
            [1; 32],
            sign(0x41, challenge.owner_signing_digest([1; 32]).unwrap()),
        )
        .unwrap();
    let mut relabelled = first.clone();
    relabelled.owner = [2; 32];
    assert!(relabelled.verify(&challenge).is_err());
    let second = challenge
        .receipt(
            [2; 32],
            sign(0x41, challenge.owner_signing_digest([2; 32]).unwrap()),
        )
        .unwrap();
    assert!(ProtectedRecoveryProof {
        challenge,
        receipts: vec![first, second]
    }
    .verify()
    .is_ok());
}

#[test]
fn maximum_inventory_fits_the_bounded_snapshot_and_rejects_oversized_storage() {
    use crate::consensus::native::async_recovery::Boundary;
    use opc_consensus::engine::{CommittedLeaderId, LogId};
    let (mut inventory, mut selection) = fixture();
    inventory.owners = (1..=MAX_PROTECTED_RECOVERY_OWNERS as u8)
        .map(|id| ProtectedRecoveryOwner::new([id; 32], public(0x40 + id)).unwrap())
        .collect();
    inventory.signature = Signed::new(sign(0x31, inventory.unsigned_digest().unwrap()));
    for participant in selection.round.participants.values_mut() {
        participant.protected_inventory = Some(inventory.commitment().unwrap());
    }
    let proof = proof(inventory.clone(), &selection);
    let plan = selection.round.digest().unwrap();
    let mut boundary = Boundary::from_entry(
        2,
        plan,
        LogId::new(CommittedLeaderId::new(1_u64 << 40, selection.leader), 1),
    );
    boundary.protected = Some(Box::new(proof));
    boundary.validate().unwrap();
    let voters = selection.round.participants.keys().copied().collect();
    boundary
        .validate_protected_scope(inventory.identity, &voters, Some(&inventory.root))
        .unwrap();
    let bytes = serde_json::to_vec(&boundary).unwrap();
    assert!(
        bytes.len() < 48 * 1024,
        "leave room for the remaining native header fields"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded-recovery.sqlite");
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA synchronous=FULL;").unwrap();
    let tx = conn.transaction().unwrap();
    crate::sqlite::consensus::async_recovery::write(&tx, Some(&boundary)).unwrap();
    tx.commit().unwrap();
    drop(conn);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let reopened = crate::sqlite::consensus::async_recovery::read(&conn)
        .unwrap()
        .unwrap();
    assert!(reopened == boundary);
    reopened
        .validate_protected_scope(inventory.identity, &voters, Some(&inventory.root))
        .unwrap();
    assert!(reopened
        .validate_protected_scope(inventory.identity, &voters, None)
        .is_err());
    conn.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE consensus_async_recovery SET boundary=zeroblob(65537);").unwrap();
    assert!(crate::sqlite::consensus::async_recovery::read(&conn).is_err());
}
