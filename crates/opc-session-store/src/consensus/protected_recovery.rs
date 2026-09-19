//! Recovery-only retirement of protected external authority.
//!
//! An Async generation can lose Q1 while a provider retains its effect. A
//! complete, root-authorized inventory therefore closes the *whole* old fence
//! range, including unknown bindings. Neither a local snapshot nor an expired
//! lease supplies this authority. Ordinary session acknowledgements are
//! unchanged. See `docs/async-protected-recovery-908.md` for composition.

use super::{SessionConsensusIdentity, SessionConsensusNodeId};
use crate::fenced_mutation_roster::RosterAttestationTrustRootV1;
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use futures_util::FutureExt;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, OnceLock},
};
#[cfg(target_os = "linux")]
use tokio::sync::{watch, Mutex};

/// Maximum number of independently accountable external owners in one scope.
pub const MAX_PROTECTED_RECOVERY_OWNERS: usize = 32;

/// Fixed recovery failures. Provider details and identifiers are never diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtectedRecoveryError {
    /// The configured authority, signature or exact request binding differs.
    #[error("protected recovery authority rejected")]
    AuthorityRejected,
    /// A required owner has not completed durable retirement and reconciliation.
    #[error("protected recovery owner pending")]
    OwnerPending,
    /// The caller's original deadline elapsed. Accepted work remains owned.
    #[error("protected recovery deadline elapsed")]
    Deadline,
}

type Result<T> = std::result::Result<T, ProtectedRecoveryError>;
const REJECTED: ProtectedRecoveryError = ProtectedRecoveryError::AuthorityRejected;

// Fixed arrays keep the signature/key wire shape closed without unbounded
// byte vectors. The public API accepts standard compressed SEC1 keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    prefix: u8,
    x: [u8; 32],
}
impl Key {
    fn new(bytes: [u8; 33]) -> Result<Self> {
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| REJECTED)?;
        Ok(Self {
            prefix: bytes[0],
            x: bytes[1..].try_into().map_err(|_| REJECTED)?,
        })
    }
    fn bytes(&self) -> [u8; 33] {
        let mut bytes = [0; 33];
        bytes[0] = self.prefix;
        bytes[1..].copy_from_slice(&self.x);
        bytes
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "SignedWire", into = "SignedWire")]
struct Signed {
    r: [u8; 32],
    s: [u8; 32],
    verified: OnceLock<VerifiedSignature>,
}

// Repeated live frontier validation must not repeat every owner's elliptic
// curve computation. This positive result binds *all* verifier inputs, not
// just an owner or challenge. It grants no scope, membership or Raft authority.
// One fixed-size entry per signature stays bounded and may follow a clone.
#[derive(Clone, Copy, PartialEq, Eq)]
struct VerifiedSignature {
    key: [u8; 33],
    digest: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

// Keep the existing wire shape exact. Every cold or wire decode starts without
// a verification result; neither serialization nor equality includes it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedWire {
    r: [u8; 32],
    s: [u8; 32],
}
impl From<SignedWire> for Signed {
    fn from(value: SignedWire) -> Self {
        Self {
            r: value.r,
            s: value.s,
            verified: OnceLock::new(),
        }
    }
}
impl From<Signed> for SignedWire {
    fn from(value: Signed) -> Self {
        Self {
            r: value.r,
            s: value.s,
        }
    }
}
impl PartialEq for Signed {
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.s == other.s
    }
}
impl Eq for Signed {}

impl Signed {
    fn new(bytes: [u8; 64]) -> Self {
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        SignedWire { r, s }.into()
    }
    fn verify(&self, key: [u8; 33], digest: [u8; 32]) -> Result<()> {
        let input = VerifiedSignature {
            key,
            digest,
            r: self.r,
            s: self.s,
        };
        if self.verified.get() == Some(&input) {
            return Ok(());
        }
        let signature = Signature::from_scalars(self.r, self.s).map_err(|_| REJECTED)?;
        if signature.normalize_s() != signature {
            return Err(REJECTED);
        }
        VerifyingKey::from_sec1_bytes(&key)
            .map_err(|_| REJECTED)?
            .verify_prehash(&digest, &signature)
            .map_err(|_| REJECTED)?;
        // Concurrent first checks may duplicate computation but never publish
        // a failed result or replace another exact positive result.
        let _ = self.verified.set(input);
        Ok(())
    }
}

fn digest(domain: &[u8], value: &impl Serialize) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(opc_consensus::encode_bounded(value).map_err(|_| REJECTED)?);
    Ok(hash.finalize().into())
}

/// One independently durable owner of member effects and/or publications.
///
/// Provision the complete inventory once per configuration epoch. Owners
/// cover all replicas, pools and previously issued work, including work whose
/// admission is absent from every returned generation. Changing an inventory
/// requires a new configuration authority; it is not a recovery shortcut.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRecoveryOwner {
    id: [u8; 32],
    key: Key,
}
impl ProtectedRecoveryOwner {
    /// Validate a stable owner identity and its dedicated retirement signing key.
    pub fn new(id: [u8; 32], key: [u8; 33]) -> Result<Self> {
        if id == [0; 32] {
            return Err(REJECTED);
        }
        Ok(Self {
            id,
            key: Key::new(key)?,
        })
    }
    /// Identity for exact inventory matching, never for diagnostic labels.
    pub fn identity(&self) -> [u8; 32] {
        self.id
    }
}

/// Root-signed assertion of the complete external owner inventory.
///
/// The root signer must establish completeness from provider ownership, not
/// from the selected Async snapshot. Signing an empty or incomplete list is
/// not valid authority. Every voter must configure the same immutable list.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRecoveryInventory {
    identity: SessionConsensusIdentity,
    voters: [u8; 32],
    root: RosterAttestationTrustRootV1,
    #[serde(deserialize_with = "bounded_inventory")]
    owners: Vec<ProtectedRecoveryOwner>,
    signature: Signed,
}
impl ProtectedRecoveryInventory {
    /// Digest signed by the configured protected trust root (P-256 prehash,
    /// canonical low-S signature). The ordered inventory must be complete.
    pub fn signing_digest(
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
        root: &RosterAttestationTrustRootV1,
        owners: &[ProtectedRecoveryOwner],
    ) -> Result<[u8; 32]> {
        if !matches!(voters.len(), 3 | 5)
            || owners.is_empty()
            || owners.len() > MAX_PROTECTED_RECOVERY_OWNERS
        {
            return Err(REJECTED);
        }
        let value = Self {
            identity,
            voters: super::types::fenced_transition_voter_set_digest(identity, voters),
            root: root.clone(),
            owners: owners.to_vec(),
            signature: Signed::new([0; 64]),
        };
        value.unsigned_digest()
    }
    /// Verify and provision the root's exact inventory assertion.
    pub fn from_signed_parts(
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
        root: RosterAttestationTrustRootV1,
        owners: Vec<ProtectedRecoveryOwner>,
        signature: [u8; 64],
    ) -> Result<Self> {
        Self::signing_digest(identity, voters, &root, &owners)?;
        let value = Self {
            identity,
            voters: super::types::fenced_transition_voter_set_digest(identity, voters),
            root,
            owners,
            signature: Signed::new(signature),
        };
        value.verify()?;
        Ok(value)
    }
    fn unsigned_digest(&self) -> Result<[u8; 32]> {
        if self.owners.is_empty()
            || self.owners.len() > MAX_PROTECTED_RECOVERY_OWNERS
            || self.owners.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self
                .owners
                .iter()
                .any(|owner| owner.id == [0; 32] || Key::new(owner.key.bytes()).is_err())
        {
            return Err(REJECTED);
        }
        digest(
            b"opc-protected-async-owner-inventory-v1\0",
            &(
                self.identity,
                self.voters,
                self.root.fingerprint(),
                &self.owners,
            ),
        )
    }
    fn verify(&self) -> Result<()> {
        self.signature
            .verify(self.root.compressed_public_key(), self.unsigned_digest()?)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn matches(
        &self,
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
        root: &RosterAttestationTrustRootV1,
    ) -> Result<()> {
        self.verify()?;
        if self.identity != identity
            || self.root != *root
            || self.voters != super::types::fenced_transition_voter_set_digest(identity, voters)
        {
            return Err(REJECTED);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn commitment(&self) -> Result<[u8; 32]> {
        self.unsigned_digest()
    }
}

/// SDK-issued exact retirement request. No application constructor exists.
///
/// The commitment covers mode, epoch, trust root, complete provider inventory,
/// all retained voter roots/incarnations, full log cuts, completed generations,
/// selected history, and this recovery round. An earlier receipt cannot
/// authorize a later round, replacement owner or different selected state.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedRecoveryChallenge {
    inventory: ProtectedRecoveryInventory,
    era: u64,
    plan: [u8; 32],
    selection: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(remote = "ProtectedRecoveryChallenge", deny_unknown_fields)]
struct ChallengeWire {
    inventory: ProtectedRecoveryInventory,
    era: u64,
    plan: [u8; 32],
    selection: [u8; 32],
}
impl ProtectedRecoveryChallenge {
    /// Exact configuration whose external effects this owner must retire.
    pub fn identity(&self) -> SessionConsensusIdentity {
        self.inventory.identity
    }
    /// Permanent inclusive floor across *all* bindings in this configuration.
    pub fn retire_through(&self) -> u64 {
        (self.era - 1) * (1_u64 << 40) - 1
    }
    /// Exact challenge commitment to persist with the owner's completion.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        digest(
            b"opc-protected-async-scope-retired-v1\0",
            &(&self.inventory, self.era, self.plan, self.selection),
        )
    }
    /// Owner-specific digest to sign after persisting this challenge's
    /// completion. A signature cannot be relabelled as another owner's reply.
    pub fn owner_signing_digest(&self, owner: [u8; 32]) -> Result<[u8; 32]> {
        if !self.inventory.owners.iter().any(|entry| entry.id == owner) {
            return Err(REJECTED);
        }
        owner_digest(self.signing_digest()?, owner)
    }
    /// Verify and assemble this owner's durable completion receipt.
    pub fn receipt(
        &self,
        owner: [u8; 32],
        signature: [u8; 64],
    ) -> Result<ProtectedRecoveryReceipt> {
        let receipt = ProtectedRecoveryReceipt {
            owner,
            signature: Signed::new(signature),
        };
        receipt.verify(self)?;
        Ok(receipt)
    }
    fn validate(&self) -> Result<()> {
        self.inventory.verify()?;
        if self.era < 2
            || self.era > (i64::MAX as u64 >> 40)
            || self.plan == [0; 32]
            || self.selection == [0; 32]
        {
            return Err(REJECTED);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn new(
        inventory: ProtectedRecoveryInventory,
        selection: &super::recovery_types::Selection,
    ) -> Result<Self> {
        let value = Self {
            inventory,
            era: selection.round.era,
            plan: selection.round.digest().map_err(|_| REJECTED)?,
            selection: digest(b"opc-protected-async-selected-history-v1\0", selection)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Authenticated completion from one exact inventory owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRecoveryReceipt {
    owner: [u8; 32],
    signature: Signed,
}
impl ProtectedRecoveryReceipt {
    fn verify(&self, challenge: &ProtectedRecoveryChallenge) -> Result<()> {
        let owner = challenge
            .inventory
            .owners
            .iter()
            .find(|owner| owner.id == self.owner)
            .ok_or(REJECTED)?;
        self.signature.verify(
            owner.key.bytes(),
            challenge.owner_signing_digest(self.owner)?,
        )
    }
}

/// Complete verified retirement evidence carried by the committed boundary.
/// Ordinary mutation APIs cannot propose it. Cold readers verify it again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRecoveryProof {
    #[serde(with = "ChallengeWire")]
    challenge: ProtectedRecoveryChallenge,
    #[serde(deserialize_with = "bounded_inventory")]
    receipts: Vec<ProtectedRecoveryReceipt>,
}
impl ProtectedRecoveryProof {
    #[cfg(target_os = "linux")]
    pub(crate) fn verify(&self) -> Result<()> {
        let challenge = self.challenge.signing_digest()?;
        if self.receipts.len() != self.challenge.inventory.owners.len() {
            return Err(REJECTED);
        }
        for (receipt, owner) in self.receipts.iter().zip(&self.challenge.inventory.owners) {
            if receipt.owner != owner.id {
                return Err(REJECTED);
            }
            receipt
                .signature
                .verify(owner.key.bytes(), owner_digest(challenge, receipt.owner)?)?;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn matches(
        &self,
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
        root: &RosterAttestationTrustRootV1,
        era: u64,
        plan: [u8; 32],
    ) -> Result<()> {
        self.verify()?;
        self.challenge.inventory.matches(identity, voters, root)?;
        if self.challenge.era != era || self.challenge.plan != plan {
            return Err(REJECTED);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn inventory(&self) -> Result<[u8; 32]> {
        self.challenge.inventory.commitment()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn matches_selection(&self, selection: &super::recovery_types::Selection) -> bool {
        ProtectedRecoveryChallenge::new(self.challenge.inventory.clone(), selection)
            .is_ok_and(|expected| expected == self.challenge)
    }
}

/// Privileged owner of an entire external provider scope, not a single call.
///
/// Before returning a signed receipt, atomically and durably advance a global
/// floor which every member *and publication* effect checks across processes,
/// pools and different admissions, including absent journal bindings. Join or
/// irrevocably fence every already accepted lower-range effect before replying.
/// Preserve immutable outcome evidence and responsibility for orphan effects:
/// a lost Q1 or `NotFound` never means `NotApplied`. Previously completed effects
/// may remain for exact higher-fence adoption; any orphan cleanup must be
/// completed or permanently fenced from successor resources before this receipt.
///
/// Retirement is idempotent, monotonic and crash durable. A delayed older
/// request cannot lower the floor or mutate resources in a newer range. Work
/// accepted before cancellation remains this owner's responsibility. A backend
/// lacking these capabilities must return `OwnerPending`, never sign readiness.
/// The key belongs to this provider owner, not to the caller requesting recovery.
#[async_trait]
pub trait ProtectedAsyncRecoveryOwner: Send + Sync + 'static {
    /// Exact stable identity from the root-authorized complete inventory.
    fn identity(&self) -> [u8; 32];
    /// Retire the complete old range, retaining responsibility across cancellation.
    async fn retire(
        &self,
        challenge: &ProtectedRecoveryChallenge,
    ) -> Result<ProtectedRecoveryReceipt>;
}

#[cfg(target_os = "linux")]
type Completion = watch::Receiver<Option<Result<ProtectedRecoveryProof>>>;
#[cfg(target_os = "linux")]
struct Accepted {
    challenge: ProtectedRecoveryChallenge,
    completion: Completion,
}

/// SDK coordinator for a fixed complete set of external recovery owners.
///
/// Accepted retirement runs under an owned supervisor after a caller times out
/// or disappears. At most one challenge is in flight; replacement waits for its
/// responsibility to complete. Retrying the exact challenge shares its result.
pub struct ProtectedAsyncRecovery {
    #[cfg(target_os = "linux")]
    inventory: ProtectedRecoveryInventory,
    #[cfg(target_os = "linux")]
    owners: Vec<Arc<dyn ProtectedAsyncRecoveryOwner>>,
    #[cfg(target_os = "linux")]
    accepted: Mutex<Option<Accepted>>,
}
impl ProtectedAsyncRecovery {
    /// Match every independently provisioned owner exactly once to the signed
    /// inventory. A missing, duplicate or additional owner is rejected.
    pub fn new(
        inventory: ProtectedRecoveryInventory,
        owners: Vec<Arc<dyn ProtectedAsyncRecoveryOwner>>,
    ) -> Result<Self> {
        inventory.verify()?;
        if owners.len() != inventory.owners.len()
            || owners
                .iter()
                .zip(&inventory.owners)
                .any(|(owner, provisioned)| owner.identity() != provisioned.id)
        {
            return Err(REJECTED);
        }
        Ok(Self {
            #[cfg(target_os = "linux")]
            inventory,
            #[cfg(target_os = "linux")]
            owners,
            #[cfg(target_os = "linux")]
            accepted: Mutex::new(None),
        })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn inventory(&self) -> &ProtectedRecoveryInventory {
        &self.inventory
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn retire_before(
        &self,
        selection: &super::recovery_types::Selection,
        deadline: tokio::time::Instant,
    ) -> Result<ProtectedRecoveryProof> {
        if tokio::time::Instant::now() >= deadline {
            return Err(ProtectedRecoveryError::Deadline);
        }
        let challenge = ProtectedRecoveryChallenge::new(self.inventory.clone(), selection)?;
        loop {
            let mut accepted = tokio::time::timeout_at(deadline, self.accepted.lock())
                .await
                .map_err(|_| ProtectedRecoveryError::Deadline)?;
            if tokio::time::Instant::now() >= deadline {
                return Err(ProtectedRecoveryError::Deadline);
            }
            if let Some(prior) = accepted.as_ref() {
                let mut completion = prior.completion.clone();
                let retryable = matches!(
                    *completion.borrow(),
                    Some(Err(ProtectedRecoveryError::OwnerPending))
                );
                if prior.challenge == challenge && !retryable {
                    drop(accepted);
                    return wait(&mut completion, deadline).await;
                }
                if completion.borrow().is_none() {
                    drop(accepted);
                    if matches!(
                        wait(&mut completion, deadline).await,
                        Err(ProtectedRecoveryError::Deadline)
                    ) {
                        return Err(ProtectedRecoveryError::Deadline);
                    }
                    continue;
                }
            }
            let (send, mut completion) = watch::channel(None);
            *accepted = Some(Accepted {
                challenge: challenge.clone(),
                completion: completion.clone(),
            });
            let owners = self.owners.clone();
            let owned = challenge.clone();
            tokio::spawn(async move {
                // join_all retains every accepted owner even if another owner
                // fails. No early-return cancellation can abandon its effects.
                let results = futures_util::future::join_all(owners.iter().map(|owner| async {
                    // A panicking adapter cannot cancel another owner's
                    // accepted effect. Its own durable responsibility remains
                    // part of the provider contract, and prevents readiness.
                    std::panic::AssertUnwindSafe(owner.retire(&owned))
                        .catch_unwind()
                        .await
                        .unwrap_or(Err(ProtectedRecoveryError::OwnerPending))
                }))
                .await;
                let result = (|| {
                    let receipts = results.into_iter().collect::<Result<Vec<_>>>()?;
                    let proof = ProtectedRecoveryProof {
                        challenge: owned,
                        receipts,
                    };
                    proof.verify()?;
                    Ok(proof)
                })();
                let _ = send.send(Some(result));
            });
            drop(accepted);
            return wait(&mut completion, deadline).await;
        }
    }
}

fn bounded_inventory<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded protected recovery inventory")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut access: A,
        ) -> std::result::Result<Vec<T>, A::Error> {
            if access
                .size_hint()
                .is_some_and(|size| size > MAX_PROTECTED_RECOVERY_OWNERS)
            {
                return Err(serde::de::Error::custom(
                    "protected recovery inventory exceeds bound",
                ));
            }
            let mut values = Vec::new();
            while let Some(value) = access.next_element()? {
                if values.len() == MAX_PROTECTED_RECOVERY_OWNERS {
                    return Err(serde::de::Error::custom(
                        "protected recovery inventory exceeds bound",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded(std::marker::PhantomData))
}

#[cfg(target_os = "linux")]
async fn wait(
    completion: &mut Completion,
    deadline: tokio::time::Instant,
) -> Result<ProtectedRecoveryProof> {
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ProtectedRecoveryError::Deadline);
        }
        if let Some(result) = completion.borrow_and_update().clone() {
            return result;
        }
        tokio::time::timeout_at(deadline, completion.changed())
            .await
            .map_err(|_| ProtectedRecoveryError::Deadline)?
            .map_err(|_| ProtectedRecoveryError::OwnerPending)?;
    }
}

fn owner_digest(challenge: [u8; 32], owner: [u8; 32]) -> Result<[u8; 32]> {
    digest(
        b"opc-protected-async-owner-retired-v1\0",
        &(challenge, owner),
    )
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+};
}
redacted!(
    ProtectedRecoveryOwner,
    ProtectedRecoveryInventory,
    ProtectedRecoveryChallenge,
    ProtectedRecoveryReceipt,
    ProtectedRecoveryProof,
    ProtectedAsyncRecovery
);

#[cfg(all(test, target_os = "linux"))]
mod tests;
