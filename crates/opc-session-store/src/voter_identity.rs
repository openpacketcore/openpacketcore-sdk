//! Volume-held incarnation keys for the explicit enrolled voter profile.
//!
//! Private keys are generated only by enrollment. They are never exported in a
//! Raft snapshot, accepted from the caller, or recovered from another voter.

use std::sync::Arc;

use opc_consensus::voter_slots::{
    voter_candidate_possession_signing_input, voter_enrollment_possession_signing_input,
    voter_rpc_possession_signing_input, SlotId, VoterCandidateChallenge, VoterEnrollmentChallenge,
    VoterIncarnation, VoterReplacementError, VoterRpcChallenge, VoterSlotIdentity,
};
use opc_consensus::ConsensusClusterId;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ConsensusSessionStoreOpenError;

const MAGIC: &[u8; 16] = b"OPC-VOTER-KEY-V1";
pub(crate) const RECORD_BYTES: usize = 154;

/// Signer backed by one SDK-enrolled volume's incarnation key.
///
/// Obtain this from [`crate::SqliteSessionBackend::enroll_voter_identity`] or
/// [`crate::SqliteSessionBackend::voter_identity_signer`]. Public values can be
/// shared with the manifest publisher; the private key has no export method.
/// Dropping the last signer zeroizes its private key. A signer is not voting
/// authority: every RPC still passes the store's current slot-table gate.
#[derive(Clone)]
pub struct VoterIdentitySigner {
    cluster: ConsensusClusterId,
    identity: VoterSlotIdentity,
    key: Arc<SigningKey>,
}

impl std::fmt::Debug for VoterIdentitySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterIdentitySigner")
            .finish_non_exhaustive()
    }
}

impl VoterIdentitySigner {
    /// Installation bound when this volume was enrolled.
    pub fn cluster_instance(&self) -> ConsensusClusterId {
        self.cluster
    }

    /// Allocated slot and incarnation bound when this volume was enrolled.
    pub fn identity(&self) -> VoterSlotIdentity {
        self.identity
    }

    /// Canonical compressed P-256 public key, suitable for possession proofs.
    pub fn public_key(&self) -> [u8; 33] {
        let point = self.key.verifying_key().to_sec1_point(true);
        let mut key = [0; 33];
        key.copy_from_slice(point.as_bytes());
        key
    }

    /// Public commitment stored in the immutable manifest or committed table.
    pub fn key_digest(&self) -> [u8; 32] {
        Sha256::digest(self.public_key()).into()
    }

    fn check_binding(
        &self,
        cluster: ConsensusClusterId,
        identity: VoterSlotIdentity,
        key_digest: [u8; 32],
    ) -> Result<(), VoterReplacementError> {
        if cluster != self.cluster || identity != self.identity || key_digest != self.key_digest() {
            return Err(VoterReplacementError::UnauthorizedReplacement);
        }
        Ok(())
    }

    /// Prove this volume's key to the authenticated manifest publisher.
    pub fn sign_enrollment(
        &self,
        challenge: &VoterEnrollmentChallenge,
    ) -> Result<[u8; 64], VoterReplacementError> {
        let binding = &challenge.binding;
        self.check_binding(
            binding.cluster_instance,
            binding.identity,
            binding.key_digest,
        )?;
        self.sign(&voter_enrollment_possession_signing_input(challenge)?)
    }

    /// Prove this incarnation on one complete, freshly challenged RPC direction.
    pub fn sign_rpc(
        &self,
        challenge: &VoterRpcChallenge,
    ) -> Result<[u8; 64], VoterReplacementError> {
        let binding = &challenge.binding;
        self.check_binding(
            binding.cluster_instance,
            binding.source.identity,
            binding.source.key_digest,
        )?;
        self.sign(&voter_rpc_possession_signing_input(challenge)?)
    }

    /// Prove a selected replacement key for the restricted candidate service.
    pub fn sign_candidate(
        &self,
        challenge: &VoterCandidateChallenge,
    ) -> Result<[u8; 64], VoterReplacementError> {
        let binding = &challenge.binding;
        self.check_binding(
            binding.cluster_instance,
            binding.identity,
            binding.key_digest,
        )?;
        self.sign(&voter_candidate_possession_signing_input(challenge)?)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], VoterReplacementError> {
        let signature: Signature = self
            .key
            .sign_prehash(&Sha256::digest(message))
            .map_err(|_| VoterReplacementError::Unavailable)?;
        Ok(signature.normalize_s().to_bytes().into())
    }

    pub(crate) fn generate(
        cluster: ConsensusClusterId,
        identity: VoterSlotIdentity,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        // Rejection sampling keeps the scalar uniform. Exhaustion or OS RNG
        // failure refuses enrollment without creating an identity record.
        let mut secret = Zeroizing::new([0; 32]);
        for _ in 0..32 {
            SysRng
                .try_fill_bytes(secret.as_mut())
                .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
            if let Ok(key) = SigningKey::from_bytes((&*secret).into()) {
                return Ok(Self {
                    cluster,
                    identity,
                    key: Arc::new(key),
                });
            }
        }
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    }

    pub(crate) fn record(&self) -> Zeroizing<[u8; RECORD_BYTES]> {
        let mut bytes = Zeroizing::new([0; RECORD_BYTES]);
        bytes[..16].copy_from_slice(MAGIC);
        bytes[16..48].copy_from_slice(self.cluster.as_bytes());
        bytes[48..50].copy_from_slice(&self.identity.slot().get().to_be_bytes());
        bytes[50..58].copy_from_slice(&self.identity.incarnation().get().to_be_bytes());
        let secret = Zeroizing::new(self.key.to_bytes());
        bytes[58..90].copy_from_slice(&secret);
        bytes[90..122].copy_from_slice(&self.key_digest());
        let digest = Sha256::digest(&bytes[..122]);
        bytes[122..].copy_from_slice(&digest);
        bytes
    }

    pub(crate) fn from_record(
        bytes: &[u8; RECORD_BYTES],
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        let refused = ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired;
        if &bytes[..16] != MAGIC || Sha256::digest(&bytes[..122]).as_slice() != &bytes[122..] {
            return Err(refused);
        }
        let cluster =
            ConsensusClusterId::from_bytes(bytes[16..48].try_into().map_err(|_| refused)?);
        let slot = SlotId::new(u16::from_be_bytes(
            bytes[48..50].try_into().map_err(|_| refused)?,
        ))
        .map_err(|_| refused)?;
        let incarnation = VoterIncarnation::new(u64::from_be_bytes(
            bytes[50..58].try_into().map_err(|_| refused)?,
        ))
        .map_err(|_| refused)?;
        let secret = Zeroizing::new(<[u8; 32]>::try_from(&bytes[58..90]).map_err(|_| refused)?);
        let key = SigningKey::from_bytes((&*secret).into()).map_err(|_| refused)?;
        let signer = Self {
            cluster,
            identity: VoterSlotIdentity::new(slot, incarnation),
            key: Arc::new(key),
        };
        if signer.key_digest() != bytes[90..122] {
            return Err(refused);
        }
        Ok(signer)
    }
}
