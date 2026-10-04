//! Purpose-separated retained signing epochs and authenticated transitions.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit_authority::ledger::{authenticate, verify};
use crate::audit_authority::AuditAuthorityError;
use crate::{AuditKey, ConfigConsensusIdentity};

const TRANSITION_OLD_DOMAIN: &[u8] = b"openpacketcore/management-audit/key-transition/old/v1\0";
const TRANSITION_NEW_DOMAIN: &[u8] = b"openpacketcore/management-audit/key-transition/new/v1\0";

/// Maximum overlapping live signing epochs. Archived exports may require a
/// separately retained verifier key set after a live epoch is safely retired.
pub const MAX_AUDIT_SIGNING_EPOCHS: usize = 8;

/// Explicit management-ledger signing material, separate from configuration
/// integrity and privacy projection. No byte export or implicit key is provided.
pub struct AuditSigningKey(AuditKey);

impl AuditSigningKey {
    /// Import nonzero material for one nonzero epoch. Import is not activation.
    pub fn new(epoch: u64, material: [u8; 32]) -> Result<Self, AuditAuthorityError> {
        let material = Zeroizing::new(material);
        AuditKey::new_with_epoch(*material, epoch)
            .map(Self)
            .map_err(|_| AuditAuthorityError::KeyUnavailable)
    }
}

impl fmt::Debug for AuditSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditSigningKey(<redacted>)")
    }
}

/// Bounded, locally admitted signing/verification material. The ledger selects
/// its authenticated active epoch; adding a newer key does not activate it.
/// Supply the same overlapping material to every voter before rotation.
pub struct AuditKeyRing {
    keys: BTreeMap<u64, AuditKey>,
}

impl AuditKeyRing {
    /// Admit one through eight distinct epochs with distinct nonzero material.
    pub fn new(keys: Vec<AuditSigningKey>) -> Result<Self, AuditAuthorityError> {
        if keys.is_empty() || keys.len() > MAX_AUDIT_SIGNING_EPOCHS {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let mut result = BTreeMap::<u64, AuditKey>::new();
        for AuditSigningKey(key) in keys {
            let material_id = material_identity(&key)?;
            if result.contains_key(&key.epoch()) {
                return Err(AuditAuthorityError::BindingMismatch);
            }
            for old in result.values() {
                if material_identity(old)? == material_id {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
            }
            result.insert(key.epoch(), key);
        }
        Ok(Self { keys: result })
    }

    /// Epoch identifiers only; never signing material or key fingerprints.
    pub fn epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.keys.keys().copied()
    }

    pub(crate) fn key(&self, epoch: u64) -> Result<&AuditKey, AuditAuthorityError> {
        self.keys
            .get(&epoch)
            .ok_or(AuditAuthorityError::KeyUnavailable)
    }

    pub(crate) fn separate_from(&self, root: &AuditKey) -> Result<(), AuditAuthorityError> {
        let root_id = material_identity(root)?;
        for key in self.keys.values() {
            if material_identity(key)? == root_id {
                return Err(AuditAuthorityError::BindingMismatch);
            }
        }
        Ok(())
    }
}

fn material_identity(key: &AuditKey) -> Result<[u8; 32], AuditAuthorityError> {
    authenticate(
        key,
        b"openpacketcore/management-audit/key-material-equality/v1\0",
        &(),
    )
}

impl fmt::Debug for AuditKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditKeyRing")
            .field("epochs", &self.keys.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransitionBody {
    pub(crate) version: u16,
    pub(crate) identity: ConfigConsensusIdentity,
    pub(crate) previous_sequence: u64,
    pub(crate) previous_anchor: [u8; 32],
    pub(crate) from_epoch: u64,
    pub(crate) to_epoch: u64,
    pub(crate) old_fingerprint: [u8; 32],
    pub(crate) new_fingerprint: [u8; 32],
}

/// Cross-authenticated transition bound to one exact fleet and ledger prefix.
/// Neither a configuration edit nor mounting a new key supplies this proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditKeyTransition {
    pub(crate) body: TransitionBody,
    old_proof: [u8; 32],
    new_proof: [u8; 32],
}

impl AuditKeyTransition {
    pub(crate) fn prepare(
        keys: &AuditKeyRing,
        identity: ConfigConsensusIdentity,
        previous_sequence: u64,
        previous_anchor: [u8; 32],
        from_epoch: u64,
        to_epoch: u64,
    ) -> Result<Self, AuditAuthorityError> {
        if from_epoch.checked_add(1) != Some(to_epoch) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let old = keys.key(from_epoch)?;
        let new = keys.key(to_epoch)?;
        let body = TransitionBody {
            version: 1,
            identity,
            previous_sequence,
            previous_anchor,
            from_epoch,
            to_epoch,
            old_fingerprint: old.fingerprint(),
            new_fingerprint: new.fingerprint(),
        };
        let old_proof = authenticate(old, TRANSITION_OLD_DOMAIN, &body)?;
        let new_proof = authenticate(new, TRANSITION_NEW_DOMAIN, &(&body, old_proof))?;
        Ok(Self {
            body,
            old_proof,
            new_proof,
        })
    }

    /// Verify both key proofs against the exact previously authenticated prefix.
    /// This does not activate the key; activation belongs to consensus apply.
    pub fn verify(
        &self,
        keys: &AuditKeyRing,
        identity: ConfigConsensusIdentity,
        previous_sequence: u64,
        previous_anchor: [u8; 32],
        from_epoch: u64,
    ) -> Result<(), AuditAuthorityError> {
        let body = &self.body;
        if body.version != 1
            || body.identity != identity
            || body.previous_sequence != previous_sequence
            || body.previous_anchor != previous_anchor
            || body.from_epoch != from_epoch
            || from_epoch.checked_add(1) != Some(body.to_epoch)
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let old = keys.key(from_epoch)?;
        let new = keys.key(body.to_epoch)?;
        if old.fingerprint() != body.old_fingerprint
            || new.fingerprint() != body.new_fingerprint
            || body.old_fingerprint == body.new_fingerprint
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(old, TRANSITION_OLD_DOMAIN, body, &self.old_proof)?;
        verify(
            new,
            TRANSITION_NEW_DOMAIN,
            &(body, self.old_proof),
            &self.new_proof,
        )
    }
}

impl fmt::Debug for AuditKeyTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditKeyTransition(<redacted>)")
    }
}
