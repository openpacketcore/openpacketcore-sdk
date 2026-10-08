//! Closed profile dispatch for shared recovery state. This module is private;
//! consumers cannot implement profiles or invoke its raw cryptographic hooks.

use super::{packet::SealedPacket, sync_packet::AuthenticatedSync};
use super::{
    Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2SyncResponderRecord as SyncRecord,
};
use super::{Ikev2CommittedWindowDomain as Domain, Ikev2WindowError as Error};
use crate::canonical::{Ikev2CanonicalError as CanonicalError, Ikev2CanonicalPolicy as Policy};
use crate::ProtectedPayloadSealContext;
use crate::{
    Ikev2AesGcmIvDomain, Ikev2EncryptionAlgorithm, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
};
use bytes::Bytes;
use zeroize::Zeroizing;

mod cbc;
mod gcm;

/// AES-GCM recovery profile with separately committed IV reservation evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ikev2GcmRecoveryProfile;

/// AES-CBC recovery profile with immutable epoch storage and random ordinary IVs.
/// CBC state has no GCM allocator, allocation token, counter or IV floor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ikev2CbcRecoveryProfile;

pub trait DirectionBinding: Clone + PartialEq + Eq {
    fn initiator_spi(&self) -> u64;
    fn responder_spi(&self) -> u64;
    fn direction(&self) -> Direction;
    fn encryption(&self) -> Ikev2EncryptionAlgorithm;
}

impl DirectionBinding for Ikev2AesGcmIvDomain {
    fn initiator_spi(&self) -> u64 {
        self.initiator_spi()
    }
    fn responder_spi(&self) -> u64 {
        self.responder_spi()
    }
    fn direction(&self) -> Direction {
        self.direction()
    }
    fn encryption(&self) -> Ikev2EncryptionAlgorithm {
        self.encryption()
    }
}

// These associated types remain behind the private profile module. CBC's
// representation is empty, rather than an optional or dummy GCM IV counter.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GcmSyncEvidence {
    pub(super) minimum_send_iv_end: u64,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CbcSyncEvidence;

pub trait RecoveryProfile: Clone + Copy + Default + PartialEq + Eq + Send + Sync + 'static {
    type Direction: DirectionBinding;
    type Epoch: Clone;
    type Sealing<'a>;
    type SyncEvidence: Clone + Copy + Default + PartialEq + Eq;
    type SyncValidation: Default;
    type CanonicalRecipe;
    fn check_domain(domain: &Domain<Self>, profile: Profile, keys: &Keys) -> Result<(), Error>;
    fn from_epoch(epoch: &Self::Epoch) -> Domain<Self>;
    fn check_epoch_transition(old: &Self::Epoch, new: &Self::Epoch) -> Result<(), Error>;
    fn reconcile_preflight(epoch: &Self::Epoch) -> Result<(), Error>;
    fn sync_admission(profile: Profile) -> Result<(), Error>;
    fn payload_len(profile: Profile, cleartext_len: usize) -> Option<usize>;
    fn seal_body(
        profile: Profile,
        keys: &Keys,
        direction: Direction,
        input: Self::Sealing<'_>,
        context: ProtectedPayloadSealContext<'_>,
        cleartext: &[u8],
    ) -> Result<Bytes, Error>;
    fn check_local_ordinary(packet: &Ordinary<Self>, epoch: &Self::Epoch) -> Result<(), Error>;
    fn check_sync_evidence(record: &SyncRecord<Self>, epoch: &Self::Epoch) -> Result<(), Error>;
    fn check_next_sync_attempt(
        previous: &mut Self::SyncValidation,
        packet: &AuthenticatedSync<Self>,
        epoch: &Self::Epoch,
    ) -> Result<(), Error>;
    fn retain_local_evidence(source: &Window<Self>, target: &mut Record<Self>)
        -> Result<(), Error>;
    fn retain_sealed(
        evidence: &mut Self::SyncEvidence,
        packet: &SealedPacket<Self>,
    ) -> Result<(), Error>;
    fn ledger_key(domain: &Domain<Self>) -> [u8; 32];
    fn binding_fingerprint(domain: &Domain<Self>) -> Result<[u8; 32], CanonicalError>;
    fn canonical_gate() -> Result<(), CanonicalError>;
    fn canonical_preflight(domain: &Domain<Self>, policy: Policy) -> Result<(), CanonicalError>;
    fn canonical_recipe(domain: &Domain<Self>) -> Result<Self::CanonicalRecipe, CanonicalError>;
    fn canonical_seal(
        recipe: &Self::CanonicalRecipe,
        domain: &Domain<Self>,
        id: u32,
    ) -> Result<Zeroizing<Vec<u8>>, CanonicalError>;
}

fn check_gcm_domain(
    domain: &Domain<Ikev2GcmRecoveryProfile>,
    profile: Profile,
    keys: &Keys,
) -> Result<(), Error> {
    let mut actual = Domain::new(
        domain.send.initiator_spi(),
        domain.send.responder_spi(),
        domain.send.direction(),
        profile,
        keys,
    )?;
    actual.canonical_format = domain.canonical_format;
    if &actual != domain {
        return Err(Error::DomainMismatch);
    }
    Ok(())
}

fn check_cbc_domain(
    domain: &Domain<Ikev2CbcRecoveryProfile>,
    profile: Profile,
    keys: &Keys,
) -> Result<(), Error> {
    let actual = super::Ikev2CbcEpochRecord::from_persisted(
        super::Ikev2CbcEpochInputs {
            initiator_spi: domain.send.initiator_spi(),
            responder_spi: domain.send.responder_spi(),
            sending_direction: domain.send.direction(),
            profile,
            keys,
        },
        domain.canonical_format,
    )?;
    if &Domain::from_cbc_epoch(&actual) != domain {
        return Err(Error::DomainMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod runtime_tests;

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
mod restart_tests;
