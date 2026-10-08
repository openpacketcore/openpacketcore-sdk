use super::*;
use crate::recovery::{cbc_epoch::CbcDirection, Ikev2CbcEpochRecord};

type Cbc = Ikev2CbcRecoveryProfile;

impl RecoveryProfile for Cbc {
    type Direction = CbcDirection;
    type Epoch = Ikev2CbcEpochRecord;
    type Sealing<'a> = ();
    type SyncEvidence = CbcSyncEvidence;
    type SyncValidation = ();
    type CanonicalRecipe = crate::canonical::cbc::Recipe;

    fn check_domain(domain: &Domain<Self>, profile: Profile, keys: &Keys) -> Result<(), Error> {
        check_cbc_domain(domain, profile, keys)
    }
    fn from_epoch(epoch: &Self::Epoch) -> Domain<Self> {
        Domain::from_cbc_epoch(epoch)
    }
    fn check_epoch_transition(old: &Self::Epoch, new: &Self::Epoch) -> Result<(), Error> {
        if old != new {
            return Err(Error::DomainMismatch);
        }
        Ok(())
    }
    fn reconcile_preflight(epoch: &Self::Epoch) -> Result<(), Error> {
        crate::crypto_module::check_cbc_admission(epoch.encryption(), epoch.integrity())
            .and_then(|()| crate::crypto_module::check_prf_admission(epoch.prf()))
            .map_err(|_| Error::ReconcileUnavailable)
    }
    fn sync_admission(profile: Profile) -> Result<(), Error> {
        let integrity = profile.integrity().ok_or(Error::SyncUnavailable)?;
        crate::crypto_module::check_cbc_admission(profile.encryption(), integrity)
            .and_then(|()| crate::crypto_module::with_entropy_operation(|_| Ok(())))
            .map_err(|_| Error::SyncUnavailable)
    }
    fn payload_len(profile: Profile, cleartext_len: usize) -> Option<usize> {
        crate::ikev2_aes_cbc_protected_payload_len(profile, cleartext_len, 0)
    }
    fn seal_body(
        profile: Profile,
        keys: &Keys,
        direction: Direction,
        (): Self::Sealing<'_>,
        context: ProtectedPayloadSealContext<'_>,
        cleartext: &[u8],
    ) -> Result<Bytes, Error> {
        crate::seal_ikev2_sa_init_aes_cbc_protected_payload(
            profile, keys, direction, context, cleartext,
        )
        .map_err(Error::Crypto)
    }
    fn check_local_ordinary(_: &Ordinary<Self>, _: &Self::Epoch) -> Result<(), Error> {
        Ok(())
    }
    fn check_sync_evidence(_: &SyncRecord<Self>, _: &Self::Epoch) -> Result<(), Error> {
        Ok(())
    }
    fn check_next_sync_attempt(
        _: &mut Self::SyncValidation,
        _: &AuthenticatedSync<Self>,
        _: &Self::Epoch,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn retain_local_evidence(_: &Window<Self>, _: &mut Record<Self>) -> Result<(), Error> {
        Ok(())
    }
    fn retain_sealed(_: &mut Self::SyncEvidence, _: &SealedPacket<Self>) -> Result<(), Error> {
        Ok(())
    }
    fn ledger_key(domain: &Domain<Self>) -> [u8; 32] {
        domain.send.epoch().ledger_key()
    }
    fn binding_fingerprint(domain: &Domain<Self>) -> Result<[u8; 32], CanonicalError> {
        domain
            .send
            .epoch()
            .binding_fingerprint()
            .ok_or(CanonicalError::FormatUnavailable)
    }
    fn canonical_gate() -> Result<(), CanonicalError> {
        crate::canonical::cbc::integration_review_gate()
    }
    fn canonical_preflight(domain: &Domain<Self>, policy: Policy) -> Result<(), CanonicalError> {
        Self::canonical_gate()?;
        crate::canonical::cbc::preflight_epoch(domain.send.epoch(), policy)
    }
    fn canonical_recipe(domain: &Domain<Self>) -> Result<Self::CanonicalRecipe, CanonicalError> {
        Self::canonical_gate()?;
        crate::canonical::cbc::Recipe::from_epoch(domain.send.epoch())
    }
    fn canonical_seal(
        recipe: &Self::CanonicalRecipe,
        _: &Domain<Self>,
        id: u32,
    ) -> Result<Zeroizing<Vec<u8>>, CanonicalError> {
        Self::canonical_gate()?;
        recipe.seal(id)
    }
}
