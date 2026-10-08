use super::*;
use crate::{
    Ikev2AesGcmIvAllocation, Ikev2AesGcmIvRecord, GENERIC_PAYLOAD_HEADER_LEN, HEADER_LEN,
    IKEV2_AES_GCM_EXPLICIT_IV_LEN,
};

type Gcm = Ikev2GcmRecoveryProfile;

// Raw byte extraction is private to this GCM-only implementation. Every caller
// below requires authenticated GCM evidence, a successfully sealed GCM packet,
// or a runtime whose retained packets have already passed that validation.
fn sending_iv_end(wire: &[u8]) -> Result<u64, Error> {
    let start = HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let iv = wire
        .get(start..start + IKEV2_AES_GCM_EXPLICIT_IV_LEN)
        .ok_or(Error::InvalidRecord)?;
    u64::from_be_bytes(iv.try_into().map_err(|_| Error::InvalidRecord)?)
        .checked_add(1)
        .ok_or(Error::InvalidRecord)
}

impl RecoveryProfile for Gcm {
    type Direction = Ikev2AesGcmIvDomain;
    type Epoch = Ikev2AesGcmIvRecord;
    type Sealing<'a> = Ikev2AesGcmIvAllocation<'a>;
    type SyncEvidence = GcmSyncEvidence;
    type SyncValidation = Option<u64>;
    type CanonicalRecipe = ();

    fn check_domain(domain: &Domain<Self>, profile: Profile, keys: &Keys) -> Result<(), Error> {
        check_gcm_domain(domain, profile, keys)
    }
    fn from_epoch(epoch: &Self::Epoch) -> Domain<Self> {
        Domain::from_iv_record(epoch)
    }
    fn check_epoch_transition(old: &Self::Epoch, new: &Self::Epoch) -> Result<(), Error> {
        if old.limits() != new.limits() || new.exclusive_end() < old.exclusive_end() {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }
    fn reconcile_preflight(epoch: &Self::Epoch) -> Result<(), Error> {
        crate::crypto_module::check_aead_admission(epoch.domain().encryption())
            .map_err(|_| Error::ReconcileUnavailable)
    }
    fn sync_admission(profile: Profile) -> Result<(), Error> {
        crate::crypto_module::check_sync_admission(profile.encryption())
            .map_err(|_| Error::SyncUnavailable)
    }
    fn payload_len(_: Profile, cleartext_len: usize) -> Option<usize> {
        crate::ikev2_aes_gcm_protected_payload_len(cleartext_len, 0)
    }
    fn seal_body(
        profile: Profile,
        keys: &Keys,
        _: Direction,
        allocation: Self::Sealing<'_>,
        context: ProtectedPayloadSealContext<'_>,
        cleartext: &[u8],
    ) -> Result<Bytes, Error> {
        allocation
            .seal(profile, keys, context, cleartext, 0)
            .map_err(Error::Iv)
    }
    fn check_local_ordinary(packet: &Ordinary<Self>, epoch: &Self::Epoch) -> Result<(), Error> {
        if sending_iv_end(&packet.wire)? > epoch.exclusive_end() {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }
    fn check_sync_evidence(record: &SyncRecord<Self>, epoch: &Self::Epoch) -> Result<(), Error> {
        if epoch.exclusive_end() < record.minimum_send_iv_end() {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }
    fn check_next_sync_attempt(
        previous: &mut Self::SyncValidation,
        packet: &AuthenticatedSync<Self>,
        epoch: &Self::Epoch,
    ) -> Result<(), Error> {
        let end = sending_iv_end(packet.wire())?;
        if end > epoch.exclusive_end() || previous.is_some_and(|old| old >= end) {
            return Err(Error::InvalidRecord);
        }
        *previous = Some(end);
        Ok(())
    }
    fn retain_local_evidence(
        source: &Window<Self>,
        target: &mut Record<Self>,
    ) -> Result<(), Error> {
        let Some(sync) = &mut target.sync else {
            return Ok(());
        };
        let ordinary = source
            .record
            .outbound
            .as_ref()
            .map(|entry| entry.request.as_ref())
            .into_iter()
            .chain(
                source
                    .record
                    .inbound
                    .as_ref()
                    .and_then(|entry| entry.response.as_deref()),
            );
        let attempts = source.record.recovery.iter().flat_map(|recovery| {
            recovery
                .attempts()
                .iter()
                .map(|attempt| attempt.request_bytes())
        });
        for wire in ordinary.chain(attempts) {
            sync.packet_evidence.minimum_send_iv_end = sync
                .packet_evidence
                .minimum_send_iv_end
                .max(sending_iv_end(wire)?);
        }
        Ok(())
    }
    fn retain_sealed(
        evidence: &mut Self::SyncEvidence,
        packet: &SealedPacket<Self>,
    ) -> Result<(), Error> {
        evidence.minimum_send_iv_end = evidence
            .minimum_send_iv_end
            .max(sending_iv_end(packet.wire())?);
        Ok(())
    }
    fn ledger_key(domain: &Domain<Self>) -> [u8; 32] {
        crate::canonical::gcm_ledger_key(domain)
    }
    fn binding_fingerprint(domain: &Domain<Self>) -> Result<[u8; 32], CanonicalError> {
        Ok(crate::canonical::gcm_binding_fingerprint(domain))
    }
    fn canonical_gate() -> Result<(), CanonicalError> {
        Ok(())
    }
    fn canonical_preflight(domain: &Domain<Self>, policy: Policy) -> Result<(), CanonicalError> {
        crate::canonical::Ikev2CanonicalEmptyReplies::preflight(domain.send.encryption(), policy)
    }
    fn canonical_recipe(_: &Domain<Self>) -> Result<Self::CanonicalRecipe, CanonicalError> {
        Ok(())
    }
    fn canonical_seal(
        _: &Self::CanonicalRecipe,
        domain: &Domain<Self>,
        id: u32,
    ) -> Result<Zeroizing<Vec<u8>>, CanonicalError> {
        crate::canonical::gcm_seal(domain, id)
    }
}
