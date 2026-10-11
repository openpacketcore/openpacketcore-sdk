use super::profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use std::sync::Arc;

use super::{
    Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record, Ikev2WindowError as Error,
};
use crate::{Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Outbound,
    Inbound,
    Sync,
}

// One bounded volatile copy, captured only when a prepared record is exposed.
pub(super) struct Witness<P: RecoveryProfile = Gcm> {
    record: Record<P>,
    kind: Kind,
}

impl<P: RecoveryProfile> Window<P> {
    // Only ordinary outbound preparation leaves the inbound record and receive
    // boundary unchanged. An absent witness never establishes this exception.
    pub(super) fn has_outbound_witness(&self) -> bool {
        self.witness
            .as_ref()
            .is_some_and(|witness| witness.kind == Kind::Outbound)
    }

    pub(super) fn remember_prepared(&mut self, record: &Record<P>, kind: Kind) {
        self.quiescent = true;
        self.witness = Some(Witness {
            record: record.clone(),
            kind,
        });
    }

    /// Reconcile the latest fenced readback in place, retaining canonical ownership.
    ///
    /// Settle or fence every outstanding write, then read both records from one
    /// consistent snapshot. The window record must exactly equal the last
    /// acknowledged record or this runtime's one privately witnessed candidate.
    /// CBC's complete epoch descriptor must stay identical. For GCM, only the IV
    /// record's high-water may increase; its limits and full binding stay unchanged.
    /// GCM coverage includes every sealed witness IV, landed or not. Keep its live
    /// IV allocator; do not restore it during this operation.
    ///
    /// Unchanged/outbound readback preserves the receive floor, admission phase,
    /// pending identity and last applicable empty reply, including failed-seal
    /// history. A newly landed inbound/sync boundary retires superseded replies
    /// and adopts the maximum live/recorded floor (`None` means exhausted).
    /// Retirement is checked on every success, including unchanged readback.
    /// No capability is acquired, no packet is sealed or released, and no effect
    /// or completion token is created. Restore durable outcomes idempotently.
    ///
    /// Every attempt fences all old completion tokens and any live local sync
    /// proposal, even at the same generation. A pending proposal therefore needs
    /// its existing bounded higher-proposal retry, spending another attempt.
    /// Clock and latched-close knowledge survive. Valid lifecycle states succeed;
    /// [`Self::ready`] reports pending sync, uncertain outcome or closure afterward.
    ///
    /// # Errors
    /// [`Error::ReconcileUnavailable`] means the provider pre-check failed before
    /// validation. Keep this quiescent runtime and retry; its cache and witness
    /// remain intact. Every other failure permanently revokes this epoch and the
    /// supplied bindings, discards cached replies and stays quiescent until
    /// [`Self::delete`]. A provider failure during packet validation is terminal.
    /// Discard consumer-held copies, keys and stored SA state on terminal failure.
    /// Without an enabled canonical capability, reconciliation cannot detect
    /// revocation elsewhere; tear down the SA on any terminal error.
    pub fn reconcile(
        &mut self,
        profile: Profile,
        keys: &Keys,
        record: &Record<P>,
        epoch: &P::Epoch,
    ) -> Result<(), Error> {
        // This identity fences ordinary and both sync token types; the canonical
        // owner has its own identity and is deliberately retained.
        self.instance = Arc::new(());
        self.quiescent = true;
        self.sync_live = false;
        if self.reconcile_terminal {
            return Err(Error::Canonical(
                crate::canonical::Ikev2CanonicalError::Invalidated,
            ));
        }
        P::reconcile_preflight(&self.canonical_binding)?;

        if let Err(error) = self.reconcile_checked(profile, keys, record, epoch) {
            crate::canonical::invalidate_profile(&P::from_epoch(&self.canonical_binding));
            crate::canonical::invalidate_profile(&record.domain);
            crate::canonical::invalidate_profile(&P::from_epoch(epoch));
            self.receive.discard_replies();
            self.witness = None;
            self.reconcile_terminal = true;
            return Err(error);
        }
        Ok(())
    }

    fn reconcile_checked(
        &mut self,
        profile: Profile,
        keys: &Keys,
        record: &Record<P>,
        epoch: &P::Epoch,
    ) -> Result<(), Error> {
        // Check immutable binding first, retaining restore's error distinction.
        if record.domain != self.record.domain || P::from_epoch(epoch) != self.record.domain {
            return Err(Error::DomainMismatch);
        }
        let kind = if record == &self.record {
            None
        } else if let Some(witness) = &self.witness {
            if record != &witness.record {
                return Err(Error::InvalidRecord);
            }
            Some(witness.kind)
        } else {
            return Err(Error::InvalidRecord);
        };
        P::check_epoch_transition(&self.canonical_binding, epoch)?;
        Self::validate_record(&self.record.domain, profile, keys, record, epoch)?;
        // Even a candidate that did not land consumed acknowledged IVs. Its
        // response-only sync IV is represented by minimum_send_iv_end.
        if let Some(witness) = &self.witness {
            if record != &witness.record {
                Self::validate_record(&self.record.domain, profile, keys, &witness.record, epoch)?;
            }
        }
        let boundary = matches!(kind, Some(Kind::Inbound | Kind::Sync));
        let next = if boundary {
            self.receive.boundary_next(record.next_receive)
        } else {
            self.receive.next
        };
        // No fallible operation may follow retirement and precede publication.
        // Retain the applicable last reply for unchanged/outbound readback.
        self.receive.retire_readback(next, boundary)?;
        self.record = record.clone();
        self.canonical_binding = epoch.clone();
        if boundary {
            self.receive.adopt_boundary(next);
        }
        if kind == Some(Kind::Sync) {
            self.observed_peer_request.set(None);
        }
        self.sync_last_observed_unix_ms = self.sync_last_observed_unix_ms.max(
            record
                .sync_recovery()
                .map(|recovery| recovery.last_observed_unix_ms()),
        );
        self.witness = None;
        self.quiescent = false;
        Ok(())
    }
}
