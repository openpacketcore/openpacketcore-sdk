use std::sync::Arc;

use super::{
    Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record, Ikev2WindowError as Error,
};
use crate::{
    crypto_module, Ikev2AesGcmIvRecord as IvRecord, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Outbound,
    Inbound,
    Sync,
}

// One bounded volatile copy, captured only when a prepared record is exposed.
pub(super) struct Witness {
    record: Record,
    kind: Kind,
}

impl Window {
    pub(super) fn remember_prepared(&mut self, record: &Record, kind: Kind) {
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
    /// Only the IV record's high-water may increase; its limits and full binding
    /// must stay unchanged. Coverage includes every sealed witness IV, landed or
    /// not. Keep the live IV allocator; do not restore it during this operation.
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
        record: &Record,
        iv_record: &IvRecord,
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
        crypto_module::check_aead_admission(self.canonical_binding.domain().encryption())
            .map_err(|_| Error::ReconcileUnavailable)?;

        if let Err(error) = self.reconcile_checked(profile, keys, record, iv_record) {
            crate::canonical::invalidate_binding(self.canonical_binding.domain());
            crate::canonical::invalidate_binding(record.domain.send_iv_domain());
            crate::canonical::invalidate_binding(iv_record.domain());
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
        record: &Record,
        iv_record: &IvRecord,
    ) -> Result<(), Error> {
        // Check immutable binding first, retaining restore's error distinction.
        if record.domain != self.record.domain
            || super::Ikev2CommittedWindowDomain::from_iv_record(iv_record) != self.record.domain
        {
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
        if iv_record.limits() != self.canonical_binding.limits()
            || iv_record.exclusive_end() < self.canonical_binding.exclusive_end()
        {
            return Err(Error::InvalidRecord);
        }
        Self::validate_record(&self.record.domain, profile, keys, record, iv_record)?;
        // Even a candidate that did not land consumed acknowledged IVs. Its
        // response-only sync IV is represented by minimum_send_iv_end.
        if let Some(witness) = &self.witness {
            if record != &witness.record {
                Self::validate_record(
                    &self.record.domain,
                    profile,
                    keys,
                    &witness.record,
                    iv_record,
                )?;
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
        self.canonical_binding = iv_record.clone();
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
