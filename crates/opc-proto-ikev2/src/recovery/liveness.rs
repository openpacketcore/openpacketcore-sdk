//! Fresh RFC 7296 §2.4 empty INFORMATIONAL requests, with bounded unwritten IDs.
//!
//! The caller schedules probes after inactivity across the IKE SA and all its
//! Child SAs, counts only authenticated fresh IKE/ESP traffic, and owns the
//! exponentially backed-off retransmission deadline. NAT keepalives are not
//! liveness evidence. A probe completion grants no application effect authority.
//!
//! One durable opt-in records the maximum unwritten probe lead. Individual
//! probes then use memory only, plus GCM allocations from an already committed
//! reservation. Ordinary commits or an explicit checkpoint fold the live floor.
//! Cold restore blocks ordinary traffic until negotiated RFC 6311 synchronization
//! skips the entire possible lead, or the consumer retires this IKE/Child epoch.
//! A persisted pending ordinary request is the exception: no later probe could
//! have escaped while that request occupied the sole local request slot.

use std::{marker::PhantomData, num::NonZeroU32};

use bytes::Bytes;

use super::{
    packet,
    profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile},
    Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2PreparedWindow, Ikev2WindowError as Error,
};
use crate::{Ikev2ExchangeKind as Exchange, PayloadChain, PayloadType};

struct Pending {
    id: u32,
    wire: Bytes,
}

pub(super) struct ProbeState {
    next_send: Option<u32>,
    pending: Option<Pending>,
    recovery_required: bool,
    pub(super) highest_request: Option<u32>,
}

impl ProbeState {
    pub(super) fn restored<P: RecoveryProfile>(record: &Record<P>) -> Self {
        Self {
            recovery_required: record.liveness_limit.is_some()
                && record
                    .outbound
                    .as_ref()
                    .is_none_or(|entry| entry.response.is_some()),
            ..Self::live(record.next_send)
        }
    }

    fn live(next_send: Option<u32>) -> Self {
        Self {
            next_send,
            pending: None,
            recovery_required: false,
            highest_request: None,
        }
    }

    pub(super) fn pending_id(&self) -> Option<u32> {
        self.pending.as_ref().map(|pending| pending.id)
    }

    pub(super) fn ready(&self) -> Result<(), Error> {
        if self.recovery_required {
            Err(Error::LivenessRecoveryRequired)
        } else {
            Ok(())
        }
    }
}

/// Exact request bytes borrowed from a live, fenced window.
///
/// Retain this borrow and the consumer's SA/send fence through submission.
/// Dropping the value leaves the probe pending; it neither sends nor cancels it.
#[must_use = "transmit these exact bytes while retaining the window and consumer send fence"]
pub struct Ikev2EmptyRequest<'a, P: RecoveryProfile = Gcm> {
    pending: &'a Pending,
    window: PhantomData<&'a Window<P>>,
}

impl<P: RecoveryProfile> Ikev2EmptyRequest<'_, P> {
    /// Complete immutable IKE packet, without transport framing.
    pub fn bytes(&self) -> &[u8] {
        &self.pending.wire
    }

    /// Retransmissions retain this Message ID and the original IV.
    pub const fn message_id(&self) -> u32 {
        self.pending.id
    }
}

/// Fresh authenticated answer to the pending probe, under the current SA fence.
/// This is an observation only, not endpoint, key, lifetime or outcome authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EmptyRequestCompletion {
    message_id: u32,
}

impl Ikev2EmptyRequestCompletion {
    /// Message ID of the answered request.
    pub const fn message_id(self) -> u32 {
        self.message_id
    }
}

impl<P: RecoveryProfile> Window<P> {
    /// Persist the opt-in bound, or checkpoint completed probes and renew the bound.
    ///
    /// Commit the exact candidate before starting a probe. The bound limits the
    /// number of unwritten probe IDs, not retransmissions or the caller's timeout.
    /// Each ordinary commit also checkpoints the live floor. Persist this field
    /// explicitly in the SA codec; omission must never decode as disabled.
    ///
    /// A cold restore with this opt-in requires negotiated RFC 6311 recovery or
    /// retirement of the IKE SA and its Children. Re-enabling cannot bypass that
    /// requirement. Choose a bound that leaves room for synchronization and rekey.
    /// # Errors
    /// Refuses a blocked lifecycle or an outstanding local request of either kind.
    pub fn prepare_liveness(
        &mut self,
        max_unwritten_probes: NonZeroU32,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Error> {
        self.ready()?;
        self.require_local_slot()?;
        let mut record = self.next_record()?;
        record.liveness_limit = Some(max_unwritten_probes);
        Ok(self.prepared(record, None, false))
    }

    pub(super) fn require_local_slot(&self) -> Result<(), Error> {
        if self.probe.pending.is_some()
            || self
                .record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none())
        {
            Err(Error::RequestOutstanding)
        } else {
            Ok(())
        }
    }

    /// Seal a fresh empty INFORMATIONAL without changing any durable record.
    ///
    /// GCM requires an allocation from an acknowledged IV reservation; CBC uses
    /// admitted random-IV encryption. The sole local request slot remains occupied
    /// until an answer or abandonment. Independent peer requests remain admissible.
    /// # Errors
    /// Refuses disabled/blocked liveness, an occupied slot, the unwritten bound,
    /// ID exhaustion, or failed cryptographic admission. Failed sealing consumes
    /// its GCM allocation but no Message ID. MAX remains available for ordinary rekey.
    pub fn send_empty_request(
        &mut self,
        profile: crate::Ikev2SaInitCryptoProfile,
        keys: &crate::Ikev2SaInitKeyMaterial,
        sealing: P::Sealing<'_>,
    ) -> Result<Ikev2EmptyRequest<'_, P>, Error> {
        self.ready()?;
        self.require_local_slot()?;
        let limit = self.record.liveness_limit.ok_or(Error::LivenessDisabled)?;
        let id = self
            .next_send()
            .filter(|id| *id < u32::MAX)
            .ok_or(Error::Exhausted)?;
        let lead = id
            .checked_sub(self.record.next_send.ok_or(Error::Exhausted)?)
            .ok_or(Error::InvalidRecord)?;
        if lead >= limit.get() {
            return Err(Error::LivenessCheckpointRequired);
        }
        let sealed = packet::seal(
            &self.record.domain,
            profile,
            keys,
            sealing,
            self.record
                .domain
                .header(Exchange::Informational, id, false),
            PayloadChain::new(PayloadType::NoNext, &[]),
        )?;
        P::retain_sealed(&mut self.packet_evidence, &sealed)?;
        self.probe.next_send = id.checked_add(1);
        self.probe.highest_request = Some(id);
        self.probe.pending = Some(Pending {
            id,
            wire: sealed.into_wire(),
        });
        self.retransmit_empty_request()?.ok_or(Error::InvalidRecord)
    }

    /// Borrow the exact pending bytes without a new ID, IV or durable write.
    /// # Errors
    /// Refuses uncertain storage, synchronization, closure or expired probe authority.
    pub fn retransmit_empty_request(&self) -> Result<Option<Ikev2EmptyRequest<'_, P>>, Error> {
        self.ready()?;
        Ok(self
            .probe
            .pending
            .as_ref()
            .map(|pending| Ikev2EmptyRequest {
                pending,
                window: PhantomData,
            }))
    }

    /// Complete only the authenticated empty response matching the pending probe.
    ///
    /// Authenticate with `open_peer` first. A duplicate, wrong ID/class/direction,
    /// nonempty response or stale pre-recovery response cannot complete a probe.
    /// # Errors
    /// Refuses blocked lifecycle or mismatching response evidence without mutation.
    pub fn complete_empty_request(
        &mut self,
        response: &Ordinary<P>,
    ) -> Result<Ikev2EmptyRequestCompletion, Error> {
        self.ready()?;
        let pending = self.probe.pending.as_ref().ok_or(Error::Drop)?;
        if response.domain != self.record.domain
            || !response.header.flags.response()
            || response.header.exchange_type != Exchange::Informational.as_u8()
            || response.header.message_id != pending.id
            || !response.payloads().is_empty()
        {
            return Err(Error::Drop);
        }
        let message_id = pending.id;
        self.probe.pending = None;
        Ok(Ikev2EmptyRequestCompletion { message_id })
    }

    /// Stop retransmitting after the caller's budget, without skipping a peer window slot.
    ///
    /// A lost request may never have reached the peer. Abandonment therefore
    /// blocks further ordinary traffic until negotiated synchronization or SA
    /// retirement; it never silently frees the slot for another request.
    /// # Errors
    /// Refuses blocked lifecycle. Returns `None` if there is no pending probe.
    pub fn abandon_empty_request(&mut self) -> Result<Option<u32>, Error> {
        self.ready()?;
        Ok(self.probe.pending.take().map(|pending| {
            self.probe.recovery_required = true;
            pending.id
        }))
    }

    /// Volatile next local ID, including probes; `None` means exhausted, never zero.
    /// This is diagnostic state, not a persistence input or send permission.
    pub const fn next_send(&self) -> Option<u32> {
        self.probe.next_send
    }

    pub(super) fn fold_send_floor(&self, record: &mut Record<P>) -> Result<(), Error> {
        P::retain_local_evidence(self, record)?;
        if record.next_send != self.next_send() {
            if record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none())
            {
                return Err(Error::InvalidRecord);
            }
            // Consumer outcomes are already durable; this cache is no longer adjacent to the floor.
            record.outbound = None;
            record.next_send = self.next_send();
        }
        if let Some(sync) = &mut record.sync {
            sync.highest_local_request = sync.highest_local_request.max(self.probe.highest_request);
        }
        Ok(())
    }

    pub(super) fn adopt_send_floor(&mut self, synchronized: bool) {
        if synchronized {
            self.fragments.cutover();
            self.packet_evidence = P::SyncEvidence::default();
            self.probe = ProbeState::live(self.record.next_send);
        } else {
            self.probe.next_send = self
                .probe
                .next_send
                .zip(self.record.next_send)
                .map(|(live, committed)| live.max(committed));
        }
    }

    pub(super) fn sync_send_floor(&self) -> Result<u32, Error> {
        let next = self.next_send().ok_or(Error::SyncClosed)?;
        if self.probe.recovery_required {
            let limit = self.record.liveness_limit.ok_or(Error::InvalidRecord)?;
            self.record
                .next_send
                .and_then(|floor| floor.checked_add(limit.get()))
                .map(|floor| floor.max(next))
                .ok_or(Error::SyncClosed)
        } else {
            Ok(next)
        }
    }
}
