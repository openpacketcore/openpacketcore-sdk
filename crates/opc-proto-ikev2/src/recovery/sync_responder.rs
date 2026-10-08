use super::profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use std::sync::Arc;

use bytes::Bytes;

use super::{
    sync_packet, Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2OrdinaryRequestDisposition,
    Ikev2SyncDisposition as Disposition, Ikev2SyncResponderRecord, Ikev2WindowError as Error,
};
use crate::{
    Ikev2AesGcmIvAllocation, Ikev2MessageIdSync as Sync, Ikev2MessageIdSyncCounters as Counters,
    Ikev2MessageIdSyncMode as Mode, Ikev2MessageIdSyncPending as Pending,
    Ikev2MessageIdSyncRuleError as RuleError, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys, PayloadChain,
};

impl<P: RecoveryProfile> Window<P> {
    /// Retain volatile sync-drop knowledge of an authenticated expected peer request.
    ///
    /// `request_disposition(New)` and `reply_empty` record this automatically,
    /// including IDs admitted by empty-enabled restart reconstruction.
    /// This explicit hook also observes an expected authenticated empty request. It
    /// grants no operation, reply, liveness or receive-floor advancement. In
    /// particular, it does not replace `reply_empty`. A crash loses this knowledge,
    /// including empty requests answered
    /// only in memory; restore can enforce only the latest durable history.
    /// # Errors
    /// Requires negotiated sync, a ready window, matching domain, request direction
    /// and exactly the expected ID. It never accepts an authenticated forward gap.
    pub fn observe_request_for_sync(&mut self, request: &Ordinary<P>) -> Result<(), Error> {
        self.ready()?;
        if self
            .record
            .sync
            .is_none_or(|state| state.agreement.mode() != Mode::Negotiated)
            || request.domain != self.record.domain
            || request.header.flags.response()
            || self.next_receive() != Some(request.header.message_id)
        {
            return Err(Error::Drop);
        }
        self.observed_peer_request.set(
            self.observed_peer_request
                .get()
                .max(Some(request.header.message_id)),
        );
        Ok(())
    }

    /// Authenticate and admit a peer sync before allocating an IV or writing state.
    ///
    /// Uses the immutable agreement attached to this window. Valid input is a
    /// complete same-profile peer SK INFORMATIONAL request at ID zero with one sync Notify.
    /// `pending` is the current same-SA local proposal from the initiating
    /// lifecycle; these pure values do not themselves authorize its transmission.
    /// If already synchronizing locally, omitting it cannot unblock ordinary work.
    ///
    /// Supply `pending_inbound` for admitted state-changing work whose result is
    /// not committed. No effects may have escaped its ordinary preparation. Pending
    /// outbound work is detected from the window. Neither kind waits for network
    /// replies: the cutover records OutcomeUncertain and scoped IKE/Child cleanup.
    /// That terminal state has no Delete preparation path yet; local cleanup alone
    /// leaves the peer to its own liveness/expiry or base-protocol invalid-SPI handling.
    /// First fence/settle uncertain storage writes; an unresolved ordinary commit
    /// cannot be guessed absent. Include operation dispositions in the same atomic
    /// consumer transaction and retain already committed outcomes idempotently.
    ///
    /// Successful admission freezes ordinary traffic and old completion tokens.
    /// Cancellation requires latest fenced readback. A response's peer P2 is not
    /// an additional drop floor: a withheld M1 above known ordinary/accepted-peer
    /// history can still be admitted, but only monotone counter maxima are adopted.
    /// M1 = P2 remains admissible until that actual history rejects it.
    /// # Errors
    /// Invalid/unnegotiated/replayed input drops without mutation. Uncertain commits,
    /// terminal disposition and exhaustion release no response or success authority.
    pub fn begin_sync_response(
        &mut self,
        profile: Profile,
        keys: &Keys,
        wire: &[u8],
        pending: Option<&Pending>,
        pending_inbound: Option<&Ordinary<P>>,
    ) -> Result<Ikev2AdmittedSyncResponse<'_, P>, Error> {
        if self.quiescent {
            return Err(Error::CommitUncertain);
        }
        if self.sync_closed {
            return Err(Error::SyncClosed);
        }
        let state = self.record.sync.ok_or(Error::Drop)?;
        if state.disposition == Disposition::OutcomeUncertain {
            return Err(Error::OutcomeUncertain);
        }
        if state.disposition == Disposition::CloseIkeSa {
            return Err(Error::SyncClosed);
        }
        if state.agreement.mode() != Mode::Negotiated {
            return Err(Error::Drop);
        }
        let durable_pending = self
            .record
            .sync_recovery()
            .and_then(|record| record.pending());
        if self.record.sync_recovery().is_some()
            && pending.is_some_and(|value| Some(*value) != durable_pending)
        {
            return Err(Error::Drop);
        }
        let pending = durable_pending.as_ref().or(pending);
        let opened = sync_packet::open_request(&self.record.domain, profile, keys, wire)?;
        let mut counters = Counters::new(
            self.record.next_send.unwrap_or(u32::MAX),
            self.next_receive().unwrap_or(u32::MAX),
        );
        counters.highest_local_request = state.highest_local_request;
        counters.highest_peer_request = state
            .highest_peer_request
            .max(self.observed_peer_request.get());
        counters.highest_local_proposal = state.highest_local_proposal;
        counters.highest_peer_proposal = state.highest_peer_proposal;
        if let Some(inbound) = pending_inbound {
            if self.request_disposition(inbound).map_err(|_| Error::Drop)?
                != Ikev2OrdinaryRequestDisposition::New
            {
                return Err(Error::Drop);
            }
            counters.highest_peer_request = counters
                .highest_peer_request
                .max(Some(inbound.header.message_id));
        }
        let (next, response) = state
            .agreement
            .evaluate_request(
                &opened.header,
                PayloadChain::new(opened.first, &opened.cleartext),
                counters,
                pending,
            )
            .map_err(|error| {
                if error == RuleError::Drop {
                    Error::Drop
                } else {
                    Error::SyncRule(error)
                }
            })?;
        let uncertain = pending_inbound.is_some()
            || self.receive.pending.borrow().is_some()
            || self
                .record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none());
        let disposition = if uncertain {
            Disposition::OutcomeUncertain
        } else if pending.is_some() || state.disposition == Disposition::AwaitLocalSync {
            Disposition::AwaitLocalSync
        } else {
            Disposition::Continue
        };
        let mut record = self.record.clone();
        record.generation = record.generation.checked_add(1).ok_or(Error::Exhausted)?;
        P::retain_local_evidence(self, &mut record)?;
        record.next_send = Some(next.next_send);
        record.next_receive = Some(next.next_receive);
        // Retired ordinary bytes cannot bypass the declared receive window, act as
        // new probes or cause a historical outcome to be applied again.
        record.outbound = None;
        record.inbound = None;
        let sync = Ikev2SyncResponderRecord::<P>::from_parts(
            state.agreement,
            next.highest_local_request,
            next.highest_peer_request,
            next.highest_local_proposal,
            next.highest_peer_proposal,
            disposition,
            record.sync.ok_or(Error::InvalidRecord)?.packet_evidence,
        )?;
        sync.validate(&record)?;
        record.sync = Some(sync);
        if disposition == Disposition::OutcomeUncertain {
            if let Some(recovery) = &mut record.recovery {
                recovery.status = super::Ikev2SyncRecoveryStatus::Closed;
            }
        }
        if let Some(recovery) = &record.recovery {
            recovery.validate(&record)?;
        }
        self.quiescent = true;
        Ok(Ikev2AdmittedSyncResponse {
            window: self,
            record,
            response,
        })
    }

    /// Consume one current-runtime, current-generation sync response permission.
    ///
    /// Release promptly after the exact durable cutover, before any later commit.
    /// A terminal response also releases its scoped-cleanup disposition. It never
    /// means pending mutation success or fresh liveness. The bytes are not retained
    /// in a replay cache; a lost response requires the peer's higher fresh proposal.
    /// # Errors
    /// Refuses old/foreign tokens and unresolved transitions without releasing bytes.
    pub fn release_sync_response(
        &mut self,
        commit: Ikev2SyncCommit,
    ) -> Result<Ikev2SyncResponse, Error> {
        if self.quiescent
            || self.sync_closed
            || !Arc::ptr_eq(&self.instance, &commit.instance)
            || self.record.generation != commit.generation
        {
            return Err(Error::StaleCompletion);
        }
        Ok(Ikev2SyncResponse {
            bytes: commit.response,
            disposition: commit.disposition,
        })
    }
}

/// Exclusive authenticated admission, freezing ordinary work before IV allocation.
#[must_use = "seal and durably commit this cutover; cancellation requires fenced readback"]
pub struct Ikev2AdmittedSyncResponse<'a, P: RecoveryProfile = Gcm> {
    window: &'a mut Window<P>,
    record: Record<P>,
    response: Sync,
}

impl<'a, P: RecoveryProfile> Ikev2AdmittedSyncResponse<'a, P> {
    fn prepare_with(
        mut self,
        profile: Profile,
        keys: &Keys,
        sealing: P::Sealing<'_>,
    ) -> Result<Ikev2PreparedSyncResponse<'a, P>, Error> {
        let response =
            sync_packet::seal_response(&self.record.domain, profile, keys, sealing, self.response)?;
        let sync = self.record.sync.as_mut().ok_or(Error::InvalidRecord)?;
        P::retain_sealed(&mut sync.packet_evidence, &response)?;
        self.window
            .remember_prepared(&self.record, super::reconcile::Kind::Sync);
        Ok(Ikev2PreparedSyncResponse {
            window: self.window,
            record: self.record,
            response: response.into_wire(),
        })
    }
}

/// Cutover storage inputs without response bytes or effect authority.
#[must_use = "commit the exact candidate before releasing the sync response or cleanup"]
pub struct Ikev2PreparedSyncResponse<'a, P: RecoveryProfile = Gcm> {
    window: &'a mut Window<P>,
    record: Record<P>,
    response: Bytes,
}

impl<P: RecoveryProfile> Ikev2PreparedSyncResponse<'_, P> {
    /// Candidate floors/history/disposition, atomically persisted with SA and operations.
    pub const fn record(&self) -> &Record<P> {
        &self.record
    }

    /// Acknowledge exact durable cutover; equality alone does not prove persistence.
    ///
    /// On uncertainty do not call this: settle/fence all older writes and reconcile
    /// the latest window and IV records in place (restore after process restart).
    /// Reading back a landed cutover never recreates
    /// this response permission, and the duplicate peer request is silently dropped.
    /// # Errors
    /// A mismatching acknowledgement leaves the window quiescent for readback.
    pub fn commit_after_durable(self, committed: &Record<P>) -> Result<Ikev2SyncCommit, Error> {
        if committed != &self.record {
            return Err(Error::CommitMismatch);
        }
        self.window.witness = None;
        let disposition = self.record.sync.ok_or(Error::InvalidRecord)?.disposition;
        self.window.record = self.record;
        self.window.observed_peer_request.set(None);
        self.window.quiescent = false;
        self.window.adopt_receive_boundary()?;
        Ok(Ikev2SyncCommit {
            instance: Arc::clone(&self.window.instance),
            generation: self.window.record.generation,
            response: self.response,
            disposition,
        })
    }
}

/// Single-use post-commit permission, bound to this runtime and cutover generation.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2SyncCommit;
/// fn duplicate(commit: Ikev2SyncCommit) { let _ = commit.clone(); }
/// ```
#[must_use = "consume with release_sync_response before a later commit"]
pub struct Ikev2SyncCommit {
    instance: Arc<()>,
    generation: u64,
    response: Bytes,
    disposition: Disposition,
}

/// One released sync reply and its committed ordinary-window disposition.
pub struct Ikev2SyncResponse {
    bytes: Bytes,
    disposition: Disposition,
}

impl Ikev2SyncResponse {
    /// Consume for one send and idempotent disposition handling; do not cache or
    /// retransmit a sync reply in response to a duplicate request.
    pub fn into_parts(self) -> (Bytes, Disposition) {
        (self.bytes, self.disposition)
    }
}

impl<'a> Ikev2AdmittedSyncResponse<'a, Gcm> {
    /// Seal a fixed nonce-echoing response with one committed ordinary allocation.
    ///
    /// No block is reserved here. If no active IV remains, use the existing bounded
    /// reservation retry guard for this same genuine peer-recovery operation:
    /// persist each charge, keep its deadline/backoff across restart and allow at
    /// most three fresh blocks. Duplicates cannot create or refresh that budget.
    /// Persist one guard identity per SA key epoch and peer recovery event with
    /// the enclosing window state; reuse it through every re-admission until a
    /// cutover lands. A Closed guard means no reply. The caller must supply an
    /// Ordinary allocation: this token does not carry its purpose, and supplying
    /// Control would spend the rekey/Delete reserve.
    /// This API grants no send permission; sealing failure burns the allocation
    /// and leaves the window quiescent until fenced readback.
    /// # Errors
    /// Rejects another SA's allocation or keys and any admitted sealing failure.
    pub fn prepare(
        self,
        profile: Profile,
        keys: &Keys,
        allocation: Ikev2AesGcmIvAllocation<'_>,
    ) -> Result<Ikev2PreparedSyncResponse<'a, Gcm>, Error> {
        self.prepare_with(profile, keys, allocation)
    }
}

impl<'a> Ikev2AdmittedSyncResponse<'a, super::Ikev2CbcRecoveryProfile> {
    /// Seal using one fresh admitted random CBC IV, without an allocation token.
    /// Persist the exact candidate before releasing its one-use action.
    /// # Errors
    /// Key/profile mismatch or provider failure retains quiescence for fenced readback.
    pub fn prepare(
        self,
        profile: Profile,
        keys: &Keys,
    ) -> Result<Ikev2PreparedSyncResponse<'a, super::Ikev2CbcRecoveryProfile>, Error> {
        self.prepare_with(profile, keys, ())
    }
}
