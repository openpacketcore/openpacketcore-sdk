use super::profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use std::sync::Arc;

use bytes::Bytes;

use super::{
    sync_packet, Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2SyncAttemptRecord as Attempt,
    Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
    Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryRecord as Recovery,
    Ikev2SyncRecoveryStatus as Status, Ikev2WindowError as Error,
};
use crate::{
    crypto_module, Ikev2AesGcmIvAllocation, Ikev2MessageIdSync as Sync,
    Ikev2MessageIdSyncCounters as Counters, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncPending as Pending, Ikev2MessageIdSyncRuleError as RuleError,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys, PayloadChain,
};

impl<P: RecoveryProfile> Window<P> {
    fn sync_open(&self) -> Result<(), Error> {
        if self.quiescent {
            return Err(Error::CommitUncertain);
        }
        if self.sync_closed
            || self
                .record
                .sync_state()
                .is_some_and(|state| state.disposition() == Disposition::CloseIkeSa)
        {
            return Err(Error::SyncClosed);
        }
        let state = self.record.sync_state().ok_or(Error::Drop)?;
        if state.disposition() == Disposition::OutcomeUncertain {
            return Err(Error::OutcomeUncertain);
        }
        if state.agreement().mode() != Mode::Negotiated {
            return Err(Error::Drop);
        }
        Ok(())
    }

    fn sync_counters(&self) -> Result<Counters, Error> {
        let state = self.record.sync_state().ok_or(Error::Drop)?;
        let mut counters = Counters::new(
            self.record.next_send.ok_or(Error::SyncClosed)?,
            self.next_receive().ok_or(Error::SyncClosed)?,
        );
        counters.highest_local_request = state.highest_local_request();
        counters.highest_peer_request = state
            .highest_peer_request()
            .max(self.observed_peer_request.get());
        counters.highest_local_proposal = state.highest_local_proposal();
        counters.highest_peer_proposal = state.highest_peer_proposal();
        Ok(counters)
    }

    fn sync_clock(&mut self, policy: Policy, clock: Clock) -> Result<(), Error> {
        let last = if self
            .record
            .sync_recovery()
            .is_some_and(|record| record.policy() == policy)
        {
            self.sync_last_observed_unix_ms
                .unwrap_or(policy.started().unix_ms())
        } else {
            policy.started().unix_ms()
        };
        if self.sync_closed
            || clock.epoch() != policy.started().epoch()
            || clock.unix_ms() < last.max(policy.started().unix_ms())
            || clock.unix_ms() >= policy.deadline_unix_ms()
        {
            self.sync_closed = true;
            self.sync_live = false;
            return Err(Error::SyncClosed);
        }
        self.sync_last_observed_unix_ms = Some(clock.unix_ms());
        Ok(())
    }

    /// Check the active event's fixed UTC deadline and persistent clock epoch.
    ///
    /// Schedule this at the deadline even when no peer traffic arrives. A clock
    /// step, rollback or expiry latches closure; call `close_sync` to persist it.
    /// Retain step/terminal knowledge across restart until latest fenced readback
    /// proves closure. Packet rejection never extends the deadline or budget.
    /// # Errors
    /// No active event drops; uncertain storage stays quiescent; expiry is terminal.
    pub fn check_sync_deadline(&mut self, clock: Clock) -> Result<(), Error> {
        self.sync_open()?;
        let recovery = self.record.sync_recovery().ok_or(Error::Drop)?;
        if recovery.status() != Status::Pending {
            return Err(Error::Drop);
        }
        self.sync_clock(recovery.policy(), clock)
    }

    /// Admit a genuinely new local recovery event before allocating an IV.
    ///
    /// Resolve pending ordinary mutations first. Supply `pending_inbound` for
    /// admitted work not yet represented in the record; it causes refusal. A
    /// replay or timeout is not a new event. After success this runtime freezes,
    /// and cancellation requires fenced readback. No caller nonce/RNG is accepted.
    /// # Errors
    /// Requires negotiated sync, resolved work, a new monotone event identity,
    /// usable counters and an unexpired clock/policy. Never downgrades to fallback.
    pub fn begin_sync(
        &mut self,
        policy: Policy,
        clock: Clock,
        pending_inbound: Option<&Ordinary<P>>,
    ) -> Result<Ikev2AdmittedSyncInitiation<'_, P>, Error> {
        self.ready()?;
        self.sync_open()?;
        if pending_inbound.is_some()
            || self.receive.pending.borrow().is_some()
            || self
                .record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none())
        {
            return Err(Error::RequestOutstanding);
        }
        if self
            .record
            .sync_recovery()
            .is_some_and(|old| policy.operation() <= old.policy().operation())
        {
            return Err(Error::Drop);
        }
        self.sync_clock(policy, clock)?;
        self.admit_sync(policy, clock, Vec::new())
    }

    /// Supersede a lost or uncertain attempt with a higher fresh proposal.
    ///
    /// Uses the same persisted event and policy. Restore never refunds an attempt
    /// or authorizes old request bytes. This API intentionally offers no exact
    /// sync retransmission: request loss and response loss both use a higher retry.
    /// # Errors
    /// Refuses an early retry, exhausted budget, expired/stepped time or unresolved
    /// storage. Check backoff before reserving a block; never reserve ahead.
    pub fn retry_sync(
        &mut self,
        clock: Clock,
    ) -> Result<Ikev2AdmittedSyncInitiation<'_, P>, Error> {
        self.check_sync_deadline(clock)?;
        let recovery = self.record.sync_recovery().ok_or(Error::Drop)?;
        let last = recovery.attempts().last().ok_or(Error::InvalidRecord)?;
        let Some(next_time) = last
            .prepared_unix_ms()
            .checked_add(recovery.policy().retry_delay_ms())
        else {
            self.sync_closed = true;
            return Err(Error::SyncClosed);
        };
        if clock.unix_ms() < next_time {
            return Err(Error::SyncBackoff);
        }
        if recovery.attempts().len() >= usize::from(recovery.policy().max_attempts()) {
            self.sync_closed = true;
            self.sync_live = false;
            return Err(Error::SyncClosed);
        }
        self.admit_sync(recovery.policy(), clock, recovery.attempts().to_vec())
    }

    fn admit_sync(
        &mut self,
        policy: Policy,
        clock: Clock,
        attempts: Vec<Attempt<P>>,
    ) -> Result<Ikev2AdmittedSyncInitiation<'_, P>, Error> {
        self.record
            .generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let counters = self.sync_counters().inspect_err(|error| {
            if *error == Error::SyncClosed {
                self.sync_closed = true;
            }
        })?;
        let agreement = self.record.sync_state().ok_or(Error::Drop)?.agreement();
        // The zero nonce is only an arithmetic placeholder, never a send input.
        let proposal = agreement.propose(counters, [0; 4]).map_err(|_| {
            self.sync_closed = true;
            Error::SyncClosed
        })?;
        self.quiescent = true;
        self.sync_live = false;
        Ok(Ikev2AdmittedSyncInitiation {
            window: self,
            policy,
            clock,
            attempts,
            proposal,
            counters,
        })
    }

    /// Authenticate the live proposal's response and prepare its durable result.
    ///
    /// Check time on admission, exact nonce/SA/class and both lower bounds, then
    /// merge with any concurrent peer cutover. All ordinary traffic stays blocked
    /// until this result commits. A landed result remains recovered even if storage
    /// acknowledges after expiry or a clock step: the response was admitted in time.
    /// # Errors
    /// Restored/unsent/superseded proposals and malformed or duplicate replies drop.
    /// Expiry/exhaustion closes the event, never extends it or changes its mode.
    pub fn complete_sync(
        &mut self,
        profile: Profile,
        keys: &Keys,
        wire: &[u8],
        clock: Clock,
    ) -> Result<Ikev2PreparedSyncInitiation<'_, P>, Error> {
        self.sync_open()?;
        let Some(recovery) = self.record.sync_recovery() else {
            return Err(Error::Drop);
        };
        let Some(pending) = recovery.pending() else {
            return Err(Error::Drop);
        };
        self.check_sync_deadline(clock)?;
        if !self.sync_live {
            return Err(Error::Drop);
        }
        let opened =
            sync_packet::open_message(&self.record.domain, profile, keys, wire, true, true)?;
        let state = self.record.sync_state().ok_or(Error::Drop)?;
        let next = state
            .agreement()
            .evaluate_response(
                &opened.header,
                PayloadChain::new(opened.first, &opened.cleartext),
                self.sync_counters()?,
                &pending,
            )
            .map_err(|error| {
                if error == RuleError::Drop {
                    Error::Drop
                } else {
                    self.sync_closed = true;
                    Error::SyncClosed
                }
            })?;
        let mut record = self.record.clone();
        record.generation = record.generation.checked_add(1).ok_or(Error::Exhausted)?;
        record.next_send = Some(next.next_send);
        record.next_receive = Some(next.next_receive);
        P::retain_local_evidence(self, &mut record)?;
        record.outbound = None;
        record.inbound = None;
        record
            .sync
            .as_mut()
            .ok_or(Error::InvalidRecord)?
            .disposition = Disposition::Continue;
        let recovery = record.recovery.as_mut().ok_or(Error::InvalidRecord)?;
        recovery.last_observed_unix_ms = clock.unix_ms();
        recovery.status = Status::Recovered;
        record
            .recovery
            .as_ref()
            .ok_or(Error::InvalidRecord)?
            .validate(&record)?;
        self.remember_prepared(&record, super::reconcile::Kind::Sync);
        self.sync_live = false;
        Ok(Ikev2PreparedSyncInitiation {
            window: self,
            record,
            action: Ikev2SyncInitiatorAction::Recovered,
        })
    }

    /// Prepare terminal scoped IKE/Child closure for pending synchronization.
    ///
    /// Use after deadline, clock step, budget or protocol exhaustion, or a consumer
    /// decision to abandon this active event. Any AwaitLocalSync window can close,
    /// including one entered through a pure pending proposal without an initiating
    /// event record. Persist before cleanup effects. A stored terminal record is
    /// idempotent cleanup history, not a new callback.
    /// # Errors
    /// Refuses uncertain storage, already committed closure or no pending sync/event.
    pub fn close_sync(&mut self) -> Result<Ikev2PreparedSyncInitiation<'_, P>, Error> {
        if self.quiescent {
            return Err(Error::CommitUncertain);
        }
        let state = self.record.sync_state().ok_or(Error::Drop)?;
        if state.disposition() == Disposition::OutcomeUncertain {
            return Err(Error::OutcomeUncertain);
        }
        if state.disposition() == Disposition::CloseIkeSa {
            return Err(Error::SyncClosed);
        }
        if !self.sync_closed
            && state.disposition() != Disposition::AwaitLocalSync
            && self
                .record
                .sync_recovery()
                .is_none_or(|record| record.status() != Status::Pending)
        {
            return Err(Error::Drop);
        }
        let mut record = self.record.clone();
        record.generation = record.generation.checked_add(1).ok_or(Error::Exhausted)?;
        record
            .sync
            .as_mut()
            .ok_or(Error::InvalidRecord)?
            .disposition = Disposition::CloseIkeSa;
        // Keep exhausted MAX history for restore; closure forbids all replay.
        P::retain_local_evidence(self, &mut record)?;
        if record.next_send.is_some() {
            record.outbound = None;
        }
        if record.next_receive.is_some() {
            record.inbound = None;
        }
        if let Some(recovery) = &mut record.recovery {
            recovery.status = Status::Closed;
            recovery.last_observed_unix_ms = recovery
                .last_observed_unix_ms
                .max(self.sync_last_observed_unix_ms.unwrap_or(0));
        }
        self.remember_prepared(&record, super::reconcile::Kind::Sync);
        self.sync_live = false;
        Ok(Ikev2PreparedSyncInitiation {
            window: self,
            record,
            action: Ikev2SyncInitiatorAction::CloseIkeSa,
        })
    }

    /// Consume a one-use action from this runtime and its current commit generation.
    ///
    /// Request release rechecks time; an expired/stepped clock emits no bytes and
    /// requires `close_sync`. Recovered means committed counter synchronization,
    /// not application-mutation success or repeatable liveness evidence.
    /// # Errors
    /// Refuses foreign/retired tokens, uncertain transitions and expired requests.
    pub fn release_sync_action(
        &mut self,
        commit: Ikev2SyncInitiatorCommit,
        clock: Clock,
    ) -> Result<Ikev2SyncInitiatorAction, Error> {
        if self.quiescent
            || !Arc::ptr_eq(&self.instance, &commit.instance)
            || self.record.generation != commit.generation
        {
            return Err(Error::StaleCompletion);
        }
        if matches!(commit.action, Ikev2SyncInitiatorAction::SendRequest(_)) {
            self.check_sync_deadline(clock)?;
            self.sync_live = true;
        }
        Ok(commit.action)
    }
}

/// Exclusive local attempt admission; cancellation requires latest fenced readback.
#[must_use = "prepare and commit the attempt; dropping keeps the window quiescent"]
pub struct Ikev2AdmittedSyncInitiation<'a, P: RecoveryProfile = Gcm> {
    window: &'a mut Window<P>,
    policy: Policy,
    clock: Clock,
    attempts: Vec<Attempt<P>>,
    proposal: Pending,
    counters: Counters,
}
impl<'a, P: RecoveryProfile> Ikev2AdmittedSyncInitiation<'a, P> {
    fn prepare_with(
        mut self,
        profile: Profile,
        keys: &Keys,
        sealing: P::Sealing<'_>,
    ) -> Result<Ikev2PreparedSyncInitiation<'a, P>, Error> {
        self.window.record.domain.check(profile, keys)?;
        let mut chosen = None;
        for _ in 0..4 {
            let mut nonce = [0; 4];
            crypto_module::with_entropy_operation(|module| module.fill_random(&mut nonce))
                .map_err(|_| Error::SyncEntropy)?;
            if self
                .attempts
                .iter()
                .all(|attempt| attempt.pending.notification().nonce() != nonce)
            {
                chosen = Some(nonce);
                break;
            }
        }
        let nonce = chosen.ok_or(Error::SyncEntropy)?;
        let value = self.proposal.notification();
        let value = Sync::new(
            nonce,
            value.expected_send_req_message_id(),
            value.expected_recv_req_message_id(),
        );
        let pending =
            Pending::from_persisted(self.proposal.sa(), value).map_err(|_| Error::InvalidRecord)?;
        let request = sync_packet::seal_message(
            &self.window.record.domain,
            profile,
            keys,
            sealing,
            value,
            false,
        )?;
        self.attempts.push(Attempt::<P>::from_parts(
            pending,
            self.clock.unix_ms(),
            request.wire().clone(),
        )?);
        let recovery = Recovery::<P>::from_parts(
            self.policy,
            self.clock.unix_ms(),
            self.attempts,
            Status::Pending,
        )?;
        let mut record = self.window.record.clone();
        record.generation = record.generation.checked_add(1).ok_or(Error::Exhausted)?;
        record.next_send = Some(value.expected_send_req_message_id());
        record.next_receive = Some(value.expected_recv_req_message_id());
        P::retain_local_evidence(self.window, &mut record)?;
        record.outbound = None;
        record.inbound = None;
        let sync = record.sync.as_mut().ok_or(Error::InvalidRecord)?;
        P::retain_sealed(&mut sync.packet_evidence, &request)?;
        sync.highest_local_proposal = Some(value.expected_send_req_message_id());
        sync.highest_peer_request = self.counters.highest_peer_request;
        sync.disposition = Disposition::AwaitLocalSync;
        sync.validate(&record)?;
        recovery.validate(&record)?;
        record.recovery = Some(recovery);
        self.window
            .remember_prepared(&record, super::reconcile::Kind::Sync);
        Ok(Ikev2PreparedSyncInitiation {
            window: self.window,
            record,
            action: Ikev2SyncInitiatorAction::SendRequest(request.into_wire()),
        })
    }
}

/// Atomic proposal/result/close storage inputs without effect permission.
#[must_use = "persist the exact record before releasing an action"]
pub struct Ikev2PreparedSyncInitiation<'a, P: RecoveryProfile = Gcm> {
    window: &'a mut Window<P>,
    record: Record<P>,
    action: Ikev2SyncInitiatorAction,
}
impl<P: RecoveryProfile> Ikev2PreparedSyncInitiation<'_, P> {
    /// Persist all fields atomically with the same fenced SA/event/operation state.
    pub const fn record(&self) -> &Record<P> {
        &self.record
    }
    /// Acknowledge the exact durable record. Equality alone is not storage proof.
    ///
    /// Uncertainty requires fencing old writes and reconciling latest records in
    /// place (restoring after process restart); no old send token survives either.
    /// SendRequest requires a
    /// fresh clock sample, not the preparation timestamp. A late/stepped request
    /// acknowledgement adopts the landed record but latches closure and releases
    /// no request; `close_sync` can persist terminal disposition. Retain step/expiry
    /// knowledge for pending events across readback. A landed Recovered result
    /// stays recovered regardless of acknowledgement time; its authenticated
    /// response already passed the deadline check on admission. CloseIkeSa also
    /// needs no clock check. Neither action authorizes sending a new request.
    /// # Errors
    /// Mismatch leaves quiescence; an expired request requires scoped closure.
    pub fn commit_after_durable(
        self,
        committed: &Record<P>,
        clock: Clock,
    ) -> Result<Ikev2SyncInitiatorCommit, Error> {
        if committed != &self.record {
            return Err(Error::CommitMismatch);
        }
        self.window.witness = None;
        let policy = self.record.sync_recovery().map(|record| record.policy());
        let check_clock = matches!(self.action, Ikev2SyncInitiatorAction::SendRequest(_));
        self.window.record = self.record;
        self.window.quiescent = false;
        self.window.observed_peer_request.set(None);
        self.window.sync_live = false;
        self.window.adopt_receive_boundary()?;
        if check_clock {
            self.window
                .sync_clock(policy.ok_or(Error::InvalidRecord)?, clock)?;
        }
        Ok(Ikev2SyncInitiatorCommit {
            instance: Arc::clone(&self.window.instance),
            generation: self.window.record.generation,
            action: self.action,
        })
    }
}

/// Single-use action permission, bound to one runtime and current commit generation.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2SyncInitiatorCommit;
/// fn duplicate(token: Ikev2SyncInitiatorCommit) { let _ = token.clone(); }
/// ```
#[must_use = "release with the matching live window before another commit"]
pub struct Ikev2SyncInitiatorCommit {
    instance: Arc<()>,
    generation: u64,
    action: Ikev2SyncInitiatorAction,
}

/// One committed initiating action; never replay a result as a new outcome.
#[non_exhaustive]
pub enum Ikev2SyncInitiatorAction {
    /// Send these exact bytes once. Loss requires a fresh higher bounded proposal.
    SendRequest(Bytes),
    /// Counter synchronization committed; ordinary traffic may resume at its floor.
    Recovered,
    /// Perform idempotent scoped IKE/Child cleanup; never switch to fallback.
    CloseIkeSa,
}

impl<'a> Ikev2AdmittedSyncInitiation<'a, Gcm> {
    /// Draw admitted entropy and seal with one committed Ordinary IV allocation.
    ///
    /// At most four entropy draws; repeat nonces from this event's bounded history are
    /// rejected. No caller RNG/nonce fallback exists. If a new block is required,
    /// use the existing durably charged reservation retry guard for this same
    /// operation, fixed deadline/clock epoch and at most three fresh blocks.
    /// Do not reserve ahead. The caller must choose Ordinary; the allocation token
    /// carries no purpose, so Control would spend rekey/Delete headroom on sync.
    /// # Errors
    /// Entropy/provider failure or repeated output emits no request. Sealing burns
    /// its allocation. Any failure retains quiescence until fenced readback.
    pub fn prepare(
        self,
        profile: Profile,
        keys: &Keys,
        allocation: Ikev2AesGcmIvAllocation<'_>,
    ) -> Result<Ikev2PreparedSyncInitiation<'a, Gcm>, Error> {
        self.prepare_with(profile, keys, allocation)
    }
}

impl<'a> Ikev2AdmittedSyncInitiation<'a, super::Ikev2CbcRecoveryProfile> {
    /// Seal using one fresh admitted random CBC IV, without an allocation token.
    /// Persist the exact candidate before releasing its one-use action.
    /// # Errors
    /// Key/profile mismatch or provider failure retains quiescence for fenced readback.
    pub fn prepare(
        self,
        profile: Profile,
        keys: &Keys,
    ) -> Result<Ikev2PreparedSyncInitiation<'a, super::Ikev2CbcRecoveryProfile>, Error> {
        self.prepare_with(profile, keys, ())
    }
}
