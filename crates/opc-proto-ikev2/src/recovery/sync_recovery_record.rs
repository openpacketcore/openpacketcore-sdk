use bytes::Bytes;

use super::{
    sync_packet, Ikev2CommittedWindowRecord as Record, Ikev2SyncDisposition as Disposition,
    Ikev2WindowError as Error,
};
use crate::{
    decode_ikev2_message_id_sync_notify, Ikev2MessageIdSyncPending as Pending, Ikev2NotifyPayload,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys, PayloadChain, PayloadType,
    GENERIC_PAYLOAD_HEADER_LEN, HEADER_LEN,
};

/// UTC milliseconds since the Unix epoch, with persistent clock-step identity.
///
/// Use CLOCK_REALTIME semantics, not process uptime. The consumer's clock service
/// must change `epoch` on every detected forward/backward step, or loss of clock
/// continuity across restart, and retain that change across further restarts.
/// Never relabel a sample with the old epoch to revive an expired operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2SyncClock {
    unix_ms: u64,
    epoch: u64,
}
impl Ikev2SyncClock {
    /// Supply a clock-service sample; this constructor does not read a clock.
    pub const fn new(unix_ms: u64, epoch: u64) -> Self {
        Self { unix_ms, epoch }
    }
    /// UTC time in milliseconds since the Unix epoch.
    pub const fn unix_ms(self) -> u64 {
        self.unix_ms
    }
    /// Persistent continuity identity, changed on a step in either direction.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Fixed budget for one genuine recovery event within a fenced IKE key epoch.
///
/// The consumer allocates monotonically increasing event identities. A peer
/// replay, timeout or restart cannot create a replacement event or policy.
/// The deadline bounds request transmission, response admission and durable
/// acknowledgement. A late or stepped acknowledgement cannot publish success.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2SyncRecoveryPolicy {
    operation: u64,
    started: Ikev2SyncClock,
    deadline_unix_ms: u64,
    max_attempts: u8,
    retry_delay_ms: u64,
}
impl Ikev2SyncRecoveryPolicy {
    /// Fix the clock, deadline, positive retry delay and at most three proposals.
    /// # Errors
    /// Rejects a reversed/empty lifetime, zero delay or a budget outside 1..=3.
    pub fn new(
        operation: u64,
        started: Ikev2SyncClock,
        deadline_unix_ms: u64,
        max_attempts: u8,
        retry_delay_ms: u64,
    ) -> Result<Self, Error> {
        if started.unix_ms >= deadline_unix_ms
            || !(1..=3).contains(&max_attempts)
            || retry_delay_ms == 0
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            operation,
            started,
            deadline_unix_ms,
            max_attempts,
            retry_delay_ms,
        })
    }
    /// Stable consumer event identity; retries never replace it.
    pub const fn operation(self) -> u64 {
        self.operation
    }
    /// Original clock sample, including its persistent continuity epoch.
    pub const fn started(self) -> Ikev2SyncClock {
        self.started
    }
    /// Fixed exclusive deadline, never extended by packets or restart.
    pub const fn deadline_unix_ms(self) -> u64 {
        self.deadline_unix_ms
    }
    /// Maximum proposals, including the initial attempt and uncertain ones.
    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
    /// Minimum delay between proposal preparations; the caller schedules the wait.
    pub const fn retry_delay_ms(self) -> u64 {
        self.retry_delay_ms
    }
}

/// One complete persisted attempt; its bytes are storage inputs, not send permission.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SyncAttemptRecord {
    pub(super) pending: Pending,
    pub(super) prepared_unix_ms: u64,
    pub(super) request: Bytes,
}
impl Ikev2SyncAttemptRecord {
    /// Rebuild stored inputs. Window restoration authenticates and correlates bytes.
    /// # Errors
    /// Rejects an empty packet; remaining checks need the enclosing SA/history.
    pub fn from_persisted(
        pending: Pending,
        prepared_unix_ms: u64,
        request: Bytes,
    ) -> Result<Self, Error> {
        if request.is_empty() {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            pending,
            prepared_unix_ms,
            request,
        })
    }
    /// Pure proposal for persistence and simultaneous counter calculations.
    pub const fn pending(&self) -> Pending {
        self.pending
    }
    /// Original attempt preparation time, used for positive retry delay.
    pub const fn prepared_unix_ms(&self) -> u64 {
        self.prepared_unix_ms
    }
    /// Exact protected storage bytes. Reading them does not authorize transmission.
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
}

/// Durable initiating-event state; completed records retain consumed history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2SyncRecoveryStatus {
    /// Ordinary work stays blocked; only the current live proposal can complete.
    Pending,
    /// Authenticated result was committed; restoration cannot repeat its effect.
    Recovered,
    /// Terminal scoped IKE/Child close, never fallback or a refreshed event budget.
    Closed,
}

/// Initiating history persisted atomically with the ordinary and responder state.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SyncRecoveryRecord {
    pub(super) policy: Ikev2SyncRecoveryPolicy,
    pub(super) last_observed_unix_ms: u64,
    pub(super) attempts: Vec<Ikev2SyncAttemptRecord>,
    pub(super) status: Ikev2SyncRecoveryStatus,
}
impl Ikev2SyncRecoveryRecord {
    /// Rebuild trusted latest fields without refunding an attempt or replacing policy.
    /// # Errors
    /// Rejects empty/oversized history, repeated nonces, non-increasing proposals,
    /// regressing receive floors, inconsistent times or a missing positive delay.
    pub fn from_persisted(
        policy: Ikev2SyncRecoveryPolicy,
        last_observed_unix_ms: u64,
        attempts: Vec<Ikev2SyncAttemptRecord>,
        status: Ikev2SyncRecoveryStatus,
    ) -> Result<Self, Error> {
        if attempts.is_empty()
            || attempts.len() > usize::from(policy.max_attempts)
            || (status != Ikev2SyncRecoveryStatus::Closed
                && last_observed_unix_ms >= policy.deadline_unix_ms)
        {
            return Err(Error::InvalidRecord);
        }
        for (index, attempt) in attempts.iter().enumerate() {
            if attempt.prepared_unix_ms < policy.started.unix_ms
                || attempt.prepared_unix_ms >= policy.deadline_unix_ms
                || attempt.prepared_unix_ms > last_observed_unix_ms
            {
                return Err(Error::InvalidRecord);
            }
            let value = attempt.pending.notification();
            for prior in &attempts[..index] {
                let old = prior.pending.notification();
                if old.nonce() == value.nonce()
                    || old.expected_send_req_message_id() >= value.expected_send_req_message_id()
                    || old.expected_recv_req_message_id() > value.expected_recv_req_message_id()
                    || prior.pending.sa() != attempt.pending.sa()
                    || prior
                        .prepared_unix_ms
                        .checked_add(policy.retry_delay_ms)
                        .is_none_or(|next| next > attempt.prepared_unix_ms)
                {
                    return Err(Error::InvalidRecord);
                }
            }
        }
        Ok(Self {
            policy,
            last_observed_unix_ms,
            attempts,
            status,
        })
    }
    /// Original immutable event policy.
    pub const fn policy(&self) -> Ikev2SyncRecoveryPolicy {
        self.policy
    }
    /// All consumed attempt inputs, including abandoned nonces and exact bytes.
    pub fn attempts(&self) -> &[Ikev2SyncAttemptRecord] {
        &self.attempts
    }
    /// Last durably recorded time, not a refreshed deadline.
    pub const fn last_observed_unix_ms(&self) -> u64 {
        self.last_observed_unix_ms
    }
    /// Durable pending/completed/terminal state.
    pub const fn status(&self) -> Ikev2SyncRecoveryStatus {
        self.status
    }
    /// Current pending arithmetic input; it is not runtime send/completion authority.
    pub fn pending(&self) -> Option<Pending> {
        (self.status == Ikev2SyncRecoveryStatus::Pending)
            .then(|| self.attempts.last().map(|attempt| attempt.pending))
            .flatten()
    }

    pub(super) fn validate(&self, record: &Record) -> Result<(), Error> {
        let sync = record.sync_state().ok_or(Error::InvalidRecord)?;
        let last = self.attempts.last().ok_or(Error::InvalidRecord)?;
        let proposal = last.pending.notification();
        if last.pending.sa() != sync.agreement().sa() {
            return Err(Error::DomainMismatch);
        }
        if sync.highest_local_proposal() != Some(proposal.expected_send_req_message_id())
            || record
                .next_send
                .is_some_and(|floor| floor < proposal.expected_send_req_message_id())
            || record
                .next_receive
                .is_some_and(|floor| floor < proposal.expected_recv_req_message_id())
        {
            return Err(Error::InvalidRecord);
        }
        let valid = match self.status {
            Ikev2SyncRecoveryStatus::Pending => {
                sync.disposition() == Disposition::AwaitLocalSync
                    && record.next_send.is_some()
                    && record.next_receive.is_some()
                    && record.outbound.is_none()
                    && record.inbound.is_none()
            }
            Ikev2SyncRecoveryStatus::Recovered => sync.disposition() == Disposition::Continue,
            Ikev2SyncRecoveryStatus::Closed => matches!(
                sync.disposition(),
                Disposition::CloseIkeSa | Disposition::OutcomeUncertain
            ),
        };
        if !valid {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    pub(super) fn validate_packets(
        &self,
        record: &Record,
        profile: Profile,
        keys: &Keys,
        iv_end: u64,
    ) -> Result<(), Error> {
        self.validate(record)?;
        let mut previous_iv = None;
        for attempt in &self.attempts {
            let (_, first, cleartext) = sync_packet::open_message(
                &record.domain,
                profile,
                keys,
                &attempt.request,
                false,
                false,
            )
            .map_err(|_| Error::InvalidRecord)?;
            let mut chain = PayloadChain::new(first, &cleartext).iter();
            let payload = chain
                .next()
                .ok_or(Error::InvalidRecord)?
                .map_err(|_| Error::InvalidRecord)?;
            if payload.payload_type != PayloadType::Notify || chain.next().is_some() {
                return Err(Error::InvalidRecord);
            }
            let notify =
                Ikev2NotifyPayload::decode_body(payload.body).map_err(|_| Error::InvalidRecord)?;
            let value =
                decode_ikev2_message_id_sync_notify(notify).map_err(|_| Error::InvalidRecord)?;
            if value != Some(attempt.pending.notification()) {
                return Err(Error::InvalidRecord);
            }
            let start = HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN;
            let iv = attempt
                .request
                .get(start..start + 8)
                .ok_or(Error::InvalidRecord)?;
            let iv = u64::from_be_bytes(iv.try_into().map_err(|_| Error::InvalidRecord)?);
            if iv >= iv_end || previous_iv.is_some_and(|previous| previous >= iv) {
                return Err(Error::InvalidRecord);
            }
            previous_iv = Some(iv);
        }
        Ok(())
    }
}
