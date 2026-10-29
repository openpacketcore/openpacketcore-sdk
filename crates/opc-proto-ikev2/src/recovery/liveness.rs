//! RFC 7296 sections 2.1–2.4 and RFC 6311 section 5.1: bounded volatile probes.
use bytes::Bytes;

use super::{
    packet, profile::RecoveryProfile, Ikev2AuthenticatedOrdinary as Ordinary,
    Ikev2CbcRecoveryProfile as Cbc, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2GcmRecoveryProfile as Gcm,
    Ikev2PreparedWindow as Prepared, Ikev2SyncDisposition as Disposition,
    Ikev2WindowError as Error,
};
use crate::{
    Ikev2AesGcmIvAllocator, Ikev2AesGcmIvPurpose, Ikev2ExchangeKind as Exchange,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys, PayloadChain, PayloadType,
};

/// Fixed elapsed-time timeout and bounded exponential retry policy for one probe.
/// The consumer schedules checks and supplies a monotone millisecond clock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2LivenessProbePolicy {
    timeout_ms: u64,
    max_transmissions: u16,
    initial_retry_ms: u64,
}

impl Ikev2LivenessProbePolicy {
    /// Count the initial send in `max_transmissions`. Retries double their delay.
    /// # Errors
    /// Refuses zero bounds or a first retry at/after the fixed timeout.
    pub fn new(
        timeout_ms: u64,
        max_transmissions: u16,
        initial_retry_ms: u64,
    ) -> Result<Self, Error> {
        if timeout_ms == 0
            || max_transmissions == 0
            || initial_retry_ms == 0
            || initial_retry_ms >= timeout_ms
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            timeout_ms,
            max_transmissions,
            initial_retry_ms,
        })
    }
    /// Fixed duration from the first send; packet rejection never extends it.
    pub const fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }
    /// Total allowed transmissions, including the initial one.
    pub const fn max_transmissions(self) -> u16 {
        self.max_transmissions
    }
    /// Positive initial retry delay; each subsequent delay doubles.
    pub const fn initial_retry_ms(self) -> u64 {
        self.initial_retry_ms
    }
}

/// Durable opt-in and retained evidence for bounded unwritten local requests.
///
/// Persist with the entire window row. The codec must encode explicit presence
/// or absence and refuse missing fields/unknown formats. This is no migration
/// reader: crossing the stored-record change requires a fresh install.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2LivenessRecord {
    max_unwritten: u32,
    last_probe: Option<Bytes>,
}

impl Ikev2LivenessRecord {
    /// Reconstruct the latest trusted atomic row, not a runtime activation.
    /// `last_probe` is the last locally sealed empty INFORMATIONAL request whose
    /// ID was folded into this row; it is evidence, never retransmission authority.
    /// # Errors
    /// Refuses a zero bound. Window restoration additionally authenticates evidence.
    pub fn from_persisted(max_unwritten: u32, last_probe: Option<Bytes>) -> Result<Self, Error> {
        if max_unwritten == 0 {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            max_unwritten,
            last_probe,
        })
    }
    /// Maximum number of probe IDs beyond the last acknowledged send floor.
    pub const fn max_unwritten(&self) -> u32 {
        self.max_unwritten
    }
    /// Latest folded probe bytes, to serialize atomically; never replay on restore.
    pub fn last_probe(&self) -> Option<&[u8]> {
        self.last_probe.as_deref()
    }
}

impl<P: RecoveryProfile> Record<P> {
    /// Attach explicitly decoded probe metadata from the same latest atomic row.
    ///
    /// This trusted reconstruction grants no runtime activation or send authority.
    /// Never omit existing metadata or infer disabled support from missing fields.
    /// # Errors
    /// Refuses replacing an already attached value; restore checks packet evidence.
    pub fn with_liveness(mut self, state: Ikev2LivenessRecord) -> Result<Self, Error> {
        if self.liveness.is_some() {
            return Err(Error::InvalidRecord);
        }
        self.liveness = Some(state);
        Ok(self)
    }
    /// Probe activation/bound/evidence fields belonging to this atomic SA record.
    pub const fn liveness(&self) -> Option<&Ikev2LivenessRecord> {
        self.liveness.as_ref()
    }
}

pub(super) fn validate_record<P: RecoveryProfile>(
    record: &Record<P>,
    profile: Profile,
    keys: &Keys,
    epoch: &P::Epoch,
) -> Result<Option<u32>, Error> {
    let Some(state) = &record.liveness else {
        return Ok(None);
    };
    let Some(wire) = &state.last_probe else {
        return Ok(None);
    };
    let probe = packet::open(&record.domain, profile, keys, wire, false)
        .map_err(|_| Error::InvalidRecord)?;
    let id = probe.header.message_id;
    if record.generation == 0
        || probe.header.flags.response()
        || probe.header.exchange_type != Exchange::Informational.as_u8()
        || !probe.payloads().is_empty()
        || id == u32::MAX
        || record.next_send.is_some_and(|next| id >= next)
        || record
            .sync
            .is_some_and(|sync| sync.highest_local_request().is_none_or(|last| id > last))
    {
        return Err(Error::InvalidRecord);
    }
    P::check_local_ordinary(&probe, epoch)?;
    Ok(Some(id))
}

pub(super) struct Probe {
    id: u32,
    wire: Bytes,
    policy: Ikev2LivenessProbePolicy,
    deadline: u64,
    transmissions: u16,
    next_retry: u64,
    interval: u64,
}

struct AdmittedProbe {
    id: u32,
    deadline: u64,
    policy: Ikev2LivenessProbePolicy,
    now: u64,
}

pub(super) struct SendState {
    pub next: Option<u32>,
    pub latest_probe: Option<Bytes>,
    highest_probe: Option<u32>,
    pub outstanding: Option<Probe>,
    recovery_required: bool,
    terminal: Option<Error>,
    last_clock: Option<u64>,
}

impl SendState {
    pub fn restore<P: RecoveryProfile>(record: &Record<P>) -> Result<Self, Error> {
        let latest_probe = record
            .liveness
            .as_ref()
            .and_then(|state| state.last_probe.clone());
        let highest_probe = latest_probe
            .as_ref()
            .map(|wire| {
                crate::decode_header(wire, opc_protocol::DecodeContext::default())
                    .map(|(_, header)| header.message_id)
                    .map_err(|_| Error::InvalidRecord)
            })
            .transpose()?;
        // A pending durable request or sync/terminal state forbade later probes.
        // Otherwise every ID in the configured lead may have escaped before loss.
        let recovery_required = record.liveness.is_some()
            && record.next_send.is_some()
            && record
                .outbound
                .as_ref()
                .is_none_or(|entry| entry.response.is_some())
            && record
                .sync
                .is_none_or(|sync| sync.disposition() == Disposition::Continue);
        let next = if recovery_required {
            record.next_send.map(|next| {
                next.saturating_add(
                    record
                        .liveness
                        .as_ref()
                        .map_or(0, |state| state.max_unwritten),
                )
            })
        } else {
            record.next_send
        };
        Ok(Self {
            next,
            latest_probe,
            highest_probe,
            outstanding: None,
            recovery_required,
            terminal: None,
            last_clock: None,
        })
    }
    pub fn check_terminal(&self) -> Result<(), Error> {
        match self.terminal {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub fn ready(&self) -> Result<(), Error> {
        self.check_terminal()?;
        if self.recovery_required {
            return Err(Error::LivenessRecoveryRequired);
        }
        Ok(())
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        self.check_terminal()?;
        if self.last_clock.is_some_and(|last| now < last) {
            self.terminal = Some(Error::LivenessClock);
            return Err(Error::LivenessClock);
        }
        self.last_clock = Some(now);
        if self
            .outstanding
            .as_ref()
            .is_some_and(|probe| now >= probe.deadline)
        {
            self.terminal = Some(Error::LivenessExpired);
            return Err(Error::LivenessExpired);
        }
        Ok(())
    }
    pub fn matches_response(&self, header: &crate::Header) -> bool {
        header.flags.response()
            && header.exchange_type == Exchange::Informational.as_u8()
            && self
                .outstanding
                .as_ref()
                .is_some_and(|probe| probe.id == header.message_id)
    }
    pub fn highest_probe(&self) -> Option<u32> {
        self.highest_probe
    }
    pub fn adopt<P: RecoveryProfile>(&mut self, record: &Record<P>, sync: bool) {
        self.next = match (self.next, record.next_send) {
            (Some(live), Some(stored)) => Some(live.max(stored)),
            _ => None,
        };
        if sync {
            self.outstanding = None;
            self.recovery_required = false;
        }
    }
    pub fn discard(&mut self) {
        self.outstanding = None;
        self.latest_probe = None;
    }
}

/// Borrowed probe packet with current exclusive window authority.
///
/// Send under the consumer's fenced SA authority while retaining this borrow.
/// Copying bytes does not preserve that authority after a lifecycle transition.
/// Dropping the packet never refunds its ID, IV or transmission budget.
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CommittedWindow;
/// fn stale(window: &mut Ikev2CommittedWindow) {
///     let probe = window.retry_empty_probe(100).unwrap();
///     let _ = window.prepare_liveness(4);
///     let _ = probe.bytes();
/// }
/// ```
#[must_use = "submit under the live fenced SA authority; dropping does not refund the send"]
pub struct Ikev2EmptyProbe<'a, P: RecoveryProfile = Gcm> {
    window: &'a Window<P>,
    wire: &'a [u8],
    id: u32,
    deadline: u64,
}
impl<P: RecoveryProfile> Ikev2EmptyProbe<'_, P> {
    /// Complete protected empty INFORMATIONAL; retransmit these bytes unchanged.
    pub const fn bytes(&self) -> &[u8] {
        self.wire
    }
    /// Live request Message ID.
    pub const fn message_id(&self) -> u32 {
        self.id
    }
    /// Fixed monotone millisecond deadline for this outstanding request.
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline
    }
    /// Key-epoch binding retained by this borrowed send authority.
    pub const fn domain(&self) -> &super::Ikev2CommittedWindowDomain<P> {
        &self.window.record.domain
    }
}

impl<P: RecoveryProfile> Window<P> {
    /// Next live local request ID, including probes not yet folded into a record.
    /// After process loss this is a conservative bound, not permission to send.
    pub const fn next_send(&self) -> Option<u32> {
        self.send.next
    }

    /// Message ID of the currently outstanding liveness request, if any.
    pub fn pending_empty_request_message_id(&self) -> Option<u32> {
        self.send.outstanding.as_ref().map(|probe| probe.id)
    }

    /// Next local request ID, including volatile advances and the restart bound.
    /// This query grants no permission to send while recovery is required.
    pub const fn next_send_message_id(&self) -> Option<u32> {
        self.next_send()
    }

    /// Prepare durable activation or checkpoint of bounded write-free probes.
    ///
    /// Persist the entire candidate atomically before acknowledgement. Each real
    /// ordinary commit also folds the live floor without an additional write.
    /// Restoring an enabled window requires RFC 6311 synchronization beyond the
    /// entire unwritten bound, or automatic scoped SA retirement if unnegotiated.
    /// This method cannot clear recovery, expiry, clock or unresolved-write state.
    /// # Errors
    /// Refuses zero bounds and ordinary lifecycle/commit exhaustion failures.
    pub fn prepare_liveness(&mut self, max_unwritten: u32) -> Result<Prepared<'_, P>, Error> {
        let state =
            Ikev2LivenessRecord::from_persisted(max_unwritten, self.send.latest_probe.clone())?;
        let mut record = self.next_record()?;
        record.liveness = Some(state);
        Ok(self.prepared(record, None, false))
    }

    pub(super) fn fold_live_send(&self, record: &mut Record<P>) {
        record.next_send = self.send.next;
        if let Some(state) = &mut record.liveness {
            state.last_probe = self.send.latest_probe.clone();
        }
        if let Some(sync) = &mut record.sync {
            sync.highest_local_request = sync.highest_local_request.max(self.send.highest_probe);
        }
    }

    fn probe_admission(
        &mut self,
        policy: Ikev2LivenessProbePolicy,
        now: u64,
    ) -> Result<AdmittedProbe, Error> {
        self.ready()?;
        let bound = self
            .record
            .liveness
            .as_ref()
            .ok_or(Error::LivenessDisabled)?
            .max_unwritten;
        self.send.clock(now)?;
        if self.send.outstanding.is_some()
            || self
                .record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none())
        {
            return Err(Error::RequestOutstanding);
        }
        let id = self.send.next.ok_or(Error::Exhausted)?;
        // Preserve the last representable ID for rekey/closure, never wrap.
        if id == u32::MAX {
            return Err(Error::Exhausted);
        }
        let stored = self.record.next_send.ok_or(Error::Exhausted)?;
        let lead = id.checked_sub(stored).ok_or(Error::InvalidRecord)?;
        if lead >= bound {
            return Err(Error::LivenessLeadExhausted);
        }
        let deadline = now.checked_add(policy.timeout_ms).ok_or_else(|| {
            self.send.terminal = Some(Error::LivenessClock);
            Error::LivenessClock
        })?;
        Ok(AdmittedProbe {
            id,
            deadline,
            policy,
            now,
        })
    }

    fn seal_probe(
        &mut self,
        profile: Profile,
        keys: &Keys,
        sealing: P::Sealing<'_>,
        admitted: AdmittedProbe,
    ) -> Result<Ikev2EmptyProbe<'_, P>, Error> {
        let AdmittedProbe {
            id,
            deadline,
            policy,
            now,
        } = admitted;
        let header = self
            .record
            .domain
            .header(Exchange::Informational, id, false);
        let sealed = packet::seal(
            &self.record.domain,
            profile,
            keys,
            sealing,
            header,
            PayloadChain::new(PayloadType::NoNext, &[]),
        )?;
        P::retain_sealed(&mut self.packet_evidence, &sealed)?;
        let wire = sealed.into_wire();
        self.send.next = id.checked_add(1);
        self.send.highest_probe = Some(id);
        self.send.latest_probe = Some(wire.clone());
        self.send.outstanding = Some(Probe {
            id,
            wire,
            policy,
            deadline,
            transmissions: 1,
            next_retry: now.saturating_add(policy.initial_retry_ms).min(deadline),
            interval: policy.initial_retry_ms,
        });
        self.borrow_probe()
    }

    fn borrow_probe(&self) -> Result<Ikev2EmptyProbe<'_, P>, Error> {
        let probe = self.send.outstanding.as_ref().ok_or(Error::Drop)?;
        Ok(Ikev2EmptyProbe {
            window: self,
            wire: &probe.wire,
            id: probe.id,
            deadline: probe.deadline,
        })
    }

    /// Check the outstanding probe's fixed deadline even when no packet arrives.
    /// # Errors
    /// No probe drops; expiry/backward time latch terminal refusal. Retain this
    /// knowledge until automatic scoped cleanup; a process restart is no reset.
    pub fn check_empty_probe_deadline(&mut self, now_ms: u64) -> Result<(), Error> {
        self.ready()?;
        if self.send.outstanding.is_none() {
            return Err(Error::Drop);
        }
        self.send.clock(now_ms)
    }

    /// Retransmit exactly the same bytes, consuming no IV or window write.
    /// # Errors
    /// Refuses early retries, spent transmissions, expiry, clock rollback or
    /// unavailable lifecycle. Retry-limit refusal still permits an in-time reply.
    pub fn retry_empty_probe(&mut self, now_ms: u64) -> Result<Ikev2EmptyProbe<'_, P>, Error> {
        self.check_empty_probe_deadline(now_ms)?;
        let probe = self.send.outstanding.as_mut().ok_or(Error::Drop)?;
        if probe.transmissions >= probe.policy.max_transmissions {
            return Err(Error::LivenessRetryLimit);
        }
        if now_ms < probe.next_retry {
            return Err(Error::LivenessBackoff);
        }
        probe.transmissions += 1;
        probe.interval = probe.interval.saturating_mul(2);
        probe.next_retry = now_ms.saturating_add(probe.interval).min(probe.deadline);
        self.borrow_probe()
    }

    /// Complete the current probe once from an authenticated INFORMATIONAL response.
    ///
    /// This is liveness evidence only, never an application outcome or durable
    /// completion. Opposite-direction peer traffic remains independent. An empty
    /// response to a nonempty durable request belongs to `prepare_completion`.
    /// RFC 7296 §1.4 permits response payloads; return them for the caller's
    /// semantic processing under its existing SA and effect authority.
    /// # Errors
    /// Drops mismatched domain/ID/class or duplicate responses. No packet
    /// can extend the fixed deadline or clear latched expiry/clock knowledge.
    pub fn complete_empty_probe<'a>(
        &mut self,
        response: &'a Ordinary<P>,
        now_ms: u64,
    ) -> Result<PayloadChain<'a>, Error> {
        self.check_empty_probe_deadline(now_ms)?;
        if response.domain != self.record.domain || !self.send.matches_response(&response.header) {
            return Err(Error::Drop);
        }
        self.send.outstanding = None;
        Ok(response.payloads())
    }
}

impl Window<Gcm> {
    /// Originate one fresh empty INFORMATIONAL from an already reserved Ordinary IV.
    ///
    /// The caller decides idleness from authenticated IKE and Child-SA ESP traffic;
    /// NAT keepalives are not liveness evidence (RFC 3948 section 4). This method
    /// never reserves an IV block or spends the control reserve. No window write
    /// occurs. Hold the returned borrow under fenced SA authority through send.
    /// # Errors
    /// Refuses disabled/exhausted bounds, pending local requests, terminal/uncertain
    /// lifecycle, clock failure or unavailable admitted IV/encryption. A failed
    /// seal burns its IV but does not advance the send ID.
    pub fn start_empty_probe(
        &mut self,
        profile: Profile,
        keys: &Keys,
        allocator: &mut Ikev2AesGcmIvAllocator,
        policy: Ikev2LivenessProbePolicy,
        now_ms: u64,
    ) -> Result<Ikev2EmptyProbe<'_, Gcm>, Error> {
        let admitted = self.probe_admission(policy, now_ms)?;
        let allocation = allocator
            .allocate(Ikev2AesGcmIvPurpose::Ordinary)
            .map_err(Error::Iv)?;
        self.seal_probe(profile, keys, allocation, admitted)
    }
}

impl Window<Cbc> {
    /// Originate one fresh empty INFORMATIONAL with an admitted random CBC IV.
    /// The caller chooses idleness using authenticated IKE and Child-SA ESP traffic,
    /// excluding NAT keepalives. Sending/completion perform no window writes.
    /// # Errors
    /// Refuses disabled/exhausted bounds, pending local requests, lifecycle/clock
    /// failure or unavailable admitted entropy/encryption. No fallback IV exists.
    pub fn start_empty_probe(
        &mut self,
        profile: Profile,
        keys: &Keys,
        policy: Ikev2LivenessProbePolicy,
        now_ms: u64,
    ) -> Result<Ikev2EmptyProbe<'_, Cbc>, Error> {
        let admitted = self.probe_admission(policy, now_ms)?;
        self.seal_probe(profile, keys, (), admitted)
    }
}
