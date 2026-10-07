//! Committed ordinary IKE window-one ordering and exact replay hooks.
//!
//! The consumer owns atomic persistence, a single fenced writer, semantic peer
//! authentication and operation validation, and idempotent application of durable
//! outcomes. A matching record is not proof of a storage acknowledgement. No
//! effect or new packet may escape preparation before that acknowledgement.
//!
//! This initial profile handles complete AES-GCM SK packets, not SKF or CBC
//! recovery. It does not enable sync, canonical empty replies or receive-floor
//! reconstruction. Empty INFORMATIONAL requests use no durable window write;
//! until a stateless handler with a volatile receive high-water exists, this
//! profile must not face peers that send DPD requests.
//! Replay probes are old bytes, not fresh liveness or new outcome evidence.

use std::{error::Error as StdError, fmt, sync::Arc};

use crate::{
    Ikev2AesGcmIvAllocation, Ikev2AesGcmIvRecord, Ikev2AesGcmIvReservationError, Ikev2ExchangeKind,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, PayloadChain,
};
use bytes::Bytes;

mod packet;
mod record;
mod reservation_retry;
pub use packet::Ikev2AuthenticatedOrdinary;
pub use record::{
    Ikev2CommittedExchangeRecord, Ikev2CommittedWindowDomain, Ikev2CommittedWindowRecord,
};

pub use reservation_retry::{
    Ikev2PreparedReservationAttempt, Ikev2PreparedRetryReservation, Ikev2ReservationAttempt,
    Ikev2ReservationRetry, Ikev2ReservationRetryError, Ikev2ReservationRetryPolicy,
    Ikev2ReservationRetryRecord,
};

/// Non-accepting durable-window failure. Every error releases no new authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2WindowError {
    /// Silently drop an unauthenticated, wrong-class, stale or mismatching packet.
    Drop,
    /// Established key/role/SPI/profile binding differs.
    DomainMismatch,
    /// Persisted fields are incomplete, inconsistent or fail packet validation.
    InvalidRecord,
    /// An outbound ordinary request remains unsettled.
    RequestOutstanding,
    /// A preparation was cancelled or its persistence is unresolved; restore latest readback.
    CommitUncertain,
    /// Acknowledgement did not equal the exact prepared record.
    CommitMismatch,
    /// Message-ID or commit-generation space is exhausted; never wrap.
    Exhausted,
    /// Stateless empty request cannot create durable work or a fresh probe.
    NoDurableWork,
    /// Completion belongs to another runtime or an older commit generation.
    StaleCompletion,
    /// Slice-3 allocation or admitted sealing failed; the supplied IV is burned.
    Iv(Ikev2AesGcmIvReservationError),
}

impl fmt::Display for Ikev2WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Drop => "ike_committed_window_drop",
            Self::DomainMismatch => "ike_committed_window_domain_mismatch",
            Self::InvalidRecord => "ike_committed_window_invalid_record",
            Self::RequestOutstanding => "ike_committed_window_request_outstanding",
            Self::CommitUncertain => "ike_committed_window_commit_uncertain",
            Self::CommitMismatch => "ike_committed_window_commit_mismatch",
            Self::Exhausted => "ike_committed_window_exhausted",
            Self::NoDurableWork => "ike_committed_window_no_durable_work",
            Self::StaleCompletion => "ike_committed_window_stale_completion",
            Self::Iv(_) => "ike_committed_window_iv_failure",
        })
    }
}
impl StdError for Ikev2WindowError {}

/// Strict admission result, after authentication, for one peer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2OrdinaryRequestDisposition {
    /// Exactly the expected request ID; plan its outcome without performing effects.
    New,
    /// Exact last committed request; replay its response without re-execution.
    CachedResponse,
}

/// Borrowed exact committed bytes. No allocation, effect or fresh liveness occurs.
pub struct Ikev2ExactReplay<'a> {
    bytes: &'a [u8],
}
impl Ikev2ExactReplay<'_> {
    /// Original complete SK packet, unchanged including its Message ID and IV.
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// Non-cloneable durable window-one runtime for one IKE key epoch.
///
/// Dropping a prepared transition leaves this runtime quiescent. Resolve all
/// possibly outstanding writes under the fence, read back the latest atomic
/// record, then replace it with [`Self::restore`]. Never guess whether a write
/// landed, roll back persisted state or re-execute a historical outcome.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CommittedWindow;
/// fn duplicate(window: Ikev2CommittedWindow) { let _ = window.clone(); }
/// ```
pub struct Ikev2CommittedWindow {
    record: Ikev2CommittedWindowRecord,
    instance: Arc<()>,
    quiescent: bool,
}

impl Ikev2CommittedWindow {
    /// Restore a trusted latest record, binding keys and authenticating cached packets.
    ///
    /// This creates no effect token. Stored outcomes are history for idempotent
    /// restoration by the consumer. Supply the latest fenced sending-IV record;
    /// its exclusive end must cover the outbound request and inbound response IVs.
    /// Restore the IV allocator from that same record separately, discarding its
    /// unconsumed tail. The cross-check detects inconsistency with cached packets,
    /// not rollback of both records or forgotten history. Writer fencing and
    /// trustworthy latest records remain caller obligations.
    /// # Errors
    /// Rejects mismatching domains, unauthentic packets, wrong directions/classes,
    /// response correlation failures, counters inconsistent with retained history,
    /// or an IV high-water at or below any locally sent cached packet's IV.
    pub fn restore(
        expected: &Ikev2CommittedWindowDomain,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        record: &Ikev2CommittedWindowRecord,
        iv_record: &Ikev2AesGcmIvRecord,
    ) -> Result<Self, Ikev2WindowError> {
        use Ikev2WindowError as Error;
        if expected != &record.domain || expected.send_iv_domain() != iv_record.domain() {
            return Err(Error::DomainMismatch);
        }
        expected.check(profile, keys)?;
        for (entry, peer, next) in [
            (&record.outbound, false, record.next_send),
            (&record.inbound, true, record.next_receive),
        ] {
            if let Some(entry) = entry {
                let request = packet::open(expected, profile, keys, &entry.request, peer)
                    .map_err(|_| Error::InvalidRecord)?;
                request.require_work().map_err(|_| Error::InvalidRecord)?;
                if request.header.flags.response()
                    || next != request.header.message_id.checked_add(1)
                {
                    return Err(Error::InvalidRecord);
                }
                if !peer {
                    request.require_reserved_iv(iv_record.exclusive_end())?;
                }
                if let Some(response) = &entry.response {
                    let response = packet::open(expected, profile, keys, response, !peer)
                        .map_err(|_| Error::InvalidRecord)?;
                    if !response.header.flags.response()
                        || response.header.message_id != request.header.message_id
                        || response.header.exchange_type != request.header.exchange_type
                    {
                        return Err(Error::InvalidRecord);
                    }
                    if peer {
                        response.require_reserved_iv(iv_record.exclusive_end())?;
                    }
                }
            }
        }
        Ok(Self {
            record: record.clone(),
            instance: Arc::new(()),
            quiescent: false,
        })
    }

    /// Last acknowledged record; while quiescent it may not be the latest durable state.
    pub const fn record(&self) -> &Ikev2CommittedWindowRecord {
        &self.record
    }

    /// Authenticate a complete peer SK packet through the admitted module.
    ///
    /// # Errors
    /// Rejects key/domain mismatches, authentication, framing or inner-chain errors,
    /// and every sync Notify including mixed/malformed sync shapes at ordinary ID 0.
    pub fn open_peer(
        &self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        wire: &[u8],
    ) -> Result<Ikev2AuthenticatedOrdinary, Ikev2WindowError> {
        packet::open(&self.record.domain, profile, keys, wire, true)
    }

    fn ready(&self) -> Result<(), Ikev2WindowError> {
        if self.quiescent {
            Err(Ikev2WindowError::CommitUncertain)
        } else {
            Ok(())
        }
    }
    fn next_record(&self) -> Result<Ikev2CommittedWindowRecord, Ikev2WindowError> {
        self.ready()?;
        let mut record = self.record.clone();
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(Ikev2WindowError::Exhausted)?;
        Ok(record)
    }
    fn prepared(
        &mut self,
        record: Ikev2CommittedWindowRecord,
        outcome: Option<Bytes>,
    ) -> Ikev2PreparedWindow<'_> {
        self.quiescent = true;
        Ikev2PreparedWindow {
            window: self,
            record,
            outcome,
        }
    }

    /// Seal and prepare a single new ordinary request without send permission.
    ///
    /// The caller reserves IVs only for genuine state-changing work, never liveness.
    /// A failed call burns its supplied allocation but changes no Message-ID state.
    /// The last representable ID should be reserved for rekey/closure by policy.
    /// # Errors
    /// Rejects pending work, unresolved commits, exhaustion, invalid payloads and
    /// empty INFORMATIONAL probes. IKE_SA_INIT and sync are outside this path.
    pub fn prepare_request(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        allocation: Ikev2AesGcmIvAllocation<'_>,
        exchange: Ikev2ExchangeKind,
        payloads: PayloadChain<'_>,
    ) -> Result<Ikev2PreparedWindow<'_>, Ikev2WindowError> {
        let mut record = self.next_record()?;
        if record
            .outbound
            .as_ref()
            .is_some_and(|request| request.response.is_none())
        {
            return Err(Ikev2WindowError::RequestOutstanding);
        }
        let id = record.next_send.ok_or(Ikev2WindowError::Exhausted)?;
        packet::require_work(exchange.as_u8(), payloads)?;
        let request = packet::seal(
            &record.domain,
            profile,
            keys,
            allocation,
            record.domain.header(exchange, id, false),
            payloads,
        )?;
        record.outbound = Some(Ikev2CommittedExchangeRecord {
            request,
            response: None,
            outcome: None,
        });
        record.next_send = id.checked_add(1);
        Ok(self.prepared(record, None))
    }

    /// Classify an authenticated peer request against the exact window-one floor.
    ///
    /// # Errors
    /// Drops wrong direction/domain, forward gaps, stale IDs and same-ID changed
    /// bytes. Stateless empty requests need a separate zero-write handler.
    pub fn request_disposition(
        &self,
        request: &Ikev2AuthenticatedOrdinary,
    ) -> Result<Ikev2OrdinaryRequestDisposition, Ikev2WindowError> {
        self.ready()?;
        if request.domain != self.record.domain || request.header.flags.response() {
            return Err(Ikev2WindowError::Drop);
        }
        request.require_work()?;
        if self
            .record
            .inbound
            .as_ref()
            .is_some_and(|entry| entry.request == request.wire)
        {
            return Ok(Ikev2OrdinaryRequestDisposition::CachedResponse);
        }
        if self.record.next_receive == Some(request.header.message_id) {
            Ok(Ikev2OrdinaryRequestDisposition::New)
        } else {
            Err(Ikev2WindowError::Drop)
        }
    }

    /// Prepare the exact reply and outcome to a nonempty, strictly admitted request.
    ///
    /// Planning must perform no irreversible effects. Commit outcome and bytes
    /// atomically before replying or publishing any effect, including error replies
    /// and empty acknowledgements of state-changing requests. Storage failure is
    /// silence, not permission to create an uncommitted TEMPORARY_FAILURE.
    /// # Errors
    /// Rejects stale/duplicate/gapped requests and every ordinary preparation failure.
    pub fn prepare_response(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        allocation: Ikev2AesGcmIvAllocation<'_>,
        request: &Ikev2AuthenticatedOrdinary,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_>, Ikev2WindowError> {
        if self.request_disposition(request)? != Ikev2OrdinaryRequestDisposition::New {
            return Err(Ikev2WindowError::Drop);
        }
        let mut record = self.next_record()?;
        let exchange = Ikev2ExchangeKind::from_u8(request.header.exchange_type)
            .ok_or(Ikev2WindowError::Drop)?;
        let response = packet::seal(
            &record.domain,
            profile,
            keys,
            allocation,
            record
                .domain
                .header(exchange, request.header.message_id, true),
            payloads,
        )?;
        record.inbound = Some(Ikev2CommittedExchangeRecord {
            request: request.wire.clone(),
            response: Some(response),
            outcome: Some(outcome.clone()),
        });
        record.next_receive = request.header.message_id.checked_add(1);
        Ok(self.prepared(record, Some(outcome)))
    }

    /// Prepare settlement of the single pending outbound request after semantic checks.
    ///
    /// # Errors
    /// Drops wrong domain, exchange, ID or response flag, and all delayed/duplicate
    /// responses after settlement. A replay probe therefore cannot create an outcome.
    pub fn prepare_completion(
        &mut self,
        response: &Ikev2AuthenticatedOrdinary,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_>, Ikev2WindowError> {
        let mut record = self.next_record()?;
        let outbound = record.outbound.as_mut().ok_or(Ikev2WindowError::Drop)?;
        // The request header was constructed or authenticated when the record was restored.
        let (_, request_header) =
            crate::decode_header(&outbound.request, opc_protocol::DecodeContext::default())
                .map_err(|_| Ikev2WindowError::InvalidRecord)?;
        if response.domain != record.domain
            || !response.header.flags.response()
            || outbound.response.is_some()
            || response.header.message_id != request_header.message_id
            || response.header.exchange_type != request_header.exchange_type
        {
            return Err(Ikev2WindowError::Drop);
        }
        outbound.response = Some(response.wire.clone());
        outbound.outcome = Some(outcome.clone());
        Ok(self.prepared(record, Some(outcome)))
    }

    /// Replay the last committed local request, pending or settled, without new state.
    ///
    /// No record means no artificial probe. Even a fresh peer response to these old
    /// bytes proves no fresh liveness and cannot repeat a settled outcome.
    /// # Errors
    /// Quiescent runtimes must resolve readback first.
    pub fn replay_request(&self) -> Result<Option<Ikev2ExactReplay<'_>>, Ikev2WindowError> {
        self.ready()?;
        Ok(self.record.outbound.as_ref().map(|entry| Ikev2ExactReplay {
            bytes: &entry.request,
        }))
    }

    /// Replay only the exact response applicable to this authenticated cached duplicate.
    /// # Errors
    /// Drops stale/mismatching inputs; refuses unresolved commits.
    pub fn replay_response(
        &self,
        request: &Ikev2AuthenticatedOrdinary,
    ) -> Result<Ikev2ExactReplay<'_>, Ikev2WindowError> {
        if self.request_disposition(request)? != Ikev2OrdinaryRequestDisposition::CachedResponse {
            return Err(Ikev2WindowError::Drop);
        }
        let bytes = self
            .record
            .inbound
            .as_ref()
            .and_then(|entry| entry.response.as_deref())
            .ok_or(Ikev2WindowError::InvalidRecord)?;
        Ok(Ikev2ExactReplay { bytes })
    }

    /// Consume a one-use completion for this runtime and current commit generation.
    ///
    /// Returns the opaque outcome, or no outcome for initial request publication.
    /// Use immediately before further ordinary commits. Consumer effect callbacks
    /// must remain fenced and idempotent; this function itself executes no callback.
    /// # Errors
    /// Refuses retired runtime/generation tokens and unresolved transitions.
    pub fn apply_committed(
        &mut self,
        commit: Ikev2WindowCommit,
    ) -> Result<Option<Bytes>, Ikev2WindowError> {
        if self.quiescent
            || !Arc::ptr_eq(&self.instance, &commit.instance)
            || self.record.generation != commit.generation
        {
            return Err(Ikev2WindowError::StaleCompletion);
        }
        Ok(commit.outcome)
    }
}

/// Exclusive prepared record: storage inputs only, no transmission or effects.
#[must_use = "commit the exact record before transmission or effects; dropping quiesces the window"]
pub struct Ikev2PreparedWindow<'a> {
    window: &'a mut Ikev2CommittedWindow,
    record: Ikev2CommittedWindowRecord,
    outcome: Option<Bytes>,
}
impl Ikev2PreparedWindow<'_> {
    /// Exact candidate to persist atomically with SA and consumer outcome.
    pub const fn record(&self) -> &Ikev2CommittedWindowRecord {
        &self.record
    }

    /// Publish only after a durable acknowledgement of this exact fenced record.
    ///
    /// Cloning the candidate is not proof of storage success. Never call this on
    /// uncertain completion. The consumer must prevent older writes from landing.
    /// # Errors
    /// Mismatching acknowledgement leaves the window quiescent for readback.
    pub fn commit_after_durable(
        self,
        committed: &Ikev2CommittedWindowRecord,
    ) -> Result<Ikev2WindowCommit, Ikev2WindowError> {
        if committed != &self.record {
            return Err(Ikev2WindowError::CommitMismatch);
        }
        self.window.record = self.record;
        self.window.quiescent = false;
        Ok(Ikev2WindowCommit {
            instance: Arc::clone(&self.window.instance),
            generation: self.window.record.generation,
            outcome: self.outcome,
        })
    }
}

/// One-use post-commit outcome permission, fenced by runtime and generation.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2WindowCommit;
/// fn duplicate(commit: Ikev2WindowCommit) { let _ = commit.clone(); }
/// ```
#[must_use = "consume with apply_committed only in the current runtime before a later transition"]
pub struct Ikev2WindowCommit {
    instance: Arc<()>,
    generation: u64,
    outcome: Option<Bytes>,
}

macro_rules! redacted_debug {
    ($($ty:ty),* $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($ty)).finish_non_exhaustive()
        }
    })* };
}
redacted_debug!(
    Ikev2CommittedWindowDomain,
    Ikev2CommittedExchangeRecord,
    Ikev2CommittedWindowRecord,
    Ikev2AuthenticatedOrdinary,
    Ikev2CommittedWindow,
    Ikev2PreparedWindow<'_>,
    Ikev2WindowCommit,
    Ikev2ExactReplay<'_>
);
