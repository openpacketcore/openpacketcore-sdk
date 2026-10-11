//! Committed ordinary IKE windows, exact replay and durable RFC 6311 sync hooks.
//!
//! The consumer owns atomic persistence, a single fenced writer, semantic peer
//! authentication and operation validation, and idempotent application of durable
//! outcomes. A matching record is not proof of a storage acknowledgement. No
//! effect or new packet may escape preparation before that acknowledgement.
//!
//! The sealed GCM and CBC profiles handle complete SK packets, not SKF recovery.
//! Canonical sending requires current profile qualification. Sync requires
//! persisted negotiated metadata and fixed event/clock
//! budgets. The opt-in empty handler answers authenticated INFORMATIONAL requests
//! with canonical bytes and advances a volatile receive floor without a durable
//! write. Trusted restart reconstruction repairs a lost stateless prefix; the
//! first nonempty result commits the repaired floor and ends reconstruction.
//! Replay probes are old bytes, not fresh liveness or new outcome evidence.

use std::{cell::Cell, error::Error as StdError, fmt, sync::Arc};

use crate::{
    Ikev2AesGcmIvAllocation, Ikev2AesGcmIvReservationError, Ikev2ExchangeKind,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, PayloadChain,
};
use bytes::Bytes;

mod cbc_epoch;
#[cfg(test)]
pub(crate) mod cbc_test_fixtures;
mod empty;
mod packet;
pub(crate) mod profile;
use profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
mod reconcile;
mod record;
mod reservation_retry;
mod sync_initiator;
mod sync_packet;
mod sync_readiness;
mod sync_record;
mod sync_recovery_record;
mod sync_responder;
pub use cbc_epoch::{Ikev2CbcEpochInputs, Ikev2CbcEpochRecord};
pub use empty::{Ikev2EmptyReply, Ikev2EmptyReplyObservation};
pub use packet::Ikev2AuthenticatedOrdinary;
pub use profile::{Ikev2CbcRecoveryProfile, Ikev2GcmRecoveryProfile};
pub use record::{
    Ikev2CommittedExchangeRecord, Ikev2CommittedWindowDomain, Ikev2CommittedWindowRecord,
    Ikev2PersistedProfileSync,
};

pub use reservation_retry::{
    Ikev2PreparedReservationAttempt, Ikev2PreparedRetryReservation, Ikev2ReservationAttempt,
    Ikev2ReservationRetry, Ikev2ReservationRetryError, Ikev2ReservationRetryPolicy,
    Ikev2ReservationRetryRecord,
};
pub use sync_initiator::{
    Ikev2AdmittedSyncInitiation, Ikev2PreparedSyncInitiation, Ikev2SyncInitiatorAction,
    Ikev2SyncInitiatorCommit,
};
pub use sync_readiness::{Ikev2RuntimeSyncNegotiation, Ikev2SyncReadiness};
pub use sync_record::{Ikev2SyncDisposition, Ikev2SyncResponderRecord};
pub use sync_recovery_record::{
    Ikev2SyncAttemptRecord, Ikev2SyncClock, Ikev2SyncRecoveryPolicy, Ikev2SyncRecoveryRecord,
    Ikev2SyncRecoveryStatus,
};
pub use sync_responder::{
    Ikev2AdmittedSyncResponse, Ikev2PreparedSyncResponse, Ikev2SyncCommit, Ikev2SyncResponse,
};

/// Non-accepting durable-window failure. Every error releases no new authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2WindowError {
    /// Silently drop an unauthenticated, wrong-class, stale or mismatching packet.
    Drop,
    /// Authenticated SKF in this SA's ordinary exchange classes is outside the
    /// unfragmented recovery profile. This diagnostic grants no response or
    /// teardown authority; the consumer must commit its scoped resolution.
    UnsupportedShape,
    /// Established key/role/SPI/profile binding differs.
    DomainMismatch,
    /// Persisted fields are incomplete, inconsistent or fail packet validation.
    InvalidRecord,
    /// An outbound ordinary request remains unsettled.
    RequestOutstanding,
    /// A preparation was cancelled or its persistence is unresolved; reconcile latest readback.
    CommitUncertain,
    /// Provider pre-check failed before readback validation; retain this runtime and retry.
    ReconcileUnavailable,
    /// Acknowledgement did not equal the exact prepared record.
    CommitMismatch,
    /// Message-ID or commit-generation space is exhausted; never wrap.
    Exhausted,
    /// Stateless empty request cannot create durable work or a fresh probe.
    NoDurableWork,
    /// Enable the qualified canonical handler before admitting empty-request traffic.
    EmptyRepliesDisabled,
    /// Canonical policy, ledger or output checks refused; there is no fallback.
    Canonical(crate::canonical::Ikev2CanonicalError),
    /// Completion belongs to another runtime or an older commit generation.
    StaleCompletion,
    /// Local synchronization remains pending; ordinary traffic is blocked.
    SyncInProgress,
    /// Recovery is terminal; persist/restore scoped close, never downgrade or retry.
    SyncClosed,
    /// Positive retry delay has not elapsed; wait without allocating/reserving an IV.
    SyncBackoff,
    /// Admitted entropy failed or repeated current-event nonces at the redraw bound.
    SyncEntropy,
    /// Current admitted encryption/entropy cannot back a production support offer.
    SyncUnavailable,
    /// A peer cutover interrupted uncommitted work; close this IKE SA and its Children.
    OutcomeUncertain,
    /// Pure synchronization returned a non-accepting rekey/close intent.
    SyncRule(crate::Ikev2MessageIdSyncRuleError),
    /// Slice-3 allocation or admitted sealing failed; the supplied IV is burned.
    Iv(Ikev2AesGcmIvReservationError),
    /// Admitted CBC ordinary/sync encryption or random-IV generation failed.
    Crypto(crate::Ikev2ProtectedPayloadCryptoError),
}

impl fmt::Display for Ikev2WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Drop => "ike_committed_window_drop",
            Self::UnsupportedShape => "ike_committed_window_unsupported_shape",
            Self::DomainMismatch => "ike_committed_window_domain_mismatch",
            Self::InvalidRecord => "ike_committed_window_invalid_record",
            Self::RequestOutstanding => "ike_committed_window_request_outstanding",
            Self::CommitUncertain => "ike_committed_window_commit_uncertain",
            Self::ReconcileUnavailable => "ike_committed_window_reconcile_unavailable",
            Self::CommitMismatch => "ike_committed_window_commit_mismatch",
            Self::Exhausted => "ike_committed_window_exhausted",
            Self::NoDurableWork => "ike_committed_window_no_durable_work",
            Self::EmptyRepliesDisabled => "ike_committed_window_empty_replies_disabled",
            Self::Canonical(_) => "ike_committed_window_canonical_refused",
            Self::StaleCompletion => "ike_committed_window_stale_completion",
            Self::SyncInProgress => "ike_committed_window_sync_in_progress",
            Self::SyncClosed => "ike_committed_window_sync_closed",
            Self::SyncBackoff => "ike_committed_window_sync_backoff",
            Self::SyncEntropy => "ike_committed_window_sync_entropy_failure",
            Self::SyncUnavailable => "ike_committed_window_sync_unavailable",
            Self::OutcomeUncertain => "ike_committed_window_outcome_uncertain",
            Self::SyncRule(_) => "ike_committed_window_sync_rule_failure",
            Self::Iv(_) => "ike_committed_window_iv_failure",
            Self::Crypto(_) => "ike_committed_window_crypto_failure",
        })
    }
}
impl StdError for Ikev2WindowError {}

/// Admission result, after authentication, for one peer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2OrdinaryRequestDisposition {
    /// Expected or reconstructed request ID; plan its outcome without effects.
    New,
    /// Exact applicable committed request; replay its response without re-execution.
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
/// window and IV records, then call [`Self::reconcile`] in place. Never guess whether a write
/// landed, roll back persisted state or re-execute a historical outcome.
/// Reconcile retains the same canonical capability and last applicable empty
/// reply, acquires no capability and creates no completion or send permission.
/// Keep the live IV allocator so burned allocations remain burned.
///
/// Use [`Self::restore`] at process start, then [`Self::enable_empty_replies`] to
/// recover a lost empty prefix. A retryable enable refusal retains the checked runtime and epoch.
/// Drop or overwrite the old runtime before enabling its replacement; while the
/// old capability lives, enable returns `Canonical(CapabilityActive)`.
/// Restore-replacement within one process still loses the last empty reply's bytes
/// while retaining its release history: that ID is refused as `AlreadyReleased`.
/// A lost last reply may therefore stall the peer until synchronization or expiry.
///
/// Canonical reply construction cannot bypass this window's receive admission:
/// ```compile_fail
/// use opc_proto_ikev2::{canonical::Ikev2CanonicalPolicy, recovery::Ikev2CommittedWindow};
/// fn bypass(window: &Ikev2CommittedWindow, policy: Ikev2CanonicalPolicy) {
///     let _ = window.canonical_replies(policy);
/// }
/// ```
///
/// Restore and empty-enable are separate operations so a refused enable retains
/// the checked runtime for retry:
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CommittedWindow;
/// let _ = Ikev2CommittedWindow::restore_reconstructing;
/// ```
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CommittedWindow;
/// fn duplicate(window: Ikev2CommittedWindow) { let _ = window.clone(); }
/// ```
///
/// Profiles cannot exchange epoch records or authenticated packet evidence:
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmIvRecord, Ikev2SaInitCryptoProfile,
///     Ikev2SaInitKeyMaterial, recovery::*};
/// fn mixed(domain: &Ikev2CommittedWindowDomain<Ikev2CbcRecoveryProfile>,
///     record: &Ikev2CommittedWindowRecord<Ikev2CbcRecoveryProfile>,
///     profile: Ikev2SaInitCryptoProfile, keys: &Ikev2SaInitKeyMaterial,
///     gcm: &Ikev2AesGcmIvRecord) {
///     let _ = Ikev2CommittedWindow::restore(domain, profile, keys, record, gcm);
/// }
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::recovery::*;
/// fn mixed(window: &Ikev2CommittedWindow<Ikev2CbcRecoveryProfile>,
///     gcm: &Ikev2AuthenticatedOrdinary) {
///     let _ = window.request_disposition(gcm);
/// }
/// ```
/// CBC preparation accepts no GCM allocation:
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmIvAllocation, Ikev2SaInitCryptoProfile,
///     Ikev2SaInitKeyMaterial, Ikev2ExchangeKind, PayloadChain, recovery::*};
/// fn mixed(window: &mut Ikev2CommittedWindow<Ikev2CbcRecoveryProfile>,
///     profile: Ikev2SaInitCryptoProfile, keys: &Ikev2SaInitKeyMaterial,
///     allocation: Ikev2AesGcmIvAllocation<'_>, payloads: PayloadChain<'_>) {
///     let _ = window.prepare_request(profile, keys, allocation,
///         Ikev2ExchangeKind::Informational, payloads);
/// }
/// ```
pub struct Ikev2CommittedWindow<P: RecoveryProfile = Gcm> {
    record: Ikev2CommittedWindowRecord<P>,
    canonical_binding: P::Epoch,
    instance: Arc<()>,
    quiescent: bool,
    witness: Option<reconcile::Witness<P>>,
    reconcile_terminal: bool,
    observed_peer_request: Cell<Option<u32>>,
    receive: empty::ReceiveState<P>,
    sync_live: bool,
    sync_closed: bool,
    sync_last_observed_unix_ms: Option<u64>,
}

impl<P: RecoveryProfile> Ikev2CommittedWindow<P> {
    /// Restore a trusted latest record, binding keys and authenticating cached packets.
    ///
    /// This creates no effect token. Stored outcomes are history for idempotent
    /// restoration by the consumer. Supply the profile's latest fenced epoch record.
    /// CBC binds the complete immutable descriptor without IV arithmetic.
    /// For GCM, supply the sending-IV record;
    /// its exclusive end must cover locally sent cached IVs, initiating attempts
    /// and the retained minimum in sync metadata even after caches are retired.
    /// At process start restore the IV allocator from that same record separately, discarding its
    /// unconsumed tail. The cross-check detects inconsistency with retained evidence,
    /// not rollback of both records or forgotten history. Writer fencing and
    /// trustworthy latest records remain caller obligations.
    /// For in-process readback use [`Self::reconcile`] and keep the live allocator
    /// and canonical capability rather than constructing replacements.
    /// Read the window and epoch records from one consistent fenced snapshot before
    /// calling this method; a failed restore is terminal for canonical use.
    /// # Errors
    /// Rejects mismatching domains, unauthentic packets, wrong directions/classes,
    /// response correlation failures, counters inconsistent with retained history,
    /// or an IV high-water below the required retained sending-IV end.
    /// Every failure permanently revokes canonical state for the supplied bindings;
    /// discard the failed SA, its stored records, keys and copied replies.
    pub fn restore(
        expected: &Ikev2CommittedWindowDomain<P>,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        record: &Ikev2CommittedWindowRecord<P>,
        epoch: &P::Epoch,
    ) -> Result<Self, Ikev2WindowError> {
        let restored = Self::restore_checked(expected, profile, keys, record, epoch);
        if restored.is_err() {
            crate::canonical::invalidate_profile(expected);
            crate::canonical::invalidate_profile(&P::from_epoch(epoch));
            crate::canonical::invalidate_profile(&record.domain);
        }
        restored
    }

    fn restore_checked(
        expected: &Ikev2CommittedWindowDomain<P>,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        record: &Ikev2CommittedWindowRecord<P>,
        epoch: &P::Epoch,
    ) -> Result<Self, Ikev2WindowError> {
        Self::validate_record(expected, profile, keys, record, epoch)?;
        Ok(Self {
            record: record.clone(),
            canonical_binding: epoch.clone(),
            instance: Arc::new(()),
            quiescent: false,
            witness: None,
            reconcile_terminal: false,
            observed_peer_request: Cell::new(None),
            receive: empty::ReceiveState::new(record.next_receive),
            sync_live: false,
            sync_closed: false,
            sync_last_observed_unix_ms: record
                .sync_recovery()
                .map(|recovery| recovery.last_observed_unix_ms()),
        })
    }

    fn validate_record(
        expected: &Ikev2CommittedWindowDomain<P>,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        record: &Ikev2CommittedWindowRecord<P>,
        epoch: &P::Epoch,
    ) -> Result<(), Ikev2WindowError> {
        use Ikev2WindowError as Error;
        if expected != &record.domain || expected != &P::from_epoch(epoch) {
            return Err(Error::DomainMismatch);
        }
        expected.check(profile, keys)?;
        if let Some(sync) = record.sync_state() {
            sync.validate(record)?;
            P::check_sync_evidence(sync, epoch)?;
        }
        if let Some(recovery) = record.sync_recovery() {
            recovery.validate_packets(record, profile, keys, epoch)?;
        }
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
                    P::check_local_ordinary(&request, epoch)?;
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
                        P::check_local_ordinary(&response, epoch)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Derive a canonical recipe from this window's checked persisted epoch binding.
    ///
    /// This primitive adds no empty-request admission, receive-floor advancement
    /// or transmission authority. DPD-facing windows must use
    /// [`Self::enable_empty_replies`] and [`Self::reply_empty`]: primitive replies
    /// leave the receive floor behind and can drop the next nonempty request.
    /// Use the window's reply admission on every reply, including cached bytes;
    /// a minted capability does not track later lifecycle changes. [`Self::ready`]
    /// is the stricter admission check for new work.
    /// # Errors
    /// Refuses a quiescent, syncing or terminal window, an ineligible marker or
    /// key binding, or unavailable canonical provider policy/qualification.
    pub(crate) fn canonical_replies(
        &self,
        policy: crate::canonical::Ikev2CanonicalPolicy,
    ) -> Result<
        crate::canonical::Ikev2CanonicalEmptyReplies<P>,
        crate::canonical::Ikev2CanonicalError,
    > {
        self.ready()
            .map_err(|_| crate::canonical::Ikev2CanonicalError::LifecycleBlocked)?;
        crate::canonical::Ikev2CanonicalEmptyReplies::<P>::from_epoch(
            &self.canonical_binding,
            policy,
        )
    }

    /// Last acknowledged record; while quiescent it may not be the latest durable state.
    pub const fn record(&self) -> &Ikev2CommittedWindowRecord<P> {
        &self.record
    }

    /// Authenticate a complete peer SK packet through the admitted module.
    ///
    /// # Errors
    /// Rejects key/domain mismatches, authentication, framing or inner-chain errors,
    /// and every sync Notify including mixed/malformed sync shapes at ordinary ID 0.
    /// An otherwise applicable, authenticated SKF returns
    /// [`Ikev2WindowError::UnsupportedShape`] before parsing its partial inner
    /// chain. Unauthenticated or foreign packets remain ordinary drops.
    pub fn open_peer(
        &self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        wire: &[u8],
    ) -> Result<Ikev2AuthenticatedOrdinary<P>, Ikev2WindowError> {
        packet::open(&self.record.domain, profile, keys, wire, true)
    }

    /// Check the window's current ordinary lifecycle availability.
    ///
    /// Read-only replies have a narrower admission check within [`Self::reply_empty`]
    /// and [`Self::replay_response`], permitting an outbound-only uncertain commit.
    /// This snapshot grants no receive or transmission authority; the consumer
    /// must keep the applicable authority through transmission.
    /// # Errors
    /// Refuses an uncertain commit, pending sync, uncertain outcome or closed SA.
    pub fn ready(&self) -> Result<(), Ikev2WindowError> {
        if self.quiescent {
            return Err(Ikev2WindowError::CommitUncertain);
        }
        self.lifecycle_ready()
    }

    fn ready_for_reply(&self) -> Result<(), Ikev2WindowError> {
        if self.quiescent && !self.has_outbound_witness() {
            return Err(Ikev2WindowError::CommitUncertain);
        }
        self.lifecycle_ready()
    }

    fn ready_for_cached_response(&self) -> Result<(), Ikev2WindowError> {
        self.ready_for_reply()?;
        self.receive.check_cached_reply()
    }

    fn lifecycle_ready(&self) -> Result<(), Ikev2WindowError> {
        if self.sync_closed {
            return Err(Ikev2WindowError::SyncClosed);
        }
        match self.record.sync_state().map(|state| state.disposition()) {
            None | Some(Ikev2SyncDisposition::Continue) => Ok(()),
            Some(Ikev2SyncDisposition::AwaitLocalSync) => Err(Ikev2WindowError::SyncInProgress),
            Some(Ikev2SyncDisposition::OutcomeUncertain) => Err(Ikev2WindowError::OutcomeUncertain),
            Some(Ikev2SyncDisposition::CloseIkeSa) => Err(Ikev2WindowError::SyncClosed),
        }
    }
    fn next_record(&self) -> Result<Ikev2CommittedWindowRecord<P>, Ikev2WindowError> {
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
        record: Ikev2CommittedWindowRecord<P>,
        outcome: Option<Bytes>,
        receive_boundary: bool,
    ) -> Ikev2PreparedWindow<'_, P> {
        self.remember_prepared(
            &record,
            if receive_boundary {
                reconcile::Kind::Inbound
            } else {
                reconcile::Kind::Outbound
            },
        );
        Ikev2PreparedWindow {
            window: self,
            record,
            outcome,
            receive_boundary,
        }
    }

    fn prepare_request_with(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        sealing: P::Sealing<'_>,
        exchange: Ikev2ExchangeKind,
        payloads: PayloadChain<'_>,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Ikev2WindowError> {
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
            sealing,
            record.domain.header(exchange, id, false),
            payloads,
        )?;
        record.outbound = Some(Ikev2CommittedExchangeRecord {
            request: request.into_wire(),
            response: None,
            outcome: None,
        });
        record.next_send = id.checked_add(1);
        if let Some(sync) = &mut record.sync {
            sync.highest_local_request = Some(id);
        }
        Ok(self.prepared(record, None, false))
    }

    /// Classify authenticated nonempty work against the live window-one floor.
    ///
    /// Returning `New` locks the pending request's exact identity and retains its
    /// ID in the volatile synchronization drop floor. It grants no effects and
    /// advances no floor. Both synchronization directions account for this work
    /// automatically. During restart reconstruction, the first
    /// nonempty request may skip a lost stateless prefix; its commit ends that mode.
    /// Older durable responses cease to apply when an empty reply advances the
    /// live floor or a new nonempty request locks pending work.
    /// An outbound-only uncertain write permits only the cached-response branch;
    /// new work still requires ordinary readiness.
    /// # Errors
    /// Drops wrong direction/domain, forward gaps, stale IDs and same-ID changed
    /// bytes. Use [`Self::reply_empty`] for stateless empty requests.
    pub fn request_disposition(
        &self,
        request: &Ikev2AuthenticatedOrdinary<P>,
    ) -> Result<Ikev2OrdinaryRequestDisposition, Ikev2WindowError> {
        let cached = self
            .record
            .inbound
            .as_ref()
            .is_some_and(|entry| entry.request == request.wire);
        if cached {
            self.ready_for_cached_response()?;
        } else {
            self.ready()?;
        }
        if request.domain != self.record.domain || request.header.flags.response() {
            return Err(Ikev2WindowError::Drop);
        }
        request.require_work()?;
        if cached {
            if !self.cached_response_applies(request) {
                return Err(Ikev2WindowError::Drop);
            }
            return Ok(Ikev2OrdinaryRequestDisposition::CachedResponse);
        }
        let mut pending = self.receive.pending.borrow_mut();
        if pending.as_ref().is_some_and(|wire| wire != &request.wire)
            || (pending.is_none() && !self.receive.accepts_new(request.header.message_id))
        {
            return Err(Ikev2WindowError::Drop);
        }
        if pending.is_none() {
            *pending = Some(request.wire.clone());
        }
        self.observed_peer_request.set(
            self.observed_peer_request
                .get()
                .max(Some(request.header.message_id)),
        );
        Ok(Ikev2OrdinaryRequestDisposition::New)
    }

    fn prepare_response_with(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        sealing: P::Sealing<'_>,
        request: &Ikev2AuthenticatedOrdinary<P>,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Ikev2WindowError> {
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
            sealing,
            record
                .domain
                .header(exchange, request.header.message_id, true),
            payloads,
        )?;
        record.inbound = Some(Ikev2CommittedExchangeRecord {
            request: request.wire.clone(),
            response: Some(response.into_wire()),
            outcome: Some(outcome.clone()),
        });
        record.next_receive = request.header.message_id.checked_add(1);
        if let Some(sync) = &mut record.sync {
            sync.highest_peer_request = Some(request.header.message_id);
        }
        Ok(self.prepared(record, Some(outcome), true))
    }

    /// Prepare settlement of the single pending outbound request after semantic checks.
    ///
    /// # Errors
    /// Drops wrong domain, exchange, ID or response flag, and all delayed/duplicate
    /// responses after settlement. A duplicate response cannot create another outcome.
    pub fn prepare_completion(
        &mut self,
        response: &Ikev2AuthenticatedOrdinary<P>,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Ikev2WindowError> {
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
        Ok(self.prepared(record, Some(outcome), false))
    }

    /// Replay the committed pending local request without new state.
    ///
    /// No request or a settled exchange yields `None`. A peer may forget its
    /// settled response, so replay is never a local liveness probe.
    /// # Errors
    /// Quiescent runtimes must resolve readback first.
    pub fn replay_request(&self) -> Result<Option<Ikev2ExactReplay<'_>>, Ikev2WindowError> {
        self.ready()?;
        Ok(self
            .record
            .outbound
            .as_ref()
            .filter(|entry| entry.response.is_none())
            .map(|entry| Ikev2ExactReplay {
                bytes: &entry.request,
            }))
    }

    /// Replay only the exact response applicable to this authenticated cached duplicate.
    ///
    /// This lookup never admits pending work or changes synchronization history.
    /// # Errors
    /// Drops stale/mismatching inputs; refuses uncertain inbound/sync commits.
    /// An outbound-only witness permits this read-only replay while new work
    /// remains blocked. Enabled canonical policy and revocation are rechecked.
    pub fn replay_response(
        &self,
        request: &Ikev2AuthenticatedOrdinary<P>,
    ) -> Result<Ikev2ExactReplay<'_>, Ikev2WindowError> {
        self.ready_for_cached_response()?;
        if request.domain != self.record.domain || request.header.flags.response() {
            return Err(Ikev2WindowError::Drop);
        }
        request.require_work()?;
        if !self.cached_response_applies(request) {
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

    fn cached_response_applies(&self, request: &Ikev2AuthenticatedOrdinary<P>) -> bool {
        request.domain == self.record.domain
            && !request.header.flags.response()
            && self
                .record
                .inbound
                .as_ref()
                .is_some_and(|entry| entry.request == request.wire)
            && self.receive.next == request.header.message_id.checked_add(1)
            && self.receive.pending.borrow().is_none()
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
        if self.ready().is_err()
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
pub struct Ikev2PreparedWindow<'a, P: RecoveryProfile = Gcm> {
    window: &'a mut Ikev2CommittedWindow<P>,
    record: Ikev2CommittedWindowRecord<P>,
    outcome: Option<Bytes>,
    receive_boundary: bool,
}
impl<P: RecoveryProfile> Ikev2PreparedWindow<'_, P> {
    /// Exact candidate to persist atomically with SA and consumer outcome.
    pub const fn record(&self) -> &Ikev2CommittedWindowRecord<P> {
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
        committed: &Ikev2CommittedWindowRecord<P>,
    ) -> Result<Ikev2WindowCommit, Ikev2WindowError> {
        if committed != &self.record {
            return Err(Ikev2WindowError::CommitMismatch);
        }
        self.window.witness = None;
        self.window.record = self.record;
        self.window.quiescent = false;
        if self.receive_boundary {
            self.window.adopt_receive_boundary()?;
        }
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
    Ikev2CommittedExchangeRecord,
    Ikev2WindowCommit,
    Ikev2ExactReplay<'_>,
    Ikev2SyncCommit,
    Ikev2SyncResponse,
    Ikev2SyncClock,
    Ikev2SyncRecoveryPolicy,
    Ikev2SyncInitiatorCommit,
    Ikev2SyncInitiatorAction,
);

macro_rules! profile_redacted_debug {
    ($($name:ident),* $(,)?) => { $(impl<P: profile::RecoveryProfile> fmt::Debug for $name<P> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($name)).finish_non_exhaustive()
        }
    })* };
}
profile_redacted_debug!(
    Ikev2CommittedWindowDomain,
    Ikev2CommittedWindowRecord,
    Ikev2SyncResponderRecord,
    Ikev2SyncAttemptRecord,
    Ikev2SyncRecoveryRecord,
    Ikev2AuthenticatedOrdinary,
    Ikev2CommittedWindow,
    Ikev2SyncReadiness,
    Ikev2RuntimeSyncNegotiation
);
macro_rules! profile_lifetime_redacted_debug {
    ($($name:ident),* $(,)?) => { $(impl<P: RecoveryProfile> fmt::Debug for $name<'_, P> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(concat!(stringify!($name), "<'_>")).finish_non_exhaustive()
        }
    })* };
}
profile_lifetime_redacted_debug!(
    Ikev2PreparedWindow,
    Ikev2EmptyReply,
    Ikev2AdmittedSyncResponse,
    Ikev2PreparedSyncResponse,
    Ikev2AdmittedSyncInitiation,
    Ikev2PreparedSyncInitiation
);

impl Ikev2CommittedWindow<Gcm> {
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
    ) -> Result<Ikev2PreparedWindow<'_, Gcm>, Ikev2WindowError> {
        self.prepare_request_with(profile, keys, allocation, exchange, payloads)
    }
    /// Prepare the exact reply and outcome to an admitted nonempty request.
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
        request: &Ikev2AuthenticatedOrdinary<Gcm>,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_, Gcm>, Ikev2WindowError> {
        self.prepare_response_with(profile, keys, allocation, request, payloads, outcome)
    }
}

impl Ikev2CommittedWindow<Ikev2CbcRecoveryProfile> {
    /// Seal with one fresh admitted random CBC IV; no reservation is used.
    /// Persist the exact candidate before transmission. Empty probes are refused.
    /// # Errors
    /// Refuses unresolved/pending work, exhausted IDs, invalid payloads or sealing failure.
    pub fn prepare_request(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        exchange: Ikev2ExchangeKind,
        payloads: PayloadChain<'_>,
    ) -> Result<Ikev2PreparedWindow<'_, Ikev2CbcRecoveryProfile>, Ikev2WindowError> {
        self.prepare_request_with(profile, keys, (), exchange, payloads)
    }
    /// Seal with one fresh admitted random CBC IV; no reservation is used.
    /// Commit the exact reply and outcome atomically before releasing either.
    /// # Errors
    /// Refuses stale/duplicate/gapped requests and ordinary preparation failures.
    pub fn prepare_response(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        request: &Ikev2AuthenticatedOrdinary<Ikev2CbcRecoveryProfile>,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
    ) -> Result<Ikev2PreparedWindow<'_, Ikev2CbcRecoveryProfile>, Ikev2WindowError> {
        self.prepare_response_with(profile, keys, (), request, payloads, outcome)
    }
}
