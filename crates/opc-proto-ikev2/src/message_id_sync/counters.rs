//! Pure RFC 6311 section 5.1 counter proposals and response correlation.

use std::fmt;

use super::{
    decode_ikev2_message_id_sync_notify, Ikev2MessageIdSync, Ikev2MessageIdSyncAgreement,
    Ikev2MessageIdSyncMode, Ikev2MessageIdSyncRuleError, Ikev2MessageIdSyncSa,
};
use crate::{Header, Ikev2NotifyPayload, PayloadChain, PayloadType, EXCHANGE_TYPE_INFORMATIONAL};

/// Caller-supplied counter knowledge for one SA, in local orientation.
///
/// These are arithmetic inputs, not durable-window authority. `None` means
/// no prior request/proposal and differs from `Some(0)`. Default is the empty
/// history, appropriate only when that is true (not for an established
/// original initiator that has sent IKE_AUTH). Record outstanding ordinary
/// requests as used even if no reply arrived. A proposal does not consume
/// its proposed ordinary ID, but any subsequent proposal must exceed it.
///
/// Restoration can supply only durable knowledge; unwritten empty requests
/// answered before a crash cannot contribute to the restored drop floor.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ikev2MessageIdSyncCounters {
    /// Lower bound for the next local ordinary request ID.
    pub next_send: u32,
    /// Lower bound for the next peer ordinary request ID.
    pub next_receive: u32,
    /// Highest ordinary local request ID known to have been used.
    pub highest_local_request: Option<u32>,
    /// Highest ordinary peer request ID known to have been received.
    pub highest_peer_request: Option<u32>,
    /// Highest local sync proposal known to have been made, including uncertain ones.
    pub highest_local_proposal: Option<u32>,
    /// Highest accepted peer sync proposal; never placed in an ordinary replay cache.
    pub highest_peer_proposal: Option<u32>,
}

impl fmt::Debug for Ikev2MessageIdSyncCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2MessageIdSyncCounters")
            .finish_non_exhaustive()
    }
}

impl Ikev2MessageIdSyncCounters {
    /// Construct pure floor inputs with no known ordinary or proposal history.
    ///
    /// Populate every known history field before evaluation. This constructor
    /// does not restore durable state or validate whether a floor is usable.
    #[must_use]
    pub const fn new(next_send: u32, next_receive: u32) -> Self {
        Self {
            next_send,
            next_receive,
            highest_local_request: None,
            highest_peer_request: None,
            highest_local_proposal: None,
            highest_peer_proposal: None,
        }
    }

    fn exhausted(self) -> Ikev2MessageIdSyncRuleError {
        if self.highest_local_request == Some(u32::MAX) {
            Ikev2MessageIdSyncRuleError::CloseIkeSa
        } else {
            Ikev2MessageIdSyncRuleError::RekeyRequired
        }
    }

    fn after(self, highest: Option<u32>) -> Result<u32, Ikev2MessageIdSyncRuleError> {
        match highest {
            None => Ok(0),
            Some(value) => value.checked_add(1).ok_or_else(|| self.exhausted()),
        }
    }

    fn usable(mut self) -> Result<Self, Ikev2MessageIdSyncRuleError> {
        self.next_send = self
            .next_send
            .max(self.after(self.highest_local_request)?)
            .max(self.highest_local_proposal.unwrap_or(0));
        self.next_receive = self
            .next_receive
            .max(self.after(self.highest_peer_request)?)
            .max(self.highest_peer_proposal.unwrap_or(0));
        // Preserve the last representable ID for attempting rekey. Never
        // call a MAX-valued result successful recovery or saturate overflow.
        if self.next_send == u32::MAX || self.next_receive == u32::MAX {
            return Err(self.exhausted());
        }
        Ok(self)
    }

    fn with_pending(
        mut self,
        sa: Ikev2MessageIdSyncSa,
        pending: Option<&Ikev2MessageIdSyncPending>,
    ) -> Result<Self, Ikev2MessageIdSyncRuleError> {
        if let Some(pending) = pending {
            if pending.sa != sa
                || self.highest_local_proposal.is_some_and(|highest| {
                    highest > pending.notification.expected_send_req_message_id()
                })
            {
                return Err(Ikev2MessageIdSyncRuleError::Drop);
            }
            self.next_send = self
                .next_send
                .max(pending.notification.expected_send_req_message_id());
            self.next_receive = self
                .next_receive
                .max(pending.notification.expected_recv_req_message_id());
            self.highest_local_proposal = Some(
                self.highest_local_proposal
                    .unwrap_or(0)
                    .max(pending.notification.expected_send_req_message_id()),
            );
        }
        Ok(self)
    }
}

/// SA-bound pending local proposal for pure simultaneous-sync calculations.
///
/// A value has no entropy, persistence or transmit authority. Runtime creation
/// must generate a fresh nonce through admitted entropy and commit a strictly
/// higher proposal before use. Lifecycles must retain only the current pending
/// proposal and consume a matched result once; these pure values are copyable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2MessageIdSyncPending {
    sa: Ikev2MessageIdSyncSa,
    notification: Ikev2MessageIdSync,
}

impl Ikev2MessageIdSyncPending {
    /// Rebuild a same-SA proposal from trusted latest persisted fields.
    ///
    /// This preserves wire data only. It grants no entropy, send or response
    /// authority. The recovery runtime additionally validates attempt history,
    /// floors, exact protected bytes and the original event budget. An uncertain
    /// restored attempt must be superseded by a higher fresh proposal.
    /// # Errors
    /// Rejects counters at MAX, which cannot represent successful recovery.
    pub fn from_persisted(
        sa: Ikev2MessageIdSyncSa,
        notification: Ikev2MessageIdSync,
    ) -> Result<Self, Ikev2MessageIdSyncRuleError> {
        if notification.expected_send_req_message_id() == u32::MAX
            || notification.expected_recv_req_message_id() == u32::MAX
        {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        Ok(Self { sa, notification })
    }

    /// Return the proposed wire data, without authorizing its transmission.
    #[must_use]
    pub const fn notification(self) -> Ikev2MessageIdSync {
        self.notification
    }

    /// Return the SA whose counter orientation and nonce this proposal uses.
    #[must_use]
    pub const fn sa(self) -> Ikev2MessageIdSyncSa {
        self.sa
    }
}

impl fmt::Debug for Ikev2MessageIdSyncPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2MessageIdSyncPending")
            .finish_non_exhaustive()
    }
}

impl Ikev2MessageIdSyncAgreement {
    /// Compute the least proposal exceeding every known used/proposed local ID.
    ///
    /// `nonce` is a synthetic/caller-supplied arithmetic input here, not an
    /// entropy source or an alternative production nonce-generation path.
    /// The caller must provide all possibly used IDs, including any pending
    /// proposal. A higher retry is obtained by recording the old proposal in
    /// `highest_local_proposal`; no state is updated or persisted here.
    ///
    /// # Errors
    /// Returns `Drop` without negotiation; exhaustion returns `RekeyRequired`
    /// while a local ordinary ID remains, otherwise `CloseIkeSa`.
    pub fn propose(
        self,
        counters: Ikev2MessageIdSyncCounters,
        nonce: [u8; 4],
    ) -> Result<Ikev2MessageIdSyncPending, Ikev2MessageIdSyncRuleError> {
        if self.mode() != Ikev2MessageIdSyncMode::Negotiated {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        let mut next = counters.usable()?;
        next.next_send = next.next_send.max(next.after(next.highest_local_proposal)?);
        let next = next.usable()?;
        Ok(Ikev2MessageIdSyncPending {
            sa: self.sa(),
            notification: Ikev2MessageIdSync::new(nonce, next.next_send, next.next_receive),
        })
    }

    fn opened_sync(
        self,
        header: &Header,
        payloads: PayloadChain<'_>,
        response: bool,
    ) -> Result<Ikev2MessageIdSync, Ikev2MessageIdSyncRuleError> {
        if self.mode() != Ikev2MessageIdSyncMode::Negotiated || header.message_id != 0 {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        self.sa()
            .validate_peer(header, EXCHANGE_TYPE_INFORMATIONAL, response)?;
        let mut payloads = payloads.iter();
        let Some(Ok(payload)) = payloads.next() else {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        };
        if payload.payload_type != PayloadType::Notify || payloads.next().is_some() {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        let notify = Ikev2NotifyPayload::decode_body(payload.body)
            .map_err(|_| Ikev2MessageIdSyncRuleError::Drop)?;
        decode_ikev2_message_id_sync_notify(notify)
            .map_err(|_| Ikev2MessageIdSyncRuleError::Drop)?
            .ok_or(Ikev2MessageIdSyncRuleError::Drop)
    }

    /// Evaluate an already authenticated, completely opened peer sync request.
    ///
    /// Requires the matching SA, opposite original-role bit, protected
    /// INFORMATIONAL request, ID zero and exactly one sync Notify. Fully
    /// reassembled SKF input is allowed. ESP-counter sync is out of scope.
    /// The caller supplies same-SA counter knowledge and its pending proposal.
    /// `Ok` returns candidate counters and nonce-echoing P2/M2 response data;
    /// persist the cutover before any effect. This method changes nothing.
    ///
    /// # Errors
    /// Returns `Drop` for invalid framing, missing negotiation, foreign or
    /// superseded pending state, or M1 at/below any known peer ordinary/sync
    /// request. Duplicates never produce cached sync replies. Exhaustion returns
    /// `RekeyRequired` or `CloseIkeSa`; neither means recovery succeeded.
    pub fn evaluate_request(
        self,
        header: &Header,
        payloads: PayloadChain<'_>,
        counters: Ikev2MessageIdSyncCounters,
        pending: Option<&Ikev2MessageIdSyncPending>,
    ) -> Result<(Ikev2MessageIdSyncCounters, Ikev2MessageIdSync), Ikev2MessageIdSyncRuleError> {
        let request = self.opened_sync(header, payloads, false)?;
        let m1 = request.expected_send_req_message_id();
        if counters
            .highest_peer_request
            .into_iter()
            .chain(counters.highest_peer_proposal)
            .any(|seen| m1 <= seen)
        {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        let mut next = counters.with_pending(self.sa(), pending)?.usable()?;
        next.next_send = next.next_send.max(request.expected_recv_req_message_id());
        next.next_receive = next.next_receive.max(m1);
        next.highest_peer_proposal = Some(m1);
        let next = next.usable()?;
        Ok((
            next,
            Ikev2MessageIdSync::new(request.nonce(), next.next_send, next.next_receive),
        ))
    }

    /// Correlate an already authenticated response with the current proposal.
    ///
    /// Framing rules match [`Self::evaluate_request`], with the response bit
    /// set. The exact four-octet nonce must match and neither wire counter may
    /// undercut the proposal. Map P2/M2 into local receive/send orientation,
    /// then take component-wise maxima with current and pending floors. This
    /// prevents a delayed response rolling back a concurrent peer cutover.
    /// `Ok` is candidate state only. Durable once-only completion and pending
    /// ordinary-work disposition belong to the later lifecycle, not this model.
    ///
    /// # Errors
    /// Returns `Drop` for missing negotiation, invalid framing, wrong nonce/SA
    /// or undercut counters, including a superseded pending proposal. Exhaustion
    /// returns `RekeyRequired` or `CloseIkeSa`.
    pub fn evaluate_response(
        self,
        header: &Header,
        payloads: PayloadChain<'_>,
        counters: Ikev2MessageIdSyncCounters,
        pending: &Ikev2MessageIdSyncPending,
    ) -> Result<Ikev2MessageIdSyncCounters, Ikev2MessageIdSyncRuleError> {
        let response = self.opened_sync(header, payloads, true)?;
        let proposal = pending.notification;
        if pending.sa != self.sa()
            || response.nonce() != proposal.nonce()
            || response.expected_send_req_message_id() < proposal.expected_recv_req_message_id()
            || response.expected_recv_req_message_id() < proposal.expected_send_req_message_id()
        {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        let mut next = counters.with_pending(self.sa(), Some(pending))?.usable()?;
        next.next_send = next.next_send.max(response.expected_recv_req_message_id());
        next.next_receive = next
            .next_receive
            .max(response.expected_send_req_message_id());
        next.usable()
    }
}
