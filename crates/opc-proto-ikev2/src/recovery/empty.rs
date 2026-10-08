use std::{cell::RefCell, marker::PhantomData};

use bytes::Bytes;

use super::{
    Ikev2AuthenticatedOrdinary as Request, Ikev2CommittedWindow as Window,
    Ikev2WindowError as Error,
};
use crate::canonical::{
    Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalPolicy as Policy, Ikev2CanonicalReply,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceivePhase {
    // No empty capability yet: restoring may have lost an unwritten prefix.
    Restored,
    // Enabling empty replies always recovers that prefix until a new boundary.
    Reconstructing,
    // An inbound exchange or sync cutover committed in this runtime.
    Current,
}

pub(super) struct ReceiveState {
    pub next: Option<u32>,
    phase: ReceivePhase,
    pub pending: RefCell<Option<Bytes>>,
    replies: Option<Canonical>,
    last_empty: Option<(u32, Bytes)>,
}

impl ReceiveState {
    pub fn new(next: Option<u32>) -> Self {
        Self {
            next,
            phase: ReceivePhase::Restored,
            pending: RefCell::new(None),
            replies: None,
            last_empty: None,
        }
    }

    pub fn accepts_new(&self, id: u32) -> bool {
        self.next.is_some_and(|next| {
            id == next || (self.phase == ReceivePhase::Reconstructing && id > next)
        }) && self.last_empty.as_ref().is_none_or(|(last, _)| id > *last)
    }

    fn retire_before(&self, next: Option<u32>) -> Result<(), Error> {
        let floor = match next {
            Some(next) => next.checked_sub(1),
            None => Some(u32::MAX),
        };
        if let Some(replies) = &self.replies {
            match floor {
                Some(floor) => replies.retire_through(floor),
                None => replies.check_live(),
            }
            .map_err(Error::Canonical)?;
        }
        Ok(())
    }

    pub(super) fn boundary_next(&self, recorded: Option<u32>) -> Option<u32> {
        match (self.next, recorded) {
            (Some(live), Some(recorded)) => Some(live.max(recorded)),
            _ => None,
        }
    }

    pub(super) fn adopt_boundary(&mut self, next: Option<u32>) {
        self.next = next;
        self.phase = ReceivePhase::Current;
        self.pending.get_mut().take();
        self.last_empty = None;
    }

    pub(super) fn retire_readback(&self, next: Option<u32>, boundary: bool) -> Result<(), Error> {
        let retire_before = if boundary {
            next
        } else {
            self.last_empty.as_ref().map_or(next, |(id, _)| Some(*id))
        };
        self.retire_before(retire_before)
    }

    pub(super) fn discard_replies(&mut self) {
        self.replies = None;
        self.last_empty = None;
    }
}

/// What an admitted empty request establishes about freshness (RFC 7296 §2.4).
///
/// No variant authorizes an endpoint, key, bearer, lifetime or application-outcome
/// mutation. Authentication and the consumer's current SA fence still apply.
///
/// Consumers must allow future observations:
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2EmptyReplyObservation as Observation;
/// fn exhaustive(value: Observation) {
///     match value {
///         Observation::Fresh | Observation::Replayed | Observation::Uncertain => (),
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2EmptyReplyObservation {
    /// New in-order traffic beyond a boundary committed in this runtime.
    Fresh,
    /// An identical request already admitted here; no fresh liveness evidence.
    Replayed,
    /// A restored prefix may have been answered before the crash; no fresh liveness.
    Uncertain,
}

/// Verified empty response holding an exclusive borrow of its admitted window.
///
/// Submit promptly while retaining this value and the external fenced SA/send
/// authority. The borrow prevents an SDK lifecycle transition before submission.
/// Copying the bytes does not copy that authority: discard copies on trust loss,
/// teardown or a blocked lifecycle. This type performs no transport operation.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::{Ikev2CommittedWindow, Ikev2AuthenticatedOrdinary};
/// fn stale(mut window: Ikev2CommittedWindow, request: &Ikev2AuthenticatedOrdinary) {
///     let reply = window.reply_empty(request).unwrap();
///     window.delete();
///     let _ = reply.bytes();
/// }
/// ```
pub struct Ikev2EmptyReply<'a> {
    reply: Ikev2CanonicalReply,
    observation: Ikev2EmptyReplyObservation,
    window: PhantomData<&'a mut Window>,
}

impl Ikev2EmptyReply<'_> {
    /// Complete immutable IKE packet without transport framing.
    pub fn bytes(&self) -> &[u8] {
        self.reply.bytes()
    }

    /// Freshness evidence only; never repeat an outcome for a replay or unknown prefix.
    pub const fn observation(&self) -> Ikev2EmptyReplyObservation {
        self.observation
    }
}

impl Window {
    /// Enable zero-write empty handling for this checked window and canonical policy.
    ///
    /// Qualify every intended algorithm before admitting a DPD-sending deployment.
    /// A successful call owns the epoch's single canonical capability for this runtime.
    /// Refusal has no ordinary-IV, committed-response or alternate-provider fallback.
    /// After restore, this always enables recovery of a lost zero-write prefix.
    /// A boundary committed in this runtime instead retains strict admission.
    /// Neither mode widens the declared window of one or invents fresh liveness.
    /// A restored `AwaitLocalSync` window must finish synchronization first.
    /// A lifecycle or capability-active refusal preserves this checked runtime
    /// and the epoch: retry after sync completes or the old capability drops.
    /// # Errors
    /// Refuses blocked lifecycle, an existing capability, or any canonical refusal.
    pub fn enable_empty_replies(&mut self, policy: Policy) -> Result<(), Error> {
        if self.reconcile_terminal {
            return Err(Error::Canonical(
                crate::canonical::Ikev2CanonicalError::Invalidated,
            ));
        }
        self.ready()?;
        if let Some(replies) = &self.receive.replies {
            replies.check_live().map_err(Error::Canonical)?;
            return Err(Error::Canonical(
                crate::canonical::Ikev2CanonicalError::CapabilityActive,
            ));
        }
        let replies = self.canonical_replies(policy).map_err(Error::Canonical)?;
        let floor = match self.receive.next {
            Some(next) => next.checked_sub(1),
            None => Some(u32::MAX),
        };
        if let Some(floor) = floor {
            replies.retire_through(floor).map_err(Error::Canonical)?;
        }
        self.receive.replies = Some(replies);
        if self.receive.phase == ReceivePhase::Restored {
            self.receive.phase = ReceivePhase::Reconstructing;
        }
        Ok(())
    }

    /// Current volatile next peer ID, including empty exchanges; `None` is exhausted.
    ///
    /// This is not a persistence input. The record's floor advances only when an
    /// ordinary inbound result or synchronization cutover is committed.
    pub const fn next_receive(&self) -> Option<u32> {
        self.receive.next
    }

    /// Whether a trusted restart still permits stateless-prefix reconstruction.
    pub const fn is_reconstructing(&self) -> bool {
        matches!(self.receive.phase, ReceivePhase::Reconstructing)
    }

    /// Admit and answer an authenticated empty INFORMATIONAL without a durable write.
    ///
    /// Enforces RFC 7296 §§1.4, 2.1–2.4: current lifecycle and window admission,
    /// exact request retransmissions, unchanged response bytes, independent request
    /// directions and checked ID exhaustion. The declared receive window is one;
    /// newer requests retire older canonical cache entries. The next nonempty
    /// request commits its result and the repaired floor through `prepare_response`.
    ///
    /// Every invocation, including a cache hit, rechecks `ready()` and admission.
    /// Failed canonical evaluations retain their request identity and charged
    /// attempt history, but advance no receive counter or liveness/effect authority.
    /// Authenticated admitted IDs still join the volatile RFC 6311 drop history.
    /// Empty acknowledgements of nonempty requests never use this path. NAT
    /// keepalives are outside IKE and cannot produce authenticated request evidence.
    /// # Errors
    /// Drops wrong class/binding, changed/stale/gapped requests and pending nonempty
    /// work; refuses disabled/blocked/unavailable canonical handling without fallback.
    pub fn reply_empty(&mut self, request: &Request) -> Result<Ikev2EmptyReply<'_>, Error> {
        self.ready()?;
        let id = request
            .canonical_message_id(&self.record.domain)
            .map_err(|_| Error::Drop)?;
        if self.receive.pending.borrow().is_some() {
            return Err(Error::Drop);
        }
        let replies = self
            .receive
            .replies
            .as_ref()
            .ok_or(Error::EmptyRepliesDisabled)?;
        let duplicate = self
            .receive
            .last_empty
            .as_ref()
            .is_some_and(|(last, _)| *last == id);
        if duplicate {
            if self.receive.last_empty.as_ref().map(|(_, wire)| wire) != Some(&request.wire) {
                return Err(Error::Drop);
            }
        } else {
            if !self.receive.accepts_new(id) {
                return Err(Error::Drop);
            }
            // Section 2.1 permits forgetting a response once the next request
            // arrives for our declared window of one, even before replying.
            self.receive.retire_before(Some(id))?;
            self.receive.last_empty = Some((id, request.wire.clone()));
        }
        self.observed_peer_request
            .set(self.observed_peer_request.get().max(Some(id)));
        let reply = replies.reply(request).map_err(Error::Canonical)?;
        if self.receive.next.is_some_and(|next| next <= id) {
            self.receive.next = id.checked_add(1);
        }
        let observation = if duplicate {
            Ikev2EmptyReplyObservation::Replayed
        } else if self.receive.phase != ReceivePhase::Current {
            Ikev2EmptyReplyObservation::Uncertain
        } else {
            Ikev2EmptyReplyObservation::Fresh
        };
        Ok(Ikev2EmptyReply {
            reply,
            observation,
            window: PhantomData,
        })
    }

    // Called only after adopting a durably acknowledged inbound/cutover record.
    // Outbound commits must not discard a volatile empty prefix or its cache.
    pub(super) fn adopt_receive_boundary(&mut self) -> Result<(), Error> {
        self.receive
            .adopt_boundary(self.receive.boundary_next(self.record.next_receive));
        if let Err(error) = self.receive.retire_before(self.receive.next) {
            // The record is committed; failed cache revocation grants no authority.
            // Resolve through trusted readback or permanent SA teardown.
            self.quiescent = true;
            return Err(error);
        }
        Ok(())
    }

    /// Consume a permanently deleted SA's runtime and remove its canonical ledger.
    ///
    /// Every consumer teardown must call this: peer Delete, local expiry, DPD
    /// timeout, RFC 6311 `OutcomeUncertain`/`CloseIkeSa`, and the old SA once it is
    /// deleted after rekey. Keep the old epoch
    /// for permitted retransmissions while both rekey epochs still exist. For
    /// teardown after decoding fails before window restore, call
    /// [`crate::canonical::Ikev2CanonicalEmptyReplies::delete_epoch`] with the
    /// trusted IV record. Window restore failures already revoke canonical state.
    /// Discard outer keys, stored SA records and reply copies in every case.
    /// Ordinary runtime drop for fenced readback is not permanent SA deletion.
    pub fn delete(mut self) {
        if let Some(replies) = self.receive.replies.take() {
            replies.delete();
        } else {
            Canonical::delete_epoch(&self.canonical_binding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_test_fixtures::{Fixture, ALGORITHMS, DIRECTIONS};

    #[test]
    #[allow(clippy::unwrap_used)]
    fn terminal_reconcile_drops_the_canonical_capability_before_delete() {
        crate::test_support::ensure_ike_crypto();
        for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
            for (role, direction) in DIRECTIONS.into_iter().enumerate() {
                let mut f = Fixture::new(
                    33_000 + (algorithm * 2 + role) as u64,
                    encryption,
                    direction,
                );
                f.window.enable_empty_replies(Policy::default()).unwrap();
                assert!(f.window.receive.replies.is_some());
                let record = f.window.record().clone();
                let changed = f.stored(None, 64);
                assert_eq!(
                    f.window.reconcile(f.profile, &f.keys, &record, &changed),
                    Err(Error::DomainMismatch)
                );
                assert!(
                    f.window.receive.replies.is_none(),
                    "terminal readback must drop the capability before SA deletion"
                );
                f.window.delete();
            }
        }
    }
}
