use super::{Ikev2CommittedWindowRecord as Record, Ikev2WindowError as Error};
use crate::{
    decode_header, Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    Ikev2ProtectedPayloadDirection as Direction,
};

/// Durable disposition of the ordinary window after responding to peer sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2SyncDisposition {
    /// Ordinary work may continue strictly at the committed floors.
    Continue,
    /// A concurrent local sync remains unresolved; ordinary traffic stays blocked.
    AwaitLocalSync,
    /// Uncommitted mutation outcome is unknown; close this IKE SA and its Children.
    ///
    /// The consumer persists and performs scoped cleanup idempotently. This is
    /// never evidence of mutation success or authority to retry it under a new ID.
    /// No Delete send permission exists in this terminal state; a separate committed
    /// close path needs qualification, otherwise the peer learns through expiry.
    OutcomeUncertain,
    /// Local recovery expired or exhausted its budget; close this IKE SA and Children.
    CloseIkeSa,
}

/// Persisted sync agreement and history, inside the same atomic ordinary record.
///
/// The enclosing window owns the current floors, generation and exact key domain.
/// All known ordinary IDs must be supplied, including outstanding local requests.
/// A peer proposal is distinct from an ordinary used ID. Peer response P2 values
/// are not a separate replay-drop floor: a future minimal proposal M1 = P2 remains
/// admissible unless ordinary or accepted-proposal history independently rejects it.
/// These fields do not enable advertisement or initiate local synchronization.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2SyncResponderRecord {
    pub(super) agreement: Agreement,
    pub(super) highest_local_request: Option<u32>,
    pub(super) highest_peer_request: Option<u32>,
    pub(super) highest_local_proposal: Option<u32>,
    pub(super) highest_peer_proposal: Option<u32>,
    pub(super) disposition: Ikev2SyncDisposition,
    pub(super) minimum_send_iv_end: u64,
}

impl Ikev2SyncResponderRecord {
    /// Rebuild trusted latest fields; `None` means no known request or proposal.
    ///
    /// Unwritten empty requests answered before a crash cannot be reconstructed
    /// here. Never manufacture that knowledge from a guessed snapshot. Attach to
    /// the matching window with `Ikev2CommittedWindowRecord::with_sync_state`.
    /// Preserve `minimum_send_iv_end` even after packet caches have been retired.
    /// For generation-zero handshake floors, seed each ordinary history with that
    /// direction's floor minus one; only a zero floor has no known request.
    /// # Errors
    /// Rejects an IV end beyond the allocator's range, exhausted proposals,
    /// local-sync waiting without a proposal, and sync history or blocking
    /// dispositions on a fallback-only agreement.
    pub fn from_persisted(
        agreement: Agreement,
        highest_local_request: Option<u32>,
        highest_peer_request: Option<u32>,
        highest_local_proposal: Option<u32>,
        highest_peer_proposal: Option<u32>,
        disposition: Ikev2SyncDisposition,
        minimum_send_iv_end: u64,
    ) -> Result<Self, Error> {
        if minimum_send_iv_end > crate::IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS
            || highest_local_proposal == Some(u32::MAX)
            || highest_peer_proposal == Some(u32::MAX)
            || (disposition == Ikev2SyncDisposition::AwaitLocalSync
                && highest_local_proposal.is_none())
            || (agreement.mode() == Mode::BaseFallback
                && (highest_local_proposal.is_some()
                    || highest_peer_proposal.is_some()
                    || disposition != Ikev2SyncDisposition::Continue))
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            agreement,
            highest_local_request,
            highest_peer_request,
            highest_local_proposal,
            highest_peer_proposal,
            disposition,
            minimum_send_iv_end,
        })
    }

    /// Immutable agreement, persisted with the enclosing authenticated key epoch.
    pub const fn agreement(self) -> Agreement {
        self.agreement
    }
    /// Highest durably known local ordinary request, including pending work.
    pub const fn highest_local_request(self) -> Option<u32> {
        self.highest_local_request
    }
    /// Highest durably known peer ordinary request; absent is distinct from zero.
    pub const fn highest_peer_request(self) -> Option<u32> {
        self.highest_peer_request
    }
    /// Highest local proposal, including a simultaneous one whose result is pending.
    pub const fn highest_local_proposal(self) -> Option<u32> {
        self.highest_local_proposal
    }
    /// Highest accepted peer M1; duplicates never produce a cached sync response.
    pub const fn highest_peer_proposal(self) -> Option<u32> {
        self.highest_peer_proposal
    }
    /// Whether ordinary traffic can resume or scoped cleanup must finish.
    pub const fn disposition(self) -> Ikev2SyncDisposition {
        self.disposition
    }

    /// Smallest permitted sending-IV reservation end, including retired packets.
    /// Persist this with every cutover; zero means no retained local-IV evidence.
    pub const fn minimum_send_iv_end(self) -> u64 {
        self.minimum_send_iv_end
    }

    pub(super) fn validate(self, record: &Record) -> Result<(), Error> {
        let domain = record.domain.send_iv_domain();
        let role = match domain.direction() {
            Direction::InitiatorToResponder => Role::Initiator,
            Direction::ResponderToInitiator => Role::Responder,
        };
        let expected = Sa::new(domain.initiator_spi(), domain.responder_spi(), role)
            .map_err(|_| Error::DomainMismatch)?;
        if self.agreement.sa() != expected {
            return Err(Error::DomainMismatch);
        }
        if record.generation == 0
            && (self.highest_local_proposal.is_some()
                || self.highest_peer_proposal.is_some()
                || self.disposition != Ikev2SyncDisposition::Continue)
        {
            return Err(Error::InvalidRecord);
        }
        for (next, ordinary, proposal, cached) in [
            (
                record.next_send,
                self.highest_local_request,
                self.highest_local_proposal,
                &record.outbound,
            ),
            (
                record.next_receive,
                self.highest_peer_request,
                self.highest_peer_proposal,
                &record.inbound,
            ),
        ] {
            if ordinary.is_some_and(|used| next.is_some_and(|floor| used >= floor))
                || (next.is_none() && ordinary != Some(u32::MAX))
                || proposal.is_some_and(|proposed| next.is_some_and(|floor| proposed > floor))
            {
                return Err(Error::InvalidRecord);
            }
            if let Some(cached) = cached {
                let (_, header) =
                    decode_header(&cached.request, opc_protocol::DecodeContext::default())
                        .map_err(|_| Error::InvalidRecord)?;
                if ordinary.is_none_or(|highest| header.message_id > highest) {
                    return Err(Error::InvalidRecord);
                }
            }
        }
        Ok(())
    }
}
