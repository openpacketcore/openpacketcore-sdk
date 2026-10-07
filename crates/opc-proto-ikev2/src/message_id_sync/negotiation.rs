//! Pure, SA-scoped offer accumulation. No authentication authority is created.

use std::{error::Error, fmt};

use super::{Ikev2MessageIdSyncError, Ikev2MessageIdSyncSupported};
use crate::{Header, PayloadType, EXCHANGE_TYPE_IKE_AUTH};

/// Local role in the original exchange that created this IKE SA.
///
/// This is independent of which peer initiates a synchronization exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2MessageIdSyncRole {
    /// Local endpoint was the original IKE initiator.
    Initiator,
    /// Local endpoint was the original IKE responder.
    Responder,
}

/// Nonzero SPI pair and local original role for pure synchronization rules.
///
/// Construction checks shape only, not peer identity, key ownership or trust.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2MessageIdSyncSa {
    initiator_spi: u64,
    responder_spi: u64,
    role: Ikev2MessageIdSyncRole,
}

impl Ikev2MessageIdSyncSa {
    /// Bind rule inputs to an established SA's SPI pair and local role.
    ///
    /// # Errors
    /// Returns [`Ikev2MessageIdSyncRuleError::Drop`] for either zero SPI.
    pub fn new(
        initiator_spi: u64,
        responder_spi: u64,
        role: Ikev2MessageIdSyncRole,
    ) -> Result<Self, Ikev2MessageIdSyncRuleError> {
        if initiator_spi == 0 || responder_spi == 0 {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        Ok(Self {
            initiator_spi,
            responder_spi,
            role,
        })
    }

    pub(super) fn validate_peer(
        self,
        header: &Header,
        exchange: u8,
        response: bool,
    ) -> Result<(), Ikev2MessageIdSyncRuleError> {
        if header.initiator_spi != self.initiator_spi
            || header.responder_spi != self.responder_spi
            || header.flags.initiator() != (self.role == Ikev2MessageIdSyncRole::Responder)
            || header.flags.response() != response
            || header.exchange_type != exchange
            || header.major_version != 2
            || !matches!(
                PayloadType::from_u8(header.next_payload),
                PayloadType::Encrypted | PayloadType::EncryptedFragment
            )
        {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        Ok(())
    }
}

impl fmt::Debug for Ikev2MessageIdSyncSa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2MessageIdSyncSa")
            .finish_non_exhaustive()
    }
}

/// Non-accepting intent from a pure synchronization rule.
///
/// No variant authorizes a packet, persistence, rekey or deletion by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2MessageIdSyncRuleError {
    /// Ignore this input without a response or counter change.
    Drop,
    /// Stop recovery; a local ordinary ID remains for attempting IKE rekey.
    /// Actual rekey also requires IV capacity and a usable ordinary window.
    RekeyRequired,
    /// No local ordinary ID remains; close this IKE SA without wrapping.
    CloseIkeSa,
}

impl fmt::Display for Ikev2MessageIdSyncRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Drop => "ike_message_id_sync_drop",
            Self::RekeyRequired => "ike_message_id_sync_rekey_required",
            Self::CloseIkeSa => "ike_message_id_sync_close_ike_sa",
        })
    }
}

impl Error for Ikev2MessageIdSyncRuleError {}

/// Immutable recovery-mode choice after successful IKE_AUTH.
///
/// A mode value alone is neither authentication evidence nor send authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2MessageIdSyncMode {
    /// No bilateral offer evidence; use the bounded base-IKE fallback.
    BaseFallback,
    /// Both peers offered synchronization; never downgrade on sync timeout.
    Negotiated,
}

/// Provisional offer evidence across one SA's IKE_AUTH/EAP rounds.
///
/// The caller must authenticate each protected message before observing it.
/// Full peer authentication is a separate prerequisite to [`Self::finish`].
#[derive(Debug, Clone)]
pub struct Ikev2MessageIdSyncNegotiation {
    sa: Ikev2MessageIdSyncSa,
    locally_ready: bool,
    local_offer: bool,
    peer_offer: bool,
}

impl Ikev2MessageIdSyncNegotiation {
    /// Start empty evidence. `locally_ready` means a complete runtime handler
    /// exists for both sync directions, including required durable ordering.
    /// These pure helpers alone are insufficient to set it in production.
    #[must_use]
    pub const fn new(sa: Ikev2MessageIdSyncSa, locally_ready: bool) -> Self {
        Self {
            sa,
            locally_ready,
            local_offer: false,
            peer_offer: false,
        }
    }

    /// Record a local offer, returning whether offering is permitted.
    ///
    /// A ready initiator offers in its first IKE_AUTH request; a responder
    /// waits for a valid initiator offer. The caller records only offers
    /// actually included in its handshake. This method sends nothing.
    pub fn record_local_offer(&mut self) -> bool {
        let allowed = self.locally_ready
            && (self.sa.role == Ikev2MessageIdSyncRole::Initiator || self.peer_offer);
        self.local_offer |= allowed;
        allowed
    }

    /// Accumulate one protected peer message's support-extraction result.
    ///
    /// Malformed/duplicate offers and absence add no evidence and never revoke
    /// earlier evidence or fail IKE_AUTH. Repeats across rounds are idempotent.
    /// An unsolicited responder offer before the local initiator offer adds
    /// nothing. Pass the result of `message_id_sync_supported()` unchanged.
    ///
    /// # Errors
    /// Returns `Drop` for the wrong SA, original role, direction or exchange.
    pub fn observe_peer_offer(
        &mut self,
        header: &Header,
        offer: Result<Option<Ikev2MessageIdSyncSupported>, Ikev2MessageIdSyncError>,
    ) -> Result<(), Ikev2MessageIdSyncRuleError> {
        self.sa.validate_peer(
            header,
            EXCHANGE_TYPE_IKE_AUTH,
            self.sa.role == Ikev2MessageIdSyncRole::Initiator,
        )?;
        if header.message_id == 0 {
            return Err(Ikev2MessageIdSyncRuleError::Drop);
        }
        if matches!(offer, Ok(Some(_)))
            && (self.sa.role == Ikev2MessageIdSyncRole::Responder || self.local_offer)
        {
            self.peer_offer = true;
        }
        Ok(())
    }

    /// Finish only after full peer authentication and successful IKE_AUTH.
    ///
    /// `authenticated_success` is a caller-supplied fact, not checked by this
    /// pure model. Failure or an unfinished handshake produces no agreement.
    #[must_use]
    pub fn finish(self, authenticated_success: bool) -> Option<Ikev2MessageIdSyncAgreement> {
        authenticated_success.then_some(Ikev2MessageIdSyncAgreement {
            sa: self.sa,
            mode: if self.local_offer && self.peer_offer {
                Ikev2MessageIdSyncMode::Negotiated
            } else {
                Ikev2MessageIdSyncMode::BaseFallback
            },
        })
    }
}

/// SA-bound result of the pure offer model, not proof of authentication.
///
/// Mode is immutable; this value holds no counters, keys, pending nonces or
/// replay cache. Durable runtime composition must provide its own evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2MessageIdSyncAgreement {
    sa: Ikev2MessageIdSyncSa,
    mode: Ikev2MessageIdSyncMode,
}

impl Ikev2MessageIdSyncAgreement {
    /// Return the SA binding.
    #[must_use]
    pub const fn sa(self) -> Ikev2MessageIdSyncSa {
        self.sa
    }

    /// Return the immutable selected mode.
    #[must_use]
    pub const fn mode(self) -> Ikev2MessageIdSyncMode {
        self.mode
    }

    /// Inherit the mode after a successful authenticated same-peer IKE rekey.
    ///
    /// The caller supplies the success/identity fact and the new original
    /// role. Both SPIs must change. A failed or uncertain rekey returns `None`.
    /// Counters, keys, IV descriptors, pending proposals and caches do not
    /// transfer. This inheritance is SDK policy requiring peer interoperability
    /// qualification; RFC 6311 does not explicitly specify it.
    #[must_use]
    pub fn inherit_rekey(
        self,
        new_sa: Ikev2MessageIdSyncSa,
        authenticated_same_peer_success: bool,
    ) -> Option<Self> {
        (authenticated_same_peer_success
            && new_sa.initiator_spi != self.sa.initiator_spi
            && new_sa.responder_spi != self.sa.responder_spi)
            .then_some(Self {
                sa: new_sa,
                mode: self.mode,
            })
    }
}
