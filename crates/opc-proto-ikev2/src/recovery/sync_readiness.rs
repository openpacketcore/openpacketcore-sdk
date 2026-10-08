use super::profile::DirectionBinding;
use super::profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use super::{
    Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowDomain as Domain, Ikev2WindowError as Error,
};
use crate::{
    decode_ike_auth_cleartext_payloads, Ikev2MessageIdSyncAgreement,
    Ikev2MessageIdSyncNegotiation as Negotiation, Ikev2MessageIdSyncRole as Role,
    Ikev2MessageIdSyncSa as Sa, Ikev2NotifyPayloadBuild,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys,
};

impl<P: RecoveryProfile> Window<P> {
    /// Mint readiness for this complete-SK runtime's two synchronization handlers.
    ///
    /// Call on the fresh key epoch's initial window before IKE_AUTH negotiation.
    /// The capability binds profile/keys/SPIs/original role, requires currently
    /// admitted encryption and entropy, and is consumed by the production offer
    /// wrapper. It is not proof of consumer durability, full peer authentication,
    /// DPD support or fragmented recovery.
    /// Both runtime directions and their
    /// storage/clock contracts must be wired by the consumer before advertising.
    /// # Errors
    /// Rejects active/negotiated windows, key mismatch or unavailable admission.
    pub fn sync_readiness(
        &self,
        profile: Profile,
        keys: &Keys,
    ) -> Result<Ikev2SyncReadiness<P>, Error> {
        self.ready()?;
        if self.record.generation != 0
            || self.record.sync.is_some()
            || self.record.recovery.is_some()
            || self.record.outbound.is_some()
            || self.record.inbound.is_some()
        {
            return Err(Error::Drop);
        }
        self.record.domain.check(profile, keys)?;
        P::sync_admission(profile)?;
        let domain = &self.record.domain.send;
        let role = if domain.direction() == Direction::InitiatorToResponder {
            Role::Initiator
        } else {
            Role::Responder
        };
        let sa = Sa::new(domain.initiator_spi(), domain.responder_spi(), role)
            .map_err(|_| Error::DomainMismatch)?;
        Ok(Ikev2SyncReadiness {
            domain: self.record.domain.clone(),
            profile,
            sa,
        })
    }
}

/// Runtime-minted readiness for one key domain/profile, not a caller boolean.
///
/// No production or synthetic constructor exists outside the checked runtime.
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2SyncReadiness;
/// let forged = Ikev2SyncReadiness {};
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2SyncReadiness;
/// fn duplicate(ready: Ikev2SyncReadiness) { let _ = ready.clone(); }
/// ```
pub struct Ikev2SyncReadiness<P: RecoveryProfile = Gcm> {
    domain: Domain<P>,
    profile: Profile,
    sa: Sa,
}
impl<P: RecoveryProfile> Ikev2SyncReadiness<P> {
    /// Consume readiness into same-domain production offer accumulation.
    pub fn negotiate(self) -> Ikev2RuntimeSyncNegotiation<P> {
        Ikev2RuntimeSyncNegotiation {
            domain: self.domain,
            profile: self.profile,
            model: Negotiation::new(self.sa, true),
        }
    }
}

/// Readiness-backed support advertisement and authenticated IKE_AUTH accumulation.
///
/// Generic Notify builders and the pure negotiation boolean remain codecs/models;
/// they do not replace this production readiness path. Persist the finished
/// agreement with the same key epoch only after full peer authentication.
pub struct Ikev2RuntimeSyncNegotiation<P: RecoveryProfile = Gcm> {
    domain: Domain<P>,
    profile: Profile,
    model: Negotiation,
}
impl<P: RecoveryProfile> Ikev2RuntimeSyncNegotiation<P> {
    /// Build and record support only when the role/peer-offer rules permit it.
    ///
    /// Include a returned offer in the protected handshake. The original initiator
    /// offers in its first request; the responder waits for a valid authenticated
    /// initiator offer. Current provider admission is rechecked before evidence is
    /// recorded; a returned value is not permission to seal/send the handshake.
    /// # Errors
    /// Withdrawn or unavailable encryption/entropy produces no offer evidence.
    pub fn local_offer(&mut self) -> Result<Option<Ikev2NotifyPayloadBuild>, Error> {
        P::sync_admission(self.profile)?;
        Ok(self
            .model
            .record_local_offer()
            .then(Ikev2NotifyPayloadBuild::message_id_sync_supported))
    }

    /// Observe an admitted-crypto opened same-domain IKE_AUTH message.
    ///
    /// Invalid/duplicate support adds no evidence, never revokes a prior valid
    /// round or fails peer authentication. Full identity authentication remains
    /// separate from packet integrity and is required before `finish(true)`.
    /// # Errors
    /// Rejects another domain, wrong role/exchange/ID/direction or invalid chain.
    pub fn observe_peer(&mut self, packet: &Ordinary<P>) -> Result<(), Error> {
        if packet.domain != self.domain {
            return Err(Error::DomainMismatch);
        }
        let payloads = packet.payloads();
        let opened = decode_ike_auth_cleartext_payloads(payloads.first_payload(), payloads.bytes())
            .map_err(|_| Error::Drop)?;
        self.model
            .observe_peer_offer(packet.header(), opened.message_id_sync_supported())
            .map_err(|_| Error::Drop)
    }

    /// Finish once after successful full IKE_AUTH; incomplete/failed auth yields none.
    ///
    /// The success fact is supplied by the consumer's authenticated handshake.
    /// Lack of bilateral offers selects fallback, never rejection of the peer.
    pub fn finish(self, authenticated_success: bool) -> Option<Ikev2MessageIdSyncAgreement> {
        self.model.finish(authenticated_success)
    }
}
