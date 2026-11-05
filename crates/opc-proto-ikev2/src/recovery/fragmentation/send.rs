use bytes::Bytes;

use super::{Ikev2FragmentationSize as Size, Keys, Profile};
use crate::recovery::{
    message::{MAX_CLEARTEXT, MAX_FRAGMENTS},
    packet::{self, SealedPacket},
    profile::RecoveryProfile,
    Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CbcRecoveryProfile as Cbc,
    Ikev2CommittedExchangeRecord as ExchangeRecord, Ikev2CommittedWindow as Window,
    Ikev2GcmRecoveryProfile as Gcm, Ikev2OrdinaryRequestDisposition as Disposition,
    Ikev2PreparedWindow, Ikev2ProtectedMessage as Message, Ikev2WindowError as Error,
};
use crate::{
    Header, Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2ExchangeKind as Exchange, PayloadChain, PayloadType,
};

fn packets<P: RecoveryProfile>(
    profile: Profile,
    header: &Header,
    payloads: PayloadChain<'_>,
    size: Size,
    evidence: &mut P::SyncEvidence,
    mut seal: impl FnMut(Header, PayloadChain<'_>, (u16, u16)) -> Result<SealedPacket<P>, Error>,
) -> Result<Message, Error> {
    packet::validate_payloads(payloads)?;
    if payloads.bytes().len() > MAX_CLEARTEXT {
        return Err(Error::FragmentationLimit);
    }
    let mut width = 0usize;
    let mut high = MAX_CLEARTEXT.min(size.ike_bytes) + 1;
    while width + 1 < high {
        let middle = width + (high - width) / 2;
        if P::payload_len(profile, middle)
            .and_then(|n| n.checked_add(28 + 4))
            .is_some_and(|n| n <= size.ike_bytes)
        {
            width = middle;
        } else {
            high = middle;
        }
    }
    if width == 0 {
        return Err(Error::FragmentationLimit);
    }
    let count = payloads.bytes().len().max(1).div_ceil(width);
    if count > MAX_FRAGMENTS {
        return Err(Error::FragmentationLimit);
    }
    let total = u16::try_from(count).map_err(|_| Error::FragmentationLimit)?;
    let mut packets = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * width;
        let end = (start + width).min(payloads.bytes().len());
        let first = if index == 0 {
            payloads.first_payload()
        } else {
            PayloadType::NoNext
        };
        let frame = seal(
            header.clone(),
            PayloadChain::new(first, &payloads.bytes()[start..end]),
            (
                u16::try_from(index + 1).map_err(|_| Error::FragmentationLimit)?,
                total,
            ),
        )?;
        P::retain_sealed(evidence, &frame)?;
        packets.push(frame.into_wire());
    }
    Message::from_persisted(packets)
}

impl<P: RecoveryProfile> Window<P> {
    fn fragment_request_with(
        &mut self,
        profile: Profile,
        exchange: Exchange,
        payloads: PayloadChain<'_>,
        size: Size,
        seal: impl FnMut(Header, PayloadChain<'_>, (u16, u16)) -> Result<SealedPacket<P>, Error>,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Error> {
        self.ready()?;
        self.record
            .fragmentation
            .ok_or(Error::FragmentationNotNegotiated)?;
        if self.send.outstanding.is_some()
            || self
                .record
                .outbound
                .as_ref()
                .is_some_and(|entry| entry.response.is_none())
        {
            return Err(Error::RequestOutstanding);
        }
        if !matches!(
            exchange,
            Exchange::IkeAuth | Exchange::CreateChildSa | Exchange::Informational
        ) {
            return Err(Error::Drop);
        }
        packet::require_work(exchange.as_u8(), payloads)?;
        let mut record = self.next_record()?;
        let id = record.next_send.ok_or(Error::Exhausted)?;
        let request = packets::<P>(
            profile,
            &record.domain.header(exchange, id, false),
            payloads,
            size,
            &mut self.packet_evidence,
            seal,
        )?;
        P::retain_local_evidence(self, &mut record)?;
        record.outbound = Some(ExchangeRecord {
            request,
            response: None,
            outcome: None,
        });
        record.next_send = id.checked_add(1);
        if let Some(sync) = &mut record.sync {
            sync.highest_local_request = Some(id);
        }
        Ok(self.prepared(record, None, false))
    }

    fn fragment_response_with(
        &mut self,
        profile: Profile,
        request: &Ordinary<P>,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
        size: Size,
        seal: impl FnMut(Header, PayloadChain<'_>, (u16, u16)) -> Result<SealedPacket<P>, Error>,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Error> {
        self.ready()?;
        self.record
            .fragmentation
            .ok_or(Error::FragmentationNotNegotiated)?;
        if self.request_disposition(request)? != Disposition::New {
            return Err(Error::Drop);
        }
        let mut record = self.next_record()?;
        let exchange = Exchange::from_u8(request.header.exchange_type).ok_or(Error::Drop)?;
        let id = request.header.message_id;
        let response = packets::<P>(
            profile,
            &record.domain.header(exchange, id, true),
            payloads,
            size,
            &mut self.packet_evidence,
            seal,
        )?;
        P::retain_local_evidence(self, &mut record)?;
        record.inbound = Some(ExchangeRecord {
            request: request.wire.clone(),
            response: Some(response),
            outcome: Some(outcome.clone()),
        });
        record.next_receive = id.checked_add(1);
        if let Some(sync) = &mut record.sync {
            sync.highest_peer_request = Some(id);
        }
        Ok(self.prepared(record, Some(outcome), true))
    }
}

impl Window<Gcm> {
    /// Seal and prepare all request fragments, consuming one committed IV per packet.
    /// Failed preparation burns any allocated IVs but releases no packets or Message ID.
    /// Persist every packet before replay; this never reserves an IV block itself.
    /// # Errors
    /// Refuses unnegotiated/blocked work, invalid payloads/size or insufficient IVs.
    #[expect(
        clippy::too_many_arguments,
        reason = "The caller owns IV purpose, allocator and transport size policy."
    )]
    pub fn prepare_fragmented_request(
        &mut self,
        profile: Profile,
        keys: &Keys,
        allocator: &mut Allocator,
        purpose: Purpose,
        exchange: Exchange,
        payloads: PayloadChain<'_>,
        size: Size,
    ) -> Result<Ikev2PreparedWindow<'_, Gcm>, Error> {
        let domain = self.record.domain.clone();
        self.fragment_request_with(
            profile,
            exchange,
            payloads,
            size,
            |header, part, fragment| {
                packet::seal_frame(
                    &domain,
                    profile,
                    keys,
                    allocator.allocate(purpose).map_err(Error::Iv)?,
                    header,
                    part,
                    Some(fragment),
                )
            },
        )
    }

    /// Prepare exact response fragments and the outcome for one atomic durable commit.
    /// # Errors
    /// Refuses invalid ordinary work, size, negotiation, lifecycle or IV admission.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep all cryptographic and atomic response inputs explicit."
    )]
    pub fn prepare_fragmented_response(
        &mut self,
        profile: Profile,
        keys: &Keys,
        allocator: &mut Allocator,
        purpose: Purpose,
        request: &Ordinary,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
        size: Size,
    ) -> Result<Ikev2PreparedWindow<'_, Gcm>, Error> {
        let domain = self.record.domain.clone();
        self.fragment_response_with(
            profile,
            request,
            payloads,
            outcome,
            size,
            |header, part, fragment| {
                packet::seal_frame(
                    &domain,
                    profile,
                    keys,
                    allocator.allocate(purpose).map_err(Error::Iv)?,
                    header,
                    part,
                    Some(fragment),
                )
            },
        )
    }
}

impl Window<Cbc> {
    /// Prepare all request fragments using admitted independent random CBC IVs.
    /// Persist every packet atomically before any transmission.
    /// # Errors
    /// Refuses invalid work, negotiation, size, lifecycle or cryptographic admission.
    pub fn prepare_fragmented_request(
        &mut self,
        profile: Profile,
        keys: &Keys,
        exchange: Exchange,
        payloads: PayloadChain<'_>,
        size: Size,
    ) -> Result<Ikev2PreparedWindow<'_, Cbc>, Error> {
        let domain = self.record.domain.clone();
        self.fragment_request_with(
            profile,
            exchange,
            payloads,
            size,
            |header, part, fragment| {
                packet::seal_frame(&domain, profile, keys, (), header, part, Some(fragment))
            },
        )
    }

    /// Prepare random-IV CBC response fragments and their atomic ordinary outcome.
    /// # Errors
    /// Refuses invalid work, negotiation, size, lifecycle or cryptographic admission.
    pub fn prepare_fragmented_response(
        &mut self,
        profile: Profile,
        keys: &Keys,
        request: &Ordinary<Cbc>,
        payloads: PayloadChain<'_>,
        outcome: Bytes,
        size: Size,
    ) -> Result<Ikev2PreparedWindow<'_, Cbc>, Error> {
        let domain = self.record.domain.clone();
        self.fragment_response_with(
            profile,
            request,
            payloads,
            outcome,
            size,
            |header, part, fragment| {
                packet::seal_frame(&domain, profile, keys, (), header, part, Some(fragment))
            },
        )
    }
}
