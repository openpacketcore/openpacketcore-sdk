use super::profile::{DirectionBinding, Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{BorrowDecode, DecodeContext, EncodeContext};
use std::marker::PhantomData;

use super::{
    Ikev2CommittedWindowDomain as Domain, Ikev2ProtectedMessage, Ikev2WindowError as Error,
};
use crate::{
    encode_header, open_protected_payloads, Header, Ikev2ExchangeKind, Ikev2NotifyPayload,
    Ikev2ProtectedPayloadDirection, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
    Ikev2SaInitProtectedPayloadProvider, Message, PayloadChain, PayloadType, ProtectedPayloadKind,
    ProtectedPayloadSealContext, IKEV2_NOTIFY_MESSAGE_ID_SYNC,
};

/// Complete authenticated ordinary SK/SKF message bound to a durable-window domain.
///
/// Created only through the admitted crypto open path; it is not admission to a
/// receive window and grants no effects. Sync Notify packets are never this type.
pub struct Ikev2AuthenticatedOrdinary<P: RecoveryProfile = Gcm> {
    pub(super) domain: Domain<P>,
    pub(super) header: Header,
    pub(super) wire: Ikev2ProtectedMessage,
    first: PayloadType,
    cleartext: Bytes,
}

impl<P: RecoveryProfile> Ikev2AuthenticatedOrdinary<P> {
    pub(crate) fn canonical_message_id(
        &self,
        expected: &Domain<P>,
    ) -> Result<u32, crate::canonical::Ikev2CanonicalError> {
        use crate::canonical::Ikev2CanonicalError as CanonicalError;
        if &self.domain != expected {
            return Err(CanonicalError::BindingMismatch);
        }
        if self.header.flags.response()
            || self.header.exchange_type != Ikev2ExchangeKind::Informational.as_u8()
            || !self.payloads().is_empty()
        {
            return Err(CanonicalError::InvalidRequest);
        }
        Ok(self.header.message_id)
    }
    /// Authenticated header for consumer semantic validation.
    pub const fn header(&self) -> &Header {
        &self.header
    }
    /// Authenticated inner chain; the consumer must still validate operation semantics.
    pub fn payloads(&self) -> PayloadChain<'_> {
        PayloadChain::new(self.first, &self.cleartext)
    }

    pub(super) fn require_work(&self) -> Result<(), Error> {
        require_work(self.header.exchange_type, self.payloads())
    }
}

// Successful admitted sealing, before ordinary/sync storage consumes the bytes.
// Only the builders below can construct this profile-typed evidence.
pub struct SealedPacket<P: RecoveryProfile> {
    wire: Bytes,
    profile: PhantomData<P>,
}
impl<P: RecoveryProfile> SealedPacket<P> {
    pub(super) fn wire(&self) -> &Bytes {
        &self.wire
    }
    pub(super) fn into_wire(self) -> Bytes {
        self.wire
    }
}

pub(super) fn require_work(exchange: u8, payloads: PayloadChain<'_>) -> Result<(), Error> {
    if exchange == Ikev2ExchangeKind::Informational.as_u8() && payloads.is_empty() {
        return Err(Error::NoDurableWork);
    }
    Ok(())
}

pub(super) fn validate_payloads(payloads: PayloadChain<'_>) -> Result<(), Error> {
    let context = DecodeContext {
        max_message_len: super::message::MAX_CLEARTEXT,
        ..DecodeContext::default()
    };
    payloads.validate(context).map_err(|_| Error::Drop)?;
    for payload in payloads.iter_with_context(context) {
        let payload = payload.map_err(|_| Error::Drop)?;
        if payload.is_protected() {
            return Err(Error::Drop);
        }
        if payload.payload_type == PayloadType::Notify {
            let notify = Ikev2NotifyPayload::decode_body(payload.body).map_err(|_| Error::Drop)?;
            if notify.notify_message_type == IKEV2_NOTIFY_MESSAGE_ID_SYNC {
                return Err(Error::Drop);
            }
        }
    }
    Ok(())
}

pub(super) struct OpenedFrame {
    pub header: Header,
    pub wire: Bytes,
    pub first: PayloadType,
    pub cleartext: Bytes,
    pub fragment: Option<(u16, u16)>,
}

pub(super) fn same_message(a: &Header, b: &Header) -> bool {
    a.initiator_spi == b.initiator_spi
        && a.responder_spi == b.responder_spi
        && a.major_version == b.major_version
        && a.minor_version == b.minor_version
        && a.exchange_type == b.exchange_type
        && a.flags == b.flags
        && a.message_id == b.message_id
}

pub(super) fn open_frame<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    wire: &[u8],
    peer: bool,
) -> Result<OpenedFrame, Error> {
    domain.check(profile, keys)?;
    let (rest, message) =
        Message::decode(wire, DecodeContext::default()).map_err(|_| Error::Drop)?;
    let direction = if peer { &domain.receive } else { &domain.send };
    let header = &message.header;
    if !rest.is_empty()
        || header.initiator_spi != direction.initiator_spi()
        || header.responder_spi != direction.responder_spi()
        || header.flags.initiator()
            != (direction.direction() == Ikev2ProtectedPayloadDirection::InitiatorToResponder)
        || !matches!(
            PayloadType::from_u8(header.next_payload),
            PayloadType::Encrypted | PayloadType::EncryptedFragment
        )
        || !matches!(
            Ikev2ExchangeKind::from_u8(header.exchange_type),
            Some(
                Ikev2ExchangeKind::IkeAuth
                    | Ikev2ExchangeKind::CreateChildSa
                    | Ikev2ExchangeKind::Informational
            )
        )
    {
        return Err(Error::Drop);
    }
    let provider = Ikev2SaInitProtectedPayloadProvider::new(profile, keys, direction.direction());
    let opened = open_protected_payloads(&message, wire, DecodeContext::default(), &provider)
        .map_err(|_| Error::Drop)?;
    if opened.len() != 1 {
        return Err(Error::Drop);
    }
    let opened = opened.into_iter().next().ok_or(Error::Drop)?;
    let fragment = if opened.kind == ProtectedPayloadKind::EncryptedFragment {
        let raw = message
            .payloads
            .iter()
            .next()
            .ok_or(Error::Drop)?
            .map_err(|_| Error::Drop)?;
        let fragment =
            crate::Ikev2EncryptedFragmentPayload::decode(raw).map_err(|_| Error::Drop)?;
        Some((fragment.fragment_number, fragment.total_fragments))
    } else {
        None
    };
    Ok(OpenedFrame {
        header: header.clone(),
        wire: Bytes::copy_from_slice(wire),
        first: opened.first_inner_payload,
        cleartext: opened.cleartext,
        fragment,
    })
}

pub(super) fn finish<P: RecoveryProfile>(
    domain: &Domain<P>,
    frames: Vec<OpenedFrame>,
) -> Result<Ikev2AuthenticatedOrdinary<P>, Error> {
    use super::message::{MAX_CLEARTEXT, MAX_FRAGMENTS};
    let first = frames.first().ok_or(Error::Drop)?;
    if frames.len() > MAX_FRAGMENTS {
        return Err(Error::FragmentationLimit);
    }
    let count = u16::try_from(frames.len()).map_err(|_| Error::FragmentationLimit)?;
    let mut cleartext = BytesMut::new();
    for (index, frame) in frames.iter().enumerate() {
        if !same_message(&first.header, &frame.header)
            || match first.fragment {
                None => count != 1 || frame.fragment.is_some(),
                Some(_) => {
                    frame.fragment
                        != Some((u16::try_from(index + 1).map_err(|_| Error::Drop)?, count))
                }
            }
        {
            return Err(Error::Drop);
        }
        if cleartext
            .len()
            .checked_add(frame.cleartext.len())
            .is_none_or(|n| n > MAX_CLEARTEXT)
        {
            return Err(Error::FragmentationLimit);
        }
        cleartext.extend_from_slice(&frame.cleartext);
    }
    validate_payloads(PayloadChain::new(first.first, &cleartext))?;
    let header = first.header.clone();
    let first = first.first;
    let wire = Ikev2ProtectedMessage::from_persisted(
        frames.into_iter().map(|frame| frame.wire).collect(),
    )?;
    Ok(Ikev2AuthenticatedOrdinary {
        domain: domain.clone(),
        header,
        wire,
        first,
        cleartext: cleartext.freeze(),
    })
}

pub(super) fn open<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    wire: &[u8],
    peer: bool,
) -> Result<Ikev2AuthenticatedOrdinary<P>, Error> {
    let frame = open_frame(domain, profile, keys, wire, peer)?;
    if frame.fragment.is_some() {
        return Err(Error::UnsupportedShape);
    }
    finish(domain, vec![frame])
}

pub(super) fn open_message<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    message: &Ikev2ProtectedMessage,
    peer: bool,
    fragmentation: bool,
) -> Result<Ikev2AuthenticatedOrdinary<P>, Error> {
    let mut frames = Vec::with_capacity(message.packets().len());
    for wire in message.packets() {
        let frame = open_frame(domain, profile, keys, wire, peer)?;
        if frame.fragment.is_some() && !fragmentation {
            return Err(Error::FragmentationNotNegotiated);
        }
        frames.push(frame);
    }
    finish(domain, frames)
}

pub(super) fn seal<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    sealing: P::Sealing<'_>,
    header: Header,
    payloads: PayloadChain<'_>,
) -> Result<SealedPacket<P>, Error> {
    domain.check(profile, keys)?;
    if !matches!(
        Ikev2ExchangeKind::from_u8(header.exchange_type),
        Some(
            Ikev2ExchangeKind::IkeAuth
                | Ikev2ExchangeKind::CreateChildSa
                | Ikev2ExchangeKind::Informational
        )
    ) {
        return Err(Error::Drop);
    }
    validate_payloads(payloads)?;
    seal_frame(domain, profile, keys, sealing, header, payloads, None)
}

pub(super) fn seal_frame<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    sealing: P::Sealing<'_>,
    mut header: Header,
    payloads: PayloadChain<'_>,
    fragment: Option<(u16, u16)>,
) -> Result<SealedPacket<P>, Error> {
    domain.check(profile, keys)?;
    let length = P::payload_len(profile, payloads.bytes().len())
        .and_then(|length| length.checked_add(if fragment.is_some() { 4 } else { 0 }))
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::Drop)?;
    header.length = 28 + u32::from(length);
    header.next_payload = if fragment.is_some() { 53 } else { 46 };
    let mut packet = BytesMut::new();
    encode_header(&header, &mut packet, EncodeContext::default()).map_err(|_| Error::Drop)?;
    packet.put_u8(payloads.first_payload().as_u8());
    packet.put_u8(0);
    packet.put_u16(length);
    if let Some((number, total)) = fragment {
        packet.put_u16(number);
        packet.put_u16(total);
    }
    let body = P::seal_body(
        profile,
        keys,
        domain.send.direction(),
        sealing,
        ProtectedPayloadSealContext {
            kind: if fragment.is_some() {
                ProtectedPayloadKind::EncryptedFragment
            } else {
                ProtectedPayloadKind::Encrypted
            },
            message_prefix: &packet,
        },
        payloads.bytes(),
    )?;
    packet.extend_from_slice(&body);
    Ok(SealedPacket {
        wire: packet.freeze(),
        profile: PhantomData,
    })
}
