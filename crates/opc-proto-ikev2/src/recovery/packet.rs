use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{BorrowDecode, DecodeContext, EncodeContext};

use super::{Ikev2CommittedWindowDomain as Domain, Ikev2WindowError as Error};
use crate::{
    encode_header, ikev2_aes_gcm_protected_payload_len, open_protected_payloads, Header,
    Ikev2AesGcmIvAllocation, Ikev2ExchangeKind, Ikev2NotifyPayload, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SaInitProtectedPayloadProvider, Message,
    PayloadChain, PayloadType, ProtectedPayloadKind, ProtectedPayloadSealContext,
    GENERIC_PAYLOAD_HEADER_LEN, HEADER_LEN, IKEV2_AES_GCM_EXPLICIT_IV_LEN,
    IKEV2_NOTIFY_MESSAGE_ID_SYNC,
};

/// Completely authenticated ordinary SK packet bound to a durable-window domain.
///
/// Created only through the admitted crypto open path; it is not admission to a
/// receive window and grants no effects. Sync Notify packets are never this type.
pub struct Ikev2AuthenticatedOrdinary {
    pub(super) domain: Domain,
    pub(super) header: Header,
    pub(super) wire: Bytes,
    first: PayloadType,
    cleartext: Bytes,
}

impl Ikev2AuthenticatedOrdinary {
    pub(crate) fn canonical_message_id(
        &self,
        expected: &Domain,
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

    pub(super) fn require_reserved_iv(&self, exclusive_end: u64) -> Result<(), Error> {
        if sending_iv_end(&self.wire)? > exclusive_end {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }
}

// Only for complete GCM SK packets already authenticated or sealed in this module.
// This extracts evidence; it is never authentication or allocation authority.
pub(super) fn sending_iv_end(wire: &[u8]) -> Result<u64, Error> {
    let start = HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let iv = wire
        .get(start..start + IKEV2_AES_GCM_EXPLICIT_IV_LEN)
        .ok_or(Error::InvalidRecord)?;
    u64::from_be_bytes(iv.try_into().map_err(|_| Error::InvalidRecord)?)
        .checked_add(1)
        .ok_or(Error::InvalidRecord)
}

pub(super) fn require_work(exchange: u8, payloads: PayloadChain<'_>) -> Result<(), Error> {
    if exchange == Ikev2ExchangeKind::Informational.as_u8() && payloads.is_empty() {
        return Err(Error::NoDurableWork);
    }
    Ok(())
}

fn validate_payloads(payloads: PayloadChain<'_>) -> Result<(), Error> {
    payloads
        .validate(DecodeContext::default())
        .map_err(|_| Error::Drop)?;
    for payload in payloads.iter() {
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

pub(super) fn open(
    domain: &Domain,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    wire: &[u8],
    peer: bool,
) -> Result<Ikev2AuthenticatedOrdinary, Error> {
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
        || header.next_payload != PayloadType::Encrypted.as_u8()
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
    validate_payloads(PayloadChain::new(
        opened.first_inner_payload,
        &opened.cleartext,
    ))?;
    Ok(Ikev2AuthenticatedOrdinary {
        domain: domain.clone(),
        header: header.clone(),
        wire: Bytes::copy_from_slice(wire),
        first: opened.first_inner_payload,
        cleartext: opened.cleartext,
    })
}

pub(super) fn seal(
    domain: &Domain,
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    allocation: Ikev2AesGcmIvAllocation<'_>,
    mut header: Header,
    payloads: PayloadChain<'_>,
) -> Result<Bytes, Error> {
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
    let length = ikev2_aes_gcm_protected_payload_len(payloads.bytes().len(), 0)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::Drop)?;
    header.length = 28 + u32::from(length);
    let mut packet = BytesMut::new();
    encode_header(&header, &mut packet, EncodeContext::default()).map_err(|_| Error::Drop)?;
    packet.put_u8(payloads.first_payload().as_u8());
    packet.put_u8(0);
    packet.put_u16(length);
    let body = allocation
        .seal(
            profile,
            keys,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &packet,
            },
            payloads.bytes(),
            0,
        )
        .map_err(Error::Iv)?;
    packet.extend_from_slice(&body);
    Ok(packet.freeze())
}
