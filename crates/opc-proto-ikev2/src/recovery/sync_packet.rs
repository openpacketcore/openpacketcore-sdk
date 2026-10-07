use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{BorrowDecode, DecodeContext, EncodeContext};

use super::{Ikev2CommittedWindowDomain as Domain, Ikev2WindowError as Error};
use crate::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload, encode_header,
    ikev2_aes_gcm_protected_payload_len, open_protected_payloads, Header, Ikev2AesGcmIvAllocation,
    Ikev2ExchangeKind, Ikev2IkeAuthPayloadBuild, Ikev2MessageIdSync as Sync,
    Ikev2NotifyPayloadBuild, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Ikev2SaInitProtectedPayloadProvider as Provider, Message, PayloadChain, PayloadType,
    ProtectedPayloadKind, ProtectedPayloadSealContext,
};

pub(super) fn open_request(
    domain: &Domain,
    profile: Profile,
    keys: &Keys,
    wire: &[u8],
) -> Result<(Header, PayloadType, Bytes), Error> {
    open_message(domain, profile, keys, wire, true, false)
}

pub(super) fn open_message(
    domain: &Domain,
    profile: Profile,
    keys: &Keys,
    wire: &[u8],
    peer: bool,
    response: bool,
) -> Result<(Header, PayloadType, Bytes), Error> {
    domain.check(profile, keys)?;
    let (tail, message) =
        Message::decode(wire, DecodeContext::default()).map_err(|_| Error::Drop)?;
    let header = &message.header;
    let direction = if peer {
        &domain.receive
    } else {
        domain.send_iv_domain()
    };
    if !tail.is_empty()
        || header.initiator_spi != direction.initiator_spi()
        || header.responder_spi != direction.responder_spi()
        || header.flags.initiator() != (direction.direction() == Direction::InitiatorToResponder)
        || header.flags.response() != response
        || header.message_id != 0
        || header.exchange_type != Ikev2ExchangeKind::Informational.as_u8()
        || header.next_payload != PayloadType::Encrypted.as_u8()
    {
        return Err(Error::Drop);
    }
    let provider = Provider::new(profile, keys, direction.direction());
    let opened = open_protected_payloads(&message, wire, DecodeContext::default(), &provider)
        .map_err(|_| Error::Drop)?;
    if opened.len() != 1 {
        return Err(Error::Drop);
    }
    let opened = opened.into_iter().next().ok_or(Error::Drop)?;
    PayloadChain::new(opened.first_inner_payload, &opened.cleartext)
        .validate(DecodeContext::default())
        .map_err(|_| Error::Drop)?;
    Ok((header.clone(), opened.first_inner_payload, opened.cleartext))
}

// Narrow private sender: owns the sole Notify and every response header field.
pub(super) fn seal_response(
    domain: &Domain,
    profile: Profile,
    keys: &Keys,
    allocation: Ikev2AesGcmIvAllocation<'_>,
    value: Sync,
) -> Result<Bytes, Error> {
    seal_message(domain, profile, keys, allocation, value, true)
}

// Narrow sender: complete fixed sync request/response only, never arbitrary data.
pub(super) fn seal_message(
    domain: &Domain,
    profile: Profile,
    keys: &Keys,
    allocation: Ikev2AesGcmIvAllocation<'_>,
    value: Sync,
    response: bool,
) -> Result<Bytes, Error> {
    domain.check(profile, keys)?;
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync(value))
        .map_err(|_| Error::Drop)?;
    let (first, cleartext) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .map_err(|_| Error::Drop)?;
    let length = ikev2_aes_gcm_protected_payload_len(cleartext.len(), 0)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Error::Drop)?;
    let mut header = domain.header(Ikev2ExchangeKind::Informational, 0, response);
    header.length = 28 + u32::from(length);
    let mut packet = BytesMut::new();
    encode_header(&header, &mut packet, EncodeContext::default()).map_err(|_| Error::Drop)?;
    packet.put_u8(first.as_u8());
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
            &cleartext,
            0,
        )
        .map_err(Error::Iv)?;
    packet.extend_from_slice(&body);
    Ok(packet.freeze())
}
