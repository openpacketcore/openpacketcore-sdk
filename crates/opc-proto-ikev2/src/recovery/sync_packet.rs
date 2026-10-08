use super::packet::{seal_frame, SealedPacket};
use super::profile::{DirectionBinding, RecoveryProfile};
use bytes::Bytes;
use opc_protocol::{BorrowDecode, DecodeContext};
use std::marker::PhantomData;

use super::{Ikev2CommittedWindowDomain as Domain, Ikev2WindowError as Error};
use crate::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload, open_protected_payloads,
    Header, Ikev2ExchangeKind, Ikev2IkeAuthPayloadBuild, Ikev2MessageIdSync as Sync,
    Ikev2NotifyPayloadBuild, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Ikev2SaInitProtectedPayloadProvider as Provider, Message, PayloadChain, PayloadType,
};

// Authentication establishes profile-typed packet evidence before any IV checks.
pub struct AuthenticatedSync<P: RecoveryProfile> {
    pub(super) header: Header,
    pub(super) first: PayloadType,
    pub(super) cleartext: Bytes,
    wire: Bytes,
    profile: PhantomData<P>,
}
impl<P: RecoveryProfile> AuthenticatedSync<P> {
    pub(super) fn wire(&self) -> &Bytes {
        &self.wire
    }
}

pub(super) fn open_request<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Profile,
    keys: &Keys,
    wire: &[u8],
) -> Result<AuthenticatedSync<P>, Error> {
    open_message(domain, profile, keys, wire, true, false)
}

pub(super) fn open_message<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Profile,
    keys: &Keys,
    wire: &[u8],
    peer: bool,
    response: bool,
) -> Result<AuthenticatedSync<P>, Error> {
    domain.check(profile, keys)?;
    let (tail, message) =
        Message::decode(wire, DecodeContext::default()).map_err(|_| Error::Drop)?;
    let header = &message.header;
    let direction = if peer { &domain.receive } else { &domain.send };
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
    Ok(AuthenticatedSync {
        header: header.clone(),
        first: opened.first_inner_payload,
        cleartext: opened.cleartext,
        wire: Bytes::copy_from_slice(wire),
        profile: PhantomData,
    })
}

// Narrow private sender: owns the sole Notify and every response header field.
pub(super) fn seal_response<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Profile,
    keys: &Keys,
    sealing: P::Sealing<'_>,
    value: Sync,
) -> Result<SealedPacket<P>, Error> {
    seal_message(domain, profile, keys, sealing, value, true)
}

// Narrow sender: complete fixed sync request/response only, never arbitrary data.
pub(super) fn seal_message<P: RecoveryProfile>(
    domain: &Domain<P>,
    profile: Profile,
    keys: &Keys,
    sealing: P::Sealing<'_>,
    value: Sync,
    response: bool,
) -> Result<SealedPacket<P>, Error> {
    domain.check(profile, keys)?;
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync(value))
        .map_err(|_| Error::Drop)?;
    let (first, cleartext) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .map_err(|_| Error::Drop)?;
    seal_frame(
        domain,
        profile,
        keys,
        sealing,
        domain.header(Ikev2ExchangeKind::Informational, 0, response),
        PayloadChain::new(first, &cleartext),
    )
}
