use super::{
    configuration::{chain, notify_entry},
    encode_payloads, once, Error, EspSpi, Limits, Notify, QosInfo,
};
use crate::{
    build_delete_payload_body, Header, Ikev2DeletePayload, Ikev2IkeAuthPayloadBuild,
    Ikev2NotifyPayload, PayloadType, EXCHANGE_TYPE_INFORMATIONAL,
};
use bytes::Bytes;
use std::{collections::BTreeSet, fmt};

/// Original IKE SA role. The UE initiated the IKE SA, even when the network
/// initiates a later CREATE_CHILD_SA or INFORMATIONAL exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// UE, whose original IKE initiator flag is set.
    Ue,
    /// N3IWF, whose original IKE initiator flag is clear.
    Network,
}
impl Peer {
    fn initiator(self) -> bool {
        self == Self::Ue
    }
    fn opposite(self) -> Self {
        match self {
            Self::Ue => Self::Network,
            Self::Network => Self::Ue,
        }
    }
}

/// Redacted correlation facts for an already opened request. These facts do
/// not prove integrity, peer authentication, or replay-window admission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestIdentity {
    initiator_spi: u64,
    responder_spi: u64,
    message_id: u32,
    exchange_type: u8,
    sender: Peer,
}
impl fmt::Debug for RequestIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestIdentity([REDACTED])")
    }
}
impl RequestIdentity {
    /// Validate the request's header role and exchange kind. The caller must
    /// supply a header authenticated together with the opened payload bytes.
    pub fn from_request(header: &Header, sender: Peer, exchange_type: u8) -> Result<Self, Error> {
        validate_header(header, sender, false, exchange_type)?;
        Ok(Self {
            initiator_spi: header.initiator_spi,
            responder_spi: header.responder_spi,
            message_id: header.message_id,
            exchange_type,
            sender,
        })
    }
    /// Match response role, message ID, exchange type and both IKE SPIs.
    pub fn validate_response(self, header: &Header) -> Result<(), Error> {
        validate_header(header, self.sender.opposite(), true, self.exchange_type)?;
        if header.initiator_spi != self.initiator_spi
            || header.responder_spi != self.responder_spi
            || header.message_id != self.message_id
        {
            return Err(Error::Incompatible);
        }
        Ok(())
    }
    /// Request sender; useful for caller-owned upper-layer notification.
    pub const fn sender(self) -> Peer {
        self.sender
    }
}
fn validate_header(
    header: &Header,
    sender: Peer,
    response: bool,
    exchange_type: u8,
) -> Result<(), Error> {
    if header.major_version != 2
        || header.initiator_spi == 0
        || header.responder_spi == 0
        || header.exchange_type != exchange_type
        || header.flags.initiator() != sender.initiator()
        || header.flags.response() != response
        || header.next_payload != PayloadType::Encrypted.as_u8()
    {
        return Err(Error::Incompatible);
    }
    Ok(())
}

/// Full replacement of the QoS association for one sender-owned inbound SPI.
/// Applying this object must replace, rather than append to, the old QFI list,
/// DSCP, default indication, and additional QoS parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modification<'a> {
    /// N3IWF inbound ESP SPI identifying the existing child SA.
    pub inbound_spi: EspSpi,
    /// Complete replacement association.
    pub replacement: QosInfo<'a>,
}
impl<'a> Modification<'a> {
    /// Construct the UP_SA_INFO and full 5G_QOS_INFO notification pair.
    pub fn payloads(self) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        Ok(vec![
            notify_entry(Notify::UpSaInfo(self.inbound_spi))?,
            notify_entry(Notify::Qos(self.replacement))?,
        ])
    }
    /// Decode a network-initiated opened modification request. Both notifies
    /// are mandatory singletons; their order is unrestricted. Unknown status
    /// notifies and unknown noncritical payloads are ignored after framing.
    pub fn decode(
        header: &Header,
        first: PayloadType,
        bytes: &'a [u8],
        limits: Limits,
    ) -> Result<(RequestIdentity, Self), Error> {
        let identity =
            RequestIdentity::from_request(header, Peer::Network, EXCHANGE_TYPE_INFORMATIONAL)?;
        let mut spi = None;
        let mut qos = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            match raw.payload_type {
                PayloadType::Notify => {
                    let value = Ikev2NotifyPayload::decode(raw).map_err(|_| Error::Framing)?;
                    if value.notify_message_type < 16_384 {
                        return Err(Error::Incompatible);
                    }
                    match Notify::decode(value)? {
                        Some(Notify::UpSaInfo(v)) => once(&mut spi, v)?,
                        Some(Notify::Qos(v)) => once(&mut qos, v)?,
                        Some(_) => return Err(Error::Incompatible),
                        None => (),
                    }
                }
                PayloadType::Unknown(_) | PayloadType::VendorId => (),
                _ => return Err(Error::Incompatible),
            }
        }
        Ok((
            identity,
            Self {
                inbound_spi: spi.ok_or(Error::Missing)?,
                replacement: qos.ok_or(Error::Missing)?,
            },
        ))
    }
}

/// Peer error code retained without its SPI or notification bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerError(u16);
impl PeerError {
    /// Nonzero RFC 7296 error-notify code (below 16384).
    pub const fn code(self) -> u16 {
        self.0
    }
}
/// Distinct modification results. Only `Accepted` authorizes a caller to apply
/// the complete replacement; a timeout leaves the peer's state unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModificationOutcome {
    /// Matching, empty INFORMATIONAL response.
    Accepted,
    /// Matching error response. Preserve the old association locally.
    Rejected(PeerError),
    /// Caller exhausted its retransmission policy without a valid response.
    AmbiguousTimeout,
}
/// A caller-recorded outgoing modification, consumable once at resolution.
#[derive(Debug)]
pub struct PendingModification(RequestIdentity);
impl PendingModification {
    /// Record a network-initiated modification after its payloads were built.
    pub fn new(header: &Header) -> Result<Self, Error> {
        Ok(Self(RequestIdentity::from_request(
            header,
            Peer::Network,
            EXCHANGE_TYPE_INFORMATIONAL,
        )?))
    }
    /// Resolve an authenticated matching response. An empty opened chain is
    /// success; a single error notification is rejection. Unexpected content
    /// fails closed. This boundary performs no SA mutation.
    pub fn response(
        self,
        header: &Header,
        first: PayloadType,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<ModificationOutcome, Error> {
        self.0.validate_response(header)?;
        limits.check(bytes.len(), 0)?;
        if first == PayloadType::NoNext && bytes.is_empty() {
            return Ok(ModificationOutcome::Accepted);
        }
        let mut error = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            if raw.payload_type != PayloadType::Notify {
                return Err(Error::Incompatible);
            }
            let value = Ikev2NotifyPayload::decode(raw).map_err(|_| Error::Framing)?;
            if !(1..16_384).contains(&value.notify_message_type) {
                return Err(Error::Incompatible);
            }
            once(&mut error, PeerError(value.notify_message_type))?;
        }
        Ok(ModificationOutcome::Rejected(error.ok_or(Error::Missing)?))
    }
    /// Record caller-determined retransmission exhaustion without claiming the
    /// peer rejected or accepted the change.
    pub fn timeout(self) -> ModificationOutcome {
        ModificationOutcome::AmbiguousTimeout
    }
}

/// Whether a peer Delete request crossed the caller's initiated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteCollision {
    /// Only the received request is outstanding.
    Ordinary,
    /// Both peers initiated deletion concurrently.
    Crossed,
}

/// Explicit TS 24.502 section 7.7 Child-SA Delete profile, distinct from generic
/// RFC 7296 paired-direction responses and the TS 24.302 dedicated-bearer profile.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildDelete {
    inbound_spis: Vec<EspSpi>,
}
impl fmt::Debug for ChildDelete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildDelete")
            .field("spi_count", &self.inbound_spis.len())
            .finish()
    }
}
impl ChildDelete {
    /// Include the complete sender-owned inbound SPI roster supplied by the
    /// caller for the released PDU session. This boundary cannot infer roster
    /// membership; use `validate_complete` against an authoritative snapshot.
    pub fn new(inbound_spis: &[EspSpi], limits: Limits) -> Result<Self, Error> {
        check_spis(inbound_spis, limits)?;
        Ok(Self {
            inbound_spis: inbound_spis.to_vec(),
        })
    }
    /// Explicit access to every received SPI, in wire order.
    pub fn inbound_spis(&self) -> &[EspSpi] {
        &self.inbound_spis
    }
    /// Verify exact set equality against the caller's complete roster. No
    /// omission, extra SPI, or duplicate is accepted; wire order is irrelevant.
    pub fn validate_complete(&self, roster: &[EspSpi]) -> Result<(), Error> {
        if self.inbound_spis.len() != roster.len() {
            return Err(Error::Incompatible);
        }
        let expected: BTreeSet<_> = roster.iter().map(|v| v.octets()).collect();
        if expected.len() != roster.len()
            || self
                .inbound_spis
                .iter()
                .any(|s| !expected.contains(&s.octets()))
        {
            return Err(Error::Incompatible);
        }
        Ok(())
    }
    /// Encode a Protocol ID 3, four-octet-SPI Delete payload.
    pub fn payloads(&self) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        let octets: Vec<_> = self.inbound_spis.iter().map(|s| s.octets()).collect();
        let refs: Vec<_> = octets.iter().map(|s| s.as_slice()).collect();
        Ok(vec![Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Delete,
            body: build_delete_payload_body(3, 4, &refs).map_err(|_| Error::InvalidValue)?,
        }])
    }
    /// Echo the received Delete payload for both ordinary and crossed NWu
    /// requests. No error Notify is added. The request's SPI order is retained.
    pub fn response_payloads(
        &self,
        _collision: DeleteCollision,
    ) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        self.payloads()
    }
    /// Decode a request from either initiator. Authentication and roster lookup
    /// remain caller-owned; this decoder checks only header and payload shape.
    pub fn decode(
        header: &Header,
        sender: Peer,
        first: PayloadType,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<(RequestIdentity, Self), Error> {
        let identity = RequestIdentity::from_request(header, sender, EXCHANGE_TYPE_INFORMATIONAL)?;
        Ok((identity, Self::decode_payloads(first, bytes, limits)?))
    }
    fn decode_payloads(first: PayloadType, bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        let mut result = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            if raw.payload_type != PayloadType::Delete {
                return Err(Error::Incompatible);
            }
            // Preflight SPI size and count before generic allocation, including
            // the malicious zero-size / huge-count generic-delete case.
            let header = raw.body.get(..4).ok_or(Error::Framing)?;
            if header[0] != 3 || header[1] != 4 {
                return Err(Error::SpiShape);
            }
            let count = usize::from(u16::from_be_bytes([header[2], header[3]]));
            limits.check(raw.body.len() + 4, count)?;
            let value = Ikev2DeletePayload::decode(raw).map_err(|_| Error::Framing)?;
            let spis = value
                .spis
                .iter()
                .map(|v| EspSpi::new((*v).try_into().map_err(|_| Error::SpiShape)?))
                .collect::<Result<Vec<_>, _>>()?;
            once(&mut result, Self::new(&spis, limits)?)?;
        }
        result.ok_or(Error::Missing)
    }
}
fn check_spis(spis: &[EspSpi], limits: Limits) -> Result<(), Error> {
    if spis.is_empty() {
        return Err(Error::Missing);
    }
    if spis.len() > (65_535 - 8) / 4 {
        return Err(Error::Limit);
    }
    limits.check(8 + spis.len() * 4, spis.len())?;
    let unique: BTreeSet<_> = spis.iter().map(|v| v.octets()).collect();
    if unique.len() != spis.len() {
        return Err(Error::Duplicate);
    }
    Ok(())
}

/// Scope of the caller's response to exhausted NWu delete retransmissions.
/// The SDK reports intent and does not discard installed state or notify an AMF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The peer returned the required acknowledgement.
    Acknowledged,
    /// Discard this IKE SA and every child SA; notify the caller's upper layers
    /// (the AMF on the network side). This is not limited to the original SPI set.
    DiscardIkeAndAllChildren,
}
/// An initiated Child-SA Delete awaiting the exact NWu echo.
#[derive(Debug)]
pub struct PendingChildDelete {
    identity: RequestIdentity,
    request: ChildDelete,
}
impl PendingChildDelete {
    /// Record an outgoing request from either peer.
    pub fn new(header: &Header, sender: Peer, request: ChildDelete) -> Result<Self, Error> {
        Ok(Self {
            identity: RequestIdentity::from_request(header, sender, EXCHANGE_TYPE_INFORMATIONAL)?,
            request,
        })
    }
    /// Require an exact echoed SPI sequence and a matching authenticated header.
    pub fn response(
        self,
        header: &Header,
        first: PayloadType,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<DeleteOutcome, Error> {
        self.identity.validate_response(header)?;
        let received = ChildDelete::decode_payloads(first, bytes, limits)?;
        if received != self.request {
            return Err(Error::Incompatible);
        }
        Ok(DeleteOutcome::Acknowledged)
    }
    /// Escalate an unanswered initiated deletion to the whole IKE SA scope.
    pub fn timeout(self) -> DeleteOutcome {
        DeleteOutcome::DiscardIkeAndAllChildren
    }
}

/// Protocol ID 1 IKE-SA deletion (no SPIs), initiated by either peer.
#[derive(Debug)]
pub struct PendingIkeDelete(RequestIdentity);
impl PendingIkeDelete {
    /// Record an outgoing IKE Delete request.
    pub fn new(header: &Header, sender: Peer) -> Result<Self, Error> {
        Ok(Self(RequestIdentity::from_request(
            header,
            sender,
            EXCHANGE_TYPE_INFORMATIONAL,
        )?))
    }
    /// Construct its single no-SPI Delete payload.
    pub fn payloads() -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        Ok(vec![Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Delete,
            body: build_delete_payload_body(1, 0, &[]).map_err(|_| Error::InvalidValue)?,
        }])
    }
    /// Decode a matching IKE Delete request from either peer. The response is
    /// an empty INFORMATIONAL exchange (RFC 7296 section 1.4.1).
    pub fn decode_request(
        header: &Header,
        sender: Peer,
        first: PayloadType,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<RequestIdentity, Error> {
        let identity = RequestIdentity::from_request(header, sender, EXCHANGE_TYPE_INFORMATIONAL)?;
        let mut seen = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            if raw.payload_type != PayloadType::Delete || raw.body != [1, 0, 0, 0] {
                return Err(Error::Incompatible);
            }
            once(&mut seen, ())?;
        }
        seen.ok_or(Error::Missing)?;
        Ok(identity)
    }
    /// Empty IKE Delete acknowledgement; both IKE SA and all child SAs are in scope.
    pub fn response(
        self,
        header: &Header,
        first: PayloadType,
        bytes: &[u8],
    ) -> Result<DeleteOutcome, Error> {
        self.0.validate_response(header)?;
        if first != PayloadType::NoNext || !bytes.is_empty() {
            return Err(Error::Incompatible);
        }
        Ok(DeleteOutcome::Acknowledged)
    }
    /// Retransmission exhaustion retains the whole-IKE-SA deletion scope.
    pub fn timeout(self) -> DeleteOutcome {
        DeleteOutcome::DiscardIkeAndAllChildren
    }
}

/// Canonical empty INFORMATIONAL acknowledgement used by modification and
/// IKE-SA deletion. Child-SA deletion instead requires an echoed Delete payload.
pub fn empty_response() -> (PayloadType, Bytes) {
    (PayloadType::NoNext, Bytes::new())
}

/// Encode a typed modification's two required notifications.
pub fn encode_modification(value: Modification<'_>) -> Result<(PayloadType, Bytes), Error> {
    encode_payloads(&value.payloads()?)
}
