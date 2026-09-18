use super::super::{
    configuration::chain, encode_payloads, Address, ConfigurationReply, DeleteOutcome, Limits,
};
use super::{Error, Notify, Path, Request};
use crate::{
    classify_ike_nat_traversal_datagram_with_context, crypto_module::with_entropy_operation,
    evaluate_ikev2_nat_detection, ikev2_aes_cbc_protected_body_len,
    ikev2_aes_gcm_protected_body_len, ikev2_nat_detection_hash, open_protected_payloads, Header,
    HeaderFlags, Ikev2ExchangeKind, Ikev2IkeAuthPayloadBuild, Ikev2InitiatorMessageIdWindow,
    Ikev2NatDetectionOutcome, Ikev2NotifyPayload, Ikev2ProtectedPayloadDirection,
    Ikev2ResponderMessageIdWindow, Ikev2SaInitProtectedPayloadProvider, NatTraversalClassification,
    PayloadType, EXCHANGE_TYPE_INFORMATIONAL,
};
use bytes::Bytes;
use opc_protocol::DecodeContext;
use std::fmt;
use subtle::ConstantTimeEq;

/// Established NAT traversal capability and current ESP encapsulation state.
/// MOBIKE peers with NAT-T support always carry IKE on UDP/4500, even when
/// their current ESP traffic is not encapsulated (RFC 4555 section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatState {
    supported: bool,
    esp_udp: bool,
}
impl NatState {
    /// Import caller-established NAT capability and current ESP mode.
    pub fn new(supported: bool, esp_udp_encapsulation: bool) -> Result<Self, Error> {
        if esp_udp_encapsulation && !supported {
            return Err(super::super::Error::Incompatible.into());
        }
        Ok(Self {
            supported,
            esp_udp: esp_udp_encapsulation,
        })
    }
    /// Whether both peers negotiated NAT traversal support.
    pub const fn supported(self) -> bool {
        self.supported
    }
    /// Whether outgoing ESP currently uses UDP encapsulation.
    pub const fn esp_udp_encapsulation(self) -> bool {
        self.esp_udp
    }
}

/// Bounded payload/header intent to seal and send through existing IKE APIs.
/// Cache and retransmit the exact sealed bytes to this exact path. A probe
/// retargeted outside this API is not valid return-routability evidence.
pub struct Outbound {
    spis: [u64; 2],
    id: u32,
    response: bool,
    path: Path,
    payloads: Vec<Ikev2IkeAuthPayloadBuild>,
    limits: Limits,
    marker_len: usize,
}
impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobikeOutbound([REDACTED])")
    }
}
impl Outbound {
    /// Exact destination/source pair in outbound packet direction.
    pub const fn path(&self) -> Path {
        self.path
    }
    /// Allocated or correlated IKE message ID.
    pub const fn message_id(&self) -> u32 {
        self.id
    }
    /// True for an acknowledgement; false for a COOKIE2 probe request.
    pub const fn is_response(&self) -> bool {
        self.response
    }
    /// Explicit payload access for the existing protected-payload sealer.
    pub fn payloads(&self) -> &[Ikev2IkeAuthPayloadBuild] {
        &self.payloads
    }
    /// Canonical opened chain for the existing protected-payload sealer.
    pub fn cleartext(&self) -> Result<(PayloadType, Bytes), Error> {
        let encoded = encode_payloads(&self.payloads)?;
        self.limits.check(encoded.1.len(), self.payloads.len())?;
        Ok(encoded)
    }
    /// Original-responder SK header for a caller-computed protected body length.
    /// The body includes IV/ciphertext/padding/ICV, excluding the SK header.
    pub fn header(&self, protected_body_len: usize) -> Result<Header, Error> {
        if protected_body_len > 65_531 {
            return Err(super::super::Error::Limit.into());
        }
        self.limits.check(
            32 + protected_body_len + self.marker_len,
            self.payloads.len(),
        )?;
        Ok(Header {
            initiator_spi: self.spis[0],
            responder_spi: self.spis[1],
            next_payload: PayloadType::Encrypted.as_u8(),
            major_version: 2,
            minor_version: 0,
            exchange_type: EXCHANGE_TYPE_INFORMATIONAL,
            flags: HeaderFlags::from_bits(false, self.response, false),
            message_id: self.id,
            length: (32 + protected_body_len) as u32,
        })
    }
}

/// Authenticated request disposition, independent of any backend operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    /// The request passed framing, authentication, freshness and policy.
    Accepted,
    /// The caller rejected its observed address pair; send Notify 40.
    UnacceptableAddresses,
    /// Its NO_NATS_ALLOWED disagreed with the observed path; send Notify 41.
    UnexpectedNatDetected,
}
/// An authenticated reply plus immediate IKE/address-list intent. Child-SA
/// migration is deliberately absent until a fresh probe has completed.
#[derive(Debug)]
pub struct ReceivedRequest {
    status: RequestStatus,
    reply: Outbound,
    ike_path: Option<Path>,
    addresses: Option<Vec<Address>>,
}
impl ReceivedRequest {
    /// Accepted or explicitly rejected by address/NAT policy.
    pub const fn status(&self) -> RequestStatus {
        self.status
    }
    /// Correlated response to seal, cache and transmit.
    pub const fn reply(&self) -> &Outbound {
        &self.reply
    }
    /// New IKE path, in inbound packet direction; present only for UPDATE.
    pub const fn ike_path(&self) -> Option<Path> {
        self.ike_path
    }
    /// Complete replacement peer address list including the observed source.
    /// An address advertisement alone never changes the Child-SA path.
    pub fn peer_addresses(&self) -> Option<&[Address]> {
        self.addresses.as_deref()
    }
}

/// Once-produced Child-SA address/encapsulation intent after authenticated
/// COOKIE2 proof for the latest accepted update. Applying it belongs to XFRM;
/// the caller must apply or discard it before processing the next SA event.
#[derive(Debug)]
pub struct Migration {
    path: Path,
    esp_udp: bool,
}
impl Migration {
    /// Verified observed path, in UE-to-network packet direction.
    pub const fn path(&self) -> Path {
        self.path
    }
    /// Desired ESP UDP encapsulation after this address change.
    pub const fn esp_udp_encapsulation(&self) -> bool {
        self.esp_udp
    }
}
/// Terminal result of a correlated authenticated COOKIE2 response.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// Latest candidate passed return-routability and may be applied once.
    Verified(Migration),
    /// A newer update superseded the probed candidate; no migration is emitted.
    Superseded,
    /// An authenticated missing/mismatching COOKIE2 requires IKE-SA closure.
    DiscardIkeAndAllChildren,
}
#[derive(Clone, Copy)]
struct Candidate {
    id: u32,
    path: Path,
    esp_udp: bool,
}
struct Probe {
    candidate: Candidate,
    id: u32,
    cookie: [u8; 32],
}

/// Network-side MOBIKE receiver bound to one established authenticated IKE SA.
/// All runtime crypto uses the admitted concrete provider. This does not
/// authenticate the subscriber or establish IKE_AUTH trust itself. Reuse the
/// SA's shared message-ID windows for every exchange, not MOBIKE-only counters.
/// This implementation follows the RFC 4555 recommended policy of requiring
/// return-routability before every Child-SA migration; there is no bypass.
pub struct Responder<'a> {
    spis: [u64; 2],
    provider: Ikev2SaInitProtectedPayloadProvider<'a>,
    limits: Limits,
    nat: NatState,
    candidate: Option<Candidate>,
    probe: Option<Probe>,
    highest_peer_id: Option<u32>,
    closed: bool,
}
impl fmt::Debug for Responder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobikeResponder([REDACTED])")
    }
}
struct Opened {
    header: Header,
    first: PayloadType,
    bytes: Bytes,
}
impl<'a> Responder<'a> {
    /// Bind nonzero IKE SPIs, a conditional NWu capability reply, the concrete
    /// initiator-to-responder crypto provider, NAT state and caller bounds.
    /// The caller supplies these from the same authenticated established SA.
    pub fn new(
        spis: [u64; 2],
        reply: ConfigurationReply,
        provider: Ikev2SaInitProtectedPayloadProvider<'a>,
        nat: NatState,
        limits: Limits,
    ) -> Result<Self, Error> {
        if spis.contains(&0)
            || !reply.mobike_supported()
            || provider.direction() != Ikev2ProtectedPayloadDirection::InitiatorToResponder
        {
            return Err(Error::Correlation);
        }
        Ok(Self {
            spis,
            provider,
            limits,
            nat,
            candidate: None,
            probe: None,
            highest_peer_id: None,
            closed: false,
        })
    }
    /// Current Child-SA encapsulation mode; it changes only after COOKIE2 proof.
    pub const fn nat_state(&self) -> NatState {
        self.nat
    }
    /// Whether an accepted candidate still awaits proof.
    pub const fn has_pending_update(&self) -> bool {
        self.candidate.is_some()
    }
    fn open(&self, datagram: &[u8], path: Path, response: bool) -> Result<Opened, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        self.limits.check(datagram.len(), 0)?;
        if path.destination().port() != if self.nat.supported { 4500 } else { 500 } {
            return Err(Error::Transport);
        }
        let ctx = DecodeContext {
            max_message_len: self.limits.bytes,
            max_ies: self.limits.entries,
            ..DecodeContext::default()
        };
        let NatTraversalClassification::Ike(message) =
            classify_ike_nat_traversal_datagram_with_context(
                path.destination().port(),
                datagram,
                ctx,
            )
        else {
            return Err(Error::Transport);
        };
        let h = &message.message().header;
        if [h.initiator_spi, h.responder_spi] != self.spis
            || !h.flags.initiator()
            || h.flags.response() != response
            || h.exchange_type != EXCHANGE_TYPE_INFORMATIONAL
            || h.next_payload != PayloadType::Encrypted.as_u8()
        {
            return Err(Error::Correlation);
        }
        let mut opened =
            open_protected_payloads(message.message(), message.ike_bytes(), ctx, &self.provider)
                .map_err(|_| Error::Authentication)?;
        if opened.len() != 1 {
            return Err(Error::Correlation);
        }
        let opened = opened.pop().ok_or(Error::Authentication)?;
        Ok(Opened {
            header: h.clone(),
            first: opened.first_inner_payload,
            bytes: opened.cleartext,
        })
    }
    fn outbound(
        &self,
        id: u32,
        response: bool,
        inbound: Path,
        payloads: Vec<Ikev2IkeAuthPayloadBuild>,
    ) -> Outbound {
        Outbound {
            spis: self.spis,
            id,
            response,
            path: inbound.reversed(),
            payloads,
            limits: self.limits,
            marker_len: if self.nat.supported { 4 } else { 0 },
        }
    }

    /// Authenticate one exact UDP datagram before applying freshness, address
    /// policy or NAT checks. Invalid or rejected requests leave windows,
    /// candidate/probe state and current encapsulation unchanged. The caller
    /// handles retransmission caching before this fresh-request boundary;
    /// a duplicate returns Replay and never re-applies migration intent.
    ///
    /// A shared receive window must be seeded through completed IKE_AUTH.
    /// The address policy runs only after cryptographic verification, framing
    /// and freshness. Returning false yields an authenticated Notify 40 reply.
    pub fn receive_request(
        &mut self,
        datagram: &[u8],
        path: Path,
        window: &mut Ikev2ResponderMessageIdWindow,
        address_policy: impl FnOnce(Path) -> bool,
    ) -> Result<ReceivedRequest, Error> {
        let opened = self.open(datagram, path, false)?;
        if window.highest_processed().is_none() {
            return Err(Error::Window);
        }
        let id = opened.header.message_id;
        let mut next_window = *window;
        if self.highest_peer_id.is_some_and(|highest| id <= highest)
            || !next_window.accept_request(id)
        {
            return Err(Error::Replay);
        }
        let request = Request::decode(opened.first, &opened.bytes, self.limits)?;
        let changes_addresses = request.update || request.additional.is_some();
        if !self.nat.supported && !request.nat.is_empty() {
            return Err(super::super::Error::Incompatible.into());
        }
        if !self.nat.supported && changes_addresses && request.no_nats.is_none() {
            return Err(super::super::Error::Missing.into());
        }

        let mut reply_payloads = Vec::new();
        if let Some(cookie) = request.cookie {
            reply_payloads.push(Notify::Cookie2(cookie).payload()?);
        }
        let status = if request.no_nats.is_some_and(|protected| protected != path) {
            RequestStatus::UnexpectedNatDetected
        } else if changes_addresses && !address_policy(path) {
            RequestStatus::UnacceptableAddresses
        } else {
            RequestStatus::Accepted
        };
        if status != RequestStatus::Accepted {
            reply_payloads.push(
                match status {
                    RequestStatus::UnexpectedNatDetected => Notify::UnexpectedNatDetected,
                    _ => Notify::UnacceptableAddresses,
                }
                .payload()?,
            );
            return Ok(ReceivedRequest {
                status,
                reply: self.outbound(id, true, path, reply_payloads),
                ike_path: None,
                addresses: None,
            });
        }

        let mut esp_udp = self.nat.esp_udp;
        if !request.nat.is_empty() {
            let evaluation = evaluate_ikev2_nat_detection(
                &request.nat,
                self.spis[0],
                self.spis[1],
                path.source().into(),
                path.destination().into(),
            )
            .map_err(|_| Error::Crypto)?;
            esp_udp = match evaluation.outcome() {
                Ikev2NatDetectionOutcome::NoNat => false,
                Ikev2NatDetectionOutcome::SourceNat
                | Ikev2NatDetectionOutcome::DestinationNat
                | Ikev2NatDetectionOutcome::Both => true,
                Ikev2NatDetectionOutcome::Unknown => return Err(Error::Crypto),
            };
            let source = ikev2_nat_detection_hash(self.spis[0], self.spis[1], path.destination())
                .map_err(|_| Error::Crypto)?;
            let destination = ikev2_nat_detection_hash(self.spis[0], self.spis[1], path.source())
                .map_err(|_| Error::Crypto)?;
            reply_payloads.push(Notify::NatSource(&source).payload()?);
            reply_payloads.push(Notify::NatDestination(&destination).payload()?);
        }
        let addresses = request.additional.map(|mut alternatives| {
            let source = Address::new(path.source().ip());
            alternatives.retain(|a| *a != source);
            alternatives.insert(0, source);
            alternatives
        });
        // Commit only after authentication, complete decode, policy and every
        // potentially failing operation. Probe completion is a separate step.
        *window = next_window;
        self.highest_peer_id = Some(id);
        if request.update {
            self.candidate = Some(Candidate { id, path, esp_udp });
        }
        Ok(ReceivedRequest {
            status,
            reply: self.outbound(id, true, path, reply_payloads),
            ike_path: request.update.then_some(path),
            addresses,
        })
    }

    /// Generate an unpredictable 32-octet COOKIE2 through the admitted module
    /// and allocate an INFORMATIONAL ID from the SA's shared outbound window.
    /// This never produces a Child-SA update. Send/retransmit the returned
    /// sealed request only to its fixed path; timers and caching remain external.
    pub fn begin_return_routability(
        &mut self,
        window: &mut Ikev2InitiatorMessageIdWindow,
    ) -> Result<Outbound, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.probe.is_some() {
            return Err(Error::State);
        }
        let candidate = self.candidate.ok_or(Error::State)?;
        if window.outstanding().is_some() || window.next_message_id() == u32::MAX {
            return Err(Error::Window);
        }
        // COOKIE2 has a 4-byte generic header, 4-byte Notify header and a
        // 32-byte token. Check the minimum complete encrypted datagram before
        // entropy generation or advancing the shared request window.
        let body_len = if self.provider.profile().encryption().is_aead() {
            ikev2_aes_gcm_protected_body_len(40, 0)
        } else {
            ikev2_aes_cbc_protected_body_len(self.provider.profile(), 40)
        }
        .ok_or(Error::Crypto)?;
        self.limits
            .check(32 + body_len + if self.nat.supported { 4 } else { 0 }, 1)?;
        let mut cookie = [0u8; 32];
        with_entropy_operation(|module| module.fill_random(&mut cookie))
            .map_err(|_| Error::Crypto)?;
        let payloads = vec![Notify::Cookie2(&cookie).payload()?];
        let allocation = window
            .allocate(Ikev2ExchangeKind::Informational)
            .map_err(|_| Error::Window)?;
        self.probe = Some(Probe {
            candidate,
            id: allocation.message_id,
            cookie,
        });
        Ok(self.outbound(allocation.message_id, false, candidate.path, payloads))
    }

    /// Open and correlate a COOKIE2 response on its original exact path.
    /// Authentication, source or framing failure leaves the probe pending.
    /// An authenticated missing/mismatching cookie closes this receiver and
    /// reports whole-IKE/all-children discard, as required by RFC 4555 §3.7.
    /// A valid response to an older, superseded update frees the outbound
    /// window but cannot commit that old path; start a new probe for the latest.
    pub fn receive_probe_response(
        &mut self,
        datagram: &[u8],
        path: Path,
        window: &mut Ikev2InitiatorMessageIdWindow,
    ) -> Result<ProbeOutcome, Error> {
        let opened = self.open(datagram, path, true)?;
        let probe = self.probe.as_ref().ok_or(Error::State)?;
        if opened.header.message_id != probe.id {
            return Err(Error::Correlation);
        }
        if path != probe.candidate.path {
            return Err(Error::Source);
        }
        let outstanding = window.outstanding().ok_or(Error::Window)?;
        if outstanding.message_id != probe.id
            || outstanding.exchange != Ikev2ExchangeKind::Informational
        {
            return Err(Error::Window);
        }
        let cookie = response_cookie(opened.first, &opened.bytes, self.limits)?;
        let matches = cookie.is_some_and(|v| bool::from(v.ct_eq(probe.cookie.as_slice())));
        window
            .complete_response_header(&opened.header)
            .map_err(|_| Error::Window)?;
        let probe = self.probe.take().ok_or(Error::State)?;
        if !matches {
            self.closed = true;
            self.candidate = None;
            return Ok(ProbeOutcome::DiscardIkeAndAllChildren);
        }
        if self
            .candidate
            .is_none_or(|latest| latest.id != probe.candidate.id)
        {
            return Ok(ProbeOutcome::Superseded);
        }
        self.candidate = None;
        self.nat.esp_udp = probe.candidate.esp_udp;
        Ok(ProbeOutcome::Verified(Migration {
            path: probe.candidate.path,
            esp_udp: probe.candidate.esp_udp,
        }))
    }

    /// Report caller-determined exhaustion of the INFORMATIONAL retransmission
    /// policy. No unproven path is emitted; ordinary IKE liveness failure has
    /// whole-IKE/all-children scope. This consumes the receiver.
    pub fn probe_timeout(self) -> DeleteOutcome {
        DeleteOutcome::DiscardIkeAndAllChildren
    }
}

fn response_cookie(
    first: PayloadType,
    bytes: &[u8],
    limits: Limits,
) -> Result<Option<&[u8]>, Error> {
    let mut cookie = None;
    for raw in chain(first, bytes, limits)? {
        let raw = raw.map_err(|_| super::super::Error::Framing)?;
        match raw.payload_type {
            PayloadType::Unknown(_) | PayloadType::VendorId => continue,
            PayloadType::Notify => (),
            _ => return Err(super::super::Error::Incompatible.into()),
        }
        let n = Ikev2NotifyPayload::decode(raw).map_err(|_| super::super::Error::Framing)?;
        if n.notify_message_type < 16_384 {
            return Err(super::super::Error::Incompatible.into());
        }
        match Notify::decode_body(raw.body)? {
            Some(Notify::Cookie2(v)) => super::super::once(&mut cookie, v)?,
            Some(_) => return Err(super::super::Error::Incompatible.into()),
            None => (),
        }
    }
    Ok(cookie)
}
