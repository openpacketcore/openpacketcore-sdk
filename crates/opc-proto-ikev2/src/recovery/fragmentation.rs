//! RFC 7383 negotiated packet fragmentation for the committed recovery window.

use std::num::{NonZeroU16, NonZeroU32};

mod send;

use opc_protocol::{BorrowDecode, DecodeContext};

use super::{
    profile::RecoveryProfile, Ikev2CommittedWindow as Window, Ikev2PreparedWindow,
    Ikev2WindowError as Error,
};
use crate::{
    Ikev2NotifyPayload, Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Message, PayloadType,
};

/// Persisted bilateral support and the caller's fixed reassembly timeout.
/// Presence means that both IKE_SA_INIT messages offered RFC 7383 support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2FragmentationParameters {
    timeout_ms: NonZeroU32,
}

impl Ikev2FragmentationParameters {
    /// Restore explicitly from the same authenticated atomic SA record.
    /// This does not prove negotiation; the consumer must preserve that history.
    pub const fn from_persisted(timeout_ms: NonZeroU32) -> Self {
        Self { timeout_ms }
    }

    /// An incomplete set expires this long after its first admitted fragment.
    pub const fn reassembly_timeout_ms(self) -> NonZeroU32 {
        self.timeout_ms
    }
}

/// Maximum IKE packet size after IP/UDP and optional Non-ESP Marker overhead.
/// The path MTU includes any reduction required by enclosing tunnels or options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2FragmentationSize {
    pub(super) ike_bytes: usize,
}

impl Ikev2FragmentationSize {
    /// RFC 7383 §2.5.1: use known PMTU, otherwise a 576-byte IPv4 datagram.
    /// # Errors
    /// Refuses a size with no room after the IP, UDP and optional marker headers.
    pub fn ipv4(pmtu: Option<NonZeroU16>, non_esp_marker: bool) -> Result<Self, Error> {
        Self::new(pmtu.map_or(576, NonZeroU16::get), 20, non_esp_marker)
    }

    /// RFC 7383 §2.5.1: use known PMTU, otherwise a 1280-byte IPv6 datagram.
    /// # Errors
    /// Refuses a size with no room after the IP, UDP and optional marker headers.
    pub fn ipv6(pmtu: Option<NonZeroU16>, non_esp_marker: bool) -> Result<Self, Error> {
        Self::new(pmtu.map_or(1280, NonZeroU16::get), 40, non_esp_marker)
    }

    fn new(mtu: u16, ip_header: usize, non_esp_marker: bool) -> Result<Self, Error> {
        let ike_bytes = usize::from(mtu)
            .checked_sub(ip_header + 8 + if non_esp_marker { 4 } else { 0 })
            .filter(|size| *size > 28)
            .ok_or(Error::FragmentationLimit)?;
        Ok(Self { ike_bytes })
    }

    /// Complete IKE packet budget, including its IKE/SKF headers and protection.
    pub const fn max_ike_packet_bytes(self) -> usize {
        self.ike_bytes
    }
}

fn offered(wire: &[u8], spis: (u64, u64), response: bool) -> Result<bool, Error> {
    let (rest, message) =
        Message::decode(wire, DecodeContext::default()).map_err(|_| Error::Drop)?;
    let h = &message.header;
    if !rest.is_empty()
        || h.exchange_type != 34
        || h.message_id != 0
        || h.flags.response() != response
        || h.flags.initiator() == response
        || h.initiator_spi != spis.0
        || h.responder_spi != if response { spis.1 } else { 0 }
    {
        return Err(Error::Drop);
    }
    let mut support = false;
    for payload in message.payloads.iter() {
        let payload = payload.map_err(|_| Error::Drop)?;
        if payload.is_protected() {
            return Err(Error::Drop);
        }
        if payload.payload_type != PayloadType::Notify {
            continue;
        }
        let notify = Ikev2NotifyPayload::decode(payload).map_err(|_| Error::Drop)?;
        if notify.notify_message_type == crate::IKEV2_FRAGMENTATION_SUPPORTED_NOTIFY_TYPE {
            // RFC 7296 §3.10: ignore Protocol ID when the SPI is empty.
            if support || notify.spi_size != 0 || !notify.notification_data.is_empty() {
                return Err(Error::Drop);
            }
            support = true;
        }
    }
    Ok(support)
}

impl<P: RecoveryProfile> Window<P> {
    /// Commit bilateral RFC 7383 support before sending or receiving IKE_AUTH.
    ///
    /// Supply the exact IKE_SA_INIT request/response retained for subsequent
    /// handshake authentication. No offer is inferred from configuration alone.
    /// Mint any synchronization readiness before this commit. Persist the result
    /// in the same row as those transcripts and the keys. Rekeyed IKE epochs
    /// inherit the committed parameters through their atomic successor record.
    /// # Errors
    /// Refuses missing/malformed/foreign offers or an already active window.
    pub fn prepare_fragmentation(
        &mut self,
        profile: Profile,
        keys: &Keys,
        request: &[u8],
        response: &[u8],
        timeout_ms: NonZeroU32,
    ) -> Result<Ikev2PreparedWindow<'_, P>, Error> {
        use super::profile::DirectionBinding;
        self.ready()?;
        self.record.domain.check(profile, keys)?;
        if self.record.generation != 0
            || self.record.fragmentation.is_some()
            || self.record.outbound.is_some()
            || self.record.inbound.is_some()
            || self.receive.pending.borrow().is_some()
            || self.next_receive() != self.record.next_receive
        {
            return Err(Error::Drop);
        }
        let direction = &self.record.domain.send;
        let spis = (direction.initiator_spi(), direction.responder_spi());
        if !offered(request, spis, false)? || !offered(response, spis, true)? {
            return Err(Error::FragmentationNotNegotiated);
        }
        let mut record = self.next_record()?;
        record.fragmentation = Some(Ikev2FragmentationParameters { timeout_ms });
        Ok(self.prepared(record, None, false))
    }
}

/// An authenticated packet either awaits its siblings, completes a message, or
/// permits only retransmission of an already committed response.
pub enum Ikev2FragmentReceive<'a, P: RecoveryProfile = super::Ikev2GcmRecoveryProfile> {
    /// No payloads or effects are available until the whole message authenticates.
    Incomplete,
    /// Complete authenticated payloads; ordinary window/semantic admission still applies.
    Message(super::Ikev2AuthenticatedOrdinary<P>),
    /// RFC 7383 §2.6.1: only fragment 1 can trigger this borrowed cached reply.
    Retransmit(super::Ikev2ExactReplay<'a>),
}

struct Assembly {
    header: crate::Header,
    total: u16,
    deadline_ms: u64,
    frames: Vec<Option<super::packet::OpenedFrame>>,
    cleartext_len: usize,
    wire_len: usize,
}

#[derive(Default)]
pub(super) struct FragmentState {
    request: Option<Assembly>,
    response: Option<Assembly>,
    last_time_ms: Option<u64>,
    failed: bool,
}

impl FragmentState {
    pub(super) fn ready(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::FragmentationLimit)
        } else {
            Ok(())
        }
    }

    fn advance(&mut self, now_ms: u64) -> Result<(), Error> {
        self.ready()?;
        if self.last_time_ms.is_some_and(|previous| now_ms < previous) {
            return Err(Error::Drop);
        }
        self.last_time_ms = Some(now_ms);
        for queue in [&mut self.request, &mut self.response] {
            if queue.as_ref().is_some_and(|set| now_ms >= set.deadline_ms) {
                *queue = None;
            }
        }
        Ok(())
    }

    fn refuse_limit(&mut self) -> Error {
        self.failed = true;
        self.request = None;
        self.response = None;
        Error::FragmentationLimit
    }

    pub(super) fn cutover(&mut self) {
        self.request = None;
        self.response = None;
    }

    fn insert(
        &mut self,
        frame: super::packet::OpenedFrame,
        now_ms: u64,
        timeout_ms: NonZeroU32,
    ) -> Result<Option<Vec<super::packet::OpenedFrame>>, Error> {
        use super::{
            message::{MAX_CLEARTEXT, MAX_FRAGMENTS, MAX_WIRE},
            packet::same_message,
        };
        let (number, total) = frame.fragment.ok_or(Error::Drop)?;
        if usize::from(total) > MAX_FRAGMENTS || frame.cleartext.len() > MAX_CLEARTEXT {
            return Err(self.refuse_limit());
        }
        let queue = if frame.header.flags.response() {
            &mut self.response
        } else {
            &mut self.request
        };
        let old = queue
            .as_ref()
            .filter(|set| same_message(&set.header, &frame.header));
        if old.is_some_and(|set| total < set.total) {
            return Err(Error::Drop);
        }
        if old.is_none_or(|set| total > set.total) {
            // Refragmentation replaces the set but never renews this exchange's timeout.
            let deadline_ms = old
                .map(|set| set.deadline_ms)
                .or_else(|| now_ms.checked_add(u64::from(timeout_ms.get())))
                .ok_or(Error::FragmentationLimit)?;
            *queue = Some(Assembly {
                header: frame.header.clone(),
                total,
                deadline_ms,
                frames: (0..total).map(|_| None).collect(),
                cleartext_len: 0,
                wire_len: 0,
            });
        }
        let set = queue.as_mut().ok_or(Error::Drop)?;
        let slot = set
            .frames
            .get_mut(usize::from(number - 1))
            .ok_or(Error::Drop)?;
        if slot.is_some() {
            return Err(Error::Drop);
        }
        let cleartext_len = set.cleartext_len.checked_add(frame.cleartext.len());
        let wire_len = set.wire_len.checked_add(frame.wire.len());
        if cleartext_len.is_none_or(|size| size > MAX_CLEARTEXT)
            || wire_len.is_none_or(|size| size > MAX_WIRE)
        {
            return Err(self.refuse_limit());
        }
        set.cleartext_len = cleartext_len.ok_or(Error::FragmentationLimit)?;
        set.wire_len = wire_len.ok_or(Error::FragmentationLimit)?;
        *slot = Some(frame);
        if set.frames.iter().any(Option::is_none) {
            return Ok(None);
        }
        let set = queue.take().ok_or(Error::Drop)?;
        Ok(Some(
            set.frames
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::Drop)?,
        ))
    }
}

impl<P: RecoveryProfile> Window<P> {
    /// Authenticate and collect one peer SK/SKF packet under the current SA fence.
    ///
    /// Use this entry point for every ordinary packet on an RFC 7383 SA. Never
    /// act on partial plaintext. A complete message still needs ordinary window
    /// admission and semantic validation. Retain the returned replay borrow and
    /// external send fence through transmission of every response packet.
    ///
    /// `now_ms` is monotone within this runtime. Schedule `expire_fragments` at
    /// `fragment_deadline_ms` even without traffic. A terminal size/count error
    /// blocks the window: retire this IKE SA and its Children.
    /// # Errors
    /// Authentication/binding, replay, stale sets and wrong window IDs drop.
    /// Authenticated unnegotiated SKF reports `FragmentationNotNegotiated`.
    /// Exceeding a resource bound reports `FragmentationLimit` and latches closure.
    pub fn receive_peer_packet(
        &mut self,
        profile: Profile,
        keys: &Keys,
        wire: &[u8],
        now_ms: u64,
    ) -> Result<Ikev2FragmentReceive<'_, P>, Error> {
        use super::packet;
        self.fragments.advance(now_ms)?;
        let frame = packet::open_frame(&self.record.domain, profile, keys, wire, true)?;
        let Some((number, total)) = frame.fragment else {
            let queue = if frame.header.flags.response() {
                &mut self.fragments.response
            } else {
                &mut self.fragments.request
            };
            if queue
                .as_ref()
                .is_some_and(|set| packet::same_message(&set.header, &frame.header))
            {
                *queue = None;
            }
            return packet::finish(&self.record.domain, vec![frame])
                .map(Ikev2FragmentReceive::Message);
        };
        let parameters = self
            .record
            .fragmentation
            .ok_or(Error::FragmentationNotNegotiated)?;
        if !frame.header.flags.response() && frame.header.exchange_type == 37 {
            if let Some(cached) = self.receive.cached_empty_request(frame.header.message_id) {
                self.ready_for_cached_response()?;
                if number != 1
                    || total != 1
                    || frame.first != PayloadType::NoNext
                    || !frame.cleartext.is_empty()
                    || cached.single_packet() != Ok(wire)
                {
                    return Err(Error::Drop);
                }
                // Reuse the complete authenticated empty request, never partial new content.
                return packet::open_message(
                    &self.record.domain,
                    profile,
                    keys,
                    cached,
                    true,
                    true,
                )
                .map(Ikev2FragmentReceive::Message);
            }
        }
        if !frame.header.flags.response() && self.fragment_reply_applies(&frame.header)? {
            self.ready_for_cached_response()?;
            if number != 1 {
                return Err(Error::Drop);
            }
            let message = self
                .record
                .inbound
                .as_ref()
                .and_then(|entry| entry.response.as_ref())
                .ok_or(Error::InvalidRecord)?;
            return Ok(Ikev2FragmentReceive::Retransmit(super::Ikev2ExactReplay {
                message,
            }));
        }
        self.ready()?;
        if frame.header.flags.response() {
            if !self.fragment_response_expected(&frame.header)? {
                return Err(Error::Drop);
            }
        } else if !self.receive.accepts_new(frame.header.message_id)
            || self.receive.pending.borrow().is_some()
        {
            return Err(Error::Drop);
        }
        let assembled = self
            .fragments
            .insert(frame, now_ms, parameters.timeout_ms)
            .map_err(|error| {
                if error == Error::FragmentationLimit {
                    self.fragments.refuse_limit()
                } else {
                    error
                }
            })?;
        match assembled {
            None => Ok(Ikev2FragmentReceive::Incomplete),
            Some(frames) => {
                packet::finish(&self.record.domain, frames).map(Ikev2FragmentReceive::Message)
            }
        }
    }

    fn fragment_response_expected(&self, header: &crate::Header) -> Result<bool, Error> {
        if self.pending_empty_request_message_id() == Some(header.message_id) {
            return Ok(header.exchange_type == 37);
        }
        let Some(entry) = self
            .record
            .outbound
            .as_ref()
            .filter(|entry| entry.response.is_none())
        else {
            return Ok(false);
        };
        let (_, request) =
            crate::decode_header(&entry.request.packets()[0], DecodeContext::default())
                .map_err(|_| Error::InvalidRecord)?;
        Ok(
            header.message_id == request.message_id
                && header.exchange_type == request.exchange_type,
        )
    }

    fn fragment_reply_applies(&self, header: &crate::Header) -> Result<bool, Error> {
        if self.receive.next != header.message_id.checked_add(1)
            || self.receive.pending.borrow().is_some()
            || self.next_receive() != self.record.next_receive
        {
            return Ok(false);
        }
        let Some(entry) = &self.record.inbound else {
            return Ok(false);
        };
        let (_, request) =
            crate::decode_header(&entry.request.packets()[0], DecodeContext::default())
                .map_err(|_| Error::InvalidRecord)?;
        Ok(
            header.message_id == request.message_id
                && header.exchange_type == request.exchange_type,
        )
    }

    /// Earliest fixed deadline for either independent reassembly direction.
    pub fn fragment_deadline_ms(&self) -> Option<u64> {
        [
            self.fragments.request.as_ref(),
            self.fragments.response.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|set| set.deadline_ms)
        .min()
    }

    /// Discard incomplete messages at their deadlines, including while idle.
    /// # Errors
    /// Refuses a regressed clock or a window closed by a fragment resource limit.
    pub fn expire_fragments(&mut self, now_ms: u64) -> Result<(), Error> {
        self.fragments.advance(now_ms)
    }
}
