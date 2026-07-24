use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::queue::{QueueRx, QueueTx};
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::{Aad, Iv, Nonce};
use crate::dtls12::context::{AuthMode, CryptoContext};
use crate::dtls12::incoming::{Incoming, Record, RecordHandler};
use crate::dtls12::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake};
use crate::error::bounded_error_len;
use crate::timer::ExponentialBackoff;
use crate::window::ReplayWindow;
use crate::{Config, Error, InternalError, KeyingMaterial, Output, SeededRng};

const MAX_DEFRAGMENT_PACKETS: usize = 50;
const MAX_SEQUENCE_NUMBER: u64 = (1_u64 << 48) - 1;

struct Rfc6083OutputBarrier {
    preceding_datagrams: usize,
    material: Zeroizing<Vec<u8>>,
}

// Using debug_ignore_primary since CryptoContext doesn't implement Debug
pub struct Engine {
    config: Arc<Config>,

    /// Seedable random number generator for deterministic testing
    pub(crate) rng: SeededRng,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord during epoch 0.
    ///
    /// This is kept separate since resends might force us to
    /// "go back" to these sequence number even if we technically
    /// progressed to epoch 1.
    sequence_epoch_0: Sequence,

    /// Counters for epoch 1 and beyond.
    sequence_epoch_n: Sequence,

    /// Queue of incoming packets.
    queue_rx: QueueRx,

    /// Queue of outgoing packets.
    queue_tx: QueueTx,

    rfc6083_output_barrier: Option<Rfc6083OutputBarrier>,
    rfc6083_prepare_ccs_barrier: Option<usize>,
    rfc6083_prepare_epoch_barrier: Option<usize>,
    rfc6083_prepare_close_notify: Option<usize>,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<Dtls12CipherSuite>,

    /// Per-record explicit nonce length, cached from the provider suite at
    /// `set_cipher_suite` time. 0 for ChaCha20-Poly1305, 8 for AES-GCM.
    explicit_nonce_len: usize,

    /// Minimum length of a protected record's encrypted fragment, cached from
    /// the provider suite. See
    /// [`crate::crypto::SupportedDtls12CipherSuite::min_protected_fragment_len`].
    /// For AEAD suites this is `explicit_nonce + tag`; used both to reject
    /// short incoming records and to size outgoing record overhead.
    min_protected_fragment_len: usize,

    /// Successful protected-record encryptions under the current DTLS 1.2
    /// outbound write key. Finished, alert, and application records all
    /// consume this cryptographic budget.
    protected_send_count: u64,

    /// Cryptographic context for handling encryption/decryption
    pub(crate) crypto_context: CryptoContext,

    /// Whether the remote peer has enabled encryption
    peer_encryption_enabled: bool,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    ///
    /// NB: pub(crate) because we need to sign it in client.rs
    pub(crate) transcript: Buf,

    /// Anti-replay window state (per current epoch)
    replay: ReplayWindow,

    /// The records that have been sent in the current flight.
    flight_saved_records: Vec<Entry>,

    /// Flight backoff
    flight_backoff: ExponentialBackoff,

    /// Timeout for the current flight
    flight_timeout: Timeout,

    /// Global timeout for the entire connect operation.
    connect_timeout: Timeout,

    /// Whether we are ready to release application data from poll_output.
    release_app_data: bool,

    /// Whether we have confirmation that the peer completed the handshake, i.e.
    /// that the peer received our final flight. Once set, a stale plaintext
    /// handshake (which is unauthenticated and replayable after encryption is
    /// enabled) no longer triggers a courtesy flight retransmission.
    ///
    /// This is set from two signals, each meaningful for one role:
    /// - the client stops its resend timer when it completes, which means the
    ///   server received our final flight (the client confirms at completion);
    /// - receiving authenticated application data, which means the peer is past
    ///   its handshake (the server's only proof the client received flight 6).
    peer_handshake_confirmed: bool,

    /// Whether a close_notify alert has been received from the peer.
    close_notify_received: bool,

    /// Whether [`Output::CloseNotify`] has already been emitted.
    close_notify_reported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Timeout {
    Disabled,
    Unarmed,
    Armed(Instant),
}

#[derive(Debug)]
struct Entry {
    content_type: ContentType,
    epoch: u16,
    fragment: Buf,
}

enum PollOutput<'a> {
    Data(&'a [u8]),
    BufferTooSmall { needed: usize },
    None(&'a mut [u8]),
}

impl Engine {
    pub fn extract_rfc6083_keying_material(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let hash = self
            .cipher_suite()
            .ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?
            .hash_algorithm();
        let mut out = self.pop_buffer();
        let mut scratch = self.pop_buffer();
        let result = self
            .crypto_context()
            .extract_rfc6083_keying_material(hash, &mut out, &mut scratch)
            .map_err(Error::CryptoError);
        self.push_buffer(out);
        self.push_buffer(scratch);
        result
    }

    pub fn rfc6083_queued_datagrams(&self) -> usize {
        self.queue_tx.len()
    }

    pub fn arm_rfc6083_output_barrier(
        &mut self,
        preceding_datagrams: usize,
        material: Zeroizing<Vec<u8>>,
    ) -> Result<(), Error> {
        if self.rfc6083_output_barrier.is_some() {
            return Err(Error::HandshakePending);
        }
        self.rfc6083_output_barrier = Some(Rfc6083OutputBarrier {
            preceding_datagrams,
            material,
        });
        Ok(())
    }

    pub fn arm_rfc6083_prepare_epoch_barrier(
        &mut self,
        preceding_datagrams: usize,
    ) -> Result<(), Error> {
        if self.rfc6083_prepare_epoch_barrier.is_some() {
            return Err(Error::HandshakePending);
        }
        self.rfc6083_prepare_epoch_barrier = Some(preceding_datagrams);
        Ok(())
    }

    pub fn arm_rfc6083_prepare_ccs_barrier(
        &mut self,
        preceding_datagrams: usize,
    ) -> Result<(), Error> {
        if self.rfc6083_prepare_ccs_barrier.is_some() {
            return Err(Error::HandshakePending);
        }
        self.rfc6083_prepare_ccs_barrier = Some(preceding_datagrams);
        Ok(())
    }

    pub fn new(config: Arc<Config>, auth: AuthMode) -> Self {
        let mut rng = SeededRng::new(config.rng_seed());

        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries(), &mut rng);

        let crypto_context = CryptoContext::new(auth, Arc::clone(&config));

        Self {
            config,
            rng,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: QueueRx::new(),
            queue_tx: QueueTx::new(),
            rfc6083_output_barrier: None,
            rfc6083_prepare_ccs_barrier: None,
            rfc6083_prepare_epoch_barrier: None,
            rfc6083_prepare_close_notify: None,
            cipher_suite: None,
            explicit_nonce_len: 0,
            min_protected_fragment_len: 0,
            protected_send_count: 0,
            crypto_context,
            peer_encryption_enabled: false,
            is_client: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            flight_saved_records: Vec::new(),
            flight_backoff,
            flight_timeout: Timeout::Unarmed,
            connect_timeout: Timeout::Unarmed,
            release_app_data: false,
            peer_handshake_confirmed: false,
            close_notify_received: false,
            close_notify_reported: false,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    /// Set the next outgoing handshake message sequence number.
    ///
    /// Used by `Client::new_from_hybrid` to account for the hybrid
    /// ClientHello (message_seq=0) that was already sent outside this engine.
    pub fn set_next_handshake_seq_no(&mut self, seq: u16) {
        self.next_handshake_seq_no = seq;
    }

    /// Advance the epoch-0 record sequence number by one.
    ///
    /// Used by `Client::new_from_hybrid` so subsequent epoch-0 records
    /// don't reuse the sequence number of the hybrid ClientHello record.
    pub fn advance_epoch_0_sequence(&mut self) {
        self.sequence_epoch_0.sequence_number += 1;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<Dtls12CipherSuite> {
        self.cipher_suite
    }

    /// Minimum length of a protected record's encrypted fragment for the
    /// negotiated suite. See
    /// [`crate::crypto::SupportedDtls12CipherSuite::min_protected_fragment_len`].
    pub fn min_protected_fragment_len(&self) -> usize {
        self.min_protected_fragment_len
    }

    /// Is the given cipher suite allowed by configuration
    pub fn is_cipher_suite_allowed(&self, suite: Dtls12CipherSuite) -> bool {
        self.config
            .dtls12_cipher_suites()
            .any(|cs| cs.suite() == suite)
    }

    /// Get a reference to the crypto context
    pub fn crypto_context(&self) -> &CryptoContext {
        &self.crypto_context
    }

    /// Get a mutable reference to the crypto context
    pub fn crypto_context_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto_context
    }

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), InternalError> {
        let cs = self.cipher_suite;
        let incoming = Incoming::parse_packet(packet, self, cs)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    /// Insert a parsed datagram into the receive queue.
    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        // Capacity guard before iterating records.
        if self.queue_rx.len() >= self.config.max_queue_rx() {
            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        // Dispatch to specialized handlers
        if incoming.first().first_handshake().is_some() {
            self.insert_incoming_handshake(incoming)
        } else {
            self.insert_incoming_non_handshake(incoming)
        }
    }

    fn insert_incoming_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first_record = incoming.first();
        let Some(handshake) = first_record.first_handshake() else {
            return Err(Error::InvalidState(
                crate::InvalidStateError::ExpectedHandshakeRecord,
            ));
        };

        let key_current = (
            handshake.header.message_seq,
            handshake.header.fragment_offset,
        );

        let maybe_dupe_seq = incoming
            .records()
            .iter()
            .filter_map(|r| r.first_handshake())
            .filter_map(|h| h.dupe_triggers_resend())
            .next();

        // Some MessageType when resent, means we must trigger
        // an immediate resend of the entire flight. Once the peer is confirmed
        // to have completed the handshake, a stale plaintext handshake is just
        // unauthenticated noise (or a replay/amplification attempt) and must not
        // drive a resend.
        if let Some(dupe_seq) = maybe_dupe_seq {
            if dupe_seq < self.peer_handshake_seq_no && !self.peer_handshake_confirmed {
                self.flight_resend("dupe triggers resend")?;
            }
        }

        // Drop old duplicates we've already processed - don't let them block newer messages.
        if handshake.header.message_seq < self.peer_handshake_seq_no {
            return Ok(());
        }

        if self.peer_encryption_enabled && first_record.record().sequence.epoch == 0 {
            // Keep old plaintext handshake records available long enough to
            // trigger flight resends above, but never queue or process them as
            // new messages after peer encryption is enabled.
            return Ok(());
        }

        // Reject new handshakes after initial handshake is complete (renegotiation not supported).
        if self.release_app_data && handshake.header.message_seq >= self.peer_handshake_seq_no {
            return Err(Error::RenegotiationAttempt);
        }

        let search_result = self.queue_rx.binary_search_by(|item| {
            let key_other = item
                .first()
                .first_handshake()
                .as_ref()
                .map(|h| (h.header.message_seq, h.header.fragment_offset))
                .unwrap_or((u16::MAX, u32::MAX));
            key_other.cmp(&key_current)
        });

        match search_result {
            Err(index) => {
                // Insert in order of handshake key
                self.queue_rx.insert(index, incoming);
            }
            Ok(_) => {
                // Exact duplicate handshake fragment
            }
        }

        Ok(())
    }

    fn insert_incoming_non_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first = incoming.first();
        let seq_current = first.record().sequence;

        if self.peer_encryption_enabled
            && seq_current.epoch == 0
            && first.record().content_type == ContentType::Handshake
        {
            return Ok(());
        }

        if self.peer_encryption_enabled {
            for record in incoming.records().iter() {
                if record.record().sequence.epoch == 0
                    && record.record().content_type == ContentType::Handshake
                {
                    if record.handshakes().is_empty() {
                        record.set_handled();
                    } else {
                        for handshake in record.handshakes() {
                            handshake.set_handled();
                        }
                    }
                }
            }
        }

        let search_result = self
            .queue_rx
            .binary_search_by_key(&seq_current, |item| item.first().record().sequence);

        if let Err(index) = search_result {
            self.queue_rx.insert(index, incoming);
        } else {
            // A reliable SCTP association suppresses transport duplicates,
            // but malformed peers and test transports must not turn disabled
            // DTLS replay detection into a process panic.
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.connect_timeout == Timeout::Unarmed {
            debug!(
                "Connect timeout in: {:.03}s",
                self.config.handshake_timeout().as_secs_f32()
            );
            let timeout = now + self.config.handshake_timeout();
            self.connect_timeout = Timeout::Armed(timeout);
        }
        if self.config.rfc6083_sctp() {
            self.flight_timeout = Timeout::Disabled;
        } else if self.flight_timeout == Timeout::Unarmed {
            debug!(
                "Flight timeout in: {:.03}s",
                self.flight_backoff.rto().as_secs_f32()
            );
            let timeout = now + self.flight_backoff.rto();
            self.flight_timeout = Timeout::Armed(timeout);
        }

        // The connect timeout is the overall timeout for establishing the connection
        if let Timeout::Armed(connect_timeout) = self.connect_timeout {
            if now >= connect_timeout {
                return Err(Error::Timeout(crate::TimeoutError::Connect));
            }
        }

        // If there is no flight timeout, we have already checked the global connect timeout.
        let Timeout::Armed(flight_timeout) = self.flight_timeout else {
            return Ok(());
        };

        if now >= flight_timeout {
            if self.flight_backoff.can_retry() {
                self.flight_backoff.attempt(&mut self.rng);
                debug!(
                    "Re-arm flight timeout due to resend in {}",
                    self.flight_backoff.rto().as_secs_f32()
                );
                let timeout = now + self.flight_backoff.rto();
                self.flight_timeout = Timeout::Armed(timeout);
                self.flight_resend("flight timeout")?;
            } else {
                return Err(Error::Timeout(crate::TimeoutError::Handshake));
            }
        }

        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Output<'a> {
        // Drain incoming queue of processed records.
        self.purge_handled_queue_rx();

        let buf = match self.poll_app_data(buf) {
            PollOutput::Data(p) => return Output::ApplicationData(p),
            PollOutput::BufferTooSmall { needed } => return Output::BufferTooSmall { needed },
            PollOutput::None(b) => b,
        };

        if self
            .rfc6083_output_barrier
            .as_ref()
            .is_some_and(|barrier| barrier.preceding_datagrams == 0)
        {
            if let Some(barrier) = self.rfc6083_output_barrier.take() {
                return Output::Rfc6083KeyingMaterial(KeyingMaterial::from_zeroizing(
                    barrier.material,
                ));
            }
        }
        if self.rfc6083_prepare_ccs_barrier == Some(0) {
            self.rfc6083_prepare_ccs_barrier = None;
            return Output::Rfc6083PrepareChangeCipherSpec;
        }
        if self.rfc6083_prepare_epoch_barrier == Some(0) {
            self.rfc6083_prepare_epoch_barrier = None;
            return Output::Rfc6083PrepareEpoch;
        }
        if self.rfc6083_prepare_close_notify == Some(0) {
            self.rfc6083_prepare_close_notify = None;
            return Output::Rfc6083PrepareCloseNotify;
        }

        match self.poll_packet_tx(buf) {
            PollOutput::Data(p) => return Output::Packet(p),
            PollOutput::BufferTooSmall { needed } => return Output::BufferTooSmall { needed },
            PollOutput::None(_) => {}
        }

        if self.close_notify_received && !self.close_notify_reported {
            self.close_notify_reported = true;
            return Output::CloseNotify;
        }

        let next_timeout = self.poll_timeout(now);

        Output::Timeout(next_timeout)
    }

    fn poll_app_data<'a>(&mut self, buf: &'a mut [u8]) -> PollOutput<'a> {
        if !self.release_app_data {
            return PollOutput::None(buf);
        }

        let mut unhandled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .filter(|r| r.record().content_type == ContentType::ApplicationData)
            .skip_while(|r| r.is_handled());

        let Some(next) = unhandled.next() else {
            return PollOutput::None(buf);
        };

        let record_buffer = next.buffer();
        let fragment = next.record().fragment(record_buffer);
        let len = fragment.len();

        if len > buf.len() {
            return PollOutput::BufferTooSmall { needed: len };
        }

        buf[..len].copy_from_slice(fragment);
        next.set_handled();

        PollOutput::Data(&buf[..len])
    }

    fn purge_handled_queue_rx(&mut self) {
        while let Some(peek) = self.queue_rx.front() {
            let fully_handled = peek.records().iter().all(|r| r.is_handled());

            if fully_handled {
                if let Some(incoming) = self.queue_rx.pop_front() {
                    incoming
                        .into_records()
                        .for_each(|r| self.buffers_free.push(r.into_buffer()));
                }
            } else {
                break;
            }
        }
    }

    fn poll_packet_tx<'a>(&mut self, buf: &'a mut [u8]) -> PollOutput<'a> {
        let Some(p) = self.queue_tx.front() else {
            return PollOutput::None(buf);
        };

        if p.len() > buf.len() {
            return PollOutput::BufferTooSmall { needed: p.len() };
        }

        let Some(p) = self.queue_tx.pop_front() else {
            return PollOutput::None(buf);
        };
        let len = p.len();
        buf[..len].copy_from_slice(&p);
        if let Some(barrier) = self.rfc6083_output_barrier.as_mut() {
            barrier.preceding_datagrams = barrier.preceding_datagrams.saturating_sub(1);
        }
        if let Some(preceding_datagrams) = self.rfc6083_prepare_epoch_barrier.as_mut() {
            *preceding_datagrams = preceding_datagrams.saturating_sub(1);
        }
        if let Some(preceding_datagrams) = self.rfc6083_prepare_ccs_barrier.as_mut() {
            *preceding_datagrams = preceding_datagrams.saturating_sub(1);
        }
        if let Some(preceding_datagrams) = self.rfc6083_prepare_close_notify.as_mut() {
            *preceding_datagrams = preceding_datagrams.saturating_sub(1);
        }

        PollOutput::Data(&buf[..len])
    }

    fn poll_timeout(&self, now: Instant) -> Instant {
        // No timeouts, return a distant future
        if self.connect_timeout == Timeout::Disabled && self.flight_timeout == Timeout::Disabled {
            const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            return now + DISTANT_FUTURE;
        }

        match (self.connect_timeout, self.flight_timeout) {
            (Timeout::Armed(c), Timeout::Armed(f)) => {
                if c < f {
                    c
                } else {
                    f
                }
            }
            (Timeout::Armed(c), _) => c,
            (_, Timeout::Armed(f)) => f,
            // Both Unarmed or mixed Unarmed/Disabled: return current time
            // to trigger handle_timeout on the next cycle.
            _ => now,
        }
    }

    pub fn flight_begin(&mut self, flight_no: u8) {
        debug!("Begin flight {}", flight_no);
        self.flight_backoff.reset(&mut self.rng);
        self.flight_clear_resends();
        self.flight_timeout = if self.config.rfc6083_sctp() {
            Timeout::Disabled
        } else {
            Timeout::Unarmed
        };
    }

    pub fn flight_stop_resend_timers(&mut self) {
        debug!("Stop connect and flight timeouts");
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;

        // The client stops its resend timer only once it has received the
        // server's final flight, which proves the server received the client's
        // final flight — so the peer is confirmed. The server, by contrast,
        // stops its timer right after sending flight 6, before the client has
        // confirmed anything, so it must NOT confirm here (it relies on later
        // authenticated application data instead).
        if self.is_client {
            self.peer_handshake_confirmed = true;
        }
    }

    fn flight_clear_resends(&mut self) {
        for entry in self.flight_saved_records.drain(..) {
            self.buffers_free.push(entry.fragment);
        }
    }

    fn flight_resend(&mut self, reason: &str) -> Result<(), Error> {
        if self.config.rfc6083_sctp() {
            debug!("Suppressing DTLS retransmission over RFC 6083 SCTP");
            return Ok(());
        }
        debug!("Resending flight due to {}", reason);

        let replace_pending_handshake_output = !self.release_app_data;
        let protected_records = self
            .flight_saved_records
            .iter()
            .filter(|entry| entry.epoch >= 1)
            .count();
        self.ensure_protected_send_budget(protected_records)?;

        if replace_pending_handshake_output {
            self.queue_tx.clear();
        }

        // For lifetime issues, we take the entries out of self
        let records = mem::take(&mut self.flight_saved_records);

        let mut result = Ok(());
        for (index, entry) in records.iter().enumerate() {
            result = self.create_record_inner(
                entry.content_type,
                entry.epoch,
                false,
                replace_pending_handshake_output && index == 0,
                |fragment| {
                    fragment.extend_from_slice(&entry.fragment);
                },
            );
            if result.is_err() {
                break;
            }
        }

        // Put the entries back into self
        self.flight_saved_records = records;

        result
    }

    pub fn has_complete_handshake(&mut self, wanted: MessageType) -> bool {
        self.has_complete_handshake_with_seq(wanted, self.peer_handshake_seq_no)
    }

    fn has_complete_handshake_with_seq(&mut self, wanted: MessageType, expected_seq: u16) -> bool {
        let mut skip_handled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
            .take(MAX_DEFRAGMENT_PACKETS)
            .flat_map(|r| r.handshakes().iter())
            .skip_while(|h| h.is_handled())
            .peekable();

        let maybe_first_handshake = skip_handled.peek();

        let Some(first) = maybe_first_handshake else {
            return false;
        };

        if first.header.message_seq != expected_seq {
            return false;
        }

        if first.header.msg_type != wanted {
            return false;
        }

        let wanted_seq = first.header.message_seq;
        let wanted_length = first.header.length;
        let mut last_fragment_end = 0;

        for h in skip_handled {
            // A different seq means we're looking at a different handshake
            if wanted_seq != h.header.message_seq {
                continue;
            }

            // Check fragment contiguity
            if h.header.fragment_offset != last_fragment_end {
                return false;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            // Found the last fragment to complete the wanted handshake.
            if last_fragment_end == wanted_length {
                return true;
            }
        }

        false
    }

    pub fn next_handshake(
        &mut self,
        wanted: MessageType,
        defragment_buffer: &mut Buf,
    ) -> Result<Option<Handshake>, InternalError> {
        if !self.has_complete_handshake(wanted) {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .flat_map(|r| r.handshakes().iter().map(move |h| (h, r.buffer())))
            .skip_while(|(h, _)| h.is_handled());

        // This sets the handled flag on the handshake.
        // Passing Some(&mut self.transcript) to have defragment write to transcript
        // before creating the handshake, avoiding borrow conflicts.
        let handshake = Handshake::defragment(
            iter,
            defragment_buffer,
            self.cipher_suite,
            Some(&mut self.transcript),
        )?;

        // Move the expected seq_no along
        self.peer_handshake_seq_no = handshake.header.message_seq + 1;

        Ok(Some(handshake))
    }

    pub(crate) fn next_record(&mut self, ctype: ContentType) -> Option<&Record> {
        let record = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .find(|r| !r.is_handled())?;

        if record.record().content_type != ctype {
            return None;
        }

        record.set_handled();

        Some(record)
    }

    /// Mark any pending ChangeCipherSpec records as handled and purge them.
    /// We can accumulate multiple ChangeCipherSpec due to resends. Since they
    /// don't have any Handshake message_seq and each resend gives a new DTLSRecord
    /// sequence number, we might have multiple.
    pub fn drop_pending_ccs(&mut self) {
        for incoming in self.queue_rx.iter() {
            for record in incoming.records().iter() {
                if record.record().content_type == ContentType::ChangeCipherSpec {
                    record.set_handled();
                }
            }
        }
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        self.create_record_inner(content_type, epoch, save_fragment, false, f)
    }

    /// Create a DTLS record in a new datagram even when the current datagram
    /// has room.
    ///
    /// RFC 6083 uses this at the epoch boundary: the preceding handshake
    /// datagrams must leave under the old SCTP-AUTH key, then sender-dry must
    /// complete before ChangeCipherSpec leaves under the old key. A second
    /// sender-dry barrier then activates the new key before Finished leaves.
    pub(crate) fn create_record_in_new_datagram<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        self.create_record_inner(content_type, epoch, save_fragment, true, f)
    }

    fn create_record_inner<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        force_new_datagram: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        if epoch >= 1 {
            self.ensure_protected_send_budget(1)?;
        }

        let sequence = if epoch == 0 {
            self.sequence_epoch_0
        } else {
            self.sequence_epoch_n
        };
        if sequence.sequence_number > MAX_SEQUENCE_NUMBER {
            let error = if epoch == 0 {
                crate::CryptoError::Epoch0SequenceNumberExhausted
            } else {
                crate::CryptoError::SendSequenceNumberExhausted { epoch }
            };
            return Err(Error::CryptoError(error));
        }

        let maybe_suite = if epoch >= 1 {
            Some(self.cipher_suite().ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?)
        } else {
            None
        };

        // Prepare the plaintext fragment
        let mut fragment = self.buffers_free.pop();

        // Let the caller fill the fragment (plaintext)
        f(&mut fragment);

        // Compute wire length of the record if serialized into a datagram.
        // Record header (13) + handshake/change/app data bytes + per-suite
        // protection overhead (if epoch >= 1). For AEAD suites the protection
        // overhead equals the min-protected-fragment-len.
        let overhead = if maybe_suite.is_some() {
            self.min_protected_fragment_len()
        } else {
            0
        };
        let record_wire_len = DTLSRecord::HEADER_LEN + fragment.len() + overhead;
        if self.config.rfc6083_sctp() && record_wire_len > self.config.mtu() {
            return Err(Error::RecordExceedsPathMtu {
                record_bytes: record_wire_len,
                path_mtu: self.config.mtu(),
            });
        }

        // Preserve a plaintext copy for retransmission, but do not publish it
        // into engine state until all fallible record construction has
        // completed.
        let saved_fragment = if save_fragment {
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);
            Some(Entry {
                content_type,
                epoch,
                fragment: clone,
            })
        } else {
            None
        };

        // Decide whether to append to the existing last datagram or create a new one
        let can_append = self
            .queue_tx
            .back()
            .map(|b| {
                !self.config.rfc6083_sctp()
                    && !force_new_datagram
                    && b.len() + record_wire_len <= self.config.mtu()
            })
            .unwrap_or(false);

        // If we cannot append, ensure we have space for a new datagram
        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            warn!(
                "Transmit queue full (max {}): {:?}",
                self.config.max_queue_tx(),
                self.queue_tx
            );
            return Err(Error::TransmitQueueFull);
        }

        let length = fragment.len() as u16;

        // Handle encryption for epochs >= 1
        if epoch >= 1 {
            let suite = maybe_suite.ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?;

            // Get the fixed part of the IV
            let iv = if self.is_client {
                self.crypto_context.get_client_write_iv()
            } else {
                self.crypto_context.get_server_write_iv()
            };

            let Some(iv) = iv else {
                return Err(Error::CryptoError(
                    crate::CryptoError::WriteIvNotAvailable {
                        is_client: self.is_client,
                    },
                ));
            };

            let explicit_nonce_len = self.explicit_nonce_len;
            let mut explicit_nonce = [0u8; DTLSRecord::EXPLICIT_NONCE_LEN];
            let seq64 = ((sequence.epoch as u64) << 48) | sequence.sequence_number;
            let nonce = match explicit_nonce_len {
                0 => Nonce::xor(iv.as_12_bytes()?, seq64),
                DTLSRecord::EXPLICIT_NONCE_LEN => {
                    explicit_nonce.copy_from_slice(&seq64.to_be_bytes());
                    Nonce::new(iv, &explicit_nonce)?
                }
                _ => {
                    return Err(Error::CryptoError(
                        crate::CryptoError::UnsupportedDtls12RecordIvLen {
                            len: bounded_error_len(explicit_nonce_len),
                            suite,
                        },
                    ));
                }
            };

            // DTLS 1.2 AEAD: AAD uses the plaintext length (DTLSCompressed.length).
            let aad = Aad::new_dtls12(content_type, sequence, length);

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, aad, nonce)?;
            let ctext_len = fragment.len();

            // For suites with a per-record nonce (e.g. AES-GCM), prefix it on the wire.
            if explicit_nonce_len > 0 {
                fragment.resize(explicit_nonce_len + ctext_len, 0);
                fragment.copy_within(0..ctext_len, explicit_nonce_len);
                fragment[..explicit_nonce_len]
                    .copy_from_slice(&explicit_nonce[..explicit_nonce_len]);
            }
        }

        if let Some(saved_fragment) = saved_fragment {
            self.flight_saved_records.push(saved_fragment);
        }

        // Build the record structure referencing the (possibly encrypted) fragment
        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_2,
            sequence,
            length: fragment.len() as u16,
            fragment_range: 0..fragment.len(),
        };

        // Increment the sequence number for the next transmission
        if epoch == 0 {
            self.sequence_epoch_0.sequence_number += 1;
        } else {
            self.sequence_epoch_n.sequence_number += 1;
        }

        // Serialize the record into the chosen datagram buffer
        if can_append {
            let Some(last) = self.queue_tx.back_mut() else {
                return Err(Error::InvalidState(
                    crate::InvalidStateError::OutgoingQueueMissing,
                ));
            };
            record.serialize(&fragment, last);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&fragment, &mut buffer);
            self.queue_tx.push_back(buffer);
        }

        if epoch >= 1 {
            self.protected_send_count += 1;
        }

        // Return the fragment buffer to the pool
        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf, &mut Self) -> Result<(), Error>,
    {
        let epoch = msg_type.epoch();
        let sequence = if epoch == 0 {
            self.sequence_epoch_0
        } else {
            self.sequence_epoch_n
        };
        if sequence.sequence_number > MAX_SEQUENCE_NUMBER {
            let error = if epoch == 0 {
                crate::CryptoError::Epoch0SequenceNumberExhausted
            } else {
                crate::CryptoError::SendSequenceNumberExhausted { epoch }
            };
            return Err(Error::CryptoError(error));
        }

        // Get a buffer for the handshake body
        let mut body_buffer = self.buffers_free.pop();

        // Let the callback fill the handshake body
        f(&mut body_buffer, self)?;

        let (required_records, new_datagrams) =
            self.required_handshake_records(body_buffer.len(), epoch)?;
        if epoch >= 1 {
            self.ensure_protected_send_budget(required_records)?;
        }
        let final_sequence = sequence
            .sequence_number
            .checked_add(required_records.saturating_sub(1) as u64)
            .ok_or({
                Error::CryptoError(if epoch == 0 {
                    crate::CryptoError::Epoch0SequenceNumberExhausted
                } else {
                    crate::CryptoError::SendSequenceNumberExhausted { epoch }
                })
            })?;
        if final_sequence > MAX_SEQUENCE_NUMBER {
            return Err(Error::CryptoError(if epoch == 0 {
                crate::CryptoError::Epoch0SequenceNumberExhausted
            } else {
                crate::CryptoError::SendSequenceNumberExhausted { epoch }
            }));
        }

        if self.queue_tx.len().saturating_add(new_datagrams) > self.config.max_queue_tx() {
            return Err(Error::TransmitQueueFull);
        }

        // Create the handshake header with the next sequence number
        let handshake_header = Header {
            msg_type,
            length: body_buffer.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body_buffer.len() as u32,
        };

        let mut buffer_full = self.buffers_free.pop();
        {
            let handshake = Handshake {
                header: handshake_header,
                body: Body::Fragment(0..body_buffer.len()),
                handled: AtomicBool::new(false),
            };
            // Serialize with body_buffer as source
            handshake.serialize(&body_buffer, &mut buffer_full);
        }
        self.transcript.extend_from_slice(&buffer_full);
        self.buffers_free.push(buffer_full);

        // Increment the sequence number for the next handshake message
        self.next_handshake_seq_no += 1;

        // We want to pack as much as possible into the outgoing datagram and
        // remain within the MTU. Fragment the handshake across records as needed.

        let total_len = body_buffer.len();
        let mut offset: usize = 0;

        // Handshake header is 12 bytes
        let handshake_header_len = 12usize;
        // Per-record protection overhead on the wire (for AEAD suites this is
        // explicit_nonce + tag). Used to size fragments to fit the MTU.
        let protection_overhead = if epoch >= 1 {
            self.cipher_suite().ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?;
            self.min_protected_fragment_len()
        } else {
            0
        };

        // At least one record must be created even if total_len == 0
        while offset < total_len || (total_len == 0 && offset == 0) {
            // How many bytes are already used in the current datagram (if any)?
            let already_used_in_current = if self.config.rfc6083_sctp() {
                0
            } else {
                self.queue_tx.back().map(|b| b.len()).unwrap_or(0)
            };
            let available_in_current = self.config.mtu().saturating_sub(already_used_in_current);

            // Fixed overhead per handshake record on the wire:
            // DTLS record header + handshake header + protection overhead (if epoch >= 1)
            let fixed_overhead =
                DTLSRecord::HEADER_LEN + handshake_header_len + protection_overhead;

            // Prefer to pack into the current datagram. If the current one cannot fit even
            // the fixed overhead, we will start a fresh datagram and compute space again.
            let available_for_body = if available_in_current > fixed_overhead {
                // There is room for at least 1 byte of handshake body in the current datagram
                available_in_current - fixed_overhead
            } else {
                // Not enough space in the current datagram for any body bytes; start a fresh datagram
                self.config.mtu().saturating_sub(fixed_overhead)
            };

            // Remaining bytes from the handshake body we still need to send.
            let remaining_body_bytes = total_len.saturating_sub(offset);

            // For empty-body handshakes (e.g., ServerHelloDone), we still send a header-only record.
            let chunk_len = if total_len == 0 {
                0
            } else {
                remaining_body_bytes.min(available_for_body)
            };

            let frag_range = if chunk_len == 0 {
                0..0
            } else {
                offset..offset + chunk_len
            };

            let frag_handshake = Handshake {
                header: Header {
                    msg_type,
                    length: handshake_header.length,
                    message_seq: handshake_header.message_seq,
                    fragment_offset: offset as u32,
                    fragment_length: chunk_len as u32,
                },
                body: Body::Fragment(frag_range),
                handled: AtomicBool::new(false),
            };

            // RFC 6083 needs an output barrier immediately before Finished so
            // SCTP-AUTH can switch keys without affecting earlier records.
            let force_new_datagram =
                self.config.rfc6083_sctp() && msg_type == MessageType::Finished && offset == 0;
            self.create_record_inner(
                ContentType::Handshake,
                epoch,
                true,
                force_new_datagram,
                |fragment| {
                    frag_handshake.serialize(&body_buffer, fragment);
                },
            )?;

            if total_len == 0 {
                // Nothing more to send for empty-body handshake
                break;
            }

            offset += chunk_len;
        }

        // Return the buffer
        self.buffers_free.push(body_buffer);

        Ok(())
    }

    fn ensure_protected_send_budget(&self, additional: usize) -> Result<(), Error> {
        let additional = u64::try_from(additional).map_err(|_| {
            Error::CryptoError(crate::CryptoError::AeadEncryptionLimitReached {
                limit: self.config.aead_encryption_limit(),
            })
        })?;
        let within_budget = self
            .protected_send_count
            .checked_add(additional)
            .is_some_and(|count| count <= self.config.aead_encryption_limit());
        if !within_budget {
            return Err(Error::CryptoError(
                crate::CryptoError::AeadEncryptionLimitReached {
                    limit: self.config.aead_encryption_limit(),
                },
            ));
        }
        Ok(())
    }

    fn required_handshake_records(
        &self,
        body_len: usize,
        epoch: u16,
    ) -> Result<(usize, usize), Error> {
        let protection_overhead = if epoch >= 1 {
            self.cipher_suite().ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?;
            self.min_protected_fragment_len()
        } else {
            0
        };
        let fixed_overhead = DTLSRecord::HEADER_LEN + 12 + protection_overhead;
        let fresh_capacity = self.config.mtu().saturating_sub(fixed_overhead);
        if body_len > 0 && fresh_capacity == 0 {
            return Err(Error::RecordExceedsPathMtu {
                record_bytes: fixed_overhead.saturating_add(1),
                path_mtu: self.config.mtu(),
            });
        }
        if body_len == 0 {
            let appends = !self.config.rfc6083_sctp()
                && self
                    .queue_tx
                    .back()
                    .is_some_and(|buffer| buffer.len() + fixed_overhead <= self.config.mtu());
            return Ok((1, usize::from(!appends)));
        }

        let available = self
            .config
            .mtu()
            .saturating_sub(self.queue_tx.back().map(|buffer| buffer.len()).unwrap_or(0));
        let first_appends = !self.config.rfc6083_sctp()
            && self.queue_tx.back().is_some()
            && available > fixed_overhead;
        let first_capacity = if first_appends {
            available - fixed_overhead
        } else {
            fresh_capacity
        };
        let after_first = body_len.saturating_sub(first_capacity);
        let records = 1 + after_first.div_ceil(fresh_capacity);
        Ok((records, records - usize::from(first_appends)))
    }

    /// Release application data from the incoming queue
    pub fn release_application_data(&mut self) {
        self.release_app_data = true;
    }

    /// Whether a close_notify alert has been received from the peer.
    pub fn close_notify_received(&self) -> bool {
        self.close_notify_received
    }

    /// Whether a received close_notify still needs to be surfaced.
    pub fn close_notify_pending(&self) -> bool {
        self.close_notify_received && !self.close_notify_reported
    }

    /// Arm the RFC 6083 sender-dry barrier that must precede a reciprocal
    /// close_notify alert.
    pub fn arm_rfc6083_prepare_close_notify(&mut self, preceding_datagrams: usize) {
        if self.config.rfc6083_sctp() {
            self.rfc6083_prepare_close_notify = Some(preceding_datagrams);
        }
    }

    /// Whether close-related output remains to be polled.
    pub fn has_pending_close_output(&self) -> bool {
        !self.queue_tx.is_empty()
            || self.rfc6083_prepare_close_notify.is_some()
            || self.close_notify_pending()
    }

    /// Discard all pending outgoing data.
    ///
    /// RFC 5246 §7.2.1: on receiving close_notify, discard any pending writes.
    pub fn discard_pending_writes(&mut self) {
        self.queue_tx.clear();
    }

    /// Abort the connection: flush all queued output, retransmission state, and
    /// disable timers so that no further packets are emitted.
    pub fn abort(&mut self) {
        self.queue_tx.clear();
        self.flight_saved_records.clear();
        self.rfc6083_prepare_close_notify = None;
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;
    }

    /// Pop a buffer from the buffer pool for temporary use
    pub(crate) fn pop_buffer(&mut self) -> Buf {
        self.buffers_free.pop()
    }

    /// Return a buffer to the buffer pool
    pub(crate) fn push_buffer(&mut self, buf: Buf) {
        self.buffers_free.push(buf);
    }

    /// Encrypt data appropriate for the role (client or server)
    fn encrypt_data(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .encrypt_client_to_server(plaintext, aad, nonce)
                .map_err(Error::CryptoError)
        } else {
            self.crypto_context
                .encrypt_server_to_client(plaintext, aad, nonce)
                .map_err(Error::CryptoError)
        }
    }

    /// Decrypt data appropriate for the role (client or server)
    pub fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .decrypt_server_to_client(ciphertext, aad, nonce)
                .map_err(Error::CryptoError)
        } else {
            self.crypto_context
                .decrypt_client_to_server(ciphertext, aad, nonce)
                .map_err(Error::CryptoError)
        }
    }

    /// Reset server handshake state after sending HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the HelloVerifyRequest exchange is stateless. After sending
    /// HVR, the server expects a fresh ClientHello containing the cookie with message_seq=1.
    ///
    /// The message flow per RFC 6347 §4.2.2:
    ///   ClientHello (seq=0)  ------>
    ///                    <------  HelloVerifyRequest (seq=0)
    ///   ClientHello (seq=1)  ------>  (with cookie)
    ///                    <------  ServerHello (seq=1)
    pub fn reset_server_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Per RFC 6347 §4.2.2, the next ClientHello (with cookie) has message_seq=1.
        // We keep peer_handshake_seq_no at 1 (already incremented after first ClientHello).
        // Clear queued incoming handshakes so the next ClientHello (with cookie)
        // isn't rejected as a duplicate of the first ClientHello (without cookie).
        self.queue_rx.clear();
        // Note: Don't clear flight_saved_records here - the HelloVerifyRequest should
        // still be resendable via timeout until we receive the valid ClientHello with cookie.
        // The flight_begin(4) call when processing the cookie-bearing ClientHello will
        // clear the old records.
    }

    /// Reset client handshake state after receiving HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the client sends the next ClientHello (with cookie) using
    /// message_seq=1. The transcript is cleared because the initial ClientHello and
    /// HelloVerifyRequest are not part of the handshake transcript per RFC 6347 §4.2.1.
    ///
    /// Note: next_handshake_seq_no is already 1 after sending the first ClientHello,
    /// so we don't reset it - the next ClientHello will correctly have message_seq=1.
    pub fn reset_client_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Note: next_handshake_seq_no stays at 1 - the next ClientHello (with cookie)
        // will have message_seq=1 per RFC 6347 §4.2.2.
        // Note: peer_handshake_seq_no stays at 1 - the next message from server
        // (ServerHello) will have message_seq=1 per RFC 6347 §4.2.2.
    }

    pub fn transcript_hash(&self, algorithm: HashAlgorithm, out: &mut Buf) {
        let mut hash = self.crypto_context.create_hash(algorithm);
        hash.update(&self.transcript);
        hash.clone_and_finalize(out);
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: Dtls12CipherSuite) -> Result<(), Error> {
        // Cache AEAD record parameters from the provider suite. The formula
        // (explicit_nonce + tag) lives on the suite trait; Engine just stores
        // the resolved values for hot-path access.
        let provider_suite = self
            .crypto_context
            .provider()
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == cipher_suite)
            .ok_or(Error::CryptoError(
                crate::CryptoError::UnsupportedCipherSuite(cipher_suite),
            ))?;
        self.explicit_nonce_len = provider_suite.explicit_nonce_len();
        self.min_protected_fragment_len = provider_suite.min_protected_fragment_len();
        self.cipher_suite = Some(cipher_suite);
        Ok(())
    }

    pub fn enable_peer_encryption(&mut self) -> Result<(), InternalError> {
        debug!("Peer encryption enabled");
        self.peer_encryption_enabled = true;

        let maybe_index_epoch1 = self
            .queue_rx
            .iter()
            .position(|i| i.records().iter().any(|r| r.record().sequence.epoch == 1));

        let Some(index_epoch1) = maybe_index_epoch1 else {
            return Ok(());
        };

        // Now decrypt all entries remaining.
        let all = self.queue_rx.split_off(index_epoch1);

        for incoming in all {
            let unhandled = incoming.into_records().filter(|r| !r.is_handled());

            for record in unhandled {
                let buf = record.into_buffer();
                self.parse_packet(&buf)?;
                self.buffers_free.push(buf);
            }
        }

        Ok(())
    }

    fn peer_iv(&self) -> Result<Iv, Error> {
        if self.is_client {
            self.crypto_context
                .get_server_write_iv()
                .ok_or(Error::CryptoError(
                    crate::CryptoError::WriteIvNotAvailable { is_client: false },
                ))
        } else {
            self.crypto_context
                .get_client_write_iv()
                .ok_or(Error::CryptoError(
                    crate::CryptoError::WriteIvNotAvailable { is_client: true },
                ))
        }
    }

    pub fn decryption_aad_and_nonce(
        &self,
        dtls: &DTLSRecord,
        buf: &[u8],
    ) -> Result<(Aad, Nonce), Error> {
        // DTLS 1.2 AEAD: AAD uses the plaintext length. Recover plaintext length
        // from the record header by subtracting this suite's wire overhead.
        let plaintext_len = dtls
            .length
            .saturating_sub(self.min_protected_fragment_len() as u16);
        let aad = Aad::new_dtls12(dtls.content_type, dtls.sequence, plaintext_len);
        let iv = self.peer_iv()?;
        let seq64 = ((dtls.sequence.epoch as u64) << 48) | dtls.sequence.sequence_number;
        let nonce = match self.explicit_nonce_len {
            0 => Nonce::xor(iv.as_12_bytes()?, seq64),
            DTLSRecord::EXPLICIT_NONCE_LEN => Nonce::new(iv, dtls.nonce(buf))?,
            len => Nonce::new(iv, dtls.nonce_with_len(buf, len))?,
        };
        Ok((aad, nonce))
    }

    pub fn generate_verify_data(&mut self, is_client: bool) -> Result<[u8; 12], Error> {
        let Some(suite) = self.cipher_suite() else {
            return Err(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ));
        };
        let algorithm = suite.hash_algorithm();
        let mut handshake_hash = self.buffers_free.pop();
        self.transcript_hash(algorithm, &mut handshake_hash);

        let suite_hash = suite.hash_algorithm();
        let mut out = self.buffers_free.pop();
        let mut scratch = self.buffers_free.pop();
        let verify_data_vec = self
            .crypto_context()
            .generate_verify_data(
                &handshake_hash,
                is_client,
                suite_hash,
                &mut out,
                &mut scratch,
            )
            .map_err(Error::CryptoError)?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError(
                crate::CryptoError::InvalidVerifyDataLength,
            ));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        self.buffers_free.push(handshake_hash);
        self.buffers_free.push(out);
        self.buffers_free.push(scratch);

        Ok(verify_data)
    }
}

impl RecordHandler for Engine {
    fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
        let epoch = record.record().sequence.epoch;

        if record.record().content_type == ContentType::ChangeCipherSpec
            && epoch == 0
            && self.peer_encryption_enabled
        {
            // DTLS 1.2 peers may retransmit their last handshake flight after
            // we have already enabled peer encryption. A late plaintext CCS is
            // no longer actionable; queuing it would leave an unhandled control
            // record in queue_rx and prevent handled app-data records behind it
            // from being purged.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Handshake
            && epoch == 0
            && self.peer_encryption_enabled
            && record
                .first_handshake()
                .and_then(|handshake| handshake.dupe_triggers_resend())
                .is_none()
        {
            // Stale plaintext handshakes must still be visible to
            // insert_incoming_handshake when they can trigger final-flight
            // retransmission. Other post-encryption epoch-0 handshakes are
            // unauthenticated and no longer actionable.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Alert {
            if epoch == 0 {
                if self.peer_encryption_enabled {
                    // Post-handshake: epoch 0 alerts are unauthenticated, discard.
                    self.push_buffer(record.into_buffer());
                    return Ok(None);
                }

                let fatal_description = {
                    let fragment = record.record().fragment(record.buffer());
                    (fragment.len() >= 2 && fragment[0] == 2).then(|| fragment[1])
                };
                self.push_buffer(record.into_buffer());

                if let Some(description) = fatal_description {
                    return Err(Error::SecurityError(crate::SecurityError::FatalAlert {
                        description,
                    }));
                }

                return Ok(None);
            }

            if !self.peer_encryption_enabled {
                // Epoch >= 1 before peer encryption is enabled must stay queued
                // for re-parsing after enable_peer_encryption().
                return Ok(Some(record));
            }

            let alert = {
                let fragment = record.record().fragment(record.buffer());
                (fragment.len() >= 2).then(|| (fragment[0], fragment[1]))
            };
            self.push_buffer(record.into_buffer());

            if let Some((level, description)) = alert {
                if description == 0 {
                    self.close_notify_received = true;
                    return Ok(None);
                }

                if level == 2 {
                    return Err(Error::SecurityError(crate::SecurityError::FatalAlert {
                        description,
                    }));
                }
            }

            return Ok(None);
        }

        if self.close_notify_received
            && record.record().content_type == ContentType::ApplicationData
        {
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        Ok(Some(record))
    }

    fn is_peer_encryption_enabled(&self) -> bool {
        self.peer_encryption_enabled
    }

    fn replay_check(&self, seq: Sequence) -> bool {
        if !self.config.replay_detection() {
            return true;
        }
        // Only epoch 1 (encrypted) records reach here; epoch 0 records are
        // returned early by the DTLS 1.2 incoming parser.
        self.replay.check(seq.sequence_number)
    }

    fn replay_update(&mut self, seq: Sequence) {
        if self.config.replay_detection() {
            self.replay.update(seq.sequence_number);
        }
    }

    fn note_decrypted_record(&mut self, content_type: ContentType) {
        // A decrypted (so authenticated) application-data record proves the peer
        // is past its handshake, which means it received our final flight. Once
        // that's known, a stale plaintext handshake (unauthenticated, replayable)
        // must no longer drive a courtesy flight retransmission. The client
        // confirms separately at its own completion (flight_stop_resend_timers).
        if content_type == ContentType::ApplicationData {
            self.peer_handshake_confirmed = true;
        }
    }

    fn decryption_aad_and_nonce(
        &self,
        dtls: &DTLSRecord,
        buf: &[u8],
    ) -> Result<(Aad, Nonce), Error> {
        Engine::decryption_aad_and_nonce(self, dtls, buf)
    }

    fn explicit_nonce_len(&self) -> usize {
        self.explicit_nonce_len
    }

    fn min_protected_fragment_len(&self) -> usize {
        self.min_protected_fragment_len
    }

    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        Engine::decrypt_data(self, ciphertext, aad, nonce)
    }

    fn can_discard_bad_protected_record(&self) -> bool {
        self.release_app_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rfc6083: bool) -> Arc<Config> {
        let builder = Config::builder().dtls13_cipher_suites(&[]);
        Arc::new(
            if rfc6083 {
                builder.rfc6083_sctp()
            } else {
                builder
            }
            .build()
            .expect("DTLS 1.2 config"),
        )
    }

    fn config_with_limit(limit: u64) -> Arc<Config> {
        Arc::new(
            Config::builder()
                .dtls13_cipher_suites(&[])
                .aead_encryption_limit(limit)
                .build()
                .expect("DTLS 1.2 config"),
        )
    }

    fn encrypted_engine(config: Arc<Config>, is_client: bool) -> Engine {
        let mut engine = Engine::new(config, AuthMode::Psk);
        engine.set_client(is_client);
        engine
            .set_cipher_suite(Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256)
            .expect("select AES-128-GCM");
        engine.crypto_context_mut().set_psk(vec![0xA5; 32]);
        engine
            .crypto_context_mut()
            .compute_psk_pre_master_secret()
            .expect("compute test pre-master secret");
        let mut out = Buf::new();
        let mut scratch = Buf::new();
        engine
            .crypto_context_mut()
            .derive_extended_master_secret(
                &[0x11; 32],
                HashAlgorithm::SHA256,
                &mut out,
                &mut scratch,
            )
            .expect("derive test master secret");
        engine
            .crypto_context_mut()
            .derive_keys(
                Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
                &[0x22; 32],
                &[0x33; 32],
                &mut out,
                &mut scratch,
            )
            .expect("derive test write keys");
        engine
    }

    fn drain_packets(engine: &mut Engine) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut buffer = vec![0_u8; crate::config::RFC6083_DTLS_MTU];
        while let Output::Packet(packet) = engine.poll_output(&mut buffer, Instant::now()) {
            packets.push(packet.to_vec());
        }
        packets
    }

    #[test]
    fn rfc6083_replay_policy_accepts_transport_ordered_duplicate() {
        let sequence = Sequence::new(1);
        let mut strict = Engine::new(config(false), AuthMode::Psk);
        assert!(strict.replay_check(sequence));
        strict.replay_update(sequence);
        assert!(!strict.replay_check(sequence));

        let mut rfc6083 = Engine::new(config(true), AuthMode::Psk);
        assert!(rfc6083.replay_check(sequence));
        rfc6083.replay_update(sequence);
        assert!(
            rfc6083.replay_check(sequence),
            "SCTP provides duplicate suppression for RFC 6083"
        );
    }

    #[test]
    fn standalone_record_larger_than_path_mtu_is_rejected() {
        let mut engine = Engine::new(config(true), AuthMode::Psk);
        let outcome = engine.create_record(ContentType::ApplicationData, 0, false, |body| {
            body.resize(crate::config::RFC6083_DTLS_MTU, 0);
        });
        assert!(matches!(
            outcome,
            Err(Error::RecordExceedsPathMtu {
                path_mtu: crate::config::RFC6083_DTLS_MTU,
                ..
            })
        ));
    }

    #[test]
    fn sequence_limit_allows_exact_maximum_and_rejects_next_without_mutation() {
        let mut epoch0 = Engine::new(config(true), AuthMode::Psk);
        epoch0.sequence_epoch_0.sequence_number = MAX_SEQUENCE_NUMBER;
        epoch0
            .create_record(ContentType::Handshake, 0, false, |body| body.push(0x01))
            .expect("exact maximum epoch-0 sequence is usable");
        let packets = drain_packets(&mut epoch0);
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0][5..11], &[0xff; 6]);

        let queued_before = epoch0.queue_tx.len();
        let transcript_before = epoch0.transcript.len();
        let mut callback_called = false;
        let error = epoch0
            .create_record(ContentType::Handshake, 0, true, |body| {
                callback_called = true;
                body.push(0x02);
            })
            .expect_err("sequence beyond 48 bits must fail");
        assert!(matches!(
            error,
            Error::CryptoError(crate::CryptoError::Epoch0SequenceNumberExhausted)
        ));
        assert!(!callback_called);
        assert_eq!(epoch0.queue_tx.len(), queued_before);
        assert_eq!(epoch0.transcript.len(), transcript_before);
        assert!(epoch0.flight_saved_records.is_empty());
    }

    #[test]
    fn aes_gcm_explicit_nonce_is_epoch_and_sequence_and_never_reused() {
        let mut sender = encrypted_engine(config_with_limit(2), true);
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            sender
                .create_record(ContentType::ApplicationData, 1, false, |body| {
                    body.extend_from_slice(payload);
                })
                .expect("protected send within limit");
        }

        let packets = drain_packets(&mut sender);
        assert_eq!(packets.len(), 1, "ordinary DTLS may coalesce records");
        let first_len = 13 + u16::from_be_bytes([packets[0][11], packets[0][12]]) as usize;
        let first = &packets[0][..first_len];
        let second = &packets[0][first_len..];
        assert_eq!(&first[13..21], &(1_u64 << 48).to_be_bytes());
        assert_eq!(&second[13..21], &((1_u64 << 48) | 1).to_be_bytes());
        assert_ne!(&first[13..21], &second[13..21]);

        let mut receiver = encrypted_engine(config_with_limit(2), false);
        receiver
            .enable_peer_encryption()
            .expect("enable receiver write epoch");
        receiver.release_application_data();
        receiver
            .parse_packet(&packets[0])
            .expect("decrypt sequence-derived AES-GCM nonces");
        let mut plaintext = [0_u8; 32];
        assert!(matches!(
            receiver.poll_output(&mut plaintext, Instant::now()),
            Output::ApplicationData(data) if data == b"first"
        ));
        assert!(matches!(
            receiver.poll_output(&mut plaintext, Instant::now()),
            Output::ApplicationData(data) if data == b"second"
        ));

        let sequence_before = sender.sequence_epoch_n;
        let mut callback_called = false;
        let error = sender
            .create_record(ContentType::Alert, 1, false, |body| {
                callback_called = true;
                body.extend_from_slice(&[1, 0]);
            })
            .expect_err("N+1 protected encryption must fail");
        assert!(matches!(
            error,
            Error::CryptoError(crate::CryptoError::AeadEncryptionLimitReached { limit: 2 })
        ));
        assert!(!callback_called);
        assert_eq!(sender.sequence_epoch_n, sequence_before);
        assert_eq!(sender.protected_send_count, 2);
        assert!(sender.queue_tx.is_empty());
    }

    #[test]
    fn protected_sequence_exact_maximum_uses_unique_wire_nonce_then_stops() {
        let mut engine = encrypted_engine(config_with_limit(2), true);
        engine.sequence_epoch_n.sequence_number = MAX_SEQUENCE_NUMBER;
        engine
            .create_record(ContentType::ApplicationData, 1, false, |body| {
                body.extend_from_slice(b"last");
            })
            .expect("exact maximum protected sequence is usable");
        let packets = drain_packets(&mut engine);
        assert_eq!(packets.len(), 1);
        assert_eq!(
            &packets[0][13..21],
            &((1_u64 << 48) | MAX_SEQUENCE_NUMBER).to_be_bytes()
        );

        let error = engine
            .create_record(ContentType::ApplicationData, 1, false, |_| {})
            .expect_err("protected sequence beyond 48 bits must fail");
        assert!(matches!(
            error,
            Error::CryptoError(crate::CryptoError::SendSequenceNumberExhausted { epoch: 1 })
        ));
        assert_eq!(engine.protected_send_count, 1);
    }

    #[test]
    fn fragmented_protected_handshake_preflights_entire_aead_budget() {
        let config = Arc::new(
            Config::builder()
                .dtls13_cipher_suites(&[])
                .mtu(256)
                .aead_encryption_limit(1)
                .build()
                .expect("small-MTU DTLS 1.2 config"),
        );
        let mut engine = encrypted_engine(config, true);
        let transcript_before = engine.transcript.to_vec();
        let sequence_before = engine.sequence_epoch_n;
        let handshake_sequence_before = engine.next_handshake_seq_no;
        let protected_send_count_before = engine.protected_send_count;
        let mut callback_called = false;

        let error = engine
            .create_handshake(MessageType::Finished, |body, _| {
                callback_called = true;
                body.resize(512, 0xA5);
                Ok(())
            })
            .expect_err("the whole fragmented message must fit the AEAD budget");

        assert!(callback_called, "body construction precedes size preflight");
        assert!(matches!(
            error,
            Error::CryptoError(crate::CryptoError::AeadEncryptionLimitReached { limit: 1 })
        ));
        assert_eq!(&engine.transcript[..], transcript_before);
        assert_eq!(engine.sequence_epoch_n, sequence_before);
        assert_eq!(engine.next_handshake_seq_no, handshake_sequence_before);
        assert_eq!(engine.protected_send_count, protected_send_count_before);
        assert!(engine.queue_tx.is_empty());
        assert!(engine.flight_saved_records.is_empty());
    }

    #[test]
    fn protected_flight_resend_preflights_before_mutating_queues() {
        let mut engine = encrypted_engine(config_with_limit(3), true);
        for byte in [0x11, 0x22] {
            engine
                .create_record(ContentType::Handshake, 1, true, |body| body.push(byte))
                .expect("initial protected flight record");
        }
        let queue_before: Vec<Vec<u8>> = engine
            .queue_tx
            .iter()
            .map(|buffer| buffer.to_vec())
            .collect();
        let saved_before: Vec<Vec<u8>> = engine
            .flight_saved_records
            .iter()
            .map(|entry| entry.fragment.to_vec())
            .collect();
        let sequence_before = engine.sequence_epoch_n;
        let protected_send_count_before = engine.protected_send_count;

        let error = engine
            .flight_resend("test")
            .expect_err("two retransmissions cannot fit the remaining one-record budget");

        assert!(matches!(
            error,
            Error::CryptoError(crate::CryptoError::AeadEncryptionLimitReached { limit: 3 })
        ));
        assert_eq!(
            engine
                .queue_tx
                .iter()
                .map(|buffer| buffer.to_vec())
                .collect::<Vec<_>>(),
            queue_before
        );
        assert_eq!(
            engine
                .flight_saved_records
                .iter()
                .map(|entry| entry.fragment.to_vec())
                .collect::<Vec<_>>(),
            saved_before
        );
        assert_eq!(engine.sequence_epoch_n, sequence_before);
        assert_eq!(engine.protected_send_count, protected_send_count_before);
    }

    fn maximum_certificate_body(body: &mut Buf) {
        let cert_len = super::super::message::MAX_CERTIFICATE_BYTES;
        let list_len = 4 * (3 + cert_len);
        body.extend_from_slice(&(list_len as u32).to_be_bytes()[1..]);
        for marker in 0_u8..4 {
            body.extend_from_slice(&(cert_len as u32).to_be_bytes()[1..]);
            body.resize(body.len() + cert_len, marker);
        }
    }

    #[test]
    fn rfc6083_maximum_certificate_fits_tx_and_rx_fragment_queues() {
        let mut sender = Engine::new(config(true), AuthMode::Psk);
        sender
            .create_handshake(MessageType::Certificate, |body, _| {
                maximum_certificate_body(body);
                Ok(())
            })
            .expect("maximum admitted Certificate must fit TX queue");
        assert_eq!(sender.queue_tx.len(), 17);

        let packets = drain_packets(&mut sender);
        assert_eq!(packets.len(), 17);
        assert!(packets.iter().all(|packet| {
            13 + u16::from_be_bytes([packet[11], packet[12]]) as usize == packet.len()
        }));

        let mut receiver = Engine::new(config(true), AuthMode::Psk);
        for packet in packets {
            receiver
                .parse_packet(&packet)
                .expect("each Certificate fragment fits RX queue");
        }
        assert!(receiver.has_complete_handshake(MessageType::Certificate));
        let mut body = Buf::new();
        let handshake = receiver
            .next_handshake(MessageType::Certificate, &mut body)
            .expect("defragment maximum Certificate")
            .expect("complete maximum Certificate");
        let Body::Certificate(certificate) = handshake.body else {
            panic!("expected Certificate body");
        };
        assert_eq!(certificate.certificate_list.len(), 4);
    }

    #[test]
    fn rfc6083_complete_maximum_certificate_flights_fit_both_roles() {
        let mut server = Engine::new(config(true), AuthMode::Psk);
        server
            .create_handshake(MessageType::ServerHello, |body, _| {
                body.push(1);
                Ok(())
            })
            .expect("ServerHello");
        server
            .create_handshake(MessageType::Certificate, |body, _| {
                maximum_certificate_body(body);
                Ok(())
            })
            .expect("server Certificate");
        for message_type in [
            MessageType::ServerKeyExchange,
            MessageType::CertificateRequest,
            MessageType::ServerHelloDone,
        ] {
            server
                .create_handshake(message_type, |body, _| {
                    body.push(1);
                    Ok(())
                })
                .expect("remaining server flight record");
        }
        assert_eq!(server.queue_tx.len(), 21);

        let mut client = Engine::new(config(true), AuthMode::Psk);
        client
            .create_handshake(MessageType::Certificate, |body, _| {
                maximum_certificate_body(body);
                Ok(())
            })
            .expect("client Certificate");
        for message_type in [
            MessageType::ClientKeyExchange,
            MessageType::CertificateVerify,
            MessageType::ClientHello,
            MessageType::HelloRequest,
        ] {
            client
                .create_handshake(message_type, |body, _| {
                    body.push(1);
                    Ok(())
                })
                .expect("remaining client flight record");
        }
        assert_eq!(client.queue_tx.len(), 21);
    }

    #[test]
    fn rfc6083_orders_key_install_ccs_and_epoch_activation_before_finished() {
        let mut engine = Engine::new(config(true), AuthMode::Psk);
        engine
            .create_record(ContentType::Handshake, 0, false, |body| {
                body.push(0xa1);
            })
            .expect("queue preceding handshake");

        let preceding_datagrams = engine.rfc6083_queued_datagrams();
        assert_eq!(preceding_datagrams, 1);
        engine
            .arm_rfc6083_output_barrier(preceding_datagrams, Zeroizing::new(vec![0x42; 64]))
            .expect("arm key installation barrier");
        engine
            .arm_rfc6083_prepare_ccs_barrier(preceding_datagrams)
            .expect("arm ChangeCipherSpec barrier");
        engine
            .arm_rfc6083_prepare_epoch_barrier(preceding_datagrams + 1)
            .expect("arm epoch activation barrier");
        engine
            .create_record_in_new_datagram(ContentType::ChangeCipherSpec, 0, false, |body| {
                body.push(1)
            })
            .expect("queue ChangeCipherSpec");

        // Enqueue a minimal epoch-1 Finished stand-in directly. Exercising the
        // encrypted record builder would require handshake keys, while this
        // regression is specifically about the observable output order and
        // record epochs at the SCTP-AUTH transition boundary.
        let mut finished = Buf::new();
        finished.push(ContentType::Handshake.as_u8());
        finished.extend_from_slice(&ProtocolVersion::DTLS1_2.as_u16().to_be_bytes());
        finished.extend_from_slice(&1_u16.to_be_bytes());
        finished.extend_from_slice(&[0; 6]);
        finished.extend_from_slice(&1_u16.to_be_bytes());
        finished.push(MessageType::Finished.as_u8());
        engine.queue_tx.push_back(finished);

        let mut buffer = vec![0_u8; crate::config::RFC6083_DTLS_MTU];
        let now = Instant::now();

        match engine.poll_output(&mut buffer, now) {
            Output::Packet(packet) => {
                assert_eq!(packet.first(), Some(&ContentType::Handshake.as_u8()));
                assert_eq!(
                    &packet[3..5],
                    &[0, 0],
                    "preceding handshake must use DTLS epoch 0"
                );
            }
            output => panic!("expected preceding handshake packet, got {output:?}"),
        }
        match engine.poll_output(&mut buffer, now) {
            Output::Rfc6083KeyingMaterial(material) => assert_eq!(material.len(), 64),
            output => panic!("expected inactive key installation, got {output:?}"),
        }
        assert!(matches!(
            engine.poll_output(&mut buffer, now),
            Output::Rfc6083PrepareChangeCipherSpec
        ));
        match engine.poll_output(&mut buffer, now) {
            Output::Packet(packet) => {
                assert_eq!(packet.first(), Some(&ContentType::ChangeCipherSpec.as_u8()));
                assert_eq!(&packet[3..5], &[0, 0], "CCS must use DTLS epoch 0");
            }
            output => panic!("expected ChangeCipherSpec packet, got {output:?}"),
        }
        assert!(matches!(
            engine.poll_output(&mut buffer, now),
            Output::Rfc6083PrepareEpoch
        ));
        match engine.poll_output(&mut buffer, now) {
            Output::Packet(packet) => {
                assert_eq!(packet.first(), Some(&ContentType::Handshake.as_u8()));
                assert_eq!(&packet[3..5], &[0, 1], "Finished must use DTLS epoch 1");
            }
            output => panic!("expected Finished packet, got {output:?}"),
        }
    }

    #[test]
    fn reciprocal_close_notify_is_blocked_by_sender_dry_output() {
        let mut engine = Engine::new(config(true), AuthMode::Psk);
        engine.arm_rfc6083_prepare_close_notify(0);
        engine
            .create_record(ContentType::Alert, 0, false, |body| {
                body.extend_from_slice(&[1, 0]);
            })
            .expect("queue close_notify");
        let mut buffer = vec![0_u8; crate::config::RFC6083_DTLS_MTU];
        assert!(matches!(
            engine.poll_output(&mut buffer, Instant::now()),
            Output::Rfc6083PrepareCloseNotify
        ));
        assert!(matches!(
            engine.poll_output(&mut buffer, Instant::now()),
            Output::Packet(_)
        ));
    }
}
