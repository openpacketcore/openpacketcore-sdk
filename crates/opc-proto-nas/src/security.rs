//! NAS security helpers, algorithm hooks and a RustCrypto AES provider.
//!
//! This module owns NAS COUNT handling, replay checks and protected-envelope
//! framing. [`AesNasSecurityAlgorithms`] implements NIA2 with NEA2 or NEA0 and
//! an explicit caller-owned key resolver. The context owns COUNT allocation
//! and the NAS connection identifier. SNOW 3G
//! (NIA1/NEA1), ZUC (NIA3/NEA3), key derivation and algorithm negotiation remain
//! outside this implementation. [`NullNasSecurityAlgorithms`] is separate and
//! supports only explicitly selected NIA0/NEA0.

mod aes;

pub use aes::{
    nea2_cipher, nia2_mac, AesNasSecurityAlgorithms, NasAesKey, NasAesKeyResolver,
    NasAlgorithmInput, NasKeyUsage,
};

use bytes::{BufMut, Bytes, BytesMut};
use opc_key::{KeyHandle, KeyPurpose};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;

use crate::{SecurityHeaderType, SecurityProtected};

/// NAS integrity algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasIntegrityAlgorithm {
    /// Null integrity algorithm.
    Nia0 = 0,
    /// 128-NIA1.
    Nia1 = 1,
    /// 128-NIA2.
    Nia2 = 2,
    /// 128-NIA3.
    Nia3 = 3,
}

impl NasIntegrityAlgorithm {
    /// Convert a TS 24.501 algorithm nibble into an integrity algorithm.
    pub const fn from_nibble(value: u8) -> Option<Self> {
        match value & 0x0F {
            0 => Some(Self::Nia0),
            1 => Some(Self::Nia1),
            2 => Some(Self::Nia2),
            3 => Some(Self::Nia3),
            _ => None,
        }
    }
}

/// NAS ciphering algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasCipheringAlgorithm {
    /// Null ciphering algorithm.
    Nea0 = 0,
    /// 128-NEA1.
    Nea1 = 1,
    /// 128-NEA2.
    Nea2 = 2,
    /// 128-NEA3.
    Nea3 = 3,
}

impl NasCipheringAlgorithm {
    /// Convert a TS 24.501 algorithm nibble into a ciphering algorithm.
    pub const fn from_nibble(value: u8) -> Option<Self> {
        match value & 0x0F {
            0 => Some(Self::Nea0),
            1 => Some(Self::Nea1),
            2 => Some(Self::Nea2),
            3 => Some(Self::Nea3),
            _ => None,
        }
    }
}

/// Direction bit used by NAS integrity and ciphering algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasSecurityDirection {
    /// Uplink NAS message.
    Uplink,
    /// Downlink NAS message.
    Downlink,
}

/// 24-bit NAS COUNT value: 16-bit overflow and 8-bit sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NasCount(u32);

impl NasCount {
    /// Create a NAS COUNT from overflow and sequence-number parts.
    pub const fn new(overflow: u16, sequence_number: u8) -> Self {
        Self(((overflow as u32) << 8) | (sequence_number as u32))
    }

    /// Create a NAS COUNT from its packed 24-bit representation.
    pub fn from_u32(value: u32) -> Result<Self, NasSecurityError> {
        if value > 0x00FF_FFFF {
            return Err(NasSecurityError::InvalidCount);
        }
        Ok(Self(value))
    }

    /// Packed 24-bit COUNT value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// COUNT overflow part.
    pub const fn overflow(self) -> u16 {
        (self.0 >> 8) as u16
    }

    /// COUNT sequence-number part.
    pub const fn sequence_number(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// Return the next COUNT, failing closed on 24-bit wrap.
    pub fn checked_increment(self) -> Result<Self, NasSecurityError> {
        Self::from_u32(
            self.0
                .checked_add(1)
                .ok_or(NasSecurityError::InvalidCount)?,
        )
    }
}

/// Monotonic replay window for one NAS direction.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NasReplayWindow {
    highest: Option<NasCount>,
}

impl NasReplayWindow {
    /// Create an empty replay window.
    pub const fn new() -> Self {
        Self { highest: None }
    }

    /// Highest accepted COUNT, if any.
    pub const fn highest(&self) -> Option<NasCount> {
        self.highest
    }

    /// Accept a new COUNT only if it is strictly newer than the prior one.
    pub fn accept(&mut self, count: NasCount) -> Result<(), NasSecurityError> {
        if self.highest.is_some_and(|highest| count <= highest) {
            return Err(NasSecurityError::ReplayRejected);
        }
        self.highest = Some(count);
        Ok(())
    }
}

/// NAS connection identifier used as BEARER (TS 33.501 §6.4.2).
///
/// Each access has its own context and COUNT pair, even when keys and the
/// algorithm provider are shared. Raw algorithm vectors can use any five-bit
/// BEARER through [`NasAlgorithmInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasConnectionId {
    /// 3GPP access, connection identifier 0x01.
    ThreeGpp,
    /// Non-3GPP access, connection identifier 0x02.
    NonThreeGpp,
}

impl NasConnectionId {
    /// The five-bit BEARER input for this NAS connection.
    pub const fn as_bearer(self) -> u8 {
        match self {
            Self::ThreeGpp => 1,
            Self::NonThreeGpp => 2,
        }
    }
}

/// COUNT state for one direction of one connection (TS 24.501 §4.4.3.1).
///
/// The transmit value is the next unused COUNT; the receive value is the
/// highest successfully authenticated COUNT. These have different restoration
/// semantics. A caller restoring keys must supply current, exclusively owned
/// state; this in-memory helper does not persist or fence contexts across
/// process restarts. Never restore an older snapshot with the same keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasCountState {
    /// Next unused transmit COUNT; `None` means exhausted, never reset to zero.
    pub next_transmit: Option<NasCount>,
    /// Highest authenticated receive COUNT, or `None` for a fresh context.
    pub highest_received: Option<NasCount>,
}

impl Default for NasCountState {
    fn default() -> Self {
        Self {
            next_transmit: Some(NasCount::new(0, 0)),
            highest_received: None,
        }
    }
}

impl NasCountState {
    fn candidate_count(&self, sequence_number: u8) -> Result<NasCount, NasSecurityError> {
        let overflow = self.highest_received.map_or(0, NasCount::overflow);
        let candidate = NasCount::new(overflow, sequence_number);
        if self
            .highest_received
            .is_some_and(|highest| candidate <= highest)
        {
            return overflow
                .checked_add(1)
                .map(|overflow| NasCount::new(overflow, sequence_number))
                .ok_or(NasSecurityError::InvalidCount);
        }
        Ok(candidate)
    }

    fn accept(&mut self, count: NasCount) -> Result<(), NasSecurityError> {
        if self
            .highest_received
            .is_some_and(|highest| count <= highest)
        {
            return Err(NasSecurityError::ReplayRejected);
        }
        self.highest_received = Some(count);
        Ok(())
    }

    fn reserve_transmit(&mut self) -> Result<NasCount, NasSecurityError> {
        let count = self.next_transmit.ok_or(NasSecurityError::InvalidCount)?;
        self.next_transmit = count.checked_increment().ok();
        Ok(count)
    }
}

/// NAS security context for one connection, selected by NAS procedures.
///
/// Clones share receive and transmit state. `protect_payload` reserves a fresh
/// COUNT before invoking algorithms, including on failure, and refuses after
/// exhaustion. Separate contexts for the same keys and connection must not be
/// created from stale state. Key lookup, persistence and lifecycle belong to
/// the caller; SDK key handles must belong to the `session` key lane.
#[derive(Clone)]
pub struct NasSecurityContext {
    /// Selected integrity algorithm.
    pub integrity_algorithm: NasIntegrityAlgorithm,
    /// Selected ciphering algorithm.
    pub ciphering_algorithm: NasCipheringAlgorithm,
    /// Integrity key handle.
    pub integrity_key: KeyHandle,
    /// Ciphering key handle.
    pub ciphering_key: KeyHandle,
    connection_id: NasConnectionId,
    uplink: Arc<Mutex<NasCountState>>,
    downlink: Arc<Mutex<NasCountState>>,
}

impl fmt::Debug for NasSecurityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NasSecurityContext")
            .field("integrity_algorithm", &self.integrity_algorithm)
            .field("ciphering_algorithm", &self.ciphering_algorithm)
            .field("integrity_key", &self.integrity_key)
            .field("ciphering_key", &self.ciphering_key)
            .field("connection_id", &self.connection_id)
            .field("uplink", &self.count_state(NasSecurityDirection::Uplink))
            .field(
                "downlink",
                &self.count_state(NasSecurityDirection::Downlink),
            )
            .finish()
    }
}

impl NasSecurityContext {
    /// Build a context with an immutable connection identifier and full COUNTs.
    ///
    /// Use [`NasCountState::default`] for a fresh context, or restore each
    /// direction's next transmit and highest authenticated receive COUNTs.
    pub fn new(
        integrity_algorithm: NasIntegrityAlgorithm,
        ciphering_algorithm: NasCipheringAlgorithm,
        integrity_key: KeyHandle,
        ciphering_key: KeyHandle,
        connection_id: NasConnectionId,
        uplink: NasCountState,
        downlink: NasCountState,
    ) -> Result<Self, NasSecurityError> {
        if integrity_key.purpose() != KeyPurpose::Session
            || ciphering_key.purpose() != KeyPurpose::Session
        {
            return Err(NasSecurityError::KeyPurposeMismatch);
        }
        Ok(Self {
            integrity_algorithm,
            ciphering_algorithm,
            integrity_key,
            ciphering_key,
            connection_id,
            uplink: Arc::new(Mutex::new(uplink)),
            downlink: Arc::new(Mutex::new(downlink)),
        })
    }

    /// Connection identifier supplied to every integrity and cipher operation.
    pub const fn connection_id(&self) -> NasConnectionId {
        self.connection_id
    }

    /// Snapshot this direction's counters; poisoned state fails closed.
    ///
    /// This is an observation, not a durable reservation. The caller owns
    /// persistence and exclusive restoration under the same keys.
    pub fn count_state(
        &self,
        direction: NasSecurityDirection,
    ) -> Result<NasCountState, NasSecurityError> {
        self.state_for(direction)
            .lock()
            .map(|state| *state)
            .map_err(|_| NasSecurityError::InvalidCount)
    }

    /// Estimate the next received COUNT, failing on 24-bit overflow.
    ///
    /// Without independent proof of non-replay, TS 24.501 §4.4.3.1 requires an
    /// estimate above the highest accepted COUNT, including after lost messages.
    pub fn count_for(
        &self,
        direction: NasSecurityDirection,
        sequence_number: u8,
    ) -> Result<NasCount, NasSecurityError> {
        self.count_state(direction)?
            .candidate_count(sequence_number)
    }

    fn state_for(&self, direction: NasSecurityDirection) -> &Mutex<NasCountState> {
        match direction {
            NasSecurityDirection::Uplink => &self.uplink,
            NasSecurityDirection::Downlink => &self.downlink,
        }
    }

    fn accept_count(
        &self,
        direction: NasSecurityDirection,
        count: NasCount,
    ) -> Result<(), NasSecurityError> {
        self.state_for(direction)
            .lock()
            .map_err(|_| NasSecurityError::InvalidCount)?
            .accept(count)
    }

    fn check_integrity<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        envelope: &SecurityProtected,
    ) -> Result<NasCount, NasSecurityError> {
        if envelope.security_header_type == SecurityHeaderType::Plain {
            return Err(NasSecurityError::InvalidSecurityHeader);
        }
        let count = self.count_for(direction, envelope.sequence_number)?;
        let message = integrity_message(envelope.sequence_number, &envelope.payload)?;
        let expected = algorithms.compute_mac(
            self.integrity_algorithm,
            &self.integrity_key,
            count,
            self.connection_id,
            direction,
            &message,
        )?;
        if !mac_eq(expected, envelope.mac) {
            return Err(NasSecurityError::IntegrityCheckFailed);
        }
        Ok(count)
    }

    /// Verify and consume a received COUNT, without deciphering.
    ///
    /// Replayed authenticated envelopes normally fail integrity against the
    /// newer estimated COUNT. A concurrent stale acceptance is ReplayRejected.
    /// NIA0 cannot detect replay because its MAC does not authenticate COUNT.
    pub fn verify_integrity<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        envelope: &SecurityProtected,
    ) -> Result<NasCount, NasSecurityError> {
        let count = self.check_integrity(algorithms, direction, envelope)?;
        self.accept_count(direction, count)?;
        Ok(count)
    }

    /// Verify and decipher, accepting COUNT only after both operations succeed.
    pub fn verify_and_decipher<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        envelope: &SecurityProtected,
    ) -> Result<VerifiedNasPayload, NasSecurityError> {
        let count = self.check_integrity(algorithms, direction, envelope)?;
        let payload = if envelope.security_header_type.is_ciphered() {
            algorithms.apply_cipher(
                self.ciphering_algorithm,
                &self.ciphering_key,
                count,
                self.connection_id,
                direction,
                &envelope.payload,
            )?
        } else {
            envelope.payload.clone()
        };
        self.accept_count(direction, count)?;
        Ok(VerifiedNasPayload { count, payload })
    }

    /// Protect a payload using the next unused COUNT for this direction.
    ///
    /// COUNT is reserved atomically and burned even if a provider fails. Clones
    /// and concurrent callers share allocation; exhaustion fails closed. Each
    /// retransmission also gets a new COUNT (TS 24.501 §4.4.3.1).
    pub fn protect_payload<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        security_header_type: SecurityHeaderType,
        payload: &[u8],
    ) -> Result<SecurityProtected, NasSecurityError> {
        if security_header_type == SecurityHeaderType::Plain {
            return Err(NasSecurityError::InvalidSecurityHeader);
        }
        let count = self
            .state_for(direction)
            .lock()
            .map_err(|_| NasSecurityError::InvalidCount)?
            .reserve_transmit()?;
        let protected_payload = if security_header_type.is_ciphered() {
            algorithms.apply_cipher(
                self.ciphering_algorithm,
                &self.ciphering_key,
                count,
                self.connection_id,
                direction,
                payload,
            )?
        } else {
            Bytes::copy_from_slice(payload)
        };
        let message = integrity_message(count.sequence_number(), &protected_payload)?;
        let mac = algorithms.compute_mac(
            self.integrity_algorithm,
            &self.integrity_key,
            count,
            self.connection_id,
            direction,
            &message,
        )?;
        Ok(SecurityProtected {
            security_header_type,
            spare: 0,
            mac,
            sequence_number: count.sequence_number(),
            payload: protected_payload,
        })
    }
}

/// Verified and optionally deciphered NAS payload.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedNasPayload {
    /// NAS COUNT used for verification.
    pub count: NasCount,
    /// Verified payload; deciphered when the envelope was ciphered.
    pub payload: Bytes,
}

impl fmt::Debug for VerifiedNasPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedNasPayload")
            .field("count", &self.count)
            .field("payload", &"<redacted>")
            .finish()
    }
}

/// Algorithm provider for NAS integrity and ciphering.
pub trait NasSecurityAlgorithms {
    /// Compute a 32-bit NAS message authentication code.
    ///
    /// `message` is the complete integrity input: for protected NAS envelopes,
    /// the sequence-number octet followed by the transmitted payload. Providers
    /// must not prepend the sequence number again. `connection_id` supplies the
    /// context-owned BEARER and must be used in the algorithm input.
    fn compute_mac(
        &self,
        algorithm: NasIntegrityAlgorithm,
        key: &KeyHandle,
        count: NasCount,
        connection_id: NasConnectionId,
        direction: NasSecurityDirection,
        message: &[u8],
    ) -> Result<[u8; 4], NasSecurityError>;

    /// Apply the NAS stream cipher. NAS ciphering is symmetric, so the same
    /// hook is used for ciphering and deciphering. Use the context-owned
    /// `connection_id` for BEARER, including when one provider serves both accesses.
    fn apply_cipher(
        &self,
        algorithm: NasCipheringAlgorithm,
        key: &KeyHandle,
        count: NasCount,
        connection_id: NasConnectionId,
        direction: NasSecurityDirection,
        input: &[u8],
    ) -> Result<Bytes, NasSecurityError>;
}

/// Null NAS algorithms used for tests and explicit no-security profiles.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullNasSecurityAlgorithms;

impl NasSecurityAlgorithms for NullNasSecurityAlgorithms {
    fn compute_mac(
        &self,
        algorithm: NasIntegrityAlgorithm,
        _key: &KeyHandle,
        _count: NasCount,
        _connection_id: NasConnectionId,
        _direction: NasSecurityDirection,
        _message: &[u8],
    ) -> Result<[u8; 4], NasSecurityError> {
        match algorithm {
            NasIntegrityAlgorithm::Nia0 => Ok([0; 4]),
            _ => Err(NasSecurityError::UnsupportedAlgorithm),
        }
    }

    fn apply_cipher(
        &self,
        algorithm: NasCipheringAlgorithm,
        _key: &KeyHandle,
        _count: NasCount,
        _connection_id: NasConnectionId,
        _direction: NasSecurityDirection,
        input: &[u8],
    ) -> Result<Bytes, NasSecurityError> {
        match algorithm {
            NasCipheringAlgorithm::Nea0 => Ok(Bytes::copy_from_slice(input)),
            _ => Err(NasSecurityError::UnsupportedAlgorithm),
        }
    }
}

/// Redacted NAS security failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasSecurityError {
    /// Unsupported NIA/NEA algorithm.
    UnsupportedAlgorithm,
    /// MAC verification failed.
    IntegrityCheckFailed,
    /// Security-protected message replay or stale COUNT.
    ReplayRejected,
    /// Invalid or overflowing COUNT.
    InvalidCount,
    /// Security context was built with a non-session key lane.
    KeyPurposeMismatch,
    /// Invalid security header for a security operation.
    InvalidSecurityHeader,
    /// BEARER does not fit the five-bit algorithm field.
    InvalidBearer,
    /// Bit length is invalid or does not match the supplied octets.
    InvalidLength,
    /// The resolver could not authorize or obtain the requested NAS key.
    KeyUnavailable,
}

impl fmt::Display for NasSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UnsupportedAlgorithm => "unsupported NAS security algorithm",
            Self::IntegrityCheckFailed => "NAS integrity check failed",
            Self::ReplayRejected => "NAS replay check failed",
            Self::InvalidCount => "invalid NAS COUNT",
            Self::KeyPurposeMismatch => "invalid NAS security key purpose",
            Self::InvalidSecurityHeader => "invalid NAS security header",
            Self::InvalidBearer => "invalid NAS bearer",
            Self::InvalidLength => "invalid NAS algorithm input length",
            Self::KeyUnavailable => "NAS key unavailable",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for NasSecurityError {}

fn integrity_message(sequence_number: u8, payload: &[u8]) -> Result<Bytes, NasSecurityError> {
    let len = payload
        .len()
        .checked_add(1)
        .ok_or(NasSecurityError::InvalidLength)?;
    let mut message = BytesMut::with_capacity(len);
    message.put_u8(sequence_number);
    message.extend_from_slice(payload);
    Ok(message.freeze())
}

fn mac_eq(left: [u8; 4], right: [u8; 4]) -> bool {
    bool::from(left.ct_eq(&right))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use opc_key::{KeyId, KeyPurpose, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
    use opc_types::TenantId;

    fn tenant() -> TenantId {
        TenantId::from_static("tenant-a")
    }

    fn session_key(id: &str, fill: u8) -> KeyHandle {
        KeyHandle::new(
            KeyId::new(id).unwrap(),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([fill; AES_256_GCM_SIV_KEY_LEN]),
        )
    }

    fn context() -> NasSecurityContext {
        NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia0,
            NasCipheringAlgorithm::Nea0,
            session_key("nas-int", 0x11),
            session_key("nas-ciph", 0x22),
            NasConnectionId::NonThreeGpp,
            NasCountState {
                next_transmit: Some(NasCount::new(7, 0)),
                highest_received: Some(NasCount::new(7, 0)),
            },
            NasCountState {
                next_transmit: Some(NasCount::new(9, 0x45)),
                highest_received: Some(NasCount::new(9, 0)),
            },
        )
        .unwrap()
    }

    #[test]
    fn count_parts_and_increment_are_bounded() {
        let count = NasCount::new(0x1234, 0x56);
        assert_eq!(count.as_u32(), 0x12_3456);
        assert_eq!(count.overflow(), 0x1234);
        assert_eq!(count.sequence_number(), 0x56);
        assert_eq!(count.checked_increment().unwrap().as_u32(), 0x12_3457);
        assert!(NasCount::from_u32(0x01_000000).is_err());
        assert!(NasCount::from_u32(0x00FF_FFFF)
            .unwrap()
            .checked_increment()
            .is_err());
    }

    #[test]
    fn replay_window_rejects_reuse_and_regression() {
        let mut window = NasReplayWindow::new();
        window.accept(NasCount::new(0, 10)).unwrap();
        assert_eq!(window.highest(), Some(NasCount::new(0, 10)));
        assert_eq!(
            window.accept(NasCount::new(0, 10)).unwrap_err(),
            NasSecurityError::ReplayRejected
        );
        assert_eq!(
            window.accept(NasCount::new(0, 9)).unwrap_err(),
            NasSecurityError::ReplayRejected
        );
        window.accept(NasCount::new(0, 11)).unwrap();
    }

    #[test]
    fn null_algorithms_verify_and_protect_nia0_nea0() {
        let ctx = context();
        let algorithms = NullNasSecurityAlgorithms;
        let payload = Bytes::from_static(&[0x7E, 0x00, 0x41]);
        let envelope = SecurityProtected {
            security_header_type: SecurityHeaderType::IntegrityProtectedAndCiphered,
            spare: 0,
            mac: [0; 4],
            sequence_number: 0x44,
            payload: payload.clone(),
        };

        let verified = ctx
            .verify_and_decipher(&algorithms, NasSecurityDirection::Uplink, &envelope)
            .unwrap();
        assert_eq!(verified.count, NasCount::new(7, 0x44));
        assert_eq!(verified.payload, payload);

        let protected = ctx
            .protect_payload(
                &algorithms,
                NasSecurityDirection::Downlink,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                &payload,
            )
            .unwrap();
        assert_eq!(protected.mac, [0; 4]);
        assert_eq!(protected.sequence_number, 0x45);
        assert_eq!(protected.payload, payload);
    }

    #[test]
    fn verify_integrity_rejects_replayed_count() {
        let ctx = NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia2,
            NasCipheringAlgorithm::Nea0,
            session_key("nas-int", 0x11),
            session_key("nas-ciph", 0x22),
            NasConnectionId::NonThreeGpp,
            NasCountState::default(),
            NasCountState::default(),
        )
        .unwrap();
        let algorithms = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| {
            Ok(NasAesKey::new(Zeroizing::new([0x11; 16])))
        });
        let envelope = ctx
            .protect_payload(
                &algorithms,
                NasSecurityDirection::Uplink,
                SecurityHeaderType::IntegrityProtected,
                b"payload",
            )
            .unwrap();
        assert_eq!(
            ctx.verify_integrity(&algorithms, NasSecurityDirection::Uplink, &envelope)
                .unwrap(),
            NasCount::new(0, 0)
        );
        assert_eq!(
            ctx.verify_integrity(&algorithms, NasSecurityDirection::Uplink, &envelope)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
        assert_eq!(
            ctx.count_state(NasSecurityDirection::Uplink)
                .unwrap()
                .highest_received,
            Some(NasCount::new(0, 0))
        );
    }

    #[test]
    fn count_overflow_advances_on_sqn_wrap() {
        let ctx = NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia0,
            NasCipheringAlgorithm::Nea0,
            session_key("nas-int", 0x11),
            session_key("nas-ciph", 0x22),
            NasConnectionId::NonThreeGpp,
            NasCountState {
                next_transmit: Some(NasCount::new(0x1234, 0)),
                highest_received: Some(NasCount::new(0x1234, 0)),
            },
            NasCountState::default(),
        )
        .unwrap();
        let algorithms = NullNasSecurityAlgorithms;
        let payload = Bytes::from_static(b"payload");
        let before_wrap = SecurityProtected {
            security_header_type: SecurityHeaderType::IntegrityProtected,
            spare: 0,
            mac: [0; 4],
            sequence_number: 0xFF,
            payload: payload.clone(),
        };
        let after_wrap = SecurityProtected {
            security_header_type: SecurityHeaderType::IntegrityProtected,
            spare: 0,
            mac: [0; 4],
            sequence_number: 0x00,
            payload,
        };

        assert_eq!(
            ctx.verify_integrity(&algorithms, NasSecurityDirection::Uplink, &before_wrap)
                .unwrap(),
            NasCount::new(0x1234, 0xFF)
        );
        assert_eq!(
            ctx.verify_integrity(&algorithms, NasSecurityDirection::Uplink, &after_wrap)
                .unwrap(),
            NasCount::new(0x1235, 0x00)
        );
        assert_eq!(
            ctx.count_for(NasSecurityDirection::Uplink, 0x01).unwrap(),
            NasCount::new(0x1235, 0x01)
        );
    }

    #[test]
    fn unsupported_real_algorithms_fail_closed() {
        let ctx = NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia2,
            NasCipheringAlgorithm::Nea2,
            session_key("nas-int", 0x11),
            session_key("nas-ciph", 0x22),
            NasConnectionId::NonThreeGpp,
            NasCountState::default(),
            NasCountState::default(),
        )
        .unwrap();
        let envelope = SecurityProtected {
            security_header_type: SecurityHeaderType::IntegrityProtected,
            spare: 0,
            mac: [0; 4],
            sequence_number: 1,
            payload: Bytes::from_static(b"payload"),
        };
        assert_eq!(
            ctx.verify_integrity(
                &NullNasSecurityAlgorithms,
                NasSecurityDirection::Uplink,
                &envelope
            )
            .unwrap_err(),
            NasSecurityError::UnsupportedAlgorithm
        );
    }

    #[test]
    fn context_rejects_non_session_key_purpose_and_debug_redacts_material() {
        let bad_key = KeyHandle::new(
            KeyId::new("config-key").unwrap(),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0xAA; AES_256_GCM_SIV_KEY_LEN]),
        );
        assert_eq!(
            NasSecurityContext::new(
                NasIntegrityAlgorithm::Nia0,
                NasCipheringAlgorithm::Nea0,
                bad_key,
                session_key("nas-ciph", 0x22),
                NasConnectionId::NonThreeGpp,
                NasCountState::default(),
                NasCountState::default(),
            )
            .unwrap_err(),
            NasSecurityError::KeyPurposeMismatch
        );

        let debug = format!("{:?}", context());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("11111111"));
        assert!(!debug.contains("22222222"));
    }
}
