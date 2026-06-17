//! NAS security helper types and algorithm hooks.
//!
//! This module owns NAS COUNT handling, replay checks, and the interface used
//! by real NAS integrity/ciphering implementations. It intentionally does not
//! hard-code NIA1/2/3 or NEA1/2/3; callers provide those algorithms behind
//! [`NasSecurityAlgorithms`] while this crate keeps framing and fail-closed
//! policy local to the codec.

use bytes::Bytes;
use opc_key::{KeyHandle, KeyPurpose};
use std::fmt;

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

/// NAS security context selected by NAS procedures.
///
/// The key handles come from the SDK key substrate. This crate validates that
/// they live in the `session` key lane but does not perform key lookup or
/// lifecycle management.
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
    uplink_overflow: u16,
    downlink_overflow: u16,
}

impl fmt::Debug for NasSecurityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NasSecurityContext")
            .field("integrity_algorithm", &self.integrity_algorithm)
            .field("ciphering_algorithm", &self.ciphering_algorithm)
            .field("integrity_key", &self.integrity_key)
            .field("ciphering_key", &self.ciphering_key)
            .field("uplink_overflow", &self.uplink_overflow)
            .field("downlink_overflow", &self.downlink_overflow)
            .finish()
    }
}

impl NasSecurityContext {
    /// Build a NAS security context from SDK key handles.
    pub fn new(
        integrity_algorithm: NasIntegrityAlgorithm,
        ciphering_algorithm: NasCipheringAlgorithm,
        integrity_key: KeyHandle,
        ciphering_key: KeyHandle,
        uplink_overflow: u16,
        downlink_overflow: u16,
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
            uplink_overflow,
            downlink_overflow,
        })
    }

    /// Derive a direction-specific COUNT from the current overflow and SQN.
    pub const fn count_for(
        &self,
        direction: NasSecurityDirection,
        sequence_number: u8,
    ) -> NasCount {
        match direction {
            NasSecurityDirection::Uplink => NasCount::new(self.uplink_overflow, sequence_number),
            NasSecurityDirection::Downlink => {
                NasCount::new(self.downlink_overflow, sequence_number)
            }
        }
    }

    /// Verify envelope integrity and return the COUNT used for verification.
    pub fn verify_integrity<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        envelope: &SecurityProtected,
    ) -> Result<NasCount, NasSecurityError> {
        let count = self.count_for(direction, envelope.sequence_number);
        let expected = algorithms.compute_mac(
            self.integrity_algorithm,
            &self.integrity_key,
            count,
            direction,
            &envelope.payload,
        )?;
        if !mac_eq(expected, envelope.mac) {
            return Err(NasSecurityError::IntegrityCheckFailed);
        }
        Ok(count)
    }

    /// Verify integrity and decipher the envelope payload when the security
    /// header type says the payload is ciphered.
    pub fn verify_and_decipher<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        envelope: &SecurityProtected,
    ) -> Result<VerifiedNasPayload, NasSecurityError> {
        let count = self.verify_integrity(algorithms, direction, envelope)?;
        let payload = if envelope.security_header_type.is_ciphered() {
            algorithms.apply_cipher(
                self.ciphering_algorithm,
                &self.ciphering_key,
                count,
                direction,
                &envelope.payload,
            )?
        } else {
            envelope.payload.clone()
        };

        Ok(VerifiedNasPayload { count, payload })
    }

    /// Build a security-protected envelope from a plain or ciphered payload.
    pub fn protect_payload<A: NasSecurityAlgorithms + ?Sized>(
        &self,
        algorithms: &A,
        direction: NasSecurityDirection,
        security_header_type: SecurityHeaderType,
        count: NasCount,
        payload: &[u8],
    ) -> Result<SecurityProtected, NasSecurityError> {
        if security_header_type == SecurityHeaderType::Plain {
            return Err(NasSecurityError::InvalidSecurityHeader);
        }
        let protected_payload = if security_header_type.is_ciphered() {
            algorithms.apply_cipher(
                self.ciphering_algorithm,
                &self.ciphering_key,
                count,
                direction,
                payload,
            )?
        } else {
            Bytes::copy_from_slice(payload)
        };
        let mac = algorithms.compute_mac(
            self.integrity_algorithm,
            &self.integrity_key,
            count,
            direction,
            &protected_payload,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNasPayload {
    /// NAS COUNT used for verification.
    pub count: NasCount,
    /// Verified payload; deciphered when the envelope was ciphered.
    pub payload: Bytes,
}

/// Algorithm provider for NAS integrity and ciphering.
pub trait NasSecurityAlgorithms {
    /// Compute a 32-bit NAS message authentication code.
    fn compute_mac(
        &self,
        algorithm: NasIntegrityAlgorithm,
        key: &KeyHandle,
        count: NasCount,
        direction: NasSecurityDirection,
        message: &[u8],
    ) -> Result<[u8; 4], NasSecurityError>;

    /// Apply the NAS stream cipher. NAS ciphering is symmetric, so the same
    /// hook is used for ciphering and deciphering.
    fn apply_cipher(
        &self,
        algorithm: NasCipheringAlgorithm,
        key: &KeyHandle,
        count: NasCount,
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
        };
        f.write_str(msg)
    }
}

impl std::error::Error for NasSecurityError {}

fn mac_eq(left: [u8; 4], right: [u8; 4]) -> bool {
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
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
            7,
            9,
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
                NasCount::new(9, 0x45),
                &payload,
            )
            .unwrap();
        assert_eq!(protected.mac, [0; 4]);
        assert_eq!(protected.sequence_number, 0x45);
        assert_eq!(protected.payload, payload);
    }

    #[test]
    fn unsupported_real_algorithms_fail_closed() {
        let ctx = NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia2,
            NasCipheringAlgorithm::Nea2,
            session_key("nas-int", 0x11),
            session_key("nas-ciph", 0x22),
            0,
            0,
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
                0,
                0,
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
