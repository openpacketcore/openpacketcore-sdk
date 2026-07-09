//! Stateless IKE cookie helper for edge DoS posture.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::IpsecLbError;
use crate::model::IpAddress;

type HmacSha256 = Hmac<Sha256>;

/// HMAC key for IKE cookie generation.
#[derive(Clone, PartialEq, Eq)]
pub struct CookieKey([u8; 32]);

impl CookieKey {
    /// Build a cookie key from bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieKey")
            .field("len", &self.0.len())
            .field("redacted", &true)
            .finish()
    }
}

/// Time slot used for stateless cookie rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct CookieSlot(u64);

impl CookieSlot {
    /// Build a cookie slot.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Previous slot, saturating at zero.
    #[must_use]
    pub const fn previous(self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

/// IKE cookie bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IkeCookie([u8; 32]);

impl IkeCookie {
    /// Build a cookie from bytes extracted from an IKE COOKIE Notify payload.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow raw cookie bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for IkeCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IkeCookie")
            .field("len", &self.0.len())
            .field("redacted", &true)
            .finish()
    }
}

/// Caller-selected IKE COOKIE enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeCookiePolicy {
    require_cookie: bool,
}

impl IkeCookiePolicy {
    /// Require a valid echoed COOKIE before allowing state or crypto allocation.
    #[must_use]
    pub const fn require_cookie() -> Self {
        Self {
            require_cookie: true,
        }
    }

    /// Allow an IKE_SA_INIT request even when no COOKIE was echoed.
    ///
    /// This is intended for deployments or traffic periods where the edge is
    /// not enforcing RFC 7296 §2.6 anti-DoS posture.
    #[must_use]
    pub const fn allow_without_cookie() -> Self {
        Self {
            require_cookie: false,
        }
    }

    /// True when this policy requires a valid echoed COOKIE.
    #[must_use]
    pub const fn requires_cookie(self) -> bool {
        self.require_cookie
    }
}

impl Default for IkeCookiePolicy {
    fn default() -> Self {
        Self::require_cookie()
    }
}

/// Input tuple for an IKE_SA_INIT COOKIE decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeCookieRequest {
    /// Initiator SPI from the IKE header.
    pub initiator_spi: u64,
    /// Source IP address observed at the edge.
    pub source_ip: IpAddress,
    /// SWu VIP or local destination address observed at the edge.
    pub destination_ip: IpAddress,
    /// COOKIE echoed by the initiator, if the request carried one.
    pub echoed_cookie: Option<IkeCookie>,
    /// Current stateless cookie rotation slot.
    pub slot: CookieSlot,
}

/// Stateless edge decision for an IKE_SA_INIT request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeCookieDecision {
    /// Request may proceed to IKE parsing, crypto, and state allocation.
    Allow,
    /// Request must be answered with an IKE COOKIE challenge.
    Challenge {
        /// Stateless cookie to include in the response Notify payload.
        cookie: IkeCookie,
    },
}

impl IkeCookieDecision {
    /// Stable decision code for metrics and tests.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Challenge { .. } => "challenge",
        }
    }
}

/// Stateless IKE cookie generator/verifier.
#[derive(Debug, Clone)]
pub struct IkeCookieGate {
    key: CookieKey,
}

impl IkeCookieGate {
    /// Build a cookie gate.
    #[must_use]
    pub const fn new(key: CookieKey) -> Self {
        Self { key }
    }

    /// Generate a cookie for an IKE_SA_INIT edge tuple.
    pub fn generate(
        &self,
        initiator_spi: u64,
        source_ip: IpAddress,
        destination_ip: IpAddress,
        slot: CookieSlot,
    ) -> Result<IkeCookie, IpsecLbError> {
        let mut mac = HmacSha256::new_from_slice(&self.key.0)
            .map_err(|_| IpsecLbError::EntropyUnavailable)?;
        mac.update(b"opc-ipsec-lb/ike-cookie/v1");
        mac.update(&initiator_spi.to_be_bytes());
        feed_ip(&mut mac, source_ip);
        feed_ip(&mut mac, destination_ip);
        mac.update(&slot.0.to_be_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&bytes);
        Ok(IkeCookie::from_bytes(cookie))
    }

    /// Verify a cookie for the current or immediately previous slot.
    pub fn verify(
        &self,
        cookie: IkeCookie,
        initiator_spi: u64,
        source_ip: IpAddress,
        destination_ip: IpAddress,
        current_slot: CookieSlot,
    ) -> Result<(), IpsecLbError> {
        let current = self.generate(initiator_spi, source_ip, destination_ip, current_slot)?;
        let previous = self.generate(
            initiator_spi,
            source_ip,
            destination_ip,
            current_slot.previous(),
        )?;
        if cookie.constant_time_eq(current) || cookie.constant_time_eq(previous) {
            Ok(())
        } else {
            Err(IpsecLbError::CookieRejected)
        }
    }

    /// Evaluate whether an IKE_SA_INIT may allocate state or must be challenged.
    ///
    /// This is intentionally stateless: the only accepted proof is a COOKIE that
    /// validates against the source/destination tuple, initiator SPI, and current
    /// or previous rotation slot.
    pub fn evaluate(
        &self,
        request: IkeCookieRequest,
        policy: IkeCookiePolicy,
    ) -> Result<IkeCookieDecision, IpsecLbError> {
        if let Some(cookie) = request.echoed_cookie {
            self.verify(
                cookie,
                request.initiator_spi,
                request.source_ip,
                request.destination_ip,
                request.slot,
            )?;
            return Ok(IkeCookieDecision::Allow);
        }

        if policy.requires_cookie() {
            let cookie = self.generate(
                request.initiator_spi,
                request.source_ip,
                request.destination_ip,
                request.slot,
            )?;
            Ok(IkeCookieDecision::Challenge { cookie })
        } else {
            Ok(IkeCookieDecision::Allow)
        }
    }
}

impl IkeCookie {
    fn constant_time_eq(self, other: Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

fn feed_ip(mac: &mut HmacSha256, ip: IpAddress) {
    match ip {
        IpAddress::V4(octets) => {
            mac.update(&[4]);
            mac.update(&octets);
        }
        IpAddress::V6(octets) => {
            mac.update(&[6]);
            mac.update(&octets);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> IkeCookieGate {
        IkeCookieGate::new(CookieKey::new([0x42; 32]))
    }

    #[test]
    fn cookie_round_trips_current_and_previous_slot_without_state() {
        let gate = gate();
        let src = IpAddress::V4([198, 51, 100, 9]);
        let dst = IpAddress::V4([203, 0, 113, 1]);
        let cookie = gate.generate(0x1234, src, dst, CookieSlot::new(9)).unwrap();
        gate.verify(cookie, 0x1234, src, dst, CookieSlot::new(9))
            .unwrap();
        gate.verify(cookie, 0x1234, src, dst, CookieSlot::new(10))
            .unwrap();
    }

    #[test]
    fn cookie_binds_source_ip_and_initiator_spi() {
        let gate = gate();
        let src = IpAddress::V4([198, 51, 100, 9]);
        let dst = IpAddress::V4([203, 0, 113, 1]);
        let cookie = gate.generate(0x1234, src, dst, CookieSlot::new(9)).unwrap();
        assert!(matches!(
            gate.verify(cookie, 0x1235, src, dst, CookieSlot::new(9))
                .unwrap_err(),
            IpsecLbError::CookieRejected
        ));
        assert!(gate
            .verify(
                cookie,
                0x1234,
                IpAddress::V4([198, 51, 100, 10]),
                dst,
                CookieSlot::new(9)
            )
            .is_err());
    }

    #[test]
    fn cookie_key_debug_is_redacted() {
        let debug = format!("{:?}", CookieKey::new([0xab; 32]));
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn cookie_token_debug_is_redacted() {
        let debug = format!("{:?}", IkeCookie::from_bytes([0xab; 32]));
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn evaluate_challenges_when_policy_requires_cookie() {
        let gate = gate();
        let src = IpAddress::V4([198, 51, 100, 9]);
        let dst = IpAddress::V4([203, 0, 113, 1]);
        let request = IkeCookieRequest {
            initiator_spi: 0x1234,
            source_ip: src,
            destination_ip: dst,
            echoed_cookie: None,
            slot: CookieSlot::new(9),
        };

        let decision = gate
            .evaluate(request, IkeCookiePolicy::require_cookie())
            .unwrap();
        assert_eq!(decision.code(), "challenge");

        let IkeCookieDecision::Challenge { cookie } = decision else {
            panic!("cookie policy should challenge cookieless IKE_SA_INIT");
        };
        assert_eq!(
            gate.evaluate(
                IkeCookieRequest {
                    echoed_cookie: Some(cookie),
                    ..request
                },
                IkeCookiePolicy::require_cookie(),
            )
            .unwrap(),
            IkeCookieDecision::Allow
        );
    }

    #[test]
    fn evaluate_rejects_invalid_echoed_cookie_even_when_policy_is_relaxed() {
        let gate = gate();
        let request = IkeCookieRequest {
            initiator_spi: 0x1234,
            source_ip: IpAddress::V4([198, 51, 100, 9]),
            destination_ip: IpAddress::V4([203, 0, 113, 1]),
            echoed_cookie: Some(IkeCookie::from_bytes([0xff; 32])),
            slot: CookieSlot::new(9),
        };

        assert_eq!(
            gate.evaluate(request, IkeCookiePolicy::allow_without_cookie())
                .unwrap_err(),
            IpsecLbError::CookieRejected
        );
    }
}
