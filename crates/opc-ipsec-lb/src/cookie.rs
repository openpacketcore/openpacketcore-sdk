//! Stateless IKE cookie helper for edge DoS posture.

use hmac::{Hmac, Mac};
use sha2::Sha256;

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

impl std::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IkeCookie([u8; 32]);

impl IkeCookie {
    /// Borrow raw cookie bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
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
        Ok(IkeCookie(cookie))
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
        if cookie == current || cookie == previous {
            Ok(())
        } else {
            Err(IpsecLbError::CookieRejected)
        }
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
}
