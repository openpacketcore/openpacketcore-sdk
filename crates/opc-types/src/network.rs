use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ParseError;

/// Validated six-bit Differentiated Services Code Point (DSCP).
///
/// The two least-significant bits in an IPv4 ToS or IPv6 Traffic Class field
/// are ECN, so a DSCP codepoint is restricted to `0..=63`. Use this type at
/// configuration boundaries so an out-of-range value cannot reach a packet
/// encoder or kernel datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DscpCodepoint(u8);

impl DscpCodepoint {
    /// Largest valid six-bit DSCP codepoint.
    pub const MAX: u8 = 63;

    /// Validate and construct a DSCP codepoint.
    pub fn new(value: u8) -> Result<Self, ParseError> {
        if value > Self::MAX {
            return Err(ParseError::new(
                "dscp codepoint",
                "must be between 0 and 63 inclusive",
            ));
        }
        Ok(Self(value))
    }

    /// Return the six-bit codepoint as an integer in `0..=63`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Return the DSCP bits in their IPv4 ToS / IPv6 Traffic Class position.
    ///
    /// The two ECN bits are zero. Packet encoders should combine this value
    /// with the packet's existing ECN bits rather than overwriting them.
    #[must_use]
    pub const fn shifted(self) -> u8 {
        self.0 << 2
    }
}

impl TryFrom<u8> for DscpCodepoint {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DscpCodepoint> for u8 {
    fn from(value: DscpCodepoint) -> Self {
        value.get()
    }
}

impl Serialize for DscpCodepoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.get())
    }
}

impl<'de> Deserialize<'de> for DscpCodepoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_six_bit_range() {
        assert_eq!(DscpCodepoint::new(0).unwrap().get(), 0);
        assert_eq!(DscpCodepoint::new(63).unwrap().get(), 63);
    }

    #[test]
    fn rejects_out_of_range_values() {
        let error = DscpCodepoint::new(64).unwrap_err();
        assert_eq!(error.kind(), "dscp codepoint");
        assert_eq!(error.message(), "must be between 0 and 63 inclusive");
        assert!(DscpCodepoint::new(u8::MAX).is_err());
    }

    #[test]
    fn serde_is_numeric_and_validated() {
        let value = DscpCodepoint::new(46).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), "46");
        assert_eq!(serde_json::from_str::<DscpCodepoint>("46").unwrap(), value);
        assert!(serde_json::from_str::<DscpCodepoint>("64").is_err());
    }

    #[test]
    fn shifted_value_leaves_ecn_bits_clear() {
        assert_eq!(DscpCodepoint::new(46).unwrap().shifted(), 0xb8);
    }
}
