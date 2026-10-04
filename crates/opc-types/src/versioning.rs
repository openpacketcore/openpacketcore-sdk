use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::{
    validation::{hex_nibble, validate_hex},
    ParseError,
};

/// Monotonic running-configuration version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigVersion(u64);

impl ConfigVersion {
    /// Sentinel pre-commit version. The first published configuration version is
    /// typically produced by advancing this value to `1`.
    pub const INITIAL: Self = Self(0);

    /// Create a new config version from a raw u64.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return the next config version, or `None` on overflow.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl fmt::Display for ConfigVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stable transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxId(Uuid);

impl TxId {
    /// Generate a new random transaction ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID as a transaction ID.
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Access the underlying UUID.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for TxId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for TxId {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            Uuid::parse_str(value).map_err(|e| ParseError::new("tx id", e.to_string()))?,
        ))
    }
}

/// 32-byte schema digest rendered as lowercase hexadecimal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaDigest([u8; 32]);

impl SchemaDigest {
    /// Create a digest from raw 32-byte array.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render as lowercase hexadecimal string.
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

impl fmt::Debug for SchemaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SchemaDigest").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for SchemaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for SchemaDigest {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = validate_hex("schema digest", value, 64)?;
        let mut bytes = [0_u8; 32];

        for (idx, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = hex_nibble("schema digest", chunk[0])?;
            let low = hex_nibble("schema digest", chunk[1])?;
            bytes[idx] = (high << 4) | low;
        }

        Ok(Self(bytes))
    }
}

impl Serialize for SchemaDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SchemaDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// UTC timestamp used across control-plane records and evidence.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Current UTC timestamp.
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Convert an `OffsetDateTime` to UTC and wrap it.
    pub fn from_offset_datetime(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }

    /// Access the inner `OffsetDateTime`.
    pub const fn as_offset_datetime(&self) -> &OffsetDateTime {
        &self.0
    }

    /// Add seconds to the timestamp, returning `None` if the result would be
    /// outside the supported timestamp range.
    pub fn add_seconds(self, seconds: i64) -> Option<Self> {
        self.0
            .checked_add(time::Duration::seconds(seconds))
            .map(Self)
    }

    // RFC 3339 permits four year digits. This wrapper always holds UTC, so
    // even all nine fractional digits fit in 30 bytes, including the final Z.
    // Keep the library's complete formatting rules and use the actual sink
    // position, including fractional digits, to select the written bytes.
    fn format_rfc3339<'a>(&self, buffer: &'a mut [u8; 30]) -> Result<&'a str, fmt::Error> {
        let mut sink = buffer.as_mut_slice();
        self.0
            .format_into(&mut sink, &Rfc3339)
            .map_err(|_| fmt::Error)?;
        let written = 30 - sink.len();
        std::str::from_utf8(buffer.get(..written).ok_or(fmt::Error)?).map_err(|_| fmt::Error)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Timestamp").field(&self.to_string()).finish()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.format_rfc3339(&mut [0; 30])?)
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|err| ParseError::new("timestamp", err.to_string()))?;
        Ok(Self::from_offset_datetime(parsed))
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self::from_offset_datetime(value)
    }
}

impl From<Timestamp> for OffsetDateTime {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buffer = [0; 30];
        let value = self
            .format_rfc3339(&mut buffer)
            .map_err(|_| serde::ser::Error::custom("timestamp cannot encode as RFC 3339"))?;
        serializer.serialize_str(value)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl serde::de::Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Timestamp::from_str(value).map_err(E::custom)
            }

            // String's visitor also accepts UTF-8 bytes. Preserve that input
            // surface for serializers that deliver bytes instead of text.
            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                match std::str::from_utf8(value) {
                    Ok(value) => self.visit_str(value),
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Bytes(value), &self)),
                }
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}
