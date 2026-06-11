use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

use crate::{validation::validate_slug, InstanceId, ParseError};

/// Canonical OpenPacketCore network-function kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NfKind(String);

impl NfKind {
    /// Known 3GPP network-function kinds.
    pub const KNOWN_VALUES: [&'static str; 16] = [
        "amf", "ausf", "bsf", "chf", "nef", "nrf", "nssf", "nwdaf", "pcf", "scp", "sepp", "smf",
        "udm", "udr", "udsf", "upf",
    ];

    /// Parse and validate an NF kind string.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        let value = value.into();
        Ok(Self(validate_slug("nf kind", &value, 64)?))
    }

    /// Return the NF kind as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this NF kind is in the known 3GPP set.
    pub fn is_known(&self) -> bool {
        Self::KNOWN_VALUES.contains(&self.as_str())
    }
}

impl AsRef<str> for NfKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for NfKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NfKind {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for NfKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NfKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Compatibility alias used by RFC examples.
pub type NetworkFunctionKind = NfKind;

/// Compatibility alias used by SBI RFC examples.
pub type NfType = NfKind;

/// Compatibility alias used by SBI RFC examples.
pub type NfInstanceId = InstanceId;
