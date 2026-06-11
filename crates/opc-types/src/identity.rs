use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

use crate::{
    nf::NfKind,
    validation::{
        validate_digits, validate_hex, validate_slug, validate_spiffe_path, validate_trust_domain,
    },
    ParseError,
};

macro_rules! string_identifier {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $max_len:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
                let value = value.into();
                Ok(Self(validate_slug($kind, &value, $max_len)?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ParseError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                Self::new(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_identifier!(TenantId, "tenant id", 128);
string_identifier!(InstanceId, "instance id", 128);
string_identifier!(
    /// Phase-0 region identifier kept as a validated slug until the topology
    /// model grows into a structured PLMN/tier composite in a later slice.
    RegionId,
    "region id",
    128
);

/// Canonical workload identity URI validated against SPIFFE-style constraints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpiffeId(String);

impl SpiffeId {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        const KIND: &str = "spiffe id";
        const CANONICAL_PATH: &str =
            "/tenant/<tenant-id>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance-id>";

        let value = value.into();
        if value.trim() != value {
            return Err(ParseError::new(
                KIND,
                "must not contain leading or trailing whitespace",
            ));
        }

        let rest = value
            .strip_prefix("spiffe://")
            .ok_or_else(|| ParseError::new(KIND, "must start with 'spiffe://'"))?;

        if rest.contains('?') || rest.contains('#') {
            return Err(ParseError::new(
                KIND,
                "must not include query or fragment components",
            ));
        }

        let slash = rest
            .find('/')
            .ok_or_else(|| ParseError::new(KIND, "must include a trust domain and path"))?;
        let trust_domain = &rest[..slash];
        let path = &rest[slash..];

        validate_trust_domain(KIND, trust_domain)?;
        validate_spiffe_path(KIND, path)?;
        let mut seg = path.trim_start_matches('/').split('/');
        let layout_err = || {
            ParseError::new(
                KIND,
                format!("path must follow canonical OpenPacketCore layout {CANONICAL_PATH}"),
            )
        };

        // Phase 1: verify the canonical 10-segment layout (fixed labels + count).
        // Layout errors must take precedence over typed-segment validation so
        // that non-canonical paths always report the layout error.
        let mut first = seg.next();
        if first == Some("trust-domain") {
            first = seg.next();
        }
        if first != Some("tenant") {
            return Err(layout_err());
        }
        let tenant_id = seg.next().ok_or_else(layout_err)?;

        if seg.next() != Some("ns") {
            return Err(layout_err());
        }
        let _namespace = seg.next().ok_or_else(layout_err)?;

        if seg.next() != Some("sa") {
            return Err(layout_err());
        }
        let _service_account = seg.next().ok_or_else(layout_err)?;

        if seg.next() != Some("nf") {
            return Err(layout_err());
        }
        let nf_kind = seg.next().ok_or_else(layout_err)?;

        if seg.next() != Some("instance") {
            return Err(layout_err());
        }
        let instance_id = seg.next().ok_or_else(layout_err)?;

        if seg.next().is_some() {
            return Err(layout_err());
        }

        // Phase 2: validate typed segments only after layout is confirmed.
        TenantId::new(tenant_id)?;
        NfKind::new(nf_kind)?;
        InstanceId::new(instance_id)?;

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn trust_domain(&self) -> &str {
        let rest = &self.0["spiffe://".len()..];
        let slash = rest
            .find('/')
            .expect("validated SPIFFE IDs always have a path");
        &rest[..slash]
    }

    pub fn path(&self) -> &str {
        let rest = &self.0["spiffe://".len()..];
        let slash = rest
            .find('/')
            .expect("validated SPIFFE IDs always have a path");
        &rest[slash..]
    }
}

impl AsRef<str> for SpiffeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SpiffeId {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for SpiffeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Public Land Mobile Network identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlmnId {
    mcc: String,
    mnc: String,
}

impl PlmnId {
    pub fn new(mcc: impl Into<String>, mnc: impl Into<String>) -> Result<Self, ParseError> {
        let mcc = validate_digits("plmn id", &mcc.into(), &[3])?;
        let mnc = validate_digits("plmn id", &mnc.into(), &[2, 3])?;
        Ok(Self { mcc, mnc })
    }

    pub fn mcc(&self) -> &str {
        &self.mcc
    }

    pub fn mnc(&self) -> &str {
        &self.mnc
    }
}

impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.mcc, self.mnc)
    }
}

impl FromStr for PlmnId {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((mcc, mnc)) = value.split_once('-') {
            return Self::new(mcc, mnc);
        }

        if !value.is_ascii() {
            return Err(ParseError::new("plmn id", "must contain only ASCII digits"));
        }

        if value.len() == 5 || value.len() == 6 {
            return Self::new(&value[..3], &value[3..]);
        }

        Err(ParseError::new(
            "plmn id",
            "must be 'MCC-MNC' or 5-6 digit compact form (MCCMN or MCCMNC)",
        ))
    }
}

impl Serialize for PlmnId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PlmnId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// Single-Network Slice Selection Assistance Information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Snssai {
    sst: u8,
    sd: Option<String>,
}

impl Snssai {
    pub fn new(sst: u8, sd: Option<impl Into<String>>) -> Result<Self, ParseError> {
        let sd = match sd {
            Some(sd) => Some(validate_hex("snssai", &sd.into(), 6)?),
            None => None,
        };

        Ok(Self { sst, sd })
    }

    pub fn sst(&self) -> u8 {
        self.sst
    }

    pub fn sd(&self) -> Option<&str> {
        self.sd.as_deref()
    }
}

impl fmt::Display for Snssai {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sst={}", self.sst)?;
        if let Some(sd) = &self.sd {
            write!(f, ",sd={sd}")?;
        }
        Ok(())
    }
}

impl FromStr for Snssai {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(sst_and_sd) = value.strip_prefix("sst=") {
            if let Some((sst, sd_hex)) = sst_and_sd.split_once(",sd=") {
                let sst = sst.parse::<u8>().map_err(|_| {
                    ParseError::new("snssai", "sst must be an unsigned 8-bit integer")
                })?;
                return Self::new(sst, Some(sd_hex));
            }

            let sst = sst_and_sd
                .parse::<u8>()
                .map_err(|_| ParseError::new("snssai", "sst must be an unsigned 8-bit integer"))?;
            return Self::new(sst, None::<String>);
        }

        if let Some((sst, sd)) = value.split_once('-') {
            let sst = sst
                .parse::<u8>()
                .map_err(|_| ParseError::new("snssai", "sst must be an unsigned 8-bit integer"))?;
            return Self::new(sst, Some(sd));
        }

        let sst = value
            .parse::<u8>()
            .map_err(|_| ParseError::new("snssai", "sst must be an unsigned 8-bit integer"))?;
        Self::new(sst, None::<String>)
    }
}

impl Serialize for Snssai {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Snssai {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}
