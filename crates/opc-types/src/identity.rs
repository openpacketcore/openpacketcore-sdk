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
            /// Parse and validate the identifier string.
            pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
                let value = value.into();
                Ok(Self(validate_slug($kind, &value, $max_len)?))
            }

            /// Create from a known-valid `&'static str`.
            ///
            /// # Panics
            ///
            /// Panics if `value` fails validation. This is intended for
            /// deterministic literals in tests and reference code; use `new`
            /// for runtime input.
            pub fn from_static(value: &'static str) -> Self {
                Self::new(value).unwrap_or_else(|e| panic!("invalid {}: {e}", $kind))
            }

            /// Return the identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the underlying String.
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

string_identifier!(
    /// Validated tenant identifier.
    TenantId,
    "tenant id",
    128
);
string_identifier!(
    /// Validated NF instance identifier.
    InstanceId,
    "instance id",
    128
);
string_identifier!(
    /// Phase-0 region identifier kept as a validated slug until the topology
    /// model grows into a structured PLMN/tier composite in a later slice.
    RegionId,
    "region id",
    128
);

/// Validated International Mobile Equipment Identity.
///
/// The exact transmitted representation is preserved. Fourteen digits carry
/// TAC and SNR only. A fifteenth digit may be either the Luhn check digit used
/// for presentation or the zero spare digit used on 3GPP protocol surfaces.
/// Wire parsing does not infer which meaning applies and never synthesizes or
/// rejects the fifteenth digit using Luhn. Formatting is always redacted;
/// callers must deliberately use [`Imei::expose`] or [`Imei::as_str`] to
/// access the original validated digits.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Imei(String);

impl Imei {
    /// Parse and validate a 14- or 15-digit IMEI without changing its digits.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        Ok(Self(validate_digits("imei", &value.into(), &[14, 15])?))
    }

    /// Deliberately expose the exact validated 14- or 15-digit IMEI.
    ///
    /// The returned value is personally identifying data and must not be
    /// written to logs, traces, panic messages, or ordinary serialized output.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Deliberately expose the exact validated IMEI as a string slice.
    ///
    /// This is an alias for [`Imei::expose`].
    pub fn as_str(&self) -> &str {
        self.expose()
    }

    /// Return the fourteen-digit TAC and SNR equipment identity.
    pub fn equipment_body(&self) -> &str {
        &self.0[..14]
    }

    /// Return the transmitted fifteenth digit, if one was present.
    ///
    /// A zero value can be either the protocol spare digit or a valid Luhn
    /// check digit. The wire representation does not distinguish those cases.
    pub fn transmitted_digit(&self) -> Option<u8> {
        self.0.as_bytes().get(14).map(|digit| *digit - b'0')
    }

    /// Return the Luhn check digit calculated from TAC and SNR.
    pub fn luhn_check_digit(&self) -> u8 {
        imei_check_digit(self.equipment_body().as_bytes())
    }

    /// Return whether this value contains all fifteen transmitted digits.
    pub fn has_transmitted_digit(&self) -> bool {
        self.0.len() == 15
    }

    /// Return whether two representations identify the same TAC and SNR.
    pub fn identifies_same_equipment(&self, other: &Self) -> bool {
        self.equipment_body() == other.equipment_body()
    }
}

impl fmt::Debug for Imei {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Imei(<redacted>)")
    }
}

impl fmt::Display for Imei {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-imei>")
    }
}

impl FromStr for Imei {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Imei {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Imei {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Exact 15-digit IMEI received from a UE protocol identity surface.
///
/// The fifteenth digit is preserved without guessing whether it is a Luhn
/// check digit or the 3GPP spare digit. This complete form is required by
/// DEVICE_IDENTITY and the TS 33.402 Annex A.4 emergency KDF. Formatting is
/// always redacted and this type intentionally has no serde implementation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Imei15(String);

impl Imei15 {
    /// Parse and preserve exactly 15 decimal IMEI digits.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        Ok(Self(validate_digits("imei15", &value.into(), &[15])?))
    }

    /// Deliberately expose the exact 15 transmitted digits.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Deliberately expose the exact 15 transmitted digits as a string slice.
    pub fn as_str(&self) -> &str {
        self.expose()
    }

    /// Return the fourteen-digit TAC and SNR equipment identity.
    pub fn equipment_body(&self) -> &str {
        &self.0[..14]
    }

    /// Return the received fifteenth digit without assigning it a meaning.
    pub fn transmitted_digit(&self) -> u8 {
        self.0.as_bytes()[14] - b'0'
    }

    /// Return the Luhn check digit calculated from TAC and SNR.
    pub fn luhn_check_digit(&self) -> u8 {
        imei_check_digit(self.equipment_body().as_bytes())
    }
}

impl fmt::Debug for Imei15 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Imei15(<redacted>)")
    }
}

impl fmt::Display for Imei15 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-imei15>")
    }
}

impl FromStr for Imei15 {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Imei15 {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Imei15 {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<Imei> for Imei15 {
    type Error = ParseError;

    fn try_from(value: Imei) -> Result<Self, Self::Error> {
        Self::new(value.0)
    }
}

impl TryFrom<&Imei> for Imei15 {
    type Error = ParseError;

    fn try_from(value: &Imei) -> Result<Self, Self::Error> {
        Self::new(value.as_str())
    }
}

impl From<Imei15> for Imei {
    fn from(value: Imei15) -> Self {
        Self(value.0)
    }
}

impl From<&Imei15> for Imei {
    fn from(value: &Imei15) -> Self {
        Self(value.0.clone())
    }
}

/// Validated International Mobile Equipment Identity and Software Version.
///
/// An IMEISV is exactly 16 decimal digits: an eight-digit Type Allocation Code,
/// a six-digit serial number, and a two-digit software-version number.
/// Formatting is always redacted and this type intentionally has no serde
/// implementation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Imeisv(String);

impl Imeisv {
    /// Parse and validate a 16-digit IMEISV.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        Ok(Self(validate_digits("imeisv", &value.into(), &[16])?))
    }

    /// Deliberately expose the 16-digit IMEISV.
    ///
    /// The returned value is personally identifying data and must not be
    /// written to logs, traces, panic messages, or ordinary serialized output.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Deliberately expose the 16-digit IMEISV as a string slice.
    ///
    /// This is an alias for [`Imeisv::expose`].
    pub fn as_str(&self) -> &str {
        self.expose()
    }

    /// Split the IMEISV into redaction-safe typed component views.
    pub fn split(&self) -> ImeisvParts<'_> {
        ImeisvParts {
            type_allocation_code: &self.0[..8],
            serial_number: &self.0[8..14],
            software_version: &self.0[14..],
        }
    }

    /// Return the exact fourteen-digit TAC and SNR equipment identity.
    pub fn equipment_identity(&self) -> Imei {
        Imei(self.0[..14].to_owned())
    }

    /// Deliberately synthesize a 15-digit presentation IMEI with Luhn digit.
    pub fn to_luhn_imei(&self) -> Imei15 {
        let mut value = self.0[..14].to_owned();
        value.push(char::from(b'0' + imei_check_digit(value.as_bytes())));
        Imei15(value)
    }
}

impl fmt::Debug for Imeisv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Imeisv(<redacted>)")
    }
}

impl fmt::Display for Imeisv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-imeisv>")
    }
}

impl FromStr for Imeisv {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Imeisv {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Imeisv {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Borrowed component views of an [`Imeisv`].
///
/// Debug formatting is redacted. Each accessor deliberately exposes one part
/// of the device identity and is subject to the same handling requirements as
/// [`Imeisv::expose`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ImeisvParts<'a> {
    type_allocation_code: &'a str,
    serial_number: &'a str,
    software_version: &'a str,
}

impl<'a> ImeisvParts<'a> {
    /// Deliberately expose the eight-digit Type Allocation Code.
    pub const fn type_allocation_code(self) -> &'a str {
        self.type_allocation_code
    }

    /// Deliberately expose the six-digit serial number.
    pub const fn serial_number(self) -> &'a str {
        self.serial_number
    }

    /// Deliberately expose the two-digit software-version number.
    pub const fn software_version(self) -> &'a str {
        self.software_version
    }
}

impl fmt::Debug for ImeisvParts<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImeisvParts(<redacted>)")
    }
}

fn imei_check_digit(body: &[u8]) -> u8 {
    let sum = body.iter().enumerate().fold(0_u16, |sum, (index, digit)| {
        let digit = u16::from(*digit - b'0');
        let weighted = if index % 2 == 1 { digit * 2 } else { digit };
        sum + weighted / 10 + weighted % 10
    });
    ((10 - (sum % 10)) % 10) as u8
}

/// Canonical workload identity URI validated against SPIFFE-style constraints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpiffeId(String);

impl SpiffeId {
    /// Parse and validate a SPIFFE ID string.
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

    /// Return the SPIFFE ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the trust domain portion.
    pub fn trust_domain(&self) -> &str {
        let rest = &self.0["spiffe://".len()..];
        rest.find('/').map_or(rest, |slash| &rest[..slash])
    }

    /// Extract the path portion after the trust domain.
    pub fn path(&self) -> &str {
        let rest = &self.0["spiffe://".len()..];
        rest.find('/').map_or("", |slash| &rest[slash..])
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
    /// Create a new PLMN identifier from MCC and MNC strings.
    pub fn new(mcc: impl Into<String>, mnc: impl Into<String>) -> Result<Self, ParseError> {
        let mcc = validate_digits("plmn id", &mcc.into(), &[3])?;
        let mnc = validate_digits("plmn id", &mnc.into(), &[2, 3])?;
        Ok(Self { mcc, mnc })
    }

    /// Mobile Country Code.
    pub fn mcc(&self) -> &str {
        &self.mcc
    }

    /// Mobile Network Code.
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
    /// Create a new S-NSSAI from SST and optional SD.
    pub fn new(sst: u8, sd: Option<impl Into<String>>) -> Result<Self, ParseError> {
        match sd {
            Some(sd) => Self::with_sd(sst, sd),
            None => Ok(Self::without_sd(sst)),
        }
    }

    /// Create an S-NSSAI with a slice differentiator.
    ///
    /// `sd` must be exactly six hexadecimal characters (0-9, a-f, A-F). It is
    /// normalized to lowercase on success.
    ///
    /// # Example
    ///
    /// ```rust
    /// use opc_types::Snssai;
    ///
    /// let s = Snssai::with_sd(1, "010203").expect("valid sd");
    /// assert_eq!(s.sst(), 1);
    /// assert_eq!(s.sd(), Some("010203"));
    /// ```
    pub fn with_sd(sst: u8, sd: impl Into<String>) -> Result<Self, ParseError> {
        let sd = validate_hex("snssai", &sd.into(), 6)?;
        Ok(Self { sst, sd: Some(sd) })
    }

    /// Create an S-NSSAI without a slice differentiator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use opc_types::Snssai;
    ///
    /// let s = Snssai::without_sd(1);
    /// assert_eq!(s.sst(), 1);
    /// assert_eq!(s.sd(), None);
    /// ```
    pub fn without_sd(sst: u8) -> Self {
        Self { sst, sd: None }
    }

    /// Slice/Service Type.
    pub fn sst(&self) -> u8 {
        self.sst
    }

    /// Slice Differentiator, if present.
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
