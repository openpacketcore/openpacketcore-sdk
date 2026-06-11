//! Canonical TS 29.500 ProblemDetails model shared by all SBI NFs
//! (RFC 007 §7).
//!
//! NF handlers return domain errors; the framework maps them onto this type
//! so every SBI route emits the same deterministic, spec-cited error body.
//! Serialization uses camelCase field names and omits unset optional fields,
//! matching the 3GPP OpenAPI `ProblemDetails` schema.

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Stable 3GPP-compatible cause code carried in ProblemDetails.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CauseCode(String);

impl CauseCode {
    /// Validate and wrap a cause-code string.
    ///
    /// Accepted grammar: 1–128 characters of uppercase ASCII letters, digits,
    /// `_` or `-` (the conventional 3GPP application-error spelling such as
    /// `MANDATORY_IE_MISSING`), with no surrounding whitespace. Anything else
    /// is rejected so cause codes stay stable, log-safe metric labels.
    pub fn new(value: impl Into<String>) -> Result<Self, CauseCodeError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CauseCodeError::Empty);
        }
        if trimmed != value {
            return Err(CauseCodeError::Whitespace);
        }
        if trimmed.len() > 128 {
            return Err(CauseCodeError::TooLong);
        }
        if !trimmed.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        }) {
            return Err(CauseCodeError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrow the validated cause-code text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the validated cause-code text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for CauseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for CauseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CauseCode {
    type Err = CauseCodeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for CauseCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CauseCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Reason a candidate string was rejected by `CauseCode::new`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CauseCodeError {
    /// The candidate was empty (or whitespace-only).
    #[error("cause code must not be empty")]
    Empty,
    /// The candidate had leading or trailing whitespace; cause codes are
    /// compared byte-for-byte, so padding is rejected instead of trimmed.
    #[error("cause code must not contain leading or trailing whitespace")]
    Whitespace,
    /// The candidate exceeded the 128-character bound that keeps cause codes
    /// usable as metric labels.
    #[error("cause code must be 128 characters or fewer")]
    TooLong,
    /// The candidate contained characters outside the
    /// `[A-Z0-9_-]` cause-code alphabet.
    #[error("cause code must be uppercase ASCII letters, digits, '_' or '-'")]
    InvalidFormat,
}

/// Structured invalid-parameter entry for TS 29.500 ProblemDetails bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidParam {
    /// Attribute name (or JSON pointer) of the offending request parameter,
    /// per the TS 29.500 `InvalidParam` schema.
    pub param: String,
    /// Optional human-readable explanation of why the parameter was
    /// rejected; omitted from the JSON body when `None`. Must not contain
    /// the rejected value itself if that value is subscriber-identifying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InvalidParam {
    /// Build an entry naming the offending parameter, with an optional
    /// client-safe reason string.
    pub fn new(param: impl Into<String>, reason: Option<String>) -> Self {
        Self {
            param: param.into(),
            reason,
        }
    }
}

/// Canonical SBI ProblemDetails model from RFC 007 §7.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDetails {
    /// HTTP status code of the response; serialized as the bare numeric
    /// status (e.g. `503`), matching the 3GPP `ProblemDetails.status` field.
    #[serde(
        serialize_with = "serialize_status_code",
        deserialize_with = "deserialize_status_code"
    )]
    pub status: StatusCode,
    /// Machine-readable application error (TS 29.500 §5.2.7.2 application
    /// errors, e.g. `MANDATORY_IE_MISSING`); the stable key consumers and
    /// metrics branch on, unlike the free-text fields below.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<CauseCode>,
    /// Short human-readable summary of the problem type; should stay the
    /// same across occurrences of the same problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Human-readable explanation specific to this occurrence. Must be
    /// client-safe: no secrets, tokens, or raw subscriber identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence of the problem
    /// (typically the request path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Per-parameter rejection details for 400-class errors; omitted from
    /// the JSON body when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid_params: Vec<InvalidParam>,
    /// Hex-encoded `supportedFeatures` bitmask (TS 29.500 feature
    /// negotiation), returned when the error relates to an unsupported
    /// optional feature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

impl ProblemDetails {
    /// Build a minimal ProblemDetails carrying only the HTTP status; all
    /// optional fields start unset and `invalid_params` empty.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            cause: None,
            title: None,
            detail: None,
            instance: None,
            invalid_params: Vec::new(),
            supported_features: None,
        }
    }
}

fn serialize_status_code<S>(status: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u16(status.as_u16())
}

fn deserialize_status_code<'de, D>(deserializer: D) -> Result<StatusCode, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = u16::deserialize(deserializer)?;
    StatusCode::from_u16(raw).map_err(serde::de::Error::custom)
}
