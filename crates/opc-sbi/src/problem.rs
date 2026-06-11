use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Stable 3GPP-compatible cause code carried in ProblemDetails.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CauseCode(String);

impl CauseCode {
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

    pub fn as_str(&self) -> &str {
        &self.0
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CauseCodeError {
    #[error("cause code must not be empty")]
    Empty,
    #[error("cause code must not contain leading or trailing whitespace")]
    Whitespace,
    #[error("cause code must be 128 characters or fewer")]
    TooLong,
    #[error("cause code must be uppercase ASCII letters, digits, '_' or '-'")]
    InvalidFormat,
}

/// Structured invalid-parameter entry for TS 29.500 ProblemDetails bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidParam {
    pub param: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InvalidParam {
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
    #[serde(
        serialize_with = "serialize_status_code",
        deserialize_with = "deserialize_status_code"
    )]
    pub status: StatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<CauseCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid_params: Vec<InvalidParam>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

impl ProblemDetails {
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
